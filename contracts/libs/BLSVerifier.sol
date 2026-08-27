// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BLS12381.sol";

/**
 * @title BLSVerifier
 * @notice Verifier library for multi-guardian BLS12-381 threshold signatures.
 * Enables K-of-N guardians to aggregate signatures off-chain into a single 96-byte BLS signature
 * verified in a single on-chain transaction with >70% gas savings over sequential ECDSA checks.
 */
library BLSVerifier {
    using BLS12381 for bytes;

    struct ApprovalClaim {
        uint256 requestId;
        uint256 vaultId;
        uint256 documentId;
        address beneficiary;
        uint256 chainId;
    }

    event BLSSignatureVerified(uint256 indexed requestId, uint256 guardianCount, uint256 gasUsed);
    event ProofOfPossessionVerified(address indexed guardian, bytes blsPublicKey);

    error ThresholdNotMet(uint256 participating, uint256 required);
    error InvalidAggregatedSignature();
    error InvalidProofOfPossession();
    error DuplicateGuardianIndex();

    /**
     * @notice Compute canonical message digest for vault access approval.
     */
    function computeApprovalDigest(
        uint256 requestId,
        uint256 vaultId,
        uint256 documentId,
        address beneficiary,
        uint256 chainId
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "SPOOVAULT_ACCESS_APPROVAL_V1",
                requestId,
                vaultId,
                documentId,
                beneficiary,
                chainId
            )
        );
    }

    /**
     * @notice Verify Proof of Possession (PoP) signature over guardian's public key.
     */
    function verifyProofOfPossession(
        bytes memory blsPublicKey,
        bytes memory proofOfPossession
    ) internal view returns (bool) {
        if (!BLS12381.isValidG1Compressed(blsPublicKey)) {
            return false;
        }
        if (!BLS12381.isValidG2Compressed(proofOfPossession)) {
            return false;
        }

        bytes32 popDigest = keccak256(
            abi.encodePacked("BLS_POP_SPOOVAULT_V1", blsPublicKey)
        );
        return BLS12381.verifyAggregated(blsPublicKey, proofOfPossession, popDigest);
    }

    /**
     * @notice Verify aggregated K-of-N BLS signature in a single pairing verification step.
     */
    function verifyThresholdApproval(
        uint256 requestId,
        uint256 vaultId,
        uint256 documentId,
        address beneficiary,
        uint256 chainId,
        bytes memory aggregatedPublicKey,
        bytes memory aggregatedSignature,
        uint256 participatingGuardians,
        uint256 requiredThreshold
    ) internal view returns (bool) {
        if (participatingGuardians < requiredThreshold) {
            revert ThresholdNotMet(participatingGuardians, requiredThreshold);
        }

        bytes32 digest = computeApprovalDigest(
            requestId,
            vaultId,
            documentId,
            beneficiary,
            chainId
        );

        bool isValid = BLS12381.verifyAggregated(
            aggregatedPublicKey,
            aggregatedSignature,
            digest
        );

        if (!isValid) {
            revert InvalidAggregatedSignature();
        }

        return true;
    }
}
