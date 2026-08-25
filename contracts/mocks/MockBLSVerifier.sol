// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../libs/BLSVerifier.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title MockBLSVerifier
 * @notice Benchmark and test helper for comparing multi-guardian ECDSA approvals vs aggregated BLS approvals.
 */
contract MockBLSVerifier {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    event BenchmarkCompleted(string method, uint256 guardianCount, uint256 gasUsed);

    /**
     * @notice Simulates K sequential ECDSA guardian signature verifications.
     */
    function verifyECDSABatch(
        bytes32 messageHash,
        address[] calldata guardians,
        bytes[] calldata signatures
    ) external returns (bool) {
        uint256 startGas = gasleft();
        require(guardians.length == signatures.length, "Length mismatch");
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();

        for (uint256 i = 0; i < guardians.length; i++) {
            address recovered = ethSignedHash.recover(signatures[i]);
            require(recovered == guardians[i], "Invalid ECDSA signature");
        }

        uint256 gasUsed = startGas - gasleft();
        emit BenchmarkCompleted("ECDSA_BATCH", guardians.length, gasUsed);
        return true;
    }

    /**
     * @notice Verifies K-of-N aggregated BLS signature in 1 single pairing check.
     */
    function verifyBLSAggregated(
        uint256 requestId,
        uint256 vaultId,
        uint256 documentId,
        address beneficiary,
        uint256 chainId,
        bytes calldata aggregatedPublicKey,
        bytes calldata aggregatedSignature,
        uint256 guardianCount,
        uint256 threshold
    ) external returns (bool) {
        uint256 startGas = gasleft();

        bool success = BLSVerifier.verifyThresholdApproval(
            requestId,
            vaultId,
            documentId,
            beneficiary,
            chainId,
            aggregatedPublicKey,
            aggregatedSignature,
            guardianCount,
            threshold
        );

        uint256 gasUsed = startGas - gasleft();
        emit BenchmarkCompleted("BLS_AGGREGATED", guardianCount, gasUsed);
        return success;
    }
}
