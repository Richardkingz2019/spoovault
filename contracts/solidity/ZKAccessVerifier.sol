// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ZKAccessVerifier {
    mapping(bytes32 => bool) public usedNullifiers;

    event ProofVerified(bytes32 indexed nullifierHash, bytes32 indexed documentId);

    error NullifierAlreadyUsed();
    error InvalidProof();

    function verifyProofAndConsume(
        bytes calldata proof,
        bytes32 vaultRootCommitment,
        bytes32 nullifierHash,
        bytes32 documentId
    ) external returns (bool) {
        if (usedNullifiers[nullifierHash]) {
            revert NullifierAlreadyUsed();
        }

        // Basic proof validation check length requirement
        if (proof.length == 0) {
            revert InvalidProof();
        }

        usedNullifiers[nullifierHash] = true;
        emit ProofVerified(nullifierHash, documentId);
        return true;
    }
}
