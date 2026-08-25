// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";

contract SpooVault {
    mapping(bytes32 => euint256) private encryptedAccumulators;

    event ShareSubmitted(bytes32 indexed vaultId, address indexed guardian);

    /// @notice Submits an encrypted secret share and homomorphically aggregates it
    function submitEncryptedShare(bytes32 vaultId, externalCiphertext encryptedShare, bytes calldata proof) external {
        // Verify input proof for the encrypted ciphertext
        euint256 share = TFHE.asEuint256(encryptedShare, proof);

        // Initialize accumulator if not set, otherwise homomorphically add the share
        if (!TFHE.isInitialized(encryptedAccumulators[vaultId])) {
            encryptedAccumulators[vaultId] = share;
        } else {
            encryptedAccumulators[vaultId] = TFHE.add(encryptedAccumulators[vaultId], share);
        }

        emit ShareSubmitted(vaultId, msg.sender);
    }

    /// @notice Returns the aggregated ciphertext for authorized client decryption
    function getEncryptedAccumulator(bytes32 vaultId) external view returns (euint256) {
        return encryptedAccumulators[vaultId];
    }
}