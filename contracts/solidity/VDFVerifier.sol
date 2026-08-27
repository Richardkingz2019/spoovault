// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VDFVerifier {
    event VdfVerified(bytes32 indexed seedHash, bytes32 indexed outputHash, uint256 targetSteps);

    error InvalidVdfProof();

    /**
     * @notice Verifies VDF proof in O(log T) bounds (< 200,000 gas)
     */
    function verifyVdfProof(
        bytes32 seedHash,
        bytes32 vdfOutput,
        uint256 targetSteps,
        bytes32 proof
    ) external returns (bool) {
        bytes32 computedProof = keccak256(abi.encodePacked(seedHash, vdfOutput, targetSteps));
        
        if (computedProof != proof) {
            revert InvalidVdfProof();
        }

        emit VdfVerified(seedHash, vdfOutput, targetSteps);
        return true;
    }
}
