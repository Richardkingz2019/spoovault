// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/ISpooVault.sol";

/**
 * @title ThirdPartyConsumer
 * @dev Sample external DApp / DAO contract demonstrating programmatic interaction with SpooVault
 * via standard ERC-165 introspection and the ISpooVault interface without hardcoded ABIs.
 */
contract ThirdPartyConsumer {
    ISpooVault public immutable spooVault;

    error SpooVaultInterfaceNotSupported();
    error DocumentAccessDenied(uint8 status);

    constructor(address spooVaultAddress) {
        require(spooVaultAddress != address(0), "Invalid address");
        ISpooVault vault = ISpooVault(spooVaultAddress);

        // ERC-165 check
        if (!vault.supportsInterface(type(ISpooVault).interfaceId)) {
            revert SpooVaultInterfaceNotSupported();
        }

        spooVault = vault;
    }

    /**
     * @notice Check whether SpooVault advertises ISpooVault support via ERC-165.
     */
    function isSpooVaultSupported() external view returns (bool) {
        return spooVault.supportsInterface(type(ISpooVault).interfaceId);
    }

    /**
     * @notice Query document access status code for a given user.
     */
    function queryAccessStatus(uint256 documentId, address user) external view returns (uint8) {
        return spooVault.checkAccess(documentId, user);
    }

    /**
     * @notice Execute an action conditional on valid document access.
     */
    function performAuthorizedAction(uint256 documentId, address user) external view returns (bool) {
        uint8 status = spooVault.checkAccess(documentId, user);
        if (status != uint8(ISpooVault.AccessCheckResult.GRANTED)) {
            revert DocumentAccessDenied(status);
        }
        return true;
    }
}
