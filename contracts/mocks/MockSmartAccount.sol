// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../interfaces/IEntryPoint.sol";

/**
 * @title MockSmartAccount
 * @notice Minimal ERC-4337 smart contract account representing a guardian with 0 AVAX balance.
 */
contract MockSmartAccount {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    address public owner;
    IEntryPoint public immutable entryPoint;

    event Executed(address indexed target, uint256 value, bytes data);

    modifier onlyEntryPointOrOwner() {
        require(msg.sender == address(entryPoint) || msg.sender == owner, "account: unauthorized");
        _;
    }

    constructor(IEntryPoint _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        owner = _owner;
    }

    receive() external payable {}

    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external onlyEntryPointOrOwner returns (bytes memory result) {
        bool success;
        (success, result) = dest.call{value: value}(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        emit Executed(dest, value, func);
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        require(msg.sender == address(entryPoint), "account: not entrypoint");

        bytes32 ethHash = userOpHash.toEthSignedMessageHash();
        address recovered = ethHash.recover(userOp.signature);
        if (recovered != owner) {
            return 1; // signature failure
        }

        if (missingAccountFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            (success);
        }

        return 0; // success
    }
}
