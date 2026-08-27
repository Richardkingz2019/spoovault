// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAxelarGateway {
    function callContract(string calldata destinationChain, string calldata destinationAddress, bytes calldata payload) external;
}

contract SpooVaultAxelarBridge {
    IAxelarGateway public immutable gateway;
    mapping(bytes32 => bool) public processedMessages;

    event CrossChainApprovalSent(bytes32 indexed vaultGID, address indexed guardian, uint8 approvalType, string destinationChain);
    event CrossChainApprovalReceived(bytes32 indexed vaultGID, address indexed guardian, uint8 approvalType);

    error MessageAlreadyProcessed();

    constructor(address _gateway) {
        gateway = IAxelarGateway(_gateway);
    }

    function sendApproval(
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes32 vaultGID,
        address guardian,
        uint8 approvalType
    ) external {
        bytes memory payload = abi.encode(vaultGID, guardian, approvalType, block.timestamp);
        gateway.callContract(destinationChain, destinationAddress, payload);

        emit CrossChainApprovalSent(vaultGID, guardian, approvalType, destinationChain);
    }

    function executeApproval(bytes32 vaultGID, address guardian, uint8 approvalType, bytes32 messageHash) external {
        if (processedMessages[messageHash]) {
            revert MessageAlreadyProcessed();
        }

        processedMessages[messageHash] = true;
        emit CrossChainApprovalReceived(vaultGID, guardian, approvalType);
    }
}
