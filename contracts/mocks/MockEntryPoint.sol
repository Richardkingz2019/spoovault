// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IEntryPoint.sol";
import "../interfaces/IPaymaster.sol";

/**
 * @title MockEntryPoint
 * @notice Realistic mock of the canonical EIP-4337 EntryPoint for unit testing Paymasters
 *         and Smart Accounts without external bundler infrastructure.
 */
contract MockEntryPoint is IEntryPoint {
    mapping(address => uint256) private _deposits;
    mapping(address => DepositInfo) private _stakes;

    event Deposited(address indexed account, uint256 totalDeposit);
    event Withdrawn(address indexed account, address withdrawAddress, uint256 amount);
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost
    );

    receive() external payable {
        depositTo(msg.sender);
    }

    function depositTo(address account) public payable override {
        _deposits[account] += msg.value;
        emit Deposited(account, _deposits[account]);
    }

    function balanceOf(address account) external view override returns (uint256) {
        return _deposits[account];
    }

    function getDepositInfo(address account) external view override returns (DepositInfo memory) {
        return _stakes[account];
    }

    function addStake(uint32 unstakeDelaySec) external payable override {
        DepositInfo storage info = _stakes[msg.sender];
        info.stake += uint112(msg.value);
        info.unstakeDelaySec = unstakeDelaySec;
        info.staked = true;
    }

    function unlockStake() external override {
        DepositInfo storage info = _stakes[msg.sender];
        require(info.staked, "not staked");
        info.staked = false;
        info.withdrawTime = uint48(block.timestamp + info.unstakeDelaySec);
    }

    function withdrawStake(address payable withdrawAddress) external override {
        DepositInfo storage info = _stakes[msg.sender];
        require(!info.staked, "must unlock first");
        require(block.timestamp >= info.withdrawTime, "stake locked");
        uint256 amount = info.stake;
        info.stake = 0;
        (bool s, ) = withdrawAddress.call{value: amount}("");
        require(s, "stake transfer failed");
    }

    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external override {
        require(_deposits[msg.sender] >= withdrawAmount, "insufficient deposit");
        _deposits[msg.sender] -= withdrawAmount;
        (bool s, ) = withdrawAddress.call{value: withdrawAmount}("");
        require(s, "withdraw transfer failed");
        emit Withdrawn(msg.sender, withdrawAddress, withdrawAmount);
    }

    function getUserOpHash(UserOperation calldata userOp) public view override returns (bytes32) {
        bytes32 packedHash = keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.callGasLimit,
                userOp.verificationGasLimit,
                userOp.preVerificationGas,
                userOp.maxFeePerGas,
                userOp.maxPriorityFeePerGas,
                keccak256(userOp.paymasterAndData)
            )
        );
        return keccak256(abi.encode(packedHash, address(this), block.chainid));
    }

    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external override {
        for (uint256 i = 0; i < ops.length; i++) {
            UserOperation calldata op = ops[i];
            bytes32 opHash = getUserOpHash(op);

            uint256 maxCost = (op.verificationGasLimit + op.callGasLimit + op.preVerificationGas) * op.maxFeePerGas;
            if (maxCost == 0) {
                maxCost = 100000 * 1 gwei;
            }

            address paymasterAddress = address(0);
            bytes memory paymasterContext;

            if (op.paymasterAndData.length >= 20) {
                paymasterAddress = address(bytes20(op.paymasterAndData[:20]));
                require(_deposits[paymasterAddress] >= maxCost, "AA31 paymaster deposit too low");

                uint256 validationData;
                (paymasterContext, validationData) = IPaymaster(paymasterAddress).validatePaymasterUserOp(
                    op,
                    opHash,
                    maxCost
                );
                require(validationData == 0, "AA33 reverted in validatePaymasterUserOp");
            }

            // Execute the operation
            (bool success, ) = op.sender.call{gas: op.callGasLimit > 0 ? op.callGasLimit : 500000}(op.callData);

            // Calculate actual gas cost (simulate realistic consumption <= maxCost)
            uint256 actualGasCost = maxCost / 2;
            if (actualGasCost == 0) {
                actualGasCost = 50000;
            }

            if (paymasterAddress != address(0)) {
                require(_deposits[paymasterAddress] >= actualGasCost, "AA31 deposit drained");
                _deposits[paymasterAddress] -= actualGasCost;

                if (beneficiary != address(0)) {
                    (bool bSuccess, ) = beneficiary.call{value: actualGasCost}("");
                    require(bSuccess, "beneficiary fee payment failed");
                }

                IPaymaster(paymasterAddress).postOp(
                    success ? IPaymaster.PostOpMode.opSucceeded : IPaymaster.PostOpMode.opReverted,
                    paymasterContext,
                    actualGasCost
                );
            }

            emit UserOperationEvent(opHash, op.sender, paymasterAddress, op.nonce, success, actualGasCost);
        }
    }
}
