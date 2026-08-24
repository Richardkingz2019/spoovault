// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ZKAccessVerifier
 * @notice On-chain Groth16 verifier for BeneficiaryAccessProof ZK-SNARKs.
 *
 *         A beneficiary submits a proof, public signals, and the verifying key
 *         constants to prove knowledge of a valid vault key share without
 *         revealing the secret share or their private identity.
 *
 *         Nullifier tracking prevents double-claiming: every (privateKey,
 *         documentId) pair produces a unique nullifier hash that is stored
 *         on first use and rejected on subsequent submissions.
 *
 * @dev    Uses EIP-196/197 precompiled contracts for elliptic-curve pairing
 *         on the BN254 curve (alt_bn128). Gas cost is ≈ 270k for a valid
 *         proof, within typical block limits.
 */
contract ZKAccessVerifier {
    // ── EIP-197 pairing precompile address ──────────────────────────────────
    address internal constant PAIRING_PRECOMPILE = address(0x08);

    // ── Gas stipend for the pairing check (matches EIP-1108) ───────────────
    uint256 internal constant PAIRING_GAS = 34_000 * 6 + 45_000;

    // ── G1 / G2 point encoding sizes (EIP-197) ─────────────────────────────
    uint256 internal constant G1_ELEMENT_SIZE = 64;  // 32 B x + 32 B y
    uint256 internal constant G2_ELEMENT_SIZE = 128; // 64 B x + 64 B y

    // ── Prime field modulus for BN254 ──────────────────────────────────────
    uint256 internal constant P =
        21_888_242_871_839_275_222_246_405_745_257_275_088_569_664_541_156_301_506_178_335_204;

    // ── Nullifier tracking ─────────────────────────────────────────────────
    /// @notice Tracks spent nullifiers to prevent double-claiming.
    ///         nullifierHash => true if already consumed.
    mapping(uint256 => bool) public spentNullifiers;

    // ── Events ─────────────────────────────────────────────────────────────
    event ProofVerified(
        uint256 indexed nullifierHash,
        uint256 indexed documentId,
        address indexed submitter
    );
    event NullifierAlreadyUsed(uint256 indexed nullifierHash, uint256 indexed documentId);

    // ── Errors ─────────────────────────────────────────────────────────────
    error InvalidProof();
    error NullifierAlreadySpent(uint256 nullifierHash);
    error InvalidInputCount();
    error NotOnCurve();

    // ── Public API ─────────────────────────────────────────────────────────

    /**
     * @notice Verify a Groth16 proof of access and mark the nullifier as spent.
     * @param a         G1 point of the proof (2 × uint256: x, y)
     * @param b         G2 point of the proof (4 × uint256, Fp2: x[0], x[1], y[0], y[1])
     * @param c         G1 point of the proof (2 × uint256: x, y)
     * @param inputs    Public signals: [vaultRootCommitment, nullifierHash, documentId]
     * @param vkAlpha   G1 point
     * @param vkBeta    G2 point
     * @param vkGamma   G2 point
     * @param vkDelta   G2 point
     * @param vkIC      Array of IC G1 points (length == inputs.length + 1)
     */
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata inputs,
        uint256[2] calldata vkAlpha,
        uint256[2][2] calldata vkBeta,
        uint256[2][2] calldata vkGamma,
        uint256[2][2] calldata vkDelta,
        uint256[2][] calldata vkIC
    ) external returns (bool) {
        // ── Nullifier replay protection ────────────────────────────────────
        uint256 nullifierHash = inputs[1];
        if (spentNullifiers[nullifierHash]) {
            emit NullifierAlreadyUsed(nullifierHash, inputs[2]);
            revert NullifierAlreadySpent(nullifierHash);
        }

        // ── Validate curve membership ──────────────────────────────────────
        if (!_isOnG1(a[0], a[1])) revert NotOnCurve();
        if (!_isOnG1(c[0], c[1])) revert NotOnCurve();

        // ── Verify IC length matches inputs ────────────────────────────────
        if (vkIC.length != inputs.length + 1) revert InvalidInputCount();

        // ── Build IC linear combination: vk_x = vkIC[0] + Σ inputs[i] · vkIC[i+1] ─
        uint256[2] memory vkX = vkIC[0];
        for (uint256 i = 0; i < inputs.length; i++) {
            uint256[2] memory term = _scalarMulG1(vkIC[i + 1], inputs[i]);
            vkX = _addG1(vkX, term);
        }

        // ── Pack the pairing input into a contiguous byte buffer ───────────
        // Groth16 verification equation (EIP notation):
        //   e(A, B) · e(vk_x, γ) · e(C, δ) == e(α, β)
        //
        // Pairing check input order (negated elements marked with −):
        //   e(A₁,  B₂)    — proof pair (positive)
        //   e(α₁,  β₂)    — VK constants (negated → −α, β)
        //   e(vk_x, γ₂)   — IC linear combination (positive)
        //   e(C₁,  δ₂)    — proof pair (positive)
        //
        //   Negation is on the G1 side (y := P - y) for EIP-197 compatibility.
        uint256 inputSize =
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE +   // e(A, B)
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE +   // e(α, β) — α is negated
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE +   // e(vk_x, γ)
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE;    // e(C, δ)

        uint256[] memory pairings = new uint256[](inputSize / 32);
        uint256 offset = 0;

        // Pair 1: e(A, B) — positive
        offset = _writeG1(pairings, offset, a[0], a[1]);
        offset = _writeG2(pairings, offset, b[0][0], b[0][1], b[1][0], b[1][1]);

        // Pair 2: e(−α, β)
        offset = _writeG1(pairings, offset, vkAlpha[0], P - vkAlpha[1]);
        offset = _writeG2(pairings, offset, vkBeta[0][0], vkBeta[0][1], vkBeta[1][0], vkBeta[1][1]);

        // Pair 3: e(vk_x, γ)
        offset = _writeG1(pairings, offset, vkX[0], vkX[1]);
        offset = _writeG2(pairings, offset, vkGamma[0][0], vkGamma[0][1], vkGamma[1][0], vkGamma[1][1]);

        // Pair 4: e(C, δ)
        offset = _writeG1(pairings, offset, c[0], c[1]);
        offset = _writeG2(pairings, offset, vkDelta[0][0], vkDelta[0][1], vkDelta[1][0], vkDelta[1][1]);

        // ── Execute pairing check ──────────────────────────────────────────
        (bool success, bytes memory result) = PAIRING_PRECOMPILE.staticcall{
            gas: PAIRING_GAS
        }(_packPairings(pairings));

        if (!success || result.length != 32 || !_b256ToBool(result)) {
            revert InvalidProof();
        }

        // ── Mark nullifier as spent ────────────────────────────────────────
        spentNullifiers[nullifierHash] = true;

        emit ProofVerified(nullifierHash, inputs[2], msg.sender);
        return true;
    }

    /**
     * @notice View-only verification (does not mark nullifiers).
     *         Useful for pre-flight checks before committing a transaction.
     */
    function verifyProofView(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata inputs,
        uint256[2] calldata vkAlpha,
        uint256[2][2] calldata vkBeta,
        uint256[2][2] calldata vkGamma,
        uint256[2][2] calldata vkDelta,
        uint256[2][] calldata vkIC
    ) external view returns (bool) {
        if (!_isOnG1(a[0], a[1]) || !_isOnG1(c[0], c[1])) return false;
        if (vkIC.length != inputs.length + 1) return false;

        uint256[2] memory vkX = vkIC[0];
        for (uint256 i = 0; i < inputs.length; i++) {
            vkX = _addG1(vkX, _scalarMulG1(vkIC[i + 1], inputs[i]));
        }

        uint256 inputSize =
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE +
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE +
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE +
            G1_ELEMENT_SIZE + G2_ELEMENT_SIZE;

        uint256[] memory pairings = new uint256[](inputSize / 32);
        uint256 offset = 0;

        offset = _writeG1(pairings, offset, a[0], a[1]);
        offset = _writeG2(pairings, offset, b[0][0], b[0][1], b[1][0], b[1][1]);
        offset = _writeG1(pairings, offset, vkAlpha[0], P - vkAlpha[1]);
        offset = _writeG2(pairings, offset, vkBeta[0][0], vkBeta[0][1], vkBeta[1][0], vkBeta[1][1]);
        offset = _writeG1(pairings, offset, vkX[0], vkX[1]);
        offset = _writeG2(pairings, offset, vkGamma[0][0], vkGamma[0][1], vkGamma[1][0], vkGamma[1][1]);
        offset = _writeG1(pairings, offset, c[0], c[1]);
        offset = _writeG2(pairings, offset, vkDelta[0][0], vkDelta[0][1], vkDelta[1][0], vkDelta[1][1]);

        (bool success, bytes memory result) = PAIRING_PRECOMPILE.staticcall(
            _packPairings(pairings)
        );
        return success && result.length == 32 && _b256ToBool(result);
    }

    /**
     * @notice Returns whether a nullifier has already been consumed.
     */
    function isNullifierSpent(uint256 nullifierHash) external view returns (bool) {
        return spentNullifiers[nullifierHash];
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    function _b256ToBool(bytes memory data) internal pure returns (bool) {
        for (uint256 i = 0; i < 31; i++) {
            if (data[i] != 0) return true;
        }
        return uint8(data[31]) != 0;
    }

    function _packPairings(uint256[] memory pairings) internal pure returns (bytes memory) {
        bytes memory packed = new bytes(pairings.length * 32);
        for (uint256 i = 0; i < pairings.length; i++) {
            uint256 value = pairings[i];
            assembly {
                mstore8(add(add(packed, 0x20), mul(i, 32)), byte(31, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 1)), byte(30, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 2)), byte(29, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 3)), byte(28, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 4)), byte(27, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 5)), byte(26, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 6)), byte(25, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 7)), byte(24, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 8)), byte(23, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 9)), byte(22, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 10)), byte(21, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 11)), byte(20, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 12)), byte(19, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 13)), byte(18, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 14)), byte(17, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 15)), byte(16, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 16)), byte(15, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 17)), byte(14, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 18)), byte(13, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 19)), byte(12, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 20)), byte(11, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 21)), byte(10, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 22)), byte(9, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 23)), byte(8, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 24)), byte(7, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 25)), byte(6, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 26)), byte(5, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 27)), byte(4, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 28)), byte(3, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 29)), byte(2, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 30)), byte(1, value))
                mstore8(add(add(packed, 0x20), add(mul(i, 32), 31)), byte(0, value))
            }
        }
        return packed;
    }

    // ── Curve helpers ──────────────────────────────────────────────────────

    function _isOnG1(uint256 x, uint256 y) internal pure returns (bool) {
        if (x == 0 && y == 0) return false;
        if (x >= P || y >= P) return false;
        // y² ≡ x³ + 3 (mod P) for BN254
        uint256 lhs = mulmod(y, y, P);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 3, P);
        return lhs == rhs;
    }

    function _addG1(
        uint256[2] memory p1,
        uint256[2] memory p2
    ) internal view returns (uint256[2] memory r) {
        if (p1[0] == 0 && p1[1] == 0) return p2;
        if (p2[0] == 0 && p2[1] == 0) return p1;

        uint256[4] memory input;
        input[0] = p1[0];
        input[1] = p1[1];
        input[2] = p2[0];
        input[3] = p2[1];

        (bool success, bytes memory output) = address(0x06).staticcall(
            abi.encodePacked(input[0], input[1], input[2], input[3])
        );
        if (!success) {
            r[0] = 0;
            r[1] = 0;
            return r;
        }

        assembly {
            mstore(r, mload(add(output, 32)))
            mstore(add(r, 32), mload(add(output, 64)))
        }
    }

    function _scalarMulG1(
        uint256[2] memory p,
        uint256 s
    ) internal view returns (uint256[2] memory r) {
        if (s == 0) {
            r[0] = 0;
            r[1] = 0;
            return r;
        }

        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;

        (bool success, bytes memory output) = address(0x07).staticcall(
            abi.encodePacked(input[0], input[1], input[2])
        );
        if (!success) {
            r[0] = 0;
            r[1] = 0;
            return r;
        }

        assembly {
            mstore(r, mload(add(output, 32)))
            mstore(add(r, 32), mload(add(output, 64)))
        }
    }

    // ── Encoding helpers ───────────────────────────────────────────────────

    function _writeG1(
        uint256[] memory buf,
        uint256 offset,
        uint256 x,
        uint256 y
    ) internal pure returns (uint256) {
        buf[offset] = x;
        buf[offset + 1] = y;
        return offset + 2;
    }

    function _writeG2(
        uint256[] memory buf,
        uint256 offset,
        uint256 x0,
        uint256 x1,
        uint256 y0,
        uint256 y1
    ) internal pure returns (uint256) {
        buf[offset] = x1;
        buf[offset + 1] = x0;
        buf[offset + 2] = y1;
        buf[offset + 3] = y0;
        return offset + 4;
    }
}