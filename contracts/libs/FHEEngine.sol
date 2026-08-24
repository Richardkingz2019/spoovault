// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FHEEngine
 * @dev Fully Homomorphic Encryption library implementing additive homomorphism
 *      and polynomial threshold aggregation over 256-bit ciphertext structures (`euint256`).
 */
library FHEEngine {
    // 256-bit prime modulus q (secp256k1 field prime): 2^256 - 2^32 - 977
    uint256 internal constant FHE_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    error InvalidCiphertextLength();
    error CiphertextDimensionMismatch();
    error EmptyCiphertextArray();
    error InsufficientSharesForThreshold();

    /**
     * @notice Modular exponentiation (base^exp mod m)
     */
    function modPow(
        uint256 base,
        uint256 exp,
        uint256 m
    ) internal pure returns (uint256) {
        uint256 res = 1;
        uint256 b = base % m;
        uint256 e = exp;
        while (e > 0) {
            if (e % 2 == 1) {
                res = mulmod(res, b, m);
            }
            b = mulmod(b, b, m);
            e /= 2;
        }
        return res;
    }

    /**
     * @notice Modular inverse using Fermat's Little Theorem
     */
    function modInverse(uint256 a, uint256 m) internal pure returns (uint256) {
        require(a % m != 0, "FHEEngine: division by zero");
        return modPow(a % m, m - 2, m);
    }

    /**
     * @notice Homomorphic Addition of two ciphertexts: ct1 (+) ct2 = Enc(m1 + m2 mod q)
     */
    function fheAdd(
        bytes memory ct1,
        bytes memory ct2
    ) internal pure returns (bytes memory) {
        if (ct1.length == 0) return ct2;
        if (ct2.length == 0) return ct1;
        if (ct1.length < 96 || ct2.length < 96) revert InvalidCiphertextLength();
        if (ct1.length != ct2.length) revert CiphertextDimensionMismatch();

        uint256 dim;
        assembly {
            dim := mload(add(ct1, 0x20))
        }

        uint256 expectedLen = (dim + 2) * 32;
        if (ct1.length != expectedLen) revert InvalidCiphertextLength();

        bytes memory result = new bytes(expectedLen);
        assembly {
            mstore(add(result, 0x20), dim)
        }

        for (uint256 i = 0; i < dim; i++) {
            uint256 a1;
            uint256 a2;
            uint256 offset = 0x40 + (i * 0x20);
            assembly {
                a1 := mload(add(ct1, offset))
                a2 := mload(add(ct2, offset))
            }
            uint256 sumA = addmod(a1, a2, FHE_PRIME);
            assembly {
                mstore(add(result, offset), sumA)
            }
        }

        uint256 bOffset = 0x40 + (dim * 0x20);
        uint256 b1;
        uint256 b2;
        assembly {
            b1 := mload(add(ct1, bOffset))
            b2 := mload(add(ct2, bOffset))
        }
        uint256 sumB = addmod(b1, b2, FHE_PRIME);
        assembly {
            mstore(add(result, bOffset), sumB)
        }

        return result;
    }

    /**
     * @notice Homomorphic Scalar Multiplication: scalar (*) ct = Enc(scalar * m mod q)
     */
    function fheMulScalar(
        bytes memory ct,
        uint256 scalar
    ) internal pure returns (bytes memory) {
        if (ct.length < 96) revert InvalidCiphertextLength();

        uint256 dim;
        assembly {
            dim := mload(add(ct, 0x20))
        }

        uint256 expectedLen = (dim + 2) * 32;
        if (ct.length != expectedLen) revert InvalidCiphertextLength();

        bytes memory result = new bytes(expectedLen);
        assembly {
            mstore(add(result, 0x20), dim)
        }

        uint256 s = scalar % FHE_PRIME;

        for (uint256 i = 0; i < dim; i++) {
            uint256 a;
            uint256 offset = 0x40 + (i * 0x20);
            assembly {
                a := mload(add(ct, offset))
            }
            uint256 mulA = mulmod(a, s, FHE_PRIME);
            assembly {
                mstore(add(result, offset), mulA)
            }
        }

        uint256 bOffset = 0x40 + (dim * 0x20);
        uint256 b;
        assembly {
            b := mload(add(ct, bOffset))
        }
        uint256 mulB = mulmod(b, s, FHE_PRIME);
        assembly {
            mstore(add(result, bOffset), mulB)
        }

        return result;
    }

    /**
     * @notice Compute Lagrange basis coefficients lambda_i at x = 0 for given evaluation points
     */
    function computeLagrangeCoefficients(
        uint256[] memory indices
    ) internal pure returns (uint256[] memory) {
        uint256 k = indices.length;
        uint256[] memory lambdas = new uint256[](k);

        for (uint256 i = 0; i < k; i++) {
            uint256 num = 1;
            uint256 den = 1;
            uint256 xi = indices[i] % FHE_PRIME;

            for (uint256 j = 0; j < k; j++) {
                if (i == j) continue;
                uint256 xj = indices[j] % FHE_PRIME;
                num = mulmod(num, xj, FHE_PRIME);

                uint256 diff;
                if (xj >= xi) {
                    diff = xj - xi;
                } else {
                    diff = FHE_PRIME - (xi - xj);
                }
                den = mulmod(den, diff, FHE_PRIME);
            }

            uint256 denInv = modInverse(den, FHE_PRIME);
            lambdas[i] = mulmod(num, denInv, FHE_PRIME);
        }

        return lambdas;
    }

    /**
     * @notice Homomorphically aggregates threshold Shamir secret shares:
     *         c_agg = Sum_{i=1}^k lambda_i (*) c_i
     */
    function aggregateThresholdShares(
        bytes[] memory ciphertexts,
        uint256[] memory indices,
        uint256 threshold
    ) internal pure returns (bytes memory) {
        if (ciphertexts.length < threshold || indices.length < threshold) {
            revert InsufficientSharesForThreshold();
        }

        uint256[] memory activeIndices = new uint256[](threshold);
        for (uint256 i = 0; i < threshold; i++) {
            activeIndices[i] = indices[i];
        }

        uint256[] memory lambdas = computeLagrangeCoefficients(activeIndices);

        bytes memory acc = fheMulScalar(ciphertexts[0], lambdas[0]);
        for (uint256 i = 1; i < threshold; i++) {
            bytes memory term = fheMulScalar(ciphertexts[i], lambdas[i]);
            acc = fheAdd(acc, term);
        }

        return acc;
    }

    /**
     * @notice Homomorphically aggregates additive secret shares:
     *         c_agg = c_1 (+) c_2 (+) ... (+) c_k
     */
    function aggregateAdditiveShares(
        bytes[] memory ciphertexts
    ) internal pure returns (bytes memory) {
        if (ciphertexts.length == 0) revert EmptyCiphertextArray();

        bytes memory acc = ciphertexts[0];
        for (uint256 i = 1; i < ciphertexts.length; i++) {
            acc = fheAdd(acc, ciphertexts[i]);
        }

        return acc;
    }
}
