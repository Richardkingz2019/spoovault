//! Groth16 ZK-SNARK verifier for the BeneficiaryAccessProof circuit.
//!
//! Verifies that a beneficiary holds a valid vault key share without
//! revealing the secret. Tracks spent nullifiers in persistent storage
//! to prevent double-claiming.
//!
//! Implements the standard Groth16 pairing check on the BN254 curve
//! using scalar-multiplication and pairing operations exposed through
//! the Soroban host environment (`env.crypto()` helpers).
//!
//! # Verification equation (EIP-197 notation)
//! e(A, B) · e(vk_x, γ) · e(C, δ) = e(α, β)
//!
//! where vk_x is the linear combination of IC points with public inputs.

use soroban_sdk::{panic_with_error, Bytes, BytesN, Env, Symbol, Val, Vec};

// ── BN254 prime field modulus ──────────────────────────────────────────────
const P: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x30;
    bytes[1] = 0x64;
    bytes[2] = 0x4e;
    bytes[3] = 0x72;
    bytes[4] = 0xe1;
    bytes[5] = 0x31;
    bytes[6] = 0xa0;
    bytes[7] = 0x29;
    bytes[8] = 0xb8;
    bytes[9] = 0x50;
    bytes[10] = 0x45;
    bytes[11] = 0xb6;
    bytes[12] = 0x81;
    bytes[13] = 0x81;
    bytes[14] = 0x58;
    bytes[15] = 0x5a;
    bytes[16] = 0x97;
    bytes[17] = 0x85;
    bytes[18] = 0x6a;
    bytes[19] = 0x16;
    bytes[20] = 0xc9;
    bytes[21] = 0xd6;
    bytes[22] = 0x07;
    bytes[23] = 0xf4;
    bytes[24] = 0xd4;
    bytes[25] = 0x12;
    bytes[26] = 0xcb;
    bytes[27] = 0x0a;
    bytes[28] = 0xec;
    bytes[29] = 0xb6;
    bytes[30] = 0x0f;
    bytes[31] = 0x30;
    bytes
};

// ── G1 point: (x, y) each 32 bytes ────────────────────────────────────────
pub type G1Point = [u8; 64];

// ── G2 point: Fp2 (x.re, x.im, y.re, y.im) each 32 bytes ─────────────────
pub type G2Point = [u8; 128];

// ── Proof: (a: G1, b: G2, c: G1) ──────────────────────────────────────────
pub struct Groth16Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

// ── Verifying key ──────────────────────────────────────────────────────────
pub struct VerifyingKey {
    pub alpha: G1Point,
    pub beta: G2Point,
    pub gamma: G2Point,
    pub delta: G2Point,
    pub ic: Vec<G1Point>,
}

// ── Public signals ─────────────────────────────────────────────────────────
pub struct PublicSignals {
    pub vault_root_commitment: [u8; 32],
    pub nullifier_hash: [u8; 32],
    pub document_id: [u8; 32],
}

// ── Contract errors ────────────────────────────────────────────────────────
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ZkVerifierError {
    InvalidProof = 1,
    NullifierAlreadySpent = 2,
    InvalidInputCount = 3,
    InvalidCurvePoint = 4,
}

// ── Data keys for persistent storage ───────────────────────────────────────
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZkVerifierDataKey {
    /// Nullifier hash → bool (spent)
    Nullifier([u8; 32]),
}

/// Verifies a Groth16 proof and marks the nullifier as spent.
///
/// Returns `Ok(true)` on success. Double-spends return `Err(NullifierAlreadySpent)`.
/// Malformed proofs return `Err(InvalidProof)`.
pub fn verify_proof(
    env: &Env,
    proof: &Groth16Proof,
    signals: &PublicSignals,
    vk: &VerifyingKey,
) -> Result<bool, ZkVerifierError> {
    // ── Nullifier replay protection ──────────────────────────────────────────
    if is_nullifier_spent(env, &signals.nullifier_hash) {
        return Err(ZkVerifierError::NullifierAlreadySpent);
    }

    // ── Validate input count ─────────────────────────────────────────────────
    if vk.ic.len() != 4 {
        // 3 public inputs + 1 constant = 4 IC points
        return Err(ZkVerifierError::InvalidInputCount);
    }

    // ── Build IC linear combination ──────────────────────────────────────────
    // vk_x = IC[0] + vaultRootCommitment · IC[1] + nullifierHash · IC[2] + documentId · IC[3]
    let ic_x = compute_ic_linear_combination(env, vk, signals)?;

    // ── Execute pairing check ────────────────────────────────────────────────
    // e(A, B) · e(vk_x, γ) · e(C, δ) = e(α, β)
    let pairing_result = execute_pairing_check(env, proof, &ic_x, vk)?;

    if !pairing_result {
        return Err(ZkVerifierError::InvalidProof);
    }

    // ── Mark nullifier as spent ──────────────────────────────────────────────
    mark_nullifier_spent(env, &signals.nullifier_hash);

    env.events().publish(
        (
            Symbol::new(env, "proof_verified"),
            Bytes::from_array(env, &signals.nullifier_hash),
            Bytes::from_array(env, &signals.document_id),
        ),
        (),
    );

    Ok(true)
}

/// Computes the IC linear combination: IC[0] + Σ s_i · IC[i+1]
fn compute_ic_linear_combination(
    env: &Env,
    vk: &VerifyingKey,
    signals: &PublicSignals,
) -> Result<G1Point, ZkVerifierError> {
    let mut acc = vk.ic.get(0).unwrap_or_else(|| {
        let mut zero = [0u8; 64];
        zero
    });

    // IC[1] · vaultRootCommitment
    acc = g1_add(env, &acc, &g1_scalar_mul(env, &vk.ic.get(1).unwrap(), &signals.vault_root_commitment))?;

    // IC[2] · nullifierHash
    acc = g1_add(env, &acc, &g1_scalar_mul(env, &vk.ic.get(2).unwrap(), &signals.nullifier_hash))?;

    // IC[3] · documentId
    acc = g1_add(env, &acc, &g1_scalar_mul(env, &vk.ic.get(3).unwrap(), &signals.document_id))?;

    Ok(acc)
}

/// Executes the Groth16 pairing check:
///
///     e(A, B) · e(−α, β) · e(vk_x, γ) · e(C, δ) ?= 1
///
/// Returns true if the pairing product equals the identity element.
fn execute_pairing_check(
    env: &Env,
    proof: &Groth16Proof,
    vk_x: &G1Point,
    vk: &VerifyingKey,
) -> Result<bool, ZkVerifierError> {
    // For the pairing check, we build a list of (G1, G2) pairs and call
    // the host's pairing function. On Soroban, the `env.crypto()`
    // interface exposes bn254 operations when the host supports them.
    //
    // The negation on G1 is done by negating the y-coordinate mod P:
    //   −(x, y) = (x, P − y)
    //
    // Pairs:
    //   1.  (A, B)       — positive proof pair
    //   2.  (−α,  β)     — α negated on G1
    //   3.  (vk_x, γ)    — IC linear combination
    //   4.  (C, δ)       — positive proof pair
    //
    // EIP-197 requires G2 points in Fp2 swapping the order: (x_im, x_re, y_im, y_re)

    let neg_alpha = negate_g1(vk.alpha);

    // Build pairing input: 4 pairs × (G1 + G2) bytes
    let mut input = Bytes::new(env);
    input.extend_from_array(&proof.a);
    input.extend_from_array(&proof.b);
    input.extend_from_array(&neg_alpha);
    input.extend_from_array(&vk.beta);
    input.extend_from_array(vk_x);
    input.extend_from_array(&vk.gamma);
    input.extend_from_array(&proof.c);
    input.extend_from_array(&vk.delta);

    // Call the bn254 pairing precompile equivalent via Soroban host
    match env.crypto().bn254_pairing_check(&input) {
        Ok(result) => Ok(result),
        Err(_) => Err(ZkVerifierError::InvalidProof),
    }
}

/// G1 point addition using the bn254 add precompile via host.
fn g1_add(env: &Env, p1: &G1Point, p2: &G1Point) -> Result<G1Point, ZkVerifierError> {
    if is_g1_zero(p1) {
        return Ok(*p2);
    }
    if is_g1_zero(p2) {
        return Ok(*p1);
    }

    let mut input = Bytes::new(env);
    input.extend_from_array(p1);
    input.extend_from_array(p2);

    match env.crypto().bn254_g1_add(&input) {
        Ok(result) => {
            let mut out = [0u8; 64];
            // Soroban returns 64 bytes (x || y) for G1 add result
            let result_bytes = result.to_array();
            let len = result_bytes.len().min(64);
            out[..len].copy_from_slice(&result_bytes[..len]);
            Ok(out)
        }
        Err(_) => Err(ZkVerifierError::InvalidCurvePoint),
    }
}

/// G1 scalar multiplication using the bn254 mul precompile via host.
fn g1_scalar_mul(env: &Env, p: &G1Point, scalar: &[u8; 32]) -> G1Point {
    if is_scalar_zero(scalar) || is_g1_zero(p) {
        return [0u8; 64];
    }

    let mut input = Bytes::new(env);
    input.extend_from_array(p);
    input.extend_from_array(scalar);

    match env.crypto().bn254_g1_mul(&input) {
        Ok(result) => {
            let mut out = [0u8; 64];
            let result_bytes = result.to_array();
            let len = result_bytes.len().min(64);
            out[..len].copy_from_slice(&result_bytes[..len]);
            out
        }
        Err(_) => [0u8; 64],
    }
}

/// Negate a G1 point: −(x, y) = (x, P − y)
fn negate_g1(point: G1Point) -> G1Point {
    let mut neg = point;
    // Negate y-coordinate (bytes 32..64) mod P
    let y_bytes = &point[32..64];
    let mut y_val = [0u8; 32];
    y_val.copy_from_slice(y_bytes);

    // Compute P - y (big-endian)
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let p_byte = P[i] as u16;
        let y_byte = y_val[i] as u16 + borrow;
        if p_byte < y_byte {
            result[i] = (p_byte + 256 - y_byte) as u8;
            borrow = 1;
        } else {
            result[i] = (p_byte - y_byte) as u8;
            borrow = 0;
        }
    }

    neg[32..64].copy_from_slice(&result);
    neg
}

fn is_g1_zero(p: &G1Point) -> bool {
    p.iter().all(|&b| b == 0)
}

fn is_scalar_zero(s: &[u8; 32]) -> bool {
    s.iter().all(|&b| b == 0)
}

// ── Nullifier state management ─────────────────────────────────────────────

/// Returns true if the nullifier has already been consumed.
pub fn is_nullifier_spent(env: &Env, nullifier: &[u8; 32]) -> bool {
    let key = ZkVerifierDataKey::Nullifier(*nullifier);
    env.storage()
        .persistent()
        .get(&to_storage_bytes(env, &key))
        .unwrap_or(false)
}

/// Marks a nullifier as spent in persistent storage.
fn mark_nullifier_spent(env: &Env, nullifier: &[u8; 32]) {
    let key = ZkVerifierDataKey::Nullifier(*nullifier);
    env.storage()
        .persistent()
        .set(&to_storage_bytes(env, &key), &true);
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn to_storage_bytes(env: &Env, key: &ZkVerifierDataKey) -> Bytes {
    match key {
        ZkVerifierDataKey::Nullifier(hash) => {
            let mut out = Bytes::new(env);
            out.push_back(0u8); // discriminant
            out.extend_from_array(hash);
            out
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Env as _;

    #[test]
    fn test_nullifier_defaults_to_unspent() {
        let env = Env::default();
        let nullifier: [u8; 32] = [1u8; 32];
        assert!(!is_nullifier_spent(&env, &nullifier));
    }

    #[test]
    fn test_mark_nullifier_as_spent() {
        let env = Env::default();
        let nullifier: [u8; 32] = [2u8; 32];
        mark_nullifier_spent(&env, &nullifier);
        assert!(is_nullifier_spent(&env, &nullifier));
    }

    #[test]
    fn test_is_g1_zero() {
        let zero: G1Point = [0u8; 64];
        assert!(is_g1_zero(&zero));

        let mut non_zero: G1Point = [0u8; 64];
        non_zero[0] = 1;
        assert!(!is_g1_zero(&non_zero));
    }

    #[test]
    fn test_is_scalar_zero() {
        assert!(is_scalar_zero(&[0u8; 32]));
        let mut non_zero = [0u8; 32];
        non_zero[0] = 1;
        assert!(!is_scalar_zero(&non_zero));
    }

    #[test]
    fn test_negate_g1_preserves_x() {
        let mut point: G1Point = [0u8; 64];
        point[0] = 0x01; // x = 1
        point[32] = 0x01; // y = 1
        let neg = negate_g1(point);
        // x should be unchanged
        assert_eq!(neg[0], point[0]);
        // y should NOT equal original y (negated)
        assert_ne!(neg[32..64], point[32..64]);
    }

    #[test]
    fn test_double_nullifier_spend_is_detected() {
        let env = Env::default();
        let nullifier: [u8; 32] = [3u8; 32];

        // First spend
        assert!(!is_nullifier_spent(&env, &nullifier));
        mark_nullifier_spent(&env, &nullifier);
        assert!(is_nullifier_spent(&env, &nullifier));

        // Second check
        assert!(is_nullifier_spent(&env, &nullifier));
    }
}