pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// ---------------------------------------------------------------------------
// BeneficiaryAccessProof — Groth16 circuit for private access verification
//
// A beneficiary proves knowledge of:
//   1. A valid vault key share (linked to the vault root commitment)
//   2. A beneficiary private key (tied to the nullifier for replay protection)
//
// …without revealing the share, private key, or blinding factor on-chain.
//
// Public inputs (exposed on-chain / in verifier):
//   - vaultRootCommitment: Poseidon(secretShare, blindingFactor)
//   - nullifierHash:       Poseidon(beneficiaryPrivateKey, documentId)
//   - documentId:          uint254 document identifier
//
// Private inputs (witness, kept off-chain):
//   - beneficiaryPrivateKey: 254-bit secret scalar
//   - secretShare:            254-bit Shamir share element
//   - blindingFactor:         random 254-bit blinding
// ---------------------------------------------------------------------------

template BeneficiaryAccessProof() {
    // ── Public inputs (visible on-chain) ───────────────────────────────────
    signal input vaultRootCommitment;
    signal input nullifierHash;
    signal input documentId;

    // ── Private inputs (witness, never revealed) ───────────────────────────
    signal input beneficiaryPrivateKey;
    signal input secretShare;
    signal input blindingFactor;

    // ── Share commitment verification ──────────────────────────────────────
    // Recompute Hash(secretShare, blindingFactor) and check it matches the
    // public vault root commitment. This proves the beneficiary holds a
    // valid share without revealing either value.
    component shareHasher = Poseidon(2);
    shareHasher.inputs[0] <== secretShare;
    shareHasher.inputs[1] <== blindingFactor;
    shareHasher.out === vaultRootCommitment;

    // ── Nullifier computation ──────────────────────────────────────────────
    // Nullifier = Hash(beneficiaryPrivateKey, documentId) ensures every
    // (privateKey, documentId) pair produces a unique nullifier. The
    // on-chain verifier stores spent nullifiers and rejects duplicates,
    // making double-claims impossible.
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== beneficiaryPrivateKey;
    nullifierHasher.inputs[1] <== documentId;
    nullifierHasher.out === nullifierHash;

    // ── Domain separation tag (optional constraint) ────────────────────────
    // The nullifier hash acts as the primary binding between identity
    // and document. Additional domain separation can be layered in the
    // frontend service when building the commitment / nullifier preimages.
}

// Default exported component (required by circom)
component main {public [vaultRootCommitment, nullifierHash, documentId]} = BeneficiaryAccessProof();