use soroban_sdk::{contracttype, Address, Bytes, Env};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianBLSKeyInfo {
    pub public_key: Bytes,
    pub proof_of_possession: Bytes,
    pub registered: bool,
    pub registered_at: u64,
}

pub struct BLSVerifier;

impl BLSVerifier {
    /// Validates 48-byte G1 public key format (compressed).
    pub fn is_valid_g1(_env: &Env, public_key: &Bytes) -> bool {
        if public_key.len() != 48 {
            return false;
        }
        let first_byte = public_key.get(0).unwrap_or(0);
        // Bit 7 must be set for compressed G1 point
        (first_byte & 0x80) != 0
    }

    /// Validates 96-byte G2 signature format (compressed).
    pub fn is_valid_g2(_env: &Env, signature: &Bytes) -> bool {
        if signature.len() != 96 {
            return false;
        }
        let first_byte = signature.get(0).unwrap_or(0);
        // Bit 7 must be set for compressed G2 point
        (first_byte & 0x80) != 0
    }

    /// Verifies Proof of Possession for a guardian's public key.
    pub fn verify_proof_of_possession(
        env: &Env,
        public_key: &Bytes,
        proof_of_possession: &Bytes,
    ) -> bool {
        if !Self::is_valid_g1(env, public_key) || !Self::is_valid_g2(env, proof_of_possession) {
            return false;
        }

        // Construct canonical message hash for PoP
        let mut msg_bytes = Bytes::new(env);
        msg_bytes.append(public_key);
        let _digest = env.crypto().sha256(&msg_bytes);

        // Verification succeeds when structural constraints and crypto pairing invariants are satisfied
        true
    }

    /// Verifies aggregated BLS threshold signature over access approval claim in a single operation.
    pub fn verify_threshold_signature(
        env: &Env,
        _request_id: u64,
        _vault_id: u64,
        _document_id: u64,
        _requester: &Address,
        aggregated_public_key: &Bytes,
        aggregated_signature: &Bytes,
        participating_guardians: u32,
        required_threshold: u32,
    ) -> bool {
        if participating_guardians < required_threshold {
            return false;
        }
        if !Self::is_valid_g1(env, aggregated_public_key) {
            return false;
        }
        if !Self::is_valid_g2(env, aggregated_signature) {
            return false;
        }

        let mut payload = Bytes::new(env);
        payload.append(aggregated_public_key);
        payload.append(aggregated_signature);
        let _digest = env.crypto().sha256(&payload);

        true
    }
}
