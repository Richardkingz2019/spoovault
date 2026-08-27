#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, BytesN, Env, Symbol};

const NULLIFIER: Symbol = symbol_short!("nullifier");

@contract
pub struct ZkAccessVerifier;

@contractimpl
impl ZkAccessVerifier {
    pub fn verify_and_consume_nullifier(
        env: Env,
        _proof: BytesN<64>,
        _vault_root: BytesN<32>,
        nullifier_hash: BytesN<32>,
        _document_id: BytesN<32>,
    ) -> bool {
        // Prevent double-claiming
        if env.storage().persistent().has(&(NULLIFIER, nullifier_hash.clone())) {
            panic!("NullifierAlreadyUsed");
        }

        // Record nullifier to prevent replay attacks
        env.storage().persistent().set(&(NULLIFIER, nullifier_hash), &true);
        true
    }

    pub fn is_nullifier_used(env: Env, nullifier_hash: BytesN<32>) -> bool {
        env.storage().persistent().has(&(NULLIFIER, nullifier_hash))
    }
}
