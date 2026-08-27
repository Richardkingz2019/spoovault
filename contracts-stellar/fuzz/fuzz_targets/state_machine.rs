#![no_main]

//! cargo-fuzz target for the Soroban vault contract (issue #150).
//!
//! `libfuzzer-sys` turns raw fuzzer bytes into a `Vec<Action>` via
//! `arbitrary`, then this target replays that sequence against a fresh
//! contract instance exactly like `src/fuzz_test.rs`'s proptest suite, using
//! only `try_*` client calls so that a malformed/adversarial sequence is
//! rejected gracefully rather than unwinding the fuzzer process. A genuine
//! Rust panic (an invariant assertion failing, an arithmetic overflow, an
//! out-of-bounds access the contract itself doesn't guard against) is what
//! libFuzzer treats as a crash, which is exactly what this target exists to
//! surface.
//!
//! Run locally with (requires the nightly toolchain and `cargo install
//! cargo-fuzz`):
//! ```sh
//! cargo +nightly fuzz run state_machine -- -max_total_time=60
//! ```
//! The acceptance target for issue #150 is a clean 1,000,000-iteration
//! campaign: `cargo +nightly fuzz run state_machine -- -runs=1000000`.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
// `soroban_sdk::Vec` is intentionally not imported as bare `Vec` here: the
// fuzz_target! macro below needs `std::vec::Vec<Action>` (what `arbitrary`
// generates), and shadowing it with soroban_sdk's own `Vec` type made the
// macro try to derive soroban `Val` conversions for `Action` instead.
use soroban_sdk::{vec, Address, Env, String, Vec as SorobanVec};
use spoovault_stellar::{
    AccessLevel, ReleaseCondition, RequestStatus, SpooVaultStellar, SpooVaultStellarClient,
};

#[derive(Arbitrary, Debug, Clone)]
enum Action {
    AcceptInvite { guardian: u8 },
    AddDocument { uploader: u8 },
    RequestAccess { requester: u8, doc_idx: usize },
    ApproveAccess { approver: u8, req_idx: usize, with_share: bool },
    RevokeAccess { guardian: u8, doc_idx: usize, target: u8 },
    MintToken { minter: u8, to: u8 },
    BurnToken { owner: u8, token_idx: usize },
    TransferToken { from: u8, to: u8, token_idx: usize },
}

struct Actors {
    creator: Address,
    guardian2: Address,
    outsider: Address,
    floating: Address,
}

impl Actors {
    fn get(&self, idx: u8) -> &Address {
        match idx % 4 {
            0 => &self.creator,
            1 => &self.guardian2,
            2 => &self.outsider,
            _ => &self.floating,
        }
    }
}

fuzz_target!(|actions: std::vec::Vec<Action>| {
    run(actions);
});

fn run(actions: std::vec::Vec<Action>) {
    // Disabling snapshot capture matters here too: a corpus run replays
    // this target thousands of times per second, and soroban-sdk's default
    // `Env::default()` would otherwise write a `test_snapshots/*.N.json`
    // file to disk on every single `Env` drop.
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);
    env.mock_all_auths();
    // See src/fuzz_test.rs: a single Env's budget is cumulative across every
    // call made against it, so a long sequence can hit a hard-to-catch host
    // panic (budget exceeded) unrelated to the invariants below.
    env.budget().reset_unlimited();

    let actors = Actors {
        creator: Address::generate(&env),
        guardian2: Address::generate(&env),
        outsider: Address::generate(&env),
        floating: Address::generate(&env),
    };

    let name = String::from_str(&env, "Fuzz Vault");
    let desc = String::from_str(&env, "fuzz");
    let guardians = vec![&env, actors.guardian2.clone()];
    let vault_id = client.create_vault(&actors.creator, &name, &desc, &guardians, &1);

    let mut document_ids: std::vec::Vec<u64> = std::vec::Vec::new();
    let mut request_ids: std::vec::Vec<u64> = std::vec::Vec::new();
    let mut token_ids: std::vec::Vec<u64> = std::vec::Vec::new();
    let mut minted = 0u64;
    let mut burned = 0u64;

    let seed_doc = client.add_document(
        &actors.creator,
        &vault_id,
        &String::from_str(&env, "meta"),
        &String::from_str(&env, "QmSeed"),
        &AccessLevel::ReadWrite,
        &ReleaseCondition::Anytime,
        &SorobanVec::new(&env),
        &SorobanVec::new(&env),
    );
    document_ids.push(seed_doc);

    for action in actions.into_iter().take(64) {
        match action {
            Action::AcceptInvite { guardian } => {
                let g = actors.get(guardian);
                let _ = client.try_accept_guardian_invite(g, &vault_id);
            }
            Action::AddDocument { uploader } => {
                let uploader = actors.get(uploader);
                if let Ok(Ok(doc_id)) = client.try_add_document(
                    uploader,
                    &vault_id,
                    &String::from_str(&env, "meta"),
                    &String::from_str(&env, "QmFuzz"),
                    &AccessLevel::ReadWrite,
                    &ReleaseCondition::Anytime,
                    &SorobanVec::new(&env),
                    &SorobanVec::new(&env),
                ) {
                    document_ids.push(doc_id);
                }
            }
            Action::RequestAccess { requester, doc_idx } => {
                if !document_ids.is_empty() {
                    let doc_id = document_ids[doc_idx % document_ids.len()];
                    let requester = actors.get(requester);
                    if let Ok(Ok(req_id)) = client.try_request_access(requester, &doc_id) {
                        request_ids.push(req_id);
                    }
                }
            }
            Action::ApproveAccess { approver, req_idx, with_share } => {
                if !request_ids.is_empty() {
                    let req_id = request_ids[req_idx % request_ids.len()];
                    let approver = actors.get(approver);
                    let share = if with_share {
                        Some(String::from_str(&env, "share"))
                    } else {
                        None
                    };
                    let _ = client.try_approve_access(approver, &req_id, &share);
                }
            }
            Action::RevokeAccess { guardian, doc_idx, target } => {
                if !document_ids.is_empty() {
                    let doc_id = document_ids[doc_idx % document_ids.len()];
                    let guardian = actors.get(guardian);
                    let target = actors.get(target);
                    let _ = client.try_revoke_access(guardian, &doc_id, target);
                }
            }
            Action::MintToken { minter, to } => {
                let minter = actors.get(minter);
                let to = actors.get(to);
                if let Ok(Ok(token_id)) = client.try_mint_access_token(
                    minter,
                    &vault_id,
                    to,
                    &String::from_str(&env, "uri"),
                ) {
                    token_ids.push(token_id);
                    minted += 1;
                }
            }
            Action::BurnToken { owner, token_idx } => {
                if !token_ids.is_empty() {
                    let token_id = token_ids[token_idx % token_ids.len()];
                    let owner = actors.get(owner);
                    if client.try_burn_access_token(owner, &token_id).is_ok() {
                        burned += 1;
                    }
                }
            }
            Action::TransferToken { from, to, token_idx } => {
                if !token_ids.is_empty() {
                    let token_id = token_ids[token_idx % token_ids.len()];
                    let from = actors.get(from);
                    let to = actors.get(to);
                    let _ = client.try_transfer(from, to, &token_id);
                }
            }
        }

        // Same quorum invariant as the proptest suite: no request ever
        // accumulates more approvals than its vault's threshold.
        for &req_id in &request_ids {
            if let Some(req) = client.get_access_request(&req_id) {
                if let Some(doc) = client.get_document(&req.document_id) {
                    if let Some(vault) = client.get_vault(&doc.vault_id) {
                        assert!(
                            (req.approved_by.len() as u32) <= vault.approval_threshold,
                            "request {} accumulated {} approvals against a threshold of {}",
                            req_id,
                            req.approved_by.len(),
                            vault.approval_threshold
                        );
                        if req.status == RequestStatus::Approved {
                            debug_assert!(req.approved_by.len() as u32 >= vault.approval_threshold);
                        }
                    }
                }
            }
        }

        // Same supply invariant as the proptest suite: the sum of every
        // actor's balance always matches shadow-tracked mints minus burns.
        let expected_supply = minted - burned;
        let actual_supply: u64 = [
            &actors.creator,
            &actors.guardian2,
            &actors.outsider,
            &actors.floating,
        ]
        .iter()
        .map(|a| client.balance(a) as u64)
        .sum();
        assert_eq!(
            actual_supply, expected_supply,
            "sum of actor balances {} diverged from shadow-tracked supply {}",
            actual_supply, expected_supply
        );
    }
}
