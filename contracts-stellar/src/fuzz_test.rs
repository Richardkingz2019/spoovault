//! Property-based random state-sequence fuzzing for the Soroban vault
//! contract (issue #150). `test.rs` covers known edge cases with hand-picked
//! scenarios; this module instead throws long, arbitrary sequences of
//! contract calls at a fresh contract instance and checks, after every
//! single call, that a small set of core invariants never break no matter
//! what order (or how malformed) the sequence is.
//!
//! `proptest` (a `std`-based crate) needs `std` to be linked into this
//! otherwise `#![no_std]` crate; `extern crate std;` here does exactly that
//! without affecting the non-test build.
extern crate std;

use super::*;
use proptest::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::vec;
use std::vec::Vec as StdVec;

/// Fixed actor roles used throughout a single fuzzing run. Keeping the pool
/// small and fixed (rather than generating fresh addresses per action) means
/// the fuzzer's random choices concentrate call sequences onto a handful of
/// identities, which is what actually exercises re-entrant-looking
/// call/approve/revoke interleavings instead of spreading everything across
/// addresses that only ever appear once.
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

/// One fuzzed step. Indices select an actor or a previously-created
/// id modulo however many exist so far; out-of-range/invalid combinations
/// are common and expected to be rejected by the contract (via `try_*`)
/// rather than accepted, exactly like a real adversarial caller.
#[derive(Clone, Debug)]
enum Action {
    AcceptInvite {
        guardian: u8,
    },
    AddDocument {
        uploader: u8,
    },
    RequestAccess {
        requester: u8,
        doc_idx: usize,
    },
    ApproveAccess {
        approver: u8,
        req_idx: usize,
        with_share: bool,
    },
    RevokeAccess {
        guardian: u8,
        doc_idx: usize,
        target: u8,
    },
    MintToken {
        minter: u8,
        to: u8,
    },
    BurnToken {
        owner: u8,
        token_idx: usize,
    },
    TransferToken {
        from: u8,
        to: u8,
        token_idx: usize,
    },
}

fn arb_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        any::<u8>().prop_map(|guardian| Action::AcceptInvite { guardian }),
        any::<u8>().prop_map(|uploader| Action::AddDocument { uploader }),
        (any::<u8>(), any::<usize>())
            .prop_map(|(requester, doc_idx)| Action::RequestAccess { requester, doc_idx }),
        (any::<u8>(), any::<usize>(), any::<bool>()).prop_map(|(approver, req_idx, with_share)| {
            Action::ApproveAccess {
                approver,
                req_idx,
                with_share,
            }
        }),
        (any::<u8>(), any::<usize>(), any::<u8>()).prop_map(|(guardian, doc_idx, target)| {
            Action::RevokeAccess {
                guardian,
                doc_idx,
                target,
            }
        }),
        (any::<u8>(), any::<u8>()).prop_map(|(minter, to)| Action::MintToken { minter, to }),
        (any::<u8>(), any::<usize>())
            .prop_map(|(owner, token_idx)| Action::BurnToken { owner, token_idx }),
        (any::<u8>(), any::<u8>(), any::<usize>()).prop_map(|(from, to, token_idx)| {
            Action::TransferToken {
                from,
                to,
                token_idx,
            }
        }),
    ]
}

fn setup<'a>() -> (Env, SpooVaultStellarClient<'a>) {
    // A property test creates and drops thousands of `Env`s across its
    // cases; committing a `test_snapshots/*.N.json` regression file per drop
    // (soroban-sdk's default for `Env::default()`) would flood the repo, so
    // snapshot capture is disabled here.
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let contract_id = env.register_contract(None, SpooVaultStellar);
    let client = SpooVaultStellarClient::new(&env, &contract_id);
    env.mock_all_auths();
    // A single `Env`'s budget is shared cumulatively across every call made
    // against it, unlike on a real network where each transaction gets a
    // fresh budget. A 60-step fuzzed sequence run against one `Env` easily
    // exceeds the default budget with a hard-to-catch host panic
    // (`HostError: Error(Budget, ExceededLimit)` deep in soroban-env-host's
    // auth bookkeeping, which `try_*` calls can't intercept) that has
    // nothing to do with the invariants this suite is actually checking.
    env.budget().reset_unlimited();
    (env, client)
}

/// Reads a document's `HasAccess` flag directly from contract storage.
/// There is no public getter for this (by design — it's an internal grant
/// flag, not part of the read API), so this reaches into the contract's own
/// storage the same way `test.rs` inspects `MockAccessRegistry`'s state:
/// via `env.as_contract`, valid because this module compiles into the same
/// crate and can see `DataKey`.
fn has_access(env: &Env, contract_id: &Address, document_id: u64, user: &Address) -> bool {
    env.as_contract(contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::HasAccess(document_id, user.clone()))
            .unwrap_or(false)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Replays a random sequence of contract calls against a freshly
    /// bootstrapped vault (one active guardian invite pending, one seeded
    /// document) and checks three invariants after every single step:
    ///
    ///  1. `approval_threshold_never_exceeded` — no access request ever
    ///     accumulates more approvals than the vault's configured
    ///     threshold (mirrors `echidna_approval_threshold_never_exceeded`).
    ///  2. `unauthorized_user_cannot_access` — an address that was never
    ///     made a guardian and never became the requester of an approved
    ///     request never ends up with document access (mirrors
    ///     `echidna_unauthorized_user_cannot_access`).
    ///  3. `token_balance_sum_matches_shadow_count` — the sum of every
    ///     actor's token `balance()` always matches the number of mints
    ///     minus burns tracked by this harness (mirrors
    ///     `echidna_vault_balance_sum_equals_total_supply`; note the
    ///     contract's `TokenCount` is a monotonically increasing id
    ///     counter, not a live supply, since `burn_access_token` never
    ///     decrements it — the actual current supply is the sum of
    ///     per-owner balances).
    #[test]
    fn random_state_sequence_never_violates_invariants(actions in prop::collection::vec(arb_action(), 1..60)) {
        let (env, client) = setup();
        let contract_id = client.address.clone();

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

        let mut document_ids: StdVec<u64> = StdVec::new();
        let mut request_ids: StdVec<u64> = StdVec::new();
        let mut token_ids: StdVec<u64> = StdVec::new();
        let mut approved_requesters: StdVec<Address> = StdVec::new();
        let mut minted = 0u64;
        let mut burned = 0u64;

        let seed_doc = client.add_document(
            &actors.creator,
            &vault_id,
            &String::from_str(&env, "meta"),
            &String::from_str(&env, "QmSeed"),
            &AccessLevel::ReadWrite,
            &ReleaseCondition::Anytime,
            &Vec::new(&env),
            &Vec::new(&env),
        );
        document_ids.push(seed_doc);

        for action in actions {
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
                        &Vec::new(&env),
                        &Vec::new(&env),
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
                        if client.try_approve_access(approver, &req_id, &share).is_ok() {
                            if let Some(req) = client.get_access_request(&req_id) {
                                if req.status == RequestStatus::Approved {
                                    approved_requesters.push(req.requester.clone());
                                }
                            }
                        }
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

            // ---- Invariant 1: approval_threshold_never_exceeded ----
            for &req_id in &request_ids {
                if let Some(req) = client.get_access_request(&req_id) {
                    if let Some(doc) = client.get_document(&req.document_id) {
                        if let Some(vault) = client.get_vault(&doc.vault_id) {
                            prop_assert!(
                                req.approved_by.len() <= vault.approval_threshold,
                                "request {} accumulated {} approvals against a threshold of {}",
                                req_id,
                                req.approved_by.len(),
                                vault.approval_threshold
                            );
                        }
                    }
                }
            }

            // ---- Invariant 2: unauthorized_user_cannot_access ----
            // `outsider` is never passed as a vault guardian, never accepts
            // an invite, and only ever appears here as a requester/target;
            // it must never end up with document access unless one of its
            // own requests was actually approved.
            for &doc_id in &document_ids {
                if has_access(&env, &contract_id, doc_id, &actors.outsider) {
                    let via_approval = approved_requesters.contains(&actors.outsider);
                    let is_uploader = client
                        .get_document(&doc_id)
                        .map(|d| d.uploaded_by == actors.outsider)
                        .unwrap_or(false);
                    prop_assert!(
                        via_approval || is_uploader,
                        "outsider gained access to document {} without an approved request or upload",
                        doc_id
                    );
                }
            }

            // ---- Invariant 3: token_balance_sum_matches_shadow_count ----
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
            prop_assert_eq!(
                actual_supply, expected_supply,
                "sum of actor balances {} diverged from shadow-tracked supply {}",
                actual_supply, expected_supply
            );
        }
    }
}
