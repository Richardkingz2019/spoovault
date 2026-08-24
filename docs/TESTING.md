# Testing Guide

SpooVault ships two smart contracts — `contracts/SpooVault.sol` (Avalanche EVM)
and `contracts-stellar/` (Stellar Soroban) — plus a React/Vite frontend. This
guide covers the full test pyramid for the contracts, from deterministic unit
tests up through the property-based and fuzz testing added for
[issue #150](https://github.com/) (Soroban & Hardhat differential fuzzing
with Echidna, Medusa, cargo-fuzz, and proptest).

## Quick reference

| Layer | Command | What it covers |
| --- | --- | --- |
| Frontend unit tests | `npm test` | Vitest suite under `src/__tests__/` |
| EVM contract tests | `npm run test:contracts` | Hardhat unit/scenario tests in `test/*.cjs` |
| Soroban contract tests | `npm run test:stellar` | Deterministic scenarios (`src/test.rs`) **and** the property-based fuzz suite (`src/fuzz_test.rs`) |
| Soroban coverage | `npm run test:stellar:coverage` | `cargo-tarpaulin`, see [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Echidna | see below | Property fuzzing of `SpooVault.sol` |
| Medusa | see below | Invariant fuzzing of `SpooVault.sol` (same harness as Echidna) |
| cargo-fuzz | see below | Coverage-guided fuzzing of the Soroban contract's call state machine |
| Smoke check | `npm run test:smoke` | End-to-end build/deploy sanity check |
| E2E | `npx playwright test` (see `e2e/README.md`) | Browser + wallet flows |

All of the above run in CI; see `.github/workflows/ci.yml`,
`.github/workflows/coverage.yml`, and `.github/workflows/fuzzing.yml`.

---

## Why fuzz on top of unit tests

Unit tests encode the edge cases a developer thought to check. The vault
contracts are call-order-sensitive state machines (guardian quorum, request
expiry, token mint/burn/transfer, cross-chain revocation nonces), and the
interesting bugs tend to live in sequences nobody wrote a test for. Fuzzing
throws large numbers of random (Echidna/Medusa/cargo-fuzz) or randomly
*generated but shrinkable* (proptest) call sequences at the contracts and
checks a small set of invariants after every step, so a violation reproduces
as a minimal failing sequence instead of a one-off manual repro.

---

## EVM: Echidna & Medusa (`fuzz/`)

Both fuzzers drive the same harness contract, `fuzz/harness/SpooVaultFuzz.sol`,
which composes an internal `SpooVault` instance (rather than inheriting it) so
the fuzzer can only reach mutating entry points through the harness's
`fuzz_*` wrapper functions. This keeps the harness's own shadow accounting
(minted/burned tokens, approval counts) exact. A second tiny contract,
`FuzzGuardian`, gives the harness a **second** on-chain identity distinct from
`address(this)`, because Solidity's `msg.sender` for a nested call is always
the immediate caller — without it, every wrapped call would appear to
originate from the same address, and approval flows (a requester can never
approve their own request) could never be exercised.

### Properties

| Property | Checks |
| --- | --- |
| `echidna_vault_balance_sum_equals_total_supply` | The harness's shadow mint/burn counter always equals `vault.totalSupply()`. |
| `echidna_minted_tokens_remain_owned` | Every token the harness minted and hasn't burned still has a non-zero owner. |
| `echidna_approval_threshold_never_exceeded` | No access request's approval count (tracked via the harness's `FuzzGuardian`-only approval path) ever exceeds the vault's configured approval threshold. |
| `echidna_unauthorized_user_cannot_access` | A fixed address that is never passed as a guardian, never minted a token, and never a requester (`UNAUTHORIZED_USER`) is never recognized as a guardian and never granted document access. |

Medusa checks the same four properties under the `invariant_*` naming
convention it expects (`invariant_vault_balance_sum_equals_total_supply`,
`invariant_minted_tokens_remain_owned`,
`invariant_approval_threshold_never_exceeded`,
`invariant_unauthorized_user_cannot_access`).

### Running locally

Echidna (via Docker, matching CI):

```sh
npm install --legacy-peer-deps
curl -sL -o solc-static-linux https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux
chmod +x solc-static-linux
docker run --rm -v "$PWD":/src -w /src --entrypoint echidna-test \
  trailofbits/echidna:v2.2.3 \
  /src/fuzz/harness/SpooVaultFuzz.sol --contract SpooVaultFuzz \
  --config /src/fuzz/echidna/config.yaml --test-mode property
```

Medusa (needs Go, crytic-compile, and solc-select):

```sh
go install github.com/crytic/medusa@latest
pip install crytic-compile solc-select && solc-select install 0.8.24 && solc-select use 0.8.24
cd fuzz/medusa && medusa fuzz --config medusa.json
```

### Campaign sizes

`fuzz/echidna/config.yaml` and `fuzz/medusa/medusa.json` run a bounded smoke
campaign (`testLimit: 5000` / `10000`) on every push and pull request so CI
stays fast. `fuzz/echidna/config.full.yaml` and `fuzz/medusa/medusa.full.json`
run the acceptance-criteria target of **100,000 runs with 0 property
invariant violations**; these run on the nightly schedule and via manual
`workflow_dispatch` (`full_campaign: true`) in `.github/workflows/fuzzing.yml`.
Point either tool at the `.full` config to reproduce that campaign locally.

---

## Soroban: proptest & cargo-fuzz (`contracts-stellar/`)

### proptest (`src/fuzz_test.rs`)

`random_state_sequence_never_violates_invariants` generates arbitrary
sequences (1–60 steps) of `Action`s — accept invite, add document, request
access, approve access, revoke access, mint/burn/transfer token — against
actors drawn from a fixed 4-address pool (creator, a second guardian, an
outsider, and a floating actor), replays them through `try_*` client calls so
malformed/out-of-order calls are rejected gracefully instead of panicking,
and checks three invariants after every single step:

1. **Approval threshold never exceeded** — no request's `approved_by` ever
   grows past its vault's `approval_threshold`.
2. **Unauthorized user cannot access** — the fixed `outsider` actor, which is
   never made a guardian, never gains `HasAccess` on any document unless one
   of its own requests was actually approved (checked by reading contract
   storage directly via `env.as_contract`, since there's no public getter for
   this internal flag).
3. **Token balance sum matches shadow count** — the sum of every actor's
   `balance()` always equals shadow-tracked mints minus burns. (Note: the
   contract's `TokenCount` is a monotonically increasing id counter, not a
   live supply — `burn_access_token` never decrements it — so the actual
   current supply has to be computed from per-owner balances instead.)

Because `proptest` shrinks a failing case to a minimal reproducing sequence
and this crate is `#![no_std]`, `fuzz_test.rs` does `extern crate std;`
(proptest is a `std`-based dev-dependency) and disables soroban-sdk's default
`test_snapshots/*.N.json` capture-on-drop, which would otherwise write one
file per generated `Env` — thousands per run.

This runs as part of the normal test suite:

```sh
cd contracts-stellar && cargo test fuzz_test
```

### cargo-fuzz (`fuzz/fuzz_targets/state_machine.rs`)

A `libfuzzer-sys` + `arbitrary` target that mirrors the same state machine
and invariants as the proptest suite (minus the storage-internal
unauthorized-access check, since a cargo-fuzz target is a separate crate with
no access to the parent crate's private `DataKey` type), but is
coverage-guided rather than purely random — libFuzzer mutates inputs toward
new code paths instead of sampling uniformly, which tends to find deeper
sequences than proptest's un-guided generation.

Requires the nightly toolchain and `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd contracts-stellar/fuzz
cargo +nightly fuzz run state_machine -- -max_total_time=60   # quick smoke run
cargo +nightly fuzz run state_machine -- -runs=1000000        # full acceptance campaign
```

CI runs a bounded `-runs=20000` smoke campaign on every push/PR and the full
1,000,000-iteration campaign on the nightly schedule / manual
`workflow_dispatch` (`full_campaign: true`), same as the Echidna/Medusa jobs.
A crash reproducer, if one is found, is written to
`contracts-stellar/fuzz/artifacts/state_machine/`; replay it with:

```sh
cargo +nightly fuzz run state_machine artifacts/state_machine/<crash-file>
```
