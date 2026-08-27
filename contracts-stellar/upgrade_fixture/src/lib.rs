#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

/// Stand-in "new contract version" used only by the `upgrade_contract`
/// integration test in `contracts-stellar/src/test.rs`. Its Wasm is
/// uploaded via `env.deployer().upload_contract_wasm` and swapped onto the
/// main `SpooVaultStellar` contract's ID, and the test confirms the swap
/// took effect by observing that a client built against *this* contract's
/// interface now works against that same contract ID (e.g. `version()`
/// changes from the main contract's `1` to this contract's `2`).
#[contract]
pub struct SpooVaultStellarUpgradeFixture;

#[contractimpl]
impl SpooVaultStellarUpgradeFixture {
    pub fn version(_env: Env) -> u32 {
        2
    }

    /// Stands in for a genuinely new capability shipped in the upgrade.
    pub fn new_feature(_env: Env) -> u32 {
        1_010_101
    }
}
