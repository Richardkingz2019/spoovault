# upgrade_fixture

Test-only fixture crate. It is a minimal, independently-versioned Soroban
contract used exclusively as the "new version" Wasm blob by the
`upgrade_contract` integration test in `contracts-stellar/src/test.rs`
(imported there via `soroban_sdk::contractimport!`).

It is never deployed and is not part of the SpooVault product surface. CI
builds it to `wasm32-unknown-unknown` before running the main crate's test
suite, since `contractimport!` reads the compiled `.wasm` file at compile
time. See `.github/workflows/fuzzing.yml` (`soroban-fuzz` job) and
`.github/workflows/coverage.yml` (`soroban-coverage` job).

To build it locally:

```sh
cd contracts-stellar/upgrade_fixture
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```
