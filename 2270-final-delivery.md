# 2270 final delivery — issue #883 (MemoryStore clone-contract proof, remove-unused-Clone)

- Verify branch: `work/883-memorystore-verify` (issue-numbered; the brief's
  `codex/b-…` name violates the repo branch policy, so the compliant name was used).
- Base: `bd30a87b` (`origin/work/883-memorystore-clone` tip; `origin/main` seen at
  `1e27bfba` during setup).
- Prior verify commit (harness hardening): `21532024` (pushed to
  `origin/work/883-memorystore-verify`).
- **Final local SHA: `650a09a3`** (`21532024..650a09a3`, committed, **not pushed —
  root owns push/PR/merge**).
- Worktree: `C:/Development/Rust/projects/eliot-swarm/B-fx2270` (detached at base,
  branched in-worktree; the PR branch `work/883-memorystore-clone` was never checked out).
- Files changed in this slice (1): only
  `crates/storage/eliot-store-memory/tests/memory_store_clone.rs`
  (+400/−89 vs `21532024`; vs PR base the slice is test-file-only).
  `src/lib.rs` was **not modified in any way** (A1780 ownership fence); no hunk needed.
- Fixture `tests/data/memory_store_clone_cases.json`: unchanged (ids/kinds/params stable).

## What this slice completes

Concrete 14-case binding reconciliation: live #883 requires one substantive
marked test per actual numbered obligation (removal branch). The prior slice had
14 `// WORK_UNIT_CASE` wrappers but drove an unrelated fixture matrix, leaving
live 7 (state/cost denominator) inside the 883/9 check, live 8 (historical
poison) inside the 883/11 check, and live 14 (shared-state/diff guard) inside
the 883/13 check. This slice aligns each marker to its live obligation without
weakening any assertion and without inventing a fork API (removal disposition
only; historical replicas stay explicitly non-production and supplemental):

| live | marked test | substantive obligation proof (all execute, none ignored) |
|---|---|---|
| 1 | `clone_contract_01_…` | `check_workspace_denominator`: reads every universe file, asserts construction-/comment-only use, no `MemoryStore`+Clone adjacency, no `store.clone()`, no `MemoryStore: Clone` bound |
| 2 | `clone_contract_02_…` | `check_generic_clone_exclusion`: no `store.clone()` receiver and no `MemoryStore` clone path in any universe file (other types' `.clone()` excluded by receiver) + fixture sweep |
| 3 | `clone_contract_03_…` | `check_production_calls`: every in-package `MemoryStore::` item ∈ {new, snapshot, register_manifest, apply_transaction, record_erasure_intent, apply_erasure, erasure_outcomes, erased_subjects, projections, outbox} + fixture sweep |
| 4 | `clone_contract_04_…` | `check_package_test_calls`: every test `MemoryStore::` item ∈ {new, default, snapshot}; no fork names outside guard strings + fixture sweep |
| 5 | `clone_contract_05_…` | `check_clone_bounds`: pins the executable `compile_fail needs_clone::<MemoryStore>()` doctest + no colon-bound in sources + fixture sweep |
| 6 | `clone_contract_06_…` | historical deep-copy replica proves independent-not-shared both ways; current construction-plus-snapshot isolation L→R |
| 7 | `clone_contract_07_…` | `check_state_field_denominator`: exact 17-field `MemoryState` + 8-field `MemorySnapshot` source blocks; removal makes no copy-cost claim and none is measured + fixture sweep |
| 8 | `clone_contract_08_…` | `check_historical_poison`: poisoned `into_inner().clone()` replica succeeds silently (the removed behavior); source proves no `into_inner` remains and poison maps to `Unavailable` + fixture sweep |
| 9 | `clone_contract_09_…` | `check_removal_absence`: `impl Clone` absent, no derive, no named fork; real consumer uses only `::new()` with no clone (compile proved by `--no-run` gate + doctest) + fixture sweep |
| 10 | `clone_contract_10_…` | neither `Clone` nor `independent_fork`/`fork_clone`/`try_clone`, no Arc/global (source guards) + fixture sweep |
| 11 | `clone_contract_11_…` | `check_snapshot_retained`: fresh-empty, determinism, one write → 1 receipt + 1 projection + 1 outbox + 1 named op, all without Clone + fixture sweep |
| 12 | `clone_contract_12_…` | `check_bidirectional_isolation`: equal start, left-write diverges/right-stable, right-write diverges, plus no-shared-state guard + fixture sweep |
| 13 | `clone_contract_13_…` | no clone/fork escape (`check_absent_clone`) + typed poison contract (`check_typed_failure` incl. historical demo and source guards; execution proof in inline `poisoned_store_refuses_snapshot_and_reports_unavailable`) + fixture sweep |
| 14 | `clone_contract_14_…` | doc contract names snapshot-as-path + absent-Clone + no-shared-state guards; diff scope = this one test file (`git diff --stat`), `apply_transaction` untouched + fixture sweep |

Full-matrix sweep `memory_store_clone_contract_883` retained (15 tests total in target).

## Exact source-consumer inventory (tracked grep `MemoryStore` over `crates/` + `bins/`; CBM unavailable, governor absent — direct grep fallback, disclosed)

- `crates/storage/eliot-store-memory/src/lib.rs` — definition (`pub struct MemoryStore`,
  `#[derive(Debug)]`, no `Clone`); `MemoryStore::new` (incl. inline tests),
  `::snapshot`, doc-only `::record_erasure_intent` / `::apply_erasure` / `::new`.
- `crates/storage/eliot-store-memory/src/epistemic_tests.rs` — `MemoryStore::new()` only.
- `crates/storage/eliot-store-memory/tests/memory_store_clone.rs` — harness:
  `::new()` / `::default()` / `.snapshot()` only.
- `crates/storage/eliot-backup/tests/restore_contract.rs:2107` —
  `eliot_store_memory::MemoryStore::new()` + `apply_transaction`; no clone.
- `crates/storage/eliot-store-surreal-adapter/src/apply/read_boundary.rs:733` —
  doc-comment mention only.
- Zero `store.clone()`, zero `impl Clone for MemoryStore`, zero `MemoryStore: Clone`
  in code (guard-string self-mentions excluded by documented convention and would
  be E0117 if real).

## Source-bound historical fixture identity

`HistoricalDeepCopyStore` in `tests/memory_store_clone.rs`: test-only
`Mutex<BTreeMap<String, String>>` replica of the inspected-base historical
`MemoryStore` Clone (issue cites inspected base `aed215f…`): lock + deep copy
into a new mutex; poisoned branch `poisoned.into_inner().clone()` (deref-clone
of the guard) recovering silently into a valid store. Demonstrates (a) the
removed independent-not-shared semantics and (b) the removed silent poisoned
copy. Never production, never a substitute fork; no `Arc`, no globals.

## Gates (isolated target `B-fx2270/target-isolated`, offline; scoped per steering)

- `cargo test --offline -p eliot-store-memory --test memory_store_clone` → **15 passed,
  0 failed** (at `650a09a3`).
- `cargo clippy --offline -p eliot-store-memory --test memory_store_clone --no-deps -- -D warnings` → **clean, exit 0** (at `650a09a3`).
- `cargo fmt --package eliot-store-memory -- --check`, filtered to touched file →
  **zero diffs in `memory_store_clone.rs`**; `git diff --check` clean.
- Retained honestly from prior slice (code unchanged since): full package
  38 (lib) + 2 (disposition) + 1 (doctest `compile_fail`) green at `21532024`;
  `cargo clippy --offline -p eliot-store-memory --lib --no-deps -- -D warnings` clean;
  dependent `cargo test --no-run --offline -p eliot-backup` green (real consumer compiles).
- Honest baseline disclosures (pre-existing on PR base, untouched, not re-looped):
  package `fmt --check` drifts in `src/lib.rs` import layout and
  `tests/disposition.rs`; `clippy --all-targets -D warnings` reports exactly the
  10 pre-existing `src/lib.rs` inline-test lints (`expect`/`expect_err`/`format!`/
  needless-question-mark, lines 2204–3710); zero lints in owned/new test code.

## Docs / protocol receipts (complete raw paths)

- Raw receipt: `C:/Development/Rust/projects/eliot-swarm/B-fx2270/.eliot/docs-read-receipt.json`
- Raw bundle: `C:/Development/Rust/projects/eliot-swarm/B-fx2270/.eliot/docs-read-bundle.md`
- Command: `python scripts/docs_read.py read --path crates/storage/eliot-store-memory/src/lib.rs --path crates/storage/eliot-store-memory/tests/memory_store_clone.rs --path crates/storage/eliot-store-memory/tests/data/memory_store_clone_cases.json --topic "memory store clone contract"`.
- Route `sha256:419bcccd252b1c4ffb9af213280f32b495005a01f2d742d3ca5e5f0ec1df0cb7`,
  read `sha256:ff3bf4f35d0d114b7afce2fec7b9d06afc92c103122f49ad20fc3cd6c92ed070`,
  pair `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`,
  50 required items, bundle SHA `4af006c32c41709a8bca29cdfe4b2f3f6fe29ec75440eb4e4a007dc3832affb0`
  (rehashed after work — matches receipt). Every required fragment read; governing
  I05-08, I02-06, I18-27 read directly (router returns decision fragments, not shard contents).
- Conformance: I5.4 (no transition change), I5.8 (snapshot stays the value projection),
  I2.6 (poison → typed `Unavailable`, `thiserror` discipline intact), I18.27 (no oracle
  weakened; historical fixture labeled non-production), I0.5 (no support claim promoted).
- Sibling seam #1934 (ACP persistence trait): not needed by this proof — nothing requested.

## Remaining gaps (for root/merge call)

- `650a09a3` is local-only on `work/883-memorystore-verify` (ahead 1 of origin); root to push/fast-forward.
- `bins/eliot-kernel` lists `eliot-store-memory` in its manifest (reverse-dep found during
  inventory); it was not compiled here (scoped gates per steering) — controller's
  integration lane covers it. No API change makes breakage impossible (test-file-only diff),
  but the compile fact is unproven for that crate in this lane.
- Pre-existing package fmt drift + 10 lib-test clippy hits remain for the owning lanes.
