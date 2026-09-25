# PR #2270 suggested body (issue #883) — root to publish on merge

## Owning issue / scope

Implements #883 (`[P-MEMORYSTORE-CLONE] Remove or make explicit the deep-copy
MemoryStore clone contract`), removal disposition per the owner's execution
decision (no required public independent fork). Owner:
`crates/storage/eliot-store-memory`. Base `origin/main` (seen `1e27bfba`);
PR branch `work/883-memorystore-clone` @ `bd30a87b`; verify branch
`work/883-memorystore-verify` @ `21532024` (harness hardening) + `650a09a3`
(live 1..14 binding reconciliation, local — root to push).

## Changed causal property and path scope

- `MemoryStore` carries no public deep-copy `Clone` contract: no
  `impl Clone for MemoryStore`, no derived `Clone`, no explicitly-named fork
  (`independent_fork`/`fork_clone`/`try_clone`), no `Arc`/shared/global state.
  (Absence already held on base; this PR proves it and removes the unused contract.)
- Independent models use `MemoryStore::new` construction plus the
  `MemoryStore::snapshot` value projection; poisoned locks stay typed
  `StoreError::Unavailable` with no `into_inner` recovery anywhere.
- Test-file-only verify diff (`tests/memory_store_clone.rs`): 14
  `// WORK_UNIT_CASE: 883/1..14` marked tests, each executing its live
  obligation — workspace denominator (1), generic-clone exclusion (2),
  production-call inventory (3), test-call inventory (4), Clone-bound accounting
  with pinned `compile_fail` proof (5), historical independent-copy fixture (6),
  17+8 state-field denominator with no cost claims (7), historical poison fixture
  with no-silent-recopy proof (8), Clone-absent + consumer-compile (9), no
  fork/Arc/global (10), snapshot retention incl. write→receipt/projection/outbox
  (11), bidirectional isolation (12), no-escape + poison contract (13), doc/diff
  guard (14) — plus the retained full-matrix sweep (15 tests in target).
- No Store API, transaction, receipt, recovery, persistence, concurrency-model,
  manifest, lockfile, workflow, or normative-doc change.

## Docs route / read receipt and attestation

- Route `sha256:419bcccd252b1c4ffb9af213280f32b495005a01f2d742d3ca5e5f0ec1df0cb7`,
  read `sha256:ff3bf4f35d0d114b7afce2fec7b9d06afc92c103122f49ad20fc3cd6c92ed070`,
  pair `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`,
  50 required items, bundle SHA
  `4af006c32c41709a8bca29cdfe4b2f3f6fe29ec75440eb4e4a007dc3832affb0`
  (raw: `B-fx2270/.eliot/docs-read-receipt.json`, `B-fx2270/.eliot/docs-read-bundle.md`).
  All required fragments read; governing I05-08, I02-06, I18-27 read directly.
  Worker attests every required item was opened and read before mutation.
- Consumer inventory (tracked grep): definition in `store-memory/src/lib.rs`;
  construction-only uses in `src/epistemic_tests.rs`, the harness, and
  `eliot-backup/tests/restore_contract.rs:2107`; comment-only mention in the
  surreal adapter. Zero `store.clone()` / `impl Clone` / `MemoryStore: Clone`.

## Proof executed and proof ceiling

- `cargo test --offline -p eliot-store-memory --test memory_store_clone`: **15 passed**.
- Full package retained: lib 38 + disposition 2 + doctest (`compile_fail`) 1, green.
- `cargo clippy --offline -p eliot-store-memory --test memory_store_clone --no-deps -- -D warnings`: **clean**; `--lib` clean. `--all-targets` shows only the
  10 pre-existing `src/lib.rs` inline-test lints in untouched regions.
- `cargo test --no-run --offline -p eliot-backup`: green (real consumer compiles).
- fmt: touched test file clean; `git diff --check` clean.
- Ceiling: package + consumer-compile proof only. No production-reachability,
  performance, shared-store, product, or release claim (`NOT_ACCEPTED / UNVERIFIED`
  unchanged).

## Affected edges / migration / rollback

- No edges changed (test-file-only diff). `bins/eliot-kernel` manifests a dep but
  needs no migration — no API changed; controller lane to compile it.
- Rollback: revert the test file; production code is byte-identical to PR base.
- Residual: package fmt drift + 10 lib-test clippy hits in non-owned regions.
