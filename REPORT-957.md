# REPORT-957 — ORS restore journal port (lane MGR-B, E2)

- Issue: #957 `[B-BACKUP-JOURNAL] Persist restore intents and receipts in the existing ORS owner`
- Branch: `work/957-ors-restore-journal` from `origin/main @ cac04ddd`
- Donor: `origin/codex/checkpoint-961-963-m2-20260923 @ 59255f3b`,
  file content from commit `0a630677` ("port E journal + Host prep +
  directory-identity seam (#957/#958)"); ported **only the #957 files**,
  byte-identical. Host preparation (`bins/eliot-host`), the
  `eliot-platform-windows` seam, and later checkpoint commits
  (`e2105e41` #1751 lease census, `53ecace4` introduction scan) were
  deliberately **not** ported (out of #957 exclusive scope).
- Worktree: `C:\Development\Rust\projects\eliot-swarm\MGR-B-957`
  (disjoint from E1; `CARGO_TARGET_DIR=...\eliot-swarm\targets\MGR-B`).

## Краткое резюме (Russian)

Перенесён долговечный журнал восстановления ORS (intents + results,
три версионированные таблицы, exact-predecessor compare-and-append,
привязка операции/предшественника) и его регистрация в ORS.
Все 16 тестов `WORK_UNIT_CASE: 957/1..16` впервые **выполнены**:
16 passed, 0 failed. Второй базы данных, импорта `eliot-backup`,
in-memory/no-op журнала нет. Хост-подготовка (#958) и шов
`platform-windows` не переносились — это чужая область.

## Changed (exclusive #957 scope only)

- NEW `crates/kernel/eliot-ors/src/restore_journal.rs` (228 lines):
  owner-neutral records, `RESTORE_JOURNAL_RECORD_SCHEMA`,
  `JournalPredecessor`, exact load/compare_and_swap bindings.
- NEW `crates/kernel/eliot-ors/src/store/restore_journal.rs` (593 lines):
  tables `ors_restore_journal_intents/results/meta_v1` + idempotent schema
  marker inside the existing `RedbRecoveryStore`; atomic single-write-txn
  intent+result/index; unknown-commit readback reconciliation; prune
  retaining unresolved intents; bounded pages/diagnostics.
- `crates/kernel/eliot-ors/src/lib.rs` (+7): `mod` + `pub use` registration.
- `crates/kernel/eliot-ors/src/store.rs` (+3): `#[path] mod` registration.
- NEW `crates/kernel/eliot-ors/tests/restore_journal.rs` (16 cases,
  `// WORK_UNIT_CASE: 957/1..16`, real temp `.redb` files).
- NEW `crates/kernel/eliot-ors/tests/data/restore-journal/*.json` (2 fixtures,
  paths frozen).

## Gate (touched crate only, `CARGO_TARGET_DIR` above)

- `cargo fmt --package eliot-ors -- --check`: package-level FAIL is
  **pre-existing drift** on main (store.rs use-block/regions byte-identical
  to HEAD; versioned_artifact.rs untouched by this lane). All #957 new
  files and both registration hunks are fmt-clean. `cargo fmt` (rewrite)
  deliberately NOT run: it would create out-of-scope diffs.
- `cargo check --locked -p eliot-ors --all-targets`: exit 0.
- `cargo clippy --locked -p eliot-ors --all-targets --no-deps -- -D warnings`:
  FAIL is **pre-existing** (`tests/doctor_redb.rs`, `src/tests.rs:40-42`,
  `src/store.rs:8598+` test region, `src/versioned_artifact.rs:864` — none
  in this diff). Scoped proof: `--lib` exit 0; `--test restore_journal`
  exit 0.
- `git diff --check`: exit 0 (no whitespace errors).
- `cargo test --locked -p eliot-ors --test restore_journal`: **16 passed,
  0 failed** (first execution evidence; donor lane never executed them).

## Doc conformance

- Route receipt `sha256:32328c…50d689`, read receipt
  `sha256:1d740c…21ec`, bundle `6e61780f…f2b` (53 required items read).
- I05-13 (backup classes, isolated restore, suspended import): journal is
  owner-neutral persistence only, no phase execution — satisfies.
- I05-16 (common durable fields, explicit identity/fence/schema/digests):
  satisfies.
- I05-22 (explicit/versioned/idempotent additive migration): satisfies.
- I05-27 (canonical operation identity, same-key/different-hash conflict):
  satisfies.
- I14-21 (unknown commit reconciled by readback, never blind retry):
  satisfies.
- I07-20 (exact reason codes, no silent success): fail-closed errors only.

## Remaining / requests

- #960 owner adapters (`RestoreJournalPort`, `RestoreTarget`) and kernel
  composition binding: explicitly out of #957 scope (lane E consumer).
- MGR-A requests: none (ORS lib/store registration done in this lane).
