# 1873 integrated delivery — backup/restore classes + product runtime (preview and isolated-runner components)

- Branch: `work/1873-product-command` in `C:/Development/Rust/projects/eliot-swarm/B-fx1873p`
  (base `6b523bdd`, preserved `B-fx2247` untouched, PR branch never checked out).
- Root-merged `origin/main` @ `2f402072` into the branch as `264d67f4`
  (no conflicts to resolve — merge is clean, zero conflict markers; both sides verified present).
- Lane commits (local only, never pushed; root publishes the new PR):
  `e06a7e0e` portable recovery + isolated driver + product command surface;
  `23eb23cb` actual isolated restore runner with temp-file journal and real bytes;
  `25bdbd82` backup/restore CLI entry with live preview and coverage proofs;
  `625c7bb6` disposition admission with exact preview-consumer pin.
- **Frozen candidate: `625c7bb686d7995daa7a2416ef37edc7c49b69f2`**.
- Full delta vs `2f402072` (14 files): `Cargo.lock` (+1 edge), `bins/eliot/Cargo.toml`
  (+1 dep), `bins/eliot/src/main.rs` (+7 additive lines), NEW
  `bins/eliot/src/backup_entry.rs`, NEW `bins/eliot/tests/backup_entry_cli.rs`,
  `crates/storage/eliot-backup/src/lib.rs` (mod wiring + #1873 APIs from merged
  #2247), NEW `src/portable_recovery.rs`, `src/isolated_restore.rs`,
  `src/product_command.rs`, `src/restore_runner.rs`, NEW tests
  `portable_recovery.rs`, `isolated_restore.rs`, `product_command.rs`,
  `restore_runner.rs`, plus `Cargo.toml` admission + `tests/disposition.rs` pin.

## Integration: both sides resolved

- 2258 side (merged `Setup` first-run CLI): `Setup` variant, `SetupCommand` enum,
  `run_setup` dispatch, `first_run_flow` module, `eliot-config` dep — all
  byte-identical post-merge; `eliot setup --help` exits 0 from the integrated
  binary; all 73 `eliot` bin unit tests green.
- 1873 side: `Backup` variant after `ControlBoard`, dispatch arm after the
  `ControlBoard` arm (`bins/eliot/src/main.rs` diff is 3 hunks, +7 lines, zero
  reflow of existing lines); `mod backup_entry;` alphabetically first per fmt;
  `eliot backup --help` lists `create-preview`, `restore-preview`,
  `key-coverage`. Disjoint enum/match regions — the two lanes converge without
  textual interference.
- Preserved conflict resolved in-lane: the #1716 disposition pin
  (`no_production_binary_selects_the_crate`) failed post-merge because the new
  `eliot → eliot-backup` edge is exactly the owner decision #1873 orders
  ("make reachable via a product-owned capability"), which the test docstring
  itself names as the resolution. Resolved by recording the admitted bounded
  non-runtime product surface in manifest metadata and pinning the exact
  consumer allowlist (`eliot: dependencies.eliot-backup` only) — tighter than
  the old ban, not a weakening. `scripts/migration_inventory_1860.py` still
  carries the old unreachable prose (cold inventory, out of lane — flagged,
  not rewritten).

## Combined proof (integrated tree, isolated target, offline)

- `cargo test --offline -p eliot-backup`: 25 + 8 + 10 + 2 + 4 + 4 + 3 + 22 + 6
  = **84 passed, 0 failed** (includes admitted-disposition pin, wrapped-key
  issuance/refusal, isolated plan/cutover gates, previews, real-bytes runner
  with durable resume, tamper/stale/key refusals).
- `cargo test --offline -p eliot --test backup_entry_cli`: **3 passed**
  through the real binary on temp fixtures (exit codes + JSON stdout).
- `cargo test --offline -p eliot --bin eliot`: **73 passed** (Setup preservation).
- `cargo clippy --offline -p eliot-backup --all-targets --no-deps -- -D warnings`:
  clean. `cargo clippy --offline -p eliot --all-targets --no-deps -- -D warnings`:
  exit 0 (only pre-existing capped dependency warnings). `cargo fmt --check`:
  zero diffs in all touched files. `git diff --check` clean.
- No resolver changes were needed beyond the disposition admission (merge was
  conflict-free); no audits ran; no Perplexity used; no push/fetch/main touched.

## Docs receipts + attestation

- Full-delta route `sha256:9d33fd8b0c02e6c754e81a326c559efeb773363cf53232685655906c67b01093`,
  read `sha256:89803828eec99b9d9d954b4cf09186f08d99d5926b30da243b6a29c8c26851b6`,
  routes `generic-source, canonical-storage, human-surfaces, release-migration`,
  pair `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`,
  55 required items (A0.1, A0.2, A0.3, A0.4, A0.6, A2.3, A4, A10.4, A11, A12.3,
  A13.3, A13.6, A13.7, A13.8, A13.9, A14.8, I0.3, I0.4, I0.5, I0.8, I0.9, I0.13,
  I0.14, I2.17, I2.20, I3, I5.1, I5.2, I5.3, I5.4, I5.5, I5.6, I5.7, I5.19,
  I5.27, I7.3, I7.4, I7.5, I7.6, I7.7, I7.8, I11, I18, I19, I20, source-candidate
  workflow, AGENTS.md, WORKFLOW.md, bins/AGENTS.md, crates/AGENTS.md,
  crates/storage/AGENTS.md, docs/ARCHITECTURE_CONTRACT.md, docs/DEPENDENCY_POLICY.md,
  docs/architecture/READING_PROTOCOL.md, workstreams/ACTIVE.toml), bundle SHA
  `d406472649c9ef20b4419546201c7aa46348dd05d967f774c75abfc9cbc48144`
  (raw `B-fx1873p/.eliot/docs-read-bundle-full.md`,
  `B-fx1873p/.eliot/docs-read-receipt-full.json`).
- I attest opening and reading every required fragment (plus governing
  I5.13/I5.10/I5.12/I5.14 direct from source); a pagination gap in one read
  pass (A13.3, I00-08, I00-09, I19, I20) was detected by header inventory and
  closed by direct reads — recorded here honestly.
- Prior lane receipts (product-surface, runner-scope, CLI-scope) listed in full
  in `1873p-pr-body.md`. CBM unused throughout — direct source grep fallback,
  disclosed.

## What this delivers / what stays open

- Delivers: wrapped-key manifest + coverage proof + restoration receipts with
  fail-closed `full_recovery` issuance; actual isolated runner (real bytes,
  receipt, durable temp journal, deterministic resume); temp-only isolated
  driver + default-deny cutover gate; CLI-shaped parse/preview surface; live
  `eliot backup` entry (previews + coverage only); admitted disposition with
  exact consumer pin; Setup/Backup coexistence proof.
- Issue #1873 stays OPEN for: real Blob/Secret owner adapters
  (unwrap/re-encryption), #960 Kernel owner ports + production durable journal,
  #961 installation cutover, `bins/eliot-kernel` reverse-dep compile,
  execution/cutover exposure in the CLI.
