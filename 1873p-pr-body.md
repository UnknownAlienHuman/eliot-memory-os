# PR body — issue #1873 (backup/restore classes with recoverability evidence)

## Owning issue / scope

Implements #1873 (`[I5-audit] Expose backup and restore classes with
recoverability evidence`), product continuation after merged PR #2247 (library
class selection and suspended-restore helpers). Owner:
`crates/storage/eliot-backup` plus the operator CLI entry in `bins/eliot`.
Base `origin/main` @ `2f402072`; branch `work/1873-product-command` (merge
`264d67f4` of `2f402072` plus e06a7e0e product surface, 23eb23cb isolated
runner, 25bdbd82 CLI entry, 625c7bb6 disposition admission).

## Changed causal property and path scope

- Portable blob recovery (`crates/storage/eliot-backup/src/portable_recovery.rs`,
  NEW): `WrappedKeyEntry`/`WrappedKeyManifest` (opaque wrapped bytes bound by
  digest, never plaintext, never opened here), exact-set `verify_key_coverage`
  over carried blob lineages, per-blob `BlobRestorationReceipt` issuance, and
  `FullRecoveryPackage` + `issue_full_recovery`, which fails closed with
  `MissingRecoveryComponent("blob_key_material")` (or `IntegrityMismatch` on
  tampering) instead of labeling success. Blob-free archives need no manifest;
  the existing `BackupBundle::build`/`validate` denominator is unchanged.
- Actual isolated restore runner (`crates/storage/eliot-backup/src/restore_runner.rs`,
  NEW): `FileRestoreTarget` implements the accepted `RestoreTarget` effect seam
  with real effects into an `IsolatedRoot` (recomputed sealed-sha checks, exact
  byte writes, purge ledger persisted before any import, ORS recorded suspended,
  count/chain verification, finalize evidence bound to observed files);
  `FileRestoreJournal` is a temp-file-backed journal proving durable resume
  across runner instances (second run returns the identical receipt and
  evidence with an empty phase log); `execute_isolated_restore` binds key
  coverage, isolated planning (purge-first, fresh lineage), and governed
  journaled execution. Rehearsal grade: production durability stays with the
  `#957`/`#960` owner, unwrap/re-encryption with the BlobStore/secret-provider
  owner, cutover with the `#961` owner.
- Isolated restore driver and cutover gate (`src/isolated_restore.rs`, from
  e06a7e0e): temp-only `IsolatedRoot` (non-temp roots refused, drops clean up),
  `plan_isolated_restore` (purge-first assert, suspended ORS, `mint` equality),
  `authorize_cutover` with default-deny (`None` → `CutoverNotAuthorized`,
  mismatch → `PlanMismatch`; sole `CutoverReceipt` constructor, source-guarded).
- Product command surface (`src/product_command.rs`, from e06a7e0e):
  `parse_backup_class`, `BackupCreateArgs` + `preview_backup_create` (refuses
  silent upgrade/downgrade), `RestorePreview` + `preview_restore` from governed
  compile.
- Operator CLI entry (`bins/eliot/src/backup_entry.rs`, NEW;
  `bins/eliot/src/main.rs` +7 purely additive lines; `bins/eliot/Cargo.toml`
  +1 edge `eliot-backup = { path = "../../crates/storage/eliot-backup",
  version = "0.1.0" }`; `Cargo.lock` +1 edge): `eliot backup create-preview`,
  `restore-preview`, and `key-coverage`, mirroring `run_doctor` (typed arg
  decode → library preview/coverage → pretty JSON exit 0; mismatches →
  `BACKUP_*_INVALID` JSON exit 2). Preview-only: no issuance, execution, or
  cutover is exposed. Merged 2258 `Setup` behavior preserved byte-for-byte
  (disjoint enum/match regions; both lanes dispatch from one binary, verified
  by `--help` smoke of each).
- Disposition admission (`crates/storage/eliot-backup/Cargo.toml`,
  `tests/disposition.rs`): the #1716 unreachable pin is superseded by the
  owner decision #1873 itself orders ("make reachable via a product-owned
  capability"): `workspace_admission` now records the admitted bounded
  non-runtime product surface, and the consumer test pins the exact allowlist
  (`eliot: dependencies.eliot-backup` only) instead of an empty set — a
  tighter pin, not a weakening.

## Docs route / read receipt and attestation

- Full-delta route `sha256:9d33fd8b0c02e6c754e81a326c559efeb773363cf53232685655906c67b01093`,
  read `sha256:89803828eec99b9d9d954b4cf09186f08d99d5926b30da243b6a29c8c26851b6`,
  routes `generic-source, canonical-storage, human-surfaces, release-migration`,
  pair `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`,
  55 required items, bundle SHA
  `d406472649c9ef20b4419546201c7aa46348dd05d967f774c75abfc9cbc48144`
  (raw `B-fx1873p/.eliot/docs-read-bundle-full.md`,
  `B-fx1873p/.eliot/docs-read-receipt-full.json`). Required handles:
  A0.1, A0.2, A0.3, A0.4, A0.6, A2.3, A4, A10.4, A11, A12.3, A13.3, A13.6,
  A13.7, A13.8, A13.9, A14.8, I0.3, I0.4, I0.5, I0.8, I0.9, I0.13, I0.14,
  I2.17, I2.20, I3, I5.1, I5.2, I5.3, I5.4, I5.5, I5.6, I5.7, I5.19, I5.27,
  I7.3, I7.4, I7.5, I7.6, I7.7, I7.8, I11, I18, I19, I20, plus the
  source-candidate workflow, AGENTS.md, WORKFLOW.md, bins/AGENTS.md,
  crates/AGENTS.md, crates/storage/AGENTS.md, docs/ARCHITECTURE_CONTRACT.md,
  docs/DEPENDENCY_POLICY.md, docs/architecture/READING_PROTOCOL.md, and
  workstreams/ACTIVE.toml — every item opened and read, with governing
  I5.13/I5.10/I5.12/I5.14 read directly from source.
- Earlier lane receipts retained in history: product-surface route
  `sha256:c2533656a1638cf4b8e2760f61c76c8ddd1a96461651c4eb56ffe84a0bf320fe` /
  read `sha256:aa2337c12128a82d5af1fd77b2247a14131fc0040c09bee4dfe754a0d6dc6d5f` /
  bundle `b918ef0d6d70d13f36cf1212b71841423b1bdac04e604fb3ec1ef2052e2ccadb`;
  runner-scope route `sha256:557feca6cc771a9f2e5719e703755cd756a161fd91726a6df2d9b4fe811daecf` /
  read `sha256:86f222e37977a12a8fa0e48033e12340c752c97fd0f9c2def88e5381a6a0b6ce` /
  bundle `fa98b64b4a4f0f081d1ba75d3b25faf5a40f39ade363ed7b454bd920c1092fc3`;
  CLI-scope route `sha256:9ff023ab17440f0da6e6ef9705a147f7c5bbfca1aa301d29d4b08352c0820a5a` /
  read `sha256:9971c31d81142e5bf8e15800af5b165cbf743f55559f784d4fd25f2ac04fd164` /
  bundle `fb19170047000c7b3bfb3bd3048043a257e2703ddac0f67195b7c9fe1334e9db`.
  Worker attests every required item was opened and read before mutation.

## Proof executed and proof ceiling

- `cargo test --offline -p eliot-backup`: 25 lib + 8 backup_classes + 10
  backup_integrity + 2 disposition (admitted state) + 4 isolated_restore + 4
  portable_recovery + 3 product_command + 22 restore_contract + 6
  restore_runner = **84 passed, 0 failed** (real restored bytes + receipt
  assertions, durable resume with identical receipt/evidence, tampered-blob
  refusal pre-effect, degraded canonical-only ceiling, key gating, stale
  lineage with zero effects — all temp-only).
- `cargo test --offline -p eliot --test backup_entry_cli`: **3 passed**
  through the real binary (exit codes + JSON stdout on temp fixtures).
- `cargo test --offline -p eliot --bin eliot`: **73 passed** (2258-era and
  older inline tests intact — Setup preservation).
- Live smoke on the built binary: `eliot setup --help` and
  `eliot backup --help` both exit 0 with their lanes' subcommands.
- `cargo clippy --offline -p eliot-backup --all-targets --no-deps -- -D warnings`:
  clean. `cargo clippy --offline -p eliot --all-targets --no-deps -- -D warnings`:
  exit 0 (only pre-existing `eliot-kernel-core` doc warnings from a
  dependency, capped). `cargo fmt --check`: zero diffs in all touched files
  (remaining package hits pre-existing in untouched regions). `git diff --check` clean.
- Ceiling: library + CLI-preview + rehearsal-runner proof only. Product status
  unchanged (`NOT_ACCEPTED / UNVERIFIED`); no Product-Pulse claim.

## Affected edges / migration / rollback

- New `eliot → eliot-backup` compile edge (used surface: `product_command`
  previews plus `verify_key_coverage`; runner modules are exercised by backup
  tests). `Cargo.lock` gains exactly that edge. No runtime/process edge: the
  CLI performs no issuance, execution, or cutover.
- Disposition migration `#1716 → #1873`: recorded in manifest metadata and
  pinned by the allowlist test; `scripts/migration_inventory_1860.py` still
  describes the old unreachable state (cold inventory prose, out of lane —
  flagged for the owning lane, not rewritten here).
- Rollback: revert the lane commits; production code paths are additive-only
  (no existing behavior modified except the disposition pin both sides of
  which are recorded).
- Residual: real Blob/Secret owner adapters (unwrap/re-encryption),
  #960 Kernel owner ports + durable journal, #961 installation cutover,
  `bins/eliot-kernel` reverse-dep compile (additive-only, controller lane).
  Issue #1873 stays OPEN for those.
