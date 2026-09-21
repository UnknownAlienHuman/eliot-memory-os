# 1955 P03 runtime delivery — `WasmP03ProcessAdapter` frozen (B1)

Branch: `codex/1955-runtime-ports` (base `69bcf7a6` + owned WIP).
Status: P03 FROZEN — implemented, proven, committed locally (root publishes).
Governor input used: FINAL freeze `323fcd4c` (NOT `ad49a77e`).

## What exists (exact locations)

Crate `eliot-process-executor`, module `wasm_p03_adapter` (new Rust module,
no new crate, no new state machine, no registry, no job table, no direct
spawn, no keys):

- `pub struct WasmP03ProcessAdapter` — composes the real
  `WindowsProcessExecutor` (sole process-state owner) + the owning lane's
  evidence sink + one single-shot Kernel-admission slot.
- `stage_admitted_request` — P-07/Kernel-issued `ProcessRequest` enters here;
  revalidated; second stage without `prepare` rejected (never a queue).
- `P03ProcessPort`: `prepare` binds staged admission to the presented
  `ProcessLaunchEnvelope` (operation/tree/generation/fence-epoch+generation/
  wall/memory/stdout ceilings, else `Denied`; empty slot → `Unavailable`);
  `start`/`cancel`/`reconcile` delegate verbatim to the executor.
- `P03ReceiptVerifierPort`: `verify_start` / `verify_cancellation` /
  `verify_reconciliation` — executor-minted receipt/evidence rebound to the
  presented binding + envelope lease authority; anything else `Denied`.
- `reconcile` is poll-safe (root-cause fix, see below): while the child is
  still driving (`Created`/`Starting`/`Running`/`Cancelling` per a
  non-destructive `inspect` guard) it reports `UnknownOutcome` with nothing
  fenced; an already-unknown op passes through to the executor's
  quarantine-reconcile path unchanged.
- Error mapping: contract rejection → `Denied`; absent executor →
  `Unavailable`; everything else → `UnknownOutcome` (never a manufactured
  denial or acceptance). No oracle change: verifiers untouched.

Supporting one-line changes (prior WIP, kept): `mod wasm_p03_adapter` in
`eliot-process-executor/src/lib.rs`; `ProcessBinding::from_request` made
`pub` in `eliot-wasm-runtime/src/types.rs` (sealed pipeline + owner lane use
the identical derivation); `eliot-wasm-runtime` contract-only dependency +
`serde_json` dev-dependency in the executor manifest; `Cargo.lock` updated.

## Root cause: `verifiers_reject_foreign_binding` UnknownOutcome abort

Actual call chain (diagnosed, not hypothesized):

1. Test polls `adapter.reconcile(&genuine)` while the real child still runs.
2. Old adapter called `executor.reconcile` directly (`lib.rs:2569`).
3. Child `Running` → `refresh_operation` returns `Ok(())` (`lib.rs:2713`).
4. Lifecycle not `UnknownOutcome` → falls through to unconditional
   `join_streams` (`lib.rs:2606`), which joins — cancelling — live capture
   threads; the still-draining requested session yields a join disposition
   (`lib.rs:3321-3342`).
5. `join_streams` false → `quarantine_operation` fences the op to
   `UnknownOutcome` (destructive) → `Err(UnknownOutcome)` (`lib.rs:2606-2608`).
6. Adapter mapped to `PortError::UnknownOutcome`; the test loop used `?` →
   instant `Error: UnknownOutcome` abort (0.04s, deterministic, not flaky —
   the sibling reap test only passed on timing luck: same race).

Fix (production path, no oracle weakening): `inspect`-guard described above
plus test poll loops (`reconcile_terminal` helper) that retry transient
`UnknownOutcome` and panic at a 20s deadline instead of passing — a genuinely
unclosable tree can never slip through as success.

## Gates (isolated target, offline, `CARGO_TARGET_DIR=target-isolated`)

- `cargo test --offline -p eliot-process-executor wasm_p03` — **8 passed**,
  0 failed (was 7 passed / 1 failed `verifiers_reject_foreign_binding`).
- Repeat runs of `verifiers_reject_foreign_binding` — pass.
- `cargo clippy --offline -p eliot-process-executor --lib` — zero findings
  in `wasm_p03_adapter.rs` (2 `needless_pass_by_value` fixed by taking
  error mappers by reference; 1 pre-existing warning in untouched
  `eliot-platform-windows/src/package_staging.rs` remains, not my surface).
- `cargo fmt -p eliot-process-executor` — clean.
- Old engine suites (36+2+2) NOT re-run per brief (untouched paths).

## Governor-freeze compatibility (read-only verification, no merge)

- `323fcd4c` exists locally; `ad49a77e..323fcd4c` touches exactly one file:
  `crates/governor/eliot-governor/src/wasm_resolution.rs` (+14/−19).
- `crates/modules/eliot-wasm-runtime/` diff across the freeze: EMPTY — the
  neutral port traits my adapter implements are byte-identical, so no
  adapter change is required by the freeze.
- Amendment claim verified read-only: neutral `derive_execution`
  (`runtime.rs:900-906`) hashes result + state-delta as raw bytes, effects
  as canonical JSON. My adapter mints no digests — unaffected.
- NO local merge performed: merging `323fcd4c` would drag a 108-file
  main-delta (`dde6b2d1` main-merge rides along) into this lane, violating
  the touch-only-listed-paths rule. Root integrates; the governor-only delta
  is the single file above.
- `wasm_resolution.rs` is absent from this worktree (governor lane file) —
  the joined test cannot compile here until root seats it.

## Joined-proof status (host lane owns the test file)

Recipe from the handoff stands as written; P03-side preconditions now met:

- Real fixture bytes confirmed present (read-only): host
  `tests/fixtures/guest-conformance.wat` (2741 B),
  `guest-conformance-divergent.wat`, `guest.wat`; `wit/guest.wit` bound by
  the provider itself as
  `sha256(include_bytes!("../wit/guest.wit"))`
  (`wasmtime_provider.rs:216,574`) — matches the recipe's interface identity.
- `WasmtimeComponentEngine::new` exists (`wasmtime_provider.rs:199`);
  `WasmHostRunner::execute_admitted` exists (`bins/eliot-wasm-host/src/lib.rs:140`,
  WASM-contour gate + verbatim A-12 delegation).
- Missing, NOT writable by this lane: `admitted_execution.rs` (or equivalent)
  seating `GovernorWasmAdmission::from_owners` (323fcd4c) + this frozen
  adapter + the real engine through `execute_admitted`, with the recipe's
  positive (`Succeeded`, output == `DeterministicEchoCore` reference,
  `wasmtime-component/47.0.4`) and negatives (divergent fixture → `Denied` →
  `UnknownOutcome`; authority `Denied` → `Rejected`; non-WASM →
  `ContourNotServedHere`; rotated fence → `Denied` pre-engine).
- Helper-only honesty note: the 8 green tests prove the production adapter
  entrypoints against real children; they do not prove the host-lane caller
  wiring — that is exactly what the joined test above must still prove.

## Docs receipts (path-scoped routes, read BEFORE mutation)

- Adapter family: route `sha256:5627b1b7…`, read
  `sha256:243738f1531b…`, bundle `b68b30cd16a6…`, 24/24 required items.
- Executor lib family: route `sha256:286fc16a77…`, read
  `sha256:ff9fff692502…`, bundle `760f3eaaab1a…`, 24/24 required items.
- Runtime types family: route `sha256:770ec73a4e…` (routes
  `generic-source`, `host-kernel`, `module-runtime`), read
  `sha256:065aa3d1468d…`, bundle `5dd0d1a65b23…`, 52/52 required items.
- Causal items read in full: I18 (UNKNOWN_OUTCOME distinct, real-edge proof),
  A13.2 (failure domains), I2.3 (outward-only deps; this dependency is
  contract-traits-only, no impl, no cycle — flagged for root awareness),
  I1.8 (exact ownership/call paths; adapter mints nothing, executor stays
  sole state owner), I2.17 (write isolation; no integration performed),
  I14.19 (WASM default contour, capability boundary), I1.1–I1.8,
  A13.3 (lifecycle verdicts stay `Rejected`), plus bundle remainder.
- CONTROL sources read: `recovery-1437-p03.json` (prior checks + hypothesis),
  `1955-governor-port-handoff.md` as amended (FINAL freeze `323fcd4c`),
  `1955-live-issue.json` (#1955, OPEN).

## Residuals

- #1955 stays OPEN. Joined `Succeeded` proof awaits root integration (seat
  `wasm_resolution.rs` @ `323fcd4c`) + host-lane writer (joined test file).
- Conformance vs lifecycle promotion distinguished per I14.19: rejected
  lifecycle verdicts stay `Rejected` (A13.3 path future, host/Governor lanes).
- No push performed (local commits only); no `target-isolated/`, `.eliot/`,
  reports, or logs committed.
