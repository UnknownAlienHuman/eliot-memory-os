# Writer T12-07 — Governed Dreamer model adapter (MGR02, #702)

## Assignment

- Role: WRITER-T12-07 for MGR02 wave item T12-07.
- Base: `9cf878959cdf4455999e32aef907f1988c0a6011` (verified `HEAD == base`, clean
  worktree before mutation; branch `work/702-t12-07-model-adapter` created from base).
- Worktree: `C:/Development/Rust/projects/eliot-swarm/mgr02-item-T12-07`.
- No `fetch`/`pull` executed. Push target only the owned branch
  `origin work/702-t12-07-model-adapter` (WIP checkpoints per assignment; no authority
  refs touched).

## Reading attestation

- T12.md sections 3 (current code reality, esp. §3.3 model binding) + 5 (slice plan,
  esp. T12-07) read first; slice text treated as authoritative per assignment. T12
  snippets are marked UNCOMPILED proposals there, so the filed signature follows the
  T12-06 landed shape (`submit_orientation(input, queue)`) rather than the sketch.
- `reader.md` (workers/MGR02/items/T12-07/reader.md) does not exist in this worktree
  (no `workers/` dir at base); proceeded on T12.md + supplier source, no scope widened.
- Documentation routing run from repo root before mutation (all PASS):
  - route `sha256:0f5fddda9edb6bcb5de2c7946244ba03e1bed89da397ef6ea2db7d0a294150e5`,
    read receipt `sha256:d5b766ca92285903121bfa340a1d3cc1fff7c869e7801ebbf8f4493e1fd9cef4`
    (`bins/eliotd/src/dreamer_model_adapter.rs`);
  - read receipt `sha256:60aca37fb284494669d2f4c705d9ebb1b97107c115fe44b709ef4cbe62359a4c`
    (`bins/eliotd/src/lib.rs`);
  - read receipt `sha256:16ef18219833005b9f08233e3400f1c4f10b3753d7bf172a2c3edb3efd075d60`
    (`bins/eliotd/src/daemon_runtime.rs`);
  - read receipt `sha256:16f56300f3cac44495acc9bb2b4eae1641ea03f98e00efb947d6efd3ad35ec90`
    (`bins/eliotd/Cargo.toml`).
  - Bundle SHA-256: `aa16b97ad049ce851ccdaae226dba1d57b287c91298c8af665642807debc6eb8`
    (59 required items); pair key
    `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`.
  - Applicable fragments read: A2.3/A10.4/A0.3 posture via T12-06 code, coordinator
    AGENTS (plan-under-gap, sealed verifier, no-vendor-hardcoding, no-silent-fallback
    rules), agent-api AGENTS (S4/S5 triple), bins/AGENTS (thin-join rule), governor
    AGENTS (finish boundary).
- Supplier sources read (delegate, never copy): `AgentCoordinator::plan`
  (core.rs:228), `new_with_admitted_provider` (core.rs:181),
  `restore_with_admitted_provider` (core.rs:1750), sealed `KernelProviderVerifier`
  (provider_admission.rs:126), `verify_provider_capability` (provider_capability.rs:268),
  `ProviderExecutionBinding` (execution_binding.rs:161), `AdmittedRouteReceipt`
  (route_receipts.rs:419), `PhysicalRouteObservationReceipt` (:517), `AgentResult`
  (api/lib.rs:976), catalogue (model_control.rs:326) + Human policy (:664),
  `OpenCodeClient::run_read_only` (client.rs:502 → `NoAuthorityRunResult`, NON-admitted).
- T12-06 landed reference (c7a44558): `GovernorDreamerAdapter::submit_orientation`
  (dreamer_admission.rs:176), lib.rs:704-711 + daemon_runtime.rs:233-244 pattern mirrored.

## Change (one bounded causal join, owned paths only)

New: `bins/eliotd/src/dreamer_model_adapter.rs` (~800 lines incl. test):

- `pub trait DreamerModelExecution` — closed execution port
  (`execute(candidate, admission, binding) -> impl Future<Output = Result<AgentResult,
  CompositionError>>`); production binds the owner-approved route only. Test binds a
  recording responder. `OpenCodeClient::run_read_only` can never satisfy it (returns
  `NoAuthorityRunResult`, a different type with no admission/binding linkage).
- `pub struct ModelInvokeInput` — owned `{request, catalogue, policy, now_unix_ms,
  admission, binding}`; ceiling is `request.launch.effect_ceiling` (never supplied twice).
- `pub struct GovernedDreamerModelAdapter<'a>` — borrows composition only (no Kernel
  client: this slice performs no Kernel reads; documented deviation from T12-06).
  `model_route_context()` (pure fence-bound context) + `invoke(config, input, execution)`.
- `pub(crate) admit_model_route_policy` — catalogue/policy shape validation, agreeing
  account scopes, snapshot current at `now_unix_ms`, policy must govern `ModelRole::Dreamer`.
- `pub(crate) verify_model_attempt_linkage` — admission/binding shape validation plus
  exact attempt/lease/fence/generation/route agreement, selected-route authorization,
  planned-route membership (no silent substitution), full-fingerprint catalogue membership
  (no vendor/model/host string matching anywhere).
- `pub(crate) invoke_admitted_model` — order: readiness → catalogue/policy → fence →
  `AgentCoordinator::plan` (plan-only coordinator, explicit typed `PlanGap::G11Unavailable`)
  → linkage pre-check → exactly one port execution → `AgentResult::validate_for_binding`
  (returns result verbatim: requested/logical/observed identities, usage, cancellation,
  unknown outcomes preserved; `UnknownOutcome` never converted).
- No `always_verified` verifier exists in eliotd; every digest recomputed by owner
  validators. Sealed per-proof verification (`Binding`/`Result` via `KernelProviderVerifier`)
  stays owned by the coordinator `admit`/`bind`/`submit_result` path — neither bypassed
  nor reimplemented. Per-role `compile_model_selection` stays owned by model-control and
  is consumed at request-construction time via lane preference-rank evidence.
- ONE test: `wrong_attempt_receipt_is_rejected_before_execution` — otherwise-valid
  fixture (real `plan`, recomputed digests, valid catalogue/policy/admission/binding
  shapes) with binding attempt-B vs admission attempt-A; asserts rejection naming the
  attempt mismatch AND recording-port call count `0`.

Registration (minimal diff, T12-06 pattern):

- `bins/eliotd/src/lib.rs`: `mod dreamer_model_adapter;`, `pub use` block,
  `DaemonComposition::dreamer_model()` readiness-gated accessor (no `start()` change).
- `bins/eliotd/src/daemon_runtime.rs`: `attach_dreamer_model(&composition)?` at the same
  attach site + `attach_dreamer_model` fn (accessor + `model_route_context()` check before
  `report_ready`; no thread/transport/credentials/run-loop change).
- `bins/eliotd/Cargo.toml` + `Cargo.lock`: added `eliot-agent-api`, `eliot-agent-contracts`,
  `eliot-agent-coordinator`, `eliot-evaluation-contracts`, `eliot-security-contracts`
  (all `workspace = true`, alphabetical). Lock diff = 5 eliotd dep edges only, zero version
  churn.
- Never touched: `dreamer_admission.rs`, `dreamer_materials.rs`, Kernel/Store files.

## Diff stat

- Commit `976418ba`: 5 files, +869 (dreamer_model_adapter.rs new;
  Cargo.toml +5; Cargo.lock +5 edges; lib.rs +24; daemon_runtime.rs +23).

## Gates (scoped; package `eliotd` verified in bins/eliotd/Cargo.toml)

Target dir `C:/Development/Rust/projects/eliot-swarm/MGR02-target-2` for all:

- `cargo check -p eliotd --all-targets` → exit 0 (2 warnings, both pre-existing
  `dead_code` in untouched `observation_adapters.rs:248,267`).
- `cargo clippy --locked -p eliotd --all-targets` → exit 0; zero warnings in
  `dreamer_model_adapter.rs` (one self-found `clone_on_copy` fixed pre-gate), zero
  warnings on edited lib.rs/daemon_runtime.rs lines (all remaining warnings at
  untouched lines, e.g. daemon_runtime.rs:209/360/492/653+; lib.rs untouched regions).
- `cargo test --locked -p eliotd` → 67 lib + 8 bin + 6 integration + 0 doc-tests,
  all pass, incl. new `dreamer_model_adapter::tests::wrong_attempt_receipt_is_rejected_before_execution`.
- `cargo fmt -p eliotd -- --check`: new file clean (via `rustfmt --edition 2024`);
  remaining diffs verified pre-existing baseline drift (reproduced with own changes
  stashed; untouched files/regions only) — left alone per scope.
- Public API added (`DreamerModelExecution`, `GovernedDreamerModelAdapter`,
  `ModelInvokeInput`, `dreamer_model`): `git grep` over `crates/` + `bins/` shows users
  only inside `bins/eliotd` → no external direct dependents to check.
- Skipped/unavailable: full-workspace suites (change closure is eliotd-local); live
  provider acceptance — NOT_EXECUTED (no credentials/runtime; recorded, not mocked).

## Residuals

- GAP-1 (orientation root-excluded) inherited from T12-06, not reopened: adapter imports
  no orientation leaf.
- Live model acceptance NOT_EXECUTED: no production `DreamerModelExecution` binding lands
  here (no credentials); first owner-approved real route + physical correlation belongs to
  T12-10 wiring, which must supply catalogue/policy/admission/binding threading plus the
  Kernel claim material for coordinator-level sealed admission.
- No silent-fallback/mid-attempt-replacement paths added; unknown-outcome reconciliation
  stays with the coordinator owner.
- Baseline fmt drift in eliotd (pre-existing, out of scope) left untouched.

## Branches/commits

- Branch: `work/702-t12-07-model-adapter` (from base `9cf87895`).
- Commits: `976418ba` (implementation + test + gates green), pushed to
  `origin work/702-t12-07-model-adapter` (this record follows as second commit).
- Files: `bins/eliotd/src/dreamer_model_adapter.rs` (new),
  `bins/eliotd/src/lib.rs`, `bins/eliotd/src/daemon_runtime.rs`,
  `bins/eliotd/Cargo.toml`, `Cargo.lock`.
