# Provider Runtime Consolidation — worklog

This log preserves the ordered implementation evidence for
`docs/tasks/ELIOT_PROVIDER_RUNTIME_CONSOLIDATION_FINAL_v2_1.md`.

## 2026-08-01 — start and recovery point

- Activated the exact task commit `fb2ca2b5059506a0d3512cdb3bc7391b92ed86a4` by a local fast-forward from `7bb7c8f`.
- Read the complete 512-line task contract. SHA-256:
  `0F8C2C57BA4AEF6510BFCF6DB87471D2DE016C2DCA7AEAB45882BA8BF9CEE71E`.
- Preserved the pre-change state in local and remote branch
  `archive/cognitive-completion-v2-pre-provider-runtime-fb2ca2b`.
- Saved the initial tracked diff as
  `C:\Users\kleym\AppData\Local\Temp\eliot-provider-runtime-before.patch`; it is empty because the tracked tree was clean.
- Preserved the pre-existing untracked `.eliot/` directory without modifying or deleting it.
- Refreshed the CodeCortex repository graph in fast, non-persistent mode: 20,462 nodes and 94,109 edges.
- Observed a graph limitation: current source contains `run_external_agent_process`, while semantic search and trace did not resolve that symbol even after refresh. Current source, Cargo metadata and diagnostics remain the truth hierarchy.

## CodeUnderstandingProof

- Goal: consolidate provider route policy, process execution, retry, campaign budget, MCP tool profile and terminalization into their contract-designated owners without increasing any declared provider budget.
- Candidate files: `eliot-types/src/provider_invocation.rs`, `eliot-types/src/external_agent.rs`, `eliot-engine/src/provider_invocation.rs`, `eliot-engine/src/adapter.rs`, `eliot-engine/src/antigravity.rs`, `eliot-app/src/host_runtime/supervised_process.rs`, `eliot-app/src/host_runtime/external_agent.rs`, `eliot-app/src/host_runtime/external_agent_process.rs`, provider call sites, MCP catalog and focused tests.
- Exact anchors: `ProviderTimeoutProfile`, `ProviderInvocationAttempt`, `ProviderRuntimeContract`, `AntigravityProcessExecutor`, `SharedAntigravityProcessExecutor`, `run_external_agent_process`, `ExternalAgentAdapterCore::execute_governed`, `AdapterSupervisor::execute`, `ProviderInvocationJournal`, `McpAccessProfile::allows` and `tool_definitions_for_profile`.
- Current execution path: caller creates inline timeout data -> adapter supervisor adds an outer manifest deadline and may redispatch -> provider-specific wrapper creates a second restart policy -> generic Windows Job Object worker spawns and reaps -> adapter performs capture/parse before durable terminal process facts.
- Current duplicated writes: timeout constructors in app/engine runners; process lifecycle in both Antigravity and external-agent wrappers; provider retry in adapter supervisor in addition to controller/campaign logic; external-agent adapter supplies `max_calls=16` and `campaign_closed=false`; Antigravity keeps independent MCP lists.
- Invariants: one process generation; `RestartStrategy::Never`; no dispatch-ack deadline for current CLI routes; no timeout increase; no provider retry below controller/campaign; every post-spawn result is a terminal process outcome; durable terminal process facts precede capture/parse; exact policy and MCP profile ID/hash cross all evidence layers.
- Blast radius: provider execution and evidence schemas across `eliot-types`, `eliot-engine`, `eliot-app`, and the Windows supervised-process tests. Non-provider process probes, Git commands and daemon bootstrap remain out of scope.
- Verifiers: the eight behavior cases B1-B8, the focused gates named in section 9 of the task, Cargo check/Clippy/fmt, source-inventory assertions, then one versioned candidate and three current-state smokes.
- Initial diagnostics: cached Rust LSP diagnostics were empty for the provider invocation, external-agent and supervised-process owner files. Workspace metadata resolved five packages and confirmed the duplicate `cognitive_field_runner` test target from `src/main.rs`.
- Edit decision: allowed. Candidate files, exact anchors, invariants and focused verifiers are known; no unresolved authority or data-loss choice is present.

## Baseline owner inventory

- Timeout constructors: multiple inline `ProviderTimeoutProfile` literals across app and engine paths.
- Outer deadline owners: `AdapterSupervisor` manifest timeout plus supervised-process route deadlines.
- Retry owners: controller/campaign logic, `AdapterSupervisor` external-candidate redispatch and restartable process specs.
- Process executors: `AntigravityProcessExecutor`, `SharedAntigravityProcessExecutor`, `run_external_agent_process` and the generic Windows supervised worker.
- Campaign ownership violation: `ExternalAgentAdapterCore::execute_governed` supplies hard-coded `max_calls: 16` and `campaign_closed: false`.
- MCP ownership violation: `SAFE_AUDITOR_MCP_TOOLS` and `LEGACY_GOVERNED_MCP_TOOLS` duplicate the catalog-owned access profile.
- Terminalization violation: process facts can remain only in memory while spool, secret scan or parse fails before journal terminal persistence.
- Compatibility path: `CognitiveProviderRuntimeContract` remains in the active external-agent type module, and `eliot-app/Cargo.toml` still defines `cognitive_field_runner` as a duplicate test target at `src/main.rs`.

## ARCH-01 — central provider route policy

- Added `ProviderRoutePolicy::for_route(host, operation_class, declared_budget)` in the provider-invocation type owner.
- The policy has a deterministic BLAKE3 hash and hash-derived stable ID, one private timeout profile, output limit, incremental-output capability and status-lookup capability.
- Made `ProviderTimeoutProfile` fields private. All provider timeout construction now occurs inside the owner; callers supply an immutable `ProviderDeclaredBudget` through typed builders.
- Removed all current CLI dispatch-ack deadlines. Spawn, dispatch and first-output facts remain distinct.
- Bound the actual policy in `ExternalAgentExecutionRequest` and its ID/hash in `ProviderRuntimeContract`, `ProviderInvocationAttempt` and `ProviderExecutionEvidence`.
- Changed `AdapterSupervisor` external-candidate deadline selection from manifest timeout to the request-bound policy's absolute deadline plus its cancellation and cleanup grace. Non-provider adapters retain manifest timeout behavior.
- Preserved the prior absolute budgets: external smoke 120 seconds, cognitive field 900 seconds, Antigravity plan 310 seconds and each caller-supplied managed/preflight budget.
- Focused timings:
  - `cargo check -p eliot-types`: 22.24 s.
  - `cargo check -p eliot-engine`: 28.75 s.
  - `cargo check -p eliot-app --bin eliot-governor`: first incremental success 14.98 s after one private-field accessor repair.
  - `cargo test -p eliot-types --test provider_route_policy`: 31.17 s including compilation; 2/2 tests, test bodies 0.00 s.
  - Related schema and reconciliation tests: 21/21, 52.50 s including compilation; test bodies 0.23 s total.
- Source inventory after ARCH-01: `ProviderTimeoutProfile { ... }` appears only in `eliot-types/src/provider_invocation.rs`; no `dispatch_ack_deadline_ms: Some(...)` remains.

## ARCH-02 — one production process runner and no automatic provider retry

- Generalized the existing Antigravity executor seam into `ProviderProcessRunner`, with exactly two implementations: production `SupervisedWindowsProcessRunner` and test-only `ScriptedProviderProcessRunner`.
- Removed `AntigravityProcessExecutor`, `AntigravitySupervisedProcessSpec/Output`, `SharedAntigravityProcessExecutor`, the independent `run_external_agent_process` lifecycle, and the disabled duplicate unsupervised Antigravity executor bodies.
- Routed external-agent Claude/Antigravity/OpenCode, cognitive Worker/Reader/Judge, managed Antigravity, generic supervised host provider launches, Antigravity delegation/live smoke, supervised Antigravity version/help probes, and dogfood Codex through `SupervisedWindowsProcessRunner`.
- Preserved Windows `OsString` arguments and environment values in `ProviderProcessSpec`; the shared runner is the only production conversion into `SupervisedProcessSpec`.
- The runner fixes provider generation to 1, `RestartStrategy::Never`, zero restarts, one Job Object, concurrent stdin/stdout/stderr drains and a complete reap receipt.
- Removed `AdapterSupervisor` external-provider redispatch and restart persistence. It retains concurrency/circuit state only; a post-dispatch failure is marked for reconciliation and never replayed below the campaign/controller.
- Corrected a semantic defect exposed by the no-redispatch test: ordinary failures had been appended to `restart_timestamps`, incorrectly opening the restart window even without a restart. Failures now update circuit state without fabricating restart evidence.
- All post-spawn callback and runtime-checkpoint persistence failures are returned as `ProviderProcessOutcome.worker_error` after process cleanup; `Err` remains the validation/spawn-before-identity boundary.
- Removed direct provider version execution from external-adapter composition. Pre-dispatch runtime identity is now the immutable executable SHA-256, avoiding a hidden provider subprocess during a zero-call preview.
- Non-provider Governor MCP reference exchanges retain the generic supervised child primitive and its pre-dispatch-only restart policy. Compatibility-only blocking helpers are deferred to ARCH-04 with the duplicate main test removal.
- Focused timings and results:
  - `cargo check -p eliot-app --bin eliot-governor`: successive successful incremental checks 4.26 s, 6.10 s, 3.77 s and 5.28 s while migrating all call sites.
  - `cargo test -p eliot-app --bin eliot-governor provider_runner`: 2/2 passed; 34.14 s including compilation, 0.83 s test bodies.
  - `cargo test -p eliot-engine --test adapters adapter`: 21 passed, 1 authenticated-SurrealDB test ignored; 9.32 s including compilation, 0.23 s test bodies.
  - One initial exact-name test invocation selected zero tests and consumed 97.30 s compiling the binary. It is explicitly excluded from evidence; the corrected nonzero filter above is the acceptance evidence.
- Source inventory after ARCH-02: no removed executor name remains; provider `SupervisedProcessSpec` construction exists only inside `SupervisedWindowsProcessRunner`; the remaining `RestartStrategy::OneForOne` call is the local Governor MCP preflight, not a provider executable.

## Campaign and MCP ownership consolidation

- Split campaign creation from reservation. `ProviderCallReservationRequest` now carries only campaign ID, task/provider identity, idempotency key and gate evidence; it has no `max_calls` or closed-state fields.
- Added controller-only `ProviderCallReservationOwner::open_campaign`. The owner persists one immutable maximum, retains historical ledgers, may close but never reopen a campaign, and rejects reservation if the controller did not pre-create the budget.
- The normal external-agent smoke controller opens an explicit unique one-call campaign before adapter dispatch. The adapter only reserves against the supplied campaign ID and therefore cannot size or reopen it.
- Delegation opens/reconciles the provider-call campaign from the already-controller-owned calibration campaign before reservation; terminal calibration state closes the call campaign.
- Moved provider MCP tool selection to `mcp_stdio/catalog.rs`. Catalog-derived `ProviderMcpToolProfileBinding` carries the profile ID, stable BLAKE3 hash and sorted exact tool names.
- Bound the catalog profile into `ExternalAgentExecutionRequest` and provider runtime contract v2. Runtime preparation recomputes the selected Reader/Worker profile from the catalog and rejects any mismatch; contract validation checks the hash and exact tool-name equality.
- Removed `SAFE_AUDITOR_MCP_TOOLS`, `LEGACY_GOVERNED_MCP_TOOLS` and the Antigravity-local status list. Antigravity receipt logic now consumes the central profile authorization decision instead of maintaining another allowlist.
- Reader/auditor routes use the bounded `external_auditor` catalog profile; cognitive Worker routes use the separate `cognitive_child` profile. Operator/doctor tools are absent from both.
- Focused timings and results:
  - `cargo test -p eliot-engine --test provider_budget_integrity`: 9/9 passed; 40.31 s including compilation, 0.21 s test bodies.
  - `provider_tool_profiles_are_catalog_derived_and_hash_stable`: 1/1 passed; 0.23 s, 0.01 s test body.
  - `cargo test -p eliot-types --test external_agent`: 2/2 passed; 25.28 s, test bodies 0.00 s.
  - `cargo test -p eliot-engine --test external_agent`: 6/6 passed; 2.11 s, test bodies 0.00 s.
  - `cargo test -p eliot-engine --test antigravity_runtime mcp_`: 7/7 passed; 19.61 s, test bodies 0.03 s.
  - An incorrect `--exact` app test filter selected zero tests after 90.86 s of duplicate-main compilation. It is excluded from evidence; the corrected one-test result above is evidence and the compile penalty is tracked for ARCH-04.
- Source inventory: no adapter hard-coded `max_calls: 16`, no reservation `campaign_closed`, and no provider-maintained auditor/legacy MCP list remains.

## ARCH-03 — terminal process facts and provider-free historical reconciliation

- Added the durable `ProcessTerminal` lifecycle state and made `ProviderInvocationJournal::record_process_terminal` the first operation after a successful `ProviderProcessRunner` return in both the normal external-agent route and the recorded Antigravity route.
- The journal now persists actual process start/exit/cleanup, first/last output, exit/forced-termination classification, timeout class, PID/Job Object identity, `ProcessReapReceipt`, worker/cancellation/timeout facts, byte counts and truncation facts before output admission, secret inspection, parsing or schema validation.
- Journal state mutation is copy-on-success: transition/output methods persist a cloned attempt and update caller memory only after the atomic write succeeds. This prevents a later unrelated persist from committing terminal facts under an older state.
- Terminal journal failure writes a provider-redispatch-forbidden reconciliation sidecar. If both the attempt write and sidecar write fail, the returned error preserves both failures and the no-redispatch assertion.
- Post-dispatch runner `Err` no longer leaves `Running`: external-agent and Antigravity routes persist `TimeoutPendingReconciliation`; the lifecycle now explicitly admits `Running -> TimeoutPendingReconciliation`.
- Fixed an invalid Antigravity error transition that tried `Running -> DispatchAckUnknown`, and removed the false supervisor error label that classified every runner error as pre-identity.
- Made historical attempt loading schema-tolerant without inventing current policy: `provider_route_policy` is `Option` with a legacy `None`, while all new attempts bind `Some(exact policy)`. The two historical Antigravity JSON attempts now load through the real `external-agent inspect` path with their old null process fields intact.
- Added typed `external-agent reconcile --invocation ... [--dry-run]`. It has no route to `ProviderProcessRunner`; it binds exact attempt, ledger, HostBroker job/session, canonical authority-close, phase log, raw-spool absence, OS PID-absence and current supervision evidence into an immutable resolution, then closes only `Running -> TimeoutPendingReconciliation -> NonReconcilableUnknown`. It explicitly preserves unknown exit/cleanup/output/reap fields and never releases the consumed slot.
- The immutable resolution is written before attempt transitions. A crash between files is resumable: rerun validates the existing resolution and completes missing transitions without rewriting the record. A completed replay is byte-identical and provider-free.

### Opus 5 escalation

- Escalation trigger: two safe evidence-source hypotheses were falsified. Neither the historical runtime files nor current supervision status retained the old `ProcessReapReceipt`; synthesizing it would falsely satisfy `proves_complete_reap`.
- One fresh read-only Claude Code consultation used exact `claude-opus-5`, effort `max`, only Read/Grep/Glob, no GUI and no provider/tool mutation. Session `92385daa-eb32-42ea-bfb5-f125c4cf54d0`; 401.2 s wall, 394.1 s API time, USD 2.776321 reported by Claude CLI.
- Accepted decisions: never synthesize process timestamps/reap receipt; classify both attempts `NonReconcilableUnknown`, not `ReconciledFailed`; keep all missing output/process facts null; write a separate immutable record plus append-only attempt transitions; bind attempted-but-absent ProcessExit/JobObject records; prohibit provider redispatch.
- Opus also found and source inspection confirmed the still-live post-dispatch `Err` branch, invalid Antigravity transition, legacy JSON load incompatibility, `pid:0` ambiguity, lossy sidecar failure and non-atomic in-memory transition mutation. All were repaired before the ARCH-03 gate.

### Historical reconciliation attempts and staging boundary

- First live dry-run stopped before mutation because the canonical role-authority report is a flat v2 close record rather than a recursively embedded revocation event. The parser was corrected from the actual two report schemas; no provider call and no file write occurred.
- Second live dry-run passed attempt/ledger/broker/authority/phase/OS checks but the unpublished debug binary was correctly rejected by daemon IPC as `unattested_cognitive_governor`. This is the intended authority boundary, not bypassed. Actual live reconciliation is deferred until the final versioned candidate is built, attested and activated.
- Both old attempt files remained byte-identical through the dry-runs. Provider calls: 0. GUI calls: 0. `external-agent inspect` now loads the legacy record and confirms `provider_route_policy=null`, `process_exit_at=null`, `cleanup_completed_at=null`.

### Focused results and timings

- `cargo check -p eliot-app --bin eliot-governor`: PASS, 19.2 s after initial implementation; later incremental PASS in 7.5 s.
- `cargo test -p eliot-engine --test provider_timeout_reconciliation`: initial run exposed the stale `Running -> OutputObserved` test matrix; corrected to include `ProcessTerminal`. Final 18/18 PASS, 21.70 s wall, 0.19 s test bodies.
- Added regression coverage for legacy JSON load, immediate process terminal facts, post-dispatch runner error, unknown PID rendering, double persistence failure and restart/no-replay behavior.
- Focused Clippy for app/engine/types all targets: final PASS with `-D warnings`, 24.47 s. Intermediate iterations exposed and repaired a Copy-only declared budget, duplicate MCP match arms, oversized dispatch future and two functions grown by earlier runner migration; no lint suppression was added.
- `cargo test -p eliot-app --bin eliot-governor external_agent`: 3/3 PASS, 76.73 s wall, 0.02 s bodies. The 76 s compile/enumeration penalty is duplicate-main evidence for ARCH-04.
- `cargo test -p eliot-types provider_route_policy` selected zero tests and is excluded from evidence. Corrected `cargo test -p eliot-types --test provider_route_policy`: 2/2 PASS, 0.50 s wall, 0.00 s bodies.
- `git diff --check`: PASS.

## ARCH-04 — remove compatibility construction and duplicate test path

- Moved the pre-unification cognitive provider contract, its MCP/preflight aliases and both legacy schema constants under `eliot_types::external_agent::legacy`. They are no longer re-exported from the crate root or cognitive-field module.
- Preserved historical evidence readback: the cognitive evidence loader may deserialize and validate the legacy contract, but no product or test path constructs a `CognitiveProviderRuntimeContract` value.
- Migrated Codex cognitive preflight and all new cognitive runtime fixtures to the sealed `ProviderRuntimeContract` v2, including exact provider executable hash, MCP tool-profile hash, route-policy hash, output-schema hash, candidate-only scope and Windows Job Object containment.
- Removed the duplicate `[[test]] cognitive_field_runner = src/main.rs` target. The supported path is the single binary test target: `cargo test -p eliot-app --bin eliot-governor cognitive_field_runner::tests`.
- Added the focused `host_runtime::provider_terminalization` owner. The large external-agent orchestrator now delegates post-dispatch supervisor failure, immediate terminal-process persistence and provider-free historical unknown finalization to that owner; process execution remains owned by `supervised_process`, and route-policy construction remains owned by `ProviderRoutePolicy`.
- Source inventory after migration: compatibility provider executors/runners = 0; legacy provider contract struct literals outside its type definition = 0; duplicate main test targets = 0; no new `too_many_lines` allowance was added.
- Problems found and repaired:
  - The first compile exposed an attempted hash of `Result<Value, serde_json::Error>` rather than the resolved schema; the schema is now resolved before serialization and hashing.
  - The first binary-test compile exposed a stale test import from the parent module after moving the current hash helper to `eliot_engine`; the test now imports the canonical helper directly.
  - Strict Clippy rejected a wildcard import inside the new legacy namespace; it was replaced with explicit report-only dependencies.
  - Moving v2 construction into the former legacy builder grew it to 113 lines. The provider argv construction was extracted as a bounded helper instead of adding a new lint allowance.
- Focused results and timings:
  - `cargo check -p eliot-app --bin eliot-governor`: PASS, 22.8 s wall after the schema-hash repair (14.64 s compiler time in the combined run was an earlier successful increment).
  - `cargo test -p eliot-types --test external_agent`: 2/2 PASS, 24.67 s compile, 0.00 s bodies.
  - `cargo test -p eliot-app --bin eliot-governor cognitive_field_runner::tests`: 25/25 PASS, 39.4 s wall, 37.93 s compile, 0.50 s bodies. This confirms removal of the duplicate target while retaining one heavy binary compilation.
  - Focused strict Clippy for `eliot-types` and `eliot-app` all targets: PASS, 24.9 s wall on the final run; `cargo fmt --all -- --check` and `git diff --check`: PASS.

## ARCH-05 / TEST-01 — one composition owner and exact production-route behavior

- Added `host_runtime::ProviderRuntime` as the provider-runtime composition owner. It owns one
  `Arc<dyn ProviderProcessRunner>` and the matching `OperationRuntimeHandle`; production
  construction of `SupervisedWindowsProcessRunner` occurs only in this module. External-agent,
  managed host, cognitive, delegation, dogfood and Antigravity command paths now obtain the runner
  from this owner instead of independently constructing it.
- Deleted the public ad-hoc `SupervisedWindowsProcessRunner::new` constructor. The remaining
  production constructor is module-restricted and is called once by `ProviderRuntime`.
- Split managed Antigravity composition into `managed_provider_process_spec` and
  `dispatch_managed_provider`. The production authority prologue, attempt write and terminal
  closeout remain on the managed path; the shared composition owner supplies the process runner.
  The managed route is intentionally not sent through `AdapterSupervisor`, because doing so would
  duplicate HostBroker/campaign ownership.
- Added a bounded `ExternalAgentAuthorityBoundary` injection seam. Production still performs the
  exact integrity, enqueue, start and canonical-result writes; behavior tests replace only that
  authority boundary while retaining the real adapter preparation, campaign reservation,
  terminalization, capture, parser and result normalization path.
- Extended the test-only `ScriptedProviderProcessRunner` with outcome queues, virtual delay, call
  count and exact `ProviderProcessSpec` capture. No real model or subprocess is used by B1-B8.
- Made `ProviderInvocationJournal::create` create-only (`create_new` plus file sync). B3 exposed
  that a repeated identical adapter request previously overwrote the original terminal attempt
  with a fresh `Prepared` record before the reservation owner rejected redispatch. The journal now
  preserves the original terminal process evidence and fails closed on duplicate creation.
- Missing pre-created provider campaigns now resolve to the typed `CampaignClosed` reservation
  decision. This lets the adapter durably transition the already-created attempt to
  `PreDispatchAborted`; previously the owner returned an untyped error and left a nonterminal
  prepared attempt even though the runner was correctly blocked.

### Opus 5 consultation

- Escalation trigger: B2 showed that one runner implementation still had eight independent
  production constructions, and the managed route created its runner inside the function under
  test. This was an owner/abstraction decision, so it met section 10 rather than being guessed
  locally.
- One fresh read-only Claude Code consultation used exact `claude-opus-5`, effort `max`, only
  Read/Grep/Glob, no GUI, no writes and no provider dispatch. Wall time: 432.2 s.
- Accepted: a small `ProviderRuntime` composition owner, shared injection into both external and
  managed routes, a production-exact managed process-spec/dispatch split, and Tokio virtual time
  for B1.
- Accepted with verification: B2 proves the external half through
  `AdapterRegistry -> AdapterSupervisor -> adapter` and the managed half through the exact
  production managed helper while sharing the same injected owner/runner.
- Rejected as architecturally incorrect: routing managed execution through `AdapterSupervisor`;
  that would double-book broker and campaign authority. Opus explicitly called this out and source
  inspection confirmed it.
- Deferred cleanup only: moving the authority seam out of the large external-agent file may improve
  layout later, but it is not a second runtime owner and is not required for the bounded task.

### B1-B8 attempts, problems and results

- The first combined B1/B3/B4/B5 attempt failed before dispatch because the fixture created a
  different `work_item_id` in invocation and launch authority. The fixture was corrected to bind
  one ID; product validation was not weakened.
- The first B1 retry hit the outer supervisor deadline because 200 ms of scaled absolute time was
  shorter than real preparation/file-system work. Added Tokio `test-util` only as a dev feature and
  used paused virtual time: the scripted provider advances six virtual seconds while the route
  retains an eight-second first-output and ten-second absolute policy.
- The first B3 retry exposed the journal overwrite defect described above. After create-only CAS,
  the second request performs zero provider calls and preserves `NonReconcilableUnknown` plus the
  complete reap receipt.
- B1/B3/B4/B5 corrected run: 4/4 PASS, 19.5 s wall including about 16 s compilation, 0.32 s test
  bodies. B2 corrected run: 1/1 PASS, 26.4 s wall including about 23 s compilation, 0.12 s body.
- The first full 8-case run selected exactly eight tests: 5 passed and 3 failed. Wall 41.12 s,
  compile 39.32 s, bodies 1.09 s. The failures were all actionable:
  - B6 compared the sealed, sorted/deduplicated Claude tool aliases with request-order aliases;
    the test now compares against the same canonical exact set while retaining profile hash checks.
  - B7 expected a raw `Err`, but `AdapterSupervisor` correctly normalized the adapter error into a
    failed `AdapterResult`. The test now checks the public result and led to the real missing-campaign
    terminalization repair above.
  - B8 scanned its own string literals and counted the legacy struct definition/impl as runtime
    construction. The source gate now excludes its own test module and distinguishes the one type
    definition from forbidden struct literals.
- Corrected individual B6/B7 results: PASS in 2.38 s and 0.07 s bodies. B8 required two assertion
  precision corrections, then passed in 0.01 s body; these were source-gate mistakes, not product
  regressions.
- Final combined `cargo test -p eliot-app --bin eliot-governor provider_runtime`: 8/8 PASS,
  1.70 s wall, 1.47 s bodies, 203 unrelated tests filtered out.
- B1 proves delayed valid Antigravity output beyond the former five-second boundary. B2 proves one
  injected runner and policy owner across external and managed routes. B3 proves terminal timeout,
  reap and no replay. B4 proves invalid exit-0 JSON is terminal `ProtocolParseFailed`. B5 proves one
  canonical result with forced complete reap. B6 runs all nine Claude/Antigravity/OpenCode ×
  Worker/Reader/Judge combinations through the normal adapter chain and checks exact policy/profile
  IDs, hashes, tools and runner specs. B7 proves no adapter-owned campaign maximum and zero runner
  calls without controller pre-creation. B8 proves the bounded source inventory.
- Performance observation: the final eight behavior bodies are far below the task's ten-second
  target. The recurring 10–40 s cost is Rust binary-test compilation/linking, not the scripted
  cognitive behavior. No evidence currently justifies a separate test-performance investigation.

### Section 9 focused gate

- `cargo test -p eliot-types provider_route_policy`: command exited successfully but selected zero
  tests across all targets after 22.25 s compilation/enumeration. Per the task contract it is not
  acceptance evidence. Corrected `cargo test -p eliot-types --test provider_route_policy`: 2/2
  PASS, 0.14 s wall, 0.00 s bodies.
- `cargo test -p eliot-engine provider_invocation`: 1/1 matching unit test PASS; 73.28 s wall,
  approximately 61 s compilation plus enumeration of every integration-test executable. The
  behavior body was 0.00 s. This filter shape is a test-infrastructure cost worth retaining in the
  report; it is not a slow provider-runtime behavior.
- `cargo test -p eliot-engine adapter`: 23 matching tests across targets, 22 PASS and one
  authenticated-SurrealDB test ignored; 3.52 s wall. The principal adapter target ran 21 PASS and
  one ignored in 0.10 s.
- `cargo test -p eliot-app --bin eliot-governor provider_runtime`: 8/8 PASS, 1.70 s wall and 1.47 s
  bodies.
- `cargo test -p eliot-app --bin eliot-governor external_agent`: 11/11 PASS, 1.68 s wall and 1.45 s
  bodies.
- `cargo test -p eliot-app --bin eliot-governor managed`: 17 PASS and one environment-dependent
  daemon test ignored, 5.10 s wall and 4.27 s bodies.
- `cargo test -p eliot-windows-ipc supervised_process`: 3/3 PASS, 3.66 s wall including 2.92 s
  compilation, 0.43 s bodies.
- `cargo fmt --all -- --check`: PASS, 1.85 s. `cargo check --workspace --all-targets`: PASS,
  31.59 s.
- First workspace Clippy run failed after 36.47 s on three new test-only `expect_used` findings:
  two poisoned mutex locks and one fixture length conversion. They were replaced with poisoned
  guard recovery and a non-panicking conversion; no lint suppression was added. Corrected
  `cargo clippy --workspace --all-targets -- -D warnings`: PASS, 22.19 s.
- Final `cargo fmt --all -- --check`: PASS, 1.70 s. `git diff --check`: PASS, 0.07 s.

## Section 11 — versioned candidate, historical reconciliation and live routes

### Candidate activation and integrity

- Committed and pushed ARCH-05 as `e18811953451138e3d6647f0d389c4edc7ca8447` on
  `codex/cognitive-completion-v2`. The pre-existing untracked `.eliot/` directory remained
  untouched and was not staged.
- Built a clean-tree release candidate into the new immutable target
  `C:\Users\kleym\AppData\Local\Eliot\builds\provider-runtime-e188119-target`.
  Full release build: 203.70 s. Binary size: 55,431,680 bytes. SHA-256:
  `9c98d96a1aa6b1982e1236117fd928283cabf805dda4486f5e6f99a24e71e87c`.
- Verified the exact 40-character source commit is embedded in the candidate image. Before
  switching, the old `authority-lc-7bb7c8f` daemon reported `overall=ready`,
  `provider_dispatch_safe=true`, zero active/awaiting/cleanup/orphan operations and clean runtime
  and authority integrity.
- Stopped the prior PID 57380 through `daemon stop --instance default`, then started the candidate
  hidden through the normal standalone daemon route. New PID: 18336. Publication path and SHA
  exactly match the candidate; daemon status/doctor are ready.
- Post-activation `runtime supervision status` reported `overall=ready`,
  `provider_dispatch_safe=true`, active/awaiting/cleanup/orphan counts all zero, clean locked
  binary SHA equality, zero orphan/pending role leases and zero partial seals.
- Provider-free Antigravity MCP preflight passed with `provider_calls=0`, GUI unused and the exact
  seven-tool `external_auditor` catalog surface. This also proved that preparation and authority
  close work on the activated candidate before spending a model call.

### Historical Antigravity reconciliation

- Reconciled these two pre-ARCH-03 attempts:
  - `external-agent-attempt-external-agent-smoke-antigravity-019fba9d-aa12-7cc2-a528-9d07fbfd2db8`;
  - `external-agent-attempt-external-agent-smoke-antigravity-019fbaa6-ed08-7963-8414-121454c64021`.
- Both dry-runs returned `provider_calls=0`, redispatch forbidden and proposed
  `NON_RECONCILABLE_UNKNOWN`; the attempts remained `RUNNING` with null exit, cleanup and reap
  fields. The provider-call ledger SHA stayed
  `2bc9b982b32f4fd49236c7f03bbc89afcab6b925e9b6af68362c6bb671c54573`.
- Apply wrote one immutable resolution per attempt and transitioned each through
  `TimeoutPendingReconciliation` to `NonReconcilableUnknown`. No process fact was synthesized;
  exit/cleanup/reap remain null, provider calls remain zero and the consumed ledger is byte
  unchanged.
- A second apply returned `idempotent_replay` for both. Attempt and resolution SHA-256 values were
  byte-identical to their first applied state.

### Current-state live smokes

- Claude `claude-opus-5`: PASS, one provider call, 54.89 s wall. Smoke
  `external-agent-smoke-claude-019fbc29-55b6-7e83-8f98-8c2e12d93242`; policy ID
  `provider-route-policy-v1:claude:external-agent-smoke:962880c74cb36693`, policy hash
  `962880c74cb366930f835a58ade7c3b9dda132dbd71d91670312ac0dcb956d59`.
  PID 76312, process elapsed 12,852 ms, real exit/cleanup timestamps, Job Object process count
  43 -> 0, complete reap and terminal `ReviewNormalized`.
- Antigravity `gemini-3.6-flash-high`: PASS, one provider call, 63.03 s wall. Smoke
  `external-agent-smoke-antigravity-019fbc2b-42d2-7243-9976-6bb354eb0066`; policy ID
  `provider-route-policy-v1:antigravity:external-agent-smoke:feedec7571425763`, policy hash
  `feedec7571425763dbe32d4a79d98aff739afa256019a65e28229bb6397793db`.
  PID 78464, process elapsed 21,835 ms, real exit/cleanup, complete reap and terminal
  `ReviewNormalized`.
- OpenCode `opencode/mimo-v2.5-free`: PASS, one provider call, 62.16 s wall. Smoke
  `external-agent-smoke-opencode-019fbc2c-8da4-7441-8277-faba2be54f22`; policy ID
  `provider-route-policy-v1:opencode:external-agent-smoke:372d93a825f8905f`, policy hash
  `372d93a825f8905f064e687d9047e5bf928016b5ad7fc8cec01fec9c5956dd47`.
  PID 13200, process elapsed 12,783 ms, real exit/cleanup, complete reap and terminal
  `ReviewNormalized`.
- All three resolved the exact requested model, invoked provider-owned `eliot_current_state`,
  returned schema-valid project/task/revision/model JSON and bound the same catalog-owned
  `external_auditor` profile/hash
  `8980ad8052aef150d6c36a782e349444c9d8c39634c368fc938a97775962a6e3`.
- All three used first-output/absolute deadlines 120,000/120,000 ms, cancellation grace 100 ms and
  cleanup grace 5,000 ms. Contract/evidence policy hashes match exactly. Each authority report has
  canonical revoked-role, retired-binding and terminal-job receipts.
- Repaired retries used: zero for Claude, Antigravity and OpenCode.
- Final operations doctor after the three calls: `overall=ready`, runtime clean, expected/observed
  governor SHA equal, active/awaiting/cleanup/orphan operations all zero, active/pending/orphan role
  leases zero and partial seals zero. Provider root PIDs 76312, 78464 and 13200 are absent from the
  OS process table.
