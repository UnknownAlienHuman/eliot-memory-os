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

## Automatic continuation — Task 02R2 recovery checkpoint

- Re-read the Recovery Plan v3.0 checkpoint and current source history. The old execution report
  stops at the P009 legacy-admission blocker, but source commit `8d2db4a` already contains the
  tuple-exact U03 repair and the later runtime-supervision work contains the typed partial-seal
  recovery. No duplicate P009 implementation was started.
- Inspected `cq-core-20260730-006` without modifying its evidence. Generation 1 is explicitly
  `abandoned`; recovery state is `complete`; all four sessions and leases were retired, all eight
  staged files were hash-preservingly quarantined, fresh state reload found no matching live
  authority, and the receipt authorizes replacement generation 2. Fresh run006 provider calls
  remain zero.
- Reused the existing Opus 5 decisions instead of spending a duplicate consultation. Those
  decisions required staged publication, typed authority compensation, explicit non-projection
  proofs and generation-2 continuation of run006 when no provider evidence exists. The applied
  recovery receipt satisfies those conditions.
- Found a new projection-recovery issue before sealing: the ignored public report roots for
  `cq-core-20260729-003`, `cq-core-20260730-005` and `cq-core-20260730-006` are absent from the
  working copy and from every Git/archive ref, while the complete private roots and run006's
  abandoned-seal record remain present. Run006's role-evidence plan still binds absolute public
  verifier/report references, so sealing must fail closed until those projections are restored or
  a typed private-evidence recovery path is implemented.
- Ran a zero-provider, zero-authority reconstruction probe using `cognitive-field prepare` against
  a new scratch report root. It passed in 2.841 s and produced the expected three-case suite and
  9e6d916 product worktree bindings. This proves the public prepare projection is reproducible,
  but the generated contract has a new output root/timestamp/hash and therefore is not accepted as
  recovery evidence for the immutable original run. No provider session or model call was made.
- Next action: establish a provenance-preserving recovery design for the missing public projections
  before generation-2 dry-run seal. Ad-hoc recreation or weakening role-evidence checks is
  forbidden.
- Escalated the projection-loss decision once to Claude Code `claude-opus-5` at `max`, with only
  Read/Grep/Glob, plan permission mode and a strict empty MCP configuration. Session
  `57aae3d9-c309-474e-9728-49fa6bd63d63` completed in 388.2 s wall / 385.3 s API time and reported
  USD 1.692341. No write, MCP or provider tool was available to the consultation.
- Opus classified this as recoverable projection loss only when every published byte is checked
  against a surviving pre-loss commitment. The existing verifier must remain unchanged;
  restoration must be typed, staged, create-only, idempotent and fresh-read verified. It confirmed
  run006 generation 2 remains conditionally valid after exact restoration.
- Opus identified one hard gap: historical `preflight.json` carries a contamination-clean claim
  but no known independent pre-loss digest. Regenerating it from the current binary would be a
  self-certification loop. Unless an independent digest-bound copy/attestation can be recovered,
  the U03 reuse chain remains blocked. The next recovery probe is therefore exact-byte recovery
  from the OneDrive deletion history, not code that admits reconstructed evidence.
- The local Recycle Bin and all local/Git/archive references contained no copy of the public roots.
  The OneDrive web route is authenticated in Chrome, but Microsoft interrupted navigation with the
  account-security confirmation page (`Is your security info still accurate?`). No account action
  was taken. The exact tab was left as a user handoff because confirming account recovery/security
  details is outside autonomous repository authority. After the operator confirms the page, the
  next bounded action is a read-only search of OneDrive's recycle history for the three exact run
  roots, followed by create-only restoration if found.

## Automatic continuation — Task 02R2 projection restoration and runtime-profile repair

### Provenance-preserving projection restoration

- After the operator completed Microsoft's account-security confirmation, OneDrive Recycle Bin
  contained exactly one deleted `cognitive-field` folder at the original
  `eliot-memory-os/reports` path (3.23 MB). The exact row was restored through the authenticated
  OneDrive UI; OneDrive reported `Restored 1 item` and the recycle row count became zero.
- Local sync restored the original public projections without reconstruction: run003 has 14
  files, run005 has 29 files and run006 has 11 files. Ten SHA-256 references extracted from
  run006 `core-role-evidence.json` all resolve and match exactly (10/10), including the reused
  run003/run005 verifier receipts and private exposure receipts.
- Exact-root `seal-status` passed in 1.387 s with `ALREADY_ABANDONED`, zero provider artifacts,
  zero provider results and generation 1 still abandoned. A first invocation used the parent
  report/private roots and failed in 0.024 s with OS error 2; correcting the CLI path shape to the
  exact run roots resolved it without data changes.

### Canonical MCP-profile defect and bounded Opus consultation

- Generation-2 `seal --dry-run` against the prior clean candidate failed in 1.188 s with
  `write rejected: provider MCP tool profile differs from the canonical catalog`. ARCH-02B had
  hard-coded `legacy-cognitive-reader` in the cognitive runner while the consolidated provider
  boundary recomputed the catalog-owned profile from purpose.
- An initial local correction proved incomplete: assigning external Readers to
  `ExternalAuditor` admitted a seven-tool profile with write-capable candidate/packet tools, and
  assigning the Codex runtime to `CognitiveChild` failed the exact runtime binding because its
  four-tool profile differs from the seven-tool Codex Worker contract.
- Escalated once to Claude Code `claude-opus-5` at `max`, read-only plan mode, strict empty MCP and
  only Read/Grep/Glob. Session `10c8dc86-596f-406d-a11b-15c617370e68` completed in 399.6 s over
  30 turns, cost USD 2.7921415, with no permission denial and no write. Opus approved canonical
  `CodexWorker`, rejected `ExternalAuditor` as the treatment/control fix and identified the exact
  tool-set mismatch. It left the treatment/control profile split as the controller decision.
- Implemented the systemic split: catalog-owned `understanding_reader` exposes exactly
  `eliot_current_state`, `eliot_fetch_l2`, `eliot_memory_influence_trace` and `eliot_recall_l0`;
  `MemoryFreeControl` resolves to the existing empty `cognitive_control` profile and sets
  `ELIOT_COGNITIVE_CONTROL=1`; Codex resolves to canonical `codex_worker`. Purpose is the sole
  central profile selector and `prepare_governed` retains strict profile equality.

### Dry-run side-effect defect and repair

- The first repaired candidate (`ADE4E38BA70633FE34D4496055C8302ACD26E0C9D735223DD7E781F38D9AB6BC`)
  passed generation-2 dry-run in 5.835 s with `authority_side_effects=0`, but a complete before/after
  SHA inventory detected one private mutation: Antigravity `.agents/mcp_config.json` was
  overwritten during preview. Public files were 11/11 identical; the private count stayed 1561
  but hashes differed. Real sealing and all providers remained fenced.
- Root cause: runtime preview and dispatch called the same MCP materialization path. Preview could
  write Claude/OpenCode runtime configs, Antigravity workspace config, global permission changes
  and a permission receipt before the later `dry_run` branch.
- Split preparation into `Preview` and `Dispatch` modes. Both compute the identical sealed paths,
  command and runtime contract, but only Dispatch may create directories, materialize provider MCP
  files or merge Antigravity permissions. The regression test proves Antigravity preview preserves
  an existing governed config byte-for-byte and creates no invocation root.
- Rebuilt provisional release SHA
  `B68D75641582F628DB49E01B94CA2865F274DDD2A3EBAB7910A0A7BDBA4FDA7B` and repeated the exact
  run006 generation-2 dry-run in 6.539 s. Result: PASS, `authority_side_effects=0`, public 11/11
  identical and private 1561/1561 identical. The planned seal ID is
  `provider-plan-seal:seal-d30199d14e30e6a9-g2`; no provider call was made.

### Focused verification and duration evidence

- Profile/runtime focused tests: six requested checks passed. The combined cold command took
  121 s; the first app compile/link consumed about 91 s while the longest behavior body was
  0.44 s. Public-enum compatibility added 2/2 PASS in 13.04 s compile-dominated wall time.
- Preview side-effect regression: 1/1 PASS; 36.80 s wall with 35.87 s compilation and 0.05 s body.
  Clean isolated release build took 213.36 s; incremental rebuilds took 121.68 s. These timings
  indicate Rust compile/link cost, not slow cognitive behavior.
- Task02R2 contract gates: cognitive field contract 2/2 PASS (1.322 s), secret boundary 5/5 PASS
  (12.475 s enumeration/compile), cognitive grading 4/4 PASS (1.921 s), cognitive CLI 2/2 PASS
  (0.977 s), format PASS (1.782 s), workspace all-target check PASS (36.069 s), workspace all-target
  Clippy with warnings denied PASS (50.365 s), diff-check PASS (0.074 s).
- The literal recovery-document command `cargo test -p eliot-app --test cognitive_field_runner`
  fails immediately because that integration target does not exist and has never existed in Git.
  No empty compatibility target was fabricated. The real same-named binary unit module was run as
  `cargo test -p eliot-app --bin eliot-governor cognitive_field_runner::tests::`: 25/25 PASS,
  0.927 s wall and 0.60 s bodies. This is recorded as a recovery-document command defect, not a
  product-test failure.
- Two tool invocations were prematurely killed by an accidentally short orchestration timeout
  before useful results (one release build start and one focused-test start). Both were rerun with
  bounded explicit limits; neither was a code/test failure and neither consumed a provider call.

### Commit-bound candidate and zero-model cutover

- Committed and pushed the runtime/profile repair as
  `69d5fb966d97e239b2567ac520659ac149ed7730` with the required subject
  `C7-02R2: bind cognitive provider runtime and resumable role evidence`. The pre-existing untracked
  `.eliot/` directory remained unstaged and untouched.
- Built a clean-tree immutable release under
  `C:\Users\kleym\AppData\Local\Eliot\builds\cognitive-profile-69d5fb9-target` in 220.60 s.
  Binary size is 55,439,872 bytes; SHA-256 is
  `25b435e3b0add2dabab2c6292d877b85dfd75d5ca06cb5f810cee5836a4148fb`; the full 40-character
  source commit is embedded in the image.
- First zero-model preflight attempt failed closed in 0.772 s with
  `unattested_cognitive_governor`: the standalone daemon still locked the prior `e188119`
  candidate. Pre-cutover runtime supervision was ready/clean, dispatch-safe and had zero
  active, stuck, awaiting-reconciliation, cleanup-pending or orphan operations.
- Cooperatively stopped old PID 18336 and started the commit-bound candidate hidden through the
  normal standalone daemon route. New PID 68272 published the exact expected path/SHA. Doctor is
  ready; runtime integrity is clean; expected and observed SHA match; partial seals, orphan
  processes and pending/orphan role leases remain zero; provider dispatch is safe.
- Second real zero-model preflight passed in 6.251 s internal / 6.532 s command wall. It proved
  Codex configuration listing, Governor MCP process start and initialize, exact seven-tool
  `codex_worker` surface, absent/disabled raw SurrealDB and a scoped status read. Runtime contract
  hash is `ca119c16fb008fe87dd2450e880abafccc4e6b7b83c6b05ea03b81e064094b63`; receipt file SHA-256 is
  `11d6c78a8da0644439b9adf5b89f48d7e3ecffec5cdb6c909ad9a8147c3d5118`. No provider session,
  provider call or model token was consumed.
- Final commit-bound run006 generation-2 dry-run passed in 5.280 s. Public 11/11 and private
  1561/1561 SHA inventories were byte-identical before/after, and `authority_side_effects=0`.
  Plan hash is `blake3:38c3fc794e802f34fb871b9f0563fe25f9b4daa834ce1814daf15058759e87b7`;
  staged manifest SHA-256 is
  `4d6e579ee13cd6d133e3147b2dc4d9196a097e083c0f2ae589f6358ffe3d08db`.

### Generation-2 activated failure and reused-Judge repair

- The real generation-2 seal failed after 15.044 s during publication with the exact error
  `Judge output binding is invalid`. No provider process was started. Transactional compensation
  completed: generation 2 is `abandoned`, all four minted leases were revoked, all four work items
  and operation jobs were terminalized, the plan was not published, provider reservations/results/
  artifacts remain zero, partial seals remain zero and replacement generation 3 is authorized.
  The typed failure receipt is `abandoned-seals/seal-d30199d14e30e6a9-g2.json`; it is preserved.
- Generation-2 residue is bounded and explicit: byte-identical reused Worker/Reader files exist in
  both U03 execution roots; `judge.json`, `reused-roles.json` and `source-deterministic.json` do not.
  Current run006 deterministic SHA-256 values remain
  `8854ad77a8b5932878cced8a37c8133216271461c584bb71f0f3e547867c9ef6` (treatment) and
  `907770e564185ee3fe8fca415b900583947f9908e092f2a42585ef8fa4af4d3f` (control).
  The 29-file run005 public inventory snapshot digest is
  `48286eb2546b7e124903dacfab7e3fe321857c7a26de9eab4aa0e324dd9e3bea`.
- Root cause: deterministic report hashes are intentionally run-scoped because every hard-gate
  record binds the current run's contract and deterministic receipt. The immutable run005 Judge
  correctly binds the run005 source deterministic hashes, while publication incorrectly assumed
  every Judge must bind the current run006 hashes. Source evidence was valid; the harness lacked a
  typed cross-run binding.
- Escalated this single architectural contradiction to Claude Code `claude-opus-5` at `max`, with
  read-only plan permission, strict empty MCP and only Read/Grep/Glob. Session
  `8ad52c31-8199-45bb-9c5f-c3727258640d` completed in 384.6 s / 381.2 s API time over 23 turns,
  cost USD 2.14080075, with no permission denial, MCP, write or provider call. A first CLI start
  received no prompt and exited locally in 2.4 s before any API request; it consumed no quota.
- Opus confirmed a product/harness contradiction, not corrupt evidence, and approved generation 3
  with zero repair provider calls. Rejected fixes include rewriting Judge bytes, copying source
  deterministic truth over run006, weakening hash checks, accepting arbitrary prior hashes,
  transplanting grades or rerunning U03.
- Implemented a typed reused-Judge deterministic binding. Run006 keeps its freshly derived
  `deterministic.json` as sole current truth. Exact source bytes are published separately as
  `source-deterministic.json`; the reuse projection records source/current hashes, source byte
  SHA-256 and an auditable field-equivalence record. Equivalence requires full report identity
  after normalizing only `report_hash` and non-empty run-scoped `hard_gate_evidence.evidence_refs`.
  Engine grading re-derives equivalence from bytes and never trusts the projection's verdict.
- Added pre-authority validation to `verify_accepted_prior_role`, closing the dry-run coverage gap:
  a non-equivalent reused Judge now fails before authority activation. Materialization preserves
  current deterministic bytes with a before/after assertion; missing, foreign or tampered source
  provenance fails closed. `CognitiveJudgeResult`, its schema and historical run005 files are
  unchanged.
- Focused verification after the repair: engine grading 7/7 PASS (including equivalent, divergent
  and missing binding cases); runner module 26/26 PASS (including different run-scoped hashes,
  current-truth immutability and tamper rejection); CLI 2/2 PASS; types contract 2/2 PASS; secret
  boundary 5/5 PASS. Behavior bodies were 0.76 s or less. Format PASS, workspace all-target check
  PASS in 21.56 s. First Clippy pass found four test-only `assigning_clones`; all were corrected
  with `clone_from` and no suppression. Final all-target Clippy PASS; diff-check PASS.

### Generation-3 candidate and pre-activation proof

- Committed and pushed the reused-Judge repair as
  `051d89b3acc1e2eb4573f082e9f14f567fa9e91c` (`C7-02R2: bind reused Judge deterministic
  provenance`). Built a new clean-tree immutable release in 216.65 s under
  `C:\Users\kleym\AppData\Local\Eliot\builds\cognitive-judge-051d89b-target`; size 55,578,624
  bytes, SHA-256 `e40994cb5f4c3735489edb80f7f614c0809d8529ad03e0faaf4437d852663a25`, exact source commit
  embedded.
- Pre-cutover runtime was quiescent and dispatch-safe. Cooperatively stopped PID 68272 and started
  the new candidate hidden as PID 17052. Publication path/SHA match the immutable candidate.
- Commit-bound zero-model preflight passed in 4.301 s internal / 4.588 s wall. Runtime contract hash
  is `e1df0d56fba0b386cb7386781c4ba33a8f7f549e053bf8125d75c0b14f372835`; Governor MCP initialized,
  the exact seven-tool Codex Worker surface was present, raw SurrealDB was disabled and scoped status
  read passed. Provider/model calls: zero.
- Generation-3 dry-run passed in 6.306 s after re-validating source/current U03 deterministic
  equivalence before authority activation. It planned seal
  `provider-plan-seal:seal-1836b600695333ba-g3`, plan hash
  `blake3:5f888363479263c2fbe8c39a3f15037ca3fd3ccc3d9ca8268e895855d30f8687` and manifest SHA-256
  `c1e09424ad08821fd759db844e28a0748d1ffb8553dcc040bfda25dd73fcfad3`.
  `authority_side_effects=0`; public 16/16 and private 1587/1587 file SHA inventories were identical
  before/after.

### Generation-3 publication and A1-A16 readback

- The real generation-3 seal succeeded in 10.704 s. It published exactly eight fresh provider
  calls and four reused roles, with zero smoke calls. Seal ID, plan hash and manifest SHA-256 are
  byte-identical to the dry-run values above. Seal status reports generation 3 as `published`;
  generations 1 and 2 remain abandoned, and no provider reservation or provider result existed at
  publication time.
- Post-publication A1-A16 readback passed. The historical run005 29-file inventory remained
  byte-identical with digest
  `48286eb2546b7e124903dacfab7e3fe321857c7a26de9eab4aa0e324dd9e3bea`. Every U03 scenario has
  exactly three reused-role projections: Worker is byte-equal to run003, Reader and Judge are
  byte-equal to run005. The treatment/current deterministic hash is
  `blake3:1cd2e52...` versus source/Judge `blake3:c7b991f...`; control/current is
  `blake3:804317ce...` versus source/Judge `blake3:f7cf1db...`. In both scenarios the projected
  source byte SHA, current binding and re-derived equivalence are true. The only normalized
  differences are `report_hash` and run-scoped `hard_gate_evidence.evidence_refs`. Provider result
  count remained zero.
- The exact eight fresh calls are: Codex Worker and Judge for U06; Antigravity Reader treatment and
  control for U06 using `gemini-3.6-flash-high`; Codex Worker and Judge for U11; and OpenCode Reader
  treatment and control for U11 using `openai/gpt-5.4`. Run006 contains no Claude call.

### Runtime-integrity pre-dispatch failure and repair

- The first external attempt targeted the U06 Antigravity treatment call
  `063d32a3-7779-44e8-90c7-b6a8cc83b44f`. It failed before provider dispatch in 3.874 s adapter /
  4.864 s wall with
  `write rejected: runtime integrity blocks external provider dispatch: published_plans_without_authority`.
  No provider process, session, reservation, result or call-budget consumption occurred; the
  outcome is a known retryable pre-dispatch failure, so it must not be retried until integrity is
  repaired.
- Runtime supervision reproduced the failure with core ready, the expected commit-bound candidate
  still running as PID 17052, zero active/stuck/reconciliation/cleanup operations, zero orphan
  processes, four active generation-3 role leases, zero pending/orphan leases and zero partial
  seals. The sole failing counter was `published_plans_without_authority=1`; provider dispatch was
  correctly fail-closed.
- Exact record/lease correlation disproved missing authority: the published generation-3 seal
  contains exactly the same four active lease IDs. Root cause is a filename/provenance defect in
  `scan_seal_inventory`: it searched for `provider-plan.json` inside the private immutable
  `published_root`, while the seal protocol atomically publishes that root with the canonical
  artifact name `candidate-provider-plan.json`; the public `provider-plan.json` is a separate
  projection. Thus every correct new seal was classified as missing its plan.
- The repair validates the actual immutable `candidate-provider-plan.json` and requires its byte
  SHA-256 to equal the seal record's `provider_plan_sha256`; mere file presence is no longer
  accepted. A focused regression proves the exact published candidate plus active generation lease
  is clean, then byte-tampers the candidate and proves fail-closed detection. The behavior body
  took 0.02 s; first compile/test wall time was 24.487 s. The complete runtime-integrity module
  passed 5/5 in 0.05 s behavior / 0.280 s wall, format passed, and package binary Clippy with
  warnings denied passed in 27.983 s. No Opus call was spent because the exact local cause and
  bounded systemic correction were unambiguous.
- Committed and pushed the repair as `2e6db2adca2d7418bbc33a6f30bf9d8fca7592f9`
  (`C7-02R2: bind seal integrity to immutable plan`). A clean-tree isolated release build took
  217.870 s and produced
  `C:\Users\kleym\AppData\Local\Eliot\builds\runtime-integrity-2e6db2a-target\release\eliot-governor.exe`,
  55,529,472 bytes, SHA-256
  `781c9b352b96ac344c4c867e37dbde81873a716516292c4ce8a8ca985c4c7ab3`; the exact 40-character
  source commit is embedded.
- With operations and orphans still zero, PID 17052 was stopped cooperatively and the new binary
  started hidden as PID 85320. Publication and doctor are ready with the exact expected path/SHA.
  Runtime supervision then reported `overall=ready`, `provider_dispatch_safe=true`, clean runtime
  integrity, the same four active generation-3 leases, and both
  `published_plans_without_authority=0` and `authority_without_published_plan=0` in 3.574 s.

### Published-seal runtime drift and Opus supersession decision

- With generation 3 still published, reservation/result counts still zero and runtime supervision
  clean, the same Antigravity call `063d32a3-7779-44e8-90c7-b6a8cc83b44f` was retried once. It
  failed before provider launch in 0.412 s with
  `production adapter preview differs from the sealed cognitive runtime`. No provider process,
  reservation, result or quota-bearing model call occurred.
- Exact comparison explains the fail-closed result: generation 3 immutably seals the former
  Governor path/SHA (`cognitive-judge-051d89b-target`, `e40994cb...`), including
  `ELIOT_GOVERNOR_EXE` and the MCP server executable binding. Production preview correctly sees
  the repaired active candidate (`runtime-integrity-2e6db2a-target`, `781c9b35...`). Reverting to
  the old daemon restores the known integrity defect; weakening equality or rewriting the
  generation-3 artifacts is forbidden.
- Escalated this post-seal transaction contradiction once to Claude Code `claude-opus-5` at
  `max`, read-only plan mode, strict empty MCP and only Read/Grep/Glob. Session
  `087e8571-fb33-433e-9cef-84a3b1f71fb5` completed in 604.6 s / 599.4 s API over 39 turns, cost
  USD 4.273312, with no permission denial, write, MCP, web or provider action.
- Opus selected one generic repair: an operator-authorized, fail-closed pre-dispatch Published-seal
  supersession transaction. It is admissible only after authoritative proof of zero reservations,
  results, journal attempts, receipts, artifacts and non-terminal operations; exact active
  generation authority; byte-exact plan/seal bindings; and runtime drift limited to the Governor
  executable binding. It revokes authority, retires sessions/jobs/work, marks generation 3
  abandoned, digest-verifies and moves immutable seal/public-plan bytes into quarantine, then
  permits a separate generation-4 seal. Exact runtime equality remains unchanged.
- Two latent prerequisites were identified for source verification: recovery inspection currently
  reads the broker reservation mirror rather than the authoritative reservation ledger; and the
  generation-independent invocation/idempotency keys can select an abandoned older job/request
  unless replay is generation-exact under a strict zero-attempt supersession fence. Call IDs and
  idempotency keys must remain stable across generation 4 so the durable double-spend guard stays
  armed; leases, sessions, jobs, epochs, seal IDs and runtime hashes must be re-minted.

### Supersession implementation and verification checkpoint

- Source verification confirmed both latent defects. One Opus detail was corrected against current
  code: `abandon_operation` intentionally writes `result_ref=abandoned:<reason>`, not `None`.
  Generation replay therefore requires `Abandoned`, `attempt=0`, an exact typed abandoned result,
  and the referenced lease already `Revoked`; attempted, unknown-outcome, result-bearing or
  non-revoked prior authority remains blocked.
- Added `cognitive-field supersede-seal --dry-run|--apply`. Its read-only classification requires
  byte-identical public/private plan bindings, exact Published seal/session/lease/job/work sets,
  zero authoritative ledger reservations, zero results, zero provider journal/reconciliation
  attempts, zero private provider artifacts, zero nonterminal operation checkpoints, zero
  incomplete seal staging and runtime differences limited to the Governor MCP command/SHA/source
  binding plus derived runtime hash.
- Apply first writes a typed `eliot-published-seal-supersession-v1` intent, then resumably revokes
  leases, retires sessions, abandons zero-attempt jobs, revokes WorkItems, marks the old seal
  Abandoned, digest-verifies and moves the immutable generation root and public plan to quarantine,
  fresh-reloads every store, and marks the intent Complete. Failpoints cover intent, authority,
  seal-state, generation-move and public-plan steps. Reused role projections remain in place. A
  separate later seal creates generation 4.
- Runtime supervision now classifies `published_seal_runtime_drift`, blocks provider dispatch, but
  permits the daemon to boot in this single recovery-only state. Exact dispatch runtime equality is
  unchanged. `ProviderCallReservationOwner::snapshot_read_only` avoids creating a ledger/lock on a
  dry-run; legacy recovery now also reads this authoritative ledger instead of the broker mirror.
- Generation-exact HostBroker replay preserves stable logical call/idempotency keys only when all
  lower-generation jobs are exact abandoned zero-attempt authority with revoked leases and no
  result. Seal activation updates a stale `AgentInvocationRequest` only under the same fence.
  Cognitive external execution now opens its sealed one-call campaign before adapter reservation;
  without this missing controller step the next real call would have failed `CampaignClosed`.
- Focused tests: cognitive runner 28/28 PASS (0.97 s behavior / 43.588 s compile-dominated wall),
  runtime integrity 5/5 PASS (0.64 s / 1.435 s), provider ledger 10/10 PASS (0.82 s / 3.690 s),
  host integration 13/13 PASS (0.02 s / 3.289 s), cognitive CLI 2/2 PASS (1.84 s / 58.816 s).
  The new crash test fails after seal-state transition, resumes to complete digest-verified
  quarantine, then proves a byte-identical replay; its behavior took 0.14 s. Engine generation
  replay and Governor-only drift classification each pass.
- The first workspace Clippy pass found only the transaction entrypoint's `too_many_lines`; a local
  reasoned annotation was added, with no warning suppression outside that state machine. Final
  workspace all-target Clippy with warnings denied passed in 28.056 s; format and check pass.
- One old ledger test expected an error for a missing campaign even though the typed API has long
  returned `Ok(CampaignClosed)`; the expectation was corrected without changing runtime behavior.
  One PowerShell timing wrapper accidentally invoked bare `cargo --help` five times and was not
  counted as testing. Two attempts to run the new real dry-run from an uncommitted debug binary
  failed before inspection with `unattested_cognitive_governor`; both public/private SHA inventories
  remained byte-identical (23 and 1600 files). No attestation bypass was added; live proof waits for
  a commit-bound candidate.
- Final inspection hardening additionally requires every seal-bound lease to be unexpired, maps
  every lease to an exact seal session, rejects duplicate lease/session IDs, rejects any extra
  active session in the same generation, and requires one session per lease. After this change the
  cognitive runner remained 28/28 PASS (0.70 s behavior / 59.276 s compile-dominated wall),
  cognitive contract 3/3 PASS (0.68 s / 0.960 s), CLI 2/2 PASS (0.09 s / 0.340 s), and final
  `eliot-app` all-target Clippy with warnings denied passed in 12.692 s. The CLI help regression now
  explicitly requires `supersede-seal` and passed in 1.555 s wall.

### Attested supersession candidate and live dry-run

- Committed and pushed the generic supersession repair as
  `dde14e3903197f30377152152786d9b805ff0ad4`
  (`C7-02R2: supersede drifted published provider seals`). A new isolated release build took
  259.788 s and produced
  `C:\Users\kleym\AppData\Local\Eliot\builds\seal-supersession-dde14e3-target\release\eliot-governor.exe`,
  55,707,136 bytes, SHA-256
  `ff6a1806054432cb1e18ace79758fb8c9623fafc0ee3d952b1759a9492a8cbab`; the exact 40-character
  source commit is embedded. The CLI has no `version`/`--version` surface, so two unsuccessful
  diagnostic invocations were stopped and the embedded value was verified directly in the binary.
- With operations, reconciliation, cleanup and orphan-process counts all zero, PID 85320 was
  stopped cooperatively. The candidate started hidden as PID 55564 and published ready with the
  exact path/SHA. Runtime supervision then entered the intentionally narrow recovery-only state:
  sole error `published_seal_runtime_drift`, provider dispatch blocked, four active generation-3
  leases, no missing/extra authority, and exact observed/expected candidate SHA.
- The real generation-3 supersession dry-run classified
  `SUPERSEDE_PUBLISHED_SEAL_RUNTIME_DRIFT` in 2.904 s with exact plan and authority, zero
  reservations, results, journal attempts, provider artifacts, nonterminal operations, incomplete
  seals or integrity errors. All 16 drift fields are the four permitted Governor binding/derived
  hash fields across the four external Reader calls. Full before/after SHA-256 inventories were
  byte-identical: 23 public files and 1,600 private files, both with zero differences.

### Live supersession, generation-4 collision, and immutable reuse repair

- The generation-3 supersession apply completed in 9.055 s without a provider call. It revoked all
  four role leases, retired the seal sessions, abandoned the zero-attempt operation jobs, revoked
  the work items, marked the seal Abandoned, and digest-verified/quarantined both the immutable
  generation root and public plan. A replay returned `ALREADY_SUPERSEDED` in 0.023 s. The public
  and private trees were byte-identical across replay (22 and 1,602 files respectively), and the
  runtime returned to `ready` with zero active leases and zero operations.
- The replacement generation-4 seal dry-run passed in 5.820 s with no mutation. The real seal then
  failed after 12.734 s at publication with
  `sealed output already exists with different content: .../evidence/U03/memory_free_control/reused-roles.json`.
  Compensation completed: generation 4 is Abandoned, authority is revoked, its candidate is
  quarantined, active/pending leases and operations are zero, and the durable abandon record is
  `abandoned-seals/seal-fd9bb12f939b7b9d-g4.json` with replacement generation 5.
- Root cause: `reused-roles.json` is a public immutable projection, but its old materializer
  regenerated generation-specific `provider_plan_hash` and `recorded_at`. The dry-run returned
  before this materialization, so it did not predict the collision; the generation collision gate
  also ran after part of seal preparation. Rewriting the old projection or weakening immutable
  publication was rejected.
- The first architecture review was sent headless to the bundled Claude Code CLI as exact
  `claude-opus-5`, max effort, read-only plan mode, strict empty MCP, and Read/Grep/Glob only.
  Session `703f5a06-7b30-4783-bce1-e74d4de580ba` used 30 turns and completed in 426.037 s wall /
  423.871 s API, USD 2.7685645, with no denial, web, MCP, or write. Its initial proposal contained
  a plan-hash/manifest-hash cycle. Local review caught the cycle; one resumed follow-up used five
  turns, 266.630 s wall / 263.250 s API, USD 1.114218, and corrected the design. An unnecessary GUI
  discovery attempt had occurred before the bundled CLI path was identified; it submitted no
  Claude prompt and changed no project/runtime state. All later Claude reviews use the headless
  executable directly.
- Adopted design: existing `reused-roles.json` bytes retain their first-binding plan hash and
  timestamp forever. Each new seal contains a generation-scoped, manifest-covered
  `role-reuse-binding.json` over a material projection that deliberately clears only those two
  carved first-binding fields. The binding has no current plan or manifest hash, preventing a hash
  cycle. A carried binding is admitted only after exact completed supersession proof, a dense chain
  of uniquely Abandoned skipped generations, digest-exact quarantined candidate plans, unchanged
  material digests, and live zero-dispatch evidence for all relevant call/lease identities.
- Seal planning now runs the full reuse write-set comparison before dry-run returns, rejects
  partial or non-bijective prior projection sets, verifies every already-present byte, stages the
  binding in the sealed manifest, validates generation collisions before activation, and cleans
  staging if lineage proof fails. Grading validates plan -> artifact manifest -> role-reuse binding
  -> all materialized projection digests. It checks carved fields against the current plan for a
  genesis binding or against the carried first-binding pair after supersession. The obsolete
  `planned_reused_roles <= 1` completion check is replaced by a required valid binding; Task-02R2
  already requires exactly four accepted U03 role sources.

### Verification, Claude zero-tool route, and test-duration issue

- The new role-reuse negative-path test proves that changing only first-binding fields leaves the
  material digest stable, that the sealed manifest binds exactly one generation binding, and that
  changing any non-carved projection field is rejected. Cognitive runner tests passed 29/29 in
  0.71 s behavior / 1.317 s warm wall; the focused new test passed in 0.03 s behavior / 14.4 s
  compile/lock wall. `eliot-app` all-target Clippy with warnings denied passed in 27.921 s.
- The first full `eliot-app` run exposed an existing B6 matrix failure for
  `Claude/MemoryFreeControl`: the intentionally empty `cognitive_control` tool profile was rejected
  as `Claude Code command input is incomplete`. It reproduced twice. A focused headless Opus 5
  review (`4dcecf58-d084-46f8-b4b2-a88f8b3b931e`) completed over 19 turns in 311.031 s wall /
  307.449 s API, USD 1.86438525, with no denials, web, MCP, or writes. It confirmed that an empty
  allow set is a legal deny-all profile and that emitting `--allowedTools ""` would be ambiguous.
- The systemic repair is confined to the Claude command builder: an empty allow set is accepted and
  the `--allowedTools` pair is omitted; non-empty routes retain byte-identical argument ordering.
  A new engine test covers zero tools, no empty argv tokens, strict MCP and deny flags, while the
  original test now pins the non-empty flag/value. Blank model, MCP config, prompt, and zero turns
  remain rejected. Engine external-agent tests passed 7/7; the full 12-cell B6 host/purpose matrix
  passed. Combined compile-dominated wall time was 73.302 s.
- Opus also identified a separate pre-existing hardening gap: the builder does not emit an explicit
  Claude `--permission-mode`; built-in read-only tools are therefore constrained by the caller's
  deny list rather than this flag. The zero-tool repair does not widen the MCP surface because the
  route still uses strict sealed MCP config, empty catalog, and sealed deny data. The permission
  mode gap is recorded for a separate bounded task and was not mixed into this repair.
- A subsequent full package run passed the 218-test unit binary but the parallel
  `multi_agent_access` integration binary timed out four tests waiting for changed
  `auth_generation`. Serial isolation took 88.446 s: three active tests passed and only
  `initialize_cannot_widen_the_authenticated_profile` repeated the same timeout; four provisioned
  tests remained ignored. Per the two-attempt limit and the explicit instruction not to turn this
  task into test-harness research, investigation stopped. This is an unrelated slow/flaky harness
  fingerprint, not evidence against the focused seal/Claude fixes, and must be recorded in Eliot
  and the final report.
- Product commit `3fe0a48d5e582abc056d269781f5c05f76a86a33` was pushed. Its isolated release
  build took 280.437 s and produced a 56,131,072-byte binary with SHA-256
  `42bf2353d945a6a4006d76e3bea38d9a9c607c24cbf18f402b2501427ce62d5f` and the exact embedded
  commit. After a clean quiescence check, PID 55564 stopped cooperatively and this candidate started
  hidden as PID 75572. Publication, doctor, and supervision all reported ready, exact path/SHA,
  dispatch safe, and zero operations, orphans, partial seals, or active/pending leases. The cutover
  wrapper itself compared publication field `status` instead of the actual `state`, so it emitted a
  false post-start error after the candidate was already ready; direct doctor/supervision removed
  the ambiguity.
- The first real generation-5 dry-run with that candidate failed closed in 10.532 s at carried
  lineage proof: `published supersession quarantine root differs from its deterministic identity`.
  Before/after inventories were identical (22 public and 1,617 private files, zero differences).
  Exact evidence showed a Windows representation mismatch only: the durable supersession record
  contains raw `\\?\C:\...` from `Path::display`, while the comparator normalized only the live
  side to slash form. The generic comparator now normalizes both `Path` identities; no durable data
  is rewritten. Its existing ordinary/verbatim regression now also covers a raw displayed verbatim
  expected string. Cognitive runner remained 29/29 green (1.03 s behavior), and package Clippy with
  warnings denied passed.

### Generation-5 publication and Published replay repair

- The path-normalization repair was committed/pushed as
  `b1c1d0c776f56b92165aef7ea219ef843396afb6`. Its isolated release build took 269.282 s and
  produced a 56,132,096-byte binary, SHA-256
  `069552c4d824cde73f44f29caeb5744daa4fe99b31412e45cd98eaf69aadb0cb`, with the exact embedded
  commit. Quiescence passed, PID 75572 stopped cooperatively, and the candidate started hidden as
  PID 109592. Publication, doctor, and supervision were ready/clean with exact path/SHA and zero
  operations, orphans, partial seals, or leases before sealing.
- The corrected generation-5 dry-run passed in 12.399 s. It proved carried first-binding plan
  `blake3:5f888363...`, the dense skipped chain `[4]`, generation 5 attempt
  `provider-plan-seal:seal-b5bbfbca42d32a7d-g5`, binding SHA-256 `c011acae...`, manifest SHA-256
  `e49e55a5...`, and zero authority side effects. Full inventories stayed byte-identical: 22 public
  and 1,617 private files, zero differences.
- The real generation-5 seal completed in 17.206 s: 8 fresh calls, 4 accepted reused roles, no
  smokes, plan `blake3:d60d948f...`, the same manifest, and Published status. Both existing
  `reused-roles.json` files were byte-identical before/after. This closes the original immutable
  projection collision.
- An immediate identical seal replay then exposed a second acceptance defect. Public state stayed
  byte-identical (23 files), but the command failed after 13.657 s with
  `existing sealed provider plan differs from the requested call plan` and left 13 staging files.
  Exact diff showed only the four external execution requests changing: the create renderer read its
  own active generation-5 leases and advanced `role_lease_epoch` (for example 9 -> 11). That changed
  launch-contract hashes, execution-request hashes, manifest hashes, and the plan hash. Runtime
  supervision remained ready/clean; no new authority or seal record was created.
- Escalated once to the existing headless Opus 5 architecture session
  `703f5a06-7b30-4783-bce1-e74d4de580ba`. The focused follow-up used 11 turns, 338.490 s wall /
  333.544 s API, USD 2.9569875, with no permission denial, write, MCP, or web access. It confirmed
  the architectural ordering error: Published replay was decided only after non-idempotent create
  rendering and staging.
- Replay is now a separate early verify-only path. It runs before staging, does not render runtime
  contracts, allocate epochs, or mint authority. It validates the Published record; byte-exact
  public/private candidate plan; self-consistent manifest and exact manifested generation tree with
  no extras; caller call intent after clearing only external generated fields; the consumed caller
  `runtime_contract_sha256` through each sealed execution request; prompt/schema hashes; exact
  active seal-bound lease/session/job/work sets; and the role-reuse binding. Runtime currency remains
  owned by seal-status/supersession rather than replay, avoiding a second source of non-idempotency.
- Only after every replay check passes, a non-dry replay may remove a staging root proven orphaned
  by the coexisting Published record and absence of Staged/Activated authority. This self-heals the
  13-file residue; dry-run remains entirely read-only. A pre-activation staging guard now cleans all
  create-preparation error returns until the durable runtime checkpoint assumes recovery ownership.
  A focused test fixes the classification boundary between caller intent and external generated
  fields; changed Codex runtime binding remains direct intent, while external consumed input remains
  bound separately by the sealed request.
