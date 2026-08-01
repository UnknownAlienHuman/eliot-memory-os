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
