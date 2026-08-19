# Domain: Security, Watchdog supervision, doctor/recovery, problem/incident, observability

**STATUS: PARTIAL v3 (Q1-Q4 answered, Q5 security hunt in progress).**

## Scope covered
(pending final pass)

## Confirmed findings so far

### Carried over from v2 (re-verified where noted)
- **Watchdog loop** `bins/eliot-watchdog/src/lib.rs:1055-1108`: sleep-tick -> `admission.reload()` -> `kernel.supervise(lease)` = `IndependentKernelSensor::record_heartbeat` (`:831`) appending a `Heartbeat` row to its own redb spool. No process probe, no hook cadence, no workspace/queue observation, no bypass detection.
- **`eliot-watchdog-core::Watchdog::{observe,tick,record_reap,restart_decision}`** (`crates/supervision/eliot-watchdog-core/src/lib.rs:220,271,318,341`) DEAD from the production process: `bins/eliot-watchdog/src/lib.rs:839` uses only `watchdog.epoch()`.
- **Credential Manager real**: `crates/eliot-windows-ipc/src/lib.rs:2158`/`:2199`. DPAPI real: `crates/kernel/eliot-platform-windows/src/lib.rs:6943`.
- **Secret boundary scanner real and widely called**: `crates/eliot-types/src/secret_boundary.rs:69`.
- **`cargo deny` runs in NO workflow**.
- **Orphan crates**: `eliot-influence`, `eliot-erasure`, `eliot-observability` (+ new ones below).
- **Doctor is a hard stub**: `bins/eliot-doctor/src/main.rs:7-16` — `main()` writes `KERNEL_ADMISSION_REQUIRED` to stderr and `exit(78)`. Nothing else.
- **Reason codes are `&'static str`/`String`**, no enumerated registry type matching `Appendix D`.

### Q1 — provenance / injection boundary
- Real contract type exists: `crates/security/eliot-source-assurance/src/lib.rs:255` `SourceAssurance` with independent axes matching `I15.5`, incl. `InstructionTaint {InstructionChannel,Data,Unknown}` (`:162`), `ThreatStatus` (`:174`), `QuarantineStatus` (`:184`).
- `SourceAssurance::admit()` (`:359`) is REAL deterministic logic: pushes `AssuranceFinding::InstructionTainted` when taint != `InstructionChannel` (`:400-406`), `Quarantined` on threat/quarantine, and returns a typed `AdmissionOutcome`.
- **But it is unreachable from production.** The only two dependents are `crates/agent/eliot-agent-acp` (`Cargo.toml:13`) and `crates/agent/eliot-agent-codex` (`Cargo.toml:13`), and BOTH have zero Rust dependents in the workspace — no crate and no bin depends on `eliot-agent-acp` or `eliot-agent-codex`. Call sites: `crates/agent/eliot-agent-acp/src/lib.rs:1148`, `crates/agent/eliot-agent-codex/src/lib.rs:229` — both in orphan crates.
- The **actual** governed write path is `WriteAdmissionService::admit` at `crates/eliot-engine/src/admission.rs:20`. It carries a much weaker `eliot_types::TaintClass` (`crates/eliot-types/src/memory.rs:82`: `LocalVerified|LocalTool|ExternalAgent|UserProvided|Unknown`) taken verbatim from `command.context().taint` (`:27`, `:55`). Enforcement is real but coarse: `:116` rejects passed verification without `LocalVerified`; `:172` requires `LocalTool|LocalVerified` for UL artifacts; `:456` requires `LocalVerified` for `AgentResultRecord`.
- **The taint value is caller-asserted, not derived from content origin.** Callers hardcode it: `crates/eliot-app/src/mcp_stdio/task_handlers.rs:3404`, `crates/eliot-app/src/mcp_stdio/operator.rs:3869`, `crates/eliot-app/src/host_runtime/event_and_authority.rs:2592` all set `taint: TaintClass::LocalVerified` literally.
- No injection/hidden-instruction screening exists. The only content inspection on the write path is `eliot_types::ul::guard::inspect_text_encoding` (`crates/eliot-types/src/ul/guard.rs:42`, called at `crates/eliot-engine/src/admission.rs:22`) — a mojibake/encoding checker, not a fence. Repo-wide grep for injection/hidden-instruction screening returns only `UlInjectionMode` (UL *context injection* budget policy, `crates/eliot-app/src/commands/ul.rs:632-653`) — unrelated meaning.

### Q2 — recovery chain
- `signal` -> `problem`: `crates/governor/eliot-problem/src/lib.rs` has REAL state machines (`Signal:224`, `Problem:361`, `ProblemState:315`, `Incident:529`, `CriticalAttention:855`, `GovernedChallenge:1051`, fence-checked `transition():411`). **Zero Rust references to `eliot_problem` exist anywhere in the repo** (grep `eliot_problem` over all `.rs`: definition crate only). `crates/governor/eliot-governor/Cargo.toml:21` declares the dependency but no code imports it.
- `directive`: `RecoveryDirective` at `crates/foundation/eliot-runtime-contracts/src/lib.rs:867`. Consumers: `RecoveryViewBuilder::add_directive` (`crates/kernel/eliot-kernel-core/src/module/recovery_state_view.rs:88`) — only called from its own unit tests (`:161`); and `eliot_rules::validate_recovery_directive` (`crates/foundation/eliot-rules/src/lib.rs:631`) — zero callers.
- `repair`: `crates/meta/eliot-doctor-core/src/lib.rs` has real `RepairRecipe:161`, `RepairRequest:258`, `RepairPlan::build:471`, `DoctorJob::admit:528`/`transition:546`/`record_attempt:557`. Sole dependent is `bins/eliot-doctor` (`Cargo.toml:17`), whose `main()` is the 16-line stub above — it never constructs any of these types.
- **Missing link: every one of them, as a wired chain.** No production code path produces a Signal, opens a Problem, issues a Directive, executes a Repair, or records a verified disposition.

### Q3 — Failure Capsule
- **ABSENT as a type.** `FailureCapsule` appears in the repo exactly twice, both as an enum *variant name* in the orphan crate: `crates/instrument/eliot-observability/src/lib.rs:270` (`OperationalEventKind::FailureCapsule`) and `:290` (listed in `is_protected()`).
- No `struct FailureCapsule`, no field set from `I16.18`, no producer on any failure path. `DiagnosticBrief` exists (`crates/meta/eliot-doctor-core/src/lib.rs:126`) but is only reachable through the stubbed Doctor.

### Q4 — observability
- **Only `tracing`.** Both production entrypoints init a plain human-readable stderr subscriber: `crates/eliot-app/src/main.rs:3376-3383` and `bins/eliot/src/main.rs:278-285` — `tracing_subscriber::fmt().with_env_filter(...).with_writer(std::io::stderr).with_target(false).init()`. Not even `.json()`; no file sink, no rotation, no separate audit stream.
- `crates/instrument/eliot-observability/src/lib.rs` (1053 lines) is a real, validated contract layer — `OperationalEvent:328`, `MetricSample:396`, `ObservabilityGap:716`, `ObservabilityBuffer:827` with `EventPriority::Protected` retention — and is an ORPHAN (zero dependents in any `Cargo.toml` except the workspace member list).
- `eliot_observation_contracts::AuditRecord` (`crates/foundation/eliot-observation-contracts/src/lib.rs:612`) has zero references outside its own definition.
- The only thing resembling a durable audit is the antigravity MCP invocation event file written to `reports/antigravity-mcp-invocations/events/{id}.json` (`crates/eliot-app/src/mcp_stdio/protocol_support.rs:808-822`) — a single feature's report artifact, not a general audit sink.

(Q5 security P0 hunt pending.)
