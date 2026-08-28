# ELIOT Implementation
## Concrete implementation of a resilient Memory OS, Harness, Smart, and Meta in Rust

**Version:** 0.29-draft
**Date:** 2026-08-14
**Status:** target implementation contract; product `NOT_ACCEPTED / UNVERIFIED`; code, runtime, and data conformance unknown; repository cutover and removal of old books not accepted
**Normative pair:** `ELIOT_ARCHITECTURE.md` + `ELIOT_IMPLEMENTATION.md`
**English edition:** 2026-08-28; English revision with the final ownership, liveness, privacy, and residency closures incorporated
**Precedence:** On semantic conflict, this book is subordinate to Architecture 4.5-draft; local implementation cannot silently alter architectural intent
**Primary platform:** Windows 11 x64
**Control-plane language:** Rust 2024 edition
**Initial canonical substrate:** separate SurrealDB server through a replaceable storage bridge
**Primary operating mode:** local-first, demand-start, single-machine primary-user installation; multi-agent and multi-project within one local ELIOT
**Development constraint:** Normative detail and test count are not progress. Every agent change closes one causal property through an independently testable Module cell, real Instrument evidence, affected Edge Proof, and a bounded Product Pulse when the change can affect the overall result
**Crate strategy:** ELIOT is crate-rich and process-sparse: many independently selectable source/build units, fewer runtime bundles and processes, and exactly one lifecycle owner for each mutable state. Crate or source ownership grants no runtime authority. Each agent receives a route-qualified bounded causal workset; numeric context and size profiles remain measurable, replaceable Empirical Profiles—not Module or system limits

---

# Concise decision

ELIOT is implemented neither as one large executable nor as a scatter of DLLs. It consists of a small resilient control Kernel, a replaceable application daemon, and replaceable process Modules. The target production topology appears below; early delivery depths may temporarily co-locate a capability behind the same public contract when its layer explicitly permits this and no second owner is created.

Source topology intentionally contains many narrow Cargo crates. A crate is an ordinary boundary for compilation, package-selective testing, dependency containment, and agent delivery. Causal and lifecycle ownership belongs to the `FunctionalCapabilityCell` or service contract and is mapped explicitly in the manifest; several tightly coupled cells may share one crate. A process generation is a broader boundary for failure, authority, and hot replacement. ELIOT does not turn every crate into a microservice.

```text
Windows Service Control Manager
├─ Eliot Host service (`eliot-host.exe`)
│  ├─ Host-owned Kernel Job Object
│  │  └─ `eliot-kernel.exe`       identity, fencing, ORS, control reserve,
│  │     │                        canonical transition gateway, recovery
│  │     ├─ `eliot-store-surreal.exe` ── client of the canonical-store process
│  │     ├─ BlobStore capability   co-located initially; optional `eliot-blob.exe` after isolation proof
│  │     ├─ `eliotd.exe`          primary Governor application daemon
│  │     ├─ `eliot-testd.exe`     isolated build/test/simulation plane, on demand
│  │     ├─ `eliot-wasm-host.exe` capability-limited Component Model generations, on demand
│  │     ├─ `eliot-native-worker-*.exe` OS-heavy or promoted native generations
│  │     ├─ `eliot-dreamer.exe`   on demand
│  │     ├─ `eliot-doctor.exe`    on demand
│  │     ├─ `eliot-mod-*.exe`     adapters, graphs, research, tools
│  │     └─ service-safe agent/model jobs
│  └─ Host-owned canonical-store Job Object
│     └─ `surreal.exe`             sole process owner of canonical DB files
└─ Eliot Watchdog service (`eliot-watchdog.exe`)
   └─ independent observation and protected minimal spool

Authorized interactive user session
├─ `eliot.exe`                    one canonical CLI; one-shot, no state ownership
├─ `eliot-user-broker.exe`        on demand
│  ├─ `eliot-ui.exe`              native WinUI client; no canonical authority
│  └─ subscription/desktop-bound runtimes; no canonical authority
└─ `eliot-notify.exe`             on demand via User Broker or signed Task Scheduler fallback; notification only
```

SCM owns only the stable Host and Watchdog services. Host owns OS process lifecycle for two isolated branches: Kernel and the canonical-store dependency. It starts `surreal.exe` as a supervised console/server process from an approved immutable manifest; ELIOT does not assume that the upstream binary implements the Windows service-control protocol. The SurrealDB process owns database files, while Host owns only start/stop/restart and Job Object containment. Kernel requests dependency lifecycle through Host and physically supervises `eliotd` and replaceable child generations. `eliotd` owns desired module state and semantic scheduling; Kernel performs generation routing, switch and fencing. Subscription- or desktop-bound runtimes are launched through a per-user `eliot-user-broker.exe`; the service identity never impersonates user-owned credentials or interactive desktop state.

Logical Governor consists of Kernel and `eliotd`, but canonical application authority remains singular. Kernel is the failure-surviving part of Governor, not a second Governor.

Primary update path:

```text
immutable artifact
→ staged generation
→ protocol/contract check
→ candidate process
→ warm-up or shadow traffic
→ health and canary
→ quiesce old admissions
→ persist one disposition for every effect-capable in-flight operation
→ commit the ORS cutover record as the durable linearization point
→ publish the candidate route, raise Authority Epoch and fence old general authority
→ drain permitted reads/exact old operations and reconcile unknown outcomes
→ retire or perform a new forward/rollback cutover.
```

Primary development path:

```text
small working vertical spine
→ real observations and performance
→ separate Modules
→ affected tests
→ canary in current work
→ Improvement Candidate
→ controlled promotion
→ full release gate only for a release or load-bearing change.
```

A full workspace rebuild and full test suite are not the normal response to a local change. They run only for a matching blast radius or release.

Runtime extensions and agent-generated components use three execution contours:

```text
WASM Component
  pure, portable, capability-limited and rapidly replaceable logic;

isolated native process generation
  Cargo/Git/LSP/browser/native libraries, credentials or OS-heavy work;

static native bundle
  trusted Kernel/control-plane or a measured hot path promoted through a new binary generation.
```

A Cargo crate is not automatically a process, and a process is not automatically a Windows service. In-process Rust dynamic libraries are not a normal promotion route: Rust ABI, shared heap, callbacks, threads and unload semantics do not provide the failure isolation required by ELIOT.

Agent Execution Fabric is not a new control plane. It is an execution projection of the existing Governor, Host Broker, and Agent Coordinator:

```text
Human / Main Agent
→ goal, constraints, assurance and budget policy
→ ELIOT chooses the simplest admissible recipe, routes, staffing and isolation
→ external runtimes execute bounded attempts
→ ELIOT reconciles evidence, audits disagreement and owns durable task state.
```

Task intent, lifecycle, evidence, authority, recovery, and decision gates are unified. The internals of Codex, OpenCode, ACP, Claude, Antigravity, and future agents remain distinct and are preserved in route and provenance records.

Instrument Plane is the deterministic foundation for development and grounding, not another agent system:

```text
ELIOT task / memory / authority
→ typed InstrumentProfile
→ one InstrumentRunner control path
→ isolated `eliot-testd` execution plane
→ one Windows ProcessExecutor semantics
→ compiler, test, simulation, component, semantic, runtime and performance instruments
→ EvidenceEnvelope + VerificationReceipt with authority, freshness, coverage and provenance
→ CodeCortex / verifier / Diagnostic Brief / Active View.
```

An agent receives neither dozens of raw tools nor permission to invent shell verifier commands. It requests the intent `verify`, `inspect`, `assist`, or `evidence`; ELIOT selects a profile, runs exact instruments, preserves raw evidence, and returns a compact verifiable result. Instrument Plane owns neither tasks, memory, Architecture, nor completion.

---

# How to read this book

This book is organized in layers.

```text
Delivery Depth D0 — bootstrap evidence/brief, Host/Kernel front door, ORS, independent deterministic Watchdog and process-grounding skeleton.
Delivery Depth D1 — one agent/WorkScope/task, canonical capture/read/write, real verifier, strict finish and first Operational Spine Proof.
Delivery Depth D2 — Module/Generation/Capability registries, independent module proofs, hot replacement, Human board, basic Doctor repair path and a second route.
Delivery Depth D3 — D3a Basic Dreamer Orientation; D3b reactive Context Compiler/cues; D3c grounded code/behavioral/causal projections.
Delivery Depth D4 — advanced Watchdog analysis, Doctor recipes, backup/restore/revocation and governed improvement loop.
Delivery Depth D5 — durable portfolio/swarm, Researcher and optional advanced domains.
```

Every accepted delivery milestone must provide independent user or operational value. A pure infrastructure-extraction track may proceed in parallel, but is not a completed product depth without a connected working capability and proof. Each subsequent depth extends the previous one; it does not rewrite Kernel or canonical history without a migration reason.

Machine-enforceable normative force is not inferred from `MUST`, `cannot`, “prohibited,” or other modal verbs. They aid human reading, but runtime or agent may block, permit, or challenge an action only through a `RuleCatalogueEntry` or `RuleBinding` that explicitly states class, owner, scope, rationale, observable property, and challenge path.

```text
HardBoundary
  → exists only when linked to an Architecture Hard Boundary or an authority, privacy, or proof invariant;
  → fail closed; ImplementationDeviation does not apply.

Contract
  → observable obligation of a specific capability;
  → when absent, returns a typed degraded or unsupported state.

Guardrail / Default
  → challengeable and replaceable through an evidence-backed ImplementationDeviation.

Experiment
  → reversible hypothesis with discriminator, budget, stop, and rollback.

Policy
  → human-owned privacy/cost/risk/model decision.
```

Unregistered explanatory prose is not an independent blocker, permission, or source of authority. One classified rule block may cover several explanatory sentences; marking every modal word is prohibited as literalist proxy work. Documentation lint checks not verbs, but that every applied reason code, directive, block, or deviation references an existing classified rule. Hidden bypass remains prohibited.

---

## Working reading routes

The full document is not a prompt for every agent. Governor and Context Compiler issue only applicable sections, contracts, and exact handles.

```text
first vertical spine
  → I0, I1.1–I1.8, I2.1–I2.5, I5.1–I5.7, I7, I14, I17–I18;

Kernel/recovery work
  → I1, I2.3–I2.5, I5.5–I5.23, I14–I16, Appendices A–D/P;

process Module or bridge
  → I2.1–I2.25, I6.4–I6.5, I7.1–I7.5, I10, I14.14, I18;

instrument, verification or Rust code-understanding work
  → I2.10–I2.23, I2.25, I10.8–I10.10, I12.9–I12.10, I16.17, I17, I18, Appendices J/P plus accepted contract-catalogue handles;

agent/runtime/swarm integration
  → I3, I7, I10.15–I10.18, I13–I14, I16, I18.16–I18.17;

memory/Dreamer/understanding
  → I9, I12–I13, I16 plus accepted contract-catalogue and cold-inventory handles only when needed;

professional/multimodal workflow
  → I4, I10.13, I10.20–I10.22, I12.35, I18.47 plus exact professional-contract handles;

migration/release
  → I0.8–I0.9, I18–I20, Appendices G–P plus the non-normative donor migration audit.
```

Names such as `component:state`, `component:context`, and `component:authority` denote logical owners in the conformance map. They do not require a Cargo crate or process with that name. Source and runtime extraction are defined by I2, not by the diagram.

## Compiled recovery/development brief

### Bootstrap before the full Context Compiler

D0–D1 do not assume that ELIOT already exists. A small deterministic `BootstrapBriefCompiler` is delivered in the same first-party `eliot-bootstrap` crate before the runtime Context Compiler. Its D0 execution owner is the short-lived `eliot.exe` command `eliot bootstrap brief`; it runs against exact Architecture/Implementation identities, a typed Human/agent work-unit seed, the generated Bootstrap Rule Catalogue and the best available CurrentSystemEvidenceSnapshot. The pure selection/rendering core is later reused by the normal Context Compiler; bootstrap does not create a second rule ontology, memory owner or task graph. The two bootstrap cells share one crate because they use one content-addressed normative/evidence input model and one independent D0 proof surface, while retaining separate FunctionalCapabilityCell manifests.

```yaml
BootstrapBriefProfile:
  normative_pair_identity:
  compiler_mode: deterministic_cli | human_selected_deterministic_render
  product_objective_and_work_unit_seed:
  current_system_evidence_snapshot_ref_or_explicit_gap:
  rule_catalogue_revision_and_rule_bindings:
  selected_contract_and_evidence_handles:
  applied_dimension_projection:
  decision_safety_floor_and_non_goals:
  normative_coverage_manifest:
  serialized_context_measurement_and_route_profile:
  validity_and_invalidation:
```

A Human may select the work-unit scope while the system is being bootstrapped, but may not hand-edit support status, rule class or evidence execution status. Missing runtime/store evidence is rendered as `NOT_RUNNING`, `UNAVAILABLE` or `UNKNOWN`, not filled with assumptions. The bootstrap compiler remains a recovery fallback after D3b, but ceases to be the normal compiler once the Context Compiler is `CURRENT_VERIFIED`.

The active agent prompt is **compiled per `CausalChangeUnit`**. A static bundle of dozens of I-sections is forbidden: it recreates the context overload and rule-following failure that ELIOT is intended to prevent.

```yaml
RecoveryDevelopmentBrief:
  product_objective_and_current_recovery_priority:
  one_causal_property_and_actual_owner_path:
  exact_product_source_runtime_and_state_identity:
  current_system_evidence_snapshot_ref_and_coverage:
  applicable_architecture_intents_and_hard_boundaries:
  classified_rule_bindings_and_exact_contract_fragments:
  normative_coverage_manifest:
  applied_dimension_projection:
  old_failing_behavior_and_competing_hypotheses:
  discriminator_and_expected_observable:
  current_evidence_failure_fingerprints_and_directives:
  allowed_effects_write_scope_and_non_goals:
  module_contract_test_capsule_and_affected_edges:
  smallest_product_pulse_or_spine_boundary:
  budget_stop_challenge_and_integration_owner:
  expansion_handles:
```

The brief contains rendered contract fragments, not whole chapters. Additional I-sections, schemas, logs and research are exposed by exact handles and loaded only when the current decision requires them. The Context Compiler records the exact serialized size, omitted material and expansion path.
 It also emits a `NormativeCoverageManifest` distinguishing `not_searched`, `searched_and_absent`, `included`, `excluded_with_reason` and `stale`; silence in a brief never means permission.

There is no universal hard token quota for this brief. It must fit a route-specific qualified context envelope **together with** instructions, tools, evidence, reasoning/review reserve and safety margin. If the decision-sufficient workset does not fit, ELIOT decomposes the work, narrows the effect, compiles a better projection or selects a qualified route; it does not silently drop the Decision Safety Floor.

The reading routes above are human navigation only. They are not agent hotsets and do not authorize loading the complete Implementation.

# Runtime layer model

Architecture describes four functional planes. Implementation decomposes runtime into ten layers `R0–R9`. `R0–R4` form a strict ownership/dependency spine. The deterministic Instrument Plane spans R4 execution modules and R5 grounded projections; it is not a separate owner or daemon. `R5–R8` are peer capability planes anchored to public R3/R4 contracts; they may cooperate only through Agent Coordinator, the canonical Module Catalog, the Kernel Generation Registry, canonical records and versioned events, not by importing each other's internals. `R9` contains replaceable surfaces.

Layer namespaces answer different questions and must not be substituted for one another:

```text
R0–R9   runtime ownership/failure position;
D0–D5   delivered product depth;
Q0–Q5   read/reconstruction depth;
IP0–IP5 Instrument Plane depth;
L0–L5   internal layering of one module cell;
T0–T4   selected verification breadth;
Proof names (Shape/Module/Edge/Integration/Product/Release)
         state what the evidence proves.
```

The reference book may use all namespaces, but one work unit never receives the complete coordinate system by default. `AppliedDimensionProjection` includes only dimensions that change the current decision, spells out the namespace name rather than a bare letter, and explains why each value matters. Omitted dimensions remain available by handle. A dimension that does not change authority, execution, proof, context or rollout is excluded from the agent brief rather than taught ceremonially.

```yaml
AppliedDimensionProjection:
  included:
    - namespace: runtime | delivery | read | instrument | cell | test_breadth | proof
      value:
      why_decision_relevant:
  omitted_with_reason:
  source_revision:
```

`ContractSurfaceProfile` measures the actually rendered rule/contract/dimension surface on real work units. Growth without Product/Recovery delta triggers simplification or generation review; it never triggers another taxonomy merely to describe the first one.

| Layer | Runtime owners | Durable state | Hot-path status | Failure effect | Replacement mode |
|---|---|---|---|---|---|
| **R0 Platform and independent supervision substrate** | SCM, `eliot-host`, deterministic `eliot-watchdog`, platform facade | approved build registry, Host state, protected Watchdog spool/anchors | supervision/control only; no semantic hot path | installation or independent observation may be unavailable; failure is explicit | side-by-side executable + Host/SCM rollback |
| **R1 Kernel** | `eliot-kernel` | ORS, epochs, generation routing, control reserve | identity/fencing only | normal semantic work pauses; recovery remains | Host-supervised generation switch |
| **R2 Canonical substrate** | store API, store bridge, blob store | canonical events, projections, receipts, blobs | bounded named reads; no semantic synthesis | canonical writes stop; cached/degraded reads only | store generation + ECXF migration |
| **R3 Harness spine** | `eliotd` task/admission/read/finish/job/Agent Coordinator services | WorkScopes, tasks, sessions, leases, problems, durable jobs and coordination state | yes | agent work degrades or pauses; Kernel survives | daemon generation switch |
| **R4 Module and Instrument fabric** | Governor Module Catalog, Kernel Generation Registry, Adapter/Instrument Supervisor, bridges, ProcessExecutor clients | desired manifests in canonical state; runtime generations/checkpoints in ORS; instrument evidence in canonical/Blob storage | explicit instrument jobs execute outside hidden gate/context hot path; only completed immutable evidence is read synchronously | only dependent capability degrades | independent process generation or rebuildable source module |
| **R5 Smart hot path and grounded projections** | context, cue, current-position, gates, EvidenceRouter, CodeCortex compositor | rebuildable indexes, evidence projections and packet manifests | yes; deterministic and bounded | handles-only/stale/probe mode | daemon/module generation |
| **R6 Smart cold path** | Dreamer, Researcher, graph/mining jobs | candidates, research packs, derived artifacts | never blocks hot path | curation/research unavailable | on-demand process/module |
| **R7 Meta analysis and bounded repair** | Watchdog analysis agents, Doctor jobs, calibration and improvement services | diagnoses, repair intents, evaluation and improvement candidates | never required for the deterministic R0 supervision heartbeat | semantic diagnosis/curation degrades; R0/R1 control continues where safe | on-demand agent/job/module generation |
| **R8 Swarm execution plane** | worker/controller processes, worktree and remote execution pools | no independent canonical ownership; checkpoints/results return through R3 | no direct hot-path ownership | affected branches pause/reassign; coordination state survives in R3/R2 | replaceable workers/executors |
| **R9 Surfaces** | MCP/CLI/UI/notifications | no canonical semantic ownership | transport only | another surface remains or capability is visible as unavailable | bridge/surface generation |


## Instrument Plane sub-stack

Instrument Plane is a deterministic implementation plane across R4 and R5. It extends Rust/Windows tooling and produces governed evidence; it does not contain an LLM or another scheduler.

| Level | Owner | Responsibility | Independent proof |
|---|---|---|---|
| **IP0 Process execution** | one `eliot-process-windows` contract/reference implementation instantiated by the authorized process-tree owner | process identity, streams, limits, cancel and cleanup semantics; operation ownership remains with Kernel/testd/UserBroker/module supervisor | process-tree and pipe-saturation suite |
| **IP1 Instrument contracts** | `eliot-types` / contract owner | typed invocation, executable/environment identity, parser and negative-result contract | schema/property/compatibility tests |
| **IP2 Instrument execution** | `InstrumentRunner` in Governor application layer | resolve profile, run stages, stream/parse evidence, aggregate result | fake-executor and real-tool contract suites |
| **IP3 Evidence normalization** | parser/normalizer micro-modules + canonical evidence path | facts, unknowns, authority, freshness, coverage, provenance, raw handles | golden and adversarial parser/evidence tests |
| **IP4 Instrument profiles** | versioned profile registry | compiler, test, dependency, concurrency, runtime and performance recipes | profile-specific fixture and affected-path tests |
| **IP5 Grounded projections** | EvidenceRouter, CodeCortex, Diagnostic Brief and verifier adapters | bounded task-relative views; conflicts and unknowns remain visible | composition/product proof |

Every IP level may be developed and tested independently against the stable contract below it. A deeper level cannot manufacture evidence missing from a lower level. IP0–IP3 are required before any graph or test-strength expansion can claim authority.

## Dependency law

Strict runtime ownership spine:

```text
R1 uses R0 platform lifecycle;
R2 is started/fenced through R1 but owns only storage execution;
R3 uses R1 authority/control and R2 canonical contracts;
R4 Modules use public R1/R3 contracts and never own canonical state.
```

Peer capability planes:

```text
R5 Smart hot path uses R3 state and precomputed R4 adapters;
R6 Smart cold path submits jobs through R3 and may consume R4/R8 execution capacity;
R0 deterministic Watchdog observes liveness/security through its independent path; R7 analysis/repair services consume bounded evidence and submit repair/improvement intents through declared public paths;
R8 swarm workers are execution resources coordinated by R3 and consume bounded R4/R5/R6 inputs;
R5–R8 never call one another's internals or share mutable state directly.
```

Surfaces in R9 use only public contracts from R1/R3 and capability resources/events. Host/Supervisor may start or stop any higher service through generic manifests; this control inversion is not semantic/source ownership.

In particular:

```text
R1 does not import MCP, SurrealDB, Dreamer, UI or agent SDK types;
R2 does not decide task meaning, policy or epistemic status;
R4 Modules do not receive canonical write authority;
R5–R8 exchange work/results only through versioned R3/R4 contracts;
R6/R7/R8 model output remains Candidate;
R9 never becomes an alternate state owner.
```

## Depth without rewrite

Each runtime layer has a **minimum useful profile**, an **extended profile** and a **replacement boundary**. Deeper profiles add capabilities behind the same public contracts. A later layer may enrich a record or projection, but cannot silently change the meaning of earlier receipts, authority, provenance or finish outcomes.

## Hot-path rule

The synchronous decision path may call only:

```text
in-memory immutable snapshots;
precomputed cue/activation mirrors;
short bounded local IPC;
bounded named canonical reads when cache is insufficient;
deterministic policy, scope, authority and consistency checks.
```

The hot path never waits for:

```text
LLM/model inference;
Dreamer/Watchdog Agent;
unbounded graph traversal;
Git mining/index rebuild;
external network/service without a cached bounded contract;
module startup, upgrade or repair;
full report rendering.
```

When a required cold capability is missing, the hot path returns a handle, stale marker, probe requirement or Recovery Directive; it does not hide the delay inside a gate.

## Layer closure and promotion

A runtime layer is not declared supported merely because its crates compile. Its profile is complete only when all six obligations exist:

```text
public contract and compatibility range;
one mutable-state/lifecycle owner;
health, freshness and capacity signal;
local failure/degradation behavior;
replacement or rebuild path;
observable proof on a real lower-layer runtime.
```

Minimum closure by layer:

| Layer | Minimum useful closure | Cannot depend on | Promotion proof |
|---|---|---|---|
| R0 | install/start/stop/rollback approved Host/Watchdog artifacts and preserve independent observation | project semantics | service restart, Watchdog-spool continuity and rollback receipt |
| R1 | front door, identity, epoch, ORS, control reserve, recovery view | model, DB semantics, UI | kill/restart daemon while Kernel retains control |
| R2 | one canonical event/receipt/read/export path | agent/Task interpretation | crash/idempotency/restore proof |
| R3 | one Session/WorkScope/task/capture/action/verify/finish loop | optional Smart/Meta modules | real task survives daemon restart |
| R4 | register/start/health/quiesce/switch one replaceable Module and execute one typed instrument through the shared ProcessExecutor | Governor internals/direct DB/module-private process semantics | generation canary, process cleanup and evidence receipt |
| R5 | deterministic state/cue/context/gate delta plus evidence-aware CodeCortex projection | model calls/cold rebuild/raw graph dumps | bounded hot-path, stale-state and incomplete-evidence scenarios |
| R6 | one bounded Dreamer/Research job with candidate result | authority/canonical writer | budget/cancel/provenance/validation proof |
| R7 | bounded diagnosis, repair candidate and Human escalation over R0/R1 evidence | owning basic liveness or canonical authority | failure receives a verified repair/degradation disposition without breaking independent supervision |
| R8 | durable work-item assignment/checkpoint/result/lineage | shared chat as state | worker/controller loss with partial-result preservation |
| R9 | one agent and one Human surface over the same contracts | alternate state ownership | surface loss leaves canonical work intact |

Promotion to a deeper delivery depth never changes an earlier receipt or semantic meaning silently. If a deeper layer requires a new field or guarantee, it uses an additive compatible contract or an explicit migration.

---

# I0. Status, compatibility matrix, and change policy

## I0.1. Three development contours

### Contour 1 — Architecture

Defines purpose, invariants, authority boundaries, and rationale. Changes when the paradigm or AI environment changes materially.

### Contour 2 — Implementation

Defines current stack, processes, contracts, defaults, fallbacks, compatibility, operating limits, and verifiable replacement points. This book may change more often than Architecture.

### Contour 3 — Code and runtime

Lives in Git branches and worktrees and the local installation. It may change daily. Deviation from Implementation is allowed only as a registered experiment or deviation with a result.

## I0.2. Current compatibility baseline

| Surface | Current line | Status | Fallback or replacement rule |
|---|---|---|---|
| Architecture source | `ELIOT_ARCHITECTURE.md` 4.5-draft; exact path, version and digest are emitted after freeze in `docs/normative-pair.toml` | priority semantic baseline | a missing/mismatched pair receipt, different digest or mixed revision makes dependent conformance and self-knowledge projections stale/untrusted |
| Rust toolchain | Rust 1.97.1, edition 2024 | source-verified DEFAULT candidate in the external compatibility ledger; local admission still absent | exact patch is pinned in `rust-toolchain.toml`; update after affected suite |
| Windows | Windows 11 x64 | target production platform | Linux is unsupported until separate CI and acceptance exist |
| MCP | final specification 2026-07-28; stateless core | source-verified target line in the external compatibility ledger; local conformance still absent | compatibility adapter for 2025-11-25; ELIOT Session remains application state in both profiles |
| Rust MCP SDK | official `rmcp` 3.1.x line; 3.1.2 candidate | source-verified beta/primary candidate in the external compatibility ledger; local bridge/conformance absent | exact patch is pinned in `Cargo.lock` only after dual-version bridge/conformance tests; SDK remains isolated in `eliot-mcp` and cannot define domain/session semantics |
| Canonical DB | SurrealDB 3.2.x compatibility line; 3.2.3 candidate, not yet admitted | source-verified provisional target in the external compatibility ledger; local workload/crash/restore proof absent | active patch is selected only after current-system audit, workload/crash/restore proof and RGF-STORAGE-MIGRATION; rollback uses the last actually verified generation |
| Host state journal | `redb`, separate Host-owned file | target default | replacement requires torn-write/recovery equivalence and no semantic-state leakage |
| Operational recovery DB | `redb`, Kernel-owned ORS file | target default | replaceable only through ORS export/import proof |
| Internal process protocol | EBP/1 over named pipes; JSON-first encoding | target default | `protobuf-v1` — RGF-PROTOCOL-TRANSPORT profile; Unix domain socket reuse the same messages |
| In-process supervision | plain Tokio behind `eliot-runtime`; `ractor` is an unpinned research candidate | baseline + RGF-RUNTIME-RESILIENCE | exact candidate/version comes only from the current compatibility receipt and lockfile; Kernel/domain never depend on actor-framework semantics and a framework becomes default only after measured simplification without ownership drift |
| WASM component runtime | Wasmtime 47.x compatibility line; 47.0.3 candidate; Component Model + `wasm32-wasip2` | source-verified PROVISIONAL candidate in the external compatibility ledger; local security/Windows conformance absent | exact patch is resolved only from the current compatibility receipt and lockfile after security/Windows conformance; WASI 0.3/`wasm32-wasip3` remains a laboratory lane |
| Build/test execution plane | isolated `eliot-testd` over EBP; same typed Instrument profiles as local/CI | target default / RGF-INSTRUMENT-TESTING | may be co-located only at D0 as an explicit extraction default; compile storms never share Kernel Control Reserve |
| Deterministic simulation | pure ELIOT event simulator first; Loom plus admitted Shuttle/Turmoil/MadSim adapters | staged / RGF-INSTRUMENT-TESTING | no simulator becomes operational truth; seeds, schedules, failpoints and cassettes are immutable artifacts |
| Windows Human UI | WinUI 3 desktop client on the stable Windows App SDK 2.3.1 line; optional Ratatui terminal board | source-verified TARGET; local UI/usability/recovery conformance absent | thin non-authoritative user-session client over the role-filtered ControlBoard/Operator API; CLI remains the mandatory recovery fallback; browser UI is optional, not the primary surface |

`Cargo.lock`, `compatibility.toml`, Module manifests, and service manifest are the exact source of patch versions. This table defines compatible lines; it does not replace the lockfile.

The table is a reviewed compatibility baseline, not an updater or a current-installation claim. `checked_at`, source identities and local admission live in the external `CompatibilityEvidenceRecord`; immutable manifests and lockfiles remain authoritative for the installed generation.

### Compatibility evidence discipline

Every row above has a `CompatibilityEvidenceRecord` outside prose:

```yaml
CompatibilityEvidenceRecord:
  surface:
  claimed_line_or_version:
  primary_source_ref:
  checked_at:
  source_digest_or_release_identity:
  installed_artifact_identity:
  local_probe_refs:
  status: declared | source_verified | locally_probed | admitted | stale | rejected
  invalidation_conditions:
```

Rules:

```text
`current candidate` means source-verified only; it is not an installed or production-admitted generation;
exact production authority comes from the installed manifest, lockfile, artifact hash and local conformance receipts;
a newer release, changed upstream contract, changed account/route or changed local artifact makes the record stale;
research prose, README text or a previous assistant answer cannot update this table without a primary-source check;
unknown or contradictory version evidence remains visible and blocks only the dependent admission.
```

### Agent Execution Fabric route baseline

| Route surface | Implementation status | Production rule |
|---|---|---|
| Codex App Server over stdio/JSONL | **PRIMARY-1 integration candidate; stable schema surface with separately gated experimental operations** | first durable vertical slice; exact executable/schema hash, stable-only schema pin, current-account probes and rollback required; WebSocket and opt-in experimental methods are non-production until separately admitted |
| OpenCode local server over HTTP/SSE | **PRIMARY-2 candidate** | second provider-neutral execution path; use public OpenAPI/session/event surface; independence is credited only from ActualRouteReceipt/IndependenceProfile; internal runtime DB is forensic-only |
| ACP over stdio | **COMPATIBILITY-1** | baseline methods plus operation-level probes for every optional capability; handshake claims alone are insufficient |
| Claude local Agent SDK | **LATER sidecar** | separate Python/TypeScript sidecar bundle; local route is distinct from hosted Managed Agents |
| Claude Managed Agents | **LATER remote beta** | separate adapter, billing, retention and beta profile; explicit user opt-in |
| Antigravity local SDK/CLI | **LATER sidecar** | local route only until an official remote session/resource/event contract is proven |
| Cursor/Copilot/other preview routes | **EXPERIMENTAL** | pinned bundle, short evidence expiry, stronger verification and visible preview status |

A route is identified by the full `RouteFingerprint`, not by a model ID or vendor label. Every line above is `PROVISIONAL` until exact-version conformance and current-account probes produce evidence. The research sources for this baseline are non-normative and are recorded in I0.3; the current primary-source checks and admission status live in the content-addressed compatibility-evidence receipt bound by the normative-pair identity.

### SurrealDB decision

SurrealDB is first because graph, document, temporal, and structured representations are available under one transaction boundary. License risk and vendor dependence are acknowledged in advance. Therefore:

```text
`eliotd` does not import the SurrealDB SDK;
database credentials belong only to the storage bridge;
all operations use a store-neutral semantic API;
full canonical export is mandatory;
shadow migration to another store is a normal scenario.
```

The choice remains an empirical Default, not a reward for using more SurrealDB-specific syntax. After D1, a `StorageValueProfile` is compiled from the actual named-operation registry:

```yaml
StorageValueProfile:
  exact_store_and_workload_identity:
  canonical_operation_families:
  operations_using_atomic_graph_document_or_temporal_features:
  portable_reference_implementation_and_round_trips:
  latency_tail_resource_and_write_amplification:
  schema_migration_backup_restore_and_operator_cost:
  bridge_query_complexity_and_maintenance_burden:
  product_or_recovery_delta:
  keep_simplify_or_migrate_candidate:
  uncertainty_review_and_kill_condition:
```

If the real workload gains little from the hybrid transaction/query model, simplification to a more mature substrate is an admissible result of `RGF-STORAGE-MIGRATION`; replacement is not limited to another multi-model database. No universal operation-count threshold is frozen in prose.

### Current distribution boundary

The first supported topology is one installation with one logical canonical owner on one primary machine. Two installations do not become replicas merely because they share documents, a provider account or exported files. Cross-device canonical replication, offline multi-writer merge and automatic multi-node failover are not current capabilities. Until a future distributed contract is accepted, transfer between installations uses explicit export/import or migration receipts, and each installation remains an independent authority lineage. Optional remote workers may execute bounded jobs but never become another canonical owner.

## I0.3. Decision sources

Authority and evidence classes are stable; filenames and audit chronology are not part of the normative contract:

1. `ELIOT_ARCHITECTURE.md` — Intent, Theory, Hard Boundaries and decision anchors.
2. This Implementation — current target owners, contracts, defaults, failure behavior and migration paths.
3. Accepted generated contract/registry artifacts — executable projections bound to the exact normative-pair digest; they cannot override either book.
4. Exact code, build, installed-runtime, store and live-operation evidence — support/conformance observations on one Product Identity; they cannot silently rewrite the books.
5. Legacy books, research, donor projects, audits and model reviews — non-normative evidence held in content-addressed external ledgers with scope, provenance, disposition and falsifier. Detailed inactive crate/test/research hypotheses are retained through the current content-addressed cold-backlog evidence receipt and do not enter normal agent context.

A named report, date, vendor document or prior assistant answer never acquires standing by being listed here. The active evidence ledger supplies exact digests and current dispositions; chronological audit prose remains outside this book.

## I0.4. Change classes

| Class | Example | Decider | Minimum verification |
|---|---|---|---|
| Local | UI text, isolated parser, report format | Module owner | Module checks |
| Compatible Module | new Module generation without state migration | Module owner + supervisor policy | contract + affected integration + canary |
| Cross-module | protocol field, shared contract, dependency edge | integration owner | affected graph + compatibility suite |
| Load-bearing | Kernel, store semantics, authority, ORS, security boundary | System Owner + architecture/conformance review | dedicated fault/migration suite |
| Release | published installation | release owner | full release gate |
| Architecture-impacting | changes Intent or Hard Boundary | Architecture Owner | Architecture revision before code promotion |

### Normative pair and evidence artifact identity

Only `ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` form the normative pair. Audits, research, migrations, benchmarks, and generated projections are evidence artifacts: they may disprove a support claim, open a gap, or propose a change, but gain no normative force from name, date, completeness, or citation count.

```yaml
NormativePairDocumentIdentity:
  document_id:
  role: architecture | implementation
  semantic_version:
  sha256:
  predecessor_sha256:
  paired_document_sha256:
  generated_at:
  status: candidate | accepted | superseded | invalidated

EvidenceArtifactIdentity:
  artifact_id:
  role: audit | research | migration_evidence | benchmark | generated_projection
  sha256:
  source_identity_refs:
  scope_and_validity:
  evidence_class_and_execution_status:
  owner_and_disposition:
  invalidation_and_expiry:
```

Hard rules for an intentionally frozen or published revision:

```text
`ELIOT_IMPLEMENTATION.md` and its published versioned copy are byte-identical;
any byte change after freeze creates a new identity and invalidates only verdicts bound to the prior digest;
an audit or PASS applies only to the exact source identities and scope it names;
Architecture/Implementation projections, Skills and agent packets carry the exact normative-pair identity they were compiled from;
no agent may combine sections from two frozen Implementation digests as one current contract;
an EvidenceArtifactIdentity can narrow or invalidate a support claim, but cannot change Architecture/Implementation without the applicable governed document revision.
```

A working draft may change under version control without minting a content-addressed identity or incrementing the display version after every edit; it acquires an identity only at the freeze/publication boundary of I0.14. The pair identity is emitted externally after both files are frozen. This prose never embeds or hand-maintains its own digest.

Normative identifiers, schemas, wire values, reason codes and generated RuleCatalogue entries use English. Explanatory prose may be Russian or English, but one classified rule block and one generated agent instruction are language-homogeneous. Translation is a projection carrying the exact source rule ID/revision; it is not a second contract. Context measurements use the tokenizer of the actual rendered language rather than assuming STU equivalence.

## I0.5. Conformance, support and evidence status

Conformance is evidence-derived state, not maintained prose. Three orthogonal dimensions are mandatory:

```text
ContractMaturity
  SKELETON | COMPATIBLE | STABLE | REPLACEABLE | RETIRED;

ImplementationSupport
  CURRENT_VERIFIED | CURRENT_UNVERIFIED | PARTIAL | BLOCKED | TARGET |
  EXPERIMENTAL | DEFERRED | DEGRADED | STALE | NOT_APPLICABLE;

EvidenceExecutionStatus
  NOT_EXECUTED | SIMULATED | EXECUTED | UNKNOWN_OUTCOME.
```

A detailed schema, trait, command or state machine in this book is `TARGET` unless exact current source handles and current Product Identity evidence say otherwise. `TARGET` is a design obligation, not evidence that a capability exists. A source implementation can be `CURRENT_UNVERIFIED`; a generated report cannot promote it.

Canonical evidence binds every support claim to an exact Product Identity and invalidation set. `docs/conformance.toml` is the deterministic, read-only **documentation projection** of M1 Architecture IDs and Appendix H. It proves mapping completeness only; it is not runtime/source support evidence and cannot promote any row above `TARGET` / `NOT_EXECUTED` without separate exact evidence. Each row preserves the exact human Appendix-H owner cell as `owner_projection`; that field is unparsed documentation text, not an executable owner registry or authority grant:

```toml
projection_status = "DOCUMENTATION_TARGET"
runtime_evidence_status = "NOT_EVIDENCE"
normative_pair_receipt = "docs/normative-pair.toml"

[[requirement]]
id = "ARCH-MOD-01"
owner_projection = "I1, I2, I14.14–I14.16"
observable_proof_family = "optional module crash while Kernel remains healthy"
contract_maturity = "SKELETON"
implementation_support = "TARGET"
evidence_execution_status = "NOT_EXECUTED"
source_handles = []
evidence_refs = []
notes = "documentation mapping only; exact runtime/source support remains unproven"
```

Rules:

```text
CURRENT_VERIFIED requires executed, current, scoped evidence on the exact identity;
CURRENT_UNVERIFIED means source exists but product behavior is not proven;
TARGET/EXPERIMENTAL/DEFERRED cannot satisfy current product acceptance;
NOT_EXECUTED or SIMULATED evidence cannot satisfy a real-effect verifier;
any invalidated dependency makes support STALE;
report wording, test count, trait presence or manual status edit cannot promote support;
several ARCH anchors may share one end-to-end proof;
no separate test is required merely because an ID exists.
```

### Current-system evidence snapshot

Current implementation support is never inferred from this prose. A generated `CurrentSystemEvidenceSnapshot` binds the exact repository/runtime/data state used by repair, migration, product and deletion decisions:

```yaml
CurrentSystemEvidenceSnapshot:
  snapshot_id_revision_and_digest:
  normative_pair_identity:
  compiler_and_execution_receipt:
  product_identity_and_source_heads:
  installed_artifact_and_generation_hashes:
  active_store_schema_and_data_revision:
  active_integration_skill_hook_and_surface_manifest_digests:
  domain_coverage:
    source: OBSERVED | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    build: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    runtime: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    store: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    integrations: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
  capability_support_rows:
    - contract_ref:
      support_claim_ref:
      support_observation_state: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
      contract_maturity:
      implementation_support:
      evidence_execution_status:
      source_handles:
      evidence_refs:
      blind_or_unobserved_boundaries:
      invalidation_set:
  current_product_blockers_and_unresolved_regressions:
  generated_at_expiry_and_invalidation:
```

Each capability row carries the exact three I0.5 dimensions. `support_observation_state` describes observation availability/state only; it is not an `ImplementationSupport` value. `UNKNOWN`, `UNAVAILABLE`, `NOT_RUNNING` or `CONFLICTED` observation cannot be copied into support, maturity or evidence execution. A bound support claim remains at the strongest state actually justified by exact evidence: absent source evidence stays `TARGET` / `NOT_EXECUTED`; present but behavior-unproven source may be `CURRENT_UNVERIFIED`; incomplete behavior may be `PARTIAL` or `DEGRADED`; invalidated evidence is `STALE`. A report may render these values only from `support_claim_ref`; manual report text cannot promote them.

`CurrentSystemEvidenceCompiler` is a D0 FunctionalCapabilityCell with no canonical mutable state. Its source-maintenance owner is the first-party `eliot-bootstrap` crate; its D0 execution owner is the short-lived `eliot.exe` command `eliot system snapshot`. After InstrumentRunner exists, the same pure compiler core executes as a typed Instrument profile and Governor admits the immutable artifact. The crate also contains the bootstrap-only adapters required to read exact repository/worktree identity, build artifacts, service/process manifests, config/policy, optional runtime/store probes and integration manifests; platform/tool adapters remain behind narrow ports. It never infers a running system from prose or a PID alone, and it does not become a daemon, store or status owner.

The compiler has an independent ModuleTestCapsule covering partial source trees, absent runtime/store, stale manifests, conflicting identities, forged support statuses and interrupted probes. A Human-provided fact is preserved as an attributed observation; it cannot directly set `CURRENT_VERIFIED` or `EXECUTED`. Manual YAML editing is not an admitted producer.

The snapshot is regenerated after any source/runtime/data change and before a repair campaign, repository cutover, old-document deletion or product claim. Missing domains remain explicit as `support_observation_state = NOT_RUNNING | UNKNOWN | UNAVAILABLE | STALE | CONFLICTED`; they never create an `ImplementationSupport` value. An absent runtime is `NOT_RUNNING`, not a global compiler failure. Dependent support remains at the strongest state justified by exact current evidence; absence or staleness never promotes a target contract to current support.

## I0.6. Decision records

An ADR is required only when a decision:

```text
changes a load-bearing default;
creates a new authority or state owner;
adds a Kernel hard dependency;
changes a canonical format or protocol;
deviates from Architecture;
makes an experiment the production default.
```

Ordinary implementation of an existing contract does not require an ADR.

## I0.7. Documentation-cycle stopping rule

Implementation is sufficiently defined for code work when:

```text
an owner exists for every process and mutable state;
the protocol and failure behavior of the first vertical spine are defined;
there is no hidden second write path;
the system can be built, started, verified, and stopped;
a local change has a clear affected-test path;
unknown details are marked as a Research Gate rather than disguised as guesses.
```

The document need not define every data structure in advance. A concrete structure appears when required by the next layer.

After these conditions are met, new prose is allowed only when it closes an unresolved decision in the next executable slice. As implementation proceeds, wire schemas, error registries, state tables, test inventories, compatibility matrices, and contract indexes move to generated artifacts; the book retains rationale, owners, failure behavior, and links.

`ContractSurfaceProfile` measures not “document quality” with one number, but operational cost:

```text
number of contracts actually applicable to one work unit;
serialized instruction/contract token cost;
number of expansion handles and stale projections;
change fan-out of one contract;
orientation time and Contract Challenge frequency;
agent errors caused by conflicting or overloaded instructions;
share of prose already duplicating executable schema or code.
```

Growth of this surface without Product or Recovery delta triggers simplification, merge, or generation review—not another documentation campaign.

---

## I0.8. Donor migration and retirement policy

Until the old three books are retired, every useful donor decision has one disposition in the current content-addressed donor-retirement ledger:

```text
RETAIN      — transferred without semantic change;
MERGE       — preserved inside a broader current contract;
SUPERSEDE   — intentionally replaced by Architecture/Implementation;
DEFER       — valuable but belongs to a later capability layer;
REJECT      — obsolete, contradictory or overengineered;
UNKNOWN     — cannot be decided before code/data audit or experiment.
```

Rules:

```text
Architecture wins every semantic conflict;
Implementation wins concrete conflicts after its corresponding contract is accepted;
old text never remains normative merely because it is more detailed;
RETAIN/MERGE require a live owning I-section or a current ContractCatalogueEntry; a cold inventory may only point to that owner;
SUPERSEDE/REJECT require a reason;
UNKNOWN blocks deletion of the donor section, not unrelated development;
no donor file is deleted until the donor migration audit has zero unresolved load-bearing items and the I19 retirement proof passes.
```

Useful exact semantics are preserved in an owning I-section and, when a concrete schema is needed, in the contract catalogue/IDL. Historical manual inventories remain cold evidence and never become an active schema source. Historical work packages, giant test matrices, obsolete phase gates and addendum precedence are not imported as current requirements.

Retirement has five independent proof classes:

```text
P1 syntactic inventory
   every supplied heading, named object and explicit rule has a disposition;

P2 semantic preservation
   each load-bearing item names current owner, behavior, failure behavior and proof,
   or an explicit supersession/rejection/defer rationale;

P3 active-reference migration
   repository source, tests, schemas, Skills, prompts, configs, CI and generated artifacts
   no longer use donor prose as active authority;

P4 runtime/data migration
   persisted records, live integrations, installed agents and reports no longer depend on
   donor paths or obsolete semantics;

P5 recovery and owner cutover
   exact archive restores, new pair is installed and discoverable, active authority contract
   points to it, and System/Architecture Owner approves retirement.
```

`P1/P2 PASS` does not imply `P3–P5 PASS`. Broad chapter mapping or identifier occurrence is navigation evidence, not proof of semantic preservation.

Audit status is always qualified by class:

```text
INVENTORY_COMPLETE       — supplied source units were enumerated;
SEMANTIC_REVIEWED        — independent ideas received owner/rationale/falsifier review;
DOCUMENT_CONFORMANT      — current Architecture/Implementation bytes have no known document contradiction in the stated scope;
SOURCE_VERIFIED          — exact code/schema/config identity implements the claim;
RUNTIME_VERIFIED         — the exact installed generation produced executed evidence;
PRODUCT_VERIFIED         — the declared user/product property passed its evaluation plan.
```

Unqualified `PASS`, heading counts, keyword coverage, generated manifests or auditor confidence cannot be promoted across these classes. Every audit claim names exact bytes, scope, blind spots and invalidation conditions.

## I0.9. Contract maturity

Every concrete contract has one maturity:

```text
SKELETON     — owner and boundary fixed; payload may still evolve;
COMPATIBLE   — wire/state shape versioned and used by at least one real path;
STABLE       — migration, failure and compatibility behavior proven;
REPLACEABLE  — alternative implementation passed equivalence/cutover proof;
RETIRED      — no active producer/consumer; history and migration retained.
```

`SKELETON` is sufficient for early layers only when missing depth is visible and does not cross a Hard Boundary. Agents must not interpret a detailed YAML example as `STABLE` unless the registry says so.

---


## I0.10. User outcome, recovery invariants and anti-proxy development contract

ELIOT distinguishes the reason the product exists from the safety properties required to build it.

```text
UserOutcomeObjective
  observable improvement for a real user/agent on a real task;

ArchitectureSafetyInvariantSet
  authority, integrity, provenance, finish, recovery and privacy properties
  that must hold while pursuing the outcome;

RecoveryAcceptanceProfile
  the bounded set of currently blocking invariant gaps whose closure enables
  the next product experiment.
```

A `RecoveryAcceptanceProfile` is compiled from the current `CurrentSystemEvidenceSnapshot`, active conformance Problems and the accepted objective. Historical failures such as split identity, shadow authority, lossy payload, weak finish, synthetic verification or a broken memory lifecycle are **regression probes**, not assertions about an unseen current tree. A probe becomes a current repair obligation only after it discriminates the exact current Product Identity.

Closing a recovery profile does not establish product value. It may be satisfied in a toy environment without improving real work. Product success additionally requires evidence appropriate to the claim. A deterministic one-scope product property may use the exact pre-change observed behavior or a declared `not_applicable_with_reason` comparison when no separate control can change the conclusion. Stochastic, comparative, population-level, non-inferiority or generalization claims require the applicable baseline/control and `ProductEvaluationPlan`.

Definitions:

| Concept | Meaning |
|---|---|
| **UserOutcomeObjective** | The user-visible or task-visible effect ELIOT is intended to improve |
| **Causal Property** | One observable system property changed by one work unit |
| **Discriminator** | Evidence that separates the proposed mechanism from the old path or a rival explanation |
| **Product Proof** | End-to-end outcome evidence on an exact Product Identity, with a claim-appropriate comparison or exact pre-change behavior, counter-metrics, uncertainty and applicable independent evaluation |
| **Activity Artifact** | Test, receipt, report, diff, type, status or log; evidence, never product success by itself |

```yaml
UserOutcomeObjectiveState:
  objective_id:
  owner:
  task_family_and_population:
  intended_user_outcome:
  primary_outcome_measure:
  comparison_basis: exact_prechange_behavior | matched_control | memory_free_control |
                    historical_reference | not_applicable_with_reason
  counter_metrics:
  disproof_and_stop_conditions:
  evaluation_plan_ref:
  product_identity_ref:
  outcome_evidence_refs:
  status: active | achieved | refuted | superseded | cancelled
  revision:

RecoveryAcceptanceProfile:
  profile_id:
  objective_ref:
  invariant_gaps:
  affected_owners:
  discriminators:
  enablement_condition:
  status: active | satisfied | superseded
  revision:
```

Only the `Requester / Domain Owner`, or a Human explicitly delegated that exact goal/acceptance authority, can revise the `UserOutcomeObjective`. The Task Controller owns the current execution-plan revision and may propose clarification, narrowing or supersession; it cannot silently redefine the user outcome. Dreamer, Watchdog, tests and reports propose or observe; they do not define success. `achieved` requires the predeclared acceptance/outcome on an exact Product Identity and the evaluation depth appropriate to the claim. Formal preregistration and inferential planning are mandatory only for stochastic, comparative or generalizing claims; a deterministic vertical-spine property may close through an exact old-path discriminator, corrected-path proof and applicable fault/restart cases. Closing every invariant gap does not automatically set the product outcome.

Rules:

```text
report/test/receipt/hash/certificate does not close a property it did not measure;
local PASS does not promote product status;
progress requires new evidence, artifact, verified state or lower material uncertainty;
status `ready`, `complete` or `certified` is scoped to exact identity and proof;
test/line/commit/type/tool/phase/token counts are counter-metrics, not goals;
a second repair of one failure class requires a new causal hypothesis or Mechanism Review;
a defect closes by changed product behavior, not by a new report.
```

Documentation changes before code only for public contract, ownership, Hard Boundary, migration or accepted default. Local mechanism choices may be resolved by bounded experiments and documented immediately after the discriminator. Prose that replaces the next discriminative artifact is development failure.

### Current recovery priority and promotion boundary

The normative book does not freeze a historical blocker list. The active `RecoveryAcceptanceProfile` is generated from the current `CurrentSystemEvidenceSnapshot`, accepted Product Objective and unresolved conformance Problems. It names exact source/runtime/data identities, affected owners, discriminators, enablement conditions and expiry. Historical findings such as permissive finish, lossy payloads, shadow writers or synthetic verification remain external regression evidence until the current snapshot confirms or refutes them; they are not silently asserted about an unseen tree.

This is **not a global feature freeze**. A confirmed blocker limits production promotion, authority, release claims and integration paths that depend on it.

Allowed before full impact proof:

```text
read-only investigation;
contract/test/discriminator work;
isolated module or prototype work with no canonical/external effects;
WASM/process shadow generations with zero authority;
research and tool experiments in a declared disposable environment;
work on unrelated owners under explicit dependency assumptions.
```

If dependency on a blocker is unknown, the result remains an isolated candidate and cannot enter the affected production path until the edge is resolved. Unknown dependency does not stop unrelated micro-modular development. Promotion requires affected-edge evidence; exploration does not.

### Rule classes at runtime

Operational rules are resolved through one generated catalogue, not inferred from prose grammar:

```yaml
RuleCatalogueEntry:
  rule_id_and_revision:
  class: HardBoundary | Contract | Guardrail | Default | Experiment | Policy
  architecture_anchor_or_policy_root:
  owning_implementation_section_and_capability:
  scope_and_applicability:
  rationale_and_failure_class:
  observable_property_or_decision_changed:
  enforcement_or_degraded_behavior:
  challenge_deviation_or_change_path:
  invalidation_and_expiry:

RuleBinding:
  rule_ref_and_exact_revision:
  work_unit_task_scope_and_state_fence:
  rendered_instruction_or_directive_ref:
  applied_or_not_applicable_reason:
  authority_and_effect_ceiling:
  delivery_and_acknowledgement_receipt:
```

Classification rules:

```text
HardBoundary
  → requires an Architecture Hard Boundary/authority/privacy/proof anchor;
  → Implementation cannot create it from convenience prose;
  → deviation is impossible without the applicable Architecture/authority change.

Contract
  → observable obligation of one capability;
  → failure returns typed degraded/unsupported state rather than invented success.

Guardrail / Default
  → may be challenged through evidence-backed ImplementationDeviation.

Experiment
  → reversible candidate with discriminator, budget, stop and rollback.

Policy
  → Human-owned privacy/cost/risk/model choice within Architecture.
```

Unregistered prose is explanation, rationale or design context. It may not be the sole source of a blocker, permission, reason code, automatic stop or deviation. One classified block may cover several explanatory sentences; a lint that merely counts modal verbs is explicitly rejected as proxy work. The documentation/evidence build instead verifies that every generated directive, blocking decision, reason code and `ImplementationDeviation` resolves to a current `RuleCatalogueEntry`. If a compiled brief includes modal or imperative prose without such a binding, it is rendered explicitly as `NONBINDING_CONTEXT`; planner, reviewer and deviation logic may not treat it as executable authority.

`NormativeCoverageManifest` accompanies every compiled brief:

```yaml
NormativeCoverageManifest:
  pair_and_catalogue_revision:
  searched_rule_scopes:
  included_rule_bindings:
  excluded_with_reason:
  not_searched_scopes:
  searched_and_absent_questions:
  stale_or_conflicting_rules:
  expansion_handles:
```

For Guardrail and Default an `ImplementationDeviation` is always available. Contract failure uses its declared degraded behavior; it is not silently reclassified. HardBoundary remains fail-closed. A missing or stale rule binding cannot be interpreted as permission.

The D0 `BootstrapRuleCatalogueCompiler` is a third pure FunctionalCapabilityCell in `eliot-bootstrap`. It compiles only explicitly registered Architecture Hard Boundaries, capability contracts, current development guardrails/defaults, active Human policies and admitted experiments into a content-addressed catalogue. It does not classify arbitrary prose by language-model judgment. The initial bootstrap catalogue is a generated evidence artifact with section handles and exact normative-pair identity; after the normal Contract Catalogue exists, the bootstrap projection is generated from that owner and ceases to be an independent input. Catalogue absence yields `NORMATIVE_COVERAGE_INCOMPLETE`, never implicit permission or a global stop unrelated to the missing scope.

## I0.11. Research, donor and audit evidence policy

Research papers, external projects, legacy books, and model audits are evidence and mechanism donors. They are not a third normative book and receive no runtime authority.

Three distinct results must not be conflated:

```text
Source inventory
  — the source was actually read and its independent ideas listed;

Semantic disposition
  — every applicable idea received RETAIN, MERGE, SUPERSEDE,
    DEFER, or REJECT with rationale;

Implementation support
  — the mechanism exists in exact source, runtime, and data identity and passed
    applicable executed proof.
```

Counts of headings, keywords, catalogue rows, or mapped findings prove only inventory and traceability. They do not prove semantic correctness, much less code support.

Every accepted donor idea has:

```text
pinned source identity;
current ELIOT owner;
observable contract and failure behavior;
negative case or falsifier;
support status and invalidation set;
explicitly rejected overgeneralization.
```

Audit chronology, source inventories, and detailed dispositions live in an external content-addressed evidence ledger. This book stores only the current contract. An Implementation change is not closed by a new report: audit and evidence must be rebound to the exact new bytes.

## I0.12. Prototype and execution-contour policy

ELIOT is crate-rich, process-sparse, and owner-sparse. Source decomposition, execution isolation, and deployment lifecycle are separate decisions.

Current execution defaults:

```text
pure bounded experimental logic
  → capability-limited component contour (currently WASM Component Model);

OS/Cargo/Git/LSP/browser/native-library/credential-heavy logic
  → isolated native process generation;

measured trusted hot path
  → static native release generation only after evidence.
```

For the default no-authority component contour, `PrototypeContourDecision` is generated automatically from the Module contract and manifest. Manual rationale is mandatory only when a prototype:

```text
selects a non-default contour;
receives credentials, authority, or external effects;
enters canary or active traffic;
changes state, migration, or recovery semantics;
claims static-native promotion.
```

Promotion remains generational:

```text
contract/conformance
→ replay
→ effect-free shadow
→ bounded canary
→ ORS cutover and new epoch
→ drain / forward rollback.
```

Neither WASM, process isolation, nor static linking creates semantic authority. One contour-independent core and conformance corpus test equivalence across admissible backends.

## I0.13. Current support, conformance and product status

Architecture defines meaning; Implementation defines the current target contract; exact code, runtime, and data evidence demonstrates support.

Every load-bearing contract has independent `ImplementationSupport`:

```text
CURRENT_VERIFIED;
CURRENT_UNVERIFIED;
PARTIAL;
BLOCKED;
TARGET;
EXPERIMENTAL;
DEFERRED;
DEGRADED;
STALE;
NOT_APPLICABLE.
```

A prose type, CLI example, schema, report, or generated catalogue row is `TARGET` by default unless exact source handles, Product Identity, executed evidence, verifier, and invalidation set exist.

Current product status:

```text
Architecture direction: accepted for continued design;
Implementation document: target contract;
local current source: UNKNOWN until CurrentSystemEvidenceSnapshot;
installed runtime: UNKNOWN;
live store/data revision: UNKNOWN;
product: NOT_ACCEPTED / UNVERIFIED.
```

No audit package, manifest, or test count can elevate this status without Product Proof.

## I0.14. Documentation and evidence-build integrity

Documentation integrity is proportional to the decision being made. Routine drafting must not become a release ceremony.

### Working-draft path

Normal iterative edits use:

```text
version control and one visible diff;
Markdown/reference/contract-owner lint;
current section-level review;
no mandatory audit report, ZIP, manifest or archive;
no claim that the draft is accepted or independently verified.
```

A working draft may change repeatedly. Its display version is not a Product Identity and no evidence package is required after every edit.

### Freeze/publication path

Content-addressed packaging is required only when the exact bytes become load-bearing outside the current editing episode, for example:

```text
normative-pair candidate/cutover;
external independent audit;
repository authority migration;
old-document deletion gate;
release or handoff that cites an exact document identity;
forensic/recovery archive.
```

Then the sequence is:

```text
1. Assemble immutable staging inputs.
2. Render documents and required machine ledgers once.
3. Reject unresolved template placeholders, duplicate owners and broken references.
4. Freeze bytes.
5. Compute pair identity and required evidence digests.
6. Build only the package required by the decision.
7. Re-extract that package and verify payload digests/references.
8. Publish atomically.
```

After freezing, any byte change creates a new candidate identity and invalidates only audits/packages that depended on the prior bytes. It does **not** require regenerating unrelated historical packages or a new prose audit merely to continue drafting.

`DocumentationEvidenceCheck` for a frozen decision verifies at least:

```text
current/versioned byte equality when a versioned copy is intentionally published;
manifest/package digest equality for the package actually being used;
no unresolved template sentinel;
referenced local evidence resolves by digest or declared external URI;
generated counts are recomputed from payloads;
no audit claims CURRENT_VERIFIED without executable evidence;
no normative section stores chronological audit history already held by the ledger.
```

A successful documentation check proves artifact integrity and traceability only. It is not Product Proof and cannot certify code/runtime/data conformance.

The normative pair is identified externally after both files are intentionally frozen:

```yaml
NormativePairIdentity:
  pair_key: hash(architecture_sha256, implementation_sha256)
  architecture_revision_and_sha256:
  implementation_revision_and_sha256:
  derived_contract_catalogue_or_generation_refs: # evidence only; not a third normative document
  external_requirement_and_decision_evidence_refs: # evidence only; do not change pair_key
  created_at_and_builder_identity:
  evidence_package_manifest_ref: # optional; required only when the freeze/publication decision uses a package
  supersedes_identity_ref:
```

Only the two document digests form `pair_key`. Requirements ledgers, contract catalogues, audits and packages remain evidence/projections and cannot become a third normative book.

The Implementation never contains its own final digest as authority. Handshakes, cutovers and audits use the external pair receipt. A normal working-draft edit needs no content-addressed package until one of the freeze/publication triggers occurs.

# I1. Concrete process topology

## I1.1. Process principle

A process boundary is used when at least one of these is required:

```text
independent restart;
hot replacement;
isolation of crashes or native code;
credential isolation;
resource-use limits;
connection of an unchanged third-party project;
independent security observation.
```

Pure computation with safe cancellation remains an in-process task or crate. Not every Architecture concept becomes a process.

## I1.2. Required processes of the first complete runtime

### 1. `eliot-host.exe`

Minimal Windows service and external Host Supervisor.

**Owns:**

```text
installation root;
approved build registry;
HostStateJournal and HostInstallationEpoch;
start/stop/restart Kernel;
start/stop isolated managed dependency branches, including the canonical store process;
request start/stop of the independent Watchdog service through SCM;
last-known-good selection for managed Kernel/dependency artifacts;
minimal recovery and rollback command channel.

Host does not select or replace its own service binary while running; Host-service replacement belongs to the installer/SCM procedure of I14.
```

**Does not own:** project semantics, canonical memory, Sessions, tasks, model routing, repairs, or Architecture decisions.

The code must remain small, dependency-light, and rarely changed. It loads no SurrealDB SDK, MCP, HTTP UI, or model clients.

### 2. `eliot-kernel.exe`

Resilient part of Governor.

**Owns:**

```text
local front-door IPC;
principal/session binding;
Authority Epochs and fencing;
Operational Recovery State;
Control Reserve;
Module/daemon generation routing;
canonical transition gateway;
minimal health and Recovery View;
startup/drain orchestration;
connection to store bridge.
```

**Does not perform:** semantic curation, Dreamer jobs, code graphs, UI, full task planning, or broad retrieval.

### 3. `eliotd.exe`

Primary Governor application daemon.

**Owns:**

```text
WorkScopes;
tasks and current plan revisions;
write admission;
read models;
Context Compiler;
Agent Coordinator;
Durable Jobs;
problem/conflict/attention application state;
module orchestration;
reports and normal API behavior.
```

Kernel can hot-replace it. Its restart changes neither canonical owner nor the validity of stale leases.

### 4. `eliot-watchdog.exe`

Independent supervision daemon installed as a separate SCM-managed service or process. Host requests start and stop through SCM, but owns neither its Job Object nor a kill-on-close handle. A Host, Kernel, or `eliotd` crash therefore does not automatically terminate Watchdog. Watchdog preserves a minimal independent signal spool and audit anchor.

### 5. `eliot-store-surreal.exe`

Storage bridge. The only ELIOT process with SurrealDB credentials and SDK.

```text
Kernel / eliotd
→ EBP Store service
→ eliot-store-surreal.exe
→ SurrealDB RPC
→ SurrealDB server.
```

Bridge accepts only closed semantic store operations and named queries. Raw SurrealQL over the runtime protocol is prohibited.

### 6. BlobStore capability; optional `eliot-blob.exe` generation

Vendor-neutral immutable payload service. It owns the Blob Store root, temporary staging, hashing, compression, local encryption envelope, reachability/GC metadata and `BlobReadyReceipt`. It has no SurrealDB credentials, no semantic query surface and no right to create canonical references by itself.

```text
agent/module/tool stream
→ governed BlobStageRequest
→ eliot-blob writes immutable CAS object
→ BlobReadyReceipt
→ canonical transition may reference BlobRef
→ failed canonical commit leaves a harmless orphan for bounded GC.
```

The target process boundary isolates untrusted large payloads, compression/native libraries, disk pressure and retention work from Kernel and the canonical DB bridge. During D1 the same `BlobStore` contract may run as an internal capability of `eliot-store-surreal` or `eliotd` as a declared Delivery Default, provided that it has one data-root owner, separate bounded resources, no SurrealDB credential leakage and an independently extractable state format. Separate `eliot-blob.exe` becomes admissible when untrusted/large-payload pressure, native codec risk, independent GC/restart, credential isolation or measured contention justifies a process boundary. Delivery depth alone does not mandate the executable. This staged co-location is not an Architecture deviation; changing the public contract or creating two blob-root owners is.

### 7. `surreal.exe`

Separate Host-managed dependency process in its own Job Object, owning the database files. It may start on demand and survives restart of `eliot-kernel` or `eliotd` because it is not in the Kernel Job Object. Host starts it from an immutable process manifest and observes process exit; Kernel and store bridge check database readiness and semantic compatibility. ELIOT does not require upstream `surreal.exe` to implement the Windows SCM service protocol and does not make a third-party service wrapper mandatory.

## I1.3. Optional and on-demand processes

### `eliot-dreamer.exe`

Separate AI service or server. Starts with the first Dreamer job or in a maintenance window, then stops after an idle period.

### `eliot-doctor.exe`

Short-lived diagnostic and repair worker. `eliotd` usually requests its start, but Kernel may cause it to start through Recovery Manifest when the application daemon is unavailable. A persistent Doctor agent is prohibited. Any canonical Doctor result applies only through the Kernel or Governor recovery gateway.

### `eliot-mod-<id>.exe`

Process Modules: code graph, LSP bridge, Researcher provider, external tool, cloud laboratory, model provider, report renderer, and other optional capabilities.

### `eliot-ui.exe`

Windows-native desktop client. The first implementation uses WinUI 3 on the stable Windows App SDK line as a thin C# user-session adapter; Rust remains the control plane and owner of all domain state. The Start Menu/desktop entry invokes the one-shot `eliot ui` bootstrap, which starts or reuses the authenticated User Broker and asks it to launch the UI as a broker-owned user-session child. The UI speaks only the role-filtered ControlBoard/Operator contract over authenticated local IPC and has no database, storage-bridge, package-manager or agent-runtime credentials of its own.

It hosts the Dreamer chat, project/onboarding views, agent and swarm launch controls, maintenance/configuration workflows, notifications and recovery guidance. Closing or crashing the UI does not stop active tasks, Dreamer jobs or the agent path. A browser surface may exist later as an optional compatibility/remote-view adapter, but it is not the primary Windows desktop surface.

### `eliot-user-broker.exe`

On-demand process inside an authenticated interactive Windows user session. It is required for routes whose subscription entitlement, credentials, desktop profile or host configuration belongs to that user rather than to the service account.

```text
Kernel / eliotd
→ issue scoped UserExecutionRequest
→ authenticate broker by installation ID + Windows SID + session ID + launch nonce
→ broker launches the exact approved runtime/adapter bundle in the user session
→ raw/normalized events, usage and effects return through EBP
→ Governor retains task, budget, authority, recovery and finish ownership.
```

The broker owns no canonical state, scheduler, route policy or durable attempt journal. It may materialize only explicitly delegated user-scoped credential/config handles, open the approved local Human surface, deliver user-session notifications and launch approved interactive routes or workspace adapters. User-owned filesystem, Git, LSP and professional-tool operations run through this branch when the service identity lacks the WorkScope ACL; every request carries exact roots, effect set and lease. The broker cannot widen paths, privacy class, budget, tools or child-agent envelope and does not expose a generic shell to the service.

The service does not manufacture an interactive logon token. The broker is started in user context by an approved per-user bootstrap — normally an agent bridge, the one-shot `eliot ui` launcher or a signed Task Scheduler entry created during installation — and then registers with Kernel. The native UI itself is never the bootstrap authority for the broker that owns it. The broker owns a scoped Job Object for the UI and launched runtimes, publishes process lineage and heartbeats, and exits after its user-session leases drain. Kernel and Watchdog verify the registered SID/session/process lineage; a broker surviving logoff or registration expiry loses launch/effect authority.

The active broker registration carries a short monotonic Kernel heartbeat/lease. Loss of Kernel heartbeat, registration expiry or epoch mismatch immediately stops new launches and new effects; already issued exact effects follow their operation permit and then the broker drains or terminates its Job Object. A broker never treats mere process survival as continuing authority.

If no matching interactive user session exists, subscription- or desktop-bound work becomes `DEFERRED_CAPACITY` or `ROUTE_UNAVAILABLE`. Background work may use only service-safe API/local routes approved for the service identity. ELIOT never copies a user's session secrets into a machine service merely to keep a route available.

### Canonical CLI and agent stdio shims

#### `eliot.exe`

One canonical user/agent/operator CLI. It is a short-lived surface over the same Kernel/Governor contracts and owns no semantic state, scheduler, policy or recovery journal. Command families are:

```text
eliot system ...
eliot bootstrap ...
eliot dev ...
eliot module ...
eliot instrument ...
eliot doctor ...
eliot recovery ...
eliot backup ...
eliot maintenance ...
eliot ui
eliot dashboard
```

`eliotctl` and `eliot-dev` are not canonical command names. Temporary migration shims, if shipped, only forward to `eliot` and are excluded from generated help/contracts after their declared expiry. The current Appendix J artifact is a bootstrap retained candidate catalogue; only a future admitted command catalogue plus compiled `eliot --help`, exact source handles and execution receipts can establish support. Prose cannot define a second CLI.

### `eliot-notify.exe`

Per-user, one-shot notification adapter. Normal launch is through the authorized User Broker. For control-plane loss, installation may register a signed Task Scheduler fallback that launches it in an existing authorized user session to read only the signed Watchdog notification envelope. It owns no canonical state and cannot execute repair or authority transitions. Its processes belong to the User Broker Job Object or the installer-owned one-shot scheduled-task boundary and terminate after delivery.


Thin processes `eliot-agent-bridge.exe --profile <id>`. They:

```text
start ELIOT through SCM when needed;
connect to the Kernel pipe;
translate the host protocol into EBP or MCP;
contain no durable state;
receive no database credentials.
```

### `eliot-testd.exe`

On-demand isolated build/test/simulation service. It is the execution plane for `InstrumentRunner`, not a second scheduler or task database.

```text
eliotd / InstrumentRunner
→ Durable TestdJob + exact InstrumentProfile + State Fence
→ Kernel starts/adopts an approved `eliot-testd` generation
→ testd provisions worktree/build sandbox and tool processes
→ raw artifacts + normalized evidence + VerificationReceipt
→ Governor admission and task verifier binding.
```

`eliot-testd` owns only active build/test process trees, temporary build roots, local dependency caches and parser checkpoints. It has no SurrealDB credentials, cannot finish tasks, cannot change agent budgets and cannot turn a tool exit code into canonical truth. It uses the same `eliot-process-windows` execution semantics as every other governed native tool. A compile storm consumes a dedicated execution pool and cannot consume Kernel Control Reserve.

During D0 the contract may be hosted by a thin separate process with only `fmt/check/test` profiles. Before agent-generated Rust, fuzzing, mutation, simulation or component promotion is admitted, the separate process boundary is mandatory.

### `eliot-wasm-host.exe`

On-demand Wasmtime Component Model host. It runs immutable component generations under explicit WIT worlds and capability grants. It has no canonical DB credentials, raw process capability, user secrets or general filesystem/network access unless a specific imported capability is present in the admitted world.

The host owns compiled component caches, instance pools, Store limits and shadow/canary execution. Governor owns component admission, policy, routing, effects and promotion decisions. A trap terminates the affected Store/instance or generation; it does not mutate Kernel state.

### `eliot-native-worker-<class>.exe`

Generic isolated native process generation for OS-heavy or promoted component code. It uses versioned EBP/native protocol and is pinned to one artifact manifest, capability envelope and Authority Epoch. Typical classes are compiler/test worker, LSP/code-intelligence worker, browser/professional-tool worker and measured native policy worker.

The native worker never shares Rust references or allocator ownership with Kernel/`eliotd`. Direct `.dll`/`.so` loading into those processes is not an admitted replacement mechanism.

## I1.4. Supervision tree

```text
Windows SCM
├─ Eliot Host service
│  ├─ Host-owned Kernel Job Object (`KILL_ON_JOB_CLOSE`)
│  │  └─ eliot-kernel
│  │     ├─ eliot-store-surreal
│  │     ├─ BlobStore capability (co-located or optional process generation)
│  │     ├─ eliotd
│  │     ├─ eliot-testd
│  │     │  └─ governed Cargo/rustc/test/sim process trees
│  │     ├─ eliot-wasm-host
│  │     ├─ eliot-native-worker-*
│  │     ├─ eliot-dreamer
│  │     ├─ eliot-doctor
│  │     ├─ eliot-mod-*
│  │     └─ service-safe agent/model jobs
│  └─ Host-owned canonical-store Job Object (`KILL_ON_JOB_CLOSE`)
│     └─ surreal.exe
└─ Eliot Watchdog service

Authorized interactive Windows user session
├─ eliot CLI (one-shot)
├─ eliot-user-broker
│  ├─ eliot-ui in the broker-owned Job Object
│  └─ subscription/desktop-bound runtimes in the broker-owned Job Object
└─ eliot-notify (one-shot via broker or signed scheduled fallback)
```

The User Broker branch is deliberately outside SCM and Host Job Objects. It is supervised in the interactive user's security context, while Kernel owns only registration, route admission, scoped launch leases and reconciliation. Exactly one active broker registration is allowed per installation + Windows SID + interactive session; a new `UserBrokerEpoch` fences the previous registration, and processes from an old broker epoch cannot receive new effect authority.

Watchdog is an SCM-owned sibling service. Kernel and the canonical-store process reside in separate Host-owned Job Objects: restarting Kernel or daemon need not stop the database process, while Host failure terminates both Host lineages, after which SCM and Watchdog initiate recovery. Kernel always belongs to exactly one `HostInstallationEpoch` and dedicated Job Object. Unexpected Kernel exit causes Host to close or terminate the entire Kernel Job Object lineage before any replacement Kernel can activate; surviving child PIDs are never adopted as the new lineage. The separate canonical-store branch may remain running, but no bridge, daemon, or Module from the failed Kernel branch retains authority. Loss of the Host process closes Job Objects and terminates managed process lineages; a detached Kernel or store process is not treated as continuing active supervision or authority. If the OS cannot prove termination, Watchdog marks the lineage suspect, closes normal admission, and requires the new Host to perform containment, fencing, and a store-integrity probe first.

`eliotd` makes semantic lifecycle decisions; Kernel physically performs start, stop, switch, and fence. Service-safe Process Modules, Dreamer, Doctor, and service-safe agent jobs are Kernel-supervised siblings of the current `eliotd`, so daemon restart neither destroys them automatically nor leaves them with old authority. Native UI and subscription or desktop-bound agent jobs belong to the authenticated User Broker lineage; Kernel owns only their registration, admission, leases, and reconciliation.

On loss of the active daemon generation, Kernel immediately revokes daemon-issued effect leases. Read-only or rebuildable Modules may remain warm, but new results are held as unbound observations until a new compatible daemon and fence exist. Effect-capable Modules and agent jobs checkpoint, pause, or terminate according to manifest.

Restart semantics are ELIOT contracts, not a requirement to use an Erlang runtime or framework:

```text
restart_self
  — local restart of one independent generation;

restart_dependents
  — restart only downstream capabilities whose state or fence depends on the failed upstream;

restart_branch
  — restart a small tightly coupled branch when partial state is more dangerous than a brief outage;

quarantine
  — after restart-budget exhaustion, disable the capability while Problem State remains open.
```

The hard-dependency graph defines startup, drain, and restart order and remains acyclic. Siblings without an invalidated dependency are not restarted.

### Modern `let it crash`

`Let it crash` applies to an isolated executor—not to data, authority, or an irreversible effect.

```text
expected error
→ typed result and Recovery Directive;

unexpected internal defect
→ task or process generation terminates;
→ supervisor records evidence;
→ stale Authority Epoch is rejected;
→ replacement starts from canonical or checkpointed state;
→ an unknown external outcome is reconciled by receipt;
→ repeated crash leads to quarantine and escalation.
```

It is prohibited to catch a panic and continue with unknown mutable state, restart a child indefinitely, repeat an effect without idempotency and reconciliation, treat restart as resolution of Problem State, or terminate independent branches because an optional Module failed.

## I1.5. Demand-start, observable use, supervision and idle shutdown

DEFAULT mode is `on_demand`. The word *daemon* describes a supervised service role, not a requirement to consume resources while ELIOT is unused.

### Observable use and activation

Any authenticated, observable use of an ELIOT surface activates the control contour before that use is treated as governed work:

```text
native UI or `eliot` CLI request;
MCP/agent bridge attach or tool call;
ELIOT-launched AgentAttempt or external-agent reconciliation;
approved maintenance, backup, migration or recovery job;
protected external effect that still requires supervision;
Watchdog observation of a registered agent/bridge event requiring reconciliation;
Task Scheduler wake created by an admitted WakeIntent.
```

An unintegrated external agent or editor that never reaches an ELIOT bridge remains outside this claim. Process names and filesystem similarity alone do not prove that ELIOT is being used; the interval is reported as `BLIND` or `UNKNOWN` rather than reconstructed as governed activity.

HostStateJournal owns one non-semantic activation lineage:

```yaml
EliotActivationRecord:
  activation_id_and_idempotency_key:
  trigger_class_and_trigger_evidence:
  requester_principal_session_or_scheduler:
  requested_capabilities_and_candidate_scope:
  state: STOPPED | STARTING | CONTROL_READY | ACTIVE | DRAINING |
         STOPPED_CLEAN | DEGRADED_RECOVERY | FAILED
  activation_generation_and_drain_generation:
  host_kernel_watchdog_and_store_generations:
  supervision_readiness_and_governance_profile:
  runtime_and_supervision_lease_refs:
  wake_intent_refs:
  drain_commit_ref_and_wake_during_drain_disposition:
  boot_session_and_power_transition_evidence:
  started_ready_draining_and_stopped_at:
  failure_and_recovery_directive:
```

Concurrent triggers with the same compatible installation/activation generation coalesce behind one start. A request is not admitted as an active Session/Attempt until it receives an activation result bound to the current Host/Kernel/Watchdog generations. Starting a process, opening a pipe or seeing an old heartbeat is not sufficient.

Activation and drain are serialized by one installation-scoped `activation_generation`. A new observable-use trigger received before the durable drain linearization point cancels drain and returns the same generation to `ACTIVE` after readiness revalidation. A trigger received after `DrainCommitRecord` creates a new activation generation only after the old generation's authority is fenced and its process descendants are terminated or explicitly reconciled. Old and new authority generations never overlap merely to make wake-up appear fast.

```yaml
DrainCommitRecord:
  activation_and_drain_generation:
  last_admission_closed_at:
  lease_and_pending_operation_snapshot:
  authority_epochs_fenced:
  processes_modules_and_store_branches_to_stop:
  wake_during_drain_disposition: cancel_drain | queue_next_generation | reject_stale
  irreversible_stage_and_recovery_owner:
  committed_at:
```

System suspend, hibernate, user logoff and boot-session change close the claimed continuous-observation interval unless the applicable platform sensor proves otherwise. Resume never trusts pre-suspend PID, pipe, UserBrokerEpoch, lease expiry or store lock. Host/Kernel/Watchdog revalidate boot/session identity, generations, cursors, ORS and pending effects before reopening `ACTIVE`; the intervening interval is `replayed`, `partial` or `blind`, never silently continuous.

### Startup

```text
agent bridge / `eliot` CLI / UI / scheduled wake
→ create or join EliotActivationRecord
→ StartService(eliot-host) when required
→ Host starts/reconciles Kernel and requests the independent Watchdog service through SCM as sibling activation branches
→ Kernel reconciles ORS/epochs and starts the canonical-store branch only when needed
→ Host/Kernel verify the current Watchdog supervision epoch and responsiveness
→ derive the actual Governance Profile
→ acquire the applicable RuntimeLease
→ run WorkScope/task/readiness admission
→ start only the remaining capabilities required by the admitted request
→ return the activation/readiness delta to the caller.
```

If Watchdog is unavailable, ELIOT does not claim independent supervision. Read-only or lower-impact work may continue only under the resulting Governance Profile and policy; Material/Critical operations that require independent supervision pause or require the explicit Human risk path. The activation is not reported fully healthy merely because Host and Kernel are alive.

An installed agent shim, hook, plugin or MCP bridge is a demand-start trigger only; it stores no semantic state or authority. If a user runs an unintegrated agent and no observable host event reaches ELIOT, setup/next attach reports the blind interval and no retroactive Watchdog claim is made.

### Runtime, supervision and wake ownership

These three operational objects are distinct and versioned:

```yaml
RuntimeLease:                    # Kernel-owned in ORS
  lease_id_holder_and_reason:
  required_runtime_branches_and_capabilities:
  task_attempt_job_or_effect_refs:
  authority_epoch_and_state_fence:
  issued_at_expires_at_and_renewal_evidence:
  state: ACTIVE | EXPIRING | EXPIRED | REVOKED | RECONCILING | CLOSED
  terminal_disposition:

SupervisionLease:                # Kernel-owned in ORS; signed mirror in Watchdog spool
  lease_id_and_opaque_scope_ref:
  observation_targets_and_sensor_profile:
  claimed_coverage_and_governance_axis:
  issuer_kernel_and_watchdog_epochs:
  issued_at_expires_at_renew_before:
  wake_on_registered_activity_policy:
  state: ACTIVE | EXPIRING | EXPIRED | REVOKED | RECONCILING | CLOSED
  revocation_and_terminal_disposition:

WakeIntent:                      # HostStateJournal; Watchdog may preserve a signed fallback copy
  wake_id_and_idempotency_key:
  reason_and_evidence_refs:
  earliest_start_deadline_and_expiry:
  required_capabilities_and_maintenance_family:
  service_safe_or_user_session_required:
  state_fence_revalidation_and_budget:
  state: PENDING | CLAIMED | STARTED | SATISFIED | CANCELLED | EXPIRED | FAILED
```

A `RuntimeLease` is acquired automatically for an active authenticated UI/CLI/MCP Session, AgentAttempt, Durable Job, upgrade/repair or unresolved external effect. It is renewed only from observable liveness/progress or an admitted wait state; process survival alone does not renew it. Orphaned leases expire and enter reconciliation.

A `SupervisionLease` is issued automatically only for an observable active obligation: an authenticated Session, attached or ELIOT-launched AgentAttempt, Durable Job, protected external effect, active maintenance/recovery/containment operation, or an explicit user `always_on`/between-session supervision policy tied to registered sensors. The mere existence of an installed ELIOT, a registered WorkScope, open Problem, repository on disk or dormant agent configuration does **not** keep Watchdog alive. Human policy selects sensor scope and whether supervision continues between interactive sessions; it does not allow ELIOT to claim coverage without a lease. Watchdog may observe the signed lease but cannot extend it. Before expiry, registered agent/bridge activity or a protected risk causes Watchdog to persist a signed `WakeIntent` and demand-start Host so Kernel can revalidate/renew or close the interval. If renewal cannot be proved, coverage ends at expiry and is reported honestly.

A `WakeIntent` schedules work but never grants semantic authority, keeps the full stack alive by itself or revives an expired lease. On wake, every target, capability, policy, budget and State Fence is revalidated. Stale/resolved intents are cancelled rather than executed because they were once queued.

A lease renewal is a new revision of the same active lease identity and must carry fresh observed evidence; it is not inferred from an alive PID, open pipe or stale heartbeat. `EXPIRED`, `REVOKED` and `CLOSED` are terminal for that lease revision. Resuming work after them requires a new admitted lease/epoch path; no mirror or queued `WakeIntent` can reactivate the old lease. `RECONCILING` permits only exact cleanup/effect/receipt reconciliation named by the lease terminal disposition and cannot admit new semantic work.

### Watchdog wake behaviour while the application stack sleeps

While a valid `SupervisionLease` exists, Watchdog may remain as the only live ELIOT service. It records bounded non-semantic observation envelopes, cursors and coverage gaps in its own spool. It does not write `SystemObservationJournal` or Cognitive Inheritance directly.

```text
authenticated bridge/session/agent heartbeat or protected control event
  → immediate signed WakeIntent + Host demand-start;

critical security/unknown-effect/containment signal
  → immediate Host/Kernel wake or the exact pre-authorized local containment path;

filesystem-only hint under a registered root
  → persist cursor/event and wake only when policy/materiality requires;
  → otherwise reconcile on the next attach/scheduled wake.
```

Demand-start reconciles the Watchdog spool through the Governor-owned journal path before observations can influence memory, policy or task state. Spool pressure narrows claimed coverage; it never turns the spool into a second semantic owner.

When no `SupervisionLease` existed and ELIOT was fully stopped, no live-observation claim is made. The next activation performs `sync-before-think`: it compares exact Workspace/VCS/source/manifests/runtime identities with the last accepted State Fence and, when an admitted OS journal cursor is available, replays its bounded interval. Offline changes become an external world-state delta with `actor/intent = unknown`; they invalidate dependent projections, packets, tasks and leases as required, but are never retroactively attributed to an agent or called governed work.

Open Problem, Incident or Critical Attention do not keep the full stack alive forever merely by existing. Durable state and the persistent inbox survive shutdown. Keep-awake is required only for active containment/repair, imminent escalation, unresolved external effect, observable agent activity or explicit policy. Otherwise a revalidated `WakeIntent` and Human-board item preserve the obligation.

### Idle drain

Idle drain starts only when no `RuntimeLease` remains and no valid `SupervisionLease` requires live sensing/containment:

```text
1. stop new background/model/swarm admission;
2. checkpoint durable jobs and attempts;
3. quiesce optional Modules;
4. flush receipts/outbox and persist/cancel WakeIntents;
5. stop `eliotd` and store bridge;
6. Kernel requests Host to stop the canonical-store process when no data/maintenance lease remains;
7. Watchdog persists observation cursors and stops through SCM when no SupervisionLease remains;
8. Host publishes the clean shutdown manifest, observes child termination and exits.
```

A new observable-use trigger during steps 1–4 normally cancels drain after revalidation; during or after the committed process/authority fence it is queued as the next activation generation. Shutdown never reopens old leases or skips receipt/effect reconciliation. A failed or timed-out drain leaves `DEGRADED_RECOVERY` plus a WakeIntent/manual entrypoint rather than reporting `STOPPED_CLEAN`.

DEFAULT idle grace is five minutes. This is a Config Default, not an invariant.

### Runtime modes

```text
on_demand       — default desktop mode;
always_on       — explicit user policy;
maintenance     — selected curation/backup/meta jobs only;
recovery        — minimal Kernel/Doctor path; normal agents disabled;
offline_export  — store stopped; export/restore only.
```

### Background wake

Windows Task Scheduler invokes a bounded maintenance command only from an admitted `WakeIntent`/policy. The job has budget, deadline and revalidation; ELIOT stops again after completion. Without Human-approved policy ELIOT does not start external models or swarm in the background. When scheduling is disabled or unavailable, the next observable use surfaces one deduplicated manual action instead of silently abandoning maintenance.
## I1.6. Windows isolation

DEFAULT:

```text
a separate Job Object is created for each failure domain and Module generation;
Watchdog and Kernel do not share a child-kill domain;
all child processes enter the applicable Windows Job Object;
Kernel descendants remain inside the Host-owned Kernel Job Object and MAY additionally enter nested per-Module/per-attempt Job Objects for tighter limits; startup probes verify the required nesting and kill-on-close semantics on the supported Windows build;
the process tree receives kill-on-close at its outer ownership boundary;
CPU, memory, and process limits are set by Module Manifest;
`system_service` uses a dedicated low-privilege service identity; `user_mode` runs under the current user without pretending to be an SCM service;
named pipes use explicit ACLs;
models and third-party Modules do not inherit secrets by default;
versioned binaries are never replaced in place while running.
```

### User-session isolation

`eliot-user-broker.exe` runs under the interactive user's token, in its own Job Object and immutable generation. Kernel never injects into an arbitrary desktop process. Registration binds installation identity, authorized SID, user-session ID, exact artifact hash and a short-lived launch nonce.

Each WorkScope resource declares its execution/access identity: `service`, `interactive_user:<sid>` or `remote`. The installer does not silently rewrite project ACLs. User-profile roots are observed or mutated through a broker-launched scoped adapter unless the Human explicitly grants the service identity access to that exact root. Snapshots and artifacts crossing back to the service preserve source SID, path scope, privacy and effect receipts.

Logout, session termination, policy change or broker loss revokes broker-bound execution leases and starts attempt reconciliation; machine-scoped canonical work remains intact.

## I1.7. Linux portability boundary

Linux is not a supported first-line target, but the following properties must not be coupled to Windows:

```text
module protocol messages;
module lifecycle;
store API;
canonical formats;
authority/fencing semantics;
job/checkpoint model;
agent interaction contracts.
```

The platform layer isolates:

| Windows | Future Linux |
|---|---|
| SCM demand-start | systemd socket activation |
| Task Scheduler | systemd timers |
| named pipes | Unix domain sockets |
| Job Objects | cgroups / process groups |
| DPAPI / Credential Manager | keyring / secret service |
| Windows notifications | desktop notification adapter |

Linux support begins only after CI, packaging, and fault tests on a real Linux installation.

---

## I1.8. Exact ownership and call paths

### One logical Governor, two internal checks

Kernel + `eliotd` form one logical Governor. Responsibilities are deliberately split:

```text
eliotd
  interprets semantic command, task/scope state and proposes PreparedTransition;

Kernel
  verifies identity, authority, State Fence, idempotency, ordering and runtime generation;

store bridge
  persists only a named, already prepared transition atomically.
```

No component alone can invent semantics, authorize them and commit them. This is a two-check implementation of one authority, not two writers or two policy owners.

`eliotd` and Kernel may not evaluate different semantic snapshots. `eliotd` emits the single canonical `PreparedTransition` defined in I5.6. Across the `eliotd`→Kernel→store boundary its load-bearing identity consists of the operation and canonical-request identities, admission decision digest, semantic source revisions, State Fence, Authority Epoch, Ordering Scopes, transition class, exact mutation-plan digest and required store-contract version.

Kernel rechecks only properties it owns and binds the activation/staging receipt to the same `admission_decision_digest`. Store commit and `WriteReceipt` repeat that digest. A digest, source-revision or mutation-plan mismatch returns `TRANSITION_DIGEST_MISMATCH`/conflict and never retries as the same decision.

### Session attach

```text
agent bridge
→ Kernel authenticates local process/profile and transport generation
→ eliotd resolves principal, WorkScope and task
→ Kernel issues generation-bound Session token
→ agent receives bootstrap/state handles.
```

Session exists only while transport identity and semantic Session refer to the same State Fence/epoch.

### Read path

```text
agent/UI/module
→ Kernel validates principal/session/read capability
→ eliotd selects Q0–Q5 contract and role-filtered projection
→ in-memory snapshot or named store read
→ result with revision/freshness/provenance.
```

For hot reads Kernel may issue a short-lived `NamedReadCapability` directly to `eliotd`. It binds exact named query, principal/role, scope, State Fence, payload cap, expiry, daemon generation and audit identity. Store bridge accepts no generic query and no write under this capability.

### Canonical write path

```text
agent/module/tool observation
→ eliotd semantic admission and PreparedTransition
→ Kernel mechanical authority/fence/idempotency/order validation
→ ORS staging and Ordering Scope reservation
→ named store transaction commits events/projections/relations/WriteReceipt/outbox row atomically
→ ORS reconciliation
→ outbox dispatch
→ caller notification.
```

Doctor, Dreamer, Watchdog, Modules and surfaces submit observations/candidates/intents through this same path. Writes have no direct-read shortcut.

### External effect path

```text
ActionContract + authority
→ bounded tool/module attempt
→ AttemptReceipt
→ observed side effects/artifacts
→ verifier/reconciliation
→ OutcomeReceipt
→ optional semantic transition.
```

Canonical commit and external effect are separate proof objects.

### Recovery path

```text
Watchdog/Kernel/Host detects failure
→ non-semantic intent/fence in Watchdog spool or ORS
→ Host/Kernel starts compatible generation
→ Doctor may execute registered repair effect
→ logical Governor reconciles canonical/external state
→ verifier resolves or escalates Problem State.
```

## I1.9. Three registries, three owners

“Module Registry” is not a single mutable object. The implementation uses three distinct owners:

| Registry | Owner | State class | Contains | Must not contain |
|---|---|---|---|---|
| **Module Catalog** | Governor / `eliotd` | canonical configuration/intent | desired module manifests, semantically admitted/allowed versions, dependencies, capability intent, policy and removal boundary | PIDs, pipes, Job Objects, Host-level artifact approval or uncommitted health |
| **Generation Registry** | Kernel / ORS | operational recovery state | installed/running/candidate generations, process handles, Authority Epoch, route switch, drain/checkpoint/restart state | project claims, task meaning, semantic policy decisions |
| **Capability Registry** | Governor composite projection | canonical manifests/evidence + Kernel generation/health + policy/supervision inputs | current usable installations/routes, evidence, limitations and admission status | lifecycle ownership, process truth or authority inferred from mere availability |

Hot replacement reconciles them:

```text
Module Catalog requests desired generation
→ Kernel stages/starts/observes candidate in Generation Registry
→ probes/production produce capability evidence
→ Governor updates Capability Registry and decides admission
→ Kernel performs fenced route switch
→ receipts/outbox reconcile the three views.
```

One table, actor or file may not own all three lifecycles. Code, protocol and documentation use these names exactly.

A Governor-admitted generation produces an immutable `KernelExecutionManifest` copied into the Generation Registry:

```text
artifact/config/protocol hashes;
start command and dependency order;
Job Object/resource limits;
health/readiness contract;
restart budget and quarantine rule;
restart_authorization_class: read_rebuild | effect_exact_lease | current_catalog_required;
authority/effect ceiling and allowed scopes;
checkpoint/state-class behavior;
accepted Module Catalog revision and receipt.
```

This is a technical execution projection, not desired-state policy. It lets Kernel restart the exact previously admitted daemon/module while `eliotd` is unavailable only within the recorded restart class.

```text
read-only/rebuildable generation
  → may restart from the exact manifest under bounded restart budget;

effect-capable generation
  → may resume only exact already-authorized operations covered by an unexpired operation lease;
  → new effect admission requires a current Module Catalog/Policy view;

Catalog/Policy unavailable, stale, revocation event unacknowledged or delivery gap open
  → candidate may start in shadow/no-effect diagnostic mode only.
```

Kernel cannot create, widen or update the manifest without a governed Catalog/lifecycle receipt. Missing, stale or incompatible manifest means visible degradation and escalation, not an improvised restart. A process restart never converts stale desired state into current authority.

Host-managed dependencies use a fourth, strictly operational record:

```text
ManagedDependencyRecord
  owner: Host;
  contains: immutable process manifest, artifact/config hash, Job Object/PID lineage,
            start/stop/restart budget, observed exit/readiness and requester identity;
  must not contain: DB claims, task state, schema meaning or canonical authority.
```

For the canonical store, process liveness comes from this record and Host/Watchdog observations; semantic readiness comes from store-bridge version/schema/transaction probes. Neither observation can substitute for the other.

Host persists these records in a separate minimal `HostStateJournal` outside Kernel ORS and Canonical Memory:

```text
installation/Host epoch and clean-shutdown marker;
active/candidate Kernel activation identity and one-time nonce state;
managed-dependency process generation, PID/Job lineage and restart budget;
approved artifact/config hashes and last observed process disposition.
```

The journal has exactly one writer — Host — and is opened through `eliot-platform::HostStateStore`. The Windows DEFAULT is a dedicated redb file under `%ProgramData%\Eliot\host`, with checksummed records and transaction durability; another platform may replace the backend without changing the contract. It stores no project semantics, task state, policy interpretation, credentials or canonical authority. Corruption closes automatic activation/restart, preserves evidence and enters manual recovery; Host never reconstructs missing state from PIDs or directory contents alone.

### Mutable-state ownership matrix

Every mutable state class has one authoritative owner. Mirrors, caches and projections may be rebuilt, but cannot mutate independently or survive owner invalidation as authority.

| State class | Authoritative owner | Durable location | Rebuildable mirrors / consumers | Forbidden ambiguity |
|---|---|---|---|---|
| Host/Kernel and Host-managed dependency artifact approval, Host activation and managed dependency process lineage | Host | HostStateJournal | Watchdog observations, ControlBoard | Kernel/daemon cannot infer Host-level approval from files or PIDs; module semantic admission remains in Module Catalog |
| cognitive inheritance, tasks, policy/config, Module Catalog and semantic receipts | logical Governor | Canonical Store | daemon caches, packets, reports | ORS, modules and vendor runtimes cannot become semantic owners |
| canonical DB files and transaction execution | SurrealDB process through store bridge | canonical DB storage | logical export, read projections | Host process liveness is not semantic readiness |
| pending operations, Authority Epochs, Generation Registry, delivery cursors, active Session/User Broker bindings and recovery intents | Kernel | ORS | Recovery View, canonical reconciliation receipts | restore never revives active operational authority |
| immutable large payload bytes, reachability and GC state | Blob Store | Blob root/CAS metadata | canonical BlobRef, read caches | DB bridge cannot write blob files; a blob receipt is not a semantic receipt |
| provisional security/liveness signals and independent integrity anchors | Watchdog | Watchdog spool | Governor Problem/Incident reconciliation | Watchdog spool is not project memory |
| user-session process tree and launch epoch | User Broker in the authenticated user session | broker runtime + ORS registration | Host/Watchdog process observations | canonical consent does not prove a live broker |
| native provider/runtime continuation state | exact external runtime/adapter generation | runtime-native state plus ELIOT locator/checkpoint | public rehydration packet | native state is not task identity or canonical truth |
| derived indexes, graphs and caches | owning Module generation | rebuildable module state | Governor read views | derived state cannot outlive invalidated source dependencies as current evidence |
| UI-local transient state | Human surface | process-local | canonical ControlBoardView | UI state cannot mutate task truth directly |

A proposed implementation that introduces a second writer for any row above is rejected even if it calls the duplicate state a cache, registry, journal or recovery store.

## I1.10. Service health state model

The shared `ServiceProcessState` vocabulary is defined once in I14.20. This section defines its health dimensions and readiness interpretation; it does not create another lifecycle enum.

Health is a vector, not one boolean:

```text
liveness;
readiness;
freshness;
compatibility;
integrity;
capacity;
supervision coverage.
```

A component is `READY` only for the capabilities whose required dimensions pass. A stale graph can be alive and compatible but not fresh; it must not advertise current impact analysis.

`ServiceProcessState` describes one running process. `ModuleGenerationState` describes discovery, staging, activation, drain and retirement of a replaceable capability artifact. A process may be alive/READY while its generation is only STAGED or DEGRADED; the two state spaces are never merged into one enum, and route switching belongs to the separate `GenerationCutover` machine.

## I1.11. Startup algorithm

```text
1. Host opens and validates HostStateJournal, the approved artifact registry and the independent Watchdog service state through SCM.
2. Host reconciles stale process lineages, then starts Kernel with the exclusive installation mutex and a dedicated Kernel Job Object.
3. Kernel opens ORS, verifies the integrity anchor and loads the Generation Registry.
4. Kernel validates the approved Blob Store manifest. It starts the blob generation on the first non-inline capture, recovery or GC demand; a failed blob probe degrades only large-payload capture and never fabricates a canonical BlobRef.
5. When canonical access is required, Kernel requests Host to start/reuse the canonical-store Job Object, then starts/reconnects the store bridge and waits for independent readiness/schema probes.
6. Kernel reconciles pending/unknown operations before enabling normal writes.
7. Kernel starts candidate `eliotd` and performs protocol/contract handshake.
8. `eliotd` loads Config/Policy snapshots and rebuilds hot mirrors from named reads/outbox cursor.
9. Required capability set is evaluated; optional failures become visible degradation.
10. Kernel publishes front-door readiness and releases queued attaches.
11. Watchdog independently confirms process/plugin/heartbeat coverage and updates the supervision evidence used by the Governance Profile.
```

Front-door readiness permits attach, inspection and policy-allowed low-impact work. Material/Critical authority remains capped by the current Governance Profile; it is not unlocked merely because the pipe is ready. No agent receives Material authority while ORS reconciliation, schema compatibility, authority-epoch recovery or the required supervision/enforcement evidence is incomplete.

## I1.12. Compatibility and rollback boundary

Every process handshake exchanges:

```text
protocol range;
contract-set digest;
canonical format range;
Architecture source digest plus externally sealed NormativePairIdentity receipt;
module generation and Authority Epoch;
required/optional capabilities;
state migration class.
```

Rollback is allowed only to an artifact compatible with current durable formats and epoch lineage. “Last known good” means **verified compatible with current state**, not merely “previously launched”.

## I1.13. Kernel unavailability

If Kernel is unavailable:

```text
no new Session, lease, canonical write or external Material authority is issued;
Host and Watchdog remain independently reachable where possible;
Recovery View shows build/generation/ORS/incident state only;
semantic task recovery waits for canonical access;
existing external tools are not claimed to be stopped unless enforcement is observed.
```

If the User Broker is unavailable, only user-session-bound routes are deferred or reconciled; machine/service-safe routes and canonical state remain available.

---

# I2. Rust workspace, crate fleet, ownership, and hot path

## I2.1. Primary decision: crate-rich, process-sparse, owner-sparse

ELIOT uses **many small crates** as the normal unit of build, package-selective testing, dependency containment, and agent context. A crate may have a source-maintenance owner, but creates no lifecycle, mutable-state, or authority owner by itself; those owners belong to the `FunctionalCapabilityCell` or service contract and may span several crates.

Restricting the system to a few large crates is incorrect. Cargo workspaces select packages through `-p`, `--workspace`, and `default-members`, compile independent units in parallel, and reuse metadata and incremental artifacts. The practical limit is determined not by the number of lines in `[workspace].members`, but by dependency-graph quality, feature sets, proc macros and build scripts, linker load, test binaries, ownership, and agent context.

Target formula:

```text
many source and build crates
+ substantially fewer runtime bundles and processes
+ one owner for each mutable state
+ one canonical semantic path.
```

A crate is not a microservice and does not create IPC by itself. Dozens of crates may be statically linked into one fast `eliotd.exe`. A process boundary appears only for a separate failure, resource, credential, or update boundary.

### Three independent quantities

```text
crate count
  compile/test/context granularity;

runtime bundle count
  independently released set of crates;

process count
  independently crashable, supervised and hot-replaceable runtime generations.
```

They must not be conflated.

### Four levels of modularity

```text
Rust module
  minimum source navigation within one owner;

Cargo crate
  independently selectable build/test/context/contract boundary;

runtime bundle / process generation
  independently supervised, fenced and hot-replaceable executable boundary;

deployment/service unit
  OS installation, activation, upgrade and rollback boundary.
```

Moving to the next level requires separate justification. A good Rust module need not become a crate; a good crate need not become a process; a process need not become a permanently running service.

### Migration baseline

The five current source owners remain migration facades, not permanent target structure:

```text
eliot-types
eliot-engine
eliot-store
eliot-windows-ipc
eliot-app
```

A new capability first receives an ELIOT-owned contract and test seam. Code is then extracted into a separate crate without a big-bang rewrite. The old crate temporarily re-exports the new contract or invokes the new service until callers migrate.

The previous donor decision of “four or five large crates” is retained only as a map of initial responsibility owners and migration facades. As target physical source topology, it is superseded by this crate-rich strategy: large responsibility domains remain, but split into independently selectable contract, core, service, and adapter crates.

Do not create parallel:

```text
task graph;
attempt journal;
provider reservation system;
canonical memory;
agent database;
finish authority;
recovery path.
```

Micro-modularity changes physical packaging, but does not multiply semantic owners.

### Workspace capacity is measured, not planned by crate count

Implementation does not assign a crate-count band to a Delivery Depth. Such bands are an easily optimized proxy: an agent can create packages that satisfy a table while making contracts, compilation and coordination worse. A crate appears only after `CrateExtractionDecision` proves a real build/test/context/dependency seam; it disappears or merges when that seam is false.

Workspace capacity is demonstrated by measurements on the actual graph and representative synthetic stress profiles:

```text
Cargo metadata and package-selection latency;
incremental and clean critical paths;
reverse-dependency fan-out;
rust-analyzer/index load;
test discovery/sharding cost;
cache/target contention under parallel agents;
manifest/contract orientation burden;
typical changed-closure size and Product Pulse outcome.
```

Delivery Depth names capability families, not package counts. The same depth may be implemented with fewer larger crates or more smaller crates when the causal/test seams and measured agent outcomes justify it. `RGF-CRATE-BUILD` owns fleet-scale experiments; its result may tune tooling profiles but never becomes a quota to fill.

### Performance model

A many-crate layout provides:

```text
a smaller invalidation unit for private changes;
more independent `rustc` jobs and package-selective commands;
a smaller agent source and context workset;
separated vendor and feature dependencies;
a smaller merge, test, and ownership blast radius.
```

Costs:

```text
fixed `rustc` and metadata overhead per crate;
more incremental artifacts and rust-analyzer crate nodes;
a public API change rebuilds its reverse closure;
generic or monomorphized code may compile in consumers;
overly small crates create manifest, glue, and context fragmentation;
a shared target root may become a lock or I/O bottleneck;
a proc-macro or build-script dependency multiplies compile cost across fan-out.
```

The optimum is not the maximum crate count, but the smallest typical change closure with acceptable fixed overhead. I2.16, I2.23, and CrateBuildProfile measure both sides.

## I2.3. Workspace topology and dependency direction

### Root core workspace

The first production workspace contains crates required for daily development and normal local runtime. It uses:

```toml
[workspace]
resolver = "3"
members = ["crates/*", "bins/*", "tests/*"]
default-members = [
  # daily core packages and primary binaries only
]
```

`default-members` is not all members. A normal root command must not accidentally build fuzzing, mutation, cloud SDKs, all vendors, and laboratory tools.

### Federated workspaces

A separate Cargo workspace is created not because there are many crates, but when a dependency island exists:

```text
a different toolchain or target;
a WASM, fuzz, Miri, Kani, or nightly-only contour;
a heavy vendor SDK that invalidates the core cache;
an upstream project preserved without rewriting;
an incompatible dependency, MSRV, or license profile;
an experimental distributed, actor, or runtime branch;
an independent release cadence for an optional Module family.
```

Initial repository topology:

```text
/workspace/core         # root production workspace and daily default-members
/workspace/modules      # optional module families when extracted
/workspace/lab          # fuzz, mutation, model experiments, benchmarks
/workspace/tools        # xtask, schema/profile generators, release tools
/upstream               # unchanged external source/bundles where applicable
```

These directories appear physically as their first real consumer appears. One root workspace is allowed until a cache or dependency conflict is demonstrated.

Cross-workspace connection uses:

```text
versioned EBP/protocol schema;
immutable artifact manifest;
a public ELIOT contract crate or generated schema package;
contract digest and compatibility receipt;
```

One lockfile is not an architectural objective. One semantic owner and one causal order matter more than one Cargo workspace.

### Source layers

```text
C0 primitives/contracts
  ids, time, errors, schemas, protocol, module/client SDK;

C1 pure domain cores
  state machines, validation, ranking, reconciliation, policy functions;

C2 application services
  task/read/write/context/coordination services over ports;

C3 adapters/instruments
  SurrealDB, Windows, Cargo, providers, MCP, code tools;

C4 process/surface composition
  binaries, service hosts, CLI, UI, bridges.
```

Dependency direction is outward only:

```text
C4 → C3 → C2 → C1 → C0
```

A dependency on a deeper stable contract is allowed, but not on higher-layer implementation. Cargo graph cycles are prohibited.

### Contract hubs

A crate with large reverse-dependency fan-out is a load-bearing hub. It must:

```text
have minimal dependencies;
contain no vendor or framework types;
change rarely;
separate additive schema change from breaking change;
have a public-contract digest and consumer tests;
not become a dumping ground for common types.
```

Unstable logic belongs near leaf crates, not in `eliot-common` or `eliot-types`.

### Runtime control does not change source ownership

```text
Host starts Kernel;
Kernel starts generations;
Governor schedules Modules;
Watchdog observes processes;
Modules return candidates and events.
```

These runtime arrows do not authorize importing the managed component's internal types. A callback does not transfer ownership to the caller.

### Lessons from Rust microservice systems

ELIOT adopts:

```text
small stable contract crates;
one mutable-state owner per service;
thin binary and composition crates;
explicit health, readiness, and capacity surfaces;
composable timeout/load-shed/rate-limit/observability middleware;
idempotent request/effect identity;
consumer/provider contract tests;
process deployment only at a real failure boundary.
```

ELIOT does not adopt:

```text
a network hop between every source module;
service-per-entity/table;
a separate database for each helper capability;
chatty distributed transactions;
Kubernetes or gRPC as mandatory local baseline;
protocol-generated types as the sole domain model.
```

Tower-like `Service` and `Layer` composition is allowed inside transport and service crates. Tonic-like multi-crate organization is useful as an example of separate contract, codegen, health, and transport packages. But local Windows ELIOT remains process-sparse: most source micro-modularity is statically linked into a few supervised runtime bundles.

## I2.4. Erlang/OTP principles in the Rust runtime

ELIOT adopts operational principles, not BEAM syntax:

```text
small state owners;
message passing instead of shared mutable cross-Module state;
supervision tree;
crash containment;
bounded restart intensity;
explicit child classes;
immutable release generations;
state migration before cutover;
observable recovery outcome.
```

### Supervision strategies

Two orthogonal fields use the same canonical vocabulary as I14.10:

| Field | Values | Use |
|---|---|---|
| group strategy | `one_for_one` | restart only the independent failed child; DEFAULT |
| group strategy | `rest_for_one` | restart failed child and explicitly declared downstream dependents |
| group strategy | `one_for_all` | rare; only for a small inseparable supervision group |
| child class | `temporary` | do not restart automatically after completion or failure |
| child class | `transient` | restart only after abnormal exit |
| child class | `permanent` | restart after any non-retirement exit within policy |

The strategy is declared in the Module or Service manifest. Supervisor does not infer it from process name.

### Restart intensity

Every supervisor branch has:

```text
attempt budget;
rolling observation window;
exponential/jittered backoff;
last-known-good generation;
quarantine condition;
escalation target;
Problem State and receipts.
```

Repeated failure does not create an endless restart loop. After budget exhaustion, the branch is quarantined or escalation moves one level higher.

### Rust boundary

Rust provides no safe general replacement of arbitrary machine code inside a live process while preserving state, as BEAM does. Therefore:

```text
source crate
  built and tested independently;

in-process service
  replaced by restarting the current disposable service or by a new `eliotd` generation;

process Module
  replaced by an individual side-by-side process generation;

Kernel/Host
  replaced by an external-supervisor cutover.
```

Rust `cdylib` unloading and arbitrary in-process code injection are not production plugin mechanisms.

### Actor implementation

ELIOT-owned supervision semantics remain behind the `eliot-runtime` facade. The DEFAULT is supervised Tokio tasks and typed bounded mailboxes. `ractor` may be used for suitable service trees only after an empirical gate and does not define:

```text
authority;
restart policy;
receipts;
state ownership;
cluster semantics;
canonical task lifecycle.
```

A distributed actor-cluster library is not a production dependency without separate conformance and failure proof.

### Graceful stop

Every supervised task or process passes through:

```text
stop admission
→ cancellation signal
→ stop accepting new work
→ checkpoint/flush/disposition effects
→ bounded wait
→ forced termination if required
→ no-orphan verification
→ receipt.
```

## I2.5. `unsafe` policy

`unsafe` is allowed only in explicitly listed crates:

```text
eliot-platform-windows;
eliot-platform-unix;
when necessary, a separate audited FFI bridge.
```

Every unsafe block has a `// SAFETY:` rationale, local invariant test, and owning reviewer. Domain, contract, and Kernel pure-core crates use `#![forbid(unsafe_code)]`.

## I2.6. Error and crash model

```text
library crates
  typed errors through `thiserror`;

process/protocol boundaries
  stable ErrorCode + structured RecoveryDirective;

binaries
  `anyhow` is allowed only after a domain error is converted into operator context;

panic
  an implementation defect, not normal control flow.
```

An error preserves:

```text
operation identity;
module/crate/generation;
State Fence and Authority Epoch;
causal chain;
retryability semantics;
known/unknown effect status;
raw evidence handle.
```

An in-process panic permits local restart only under I2.4 and I14. Otherwise the generation terminates. A process crash is a normal supervision event, but not successful recovery without a verifier.

## I2.7. Build profiles and compilation modes

ELIOT does not use one Cargo profile for every purpose.

### `dev-local`

```text
incremental = true;
separate target root per worktree or build fingerprint;
package-local `cargo check -p` and focused tests;
fastest possible feedback to the active agent;
`sccache` is not assumed effective while incremental compilation is enabled.
```

### `dev-shared`

```text
incremental = false;
`sccache` MAY be used through ProcessExecutor;
content-addressed BuildFingerprint;
suitable for repeated builds across worktrees or agents;
is not proof without an actual test or verifier run.
```

### `edge`

```text
real adapter/process/store/protocol boundary;
separate fixture namespace and resource lease;
codegen and linking errors are checked by a real build, not only `cargo check`.
```

### `product-pulse`

```text
actual front door;
accepted owner path;
minimum real artifact or effect;
bounded frequency;
may run on a candidate generation beside the live stable generation.
```

### `release`

```text
locked dependencies;
reproducible manifest/SBOM/license inputs;
clean or declared cache state;
all required workspaces/profiles;
full release proof.
```

### Rules

```text
`cargo check` provides a fast Shape or Module signal, but does not prove codegen, linking, or runtime;
`cargo build --timings` regularly measures compiler units, critical path, and parallelism;
profile identity belongs to BuildFingerprint;
a result from one profile is not renamed as proof for another;
a cache hit accelerates compilation but transfers no test verdict.
```

Release binaries are built from thin binary crates; substantial logic lives in library crates. This improves independently cached and tested source units and prevents a binary crate from becoming an integration monolith.

## I2.8. Package metadata, source ownership and generated registry

A separate `OWNER.toml` for every small crate creates file ceremony. Derivable source and build metadata lives in `Cargo.toml`; causal and lifecycle ownership remains with `FunctionalCapabilityCell` and Module or service contracts.

```toml
[package.metadata.eliot]
layer = "C1"
purpose = "bounded responsibility statement"
source_maintenance_owner = "source-owner-id"
functional_cell_refs = ["cell-id"]
independent_proof_profile = "crate-fast"
contract_refs = ["..."]
component_contract_ref = "" # only when a real multi-contour component exists
```

`CrateRegistry` is generated from `cargo metadata`, source annotations, the contract catalogue, test inventory, and runtime manifests:

```text
crate identity and version;
layer and dependency rules;
source-maintenance owner and current WorkLease holder;
FunctionalCapabilityCell references and their separate lifecycle owners;
public contract digest;
source/context footprint;
reverse dependencies and fan-out;
build/test profiles and proof ceiling;
runtime bundle/module-generation mappings derived from referenced cell/runtime manifests;
hot-path participation derived per cell;
current conformance evidence.
```

`state_class`, `effect_class`, failure and replacement boundaries, and runtime authority are not inferred from package name or source owner: they belong to referenced functional cells and Module manifests. A private Rust module receives no separate manifest. A transient agent editing a crate receives a WorkLease and becomes neither source owner nor lifecycle owner.

## I2.10. Runtime module and state classes

Module manifest declares three orthogonal classifications: execution contour, runtime role and state ownership. None of them is inferred from a crate name.

### `ModuleExecutionContour`

| Contour | Use | Isolation / replacement | Examples |
|---|---|---|---|
| `wasm_component` | Pure or nearly pure experimental logic with a narrow capability surface | Wasmtime Store/instance; immutable component generation | routing/scoring policy, validators, deterministic transforms, context assembly policy |
| `native_process` | OS, Cargo, Git, LSP, browser, native libraries, credentials or long CPU work | separate process/Job Object; versioned protocol; rolling generation | testd, code tools, provider bridges, professional tools |
| `static_native` | Trusted Kernel/control path or a measured stable hot path | new signed binary/process generation; Host/Kernel cutover | authority/fencing core, serialization hot path after proof |
| `development_only` | generators, fuzzers, benchmarks, migration/test utilities | never required by production runtime | simctl, schema/profile generators, fuzz targets |

Rules:

```text
crate boundary ≠ process boundary;
process boundary ≠ Windows service boundary;
WASM/native/static are deployment contours over the same ELIOT-owned contract;
static native is not a default reward for maturity;
in-process Rust dynamic libraries are not an ordinary promotion step;
OS-heavy capability does not gain authority merely by running outside WASM.
```

A component may remain WASM permanently when its latency is negligible relative to model/tool work and isolation is valuable. Native promotion requires profiling and the same conformance corpus. Static integration is the last step and is performed only by a normal release generation; there is no live unload/reload of Rust code inside Kernel or `eliotd`.

### `ModuleRuntimeClass`

| Class | Examples | Default replacement |
|---|---|---|
| `kernel_internal` | fencing/front door | Host-managed Kernel generation |
| `daemon_service` | task/context/job service | service restart or daemon generation |
| `process_bridge` | MCP/LSP/provider/tool bridge | independent process generation |
| `component_host` | Wasmtime or native component pool | host generation + component route cutover |
| `test_execution_plane` | build/test/simulation service | independent testd generation |
| `derived_index` | code graph/cue/search | rebuild/shadow/switch |
| `operational_worker` | crawler/external queue | checkpoint/quiesce/switch |
| `cognitive_service` | Dreamer/model router | job-bound route switch |
| `supervisor_security` | Watchdog sensor | independent service generation |
| `surface` | UI/notifications | independent restart/switch |
| `development_tool` | impact/schema/simulation generator | never required at runtime |

### `ModuleStateClass`

```text
stateless
  no state survives request/process;

host_state_externalized
  state remains in ELIOT-owned snapshot/delta form; generation is replaceable;

rebuildable
  derived state recreates from canonical/external sources;

checkpointed_operational
  non-semantic state resumes from versioned checkpoint/reconciliation;

external_canonical_adapter
  adapter owns no ELIOT semantics; authoritative data lives behind declared surface.
```

No hot-replaceable Module declares `canonical_semantic`. Canonical storage, semantic admission and mechanical fencing remain one path with separated responsibilities.

### `ModuleReplacementClass` and `IterationLane`

Source decomposition and runtime replacement are independent decisions. Every independently planned capability declares one replacement class:

```text
component_generation
  one sandboxed component generation can shadow/canary/cut over independently;

process_generation
  one native process generation can be replaced through I14.14;

daemon_generation
  crates linked into `eliotd` change through a side-by-side daemon generation while Kernel,
  canonical store and independent services remain alive;

host_generation
  Host/Kernel/service-shell change through the external Host/SCM cutover contract;

offline_release
  no safe online cutover exists yet; explicit owner/reason/recovery required.
```

`daemon_generation` is a real online system-replacement boundary even though Rust code is not unloaded inside a process. A regularly edited crate is not forced into WASM or its own process when that would duplicate state ownership, add IPC latency or weaken the public contract.

Its development loop is classified separately:

```text
interactive
  package proof normally returns within the qualified interactive profile;

normal
  independently runnable but not expected on every edit;

slow
  long compile/simulation/integration proof; scheduled as a Durable Job;

manual_release
  proof/replacement requires explicit release or platform boundary.
```

`ProofLatencyProfile` and replacement cost determine scheduling. Unknown or slow proof moves the capability out of automatic interactive scheduling; it does not by itself make the Module incorrect or require an arbitrary split.

### Execution-selection decision

Choose the least privileged contour that can express the capability:

```text
pure + bounded host calls
  → WASM Component candidate;

needs OS/native tool or broad async I/O
  → native process generation;

measured control-path bottleneck with stable contract and complete rollback
  → static native release candidate;

uncertain
  → native process first; do not use in-process dynamic loading as compromise.
```

The decision and rejected alternatives are recorded in the Module Catalog. A later change of contour is a promotion/migration, not an invisible build optimization.

## I2.11. Independent build, proof and release units

Every first-party crate must have an independently selectable proof surface that matches its actual proof ceiling:

```text
`cargo check -p <crate>` or equivalent shape or build proof;
behavioral unit, property, or model tests only where the crate actually owns behavior;
a contract, facade, or data-only crate may use compile, schema, or consumer-contract proof instead of artificial unit tests;
public contract selector when applicable;
source/context/build metrics and clear reverse-dependency impact;
explicit declaration of behavior that cannot be proved package-locally.
```

Absence of a meaningless package-local test is not a defect when the proof ceiling and mandatory consumer or edge profile are stated. But absence of any independently invocable proof makes the capability `CURRENT_UNVERIFIED` or `TARGET`, not supported.

A release unit may contain several crates:

```text
eliotd bundle;
Kernel bundle;
Watchdog bundle;
store bridge bundle;
agent bridge bundle;
optional Module bundle.
```

Runtime bundle manifest records the exact crate and artifact graph, protocol range, SBOM, symbols, license report, and rollback compatibility.

### When a separate workspace or lockfile is required

```text
a heavy dependency island causes measured cache invalidation;
a different toolchain, target, or profile is required;
an upstream project must remain in delivered form;
a Module is released independently;
license or MSRV requires containment;
core-workspace feature unification becomes unstable.
```

A separate workspace receives no ELIOT authority of its own. Compatibility is checked through protocol, schema, and artifact digests and integration proofs.

## I2.12. Third-party Rust adoption rule

Before implementing a subsystem, maintainers search for a suitable upstream project. Adoption requires:

```text
compatible licensing;
acceptable maintenance and frozen-project risk;
Windows support for the required path;
bounded dependency/security footprint;
clear failure semantics;
thin facade/process bridge;
export/removal path;
no upstream types in public ELIOT contracts.
```

Order of preference:

```text
use upstream unchanged behind a facade;
wrap an executable or service behind EBP;
contribute upstream;
fork only with explicit divergence ownership;
write from scratch only for genuinely unique ELIOT contract.
```

An upstream project does not dictate ELIOT crate topology. Its source may live in a separate workspace or bundle.

## I2.13. No framework ownership of architecture

Tokio, ractor, axum, rmcp, SurrealDB, nextest, sccache, and future frameworks implement local mechanics. None defines:

```text
authority;
canonical record semantics;
task lifecycle;
epistemic status;
module ownership;
finish outcome;
Architecture conformance;
supervision policy ELIOT;
swarm decision authority.
```

A framework always remains behind an ELIOT-owned crate contract and removal boundary.

## I2.14. Cargo feature, dependency, codegen, and cache hygiene

Many crates accelerate development only under a disciplined graph.

### Feature policy

```text
a workspace-wide `full` feature is prohibited without measured justification;
Tokio features are selected per crate;
vendor SDK features terminate at bridge implementation;
platform, storage, and provider feature sets do not leak into domain crates;
default features are disabled when they pull unused runtimes, TLS, or storage;
a feature flag does not silently change authority or semantic meaning.
```

### Expensive-unit isolation

The following are isolated separately:

```text
proc-macro crates;
build-script-heavy crates;
generated code;
FFI/native linking;
large generic/codegen-heavy algorithms;
heavy dev/test dependencies;
nightly/fuzz/mutation crates.
```

Proc-macro, binary, and linker-invoking crates are not treated as ordinary cacheable units. A binary wrapper remains thin.

### Generic boundaries

A generic-heavy public API may shift monomorphization into every consumer. Therefore:

```text
a generic algorithm stays in a leaf or core crate where practical;
a contract hub exports concrete data and narrow traits;
`dyn` or erasure is allowed at a cold or replaceable boundary after measurement;
`#[inline]` and LTO are not doctrine;
compile-time and runtime trade-offs are measured.
```

### Dependency diagnostics

Every dependency-changing unit runs:

```text
`cargo tree -d`;
`cargo tree -e features` for affected packages;
license/advisory/source review;
compile-time and binary-size delta;
removal-boundary check;
feature-set stability check.
```

### Workspace-hack / cargo-hakari

`workspace-hack` is not a day-one Default. It is allowed after a Research Gate when BuildTimings or BuildFingerprints show repeated compilation of common dependencies because of divergent feature sets. Promotion requires measured Windows improvement, a generated manifest, a verification step, and a removal path.

## I2.15. Hot-path modularity

### Runtime hot path

Normal decision path:

```text
IPC/frame receive
→ identity/session/fence validation
→ immutable state snapshots
→ exact task/cue/attention lookup
→ deterministic policy/gate
→ compact response/receipt.
```

Hot-path crates may be numerous: static linkage adds no runtime hop. Their contracts require:

```text
no model call;
no process startup or module discovery;
no index rebuild or blocking filesystem scan;
no unbounded DB/tool/network wait;
no lock held across `await`;
no mutable cross-crate singleton;
bounded allocations/collections;
immutable or versioned snapshot inputs;
explicit stale/degraded result;
cheap tracing with raw expansion by handle.
```

Hot data is published through immutable snapshots or atomic generation swap. Writer and cold services prepare projections asynchronously; the hot path only reads a compatible revision.

### Dependency shape

There is no fixed maximum crate-layer count. Review starts for observed causes:

```text
latency trace shows material overhead;
build critical path and reverse fan-out slow the change loop;
the agent workset loses the Decision Safety Floor or complete causal closure;
a dependency cycle or heavy adapter enters the hot path;
a high-churn contract hub forces unrelated crates to rebuild continually;
ownership or recovery boundary becomes unclear.
```

Contract hubs must remain stable; heavy adapters, UI, Researcher, Dreamer, vendor SDKs, and test frameworks stay outside the hot path. A thin composition root is the Default, not a numerical depth rule.

### Cold path

```text
model jobs;
Dreamer/Researcher;
semantic indexing;
compaction/consolidation;
large graph traversal;
coverage/mutation;
module startup/update;
repair/migration;
full report rendering.
```

The cold path never blocks an action gate silently. It creates a Durable Job and later updates a projection.

## I2.16. Crate size and Agent Context Envelope

### Why LOC is insufficient

An agent breaks a Module not because a crate has a certain line count, but because the following cannot fit together for the change:

```text
goal and invariants;
public contract;
owned state machine;
production source;
relevant tests;
one-hop providers/consumers;
real diagnostics;
position in the product path.
```

Implementation therefore distinguishes three sizes:

```text
Physical Crate Size
  all Human-authored source and ordinary package tests;

Loaded Crate Slice
  production source and focused tests actually loaded in one agent episode;

Agent Workset
  Loaded Crate Slice + module-specific contract, one-hop interfaces,
  FailureFingerprints, diagnostics, and Product Pulse context.
```

A physical crate may exceed one episode only when it contains independently testable internal cells and the loaded slice is demonstrably complete. Arbitrary file chunking is not completeness.

### Deterministic estimate

```text
STU (Source Token Unit) = ceil(UTF-8 bytes / 3)
```

STU is a conservative fallback estimate for planning Rust and Markdown source. When the exact route tokenizer is available, use it; quality curves live in the Effective Context Profile.

### Candidate envelopes and selection rule

ELIOT does not plan ordinary implementation work against a provider's nominal maximum. The `100k`, `130k`, and `150k` bands below are reference candidate profiles, not a closed list or one universal starting band. An installation may qualify smaller or intermediate bands when exact route evidence supports them. Planner selects the **smallest `QUALIFIED_FOR_PROFILE` envelope** that contains the Decision Safety Floor, governing instructions, advertised tool surface, evidence and diagnostics, protected reasoning and review reserve, and the complete causal workset. If no band is qualified yet, selection remains provisional and exposes uncertainty; nominal route size is not grounds to choose the largest envelope or split a Module automatically.

Reference allocation:

| Total active context | system/tools | task/Architecture/contracts | evidence/diagnostics | reasoning/edit/review reserve | margin | primary source + focused tests |
|---:|---:|---:|---:|---:|---:|---:|
| 100k | 18k | 18k | 7k | 25k | 8k | ≈24k |
| 130k | 18k | 22k | 8k | 35k | 12k | ≈35k |
| 150k | 20k | 24k | 10k | 40k | 13k | ≈43k |

This is a planning profile, not a promise of uniform model usability. Tool output, history growth, and failed attempts consume the same envelope; source allowance is not prefilled to its limit.

```yaml
ContextEnvelopeSelectionReceipt:
  task_route_and_impact_profile:
  selected_effective_context_profile:
  selected_candidate_band:
  decision_safety_floor_tokens:
  instruction_and_directive_tokens:
  tool_surface_tokens:
  evidence_and_diagnostic_tokens:
  protected_reasoning_review_and_margin:
  loaded_source_and_test_slice:
  rejected_smaller_and_larger_bands_with_reason:
  qualification_status_and_uncertainty:
  actual_serialized_measurement_ref:
```

The receipt prevents a planning number from becoming an invisible law. A larger band is selected only when a smaller qualified band cannot carry the decision-sufficient workset or when a controlled experiment demonstrates better outcome without unacceptable distraction, latency or cost.

```text
100k route
  one narrow crate or cell; Loaded Crate Slice target 20–30k STU;

130k route
  normal mode; Loaded Crate Slice target 30–45k STU;

150k route
  upper normal mode; Loaded Crate Slice target 35–50k STU;

>180k
  explicit route experiment, cross-crate integration or reconstruction episode;

250k+
  never the default implementation mode merely because of nominal capacity.
```

### Route-specific Agent Workset

`Agent Workset` includes the task, contract, and evidence portion specific to the Module and is therefore larger than one source slice. Its ceiling derives from the total envelope, not one number for all routes.

| Total active context | Workset target | Upper review band | Remaining protected reserve |
|---:|---:|---:|---:|
| 100k | 45–55k STU | 65k STU | system/tools + >=25k reasoning/review + margin |
| 130k | 60–75k STU | 90k STU | system/tools + >=30k reasoning/review + margin |
| 150k | 70–90k STU | 105k STU | system/tools + >=35k reasoning/review + margin |

Exceeding the upper review band is an observation, not an independent prohibition or mandatory ceremony trigger. `ContextScaleReview` opens only when size coincides with an incomplete causal workset, lost edges, insufficient reasoning or review reserve, repeated agent error, unacceptable cost, or Product-Pulse degradation. Planner then considers contract, Module, or Edge decomposition; a more exact projection; or another qualified route. Task Controller may retain a cohesive work unit when the Decision Safety Floor, one-hop effects, verifier, and review reserve fit under the exact tokenizer profile and Product Pulse and counter-metrics show no degradation. That decision remains scoped evidence, not a new permanent Default.

### Physical crate size profiles

Count Human-authored production source and ordinary tests. Generated code, large golden corpora, vendor source, and raw fixtures have separate profiles and are not loaded in full.

| Crate class | Starting target | Review band | Legacy high-review band |
|---|---:|---:|---:|
| primitives/contracts | 5–15k STU | 25k | 40k |
| low-level hot-path primitive | 15–30k | 40k | 60k |
| pure component/domain core | 20–40k | 55–60k | 80k |
| control/service implementation | 30–50k | 70k | 100k |
| adapter/parser/bridge library | 5–20k | 30k | 45k |
| facade/composition/binary | 5–15k | 25k | 40k |
| shared test-support | 10–30k | 45k | 70k |

`Legacy high-review band` exists only for migration and is not a target for new code. All ranges are Empirical Profiles. Crossing a numeric band alone records profile evidence; `CrateScaleReview` becomes active only when a representative task must load an unsafe or incomplete slice, proof, build, or fan-out cost degrades, ownership becomes ambiguous, or agent or Product-Pulse outcomes regress. An unqualified full-crate task may be withheld from automatic scheduling, but the crate is neither failed nor split by size. Cohesion, edge cost, public-contract quality, independently selectable cells, and measured outcomes decide. A cohesive control crate may remain physically larger than one Loaded Slice when the actual workset is complete and independently provable.

For rough orientation using fallback `bytes/3`: 5k STU ≈ 15 KiB UTF-8 source, 12k ≈ 36 KiB, 25k ≈ 75 KiB, 35k ≈ 105 KiB, 60k ≈ 180 KiB. LOC is intentionally not normalized: generated formatting, comments, schemas, and test style produce very different bytes per line.

Crate size is not evaluated apart from change closure. A small contract hub with huge reverse fan-out may cost more than a large leaf crate; a large service crate may remain temporarily when an agent can see independently testable internal cells and extraction would still increase risk.

### Mandatory context around a local change

Even a small crate cannot be assigned to an agent without semantic context. The workset always contains:

```text
Product Objective / causal property;
crate purpose and invariants;
public contract digest;
owned state/effects;
one-hop producers and consumers;
relevant FailureFingerprints;
affected edge tests;
smallest Product Pulse;
explicit non-goals.
```

This prevents optimization of a local expression at the expense of Architecture.

### Qualification of context and crate profiles

Every numeric envelope in I2, I7, I14, I18 and Appendices C/O is an `EmpiricalParameter`, not a universal limit:

```yaml
EmpiricalParameter:
  parameter_id:
  candidate_value_and_units:
  status: UNVALIDATED | OBSERVED | QUALIFIED_FOR_PROFILE | STALE | REJECTED
  profile: {hardware, os, model, route, tokenizer, serializer, task_family, risk_class}
  experiment_and_baseline_refs:
  distribution_and_uncertainty_refs:
  counter_metrics:
  expiry_and_invalidation:
  kill_condition:
```

`UNVALIDATED` values guide planning only. They cannot by themselves block a Material/Critical action, certify a route, force a crate split or justify product acceptance. Crossing a planning ceiling triggers decomposition/review or a profiled experiment; it is not an Architecture violation.


### Exact serialized-context measurement

Context admission and profile qualification use the exact bytes that the selected route will receive, not an abstract source estimate:

```yaml
SerializedContextMeasurement:
  envelope_digest:
  serializer_id_version_and_options:
  route_model_and_actual_tokenizer_id_version_hash:
  rendered_bytes:
  actual_tokens:
  estimator_id_version_and_estimate:
  absolute_and_relative_error:
  false_safe_overflow:
  false_reject_or_unnecessary_decomposition:
  truncation_or_provider_rewrite_evidence:
  placement_and_relevance_profile:
  validity_scope_and_invalidation:
```

`STU`, byte ratios and historical token averages are planning fallbacks only. They never prove that a Decision Safety Floor fits, never authorize truncation and never force a Module split by themselves. An estimator is `QUALIFIED_FOR_PROFILE` only after measuring both dangerous directions: false-safe overflow/truncation and false rejection/decomposition. Any change to route, tokenizer, serializer, tool surface or provider rewrite behavior invalidates the qualification.

## I2.17. Parallel agent development contract

An agent swarm develops FunctionalCapabilityCells in parallel only after freezing the applicable contract revision; crates are source and build containers.

```text
Contract/Evidence wave
  owner, public API, old failure, discriminator, fixtures;

Module-cell wave
  disjoint FunctionalCapabilityCells are implemented in parallel within bounded source packages;

Edge wave
  independent integrators verify real boundaries;

Product Pulse
  the shortest actual front-door path catches architectural drift.
```

### Assignment rule

One `AgentWorkUnitBrief` contains by default:

```text
one primary FunctionalCapabilityCell;
bounded support closure, justified by one-hop contracts/effects and measured context;
one causal property;
one discriminator;
one contract revision;
one integration owner;
an Agent Workset within I2.16.
```

A cross-crate defect is decomposed into:

```text
contract change unit;
provider/consumer crate units;
edge integration unit;
product pulse.
```

An agent receives neither a giant task such as “fix the entire subsystem” nor a meaningless atomized task such as “change one line” without product context.

### ContractChallenge

An agent must return a challenge instead of proxy optimization when:

```text
the primary owner is wrong;
the discriminator does not fail on the old production path;
the contract is contradictory;
the oracle would need a hidden change;
a decision-sufficient workset fits no applicable qualified Context Envelope;
a local edit would break a product invariant;
several tasks conflict over a public contract or state owner.
```

### Write isolation

Every mutating lane has a worktree, write and path claims, BuildFingerprint, test-resource namespace, and IntegrationCandidate. A worker does not integrate its own result.

## I2.18. Build, test and artifact graph

`BuildTestGraph` is the agent-planning/affected-proof projection over the narrower `BuildExecutionGraph`, `VerifierCoverageGraph`, public contracts, runtime bundles and failure history. It is not a third graph owner and never invents build/test edges not present in those sources.

`BuildTestGraph` is compiled from:

```text
Cargo metadata package/target/feature graph;
source-to-crate ownership;
public contract digests;
Rust semantic edges where available;
test inventory and overlays;
process/runtime bundles;
Module/Instrument manifests;
historical failures and escaped regressions.
```

### Core identities

```text
CrateIdentity
  package id + source revision;

PublicContractDigest
  public Rust/schema/protocol surface;

BuildFingerprint
  toolchain + target + profile + features + env class
  + crate/source closure + build scripts + proc macros;

ModuleTestCapsuleRevision
  selector + fixtures + oracle + resource classes;

RuntimeBundleIdentity
  exact crates/artifacts/protocol manifest.
```

### Change selection

```text
private implementation change
  primary crate tests + known behavioral edges;

public contract change
  primary crate + direct/reverse consumers + contract tests;

proc-macro/build-script/generated-schema change
  all affected expansion/build consumers;

feature/workspace/toolchain/lock/profile change
  wider dependency closure;

process/protocol/state migration change
  affected runtime bundle, recovery edge and Product Pulse.
```

Cargo decides which compiler units to rebuild; ELIOT decides which proofs are required. These decisions remain distinct.

### Single-flight builds

One exact BuildFingerprint has one producer. Other lanes become waiters and receive the same artifact and evidence. A failed producer is not restarted by every agent without a new hypothesis or identity.

## I2.19. Layered module cell

Every nontrivial capability has an internal direction:

```text
L0 Contract
  ELIOT-owned types, schemas, errors, invariants;

L1 Core
  pure logic or explicit state machine;

L2 Ports
  narrow traits for storage, clock, process, filesystem, tools, events;

L3 Adapters
  Windows, SurrealDB, Cargo, provider and tool implementations;

L4 Service
  lifecycle, concurrency, retry, health, recovery;

L5 Surface
  MCP, IPC, CLI, UI, EBP translation.
```

These are logical layers. They become separate crates when they create an independent context, test, or dependency seam. For a small capability, L0–L2 may remain in one pure crate, L3 in an adapter crate, and L4–L5 in a composition crate.

Hard rules:

```text
Core does not import Adapter or Surface;
Service depends on Ports;
Adapter does not decide task truth, policy, or finish;
Surface does not bypass Service or Governor admission;
fake-port proof is not represented as real-edge proof;
the public contract is not owned by a vendor library.
```

### Portable component cell

A capability intended for more than one execution contour is organized around one semantic core:

```text
<component>-contract
  ELIOT-owned types/WIT-compatible domain schema;

<component>-core
  deterministic state transition / pure logic;
  no Tokio, Wasmtime, process, DB or provider dependency;

<component>-wasm
  thin WIT adapter and guest packaging;

<component>-native
  thin EBP/native-process adapter;

<component>-conformance
  common fixtures, differential/property tests and generation comparator.
```

The adapter is intentionally boring: decode, validate, call core, encode. It cannot add retries, policy, task state or external effects. If behavior differs between core, WASM and native execution, the generation is not promotable until the difference is explicitly accepted as a contract revision.

A component that has only one justified contour need not create empty adapter crates. The structure is introduced when a second backend, portability proof or independent sandbox boundary is real.

## I2.20. Module Contract Kit, Crate Context Capsule, and Module Test Capsule

### `FunctionalCapabilityCell`

A functional cell is a causal decomposition unit, not a sentence-length rule and not automatically a Cargo crate:

```yaml
FunctionalCapabilityCell:
  cell_id:
  purpose_and_user_or_system_property:
  causal_responsibilities:
  lifecycle_owner:
  owned_state_or_explicit_statelessness:
  allowed_effect_classes:
  public_contract_refs:
  independent_proof_surface:
  failure_degradation_and_recovery_boundary:
  replacement_and_rollback_boundary:
  providers_consumers_and_product_pulse:
```

One crate may contain several cells when either: (a) they form a stateless cross-owner contracts/primitives island with no mutable state or effects; or (b) they share one lifecycle owner, one coherent contract/dependency island and one package proof boundary. Several unrelated mutable-state owners, unrelated effect classes or independent rollback boundaries inside one crate trigger `MicroModuleTopologyReview`. A single cohesive cell may remain large when its complete Agent Workset is measurable and independently provable. Package membership never transfers lifecycle authority between cells.

### `EffectiveMicroModuleManifest`

The manifest is generated from Cargo, contract catalogue, Build/Test/Verifier graphs and runtime manifests; it is not another manually maintained authority: One manifest represents one FunctionalCapabilityCell; a crate containing several cells has several manifests.

```yaml
EffectiveMicroModuleManifest:
  manifest_id_revision_and_digest:
  functional_cell_ref:
  source_modules_and_crates:
  lifecycle_owner:
  runtime_owner_and_bundle:
  public_contract_digest:
  owned_state_and_effect_classes:
  execution_contour_and_replacement_class:
  iteration_lane_and_proof_latency_profile_ref:
  physical_source_STU:
  loaded_slice_and_agent_workset_profiles:
  dependency_ports_and_one_hop_providers_consumers:
  independent_proof_entrypoint_and_proof_ceiling:
  affected_edge_profiles:
  product_pulse_ref:
  failure_degradation_recovery_and_removal_boundary:
  current_support_freshness_and_invalidation:
  split_merge_extraction_conditions:
```

### `ProofLatencyProfile`

```yaml
ProofLatencyProfile:
  module_cell_and_proof_profile:
  exact_machine_toolchain_cache_and_build_fingerprint:
  sample_count_warmup_and_contention:
  p50_p95_p99_and_max:
  CPU_RSS_IO_and_queue_wait:
  expected_lane: interactive | normal | slow | manual_release
  qualification_status_expiry_and_invalidation:
```

Missing proof-latency evidence disables automatic assignment to the interactive lane; it does not fabricate failure or force a split. The scheduler may still run the proof as a bounded Durable Job.

### `ModuleContractKit`

```yaml
ModuleContractKit:
  contract_revision:
  crate_or_cell_identity:
  purpose_and_invariants:
  public_types_and_schemas:
  owned_state_and_effects:
  dependency_ports:
  compatibility_rules:
  negative_cases:
  known_unknowns:
  oracle_origins:
```

### `CrateContextCapsule`

```yaml
CrateContextCapsule:
  product_objective:
  functional_capability_cell_refs:
  effective_micro_module_manifest_ref:
  primary_source_package:
  source_token_estimate:
  selected_source_and_tests:
  one_hop_providers:
  one_hop_consumers:
  architecture_implementation_refs:
  failure_fingerprints:
  edge_tests:
  product_pulse:
  omitted_material_and_handles:
  effective_context_profile:
```

### `ModuleTestCapsule`

```yaml
ModuleTestCapsule:
  shape_checks:
  unit_property_model_tests:
  parser_or_golden_corpus:
  fake_port_contract_tests:
  real_edge_profiles:
  fault_restart_replay_cases:
  resource_and_serial_groups:
  proof_level_ceiling:
  known_uncovered_behavior:
  expected_nonzero_test_count:
```

Capsules are generated from Cargo, test, and instrument metadata and supplemented only with non-derivable semantic fields. A crate or cell without an executable `ModuleTestCapsule` may be investigated, but is not independently supported.

### Generated local agent surfaces

Each independently planned crate/module exposes two concise **resource projections** generated from the same contract source:

```text
Contract projection
  purpose, owned state/effects, public invariants, dependency ports,
  compatibility, proof ceiling and promotion/replacement boundary;

Agent-working projection
  one-screen instructions: how to check the unit, exact profile commands,
  prohibited shortcuts, relevant handles and escalation route.
```

The normal surface is a resource/handle compiled into the Agent Workset. `CONTRACT.md` and `AGENTS.md` are optional materializations only for host tools that require local files; ELIOT does not create two files per crate by default. Projections are not separate normative sources. They carry the source contract digest and generator version; stale projections are rejected. Handwritten rationale belongs in Architecture/Implementation records, while commands/test inventory are generated from Cargo and Instrument metadata.

The triad `ModuleContractKit` + `CrateContextCapsule` + `ModuleTestCapsule` is mandatory, not advisory. A capability missing any element cannot have `ImplementationSupport` above `CURRENT_UNVERIFIED`, regardless of code quality or test count: without a contract kit the boundary is undefined; without a context capsule the agent lacks a decision-sufficient workset; without a test capsule there is no independently invocable proof. This directly violates `ARCH-MOD-03`.

## I2.21. Crate and boundary validation

`eliot dev crate validate` checks:

```text
layer direction and cycles;
public vendor-type leakage;
missing purpose/owner/test selector;
source and Agent Workset budgets;
public contract digest;
FunctionalCapabilityCell coverage and one lifecycle owner per mutable state;
generated EffectiveMicroModuleManifest freshness and catalogue digest;
replacement class, iteration lane and ProofLatencyProfile for automatic scheduling;
reverse-dependency fan-out;
forbidden dependency islands in hot/core crates;
crate-to-runtime-bundle mapping;
state/effect owner uniqueness;
required edge profiles;
zero-test selection;
forbidden direct process/store calls;
Cargo feature duplication and profile drift.
```

Validation returns evidence and a recommendation. It does not declare the Architecture correct merely because the dependency graph is clean.

### `CrateScaleReview`

Review starts on any of:

```text
physical review/high-review band on the applicable profile;
Agent Workset upper review band or absence of a qualified complete envelope;
high compile critical-path cost;
high reverse-dependency fan-out × change frequency;
two independent fixture or test families;
repeated defect escape across the crate boundary;
systematic co-change with a neighboring crate;
the appearance of a second causal responsibility.
```

Outcome:

```text
keep;
split;
merge;
extract contract;
move heavy dependency to adapter/workspace;
create thin facade;
mark migration legacy with expiry;
run experiment before change.
```

## I2.22. Parallel build, cache, artifact and environment lanes

Each mutating work item receives:

```text
worktree;
BuildFingerprint;
target/build mode;
fixture namespace;
runtime environment lease;
resource claims;
contract revision;
candidate identity.
```

### Target roots

```text
%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\<fingerprint>
```

Governed instruments do not use the repository `target/` directory by default.

### Cache modes

```text
interactive incremental
  separate worktree target; best repeated feedback within one lane;

shared non-incremental + sccache
  reuse across agents and worktrees under an exact normalized fingerprint;

release
  locked and declared cache; proof depends on source, tool, and run identity,
  not on the fact of a cache hit.
```

Incremental compilation and sccache are not enabled together as a universal magic optimization. Instrument Plane measures hit rate, cold and warm time, cache size, and invalidation.

### Derived-cache trust and reuse

Any reuse of a derived cache or artifact is bound to exact dependency closure:

```text
source and generated-input digests;
toolchain/compiler/parser/runtime versions;
configuration, features and environment fingerprint;
producer identity and generation;
cache root identity, owner/ACL and reparse/symlink disposition;
format/schema revision;
content integrity digest;
```

Rules:

```text
checksum detects corruption but does not authenticate producer or root;
missing, unreadable, untrusted or mismatched cache is a cache miss, not a correctness failure;
no correctness path depends on cache availability;
a result derived from one observed subset cannot overwrite a broader valid cache union
unless the cache contract declares replacement semantics;
partial cache load preserves known-good entries and records rejected/corrupt entries;
restore or copy never upgrades cache authority without requalification;
cache hit carries artifact lineage but never reuses an old test/verifier verdict.
```

The cache layer is rebuildable and may improve performance only after equality checks against the uncached reference path.

### Test concurrency

Test groups declare resource weight and exclusive resources. Nextest partitioning and filtersets distribute independent tests across lanes; stateful ports, services, and database volumes receive separate leases. A worktree does not isolate runtime resources.

Verification has priority over background indexing, coverage, mutation, and Dreamer jobs. A background build cannot displace Kernel, Watchdog, Control Reserve, or interactive product work.

## I2.23. Capability-family topology and crate extraction decisions

Implementation fixes responsibility families, not a target count or frozen list of crate names. The current families are:

```text
foundation and public contracts;
Host, Kernel and platform lifecycle;
Governor task, authority and canonical transitions;
store, blob, export, migration and recovery;
Instrument/test execution and evidence normalization;
memory, context, understanding and derived projections;
Watchdog, Doctor, Dreamer and Meta;
agent routes, coordination and bounded swarm;
human/agent surfaces and optional domain/vendor/research contours.
```

Root `default-members` contains only primary binaries, contracts, Kernel/Governor core, primary store path, Instrument Plane baseline, the first agent route and short local proofs. Vendor bridges, coverage/mutation/fuzz, heavy code-index pilots, cloud/AWS, Researcher providers, professional modules, benchmark corpora and experimental actor/WASM/distributed routes remain outside the root default command unless a current work profile needs them.

### Crate admission and merge criteria

A separate crate is preferred only when an executable contract/test/context seam exists and an explicit `CrateExtractionDecision` predicts net benefit. Strong admission grounds are:

```text
independent public or inter-layer contract;
independent unit/property/model-test seam;
separate owner or bounded agent work item;
different dependency, security or license profile;
materially different change cadence;
multiple real consumers;
heavy optional dependency island;
measurable context/rebuild blast-radius reduction;
replaceable implementation boundary;
own pure state machine or causal responsibility.
```

The expected agent seam is concrete: a bounded route can read the capability with its contract/tests, change one causal responsibility, run package-local proof, see one-hop consumers/providers and avoid loading unrelated subsystems.

The following normally remains an ordinary Rust module:

```text
private helper without an independent contract;
small type group used by one parent;
implementation always changed and tested with its owner;
file split only for navigation;
algorithm fragment without an independent reason to change.
```

Crates should merge when most of these conditions hold:

```text
they almost always change in one work unit;
no independent consumer or test selector exists;
one is a pass-through of the other;
manifest/API overhead exceeds context savings;
private mutable state is repeatedly threaded across the boundary;
the split creates cyclic adapter/facade construction;
there is no measured build, fault, dependency or agent blast-radius benefit.
```

Crate-per-file and crate-per-type are prohibited proxy goals. A new package without a real consumer/test seam is rejected unless it is a time-bounded migration facade with an owner, expiry and removal test.

### Canonical extraction decision

```yaml
CrateExtractionDecision:
  affected_functional_cells_and_lifecycle_owners:
  current_source_dependency_and_change_closure:
  proposed_package_boundary:
  public_contract_and_independent_test_entrypoint:
  first_real_consumer_or_time_bounded_migration_facade:
  source_maintenance_owner_and_vendor_type_boundary:
  dependency_security_license_and_build_isolation:
  expected_agent_workset_context_and_reverse_fanout_delta:
  expected_compile_test_integration_and_release_cost_delta:
  migration_reexport_rollback_removal_and_expiry:
  counter_risks_merge_or_rejoin_condition:
  evidence_status_and_review_owner:
  disposition: keep | split | merge | extract_contract | isolate_dependency | experiment
```

A proposed name or presence in a research document is not an implementation task. Historical names and extraction hypotheses live in the external cold backlog until a measured change closure activates them.

### Workspace and fleet evidence

`WorkspaceScaleProfile` is an empirical vector over the actual workspace; it has no universal `small/medium/large` package-count threshold:

```yaml
WorkspaceScaleProfile:
  package_target_feature_and_build_script_counts:
  metadata_and_rust_analyzer_load:
  clean_incremental_and_package_selective_build_distributions:
  reverse_fanout_and_typical_change_closure:
  test_inventory_and_sharding_cost:
  shared_target_cache_and_io_contention:
  parallel_agent_throughput_and_merge_cost:
  manifest_contract_and_orientation_burden:
  validity_scope_expiry_and_countermetrics:
```

Generated `CrateFleetReport` adds source/context footprint, public API surface, change/co-change frequency, reverse fan-out, cold/warm compile and critical-path time, test discovery/execution cost, dependency/feature weight, defect attribution, agent success/repair escapes and runtime-bundle mapping. Its `ContractSurfaceProfile` records applicable contracts/owners, agent-visible contract tokens, one-hop edges, generated/manual duplication, proof latency, Product Pulse dependency and wrong-owner incidents.

`WorkspaceScaleReview` opens when package-selective work repeatedly reaches a wide closure, metadata/rust-analyzer latency blocks interactive work, target/cache contention appears, feature unification causes incompatible rebuilds, typical changes cross many owners, or added parallel lanes no longer improve throughput.

A scalar may sort candidates but cannot authorize split or merge. A split is rejected when it reduces source size while increasing contract surface, ceremony or wrong-owner rate. A merge is rejected when it removes independent proof or replacement. Topology changes are admitted only when context/build/test/ownership outcomes improve without material regression in Product Pulse, dependency clarity, recovery or agent correctness.

### Capability cell registry

`FunctionalCapabilityCell` is enumerable, not only referenced. A generated `CapabilityCellRegistry` is compiled from `[package.metadata.eliot].functional_cell_refs`, Module/service manifests and the contract catalogue:

```text
cell id and revision;
one-line causal responsibility;
owns: contract surface, mutable state or explicit statelessness, effects;
must not own: explicit non-responsibilities;
runtime layer and execution contour;
replacement class and iteration lane;
independently invokable proof entrypoint;
one-hop providers and consumers;
current support and invalidation set.
```

The registry is the answer to “how many cells exist and who owns what” without reading this chapter. It is generated: prose never maintains a parallel list. A cell without a proof entrypoint, with an undeclared state owner or with a second owner for the same mutable state is a registry defect, not an acceptable variant.

A crate may host several cells and one cohesive cell may span several crates; the registry keeps both mappings explicit so source packaging and causal ownership never silently merge.

## I2.25. Improving the system during real work

The running stable generation is neither edited nor rebuilt in place.

```text
real workload creates Problem/Improvement Candidate
→ AgentDevelopmentPlanner selects one FunctionalCapabilityCell and its bounded source packages
→ isolated worktree and build lane
→ package proof
→ affected real edge
→ shadow/canary generation on bounded workload
→ comparison with stable generation
→ authorized Module promotion owner or pre-authorized System policy decision; Main Agent supplies the recommendation and evidence
→ forward cutover or rejection
→ outcome updates memory, tests, Skills and crate profile.
```

Rules:

```text
background compilation has a lower resource class;
real project state is not used as an unprotected test fixture;
canary effects are read-only or separately authorized;
self-learning does not mean self-writing source without an owner;
agent and model-route policy and budget are Human-defined;
a failed experiment does not damage the stable generation;
new evidence may change a crate split or merge decision.
```

ELIOT can therefore improve during operation, while the production hot path remains on a known generation until the candidate passes its proof.

# I3. First-run installation, survey, and registry

## I3.1. Installation form

Installation profile determines both process supervision and writable roots.

```text
system_service — DEFAULT; one elevated installation, SCM demand-start and strongest recovery;
user_mode      — no admin: per-user binaries, launcher + Task Scheduler/current-user supervision;
portable_dev   — repository-local binaries/state, development and tests only.
```

Profile paths:

| Profile | Immutable binaries | Durable/service data | User config/cache |
|---|---|---|---|
| `system_service` | `%ProgramFiles%\Eliot\<component>\<version>` | `%ProgramData%\Eliot` | `%LocalAppData%\Eliot` |
| `user_mode` | `%LocalAppData%\Programs\Eliot\<component>\<version>` | `%LocalAppData%\Eliot\data` | `%LocalAppData%\Eliot\config\|cache` |
| `portable_dev` | repository `target/eliot-dev/<generation>` | repository `.eliot-dev/state` | repository `.eliot-dev/config\|cache` |

Mutable data is never stored beside immutable versioned binaries, except inside the explicitly disposable `portable_dev` profile. CLI/agent bridges are added to the current user's PATH or registered through the selected host integration.

`user_mode` preserves EBP, Kernel and module contracts, but its Governance Profile honestly reports weaker restart, independent-Watchdog and OS-level isolation guarantees. Code may not assume `%ProgramData%` or administrative service rights merely because the Windows production profile supports them.

For `system_service`, installer configures a narrow service DACL: authorized local users may query and demand-start Eliot Host, but cannot change the binary path, service account, recovery policy or protected configuration. Normal stop/drain is requested through authenticated ELIOT control so receipts and shutdown manifests are preserved; administrative SCM stop remains recovery-only. This allows ordinary-user startup without granting service reconfiguration rights.

### Installation owner and user-session binding

`system_service` has a primary System Owner SID and an explicit list of authorized interactive-user brokers. The service account does not inherit their subscriptions or desktop credentials. Adding another user is a visible registration/consent transition with a distinct broker identity; private WorkScopes and memory are not merged automatically.

## I3.2. Deterministic setup before agents

The trust root is created without a model:

```text
1. user confirms the installation identity;
2. System Owner principal is created;
3. local service keys and tokens are generated;
4. ACLs are installed;
5. privacy mode is selected;
6. storage starts and is verified;
7. the first signed configuration snapshot is created.
```

Setup Agent may explain settings after this point, but creates no authority.

## I3.3. Installation Survey

Survey safely discovers:

```text
Codex CLI/Desktop;
Claude Code/Desktop;
OpenCode;
Antigravity/agy;
Git and Git worktrees;
VS Code / JetBrains;
Rust toolchain;
LSP servers;
MCP configurations;
known code graph tools;
local model runtimes;
registered browsers/professional tools;
SurrealDB installations;
optional cloud CLIs.
```

Probe order:

```text
known configuration paths and manifests;
PATH metadata;
file version/signature;
only then a safe `--version` or initialization probe without secrets or elevated rights.
```

A discovered executable is not started automatically as a trusted Module.

Existing SurrealDB processes/installations are observations or import candidates, not implicit members of the ELIOT store lineage. Setup never kills, adopts or reuses an unrelated process merely because its port or binary name matches. The installer chooses and records an installation-owned loopback endpoint/data root, verifies the owning PID/artifact/HostState lineage before every start/reconnect, and returns a Recovery Directive on collision. Legacy data enters only through an explicit read-only inspection/import/migration path.

### I3.3.1. Ecosystem Discovery Catalogue and managed external tools

The survey is driven by an ELIOT-owned `IntegrationDiscoveryCatalogue`. It is a versioned set of detection, probe, install/update and removal recipes; it is **not** a second Capability Registry and does not assert that anything is installed, healthy or supported. Observed installations and capabilities still enter the Governor-owned registry of I3.4 only through evidence.

```yaml
IntegrationDiscoveryCatalogueEntry:
  family_id:
  category: agent_runtime | editor_host | local_model_runtime | mcp_server |
            code_intelligence | database | toolchain | package_manager |
            browser_professional_tool | cloud_cli
  supported_platforms:
  known_executable_config_and_manifest_locations:
  safe_discovery_and_negative_capability_probes:
  official_install_update_remove_surfaces:
  required_execution_identity_and_credentials:
  license_supply_chain_and_privacy_notes:
  adapter_or_bridge_candidates:
  evidence_expiry_and_revalidation:
```

Initial discovery families are deliberately broader than the first production route set:

```text
agent runtimes/hosts:
  Codex App Server/CLI/Desktop;
  Claude Code/Desktop/Agent SDK;
  OpenCode;
  Gemini CLI;
  Cursor Agent/ACP;
  Zed Agent and external ACP agents;
  Antigravity;
  GitHub Copilot agent/CLI/SDK surfaces;
  Cline, Roo Code and Continue extension families;
  Kiro CLI, Goose, Aider, OpenHands and generic ACP/stdio agents;

local model runtimes:
  LM Studio/llmster;
  Ollama;
  admitted OpenAI-compatible local endpoints;

editors and professional hosts:
  Visual Studio Code, JetBrains IDEs, Zed, Visual Studio;
  registered browsers and professional applications;

development and data tools:
  Git/worktrees, Rustup/Cargo, rust-analyzer, nextest, Miri and admitted Cargo tools;
  SurrealDB and its exact managed generation;
  Codebase Memory MCP, RepoWise or another code-intelligence candidate;
  Docker/VM/laboratory, package managers and optional cloud CLIs.
```

Presence in this seed catalogue is not a popularity, quality or production-support claim. Each family needs an exact runtime/adapter fingerprint and capability evidence. Unknown or closed runtimes may be used through a bounded CLI/ACP/sidecar profile, but their internal database or UI state never becomes ELIOT recovery truth.

The seed is not a closed vendor enum. New families arrive as signed/versioned catalogue data or an admitted bridge manifest with origin, license, detection-only semantics and removal path; catalogue update cannot install software, grant credentials or advertise a capability by itself. The System Owner accepts catalogue revisions through the normal installation/configuration path; Installation Survey consumes them and Governor remains the sole owner of admitted capability state. The Human UI shows `discovered`, `declared`, `probed`, `admitted`, `degraded` and `unsupported` separately.

A Human, Main Agent or Dreamer may request installation, update, repair, removal or registration through a `ManagedEnvironmentChangeRequest`:

```yaml
ManagedEnvironmentChangeRequest:
  requester_and_reason:
  action: install | update | repair | remove | register | reconfigure
  target_family_and_exact_candidate:
  expected_capability_or_problem_delta:
  source_license_signature_and_dependency_closure:
  affected_routes_modules_workscopes_and_credentials:
  impact_class_and_required_owner:
  backup_rollback_or_forward_repair:
  verifier_and_post_change_probe:
  budget_and_stop_condition:
```

The request is compiled into the existing `InstallationTransaction`, Module-generation change or configuration transition. An agent or Dreamer never runs `winget`, `scoop`, `choco`, `npm`, `uv/pipx`, `cargo install`, an updater or a downloaded installer directly as authority. Package-manager output is evidence from an effect executor. Core storage updates require backup/restore and store-gate proof; optional code-intelligence tools begin as sealed pilots and may be removed without affecting canonical memory.

The generic environment planner never updates the active canonical store, Host, Kernel, Watchdog or their protected state in place. SurrealDB/store changes use the store-generation, backup, migration and cutover contracts; Host/Kernel/Watchdog changes use their own side-by-side generation/rollback paths. Code-intelligence servers, MCPs and agent runtimes may use the managed-tool path only behind a bridge manifest and capability requalification. Package-manager success is installation evidence, not production admission.

## I3.4. Capability and Route Registry

This is the Governor-owned evidence view from I1.9. It is neither the Module Catalog nor the Kernel Generation Registry.

Registry stores evidence-linked facts, not vendor labels and booleans. It separates five identity layers:

```text
host family       — codex, opencode, claude, antigravity, acp-agent, ...;
adapter            — exact ELIOT integration implementation or bundle;
protocol/transport — App Server+stdio, HTTP+SSE, ACP+stdio, sidecar+NDJSON, ...;
runtime instance   — exact executable/package version and hash;
route              — provider/model/auth/billing/feature configuration.
```

Canonical registry shapes:

```yaml
RuntimeInstallation:
  installation_id:
  host_family:
  executable_or_endpoint:
  runtime_version_and_hash:
  os_architecture:
  execution_identity: service | interactive_user | remote
  user_or_service_binding:
  discovered_from:
  status: candidate | enabled | disabled | quarantined

Observed degradation/readiness is held in capability evidence, not in the installation definition.

UserBrokerAuthorization:
  installation_id:
  user_sid:
  allowed_route_classes:
  privacy_and_budget_ceiling:
  consent_and_policy_snapshot:
  status: allowed | suspended | revoked

UserBrokerRegistration:   # Kernel-owned ORS record, not canonical semantic state
  registration_id:
  installation_id_and_user_sid:
  windows_session_id:
  broker_artifact_hash_and_generation:
  broker_epoch:
  pid_job_lineage_and_pipe_identity:
  launch_nonce_and_lease_refs:
  last_heartbeat_and_expiry:
  status: attaching | active | draining | detached | expired | fenced

HostAdapterManifest:
  adapter_id_and_hash:
  protocol_kind:
  transport_kind:
  compatibility_range:
  permissions_network_and_secret_boundary:
  raw_and_normalized_event_contract:
  launch_health_cancel_reconcile_contract:
  supply_chain_and_rollback:

RuntimeRoute:
  route_id:
  adapter_id:
  provider_and_model_request:
  auth_profile_class:
  billing_mode:
  execution_identity: service | interactive_user | remote
  required_user_broker_class:
  reasoning/tool/context serializer fingerprint:
  privacy_classes:
  quota_sources:
  required_capability_profile_ref:
```

`RuntimeRoute` owns configured intent and compatibility only. Current liveness/readiness/capacity is joined from `CapabilityEvidenceRecord` and `DynamicCapabilityPulse`; it is not mutable state inside the route definition.

### Capability evidence

Capability is not a boolean. Every capability claim has:

```yaml
CapabilityEvidenceRecord:
  capability:
  status: declared | probe_passed | observed | degraded | broken | unsupported | unknown
  source: official_contract | runtime_handshake | active_probe |
          production_observation | source_inspection |
          reproduced_failure | imported_legacy_declaration
  scope_fingerprint:
    runtime_hash:
    adapter_hash:
    os_architecture:
    auth_profile_class:
    provider_model_route:
    feature_flags_and_serializer:
  limitations_and_negative_evidence:
  evidence_refs:
  observed_at:
  expires_at:
```

Rules:

```text
legacy bool → declared/imported_legacy, never verified;
broken/unsupported on the exact fingerprint overrides declared;
production admission requires matching probe_passed or observed evidence;
runtime/adapter/provider/serializer change makes dependent evidence stale;
capability may be route/account-specific and cannot be generalized silently;
quarantine is keyed as narrowly as the evidence permits, not by vendor name alone.
```

The following donor-derived shapes are **evidence variants/views under `CapabilityEvidenceRecord`**, not independent capability owners or parallel registries:

```text
ProcessOriginEvidence          — neutral process-attribution observation;
OwnershipChallengeReceipt      — operation-specific ownership challenge;
StaticCapabilityAttestation    — expensive identity/compatibility evidence;
DynamicCapabilityPulse         — current liveness/readiness/capacity evidence;
BehavioralCapabilityChallenge  — harmless negative challenge for one property;
CapabilityOutcome              — scoped degradation/requalification result.
```

They may be persisted as typed evidence records, but current availability and admission are derived only by the Governor-owned Capability Registry view.

### Route fingerprint and actual route

`RouteFingerprint` includes all semantics that can change behavior:

```text
host family and adapter;
protocol/transport;
runtime and adapter hashes;
provider/model/auth/billing;
message serializer/chat template;
tool-call ID and role ordering semantics;
reasoning continuation/compaction behavior;
feature flags and behavior-affecting tool/context profile hashes.
```

The task Policy/Config snapshot, privacy class and budget envelope are referenced by the RoutingReceipt and RunAttempt, not folded into the stable route fingerprint unless they actually change the prompt/tool/serializer behavior. Unrelated policy edits therefore do not invalidate route capability evidence.

Requested route and observed route are stored separately in `ActualRouteReceipt`. If runtime does not expose provider/model/billing evidence, the field is `unknown`, not inferred from UI selection or prompt text.

### Usage and quota

Usage values distinguish:

```text
known;
estimated;
unknown;
not_exposed;
not_applicable.
```

Quota windows may coexist: rolling hours, week, month, credits, premium requests, RPM/concurrency. Every value preserves source, confidence, observed time and reset time. Subscription quota is not converted to dollars without an explicit provider contract.

### Route outcome profile

`RouteOutcomeProfile` is a derived Empirical Profile used by routing, never a capability or proof by itself:

```yaml
RouteOutcomeProfile:
  route_fingerprint:
  task_class_and_recipe:
  governance_and_environment_profile:
  sample_window_and_distribution:
  verified_complete_partial_failed_unknown_counts:
  verifier_coverage_and_quality_measures:
  latency_cost_quota_and_cleanup_measures:
  continuation_context_and_route_mismatch_failures:
  independence_and_common_lineage_notes:
  confidence_coverage_and_known_biases:
  evidence_refs:
  valid_until_and_stale_dependencies:
```

The profile is sparse and conservative. Before enough equal-stack evidence exists, routing uses policy defaults and controlled pilots. A fingerprint, evaluator, task-distribution or behavior-affecting harness change makes the affected profile stale. Aggregated success never authorizes an action or hides minority failures.


### Process origin, capability challenge and readiness evidence

Capability readiness is derived from multiple orthogonal observations, never one boolean, PID, port or cached declaration.

```yaml
ProcessOriginEvidence:
  process_ref_and_pid:
  observed_start_identity_and_exit_or_zombie_state:
  image_and_argv0_artifact_refs:
  managed_tree_and_shared_runtime_refs:
  origin: INSIDE_MANAGED_TREE | SHARED_SUBSTRATE | ELSEWHERE | UNKNOWN
  evidence_refs:
  observed_at_and_freshness:
  valid_for_operation_classes:

CapabilityProbeResult:
  capability_and_generation:
  neutral_observations:
  coverage_and_ambiguity:
  evidence_refs:

OperationDisposition:
  operation_class:
  probe_result_ref:
  decision: ALLOW | ALTERNATE | OBSERVE_ONLY | REQUIRE_AUTHORITY | BLOCK
  policy_rule_and_scope:
  recovery_directive_ref:
```

`ProcessOriginEvidence` is evidence, not authority. The same ambiguous origin may permit read-only status, choose an alternate launch port and still forbid shutdown/mutation. Policy consumes the neutral probe through `OperationDisposition`; probe code does not decide the action.

An ownership claim used for kill, mutation, adoption or credential attachment additionally requires a current `OwnershipChallengeReceipt` binding installation identity, process start identity, generation/epoch and a non-reusable nonce or owner-token challenge. Port occupancy, executable family, PID file or path similarity alone can never authorize control of the process.

```yaml
OwnershipChallengeReceipt:
  installation_and_managed_generation:
  process_ref_pid_and_start_identity:
  image_argv0_and_managed_tree_evidence:
  authority_epoch_and_state_fence:
  challenge_nonce_or_owner_token_hash:
  observed_response_and_checked_at:
  allowed_operation_classes:
  expiry_and_invalidation_set:
```

Critical capabilities combine:

```yaml
StaticCapabilityAttestation:
  artifact_config_protocol_and_dependency_hashes:
  compatibility_claims_and_expensive_probe_receipts:
  invalidation_set:

DynamicCapabilityPulse:
  exact_generation:
  cheap_behavioral_probe:
  observed_at_and_freshness_window:
  liveness_readiness_capacity_and_degradation:
```

Static compatibility without a live pulse is not current readiness. A live `/health` without exact artifact/generation identity is not semantic capability.

`BehavioralCapabilityChallenge` proves one exact property through an intentionally invalid but harmless request and the expected typed failure:

```yaml
BehavioralCapabilityChallenge:
  capability_revision_and_target_generation:
  harmless_invalid_request:
  expected_typed_failure:
  forbidden_effects:
  observed_response:
  result: SUPPORTED | UNSUPPORTED | AMBIGUOUS
  state_fence_and_evidence_refs:
```

Examples include wrong capability token, invalid revision, known-bad verifier artifact and an advertised optional method. A successful challenge never generalizes beyond its exact property/fingerprint.


A capability failure is scoped to the narrowest observed lifecycle. One bad call or item does not silently poison an installation or every future route:

```yaml
CapabilityOutcome:
  capability_and_requested_mode:
  effective_mode:
  degradation_scope: ITEM | CALL | ATTEMPT | SESSION | GENERATION | INSTALLATION
  reason_and_evidence_refs:
  affected_outputs_or_operations:
  proof_ceiling:
  recovery_requalification_or_expiry:
```

Promotion to a broader degradation scope requires evidence that the broader owner or generation is defective. A call-scoped fallback remains visible in the attempt receipt and cannot become a sticky global capability flag. Conversely, a generation-level challenge failure cannot be hidden as one harmless call error.

## I3.5. First-run user decisions

Wizard asks only questions that change privacy, cost, authority, or automatic operation. Advanced configuration remains optional; every Default is visible and reversible.

```text
which roots and resources may be discovered and observed automatically;
which agent and runtime families may be registered and started;
which model providers and local runtimes to use by role:
  Main Agent, Worker, Auditor, Verifier-model, Watchdog Agent, Dreamer, and Research;
which data may be sent to each route or ELIOT Research;
monthly, daily, and per-job budgets; subscription windows; and scarce-resource ceilings;
preferred assurance, cost, and privacy preset;
whether automatic Watchdog and Dreamer jobs are allowed;
whether swarms and native recursive delegation are allowed and their upper envelopes;
full-stack mode: demand-start or explicitly always-on;
lightweight supervision mode for active WorkScopes;
maintenance mode:
  suggest_only | manual | idle_only | scheduled | continuous_bounded;
whether background curation, backup rehearsal, reindexing, and capability survey are allowed;
whether remote Dreamer queries are allowed;
whether an ELIOT Research endpoint is configured and which exchange classes are allowed;
which installation and update operations require separate Human approval.
```

When the user omits model selection for a role, the route remains `UNASSIGNED` or uses an explicitly displayed local or economy Default; Dreamer and Watchdog receive no hidden paid route. When automation is disabled, the system stores deduplicated maintenance and requalification recommendations on the Human board instead of starting them silently.

## I3.6. Model, Route and Portfolio Policy

```yaml
ModelRolePolicy:
  main_agent_route_classes:
  worker_route_classes:
  auditor_route_classes:
  verifier_model_route_classes:
  watchdog_route_classes:
  dreamer_route_classes:
  independent_review_requirements:
  local_only_data_classes:
  external_allowed_data_classes:
  per_job_task_period_budgets:
  active_quota_windows:
  max_active_lanes:
  max_writers_per_deliverable:
  max_swarm_fanout_and_depth:
  native_child_policy:
  auto_launch_job_classes:
  human_approval_classes:
  preview_beta_policy:
```

Human selects **assurance and cost intent**, not a permanent model proportion. Built-in presets:

```text
economy   — one cheap worker; review only on risk/failure;
balanced  — one writer plus conditional independent review;
assurance — one writer plus mandatory blind cross-family audit;
research  — incremental read-only evidence fan-out and synthesis;
incident  — bounded rival-hypothesis lanes, strong logging and escalation.
```

Actual staffing and route mix are plan receipts for a task class, computed from current capability evidence, task outcomes, quotas, machine capacity, privacy and independence. A static global ratio such as “70% model A / 20% model B / 10% model C” is forbidden as a production default.

DEFAULT route classes are capability-based:

```text
bulk_implementation;
architecture_reasoning;
independent_blind_audit;
fast_read_only_scout;
watchdog_diagnostic;
dreamer_curation;
dreamer_orientation;
research_synthesis;
subjective_evaluation.
```

Dreamer, Watchdog, child agents and native runtimes cannot expand this policy or create budget. An unavailable class yields explicit defer/degrade/escalate behavior; it never silently spends more, changes provider mid-attempt or sends a higher privacy class externally.

## I3.7. Plugin registration

Setup installs a bridge or plugin only after preview:

```text
files to modify;
exact config block;
installed hooks;
registered MCP server;
tool/skill count;
rollback copy;
expected IntegrationCoverageProfile.
```

After installation, `eliot doctor integration <profile>` checks hash, active registrations, hook events, and handshake. Installation success is not runtime liveness.

## I3.8. Updates

Update packages are placed in versioned directories. Installer never overwrites a running binary.

Channels:

```text
stable;
preview;
local-dev.
```

Kernel/Host update — release-level operation. Optional module update — normal hot generation operation.


---

## I3.9. Configuration layers

Precedence, from broadest to narrowest:

```text
compiled safe defaults
→ installation config
→ System Owner policy
→ WorkScope Profile
→ task/work-item policy
→ Session capability token
→ exact human approval.
```

Lower layers may narrow authority, privacy, cost or effects. They cannot expand a higher boundary unless the higher layer explicitly delegates expansion.

Files are typed TOML/JSON with generated schema; arbitrary scripts are not policy.

```text
%ProgramData%\Eliot\config\installation.toml
%ProgramData%\Eliot\config\policy.toml
%ProgramData%\Eliot\config\modules\*.toml
%LocalAppData%\Eliot\config\user.toml
<scope>\.eliot\profile.toml        optional, untrusted until admitted
```

Repository/workspace config is input, not authority. It cannot grant itself secrets, write paths or model budget.

## I3.10. Immutable Config and Policy snapshots

Every admitted operation references immutable:

```text
ConfigSnapshotId;
PolicySnapshotId;
CapabilityRegistryRevision;
ModuleCatalogRevision.
```

Hot reload flow:

```text
watch file/event
→ parse full candidate
→ validate schema, signatures, invariants and dependency compatibility
→ create immutable snapshot
→ compare affected capabilities
→ atomically publish via ArcSwap
→ invalidate dependent views/leases where required
→ retain previous snapshot for rollback.
```

Invalid config never partially updates live state. Secret values are references, not copied into snapshots, logs or model bundles.

A candidate copied from another machine, installation or WorkScope is not activated merely because it passes the schema. `ConfigApplicabilityReceipt` binds it to the observed machine/environment/capability profile and classifies each affected setting as `APPLICABLE`, `NARROWED`, `UNQUALIFIED`, `UNSUPPORTED` or `CONFLICTED`. Only settings whose declared owner and compatibility predicate match the current profile may publish; unqualified performance/resource defaults remain planning evidence, while authority/privacy/effect conflicts reject the dependent snapshot. The previous snapshot remains active and the operator receives the exact incompatible fields and recovery path.

### Dreamer- and UI-initiated configuration changes

The same settings can be changed directly through the Human UI or requested in natural language through Dreamer. Both routes compile to one governed `ConfigurationChangeIntent`; Dreamer does not edit files, registries or live snapshots itself.

```yaml
ConfigurationChangeIntent:
  requester_and_trigger: human | dreamer | watchdog_problem | maintenance_policy
  natural_language_request_and_normalized_delta:
  affected_setting_owners:
  impact: presentation_only | operational_reversible | model_cost_route |
          data_retention | privacy_security_authority | storage_migration
  current_and_candidate_snapshot_refs:
  expected_benefit_and_counter_risks:
  required_capability_budget_and_approval:
  validation_shadow_or_probe:
  rollback_and_review_condition:
```

Execution path:

```text
request
→ Dreamer/UI explanation and candidate delta
→ deterministic owner/schema/applicability validation
→ Watchdog risk observation
→ required Human/System/WorkScope approval or pre-authorized low-impact policy
→ immutable candidate snapshot
→ targeted probe/shadow where applicable
→ atomic publication
→ post-change observation
→ keep, narrow or rollback.
```

Only presentation settings and explicitly pre-authorized, reversible operational settings may publish without a new Human confirmation. Model/provider cost, automatic agent launch, privacy, secrets, authority, storage, remote access and destructive retention changes require the role that owns that boundary. A Dreamer-originated change with no user request, open Problem, accepted maintenance plan or valid scheduled policy is a Watchdog signal; the previous snapshot remains the rollback anchor.

If independent Watchdog coverage is unavailable, presentation-only changes may proceed under normal audit and pre-authorized low-impact changes may proceed only with an explicit degraded-supervision receipt. Model/cost routing, automatic launches, privacy/security/authority, remote access, storage/migration and destructive retention changes pause until supervision is restored or the owning Human explicitly authorizes a narrowly scoped emergency action. Rollback to a previously approved last-known-good snapshot remains available through the recovery path.

## I3.11. WorkScope Profile

The old `ProjectProfile` semantics are retained as `WorkScopeProfile`:

```yaml
WorkScopeProfile:
  scope_id:
  roots_and_resources:
  scope_kind:
  owners:
  truth_surfaces:
  adapters_and_verifiers:
  manifests_and_load_order:
  protected_and_generated_paths:
  network_and_tool_policy:
  model/privacy/cost_policy:
  cue_and_graph_rules:
  retention_and_backup_policy:
  compatibility_requirements:
```

A profile describes available surfaces and policy; it does not assert that an adapter is healthy or a claim is true.

## I3.12. Credential lifecycle

Credentials are stored through Windows Credential Manager/DPAPI-backed secret provider. Registry stores only `SecretRef`.

```text
create/import by authorized Human;
assign to module/route capability;
materialize only in target process;
never expose to agent/context/logs;
rotate on schedule, compromise or recovery;
revoke invalidates dependent Sessions/jobs;
audit access by reference, not value.
```

## I3.13. Uninstall and data disposition

Uninstall is a governed lifecycle, not recursive deletion.

```text
preview affected services, integrations, routes and data roots
→ quiesce agents/jobs and revoke new admissions
→ remove host plugins/hooks/MCP registrations with rollback receipts
→ stop and unregister services
→ DEFAULT: preserve canonical data and offer ECXF export
→ optional privacy purge is a separate explicit authorized operation
→ remove immutable binaries only after reference check
→ leave final uninstall/data-disposition receipt outside the removed runtime.
```

Uninstall never silently deletes memory, backups or unresolved external effects. A failed integration rollback opens a Problem State and leaves exact manual recovery instructions.

## I3.14. Registry revalidation

Installation Survey is not one-time truth. Revalidate on:

```text
executable/config/plugin change;
module upgrade;
model/provider/harness version change;
repeated launch failure;
missing runtime events;
user request;
periodic low-cost maintenance.
```

Declared capability and observed capability are stored separately. Runtime observation wins for current availability.

## I3.15. Installation and update transaction

Installation, repair and update are durable Host/installer operations rather than a sequence of best-effort file copies. They do not use Canonical Memory as their control state and do not infer success from directory presence.

```yaml
InstallationTransaction:
  transaction_id_and_installation_epoch:
  profile_and_requested_operation: install | update | repair | remove
  current_active_manifest_and_candidate_manifest:
  immutable_staging_root_and_artifact_digests:
  planned_file_acl_service_task_plugin_and_config_changes:
  precondition_and_ownership_evidence:
  stage:
    PLANNED | STAGING | STATIC_VERIFIED | REGISTERING | ACTIVATING |
    ACTIVE_VERIFIED | CLEANING | COMPLETED | ROLLBACK_REQUIRED |
    ROLLED_BACK | QUARANTINED
  completed_stage_refs_and_pending_external_changes:
  rollback_or_forward_repair_plan:
  last_known_good_and_no_return_boundary:
  observed_postconditions_and_recovery_command:
```

Owner and durable state:

```text
installer/bootstrap owns the transaction while no Host is active;
Host owns activation/recovery once its HostInstallationEpoch is established;
HostStateJournal stores the minimal current transaction/activation lineage;
large logs/packages remain immutable artifacts;
Canonical Store receives only later installation/capability observations and policy decisions,
not the transaction's operational authority.
```

Algorithm:

```text
observe exact current installation/service/task/plugin state
→ create immutable plan and staging root
→ download/copy without touching active generation
→ verify hashes, signatures/licenses, ACL plan and executable/dependency closure
→ register candidate service/tasks/plugins without granting runtime authority
→ switch the applicable activation pointer or SCM configuration through one observed installer operation
→ start and run exact health/conformance challenge
→ mark active only after observed postconditions
→ clean superseded staging after rollback window.
```

Interruption at any stage preserves the old active generation when possible and gives every old/new/partial artifact one explicit disposition. Restart resumes from the last verified stage or performs forward rollback; it never merges a partial candidate into the old tree, adopts an unknown process, reconstructs approval from paths/PIDs or labels a merely present file as installed. A stage that changed an external OS object but lacks acknowledgement remains `UNKNOWN_OUTCOME/ROLLBACK_REQUIRED` until read-back reconciliation.

This contract applies equally to `system_service`, `user_mode`, Module bundles, User Broker packages, Skills/plugins and exact compatibility artifacts. The narrower hot-generation cutovers of I14 reuse their existing owners; `InstallationTransaction` coordinates only installation-level files/registrations and does not become a second ModuleGeneration lifecycle.

---

# I4. WorkScopeResolver and BootstrapScanner

## I4.1. WorkScope identity

`WorkScope` is not an alias for a Git repository. Runtime type:

```yaml
WorkScopeDescriptor:
  scope_id:
  kind: git_repo | directory | document_set | service | remote_system |
        gui_workspace | research_corpus | composite | ad_hoc | eliot_system
  display_name:
  repository_lineage_ref:         # optional for non-repository scopes
  workspace_instance_refs:        # exact local checkouts/worktrees/resources
  owners:
  canonical_resources:
  root_paths:
  external_resource_ids:
  truth_surfaces:
  verifier_ids:
  privacy_profile:
  authority_profile:
  resource_execution_identities: service | interactive_user:<sid> | remote
  generation_vector:
  current_state_fence:
  available_capabilities:
  missing_capabilities:
  lifecycle: provisional | active | suspended | archived
```

Identity fingerprint derives from stable resources, not display name. Git branch and commit belong to the generation, but do not define the WorkScope alone.

### Repository lineage, workspace instance and similar-repository conflicts

Repository identity is split into three layers so that clones, worktrees, forks and similarly named directories cannot be silently merged:

```yaml
RepositoryLineageIdentity:
  lineage_id:
  explicit_eliot_binding_ref:
  vcs_object_store_and_initial_history_evidence:
  normalized_remote_and_fork_relations:
  project_manifest_and_declared_identity_refs:
  known_aliases_relocations_and_supersessions:

WorkspaceInstanceIdentity:
  instance_id:
  installation_and_machine_id:
  root_path_and_filesystem_identity:
  vcs_common_dir_object_store_and_worktree_identity:
  current_head_branch_dirty_generation:
  editor_host_and_process_binding_refs:
  observed_at_and_freshness:

WorkScopeCandidateSet:
  observed_session_cwd_file_and_resource_handles:
  candidate_scope_lineage_and_instance_refs:
  supporting_and_conflicting_evidence:
  exact_memory_task_and_policy_bindings_per_candidate:
  cheapest_disambiguation_question_or_probe:
  disposition: unique | ambiguous | new_scope | stale_binding | conflicted
```

Two checkouts may belong to one repository lineage while remaining different workspace instances. A fork or copied directory may share names and history without sharing ELIOT task/memory authority. `.eliot` markers, remote URLs, folder names and a matching `Cargo.toml` are evidence only; copied markers cannot grant scope authority.

When several similar repositories are present, ELIOT does not union their memory or select the last/nearest/open scope by convenience. It returns `AMBIGUOUS_RESULT`, keeps project-specific memory separated, allows only privacy-bounded read-only discrimination, and asks the Human or active agent the smallest useful question. A confirmed move or additional clone creates a `ScopeRelocationOrAttachReceipt`; it does not rewrite the old root identity or task history.

Memory applicability is also explicit across clones:

```text
lineage_portable
  project charter, stable decision/failure/procedure or source evidence whose scope/generation predicate
  is satisfied by another authenticated instance of the same lineage;

workspace_instance_bound
  dirty-state observations, local paths, running services, generated artifacts and environment facts;

task_bound
  goal, acceptance, current plan, leases, attention and attempt history.
```

A lineage match may propose reuse of `lineage_portable` records, but Context Compiler still checks source generation, branch/config/environment and current evidence. It never transports instance- or task-bound state merely because Git history overlaps.

Legacy records that carry only a display name, old path or repository URL are not attached automatically to a modern lineage. A bounded `ScopeBindingMigrationCandidate` lists the candidate WorkScopes and exact supporting/conflicting evidence. Only an authorized resolution produces a forward `ScopeBindingMigrationReceipt`; unresolved records remain cold/quarantined and are excluded from project-specific automatic context. The old locator remains in provenance so a wrong historical binding can be corrected without rewriting history.

## I4.2. Resolution order

`WorkScopeResolver` uses an evidence-first order:

```text
1. current authenticated Session/Task binding with exact WorkspaceInstance identity;
2. explicit Human/host binding token naming an existing WorkScope revision;
3. resumed durable task with matching repository lineage and current instance evidence;
4. host-observed cwd/open-file/resource handles plus VCS common-dir/worktree identity;
5. previously registered WorkspaceInstance or verified relocation/attach receipt;
6. repository-lineage evidence and exact resource bindings;
7. detected manifest/service boundary as a new-scope candidate;
8. provisional ad_hoc/new scope bound only to the current session.
```

Display name, nearest path, longest prefix, most recently used task and semantic similarity are never sufficient to bind an existing scope. Ambiguous match is not selected silently. Resolver returns the candidate set and the cheapest discriminative question; until resolution, project-specific memory from different candidates is not mixed and Material authority is withheld.

Scope resolution must not depend on already having an authenticated WorkScope. An explicitly user-selected root, an authenticated host cwd/open-file handle or an admitted launcher request may create a short-lived `DiscoveryReadLease`:

```yaml
DiscoveryReadLease:
  proposer_principal_session_and_host:
  candidate_root_handles_and_filesystem_identity:
  allowed_reads: filesystem_identity | vcs_identity | manifest_names_and_hashes |
                 bounded_known_format_headers | governing_source_candidates
  forbidden: project_memory_admission | external_model_delivery | mutation |
             credential_read | broad_neighbor_scan
  privacy_and_retention: ephemeral_local_only
  deadline_and_consumption_limit:
  evidence_and_terminal_disposition:
```

The lease exists only to distinguish candidate roots and discover the sources needed for onboarding. It does not authenticate the candidate as an existing WorkScope, does not allow its content to be mixed with another candidate and does not create project authority. A candidate requiring broader reading is shown to the Human/agent for explicit expansion. This prevents the cold-start circle “scope must be known before the files needed to identify scope can be read.”

### I4.2.1. ScopeBindingGuard and mid-task revalidation

A high-ranked existing binding is not trusted forever. `ScopeBindingGuard` revalidates the actual workspace/resource identity at:

```text
Session attach/resume;
first tool/process event for a task;
agent/process launch;
worktree/root/cwd/editor-workspace change;
before a scope-sensitive canonical write or Material effect;
after VCS common-dir/object-store, relocation or generation change.
```

```yaml
ScopeBindingGuardReceipt:
  session_task_and_expected_scope_revision:
  expected_and_observed_workspace_instance:
  repository_lineage_and_generation:
  supporting_conflicting_and_missing_evidence:
  disposition: MATCHED | STALE_BINDING | DIFFERENT_INSTANCE | AMBIGUOUS |
               PROVISIONAL_REBIND | CONFLICTED
  allowed_actions_and_memory_visibility:
  required_question_probe_or_rebind:
  state_fence_and_expiry:
```

A mismatching cwd, open file, process root or worktree does not silently move the task or reuse its memory. Safe observations may be captured under a provisional/quarantined scope with the conflicting lineage preserved; project-specific context, writes and effects remain withheld until an explicit bind/rebind/relocation receipt. `MATCHED` is required again after any generation change that can alter the real target of the task.

## I4.3. BootstrapScanner

Scanner is a deterministic fast pass. It must complete without a model call.

It collects:

```text
canonical paths and filesystem identity;
Git presence, branch, commit, dirty summary;
file type distribution;
manifests and project units;
known build/test commands from registered profiles;
running processes/services connected to roots;
open editor/workspace metadata;
existing ELIOT project records;
available LSP/code graph/tool adapters;
recent filesystem changes;
known artifacts and output directories;
required execution identity for each root/tool and whether a matching User Broker is attached.
```

Output:

```yaml
ProvisionalScopeProfile:
  proposed_kind:
  identity_fingerprint:
  roots:
  project_units:
  likely_languages:
  active_resources:
  truth_surfaces_available:
  verifier_candidates:
  adapter_candidates:
  capability_gaps:
  confidence:
  onboarding_recommendation: none | shallow | normal | deep
  scan_evidence_refs:
```

### I4.3.1. Authenticated WorkScope proposal and scan boundary

An explicit path, project name or host hint is evidence, not scope authority. Resolution uses a `WorkScopeProposal` and produces a durable `WorkScopeResolutionReceipt`:

```yaml
WorkScopeProposal:
  proposer_principal_and_session:
  proposed_kind_and_resources:
  source: human | host | resumed_task | scanner | adapter
  authenticated_root_or_resource_identities:
  competing_candidate_refs:
  requested_privacy_and_authority_profile:

WorkScopeResolutionReceipt:
  selected_scope_and_generation:
  supporting_evidence:
  rejected_or_unresolved_candidates:
  owner_or_policy_authority:
  state_fence:
```

Unambiguous is not equivalent to authenticated. A scope whose principal/root/resource identity is not established remains provisional and cannot receive Material effects; dependent calls return `WORKSCOPE_UNAUTHENTICATED`.

BootstrapScanner applies privacy before durable capture:

```text
scan only registered/consented roots and fields;
collect the minimum ephemeral metadata required for discrimination;
command lines, editor state, recent output and neighboring roots are excluded by default;
secrets and high-risk literals are redacted or represented by non-reversible identity before persistence;
raw excluded material is not placed in logs, packets or model jobs;
ScanDisclosureReceipt records allowed, omitted, redacted and unresolved fields.
```

Missing privacy scope returns `SCAN_PRIVACY_BOUNDARY_REQUIRED`; the scanner may still offer a non-persisted discriminative question.

## I4.4. Progressive onboarding

### Level 0 — contact

```text
scope identity;
current roots;
Git/filesystem state;
active task;
minimum truth surface;
minimum verifier;
```

Level 0 is built lazily on first contact and may initially be provisional. Read-only exploration, safe capture and reversible scope discovery may begin in an ad-hoc provisional scope. Adequate Level 0 is required before scope-sensitive durable promotion or an unobserved Material effect. It must be fast, requires no graph mining and must not become a setup ceremony.

### Level 1 — structural

```text
manifest units;
entrypoints;
static dependency edges;
module boundaries;
build/test map;
Architecture anchors if scope is ELIOT.
```

### Level 2 — cognitive

```text
charter;
system map;
subsystem capsules;
key invariants;
known decisions/failures;
concept and artifact lineage.
```

### Level 3 — behavioral/research

```text
Git co-change/hotspots;
long history;
external research corpus;
calibration history;
deep Dreamer synthesis.
```

Level 0 must be sufficient before scope-sensitive durable promotion or a Material effect. Initial exploration, safe capture, and probes that construct Level 0 may begin earlier in the provisional scope. Levels 2–3 start only for a value or budget reason and may run in the background.

Onboarding is a checkpointed Durable Job:

```text
preflight → structural scan → deterministic concept seed/mapping
→ derived pyramid build → coverage/reconstruction report.
```

Each level is idempotent and independently resumable. Human review may later supersede artifacts but does not block deterministic progress. Model jobs are batched at subsystem/artifact level, bounded by policy and never run per file by default.

### I4.4.1. Cold start, task/document readiness and first useful work

An empty ELIOT corpus is a normal explicit state, not permission to guess. `ColdStartController` is a Governor/WorkScopeResolver capability, not a separate daemon. It is triggered automatically by first UI project open, agent attach/launch, first event on an unknown workspace, explicit onboarding request, stale scope generation or resume without a current task. It compiles `OnboardingReadinessReceipt` before the first scope-sensitive work:

```yaml
OnboardingReadinessReceipt:
  scope_resolution: unbound | provisional | authenticated | ambiguous
  repository_lineage_and_workspace_instance:
  task_binding: none | exploratory | current_task_contract | ambiguous | stale
  task_goal_acceptance_and_owner_refs:
  source_document_candidates:
    discovered:
    admitted_authoritative:
    conflicting_or_stale:
    omitted_or_unavailable:
  source_build_runtime_and_store_identity:
  privacy_authority_and_route_profile:
  truth_surface_and_verifier_readiness:
  memory_state: empty | partial | current | contaminated | unknown
  minimum_understanding_seed:
  missing_inputs_and_safe_allowed_actions:
  recommended_onboarding_dreamer_and_maintenance_jobs:
  governing_source_set_ref:
  state_fence_and_expiry:
```

Cold-start compilation is single-flight per exact candidate workspace identity and governing-source generation:

```yaml
OnboardingLease:
  lease_id_and_installation:
  repository_lineage_candidate:
  workspace_instance_candidate:
  governing_source_generation:
  compiler_owner_and_epoch:
  waiting_sessions_attempts_and_requests:
  state: DISCOVERING | RESOLVING | COMPILING | READY | AMBIGUOUS | FAILED | EXPIRED
  candidate_scope_and_task_refs:
  expiry_cancellation_and_terminal_receipt:
```

Compatible concurrent attaches join the same lease and receive the same `OnboardingReadinessReceipt`. Candidates with different filesystem/VCS identity, privacy boundary or governing-source generation never coalesce merely because directory names/remotes are similar. No worker independently creates a second WorkScope or “latest task” while the lease is active. A changed root, dirty-base identity or governing source invalidates the compiled readiness and creates a new revision rather than mutating the old receipt.

The deterministic bootstrap searches only authenticated roots or roots covered by the limited `DiscoveryReadLease` of I4.2 for likely governing sources—task brief, README, AGENTS/instructions, Architecture/Implementation, manifests, build/test documentation, schemas and recent change evidence. File names create candidates, not authority. Conflicting project documents become a Conflict Set; a model summary cannot choose the winner silently.

```yaml
GoverningSourceSet:
  scope_and_task_revision:
  sources:
    - exact_handle_and_digest:
      role: user_task | architecture | implementation | agent_instruction |
            build_test_contract | domain_policy | supporting_reference
      owner_or_authority_basis:
      applicable_scope_and_generation:
      precedence_or_conflict_rule:
      status: admitted | candidate | stale | superseded | conflicted | unavailable
  unresolved_conflicts_and_required_owner:
  coverage_and_explicit_absence:
  state_fence_and_expiry:
```

A source becomes governing because an applicable authority/contract says so, not because of its filename, recency, location or model summary. Architecture/Implementation precedence is used only where the project has declared that normative pair. Other projects may have a different source model. The agent receives the resolved set, conflicts and missing coverage; it never invents precedence locally.

Task intake is explicit. If no current TaskContract exists, UI/agent/host may submit a `TaskIntakeCandidate`:

```yaml
TaskIntakeCandidate:
  proposer_principal_session_and_route:
  user_goal_or_explicit_exploratory_question:
  acceptance_or_expected_artifact:
  constraints_non_goals_and_risk_preferences:
  proposed_scope_and_source_handles:
  decision_owner_and_task_controller_candidate:
  source: human_ui | agent_explicit | host_visible_prompt | resumed_work | import
  confidence_and_missing_fields:
```

Host-visible prompt text is an observation and privacy-bounded candidate, not automatic user authority. A task becomes current only after the applicable Human/Task owner or an existing delegated task binding admits it. An agent-facing `TASK_SELECTION_REQUIRED` response contains the minimal valid intake example and may offer a bounded `exploratory` task that cannot perform scope-sensitive Material effects.

Before a Material project change, ELIOT must have at least:

```text
authenticated WorkScope/workspace identity;
a current TaskContract or an explicit bounded exploratory task;
user goal/acceptance and decision owner;
minimum governing-document/source coverage with exact handles, or an explicit evidence-backed `no governing document found/not applicable` state;
current source/workspace generation;
applicable privacy/authority;
one usable truth surface or an honest no-proof disposition.
```

Read-only orientation, source discovery, safe capture and probes needed to reach that state are allowed earlier. A project is not forced to create a README/Architecture merely to satisfy the scanner: explicit absence or non-applicability is valid when the TaskContract, source and truth surfaces provide sufficient grounding. Missing task data returns `TASK_SELECTION_REQUIRED`; several plausible tasks/scopes return `AMBIGUOUS_RESULT`; missing context/proof returns a typed onboarding directive rather than a generic refusal. The Human or active agent can bind the task and documents directly. Dreamer may synthesize a charter/orientation candidate only after exact sources are admitted and can ask one concise clarification; it cannot invent project purpose or acceptance.

The controller has an explicit readiness lifecycle:

```text
UNSEEN → SCANNING → NEEDS_SCOPE | NEEDS_TASK | NEEDS_SOURCES |
READY_READ_ONLY | READY_MATERIAL | DEGRADED | CONFLICTED.
```

The current state is returned to the agent and Human surface; it is not buried in a setup log. `READY_READ_ONLY` permits orientation/probes/capture but not scope-sensitive mutation. `READY_MATERIAL` is always tied to one TaskContract revision and ScopeBindingGuard receipt. If the user starts an external agent before onboarding completes, ELIOT attaches it in a bounded exploratory role and asks the smallest missing question rather than silently creating a broad task.

The receipt also proposes, but does not silently start, useful first maintenance: Dreamer Orientation, exact code/build map, Skill/bridge registration, backup verification or a code-intelligence pilot. Automatic execution depends on the user’s maintenance/model budget policy. When automation is disabled or no model budget exists, one deduplicated Human-board maintenance recommendation remains visible until accepted, waived or superseded.

## I4.5. Generation vector and State Fence

One global integer generation is prohibited. `StateFence` contains only load-bearing dependencies.

```yaml
StateFence:
  scope_id:
  resource_generations:
  revision_heads:        # exact dependency-key/revision pairs, not one global scope counter
  authority_epoch:
  integration_revision:
  module_generations:
  verifier_generations:
  created_at:
```

Compiler or admission may add a dependency. Removing an observed or policy-required dependency to preserve authority is prohibited.

`ScopeSnapshot` — immutable operation-local resolution of a scope expression for retrieval, research or another bounded information job:

```yaml
ScopeSnapshot:
  snapshot_id_and_revision:
  resolved_scope_expression:
  participant_scope_and_project_generations:
  member_source_revision_refs:
  policy_authority_and_disclosure_closure:
  purge_ledger_revision:
  state_fence_ref:
  digest_created_at_and_expiry:
```

Every model call, artifact and citation that claims this resolved scope binds the snapshot digest. A purge or newly applicable deny invalidates every dependent snapshot immediately. A member revision purged before execution is excluded when the snapshot is refreshed and cannot re-enter through an older index, cache or summary. The snapshot does not mint scope, authority or source admissibility; it records the exact closure selected by existing owners. When load-bearing, its digest enters `StateFence.revision_heads`.

`SourceView` answers what “current” means before planning or readback. It is selected explicitly rather than inferred from whichever bytes happen to be easiest to open:

```yaml
SourceView:
  kind: working_tree_current | git_index | git_commit | imported_snapshot | retained_revision
  workspace_instance_id:
  workspace_view_revision_ref:
  git_commit_oid:
  imported_snapshot_id:
  retained_revision_id:

WorkspaceViewRevision:
  workspace_instance_id:
  root_filesystem_identity:
  repository_lineage_id:
  head_commit_and_branch:
  git_index_identity:
  inventory_revision:
  worktree_observation_cursor:
  authenticated_ide_overlay_revision:
  ignore_and_source_admission_policy_revision:
```

For `working_tree_current`, precedence is authenticated unsaved IDE buffer, then confirmed saved worktree revision, then the selected published base representation. One compound query uses one workspace-view revision across all branches. Drift forces replan or an explicit stale/incomplete result; results from two revisions are never merged as one coherent answer. These view objects are operation-local dependencies inside the existing State Fence, not a second workspace, publication or canonical-state owner.

An authenticated unsaved IDE overlay is an ephemeral read surface. Unless an explicit save or governed admission creates a new `SourceRevision`, `EvidenceHandle`, or `ArtifactRevision` with a receipt, its bytes MUST NOT enter CanonicalStore, BlobStore, Operational Recovery State, backups, telemetry payloads, provider caches, experience corpora, `AttemptLearningDelta`, `CampaignHarnessOverlay`, Skill or procedure candidates, or any promotion input. Policy may retain only non-reconstructive metadata required to fence the view—digest, size, editor or Session identity, and invalidation cursor. Closing, replacing, or losing authentication for the overlay invalidates every dependent view.

## I4.6. Change detection

Sources:

```text
filesystem watcher (`notify`) as hint;
Git reconciliation as authoritative code change summary;
process/service health;
remote ETag/version probe;
editor/host event;
module outbox event;
manual Human declaration.
```

A watcher event is not a canonical fact by itself. It starts bounded reconciliation.

A change:

```text
increment affected resource generation;
invalidate dependent views and leases;
mark derived capsules/graphs dirty;
keep independent scopes active;
queue context delta and attention if material.
```

Every current-state observation carries an orthogonal freshness value:

```yaml
observation_freshness: current_confirmed | observed_with_age | gap_detected | unknown
```

A watcher/USN overflow, missing cursor interval or unresolved editor-overlay gap prevents the claim “current workspace state”. The system reconciles within budget or returns `OBSERVATION_GAP`; it does not relabel an old index as current. A bounded non-strict read may use `observed_with_age` only when the age and limitation are exposed. Exact absence, completeness and current-state claims require `current_confirmed`. Historical/frozen views may deliberately use retained immutable bytes and state that view explicitly.

## I4.7. Scope transition

Expand/contract/merge/split/move:

```text
1. create proposed ScopeTransition;
2. identify records/authority affected;
3. preserve old scope and provenance;
4. copy/reference data only as candidates unless validity transfers deterministically;
5. issue new scope generation;
6. invalidate incompatible sessions/leases;
7. verify new truth and access boundaries;
8. commit receipt.
```

Cross-scope atomicity is not promised. Use a saga with visible partial outcomes.

## I4.8. ELIOT self-scope and immediate system-experience bank

`kind = eliot_system` binds:

```text
accepted Architecture revision;
Implementation revision;
Module Catalog, Generation Registry and Capability Registry views;
conformance map;
current builds;
operational health;
incidents and improvement candidates.
```

Every ELIOT component emits observations about its own operation at the boundary where they become observable. This is implemented as two related but distinct stores so that “record everything” does not turn Cognitive Inheritance into a log dump. The Governor-owned operational/audit admission path owns `SystemObservationJournal`; Canonical Memory owns only the admitted `eliot_system` experience records. Watchdog, Dreamer, Doctor, agents and Modules are producers, not alternate writers:

```text
SystemObservationJournal
  append-only operational/audit events for every normalized observation,
  with exact raw/log/blob handles, retention and coverage gaps;

EliotSystemExperienceBank
  canonical self-scope ObservationCandidates/episodes/failures/outcomes derived from
  material or recurring journal events, with provenance and no automatic truth/policy status.
```

These are logical stores with different authority and retention, not a requirement for two database products. `SystemObservationJournal` is the Governor-owned durable-audit family behind `CanonicalStoreService` (or a compatible append-only audit segment through the same store bridge); raw high-volume bodies live in BlobStore/operational logs by handle. `EliotSystemExperienceBank` is the only semantic self-memory. Neither Watchdog spool nor operational logs can answer semantic queries or promote records without Governor reconciliation.

Before an active interval begins, Governor/Kernel compile an `ActiveObservationPlan` from versioned producer obligations and actual integration capability. The owner of each Module/route contract declares its `ObservationObligationProfile`; Governor owns the admitted profile catalogue and plan compilation; Watchdog independently challenges observed coverage; no producer can self-certify that its own silence means healthy operation:

```yaml
ObservationObligationProfile:
  producer_capability_and_generation:
  applicable_activation_session_task_or_job_classes:
  expected_event_classes_and_trigger_boundaries:
  required_capture_route_and_minimum_durability:
  denominator_source_and_expected_count_or_interval:
  allowed_sampling_coalescing_and_raw_handle_policy:
  maximum_blind_interval_and_freshness:
  failure_gap_and_governance_disposition:
  invalidation_set:

ActiveObservationPlan:
  activation_and_governance_profile:
  admitted_obligation_profile_refs:
  observable_and_unobservable_sources:
  expected_denominators_and_cursor_ranges:
  protected_event_classes:
  known_blind_intervals:
  expiry_and_recompile_triggers:
```

Silence is evidence of absence only when the corresponding obligation, denominator and observation interval were known and complete. Otherwise ELIOT records `INCOMPLETE_COVERAGE`, `UNAVAILABLE` or `UNKNOWN`; it never invents a missing observation after the run. New Module/route generations cannot claim full supervision until their observation obligations are registered and challenged.

```yaml
EliotSystemObservationEvent:
  event_id_and_time:
  producer_generation_and_trace:
  kind: agent_feedback | context_packet | memory_delivery | tool_or_route |
        task_progress | loop_or_no_progress | failure_or_repair | queue_resource |
        configuration | maintenance | security | product_outcome | user_correction
  affected_scope_task_attempt_module_or_route:
  observed_delta_and_expected_baseline:
  evidence_and_raw_handles:
  coverage_and_blind_intervals:
  privacy_retention_and_disclosure:
  candidate_importance_and_dedup_key:
```

The minimal event or an explicit telemetry-gap record is persisted before the observer reports success. If canonical self-scope admission is unavailable, Watchdog spool/ORS-outbox preserves the event identity for reconciliation. High-volume raw telemetry remains in operational logs/BlobStore; Dreamer/Meta receives bounded aggregates and exact handles. Promotion to a FailureFingerprint, procedure, policy or ImprovementCandidate requires the normal governed path and outcome evidence.

“Every observation” means every admitted observation transition or explicit coverage gap, not every high-frequency metric sample or raw log line. Sensors may aggregate samples before journal admission only under a versioned aggregation/coverage rule that preserves min/max/count/time range and raw evidence handles.

Self-observation is bounded rather than lossy-by-convenience. Repeated low-value events may be coalesced behind one count/time-range record and raw handle; critical state transitions, feedback, unknown effects and coverage gaps are never replaced by a success counter. Queue pressure creates an explicit `self_observation_gap` Watchdog/audit coverage record through protected capacity and lowers the applicable Governance Profile. The journal itself cannot block unrelated product work unless the missing observation crosses a declared Hard Boundary.

Self-observation is explicitly non-recursive. Admission, coalescing, import and read of a `SystemObservationJournal` event do not emit another ordinary journal event about themselves. Only a change of journal health, coverage, persistence or reconciliation state emits one separately keyed control event. Feedback about a feedback request follows the same rule. This prevents infinite “observation of observation” chains and false activity.

Durability is proportional to the guarantee being claimed:

```text
critical authority/effect/security/finish/coverage transition
  → durable journal/audit or protected gap record before success is returned;

ordinary diagnostic/performance/utility observation
  → durable bounded outbox enqueue before the producer forgets it;
  → semantic import may be asynchronous;

high-rate sample
  → versioned aggregate plus raw evidence handle and coverage interval.
```

Failure of the ordinary Meta import path does not sabotage unrelated product work. It creates a visible coverage gap and degrades only guarantees that depended on that observation. Failure of the protected path blocks only the exact transition whose auditability is a Hard Boundary.

Before a Material change to ELIOT, the self-scope compiler adds applicable `ARCH-*`, Implementation sections, current conformance gaps, recent system-experience evidence and open improvement/recovery obligations. Ordinary project packets do not inherit the self-scope journal or maintenance history by default; only an active system directive, route/tool limitation or admitted system lesson that changes the current task may cross that boundary, with an exact handle and influence receipt.

---

# I5. Storage and canonical memory

## I5.1. Storage boundary

The domain system sees the `CanonicalStoreService` interface, not SurrealDB.

```text
writes:
  eliotd builds PreparedTransition
  → Kernel stages/orders/authorizes
  → store bridge executes named transaction;

reads:
  eliotd uses Kernel-issued read capability
  → bounded named read or hot mirror
  → store bridge/current storage implementation.
```

Storage bridge process:

```text
owns credentials;
owns vendor SDK;
validates protocol and schema generation;
executes named operations;
returns receipts and exact errors;
has no model/agent surface;
cannot invent semantic transitions.
```

## I5.2. Three storage classes

### Canonical Store

Contains:

```text
cognitive inheritance;
tasks and durable work;
claims/models/evidence/relations;
problems/conflicts/attention;
module/config/policy snapshots;
canonical events, revisions and receipts;
audit records.
```

### Operational Recovery State (`redb`)

Kernel-owned, non-semantic. ORS indexes only operational metadata and stores either an opaque serialized canonical envelope or an immutable encrypted/local payload locator; it never parses that payload as project meaning.

```text
operation/idempotency identity and Ordering Scope sequence;
opaque pending envelope bytes or payload locator + integrity digest;
Authority Epochs;
durable job checkpoint/cancellation metadata;
module/process generations, active Session bindings and active user-broker registrations/epochs;
recovery/problem/incident intents;
integrity anchors needed for Kernel recovery;
control state needed to reconcile after restart.
```

Rules:

```text
original privacy, visibility, taint and retention travel with the pending payload;
semantic fields are not indexed for recall, ranking or Current Epistemic Position;
model/Dreamer/agent queries never receive ORS payload directly;
reconciliation commits or rejects through the same canonical transition path;
resolved payload is deleted or archived under bounded recovery retention;
if ORS cannot durably stage the complete opaque operation, `accepted_pending` is forbidden.
```

ORS does not answer semantic queries and never becomes fallback memory.

Every opaque value is wrapped in a versioned `RecoveryPayloadEnvelope`:

```yaml
contract_version:
operation_or_checkpoint_id:
privacy_and_visibility_class:
key_id_and_ciphertext_or_immutable_locator:
payload_hash_and_length:
authority_epoch_and_state_fence:
created_at_and_expires_at:
```

The installation secret provider owns the key reference. `expires_at` is a cleanup horizon only after a terminal reconciliation/disposition; unresolved operations, unknown external effects and active checkpoints cannot expire automatically. Decryption failure, missing key or hash mismatch creates a Recovery Problem; plaintext fallback and silent deletion are forbidden.

### Blob Store

The store-neutral `BlobStore` contract has exactly one active data-root owner. The default early topology keeps it co-located behind the store/daemon contract; an independent `eliot-blob.exe` generation is a measured isolation/replacement option, not an automatic D2 obligation. During D1 the owner MAY be an explicitly declared internal backend in `eliot-store-surreal` or `eliotd` under the same contract, bounded resources and extractable on-disk format. An internal and process backend may never own the same root concurrently. The capability has no canonical semantic or DB authority and exposes only scoped stage/read/reachability/GC operations.

Content-addressed immutable storage for large payloads:

```text
raw tool outputs produced by governed task activity;
explicit document/source snapshots and Research Packs;
trace/log excerpts or bounded task diagnostics;
artifacts;
module packages;
export segments;
report attachments.
```

Blob Store is a payload substrate, not a corpus-ingestion pipeline. D0–D4 do not watch directories and dump documents, logs or media into ELIOT automatically. Bulk acquisition, parsing, indexing and RAG are governed by Researcher and executed only by admitted providers (I21); Blob Store never becomes the ingestion owner. Ordinary task execution may spool exact large tool output/log evidence when a canonical observation or trace references it. An unreferenced external corpus is not cognitive memory merely because its bytes exist in Blob Store.

## I5.3. Store-neutral semantic API

### Semantic command families (summary; activation rules are in I5.17)

```text
capture/source observation;
task/WorkScope/plan state;
epistemic revision, conflict and attention;
canonical transition and receipt;
instrument, verification and finish;
authority, lease, capability and external effect;
session, attempt, coordination and integration;
module/config/lifecycle and recovery;
audit/telemetry evidence.
```

Exact executable variants exist only in an admitted contract catalogue bound to the current normative-pair receipt. Bootstrap retained projections under `docs/generated/` preserve design coverage but remain `ImplementationSupport = TARGET` with `EvidenceExecutionStatus = NOT_EXECUTED`; they cannot create a command, handler or public surface.

### Named reads (summary; physical/query profile is defined by I5.20 and Appendix N)

```text
GetRevisionHeads
GetScopeRevisionView
GetTaskState
GetCurrentEpistemicPosition
GetEvidencePack
GetUnderstandingProjectionInputs
GetAttentionAndProblems
GetModuleCatalogState
GetCapabilityEvidenceState
GetConformanceState
GetMailbox
GetAuditRange
ResolveWriteReceipt
```

No command contains a raw query string.

`GetGenerationRegistryView`, active Session/User Broker bindings, ORS operation state and live process health are Kernel/control reads, not canonical-store named reads. `CapabilityRegistryView` is composed by Governor from canonical manifests/evidence plus Kernel Generation Registry, current health, policy and Watchdog supervision; the store supplies only `GetCapabilityEvidenceState`. A store implementation therefore cannot become the owner of active process state or current capability admission.

## I5.4. Canonical transition

Atomic unit:

```text
semantic event(s);
materialized projection changes;
typed relation changes;
scope revisions;
canonical receipt;
outbox intent;
audit chain fields.
```

Everything commits in one database transaction. Notification never announces a commit before its receipt.

## I5.5. Write envelope

```yaml
CanonicalWriteEnvelope:
  protocol_version:
  write_intent_id:       # stable user/agent intent across typed correction attempts
  operation_id:
  idempotency_key:
  principal:
  session_id:
  scope_id:
  scope_level: session | task | project | portfolio | system
  task_id:
  task_binding_evidence_ref:
  ordering_scopes:      # one or more; complete set declared before staging
  state_fence:
  authority:
  impact_class:
  semantic_commands:
  canonical_provenance_handles:
  evidence_handles:
  blob_handles:
  origin_assurance:
  instruction_taint:
  privacy_class:
  base_dependency_revisions:
  expected_post_commit_revisions:
  freshness_predicate:
  expected_revisions:
  conflict_policy:
  response_mode: wait_for_commit | accept_after_stage
```

An agent-provided semantic label is only a proposal. Governor may reduce the requested epistemic effect, but never discards the original observation. `operation_id` is globally unique within the installation. `idempotency_key` identifies the same logical transition across retries: the same key with the same canonical request hash resolves to the same submission and receipt; the same key with a different hash is rejected as an identity conflict.

One envelope belongs to one WorkScope and one atomic semantic transition. Multiple commands or batch items are allowed only when they share the same causal intent, authority, privacy boundary and complete `ordering_scopes` set. The envelope commits or rejects as a unit. Cross-WorkScope atomic writes, hidden partial success and a command that silently creates a second transition are forbidden.

Task binding and capture are deliberately separated:

```text
`eliot.observe`
  may preserve a safe raw observation as a cold `ObservationCandidate`
  when task selection is absent or ambiguous;

reusable task memory, Claim/Failure/Procedure promotion and task-control writes
  require current `TaskSelectionEvidence`, exact TaskContract revision,
  acceptance digest, WorkScope, State Fence and compatibility disposition;

wrong-scope or incompatible task binding
  rejects the reusable/task-bound transition with `TASK_SELECTION_REQUIRED`
  or `TASK_SCOPE_INCOMPATIBLE`;
  it never silently selects the most recent/open task.
```

A cold unbound capture has no task-specific activation, no support/influence promotion and no finish relevance until a later governed binding transition. This preserves capture-first behavior without recreating the wrong-task contamination observed in the old testbed.

`canonical_provenance_handles` are immutable exact handles. Abbreviated IDs, display labels, prose citations or resolver guesses may be shown in UI, but they cannot satisfy source, evidence, verifier, dependency or authority fields.

### Response modes

```text
wait_for_commit
  wait for canonical WriteReceipt until caller deadline;

accept_after_stage
  return only after complete ORS staging; caller polls/subscribes and MUST NOT retry;

internal_fire_and_observe
  maintenance/system-only service option, not an agent envelope value; no interactive waiter, operation remains fully receipted.
```

If `wait_for_commit` exceeds its deadline after durable staging, the actual result becomes `ACCEPTED_PENDING` with the same operation identity. Request mode and observed result are different fields; a timeout never fabricates rollback or duplicates the write.

## I5.6. Admission and staging

```text
1. authenticate principal/session;
2. validate schema, envelope, size and canonical request identity;
3. resolve authenticated WorkScope, scope level and Ordering Scopes;
4. resolve TaskSelectionEvidence and TaskContract compatibility when the command is task-relative;
5. verify State Fence, authority and expected current revisions;
6. validate exact canonical provenance/evidence/blob handles;
7. normalize paths/resources and privacy/source visibility;
8. attach instruction taint/origin/disclosure metadata;
9. classify impact and requested semantic effect;
10. normalize freshness against base dependencies and expected post-commit revisions;
11. reject reusable admission that would be stale immediately after its own commit;
12. build deterministic MutationPlan and admission-decision digest;
13. stage the complete immutable operation in ORS/redb;
14. return `ACCEPTED_PENDING` for `accept_after_stage` or wait for the canonical receipt;
15. serialize by Ordering Scope;
16. execute store transaction;
17. reconcile receipt into ORS;
18. dispatch the already committed outbox row.
```

No LLM call occurs in this path.

Freshness is evaluated at an explicit point. A reusable candidate carries a normalized predicate over external/source dependencies and the expected state after its own transition:

```yaml
FreshnessAdmission:
  base_revision_heads:
  expected_post_commit_revision_heads:
  dependency_fence:
  predicate_normal_form:
  disposition: CURRENT | SELF_INVALIDATING | PROJECTION_PENDING |
               EXTERNAL_REVISION_RACE | INCOMPLETE
```

The candidate's own commit increment cannot make it stale by construction. `SELF_INVALIDATING`, unresolved provenance, task mismatch or an external revision race rejects hot/reusable promotion; the safe raw observation may remain cold/quarantined. `WriteReceipt.status=committed` proves durable transport only. It does not prove novelty, freshness, task compatibility, support or verification.

When the canonical candidate is durably committed but its cue/index/context projection has not reached the same source fence, the caller receives `CANDIDATE_COMMITTED_PROJECTION_PENDING`. The record exists and may be fetched by exact handle, but it cannot fire on the hot path or support a Material decision until a `ProjectionPublicationRecord` makes the applicable projection `CURRENT`.

`ACCEPTED_PENDING` proves only that the complete opaque operation was durably staged under the same identity. Normal writer readiness after restart requires ORS enumeration, receipt/store reconciliation and residual-unknown disposition; the status never implies canonical commit or exactly-once external effect.

ORS staging uses a bounded micro-batch only to amortize local transaction/fsync overhead:

```text
first request is flushed immediately under low load;
drain only immediately available operations up to configured item/byte/time cap;
reserve Ordering Scope sequences atomically in one redb transaction;
acknowledge each caller only after that ORS transaction commits;
each PreparedTransition still receives its own canonical transaction and receipt.
```

The micro-batch is an optimization profile, not an ordering or atomicity promise between unrelated operations.

### `PreparedTransition`

`eliotd` produces a deterministic, immutable execution plan after semantic admission:

```yaml
PreparedTransition:
  operation_and_idempotency_identity:
  normalized_semantic_commands:
  mutation_plan_hash:
  principal_session_scope_task:
  ordering_scopes:
  required_authority_and_epoch:
  required_state_fence_and_revisions:
  policy_config_schema_snapshots:
  admission_contract_set_digest:
  proposing_daemon_generation:
  named_store_operation_manifest_digest:
  transition_class: capture_candidate | epistemic | task_control | lifecycle_policy | recovery_schema
  requested_effect_ceiling:
  required_proof_and_approval_refs:
  named_store_operations_and_parameters:
  event_projection_relation_intents:
  receipt_and_outbox_intents:
  privacy_origin_taint_metadata:
```

Kernel does not reinterpret project meaning. It verifies identity, authority, fence, ordering, plan hash, admission/operation-manifest digests, `transition_class`, effect ceiling, required proof/approval handles, allowed named operations and compatibility before staging. A staged plan remains executable after daemon replacement only when the candidate Kernel/store bridge still supports the exact recorded contract/manifests; otherwise it stays staged and enters visible recovery instead of being reinterpreted by newer code. Every named store operation manifest declares the transition classes and maximum epistemic/control effect it may realize. Store bridge rejects a plan whose class, scope or effect exceeds that manifest; it cannot add commands or widen scope. This is a generic hard-boundary check, not a second semantic engine.

## I5.7. Ordering and parallelism

`OrderingScope` is selected by the state whose preconditions may mutually invalidate.

DEFAULT classes:

```text
scope:<scope_id>
task:<task_id>
problem:<problem_id>
module:<module_id>
principal:<principal_id>
config:<config_domain>
```

One `OrderingScope` has one active writer epoch and one in-flight canonical transition. Independent Ordering Scopes execute concurrently.

Multi-scope transition:

```text
declare all scopes before execution;
sort by stable scope identity;
reserve every scope sequence atomically in one ORS transaction or reserve none;
assign one monotonic reservation_order from the single ORS coordinator;
store transaction verifies every declared `RevisionHead` dependency and every expected `OrderingHead` sequence/hash before commit;
release/finalize all reservations from one canonical receipt;
use an explicit saga when external effects, long waits or substrate limits prevent one transaction.
```

The ORS reservation produces an immutable `WriterReservationToken` bound to:

```text
writer_epoch;
reservation_order;
all Ordering Scopes and reserved sequences;
PreparedTransition/admission digest;
expected RevisionHeads/OrderingHeads;
expiry and recovery owner.
```

`reserve → eligible → execute → finalize/release` checks the same token and writer epoch at every step. A stale executor cannot finalize or release another generation's reservation. Recovery reconciles the token against the canonical receipt before reuse or disposition. Metrics include oldest-ready age, per-scope wait, head retries, reservation conflicts and executor utilization; they diagnose starvation without replacing per-OrderingScope concurrency by a global writer gate.

All multi-scope reservations pass through one short ORS write transaction. Its `reservation_order` creates the same precedence between overlapping operations in every shared scope and therefore prevents cyclic wait graphs. This does **not** serialize independent store transactions: operations with disjoint Ordering Scopes execute concurrently after reservation. No scope lock/DB transaction is held while waiting for a predecessor, model, tool or network operation.

### WriteCoordinator

Committed and uncommitted order have different owners:

```text
Canonical Store `OrderingHead`
  owns the last committed sequence/hash of durable semantic history;

ORS `ReservationHead`
  owns only uncommitted reservations, predecessor waits and retry/dead-letter state;
  it cannot advance canonical history by itself.
```

Execution rules:

```text
configurable executor lanes share one fair ready-scope scheduler;
one canonical transaction may be in flight per Ordering Scope;
independent scopes may commit concurrently, even when assigned to one executor lane;
a retry delay blocks only that scope head, never the whole lane;
deterministic rejection/dead-letter closes or explicitly gaps the reserved sequence before successors proceed;
recovery reconciles ORS reservations against canonical OrderingHeads/receipts before new allocation;
lane-count change requires drained generation switch.
```

Initial desktop default:

```text
writer_executors = min(4, logical_cpu_count)
store_transaction_limit = writer_executors
```

These are runtime defaults and are tuned by real store workload. Increasing them cannot weaken ordering, ORS capacity, Control Reserve or receipt reconciliation.

## I5.8. Canonical event and projections

The event journal is the audit and rebuild source, while normal reads use projections.

```yaml
CanonicalEvent:
  event_id:
  operation_id:
  scope_id:
  ordering_links:
    - ordering_scope:
      ordering_sequence:
      previous_event_hash:
      event_hash:
  event_ordinal:
  event_type:
  payload_ref:
  principal:
  authority_epoch:
  state_fence:
  occurred_at:
  committed_at:
```

A transition touching several Ordering Scopes has one immutable semantic event identity and one chain link per affected scope. Each link hashes the same event identity/payload plus its scope, sequence and previous link. This preserves one atomic transition without pretending that several causal streams share one head.

Projection rebuild is a Doctor recipe, not a normal write path.

Every derived projection is published through one `ProjectionPublicationRecord`:

```yaml
ProjectionPublicationRecord:
  projection_kind_and_generation:
  projection_definition_digest:
  dependency_definition_digest:
  source_generation_and_cursor:
  source_revision_heads:
  state_fence:
  publication_mode: FULL | DELTA | REFERENCE_FALLBACK
  selection_basis_and_whole_DAG_cost:
  full_cost_estimate_and_observed_cost:
  delta_cost_estimate_and_observed_cost:
  semantic_equality_oracle_ref:
  atomic_data_and_provenance_commit_ref:
  sink_acceptance_and_readback_refs:
  arrival_and_claim_fences:
  provenance_manifest_ref:
  visible_lag_checkpoint_and_error:
  split_view: NONE | DETECTED | RECONCILING
  assurance_ceiling:
  status: PENDING | CURRENT | STALE | FAILED | INCONCLUSIVE
```

A derived `ProjectionMaintenanceDecision` chooses `FULL`, `DELTA` or the exact/reference fallback from measured whole-dependency cost, equality risk, source churn and recovery cost:

```yaml
ProjectionMaintenanceDecision:
  projection_kind_definition_and_dependency_digest:
  source_and_target_state_fences:
  mode: FULL | DELTA | REFERENCE_FALLBACK
  whole_dependency_DAG_cost_and_tail_profile:
  changed_rewritten_and_logical_row_fraction:
  layered_logical_WAL_file_device_write_evidence:
  same_fence_equality_oracle:
  source_churn_and_recovery_cost:
  deterministic_fallback:
  publication_and_rollback_plan:
  status: SELECTED | INCONCLUSIVE | REJECTED
```

Changed-row count alone is insufficient. Candidate data and provenance become visible atomically; partial provenance, a stale definition, a mismatched source generation or a split view leaves the projection `PENDING/STALE`. Full and delta paths satisfy the same same-fence equality oracle and publish layered logical/WAL/file/device write numerators separately when storage economics are claimed.

For source/build/behavioral/concept graphs, the canonical fence is:

```yaml
GraphRevisionFence:
  source_product_worktree_and_state_fence:
  source_revision_heads_and_dirty_overlay_digest:
  graph_definition_dependency_and_schema_digest:
  parser_LSP_build_profile_and_adapter_generations:
  covered_relation_and_configuration_scope:
  visible_projection_generation_and_publication_receipt:
  publication_status: BUILDING | CURRENT | STALE | SPLIT_VIEW | FAILED
  reference_path_and_fallback:
  assurance_ceiling:
```

A stale or unknown graph may navigate with an explicit ceiling; it cannot prove absence, non-impact, authority or the Current Epistemic Position. Scope, disclosure and influence closure are checked before candidate generation and again at every pivot, rerank, community expansion, summary, compilation, tool call and export. Final packet filtering does not repair an unauthorized or contaminated candidate set.

Projection state is a rebuildable view and never authorizes a write, action or finish.

## I5.9. SurrealDB implementation

SurrealDB bridge TARGET DEFAULT (current support is determined only by I0.5 evidence):

```text
separate server process;
remote Rust SDK only inside bridge;
stable fields enforced by generated codecs/schema constraints; SCHEMAFULL preferred for mature records;
typed relation tables;
parameterized named queries;
server-side transactions;
RocksDB-backed single-node service until measured replacement;
logical backup/export only; no copying live DB files.
```

The retained audited source lineage did not prove generic payload round-trip, admission or migration guarantees. That result is regression evidence, not a current repository verdict: current support is classified only by an exact I0.5 `CurrentSystemEvidenceSnapshot`. `SCHEMALESS` by itself is not the defect: a flexible payload is admissible only behind a tagged/versioned codec, required-field constraints, property-based round-trip tests and explicit migration. Stable records normally use SCHEMAFULL or equivalent generated constraints.

### Compatibility gate

SurrealDB 3.2.x is admissible in production after:

```text
schema/migration rehearsal;
transaction/idempotency proof;
crash/restart proof;
backup/restore proof;
query latency on real ELIOT fixture;
no regression against fallback line.
```

Until then, an installation may use only its latest locally qualified fallback generation, regardless of minor-line label. `compatibility.toml` exposes the active decision.

### Store connection generations

Store bridge maintains a fixed bounded client set, not one connection per request:

```text
read clients       — named Q0–Q4 reads under read semaphore;
write clients      — canonical transactions under WriteCoordinator limit;
health/admin client— isolated version/schema/backup/health operations.
```

The target primary transport is the remote RPC/WebSocket path admitted by the exact current compatibility profile. Without that evidence, transport support remains unqualified. HTTP/admin fallback may be used only when separately admitted for the exact health/recovery operation. CLI/offline access requires a stopped store and maintenance authority. Raw database MCP/passthrough is forbidden.

Each client set has a generation, deadlines and bounded reconnect backoff. A broken generation is replaced explicitly; an in-flight write with unknown outcome is resolved by `WriteReceipt` before any replay.

### Canonical-store process generation replacement

The upstream server binary is a Host-managed dependency generation, not an in-place mutable executable and not a second Module Catalog owner.

```text
install immutable candidate binary/config;
rehearse candidate against an isolated imported/copy-on-write dataset;
verify file-format, protocol, schema, transaction and backup compatibility;
quiesce new canonical transactions and reconcile in-flight receipts;
create an ExportFence/backup receipt when the update can change durable format;
prove old process termination and exclusive release of the production data root;
start candidate through HostStateJournal/ManagedDependencyRecord;
verify process liveness plus store-bridge semantic readiness;
resume writes or stop candidate and restart a compatible generation.
```

Two server processes never open the same production data root. A server crash during a possibly committed transaction is reconciled by operation identity/WriteReceipt before any retry. Binary rollback is allowed only while durable format remains compatible; otherwise use isolated restore or forward repair.

`ServiceContract` for the canonical store declares a vendor-supported graceful stop route when one is available, a bounded drain deadline, process-exit observation and a final forced Job Object termination fallback. Forced termination is never called a clean shutdown; the next start performs storage-integrity and unknown-write reconciliation before admitting canonical writes.

## I5.10. Canonical Exchange Format

`ECXF/1` enables database replacement.

```text
manifest.json
schema/
events/*.ndjson.zst
projections/*.ndjson.zst
blobs/<residency-key-digest>/<content-digest>.blob
receipts/*.ndjson.zst
integrity.json
privacy-purge-ledger.json
```

The manifest contains:

```text
format version;
source store adapter/version;
Architecture source digest plus externally sealed NormativePairIdentity receipt;
scope/revision ranges;
checksums;
opaque blob residency identities plus retention/erasure domains;
encryption/compression;
missing/unsupported features;
purge state;
export receipt.
```

Export is independent of SurrealQL.

### Consistent export boundary

An ECXF export is tied to an `ExportFence` containing schema/store generation, scope revisions, Ordering Heads, event range and blob residency/reachability manifest. The bridge uses a database-supported consistent snapshot/transaction when available. Otherwise it records a base fence, exports immutable history/projections, tails canonical events to a final fence and briefly quiesces affected writes for final reconciliation. If neither route can prove a coherent boundary, the export fails; mixing unrelated table moments into one “backup” is forbidden.

## I5.11. Storage replacement

```text
1. install candidate store bridge;
2. import snapshot into candidate;
3. verify counts, hashes, graph/projection invariants;
4. run shadow reads against both stores;
5. tail canonical events into candidate;
6. quiesce affected writes;
7. reconcile final sequence;
8. commit the `canonical_store` CapabilityRouteScope cutover through Kernel Generation Registry;
9. canary reads/writes;
10. keep old store read-only for rollback window;
11. retire only after backup and cutover receipt.
```

Rollback switches generation back only if no irreversible migration/effect occurred; otherwise uses forward repair.

## I5.12. Blob Store

`BlobStore` is a vendor-neutral CAS contract with one active root owner. A co-located or process backend MUST implement the same contract, receipt format, encryption lineage, reachability rules and conformance suite. Kernel routes process-backed requests; `eliotd` decides whether a payload is admissible and later references only a completed `BlobReadyReceipt`. A component that is not the declared active owner never writes the blob filesystem directly. Extraction from an internal backend to `eliot-blob.exe` is a generation cutover: quiesce stages, reconcile temp/ready receipts, fence the old owner, switch the route, then resume.

Logical object identity is scoped by deletion and retention obligations:

```text
ObjectResidencyKey = scope_domain_id + access_domain_id + confidentiality_domain_id +
                     encryption_key_domain_id + retention_domain_id + erasure_domain_id +
                     content_digest
```

`content_digest` includes the active Blob format's algorithm and version; the current default is BLAKE3, but the ownership rule is algorithm-neutral. `scope_domain_id` binds the lawful WorkScope or source namespace; access and confidentiality domains bind principals and disclosure; `encryption_key_domain_id` binds the permitted key lineage; retention and erasure domains bind lifecycle and purge closure. Equal bytes deduplicate only when **all** residency-domain identities are equivalent. Byte equality never permits cross-domain physical co-residency, ciphertext reuse, encryption-key reuse, or coupling of retention and erasure obligations. Moving content between domains is an explicit copy or re-encryption transition with a receipt and an explicit disposition for the old copy—not a metadata relabel.

Physical path is derived from the full residency identity, not from a global content digest alone:

```text
C:\ProgramData\Eliot\blobs\<residency-key-digest>\<prefix>\<content-digest>.blob
```

Algorithm:

```text
stream through privacy/redaction policy;
compute the versioned digest of the exact post-policy canonical bytes;
resolve scope, access, confidentiality, encryption-key, retention and erasure domains and derive the residency key;
retain a separate protected source checksum only when policy permits;
compress and AEAD-encrypt to a temp envelope;
flush and fsync ciphertext plus metadata;
atomic rename;
return immutable `BlobReadyReceipt`/BlobRef only after durable rename and metadata commit;
allow canonical transition to reference only that receipt;
GC only after grace period and a coherent live-set scan.
```

The live set is the union of canonical references under a stable revision fence, unresolved ORS/staged-operation blob references, active export/backup/transfer leases and retention/purge holds. If any required source is unavailable or inconsistent, GC does not delete. A canonical-only reachability scan is insufficient because a durably staged operation may legitimately reference a blob that is not canonical yet.

Encryption uses a random installation master key protected by the platform secret provider and filesystem ACL for the ELIOT service identity; only the Blob Store code path receives the materialized key handle. Blob payloads use versioned per-object/per-scope AEAD envelopes; the master key, plaintext data keys and secrets never enter TOML, canonical memory or logs. This limits accidental exposure but is not claimed as a hard boundary against arbitrary code already compromised under the same privileged OS identity; `dpapi-machine` alone is never treated as authorization. Key rotation creates a new key lineage and background rewrap job; missing key material degrades reads/recovery visibly and never causes plaintext fallback.

`BlobReadyReceipt` binds the logical residency identity, versioned content digest, stored length, compression/encryption format, key lineage, privacy/retention class, erasure domain, durable path generation and operation identity. It proves durable payload availability only; admissibility and semantic meaning remain the later canonical transition.

Inline threshold DEFAULT: 32 KiB. Exact value lives in config/profile.

## I5.13. Backup and restore

Backup classes are explicit:

```text
full_recovery
  canonical logical export + referenced blobs + coherent OrsSnapshotFence
  + config/policy/module and approved Host/dependency build manifests
  + integrity anchors + purge ledger
  + a bounded WatchdogSpoolFence for unreconciled critical signals/intents
  + an optional forensic HostStateAuditFence that is never restored as active authority;

canonical_only_degraded
  coherent canonical export and blobs, but no self-consistent ORS snapshot;
  preserves semantic data only and is never advertised as operational recovery;

scope_export
  bounded ECXF transfer for one declared scope; not an installation backup.
```

Restore:

```text
restore to isolated root;
validate format/schema/checksums;
apply privacy purge ledger;
rebuild projections/indexes;
verify receipt/event chain;
issue a new Authority Epoch lineage above all observed epochs;
restore no active SessionBinding, user-broker registration, `UserBrokerEpoch`, launch lease or route continuation as current authority; they return only as historical/suspended recovery evidence;
import restored ORS operations as `suspended_recovery`, never runnable; reconcile canonical receipts and external-effect evidence before any replay;
run semantic and operational recovery checks;
Human/System Owner authorizes cutover;
create a new HostInstallationEpoch/Kernel activation lineage rather than restoring HostStateJournal as active;
retain pre-cutover state until explicit retirement.
```

Backup existence is not recovery proof. Scheduled restore rehearsal is a release/maintenance job.

A portable/full backup may not merely copy installation-encrypted blob files and assume the destination owns the key. It either re-encrypts payloads into the backup envelope or records a separately protected wrapped-key manifest and restoration receipt. The backup contains key lineage and format metadata, never plaintext master/data keys. Missing or unverifiable key material makes the affected blob set unrestorable and fails `full_recovery` proof.

Export and backup never merge blob records solely because their content digests match. Every entry preserves the opaque residency-key digest, versioned content digest, retention/erasure domains and purge-ledger revision. Equal bytes under different obligations remain distinct logical objects; restore applies the current purge ledger and may not coalesce them into a shared residency object.

A `full_recovery` backup receipt requires one manifest binding the ECXF `ExportFence`, every referenced blob residency identity and content digest, a self-consistent `OrsSnapshotFence`, purge-ledger revision, configuration/policy/module and approved Host/dependency build manifests, integrity anchors and any unreconciled critical Watchdog signals/intents under a `WatchdogSpoolFence`. If a `HostStateAuditFence` is attached, it contains only a logical forensic digest/snapshot of installation lineage and observed dispositions; it is optional for recovery because cutover creates a new Host lineage, and it is never restored as active authority. Watchdog/Host operational snapshots restore only as forensic/suspended evidence and never as active supervision or authority. Missing blobs, an unexplained revision gap or an incoherent ORS fence fails that class rather than producing a partial “successful” backup. `canonical_only_degraded` uses a different explicit receipt/status and cannot satisfy normal restore-readiness policy. Incremental backups preserve the base snapshot and exact canonical event interval needed for replay.

`OrsSnapshotFence` is a logical Kernel export, not a copy of a live redb file. It records Host/Kernel authority lineage, last reconciled canonical receipt/event/outbox cursors, pending-operation identities and hashes, job checkpoints, generation cutovers and snapshot time. The ORS and canonical export are not claimed to be one cross-store transaction: the manifest records their relation, and restore imports every ORS item as `suspended_recovery` for receipt/effect reconciliation. If Kernel cannot produce a self-consistent logical ORS snapshot, only a `canonical_only_degraded` receipt may be issued; it preserves canonical data but is not advertised as a full backup or normal operational-recovery point.

## I5.14. Retention and erasure

Privacy erase operation enumerates:

```text
canonical payload;
derived projections/indexes;
blob store;
ORS pending copies;
backup catalog and future restore path;
Route Continuation State;
provider-side data when API supports deletion.
```

Evidence handles expose one closed availability axis, orthogonal to epistemic status, execution/evaluation and source admissibility:

```text
EvidenceHandleAvailability:
  LIVE | STALE | COLD_RESTORABLE | REDACTED | RETENTION_BLOCKED | BROKEN_INTEGRITY
```

These are not all terminal states. `STALE` may be revalidated, `COLD_RESTORABLE` may be restored through a qualified path, and the retention-blocked state records a hold/policy reference plus next review or expiry while ordinary use remains unavailable where policy permits. `REDACTED` returns no deleted content—only a non-revealing tombstone/purge reference. It is not `BROKEN_INTEGRITY` and cannot be silently substituted by a summary, cached excerpt or other derivative. `BROKEN_INTEGRITY` means required bytes/digest lineage cannot be proven and never masquerades as privacy erasure.

Erasure produces purge receipt and non-revealing tombstone/digest when policy permits. Restore refuses to resurrect purged payload.

---

## I5.15. Canonical contract catalogue

The versioned contract catalogue/IDL is the single catalogue of load-bearing public and durable contracts. **No generated authoritative catalogue exists yet; `ImplementationSupport = TARGET` and `EvidenceExecutionStatus = NOT_EXECUTED`.** Until a real generated catalogue is consumed by current source/tests and bound evidence, the owning I-section remains authoritative for meaning, owner, behavior and failure semantics.

Appendices N/P/H are target/discoverability projections. They cannot override an owning I-section, create support by presence, or become a second field-level schema owner.

```yaml
ContractCatalogueEntry:
  contract_name_and_kind:
  single_owning_section:
  owner_capability_and_state_owner:
  contract_revision_and_digest:
  generated_schema_trait_and_surface_refs:
  projection_index_refs:
  implementation_support_and_proof_ceiling:
  compatibility_migration_and_invalidation:

ContractCatalogueBuildReceipt:
  implementation_and_architecture_digests:
  discovered_normative_contracts_and_owners:
  generated_IDL_code_schema_and_surface_refs:
  unresolved_manual_or_duplicate_definitions:
  consumer_coverage_and_current_support:
  build_tool_and_artifact_digests:
```

Only blocks explicitly marked `ContractShape: normative` require an entry; unmarked YAML/examples are explanatory target projections. A missing entry for a marked contract makes coverage `PARTIAL`; a second field-level definition is an owner collision.

Concrete storage tables may combine or split records for performance, but implemented contracts preserve identity/scope, provenance/anchors, epistemic and lifecycle status, applicable time dimensions, State Fence/policy/config, relations/supersession, privacy/visibility and reconstruction/receipt path.

### Initial executable set

D0/D1 activates only the minimum needed for the operational spine:

```text
Product/WorkScope/Task identity;
State Fence, Authority Epoch and Operation Identity;
TaskContract and ObservationCandidate;
PreparedTransition, OperationState and WriteReceipt;
Instrument/Verification receipts;
Finish attempt/proof/decision;
ProblemState and RecoveryDirective;
Agent response disposition and generated reason-code registry.
```

Later contracts activate when a real consumer/test seam appears. Entries outside the active set remain target/migration vocabulary and are not handed to agents as work merely because they are listed.

## I5.16. Common durable fields

Every durable semantic record carries, directly or through an immutable envelope:

```yaml
id:
record_kind:
scope_id:
task_id:
created_by_principal:
created_at:
observed_at:
valid_time:
known_time:
transaction_time:
state_fence:
epistemic_status:
lifecycle_status:
authority_class:
origin_assurance:
instruction_taint:
semantic_screening:
privacy_class:
visibility:
source_refs:
evidence_refs:
verification_refs:
supersedes_refs:
policy_snapshot_id:
config_snapshot_id:
schema_version:
```

Derived/exportable records additionally carry, when applicable:

```text
influence_dependency_closure_ref;
disclosure_dependency_closure_ref;
source_availability;
coverage_and_assurance_ceiling;
coordinate_basis_and_approximation;
```

Absence of a closure or coverage record means `unknown`, not unrestricted/complete.

Fields that do not apply remain explicit `None`; they are not silently omitted from the semantic model.

## I5.17. Semantic command families and activation

Implementation defines a small set of semantic command **families**; exact variants are generated from the active contract catalogue. A permanent prose list of every anticipated future command is forbidden because it becomes a feature checklist and a second schema registry.

```text
Capture and source observation;
Task/WorkScope/plan state;
Epistemic revision and conflict/attention;
Canonical transition and receipt;
Instrument, verification and finish;
Authority, lease, capability and external effect;
Session, agent attempt, coordination and integration;
Module/config/lifecycle and recovery;
Audit/telemetry evidence.
```

The D0/D1 surface activates only variants required by the operational spine. A Module adds a command only when its owning section, catalogue entry, consumer and affected proof exist. Unknown variants remain unsupported; they are not silently mapped to generic upsert/status behavior.

Batch forms are bounded envelopes for one source/attempt/WorkScope and shared provenance. Full schema, visibility, authority, privacy, scope and fence validation occurs before staging. A boundary violation rejects the atomic envelope. Semantic type/relation/cue ambiguity instead preserves the item as `ObservationCandidate` when safe capture is allowed.

The command profile fixes item/byte limits. Oversized input is rejected before sequence reservation with a split directive; the server never silently splits one causal envelope into several commits.

Ownership is derived from the owning I-section and active catalogue:

```text
definition/plan intent requires the current Task Controller authority;
Governor owns admission and canonical semantic transitions;
Kernel owns mechanical generation/epoch/ORS lifecycle, never semantic intent;
Instrument evidence requires the admitted InstrumentRunner identity and executed status;
model/worker/Dreamer outputs remain candidate-only;
external effects require proposal → authority → executor → outcome reconciliation;
derived index/session/episode inputs remain coverage-bounded observations;
Module process generation is never mutated by a semantic command.
```

There is no `RawRecordUpsert`, raw storage query or generic `set status`. Detailed historical candidate vocabulary is retained in the non-normative cold backlog; reactivation requires a real owner, consumer, migration and falsifier.

## I5.18. Relation registry

Canonical relation families:

```text
supports / contradicts / verified_by / supersedes;
belongs_to / covers / implements / depends_on;
calls / reads / writes / produces / consumes;
causes / fails_because / resolved_by / invalidated_by;
blocks / unblocks / satisfies / reopens;
mentions / derived_from / included_in / used_for / suppressed_by;
authorized_by / assigned_to / influenced_by / invalidates_influence;
derived_disclosure_from / declassified_by;
grant_parent / introduced_as / bound_with_credential;
builds / emits_artifact / executes_test / covers_code / verifies_property;
co_change / resembles / diverges_from.
```

Every relation has:

```text
type and direction;
scope and time;
source/provenance;
epistemic status;
dependency/invalidation rule;
lifecycle and supersession.
```

`similarity`, `sequence` and `co_change` cannot be promoted to causal relation without a separate governed transition.

## I5.19. Write submission, execution and receipts

Three different outcomes are not collapsed.

### `WriteSubmission`

Returned by admission/front door before a final canonical receipt:

```yaml
submission_id:
operation_id:
request_hash:
state: not_accepted | staged | resolved_existing
reason_codes:
ors_stage_ref:
canonical_receipt_ref:
retry_identity_rule:
next_allowed_action:
```

`not_accepted` means the requested domain mutation was not staged, no Ordering Scope sequence was reserved and no external effect was issued. Corrected payload uses a new operation identity; exact retry of the same hash returns the same decision. Syntax/shape errors are operational responses. Authority/security/revision denials may create a separate governed audit/Problem transition with its own identity; that control evidence must not be confused with execution of the rejected request.

`staged` means ORS accepted the exact operation identity; caller must not create a duplicate and may poll. `resolved_existing` points to an already final receipt for the idempotency key.

### Canonical execution

For each staged `PreparedTransition`:

```text
1. resolve existing WriteReceipt by idempotency key;
2. verify ordering predecessor and active Authority Epoch;
3. revalidate required revisions/policy;
4. execute one named parameterized transaction;
5. append canonical events;
6. update projections and typed relations;
7. update the exact affected RevisionHeads and OrderingHeads;
8. append audit-chain fields;
9. create final WriteReceipt and outbox rows;
10. commit;
11. reconcile ORS and notify waiters.
```

`WriteReceipt` is terminal:

```yaml
operation_id:
idempotency_key:
scope_and_ordering_sequences:
status: committed | rejected | dead_letter | cancelled
commit_id:
revision_before_after:
applied_command_ids:
emitted_event_ids:
projection_refs:
policy_config_schema_versions:
committed_at:
error_code_and_evidence:
resubmission: none | new_identity_after_condition
```

`retry_wait`, `applying`, `unknown_outcome` and `reconciling` are ORS `OperationState`, never canonical receipt statuses. A final receipt is immutable: retrying the same operation identity returns the same receipt. `new_identity_after_condition` only authorizes a newly admitted operation after the named condition changes; it never replays the terminal operation. `rejected` and `cancelled` assert that the requested domain mutation and external effect did not occur and safely disposition a reserved order. The receipt/audit/sequence disposition itself is a canonical control transition; it is never described as “no canonical write”. `dead_letter` is terminal only when the original mutation is proven not to have been applied; it preserves the unusable operation and opens a `SequenceGap` whose ordering position still requires disposition. If any canonical/external effect is unknown, no final `dead_letter` receipt is fabricated: the ORS operation remains `UNKNOWN_OUTCOME/RECONCILING`, the gap is open and only dependent scopes pause. Recovery resolves the gap through a canonical `SequenceDisposition` preserving original evidence.

Unknown commit is never retried blindly. Kernel queries receipt by identity; proven rollback may retry the same operation; unresolved outcome pauses only dependent scopes and opens Problem State.

### Receipt taxonomy and common envelope

The many domain names ending in `Receipt` do **not** create many receipt stores, writers or unrelated lifecycle roots. Every durable receipt is a typed payload inside one versioned envelope owned by the subsystem that performed the transition:

```yaml
ReceiptEnvelope:
  receipt_id_and_kind:
  schema_and_contract_revision:
  installation_product_workscope_task:
  operation_attempt_and_idempotency_identity:
  principal_owner_and_generation:
  authority_epoch_and_state_fence:
  input_output_and_artifact_digests:
  terminal_or_observed_disposition:
  evidence_and_raw_handle_refs:
  privacy_disclosure_and_retention:
  created_observed_committed_at:
  supersession_invalidation_and_reconciliation_refs:
  typed_payload:
```

Receipt classes are limited to:

```text
canonical transition;
external effect/process execution;
delivery/observation;
evaluation/verification;
recovery/cutover/migration.
```

A new domain-specific name ending in `Receipt` is only a typed payload kind or a derived view unless it proves a distinct owner, lifecycle, idempotency boundary and query need. Common identity, authority, fence, provenance and terminal semantics are never redefined in the payload. A report, candidate, plan, preview or registry view is not renamed into a receipt merely to sound authoritative. Generated contract checks reject duplicate common fields and two payload kinds claiming the same transition.

## I5.20. Read model, consistency and cache

Read tiers:

```text
Q0 handle/preview;
Q1 current task/scope state;
Q2 exact evidence and relations;
Q3 Active Understanding View / Context Packet;
Q4 audit/replay/evidence pack;
Q5 research/reconstruction cold job.
```

`ReadConsistency` modes:

```text
eventual             — cheap preview;
at_least_revision    — read-your-write after receipt;
stable_scope         — coherent packet/current-position assembly;
exact_fence           — all listed dependency revisions must match.
```

Stable-scope algorithm:

```text
derive the exact dependency revision keys for the requested view;
read RevisionHead set A;
execute bounded named reads;
read the same RevisionHead set B;
if every dependency revision matches, publish;
else retry once or return stale/churn directive.
```

`ScopeRevisionView` is a rebuildable aggregate for previews and diagnostics. It is not a write-serialization row and is never sufficient for a Material State Fence by itself.

Caches are revision-keyed and reconstructible:

```text
RevisionHeadCache;
PacketCache;
Cue/Activation mirror;
Module Catalog / Capability Registry snapshot;
read-through exact-atom cache.
```

No cache invents freshness. Every reused response has dependency set and invalidation conditions. Cache reuse also obeys I2.22: integrity is separate from origin authentication, untrusted roots/reparse paths are rejected or treated as misses, and a cache is never a correctness dependency.

## I5.21. Transactional outbox and notifications

Domain transition, receipt, revision and outbox intent commit atomically. Outbox delivery is at-least-once and idempotent.

```text
subscriber lag never blocks canonical commit;
undelivered rows remain queryable;
resource/job/mailbox notifications carry sequence;
projection/cue/cache consumers checkpoint cursor;
outbox mismatch opens projection-health Problem State.
```

Sender WAL/outbox state does not prove that a sink accepted or applied an item. The existing event/receipt owner records sink-side phases:

```text
ARRIVED
→ CLAIMED under consumer generation/claim fence
→ APPLIED | REJECTED | UNKNOWN
→ READBACK_CONFIRMED | IRRECONCILABLE.
```

`arrival_fence` prevents replay from an obsolete producer lineage; `claim_fence` prevents two consumer generations from applying the same logical item concurrently. Cursor advancement is bound to the declared sink phase. Crash after sender commit but before sink-owned acceptance remains `UNKNOWN`; it is reconciled by stable operation/effect identity and sink readback, never inferred from timeout or missing acknowledgement.

Raw DB changefeeds are not an agent surface. A future changefeed may optimize the outbox only after equivalence proof.

## I5.22. Schema and migration rules

```text
core schema is explicit and versioned;
relation endpoints and required fields are enforced where supported;
migration IDs/checksums are immutable after release;
one migration lease exists per installation;
additive/forward-compatible change is preferred;
data rewrites are Durable Jobs with checkpoints;
destructive/irreversible migration requires backup and Human approval;
blocking migration prevents normal writer readiness, not all recovery inspection;
every migration produces schema snapshot and receipt;
rollback class is declared: reversible | forward-repair | restore-required.
```

Migration code runs only through the store bridge under Kernel-issued migration capability. Agents never execute arbitrary migration queries.

## I5.23. Recovery/import inbox

Offline producers and legacy migration may submit signed/hashed `CanonicalWriteEnvelope` files to a recovery inbox:

```text
write temp;
flush/fsync;
atomic rename;
Kernel imports into ORS;
normal admission and receipt path applies;
file moves to applied/rejected/dead-letter with receipt sidecar.
```

Arbitrary `.surql` or vendor script is admin maintenance input and cannot enter the normal hot path.

---

## I5.24. Operational control state versus cognitive inheritance

The canonical store contains several governed state families under one owner, but they do not have interchangeable authority.

```text
Operational control state
  TaskContract, WorkItem, Attempt, Lease, Authority Epoch, Effect ledger,
  GenerationCutover, Durable Job, outbox and terminal receipts;

Cognitive inheritance
  sources, observations, evidence, epistemic positions, models, decisions,
  procedures, failures, relations and memory lifecycle;

Derived indexes/projections
  Ready Queue, search/cue/code graphs, packets, dashboards and reports;

Artifact state
  immutable source/output/build/log/component/failure objects by digest.
```

Task, lease, effect, generation and job truth is resolved from operational records and receipts, never from semantic similarity, a memory summary, an agent narrative or a derived index. Cognitive inheritance may inform planning and verification but does not authorize an effect. Derived projections are rebuildable and cannot become a second control ledger.

This is a logical separation, not a requirement for four databases. The first SurrealDB implementation may keep the families under one transaction boundary while preserving owners, schemas, queries, retention and recovery rules.

## I5.25. Response reuse, cited dependencies and invalidation

A rendered answer, packet, report or cached projection is reusable only when ELIOT can name the facts and contracts on which its current meaning depends. Cache identity alone is insufficient.

`ResponseReuseReceipt` binds:

```text
response/artifact identity and renderer/schema revision;
question, WorkScope, Task and visibility scope;
State Fence and Current Epistemic Position revision;
cited facts, evidence, claims, policies, Tool Definitions and verifier contracts;
freshness/supersession/revocation watches;
allowed reuse classes and exact invalidation conditions;
reuse decisions and downstream outcome refs.
```

Rules:

```text
no dependency set → no current-state reuse;
a source, policy, verifier, Tool Definition or scope revision invalidates the dependent response;
invalidated output remains historical evidence but is removed from current influence;
re-rendering from the same stale inputs does not restore validity;
reuse across WorkScope, principal, route or privacy boundary requires an explicit compatible projection;
cache hit never upgrades epistemic status or completion.
```

Dependency invalidation uses the same explicit influence graph as I12.20. Similarity is not a revocation mechanism. When dependency lineage is incomplete, the response is marked `dependency_incomplete` and may be shown only with that limitation or rebuilt from primary evidence.


## I5.26. Derived disclosure and observation-domain closure

Governor owns canonical observation-domain lineage, disclosure closure revisions and DisclosureDecisions. Source/adapter ingress may attach direct domain observations; Context Compiler and Agent Coordinator compile closures for exact packets/waves; Watchdog observes bypass or leakage; Dreamer may only propose a transformation or classification candidate.

Epistemic provenance and disclosure permission are separate graphs.

```text
Influence Dependency Closure
  answers what currently supports or influences a representation;

Disclosure Dependency Closure
  answers which authorization/privacy domains remain material to it
  and therefore constrain where it may be sent or shown.
```

A public false claim can be freely disclosed and have zero support. A verified private fact can have strong support and narrow disclosure. Summary, compaction, Dreamer synthesis, model restatement or adapter normalization does not clear either lineage.

### Observation domains

`ObservationDomainRef` labels policy-sized source domains, not every token or line:

```yaml
ObservationDomainRef:
  domain_id:                    # opaque, non-revealing stable ID
  protected_display_label_ref:  # optional; never required on hot path
  kind: local_root | connected_resource | user_private | tenant |
        secret_class | provider_retention | licensed_source | custom
  authority_root:
  resource_scope:
  privacy_class:
  visibility_and_export_rule:
  model_route_rule:
  ACL_or_verifier_adapter:
  generation_and_state_fence:
```

Logical examples (not literal wire IDs):

```text
private repository domain;
connected-drive folder domain;
production credential class;
human-private domain;
provider-retention class;
non-redistributable corpus.
```

Stored domain IDs are opaque. Human-readable labels are protected metadata and may be purged or redacted while a non-revealing tombstone/digest preserves revocation and audit continuity. Closure membership is security metadata; it is not automatically exposed to the recipient whose disclosure is being decided.

### Closure and decision

```yaml
DisclosureDependencyClosure:
  closure_id:
  subject_ref:
  direct_domain_refs:
  inherited_closure_refs:
  derivation_or_transformation_refs:
  completeness: complete | partial | unknown
  declassification_receipt_refs:
  policy_snapshot_id:
  state_fence:
  revision:

DisclosureDecision:
  subject_and_closure_ref:
  recipient_principal_or_route:
  recipient_capability_set:
  covered_domains:
  uncovered_domains:
  decision: allow | allow_redacted | recompute_narrower |
            fork_private | require_authority | deny
  policy_snapshot_and_state_fence:
  receipt_ref:
```

A model-written claim that sensitive material was removed is not declassification. Subtracting a domain requires a registered deterministic or externally verified transformation:

```yaml
DeclassificationReceipt:
  input_closure_ref:
  transformation_id_and_version:
  exact_input_and_output_hashes:
  removed_or_generalized_domains:
  preserved_domains:
  verifier_and_property:
  residual_limitations:
  authority_and_policy_ref:
```

### Propagation

```text
capture
→ attach direct ObservationDomainRefs;

deterministic/model transformation
→ union all input closures by default;

registered sanitizer/aggregator
→ may remove a domain only through DeclassificationReceipt;

packet/model/swarm compilation
→ compute exact output closure;

route/share/export admission
→ compare closure with principal/route capabilities;

privacy/ACL/source change
→ invalidate dependent DisclosureDecisions by explicit edges.
```

Authorization, WorkScope and disclosure closure are enforced before candidate generation and again after every selection-transforming stage: graph pivot, rerank, community/cluster expansion, summary, context compilation, tool invocation and export. An unauthorized structural edge or shared-history signal cannot change candidate membership merely because the final facts are individually authorized. ELIOT reports unauthorized retrieval, selection-integrity harm and benign cross-user/route behavioral contamination as distinct outcomes; final packet filtering is not a cure for an already contaminated decision path.

For a shared `RootContextRevision`, adding evidence with a broader closure creates a new revision and reruns admission for every recipient. If one recipient lacks coverage, ELIOT chooses one explicit result:

```text
private fork;
verified redacted projection;
recipient re-authorization/removal;
narrower task;
denial.
```

It never silently upgrades a shared root.

Failure behavior:

```text
complete closure + covered recipient
  → normal delivery;

partial/unknown closure
  → local processing may continue inside the current boundary;
  → remote/export/share returns `DISCLOSURE_CLOSURE_INCOMPLETE`
    or is recomputed narrower;

ACL adapter unavailable
  → no access is inferred from login or prior success;

sanitizer inconclusive
  → full input closure remains;

revocation after delivery
  → stop future delivery, revoke enforceable handles,
    retain delivery receipt and open a Problem when external recall is impossible.
```

The closure uses stable domain IDs and compact sets/bitsets on hot paths; full evidence remains handle-based. ELIOT does not build a global per-datum observer graph.


## I5.27. Canonical operation identity and effect identity

Idempotency is defined over canonical bytes, not over caller spelling or an unversioned hash.

```yaml
CanonicalOperationIdentity:
  installation_id:
  domain_separator:
  idempotency_namespace:
  canonical_encoding_version:
  canonical_request_hash:
  semantic_command_kind:
  principal_and_scope:
  operation_id:
  retention_and_collision_window:
```

Canonical encoding is deterministic and versioned; fields affecting authority, scope, ordering, privacy or effect cannot be omitted/defaulted silently. Reusing an idempotency key with a different canonical request hash returns `IDENTITY_CONFLICT` and performs no transition.

Database idempotency and external-effect idempotency remain separate. An external effect has its own effect identity, provider capability statement and reconciliation state; a committed canonical intent never proves that the effect occurred exactly once.

# I6. Contract levels

## I6.1. Purpose

Contracts must give the agent sufficient certainty without ritual. Depth follows impact and uncertainty, not a desire to fill fields.

## I6.2. Four levels

### Primitive

For a read-only, reversible, local, obvious action.

```text
intent;
scope;
expected output;
one stop condition.
```

### Standard

For ordinary development of one Module or work item.

```text
goal and acceptance;
read/write impact;
current State Fence;
expected observable;
verifier;
writeback requirement.
```

### Deep

For Material or Critical, cross-Module, migration, security, or stateful change.

```text
competing options and rationale;
full impact/Ordering Scopes;
authority chain;
invariants and negative memory;
rollback/compensation;
independent observation requirement;
recovery and escalation;
explicit residual unknowns.
```

### Release

For a public installation or release.

```text
compatibility matrix;
migration and rollback;
backup/restore proof;
hot-upgrade proof;
fault/restart proof;
full affected + release suite;
known issues;
artifact provenance/signature.
```

## I6.3. Impact classification

Governor computes baseline class from registered detectors. Agent may raise, never lower.

```text
Observe      — no state/effect;
Reversible   — local state, cheap deterministic rollback;
Material     — durable behavior/state/artifact or multi-file/module effect;
Critical     — security, authority, schema, destructive/external irreversible effect;
Forbidden    — policy excludes action regardless of rationale.
```

Mismatch between agent-declared and computed class creates Watchdog signal if repeated or suspicious.

## I6.4. Module contract

Every hot module ships immutable `module.toml`:

```toml
module_id = "codegraph.git"
version = "0.1.0"
artifact_hash = "blake3:..."
protocol = ["ebp.module.v1"]
architecture = ["ARCH-GROUND-01", "ARCH-MOD-02"]
capabilities = ["codegraph.query", "codegraph.refresh"]
required_capabilities = ["filesystem.read", "git.read"]
optional_capabilities = ["lsp.symbols"]
advisory_capabilities = ["behavioral_graph.read"]
startup_after = ["filesystem.read", "git.read"]
drain_before = ["filesystem.read", "git.read"]
invalidation_triggers = ["git.head", "git.dirty", "module.config"]
state_owner = "module-derived"
failure_domain = "process:codegraph.git"
hot_replace = true
supervision_plan = "one_for_one"
child_restart = "transient"
restart_intensity = "3/10m"
resource_profile = "background-medium"
privacy_classes = ["project_code"]
permissions = ["read:scope_root"]
health_contract = "health/codegraph-v1"
checkpoint_contract = "checkpoint/derived-v1"
compatibility_state = "rebuildable"
independent_test_profile = "module/codegraph-git"
contract_fixture_set = "ebp.module.v1/codegraph.query"
affected_test_tags = ["codegraph", "git", "process"]
```

Module contract MUST declare:

```text
owner;
inputs/outputs;
owned mutable/derived state;
authority/effects;
dependencies typed as required, optional or advisory;
startup/drain order and invalidation triggers;
failure domain and protocol range;
eligible supervision strategy, restart-intensity window and cooldown;
health/readiness/freshness;
restart/rebuild/quarantine;
state migration or rebuild path;
telemetry;
independent module/contract/fault test entrypoints;
consumer/provider fixture revisions;
removal boundary.
```

The graph of `required_capabilities` must be acyclic before a generation can reach `READY`. Optional/advisory back-references may carry observations or hints, but they cannot become mutual liveness prerequisites. Startup follows required dependencies; drain runs in reverse; a missing optional/advisory dependency is expressed as a capability/freshness downgrade, not a deadlock.

## I6.5. Bridge contract

A bridge translates, isolates and observes. It MUST NOT contain project semantics that belong in Governor/Dreamer.

```yaml
BridgeContract:
  bridge_id:
  upstream_project_and_license:
  upstream_version:
  Eliot_capabilities:
  protocol_mapping:
  data_classes:
  credentials_boundary:
  side_effects:
  timeouts_and_cancellation:
  health_probe:
  failure_translation:
  process_executor_profile:
  independent_contract_suite:
  fixture_and_golden_corpus:
  update_method:
  export/removal_path:
```

## I6.6. Action contract

```yaml
ActionContract:
  action_id:
  task_id:
  intent:
  scope_and_state_fence:
  impact_class:
  authority_ref:
  read_set:
  write_or_effect_set:
  preserved_invariants:
  expected_observable:
  verifier:
  rollback_or_compensation:
  stop_conditions:
```

Governor may auto-fill known fields. Agent edits only material uncertainty.

For an external or otherwise effectful action the contract is compiled into three records:

```text
ProposedEffect
  what an agent/component asks to do; no authority;

AuthorizedEffect
  exact proposal + policy/approval/lease/epoch/idempotency and executor boundary;

EffectReceipt
  observed committed/rejected/unknown/compensated outcome.
```

The proposer never executes merely because it produced valid JSON. Replay and simulation can process `ProposedEffect` without performing the effect. Unknown outcome blocks the dependent Ordering Scope until reconciliation; a retry uses the same idempotency identity or a new explicitly related operation after proven rollback.

## I6.7. Evaluation contract

```yaml
EvaluationContract:
  verifier_id:
  property:
  scope/environment/version:
  accepted_inputs:
  expected_output_schema:
  pass/inconclusive/fail semantics:
  known_blind_spots:
  independence_profile:
  freshness:
  invalidation_conditions:
  owner:
```

Registration does not prove competence. Competence is tracked by actual outcomes and calibration.

## I6.8. Contract rejection

Error returns all defects in one response:

```yaml
ContractError:
  code:
  schema_digest:
  invalid_fields_and_paths:
  missing_fields:
  allowed_enum_values:
  semantic_vs_schema_error:
  evidence_refs:
  safe_fallback:
  minimal_valid_example:
  next_allowed_action:
  retry_policy:
  write_mutation_status: NOT_ATTEMPTED | STAGED | COMMITTED | UNKNOWN
  write_intent_id:
  proposed_operation_id:
  corrected_operation_id:
  corrected_from_operation_id:
```

Semantic ambiguity defaults to safe capture as Observation Candidate, not data loss.

`AdmissionRejection` is a typed pre-stage result, not a canonical receipt:

```yaml
AdmissionRejection:
  request_id:
  proposed_operation_id:
  stage_state: none
  ordering_sequence_assigned: false
  decision: not_accepted | conflict
  all_contract_errors:
  durable_audit_or_problem_ref:   # only when policy/security requires one
  safe_capture_fallback:
  corrected_retry_identity_rule:
  next_allowed_action:
```

A corrected payload normally receives a new operation identity. Exact retry of the same request hash returns the same rejection. The system never reports `ACCEPTED_PENDING` unless the entire immutable payload has actually committed to ORS.

A schema-invalid request with `NOT_ATTEMPTED` does not consume the stable `write_intent_id`. The corrected request receives a new operation ID, canonical request hash and normally a new idempotency key, while `corrected_from_operation_id` preserves lineage. Reusing one idempotency key with different canonical bytes is always `IDENTITY_CONFLICT`. Every release runs the published minimal accepted examples against the current generated schema.

## I6.9. Recoverable implementation deviation

`ImplementationDeviation` is the concrete record implementing Architecture's `Recoverable Deviation`; it is not a separate exception doctrine.

```yaml
ImplementationDeviation:
  deviation_id:
  from_contract_or_default:
  scope:
  owner:
  reason_and_evidence:
  hard_boundaries_checked:
  expected_benefit:
  risk:
  rollback:
  review_condition:
  outcome_ref:
  disposition: active | promoted | rejected | expired
```

Deviations are not permanent exceptions.

---

## I6.10. Authority records

### Capability token

Binds principal to allowed operations, scopes, visibility, data classes, model/tool routes and expiry. It never grants more than its issuing policy.

Kernel performs only a generic authority/fence decision:

```yaml
AuthorityDecision:
  verdict: allow | deny
  reason_codes:
  effective_scope_and_effect_ceiling:
  authority_epoch_and_state_fence:
  granted_or_required_authority_ref:
  next_allowed_action:
```

Semantic action admissibility remains a Governor gate; `AuthorityDecision` cannot promote truth or choose a task plan.

### Kernel authority projection

Before a CapabilityToken, lease, approval or operation-specific permit becomes effective, `eliotd` compiles its mechanically enforceable subset into an immutable `KernelAuthoritySnapshot` and Kernel commits it to ORS:

```text
principal/session/token identity;
allowed named operations and transition classes;
exact scope/effect/data-class ceilings;
State Fence, policy/config/lease revisions and Authority Epoch;
expiry/heartbeat/revocation conditions;
required approval/proof handles;
source canonical receipt and snapshot hash.
```

Kernel validates requests only against this projection and current revocation/epoch state. It may expire, fence, revoke or further narrow authority and record a reconciliation intent, but it cannot create a token, widen scope/effect, reinterpret policy or choose a task action. During `eliotd` outage no new semantic authority is issued; only exact operations already present in a valid snapshot/continuation permit may complete. Kernel restart reconstructs the projection from ORS plus canonical receipts; mismatch or missing lineage closes effect admission until reconciliation. Restore imports snapshots only as historical/suspended evidence and issues new authority explicitly.

Authority activation is an explicit asymmetric saga; no cross-store atomicity is claimed:

```text
grant/widen:
  canonical decision records proposed authority as PENDING_KERNEL_ACTIVATION
  → Kernel validates and commits KernelAuthoritySnapshot in ORS
  → AuthorityActivationReceipt makes the exact grant effective
  → canonical projection records ACTIVE;

revoke/narrow/expire:
  Kernel commits AuthorityRevocation in ORS first and stops matching effects
  → canonical revocation transition reconciles afterward
  → failure to write canonical state leaves a visible stricter revocation intent,
    never an active right without enforcement.
```

A canonical token/approval row without matching activation receipt is not authority. Crash after canonical proposal but before ORS activation leaves it inactive. Crash after ORS revocation but before canonical reconciliation leaves it revoked and opens a scoped recovery item. Exact retries use the same grant/revocation identity. Activation happens when a delegated token/lease/approval boundary changes, not on every request: many Primitive/Standard operations may reuse one current snapshot until its fence, expiry or revocation changes.

### Epoch identity

Every authority-bearing generation uses a typed epoch, not a bare counter:

```yaml
EpochId:
  lineage_id: uuid
  sequence: u64
```

`lineage_id` changes after restore, break-glass reconstitution or loss of the previous trusted epoch source; `sequence` increases within one active lineage. Validity requires an exact match to the currently active lineage and an allowed sequence/operation permit. Epochs from different lineages are never ordered by timestamp or UUID and never become valid because their numeric sequence is larger. HostInstallationEpoch lives in HostStateJournal; Kernel/module/lease epochs live in ORS/canonical receipts as appropriate. Restore and rollback create a new lineage or a newer sequence and never reactivate an old tuple.

### Leases

```text
TaskControllerLease — authority to transition one task's current plan revision;
WorkLease      — ownership of a work item;
SwarmCoordinatorLease — authority to advance one `SwarmExecutionState`, coordinate its current wave and aggregate results under an exact active `SwarmPlanAdmission` and `SwarmPlanDefinition` revision; it cannot revise definition intent or admission ceilings;
WorktreeLease  — exclusive authority over an isolated mutable tree;
ActionLease    — short-lived authority for exact Material/Critical effects;
MigrationLease — installation-wide schema/data transition;
RecoveryLease  — exact bounded repair/cutover action.
```

Each lease carries:

```text
holder;
scope/effect set;
State Fence;
Authority Epoch;
issued/expires/heartbeat;
verifier/receipt obligations;
revocation and reassignment rule.
```

Stale epoch or expired lease can still provide historical evidence, but cannot authorize a new effect.

### Approval

```yaml
ApprovalRequest:
  exact_action_hash:
  impact_and_scope:
  requested_by:
  evidence_and_unknowns:
  expiry:
  allowed_once:

ApprovalRecord:
  request_ref:
  approver_principal:
  verdict:
  conditions:
  decided_at:
```

Approval authorizes the exact action only. It does not prove a fact, verifier competence or successful outcome.

## I6.11. Gate and decision mapping

Different control questions keep different result types. A universal `verdict` enum is forbidden because it would erase distinctions between admission, action authority, memory influence, finish and lifecycle.

Shared metadata:

`DecisionEnvelope<T>` is an ephemeral request/response projection. Durable facts remain in the corresponding `PolicyDecision`, `WriteReceipt`, `FinishDecision`, lease, approval, Problem/Conflict/Attention or lifecycle receipt; a transport response is never a second decision ledger.

```yaml
DecisionEnvelope:
  decision_id:
  decision_kind:
  result:                # typed by decision_kind
  reason_codes:
  evidence_and_blocking_refs:
  state_fence:
  authority_or_lease_ref:
  next_allowed_action:
  recovery_or_conflict_directive_ref:
```

Closed typed results:

```text
WriteAdmissionDecision
  admitted | admitted_candidate | not_accepted | conflict;

MemoryAdmissionDecision
  include_exact | include_handle | include_with_warning |
  require_revalidation | suppress | quarantine;

NegativeMemoryDecision
  no_match | warn_similar | require_discriminative_probe |
  block_exact_repeat | reopened_with_evidence;

ActionDecision
  allowed | allowed_read_only | require_probe |
  require_refresh | require_approval | denied;

FinishDecision
  VERIFIED_COMPLETE | PARTIAL | BLOCKED | FAILED_VERIFICATION |
  DEGRADED_NO_PROOF | UNSAFE_TO_FINISH | CANCELLED | SUPERSEDED;

LifecycleDecision
  applied | accepted_for_canary | deferred | rejected.
```

Only `block_exact_repeat` may produce `ActionDecision.denied` from failure memory without another policy/decision, and only under a registered deterministic trigger in matching scope. Similarity alone warns or requires probe.

A model may propose inputs or explanation. Decision owner and transition path remain deterministic/policy/Human as declared. Ownership is split without creating two semantic gates:

```text
eliotd/Governor
  owns semantic admission, memory influence, action applicability,
  finish and lifecycle meaning;

Kernel
  rechecks principal, capability token, impact/effect ceiling,
  State Fence, Authority Epoch, operation identity and generation;

store bridge
  enforces named-operation/transition-class ceilings and atomic persistence only.
```

Legacy gate names are compatibility projections documented in the donor migration audit, not canonical result types.

## I6.12. Understanding frame without ceremony

Before a Material/Critical action, the system needs a public action model, not a ritual essay. The server pre-fills:

```yaml
ActionFrame:
  goal_and_acceptance:
  current_epistemic_position:
  exact_load_bearing_atoms:
  causal_or_operational_model:
  rivals_and_material_unknowns:
  discriminative_probe_or_reason_none:
  causal_evidence_status: grounded | partial | absent | not_applicable
  invariants_and_negative_memory:
  write_or_effect_set:
  prediction_fixed_before_observation:
  expected_observable:
  verifier:
  rollback_or_compensation:
  next_allowed_action:
```

Agent edits only fields it actually knows better. Missing semantic depth leads to a reversible probe, narrower effect admission or an explicit degraded proof ceiling, not a 16-field archaeology exercise. A filled template is not evidence of understanding. Missing causal evidence does not erase unrelated pre-existing authority, but it cannot be used as the epistemic basis for a wider Material/Critical effect.

## I6.13. Zero-archaeology error contract

Every validation response aggregates all known defects and includes:

```text
stable ErrorCode;
all invalid/missing fields;
record/contract references;
current revision/fence where relevant;
minimal valid example;
safe fallback;
next allowed action;
retry/poll semantics;
operation handle if staged.
```

Raw deserialization errors and one-field-at-a-time loops do not cross the agent boundary.

## I6.14. Conflict versus failure

```text
revision/semantic disagreement → Conflict Set and Conflict Directive;
missing capability/data → Unknown or Recovery Directive;
invalid request → typed rejection;
internal defect → Problem State/Incident;
policy denial → explicit denial with owner/appeal route.
```

A small conflict does not crash a service or globally block unrelated work.

---


## I6.15. Capability Grant Lineage, introductions and resource facets

Governor owns canonical grant semantics, parent lineage, policy reconciliation and introduction compilation. Kernel owns activation/revocation enforcement, Authority Epoch fencing and compact snapshots/handles. Adapters and workers can request or present capability evidence but never create a grant or introduction themselves.

Installed capability, authority and presented tool/resource surface are three different states:

```text
Capability Registry
  what exists and is currently healthy/probed;

Capability Grant Lineage
  what a holder is permitted to use/do;

Capability Introduction
  which exact resource facet is presented to one Session/Attempt/component now.
```

Availability never creates authority. Authority does not create an ambient catalog.

### Capability grant lineage

`CapabilityToken` remains a compact transport/projection form. Canonical delegation is represented by an acyclic `CapabilityGrant` lineage:

```yaml
CapabilityGrant:
  grant_id:
  parent_grant_id:             # absent only for an explicit authority root
  authority_root_ref:
  issuer_principal:
  holder_principal_session_attempt_or_component:
  allowed_operations:
  resource_and_effect_set:
  data_and_observation_classes:
  route_and_credential_constraints:
  subtree_depth_fanout_budget:
  state_fence:
  authority_epoch:
  issued_at_expires_at:
  max_uses:
  status: pending_activation | active | narrowed | revoked | expired | stale
  canonical_decision_ref:
  kernel_activation_or_revocation_ref:
```

Rules:

```text
parent relation is acyclic;
each child is an intersection of parent authority, requested scope and current policy;
multiple independent authority paths are separate grants, never a mutable multi-parent row;
each effect cites the exact supporting grant path(s);
restore never reactivates a path or epoch.
```

For the first single-user/single-agent slice with no delegation, the lineage may be represented by one authority-root grant and one derived snapshot; no general graph engine or transitive-revocation service is required. Full parent/descendant traversal becomes active only when a real child delegation, alternate authority path or cross-principal resource introduction exists. The simple representation must migrate losslessly into the same contract later.


`EffectiveCapabilitySnapshot` is a derived view:

```text
path effective = root ∩ grant_1 ... ∩ current policy ∩ State Fence;
holder effective = union of valid independent path-effective sets.
```

Revocation is lazy and reverse-reachable:

```text
revoke/narrow exact edge in Kernel/ORS first;
increment grant-graph revision and affected epochs;
recompute only dependent descendants;
preserve a descendant only if another valid root path covers the exact use;
invalidate snapshots and introductions;
interrupt/fence live agent proxies, WASM handles and effect routes;
reconcile canonical state and retain history.
```

`GrantRevocationPreview` shows affected holders, lost operations/resources, surviving alternate paths and in-flight effects. It is advisory; commit revalidates graph revision.

### Capability introduction

```yaml
CapabilityIntroduction:
  introduction_id:
  holder_session_attempt_or_component:
  supporting_grant_refs:
  resource_handle:
  facet_manifest_ref:
  introduced_operation_set:
  observation_domain_refs:
  credential_binding_ref:
  state_fence_and_authority_epoch:
  registry_and_grant_graph_revisions:
  issued_at_expires_at:
  max_calls_or_budget:
  status: active | suspended | revoked | stale | consumed
  receipt_ref:
```

The Attempt compiler derives the minimal introduction set from:

```text
WorkItem + RoleProfile + current grants + privacy/cost policy
+ Capability Registry evidence + State Fence.
```

The introduction set is compiled once per Attempt/root revision and reused until its grant, registry, policy, credential or State Fence dependency changes; it is not a per-call ceremony.

Unintroduced resources are absent even when an adapter is globally installed. A missing exact resource facet returns `CAPABILITY_INTRODUCTION_REQUIRED`; a revoked or stale supporting grant returns `CAPABILITY_GRANT_REVOKED`. Neither condition is translated into a generic tool failure or silently widened introduction.

### Facet manifest

A facet is a stable, narrow, typed interface over a semantic resource:

```yaml
FacetManifest:
  facet_id_and_semver:
  semantic_resource_kind:
  interface_schema_or_WIT_digest:
  implementation_compatibility_range:
  methods:
    - method_id:
      input_output_schema_digest:
      authority_class:
      effect_class:
      observation_class:
      disclosure_propagation:
      idempotency_class:
      simulation_class:
      compensation_class:
      replay_class:
      timeout_and_resource_profile:
  collision_and_reserved_name_policy:
  removal_and_migration_boundary:
```

Every method admitted to an agent/component/public capability surface requires an exhaustive method profile generated from the owning contract. A new unclassified method cannot be exported on that surface. Internal methods and quarantined legacy compatibility routes are not forced into a mass classification campaign merely because they exist; they remain unavailable until a real consumer/migration slice admits them. Contract tooling compares the admitted Rust traits, WIT worlds, EBP registry, MCP schemas and generated role surfaces.

Agent, WASM and native contours use the same semantic facet:

```text
agent route
  → short task-shaped method projection + exact handles;

WASM component
  → stable WIT resource interface + runtime-introduced handles;

native worker
  → EBP proxy/stub generated from the same facet contract.
```

Stable facet families are reused; ELIOT does not generate a unique WIT world per task when dynamic resource handles suffice.

### Principal-bound credential use

```yaml
CredentialUseBinding:
  binding_id:
  resource_and_facet:
  acting_principal:
  credential_owner_principal:
  mode: self_owned | service_owned | explicit_delegation | human_escrow
  allowed_operations_and_data_classes:
  billing_and_retention_route:
  state_fence_and_expiry:
  revocation_ref:
```

A child does not inherit controller credentials by role. Explicit delegation creates a grant and introduction receipt; the actual acting account appears in effect/usage receipts.

An agent may request a missing introduction, but the request is only a candidate:

```text
requested resource/property;
requested facet/operations;
why the current set is insufficient;
expected decision/proof delta;
privacy, cost and effect implications.
```

The result is introduced, denied, needs Human/resource selection, safer-facet required, route unavailable or probe through an existing capability.

No new authority owner is created by these contracts. Governor decides semantic admission; Kernel enforces current grant/introduction/epoch snapshots; adapter/component only implements the facet.



### Native resource leases and executable dependency closure

A service/worker does not receive ambient file-system authority merely because a Human selected a path. `NativeResourceLease` is required when a resource crosses a user/service, trusted/untrusted-module or external-worker boundary, and for Material/Critical use whose identity may change between selection and execution. Ordinary reads and edits inside an already authenticated WorkScope/worktree root use the bounded WorkLease/Facet capability and do **not** create one lease per file. User Broker or another authorized issuer creates a one-shot operation-bound lease only for the exact boundary-crossing operation:

```yaml
NativeResourceLease:
  lease_id_and_nonce:
  issuer_broker_epoch_and_consumer_generation:
  principal_attempt_and_operation:
  opaque_resource_ref:
  canonical_resource_identity:
  resource_kind_and_reparse_network_device_policy:
  size_mtime_or_directory_generation:
  issued_at_expires_at:
  state_fence:
  signature_or_protected_issuer_identity:
  consumed_at_and_receipt:
```

Immediately before use, the consumer re-resolves and remeasures the resource identity. Replay, operation mismatch, stale broker epoch, symlink/reparse substitution, changed file identity or expired lease fails closed for the dependent operation. Signing secrets never enter the child environment. Agents see an opaque `ResourceRef`, not a broad reusable path grant.

Consent/approval applies to the full executable dependency closure, not a package label. The closure is computed and cached per immutable artifact/build generation; it is revalidated on dependency/config/toolchain change, not rebuilt ceremonially for every attempt:

```yaml
ExecutableDependencyClosure:
  root_artifact:
  executable_code_dependencies:
  data_with_execution_semantics:
  build_macro_template_deserialization_and_plugin_surfaces:
  combined_fingerprint:
  scanner_policy_and_containment_revision:
  approved_by_scope_and_expiry:
  hard_block_and_approvable_findings:
  invalidation_set:
```

Execution classes remain distinct:

```text
native code;
deserialization/pickle-like execution;
build script and procedural macro;
template/macro execution;
plugin/model loading;
model/tool-generated command execution.
```

A static scanner is hardening and triage, not a sandbox or semantic oracle. The applicable containment, negative challenge, runtime identity and verifier remain mandatory. Approval of one artifact does not transitively approve its changed tokenizer, base model, adapter, plugin or build dependency.

## I6.16. Scoped understanding assessment

ELIOT never emits a global `understands=true` or a single understanding score. An assessment is tied to a question/task family and a State Fence:

```yaml
ScopedUnderstandingAssessment:
  subject_route_or_coupled_system:
  question_and_task_family:
  product_and_state_fence:
  current_model_and_rivals:
  material_unknowns:
  pre_probe_predictions:
  selected_discriminator_or_action:
  observed_outcome_and_verifier:
  model_revision_after_outcome:
  counterfactual_or_held_out_evidence:
  transfer_boundary_and_requalification:
  onboarding_slice_and_missing_inputs:
  status: NOT_ONBOARDED | UNTESTED | LOCALLY_ADEQUATE |
          REFUTED | INCONCLUSIVE | STALE
```

Graphs, prose quality, self-report, delivery receipts or agreement among correlated agents cannot set `LOCALLY_ADEQUATE`. The minimum evidence is a public rival-aware model, a prediction fixed before observation, a discriminative probe/action, applicable outcome evidence and revision when prediction fails. Product-level claims additionally require held-out or otherwise leakage-controlled evaluation.

`NOT_ONBOARDED` means that no current Product/State-Fence-bound situation model or sufficient onboarding slice exists; `LOCALLY_ADEQUATE` is forbidden until the missing inputs are resolved. Fixed graph size, edge-count or context thresholds cannot establish understanding. Where applicable, the assessment includes an unanswerable/stale case, counterfactual/intervention or state-update case, held-out/compositional transfer and abstention precision/coverage.

# I7. Agent interaction and reactivity

## I7.1. Eliot Bridge Protocol (`EBP/1`)

EBP is a stable language-neutral message contract. Transport and encoding are negotiated profiles; neither is allowed to leak into domain records.

First delivery profile:

```text
transport: length-delimited frames over Windows named pipes;
encoding: UTF-8 JSON generated from Serde types;
debugging: the wire payload is directly inspectable and replayable;
large data: immutable Blob/Resource handles, never giant inline frames.
```

This JSON-first choice is deliberate: D0/D1 need a working bridge, simple diagnostics and one schema system more than speculative serialization speed. `protobuf-v1` through `prost` remains an optional encoding profile behind RGF-PROTOCOL-TRANSPORT. It is promoted only if measured local load shows a material latency/CPU/size benefit without creating a second divergent contract. Both encodings MUST pass the same semantic fixtures and compatibility tests.

Named pipes and JSON are current Windows-first Defaults, not security or performance proofs. Transport admission requires the production profile to disclose framing, ACL/authentication, reconnect, contention, crash, message-size and backpressure behavior on the exact Product Identity. A local microbenchmark cannot establish universal superiority, and changing transport/encoding cannot change the semantic contract or proof ceiling.

Reasons for EBP itself:

```text
stable contract across Rust/compiler versions;
independent hot module builds;
streaming, cancellation and server events;
future non-Rust modules without Rust ABI/C-layout coupling;
explicit compatibility, authority and failure semantics.
```

## I7.2. Frame

Conceptual frame, represented by the selected encoding profile:

```yaml
Frame:
  protocol_version:
  encoding_profile:
  connection_id:
  request_id:
  kind: request | response | event | cancel | heartbeat | control
  message_type:
  payload:
  trace_context:
```

Framing uses a 4-byte little-endian unsigned body length followed by the encoded body. The parser reads the prefix into a fixed buffer, rejects zero/oversize values before allocation, then reads exactly that many bytes. `json-v1` body is UTF-8 JSON; other encoding profiles reuse the same frame boundary.

Hard limits:

```text
frame default max: 4 MiB;
hot response default max: 64 KiB;
hard MCP structured response: 256 KiB;
large payload: Blob/Resource handle;
per-connection in-flight requests bounded;
heartbeats, cancellation and recovery frames use reserved control capacity.
```

Unknown fields are tolerated only according to the negotiated protocol minor-version rule. Unknown message types are rejected explicitly; they are never interpreted as generic commands.

### Durable/control event envelope

Request/response correlation is insufficient for reconnect, hot replacement and native host streams. Every durable/control event uses:

```yaml
EventEnvelope:
  stream_id:
  producer_id:
  producer_generation:
  authority_epoch:
  event_id:
  sequence:
  causal_predecessor_refs:
  delivery_class: durable_control | durable_observation | best_effort_telemetry
  ack_required:
  payload_type:
  payload_or_blob_ref:
  state_fence:
  trace_context:
```

`durable_control` and `durable_observation` are delivered at least once. The receiver persists event ID, sequence and disposition; the producer replays unacknowledged events after reconnect. Duplicates are idempotent. Best-effort telemetry is a separate class and may be sampled or dropped only with an explicit telemetry-gap signal.

A generation switch cannot discard an unacknowledged durable stream. Host/native cursors advance only after the admissible raw/hash record, normalized projection and event disposition are durably related.

`EventAckReceipt` uses explicit phases:

```text
RECEIVED
→ DURABLE
→ NORMALIZED
→ APPLIED | REJECTED | UNKNOWN.
```

The producer and consumer declare which phase advances each cursor. A transport acknowledgement cannot impersonate durable or canonical application. Unknown/parse-failed events retain the event identity, raw/redacted source handle and retry/reconciliation route; replay never creates a second logical event.

## I7.3. Handshake

```text
ClientHello:
  protocol range;
  module/bridge identity;
  artifact hash;
  launch nonce;
  capabilities;
  State/Authority Epoch;
  privacy classes;
  max frame.

ServerHello:
  selected protocol;
  session/principal binding;
  allowed capabilities/effects;
  config snapshot;
  heartbeat;
  control channel;
  rejection reason if incompatible.
```

Module self-assertion is checked against the Module Catalog, Generation Registry and Capability Registry evidence. Old generation cannot reconnect after epoch fencing.

## I7.4. Module lifecycle messages

```text
Start
Ready
Health
Execute
Result
Event
Cancel
Quiesce
Checkpoint
RestoreCheckpoint
DrainStatus
Shutdown
Fatal
```

Every request has idempotency identity, deadline and cancellation semantics. Every durable lifecycle `Event` follows the EventEnvelope replay/ack contract of I7.2.

## I7.5. Named pipes

```text
\\.\pipe\eliot\kernel\frontdoor
\\.\pipe\eliot\kernel\store
\\.\pipe\eliot\kernel\daemon\<generation>
\\.\pipe\eliot\module\<module_id>\<generation>
\\.\pipe\eliot\watchdog\signals
```

ACL allows only expected service/user SID. Each launched child also presents random nonce delivered via protected inherited handle/file, not command line.

### Agent-facing transport profiles

```text
stdio shim
  DEFAULT: agent starts a near-stateless bridge which connects to Kernel front door;

loopback Streamable HTTP
  OPTIONAL: for local hosts that cannot manage stdio reliably; disabled by default;

remote transport
  FORBIDDEN for normal MCP/control access in the first line.
```

The loopback HTTP profile binds only `127.0.0.1`/`::1`, requires a scoped short-lived bearer credential issued through local setup, enforces the same Session/authority contracts, and exposes no admin or database surface. It validates `Host` and, for browser-originated requests, `Origin` against the exact loopback profile; non-loopback, ambiguous and DNS-rebinding forms are rejected. Binding `0.0.0.0`, trusting loopback without host validation, or reusing the local credential remotely is forbidden. Losing the HTTP bridge does not affect Kernel or canonical state. Future online access is limited to the separate bounded Dreamer gateway of I9.13/I15.13.

## I7.6. MCP surface

Current concrete logical tools:

```text
eliot.state       — current task/scope/attention/health preview;
eliot.packet      — compile or refresh Active Understanding View;
eliot.observe     — capture observation/decision/failure/outcome naturally;
eliot.query       — exact/pull/Dreamer orientation query;
eliot.act         — request/inspect action authority and contract;
eliot.verify      — run/register verification result;
eliot.coordinate  — work items, agents, Concilium, swarm;
eliot.finish      — submit typed finish attempt.
```

`eliot.query` carries an explicit `QueryIntent` for broad/current/history/provenance/navigation/verification/change-impact/context-reconstruction requests. An immutable exact resource URI may determine its own intent. A broad query with no resolvable intent is rejected with `INVALID_ARGUMENT`; the server does not silently treat historical reconstruction as the current supported position or navigation as evidence.

`eliot.observe` is the single capture surface and has typed suboperations:

```text
observation    — what was observed, with source/effect metadata;
decision       — chosen path, alternatives and revisit condition;
failure        — failed path, signature, evidence and next discriminator;
outcome        — actual artifact/effect/verifier result;
influence_ack  — how a delivered memory item affected the next public decision/action/verifier.
```

`MemoryInfluenceAcknowledgement` is not a claim about hidden reasoning. It names the memory handle, influence class and a downstream public reference. `changed_action`, `changed_verifier` and `prevented_failure` are rejected without an applicable action/verification/outcome reference. Missing acknowledgement means `unknown`, not `unused`. Delivery, acknowledgement, use and causal benefit remain different states.

A legacy bridge may expose `eliot.memory_use` as an alias for `eliot.observe { kind: influence_ack }`; it is not a ninth canonical hot operation and cannot carry different semantics.

Large packets and evidence use MCP resources. Long operations use MCP Tasks when supported; otherwise return ELIOT Durable Job handle.

`eliot.coordinate` is the single semantic execution-fabric surface. Its operation discriminator covers:

```text
delegate   — create a bounded work item/attempt;
audit      — request independent review over a sealed artifact packet;
compare    — compare isolated candidates through deterministic criteria and Concilium;
wait       — await durable run/job changes;
inspect    — read run lineage, evidence, route and capacity state;
cancel     — cancel/reconcile a run or subtree;
send       — durable mailbox/attention response.
```

These are not additional hot MCP tools and do not expose vendor flags or binary paths. Bridges may present convenience aliases, but canonical semantics remain `eliot.coordinate`.

Worker profiles may expose only subset. Tool descriptions remain short; deep contracts are resources/schema.

Tool input/output schemas are generated from the same `serde`/`schemars` contract types used by EBP clients. Hand-written MCP schemas, separate field names or host-specific semantic forks are forbidden. Compatibility adapters translate at the bridge boundary and are tested against canonical semantic fixtures.

## I7.7. MCP versions and stateless core

Primary MCP version: final 2026-07-28 through the official `rmcp` 3.1.x compatibility line; 3.1.2 is the current source-verified candidate and remains unadmitted until local bridge/conformance proof. The core protocol is stateless: ELIOT never derives durable Session, authority or continuity from an MCP connection or initialize handshake. Any selected patch is pinned only after ELIOT dual-version conformance, because SDK wire regressions must not leak into domain/session semantics.

Each request maps through a Kernel-owned `ActiveSessionBinding` in ORS, created from a scoped local credential plus canonical request metadata/tool input. The durable ELIOT Session and immutable attach/detach receipts remain canonical; the active transport binding is operational and never revives from backup. A long-lived stdio process is only a transport optimization. MCP Tasks are optional; when absent, ELIOT returns the same Durable Job handle/resource and polling/subscription contract.

The 2025-11-25 compatibility adapter may use transport/session hints for correlation, but maps them to the same ELIOT Session and cannot create authority or task identity. Version-specific behavior remains isolated in `eliot-mcp`.

MCP 2026-07-28 has a stateless protocol core. `AgentSession` in ELIOT is application state bound by explicit authenticated attach metadata; it is not inferred from a transport connection or an MCP initialize session. Reconnect, stdio restart and HTTP requests therefore reuse an explicit ELIOT session/task binding. MCP Tasks are used only when the client advertises the extension; otherwise ELIOT exposes its own Durable Job handle.

## I7.8. Agent interaction loop

```text
1. resolve an authenticated application SessionBinding;
2. run/revalidate ScopeBindingGuard and cold-start readiness;
3. resolve or explicitly request TaskIntake/active TaskContract;
4. return boot delta, OnboardingReadiness, IntegrationCoverageProfile and derived GovernanceProfile;
5. frame or resume task;
6. compile Active Understanding View;
7. before Material action, ensure current authority/action model;
8. observe tool/action result through hook/bridge or explicit observe;
9. update state, attention and pending context;
10. verify expected observable;
11. record outcome/lesson candidate and route/system feedback;
12. finish with one typed outcome;
13. checkpoint and detach.
```

## I7.9. Strict finish input and outcomes

The public finish surface accepts only a candidate request:

```yaml
FinishAttemptDraft:
  task_id:
  expected_task_revision:
  requested_outcome:
  artifact_refs:
  observation_refs:
  verifier_run_refs:
  remaining_unknowns_declared_by_caller:
  rationale_candidate:
```

The caller does not submit `CompletionProof`. The Finish service rehydrates the current TaskContract, acceptance items, exact artifacts, current State Fence, executed verifier runs and effect outcomes, then derives:

```yaml
DerivedCompletionProof:
  task_and_revision:
  per_acceptance_coverage:
  artifact_and_verifier_bindings:
  checks_not_executed_or_stale:
  unresolved_effects_and_unknowns:
  proof_ceiling:
  derivation_digest:
```

A legacy caller-supplied proof is rejected with `LEGACY_FINISH_INPUT_REJECTED`; absence of strict fields never selects a weaker path. A verifier with execution status `NOT_EXECUTED` or `SIMULATED`, stale scope, missing artifact binding or unknown outcome cannot support `VERIFIED_COMPLETE`.

The closed `FinishDecisionOutcome` set remains:

```text
VERIFIED_COMPLETE;
PARTIAL;
BLOCKED;
FAILED_VERIFICATION;
DEGRADED_NO_PROOF;
UNSAFE_TO_FINISH;
CANCELLED;
SUPERSEDED.
```

Only `VERIFIED_COMPLETE` means done. Every other outcome lists completed artifacts/effects, uncovered acceptance items, material unknowns and continuation/rollback. A job result never sets this enum directly.

A `Stop`, disconnect, non-response, truncated output or parse failure is never a FinishDecision. A durable `StopBoundaryRecord` closes new admissions at one revision and records:

```text
stop/interrupt identity and time;
task/attempt/state fence and event cursor;
in-flight operations and child attempts;
external-effect dispositions;
last durable/normalized/applied event;
required checkpoint, reconciliation or finish action.
```

The mandatory `StopHookForgeryTest` proves that caller text or a forged hook event cannot mint this record, a DerivedCompletionProof or a terminal task outcome.

## I7.10. Reactive delivery

### Event-integrated host

```text
SessionStart      → identity, scope, task, critical attention, brief architecture context;
PromptSubmit      → classify continuation/correction/interruption/new task; update constraints and invalidate dependent packet;
PreToolUse        → prepared context delta + authority decision;
PostToolUse       → observation, changed resources, diagnostic cues;
PreCompact        → public handoff/checkpoint;
PostCompact       → revalidate and emit resume delta;
Stop              → finish/checkpoint requirement.
```

Hot path contains no model call. Semantic work is prepared asynchronously.

Reactive delivery reuses the single `EventEnvelope` / `EventAckReceipt` owner from I7.2; it does not create a second hook database. One Host Event service owns each append-only source cursor and the durable spool drain. Every captured hook/host event binds event and idempotency identity, principal/session, WorkScope/task/plan revision, raw-or-deterministically-redacted source handle, State Fence and source sequence.

```text
RECEIVED → DURABLE → NORMALIZED → APPLIED | REJECTED | UNKNOWN
```

Cursor advancement occurs only at the declared durable/application phase. Crash, duplicate, predecessor gap, reorder, payload mutation, timeout and cross-scope replay are fault-tested. A restart replays the same logical event identity; it never creates a second semantic observation or silently skips an unresolved predecessor. An advisory hook may disappear without becoming a hidden product dependency; its lost coverage remains explicit in `IntegrationCoverageProfile`.

An interruption that changes the active goal or invalidates the current plan creates a durable `InterruptBarrier` task event/projection. It marks old branches `paused`, `killed` or `completed`, records forbidden resumptions, revokes incompatible leases and requires a fresh packet before Material continuation. A later resume must reference the barrier and current State Fence; conversational momentum cannot silently reactivate the old plan.

### Tool-only host

```text
boot/pending context piggybacks on ELIOT responses;
unsupported enforcement is marked advisory;
material actions not seen by ELIOT remain ungoverned;
finish cannot be VERIFIED_COMPLETE when required trace is absent;
Watchdog observes interaction gaps where possible.
```

System never claims it blocked an external action it could not intercept.

## I7.11. Context payload profiles and Decision Safety Floor

The existing byte/token figures are unvalidated planning candidates until a route-specific profile is qualified under I2.16. They guide rendering, not correctness.

Every packet atom has a loss policy:

```yaml
ContextAtomPolicy:
  atom_id:
  class: AUTHORITY | GOAL | SCOPE | ACCEPTANCE | SOURCE | VERIFIER |
         MATERIAL_UNKNOWN | NEGATIVE | SECURITY | OPTIONAL
  loss_policy: NON_DROPPABLE | HANDLE_ONLY | EXTRACTIVE | SUMMARIZABLE
  dependency_and_invalidation_refs:
  applicable_effect_classes:
```

`DecisionSafetyFloor` for a Material/Critical boundary contains all currently applicable non-droppable atoms:

```text
goal/acceptance and current scope;
authority, policy and State Fence;
load-bearing source/provenance and current epistemic status;
material unknowns, conflicts and negative memory;
exact expected effect and applicable verifier;
active recovery/conflict/security directives.
```

The compiler may compact optional narrative, move expandable evidence to handles and decompose work, but it may not silently remove the floor. If the floor cannot be delivered and expanded before the decision, compilation returns `DECISION_CONTEXT_INCOMPLETE`; the allowed response is decomposition, a safer partial action, a different qualified route or Human decision—not continuation with a fluent incomplete packet.

Every Material/Critical action or resumed branch carries the canonical `DecisionExecutionLineageRefs` defined in I12.31. Context compilation validates that its goal/task, evidence, epistemic position, rationale, authority/effect, artifact/verifier/outcome and omission/handoff links are complete for the decision class.

The chain proves traceability and continuity, not causal benefit. Missing, stale, revoked or superseded load-bearing links return `DECISION_CONTEXT_INCOMPLETE` or a narrower safe action. A fluent summary cannot substitute for the chain, and success after delivery does not create causal credit without intervention/counterfactual evidence.

Every compaction emits a field-level loss/omission manifest and reversible handles to retained source. Approximate token estimates never prove preservation.

## I7.12. Short Skills

### Core Skill

```text
Solve the task; use the current ELIOT task view as state.
Refresh before a Material effect when the view is stale or the goal, scope or load-bearing state changed.
Record material observations, decisions, failures and outcomes unless ELIOT already acknowledged them; follow its retry identity.
Report missing, stale, wrong-scope, irrelevant or excessive context through the supplied feedback handle; do not manufacture positive feedback.
Separate observation from inference.
Follow typed directives; challenge a false block with evidence or escalate.
In degraded mode do only work the directive explicitly permits.
Use `eliot.finish`; only `VERIFIED_COMPLETE` means done.
```

### Memory Skill

```text
Record meaning the bridge cannot infer while context is fresh.
State what happened, why it matters and when it may matter again.
Unknown type never blocks safe capture.
```

### Conflict Skill

```text
Do not vote or overwrite.
Preserve rival claims and shared lineage.
Run the cheapest safe test that distinguishes them.
Name the decision owner and residual uncertainty.
```

### Failure Skill

```text
Do not repeat an exact failed path without new evidence.
Change the hypothesis, route or precondition.
Record the new outcome and reopen condition.
```

### Development Skill

```text
Optimize the Product Objective, not reports, test counts or forms.
Work in one primary micro-module and one causal property.
Before code, run or define the discriminator that can refute the hypothesis.
Run the module proof and affected edge proof; do not run the full suite without impact evidence.
Do not repair unrelated paths or change the oracle to fit the patch.
A second repair of the same failure class requires a new hypothesis or Mechanism Review.
Treat tests, receipts and reports as evidence only.
Challenge a harmful guardrail openly; never bypass a Hard Boundary.
Claim only the exact scope actually proven.
```

Host-specific skill adds only host limitations and exact tool names. Skills do not restate Architecture.

Skill context is paid at three separate points and each has its own budget:

```text
index     name and one-line trigger description of every route/profile/policy-eligible Skill;
          paid every session for that eligible catalogue;
body      the Skill instruction itself; paid on activation; kept intent-dense;
runtime   references, scripts and assets; paid only when actually read or executed.
```

The trigger description states **when to load**, not what the Skill can do; it is evaluated by activation precision, activation recall and forbidden activation. A verbose body is not a local cost: several Skills may be active at once, so one oversized Skill degrades unrelated capabilities. Adding a Skill can regress another Skill without modifying it, which is why the catalogue is evaluated as shared behavioral surface rather than as isolated documentation (I7.25).

## I7.13. Skill validation and promotion

All Skills pass cheap structural checks:

```text
one observable trigger;
one line per action;
no ambiguous obligation wording;
all named tools/contracts/capabilities exist;
where-not-apply and stop/escalation present;
host/profile/dependency versions visible;
token/description budget;
no authority claim that belongs to a gate/tool.
```

Promotion depth is proportional:

```text
host/task-specific Skill
  → one matching real route scenario + dependency checks;

shared cross-route Skill or Material/Critical instruction
  → second materially different route/evaluator for a validated portability claim;

Human scoped approval without independent transfer evidence
  → permits bounded use only as provisional/scoped and does not certify cross-route validity;

single-route installation without independent route
  → Skill may remain scoped/provisional; basic work is not blocked globally.
```

A changed host/tool/contract dependency marks the Skill stale. Installed is not delivered: Hotset injection has a Delivery Receipt. Skills guide behavior; gates, leases, sandbox and tools provide enforcement.

## I7.14. Session lifecycle

```text
ATTACHING → ACTIVE ↔ SUSPENDED → DETACHED | EXPIRED | REVOKED
```

Session loss:

```text
revokes session-bound leases;
checkpoints durable tasks/jobs;
does not delete work/evidence;
raises Authority Epoch before reassignment;
retains Route Continuation State only under policy/TTL.
```

MCP connection loss, stdio restart or HTTP reconnect does not end the ELIOT Session automatically. Session state changes only through the application lifecycle, expiry/revocation or explicit detach; transport bindings may be replaced and are recorded as continuity observations.

## I7.15. Route Continuation and transfer

Continuity is the closed `ContinuityKind` enum for the current protocol line:

```text
NativeResume — same compatible runtime/route continues the same native session;
NativeFork   — runtime creates a child/branch with native history semantics;
Replayed     — ELIOT replays durable public messages/events into a new attempt;
Rehydrated   — a new attempt receives compiled state/artifacts without prior dialogue;
Fresh        — no prior conversational state is transferred.
```

Only `NativeResume` preserves native session identity. Every other kind creates a new ELIOT attempt. `NativeFork` remains a child attempt even when the runtime calls it a continuation.

Route Continuation State may contain opaque provider/harness continuation required for exact resume. It is:

```text
separate from canonical cognitive inheritance;
never evidence, authority or rationale;
not indexed or sent to another route automatically;
protected by privacy/retention;
scoped to exact runtime/adapter/route fingerprint;
deleted on expiry, route invalidation or provider-policy request.
```

Cross-runtime transfer defaults to `Rehydrated` and uses a sealed packet:

```text
task/acceptance and current plan;
Current Epistemic Position and Architecture constraints;
base/diff/environment receipts;
artifacts and exact evidence handles;
failed paths and reopen conditions;
open unknowns, permissions, budgets and output schema.
```

A native transcript, reasoning signature, tool-call ID or compaction summary is not portable. `Replayed` re-emits only public messages/events as inert context; it never re-executes prior tool calls or external effects. UI and reports must not label replay/rehydration as “the same session”.

Every non-fresh transfer is bound by one `HandoffCausalLink`:

```yaml
HandoffCausalLink:
  source_attempt_session_and_revision:
  source_state_fence_and_authority_epoch:
  source_event_and_outbox_cursors:
  in_flight_operations_and_effect_dispositions:
  handoff_checkpoint_and_omission_manifest_digest:
  replay_from_cursor_or_rehydration_bundle_digest:
  target_attempt_and_route_fingerprint:
  post_resume_revalidation_receipt:
  completeness: COMPLETE | PARTIAL | STALE | UNKNOWN
```

Resume/replay is not admitted as causally continuous when the source revision, fence/epoch, cursor, omission manifest or effect disposition is missing or stale. The target may start as a new `Rehydrated` attempt with explicit unknowns, but it cannot inherit completion, authority or proof from an incomplete link.

## I7.16. Host integration coverage and Governance Profile

`IntegrationCoverageProfile` records what a concrete host/adapter fingerprint actually exposes and enforces. `GovernanceProfile` is the Governor-derived vector used for authority and user-visible guarantees; it combines integration observation/enforcement with Watchdog supervision and trace freshness. Watchdog supplies supervision evidence but does not own the final profile.

Each integration profile declares each lifecycle/effect event as `ENFORCED | OBSERVED | EXPLICIT_OBSERVE | UNAVAILABLE`, plus completeness, pre/post-dispatch ordering, proof ceiling, source and gap evidence. Hook observation never mints authority. A profile based only on installed config or self-report remains unverified until host-observed events and effects match it.

Logical event set:

```text
SessionStart;
UserPromptSubmit;
SubagentStart;
PreToolUse;
PermissionRequest;
PostToolUse;
PreCompact;
PostCompact;
SubagentStop;
Stop/FinishAttempt.
```

Profile examples:

```text
EventIntegrated — lifecycle and tool outcomes visible; pre-action context/enforcement available;
ToolOnly        — only ELIOT calls visible; delivery is delayed/advisory;
ObserveOnly     — external traces visible, no reliable enforcement;
OfflineWorker   — bounded input/output job with no live host events.
```

The integration profile records actual runtime coverage, not only installed configuration. Missing events update the corresponding observation/enforcement axis; Governor then derives a new revision-bearing GovernanceProfile and revokes authority that depended on the lost guarantee. No component replaces the vector with a single marketing grade.

## I7.17. Convenience surfaces

### Auto-boot

First successful ELIOT response in a Session includes once:

```text
principal/profile identity;
WorkScope and task;
current revisions/freshness;
project/system orientation handles;
critical attention/problems;
actual GovernanceProfile and its limiting IntegrationCoverageProfile evidence.
```

The same state is available as a bounded `GetUnderstandingBootstrap` composition over existing owners. `OnboardingReadinessReceipt` of I4.4.1 is the canonical readiness decision; `UnderstandingBootstrap` is its agent-facing projection plus current cognitive state and cannot report a stronger readiness:

```yaml
UnderstandingBootstrap:
  onboarding_readiness_ref_and_disposition:
  product/workscope identity:
  task_selection: BOUND | UNIQUE | AMBIGUOUS | NONE
  TaskSelectionEvidence:
    scope_level: session | task | project | portfolio
    candidate_task_handles:
    selected_task_and_revision:
    acceptance_digest:
    selection_source_and_reason:
    contamination_flags:
  role/lease and State Fence:
  current assessment: NOT_ONBOARDED | STALE | READY | DEGRADED
  supported/verified/candidate counts:
  bounded relevant handles:
  conflicts/unknowns:
  next safe expansion:
```

Ten open tasks return `AMBIGUOUS`; ELIOT does not silently choose the newest task. A task found only through a previous evaluation candidate is marked `CROSSOVER_CONTAMINATED` until independently rebound.

### Auto-bind

Observation/candidate write derives cues from touched files, symbols, errors, commands, task and active artifacts. Agent supplies only a short reuse note when automatic binding is insufficient.

### Frame stub

`eliot.act` returns a prefilled ActionFrame from current state; the agent supplies intent, expected observable and remaining uncertainty.

### Dry run

Operations with a real validation/simulation capability support `dry_run` with zero side effects and return the normalized envelope plus effect preview. When the external tool cannot safely simulate an effect, ELIOT returns `DRY_RUN_UNSUPPORTED` and the best available static preview; it never pretends that validation occurred.

### Memory confidence

Recall/packet responses return one server-derived `RecallDisposition`:

```text
ADMITTED_STRONG | ADMITTED_WEAK | NO_MATCH | NO_USEFUL_MEMORY |
EMPTY_CORPUS | SCOPE_SUPPRESSED | STALE_PROJECTION |
CONFLICTED | INCOMPLETE_COVERAGE.
```

The receipt binds scope, source/projection revisions, State Fence, visible and suppressed counts, freshness and a short reason. Default agent output contains bounded top handles plus `rank_trace_handle`; full ranking/suppression traces are debug expansions. The agent never invents `NO_USEFUL_MEMORY`.

## I7.18. Read/resources surface

Large or progressive data are addressed by immutable/revisioned resources:

```text
eliot://scope/<id>/state
eliot://task/<id>/packet/<revision>
eliot://evidence/<id>
eliot://conflict/<id>
eliot://problem/<id>
eliot://session/<id>/attention
eliot://session/<id>/mailbox
eliot://job/<id>/result
eliot://report/<id>
eliot://architecture/<revision>/<anchor>
```

Hot responses contain previews/handles. Full evidence, audit and large reports are expanded explicitly.

## I7.19. Reactive context sequence

```text
observed world/tool/task event
→ normalize cues
→ exact firing
→ bounded precomputed relation activation
→ admission by scope/status/risk
→ pending injection
→ host hook or next ELIOT response
→ Delivery/Injection Receipt
→ later influence/use/outcome update.
```

Critical items remain sticky until resolved/waived/superseded. Normal items are session-deduplicated unless invalidated.

## I7.20. Agent-facing error contract

Agent-facing failure control has two layers:

```text
AgentResponseDisposition (small closed control enum):
  INVALID_REQUEST | DENIED | STALE_OR_CONFLICT | NEEDS_EVIDENCE |
  UNAVAILABLE_OR_CAPACITY | RECOVERY_REQUIRED | FAILED;

reason_code (open versioned registry):
  exact machine-readable cause from Appendix D.
```

Appendix D and `docs/generated/reason-codes.md` are the current human/machine-readable documentation projections of the additive reason-code set, not a giant control-state enum that every bridge or agent must understand. I7.20 owns the exact current documentation set; a future generated runtime registry must match it. Until exact runtime source and execution evidence exists, the projected registry remains `ImplementationSupport = TARGET` with `EvidenceExecutionStatus = NOT_EXECUTED`. Bridge-only legacy aliases remain separate. Unknown future reason codes are preserved verbatim and handled through the stable disposition and typed directive; they do not break decoding or silently become success. Aliases are accepted only at migration/compatibility boundaries and are not members of the current reason catalogue. Agent surfaces group reasons without changing their exact identity:

```text
request/identity     — INVALID_ARGUMENT, AUTHENTICATION_REQUIRED, WORKSCOPE_UNAUTHENTICATED,
                       SCAN_PRIVACY_BOUNDARY_REQUIRED, IDENTITY_CONFLICT, TASK_SELECTION_REQUIRED,
                       TASK_SCOPE_INCOMPATIBLE, DISPATCH_PERMIT_REQUIRED, DRY_RUN_UNSUPPORTED,
                       PROCESS_OWNERSHIP_UNPROVEN, RESOURCE_LEASE_REQUIRED,
                       RESOURCE_IDENTITY_CHANGED, RESOURCE_LEASE_REPLAYED;
authority/policy     — AUTHORITY_REQUIRED, POLICY_DENIED, ACTION_LEASE_REQUIRED,
                       WRITESET_VIOLATION, IMPACT_ESCALATION_REQUIRED;
state/conflict       — STALE_STATE_FENCE, STALE_AUTHORITY_EPOCH, STALE_PROJECTION, OBSERVATION_GAP,
                       SCOPE_CONFLICT, CONFLICT_OPEN, CRITICAL_ATTENTION_OPEN, SEQUENCE_GAP_OPEN, TRANSITION_DIGEST_MISMATCH,
                       AMBIGUOUS_RESULT, DESCENDANT_CLOSURE_INCOMPLETE;
cognition/proof      — NEEDS_REASONING_CANDIDATE, CUE_BINDING_REQUIRED,
                       PACKET_REFRESH_REQUIRED, PROBE_REQUIRED, NOT_ONBOARDED,
                       CAPSULE_STALE, VERIFIER_REQUIRED, VERIFIER_STALE, VERIFICATION_NOT_EXECUTED,
                       LEGACY_FINISH_INPUT_REJECTED, DECISION_CONTEXT_INCOMPLETE,
                       CONTEXT_PROFILE_UNVALIDATED, TRACE_INCOMPLETE,
                       REFERENCE_NOT_ALLOWED, UNSUPPORTED_PRECISION;
route/integration    — CAPABILITY_UNVERIFIED, CAPABILITY_DEGRADED,
                       CAPABILITY_UNAVAILABLE, SUPERVISION_UNAVAILABLE, CAPABILITY_GRANT_REVOKED,
                       CAPABILITY_INTRODUCTION_REQUIRED, ROUTE_UNAVAILABLE, ROUTE_MISMATCH,
                       RESEARCH_SOURCE_UNAVAILABLE, EXTERNAL_ATTACH_RECONCILIATION_REQUIRED,
                       ADAPTER_UNAVAILABLE, ADAPTER_INCOMPATIBLE, RUNTIME_FAILED,
                       CANCELLATION_UNCONFIRMED, ENVIRONMENT_UNAVAILABLE,
                       PROTOCOL_INCOMPATIBLE, NO_PROGRESS,
                       TRANSLATION_LOSS_FORBIDDEN, STREAM_SEMANTIC_ORDER_VIOLATION,
                       MODEL_ATTEMPT_UNKNOWN_OUTCOME;
instrument/evidence  — INSTRUMENT_UNAVAILABLE, INSTRUMENT_FAILED,
                       INSTRUMENT_PARSER_INCOMPATIBLE,
                       INSTRUMENT_EVIDENCE_INCOMPLETE,
                       INSTRUMENT_OUTPUT_TRUNCATED,
                       PROCESS_TREE_CLEANUP_FAILED,
                       TESTD_UNAVAILABLE, TESTD_JOB_FAILED,
                       BUILD_SANDBOX_UNPROVEN,
                       COMPONENT_INTERFACE_INCOMPATIBLE,
                       COMPONENT_CAPABILITY_DENIED, COMPONENT_TRAP,
                       COMPONENT_DIVERGENCE, COMPONENT_MIGRATION_REQUIRED,
                       SIMULATION_REPLAY_MISMATCH,
                       GENERATION_PROMOTION_BLOCKED,
                       NEGATIVE_RESULT_UNPROVEN, EVIDENCE_STALE,
                       EVIDENCE_COVERAGE_PARTIAL;
testing              — TEST_INVENTORY_STALE, TEST_POLICY_INCOMPLETE;
capacity/availability— BUSY, STATE_CHURN, DEADLINE_EXCEEDED, STORAGE_BACKPRESSURE,
                       ACCEPTED_PENDING, DB_UNAVAILABLE, DEFERRED_CAPACITY,
                       PROVIDER_QUOTA, BUDGET_EXHAUSTED, MODULE_QUARANTINED;
security/recovery    — PRIVACY_DENIED, DISCLOSURE_CLOSURE_INCOMPLETE,
                       OMITTED_SOURCE_UNAVAILABLE, SOURCE_QUARANTINED, ORIGIN_AUTHENTICATION_FAILED,
                       EXECUTABLE_DEPENDENCY_UNAPPROVED, MIGRATION_MAPPING_INCOMPLETE, UNKNOWN_COMMIT,
                       UNKNOWN_OUTCOME, RECOVERY_REQUIRED, RECOVERY_LOCK_UNAVAILABLE,
                       CUTOVER_BLOCKED_INFLIGHT_EFFECT, INCIDENT_LOCKDOWN.
```

Every non-success response includes `disposition`, exact `reason_code`, the applicable Recovery or Conflict Directive and the same operation identity when one exists. Bridges switch on the stable disposition and MAY specialize known reason codes; they may not require an exhaustive compile-time match over the entire additive reason registry. Legacy names translate only through the bridge-alias mapping projected in `docs/generated/reason-codes.md` and never create host-specific semantic control enums. Silence, raw deserialization output and generic internal-error prose are not normal control behavior.

## I7.21. Default agent role capability profiles

Profiles are defaults compiled into Capability Tokens; WorkScope policy may narrow them. A role name never grants more than the issued token/lease.

| Role | Normal operations | Mutation ceiling | Required authority | Explicitly forbidden |
|---|---|---|---|---|
| **Requester / Domain Owner** | goal, acceptance, value, task-level risk/cost preferences, outcome evidence | revise or supersede the `UserOutcomeObjective`; accept/reject the claimed user outcome | authenticated role or exact delegated goal/acceptance capability | factual proof, Architecture or installation policy by preference alone |
| **Main Agent** | state, packet, query, observe, act, verify, propose coordination/finish | content decisions, candidates, action/finish attempts inside delegated task authority | task role capability; Action Lease for effects | changing user goal, current plan ownership unless separately Task Controller, schema/admin, self-verification outside Evaluation Contract, direct truth/policy promotion |
| **Task Controller** | state, work graph, plan, agents, conflicts, budgets inside the delegated task envelope | current plan revision, assignment/reassignment, bounded task disposition proposals | active TaskController lease/epoch | redefining user outcome, Architecture/policy, factual proof, Module deployment authority, executing effects without Action Lease |
| **Worker** | state, packet, query, observe, coordinate; `act` only for assigned item | evidence, observations, candidate result, lease-covered effect | Work Lease; Worktree/Action Lease when mutating | task finish, active-plan overwrite, policy/schema, unrelated paths |
| **Auditor / Challenger** | state, packet, query, observe, coordinate | audit finding, counterevidence, conflict/challenge candidate | read/audit capability for exact scope | live-tree or external effect, truth promotion, task finish |
| **Verifier Agent** | state, query, verify, observe | scoped evaluation candidate or VerificationRun for registered verifier IDs; verifier artifacts | Verifier capability + Evaluation Contract | redefining acceptance/verifier, implementing the fix it judges unless roles are explicitly separated and independence is downgraded |
| **Synthesis Agent** | query, packet, coordinate, observe | lineage-preserving synthesis candidate | aggregation work item | majority vote as proof, dropping dissent, canonical decision/finish |
| **Curator / Dreamer Agent** | bounded job resources; no general live tool surface by default | curation/research/memory transformation candidates | Dreamer job + budget/privacy policy | direct canonical write, policy/authority/epistemic promotion |
| **External reviewer** | bounded packet/evidence/artifact bundle | candidate findings or patch in scratch worktree | ExternalReviewRequest | local DB, live tree, secrets, finish/approval |
| **Architecture Owner** | accepted Architecture, rationale, conflicts and evidence for change | accept/supersede an Architecture revision | authenticated Architecture Owner role | runtime facts, project outcome or implementation support without evidence |
| **System Owner / delegated Operator** | installation, route/model availability, Module Catalog policy, services, backup and ordinary migration | policy-covered infrastructure/config/module-generation transition | authenticated System Owner or narrower delegated operator capability; exact approval for Critical actions | break-glass authority, project factual truth or task completion by administrative role alone |
| **WorkScope Owner** | scope resources, privacy/retention, local verifier/evaluation contracts and risk boundaries | approve/narrow WorkScope policy and applicable verifier contracts | authenticated WorkScope Owner role | global installation/Architecture policy or factual proof by designation alone |
| **Approver** | inspect exact Critical request/evidence/unknowns | one-shot approval or denial for the exact action hash | authenticated Approver role and current request | executing the action, changing its scope after approval, factual verification |
| **Recovery Principal** | break-glass/recovery view, exact repair/cutover surfaces | one bounded RecoveryLease transition | pre-established Recovery Principal role + incident/recovery evidence | normal project decisions, broad admin access, reusing break-glass as normal path |
| **Human observer / read-only** | ControlBoard, state, evidence, reports | observation/correction candidate only | authenticated local Human principal | any mutation or proof by assertion |

A single model process may perform several roles sequentially, but every role transition creates a new scoped capability context and updates the Independence Profile. It may not silently retain stronger authority from a previous role.

---

## I7.22. Host runtime identity, discovery and conformance

Discovery and conformance are separate:

```text
Discovery:
  find installation, hash executable/package, read version/help/manifest,
  create declared candidate profile.

Conformance:
  execute bounded operation probes, capture raw events/effects,
  classify failures, issue expiry-scoped capability evidence.

Production observation:
  confirm the same capability on the exact active fingerprint;
  detect route drift, cancellation failure, empty success and event loss.
```

An attempt may run with partially unknown actual-route fields only when policy permits. Unknown provider/model/billing identity cannot satisfy an independence claim, a provider-specific privacy claim, a billing claim or a route-specific verifier requirement. Observed route mismatch makes the result candidate-only, invalidates dependent capability evidence and normally quarantines that exact fingerprint pending reconciliation.

`--help`, README, model catalog and handshake booleans never grant production capability by themselves. Adapter admission requires exact scope-matching evidence and rejects stale/broken evidence.

No silent mid-attempt failover:

```text
before provider/runtime work begins:
  route may be retried or substituted under the same logical request;

after meaningful provider output, tool use or external effect:
  substitution creates a new attempt with a causal link and sealed handoff.
```

## I7.23. Raw and normalized host events

Every native event is stored as:

```text
immutable raw payload/blob + hash;
normalized HostEventEnvelope;
adapter and transformation versions;
sequence/event/cursor and parent-child lineage;
normalization loss/warnings;
requested/actual route and usage references.
```

Normalized event is used for policy, state and UI. Raw payload is used for forensic replay and parser correction **only within the applicable retention/privacy contract**. Secret values, provider-forbidden hidden reasoning and data outside the WorkScope privacy boundary are never persisted merely to preserve “rawness”. The ingest path stores an exact transport hash plus either the allowed raw bytes or a deterministic redacted representation with a redaction receipt. Cursor advancement is published only after the admissible raw/hash record and normalized projection are durably related and the EventEnvelope disposition is recorded. Reconnect replays unacknowledged durable events by stream cursor; duplicates are idempotent.

Logical turn state, process state and native event cursor are distinct. A live process may be idle/orphaned; a native `completed` status may still map to ELIOT `PARTIAL`, `FAILED_VERIFICATION` or `UNKNOWN_OUTCOME`.

Structured usage records preserve root/child/aggregate scope and `known | estimated | unknown | not_exposed | not_applicable`. Zero is never used as a substitute for missing data.

For evaluations and policy claims, ELIOT derives a `HostObservedComplianceTrace` from immutable host/runtime events rather than model prose:

```text
allowed Tool/Facet manifest digest;
observed tool calls and non-tool actions;
filesystem/repository/shell/web access;
artifact writes and external effects;
raw-event/cursor coverage and blind intervals;
PASS | TAINTED | FAIL disposition.
```

A run advertised as ELIOT-only loses compliance comparability when it reads hidden schema/output files, uses undeclared shell/web access or writes outside its namespace. Missing host coverage is `TAINTED/UNKNOWN`, never a self-reported PASS.

Any claim about observed compliance, event completeness, hook enforcement or route behavior also binds a versioned denominator:

```yaml
ObservationCoverageManifest:
  product_session_attempt_and_route_fingerprint:
  expected_event_sources_and_event_classes:
  observable_and_unobservable_actions:
  first_and_last_expected_cursors_by_stream:
  received_applied_rejected_and_unknown_counts:
  sequence_gaps_duplicates_reorders_and_payload_mutations:
  blind_intervals_and_missing_source_reasons:
  coverage_by_material_action_and_effect_route:
  denominator_origin_and_sampling_policy:
  completeness: COMPLETE | PARTIAL | UNKNOWN | NOT_APPLICABLE
  proof_ceiling_and_invalidation:
```

An absent event is evidence of non-occurrence only when the applicable source/class is in the denominator, its cursor interval is complete and no blind interval covers the action. Otherwise the result is `UNKNOWN/PARTIAL`; coverage percentages without a declared denominator are invalid. Gap, duplicate, reorder, payload-mutation and cross-scope replay faults are part of the host-event conformance suite.

## I7.24. Tool surface economy and cognitive exposure

Tool descriptions, schemas, defaults, examples and permission text are versioned cognitive inputs. They consume context, shape the model's action ontology and may carry injection or stale-capability risk. The bridge therefore compiles a task-relative surface instead of exposing the whole catalog.

`ToolSurfaceDecision` records:

```text
task/role/route/Governance Profile and State Fence;
considered Tool Definitions and capability evidence;
always-visible, lazy-visible, hidden and forbidden sets;
schema/context cost and expected decision/proof delta;
side effects, authority and privacy boundary;
cheaper or safer alternative;
selection/suppression reason, expansion path and invalidation dependencies.
```


Tool schema is not enough to govern behavior. Every introduced tool version is joined to one ELIOT-owned semantic profile:

```yaml
ToolSemanticProfile:
  tool_definition_and_version:
  operation_class: OBSERVE | NAVIGATE | PROPOSE | MUTATE | VERIFY | PROGRESS | COMPLETE_CANDIDATE
  effect_class:
  authority_and_introduction_requirements:
  idempotency_class:
  reversibility_or_compensation_class:
  expected_result_semantics:
  repetition_polling_pagination_and_terminal_semantics:
  evidence_and_completion_ceiling:
  timeout_resource_and_privacy_profile:
  compatibility_and_invalidation_set:
```

`ToolSemanticProfile` is the method-level operational projection of the owning `Tool Definition` and, where the tool is introduced as a resource facet, of the owning `FacetManifest`. It is not a second tool catalogue or authority source. One versioned method identity has one operational semantics owner; generated MCP/WIT/EBP views must agree with it.

Tool names, descriptions and shell substrings never define these semantics. A router or Stage classifier may consume `ToolSemanticProfile`; it may not infer “test passed”, “task complete”, “safe to retry” or “read-only” from a vendor tool name. A missing profile limits the tool to the narrowest observable capability or removes it from the Material surface.

Rules:

```text
the eight logical ELIOT operations remain the stable hot surface;
provider/native tools are exposed only for the current task and role;
large schemas are handles-first and loaded lazily;
README/handshake claims do not make a tool available without capability evidence;
Tool Definition changes invalidate dependent Skills, profiles, packets and competence evidence;
repeated calls without new evidence, state transition or effect create a tool-loop signal;
tool-count reduction is not a goal if it removes a load-bearing capability;
an unavailable or forbidden capability is absent from the advertised surface, not merely discouraged in prose;
no model-authored tool choice creates authority to execute the tool.
```


`ToolSurfaceBudget` is a generated CI/profile contract over the **actually advertised** surface:

```yaml
ToolSurfaceBudget:
  role_route_profile_and_actual_fingerprint:
  builtin_visible_hidden_and_MCP_tool_counts:
  ELIOT_and_non_ELIOT_tool_counts:
  schema_description_example_and_permission_tokens:
  first_prompt_total_tokens_by_actual_tokenizer:
  protected_reasoning_review_and_evidence_reserve:
  per_tool_description_tokens:
  first_line_task_shape:
  lazy_reference_handles:
  overflow_and_quality_disposition:
  change_delta_and_owner:
  validity_scope_and_expiry:
```

A new capability requires budget-delta review. Reference detail moves to lazy resources; the first line names the task shape. Budget overflow is not an automatic rejection if the capability is load-bearing, but it requires a measured context/decision justification and an explicit alternative. Source-file docstring size is not the metric; the rendered schema delivered to the route is.

For ordinary exact operations the decision may be compiled mechanically and need not create a separate user-visible ceremony. A material expansion of the tool surface, a new effect class or a high-cost route is receipted.

Expensive, model-backed, swarm, network, broad-search or effect-capable calls carry a lightweight `ToolCallIntent` naming the expected evidence/decision/artifact/proof delta, why a cheaper cached/exact route is insufficient, budget/stop/retry conditions and operation identity when durable work/effects are possible. Cheap exact reads are exempt. Repeating materially the same call on the same inputs without a new expected delta produces a loop/no-progress signal, not progress.

Tool-result delivery is measured separately from transport completion. A result receipt carries exact digest, admissible source handle, rendered bytes/tokens under the actual tokenizer and `FULL | PARTIAL | TRUNCATED | MISSING`. Large evidence is handle-first; a completed tool call with a truncated result cannot satisfy a complete-evidence or verifier requirement.


Tool availability and tool use are orthogonal observations. Each evaluated turn/run stores a `ToolExposureReceipt`:

```yaml
ToolExposureReceipt:
  tool_definition_and_route_fingerprint:
  registered:
  advertised_to_route:
  eligible_under_scope_policy_and_grant:
  selected_by_planner_or_model:
  called:
  transport_completed:
  result_delivery: FULL | PARTIAL | TRUNCATED | MISSING
  result_digest_and_exact_token_cost:
  expanded_or_retried:
  observably_used_in_decision_action_or_verifier:
  terminal_task_or_product_outcome_ref:
```

The fields are not one success ladder: an advertised tool may never be eligible; a completed call may deliver a truncated result; a delivered result may be ignored; a gold tool appearing in the surface is not a correct-tool decision. Surface and result experiments therefore report advertisement cost, selection, execution, delivery and downstream use separately.

## I7.25. Skill lifecycle, interaction and execution evidence

A Skill is a compact behavioral interface over deeper contracts. It is not considered useful because it is installed, injected or quoted. ELIOT maintains one derived `SkillLifecycleView`:

```yaml
SkillLifecycleView:
  skill_ref_and_revision:
  task_host_route_and_governance_scope:
  applies_when_and_does_not_apply_when:
  dependency_and_tool_definition_versions:
  delivered_expanded_and_executed_counts:
  eligibility_activation_and_activation_latency:
  adherence_at_early_mid_and_final_checkpoints:
  verified_success_failure_and_uncertain_outcomes:
  observed_decision_or_verifier_delta:
  false_activation_and_distractor_history:
  interactions_ordering_and_mutual_exclusion:
  stale_or_quarantine_reason:
  proposed_action: keep | patch | split | merge | suppress | archive | quarantine | restore
  evidence_review_and_rollback:
```

Rules:

```text
installed != delivered != executed != useful;
eligible != activated != adhered: an update may be eligible and never retrieved, retrieved and never used, used early and abandoned by the final turn;
silence about adherence is unknown, not compliance;
retrieval, repetition and model agreement do not reinforce a Skill;
Skill execution is linked to exact steps, artifacts and verifiers when observable;
shared success may remain distributed or uncertain rather than being assigned to one Skill;
where-not-apply, stop and escalation are first-class;
conflicting Skills create an Instruction Conflict and are not resolved by prompt order;
dependency or Tool Definition change marks the Skill stale before Material use;
Dreamer/Curator may propose lifecycle changes, but they remain reversible candidates until governed promotion.
```

A `SkillExecutionEvidence` can show that a procedure was followed and what happened; it cannot prove that the Skill alone caused the result. Per-attempt eligibility, packet position, retrieval, delivery, observable activation and adherence for a Skill/overlay/procedure are bound by the `HarnessActivationReceipt` in I12.24; aggregate lifecycle counts never substitute for that exact receipt. A `SkillInteractionView` records conflicts, required ordering and mutual exclusion only when observed or explicitly specified.

Skill curation is selective and batch-oriented. It examines actual usage, failure, transfer and distractor evidence; it does not rewrite the hot Skill after every task. Low observed utility changes exposure or review priority, not epistemic status or authority.



## I7.26. Reversible payload budget and omission handles

Every material payload is either delivered completely or shortened through a durable reversible projection. Silent truncation is forbidden.

```yaml
OmittedPayloadRef:
  omission_id:
  source_blob_or_operation_ref:
  source_checksum:
  original_bytes:
  rendered_bytes:
  omitted_count_or_ranges:
  omission_reason:
  preserved_priority_classes:
  renderer_and_budget_profile:
  created_at:
  retention_and_expiry:
  expansion_uri:
  completeness: complete_source_preserved | partial_source |
                source_unavailable | unknown
```

Algorithm:

```text
1. Normalize/redact according to privacy policy.
2. Persist the admissible exact source or existing BlobRef before rendering a
   material shortened view.
3. Apply a typed reducer or deterministic range selection.
4. Preserve errors, failure signatures, exit status and exact anchors first.
5. Preserve exact quoted spans that carry evidential weight before any generative restatement.
6. Return preview + omission handle + completeness metadata.
7. Expansion reads the stored source; it never re-executes the original tool/effect.
8. Expired/missing source yields `OMITTED_SOURCE_UNAVAILABLE` with an explicit unavailable/partial result; the original effect is never re-executed.
```

If a material omitted portion cannot be durably preserved, the response cannot claim completeness or satisfy proof. It returns an evidence-incomplete/truncated disposition with a Recovery Directive. For non-material convenience views, an explicit partial preview is allowed but never promoted.

`OutputReducer` families are replaceable renderers for tests, build, lint, Git, search, logs and file listings. They preserve exit code and raw handle and do not decide semantic truth. A reducer that does not reduce size passes through the source unchanged.

Payload budgets apply consistently to:

```text
MCP/EBP responses;
tool/instrument output;
CodeCortex and Dreamer packets;
diffs and reports;
swarm reduction artifacts.
```

The Blob Store is the only payload substrate. RepoWise-style omission is not implemented as another semantic SQLite store.


## I7.27. Evidence execution, parsing, evaluation and independence

One `passed` boolean is forbidden. Instrument/model/tool evidence carries orthogonal status:

```yaml
EvidenceStatus:
  execution: NOT_EXECUTED | SIMULATED | EXECUTED | UNKNOWN_OUTCOME
  parsing: RAW | PARSED | PARSE_FAILED | NOT_APPLICABLE
  evaluation: UNASSESSED | PASS | FAIL | INCONCLUSIVE | STALE
  independence: SELF_REPORTED | SAME_PATH | SAME_ROUTE_NEW_PROMPT |
                DISTINCT_MODEL_SAME_EVIDENCE | DISTINCT_OBSERVATION_ROUTE |
                DISTINCT_IMPLEMENTATION_OR_TOOLCHAIN | DISTINCT_FAILURE_DOMAIN |
                DISTINCT_ANALYST_OR_TEAM | HUMAN_OBSERVATION | INDEPENDENT_FORMAL_CHECKER
  artifact_binding: UNBOUND | BOUND_EXACT | BOUND_PARTIAL
  attribution: OBSERVED_ASSOCIATION | SUPPORTED_CONTRIBUTION | OBSERVED_UNDER_INTERVENTION |
               COMPOSITE_BENEFIT | CONTRADICTED | UNKNOWN
  scope_and_state_fence:
```

Independence is a non-ordinal failure-domain profile, not a proof ladder. It names what actually changed; multiple labels may apply. A different prompt on the same route is the weakest variation and never satisfies an independent-verification requirement by itself. A different model that shares the same evidence, parent context or evaluator remains dependent on those domains, and no independence label proves correctness.

`attribution` asks not “was a result obtained?” but “was the mechanism demonstrated?” A composite change may legitimately be used operationally as `COMPOSITE_BENEFIT`, but its narrative explanation is not a demonstrated mechanism without separation or control.

Synthetic plan/profile records use `NOT_EXECUTED`; they may test shape and scheduling only. A real verifier requires `EXECUTED`, exact executable/config/artifact identity, immutable raw evidence handles and an applicable Evaluation Contract. Parser success is not execution; execution is not independent verification; independence is not correctness.

## I7.28. Agent, Human and route feedback contract

ELIOT treats feedback from the working agent as a first-class observation because the route is often the first participant to notice wrong scope, missing context, irrelevant memory, confusing instructions or tool friction. Feedback remains fallible self-report and is correlated with actual packet/tool/outcome evidence before changing policy.

Each significant packet, directive, agent launch and finish surface carries an expiring `feedback_handle`. Feedback uses `eliot.observe { kind: observation }` with the `AgentFeedbackReceipt` subtype; no ninth hot MCP tool is added. The handle routes the record to the `eliot_system` self-scope, so a `wrong_scope` or `scope_ambiguous` complaint is not rejected by the very project binding it challenges. It preserves both claimed and observed scope candidates but has no authority to rebind the project or write its semantic memory.

```yaml
AgentFeedbackReceipt:
  feedback_id_and_handle:
  principal_route_attempt_and_session:
  subject_ref: packet | task | scope | memory_item | instruction | tool | bridge |
               verifier | swarm | maintenance | configuration
  disposition: useful | partly_useful | missing_required_context | wrong_scope |
               stale | contradictory | too_large | too_fragmented | irrelevant |
               instruction_conflict | tool_friction | loop_risk | other
  concise_observation_and_optional_requested_delta:
  public_decision_action_or_failure_ref:
  implicit_telemetry_refs:
  confidence_and_limits:
  state_fence_and_time:
```

```yaml
FeedbackCapabilityProfile:
  route_adapter_and_fingerprint:
  feedback_surfaces: in_band_tool | native_event | result_envelope | post_run_prompt | none
  interruption_and_token_cost:
  correlation_limits_and_blind_intervals:
  supported_subjects_and_max_payload:
  expiry_and_probe_evidence:

FeedbackDispositionReceipt:
  feedback_ref_and_current_state_fence:
  decision: accepted_observation | deduplicated | disputed | needs_evidence |
            current_packet_repaired | scope_revalidation_started |
            queued_meta_candidate | rejected_privacy_or_authority
  immediate_delta_or_recovery_handle:
  durable_problem_or_improvement_ref:
  evidence_needed_and_decision_owner:
  returned_to_route_or_human_at:
```

A route that cannot emit feedback is recorded as `feedback capability unavailable`; its silence is unknown, not satisfaction. For such routes ELIOT may use a result-envelope field or a bounded post-run query, but never fabricates agent approval. Governor/Diagnostic Compiler owns `FeedbackDispositionReceipt`; Scope Resolver, Context Compiler, bridge/tool owner or Meta job may execute the named recovery but cannot rewrite the disposition as a second owner. Accepted feedback receives a disposition visible to the agent/Human when the route supports it, so feedback is not a write-only complaint sink.

Feedback is requested only at useful boundaries—on an explicit problem, after a decision-critical packet, at handoff/finish, or when Watchdog detects drift. Per-turn ratings and mandatory prose are forbidden. Silence means unknown, not satisfaction. Human corrections use the same contract with a Human source class.

`FeedbackSolicitationPolicy` requests one compact disposition only at informative boundaries: first Material packet, substantial truncation/expansion, scope conflict, repeated correction, route handoff, tool failure, finish and a detected no-progress interval. It is suppressed when the same packet/problem has already been rated, when answering would disrupt the task or when expected information value is low.

Feedback may repair the current interaction without waiting for Meta promotion:

```text
wrong_scope / scope_ambiguous
  → freeze dependent context/effects and run ScopeBindingGuard;
missing_required_context
  → offer exact handles or compile a bounded delta;
stale / contradictory
  → revalidate the affected sources/fence and expose the conflict;
too_large / too_fragmented
  → produce a smaller Decision-Safety-Floor-preserving packet;
tool_friction / instruction_conflict
  → return a typed recovery/example and record the observation.
```

These are current-session recovery actions, not proof that the agent’s diagnosis is correct. The feedback path updates the self-scope observation bank, Context/Memory quality projections and, when useful, a bounded Meta/Dreamer diagnostic job. A single complaint does not rewrite ContextRecipe, Skill, route policy or memory. Repeated supported feedback produces a Problem/ImprovementCandidate with exact packet, cost, omission, decision and outcome evidence.

## I7.29. PortableSkillPackage

`PortableSkillPackage` is the user-facing portable packaging contract for one or more Skills. Each package revision is an immutable user-owned artifact; it is not a Skill-utility state, Tool Definition, capability grant, scheduler or authority boundary.

```text
<package>/
  manifest.yaml
  SKILL.md
  references/      optional
  scripts/         optional
  assets/          optional
```

```yaml
PortableSkillPackageRevision:
  package_id_revision_and_supersedes:
  canonical_tree_digest_algorithm_and_value:
  source:
    kind: profile_local | project_local | shared_external_directory |
          git_or_hub_url | eliot_generated_candidate
    locator_retained_snapshot_source_digest_and_lock:
    source_view_workscope_and_provenance:
  manifest_format_and_compatibility_profile:
  skill_entries_bundles_and_optional_short_aliases:
  declared_dependencies_and_required_capability_refs:
  tool_definition_and_configuration_requirements:
  applies_when_where_not_apply_stop_and_escalation:
  verification_entrypoint_ref:
  reference_script_and_asset_inventory:
  write_policy: protected_human_only | governed_candidate_writeback
  package_admission_disposition: DISCOVERED_UNTRUSTED | QUARANTINED |
                                 TRUSTED_SCOPED | REJECTED | RETIRED
  trust_scope_principal_receipt_expiry_and_recheck_rule:
```

Discovery/import pipeline:

```text
resolve SourceAdmissionPolicy and exact SourceView;
capture a retained immutable snapshot of regular package files;
reject path traversal, symlink/reparse escape and mutable external references;
compute a versioned digest over normalized relative path, file type and exact bytes;
validate manifest, dependency/capability names, secrets and executable supply chain;
record provenance/lock data and quarantine or request scoped trust;
compile only the admitted Skill entries for the current route/profile/policy catalogue.
```

A Git/Hub URL is an acquisition locator only; executable use always binds the retained snapshot and digest. Project-local trust binds exact WorkScope/root identity, source-view revision, package digest and trust principal. Any byte, dependency declaration or path-identity change creates a new revision, triggers rescan and does not inherit trust from the old path. Profile-local and shared packages follow the same revision rule; location alone is never trust.

`SKILL.md` becomes eligible instruction content only after package admission. Large `references/` are loaded on demand through the index/body/runtime budget of I7.12 and remain source material, not authority. Presence under `scripts/` does not register a tool or permit execution: every script and verification entrypoint requires an admitted Tool Definition, exact capability grant, sandbox/effect policy and execution receipt. Import/discovery therefore has zero execution authority.

Dependency, host, contract or Tool Definition drift marks the compiled Skill stale under I7.13/I7.25 before Material use; it does not rewrite historical package trust or outcomes. Quarantine/trust describes package admission only. I7.25 remains the sole owner of installed/delivered/executed/useful evidence, and causal-helpfulness still requires the applicable decision/verifier/outcome proof rather than package load, citation or successful transport.

An agent or `/learn` surface may propose a new package or immutable revision from a URL, directory, conversation, notes or document. ELIOT-generated material starts untrusted/quarantined. Writeback is an exact governed diff against the current revision with source provenance, verifier and Human/policy approval; a protected package rejects agent edits. No difficult task, repeated wording or successful import automatically promotes or rewrites a user package.

Retirement prevents future activation but preserves revision history, provenance, execution evidence and rollback/restore inspection. Short aliases and bundles are namespaced surface entries resolved against the active eligible catalogue; alias selection does not widen package trust, capability or task authority.

# I8. Watchdog implementation contract

## I8.1. Process and authority

`eliot-watchdog.exe` is a separate Windows service or process outside the Host and Kernel failure domain. Its run policy is dual: while a valid `SupervisionLease` exists for an observable Session, AgentAttempt, Durable Job, protected effect, maintenance or recovery operation, or explicit supervision policy, the minimal deterministic sensor remains running even if Kernel and `eliotd` sleep; a dormant registered WorkScope alone is insufficient. Outside that active interval it stops after persisting journal cursors and wake intents. Host, CLI, or SCM may start it on demand. Watchdog never becomes a Host or Kernel child and remains independently observable during `eliotd` failure.

This is the direct Implementation of Architecture 4.5: Watchdog is continuous and independent for every interval in which ELIOT is observably used or claims supervision. When there is no active Session, job, effect, maintenance/recovery obligation or user-enabled supervision policy, the interval is closed, cursors/wake state are persisted and Watchdog may stop. There is no claim of machine-wide observation outside such an interval and no Architecture conflict.

Watchdog owns:

```text
supervision observations;
signal processing state;
independent minimal spool;
security/liveness rules;
request to contain, diagnose, restart or escalate.
```

Watchdog does not own:

```text
canonical semantic transitions;
Current Epistemic Position;
task decisions;
module repair execution;
Architecture changes;
completion;
model/swarm budget.
```

Canonical Problem/Incident transition performs Governor. If Governor is unavailable, Watchdog writes `problem_intent`/`incident_intent` into its **own physically separate minimal spool** (`watchdog.redb`) for later reconciliation. This spool uses the same restricted non-semantic envelope as ORS but is not stored in the Kernel ORS failure domain.

## I8.2. Independent observation routes

At least one route for process/integration health must not depend on `eliotd` self-report.

Windows sensors:

```text
SCM service state;
process handle and exit code;
Job Object membership/resource counters;
named-pipe availability and handshake;
filesystem change journal / watched paths, including persisted USN cursor replay on wake for registered Windows WorkScopes;
module artifact and config hashes;
Host-managed SurrealDB process health from an independent read-only probe;
Kernel heartbeat;
agent hook/bridge event cadence;
network/listener inventory for registered services;
security audit signals from OS and bridges.
```

Independent observation proves event existence, not principal attribution. Attribution requires correlation identity; otherwise origin remains `unknown`.

Observation coverage is explicit:

```text
CONTINUOUS       — sensor observed the interval live;
JOURNAL_REPLAYED — OS/application journal covered the interval after wake;
PARTIAL          — some sources or sequence ranges are missing;
BLIND            — no competent source covered the interval;
UNKNOWN          — coverage cannot be established.
```

A persisted USN/host-event cursor lives in HostStateJournal/Watchdog spool, not canonical memory. Replay is bounded, records journal wrap/gaps, and emits an `ObservationCoverageManifest`; it cannot reconstruct hidden tool intent or principal attribution from file changes alone. Push claims are limited to the observed/replayed channels.

## I8.3. Deterministic supervision loop

```text
observe
→ normalize event
→ correlate with registered process/session/module/task
→ evaluate deterministic rules
→ deduplicate/update Signal
→ open/update problem intent if threshold crossed
→ emit a signed pre-authorized containment request to the owning Host/Kernel boundary
→ invoke Doctor or bounded Watchdog Agent if semantic diagnosis needed
→ verify resolution
→ close/reopen/escalate.
```

No LLM call in heartbeat or hard security path. Watchdog does not write HostStateJournal, ORS or canonical state directly. Host/Kernel revalidate target, evidence, recipe class, current epoch and allowed effect before executing containment. If Kernel is unreachable, Host may perform only a pre-registered process stop/restart/fence action; result is written to HostStateJournal and Watchdog spool for later canonical reconciliation.

Process liveness and control responsiveness are separate. Watchdog performs an authenticated bounded `HostResponsivenessChallenge` against the current HostInstallationEpoch. `process_alive + challenge_timeout` becomes `ALIVE_UNRESPONSIVE`, not healthy. Under an installation-time pre-authorized SCM recovery policy, Watchdog may request SCM to stop/restart only the exact Host service generation after the challenge and restart budget fail; it cannot select artifacts, alter semantic state or widen authority. Every attempt is recorded in the Watchdog spool and Windows Event Log for later reconciliation.

## I8.4. Interaction heartbeat

For active Material work Watchdog expects observable progress envelope:

```text
session attach;
WorkScope/task sync;
packet/action boundary;
material tool/action observation;
verification or explicit unknown;
checkpoint/finish.
```

Rules are contextual, not a fixed “write every N seconds” dogma.

Examples:

```text
workspace changes while no PostTool/observe events arrive
  → integration gap signal;

observed cwd/worktree/root differs from the bound WorkspaceInstance
  → WatchdogSignal `scope_drift`; freeze dependent context/effects and request rebind;

many material tool calls without packet/state refresh after invalidation
  → stale-context warning or require refresh;

same failed action signature repeated without new evidence
  → repeated-failure attention;

native/external child appears without an admitted AgentAttempt or parent lineage
  → orphan-descendant signal and no proof/effect admission;

child context, token, tool or descendant usage approaches/exceeds its envelope
  → narrow/cancel/escalate the subtree; unrelated attempts continue;

active agent and changing files, but no ELIOT observations for configured window
  → ask agent for resync; persistent gap lowers Governance Profile;

agent idle with no external change
  → no violation.
```

Cadence defaults are Empirical Profiles per harness/task family.

## I8.5. Hook/plugin health

Watchdog tracks:

```text
expected hook set;
last event per hook;
sequence gaps;
plugin/config hash;
active MCP registration count;
bridge protocol version;
observed tools vs declared intercept coverage;
unknown-origin changes;
failed hook exit/status;
multiple competing ELIOT registrations.
```

`installed = true` is not `healthy = true`.

Health compares one semantic installation chain:

```text
tracked source manifest;
generated plugin/Skill/schema manifest;
installed cache/config/registration manifest;
bridge and executable hashes;
active process/runtime fingerprint;
live event readback and coverage receipt.
```

It also tests bounded reentrancy, backpressure, crash, timeout and duplicate-registration behavior. A matching config file without a live event path is `INSTALLED_UNOBSERVED`, not healthy.

## I8.6. Bypass detection

Signals include:

```text
process accesses SurrealDB endpoint/credentials outside storage bridge;
process touches the database path outside the active Host-managed SurrealDB process lineage;
unregistered direct canonical export/import;
agent executes known DB CLI/query path;
module writes outside declared effect set;
unknown process changes protected config, Module Catalog, Generation Registry or Capability Registry state;
old generation emits after fencing;
external effect appears without action/receipt lineage.
```

Content may be semantically correct and still be rejected as canonical if it bypassed the write path. Observation of the effect remains evidence. These detections exist only where the active `IntegrationCoverageProfile` names a competent sensor. Missing coverage is reported as a supervision gap; absence of a signal is never treated as proof that bypass did not occur.

## I8.7. Security Source Assurance

Watchdog records independently observable security features and deterministic risk flags. Optional Watchdog Agents may propose a semantic risk assessment as candidate-only output. Governor stores the governed profile with both sources separated; model confidence alone cannot create quarantine, Incident or authority change.

```yaml
SourceSecurityAssessment:
  source_ref:
  identity_assurance:
  integrity_assurance:
  instruction_injection_risk:
  deception_risk:
  exfiltration_risk:
  persistence_risk:
  suspicious_patterns:
  affected_capabilities:
  suggested_quarantine:
  required_probe:
  confidence_and_limits:
```

It does not decide semantic truth.

## I8.8. Prompt/tool/memory injection signals

Examples:

```text
external document attempts to issue system/tool instructions;
Tool Definition changes name/schema/defaults unexpectedly;
source asks to persist standing instruction or secret;
summary attempts to raise source authority;
multiple model outputs repeat one poisoned lineage;
remote Dream query attempts broad data extraction;
memory transformation drops origin/minority evidence;
procedure candidate introduces undeclared side effect.
```

Response:

```text
preserve raw source;
mark instruction taint/security risk;
limit allowed influence/effects;
request Governor to quarantine the affected influence dependency closure when a deterministic rule/policy or authorized decision supports it;
ask Dreamer for bounded semantic analysis only when policy permits;
open Problem/Incident for high impact;
notify the named task/security/Human decision owner with evidence, not alarmist prose.
```

## I8.9. Signals

```yaml
WatchdogSignal:
  signal_id:
  rule_id:
  severity: info | warning | blocking | incident_candidate
  subject:
  scope_id:
  observed_at:
  evidence_handles:
  attribution: known | suspected | unknown
  processing_state:
  delivery_state:
  disposition:
  dedup_key:
  reopen_condition:
```

Axes are independent. Acknowledgement does not resolve.

### I8.9.1. Risk accumulation, model escalation and flexible response

Watchdog maintains a multidimensional `RiskEvidenceVector`; the optional numeric score is only a policy projection for triage and route selection, never truth, authority or an automatic universal blocker.

```yaml
RiskEvidenceVector:
  subject_and_scope:
  impact_and_effect_class:
  likelihood_or_recurrence:
  evidence_confidence_and_observation_coverage:
  propagation_and_blast_radius:
  reversibility_and_external_residue:
  persistence_and_compromise_potential:
  uncertainty_and_common_lineage:
  current_damage_and_repair_history:
  supporting_and_counterevidence:

RiskAccumulatorView:
  deduplicated_signal_refs:
  correlated_lineage_groups:
  decayed_and_reopened_risk_pressure:
  policy_score_and_explanation:
  next_action: observe | request_resync | cheap_diagnosis | strong_diagnosis |
               concilium | preauthorized_containment | human_escalation
```

Repeated copies of one event do not add linearly. Many low-severity independent anomalies may justify diagnosis; one Hard Boundary observation may require immediate local containment without waiting for a score. Thresholds and model routes are Human-owned Policy/Empirical Profiles.

When deterministic evidence is insufficient, Watchdog creates a bounded `WatchdogAgentRequest`. Low-complexity classification may use a cheap local route; cross-layer ambiguity, possible compromise or repeated repair failure may use a stronger independent route or Concilium. The agent receives evidence handles, a precise question, no broad mutation authority and an explicit stop condition.

Accumulating damage, failed Doctor recipes, unknown external effects or a widening blind interval raises persistent Human attention. The system narrows only the dependent operation/module when possible; it does not sabotage unrelated work merely because the aggregate score is high.

A derived calibration projection evaluates the risk policy rather than treating its score as self-validating:

```yaml
RiskPolicyCalibration:
  policy_profile_revision_and_validity_scope:
  classified_signal_and_action_samples:
  missed_critical_harm_and_residual_damage:
  false_containment_false_block_and_unnecessary_escalation:
  diagnosis_utility_recovery_time_and_human_attention:
  route_cost_and_independence:
  uncertainty_and_sample_limitations:
  proposed_keep_narrow_rollback_or_experiment:
```

Threshold/profile changes are Improvement Candidates with rollback; a high score that repeatedly predicts nothing is evidence against the risk policy, not evidence that work should be blocked harder.

## I8.10. Containment

Watchdog issues signed requests for pre-authorized circuit breakers; it does not mutate HostStateJournal, ORS, Module Catalog, route policy or canonical state itself.

```text
request Host/Kernel to close normal admission;
request Kernel to revoke/fence a Session, lease or Module epoch;
request Kernel to quarantine a module generation;
request Host/Kernel to stop a child process;
request the owning gateway/module to disable remote Dream access;
request Governor to remove a route from new admission;
preserve evidence and request scoped isolation.
```

The receiving owner revalidates current epoch, target, evidence, recipe class and exact allowed effect, then records the actual containment receipt. Watchdog cannot create a new permission, canonical transition or semantic conclusion.

If Governor is unavailable, Host may execute only its pre-registered process stop/restart/fence operations; an independent effect interlock may deny only the exact effect class it already owns. Both record a non-semantic result/intent in HostStateJournal or the physically separate Watchdog spool for later reconciliation. Kernel ORS receives that intent only after the corresponding control path is available.

## I8.11. Watchdog Agents

A Watchdog Agent is a short-lived `DurableJob` with:

```text
one exact diagnostic question;
bounded recent trace/evidence bundle;
output schema;
model route and failure-domain profile;
budget/deadline;
candidate-only effect;
required verifier or Human decision for high impact.
```

Examples:

```text
“Explain why hook events disappeared after version X.”
“Compare these three repeated repair failures and propose a discriminating probe.”
“Review this suspected prompt-injection lineage without executing content.”
```

Different model is not automatically independent. Route independence records provider/model family, harness, evidence bundle, evaluator and conceptual frame.

For high-severity or low-confidence assessments, policy requires one of:

```text
a deterministic discriminative probe;
a second bounded assessment from a materially different failure domain;
Main Agent or Human review with the conflicting evidence visible.
```

Disagreement becomes a Conflict Set and recommended probe. Assessments are never averaged or accepted by vote.

## I8.12. Restart budgets

Per process/module manifest:

```yaml
RestartPolicy:
  max_attempts_in_window:
  window:
  backoff:
  jitter:
  reset_after_healthy:
  quarantine_after_exhaustion:
  escalation_target:
```

DEFAULT process sequence: immediate once, short backoff, then increasing bounded backoff. Exact numbers live in config and fault profiles.

Repeated repair/restart without new evidence stops automatically.

## I8.13. Watchdog failure

```text
SCM recovery policy and, when available, Host supervision observe process exit;
SCM/installer starts the last approved compatible generation;
Kernel/Governor lower Supervision axis;
Material work may continue only per policy and visible degradation;
Critical work pauses unless independent supervision is restored or Human explicitly accepts risk;
failed Watchdog does not repair itself;
repeated failure escalates through fallback notification.
```

If Host/OS/machine and fallback notification all fail, internal notification is impossible; this is platform/manual recovery boundary.

The fallback path is defined in I11.6 and remains independent of normal Kernel/UI delivery. `Host alive but unresponsive` is a distinct failure from Host exit: Watchdog uses the challenge/SCM path of I8.3, bounded restart intensity and then a persistent manual-recovery notification. Process survival never counts as responsiveness.

## I8.14. Watchdog observables

```text
heartbeat lag;
trace completeness by IntegrationCoverageProfile;
unknown-origin changes;
repeated action/failure loops;
module restart/quarantine counts;
security signals and false positives;
time to detect and contain;
unresolved signal/problem age;
independent sensor freshness;
critical telemetry gaps.
```

Metrics do not become one “safety score”.

## I8.15. Watchdog generation replacement

Watchdog is outside Kernel's child tree, so its replacement is controlled through SCM/Host rather than the Module route table.

```text
1. stage immutable candidate service artifact and manifest;
2. start the candidate under a temporary SCM service identity or equivalent installer-owned
   shadow process, with a separate candidate spool and zero containment authority;
3. compare sensor coverage, signal normalization, anchor continuity and resource use;
4. publish an explicit temporary supervision-degradation notice if a gap is unavoidable;
5. installer/SCM performs one observed activation change and issues a new supervision epoch;
6. only after activation may the candidate request containment; drain/stop the old service;
7. retain the previous compatible artifact and spool reconciliation receipt.
```

Two Watchdog generations may observe simultaneously, but only one active supervision epoch may request containment. Duplicate signals deduplicate by evidence identity and observation route; agreement of two generations is not independent evidence when they share sensors.


## I8.16. Development drift supervision

Watchdog observes not “code correctness,” but signs that local proxies have displaced the product objective:

```text
growth in commits, tests, or reports without new product evidence;
repeated repair of one failure class without a new hypothesis or discriminator;
PASS with zero tests actually run;
a local green result against stale or different source, configuration, or installed generation;
frequent status or certificate prose while blockers remain open;
branch/worktree/install/DB/docs identity divergence;
a large cross-owner diff without one named causal property;
a repeated error that produced no FailureFingerprint, discriminator,
or Improvement Candidate;
activity continues, but the agent stops reporting observations and outcomes.
```

Watchdog creates a `DevelopmentDriftSignal` and Diagnostic Brief. Repeated repair is keyed by a normalized `FailureClassIdentity` derived from affected property, actual owner and path, violated invariant, observable symptom, and failing boundary—not by test name or prose label. The deterministic detector does not declare agent intent, reward hacking, or root cause as fact. Dreamer or an auditor may propose explanations; Task Controller or Human decides whether to narrow work, require Mechanism Review, change route, or continue.

---

## I8.17. Ingress taint before transformation

Instruction taint, origin, privacy/disclosure domains and raw-source identity are attached at the first trusted ingress boundary, before summarization, embedding, parsing into model prose, Dreamer synthesis or Skill compilation.

```text
raw content
→ source/origin/disclosure/taint labels
→ bounded transformation
→ inherited dependency closures
→ candidate output
→ optional governed screening/declassification.
```

Transformation cannot remove instruction taint or elevate authority. A registered declassifier may narrow disclosure closure only with its own verifier and receipt; it never turns untrusted content into an instruction. Tool/Skill descriptions are versioned cognitive inputs and their change invalidates dependent profiles and packets.

## I8.18. System feedback, memory/context health and maintenance debt

Watchdog continuously correlates the self-scope observation bank with task and runtime evidence. It detects classes that ordinary process health misses:

```text
AgentLoopSignal
  repeated tool/plan/error signature without evidence or state delta;

ContextQualityDrift
  excessive packet size/replay, low useful expansion, missing Safety Floor,
  wrong-scope/stale feedback or high omission regret;

MemoryUtilityDrift
  growing candidate/stale/duplicate corpus, frequent delivery without acknowledged use,
  false activation, negative transfer or no downstream outcome;

ObservationCoverageGap
  workspace/process activity without expected agent/bridge/self-observation lineage;

MaintenanceDebt
  overdue backup/index/curation/update/repair, repeated deferred Problems or stale capabilities.
```

A signal is opened from observed deltas, not a psychological claim that an agent is “lazy” or “confused.” Persistent or cross-cutting drift compiles a Diagnostic Brief and requests Dreamer/Watchdog-Agent analysis. The result may propose a smaller packet, scope resync, curation, new discriminator, route change, maintenance plan or Human decision. It cannot delete memory, alter policy or terminate unrelated work by prose alone.

# I9. Dreamer implementation contract

## I9.1. Process model

`eliot-dreamer.exe` — separate supervised AI service and the primary cold-path intelligence coordinator of ELIOT. The process is demand-started for an admitted Dreamer query/job/maintenance obligation and may stop when no such obligation remains; while active but between model calls it stays lightweight and launches no permanent LLM loop. “Primary intelligence” means that it organizes hypotheses, maintenance and cognitive work; it does not mean canonical ownership, unrestricted execution or final authority.

```text
Dreamer request/problem trigger
→ policy/budget admission
→ bounded input bundle
→ one model agent or controlled swarm
→ structured candidate output
→ provenance/loss checks
→ deliver result
→ explicit disposition by the named Governor, task, WorkScope or Human decision owner.
```

Dreamer has no DB credentials and no canonical write endpoint except candidate submission through Governor.

## I9.2. Dreamer service responsibilities

```text
job admission against Human policy;
input-bundle construction via Governor handles;
model/sandbox route selection;
launch through Agent Coordinator;
checkpoint and cancellation;
output schema validation;
source/lineage preservation checks;
system-maintenance and configuration-plan candidates;
agent/work decomposition and route-complexity planning;
feedback, context and memory-health diagnosis;
ELIOT Research federation queries and exchange planning;
result delivery and accounting.
```

Dreamer does not determine current epistemic status or final action.

## I9.3. Job classes

### Orientation

```text
What does ELIOT know about goal/scope?
Which decisions/failures/unknowns matter?
What hidden relations may change the next action?
Which Architecture anchors and Implementation contracts/defaults apply?
```

Output: `DreamPacket`.

### Curation

```text
classify candidates;
propose relations;
reconstruct episodes;
identify duplicates/false merges;
propose concepts/procedures/failure fingerprints;
propose accessibility/influence changes;
identify memory pollution and missing provenance.
```

Output: `CurationCandidateSet`.

### Clarification

Creates one short question to active agent:

```text
ambiguous observation;
missing scope;
observation vs interpretation unclear;
missing outcome/reuse condition;
contradictory decisions.
```

Question includes why answer matters and safe fallback if unanswered.

### Research synthesis

Works on governed `ResearchPack` or source handles:

```text
rival hypotheses;
source portfolio and independence;
claim/counterclaim matrix;
unknowns and discriminative questions;
Concilium plan;
research brief with uncertainty.
```

Acquisition/parsing/indexing is governed by Researcher and executed by admitted providers (I21); Dreamer receives only governed source handles and bundles.

`ResearchPack` is the acquisition/synthesis boundary:

```yaml
ResearchPack:
  question_and_scope:
  source_handles_and_source_cards:
  acquisition_route_and_time:
  authority_freshness_competence:
  independence_and_shared_lineage:
  privacy_and_allowed_use:
  coverage_and_missing_source_classes:
  state_fence_and_invalidation:
```

Dreamer returns a `ResearchBrief` that keeps claims, counterclaims, exact citations, source dependence, unknowns and recommended probes separate. It cannot convert the pack into project truth by prose quality.

### Architecture/self query

Produces two authority-separated projections from exact accepted sources and current conformance state:

```text
ArchitectureBrief
  applicable ARCH-*;
  intent and rationale;
  affected guarantees and Hard Boundaries;
  unresolved Architecture questions;
  exact accepted Architecture revision and source digest.

ImplementationBrief
  applicable I-sections, contracts, DEFAULTs and Research Gates;
  concrete owners, protocols, state and failure behavior;
  supported / partial / absent / deviated mechanisms;
  migration and compatibility constraints;
  exact accepted Implementation revision and source digest.
```

Architecture has semantic precedence. Implementation explains the currently accepted realization and may expose a gap, DEFAULT or experiment; it cannot reinterpret Architecture silently. Code, tests and runtime observations update conformance evidence but do not replace either accepted source. A combined answer keeps the two projections visibly separate and opens a conformance Problem State when Architecture, Implementation and observed runtime disagree.


### Development diagnosis

Analyzes a bounded set of development evidence:

```text
Product Objective and current product gap;
sequence of repairs and changed paths;
failed/passed discriminators;
actual runtime/source identities;
open conformance gaps;
activity artifacts without product delta;
related FailureFingerprints and prior attempts.
```

Returns:

```text
rival root-cause hypotheses;
common-mode assumptions;
likely proxy metrics and local-optimum loops;
minimum discriminating experiment;
proposed repair scope and owner;
which guardrails or rules should be challenged, narrowed, or retained.
```

Output remains a candidate. Dreamer creates no feature freeze, changes no rule class, closes no defect, and assigns no product status.

### System maintenance and self-improvement planning

Dreamer consumes bounded self-scope observations and prepares a `MaintenancePlanCandidate`:

```text
curation/compaction/reconsolidation candidate;
context/Skill/tool-surface improvement;
route/capability requalification;
backup/index/module/integration maintenance;
configuration change intent;
new diagnostic experiment or Mechanism Review;
Human escalation with the smallest useful decision packet.
```

It does not execute maintenance directly. `eliotd`/Agent Coordinator/installer/Doctor own execution under the relevant policy and leases.

### Agent orchestration planning

Dreamer may translate a Human/Main-Agent objective into a `CognitiveWorkPlanCandidate` naming work units, required competence, route classes, context/evidence budgets, independence, descendant limits and synthesis/verifier paths. The deterministic TaskGraphCompiler and Governor decide what becomes executable. Dreamer may choose “one strong agent”, “several cheap scouts”, “external main agent with visible native children”, or “no model job; ask one question/probe” according to expected value and current policy.

### Configuration assistance

Dreamer may explain current settings and produce the `ConfigurationChangeIntent` of I3.10 from a natural-language request or diagnosed problem. It never edits the active snapshot itself and cannot raise cost, privacy, remote access, authority or automatic-launch ceilings without the owning Human role.

## I9.4. Dreamer input bundle

```yaml
DreamJobInput:
  job_id:
  job_class:
  exact_question:
  requester:
  scope_id:
  task_id:
  state_fence:
  evidence_handles:
  memory_handles:
  architecture_handles:
  implementation_handles:
  conformance_handles:
  conflicts_and_unknowns:
  privacy_profile:
  allowed_tools:
  allowed_model_routes:
  budget:
  deadline:
  output_schema:
  forbidden_effects:
```

Input bytes/tokens are bounded. Handles are expanded only under policy.

## I9.5. Dream Packet

```yaml
DreamPacket:
  packet_id:
  question:
  scope_and_state_fence:
  source_coverage:
  resolved_epistemic_position_handles:
  anchored_evidence_by_status:
  synthesized_interpretations:
  rival_models_and_dissent:
  hidden_relation_candidates:
  unknowns_and_gaps:
  recommended_probes_or_next_actions:
  architecture_implications:
  model_routes_and_cost:
  invalidation_conditions:
  provenance:
```

Sections `resolved` and `evidence` are populated/checked from Governor records. Model text cannot declare them confirmed.

## I9.6. Curation candidate

```yaml
CurationCandidate:
  candidate_id:
  kind: classification | relation | episode | concept | procedure |
        failure | merge | split | reconsolidation | accessibility | repair
  source_handles:
  proposed_transformation:
  support:
  counterevidence:
  scope_and_applicability:
  preservation_report:
  uncertainty:
  verifier_or_replay:
  expected_benefit:
  rollback:
```

## I9.7. Memory transformation validation

Any model transformation checks:

```text
coverage — load-bearing source elements represented;
preservation — alternatives/minority/temporal distinctions not erased;
faithfulness — no unsupported additions;
lineage — every material conclusion traceable;
reversibility — source can be reopened;
source authority — transformation does not raise ceiling;
dependency closure — revocation propagates.
```

Failure leaves original data intact and stores rejected candidate only if useful for diagnosis.

## I9.8. Background policy

Dreamer background work uses the canonical `MaintenanceAutomationMode` of I14.22 rather than a second scheduler-policy enum. DEFAULT desktop mode for Dreamer curation is `idle_only`, with no external model calls unless the user enables them and a route/budget exists. `off` disables even proactive curation recommendations except safety/recovery obligations; `suggest_only` creates a deduplicated Human-board proposal without starting a model job.

Triggers:

```text
candidate backlog crossed value threshold;
repeated failure/conflict;
user/Main Agent query;
Watchdog Problem State;
Architecture/WorkScope generation change;
memory health degradation;
maintenance schedule.
```

One observation never automatically means one model call. Jobs are batched by scope/problem.

### DreamCycle — bounded “sleep-like” maintenance

A `DreamCycle` is the explicit implementation analogue of human sleep-like offline integration. It is one `Dreamer curation` maintenance `DurableJob`, not a new scheduler or memory lifecycle. It is not a permanent thinking loop and does not rewrite memory. A cycle selects a bounded scope and review horizon, replays recent/active episodes plus unresolved conflicts and utility signals, then may launch short curation/challenge agents to propose:

```text
episode consolidation and compact orientation;
duplicate/false-merge review;
relation, concept, procedure or FailureFingerprint candidates;
reconsolidation/reopen/extinction candidates;
context/Skill/tool-surface improvements;
missing evidence, unresolved contradictions and discriminative probes.
```

Every cycle records the sampled coverage, omitted material, model/agent routes, budget, candidate set, rejected transformations and later utility. Primary evidence and minority alternatives remain intact. A cycle whose outputs are unused, repeatedly wrong or more expensive than the measured benefit is narrowed, disabled or sent to Mechanism Review.

### Candidate backlog discipline

Dreamer does not create an unbounded advice heap. Curation/research candidates are deduplicated by target, problem class, source lineage and proposed effect. The active backlog is bounded by policy; stale, superseded and low-value candidates are compressed or archived with receipts. A Material unresolved candidate without an owner becomes Human/Agent Attention instead of being regenerated repeatedly. Only one automatic experiment per target may be active at a time.

## I9.9. Agent/swarm launch and no-lost-child contract

Dreamer submits `AgentLaunchRequest` or `SwarmPlanRequest` to `eliotd`/Agent Coordinator. It cannot fork processes, invoke a provider, allocate a subscription lane or attach tools by itself.

Every launch origin—Human UI/CLI, Main Agent, Dreamer, schedule, API or recovery recipe—passes one Governor-owned `AgentAdmissionReadinessGate`; no surface may implement a weaker private launch path:

```yaml
AgentAdmissionReadinessDecision:
  request_origin_and_product_identity:
  WorkScopeCandidateSet_and_ScopeBindingGuard:
  OnboardingReadinessReceipt_and_GoverningSourceSet:
  TaskContract_revision_or_exploratory_contract:
  requested_impact_role_tools_effects_and_descendants:
  allowed_mode: READ_ONLY_ORIENTATION | BOUNDED_EXPLORATORY | MATERIAL
  decision: ADMIT | NARROW | NEEDS_SCOPE | NEEDS_TASK | NEEDS_SOURCES |
            NEEDS_CAPABILITY | NEEDS_SUPERVISION | DENY
  exact_missing_input_recovery_and_expiry:
```

`MATERIAL` requires `READY_MATERIAL`, an authenticated scope, current TaskContract/acceptance, applicable governing sources, route/tool capability and the Governance Profile required by the action. `READY_READ_ONLY` may admit orientation, source discovery, safe capture or discriminative probes with no scope-sensitive effect. An external process already doing work uses the attach-reconciliation path rather than retroactive launch admission. This gate is evaluated again after any scope, task, source, route or supervision generation change.

```yaml
AgentLaunchRequest:
  initiating_user_problem_policy_or_dreamer_job_ref:
  objective_task_and_parent_attempt:
  work_units_and_expected_outputs:
  required_competence_and_route_complexity:
  allowed_route_classes_and_native_child_policy:
  RootContextRevision_and_per_attempt_context_budget:
  evidence_tool_and_capability_introductions:
  privacy_cost_time_and_resource_envelope:
  max_depth_fanout_and_cumulative_descendant_budget:
  verifier_synthesis_and_integration_owner:
  cancellation_cleanup_and_escalation:
```

Admission checks:

```text
job class and task decomposition allowed;
provider/model/runtime capability proven on the exact route;
data privacy/disclosure compatible;
budget, context headroom and scarce resources available;
fan-out/depth/cumulative descendants within the parent envelope;
expected value/coverage and stop condition stated;
synthesis, verifier and integration owners present;
Watchdog observation coverage sufficient for the requested impact.
```

Every child is registered as an ELIOT `AgentAttempt` **before** process/provider launch and has exact parentage, route, WorkLease, context/effect envelope, heartbeat/event cursor, usage, cancellation cascade and terminal disposition. Parent termination, route loss or coordinator restart leaves no “lost children”: descendants are cancelled, checkpointed, reassigned or explicitly quarantined/reconciled by identity. A live process or provider session without an admitted attempt is an orphan supervision event and cannot publish effects or proof.

External strong agents may use their native subagent mechanism only when the exact runtime exposes child creation, parentage, route, tool inheritance, cumulative usage, cancellation and results. Otherwise native children are disabled for Material work; the parent must delegate through ELIOT. When a remote/closed runtime cannot expose child-level lifecycle at all, ELIOT may admit only the whole runtime invocation as one **opaque parent attempt** under a top-level cumulative budget, effect ceiling and terminal receipt. It makes no no-lost-child claim below that boundary, gives no independence credit to hidden children and forbids descendant-owned effects/proof. Hidden or unobservable subagents that mutate the workspace or outlive the opaque parent trigger containment/reconciliation and downgrade the route profile.

For Material work, an opaque parent can reach a terminal ELIOT disposition only when capability evidence on the exact runtime fingerprint proves either that the provider terminal event closes all descendant execution, or that every descendant effect is mediated and reconciled through the parent boundary. If this property is absent or contradicted, the route is limited to read-only/candidate work or the attempt remains `UNKNOWN_OUTCOME` through the declared external-effect observation window. A provider “completed” message alone cannot prove that hidden descendants stopped.

Context and budget are enforced per child and cumulatively where the exact runtime exposes an enforcement surface. Children receive only the minimum RootContext overlay and capability facets for their work unit; they do not inherit the parent’s full prompt, credentials or memory. Child swarm cannot expand budget, authority, scope, data class or automatic-launch policy.

Child-resource capability is recorded on separate observation and enforcement axes. A runtime that reports usage but cannot limit it is `OBSERVE_ONLY`: Watchdog may warn, stop/cancel the parent at a visible threshold or deny further children, but ELIOT does not claim a hard context/cost bound. Material/Critical automatic swarm requires either child-level enforcement, a provider/runtime hard cap or an opaque-parent envelope whose worst-case cost/effects are acceptable to Human policy.

## I9.10. Model routing

Router considers:

```text
capability/competence profile;
context safe operating envelope;
privacy locality;
cost and latency;
source/model independence;
known biases/failure signatures;
tool support;
current health/availability.
```

Fallback is disclosed in result. Dreamer never silently substitutes materially different cost/privacy route.

## I9.11. Clarification routing

```text
active agent exists and question is task-local
  → mailbox/next ELIOT response;

no active agent or decision is normative/irreversible/privacy/security
  → persistent Human attention;

answer absent
  → preserve unknown and use declared safe fallback;

question repeatedly unanswered
  → consolidate into one problem, not notification spam.
```

## I9.12. Human interaction

Human can ask Dreamer through Control Plane:

```text
Orientation or Memory Query;
Architecture / Implementation Query;
Research Query or ELIOT Research handoff;
Conflict / Incident Analysis;
Curation, Maintenance or Memory Repair Request;
configuration explanation/change request;
launch, pause, inspect or replan an external agent/swarm on a selected project.
```

Natural-language chat produces an `OperatorIntentCandidate`, not a direct shell/DB/config command. The UI shows the resolved WorkScope/task, proposed agents/tools, route and actual capability evidence, context/budget, effects, risk, approvals and rollback before execution. Human can edit or reject the plan. Dreamer may answer immediately for read-only orientation, but launch/configuration/maintenance operations follow their normal owners and receipts.

Human sees sources, route, cost, uncertainty and whether result is candidate.

## I9.13. Remote Dreamer gateway

Optional future process `eliot-dream-gateway`.

Allowed:

```text
authenticated bounded question;
predefined WorkScope visibility;
read-only redacted bundle;
answer with citations and gateway-scoped signed references allowed for the remote principal;
audit and security signal.
```

Forbidden:

```text
direct database/retrieval API;
local filesystem/tool access;
write or agent-launch authority;
raw operational telemetry;
broad project enumeration;
secret-bearing bundle.
```

Remote references never expose local `eliot://`, filesystem, blob path, DB key or reusable internal capability. The gateway resolves them through principal-bound, expiring answer resources and re-applies privacy/visibility checks on every expansion.

Remote input always instruction-tainted data. Gateway can be disabled independently.

## I9.14. Researcher boundary

Researcher is defined in I21. Dreamer relationship only:

```text
Dreamer may request an inquiry at a declared evidence grade;
Dreamer receives governed sources, evidence bundles and bounded briefs;
Dreamer interprets and proposes; it does not select the coverage denominator,
  admit a source, freeze evidence or close an inquiry disposition;
a Dreamer synthesis never upgrades the evidence grade of the material it used.
```

Reference firewall: I21.7 · Dispositions: I21.9 · Federation: I21.11 · Providers: I20.5.

## I9.15. Dreamer failure

```text
job fails → candidate absent, source state unchanged;
process crashes → daemon restarts within budget; durable job resumes/reassigns;
model route unavailable → alternate allowed route or blocked/partial response;
invalid output → reject candidate, retain exact diagnostic;
repeated false merge/procedure → lower route/profile and open improvement problem;
budget exhausted → checkpoint, return coverage and recovery directive.
```

No Dreamer failure blocks basic Memory OS/Harness operation. If no Dreamer route is assigned or currently available, the native UI exposes deterministic orientation handles, direct settings/maintenance forms and a typed `ROUTE_UNAVAILABLE` explanation; it never suggests that chat changed the system.

## I9.16. Dreamer quality and job economics

Track per job and per job family:

```text
accepted/rejected/expired candidates;
verified decision, verifier and downstream outcome delta;
false merge/split/procedure and negative transfer;
source coverage, missed material evidence and unresolved uncertainty;
model/agent/swarm calls, raw route usage and retries;
CPU/RAM/storage/network, queue wait, wall latency and Human attention;
context/reconstruction savings without shifted acquisition or recovery cost;
clarification usefulness, backlog age and expiry;
model-route calibration, rollback and invalidation.
```

`DreamerJobEconomics` is a projection of Durable Job, route usage, curation and outcome receipts—not a new owner. A Dreamer route, curation class or autonomous schedule is promoted only when the declared downstream utility exceeds full compute/storage/context/Human cost and measured harms on held-out/live work. An elegant synthesis with no later use or expired validity is not utility. No single intelligence score.

---

## I9.17. Dreamer as ELIOT maintenance agent

Dreamer is the default intelligent service for maintaining ELIOT’s own cognitive quality. It reviews the `eliot_system` experience bank, open Problems, AgentFeedbackReceipts, memory/context quality, stale capabilities and maintenance debt, then proposes a bounded plan to the daemon.

Allowed requests:

```text
run a curation/orientation/diagnostic job;
spawn one agent or an admitted swarm through Agent Coordinator;
ask an external strong agent for bounded diagnosis;
propose route/model/tool/plugin installation or requalification;
propose configuration or maintenance changes;
prepare an ImprovementCandidate or Human decision packet.
```

Dreamer never acts as an unobserved administrator. Every request has an initiating user/problem/policy trigger, exact scope, budget, state fence, expected delta and rollback. Watchdog observes the request, configuration publication, spawned descendants and post-change outcome. A spontaneous or repeatedly ineffective Dreamer action is itself self-scope evidence and may roll back the candidate route/profile or require Human review.

# I10. Agent and tool integrations

## I10.1. Bridge doctrine

Third-party project remains upstream-shaped. ELIOT integration adds:

```text
one process/container boundary when practical;
one thin protocol adapter;
one capability manifest;
one health/failure translation;
one update/removal path.
```

Do not fork or copy internal code unless upstream cannot be used safely and replacement benefit is demonstrated.

## I10.2. Bridge acceptance checklist

Before adding project:

```text
license compatible and recorded;
maintainer/release health acceptable;
Windows execution verified;
headless/noninteractive interface exists;
input/output contract can be bounded;
crash can be isolated;
credentials/effects can be constrained;
version can be detected;
state can be exported/rebuilt;
replacement path exists;
measured value exceeds integration cost.
```

Failure does not automatically reject experimental use; it determines isolation and production status.

## I10.3. Bridge types

```text
MCPBridge      — external MCP server/client;
CliBridge      — supervised subprocess with structured stdout/files;
HttpBridge     — local/remote API;
LspBridge      — language server;
GraphBridge    — code/dependency graph;
ModelBridge    — provider/local model;
StoreBridge    — canonical storage;
AppBridge      — professional software/API;
CloudBridge    — AWS/lab/remote compute;
ResearchBridge — acquisition/indexing corpus.
```

All expose EBP capability contracts to internal system.

### Tool and adapter route selection

Normal exact calls are routed automatically from Capability Registry, WorkScope Profile and current health; the agent is not asked to choose among equivalent tools. A `ToolRouteDecision` is recorded only when the choice is expensive, side-effectful, ambiguous, privacy-sensitive or materially changes proof quality.

Selection considers:

```text
property/capability match and exactness;
truth/evaluation competence;
freshness and health;
State Fence and WorkScope fit;
latency/cost/resource envelope;
side effects and authority;
privacy/source assurance;
known failure profile and overlap with already available evidence;
expected information, decision or verification delta.
```

A call whose expected delta is negligible is skipped or deferred. This is a routing optimization, not a requirement that the Main Agent write an essay before every tool call.

### Execution identity boundary on Windows

Every route profile declares `execution_identity = service | interactive_user | remote`. `interactive_user` routes are launched only through the authorized User Broker of I1.3. A bridge cannot silently switch execution identity to obtain subscriptions, desktop state or credentials.

## I10.4. Codex App Server profile

**Priority:** PRIMARY-1 ELIOT route. **Status:** PROVISIONAL as an ELIOT integration until exact-version, current-account and recovery proof pass. The upstream App Server publishes a stable schema surface and separately gates experimental methods/fields; ELIOT pins the stable-only generated schema by default and admits each experimental operation independently.

Candidate local transport for the P0 pilot:

```text
`codex app-server --listen stdio://`;
JSON-RPC-lite over newline-delimited JSON;
one supervised process or bounded tenancy profile;
exact generated schema pinned to executable hash.
```

It becomes an admitted ELIOT route only after exact-version conformance and recovery tests. The installed generation remains pinned and immediately replaceable because the protocol evolves with the executable; however, ELIOT does not mislabel the stable schema subset as experimental. Any opt-in experimental API stays disabled unless its exact descriptor, capability negotiation, negative tests and rollback path are admitted separately.

WebSocket listener is experimental and not a production dependency. Integration covers thread/turn/item events, approvals, interrupt, result reconciliation and supported native session operations.

Rules:

```text
skills/MCP/config are installed through ELIOT integration lifecycle;
plugin mutation APIs are not a v1 dependency;
native child agents are optional runtime-local accelerators;
child output is candidate evidence, never task completion;
model/effort/service-tier and actual route require receipts/probes;
crash, interrupt, unknown outcome, resume/fork and descendant cleanup are mandatory tests.
```

Codex agent never receives SurrealDB endpoint or canonical write authority.

A ChatGPT-subscription or desktop-profile Codex route declares `execution_identity = interactive_user` and runs through the authorized User Broker. An API-key or otherwise service-safe Codex route may use `execution_identity = service` only when its credentials, retention and network policy are explicitly approved for the service identity. The two are separate `RuntimeRoute` fingerprints and continuity does not transfer silently between them.

## I10.5. Claude routes

Claude local Agent SDK and Claude Managed Agents are separate adapters and fingerprints.

### Local Agent SDK sidecar

**Priority:** P1. Official SDK surface is Python/TypeScript, therefore Rust integration uses an immutable supervised sidecar:

```text
versioned NDJSON/JSON-RPC bridge;
no durable DB or task authority;
exact SDK/runtime versions and native session locator;
tools, permissions, events, cancellation and usage receipts;
secrets materialized only inside the sidecar process.
```

Local transcript/session semantics are not treated as server-managed durability. Agent Teams/native subagents remain experiments behind child-policy probes.

### Managed Agents

**Priority:** P1 remote beta, explicit opt-in.

Separate profile records beta contract, API billing, retention/deletion, environment, session lifecycle, vault references and event stream. A local Claude session cannot be silently continued as a Managed Agent session; it becomes a `Rehydrated` attempt.

## I10.6. OpenCode HTTP/SSE profile

**Priority:** PRIMARY-2 route. **Status:** PROVISIONAL until exact installed server, provider account and event semantics pass RGF-AGENT-ROUTES/RGF-AGENT-ROUTES.

```text
local authenticated server;
public OpenAPI HTTP operations;
global/project SSE event streams;
session create/read/fork/abort/diff/reconcile;
provider/model discovery and actual route receipt;
server bind restricted to loopback profile.
```

OpenCode internal SQLite/Drizzle/storage is not a public recovery contract. Normal reconciliation uses ELIOT attempt journal + health/session/event API + worktree/artifact state. Exact-version read-only forensic snapshots may be used only with explicit degraded receipt and never override contradictory public API evidence.

OpenCode native agents/plugins are optional runtime-local optimizations. ELIOT owns task DAG, budgets, authority and finish.

## I10.7. ACP, Antigravity and generic profiles

### ACP compatibility profile

**Priority:** COMPATIBILITY-1 route. Baseline protocol/session operations are admitted only after provider-free contract tests.

Version rule:

```text
ACP v1 stable line
  production compatibility baseline;
  session load/resume/close and every extension follow negotiated capability markers
  plus an exact adapter/runtime probe;

ACP v2 draft line
  experimental adapter profile only;
  never becomes the default merely because an agent advertises a v2 draft version;
  each operation is feature-gated, version-pinned and rollbackable;
  production promotion requires the specification and SDK line to be declared stable
  and the same ELIOT conformance suite to pass.
```

Every operation that affects continuity, workspace roots, model/mode, MCP, files or reasoning events is challenged by a direct probe on the exact adapter/runtime fingerprint; advertisement alone is not production evidence. ACP agent task/session state remains external runtime state. ELIOT preserves its own attempt, task and evidence lifecycle independently.

### Antigravity local profile

**Priority:** P1 after live probes. Use only documented local SDK/CLI/MCP surfaces through a supervised sidecar or structured process adapter. Do not assume a general remote managed-session API until an official resource/session/event contract is verified.

```text
SDK preferred over PTY/CLI when it exposes structured lifecycle;
PTY/TUI scraping is degraded fallback only;
hooks are observation/defence-in-depth, not root enforcement;
native subagents default-disabled for write/MCP work until inheritance,
cancellation, usage and output contracts pass exact-version probes.
```

### Generic minimum

```text
structured MCP/ACP/HTTP/sidecar/CLI transport;
authenticated attach and exact runtime identity;
working root/scope and route fingerprint;
tool/action observation or explicit observe calls;
cancellation and reconciliation;
finish/checkpoint call;
visible limitations and capability evidence.
```

Tool-only integration supports basic value but cannot claim full enforcement.


## I10.8. Instrument Plane, canonical verification and code intelligence

### I10.8.1. Purpose and ownership

Instrument Plane is the deterministic grounding fabric for development and verification:

```text
Human/Main Agent judgment
→ ELIOT task, authority and context
→ InstrumentProfileResolver
→ InstrumentRunner (control/aggregation)
→ TestExecutionPlane
→ isolated `eliot-testd`
→ one Windows ProcessExecutor semantics
→ exact tools / simulator / component builder
→ EvidenceEnvelope + VerificationReceipt
→ verifier, CodeCortex, Diagnostic Brief and Active View.
```

Canonical ownership:

| Concern | Owner | Forbidden alternative |
|---|---|---|
| tasks, acceptance, leases and finish | Governor | instrument-local task DB or tool self-certification |
| process-launch semantics | `eliot-process-windows` contract/reference implementation; each Kernel/testd/UserBroker supervisor owns its operations/tree | module-specific `Command::new` semantics or a global executor that steals lifecycle ownership |
| instrument definitions/profiles | Instrument Registry | duplicated command maps in PatchRunner/Justfile/CI |
| raw evidence | Blob Store + canonical handles | source-repository log files as authority |
| package graph | Cargo metadata instrument | guessed package relations |
| Rust symbol semantics | admitted rust-analyzer/SCIP backend | regex as primary semantic engine |
| heuristic architecture graph | quarantined/admitted graph adapter | source-of-truth or write authority |
| evidence fusion | CodeCortex compositor | model-written summary as authority |

Instrument Plane has no LLM, memory owner, scheduler or architecture authority. It may invoke deterministic tools only through typed profiles admitted by Governor.

### I10.8.2. IP0 — one Windows ProcessExecutor

All governed external processes use one public facade and one audited Windows semantic implementation. This means one contract/reference code path, **not** one global executor process, thread or mutable operation owner. Kernel owns daemon/module generations, `eliot-testd` owns its build/test descendants, User Broker owns interactive-user descendants, and an admitted module supervisor may own its isolated workers; each uses the same `eliot-process-windows` implementation and evidence format. This section owns the normative behavior. `docs/generated/rust-boundary-interfaces.md` §P.12 preserves one bootstrap **candidate Rust mapping** and is not a second contract owner or proof of source support. The semantic operations are `start`, `inspect`, `cancel` and `reconcile`; `start` receives a governed evidence sink. Only a future interface generated from the admitted catalogue and matched to exact source/API evidence may become an implementation-admission input.

The production Windows implementation is backed by the audited `eliot-windows-ipc` process guardian and provides:

```text
CreateProcessW with explicit executable/argv/env/cwd;
suspended launch and Job Object assignment before resume;
process, image and signer/hash identity;
parent/child/grandchild observation;
concurrent streaming stdout/stderr drain;
wall, idle, memory, CPU and process-count limits;
cancellation with explicit cleanup result;
completion-port lifecycle events;
raw stream storage and bounded previews;
no-orphan outcome or explicit cleanup failure.
```

Every governed launch carries a Kernel-issued `DispatchPermit` inside `ProcessRequest`:

```yaml
DispatchPermit:
  operation_id:
  action_lease_ref:
  state_fence:
  authority_and_generation_epoch:
  expected_revision_heads:
  executable_environment_and_effect_digest:
  expires_at:
  one_shot_nonce:
```

The Windows executor creates the process suspended, assigns the Job Object, resolves the actual image identity, and then asks Kernel to validate the permit against the current fence/epochs/revision heads **before `ResumeThread`**. `ProcessStartReceipt` binds the permit digest, validation revision, actual process/image/Job identity and resume time. Missing/expired/mismatched permits return `DISPATCH_PERMIT_REQUIRED`, `STALE_STATE_FENCE` or `STALE_AUTHORITY_EPOCH`; a child is never resumed on a stale pre-launch check.

The Kernel round trip applies at the authority/process-tree boundary, not to every descendant spawned by Cargo, a browser or another already admitted tool. Descendants remain inside the admitted Job Object/resource/effect envelope and are observed as lineage; an unexpected escape or effect is a failure.

For a deterministic multi-stage `TestdJob` or equivalent profile, Kernel activates one immutable `ProcessExecutionGrant` covering the exact profile DAG, executable allowlist, environment, resource envelope, State Fence and expiry. The owning testd/module supervisor may derive one-shot stage nonces under that grant without contacting Kernel for every compiler/test command; it cannot change executable class, effects, roots or budget. Revocation/epoch change invalidates unused stage nonces and stops new stages. Thus control remains explicit without turning Kernel into a per-process scheduling bottleneck.


Direct `std::process::Command`, `tokio::process::Command` or shell launch is forbidden outside:

```text
minimal bootstrapping needed to start Host/Kernel;
ProcessExecutor implementation;
test-only fixtures explicitly marked as such.
```

`clippy.toml` / workspace lint uses `disallowed-methods` for direct process-spawn APIs outside the allowlist, supplemented by source audit for aliases/wrappers. Process failure never becomes a product/test verdict until an instrument parser interprets the exact outcome.

### I10.8.3. IP1 — typed, extensible instrument contracts

Executable authority comes from an admitted `InstrumentSpec`, never from model-authored command text. The stable core distinguishes a small semantic class from a replaceable concrete kind:

```rust
pub enum InstrumentClass {
    SourceIdentity,
    Compiler,
    Test,
    SemanticIndex,
    HeuristicAnalysis,
    RuntimeDiagnostic,
    SecurityDependency,
    Concurrency,
    UnsafeFfi,
    Performance,
}

pub struct InstrumentSpec {
    pub kind_id: InstrumentKindId,          // opaque, versioned identifier
    pub class: InstrumentClass,
    pub executable: ExecutableRef,
    pub invocation_schema_ref: SchemaRef,
    pub fixed_or_validated_arguments: Vec<OsString>,
    pub environment_profile: EnvironmentProfileId,
    pub parser_id: ParserId,
    pub timeout_policy: TimeoutPolicy,
    pub resource_limits: ResourceLimits,
    pub authority_class: EvidenceAuthorityClass,
    pub negative_result_contract: NegativeResultContract,
    pub network_policy: NetworkPolicy,
    pub credential_policy: CredentialPolicy,
}
```

Built-in kinds are registered initially:

```text
cargo-metadata; cargo-clippy; rustfmt-check;
nextest-list; nextest-run; rust-analyzer-scip; ripgrep-json;
codebase-memory-index; codebase-memory-query;
cargo-llvm-cov; cargo-mutants; cargo-deny; cargo-hack; cargo-shear;
loom-test; shuttle-test; turmoil-sim; madsim-sim; eliot-sim-replay;
miri-test; cargo-careful; cargo-fuzz;
component-build-wasip2; component-inspect; component-conformance; component-shadow-compare;
criterion-bench; hyperfine-bench;
windows-etw-capture; windows-procdump; windows-process-scenario.
```

A new kind does not require changing Kernel or the semantic class enum. It is admitted through a versioned Module/Instrument manifest with:

```text
exact executable identity and supply-chain receipt;
argument schema and fixed command template;
parser generation;
environment/resource/credential policy;
evidence authority, freshness and coverage semantics;
negative-result contract;
golden and process-fault suite;
removal and replacement boundary.
```

Unregistered kind IDs, arbitrary shell text and agent-supplied executable/argv combinations fail before launch. Dynamic extensibility therefore does not become arbitrary command execution. Parser and profile generations can be replaced independently through normal Module/daemon cutover; no Rust DLL ABI is introduced.

Generic short adapters and long-running instruments remain different contracts. Each adapter/instrument has its own semaphore and circuit state; a system-wide resource pool never overrides the module's declared maximum concurrency.

### I10.8.4. IP2 — InstrumentRunner

`InstrumentRunner` performs deterministic orchestration only:

```text
resolve exact InstrumentProfile revision;
resolve and verify executable/component/simulator identities;
resolve WorkScope, candidate, target layout and environment;
submit each external/build/test stage through `TestExecutionPlane` under a durable stage identity;
allow only explicitly pure in-process transforms to bypass testd;
observe/reconcile stage state independently of the requesting transport;
receive testd streaming/parser checkpoints and raw evidence handles;
write one InstrumentRun per stage;
aggregate VerificationProfileRun or DiagnosticBrief input;
submit canonical observations through the ordinary governed write path.
```

One logical InstrumentRunner means one canonical profile/admission/result path, not one global thread, one process or one giant tool-specific struct. `eliot-testd` executes admitted external stages and uses `ProcessExecutor`; InstrumentRunner never recreates tool launch semantics. Profile stages form a bounded DAG:

```text
independent stages may run concurrently;
causally dependent stages remain ordered;
identical build stages use single-flight by exact build fingerprint;
one target root has one build-coordination owner;
no DB transaction, ordering slot or global lock is held while a tool runs;
tool-specific logic remains in profile, parser and executable micro-modules.
```

`BuildExecutionKey` includes workspace, worktree/candidate, toolchain, feature/profile set, environment and build class. An artifact may be reused only under an exact compatible key and evidence receipt. This avoids hundreds of agents launching duplicate or mutually blocking Cargo builds while preserving worktree isolation.

It does not:

```text
invent commands from natural language;
choose architecture or task goal;
run arbitrary shell verifier strings supplied by an agent;
mark a claim verified or task complete;
accept a tool's own freshness/completeness claim without validation;
hide failed/missing stages behind a successful aggregate.
```

The same profile compiler is used by:

```text
local verify/inspect/assist;
agent verifier requests;
external patch candidate verification;
Justfile wrappers;
CI;
FinishService verifier binding.
```

No fifth verification path is permitted.

### I10.8.5. IP3 — streaming evidence and normalization

`ProcessExecutor` streams stdout/stderr concurrently:

```text
process stream
→ bounded preview ring;
→ incremental parser;
→ append-only temporary raw evidence object;
→ final BlobRef + digest + truncation/parse metadata.
```

Independent limits exist for preview bytes, stored raw bytes, event count, line length, idle/wall time and Job Object resources. Pipe saturation must not deadlock the child. Truncation is explicit evidence, never silent.

Every normalized result is an `EvidenceEnvelope` with independent dimensions:

```text
Authority:
  source identity | compiler/language | compiler-derived semantics |
  deterministic runtime/test | heuristic static | model interpretation;

Freshness:
  exact_candidate | exact_commit | exact_quiesced_worktree |
  known_older_snapshot | stale | unknown;

Coverage:
  complete_for_scope | partial_for_scope | not_applicable | unknown;

Provenance:
  executable hash/version/file identity;
  config/environment/feature/toolchain hash;
  WorkScope/base/candidate/worktree;
  invocation and profile revision;
  start/finish/resource outcome;
  raw evidence handles.
```

Authority is property-relative, not a universal scalar. Rust compiler evidence outranks a heuristic parser for type validity; a runtime test outranks static inference for the observed behavior it actually exercises.

### I10.8.6. Negative-result contract

Absence is a fact only when all conditions hold:

```text
freshness is exact for the candidate and scope;
coverage is complete for the queried relation/scope;
the instrument contract can prove absence;
no higher-authority contradictory evidence exists.
```

Otherwise ELIOT returns a typed unknown such as:

```text
not_found_in_partial_index;
unknown_due_to_staleness;
unknown_due_to_cfg_or_macro_coverage;
unknown_due_to_worktree_overlay;
unknown_due_to_truncation_or_tool_failure.
```

Statements such as `no callers`, `dead symbol`, `no dependents` and `change cannot affect X` never arise from incomplete heuristic evidence.

### I10.8.7. IP4 — instrument profiles

A profile is a versioned deterministic recipe:

```yaml
InstrumentProfile:
  profile_id:
  task_or_change_triggers:
  required_and_optional_instruments:
  stage_dependencies:
  selection_rules:
  target_layout:
  resource_and_timeout_policy:
  parsers:
  evidence_authority_and_coverage:
  negative_result_semantics:
  ranking_and_compaction:
  success_partial_failure_rules:
  exact_rerun_contract:
  context_projection:
```

Initial profiles:

| Profile | Instruments | Purpose |
|---|---|---|
| `compiler` | Cargo metadata, rustc/Clippy JSON, `rustc --explain` on demand | exact compilation/type/lint failures |
| `test` | nextest list JSON, affected nextest/JUnit, exact rerun | discovered tests, failures, hangs and runtime evidence |
| `snapshot` | approved snapshot framework in exploratory/sealed modes | exact expected/actual artifact difference |
| `test-strength` | base/candidate probe, changed-line coverage, selected mutation | detect green tests that do not exercise the change |
| `architecture` | Git, full Cargo graph, rust-analyzer/SCIP, optional heuristic scout | ownership, references, implementations and impact candidates |
| `dependency` | cargo-deny/hack and admitted unused-dependency analyzer | features, advisories, licenses and dependency hygiene |
| `concurrency` | Loom, Shuttle/paused time where admitted | ordering, cancellation, deadlock and retry invariants |
| `unsafe-ffi` | Miri, careful/sanitizer/fuzz/formal tools where supported | unsafe/FFI boundary evidence |
| `windows-runtime` | Job Object observer, ETW/WPR/ProcDump and fixtures | process, service, pipe and cleanup failures |
| `performance` | Criterion/Divan, hyperfine and admitted allocation/ETW probes | workload-bound regression evidence |

Profiles are added only when observed failure or product need justifies them. A profile is not another model agent.

### I10.8.8. IP5 — Rust understanding stack

Rust code understanding uses layered evidence:

```text
Layer A: Git and Cargo
  exact candidate identity, changed files, package/target/feature graph,
  reverse package dependencies and affected test binaries;

Layer B: pinned rust-analyzer/SCIP
  definitions, references and implementations on an exact quiesced candidate;

Layer C: optional heuristic scout
  Codebase Memory or another admitted graph for architecture clusters,
  candidate paths and exploration reduction;

Layer D: CodeCortex compositor
  task-relative fusion with ELIOT decisions, invariants, failures,
  diagnostics, runtime observations and verifiers.
```

Rules:

```text
Cargo metadata is parsed through a maintained Rust library, not ad-hoc traversal;
clean tracked files use Git tree/index identity; only dirty/untracked content is rehashed;
rust-analyzer/SCIP starts one-shot on exact candidate before persistent LSP is considered;
rustc/Clippy remain build/type authority; rust-analyzer supplies navigation evidence;
heuristic graphs are optional and never authorize writes or prove negative facts;
all graph outputs carry adapter build, candidate identity, freshness and coverage;
CodeCortex does not parse Rust through hard-coded regexes or invent invariant cards.
```

A Codebase Memory pilot, if admitted, runs as a pinned CLI process under ProcessExecutor with isolated cache, no host installation, no hooks/Skills/ADR/UI/daemon/watcher and read-only query subset. It remains heuristic until the ELIOT golden suite proves freshness, worktree identity, negative-result correctness and resource cleanup.

### I10.8.9. Agent-facing projection

Instrument Plane does not add dozens of hot tools. The existing `eliot.query`/`eliot.verify` surface exposes four semantic intents:

```text
verify(profile, scope);
inspect(definition|references|implementations|impact|tests|architecture, target);
assist(compiler|test-strength|concurrency|windows-runtime|dependency|performance, target);
evidence(handle, bounded slice).
```

The result contains compact facts, primary failures, conflicts, unknowns, exact reruns and unexpanded raw handles. Backend names are hidden unless the agent diagnoses disagreement or asks for provenance.

An agent may run a direct shell command for exploratory feedback when its host policy allows it. Such output is captured as an observation with the actual Governance Profile; it does not satisfy a registered verifier or finish obligation merely because the command exited successfully. Canonical proof requires either re-execution through the applicable InstrumentProfile or exact ProcessEvidence imported through the same profile contract. Watchdog treats an attempt to present an ungoverned shell result as canonical proof as a protocol-discipline signal, not as an automatic security Incident.

### I10.8.10. Migration from overlapping verification paths

Current migration source contains overlapping high-level verification, patch verification, repository automation and CI definitions. They converge on one InstrumentRunner:

```text
high-level verification domain
  → profile/result types and reporting over actual InstrumentRuns;

PatchRunner
  → disposable worktree/candidate handling only;
  → no private command map and no reverse-patch transaction illusion;

Justfile and CI
  → thin invokers of the same named profile;

CodeCortex
  → consumes existing instrument evidence; does not rerun diagnostics privately.
```

Synthetic successful command records, synthetic flake reports, hard-coded baseline pass text, hard-coded CodeCortex invariants and static test inventory as authority are removed or quarantined. Normal agent edits happen in leased worktrees; external patch candidates are applied and verified in disposable worktrees, then promoted as an IntegrationCandidate.

Path identity preserves case. Existing paths use handle-derived Windows/file/Git identity when equality or security matters; proposed paths use traversal-safe lexical normalization without lowercasing.

### I10.8.11. Instrument failure and replacement

Each parser, profile, executable adapter and optional code-intelligence backend is a micro-module under I2.16. Failure localizes to the affected profile/stage:

```text
required instrument unavailable
  → profile partial/failed with explicit missing proof;

optional instrument unavailable
  → reduced coverage and typed unknown;

parser incompatible
  → raw evidence preserved, normalized result unavailable;

process cleanup failure
  → Problem/Incident, route quarantine and no false pass;

stale code index
  → stale evidence; no negative fact;

replacement
  → new immutable tool/profile/parser generation, golden contract tests,
     shadow/canary and revisioned cutover.
```

Instrument evidence never outlives its executable, config, candidate and parser dependency set without revalidation.


### I10.8.12. Source ownership and first crate extraction wave

The current repository begins with five broad crates, but the target Instrument Plane is crate-first under I2. The migration does not create a parallel product; it extracts existing responsibilities into narrower packages inside the same Cargo workspace.

First extraction ownership:

```text
eliot-types
  → eliot-contracts / eliot-evidence / eliot-receipts;
  → eliot-instrument-api;
  → stable data-only foundation contracts;

eliot-windows-ipc
  → eliot-platform-windows / eliot-process / eliot-ipc;
  → the single platform-specific unsafe/process boundary;

eliot-engine
  → eliot-instrument-runner;
  → eliot-instrument-cargo / nextest / rustc / rustfmt / scip;
  → eliot-code-graph / eliot-code-cortex / eliot-build-test-graph / eliot-test-selection;

eliot-app
  → eliot-cli and thin process composition targets;
  → no verification/process/domain logic.
```

Initial source layout:

```text
crates/foundation/eliot-evidence/
crates/foundation/eliot-receipts/
crates/instrument/eliot-instrument-api/
crates/kernel/eliot-process/
crates/kernel/eliot-platform-windows/
crates/instrument/eliot-process-executor/
crates/instrument/eliot-instrument-runner/
crates/instrument/eliot-instrument-rustc/
crates/instrument/eliot-instrument-nextest/
crates/instrument/eliot-instrument-scip/
crates/instrument/eliot-code-graph/
crates/instrument/eliot-code-cortex/
crates/instrument/eliot-build-test-graph/
crates/surfaces/eliot-cli/
```

Existing `verification.rs`, `patch.rs`, `codecortex.rs`, process helpers and command definitions are migrated into these crates or reduced to compatibility facades during one bounded transition. They do not remain alternative owners.

Migration order:

```text
1. freeze current public behavior and raw evidence fixtures;
2. extract stable contract crates;
3. extract ProcessExecutor boundary;
4. extract InstrumentRunner and parsers;
5. redirect high-level verification, PatchRunner, Justfile and CI;
6. extract code-intelligence backends/compositor;
7. remove old private execution/parsing paths;
8. compare CrateBuildProfile and CrateContextProfile before/after.
```

Acceptance requires:

```text
no duplicate process semantics;
no duplicate verification profile authority;
package-selective tests for every extracted crate;
real-edge tests through ProcessExecutor;
smaller AgentWorkUnitBrief context than the old broad crate;
no regression in product pulse;
old facade can be deleted without losing behavior.
```

The target split is a DEFAULT. Exact package names may change after CURRENT_SYSTEM_AUDIT, but the ownership and context boundaries may not be collapsed back into one Instrument/CLI hotspot without evidence.

### I10.8.13. Durable Instrument job lifecycle

A profile run is a specialization of the one canonical Durable Job machine in I14.20; it does not define a competing execution lifecycle.

Canonical job state remains:

```text
NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED
→ VERIFYING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | STALE | UNKNOWN_OUTCOME.
```

Instrument-specific progress is an orthogonal `InstrumentPhase`:

```text
RESOLVING
→ PROVISIONING
→ RUNNING_STAGE
→ PARSING
→ FINALIZING.
```

Each stage has:

```text
stable stage/operation identity;
profile and InstrumentSpec revision;
candidate/State Fence;
ProcessExecutor operation ref;
raw stream and parser checkpoint;
resource reservation;
result/disposition.
```

Runner/daemon restart behavior:

```text
process still owned and observable
  → reconcile ProcessEvidence and continue/finalize;

process terminated with proven no effect
  → retry under the same stage identity according to profile;

outcome unknown or generated external artifact ambiguous
  → UNKNOWN_OUTCOME, block only dependent profile/acceptance and reconcile;

parser failed after raw capture
  → preserve raw evidence, rerun parser generation without rerunning tool when safe.
```

No detached compiler/test/index process survives loss of its owned job lineage. Re-execution never hides the first failed/unknown attempt.

### I10.8.14. Build artifact and evidence reuse

Build artifacts may be reused only by an exact `BuildFingerprint`:

```text
source/candidate identity;
Cargo lock and relevant manifests;
toolchain and executable identity;
features/targets/profile;
environment and build-script inputs;
target/build class;
contract/profile revision.
```

Reuse rules:

```text
cached compilation artifact may avoid recompilation when fingerprint is exact;
cache hit carries provenance and does not create a new compiler observation by itself;
test verdict is not reused merely because the binary is cached;
raw evidence/result may be reused only under its explicit dependency/freshness contract;
unknown build-script/environment input disables authoritative reuse;
cache corruption or identity mismatch deletes/quarantines only the affected entry.
```

Compiler cache is a performance organ, not a truth owner. It can reduce build time without changing Instrument profile semantics.

### I10.8.15. IP7 — isolated `eliot-testd` execution plane

`InstrumentRunner` remains the canonical profile coordinator in `eliotd`; `eliot-testd` is a replaceable native execution service. This split keeps compilation, proc macros, linkers, large outputs, fuzzers and simulators outside the control plane.

```text
InstrumentRunner
  owns profile resolution, stage graph, durable job relation and evidence aggregation;

eliot-testd
  owns worktree/sandbox provisioning, toolchain/cache access, concrete stage execution,
  streaming parsers, component builds and simulation workers;

ProcessExecutor
  owns Windows process-tree semantics for every launched tool;

Governor
  owns evidence admission, verifier applicability and finish.
```

Minimal service cells:

```text
worktree manager;
build-sandbox manager;
toolchain/executable registry;
dependency/cache manager;
Cargo/nextest runner;
diagnostic normalizers;
test scheduler;
simulation runner;
WASM component builder;
generation publisher client;
artifact/receipt client.
```

`TestdJobRequest` is typed and references an immutable Instrument/Profile revision. It cannot contain a free-form shell string. Tool surfaces exposed through `eliot.verify` remain intents (`crate-fast`, `component-conformance`, `sim-replay`, `trace-inspect`), not dozens of independent MCP authorities.

`eliot-testd` uses dedicated resource pools:

```text
interactive check/test;
verification;
component build;
simulation/concurrency;
fuzz/mutation/coverage/nightly.
```

Load shedding stops background and speculative jobs before control-plane work. Restart reuses only exact BuildFingerprint artifacts and parser checkpoints; unknown tool outcome is reconciled, not blindly rerun.

### I10.8.16. IP8 — component build and generation promotion service

Component build is an Instrument profile family, not a second deployment authority.

```text
source/worktree candidate
→ build native core tests
→ compile `wasm32-wasip2` Component
→ inspect WIT/interface digest and imports
→ run common conformance/differential corpus
→ recorded deterministic replay
→ publish immutable GenerationManifest
→ shadow comparison
→ canary under Governor policy
→ ORS route cutover / Authority Epoch
→ rollback by forward route switch when required.
```

The builder signs or hashes the artifact set, records toolchain/lockfile/dependency provenance and returns a `GenerationCandidateReceipt`. It cannot activate a generation. Activation is a Kernel/Governor operation under I14.19 and I14.20.

WASI 0.3/`wasm32-wasip3`, AOT strategy, pooling and native promotion are separate empirical profiles. The production baseline remains `wasm32-wasip2` until the same corpus passes on Windows with the exact pinned Wasmtime generation.


### I10.8.17. Code-intelligence capability planes and query semantics

Code intelligence is routed by capability, not by product brand:

```text
source/semantic graph
  exact source, Cargo ownership, definitions/references/implementations;

build/execution/verifier graph
  packages, targets, features/configurations, build scripts, artifacts,
  runners, tests, registered verifiers and coverage edges;

behavioral/history graph
  co-change, churn, hotspots, ownership, fix episodes and drift;

episodic/history projection
  governed Git/session episodes and decision provenance.
```

Each projection is rebuildable and has one selected lifecycle owner for one source/index root. Two always-on watchers over the same root are forbidden outside an explicit comparison experiment.

`QueryIntent` determines stale and assurance semantics:

```yaml
QueryIntent:
  mode: current_position | historical_reconstruction | provenance |
        navigation | verification | change_impact | context_reconstruction
  time_scope:
  branch_environment_scope:
  freshness_policy:
  required_assurance:
```

A stale episode may be valid history and invalid current evidence. A navigation lead may be useful and not evidence.

Result types do not collapse:

```yaml
NavigationCandidate:
  locator:
  why_ranked:
  coverage_state:
  not_evidence: true

EvidenceAtom:
  exact_source_ref:
  exact_anchor:
  observed_scope:
  assurance:

AmbiguitySet:
  query:
  candidates:
  disambiguation_evidence:
  continuation_handles:
```

An unresolved set returns `AMBIGUOUS_RESULT` with all admissible candidates and the cheapest available disambiguation probe. No adapter or Governor projection silently selects the first match.

Coverage/absence is a closed algebra:

```text
complete;
partial;
ambiguous;
stale;
no_index;
no_map;
unknown;
not_applicable.
```

An empty list is never interpreted without this discriminator. Downstream assurance cannot exceed upstream coverage.

`AssuranceCeiling` records:

```text
upstream coverage;
coordinate basis;
approximation kind;
permitted uses;
prohibited uses.
```

Historical/current coordinate conversions are labeled approximate unless exact identity is proven.


Every graph/index query is bound to the canonical `GraphRevisionFence` and publication contract of I5.8. Code-intelligence resolution adds the exact Product/worktree overlay, parser/LSP/build profile, covered relation/configuration scope and reference fallback as dependencies of that fence.

`STALE`, `SPLIT_VIEW`, `FAILED` or unknown coverage cannot prove absence, non-impact or safe deletion. The caller either falls back to exact source/build/verifier evidence, widens the proof tier or returns an explicit unknown.

Scope, authority and disclosure are enforced **before candidate generation and at every structural transformation**, not only when the final packet is rendered. The selection-integrity chain receipt defined in I12.13 covers:

```text
initial source/candidate set;
graph expansion or pivot;
community/cluster selection;
rerank and pruning;
summary/capsule generation;
context compilation;
tool/export delivery.
```

It records admitted and rejected candidates, scope/disclosure closure, transformation lineage and whether untrusted structure changed membership. Unauthorized retrieval, selection-integrity harm and later behavioral contamination are separate outcomes; final-output filtering cannot cleanse an earlier unauthorized selection path.

### I10.8.18. Derived-index reference path, impact directives and source views

Every load-bearing optimized projection has:

```text
an exact or slower reference implementation;
differential agreement tests;
rebuild/repair procedure;
query-plan/index-use assertion where applicable;
visible fallback/degraded state;
no confident empty result on index failure.
```

An optimized index may reduce latency; it cannot become a second truth owner.

The build/test plane materializes two linked derived graphs:

```text
BuildExecutionGraph:
  workspace/package/target/feature/configuration/build-script/artifact/runner;

VerifierCoverageGraph:
  test/verifier → exact artifact/code/property/configuration/time scope.
```

Edges carry source revision, tool/profile generation, coordinate basis, coverage and assurance. Filename-pattern guesses are separate from coverage evidence. `no_map` means unknown and triggers broader verification according to policy.

Agent-facing change analysis prefers directives over a composite score:

```yaml
ChangeImpactDirective:
  structural_breaks:
  behavioral_drift_candidates:
  missing_expected_cochanges:
  impacted_verifiers_exact:
  missing_tests:
  unknown_coverage:
  required_broader_profile:
  evidence_refs:
```

`will_break` requires structural/contract evidence. Co-change can only say `may drift`.

Any graph-assisted development/evaluation result preserves one bounded use trace inside existing code-intelligence receipts:

```text
graph composition/definition/source fence;
advertised → eligible → called → delivered → observably used;
first exact source read, first edit boundary and first verifier;
no-graph/exact-reference baseline where benefit is claimed;
total tokens/cache/latency and additional process/index cost;
clean→stale and pass→fail harm, ambiguous/unknown/no-map outcomes;
paired artifact/verifier result and scoped ablation status.
```

Graph benefit is scoped to the exact composition/profile. `ABLATION_SUPPORTED` does not make graph output truth or understanding. A stale-edge fault corpus must include wrong-action and missed-impact cases; publication is blocked by the `GraphRevisionFence` defined in I5.8.

Task-shaped code views support batch targets with per-target isolation:

```text
successful;
failed;
cancelled;
stale;
ambiguous;
omitted;
shared State Fence.
```

`SourceSkeleton` is a navigation projection:

```text
imports;
all signatures/declarations;
selected exact bodies;
line-numbered omitted ranges;
selection trace;
source checksum/parser generation/freshness.
```

Before a broad edit, the agent receives a full-read or AST-aware-edit requirement when the skeleton does not prove sufficient coverage.

Analysis depth is adaptive:

```text
high danger/centrality/recent demand
  → deeper analysis and shorter freshness objective;

stable peripheral code
  → cheap card/handle.
```

Depth never raises epistemic status.

Cross-repository work is limited initially to contract/conformance diagnostics:

```text
unmatched consumer/provider;
weak or inferred integration;
incompatible contract change;
orphan implementation;
Architecture/Implementation conformance gap.
```

A generic global map/dashboard remains optional.


Projection maintenance uses the canonical `ProjectionMaintenanceDecision` of I5.8. For code-intelligence projections its measured inputs include the whole dependency-DAG cost, changed/rewritten fraction, logical and storage write amplification where observable, tail latency, source churn, same-fence equality oracle, reference fallback and rollback plan. Incremental work is never presumed cheaper merely because fewer source rows changed.

A delta candidate that fails the equality oracle, loses dependency lineage or produces a split view is discarded and rebuilt from the reference path. The active graph generation never mixes data from one fence with provenance from another.

Graph value is measured against a matched exact/no-graph baseline. The evaluation records total graph construction/query/context cost, actual advertisement→call→use, first source read/edit, first verifier, stale-edge actions and pass→fail harm. A graph arm may improve navigation while remaining unqualified for causal, absence or authorization claims.

### I10.8.19. Code-intelligence adapter arbitration and RepoWise pilot

`CapabilityRouteDecision` is the code-intelligence specialization of the existing `ToolRouteDecision`; it does not create another scheduler, policy owner or durable decision family. It selects the owner for one query family and packet generation:

```yaml
CapabilityRouteDecision:
  capability:
  query_intent:
  scope_and_source_fence:
  policy_and_capability_registry_revisions:
  candidates:
    - adapter_id:
      coverage_state:
      generation:
      assurance_ceiling:
      expected_cost:
      known_failures:
  selected_owner:
  fallback_owner:
  disagreement_policy:
  evidence_required:
  validity_and_invalidation:
  decision_receipt_ref:
```

A common adapter manifest includes executable/protocol hashes, index generation, source revision, dirty-state/cache-root identity, coverage, parser failures, response budget, lifecycle owner, network and license profile.

A common result envelope includes:

```text
capability/query intent;
adapter/generation/source fence;
complete/partial/ambiguous/stale/unavailable/unknown status;
navigation candidates;
evidence atoms;
derived relations;
impact directives;
ambiguity sets;
coverage and approximation;
omission handles;
raw result reference;
authority = derived observation.
```

Disagreement preserves both observations, compares source fences/coverage and requests the cheapest discriminative probe. Confidence values are never averaged into truth.

RepoWise and `codebase-memory-mcp` are admitted only as supervised derived adapters:

```text
pinned immutable artifact and license record;
isolated cache root;
read-mostly capability subset;
no direct ELIOT write;
no direct agent hooks/Skills/ADR mutation;
no generated answer as proof;
no `safe_to_delete` authority;
no second auto-watch owner;
no broad generated wiki injection;
no Python/third-party dependency in Kernel or semantic core.
```

RepoWise is especially valuable as a donor/pilot arm for session episodes, Git behavior, reversible payloads, source skeletons, risk/test directives and context delivery. `codebase-memory-mcp` is a competing/overlapping source-semantic graph arm. Capability ownership is selected by a sealed pilot over real Rust/ELIOT tasks, coverage, freshness, resource use, failure recovery and agent decision delta. Neither receives monopoly by README claim.

AGPL or other restrictive code is not copied into ELIOT. Process separation is an architectural isolation boundary, not a license exemption. Redistribution, packaging or hosted use requires a separate license review; until admitted, a pilot uses a user-supplied or maintainer-local pinned artifact and publishes no donor code. Selected mechanisms are reimplemented clean-room in first-party contracts.


### Bulk mechanics execute as a program, not as model turns

When a task requires many similar operations — fan-out over queries, filtering, joins, deduplication, normalization or per-item extraction — a turn-per-operation loop is the wrong shape. Each operation costs one inference round trip, intermediate candidates pollute context, one failure can end the whole trajectory, and mechanical work is performed semantically.

The admitted shape separates three responsibilities:

```text
the route proposes the semantic strategy and the shape of the result;
a deterministic bounded program executes the repetitive mechanics inside the Instrument Plane;
only samples, aggregates, errors and selected evidence return to the model context.
```

The program is an instrument invocation with the normal contract: exact executable identity, bounded resources, cancellation, per-item failure isolation, durable intermediate artifacts and an `EvidenceEnvelope`. It receives no ambient authority, and per-branch failure never discards successful siblings.

This shifts mechanics out of the model loop; it does not remove the need for evidence, coverage accounting or verification. A generated program can be efficient and still retrieve the wrong sources.

## I10.9. Git bridge

Uses typed Git instrument/bridge operations through the shared ProcessExecutor (or an admitted in-process read-only library facade):

```text
status/branch/commit/diff;
worktree create/remove;
apply/check patch;
blame/log/co-change mining;
change manifest;
base drift.
```

No hidden `reset --hard` or destruction of human dirty changes. The bridge executes under the resource's declared execution identity. User-owned roots use a broker-launched scoped Git adapter unless explicit ACL policy admits the service identity; operation receipts preserve SID, root and worktree/environment lease.

## I10.10. LSP and diagnostics

Rust semantic navigation defaults to one-shot rust-analyzer/SCIP under Instrument Plane until a measured persistent-session profile is admitted. Other LSP processes may be shared per workspace/language where safe. Bridge normalizes:

```text
definition/reference;
diagnostics;
symbols;
rename/edits as candidates;
server health/version/config hash.
```

Diagnostics are Instrument/Tool observations with exact executable, config, candidate, freshness and coverage; they are not model facts and are not rerun privately by CodeCortex.

## I10.11. External model bridges

Each provider/model adapter:

```text
receives bounded model-neutral job;
translates tools/messages under a versioned serializer contract;
reports requested and observed route separately;
reports structured usage/quota/cost with source and missing-data state;
preserves required reasoning/tool continuation semantics for that fingerprint;
obeys data/privacy policy;
returns candidate artifact, raw native events and provider receipt;
can be disabled, quarantined or replaced independently.
```

A model ID is not a route identity. Harness, serializer, auth/billing surface, reasoning mode and continuation behavior are part of `RouteFingerprint`.

### DeepSeek/OpenCode Go candidate route

`DeepSeek V4 Flash` through OpenCode Go is an **Empirical Route Profile**, not a capability inferred from the checkpoint name. Admission requires RGF-AGENT-ROUTES and an exact fingerprint covering provider endpoint, OpenCode/runtime version, serializer/chat template, tool-role ordering, reasoning mode, reasoning-continuation preservation, compaction and auth/quota surface.

Mandatory pilot probes:

```text
multi-turn tool call → tool result → continued reasoning/tool call;
reasoning/assistant continuation survives the host serializer as required by the route;
actual provider/model and missing fields are reported honestly;
context/output limits and compaction are measured rather than inferred from advertised capacity;
quota/reset/usage are sourced and never treated as zero when unavailable;
controlled implementation tasks are compared with an equal-stack fallback route.
```

Until the pilot demonstrates architecture/planning and verification quality, the route is eligible mainly for bounded implementation, read-only scouting and broad inexpensive coverage. It does not become sole Task Controller, Architecture authority or independent verifier by price or advertised context size.


### Provider protocol translation and physical model-attempt boundary

Provider protocol conversion is a replaceable bridge capability, not a property of canonical memory. ELIOT owns a provider-neutral runtime IR and never re-exports an upstream project's decision or session types as domain contracts.

```yaml
ProviderPayloadHandle:
  artifact_digest_and_wire_format:
  privacy_disclosure_and_retention:
  producer_route_and_generation:
  exact_raw_or_deterministically_redacted_representation:

TranslationPolicyProfile:
  profile: EXPLORATORY | AGENT_TOOLING | PROOF_BEARING | SAME_FORMAT_EXACT
  unknown_field_policy:
  lossy_conversion_policy:
  identifier_policy:
  preservation_policy:
  target_capability_requirements:

TranslationReceipt:
  source_and_target_wire_formats:
  codec_and_policy_revisions:
  source_normalized_and_target_digests:
  diagnostics_refs:
  loss_class:
  event_order_changes:
  synthetic_reconstruction:
  exact_replay_used:
  preservation_generation_and_invalidated_by_mutation:
  omission_and_recovery_handles:
```

A normalized mutation automatically invalidates exact preserved replay. Convenience APIs that discard diagnostics are forbidden on load-bearing paths. Buffered↔stream conversion, tool-argument repair, unknown-block dropping, output-index collapse and event reordering are explicit transformations with proof ceilings.

Large provider inputs are immutable content-addressed bundles or shared read-only buffers plus a small target-specific overlay; adapters do not deep-clone a 100k+ context tree for every classifier, retry or fallback. Raw payload remains behind `ProviderPayloadHandle`, and every derived target representation is linked by `TranslationReceipt`.

Within one provider event boundary, reasoning/thinking deltas precede visible answer deltas unless the source protocol explicitly defines otherwise. Once visible answer content begins, a translator may not silently reopen reasoning. Cross-format ordering is covered by differential/property/fuzz tests.

Routing and execution are separate. `ModelAttemptRole` is a typed enum (`CLASSIFIER | JUDGE | ANSWER | RETRY | FALLBACK | AUDIT | TOKEN_COUNT | SHADOW`) and is never encoded only in free-text rationale.

```yaml
RoutingContextBundle:
  decision_turn:
  goal_and_acceptance_revisions:
  current_query_or_work_unit_handle:
  operational_signals_and_required_capabilities:
  privacy_budget_and_state_fence:
  admitted_background_evidence_handles:
  context_recipe_and_compiler_revision:

ModelCallIntent:
  logical_decision_ref:
  attempt_role: ModelAttemptRole
  routing_context_bundle_ref:
  provider_neutral_input_bundle:
  introduced_tools_and_semantics:
  requested_route_and_deadlines:
  privacy_cost_authority_and_state_fence:

PhysicalModelAttemptReceipt:
  attempt_and_logical_decision_ids:
  requested_and_observed_route_fingerprints:
  request_digest_and_translation_receipt:
  start_first_byte_first_semantic_and_terminal_times:
  cancellation_and_unknown_outcome_disposition:
  provider_status_usage_and_cost:
  safe_public_error:
  restricted_raw_error_artifact:
```

The existing `RoutingReceipt` is the single canonical logical route-decision receipt (the Switchyard research calls the same role `LogicalRouteDecisionReceipt`). It records:

```yaml
RoutingReceipt:
  decision_id_and_decision_turn:
  route_assessment_candidate_ref:
  requested_route_and_selected_route:
  considered_alternatives_and_dispositions:
  decision_source: SIGNAL | JUDGE | ABSTAIN | TIMEOUT | INVALID | DEFAULT | MANUAL | CONTEXT_FALLBACK | PROVIDER_FALLBACK
  privacy_and_cost_admission:
  policy_context_recipe_and_compiler_revisions:
  state_fence:
  pinned_until_boundary:
  evidence_and_uncertainty_refs:
```

A mid-turn fallback cannot silently change tool, reasoning, privacy or billing semantics. The logical receipt never proves that a provider call occurred; that belongs only to `PhysicalModelAttemptReceipt`.

Route policy may use a model-generated `RouteAssessmentCandidate`, but deterministic policy performs admission. Magnitude of a classifier score is not calibrated confidence. A scoped `RouteFailureFingerprint` records route, task/context shape, decision turn, failure class, evidence, expiry and revalidation; it must not quarantine an entire vendor when the failure is narrower.

A classifier/judge is a separate bounded physical attempt with its own deadline, cost quota, reference manifest and failure disposition. Timeout, invalid schema or abstention yields a typed degraded/default decision; it does not masquerade as model certainty. Every static policy branch and fallback tier participates in a reachability check so a dead branch or permanently shadowed route is reported before canary.

### Provider transport hardening

Every privileged provider transport declares and proves:

```text
connect, TLS/headers, first-byte, semantic-idle, overall-job and cleanup deadlines;
retryable conditions, bounded attempt count, exponential backoff with jitter and Retry-After cap;
header allowlist and explicit privacy admission;
bounded request/response/error/event bodies;
safe public error plus restricted raw error artifact;
cancellation and terminal reconciliation;
authenticated loopback/IPC default for local servers;
no synchronous routing-log I/O on the hot path;
no exclusive route/session/state lock across provider/model/network wait.
```

Stateful routing uses snapshot → release lock → external call → reacquire → revision/fence validation. Process-local session affinity is an optimization only and never task continuity or authority. TTL/cleanup/affinity maintenance runs as a supervised bounded job with health, cancellation and observable eviction policy; detached cleanup tasks and arbitrary hash-map eviction are not production lifecycle mechanisms. Invalid, timed-out or abstaining route assessments produce a typed decision source and the declared deterministic baseline/fallback; they are never converted into fabricated classifier confidence.

### Switchyard adoption boundary

A pinned Switchyard `protocol + translation` snapshot MAY be tested behind an ELIOT facade. The first experiment is a representative request/response/stream conformance corpus on Windows with diagnostics preservation, loss accounting, allocation/cost measurement and maintenance review. Stage Router, LLM classifier and whole server remain effect-free shadow candidates until an equal-stack Product Pulse shows material benefit. Switchyard's server, transport, session state and skill store never become ELIOT control owners.

### Optional Unsloth/local-ML execution contours

Unsloth Core/Zoo is an optional pinned ML execution dependency behind ELIOT-owned process bridges. It is not linked into Kernel/Governor, does not receive canonical-store credentials and does not own task, memory, route, budget, evidence or finish state.

The default physical split is:

```text
training worker generation;
clean export/quantization/calibration worker generation;
inference/local-subagent worker generation;
optional Researcher-provider/RAG worker generation.
```

Modes that require incompatible global Python imports, patches, compiler state or device libraries use clean process generations rather than a mutable “toggle” in one giant daemon. Shared model/download CAS is allowed; interpreter/module state is not silently transferred.

Every ML run binds:

```text
exact base/adaptor/model repository and revisions;
tokenizer/template/processor revisions;
dataset manifest, lineage, licenses and privacy;
Torch/Transformers/TRL/PEFT/Unsloth/Zoo/CUDA/driver/runtime fingerprints;
actual device, precision, quantization, load mode and resource profile;
requested-versus-resolved execution receipt;
checkpoint/export/evaluator identities;
cancellation, recovery, cleanup and artifact receipts.
```

A small local model may serve bounded repetitive implementation/scouting or a measured specialist. It cannot become Architecture authority, Current Epistemic Position, permission, general verifier or sole Task Controller. Parametric learning may target narrow replaceable capabilities such as classification/reranking/normalization; user goals, Architecture, authority, privacy, active commitments and current epistemic state remain external governed records.

Admission requires RGF-AGENT-ROUTES and a matched product/control evaluation on this Windows installation. Studio/Desktop, its product database/UI/control plane and “last prose message = result” are not adopted.


### Measurement-path identity

Every benchmark, route comparison and transport/performance claim binds the exact path that was actually measured:

```yaml
MeasurementPathIdentity:
  source_and_build_identity:
  executable_module_and_generation:
  invoked public method_or_handler:
  adapter_codec_and_profile revisions:
  runtime_route_and_environment:
  candidate_or_legacy_path discriminator:
  raw execution_receipt_refs:
```

A benchmark of a legacy Python path, synthetic service, alternate handler or unobserved fallback cannot be attributed to the current Rust/native production path. Missing path identity narrows the claim to `UNVERIFIED_PATH` rather than borrowing the product label.

## I10.12. Cloud and laboratory modules

Remote compute is optional `CloudBridge`:

```text
explicit environment template;
credentials isolated in bridge;
resource/budget lease;
artifact/output import through evidence path;
automatic shutdown;
no direct canonical DB access;
remote failure becomes partial job, not core failure.
```

## I10.13. Professional applications

App bridge declares:

```text
supported artifacts/actions;
UI/API observation quality;
side effects;
undo/recovery;
artifact verifier;
representation gaps;
interactive Human boundary.
```

ELIOT generality comes from common contracts, not from one giant universal pipeline.

## I10.14. Bridge updates

```text
new upstream version staged as new bridge generation;
contract compatibility checked;
shadow health/query if read-only;
canary on bounded WorkScope;
route switch;
drain old;
rollback if metrics/outcomes regress.
```

Upstream project directory/package remains unchanged and updateable.


## I10.15. Agent Execution Fabric and durable swarm

Agent Execution Fabric extends the existing Host Broker and Agent Coordinator. It does not introduce a second scheduler, task store, attempt journal, write authority or recovery path.

A model-produced plan is never executed directly. It is compiled through a deterministic `TaskGraphCompiler`:

```text
Planner Candidate
→ schema and objective/acceptance linkage
→ dependency and ownership validation
→ effect/authority and WorkScope validation
→ cycle check; bounded loop compilation with max iterations/budget/termination
→ overlap, WIP, environment and budget analysis
→ immutable SwarmPlanDefinition
→ Governor admission
→ Ready Queue execution.
```

The durable execution unit is an `AgentAttempt`, not an agent personality. A route/session is an ephemeral executor attached to one attempt with exact packet, budget, lease, artifact lineage and continuity kind. Free-form group chat may be captured as a research artifact, but it is not the task graph, mailbox or completion mechanism.

Agent output is typed:

```text
artifacts;
evidence;
findings and rivals;
proposed effects;
unresolved questions;
proposed next work.
```

A proposed effect follows proposal → authorization → idempotent execution → effect receipt. A worker, component or synthesis agent cannot perform the commit merely because it generated the proposal.

```text
Human / Main Agent
→ ExecutionIntent: goal-linked role, assurance, cost and privacy preference
→ Recipe Planner chooses the simplest admissible workflow
→ Route Allocator selects evidence-backed runtime routes
→ Ready Queue runs a fenced admission saga for internal WIP, cost/quota budget and resource claims
→ adapters execute bounded attempts
→ Governor reconciles events, artifacts, evidence and verification
→ the named content/acceptance decision owner resolves substantive ambiguity.
```

The system unifies task/lifecycle/evidence, not vendor internals.

`RecipePlanner`, `RouteAllocator` and Ready Queue admission are deterministic/policy capabilities of `AgentCoordinator` inside `eliotd`. Main Agent, Dreamer or a planning worker may propose decomposition, recipe or route preferences, but the proposal remains a Candidate until dependency, impact, capability, budget, privacy and overlap checks pass. None of these capabilities owns a second task graph or substantive decision authority.

### Semantic objects

```text
SwarmPlanDefinition
  immutable orchestration proposal bound to one task/recipe revision: objective, acceptance links,
  Task Controller lease/epoch, RootContextRevision, work graph, privacy/budget/route/depth/fanout/WIP
  ceilings and stop conditions; each definition revision is authored only by the Task Controller;

SwarmPlanAdmission
  Governor-owned disposition of one exact SwarmPlanDefinition under a Policy/Capability/State Fence:
  admitted, rejected, stale, cancelled or superseded; it records admissible ceilings and a receipt
  but cannot rewrite the definition or substantive task choice;

SwarmExecutionState
  execution/aggregation revision for one admitted definition: coordinator lease/epoch,
  current wave, assignment/checkpoint/reduction state, coverage ledger and operational outcome;
  owned by AgentCoordinator under the SwarmCoordinatorLease and unable to widen the admitted plan;

RoleProfileId and RecipeId
  opaque, versioned manifest IDs; no closed vendor enum;

RootContextRevision / SwarmWave
  immutable shared root handles, State Fence and disclosure policy for one execution wave;
  a changed root creates a new wave and forces descendant revalidation rather than silent context mutation;

CoordinationMapView
  rebuildable recipient-addressing projection over one frozen SwarmPlanDefinition and current execution
  assignments: work-item identity, one-line responsibility, dependency/overlap edges, assigned attempt/role
  and mailbox route handle; it contains no mutable plan state and creates no semantic subscription owner;

ReductionPlan
  bounded fan-in tree, deterministic pre-dedup/grouping, lineage preservation,
  synthesis stages and stop/escalation rules;

RoleProfileManifest
  semantic role, allowed operations/effects, required competence and independence,
  input/output contract, stop/escalation and visibility limits;
  learning_role: actor | refiner | evaluator | promotion_owner | not_applicable;

RecipeManifest
  ordered/parallel stages, work-item templates, dependency/merge rules,
  admissible role/route classes, expansion/contraction conditions,
  verifier/audit requirements, budget and failure/partial-result behavior;

ExecutionIntent
  role, assurance, budget class, route-class preference,
  independence requirement and optional recipe hint;

ParallelismEvidence
  decomposition/path claims, shared invariants, overlap,
  merge cost, environment contention and expected information gain;

StaffingPlan
  recipe revision, lanes, expansion/contraction rules,
  admission, audit and resource-mix policy;

RoutingReceipt
  requested class, selected RouteFingerprint, rejected alternatives,
  current capability/quota evidence and cost/privacy rationale.
```

Definition, admission and execution lifecycles are separate and are defined once in I14.20. At this layer ownership is fixed: Task Controller owns `SwarmPlanDefinition` revisions; Governor owns `SwarmPlanAdmission`; AgentCoordinator owns `SwarmExecutionState` under an exact active admission.

The SurrealDB DEFAULT uses separate definition, admission and execution records with separate owner revisions/Ordering Scopes. Another store may co-locate them physically only if field ownership, revisions and immutable owner events remain enforceable. A derived `SwarmPlanView` may join them for reads, but is not a mutable owner. AgentCoordinator may advance execution mechanically only under an active admission receipt; any change to objective, acceptance, ceilings, work graph semantics or stop conditions requires a new Task Controller definition revision and a new Governor admission. A new definition never mutates a running wave in place: the Task Controller proposes drain/cancel/supersession, Governor admits the disposition, and a new execution revision starts against the new definition. None of these objects owns task truth: task finish remains I7.9. Loss of Task Controller or coordinator revokes only the corresponding lease; definitions, admission receipts, work items, events, evidence and verified partial results survive and are reassigned under a newer epoch.

Recipe/role manifests are content-addressed, versioned and policy-approved inputs compiled into existing `AgentInvocationRequest`, `HostLaunchContract`, Durable Jobs, leases and receipts. Distributed/external bundles additionally require signature verification; local built-ins do not gain a pointless signing ceremony. Unknown manifests are not executable until schema, provenance and policy validation.


### Module-oriented development swarms

For software implementation, decomposition starts from `BuildTestGraph` and the generated `EffectiveMicroModuleManifest`, not from arbitrary file count.

```text
contract/fixture lane
→ independent module implementation lanes
→ module-local InstrumentProfile proofs
→ affected edge integration lane
→ blind causal/property audit
→ one governed IntegrationLease.
```

Each work item names one primary micro-module, frozen public contract revision, exact discriminator, independent test command and affected integration edges. Agents may inspect wider context but cannot widen their write scope silently. Cross-cutting contract or schema changes are planned as their own ordered wave before consumer implementations.

Parallelism is rejected when agents would edit the same mutable owner, share an unisolated build/runtime resource, require the same sequential reasoning state or create merge cost larger than expected evidence value.

### Built-in recipes

First supported recipes:

```text
SoloVerified
  one capable agent → deterministic verifier → optional narrow review;

ScoutThenImplement
  read-only scout → compact evidence/plan artifact → fresh single writer → verifier;

ParallelEvidenceSynthesis
  bounded read-only lanes with first-pass sibling isolation → lineage-aware dedupe → synthesis candidate;

NegotiatedInterdependentInvestigation
  independent whole-question mapping by future workers → disclosed overlap/dependency comparison →
  Task Controller freezes a revised partition → parallel execution with admitted peer deltas →
  cross-review/selective replan → lineage-aware synthesis and verification;

ImplementThenBlindAudit
  one writer → tests → blind cross-family reviewer → correction/probe → final gate;

LiveLearningCampaign
  bounded attempt → instrumented outcome → AttemptLearningDelta →
  admitted task-local overlay revision → exact CampaignLearningStateView →
  next attempt compilation + HarnessActivationReceipt →
  periodic consolidation, promotion or honest stop.
```

`LiveLearningCampaign` is selected when work is long or multi-step, feedback is frequent and competent enough to change strategy, and the next attempt is expected to use the previous outcome. Its minimum profile is one actor, one lineage and one local overlay; population search is not required. Before each materially comparable attempt, Context Compiler builds the exact derived learning-state view from existing owner revisions, then records retrieval/delivery/observable activation against that view. A missing/stale load-bearing owner ref blocks only the dependent compilation. The recipe adds no scheduler, task graph, attempt journal or authority path: the task-local overlay defined in I12.24 is admitted by Governor like any other bounded state, and terminal campaign dispositions never equal task `VERIFIED_COMPLETE`.

Campaign admission records `closure_due_at`, `expires_at`, `closure_owner_ref`, and `terminalization_policy_ref` on the existing Task or Durable Job state; it creates no new scheduler or mutable campaign owner. A campaign cannot remain active indefinitely. At `closure_due_at`, the owner emits `CampaignLearningClosure` or an explicit delayed or inconclusive disposition. At `expires_at`, Governor rejects new overlay revisions and inherited attempts, then terminalizes the campaign to the strongest evidence-supported closure disposition. A missing closure owner is reassigned or escalated; it never leaves an immortal active campaign.

Four functions are separated even when one model performs them sequentially: Actor solves the current task; Refiner analyses experience and proposes the local delta; Evaluator measures the declared property; Promotion Owner decides scope of influence. Role transition creates a new bounded context and capability envelope. Refiner cannot finish the task or promote its own update; Actor cannot edit the evaluator or the retention set. Same-model operation is allowed and explicitly lowers the recorded `IndependenceProfile`.

Later, only after route and recipe evidence:

```text
CompetitiveImplementation;
PathShardedImplementation;
RedTeamAudit;
IncidentDiagnosis.
```

Arbitrary free-form swarms and general DAG builders are not prerequisites. One writer per deliverable is DEFAULT.

### Negotiated decomposition and disclosure boundary

`NegotiatedInterdependentInvestigation` is used only when the task is plausibly cross-cutting and the initial partition itself is uncertain. It does not become a four-agent default and it does not require unanimity.

```text
P1 Independent Mapping
  every future execution lane receives the same high-level question and shared root;
  each independently produces a dependency sketch, unknowns, candidate subquestions and likely overlaps;
  sibling conclusions remain hidden until each mapping is sealed;

P2 Partition Decision
  sealed mappings are disclosed;
  workers identify overlaps, causal cross-boundary dependencies and blind spots;
  the Task Controller records one immutable SwarmPlanDefinition revision and preserved dissent;
  Governor admission remains required; workers cannot mutate the current plan in place;

P3 Parallel Execution
  every attempt executes its frozen work item;
  admitted peer-relevant deltas may be delivered at the next admissible boundary under I10.18;

P4 Cross-review and Selective Replan
  factual conflict, thin evidence, invalidated assumption or omitted observation returns proposed next work;
  the Task Controller opens only the affected branch through a new definition revision and admission;

P5 Synthesis and Verification
  reduction preserves lineage, dissent, coverage gaps and the applicable verifier ceiling.
```

During P1, ordinary peer messages are queued but not disclosed; only an exact safety, authority, privacy or destructive-effect blocker may cross the independence boundary, and that disclosure changes the IndependenceProfile. After P1, receiving a message does not widen write scope, authority, budget, acceptance or plan semantics. A worker may request pause/revalidation, but only the existing coordinator/Governor owners can change execution state.

The recipe begins as a read-only architecture/onboarding/root-cause/security/research profile. Mutating use is promoted only after the coordination ablation and isolated disjoint-worktree canary of I18.11 show a verified benefit without unacceptable harmful redirection, context growth, contamination or merge cost.

### Recipe selection and incremental staffing

Planner chooses the simplest recipe that satisfies task impact and requested assurance. It evaluates:

```text
subtask separability and acceptance independence;
path/schema/state overlap;
need for common sequential history;
merge and coordination cost;
expected evidence diversity and correlated-error risk;
tool/runtime/environment contention;
current route quality, health and quotas;
human attention backlog.
```

Fanout begins at one lane and expands only when the next lane has expected marginal value. Fixed global swarm sizes and static vendor percentages are forbidden defaults.

### Route allocation and failover

Hard constraints are applied before scoring:

```text
required capabilities and exact conformance evidence;
impact/permission and data policy;
local/remote and secret boundary;
route/account health and quota reservation;
worktree/environment compatibility;
independence requirement.
```

Soft score may consider quality, latency, context efficiency, cost/quota pressure and historical outcomes for the task class.

No silent mid-attempt failover. After provider/runtime work has produced meaningful output or an effect, another route creates a new attempt with a sealed handoff and visible causal link.

### Ready Queue and fenced WIP admission

ELIOT maintains two operational projections over canonical work/attention state:

```text
Ready Queue
  executable work whose dependencies and policy are satisfied;

Human Attention Queue
  approvals, questions, conflicts and capacity decisions requiring a person.
```

They are not second task or notification stores. Because canonical work state and Kernel-owned leases/resource claims have different durable owners, admission is a fail-closed saga rather than a fictitious cross-store transaction:

```text
1. AgentCoordinator revalidates dependencies, State Fence, recipe, route evidence and policy.
2. Kernel stages an inactive `AdmissionReservation` in ORS for the exact work item,
   pessimistic cost/quota view, lane, Work/Action and environment claims.
3. Governor commits the canonical `SwarmPlanAdmission`/work-item `ADMITTED` transition,
   admitted attempt identity and launch outbox, referencing the reservation receipt.
4. Kernel activates the reservation and launch authority only after observing the matching
   canonical receipt and unchanged State Fence/Authority Epoch.
5. Launch/provisioning begins. Rejection, timeout or crash before activation cannot launch work;
   an unconsumed reservation is released or reconciled by identity.
```

This uses the same asymmetric principle as authority activation: failure may temporarily reduce capacity, but cannot grant an unrecorded launch. Provider quotas and external environments cannot participate in either local durable transition. Their actual allocation happens later as an idempotent provisioning effect and is reconciled; failure closes that attempt with evidence, releases its active reservation and returns the work through a new admission revision. If capacity is unavailable before admission, work enters `DEFERRED_CAPACITY` with `not_before`/quota reset and does not remain falsely `RUNNING`. Scheduler pulls the next admissible item; no model is required to launch its successor.

### Subscription and portfolio scheduling

Quota windows are first-class and simultaneous: rolling hours, week, month, credits, requests, concurrency and provider-specific limits. Provider meter/invoice outranks ELIOT estimates. Missing usage is `unknown` or `not_exposed`, not zero.

User chooses policy preset and upper envelopes. Governor computes temporary task-class route mix from grounded outcomes and remaining capacity. Strong reviewer/arbitration reserve is not consumed as bulk implementation capacity unless policy explicitly permits it.

### Isolation beyond worktrees

Three independent leases are used:

```text
CodeIsolation
  branch/worktree/path claims;

ProcessIsolation
  Job Object/process group, cwd/env, resource limits and descendant cleanup;

RuntimeIsolation
  ports, services, DB/volumes, browser profiles, caches and remote environment.
```

A mutating/integration lane receives `ExecutionEnvironmentLease` in addition to `WorktreeLease`. Multiple writers require disjoint code invariants, separate mutable runtime resources, sufficient host capacity and a bounded integration plan. Job Objects alone do not isolate ports or service state.

### Blind review and Concilium

Blind reviewer receives a dedicated `BlindAuditPacket`, not the writer's ordinary current packet:

```text
task/acceptance and Architecture constraints fixed before the attempt;
base/candidate diff or artifact;
raw commands/tests/evidence and exact verifier state;
pre-existing negative memory and invariants whose lineage predates the candidate attempt;
explicit coverage gaps and allowed probes.
```

The packet excludes author confidence, self-justification, generated plan/rationale, prose summaries, sibling findings and attempt-created memory unless a later rebuttal/challenge stage discloses them explicitly. Disclosure changes the IndependenceProfile and is recorded. `AuditFinding` requires claim, category/severity, exact evidence, affected resources and optional reproduction/verifier. “Cross-family” or “independent” credit is granted only when `ActualRouteReceipt` and `IndependenceProfile` support it; an unknown actual route may still review, but counts only as a blind non-independent perspective.

First-pass discovery/audit lanes receive one pinned `RootContextRevision` and their own work-item overlay, but not sibling conclusions. The root is immutable for that wave. A change in Architecture, task constraints, critical evidence or shared source creates a new `SwarmWave`; descendants are marked stale or explicitly revalidated, never silently updated in place. After each first-pass result is sealed, challenge/reduce stages may disclose rival findings; from that point the independence profile records the shared information path.

Large result sets are reduced through a bounded `ReductionPlan`, not one giant synthesis prompt:

```text
deterministic schema/provenance validation
→ exact duplicate and shared-lineage grouping
→ bounded first-level reducers
→ challenge/counterevidence stage
→ final synthesis candidate with coverage ledger and dissent.
```

Every reducer has a maximum fan-in, input State Fence and output lineage. Overflow creates another reduction level or a handle; it is never truncated silently.

Disagreement flow:

```text
normalize rival claims and Evidence Lineage
→ run deterministic/discriminative probe if possible
→ if unresolved, arbiter receives only the disagreement packet
→ arbiter selects next observation or records residual uncertainty.
```

Model vote never promotes truth.

### Context and session continuity

Task, work graph, decisions, artifacts and evidence are durable. Runtime process and native session are disposable. Long-lived “personality workers” are not the continuity mechanism.

Rotation triggers include terminal work item, context pressure, repeated correction, route fingerprint change, no progress, security event or role boundary. Cross-runtime transfer uses `Rehydrated` attempt and public inheritance; native resume is only an optimization inside one compatible fingerprint.

Native runtime subagents are allowed only as bounded optimizations behind depth/fanout/tool-inheritance/cancellation/usage policy. Recursive delegation is disabled unless the parent `WorkLease` contains an explicit subtree envelope with maximum depth/fanout, child route classes, cumulative budget, allowed effects, lineage and cancellation cascade. A child cannot enlarge that envelope. Native children never own the ELIOT work graph and their final message is not proof. If a runtime cannot expose child creation, parentage, effective route, usage and cancellation on the exact fingerprint, native delegation is disabled for Material mutation and does not count as independent coverage; an unexpected child becomes a supervision signal and its effects require reconciliation.

`NoLostChildInvariant` is operational rather than rhetorical: the coordinator periodically reconciles admitted descendants against host/provider process/session inventory. Every child has one terminal state—`COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`, `UNKNOWN_OUTCOME`, `STALE` or `QUARANTINED`—plus artifact/effect cleanup. A parent cannot finish while a descendant is live, unreachable or has unresolved effects; it may return `PARTIAL/BLOCKED` with explicit child state instead. Watchdog owns independent orphan detection, while AgentCoordinator owns cancellation/reassignment and canonical execution reconciliation.

```yaml
DescendantClosureReceipt:
  parent_attempt_or_swarm_execution:
  admitted_descendant_set_and_lineage_revision:
  observed_runtime_process_session_set:
  terminal_disposition_per_visible_descendant:
  opaque_runtime_parent_disposition:
  artifact_checkpoint_cleanup_and_effect_reconciliation:
  unreachable_or_unknown_descendants:
  observation_coverage_and_blind_intervals:
  parent_finish_ceiling: complete | partial | blocked | unknown_outcome
  coordinator_and_watchdog_evidence_refs:
```

A parent FinishAttempt or swarm terminal transition must reference a current `DescendantClosureReceipt`. Closed runtimes that do not expose descendants are represented as one opaque parent invocation; ELIOT never claims child-level cancellation, budget, independence or cleanup for hidden children.

### Composite run lifecycle and recovery

I14.20 is the single canonical lifecycle vocabulary for ReadyWorkItem, RunAttempt, DurableJob, SwarmPlanDefinition, SwarmPlanAdmission and SwarmExecutionState. The physical state remains with each declared owner; the Fabric uses compatible typed machines rather than one overloaded status field or one new global registry.

`DEFERRED_CAPACITY` belongs only to work admission. It never describes a running attempt or execution state. A `RunAttempt` exists only after `ADMITTED`. External route/environment provisioning is a fallible observed effect after admission; failure releases claims and creates a new admission revision rather than rewriting the old attempt as “not started”.

A parent awaiting deferred child work remains `WAITING_CHILD`; the parent attempt is not capacity-deferred retroactively. Native `completed` is only runtime evidence until ELIOT verifies artifacts/results. Process liveness, logical turn, event cursor and task completion are independent fields.

Progress is new evidence, artifact, accepted patch, resolved finding, verifier result or meaningful state transition—not prose volume. Repeated normalized `(tool,args,error)` and absence of evidence trigger interrupt → diagnosis/replan → cancel/reconcile; unlimited continue/self-repair loops are forbidden.


### Shared-wave disclosure and capability-introduction gate

Each `RootContextRevision` records:

```text
recipient principals/routes;
Disclosure Dependency Closure;
IntroductionSetDigest per recipient/Attempt;
grant-graph and Capability Registry revisions.
```

Adding evidence, a tool/resource facet or a recipient creates a new root revision. Before delivery ELIOT recomputes:

```text
privacy/disclosure coverage;
authority grant paths;
credential binding;
route/provider retention policy;
tool/facet schema exposure.
```

A recipient that cannot receive the broadened root is moved to a private fork, receives a verified redacted projection, is re-authorized/removed, or blocks only the dependent wave. The shared root is never silently widened.

Child attempts receive only introductions inside the admitted subtree envelope. Native child creation that cannot expose exact child lineage, effective route, usage, cancellation and introduction set remains disabled for Material mutation.


### Human control

The role-filtered Human Control Plane may pause/cancel/replan under task authority, change policy/budget only under its owning Human role, approve an exact Critical effect only as Approver, request Concilium, replace Task Controller when authorized, or take over a work item through a new lease. Every intervention is a durable Coordination Event and does not depend on vendor UI state.

## I10.16. Governed integration of candidate implementations

Mutating swarm branches never merge themselves. Each result creates an `IntegrationCandidate`:

```yaml
IntegrationCandidate:
  candidate_id:
  task_and_work_item:
  producer_attempt_and_lineage:
  base_commit_and_state_fence:
  worktree_or_artifact_refs:
  diff_and_changed_path_manifest:
  declared_read_write_effect_sets:
  evidence_and_verification_refs:
  unresolved_conflicts_and_unknowns:
  rollback_or_compensation:
  status: proposed | ready | stale | integrating | accepted | rejected | conflicted | unknown_outcome
```

`IntegrationQueue` is a projection over canonical candidates, dependencies, approvals and the current integration lease. It is not another scheduler or database.

Because worker parallelism can outrun the single integration owner of one mutable target, the projection exposes queue/backlog counter-metrics: candidate age and count, wait-to-first-review, verifier and rebase cost, stale-by-base-drift rate, conflict/rework rate, accepted verified delta per review window, and completed-worker-to-integrated-result ratio. Rising integration pressure narrows fan-out or decomposes contracts/edges before adding workers; it never creates a second integration owner for the same target.

DEFAULT integration discipline:

```text
one active integration owner and lease per target branch/deliverable;
revalidate base, dirty human changes, path/effect set and State Fence;
run required verifier in candidate worktree/environment;
apply through the governed Git/artifact bridge;
never use git reset --hard or destroy unrelated dirty work;
semantic merge conflicts become ConflictSet/Concilium work, not automatic text acceptance;
run post-apply verifier and record OutcomeReceipt;
on failure, execute explicit rollback/compensation and retain candidate/history.
```

Independent candidates may be prepared in parallel; canonical integration is ordered where effects overlap. Base drift marks only dependent candidates stale. Accepting one candidate never erases dissent or evidence from rejected alternatives.

## I10.17. Adapter subsystem

Adapter classes:

```text
truth adapter;
verifier adapter;
code/dependency adapter;
artifact/professional-tool adapter;
provider-memory feed;
external-agent adapter;
research acquisition adapter;
notification/surface adapter.
```

Common contract:

```yaml
AdapterManifest:
  adapter_id_and_version:
  capabilities:
  input_output_schemas:
  truth_or_effect_semantics:
  required_permissions_and_data_classes:
  timeout_cancellation_idempotency:
  health_readiness_freshness:
  failure_translation:
  evidence_and_receipt_rules:
  compatibility_and_removal:
```

`AdapterSupervisor` owns the adapter reconciliation loop: it reads desired state from the Module Catalog, interprets health observations, applies circuit/restart policy and proposes lifecycle actions. It does not own a second desired-state store or the Capability Registry. Kernel owns physical process lifecycle, Job Objects, the Generation Registry, generation routing and fencing; Governor owns Module Catalog transitions and Capability Registry evidence. AdapterSupervisor does not decide semantic truth.


Each adapter has an independent runtime state:

```text
per-adapter semaphore and queue;
health/readiness/freshness;
circuit and restart budget;
current generation and in-flight requests;
resource and output limits.
```

A separate system-wide semaphore/ResourceArbiter limits aggregate load. The global limit never increases an adapter's own declared concurrency. Short service adapters use `AdapterManifest`; long-running compiler/test/index/runtime instruments use `InstrumentSpec` and InstrumentRunner rather than stretching one generic timeout/output contract.

Selection order prefers:

```text
exact/direct competent source;
registered local deterministic adapter;
existing warm supervised process;
bounded external route;
model synthesis only when interpretation is actually required.
```

### Baseline adapter capability registry

The first implementation preserves the useful exact routes from the former Governor without requiring their old class names:

| Legacy capability/name | Current adapter/module capability | Default lifecycle | Fallback |
|---|---|---|---|
| `GitStateAdapter` | `workspace.git_state` | built-in/platform or warm bridge | filesystem generation; mark Git facts unavailable |
| `FilesystemMetadataAdapter` | `workspace.fs_metadata` | built-in platform facade | direct bounded stat/read |
| `Process/ServiceHealthAdapter` | `runtime.process_health`, `runtime.service_health` | Watchdog/platform sensor | visible unknown/degraded; no invented health |
| `RipgrepAdapter` | `code.exact_text_search` | lazy process/module | bounded native search alternative |
| `AstGrepAdapter` | `code.structural_search` | lazy module | exact text/LSP; structural claim remains unavailable |
| `CodeGraphAdapter` | `code.graph_query` | shared warm process module | exact file/symbol/LSP route |
| `LspAdapter` | `code.definition_reference_diagnostic` | shared/lazy project module | code graph/exact source reads |
| `DiagnosticsAdapter` | `diagnostic.collect_normalize` | project/tool module | verifier/tool output capture |
| `DomainApiAdapter` | `domain.api_truth` | WorkScope-selected optional module | docs/direct probe/unknown |
| `DocumentationAdapter` | `source.document_exact` | Researcher or bounded source bridge | source unavailable/unknown |
| `VerifierMapAdapter` | `verification.registry_query` | Governor projection over Capability Registry | explicit missing verifier |
| `ArtifactVerifierAdapter` | `artifact.evaluate` | scoped professional/verifier module | deterministic partial checks or degraded proof |
| `ExternalAgentAdapter` | `agent.external_job` | transient supervised bridge | alternate route/defer |
| `ProviderMemoryAdapter` | `memory.provider_feed` | lazy read-only feed | ELIOT canonical memory remains authoritative owner |

Execution rules for every process/CLI adapter:

```text
construct executable and argv separately; never interpolate a shell command by default;
set explicit cwd and environment allowlist;
bind process to a Job Object/resource profile;
stream bounded stdout/stderr overflow to Blob Store;
kill the owned process tree on deadline/cancellation;
record exact version, input hash, duration, exit/protocol status and raw-output handle;
preserve path/symbol/range identity where the capability provides it;
never expose secrets in argv, logs or returned prose;
never write canonical state directly;
never invoke a model implicitly from a deterministic adapter contract.
```

Transport failure, semantic `no results`, stale index and unsupported capability are distinct outcomes; only transport/integrity failures count toward the circuit breaker.

## I10.18. Mailbox, blackboard, live peer delivery and anchored review

### Mailbox

Durable directed coordination:

```text
at-least-once delivery;
ordered sequence per recipient/task;
message-id idempotency;
ack for control messages where the contract requires it;
large payload by handle;
expiry/reassignment after Session loss;
route-qualified delivery capability and visible degradation.
```

Message kinds:

```text
assignment;
checkpoint;
question;
conflict notice;
result;
verifier result;
cancel/supersede;
attention/escalation;
live peer delta;
anchored review item/batch.
```

The common `EventEnvelope`/`ReceiptEnvelope` owns identity, sender/recipient principal, timestamps, ordering, provenance, privacy/disclosure, State Fence and delivery receipts. Payload records below do not duplicate those fields.

### Coordination map

A worker addresses peers through the derived `CoordinationMapView` from I10.15:

```text
work-item identity and one-line responsibility;
dependency/overlap edges;
assigned attempt and role;
mailbox route handle;
current frozen plan/wave revision.
```

It is rebuilt from the frozen plan and current assignments. It is not an `AttemptInterestSet`, semantic subscription engine, new scheduler or mutable routing owner. Initial routing is explicit by attempt/work-item reference; automatic semantic subscriptions remain an experiment until measured need.

### Live peer message

```yaml
LivePeerMessagePayload:
  sender_attempt_and_work_item:
  recipient_attempt_or_work_item_refs:
  frozen_plan_and_wave_revision:
  kind: relevant_finding | assumption_invalidated | dependency_discovered |
        plan_contradiction | obstacle | abandoned_dead_end
  concise_delta:
  evidence_and_artifact_handles:
  requested_reaction: inform | revalidate | reply | pause_dependent_effect
  urgency: normal | before_next_dependent_effect
  dedup_key_and_expiry:
  delivery_policy: next_admissible_boundary
```

Sender semantics:

```text
sender waits for durable mailbox admission of the message;
sender does not wait for recipient acknowledgement, response or plan revision;
current model/tool step is never interrupted;
no full thread/transcript snapshot is attached by default;
only the bounded delta plus exact expansion handles is delivered.
```

Delivery profile:

```text
EventIntegrated
  inject an admitted delta before the next model/tool step when the host exposes a safe boundary;

ToolOnly
  include it in the next ELIOT response/turn boundary;

OfflineWorker
  deliver at the next checkpoint, relaunch or explicit coordinator boundary;

Unavailable
  retain the mailbox item, expose the delivery capability gap and do not claim passive awareness.
```

The Context Compiler admits a live delta only after checking recipient/work-item relevance, exact plan and State Fence, privacy/disclosure, evidence availability, novelty/deduplication, urgency, payload budget and first-pass independence policy. An `assumption_invalidated`, `plan_contradiction` or `before_next_dependent_effect` message may create a revalidation/pause obligation, but it creates no truth, authority, finish, plan revision or write-scope expansion.

Delivery, recipient acknowledgement, public use in a decision/artifact and outcome-helpfulness are separate observations. A message can be delivered and ignored, used and harmful, or helpful only under a later outcome comparison. These states are never collapsed into one success flag.

### Blackboard

Shared typed facts/candidates for a task or swarm:

```text
FindingCandidate;
EvidenceHandle;
Unknown;
HypothesisCandidate;
ConflictNotice;
DecisionRequest;
VerifierResult;
ArtifactHandle;
Blocker.
```

It is not a transcript or free-form group chat. Blackboard items retain author, lineage, State Fence and lifecycle. A live peer message may point to a blackboard item but does not duplicate or silently promote it.

### Anchored review items

`AnchoredReviewItem` is durable review coordination under the existing coordination/attention path. It creates no new store, scheduler, task graph or authority owner.

```yaml
AnchoredReviewItem:
  review_item_id:
  author_principal:
  target_kind: public_message | public_plan | public_rationale |
               tool_result | diff | source | verifier_result
  original_target_revision_and_anchor:
  kind: question | correction | objection | requested_change |
        missing_evidence | scope_issue | acceptance_issue
  content:
  state_fence:
  lifecycle: draft | pending_delivery | delivered | answered |
             resolved | rejected_with_reason | stale | superseded
  response_change_and_verifier_refs:
```

`ReviewBatch` is a derived delivery envelope over several independent items submitted together. It has no independent lifecycle owner. Every item receives its own disposition; unresolved items remain visible obligations and cannot disappear because the surrounding message was answered.

Rules:

```text
review targets are public artifacts, public rationale, exact code/diff/tool/verifier surfaces only;
hidden chain-of-thought is neither persisted nor a review target;
original revision/anchor is immutable history;
current-location resolution uses I10.21 and remains exact/moved/modified/ambiguous/stale/deleted/unavailable;
ambiguous resolution never silently attaches to the most similar fragment;
a comment/request does not grant write/effect/goal/acceptance authority;
rejection requires a reason; requested change requires normal owner, effect and verifier paths;
resolution of a review item is distinct from acknowledgement or delivery.
```

Anchored review may escalate a real blocker to the existing Problem/Conflict/Critical-Attention owner, but it is not itself a second problem or approval system.

## I10.19. Provider memory feeds

Provider-native memories may be imported as scoped source feeds with a `ProviderMemorySurfaceProfile`:

```text
provider and memory type;
retention/export/deletion semantics;
scoping and user controls;
source assurance and poisoning risk;
actual model/fallback route;
allowed authority: candidate only.
```

They never become policy, current position or canonical memory without normal capture/reconciliation.

## I10.20. Professional workflow bridges

Non-code domains use the same Harness, evidence, authority and finish contracts. A `ProfessionalExecutionContract` composes:

```text
domain method and target software/version;
input assets and immutable source/reference handles;
output workspace, allowed write roots and expected deliverable manifest;
allowed substitutions and forbidden shortcuts;
reference visibility and evaluator isolation;
environment/profile and professional tool route;
artifact evaluator, acceptance properties and proof ceiling;
checkpoint, abandonment, rollback/compensation and delivery conditions.
```

The worker receives only references it is allowed to use. A hidden reference used solely by the evaluator is not included in the worker packet, tool surface, filesystem view or logs. A reference-isolation receipt records which assets were visible to which principal and route.

A plausible message does not replace a required artifact. Completion requires the artifact in the declared output workspace, a manifest/checksum and the applicable evaluation result. Tool/app bridges provide observability and effects; domain method and acceptance remain Task/ProfessionalExecution contracts.

## I10.21. ChangeMonitor and evolving anchors

ChangeMonitor combines host events, filesystem notifications, Git reconciliation, process/tool receipts and artifact scans.

It records:

```text
before/after resources and exact source/artifact revisions;
origin attribution confidence;
associated Session/ActionLease/tool operation/attempt;
unknown-origin changes;
exact diff/artifact/operation handles;
State Fence invalidations.
```

Filesystem notification alone is a hint. Git/content checksum/re-read supplies evidence. Unknown-origin Material mutation blocks governed acceptance until reconciled, but does not crash unrelated modules.

### EvolvingAnchorResolver

The resolver is a deterministic rebuildable projection over immutable original identity, ChangeMonitor observations, VCS/diff history and admitted code-intelligence evidence. It is not a canonical operation store and does not create a second source-history owner.

Resolution order:

```text
original artifact/revision plus existing operation/diff identity;
→ exact file/symbol/AST identity where available;
→ content fingerprint plus structural-neighborhood fingerprint;
→ historical range fallback;
→ explicit resolution status.
```

Status:

```text
exact | moved | modified | ambiguous | stale | deleted | unavailable.
```

Rules:

```text
`ambiguous` never auto-selects the nearest or most similar current fragment;
a deleted target remains addressable as a historical anchor;
text-preserving move/rename may resolve as moved without implying semantic equivalence;
semantic-preserving refactor may make an old review item stale when its requested decision no longer applies;
algorithm/version, inputs, evidence and confidence class are recorded;
false attachment is treated as more harmful than missed automatic resolution;
Human correction produces a new resolver observation, never a rewrite of original history.
```

For public messages/plans/verifier results, immutable revision/span identity is preferred. For source/diff targets, symbol/AST and VCS/diff evidence are used when present. DeltaDB-style character-permalink guarantees are not claimed without an admitted operation/delta substrate that can actually prove them.

`ChangeMonitor`, the resolver and the existing decision/effect/artifact/verifier lineage feed the `ChangeProvenanceView` of I12.10/I12.31. A new durable `CausalChangeOperation` record is introduced only after measured reconstruction failures show that existing operation identities and receipts cannot recover the required boundary; naming convenience is insufficient.

## I10.22. Professional execution safeguards and abandonment

Professional work has three independent owners:

```text
Task/Domain owner — method, goal, acceptable substitutions and deliverable;
bridge/environment owner — software/process capability and observed effects;
evaluator owner — measurement contract and reference isolation.
```

The same agent may perform several roles only when the Evaluation Contract permits it; shared reference or self-judging limitations remain visible.

`PrematureAbandonmentSignal` is raised when an attempt stops, reports success or changes approach while a required deliverable, verifier or declared workflow boundary remains unresolved. It does not force continuation: the Task Controller may reframe, supersede, accept partial work or ask the Human, but the missing artifact cannot disappear from state.

Approach changes are recorded as a new revision with rationale, preserved partial artifacts and impact on acceptance. A bridge may suggest a fallback application or file format; it cannot silently substitute one.

## I10.23. MessagingBridge

`MessagingBridge` is an optional user-channel adapter contract over existing ELIOT principals, Sessions, tasks, Human Control, mailbox/outbox and delivery receipts. It does not own task semantics, memory, schedule, approval authority, route policy or completion. Local UI/CLI operation remains available when every messaging adapter is absent.

```yaml
MessagingBridgeProfile:
  bridge_generation_platform_and_adapter_fingerprint:
  enrolled_principal_binding_and_access_policy:
  chat_thread_session_task_and_workscope_binding:
  negotiated_capability_profile:
  inbound_media_contract:
  outbound_delivery_contract:
  session_command_surface_and_version:
  approval_and_attention_surface:
  scheduled_delivery_target_ref:
  canonical_outbox_and_sink_receipt_projection:
  reconnect_replay_duplicate_and_freshness_policy:
```

A platform account, chat or thread is a transport locator, not an ELIOT principal or Session. Enrollment binds the exact platform identity fingerprint to an existing principal under revocable access policy. Every inbound turn resolves an explicit Session, WorkScope and Task or creates a typed `OperatorIntentCandidate`; transport reconnect does not infer continuity from chat history alone. Platform message/update identity plus adapter generation and principal binding form one replay-safe inbound event identity, so webhook/polling duplicates cannot create a second task or approval.

Commands compile to typed existing operations such as session create/resume/status/stop, approval/denial, route selection, automation inspection and Skill invocation. A command never exposes a generic shell/database path or bypasses its owning contract. Approval binds the exact action/effect digest, scope, State Fence, Authority Epoch, principal and expiry; `/approve` is not session-wide authority and a replay after expiry or revision change is rejected.

The capability profile is negotiated and evidenced per adapter generation: text limits, threads, editing/streaming, reactions, inbound/outbound media, file size/type, idempotency keys, acknowledgement/readback and duplicate behavior are never assumed. Unsupported capability yields an explicit degraded result or another Human surface; it is not silently emulated with weaker guarantees.

Inbound files/media are admitted through `SourceAdmissionPolicy`, privacy scanning and Blob Store as immutable handles before model/tool exposure. Outbound files/media resolve from immutable artifact handles through disclosure closure and recipient policy; a local filesystem path is never sent as if it were the artifact. Revocation stops future delivery where enforceable and preserves the historical delivery receipt.

The “durable delivery ledger” is a read model over the canonical outbox row and sink-owned phases from I5.21, not a second store or lifecycle owner. The logical message binds principal, chat/thread target, task/result/artifact refs, adapter generation, disclosure decision, freshness window and stable sink operation identity.

Crash/reconnect behavior is exact:

```text
result committed and send not started
  → the existing outbox item is claimed and delivered after restart;

send started and acknowledgement/readback lost
  → sink state remains UNKNOWN and is reconciled by platform idempotency/readback;

no reconciliation surface and policy chooses at-least-once resend
  → create a new marked delivery attempt for the same logical message,
    expose possible_duplicate, preserve the old UNKNOWN attempt and freshness limit;

in every case
  → never re-execute the agent turn, model call, tool call or task effect merely to deliver.
```

Scheduled delivery is authored by `UserAutomation` or another existing Durable Job owner and committed through the outbox; the bridge only validates the target and performs delivery. Delivery, recipient acknowledgement, task completion, approval resolution, public use and outcome-helpfulness remain separate observations. A delivered “done” message cannot close a task, and a completed task is not represented as delivered until the sink receipt says so.

Telegram is the first implementation `Experiment`, not a core dependency. Promotion to a Default requires Product Proof of principal/session binding, text plus file delivery, restart between result commit and send, visible unknown/duplicate handling, access revocation and non-reexecution of task effects. A second adapter is admitted only after the same common-contract proof, so adapter count cannot substitute for reliability.

---

# I11. Human control plane and notifications

## I11.1. First UI

DEFAULT: a Windows-native WinUI 3 desktop application on the stable Windows App SDK line. The first target is Windows App SDK 2.3.1, admitted only after packaging, startup, update, accessibility and recovery tests on the supported Windows 11 profile.

Stack and boundary:

```text
thin C# WinUI 3/XAML client in the interactive user session;
Windows App SDK stable runtime and native app notifications;
authenticated EBP/ControlBoard/Operator client through User Broker;
no Electron/Tauri and no public network bind;
no database, package-manager, provider credential or canonical state ownership;
Rust Host/Kernel/eliotd remain the control plane.
```

The UI provides Dashboard, Dreamer chat, WorkScope/onboarding, agent/swarm launcher, settings, maintenance, problems, evidence and recovery views. It uses native Fluent/WinUI interaction patterns, light/dark and high-contrast modes, high-DPI scaling, keyboard navigation, screen-reader labels and progressive disclosure: ordinary users see the decision and safe next action, while exact receipts/IDs remain expandable. Visual polish cannot hide degraded capability behind a green state. UI actions compile typed operator intents; the UI does not invent commands or call agent binaries directly.

The single canonical CLI `eliot.exe` (`eliot`) is the mandatory administrative, automation and recovery fallback. It is **not** an ELIOT coding-agent/provider CLI: ELIOT launches and supervises installed external agents through their own runtimes and bridges.

`eliot dashboard` MAY provide a lightweight terminal surface using Ratatui + Crossterm. It renders the same role-filtered `ControlBoardView` and owns no state. An optional loopback web viewer may be added for compatibility or remote-view experiments, but it is not the primary Windows UI and cannot expose more authority than the native client.

## I11.2. ControlBoardView

Single canonical read projection rendered differently for Human, Main Agent, Watchdog and Dreamer.

Sections:

```text
Product — current Product Objective, accepted Product Identity,
          last verified product delta, open Hard Boundary gaps,
          current Product Proof and exact unproven scope;
System — Host/Kernel/DB/modules/queues/backup;
Integrations — agents/hooks/tools/models and Governance Profile;
Tasks — goals, plan, causal property, discriminator, progress evidence,
        unknowns and finish readiness;
Development — repeat-repair count by failure class, activity/product-delta ratio,
              zero-test or stale-identity runs, open Mechanism Reviews;
Agents/Swarm — sessions, work items, negotiated partitions, admitted live-peer delivery,
               budgets, coverage and visible delivery gaps;
Review — pending anchored review items/batches, per-item dispositions and stale/ambiguous anchors;
Change lineage — public decision/conversation ↔ operation/diff ↔ historical/current code ↔ verifier/outcome;
Attention — blocking obligations and conflicts;
Problems/Incidents — owner, evidence, repairs, next action;
Memory — candidates, conflicts, stale/poisoned influence, curation;
Architecture / Implementation — accepted revisions, applicable contracts, conformance gaps, defaults, Research Gates and deviations;
Costs — model/cloud usage and remaining authority;
Notifications — persistent inbox.
```

## I11.3. Human actions and role authority

The Control Plane exposes actions by authenticated role; “Human” is not one undifferentiated superuser.

| Human role | Normal actions |
|---|---|
| Requester / Domain Owner | define/clarify/supersede user outcome and acceptance; set task cost/risk preferences; accept or reject the claimed user outcome |
| Architecture Owner | inspect and accept/supersede Architecture revisions |
| System Owner / delegated Operator | start/stop ELIOT; manage routes/models, Module Catalog policy, ordinary module generations, backup and migration within delegation |
| WorkScope Owner | open/close/narrow WorkScope; set scope privacy/retention/risk and applicable verifier contracts |
| Approver | approve/deny one exact Critical action hash |
| Recovery Principal | execute one predeclared bounded break-glass/recovery transition |
| Any authorized role | inspect evidence/receipts, request Dreamer/Watchdog analysis, acknowledge notifications; resolution still requires the role that owns the underlying state |

Task Controller assignment, swarm launch/stop, Improvement Candidate disposition and problem/attention resolution are allowed only when the caller holds the corresponding task, budget, policy or state-owner capability. UI must state consequences, affected scope, expiry and current authority—not display raw internal IDs alone or offer a button the principal cannot lawfully execute.

## I11.4. Dreamer/Watchdog conversation and operator intent

The native UI exposes a persistent Dreamer chat and a narrower “Ask Watchdog” diagnostic surface. Both are typed job/operator-intent interfaces:

```text
user question or requested action;
resolved WorkScope/task and onboarding state;
source/evidence handles;
proposed agents/tools/maintenance/configuration delta;
route, cumulative context and budget;
risk, approvals, effects and rollback;
result status: candidate/advisory/verified portion;
follow-up, edit, confirm, pause, cancel or escalate actions.
```

Examples:

```text
“Explain what ELIOT knows about this project.”
“Clean up this scope’s memory and show what would change.”
“Start Codex on task X and use Claude for a blind audit.”
“Run maintenance now, but do not call paid external models.”
“Switch the default Dreamer route to a local model.”
“Install or update the admitted SurrealDB generation.”
“Pilot Codebase Memory MCP for this repository.”
```

Natural language creates an `OperatorIntentCandidate` and visible plan. Direct read-only questions may execute immediately inside authority. Effects, software/configuration changes and agent launches follow their owners and approval policy. This is not direct chat with database, package manager, shell or daemon internals.

The durable conversation surface is a privacy-scoped `SessionEpisode` plus Dreamer job/request/result records. Provider-bound `RouteContinuationState` is stored separately and never becomes the chat’s authority or knowledge. After UI or route restart, the conversation is reconstructed from public messages, exact source/result handles and terminal job state; hidden reasoning, stale continuation or a cached UI transcript cannot authorize or prove an action.

## I11.5. Persistent notifications

Severity:

```text
Critical      — integrity/security/unknown external effect/control loss;
ActionRequired— approval, blocked task, failed credential/repair;
Warning       — degraded hooks, repeated failures, stale backup, pressure;
Info          — verified completion, maintenance result, update available.
```

Each notification:

```yaml
Notification:
  notification_id:
  severity:
  subject:
  summary:
  evidence_handles:
  affected_scope:
  owner:
  required_action:
  deadline_or_review:
  dedup_key:
  delivery_channels:
  acknowledgement:
  resolution_ref:
```

Delivery and resolution are separate.

## I11.6. Windows notifications

`eliot-notify.exe` is a per-user one-shot notification adapter. Normal delivery is launched through the authorized User Broker. A separately registered signed Task Scheduler fallback may launch it without Kernel/User Broker only to read a minimal signed envelope produced by Watchdog.

```text
normal:
  canonical notification → User Broker → native toast → authenticated local UI;

control-loss fallback:
  Watchdog spool + Windows Event Log → signed minimal envelope
  → Task Scheduler / next `eliot` launch → `eliot-notify` or recovery banner;

no interactive user session:
  no immediate desktop toast is promised; Event Log/spool persist the obligation.
```

The fallback envelope contains only incident class, installation identity, timestamp, evidence digest and `eliot recovery status` instruction. It contains no secrets, project content or large evidence and grants no repair authority. Loss of notification delivery never resolves the underlying Problem/Critical Attention.

The Host/Kernel service does not attempt to display desktop toasts directly. Notification adapter loss degrades delivery only; canonical notification state or Watchdog control-loss evidence remains durable in its owning store.

## I11.7. Notification behavior

```text
repeat events update one persistent item;
acknowledgement suppresses repeated toast, not problem;
critical unresolved item remains on board;
quiet hours suppress noncritical popups only;
failed delivery remains visible in inbox and metrics;
resolved item closes only with evidence/authorized disposition.
```

Notification and approval policy is evaluated on separate outcomes:

```text
missed critical risk and final harm;
false-critical/benign false block;
notification and approval count;
pre-exposure prevention versus conditional intervention;
interruption time and resumption latency;
final task correctness, rework and Human attention/overtrust.
```

A quieter policy is not better if it misses material risk; a stricter policy is not better if it creates false blocks and destroys task outcome. Suppression experiments never remove the persistent canonical item or exact expiring approval boundary.

## I11.8. Authentication

The primary WinUI client authenticates through the interactive User Broker and authenticated local IPC. The binding includes Windows user/session identity, UI process identity, a short-lived Kernel challenge/session token, requested Human role and exact ControlBoard/Operator capability set. UI restart creates a new operational binding and never revives authority from cached application state.

State-changing requests require an explicit authenticated Human principal and the same typed authority/approval contracts as CLI or agent surfaces. Recovery operations may require a one-shot local CLI/Recovery Principal confirmation token. The optional loopback web compatibility viewer, when enabled, uses a separate short-lived browser token bound to user SID, Origin validation and CSRF protection; it is disabled by default and cannot expose a wider capability set than the native UI.

## I11.9. Accessibility and ordinary-user design

```text
plain language first, technical detail expandable;
no requirement to understand database/schema/agents;
show “what happened / why it matters / what to do”;
provide safe default action;
never hide degraded capability behind green status;
allow expert access to exact evidence and receipts.
```


## I11.10. Human attention, approval and telemetry evaluation

The Human Control Plane is evaluated as a coupled intervention, not by notification volume or approval speed alone. A scoped `HumanAttentionEvaluation` records:

```yaml
HumanAttentionEvaluation:
  policy_and_task_risk_profile:
  notification_approval_and_telemetry_profile:
  missed_critical_and_false_critical_counts:
  pre_exposure_prevention_and_conditional_intervention:
  final_harm_and_residual_risk:
  benign_false_blocks_and_abandoned_work:
  interruption_and_resumption_time_quality:
  task_correctness_rework_and_human_attention:
  overtrust_undertrust_and_recoverability_observations:
  privacy_purpose_retention_and_disclosure_cost:
  evaluator_scope_uncertainty_and_invalidation:
```

A quieter policy is not superior when it misses material risk; a stricter policy is not superior when false blocks and interruption destroy the task outcome. Notification suppression never removes the persistent canonical obligation. Approval experiments retain exact action scope and expiry. Richer telemetry remains experimental unless its incremental recovery/diagnostic value exceeds privacy, attention, storage and false-inference costs on a paired profile.


---

Anchored review and provenance navigation are evaluated separately from notification policy:

```text
per-item delivery and disposition completeness;
missed or silently dropped review obligations;
false attachment versus explicit ambiguous/stale status;
time to locate original and current target;
ability to navigate decision → change → verifier and current code → originating decision;
Human correction rate, reviewer burden and duplicate-note rate;
changes accepted/rejected with exact owner, authority and proof;
privacy exposure from reviewed public artifacts and expansion handles.
```

A fast response that skips one of several independent comments fails review completeness. A resolver that attaches a note to the wrong current fragment is worse than returning `ambiguous`; the UI must preserve the historical target and offer explicit correction rather than invent continuity.

## I11.11. Project launcher, environment manager and ordinary-user workflow

The Human does not need to open a terminal or understand agent runtimes. The native UI presents:

```text
Projects
  discovered and registered WorkScopes, similar-repository conflicts, cold-start readiness;

Agents
  installed runtime families, exact current capability/health, routes, quotas and preview status;

Start work
  goal/task, project, assurance/cost/privacy preset, selected or automatic agent plan;

Maintenance
  backup, curation, reindex, route/tool requalification, updates and repair;

Settings
  direct forms and Dreamer-assisted natural-language changes with impact/rollback preview;

Research
  local Dreamer query and optional ELIOT Research federation jobs.
```

The UI can start Codex, Claude Code, OpenCode, Gemini CLI, ACP agents, local-model workers or later admitted routes through `AgentLaunchRequest`; it can also attach to work initiated by an external agent and bind its Session/WorkScope/task after verification. `Start work` first exposes the `WorkScopeCandidateSet`, ScopeBindingGuard and `OnboardingReadinessReceipt`; it cannot hide an ambiguous clone, missing task or conflicting governing document behind an automatic agent launch. It never assumes the newest executable is healthy merely because it was discovered.

Attaching an already-running external agent does not retroactively make its earlier activity observed or authorized. ELIOT creates an `ExternalAttachReconciliationReceipt`:

```yaml
ExternalAttachReconciliationReceipt:
  external_process_session_route_and_actual_identity:
  attach_time_and_pre_attach_blind_interval:
  observed_workspace_instance_scope_and_task_candidates:
  last_known_base_and_current_workspace_artifact_delta:
  imported_transcript_event_and_tool_coverage:
  known_unknown_or_unattributed_external_effects:
  scope_authority_privacy_and_credential_disposition:
  required_verification_cleanup_or_human_decision:
  continuation_kind_and_new_attempt_identity:
```

Pre-attach changes are candidate artifacts/observations and cannot become proof, task completion or agent-attributed experience until reconciled. If exact process/session or workspace ownership cannot be established, the route attaches read-only or as a new bounded attempt with an explicit blind interval. Any request to continue Material work before that disposition returns `EXTERNAL_ATTACH_RECONCILIATION_REQUIRED`.

A first-run “recommended integrations” page is generated from the discovery catalogue and current evidence. It may offer installation/registration plans for supported tools, SurrealDB or a code-intelligence pilot, but nothing is installed, updated or granted credentials without the applicable Human policy and visible transaction.

## I11.12. UserAutomation

`UserAutomation` is a first-class user-owned one-shot or recurring intent/configuration object over the existing Task Scheduler, `WakeIntent` and Durable Job contracts. It is a product capability, not `MaintenanceAutomationMode`, and it creates no scheduler, task graph, attempt journal, route owner, canonical writer or authority path.

```yaml
UserAutomationRevision:
  automation_id_revision_and_supersedes:
  owner_principal_and_workscope:
  natural_language_intent:
  normalized_schedule:
    kind: one_shot | recurring
    expression_and_calendar:
    timezone_and_dst_fold_gap_policy:
    start_end_and_next_occurrence_projection:
  mode: agent | deterministic_process
  task_template_or_qualified_script_ref:
  portable_skill_package_revision_refs:
  workdir_and_workscope_binding:
  route_reasoning_and_cost_policy:
  expected_provider_model_and_adapter_fingerprints_or_allowed_set:
  delivery_target:
  preflight_contract_revision:
  budget_deadline_and_resource_ceiling:
  concurrency_policy: forbid_overlap | queue_one | coalesce_latest
  recursion_policy_and_max_child_depth:
  configuration_state: active | paused | blocked_config | retired
  current_execution_refs:
  execution_history_query_ref:
```

The original natural-language request remains visible, but the normalized schedule is the trigger contract. Before activation the Human surface shows timezone, DST fold/gap behavior, next occurrences, work scope, route/cost ceiling and delivery target. An ambiguous calendar phrase is not silently guessed. An edit creates a new immutable revision and invalidates not-yet-admitted wake intents of the superseded revision.

Every trigger compiles one stable `AutomationOccurrenceIdentity` from the automation revision and exact calendar occurrence; `run-now` uses an explicit manual nonce and does not mutate the schedule. Duplicate wake/restart events resolve to the same occurrence. Task Scheduler may wake Host only from the admitted intent; the `WakeIntent` itself grants no task, route, tool, effect or delivery authority.

Before any model call, a deterministic `AutomationPreflightReceipt` validates:

```text
current configuration state and occurrence claim;
principal, WorkScope, workdir and State Fence;
task template or qualified script identity;
exact trusted/current Skill package revisions and Tool Definitions;
provider/model/adapter fingerprint, credentials and Human route/cost policy;
delivery capability and disclosure policy;
budget, deadline, overlap, recursion and unresolved-prior-effect rules.
```

A configuration failure enters `blocked_config`, makes zero model calls and updates one deduplicated actionable notification. Unexpected provider/model drift fails closed unless the Human policy already admitted the observed compatible set; there is no silent route substitution. Transient capacity failure may defer the occurrence without rewriting configuration truth.

Agent mode creates the normal admitted task/attempt/job path. Deterministic mode executes only a qualified script/process whose capability profile excludes model-provider access; it never calls an LLM directly, indirectly or through a fallback. Exact stdout/stderr are delivered verbatim when within policy/size limits, otherwise through the reversible payload contract of I7.26; neither path uses model summarization, and bytes are evidence rather than implicit truth. In both modes, route/effect authority and verification remain with their existing owners.

Configuration state and execution state are separate. `active` may coexist with one currently running occurrence; `current_execution_refs` is a projection of the canonical Durable Job lifecycle in I14.20, not another lifecycle. The execution history remains immutable Durable Job/effect/receipt history. `pause` stops future admission but does not silently cancel an already admitted job; cancellation is an explicit operation. `remove` retires/tombstones the automation, cancels only unadmitted future wakes and preserves history plus outstanding reconciliation obligations.

Supported user operations are:

```text
create; list/status/history; pause/resume; edit; run-now; remove; inspect last failure.
```

The same occurrence is never blindly rerun after `UNKNOWN_OUTCOME`; I14.21 reconciliation decides its disposition. A later calendar occurrence is a different identity but is blocked when unresolved prior effects violate the declared overlap policy. By default an automation execution cannot create, edit, resume or trigger another automation; scheduling authority requires a separate exact Human-approved operation, so scheduler jobs cannot recursively manufacture scheduler jobs.

Delivery is requested through the declared target and canonical outbox; delivery failure does not rerun the task/model/tool effects and does not rewrite job completion. A repeated failure class updates one persistent notification keyed by automation revision and failure fingerprint. It does not emit one alert per occurrence; a material revision, verified recovery or Human disposition reopens that notification key.

# I12. Understanding, memory classification, curation and retrieval

## I12.1. State model

Canonical Memory stores records and history. `UnderstandingState` is a governed, versioned view plus rebuildable projections; it is not a second store.

```text
Canonical observations/evidence/events
+ current WorkScope generations
+ accepted relations/models/decisions
+ derived concept/graph/capsule projections
→ WorkScope Understanding State
→ Task Understanding
→ Active Understanding View.
```

ELIOT System Self-Model is separate from project scopes and cannot leak project claims across scopes.

## I12.2. Capture path

Agent-facing `eliot.observe` accepts natural content with optional hint:

```yaml
ObservationInput:
  text_or_structured_payload:
  hint: observation | decision | failure | outcome | unknown | reuse_candidate | auto
  task_id: optional
  affected_resources: optional
  expected_reuse_note: optional
  source_handles: optional
```

Governor auto-attaches:

```text
principal/session/model route;
WorkScope/task;
time and State Fence;
touched paths/entities/tools;
origin and instruction taint;
privacy/visibility;
exact action/tool lineage.
```

No observation is rejected only because the agent chose wrong kind. Invalid authority/privacy/scope can reject effect, but raw safe capture becomes candidate when possible.

## I12.3. Classification pipeline

### Deterministic first pass

```text
registered verifier output → verification observation;
failed tool/test with stable signature → failure observation candidate;
authenticated direct Human goal/constraint event → instruction/constraint record in Human authority scope;
explicit agent decision with alternatives → decision candidate;
file/tool output → source/tool observation;
unknown question → Unknown item;
uncertain content → Observation Candidate.
```

### Semantic curation

Dreamer batch may propose:

```text
claim/hypothesis/decision/failure/procedure/concept;
relations;
merge/split;
scope/applicability;
reopen/extinction;
future activation cues.
```

All remain candidates until governed transition.

## I12.4. Core record families

Implementation uses a compact set of canonical families, not one table per cognitive metaphor.

```text
SourceRecord       — immutable origin/snapshot/blob lineage;
ObservationRecord  — what a route observed;
Interpretation     — claim/hypothesis/model with support/counterevidence;
AssumptionRecord   — load-bearing assumption with origin, necessity, failure mode and dependents;
DecisionRecord     — chosen action/policy/task decision and rationale;
ExperienceRecord   — episode/action/outcome/failure/procedure candidate;
CommitmentRecord   — future obligation/deadline/trigger;
TaskRecord         — goal/plan/work/finish;
ControlRecord      — attention/problem/conflict/authority/module/job;
ArtifactRecord     — produced or evaluated artifact;
ProjectionRecord   — capsule/graph/index/context manifest;
AuditRecord        — immutable transition/receipt/security history.
```

An assumption is a first-class record because retraction must be mechanical. When an assumption is refuted, its dependents are **withdrawn**, not rewritten: a proposition records under which minimal assumption set it holds, and loses current support when that set fails. This preserves history and makes conflicting contexts coexist without premature consensus.

Typed payloads discriminate subtypes. Storage adapter may use normalized tables/relations, but API stays family-based.

## I12.5. Epistemic status

```text
observed;
supported;
verified;
contested;
stale;
superseded;
rejected;
unknown.
```

A rendered material statement also carries an object-local label set; the labels do not replace the canonical status above and are not mutually exclusive truth states:

```yaml
StatementLabelSet:
  basis: SOURCE_SUPPORTED | DERIVED_INFERENCE | HYPOTHESIS | EDITORIAL_RECOMMENDATION
  conditions: [CONTESTED | UNRESOLVED | REDACTED_DEPENDENCY]
```

`basis` states how the sentence is being presented; `conditions` state why it cannot be read as an uncontested live assertion. A source-supported statement may also be contested, and a hypothesis may remain unresolved. `REDACTED_DEPENDENCY` means a load-bearing support handle was purged/redacted and forces withdrawal or revalidation under the existing dependency graph. Citation eligibility remains owned by the exact evidence/reference path in I21.7: model prose cannot mint a citation identifier, and every emitted citation resolves to an admitted live evidence handle and allowed reference entry.

`verified` requires applicable Evaluation Contract and current VerificationRun. Model summary cannot upgrade.

Separate axes:

```text
support/status;
assertability: ASSERTABLE | NON_ASSERTABLE_UNVERIFIED | ABSTAIN_OR_FENCE;
accessibility/activation;
allowed influence;
physical existence;
source security/taint.
```

A claim may be mentionable as historical/third-party content while remaining non-assertable. Third-party-only, stale, contested or absent support cannot be rendered as an ELIOT assertion; the Decision Safety Floor records the support handles and returns `ABSTAIN_OR_FENCE` or a narrower attributed statement. Mixed-provenance transformations inherit the minimum allowed assertability/influence of their supporting sources unless a registered verified transition changes it.

## I12.6. Cue binding

Reusable record has at least one activation route:

```text
file/path/symbol;
error signature;
command/tool;
service/process;
dependency/API;
task class;
concept/subsystem;
commitment/deadline;
problem/incident;
Architecture/module ID.
```

Bindings are generated from observed touched-set first. Agent may add expected reuse. Unbound record remains cold and available to Dreamer/pull; it is not discarded.

`CUE_BINDING_REQUIRED` applies only to an attempted promotion into reusable hot memory when auto-binding cannot produce an admissible route. The underlying safe observation is retained as a cold `ObservationCandidate` and the response returns suggested bindings; it is not a failed capture.

Normalization is a single shared pure contract used by capture and firing:

```text
path        → canonical WorkScope-relative identity preserving case and Git spelling; a separate comparison key follows the actual directory case-sensitivity policy and never destructively lowercases the canonical path;
symbol      → adapter-resolved stable container/name identity where available;
error       → stable signature over tool/rule/message class/path class, excluding commit/config noise;
command     → executable + stable subcommand tokens, volatile arguments removed;
task class  → deterministic profile over task/artifact/subsystem fields;
service/API → registered capability identity and version range.
```

Write-side and read-side normalization cannot be separate implementations. Property/fuzz tests exercise roundtrip symmetry and cross-scope isolation.

## I12.7. Cue Index

Derived projection:

```text
(scope, cue_kind, normalized_value)
→ record handles, status, freshness, danger, token estimate.
```

Hot mirror uses immutable per-scope snapshots via `ArcSwap`. Updates come from canonical outbox. Full rebuild is possible.

Firing rules:

```text
inputs come only from observed task/tool/world events;
exact matches precede prefix/signature matches;
negative memory and invariants precede decisions, claims, skills and capsules;
items already delivered in one Session are suppressed unless invalidated;
result count/payload is bounded; overflow is a resource handle;
normal firing is deterministic and model-free.
```

No redb semantic index.

## I12.8. Exact-first orientation

```text
1. active task/current handles;
2. exact path/symbol/entity/artifact/error;
3. typed relation neighborhood;
4. lexical/full-text search;
5. optional vector shortlist;
6. Dreamer synthesis/research.
```

Vector similarity never blocks or verifies.

## I12.9. Graph layer

Unified query facade over:

```text
static code/dependency graph;
behavioral co-change/hotspot graph;
causal experience graph;
task/execution graph;
artifact lineage;
concept/normative graph;
source/influence dependency graph.
```

Every edge carries:

```text
type/direction;
scope/time;
source/provenance;
epistemic status;
adapter/build revision;
invalidation condition.
```


## I12.10. CodeCortex implementation

`CodeCortexService` is a deterministic **task-relative evidence compositor**. It owns no universal graph, tool process, parser or truth. It consumes admitted Instrument Plane evidence and canonical ELIOT state.

Input stack:

```text
TaskContract, acceptance, current plan and WorkScope;
exact Git/base/candidate/worktree identity;
changed paths and owning Cargo packages;
full Cargo package/target/feature/reverse-dependency graph;
rust-analyzer/SCIP definitions, references and implementations;
latest compiler/test/runtime InstrumentRuns;
optional heuristic graph observations with explicit limitations;
ELIOT decisions, invariants, FailureFingerprints, artifacts and verifier map.
```

Output is a bounded `CodeCortexReport` whose every relation carries:

```text
relation kind and endpoints;
evidence authority;
freshness;
coverage;
optional confidence only for heuristic evidence;
source handle and dependency set;
conflicts/unknowns.
```

Report sections:

```text
task entrypoints and exact anchors;
ChangeProvenanceView linking public decisions, attempts, operations, diffs, reviews, historical/current anchors and verifiers;
changed symbols and owning packages;
reverse package and public-symbol impact;
references/implementations and candidate call paths;
relevant test inventory and verifier handles;
architecture/concept boundaries and declared invariants;
known failures and prior decisions;
source disagreements;
coverage gaps and cheapest probes;
handles for expansion.
```

Blast radius is a provenance-preserving union, not a set of text matches:

```text
changed files
+ owning packages
+ reverse package dependencies
+ semantic references to changed public symbols
+ tests covering affected packages/symbols
+ heuristic cross-service candidates.
```

Each reason remains separate. Missing CodeCortex discovery never denies an authorized Add/Modify/Delete/Rename; write authority comes from TaskContract, ActionScope and leases. For a new file, graph coverage may be `not_applicable` or `unknown`, not `file_outside_report`.

`ChangeProvenanceView` is a rebuildable bidirectional projection over existing owners:

```text
request/public message/plan/rationale
→ attempt, action, tool and effect identities
→ ChangeMonitor diff/artifact observations
→ original and currently resolved anchors
→ AnchoredReviewItems
→ verifier/outcome
→ later supersession or correction;

current file/symbol/range
→ operations/attempts that created or touched it
→ linked public decisions/messages
→ artifacts, reviews and verifiers.
```

Every edge carries attribution `exact | receipt_linked | correlated | ambiguous | unknown`. `correlated` is never rendered as causal proof. Missing or ambiguous links remain visible and cannot be repaired by a model-authored narrative.

CodeCortex does not:

```text
parse Rust with ad-hoc text rules;
run duplicate compiler/test commands;
serve hard-coded invariant cards;
turn heuristic similarity/co-change into causal proof;
hide disagreement between rust-analyzer and heuristic graph;
return confident negative answers from partial/stale indexes;
call Dreamer in the hot compositor path.
```

A model may explain unresolved relations later through Dreamer/Concilium, but the original evidence and conflict remain visible. Material code work needs either a fresh applicable report or explicit unknown hops and Investigation Mode; this is a content requirement, not a separate ceremony.

## I12.11. Concept Pyramid

Derived hierarchy:

```text
Project Charter
→ System Map
→ Subsystem Capsule
→ Module/Workflow Card
→ exact code/evidence/artifacts.
```

Deterministic sections are built from graph/evidence. Dreamer writes only bounded semantic sections and cites handles. All artifacts have dependency manifest and dirty flag.

No fixed token limits are architectural; DEFAULT compiler budgets live in context profiles. First line targets may retain historical approximate budgets, but correctness overrides them.

## I12.12. Current Epistemic Position Resolver

Input question is explicit or derived from task/action property.

```text
collect exact current observations;
filter by scope/time/generation;
resolve deterministic supersession/freshness;
retain rival interpretations;
mark verifier competence/freshness;
return observed/supported/assumed/conflicted/stale/unknown;
identify cheapest inquiry.
```

Fresh direct outlier updates evidence and may create conflict; it does not blindly overwrite aggregate.

### Investigation Mode

When a Material/Critical decision depends on unresolved, stale or conflicting state:

```text
allow exact reads, reversible probes, source capture, hypothesis work and Concilium;
block only the dependent effect/finish claim;
show why the unknown matters;
return the cheapest discriminative probe or safe partial action;
retain `data insufficient` as a valid outcome;
exit only after evidence, authorized risk acceptance or supersession.
```

Investigation Mode is a task/action state, not a separate daemon or workflow engine.

## I12.13. Context Compiler

Pipeline:

```text
Task frame
→ Critical Attention and hard constraints
→ Current Epistemic Position
→ goal/semantic/causal model
→ active plan/continuity
→ invariants and negative memory
→ exact evidence and unknowns
→ available tools/authority
→ next boundary and verifier
→ decision-local tail.
```

Each candidate receives:

```text
scope fit;
freshness;
epistemic support;
source assurance;
expected decision delta;
risk/negative-memory value;
unknown/probe value;
route accessibility;
token/position cost;
distraction/repetition penalty.
```

The ordering, feature configuration, layout and budgets are selected by a versioned `ContextRecipe` owned by Context Compiler:

```yaml
ContextRecipe:
  recipe_id_revision_and_digest:
  applicable_task_route_impact_and_governance_profiles:
  stage_graph_and_order:
  candidate_feature_configuration:
  admission_and_suppression_policy:
  instruction_directive_evidence_tool_and_result_budgets:
  protected_reasoning_review_and_margin_reserve:
  layout_position_and_repetition_policy:
  omission_and_expansion_policy:
  scorecard_blocking_dimensions:
  execution_contour_and_generation:
  empirical_qualification_and_counter_metrics:
  parent_supersession_kill_and_rollback:
```

A recipe cannot weaken Decision Safety Floor, ContextAtomPolicy classes, authority/privacy, active Recovery/Conflict Directives, reversible omission or proof ceilings. It may be changed only as an Improvement Candidate through replay, shadow/canary and rollback. `ContextEconomyReceipt` binds the exact recipe revision.


Each semantic role is budgeted in whole, addressable units rather than arbitrary token slices:

```yaml
ContextSectionBudget:
  semantic_role:
  unit_boundary_kind:
  minimum_required_whole_units:
  protected_floor_or_required_refs:
  planning_maximum_and_route_profile:
  omission_or_handle_policy:
  degradation_behavior:
  disable_feature_when_floor_cannot_be_preserved:
```

Examples of whole units are an EvidenceAtom, ClaimCard, ToolDefinition, source-catalog entry, WorkItem, completed causal stage or Architecture/Implementation anchor. A JSON object, URL, source identity, tool call/result pair or evidence edge may not be cut into a syntactically valid but semantically false fragment.

Before filling optional context, Context Compiler requests the applicable `DownstreamHeadroomReservation` owned by I14.29. A swarm fan-out leaves reducer/verifier budget; acquisition leaves synthesis/output budget; a long packet leaves a decision-local tail and response/tool-result headroom. If required headroom and the Decision Safety Floor cannot coexist, the task is decomposed or narrowed rather than filled to the nominal window.

Compaction and transformation priority are evidence-based, not a permanent list of names:

```yaml
SemanticSensitivityProfile:
  route_task_family_and_context_recipe:
  item_class_or_feature:
  ablation_replay_and_transfer_evidence:
  fidelity_floor_and_failure_signatures:
  allowed_transformations_and_precision_ceiling:
  dependencies_expiry_and_requalification:
```

Goal/acceptance, authority/effect scope, State Fence, primary anchors, strongest counterevidence, exact failure/discriminator, privacy boundary and stop/revisit conditions begin conservatively, but their profile still requires replay/ablation evidence. The same mechanism prevents a verbose early source from consuming every slot before rivals, unknowns and negative evidence are represented.

Decision: include payload, include handle, warn, require revalidation, suppress, quarantine. The synchronous compiler uses only stored/precomputed features and exact relations. An unknown expected decision delta is not negative evidence and cannot by itself justify suppression; uncertain but potentially load-bearing material is kept as a handle, warning or explicit coverage gap.

Each compiled View emits a vector `PacketQualityScorecard`:

```text
acceptance/decision coverage;
causal and operational sufficiency;
exact-anchor/provenance coverage;
freshness and State Fence coherence;
visibility of rivals, conflicts and unknowns;
negative-memory/invariant coverage;
verifier/action readiness;
route-specific accessibility/layout risk;
instruction_sufficiency: governing instructions, active directives, non-goals and applicable negative memory;
payload, handle and reconstruction cost;
known omissions and expansion paths;
telemetry/measurement cost and coverage.
```

No scalar packet score may hide a load-bearing failed dimension.


### Boundary metadata and format-preserving degradation

Packing, batching, compaction and swarm reduction preserve semantic boundaries explicitly:

```yaml
BoundaryMetadataEnvelope:
  logical_units_and_order:
  source_attempt_stage_and_owner:
  scope_task_and_state_fence:
  provenance_disclosure_and_influence_closures:
  exact_start_end_or_member_handles:
  omission_and_expansion_refs:
  completeness_and_precision:
  transformation_revision:
```

A packed representation cannot merge adjacent tasks, documents, tool outputs, source families or causal stages merely because the byte/token shape is convenient. Boundary loss is a visible transformation defect.

Degradation is whole-unit and operation-specific. If a unit's required metadata, source, precision or semantics cannot be preserved, ELIOT chooses one explicit disposition:

```text
retain exact handle only;
return a narrower extractive view;
mark the whole unit incomplete/unsupported;
route to a compatible contour;
block only the dependent decision/effect.
```

It may not silently mix exact and degraded fields in a way that makes the logical unit appear complete. Enrichment is additive: derived summaries, graph hints and generated prose never replace the exact retained source or reduce its disclosure/influence lineage.

For multi-source packets, bounded evidence allocation prevents one verbose source/agent/tool from exhausting the entire view before load-bearing rivals, unknowns or negative evidence are represented. Allocation policy remains a versioned `ContextRecipe` and is evaluated by decision/outcome delta rather than equal-token aesthetics.

### Selection integrity

`ARCH-CTX-04` requires that retrieval proposes and the compiler admits. The risk is that untrusted content changes **membership** rather than instructions: a document that inflates its own relevance, a tool result that displaces a competing source, or a summary that quietly drops the counterexample.

Every membership-changing transformation — ranking, pruning, deduplication, summarization, context compilation and export — appends an immutable stage to one chain receipt:

```yaml
SelectionIntegrityReceipt:
  receipt_identity_root_context_recipe_and_state_fence:
  initial_candidate_count_digest_and_taint_summary:
  transform_stages:
    - ordinal_transformer_identity_and_config_digest:
      input_membership_count_and_digest:
      output_membership_count_and_digest:
      admitted_and_rejected_candidates_with_reason:
      untrusted_input_influenced_membership: true | false | unknown
      suppressed_counterevidence_or_minority_items:
      budget_or_policy_forced_omissions:
  final_selected_set_count_digest_and_packet_or_export_ref:
  expansion_handles:
```

A stage may append but never overwrite an earlier membership decision. `untrusted_input_influenced_membership = unknown` is admissible and is itself a finding: it lowers the claim ceiling of the resulting packet instead of being resolved by assumption.

## I12.14. Hot path

The hot path is a bounded synchronous control/evidence path assembled from the `hot-spine` crate group defined in I2.15. It may include many Rust crates while remaining one in-process call graph inside Kernel or `eliotd`.

```text
session/task lookup;
State Fence and Governance Profile check;
exact current-state/cue lookup;
precomputed activation/attention read;
authority/admission decision;
packet delta and decision-local tail assembly;
ready capability/profile lookup;
small canonical read/write admission and receipt.
```

It MUST NOT perform:

```text
model inference;
Dreamer/Watchdog Agent call;
process or service startup;
Cargo/rustc/test execution;
semantic indexing or graph rebuild;
network discovery;
migration/repair;
unbounded storage scan;
unbounded decompression/rendering;
waiting on an optional Module that is not already READY.
```

Hot-path dependencies are explicit in `HotPathManifest`:

```yaml
HotPathManifest:
  operation:
  owning_service:
  crate_closure:
  immutable_snapshot_dependencies:
  queues_and_capacity:
  synchronous_external_calls:
  fallback_or_degradation:
  HotPathProfile_ref:
```

Rules:

```text
crate closure must be acyclic and free of vendor SDK leakage;
state is read through immutable/revisioned snapshots where possible;
queues are bounded and expose backpressure;
no hidden global singleton or detached task;
optional process call is allowed only under I2.15 readiness/latency/fallback contract;
semantic/cold work updates PendingContextDelta asynchronously;
failed/stale evidence returns handle, unknown, probe or RecoveryDirective;
no background work is smuggled into a gate because the caller is waiting.
```

Every hot operation has measured queue wait, service time, allocations, lock contention, cache behavior and degradation rate. A crate entering the hot-spine group requires a HotPathProfile and an affected product pulse.

## I12.15. Bounded spreading activation

Optional derived feature after direct cue:

```text
depth and fan-out bounded;
edge weights fixed per versioned profile;
max accumulation, not popularity sum;
exact match remains first;
trace records activation path;
no blocking based on semantic spread alone.
```

Specific weights are Implementation profile and benchmarked before default enablement.

## I12.16. Context consistency

Compiler:

```text
derives the exact dependency RevisionHead keys and reads them as Fence A;
queries required projections;
reads the same RevisionHead set as Fence B;
if every relevant dependency is unchanged → coherent;
if changed once → retry;
if churn persists → return explicit stale/partial sections or require refresh.
```

It does not claim simultaneous observation of independent truth surfaces when none exists.

## I12.17. Compaction and resume

Pre-compaction `HandoffCheckpoint` preserves:

```text
goal/acceptance;
current plan revision;
done/open/killed/deferred;
current epistemic position handles;
exact load-bearing atoms;
current diff/artifacts;
pending verifiers;
critical attention/conflicts;
next action and stop condition;
State Fence;
known losses.
```

Resume:

```text
revalidate scope/world/module generations;
revoke stale leases;
rebuild delta View from canonical state;
explicitly mark lost distinctions;
never treat summary as original rationale/evidence.
```

## I12.18. Prediction and calibration

Material causal/action model records before action:

```text
predicted verifier verdict;
predicted diagnostic change;
predicted effect/blast radius;
expected observable value/range;
confidence or alternatives where useful.
```

Matcher compares with VerificationRun, diagnostics, changed artifacts and real effects.

Outcomes:

```text
hit;
partial;
miss;
unresolvable.
```

Calibration is per scope/subsystem/task family/model-harness route. It informs decisions; it is not a universal understanding score.

Typed relation state prevents topology or co-change from being laundered into causality:

```yaml
CausalRelationEvidence:
  relation_and_endpoints:
  status: STRUCTURAL | BEHAVIORAL_CORRELATION | CAUSAL_HYPOTHESIS |
          PREDICTION_SUPPORTED | INTERVENTION_SUPPORTED | REFUTED | UNKNOWN
  mechanism_and_rival_refs:
  predeclared_predictions:
  intervention_or_discriminator:
  observed_outcome_and_verifier:
  counterfactual_and_confounder_disposition:
  scope_transfer_boundary:
  evidence_lineage_and_state_fence:
```

Only `INTERVENTION_SUPPORTED` or an explicitly qualified natural experiment may support a causal operational claim; `PREDICTION_SUPPORTED` remains defeasible, and structural/behavioral edges remain navigation or hypothesis evidence. Missing confounder/counterfactual information is `UNKNOWN`, never an implicit positive edge. Relation status is revised forward and retains prior evidence.

## I12.19. Negative memory

Exact deterministic trigger can block/requires probe within matching scope. Semantic similarity only warns.

```yaml
FailureFingerprint:
  trigger:
  failed_action:
  affected_scope/resources:
  violated_invariant:
  evidence:
  causal_status:
  do_not_repeat_until:
  reopen_condition:
  discriminative_check:
  false_activation_history:
```

Extinction narrows influence after new evidence; history remains.

## I12.20. Influence revocation

When source/tool/verifier revoked:

```text
mark root invalid/revoked;
traverse explicit dependency closure;
remove current support/allowed influence from derived packets, procedures,
  indexes and swarm findings; preserve historical decisions but contest/reopen any
  current justification, plan or pending effect whose validity depended on the revoked source;
invalidate caches/context/module profiles;
retain forensic history;
rebuild from clean inputs;
ensure backup/restore purge/revocation ledger prevents resurrection.
```

Revocation/taint traverses model summaries, compiled views/wiki, SessionEpisode-derived claims, procedures, answer/context projections and benchmark/evaluation inputs. Any mixed-lineage derived item inherits the minimum allowed influence/assertability of its material supporting sources. If lineage incomplete, quarantine the bounded affected scope and open Problem State; do not purge the entire memory by similarity.

## I12.21. Memory ecology, residual experience and transfer

Memory ecology is evaluated per item and cluster, not only by corpus counts. `MemoryEcologyAssessment` preserves:

```text
retrieval, acknowledgement, verified-use and decision-delta history;
verification success, contradiction, stale-hit and false-activation history;
horizon/checkpoint, expiry/eviction regime and workload/exposure denominators;
representation path: raw episode | typed relation | compiled view | active context;
historical-recall and current-state outcomes separately;
correct | wrong-specific | abstained | unknown outcome classes;
evaluator revision/provenance, comparison/intervention and uncertainty;
context-dominance/gravity and maintenance/storage/curation cost;
minority evidence and unresolved discriminators;
where-applies / where-not-applies and transfer evidence;
negative-transfer, poisoned-influence and suppression history;
obsolete/current/reopen cohorts and valid-near-match positive controls for negative memory;
residual distinctions lost or retained by compression;
recommended keep, narrow, split, compress, suppress, archive, reactivate or review action.
```

Influence is represented as an observable ladder, never one boolean:

```text
stored
→ available
→ delivered
→ acknowledged
→ expanded
→ cited_or_used
→ changed_decision_or_action
→ used_for_verification
→ outcome_supported_or_refuted.
```

The ladder may skip states only when stronger downstream evidence exists. A Delivery Receipt proves only delivery. An acknowledgement proves only receipt. A model statement that memory was useful is candidate evidence until linked to a public decision/action/verifier/outcome. The system may infer use from exact downstream references, but it does not infer hidden thought.

Maintenance reports aggregate these assessments:

```text
candidate backlog;
stale/conflicted/superseded;
cue coverage;
false activations/blocks;
unused context cargo;
negative transfer;
poisoned influence;
missing forgetting;
promotion rate;
Dreamer curation quality;
reconstruction cost and decision quality.
```
Additional first-class capture/binding counter-metrics are:

```text
cold_capture_ratio
  observations captured without a current task binding / all captured observations;

time_to_binding_p50_p95
  elapsed time from cold capture to a governed WorkScope/task/reuse binding;

cold_capture_never_bound
  share still unbound at the declared observation-window end;

binding_rejection_or_rebind_rate
  wrong-scope/ambiguous bindings rejected or later corrected.
```

Dreamer curation may propose candidate bindings for cold observations using source, touched resources, time and later task evidence. Governor/Task owner validates the binding; Dreamer cannot promote support, task control or hot influence. A high cold-capture ratio is an orientation/ingress problem signal, not a reason to discard observations or weaken capture-first.

`MemoryLifecycleEconomicsProfile` measures the whole trajectory rather than only retrieval:

```text
capture/ingest;
read input/output, write and storage by representation path;
semantic construction and reconciliation;
logical rows, file/WAL bytes and device-write evidence separately;
write amplification and storage growth;
source-change → invalidation/revalidation freshness latency;
retrieval, packet, tokenizer/rendering and model-serving cost;
curation, forgetting, purge, rebuild and recovery cost;
wall-clock, tail latency and Human attention;
prevented errors and observed decision/outcome delta;
missing coverage, exclusions and amortization horizon.
```

A local improvement that hides cost in ingestion, background LLM jobs, storage, recovery or Human work is not a net improvement. `MemoryWorkloadProfile`, `MemoryPhaseCostRecord` and `FreshnessLatencySLO` import as projections of this empirical profile; they do not create universal fixed thresholds.

`WeakClaimEcologyProfile` is a scoped diagnostic, not a universal deletion/promotion threshold:

```text
weak_claim_rate = candidate_or_unverified_claims / evaluated_claims;
```

It records denominator, task/route/corpus profile, age and operation mix, evaluator revision, exclusions and uncertainty. A high rate yields `CONTEXT_PROFILE_UNVALIDATED`, `PROBE_REQUIRED` or a curation/evaluation candidate under the applicable profile; it never auto-promotes, auto-deletes or proves that the architecture is bad.

Memory revision/reconsolidation is represented through the existing canonical `MemoryTransition` / `WriteReceipt` owner and a derived `MemoryRevisionEvidence`, not a second memory system:

```yaml
MemoryRevisionEvidence:
  prior_and_new_record_or_model_refs:
  reactivation_trigger_and_task_scope:
  new_observation_outcome_or_prediction_error:
  old_and_new_epistemic_accessibility_and_influence_state:
  retained_narrowed_and_lost_distinctions:
  retrieval_downstream_use_interference_and_false_recall_checks:
  affected_procedures_views_and_dependency_closure:
  rollback_reopen_or_no_return_boundary:
  verifier_or_review_disposition:
```

Raw episodes and source observations remain immutable. Revision changes current support, applicability, accessibility or influence through forward transitions; it cannot rewrite the prior narrative as though it never existed.

Memory-lifecycle proof depth follows effect. A reversible accessibility-only change records a minimal reason, scope, reopen condition and outcome; it does not require the full evaluation below. A Material change to allowed influence requires a scoped `MemoryLifecycleEvaluation`. Physical purge or irreversible/no-return behavior requires the full closure, replica/backup/provider and resurrection checks. The full form is:

```yaml
MemoryLifecycleEvaluation:
  operation: suppress | demote | archive | quarantine | extinguish | physical_purge
  evaluator_kind_and_ground_truth_access:
  corpus_scope_age_operation_mix_and_exposure:
  current_obsolete_context_shift_and_valid_near_match_cohorts:
  false_delete_false_retain_false_block_and_reopen_counts:
  abstention_inconclusive_and_missing_coverage:
  delayed_OOD_and_downstream_noninferiority_or_harm_bound:
  replica_cache_backup_provider_and_disclosure_scope:
  restore_resurrection_and_no_return_test:
  uncertainty_and_terminal_disposition:
```

Rules:

```text
low use never reduces epistemic support by itself;
negative memory and invariants are not suppressed only because they rarely changed an action;
minority/counterevidence remains addressable until its discriminator or applicability is resolved;
procedure or theory transfer requires explicit target scope and local verification;
compression creates an ExperienceCompressionRecord naming sources, retained/lost distinctions, round-trip evidence, cost, revocation behavior and residual handles;
retrieval, repetition and model agreement do not reinforce support automatically;
negative transfer opens review of the source procedure/model and dependent influence closure;
without adequate adjudication, only reversible suppress/quarantine/archive is allowed—destructive purge or permanent extinction cannot claim epistemic safety.
```

Lifecycle changes are proposals unless mechanically reversible, derived and already authorized by policy. Dreamer may prepare the assessment; Governor applies only the allowed transition. One model's delete recommendation is never its own oracle. Proof depth may increase with observed harm or uncertainty, but a low-risk reversible suppression is not turned into a purge-grade ceremony.

## I12.22. Theory Portfolio and practical weighting

A `TheoryPortfolio` preserves competing scoped models. It does not collapse them into one scalar confidence.

```yaml
TheoryModel:
  theory_id:
  question_and_scope:
  proposition_or_mechanism:
  dependencies:
  supporting_evidence:
  counterevidence:
  predictions_and_tests:
  successful_and_failed_transfers:
  downstream_artifact/procedure effects:
  source/independence profile:
  freshness_and_revision_conditions:
  operational_status: candidate | usable | preferred | contested | stale | refuted
```

Update rules:

```text
independent observation, discriminative prediction hit and practical verifier success
  → add scoped support;

failed prediction, downstream artifact/procedure error, invalid verifier,
poisoned lineage or scope drift
  → reduce current applicability/support and open review;

agreement sharing one Evidence Lineage
  → one support family, not many votes;

success in new scope
  → transfer support only after revalidation;

replacement theory
  → old theory/history retained with supersession/revision links.
```

A theory that remains locally successful but causes errors in dependent models/procedures is not silently discarded; dependency graph opens or updates `ConflictSet(kind=theory_conflict)` and selects discriminative tests through Concilium.

## I12.23. Architecture and Implementation Knowledge pipeline

ELIOT treats its accepted design books as protected primary self-knowledge with different authority.

```text
Architecture
  defines intent, theory, decision anchors, Hard Boundaries and conflict rationale;
  has semantic precedence over Implementation.

Implementation
  defines the accepted current contracts, owners, protocols, state boundaries,
  DEFAULTs, Research Gates, failure behavior and observable proofs;
  may expose uncertainty or a migration gap but may not silently change intent.
```

Both accepted revisions are registered from exact bytes. Their identity is external to their own contents:

```text
accepted file bytes and BLAKE3/SHA-256 digest;
accepted revision, status and acceptance receipt;
Architecture heading/ARCH anchors and rationale;
Implementation I-section/appendix anchors, contract/default/experiment class,
owner, failure behavior, proof and Research Gate references;
change and supersession history;
dependent code/modules/tests/config/migrations;
invalidated briefs, packets and conformance projections.
```

The accepted Implementation digest is stored in the release/acceptance manifest and canonical source record; it is not self-embedded into the document being hashed.

Pipeline:

```text
Architecture acceptance
→ immutable Architecture SourceRecord
→ deterministic Architecture parser
→ ArchitectureIndex.

Implementation acceptance
→ immutable Implementation SourceRecord
→ deterministic Implementation parser
→ ImplementationIndex.

ArchitectureIndex + ImplementationIndex
→ typed dependency links to modules/contracts/tests/config/migrations
→ current conformance evidence from code/runtime/receipts
→ self-scope Task Understanding and Active Understanding View.
```

Parser output is derived and rebuildable. It never gains more authority than the exact accepted source. At minimum it preserves:

```text
source digest and exact anchor;
statement class and precedence;
owner and affected capability;
state/failure/recovery boundary;
observable proof or explicit Research Gate;
dependency and invalidation set.
```

For any Material change to ELIOT, `eliot.packet` MUST include the applicable Architecture anchors, applicable Implementation contracts/defaults, current support status, known deviations and affected guarantees. The agent does not receive both books wholesale.

Dreamer may produce `ArchitectureBrief`, `ImplementationBrief` or a combined `EliotSelfBrief`. Every brief carries both source digests, exact handles and the precedence boundary. It is a projection, not a new design authority.

Observed code, tests, generated schema, module manifests and runtime behavior are conformance evidence. They cannot replace accepted Architecture or Implementation merely because the running system behaves differently. A mismatch opens a scoped conformance Problem State with four separate possibilities:

```text
implementation defect;
stale or inaccurate Implementation text;
intentional governed deviation/migration gap;
Architecture question requiring Architecture Owner.
```

No automatic repair chooses among those meanings. Main Agent or Human decision authority resolves the issue with evidence and, when necessary, updates the appropriate book through its acceptance path.

## I12.24. Meta-learning and improvement delivery

ELIOT improves through evidence-backed advice, agent work and reversible experiments. It never silently rewrites code, policy or memory authority.

Learning has two loops (A14.5). The existing `ImprovementCandidate` pipeline below is the **outer** loop. The inner loop runs inside one active task and is represented by three durable learning records plus one immutable derived state view and one immutable activation receipt in this section. None becomes an owner: both loops reuse Durable Jobs, `AgentAttempt`, canonical records, registered evaluators, Context Compiler delivery and Governor admission. Neither loop creates a second task graph, attempt journal, scheduler, memory owner or authority path.

Mutable behavioral state is layered, and a lower layer never acquires authority over a higher one:

```text
Frozen Constitutional Anchor  user objective, values, Architecture, Hard Boundaries,
                              authority/privacy/cost ceilings, canonical write and finish semantics;
Stable Product Harness        accepted ELIOT generation and contracts;
Task-Family Harness           validated reusable recipe/profile for a compatible task class;
Campaign Overlay              rapidly changing task-local executable/behavioral state;
Attempt Working State         ephemeral reasoning, scratch artifacts and next action.
```

`Frozen` means fixed for the exact campaign/task-definition revision. An authorized change to objective, Architecture, boundaries or ceilings supersedes that baseline, creates a new State Fence and forces revalidation; it does not make Architecture globally immutable.

```yaml
ImprovementCandidate:
  candidate_id:
  trigger_problem_or_metric:
  evidence_and_trace:
  affected_scope/task_family/module:
  root_cause_hypotheses:
  proposed_change:
  expected_delta:
  counter_metrics:
  validity_scope:
  owner_and_decision_authority:
  delivery_target:
  canary_plan:
  rollback:
  stop_condition:
  lifecycle: proposed | triaged | accepted_for_experiment | running |
             supported | narrowed | rejected | rolled_back | stale | archived
```

Triggers:

```text
repeated failure/repair or no-progress loop;
false block/false positive;
context/retrieval/memory-transformation regret;
module/route/recipe drift;
accepted `ImplementationDeviation`;
Human/agent complaint;
security incident;
Architecture/Implementation/runtime conformance gap;
positive surprise with plausible reusable value: unexpected success, cheaper path, correct abstention,
  useful environment discovery, better decomposition or verifier choice;
successful transfer or evidence that an existing procedure is unnecessary;
Dreamer/Watchdog/Concilium suggestion.
```

Pipeline:

```text
instrumental signal/outcome
→ durable Problem or evidence set
→ Dreamer/Concilium analysis only when semantic work adds value
→ deduplicated Improvement Candidate
→ concise Improvement Brief to active Main Agent or Human at a safe boundary
→ decision owner selects reject / investigate / work item / experiment
→ isolated worktree or candidate Module generation
→ fixed replay as diagnostic evidence only
→ affected checks + matched-budget live shadow/canary on untouched work
→ delayed outcome/rework/maintenance window and rollback reconciliation
→ promote, narrow, rollback or archive
→ update external inheritance and route/module profiles.
```

`ImprovementBrief` shows problem, evidence, likely benefit, risk, proposed owner, cost, next reversible step and what remains unknown. The named decision owner does not search raw metrics.

Replay-only evidence cannot promote a policy/module/Skill/retrieval change. The evaluation record binds the single canonical `BudgetEquivalenceLedger` and `ComplexityEconomicsDelta` contracts of I18.47. Actual compute/tool/test-time-scaling/Human costs, frozen same-budget and compute-matched alternatives, replay→live transfer and delayed harms remain visible. An unmatched ledger or inconclusive complexity delta cannot promote the candidate merely because replay or a local metric improved.

Application classes:

```text
advisory
  default; changes nothing until owner acts;

pre-authorized reversible tuning
  bounded parameter/ranking/application-queue profile or `ContextRecipe` inside a declared safe range;
  one experiment per control surface, automatic rollback;
  never changes authority, privacy, finish semantics, Decision Safety Floor, ContextAtomPolicy,
  verifier definition, canonical durability, Kernel/Watchdog reserve or last-resort recovery capacity;

code/module/config change
  normal work item, impact tests, immutable candidate, canary and rollback;

schema/authority/verifier/privacy/Architecture/destructive forgetting
  explicit owner decision and corresponding migration/proof.
```

External research or foreign-project findings enter this pipeline only as `KnowledgeTransferCandidate`, a typed view of `ImprovementCandidate` that binds source scope/population, transfer limits, local discriminator, target task family, expiry and forbidden direct instruction use. It may yield a Skill, procedure, Default, FailureFingerprint or rejected transfer only after local evidence; source repetition or prose quality does not promote it.

### `CampaignLearningStateView`

Compact immutable view from which the next materially comparable attempt is compiled. It is generated from exact existing owner revisions; it is not a transcript, mutable campaign aggregate, scheduler, journal or new semantic owner.

```yaml
CampaignLearningStateView:
  view_id_revision_and_built_at:
  campaign_task_recipe_and_state_fence:
  source_owner_revisions:
    task_controller_objective_acceptance_plan_and_open_items:
    agent_attempt_lineage_and_latest_outcomes:
    governor_admission_authority_epoch_and_policy_snapshot:
    context_compiler_recipe_tool_surface_and_delivery_revision:
    evaluator_contract_holdout_and_result_refs:
    memory_experience_and_artifact_projection_refs:
  frozen_anchor_digest:
  stable_and_task_family_harness_refs:
  active_campaign_overlay_ref:
  current_position:
    objective_acceptance_open_items_and_next_safe_action:
    active_hypotheses_rivals_unknowns_and_confounders:
    active_candidate_parent_branch_and_next_discriminator:
  experience_position:
    attempt_lineage_failure_signatures_and_exact_trace_handles:
    relevant_prior_campaign_or_task_family_learning_refs:
    bounded_campaign_experience_retrieval_plan_refs:
    preserved_success_set_or_constraints_ref:
  adaptation_position:
    latest_attempt_learning_delta_and_changed_surfaces:
    local_updates_pending_revalidation:
    reusable_candidate_and_rejected_or_expired_update_refs:
  evaluation_position:
    applicable_gate_results_noise_uncertainty_and_holdout_integrity:
  economics_and_progress:
    tokens_cost_wallclock_tools_human_attention_and_verified_delta_history:
    equivalent_retry_failure_plateau_and_intervention_state:
  completeness_scope_and_required_fields_ref:
  completeness: COMPLETE_FOR_DECLARED_RECIPE | PARTIAL | STALE | BLOCKED
  missing_or_stale_owner_refs:
  invalidation_expiry_and_rebuild_reason:
```

The history slice is compiled through one or more campaign-scoped `RetrievalPlan` records from I12.26. It may expose exact handles, bounded summaries, diffs or raw slices permitted by disclosure/retention policy, but it never copies the full campaign into a second store. A future object named `CampaignExperienceView` may be admitted only as a read-only generated projection over the same canonical records after its P2 Product Proof; it cannot become a memory owner or mutable campaign aggregate.

`COMPLETE_FOR_DECLARED_RECIPE` means only that every field required by the bound recipe/revision and State Fence is present and current; it never means complete history, complete world knowledge or complete evidence. The view never accepts writes and never resolves disagreement between owners. Context Compiler verifies every load-bearing revision and State Fence before use. `PARTIAL` may support a narrower safe attempt only when omitted fields are explicitly non-load-bearing; `STALE`/`BLOCKED` cannot be silently filled from a transcript, model memory or a convenient current file. A new owner revision rebuilds the view rather than mutating it in place.

### `AttemptLearningDelta`

The durable edge from one consequential attempt to the next materially related attempt. Without this edge an attempt may store a failure, open a candidate and still repeat the same strategy.

```yaml
AttemptLearningDelta:
  delta_id_revision_campaign_attempt_and_state_fence:
  actor_route_overlay_and_artifact_identity:
  before:
    hypothesis_prediction_and_selected_strategy:
    expected_observable_and_verifier:
  observed:
    raw_trace_and_artifact_refs:
    evaluator_outcome_and_actual_effect:
    coverage_noise_and_unknowns:
  interpretation:
    supported_and_contradicted_mechanisms:
    confounders_and_shared_changed_surfaces:
    attribution_ceiling:
  next_behavior_delta:
    changed_hypothesis_strategy_or_abstraction:
    changed_context_memory_skill_tool_or_route_use:
    changed_candidate_parent_verifier_order_or_search_probe_stop_condition:
  retry_relation:
    materially_equivalent_to_prior_attempt: true | false | unknown
    unchanged_retry_reason: replication | noise_estimation | controlled_comparison |
                            exact_reproduction | recovery_proof | verifier_calibration | none
  persistence:
    overlay_revision_ref_and_reusable_candidate_refs:
    activation_scope_expiry_and_rollback_condition:
  disposition: LOCAL_UPDATE_ADMITTED | NEXT_PROBE_CHANGED | REUSABLE_CANDIDATE_OPENED |
               NO_JUSTIFIED_CHANGE | INCONCLUSIVE | INVALID_EVIDENCE
```

Actor/Refiner may propose interpretation and next-behavior fields; immutable attempt/evidence owners supply their references, and Governor admission is required before any behavioral effect. The record is not a second attempt journal and cannot rewrite source evidence, task truth or evaluator state.

A consequential boundary is a material implementation attempt, a verifier outcome, a substantial recovery attempt, a repeated failure signature, a campaign checkpoint or plateau, a route/model handoff, an accepted artifact outcome, a finish/cancel/supersession, or a delayed regression. A `read_file` or `grep` is not consequential. Most fields are derived from existing attempt and evidence records; the agent is not required to author prose after every step.

### `CampaignHarnessOverlay`

Versioned task-local behavioral artifact that the next attempt is compiled from.

```yaml
CampaignHarnessOverlay:
  overlay_id_revision_parent_and_state_fence:
  stable_and_task_family_harness_base_refs:
  task_framing_and_local_context_recipe_delta:
  task_local_memory_and_working_rules:
  local_skills_checklists_and_helpers:
  tool_surface_and_invocation_delta:
  decomposition_route_and_abstraction_delta:
  verification_order_and_search_probe_stop_rules_delta:
  source_attempt_learning_delta_refs:
  changed_surfaces_and_exact_artifact_refs:
  intended_mechanism_predeclared_prediction_and_expected_observable:
  expected_fixed_tasks_or_failure_signatures:
  possible_regressions_confounders_and_co_changes:
  next_discriminator:
  preserved_success_constraints:
  allowed_effect_and_authority_ceiling:
  validation_status_and_results:
  expiry_invalidation_and_rollback:
```

Actor/Refiner proposes the artifact; Governor admits its local effect; Context Compiler activates it for a compatible attempt. Task Controller and Governor retain objective, plan-revision and authority ownership. The artifact has no independent authority. For every nontrivial revision, the changed-artifact, intended-mechanism, prediction, expected-observable, regression/confounder, preserved-success and next-discriminator fields are frozen **before** evaluation. Together with the source `AttemptLearningDelta`, activation receipt and closure lineage, they carry the donor `HarnessChangeManifest` semantics; no separate mutable manifest or second change owner is created.

Lifecycle:

```text
PROPOSED → SHAPE_VALIDATED → LOCAL_ADMITTED → ACTIVE_FOR_NEXT_ATTEMPT → OBSERVED
→ RETAIN_LOCAL | OPEN_REUSABLE_CANDIDATE | REVISE | ROLLBACK | EXPIRE | INVALIDATE
```

Local admission requires the same user objective and acceptance revision, no authority/privacy widening, no evaluator or sealed-holdout modification, reversible local effect, a named source delta and parent, a next discriminator and a rollback path. An overlay is not canonical doctrine and is not visible to unrelated tasks. It cannot change the user objective, Architecture, Hard Boundaries, authority/privacy/cost ceilings, canonical write or finish semantics, the oracle used to promote the same candidate, sealed holdout answers, the stable production generation, provider identity while claiming a same-route comparison, or its own promotion decision. It may open a candidate to change any of these; it may not apply one as a local shortcut.

A local overlay may change only bounded search or probe stopping rules and verification ordering within the current task plan. It cannot change task-level stop, finish, acceptance, cancellation, budget, or authority policy. Any task-level policy change remains an Improvement or plan candidate, requires a Task Controller plan revision plus Governor admission through the normal authority path, and is never applied by Context Compiler alone.

### `HarnessActivationReceipt`

Immutable per-attempt evidence that records whether the admitted learning surface was eligible, compiled, retrieved and delivered, whether qualifying observable activation occurred, and whether its prescription was followed or violated. Receipt existence never implies successful delivery, use, adherence or benefit. It does not grant authority, schedule an attempt or infer causal benefit.

```yaml
HarnessActivationReceipt:
  receipt_id_revision:
  campaign_attempt_actor_route_and_state_fence:
  compiled_from_campaign_learning_state_view_ref:
  context_compiler_and_render_profile_revision:
  exact_stable_task_family_overlay_skill_memory_and_procedure_refs:
  preserved_success_set_or_constraints_ref:
  eligibility_and_retrieval_reason:
  retrieval:
    status: NOT_ELIGIBLE | ELIGIBLE_NOT_RETRIEVED | RETRIEVED | EXPANDED | UNKNOWN
    expansion_or_tool_query_refs:
  delivery:
    status: NOT_DELIVERED | FULL | PARTIAL | MISSING
    packet_position_serialized_digest_bytes_and_actual_tokens:
  activation:
    status: NOT_ASSESSED | NOT_OBSERVED | OBSERVED | UNKNOWN
    acknowledgement_ref:
    observation_limit_reason:
    first_qualifying_observable_use_ref:
  adherence:
    status: NOT_ASSESSED | OBSERVED_FOLLOWED | OBSERVED_PARTIAL | OBSERVED_VIOLATED | UNKNOWN
    early_mid_final_checkpoint_refs:
    prescribed_or_avoided_action_and_required_verifier_refs:
  conflicts_suppression_or_compaction_loss:
  downstream_decision_action_artifact_and_verifier_refs:
  receipt_completeness_and_missing_fields:
  invalidation_expiry_and_missingness:
```

Retrieval, delivery, observable activation, adherence and outcome remain orthogonal; the fields are not a success ladder. A retrieved update may not be delivered, a delivered update may have no qualifying use observation, and an observed use may violate the prescription or be harmful. An acknowledgement is a delivery/attention signal only and never substitutes for `first_qualifying_observable_use_ref`. `activation.status = NOT_OBSERVED` means only that no qualifying activation evidence was observed; it does not prove non-use. No activation receipt proves adherence, attribution, benefit or promotion. Exact downstream benefit remains subject to I7.27 and I12.34. Missing or inconclusive observability remains `UNKNOWN`, never presumed compliance.

### `CampaignLearningClosure`

Terminal or major-checkpoint consolidation for one campaign.

```yaml
CampaignLearningClosure:
  closure_id_revision_campaign_and_state_fence:
  closure_due_at_expiry_and_terminalized_at:
  closure_owner_and_terminalization_policy_ref:
  starting_and_final_harness_stack:
  outcome_summary:
    artifacts_effects_verifiers_and_solved_scope:
    cost_time_and_human_attention:
    delayed_outcome_status:
  learning_summary:
    validated_local_adaptations_and_rejected_updates:
    failure_mechanisms_closed_or_open:
    preserved_success_and_regression_results:
    activation_and_adherence_findings:
    attribution_and_confounders:
  inheritance_actions:
    first_order_epistemic_updates:
    retained_campaign_local_state:
    reusable_and_structural_candidates:
    negative_memory_and_reopen_conditions:
  disposition: LOCAL_LEARNING_RETAINED | REUSABLE_CANDIDATE_OPENED | SCOPED_UPDATE_PROMOTED |
               NO_REUSABLE_DELTA | INCONCLUSIVE | DEFERRED_OUTCOME | REJECTED_TRANSFER | ROLLED_BACK
  future_activation_scope_retention_and_revalidation:
  owner_receipts_and_expiry:
```

Closure is assembled through existing Meta, Memory OS and Governor paths from canonical evidence. Its disposition records, but never performs, a promotion; `SCOPED_UPDATE_PROMOTED` is valid only with the separate authorized owner receipt it references.

`NO_REUSABLE_DELTA` is a legitimate and explicit disposition: one-off external event, insufficient evidence, existing procedure already covered the case, mechanism not identified, update cost above expected value, unsafe transfer, task too unique, or immature product outcome. Silence is not a disposition, because it hides lost learning.

Closure does not block the finish ceremony. A task may reach an honest `FinishDecision` while learning closure completes asynchronously, provided raw evidence is durable, the next task cannot silently use an unclosed candidate, learning debt is visible and an owner/review condition exists. A consequential episode is not learning-closed until it has a disposition.

Before closure, only the exact non-expired `LOCAL_ADMITTED` overlay of the active campaign may influence a compatible attempt. A draft delta, unclosed reusable candidate, expired overlay, or ownerless learning record is ineligible for retrieval, delivery, compilation, or use by another task. Cross-task carryover requires a new governed admission that revalidates scope, authority, retention, evaluator, and rollback. Expiry invalidates influence; it does not silently retain the last behavior.

Active candidate backlog is bounded by target surface and value. Duplicates merge by evidence lineage; stale/ownerless low-value candidates are summarized and archived. Advice quality is measured by adoption, verified delta, regressions, false positives, Human/agent attention cost and rollback rate. Repeatedly disproven advice loses priority; report polish creates no weight.

### D1 named-record disposition and rollout gates

The D1 donor's named objects are not silently dropped or implicitly admitted. The following table is the authoritative disposition for those names; it separates preservation of a mechanism from admission of a new schema/owner.

| D1 name | Disposition | Current normative mechanism | Admission/rollout boundary |
|---|---|---|---|
| `CampaignLearningState` | **MERGED / RENAMED** | immutable generated `CampaignLearningStateView` over exact existing owner revisions | P1 target contract; no mutable aggregate, store, scheduler or journal |
| `CampaignExperienceView` + `ExperienceQuery` | query mechanism **MERGED**; separately named view **DEFERRED** | campaign-scoped `RetrievalPlan` in I12.26 plus bounded result handles in `CampaignLearningStateView` | named read-only view may be admitted at P2 only after measured need/Product Proof; never a canonical memory owner |
| `HarnessChangeManifest` | **MERGED** | pre-evaluation frozen fields on `CampaignHarnessOverlay`, source `AttemptLearningDelta`, activation receipt and closure lineage | no separate mutable manifest or change authority |
| `FailureMechanismCluster` | named schema **DEFERRED** | exact failure signatures, supported/contradicted mechanism hypotheses, rivals, confounders and next discriminators remain in existing attempt/delta/evidence records | P2 only after clustering precision, correction path and owner seam are proved; similarity alone cannot create mechanism truth |
| `PreservedSuccessSet` | mechanism **REQUIRED where applicable**; separately named view **DEFERRED** | `preserved_success_set_or_constraints_ref`, frozen regression constraints and existing evaluator/holdout owners | P3 admission requires a bounded selection rule, sealed-case handling, expiry/requalification and demonstrated forgetting detection |
| `TaskFamilyHarnessPortfolio` | **DEFERRED** | current stable/task-family harness revision references and existing router/profile evidence | P3 only after bidirectional transfer, retention, routing and complexity/cost evidence; no portfolio owner is implied now |
| `LearningPlateauSignal` | **MERGED** | `CampaignLearningStateView.economics_and_progress`, I16.23 no-progress telemetry, Watchdog observation, Task Controller plan revision and Governor admission | no new mutable signal owner; a later generated view must preserve the same owner separation |
| `LiveLearningDevelopmentCampaign` | alias **REJECTED** | canonical recipe name is `LiveLearningCampaign` | a second recipe/task/scheduler identity is forbidden |

`DEFERRED` above applies to the named schema/rollout level, not to the underlying requirement. Exact history access, pre-evaluation change lineage, preserved-success constraints, plateau detection and task-family boundaries remain represented by their current owners. Equivalent fields do not authorize an undeclared root record, table, scheduler, task graph, evaluator, promotion authority or global harness state.

## I12.25. Canonical cognitive record semantics

Useful distinctions from the old Canonical Master and Governor are retained by their owning sections and the cold donor inventory. Main distinctions:

```text
SourceSnapshot / EvidenceAtom / ToolObservation preserve observation;
ClaimCard / HypothesisCard / TheoryPortfolio preserve interpretation and rivals;
DecisionNote / ActiveDecisionState preserve commitments and rationale;
FailureFingerprint / SkillCard preserve scoped procedural experience;
ContextPacket / ContextCargoReceipt preserve selection and delivery;
ActionContract / ProbeEnvelope / VerificationRun preserve reality contact;
FinishAttemptDraft / DerivedCompletionProof / FinishDecision preserve honest closure;
Trace/Influence records preserve observed contribution without claiming hidden thought.
```

Record names may map to one Rust enum/table family, but these semantic differences cannot be collapsed.

## I12.26. Memory admission and retrieval trace

Candidate retrieval begins with deterministic known-handle lookup when a handle is supplied. Exact entity/path/symbol/error/task cues remain independently usable even when every graph is empty. The remaining routes are compiled into a `RetrievalPlan` from task, corpus, risk, freshness, coverage, latency and measured outcome/cost:

```yaml
RetrievalPlan:
  required_exact_routes:
  optional_routes: typed_relations | lexical | dense | graph | episode | Dreamer
  order_or_parallelism_and_reason:
  source_projection_fences:
  campaign_experience_query:
    campaign_or_task_family_scope:
    intent: NONE | FIND_SIMILAR_FAILURE | COMPARE_CANDIDATES | TRACE_DECISION |
            LOCATE_INFORMATION_LOSS | INSPECT_TOOL_LOOP | FIND_REGRESSION |
            FIND_PRIOR_SUCCESS | INSPECT_PARENT_LINEAGE | TEST_CONFOUND | RETRIEVE_RAW_SLICE
    exact_handles_and_filters:
    artifact_step_tool_error_and_metric_predicates:
    temporal_and_lineage_range:
    output_mode: INDEX | SUMMARY_WITH_HANDLES | DIFF | RAW_SLICE | GRAPH_NEIGHBORHOOD
    token_byte_and_time_budget:
    disclosure_retention_and_hidden-reasoning_fence:
  coverage_and_negative-claim requirements:
  budget_and_stop_conditions:
  fallback_or_abstention:
```

There is no universal `lexical → dense → graph` order. A hidden structural task may use a bounded graph route early; a known exact handle bypasses broad retrieval. `campaign_experience_query` is optional and `NONE` outside the applicable campaign/task-family scope. When present, it selects a bounded history slice from existing canonical attempt, memory, artifact, journal and Blob-handle owners; it does not create a `CampaignExperienceView` store, retain hidden provider reasoning or authorize full-history dumping. Every route remains subject to the same admission, disclosure, retention and proof ceilings, and its selected result/coverage handles are bound into `CampaignLearningStateView`.

`MemoryAdmissionDecision` evaluates:

```text
scope and State Fence;
epistemic status/freshness;
source assurance and allowed influence;
expected decision/information delta;
negative-memory/invariant/verifier value;
contradiction and framing risk;
token/latency cost;
repetition and distraction.
```

Outcome:

```text
include_exact;
include_handle;
include_with_warning;
require_revalidation;
suppress;
quarantine.
```

The associated `RecallDisposition` is a closed operational result, not a confidence scalar:

```text
ADMITTED_STRONG;
ADMITTED_WEAK;
NO_MATCH;
NO_USEFUL_MEMORY;
EMPTY_CORPUS;
SCOPE_SUPPRESSED;
STALE_PROJECTION;
CONFLICTED;
INCOMPLETE_COVERAGE.
```

It records scope and `TaskSelectionEvidence`, source/projection revisions and State Fence, freshness/coverage/assurance ceiling, visible and suppressed counts, route costs, a short agent-facing reason and the full rank-trace handle. Historical `LOW_CONFIDENCE` output maps to `ADMITTED_WEAK`; it is not a separate canonical disposition.

Before a retrieved candidate is projected or cited, coherent readback reopens the exact admitted source revision under the same `SourceView`, workspace-view revision and State Fence; verifies digest and byte length; resolves the requested anchor through its exact coordinate/native mapping; and verifies the selected unit or excerpt digest. Bytes currently present at a path cannot be cited as an earlier revision. Index/vector payload text may be shown as a non-authoritative preview, but citation and support require governed source readback. A missing revision, mapping or digest produces a narrower unsupported result, replan or typed gap—never a citation to convenient current bytes.

Before exact cue firing, source/projection revisions and the State Fence are compared. A mismatch yields `STALE_PROJECTION`, `PACKET_REFRESH_REQUIRED` or `PROBE_REQUIRED`; stale projection data is never silently injected into a Material decision.

Every material inclusion/suppression has `FusedRankTrace` or equivalent:

```text
candidates considered;
features and exact relations;
selected tier;
suppression reasons;
packet location;
dependency/invalidation set.
```

Vector similarity can nominate a candidate; it cannot create evidence, relation, blocker or causal status.

## I12.27. Metacognitive projections

Derived views:

```text
CoverageMap      — covered/thin/blind by subsystem/WorkScope;
NoveltyFlag      — touched entities with little/no prior evidence;
DangerZone       — hotspots, failures and high-impact paths;
CalibrationView  — prediction/outcome agreement by task family/subsystem;
IntegrationView  — actual observation/enforcement/supervision capabilities;
MemoryHealthView — stale/conflicted/duplicate/false-activation/influence trends.
```

These are computed from records/graphs/receipts. Model self-report may be additional evidence but never the sole calculation.

## I12.28. Concept and behavioral build artifacts

Concept Pyramid artifacts are versioned derived records:

```text
Project Charter;
System Map;
Subsystem Capsule;
Module/Workflow Card;
Architecture Brief;
Implementation Brief.
```

Each has:

```text
fixed purpose/section contract;
source/dependency manifest;
exact anchors;
budget profile;
fresh/dirty/stale state;
build receipt;
supersession chain.
```

Compilation pipeline:

```text
1. seed boundaries from manifests/directories/static graph and behavioral clusters;
2. create total file/artifact → concept mapping; unresolved items enter `_unassigned`;
3. fill entrypoints, invariants, dangers, decisions and verifiers deterministically;
4. ask Dreamer/model only for bounded purpose/boundary synthesis when needed;
5. validate every load-bearing sentence against handles and scope;
6. publish as derived projection with dependency manifest and build receipt;
7. mark dirty from outbox dependency changes and rebuild asynchronously;
8. Requester/WorkScope Owner may supersede, rename or split within authority; deterministic onboarding itself does not wait for a preference decision.
```

Deterministic sections are filled from graphs/records. Model jobs write only semantic synthesis that cannot be derived mechanically. Invalid anchors or excessive loss prevent publication; a deterministic degraded fallback keeps onboarding moving. Publication of a derived projection never upgrades the underlying claims.


Decision/capsule freshness also records dependency drift separately from truth status:

```yaml
DependencyDriftObservation:
  subject_ref:
  dependency_set_at_birth:
  changed_dependency_refs:
  changed_fraction_or_structural_delta:
  source_and_current_fences:
  interpretation: unchanged | review_required | incompatible | unknown
  evidence_refs:
```

A changed dependency set does not by itself contradict or supersede a decision. It raises a revalidation obligation. A hotspot or central component lacking rationale, invariant, verifier or current owner creates a `ConformanceGap`; it does not become a model-generated explanation.

Behavioral graph jobs retain:

```text
co-change support/confidence;
hotspot/churn/failure density;
mining window and classifier version;
static-edge existence;
run receipt and head commit.
```

Correlation remains correlation.

## I12.29. Calibration aggregation and staleness

I12.18 owns per-action prediction capture and matching. This section owns only aggregation:

```text
aggregate by WorkScope/subsystem/task family and exact model-harness-route profile;
exclude `unresolvable` from hit/miss rates while reporting its frequency separately;
retain prediction/evidence lineage and sample distribution;
mark aggregate stale when verifier, route, Tool Definition, context policy or relevant environment profile changes;
use the result for routing/inquiry/Improvement Candidates, never as a scalar understanding authority.
```

## I12.30. Memory trajectory error registry

`MemoryTrajectoryCorrectness` tracks explicitly:

```text
stale_read;
false_promotion;
missed_forgetting;
wrong_scope_reuse;
negative_transfer;
poisoned_memory_use;
false_activation;
false_block;
missing_context_regret;
lossy_transformation;
revoked_influence_resurrection.
```

These errors drive Dreamer/Meta candidates; they are not all release blockers.

## I12.31. Rationale and handoff

Decision rationale is captured at the decision boundary:

```text
chosen option;
why now;
alternatives and rejection reasons;
confidence/unknowns;
revisit conditions.
```

If missing, record is marked degraded rationale. Dreamer may add a retrospective hypothesis, never rewrite it as original rationale.

`HandoffArtifact` preserves control state, exact anchors, current diff/artifacts, pending verifiers, killed/forbidden resumptions, next action and State Fence. Resume revalidates reality; prose summary alone is insufficient.


Every Material decision/resume exposes typed `DecisionExecutionLineageRefs`:

```yaml
DecisionExecutionLineageRefs:
  governing_goal_acceptance_and_task_revision:
  observations_evidence_and_current_epistemic_position:
  theory_rivals_unknowns_and_rationale:
  decision_and_ActionContract:
  proposed_authorized_and_observed_effect_refs:
  operation_diff_and_change_observation_refs:
  original_and_current_anchor_resolution_refs:
  anchored_review_item_and_disposition_refs:
  artifact_and_verifier_refs:
  outcome_and_memory_revision_refs:
  state_fence_authority_epoch_and_supersession:
  completeness: COMPLETE | PARTIAL | STALE | UNKNOWN
```

A Material resume or claimed continuation fails closed when a load-bearing lineage ref is missing, stale or superseded. The chain proves reconstructable traceability, not causal benefit: outcome improvement still requires intervention, counterfactual or another credible comparison.

The public handoff/review surface exposes the `ChangeProvenanceView` from I12.10, not hidden reasoning. It supports both directions:

```text
public decision/conversation → operation/diff → historical/current code/artifact → verifier/outcome;
current code/artifact → touching operations/attempts → public decisions/reviews → verifier/outcome.
```

Each link is classified `exact`, `receipt_linked`, `correlated`, `ambiguous` or `unknown`. Review, resume and incident diagnosis may use correlated links as inquiry cues, but only exact/receipt-linked evidence may satisfy a claim that one decision produced one change. Original anchors and historical deleted targets remain navigable even when no current anchor can be resolved.

## I12.32. Context Economy Ledger

Context efficiency is measured without making compactness the objective.

```yaml
ContextEconomyReceipt:
  task_route_profile:
  context_recipe_ref:
  envelope_selection_receipt_ref:
  delivered_payload_and_handle_cost:
  instruction_layer:
    delivered_instruction_directive_and_negative_memory_atoms:
    omitted_atoms_and_reason:
    actual_tokenizer_tokens_and_position:
    instruction_related_failure_or_recovery_refs:
  compilation_stage_costs:
    exact_retrieval:
    optional_retrieval:
    admission_ranking:
    render_omission:
    lint_scorecard_measurement:
    receipt_persistence:
  telemetry_cost:
    CPU_time_wall_time_allocations_bytes_and_IO:
    sampling_profile_and_coverage:
    omitted_measurements_and_reason:
  per_tool_delivery:
    - tool_call_and_result_ref:
      unique_payload_bytes:
      rendered_tokens_by_actual_tokenizer:
      cumulative_replayed_tokens:
      delivery: FULL | PARTIAL | TRUNCATED | MISSING
      expansion_count:
      decision_delta_or_unused:
  cold_orientation_reads_queries_and_expansions:
  time_to_first_safe_material_action:
  reconstruction_or_rehydration_cost:
  missing_context_regret:
  decision_verification_outcome_refs:
  baseline_or_comparison_class:
  net_cost_delta:
```

Rules:

```text
compare within the same task family, route, tools and Governance Profile;
critical context may be token-positive when it prevents material risk;
positive token delta alone does not justify suppression if decision quality improves;
repeated context with no observed decision/proof value creates an Improvement Candidate;
handles-only or layout changes are canary experiments with rollback;
model output tokens are not disguised as orientation savings.

Raw provider events remain step-level evidence: uncached input, cache read/write, text output, exposed reasoning, provider total, component-sum delta, missingness, retry/compaction and billing/context-occupancy semantics are preserved where exposed. Session summaries cannot overwrite those events. Tool schemas/results are attributed separately only under a controlled counterfactual; otherwise they remain part of total prompt/context cost.
```

This preserves the useful UL token ledger while subordinating it to correctness, decision sufficiency and observed outcomes.


The same receipt distinguishes the work stages that a compact-context claim may otherwise hide:

```text
time_to_bounded_orientation;
time_to_first_attempted_action;
time_to_first_safe_material_action;
time_to_first_correct_action;
time_to_first_applicable_verifier_result;
rework after the first action.
```

A `ContextMeasurementEvidence` binds the exact serialized envelope digest, serializer options, actual tokenizer identity/version, actual rendered tokens, estimator identity/value/error, placement/relevance profile and any provider rewrite/truncation. False-safe overflow and false rejection/decomposition are measured separately; an unqualified estimator cannot prove a floor fits.

A claim that selective/compacted context preserves quality requires a predeclared comparison against the safest applicable larger-context or token-matched baseline, a non-inferiority/quality criterion and a separate safety bound. When the Decision Safety Floor cannot be proven under the selected profile, the fallback is an admissible fuller context within the route's safe envelope, decomposition, a safer partial action or abstention—not silent compression.

## I12.33. Understanding Evaluation Job

A policy-scheduled or manually requested Durable Job tests reconstruction and prediction without creating authority.

```text
1. Select active/stale/high-risk subsystems or task families.
2. Generate grounded questions from exact graph/verifier/artifact state:
   entrypoints, invariants, blast radius, expected verifier, current unknowns.
3. Give the evaluated route only the declared cold-start inheritance slice.
4. Grade against exact anchors, registered verifier state and dependency graph.
5. Record coverage, calibration, lost distinctions and false confidence.
6. Mark affected derived projections dirty or propose an Improvement Candidate.
```

The job never promotes claims, changes policy, grants authority or marks tasks complete. Frequency, task sample and route matrix are policy/budget decisions; “weekly” is not a universal contract.

Applicable evaluation profiles include held-out/compositional, intervention/counterfactual or state-update, and unanswerable/stale cases; report abstention precision/coverage separately from answer accuracy and compare against a matched memory-free/control condition. A case may be `NOT_APPLICABLE`, but it cannot disappear silently from coverage accounting.


## I12.34. Cognitive proof ladder and ecological field proof

A lower proof level is not elevated by suite name or a polished report:

```text
TransportProof
  bytes/record crossed the intended boundary;

RetrievalProof
  correct scoped item was found and delivered;

UseProof
  agent demonstrably referenced it in a decision/action/verifier;

DecisionDeltaProof
  treatment changed first boundary, unknown, verifier or avoided failure;

OutcomeBenefitProof
  changed decision improved real artifact/verifier outcome
  relative to a matched control or strong counterfactual;

RetentionProof
  benefit remains after the declared delay/restart/requalification window
  and preserved previously verified behavior does not regress;

TransferProof
  benefit survives revalidation on a new declared scope, task or route.
```

Different claims have different ceilings. A task-local correction may legitimately stop at `UseProof` or `DecisionDeltaProof`. A reusable Skill, procedure, or system policy is not promoted without `OutcomeBenefitProof` and `RetentionProof`. A general portability claim requires `TransferProof`.

Intermediate learning states form neither a second ladder nor one aggregate status. Their lineage is typed: capture and interpretation use `AttemptLearningDelta`; admitted adaptation uses `CampaignHarnessOverlay`; eligibility, retrieval, delivery, observable activation, and adherence use exact per-attempt `HarnessActivationReceipt`; campaign disposition uses `CampaignLearningClosure`; aggregated Skill history uses `SkillLifecycleView`; execution, evaluation, and attribution use applicable `EvidenceStatus` fields. These records explain why a proof step was or was not reached, but do not elevate it by themselves.

A receipt with `retrieval.status = RETRIEVED | EXPANDED` and `delivery.status = FULL`, but `activation.status = NOT_ASSESSED | NOT_OBSERVED | UNKNOWN`, proves only bounded retrieval and delivery—not `UseProof`. `activation.status = OBSERVED` requires `first_qualifying_observable_use_ref` and proves only observable use at the declared boundary; acknowledgement is insufficient. Even observed activation proves neither adherence, decision delta, attribution, nor benefit. Exact-handle read is a forensic capability. Marker recovery is not project understanding.

Product-level Understanding acceptance uses an ecological A/B field test:

```text
fresh agent and real unseen task;
no marker, answer terms, exact handle or prescribed retrieval query;
automatic correct WorkScope/task binding;
one useful prior decision/failure in memory;
world/task contact delivers memory before Material action;
agent publishes causal model, rival/unknown and expected observable;
real verifier checks the artifact/effect;
matched memory-free control uses the same model/harness/tools/task family;
primary outcomes: first-boundary correctness and artifact/verifier result;
next independent session reuses the lesson after restart;
tokens, calls and latency are counter-metrics.
```

A suite/harness can be accepted as evaluation infrastructure without the product passing it. Reports must state this distinction explicitly.

## I12.35. Multimodal, object and workflow continuity

ELIOT preserves continuity across code, documents, images, audio/video, GUI state, services and professional workflows without pretending that a text summary is equivalent to the source modality.

`ContinuityObservation` contains:

```text
source/modality and exact temporal/spatial/byte/range anchor;
source checksum, capture route and representation limits;
entity/object identity hypotheses with confidence and contrary evidence;
before/after StateDiff and affected workflow step;
relations to task, artifact, service, participant and verifier;
raw/derived handles and loss warnings.
```

`WorkflowStateView` tracks:

```text
workflow identity, current/previous step and owner;
inputs, outputs, pending commitments and external effects;
expected observable and verifier;
interruption/resume boundary and idempotency;
artifact lineage and unresolved representation gaps.
```

Identity is type-relative: a rename, crop, render, export, restart, merge or split may preserve one kind of identity while changing another. ELIOT stores competing continuity hypotheses rather than merging by filename or semantic similarity.

When a modality-competent observation/evaluator is absent, the property remains unknown or degraded. A model-generated textual description is a derived candidate and cannot prove visual, acoustic, spatial or interaction properties that it did not measure.

---

## I12.36. Memory threat handling and Environment Runbooks

`MemoryThreatProfile` is a composable assessment attached to candidate/admitted memory and derived views. Initial threat kinds preserve the old donor distinctions without making them a universal scalar:

```text
wrong_scope; stale; contradicted; duplicate; overbroad;
instruction_injection; tool_definition_drift; poisoned_lineage;
sycophantic_or_authority_laundering; negative_transfer; privacy_boundary;
unknown_due_to_incomplete_lineage.
```

Each assessment carries evidence, confidence/unknowns, affected influence, default handling proposal and clearance/reactivation route. Handling may be `warn`, `require_revalidation`, `suppress`, `quarantine`, `revoke_influence`, `preserve_as_counterevidence` or `ask`. The final transition follows authority and policy; similarity alone cannot create a hard blocker or purge.

`MemoryAuditSuspension` is represented as a reversible hot-path suspension inside the normal lifecycle: the item remains addressable for audit, retains provenance and has an owner plus release condition. It is not physical erasure and does not silently alter factual support.

Operational procedural memory uses `EnvironmentRunbook`:

```yaml
EnvironmentRunbook:
  environment_service_or_tool_scope:
  setup_and_preconditions:
  health_and_readiness_checks:
  common_failures_and_normalized_signatures:
  bounded_recovery_steps:
  where_applies_and_where_not_apply:
  required_authority_effects_and_secrets:
  expected_observables_and_verifiers:
  last_verified_state_fence:
  evidence_owner_and_lifecycle:
```

A runbook is not an executable permission. It may be proposed by Dreamer or derived from repeated grounded episodes, but execution uses normal Action/Recovery contracts. It becomes stale when environment generation, credentials, policy, Tool Definition, dependency or verifier changes.

Environment runbooks, residual experience and professional methods are retrieved by exact scope/cue first. They are demoted or split when transfer produces errors; they are never promoted solely because the same prose appeared repeatedly.



## I12.37. Governed SessionEpisode and typed source ingestion

A working session can be valuable as an episode even when no durable claim or procedure should be extracted.

```yaml
SessionEpisode:
  episode_id:
  session_and_attempt_refs:
  capture_mode: model_free
  body_kind: dialogue_prose
  source_ref:
  source_availability: present | pruned | unavailable | unknown
  content_self_contained:
  portability: local_private | project_shareable | exportable_redacted
  touched_entity_refs:
  observed_start_and_end:
  truncated_and_completeness:
  provenance_and_state_fence:
```

`SessionEpisode` is a typed `ExperienceRecord` in canonical memory; any search/index over it is rebuildable. Governor/Host event ingestion owns the source cursor, not the episode adapter or Dreamer.

Rules:

```text
the episode is reconstruction/provenance, not the Current Epistemic Position;
its body is untrusted/instruction-tainted content and never enters the instruction channel;
only privacy-admissible normalized events are rendered; secrets, provider-forbidden hidden reasoning and raw tool floods remain excluded or handle-based;
tool dumps remain Blob/Instrument evidence and are not duplicated into prose;
claim/procedure extraction is a separate candidate transition;
source unavailable ≠ record false ≠ record current ≠ automatic deletion;
privacy purge may remove the self-contained episode;
provider transcript pruning alone does not.
```


Git history may produce a deterministic `GitFixEpisodeCandidate`:

```yaml
GitFixEpisodeCandidate:
  commit_and_parent:
  observed_at:
  author_intent_excerpt:
  changed_paths_and_production_subset:
  verifier_or_test_changes:
  issue_or_pr_refs:
  scope_checksum_at_birth:
  current_scope_delta:
  classification_basis:
  epistemic_status: observed
```

A commit message is evidence of author intent, not proof of root cause. A “fix” classifier creates an episode candidate, not a causal edge, FailureFingerprint or active procedure.

Different sources use different ingestion semantics:

```text
rederived snapshot
  → replace/reconcile exact kind;

accumulating historical window
  → append and prune outside an observed window;

append-only cursored session
  → merge by stable identity, cursor and presence semantics.
```

`HarnessEventAdapter` normalizes vendor transcripts/events into one append-only stream. Exactly one cursor owner reads each source; multiple miners receive a bounded tee. Consumers cannot advance source cursors independently.

Cold maintenance is time-boxed:

```text
bounded pass;
durable per-source cursor;
idempotent merge;
visible partial coverage;
resume on the next maintenance job.
```

Timeout does not convert the whole corpus to failed or complete.

Retrieval is corpus-specific:

```yaml
RetrievalCorpusProfile:
  corpus_kind: source_code | generated_doc | session_episode |
               git_episode | decision | diagnostic |
               external_research | foreign_codebase | bulk_operational_log
  tokenizer:
  candidate_generator:
  ranking_features:
  stopword_and_length_policy:
  evaluation_set_ref:
  validity_scope:
```

Tuning for one corpus is not inherited by another without an evaluation. SessionEpisode is private by default; promotion to project-shareable/exportable requires explicit policy and disclosure closure.

Externally acquired material uses the existing Source/Interpretation lifecycle rather than a new semantic owner:

```yaml
ExternalFindingRecord:
  interpretation_id_and_source_snapshot_ref:
  question_claim_and_declared_scope_population:
  method_and_evidence_class:
  effect_uncertainty_and_negative_results:
  reproduction_status: NOT_CHECKED | REPRO_OK | REPRO_FAILED | ARTIFACT_UNAVAILABLE
  transfer_limits_and_ELIOT_differences:
  contradicting_and_shared_lineage_refs:
  source_freshness_license_privacy_and_allowed_use:
  epistemic_status: observed | contested | stale | rejected
  assertability: NON_ASSERTABLE_UNVERIFIED
  revalidation_expiry_and_state_fence:
```

```yaml
KnowledgeTransferCandidate:
  improvement_candidate_ref:
  external_finding_refs:
  target_task_family_scope_and_owner:
  proposed_practice_skill_procedure_default_or_failure_memory:
  local_discriminator_and_baseline:
  transfer_assumptions_and_forbidden_generalizations:
  canary_budget_counter_metrics_and_rollback:
  expiry_revalidation_and_validity_scope:
```

It never enters the instruction channel directly. Transfer to practice follows:

```text
ExternalFindingRecord
→ KnowledgeTransferCandidate / local discriminator
→ isolated module/recipe/Skill/procedure experiment
→ matched outcome, BudgetEquivalenceLedger and counter-metrics
→ promote narrowly, retain as evidence, narrow, reject or expire.
```

The episode search path returns historical reconstruction leads. It does not satisfy a verifier, current-position requirement or external factual claim without fresh evidence.


## I12.38. Causal influence status

The existing influence ladder records observable use stages. Causality is a separate axis:

```yaml
InfluenceEvidence:
  memory_or_context_item_ref:
  delivery_and_ack_refs:
  public_decision_or_action_reference:
  intervention_or_ablation_id:
  control_condition:
  downstream_artifact_delta:
  outcome_delta:
  known_confounders:
  assignment_masking_and_replacement_policy:
  seed_and_held_out_status:
  effect_estimate_and_uncertainty:
  underpowered_disposition:
  causal_status: UNKNOWN | OBSERVED_CORRELATION | ABLATION_SUPPORTED | CONFOUNDED
```

`delivered`, `acknowledged`, `cited` and `decision changed` are progressively stronger observations, but none alone proves benefit. `ABLATION_SUPPORTED` requires a credible intervention/control and applicable outcome measure. Missing acknowledgement remains `unknown`; correlated agents do not create independent causal evidence by repetition.

# I13. Conflict and attention contract

## I13.1. Conflict types

```text
Epistemic — incompatible claims/models/evidence;
State — revision/fence/write race;
Plan — competing task paths/owners;
Authority — overlapping or absent permission;
Artifact — incompatible outputs/patches;
Instruction — conflicting Human/Architecture/policy/Skill constraints;
Resource — queue/budget/module contention;
Architecture — Implementation cannot satisfy stated intent.
```

## I13.2. Conflict Set

```yaml
ConflictSet:
  conflict_id:
  type:
  scope_id/task_id:
  candidates:
  evidence_and_lineage:
  authority_and_owners:
  common_mode_failures:
  resolved_parts:
  unresolved_residue:
  argument_acceptability:
  minimal_supporting_assumption_sets_and_defeated_argument_refs:
  discriminative_probe:
  decision_owner:
  affected_actions:
  state: open | investigating | decided | superseded | resolved
```

Conflict is localized state, not global failure.

Claim acceptability is structured, not scalar:

```text
GROUNDED               supported by an admitted, undefeated argument;
CONTESTED              coherent support and an undefeated attack coexist;
DEFEATED               support invalidated;
ASSUMPTION_DEPENDENT   valid only under a named assumption set;
UNDECIDED              no sufficient argument either way.
```

This `argument_acceptability` axis describes support/attack relations inside one Conflict Set. It is orthogonal to I12.5 epistemic status, I7.27 evidence execution/evaluation and the Conflict Set lifecycle state; it does not create another global status dictionary.

A single confidence number is not a substitute: it does not say which assumptions were used, which evidence is independent, what happens if one source is retracted, or who produced the number. `CONTESTED` and `UNDECIDED` are legitimate terminal argumentative states while the Conflict Set itself may remain open, decided or resolved; the system is not obliged to pick a winner when the available evidence is non-diagnostic.

This is a semantics of relations, not an instruction to build a graph database (I12.9).

## I13.3. Conflict Directive

Returned to agent/Human:

```yaml
ConflictDirective:
  conflict_id:
  concise_problem:
  what_is_observed:
  rival_interpretations_or_states:
  shared_lineage_and_independence:
  what_is_already_resolved:
  what_remains_unknown:
  cheapest_useful_probe:
  who_may_decide:
  worker_allowed_actions:
  controller_required_action:
  temporarily_forbidden_effects:
  human_view:
  resolution_condition:
```

Agent does not infer procedure from error code alone.

## I13.4. Concilium runtime

Stages:

```text
1. Frame exact question and decision boundary.
2. Separate observations from interpretations.
3. Map evidence lineage and common-mode failures.
4. Gather strongest objections/minority findings.
5. Produce rival predictions.
6. Select discriminative tests or reversible trials.
7. Update Theory Portfolio.
8. Decision owner chooses provisional action.
9. Record dissent and revision conditions.
```

Concilium may use tools, Humans, one agent or swarm. It is not vote tally.


Concilium quality is evaluated without making the panel an oracle. `ConciliumEvaluationReceipt` reports solution/verifier outcome, anchoring to the first proposal, rival and counterevidence coverage, quality/discriminative power of selected probes, revision after contrary evidence, common-lineage exposure, cost and Human burden. Agreement count is not a success metric; a panel that adds narratives but worsens probe quality or outcome is narrowed or removed.

## I13.5. State/revision conflicts

```text
stale expected revision → reject effect, preserve observation/candidate;
old Authority Epoch → reject as fenced;
overlapping write/effect sets → serialize or create plan conflict;
unknown commit → resolve receipt before retry;
partial multi-scope outcome → saga state and compensation.
```

## I13.6. Instruction conflict

Instruction Hotset precedence:

```text
1. Architecture Hard Boundaries and accepted system policy;
2. authenticated Human goal/constraints within authority;
3. WorkScope/task contract;
4. active Recovery/Conflict Directive;
5. triggered Skills/tool guidance;
6. advisory model/Dreamer suggestions.
```

Higher semantic authority does not make an external fact true. A layer with a larger number may operationalize or narrow an earlier boundary, but may not widen authority/privacy/effects or contradict it. Recovery and Conflict Directives derive their force from the cited policy, state and authority records; the directive itself creates no new authority. Conflict involving Human goals may require clarification rather than automatic choice.

## I13.7. Critical Attention

```yaml
CriticalAttentionItem:
  attention_id:
  kind:
  source/evidence:
  scope/task:
  owner:
  affected_action_classes:
  delivery_state:
  acknowledgement_state:
  influence_state:
  resolution_state:
  deadline_or_review:
  escalation_target:
  resolution_condition:
  waiver_authority:
```

Blocking ends only on verified resolution, authorized waiver or supersession. Delivery/acknowledgement alone do not close.

## I13.8. Attention ownership

Default owners:

```text
task issue → Task Controller;
security/integrity → System Owner/Recovery Principal;
architecture gap → Architecture Owner;
verifier/evidence gap → WorkScope Owner or Task Controller;
module health → module owner/Doctor;
budget → Requester/System Owner according to policy.
```

Lost owner triggers reassignment/escalation with new Authority Epoch.

## I13.9. Problem Registry

```yaml
ProblemState:
  problem_id:
  class: operational | integration | cognitive | data_quality | security | cost
  severity:
  scope/affected_dependencies:
  symptom:
  evidence:
  hypotheses:
  owner_and_epoch:
  containment:
  repair_history:
  next_probe_or_action:
  resolution_condition:
  state: open | triaged | diagnosing | contained | repairing |
         verifying | resolved | accepted_risk | superseded | quarantined
  reopen_history:
```

Notification/restart is not resolution.

Problem ownership is lease/epoch-bound. If the owner Session, agent, Module or Human delegation disappears, the Problem remains open, the old owner is fenced, and ownership becomes `unassigned` until reassigned to an eligible successor or escalated through Critical Attention. Loss of the owner never implies resolution or acceptance of risk.

### Semantic contamination versus structural corruption

```text
semantic_contamination
  records/interpretations/procedures may be wrong or poisoned while ordering,
  provenance and storage integrity remain intact;

structural_corruption
  canonical ordering, receipts, provenance, schema/storage integrity or authority
  state cannot be trusted.
```

Semantic contamination is handled by scoped quarantine, contest/reweighting, influence-dependency revocation, Dreamer/Concilium audit, practical tests and forward correction. Raw source and forensic history remain. A large or uncertain contamination event may clone a snapshot into an isolated candidate canonical-store generation for swarm analysis and clean cutover, but restore is not treated as epistemic proof.

Structural corruption closes affected writes, opens an Incident and uses isolated restore/rebuild/break-glass contracts. Backups and Git-like history are recovery instruments; they do not decide which theory is correct.

## I13.10. Incident promotion

Problem becomes Incident when deterministic policy or authorized Human finds:

```text
canonical integrity or authority compromised;
secret/privacy/security breach;
critical telemetry/control path lost;
unknown Material/Critical external effect;
persistent blocking condition with unsafe continuation;
structural corruption;
Control Reserve/last-resort path exhausted.
```

Watchdog model opinion alone cannot open Incident.

## I13.11. Diagnostic Brief

Compiler combines:

```text
symptom/severity;
affected module/scope/tasks;
timeline and correlation;
exact evidence/log handles;
recent config/module changes;
graph dependencies;
prior failures/repairs;
current hypotheses and unknowns;
next discriminative probe;
allowed repairs/escalation.
```

Agent receives problem model, not raw log dump.

---

# I14. Queueing, backpressure and degraded behavior

## I14.1. Work classes

```text
control;
interactive;
verification;
canonical_write;
normal_background;
model_jobs;
swarm;
reporting;
maintenance.
```

Each has bounded items, bytes, concurrency and deadline profile.

## I14.2. Default queue profiles

Initial defaults, tuned after measurement:

| Pool | Items | Concurrency | Behavior under pressure |
|---|---:|---:|---|
| control | reserved | dedicated | never borrowed by normal work |
| interactive | 512 | CPU/latency bounded | BUSY with short retry |
| verification | 512 | separate semaphore | preserve finish/proof |
| canonical writes | 2048 + byte cap | store lanes | durable stage or backpressure |
| background | 1024 | low priority | pause/drop rebuildable work |
| model jobs | policy budget | route-specific | checkpoint/deny |
| swarm work | plan envelope | bounded fan-out | stop admission/replan |
| reports | 128 | low | regenerate later |

Numbers are defaults in `runtime.toml`, not Architecture.

## I14.3. Control Reserve

Capacity reserved independently at every applicable bottleneck:

```text
Kernel control channel and runnable task slots;
ORS write budget and durable queue bytes;
store connection/transaction slot and pending-write memory;
process launch/termination path;
notification/inbox transition;
CPU task slot and protected memory reserve;
pipe/message bytes, file descriptors/handles and disk-queue capacity.
```

Used for:

```text
cancellation;
fencing;
health;
Critical Attention/Problem/Incident transition;
critical telemetry;
safe shutdown;
recovery.
```

Normal workload cannot consume it.

Reserve accounting is multidimensional. Admission checks the exact bottleneck vector rather than one scalar percentage; exhaustion of CPU, memory, pipe bytes, ORS writes, disk queue or handles may independently close normal/background admission while preserving the applicable recovery/control lane. Each disposition names the exhausted resource and the work shed, deferred or quarantined.

`Last-resort Control Slot` is preallocated outside normal accounting for reserve-exhaustion/gap record. If unavailable, system enters platform/manual recovery boundary.

## I14.4. Backpressure responses

```text
BUSY                 — request not accepted; retry directive;
STORAGE_BACKPRESSURE — no durable staging available;
ACCEPTED_PENDING     — staged; do not retry, poll operation;
DB_UNAVAILABLE       — canonical-sensitive action blocked;
BUDGET_EXHAUSTED     — checkpoint and ask for route/scope/budget decision;
STATE_CHURN          — packet/read could not stabilize;
CAPABILITY_DEGRADED  — requested operation unavailable, alternatives shown;
```

Every response includes `RecoveryDirective`.

## I14.5. Recovery Directive

```yaml
RecoveryDirective:
  error_code:
  cause:
  evidence_handles:
  state_preserved:
  commit_status: none | staged | committed | unknown
  actions_temporarily_forbidden:
  retry_strategy:
  retry_after_or_poll_handle:
  preserve_operation_id:
  safe_fallback:
  next_allowed_action:
  human_action_required:
  escalation_condition:
  resolution_state:
```

## I14.6. Durable work, admission and execution axes

A durable work request exists before an attempt, but admission and execution are separate axes.

### Work admission

```text
BLOCKED_DEPENDENCY
→ READY
→ ADMITTED
| DEFERRED_CAPACITY
| CANCELLED
| STALE

DEFERRED_CAPACITY → READY | CANCELLED | STALE.
```

`DEFERRED_CAPACITY` records unavailable resource/route/quota, `not_before`, source of reset and alternatives. Ready Queue is a projection of `admission_state=READY`; it is not another task store.

### Execution axis

```text
NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED
→ VERIFYING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | STALE | UNKNOWN_OUTCOME.
```

A Job can own several sequential attempts. An external `RunAttempt` is created only after work becomes `ADMITTED` and has its own provisioning/launch/runtime states from I10.15/I14.20. Capacity loss during provisioning closes that attempt with evidence and returns the work through a new admission revision; it does not mutate the running attempt into `DEFERRED_CAPACITY`.

Fields:

```text
job/work item/parent and recipe;
admission_state and execution_state as separate typed fields;
owner and Authority Epoch;
State Fence/dependency receipts;
eligible routes and attempt refs;
input/output/checkpoint handles;
budget/quota/deadline;
worktree/environment leases;
expected artifact/verifier;
coverage, result and receipts.
```

`AdmissionReservation` is Kernel-owned ORS state, not semantic work state:

```yaml
reservation_id:
work_item_and_proposed_attempt_id:
owner_epoch_and_state_fence:
resource_lane_environment_and_effect_claims:
pessimistic_cost_and_quota_view:
status: staged_inactive | active | released | expired | reconciling
canonical_admission_receipt_ref:
activation_receipt_ref:
expires_at_and_release_reason:
```

Only `active` under the matching canonical admission may launch work or hold effect authority. A staged reservation can reduce available capacity but cannot create a process or external effect. Crash/retry reuses the same reservation identity; release/expiry is receipted and cannot cancel a running attempt silently.

At-least-once execution is allowed only for idempotent, fenced or reconciled effects. Internal admission crosses canonical and ORS ownership through the `AdmissionReservation` saga defined in I10.15: ORS first stages inactive claims; canonical state records `ADMITTED` and the launch outbox; Kernel then activates the exact reservation. No process may launch from an ORS reservation alone or from a canonical admission without the matching activation receipt. Provider/environment provisioning remains a later observed idempotent effect. A durable object is never simultaneously “running” and “capacity deferred”.

## I14.7. Task outcome mapping

| Job/run outcome | Task consequence |
|---|---|
| COMPLETED | candidate artifact/result; acceptance only after applicable verifier |
| PARTIAL | task remains active or may finish `PARTIAL` with explicit coverage |
| FAILED | alternate plan/retry may run; task status depends on acceptance and evidence |
| CANCELLED | task remains active or receives authorized `CANCELLED` outcome |
| STALE | result excluded; replan/requeue; never proof |
| UNKNOWN_OUTCOME | dependent effects/finish pause until reconciliation or explicit accepted risk |
| DEFERRED_CAPACITY | task remains active; may wait, narrow, approve budget or select another route at a new attempt boundary |

Job completion never equals task completion automatically.

## I14.8. Fair and portfolio-aware scheduling

```text
separate control, interactive, verification, route/model and background pools;
weighted fair polling and age within class;
per-principal/module/swarm/route/auth-profile WIP limits;
pessimistic quota reservation through the fenced admission saga and later reconciliation;
strong reviewer/arbitration reserve protected from bulk workers;
background/model/swarm admission pauses under interactive/control pressure;
one writer per deliverable by default;
no unbounded retries or recursive fanout.
```

Scheduler is pull-based: terminal/deferred/blocked attempt releases its slot, then the next currently admissible Ready Work Item is selected. Mechanical queue progress never depends on an LLM remembering to start another agent.

## I14.9. Poison operations

After bounded retries a deterministic/corrupt operation is dead-lettered with proven no-effect, opens a `SequenceGap` for its reserved position and creates or updates a quarantined Problem State.

```text
preserve operation identity/evidence/order;
pause only affected Ordering Scopes and declared dependents;
allow independent Ordering Scopes;
choose replace_same_identity, skip_proven_no_effect or cancel_dependents;
close the gap only through a canonical SequenceDisposition receipt;
never spin the whole writer lane indefinitely.
```

Operations rejected before sequence assignment consume no ordering position. Automatic endless retry and unaudited gap skipping are forbidden.

## I14.10. Supervision strategies and restart intensity

Erlang-style supervision is explicit in Module/daemon manifests; it is not inferred from process-tree shape.

### Child restart class

```text
permanent
  restart after any exit unless the owner is quiescing or retiring it;

transient
  restart only after abnormal exit or failed health contract;

temporary
  never restart automatically; preserve outcome/evidence and let the owner decide.
```

### Group strategy

```text
one_for_one — DEFAULT; restart only the failed independent child;
rest_for_one — restart the failed child and explicitly declared downstream
               dependents whose operational state or fence became invalid;
one_for_all — restart one small declared supervision group only when its members
              share inseparable operational state and independent recovery is unsafe.
```

Startup order alone does not define `rest_for_one`; the manifest dependency/invalidation graph does. `one_for_all` may not include Kernel, canonical store, Watchdog or unrelated Modules and requires a measured failure reason.

Every supervised child has a bounded restart-intensity window, backoff, cooldown, stable-uptime reset condition and quarantine threshold. A restart attempt records exit evidence, generation, State Fence, resource state and unresolved effects. Exceeding the intensity budget stops automatic restart, opens or updates Problem State and moves the child/group to `QUARANTINED` or `MANUAL_RECOVERY`. Restart restores liveness only; it never resolves the underlying Problem State without verifier evidence.

## I14.11. Canonical store outage

```text
Kernel remains responsive;
current semantic reads show stale/unavailable boundary;
safe pending operations may stage only while ORS capacity exists;
new Material/Critical authority depending on canonical truth stops;
optional modules may continue read-only local work if policy permits;
reconnect uses bounded generation replacement;
unknown commit reconciles by receipt;
after recovery invalidate packets/leases and refresh state.
```

## I14.12. Memory pressure

```text
stop background/model/swarm admission;
evict rebuildable caches;
convert payloads to handles;
checkpoint jobs;
quarantine runaway module;
preserve control and receipts;
return visible degradation.
```

Kernel OOM is not acceptable recovery strategy; process/resource limits isolate modules before core.

## I14.13. Idle drain and cancellation

Drain hierarchy:

```text
stop new work;
cancel noncritical child tasks;
checkpoint durable jobs;
quiesce modules;
complete/abort in-flight canonical transactions explicitly;
flush receipts/outbox;
stop dependency order;
write clean shutdown manifest.
```

Cancellation never claims rollback of already executed external effect.

## I14.14. Module hot replacement

### Artifact layout

```text
modules/<module_id>/<semver>/<artifact_hash>/
  module.exe
  module.toml
  signatures/
  symbols/
  contracts/
  test-receipts/
```

Running artifacts are immutable. Active generation is registry state.

### Upgrade sequence

Cutover applies to a declared `CapabilityRouteScope` (module + capability + affected WorkScope/effect domain). It does not pretend that every operation in the process changes owner at one instant.

```text
1. package and verify immutable candidate;
2. validate protocol/dependency/license/state-class compatibility;
3. start candidate with no effect authority;
4. restore/checkpoint/rebuild according to ModuleStateClass;
5. run readiness plus shadow or isolated canary;
6. quiesce new admissions to the old route scope;
7. classify every in-flight request and persist a GenerationCutoverRecord in ORS;
8. commit one ORS cutover transition:
     active route for new admissions = candidate;
     new Authority Epoch = issued;
     old general generation authority = fenced;
     exact allowed old-operation dispositions = fixed;
9. atomically swap the in-memory route snapshot from that committed record;
10. drain/reconcile old operations, publish GenerationCutoverReceipt,
    retain rollback artifact and retire the old generation.
```

`GenerationCutoverRecord` and its operational `GenerationCutoverReceipt` are owned by Kernel/ORS. Canonical Memory may later record a referenced observation/audit event, but it never becomes the owner of the active generation or cutover machine.

The ORS commit is the durable linearization point. Crash before it leaves the old route active. Crash after it reconstructs the candidate route and fences from the committed record before accepting work. Rollback is another cutover with a newer epoch; an old epoch is never reactivated. Candidate failure before the linearization point leaves the old generation active. Irreversible state migration requires forward repair or a separately proven rollback path.

### In-flight disposition

Every accepted request records ModuleGeneration, operation identity, impact/effect set and State Fence. At cutover it receives exactly one disposition:

```text
drain_read
  → read/stream may finish while its input fence remains valid;

finish_exact_authorized_operation
  → only the already admitted operation may finish under a committed
     `OperationContinuationPermit`; this is not general old-generation authority;

checkpoint_transfer
  → candidate resumes from a compatible checkpoint under a new attempt/generation receipt;

cancel_proven_no_effect
  → cancellation is accepted only when no external/canonical effect is proven;

block_scope_unknown_outcome
  → outcome is unresolved; conflicting new effects in the affected scope remain blocked
     until receipt/probe/reconciliation resolves it.
```

An unfenced external effect may not silently cross cutover. If the old process has already issued it, the committed cutover may create one non-renewable `OperationContinuationPermit` bound to operation ID, effect hash, old generation/epoch, exact scope, deadline and allowed completion messages. Kernel/store/tool boundaries accept the old epoch only with that permit; it cannot create child effects, widen scope, migrate to another process generation or authorize retry. Final OutcomeReceipt consumes/closes it. Old-process loss before a final outcome becomes `UNKNOWN_OUTCOME`; the permit is not reissued. If the effect has not been issued, the operation is checkpointed or cancelled with no-effect proof. Unrelated scopes may switch and continue.

### Request pinning

```text
shadow/canary
  → evidence only unless isolated effect scope is explicitly granted;

new request after cutover
  → candidate generation and new epoch only;

old request not listed in the committed cutover record
  → rejected as stale;

retry
  → follows operation identity/receipt and its disposition,
     never merely the newest generation.
```

Exactly one generation owns **new** effect admission for a CapabilityRouteScope. A bounded allowlist of pre-cutover operation identities may finish only as declared above. `GenerationCutoverReceipt` records old/new generations and epochs, route-scope hash, state migration, all in-flight dispositions, linearization record, health proof, rollback boundary and unresolved scopes.

## I14.15. Daemon hot replacement

Kernel preserves front door and canonical gateway while replacing `eliotd`. The same durable cutover semantics apply, but daemon semantic proposals and already admitted executions are distinguished.

```text
candidate starts with a new daemon generation and no write/effect authority;
loads projections, catches up the outbox cursor and verifies contract/state compatibility;
Kernel closes new application admission to the old daemon;
old daemon checkpoints current plan/job state and submits its in-flight disposition set;
Kernel commits DaemonCutoverRecord: new route/epoch, old proposal fence,
  exact staged-operation identities already owned by Kernel, unresolved effect scopes;
Kernel publishes the candidate route;
old daemon drains eligible reads and exits;
Sessions rebind through Kernel where the host permits.
```

A `PreparedTransition` already staged by Kernel is Kernel-owned and continues by operation identity even if its proposing daemon exits. An unstaged old-daemon proposal is stale after cutover. A tool/external effect launched by the old daemon follows the I14.14 in-flight rules; an unknown conflicting outcome blocks only its scope. Rollback is another generation transition with a newer epoch, never revival of the old epoch. Lost requests are recovered from submission/receipt state, not recreated semantically.

## I14.16. Kernel and Host update

Kernel is replaced only by Host Supervisor through an exclusive installation lineage.

### Kernel side-by-side cutover

Host owns `KernelActivationRecord` inside the separate crash-safe HostStateJournal, outside Kernel ORS and Canonical Memory. It contains only installation epoch, approved artifact hash, active/candidate pipe identity, one-time activation nonce and activation state; it cannot answer semantic questions or issue project authority.

```text
1. quiesce application, reconcile canonical writes and checkpoint ORS;
2. start candidate Kernel on a candidate pipe in `shadow_no_authority` mode;
3. candidate may inspect immutable/read-only snapshots and run compatibility checks;
4. candidate cannot write ORS/store, issue Session/lease/epoch or accept normal work;
5. old Kernel writes a KernelHandoffReceipt, closes admission/front door,
   releases KernelOwner/ORS locks and exits;
6. Host verifies process termination and lock release, advances HostInstallationEpoch
   and writes a one-time activation nonce to KernelActivationRecord;
7. candidate presents the nonce, acquires the exclusive ORS/KernelOwner locks,
   reconciles the handoff, creates a strictly newer/global-distinct authority lineage
   and opens the stable front-door pipe;
8. Host marks the candidate active only after KernelReadyReceipt;
9. rollback repeats the process with another activation nonce and newer lineage.
```

The activation-record transition plus exclusive OS locks is the linearization boundary; no claim is made about impossible atomicity across independent OS resources. Agent bridges retry during the short front-door gap. Two Kernels may coexist only while the candidate has zero authority. If old-process termination, lock exclusivity, handoff integrity or activation nonce ownership cannot be proven, cutover stops and manual recovery is required. Kernel change runs T3/T4 tests.

### Host Supervisor replacement

Host cannot hot-load itself. Installer/SCM performs side-by-side replacement:

```text
confirm independent Watchdog/fallback and rollback artifact;
cleanly stop Kernel and preserve recovery manifest;
install candidate Host at immutable path;
update SCM binary/config through one explicit installer operation and read back the observed SCM configuration;
start candidate and verify HostStateJournal, build registry, Kernel Job Object ownership and rollback control;
restore the prior observed service configuration if startup proof fails.
```

A short visible control-plane gap is preferable to a recursive supervisor chain.

## I14.17. User Broker update and reattachment

User Broker binaries are immutable per generation and are never replaced in place inside a logged-on session.

```text
stage candidate artifact and authorization policy
→ start candidate with no launch/effect authority
→ authenticate SID/session/artifact and verify EBP contract
→ create a higher/new-lineage UserBrokerEpoch
→ fence old registration from new launches
→ transfer only explicit broker-independent Session bindings
→ let old exact operations drain or reconcile; terminate its Job Object
→ publish registration/cutover receipt.
```

Existing child runtimes stay pinned to the broker/epoch that launched them until their operation is completed, cancelled or marked unknown; they are never silently adopted by a new broker. Logout or inability to prove old Job Object termination stops cutover and requires reconciliation.

## I14.18. Dynamic library policy

Rust dynamic libraries are NOT the production plugin ABI because Rust ABI is unstable and unload safety is weak.

Allowed:

```text
platform DLLs behind audited FFI bridge;
third-party DLL loaded inside disposable process module;
optional future C-ABI component with explicit ownership and no Rust types.
```

Primary hot replacement uses processes.

## I14.19. WASM components

WASM Component Model is the **default first contour** for pure, bounded, portable experimental logic. Every new Prototype follows the `PrototypeContourDecision` contract in I0.12; choosing an isolated native process requires an explicit capability/isolation reason, and a static native bundle is never the first contour for new experimental behavior. WASM is not a universal plugin mechanism and does not replace native process isolation for OS-heavy work.

Guest linear-memory and capability isolation do not prove Windows host isolation, build-time safety, filesystem/network confinement, credential safety, supply-chain integrity or cleanup of native helpers. The component build and host-call implementations remain separate admitted boundaries; claims beyond the measured Wasmtime/WIT property use the native sandbox/VM profile or stay explicitly unproven.

### Baseline

```text
runtime: pinned Wasmtime generation behind `eliot-wasm-host`;
production guest target: `wasm32-wasip2`;
interface: ELIOT-owned versioned WIT worlds;
WASI 0.3 / `wasm32-wasip3`: laboratory profile until exact Windows toolchain,
component, streaming/async and migration conformance passes.
```

The chosen target is recorded in the GenerationManifest. `wasm32-unknown-unknown` may be used for a completely self-contained library experiment, but it is not the standard capability-oriented component target.

### Admissible component classes

```text
policy/routing/scoring functions;
validators and schema transformations;
deterministic workflow nodes;
context/ranking transforms;
retry/error classifiers;
pure planner/reviewer support logic.
```

Not admitted as ordinary WASM components:

```text
Cargo/rustc/Git/LSP/browser/debugger processes;
canonical storage;
credential-bearing provider adapters;
unbounded async I/O;
code that requires raw shell/filesystem/network;
logic whose primary state cannot be externalized or migrated.
```

### WIT capability boundary

A world imports only named capabilities. Absence of filesystem, network, process, secrets or clock imports means that the guest cannot request those effects through the supported host surface. Host calls remain proposals or bounded data operations; they do not bypass Governor authority.

Every manifest declares:

```text
component/interface/artifact digests;
allowed imports/exports and capability grants;
state class and migration contract;
memory/table/instance/stack limits;
wall deadline, epoch/fuel policy and cancellation;
max host calls, input/output bytes and artifact access;
privacy/source policy;
shadow/canary comparator and rollback generation.
```

Wasmtime Store limits are enforced per invocation/generation. Epoch interruption is the default wall/cancellation mechanism for longer code; fuel may additionally bound deterministic CPU work. Pooling and AOT/precompiled artifacts are performance Defaults only after exact-engine compatibility and memory/latency measurements.

### Core, guest and native equivalence

The semantic core lives outside Wasmtime and has no runtime dependency. The WASM guest and native process adapters invoke the same core or satisfy the same conformance corpus. Differential tests compare:

```text
result and error class;
proposed commands/effects;
state delta;
resource/host-call envelope;
determinism under the same seed and input.
```

A backend-specific divergence is either a documented contract revision or a promotion failure.

### Generation and activation

A component is immutable after publication. Normal lifecycle:

```text
DRAFT
→ BUILT
→ CONFORMANCE_PASSED
→ REPLAY_PASSED
→ SHADOW
→ CANARY
→ ACTIVE
→ DRAINING
→ RETIRED | REJECTED | ROLLED_BACK.
```

These labels are a projection of the canonical ModuleGeneration/GenerationCutover machines; they do not create another mutable owner.

Shadow execution uses isolated state, cannot perform external effects and cannot influence scheduler decisions. The comparator records exact, semantic, invariant, effect-proposal, latency, memory, host-call and nondeterminism divergence. Canary thresholds are empirical per component class, never copied as universal constants.

### State migration and rollback

Preferred state ownership:

```text
host owns versioned snapshot;
component receives snapshot/input;
component returns delta/proposal;
host validates and commits under normal authority.
```

A stateful component must export/import a versioned state through an explicit migration contract. Migration is independently tested, reversible or backup-protected, and is not combined with unrelated behavioral change when that would destroy diagnosis.

Rollback is a routing operation:

```text
new requests → prior compatible generation;
candidate stops admission;
in-flight work drains/cancels according to exact disposition;
already authorized effects follow their operation permits;
state uses the prior compatible snapshot or a forward repair.
```

Old epochs are never reactivated.

### Native/static promotion

A WASM component is promoted to isolated native process only when measurement shows a material benefit and the native backend passes the same contract, differential, fault, shadow and rollback proofs. Static integration into `eliotd`/Kernel additionally requires a stable interface, trusted supply chain, hot-path profiling and normal binary release/rollback.

Promotion to native is not a required maturity stage. A policy, validator, routing or transformation component may remain an active WASM generation indefinitely when its measured overhead is immaterial and the capability-isolation/replacement value is higher.

Direct in-process `.dll`/`.so` hot unloading is not an admitted middle step. A C ABI or `abi_stable` can stabilize representation but does not isolate panics, UB, allocator ownership, callbacks, threads or unload lifecycle.

## I14.20. Canonical runtime lifecycle vocabulary

This is the single normative vocabulary for shared cross-component runtime lifecycles. It is not one physical mutable registry or a second state store. Each machine remains owned by the component named in its contract; this section only prevents incompatible lifecycle meanings.

### Service process

```text
STOPPED → STARTING
STARTING → RECOVERING | READY
RECOVERING → READY | DEGRADED
READY ↔ DEGRADED
READY | DEGRADED → QUIESCING → STOPPED
STARTING | RECOVERING | READY | DEGRADED | QUIESCING → FAILED
FAILED → STOPPED | RESTART_WAIT | QUARANTINED | MANUAL_RECOVERY
RESTART_WAIT → STARTING | QUARANTINED | MANUAL_RECOVERY.
```

Process liveness/readiness and capability-generation state remain separate.

### Write submission and ORS operation

```text
WriteSubmission:
  RECEIVED → NOT_ACCEPTED | STAGED | RESOLVED_EXISTING

ORS Operation:
  STAGED → ASSIGNED → APPLYING → RESOLVED
  STAGED | ASSIGNED | RETRY_WAIT → RESOLVED(cancelled), only with proven no-effect
  APPLYING → RETRY_WAIT → APPLYING
  APPLYING → UNKNOWN_OUTCOME → RECONCILING
  RETRY_WAIT/RECONCILING → RESOLVED | DEAD_LETTER

Final WriteReceipt:
  COMMITTED | REJECTED | CANCELLED | DEAD_LETTER.

`DEAD_LETTER` requires proven no-effect; ambiguous effect remains `UNKNOWN_OUTCOME`
until reconciliation produces a final receipt/disposition.
```

### Task lifecycle and finish decisions

Operational task state and the outcome of one finish attempt are separate machines.

```text
TaskLifecycle:
  PROPOSED → OPEN → FRAMED → ACTIVE ↔ VERIFYING
  ACTIVE | VERIFYING → SUSPENDED | BLOCKED
  SUSPENDED | BLOCKED → ACTIVE
  any non-closed state → CLOSING → CLOSED
  CLOSED → REOPENED → ACTIVE.

FinishDecisionOutcome:
  VERIFIED_COMPLETE | PARTIAL | BLOCKED | FAILED_VERIFICATION |
  DEGRADED_NO_PROOF | UNSAFE_TO_FINISH | CANCELLED | SUPERSEDED.
```

Mapping rules:

```text
VERIFIED_COMPLETE
  → closes the task as completed only with applicable proof;

CANCELLED / SUPERSEDED
  → close after authorized disposition of completed work and external effects;

PARTIAL
  → normally leaves the task SUSPENDED/ACTIVE with explicit coverage;
    it closes incomplete work only when the Requester/Task Controller explicitly
    requests that disposition and no unresolved effect requires continued supervision;

BLOCKED
  → sets operational state BLOCKED and records the unblock condition;

FAILED_VERIFICATION
  → keeps the task ACTIVE or BLOCKED with failed evidence and next corrective action;

DEGRADED_NO_PROOF / UNSAFE_TO_FINISH
  → do not close the task as done; they preserve a blocked/suspended state and next action.
```

`REOPENED` is a new lifecycle revision, not a rewrite of the prior `FinishDecision`. Every closure/reopen preserves the acceptance ledger, effects, evidence and causal link.

### Ready work admission

```text
BLOCKED_DEPENDENCY → READY
READY → ADMITTED | DEFERRED_CAPACITY | CANCELLED | STALE
DEFERRED_CAPACITY → READY | CANCELLED | STALE.
```

### Admission reservation

```text
STAGED_INACTIVE → ACTIVE | RELEASED | EXPIRED | RECONCILING
RECONCILING → ACTIVE | RELEASED | EXPIRED
ACTIVE → RELEASED | RECONCILING.
```

`ACTIVE` requires the exact canonical admission receipt, unchanged State Fence and matching Authority Epoch. `STAGED_INACTIVE` may reserve bounded internal capacity but cannot provision or launch. `RECONCILING` cannot create a new effect. Release, expiry and recovery reuse the same reservation identity and produce a receipt; an active reservation attached to a nonterminal attempt cannot be expired as cleanup.

### Swarm definition, admission and execution

```text
SwarmPlanDefinition lifecycle:
  DRAFT → FROZEN → SUPERSEDED | CANCELLED;

SwarmPlanAdmission lifecycle:
  PENDING → ADMITTED | REJECTED | STALE | CANCELLED | SUPERSEDED;

SwarmExecutionState lifecycle:
  NOT_STARTED → RUNNING ↔ PAUSED → REDUCING → VERIFYING
  → COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME.
```

Task Controller alone authors definition revisions. `FROZEN` is immutable and is the only revision that can be admitted. Governor alone records admission disposition for an exact frozen definition. AgentCoordinator advances execution only under `SwarmCoordinatorLease` and the matching active admission. Changing objective, acceptance, ceilings, work-graph semantics or stop conditions creates a new draft/frozen definition plus a new admission and an explicit drain/cancel disposition for the old execution. Staleness of an execution result is a separate applicability disposition; it never rewrites what the execution actually did.

### Live peer message delivery

```text
DRAFT → ADMITTED → QUEUED
QUEUED → DELIVERED | STALE | EXPIRED | CANCELLED
ADMITTED → STALE | CANCELLED.
```

`DELIVERED` means the exact admitted delta reached a route-qualified admissible boundary. Recipient acknowledgement, public use and later outcome-helpfulness are separate observations and never rewrite this lifecycle. A sender does not wait for them. A plan/State-Fence mismatch marks the queued item `STALE`; it is not silently retargeted.

### Anchored review item

```text
DRAFT → PENDING_DELIVERY → DELIVERED
DELIVERED → ANSWERED | STALE | SUPERSEDED
ANSWERED → RESOLVED | REJECTED_WITH_REASON | STALE | SUPERSEDED
PENDING_DELIVERY → STALE | SUPERSEDED.
```

Delivery/answer does not imply resolution. `STALE` preserves the original target and current resolver result. `SUPERSEDED` points to the replacement item/revision. A batch is a derived envelope and has no separate lifecycle.

### Run attempt

```text
ADMITTED → PROVISIONING → LAUNCHING → RUNNING
↔ WAITING_TOOL | WAITING_HUMAN | WAITING_CHILD | CHECKPOINTED
→ VERIFYING → AUDITING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME.
```

Attempt execution history is never rewritten to `STALE`. If its State Fence, route evidence or parent-plan revision becomes invalid, a separate result/applicability disposition marks the produced evidence/artifact stale and prevents proof/integration. The attempt still records what actually ran and how it ended; a new admitted attempt performs replacement work.

### Integration candidate

```text
PROPOSED → READY | STALE | REJECTED
READY → INTEGRATING | STALE | REJECTED | CONFLICTED
INTEGRATING → ACCEPTED | REJECTED | CONFLICTED | UNKNOWN_OUTCOME
UNKNOWN_OUTCOME → ACCEPTED | REJECTED | CONFLICTED, only through reconciliation evidence.
```

Only the holder of the current `IntegrationLease` may enter `INTEGRATING`. `ACCEPTED` requires governed apply plus post-apply verification. Unknown external/Git/artifact outcome never becomes `REJECTED`; it remains `UNKNOWN_OUTCOME` until reconciled.

### Durable Job execution

```text
NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED
→ VERIFYING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME.
```

Execution outcome is immutable history. A separate applicability/freshness disposition may mark its outputs stale for a new State Fence, route or parent revision; it does not rewrite the job outcome to `STALE`.

### Session

```text
ATTACHING → ACTIVE ↔ SUSPENDED → DETACHED | EXPIRED | REVOKED.
```

### Authority activation and token projection

`CapabilityToken` is a compact compatibility/transport projection of currently activated authority; it is not the parent-lineage owner defined in I6.15.

```text
PROPOSED → PENDING_KERNEL_ACTIVATION → ACTIVE
ACTIVE → EXPIRED | REVOKED | SUPERSEDED
PENDING_KERNEL_ACTIVATION → REJECTED | CANCELLED | STALE.
```

Only `AuthorityActivationReceipt` enters `ACTIVE`. ORS revocation takes effect before canonical reconciliation and cannot be reversed by replaying an older token record.

### Capability grant lifecycle

```text
PROPOSED → PENDING_KERNEL_ACTIVATION → ACTIVE
ACTIVE → REVOKED | EXPIRED | STALE
PENDING_KERNEL_ACTIVATION → REJECTED | CANCELLED | STALE
ACTIVE --narrow by a new grant revision and activation receipt--> ACTIVE.
```

A grant cannot enter `ACTIVE` unless its parent path is active and the child set is a strict subset/intersection. Narrowing creates a new immutable grant revision/receipt; it is not a mutable `NARROWED` lifecycle state. Widening or restoration requires a new grant/epoch. Graph revision changes invalidate derived effective snapshots. Regrant after revocation creates a new grant/epoch; it does not reactivate the old record.

### Capability introduction lifecycle

```text
REQUESTED → COMPILED → ACTIVE
ACTIVE → SUSPENDED | REVOKED | STALE | CONSUMED | EXPIRED
COMPILED → REJECTED | STALE.
```

`ACTIVE` requires matching supporting grants, registry revision, State Fence, credential binding and FacetManifest. Introduction does not survive holder/session/epoch change.

### Disclosure closure and decision lifecycle

```text
closure:
  COMPUTING → COMPLETE | PARTIAL | UNKNOWN
  COMPLETE | PARTIAL | UNKNOWN → STALE | SUPERSEDED

decision:
  REQUESTED → ALLOW | ALLOW_REDACTED | RECOMPUTE_NARROWER |
              FORK_PRIVATE | REQUIRE_AUTHORITY | DENY
  any issued decision → STALE | REVOKED | SUPERSEDED.
```

A change in source domain, ACL/policy, recipient/route, State Fence or declassifier validity invalidates the exact decision and its compiled packet/bundle. Historical delivery receipts remain immutable. `PARTIAL` or `UNKNOWN` never defaults to external allow.

### Blueprint instance

```text
PROPOSED → VALIDATING → BINDING → CONFORMANCE
→ STAGED → ACTIVE
ACTIVE → UPDATING | DRAINING | REVOKED
UPDATING → ACTIVE | ROLLED_BACK | FAILED
DRAINING → RETIRED
any pre-active state → REJECTED | FAILED.
```

Blueprint instance state is a projection over normal component/module generation and binding receipts; it is not a second deployment authority.

### Lease

```text
REQUESTED → ACTIVE → RELEASED | EXPIRED | REVOKED | SUPERSEDED
ACTIVE --renew with a new lease revision/expiry and the same lineage--> ACTIVE.
```

### Module generation

```text
DISCOVERED → STAGED
STAGED → STARTING | RETIRED | QUARANTINED
STARTING → RECOVERING | READY | FAILED
RECOVERING → READY | DEGRADED | FAILED
READY → ACTIVE | DEGRADED | QUIESCING
ACTIVE ↔ DEGRADED
ACTIVE | DEGRADED → QUIESCING → DRAINED → STOPPED → RETIRED
FAILED → RESTART_WAIT → STARTING | QUARANTINED | MANUAL_RECOVERY.
```

### Generation cutover

```text
PREPARING → ARMED → COMMITTED → RECONCILING → COMPLETED
PREPARING/ARMED → FAILED
COMMITTED/RECONCILING → COMPLETED | FAILED_REQUIRES_FORWARD_CUTOVER.
```

Rollback is never a backward state transition. It is a new cutover with a newer Authority Epoch. `COMMITTED` is the ORS linearization point; unresolved scopes remain explicit during reconciliation.

### Kernel activation

```text
IDLE → SHADOW_NO_AUTHORITY → HANDOFF_PREPARED → OLD_TERMINATED
→ NONCE_ISSUED → ACTIVATING → ACTIVE
any pre-active state → FAILED | MANUAL_RECOVERY.
```

Only HostStateJournal plus exclusive KernelOwner/ORS locks may advance this machine. A failed candidate never inherits the old Kernel epoch, and restore never revives an activation record as current authority.

### Claim

Epistemic status and lifecycle are independent:

```text
observed → supported → verified;
any → contested | stale | superseded | rejected;
active → dormant | suppressed | archived | quarantined.
```

Privacy erasure is a separate purge-ledger process.

### Problem/Incident

```text
OPEN → TRIAGED → DIAGNOSING | CONTAINED | REPAIRING
→ VERIFYING → RESOLVED | ACCEPTED_RISK | SUPERSEDED | QUARANTINED.
```

New evidence may reopen. Identical labels in different typed machines are not interchangeable; serialized state always includes machine kind and schema version.

## I14.21. Unknown commit recovery

```text
connection fails during commit;
Kernel queries WriteReceipt by idempotency key;
if committed → reconcile ORS;
if known rollback → retry under same identity;
if unknown → pause Ordering Scope, preserve operation and open Problem State;
Human/Doctor chooses evidence-backed reconciliation; no blind duplicate effect.
```

## I14.22. Maintenance jobs

Registered maintenance families:

```text
backup/restore rehearsal;
blob GC/reachability;
outbox/receipt reconciliation;
projection/index rebuild;
cue/concept/graph maintenance;
Dreamer curation;
calibration/understanding exam;
integration/capability survey;
security/dependency scan;
derived-index reference/differential rebuild;
SessionEpisode cursor/retrieval maintenance;
grant/disclosure closure reconciliation;
donor/conformance audit;
self-quality, feedback and maintenance-debt review;
external Research exchange cleanup/requalification.
```

A maintenance job may originate from:

```text
explicit Human UI/CLI request;
accepted Dreamer `MaintenancePlanCandidate`;
Watchdog/Doctor Problem or recovery recipe;
first-run/onboarding recommendation;
Human-approved idle/scheduled policy;
installation/update/migration transaction.
```

Human policy selects one `MaintenanceAutomationMode` per family:

```text
off                — no automatic job or proactive recommendation, except mandatory safety/recovery obligations;
suggest_only       — create/deduplicate a Human-board recommendation;
manual             — run only after explicit request;
idle_only          — run while no conflicting interactive work exists;
scheduled          — run at approved windows through Task Scheduler/Host wake;
continuous_bounded — maintain a small admitted backlog under fixed resource/model ceilings.
```

The Governor-owned `MaintenanceTriggerEvaluator` is the single producer of these decisions. It runs on admitted problem/signal/self-observation events, cold-start completion, idle transition, scheduled wake and startup reconciliation. It is a deterministic capability of `eliotd`, not a second scheduler: it may emit a decision, Human-board item or Durable Job request, while Ready Queue/Agent Coordinator/installer/Doctor retain execution ownership. If the evaluator is unavailable, the relevant trigger remains durable and is surfaced on the next startup; safety/recovery triggers use their existing protected paths.

One derived `AutomationTriggerDecision` makes the start behavior inspectable; it is not a new scheduler or authority:

```yaml
AutomationTriggerDecision:
  trigger_event_and_evidence:
  affected_scope_problem_or_family:
  deterministic_action_now:
  optional_dreamer_watchdog_agent_doctor_or_swarm_job:
  applicable_maintenance_mode_route_budget_and_user_session:
  decision: start | suggest | defer | suppress_duplicate | block | escalate
  durable_job_or_human_attention_ref:
  expiry_reopen_and_outcome_receipt:
```

When the final observable-use obligation is about to release its Runtime/Supervision lease, `MaintenanceTriggerEvaluator` emits one `EndOfActivityMaintenanceAssessment` before drain admission:

```yaml
EndOfActivityMaintenanceAssessment:
  activation_and_scope_set:
  closed_sessions_attempts_jobs_and_effects:
  pending_observations_feedback_projections_and_receipts:
  maintenance_debt_and_due_policy_families:
  eligible_service_safe_routes_and_budget:
  user_session_required_work:
  decision: no_action | start_bounded_job | schedule_wake | suggest_once | defer
  runtime_or_wake_intent_refs:
  shutdown_may_proceed_and_reason:
  expiry_and_outcome_receipt:
```

The assessment does not keep ELIOT alive merely because data exists. Only an admitted bounded job/active repair acquires a new RuntimeLease; otherwise work is scheduled, suggested once or deferred and drain continues. This is the deterministic bridge from normal use to maintenance, not a permanent background “thinking” loop.

| Trigger | Deterministic action | Optional intelligent work | When automation is unavailable/off |
|---|---|---|---|
| unknown/stale WorkScope, first attach or missing task/sources | run resolver, guard and cold-start receipt | Dreamer Orientation/clarification | show one onboarding action; allow bounded read-only discovery |
| repeated failure, loop/no-progress, missing observations or widening blind interval | open/update signal/problem and preserve evidence | Watchdog Agent, Dreamer diagnosis or Concilium selected by risk/complexity | show one Diagnostic Brief; contain only an exact pre-authorized danger |
| memory/context utility degradation or candidate backlog | compute deterministic health/coverage view | DreamCycle/curation agents | show one curation recommendation; do not silently grow context |
| stale/changed agent, model, tool, MCP, DB or code-intelligence capability | invalidate capability evidence and stop unsupported admission | requalification or managed environment plan | show exact install/update/reprobe action; current verified generation remains |
| idle/scheduled maintenance window | start only admitted service-safe jobs | bounded Dreamer/agent job if route/budget policy permits | checkpoint/defer; no fake completion |
| Doctor attempts exhausted, unknown effect persists or damage accumulates | quarantine dependent scope/module and preserve repair history | strong diagnosis/Concilium if policy permits | persistent Human attention and safe manual entrypoint |
| external knowledge gap | create ResearchQueryRequest or local-source plan | Dreamer synthesis after returned evidence | retain explicit unknown/coverage gap |
| user/Dreamer asks to change configuration or launch agents | compile typed candidate and validate owners/policy | Dreamer plan only; daemon/Agent Coordinator executes | present exact confirmation or reason for deferral |

Each execution is a Durable Job with idempotency, lease, checkpoint, budget, cancellation, progress and receipt. Paid model calls, swarms, destructive forgetting/purge, configuration publication, software updates and migrations require their separate route/authority policy even when the maintenance family is automatic. Maintenance cannot starve control, active-agent, interactive verification or Product Pulse classes.

Scheduled/background maintenance may use only service-safe routes and credentials explicitly admitted for unattended operation. Subscription-, IDE-, browser- or desktop-bound agents require an active authenticated User Broker plus a separate `interactive_maintenance` policy; otherwise the job checkpoints/defer and leaves one Human-board action. ELIOT does not retain a user desktop credential merely to make a schedule appear successful and does not fake an interactive logon.

If automation is disabled, the required route is unavailable or budget is exhausted, ELIOT preserves one actionable recommendation with reason, evidence, expected benefit, cost, expiry and safe deferral consequence. It does not repeatedly notify or pretend maintenance occurred. Every maintenance result enters the `eliot_system` observation/experience path and is evaluated against recurrence, product/recovery delta, false changes, cost and operator burden; completion of a maintenance job is not evidence that the maintained subsystem improved.

## I14.23. Safe shutdown

```text
stop new normal admissions;
revoke/finish expiring action authority;
request jobs/modules checkpoint/cancel;
drain canonical writes and reconcile pending receipts;
flush audit/outbox/ORS;
quiesce modules in reverse dependency order;
stop store only when no canonical data lease remains;
publish intentional shutdown state to Watchdog/Host.
```

Deadline expiry produces visible incomplete-shutdown recovery state; it does not silently discard pending work.

A wake/attach request racing with shutdown follows I1.5 `DrainCommitRecord`: before linearization it cancels drain; afterward it waits for a fresh activation generation. Suspend/hibernate/logoff closes pre-transition readiness and forces boot/session/generation revalidation. No caller may “rescue” shutdown by reviving an old lease or process handle.

## I14.24. Local failure containment matrix

| Failure | Immediate containment | Independent work | Recovery |
|---|---|---|---|
| Host Supervisor crash | SCM records exit; Kernel generation is treated suspect and no new Host-owned launch authority is assumed | independent Watchdog service remains where observed; no new claim about Kernel supervision until Host returns | bounded SCM restart or approved compatible rollback |
| HostStateJournal unavailable/corrupt | stop automatic Kernel/dependency activation and restart; preserve observed processes as suspect | Watchdog and read-only forensic inspection remain where observed | restore/repair journal from approved manifests and evidence, create a new Host epoch, require manual recovery proof |
| Kernel crash | Host closes the failed Kernel Job Object lineage, fences its epoch and permits no new Session/write/lease/Material authority | separate canonical-store branch, Watchdog and platform recovery surface remain where observed | compatible Kernel restart, ORS/epoch reconciliation, then fresh bridge/daemon/module generations |
| ORS unavailable/corrupt | close durable mutation and effect admission; never return `ACCEPTED_PENDING`; authority snapshots cannot be assumed | read-only inspection and independent noncanonical work where honest | isolated ORS repair/restore; reconcile authority/operations; unresolved state becomes Problem/Incident |
| optional module crash | fence generation; reject new calls | continues | restart/quarantine |
| `eliotd` crash | Kernel revokes daemon epoch | external effects stop; recovery/control remain | compatible daemon generation; rebuild hot mirrors |
| required `eliotd` service actor/pool fails | fence the affected mailbox/capability; do not continue with uncertain owned state | independent daemon capabilities continue only when the actor state is disposable/checkpointed/rebuildable and no effect is unreceipted | supervised actor restart under I2.4 conditions; otherwise terminate the whole daemon generation and recover through Kernel |
| store bridge crash | stop canonical operations | cached reads/independent modules where honest | restart/reconnect/reconcile |
| SurrealDB unavailable | bounded ORS staging; no false commit | noncanonical observation may continue within limits | Host-managed process restart/reconnect; receipt reconciliation |
| Blob Store unavailable | reject/limit large capture; do not create dangling canonical success | small inline operations may continue | repair path/space, reconcile orphan/temp files |
| Task Controller/Main Agent lost | revoke session/leases; checkpoint task/work graph | other tasks continue; verified artifacts preserved | reassign under new epoch and rehydrate from public inheritance |
| worker/auditor/verifier agent lost | mark work item partial/stale; stop its authority | sibling work continues | reassign or accept coverage gap; never promote missing result |
| hook/agent bridge unavailable | lower observation/enforcement axes; mark unseen work ungoverned | read/query and other integrations continue | reinstall/restart bridge, resync task/world state |
| WorkScope ambiguous, stale or mismatched to observed workspace | withhold project-specific context, writes and Material effects; preserve candidate set and safe observations | privacy-bounded read-only discrimination and unrelated scopes continue | ask the smallest question/probe; issue explicit bind/rebind/relocation receipt and new State Fence |
| cold start lacks task or governing-source readiness | expose `NEEDS_SCOPE/NEEDS_TASK/NEEDS_SOURCES`; do not infer the last/nearest task or document authority | source discovery, read-only orientation, safe capture and onboarding probes continue | Human/agent submits TaskIntake/binding; deterministic onboarding and optional Dreamer orientation produce a new readiness receipt |
| self-observation journal/experience import unavailable or under pressure | preserve a minimal event or protected coverage-gap record; stop claiming complete self-observation | product work continues unless the missing signal crosses a Hard Boundary | repair/replay/coalesce the journal, reconcile self-scope candidates and lower/restore Governance Profile by evidence |
| orphan or unreachable agent/subagent descendant | deny new proof/effect admission from the orphan; fence/cancel the affected subtree and preserve unknown effects | unrelated attempts/scopes continue | AgentCoordinator reconciles process/provider inventory, terminal disposition and cleanup; repeated loss escalates to Watchdog Agent/Human |
| User Broker lost, user logs out or broker session changes | revoke broker/session launch leases; terminate or mark unknown affected interactive-user attempts; retain requested/actual route evidence | service-safe routes and unrelated tasks continue | reattach a newly authenticated broker, reconcile attempts, or reroute/defer with explicit continuity kind |
| already-running external agent attaches after an unobserved interval | treat pre-attach changes/effects as unattributed candidates; deny proof/finish and further Material work until reconciliation | read-only inspection and unrelated tasks continue | create `ExternalAttachReconciliationReceipt`, verify workspace/effects and start a new bounded attempt or explicit Human disposition |
| durable event stream, replay cursor or acknowledgement state unavailable | stop new effects/cutovers that depend on the affected stream; preserve producer generation and delivery intent in ORS | unrelated streams and read-only work continue | rebuild cursor from durable events/receipts, replay idempotently, or open a scoped telemetry gap |
| Module Catalog unavailable or stale | freeze desired-state changes and new module admission; do not infer intent from running processes | already admitted healthy generations may continue under valid leases/fences | restore canonical catalog view, compare with Generation Registry and reconcile drift |
| Capability Registry unavailable or stale | stop new route/module choices that depend on missing evidence; keep declared capability non-production | exact active attempts may continue only within already validated capability/lease scope | rebuild evidence projection, rerun required probes and issue a new registry revision |
| capability grant/introduction graph unavailable or inconsistent | stop new calls/effects and revoke uncertain introductions; do not infer authority from tokens alone | independent work continues only under already validated unaffected snapshots | restore/recompute from canonical grants + ORS activation receipts, issue new graph revision/epochs and reconcile live handles |
| Disclosure Dependency Closure partial/unknown for external recipient | deny or recompute only the affected disclosure; preserve local processing inside the current boundary | unrelated/local work continues | restore source/ACL lineage, verified declassification or private fork; record unresolved external deliveries |
| derived code-intelligence index corrupt/stale | mark projection unavailable/partial and prohibit confident absence/impact claims | exact Git/Cargo/source/verifier routes and unrelated work continue | use exact reference fallback, rebuild isolated generation and differential-check before reactivation |
| SessionEpisode cursor/source path unavailable | preserve last sealed episode and mark source coverage/availability explicitly; do not fabricate completion | current task/canonical events continue | resume one cursor owner, reconcile idempotent segments or retain historical episode with unavailable-source label |
| code graph/LSP/diagnostic adapter down | mark capability stale/unavailable | exact file reads, Git, other truth surfaces continue | restart/replace adapter; bounded fallback/probe |
| accepted Architecture/Implementation source or self-index unavailable/stale | forbid Material self-change that depends on the missing contract; expose the exact missing revision/digest | ordinary non-self WorkScopes continue under their valid contracts | restore the accepted source/index, verify digest and rebuild conformance projections; never infer design authority from running code |
| Watchdog down | lower supervision axis | normal work only within policy | Host restart; persistent Human warning |
| Watchdog spool/integrity-anchor path unavailable | stop claiming durable independent delivery/anchoring; lower supervision and record the gap through another available protected path | live sensors may continue as explicitly volatile observations; independent work follows the reduced Governance Profile | repair or replace the spool generation, reconcile the blind interval and re-anchor before restoring full supervision credit |
| Doctor crash/repair loop | stop recipe and preserve attempt evidence | unrelated work continues | retry only within remaining budget; otherwise quarantine/escalate |
| Dreamer/model unavailable | no synthesis | deterministic/human/main-agent work continues | alternate route/defer |
| Dreamer issues an untriggered or unauthorized maintenance/config/agent request | reject publication/launch, retain current snapshot and record self-scope risk evidence | deterministic work and authorized Dreamer jobs continue | inspect trigger/route policy; narrow or roll back Dreamer profile; require Human review if repeated/high impact |
| ELIOT Research bridge or external Research system unavailable | mark external knowledge/long-job coverage unavailable or partial; do not fabricate citations | local ELIOT hot path, canonical memory and already imported evidence continue | retry/defer through Durable Job, use local sources/manual import or requalify/replace the bridge |
| UI down | no primary native Human surface; persistent obligations remain | agent path and CLI continue | restart/rebind native UI; recovery-critical actions remain available through CLI and fallback notifications |
| notification adapter down | keep persistent inbox item; delivery channel degraded | work continues unless item is blocking | retry/alternate channel; do not mark delivered |
| secret provider or required credential unavailable | deny dependent process/route/store start and never fall back to argv, plaintext config or inherited broad environment | credential-independent local/read-only work continues where honest | reauthenticate/rotate the exact SecretRef, re-probe dependent capability and invalidate stale sessions/generations |
| budget exhausted | checkpoint/cancel new model/swarm work | deterministic/local work continues | narrow scope, choose route, approve budget or finish partial/blocked |
| Control Reserve threatened | stop normal/background admission and shed rebuildable work | control/recovery remains | release resources; identify runaway owner |
| Control Reserve/last-resort path lost | enter manual/platform recovery boundary | no claim of full manageability | Human/platform recovery and incident reconciliation |
| one Ordering Scope poison | quarantine head/dependents | other scopes continue | repair/reject/gap receipt |
| conflict | local Conflict Set | unrelated tasks/scopes continue | probe/decision/supersession |
| config candidate invalid | retain old snapshot | continues | fix candidate |
| migration interrupted/incompatible | fence schema generation; stop affected writes | unaffected read/operational surfaces only | resume checkpoint, forward repair or isolated restore |
| backup/restore verification fails | forbid cutover and retain current active state | normal system may continue if active store healthy | repair backup path; new rehearsal/receipt |
| candidate module/daemon update fails | keep old route active; quarantine candidate | continues on old generation | diagnose/rebuild/replace candidate |
| critical telemetry gap | record gap through reserve/Watchdog path and lower governance profile | only policy-allowed work | restore observation path; reconcile blind interval |

---

## I14.25. Doctor implementation contract

`eliot-doctor.exe` is a short-lived repair worker, not a permanently reasoning service and not a second Governor. One invocation owns one bounded diagnostic or repair job. Kernel may start it from a Governor request or from a signed Recovery Manifest when `eliotd` is unavailable.

### Inputs

```text
Problem/Incident identity or non-semantic recovery intent;
Diagnostic Brief and exact evidence handles;
Module Catalog snapshot, Capability Registry evidence and Kernel Generation Registry view;
registered RepairRecipe;
current State Fence, Authority Epoch and recovery lease;
last-known-good compatible artifacts/config;
repair budget, deadline, cancellation and escalation target.
```

Doctor does not receive broad database credentials, arbitrary shell authority or a free-form mandate to “fix ELIOT”. Every infrastructure effect is enumerated by the recipe and constrained by the recovery lease.

### Repair classes

```text
automatic_safe
  idempotent restart/reconnect; rebuild derived cache/index; remove stale session/process;
  reconcile a pending operation whose canonical/external outcome is already proven;

guarded
  config or credential transition; integration registration; module generation switch;
  schema/data repair; service/store cutover; restore or forward migration;

diagnose_only
  structural corruption; unknown owner/outcome; repeated repair failure;
  unregistered external effect; unclear privacy/authority impact.
```

`automatic_safe` may run only under pre-authorized policy and remaining budget. `guarded` requires the exact owner/approval named by the recipe. `diagnose_only` produces evidence, a proposed plan and escalation; it performs no repair effect.

### `RepairRecipe`

```yaml
RepairRecipe:
  recipe_id_and_version:
  problem_classes:
  applicable_components_and_generations:
  prerequisites_and_state_fence:
  required_authority_and_approval:
  exact_allowed_effects:
  commands_or_module_operations:
  expected_observables:
  verification_contract:
  rollback_or_compensation:
  attempt_budget_and_cooldown:
  stop_and_quarantine_conditions:
  evidence_and_receipt_requirements:
```

Recipes are versioned policy/config artifacts, reviewed like executable operations and bound to exact component/protocol ranges. A model may propose a recipe candidate; it cannot activate one.

### Execution lifecycle

```text
REQUESTED
→ ADMITTED
→ DIAGNOSING
→ READY_FOR_REPAIR
→ RUNNING
→ VERIFYING
→ SUCCEEDED | FAILED | PARTIAL | CANCELLED | QUARANTINED | ESCALATED.
```

Algorithm:

```text
1. authenticate recovery job and load current evidence/fence;
2. verify recipe applicability, remaining budget and authority;
3. refuse or re-diagnose if the problem changed;
4. execute the smallest allowed effect through Kernel/Module/Store recovery boundary;
5. capture attempt and side-effect receipts;
6. run the independent verification contract;
7. submit repair outcome/reconciliation intent to Governor/Kernel;
8. resolve, keep open, quarantine or escalate the Problem State;
9. emit a candidate lesson/recipe improvement, never automatic doctrine.
```

Doctor never performs a canonical semantic transition itself. When Governor is unavailable, it may write only an opaque reconciliation intent plus evidence locator/digest to ORS through Kernel; it cannot store or reinterpret semantic evidence there. Canonical reconciliation occurs after the governed application path is restored.

### Repair-loop and Doctor failure

```text
repeating the same recipe without new evidence is forbidden after its attempt budget;
failed verification does not count as repair success merely because the process restarted;
unknown external outcome pauses the affected Ordering Scope and requires reconciliation;
repeated failure quarantines the component or recipe and escalates;
Doctor crash is handled by Kernel as a temporary child; the same job resumes only from a durable checkpoint/receipt;
Doctor cannot update its own binary, recipe policy or authority.
```

Doctor artifacts are immutable generations. Replacing Doctor uses the normal stateless/on-demand module staging and contract tests; there is no mutable Doctor state to migrate beyond the Durable Job checkpoint.

## I14.26. Recovery View contract

`RecoveryView` is the smallest inspection surface that survives loss of normal application behavior. It is operational and explicitly stale where evidence is stale; it never becomes a second task/memory projection.

Owner and sources:

```text
Kernel assembles the normal RecoveryView from ORS, active epochs/cutovers,
Host/SCM observations, store-bridge readiness and reconciled Watchdog signals;

when Kernel is unavailable, `eliot recovery status` reads only the authenticated
Host recovery channel plus the independent Watchdog fallback surface;

canonical task goals, claims and decisions are shown only after canonical read access
returns; HostStateJournal, Watchdog spool and ORS are never interpreted as substitutes.
```

Minimum fields:

```yaml
RecoveryView:
  generated_at_and_source_freshness:
  installation_host_kernel_and_watchdog_lineages:
  active_and_candidate_artifacts:
  process_and_store_liveness_vs_semantic_readiness:
  ors_integrity_capacity_and_reconciliation_state:
  active_cutovers_authority_revocations_and_unknown_outcomes:
  unavailable_guarantees_and_current_governance_ceiling:
  pending_nonsemantic_problem_incident_repair_intents:
  last_known_compatible_artifacts_and_backup_classes:
  exact_manual_or_automatic_next_actions:
  evidence_and_receipt_handles:
```

If sources disagree, the view exposes disagreement and blocks only the dependent recovery action. It does not merge by timestamp, infer health from a PID, infer semantic readiness from process liveness or claim that an unobserved tool/effect stopped. Large evidence is referenced by authenticated handles. Recovery-critical CLI commands consume the exact view revision/lineage and fail stale rather than acting on a changed system.

---


## I14.27. Capability Blueprint and independent instance lifecycle

A `RecipeManifest` describes orchestration. A `CapabilityBlueprint` packages a reusable micro-module composition without exporting live authority or user state. Governor owns blueprint catalogue/provenance and instance admission; Kernel owns only resulting generation activation/fencing; no blueprint package is an authority token.

```yaml
CapabilityBlueprint:
  blueprint_id_and_version:
  title_purpose_output_kinds:
  origin_and_provenance_chain:
  component_graph:
  license_sbom_and_dependency_policy:
  artifact_contract_and_interface_digests:
  facet_and_binding_requirements:
  state_schema_and_migration_contract:
  conformance_and_ModuleTestCapsule_refs:
  verifier_requirements:
  compatibility_and_removal_boundary:
  package_hash_signature_and_size_limits:
```

A blueprint explicitly excludes:

```text
credentials and secret handles;
active grants/tokens/leases/epochs;
canonical project memory;
live task/module state unless exported as a separate governed data package;
chat history or hidden reasoning;
Route Continuation State;
user-specific route/account bindings;
unresolved external effects;
owner-specific policy expansion.
```

Instantiation creates an independent instance:

```yaml
BlueprintInstance:
  instance_id:
  blueprint_digest:
  WorkScope_and_instantiating_principal:
  resolved_binding_refs:
  independent_generation_refs:
  independent_state_root_or_snapshot:
  local_policy_and_authority_refs:
  instantiation_receipt:
  fork_update_lineage:
```

Saga:

```text
verify immutable package/signature/provenance/license/SBOM;
validate Architecture/Implementation/interface and dependency-policy compatibility;
resolve each binding through Capability Introduction;
run common conformance and real-runtime namespace tests;
create independent state/generations;
activate through normal Module/Generation cutover;
retain blueprint digest for migration, revocation and vulnerability invalidation.
```

Publishing a new version never mutates an existing blueprint. Same semantic version with a different digest is rejected. Forks receive new identity and preserve origin lineage.

Two sharing modes remain distinct:

```text
share live state
  → ordinary authority, disclosure and collaboration contracts;

share blueprint
  → state/credential-free package that creates another independent instance.
```

Blueprint implementation is deferred until Operational Spine Proof 1 and one component has completed the WASM/native promotion proof. The contract exists now so Recipe, ModuleCatalog and external package work do not collapse into one ambiguous object.


## I14.28. Effect-specific lifecycle and empirical resource profiles

Canonical intent and external effect are separate state machines. Every effect class declares:

```yaml
EffectClassContract:
  class_id:
  issue_owner:
  identity_schema:
  provider_idempotency: NONE | CONDITIONAL | GUARANTEED_FOR_SCOPE
  observation_method:
  reconciliation_method:
  compensation_method_and_limit:
  timeout_disposition: UNKNOWN_OUTCOME
  verifier_and_proof_ceiling:
```

Lifecycle:

```text
PREPARED → AUTHORIZED → ISSUED
         → ACKNOWLEDGED | UNKNOWN_OUTCOME
         → OBSERVED
         → RECONCILED | COMPENSATED | IRREVERSIBLE_RESIDUE.
```

A sequence gap, timeout, process exit or canonical receipt never proves `no effect`. Generic rollback claims are forbidden; compensation is effect-specific and may leave residue.

Queue capacities, timeouts, retry budgets and Control Reserve sizes are `EmpiricalParameter`s. Before qualification they are conservative planning hypotheses. Qualification records arrival/service distributions, burst and fan-out, p95/p99 latency, saturation, starvation, restart storms, control-lane preservation, error/unknown-outcome rates and a kill condition. No one number is a universal liveness guarantee.


External-effect truth is grounded in sink-owned evidence where the sink supports it:

```yaml
EffectAcceptanceEvidence:
  effect_and_provider_idempotency_identity:
  arrival_and_claim_fence:
  sink_acceptance_or_provider_receipt:
  independent_readback_or_observation:
  acknowledgement_semantics:
  reconciliation_attempts:
  outcome: ACCEPTED | REJECTED | UNKNOWN | IRRECONCILABLE
  compensation_or_residue:
```

A client-side WAL, send success or acknowledgement cannot resolve whether the sink accepted a write unless the effect contract explicitly defines that acknowledgement as authoritative. Crash recovery therefore queries sink-owned acceptance/readback before retry; `IRRECONCILABLE` remains visible and cannot be converted to `not_committed`.


## I14.29. Stage-local recovery, progress clocks and parkable resources

Durable pipelines recover at independently verifiable causal stages, not at arbitrary process or whole-task boundaries.

```yaml
StageRecoveryReceipt:
  durable_job_attempt_and_pipeline_revision:
  last_verified_prefix:
  preserved_stage_outputs_and_receipts:
  interrupted_stage:
  invalidated_partial_outputs:
  downstream_suffix_invalidated:
  new_attempt_ref:
  state_fence_before_after:
  cleanup_evidence:
  unresolved_external_effects:
```

Resume preserves the verified prefix, clears or quarantines the interrupted suffix and repeats only the smallest causal stage whose effect/outcome is not proven. A partial artifact never becomes a finished stage because its process exited cleanly or bytes exist.

Every long operation uses independent progress clocks:

```yaml
ProgressClockSet:
  admitted_at:
  process_started_at:
  first_transport_output_at:
  first_semantic_delta_at:
  last_transport_heartbeat_at:
  last_semantic_delta_at:
  current_stage_started_at:
  stage_deadline:
  semantic_idle_deadline:
  total_deadline:
  cleanup_deadline:
  progress_evidence_refs:
```

Queue keepalive, TCP/SSE heartbeat and output bytes prove transport liveness only. Semantic progress requires a new accepted artifact, evidence delta, stage transition, resolved finding or other task-specific observable.

A logical Attempt may park a scarce physical resource without losing identity:

```yaml
ParkableResourceSublease:
  parent_attempt_and_resource_class:
  physical_lease_and_generation:
  parked_at_reason_and_checkpoint:
  resources_released_and_resources_still_held:
  reacquire_priority_and_budget:
  expiry_cancellation_and_fairness_policy:
  reacquire_receipt_or_failure:
```

Examples include GPU inference waiting for Human tool approval or an agent execution slot waiting for merge authority. Parking does not retain hidden GPU/process capacity, does not bypass the queue and does not guarantee reacquisition. Cancellation while parked is terminal unless a new attempt is admitted.

Pipelines that can consume all currently free capacity reserve downstream headroom explicitly:

```yaml
DownstreamHeadroomReservation:
  pipeline_stage_and_consumer:
  transient_resource_formula_or_empirical_profile:
  CPU_memory_GPU_disk_network_context_model_and_queue_reservations:
  uncertainty_and_overcommit_policy:
  release_condition:
  measured_peak_and_reconciliation:
```

This reservation is separate from Kernel Control Reserve. It protects product completion of the admitted pipeline—for example reduction, verification, export or response generation—without granting the stage authority over system recovery capacity.

`ResolvedExecutionReceipt` records actual execution rather than the configured label:

```yaml
ResolvedExecutionReceipt:
  requested_route_resource_and_revision:
  resolved_provider_model_repo_and_revision:
  actual_runtime_and_artifact_hashes:
  tokenizer_template_processor_and_adapter_refs:
  device_precision_quantization_and_load_mode:
  fallback_or_remap_chain:
  resource_attestation_status: ATTESTED | INCOMPLETE | UNKNOWN
  compatibility_profile_and_state_fence:
  evidence_refs_and_reason_if_unattested:
```

Fallback is classified before continuation:

```text
same semantics + same State Fence
  → same attempt may retry;

same objective but different route/resource/tool/context semantics
  → new attempt with sealed handoff and new receipts;

equivalence cannot be established
  → UNKNOWN / DEGRADED / BLOCKED;

exact requested identity unavailable
  → never substitute latest/default silently.
```

A materially different fallback is not a successful execution under the original label.

Ownership clarification:

```text
ProgressClockSet
  → fields/projection of the owning DurableJob or AgentAttempt;

StageRecoveryReceipt
  → typed Recovery/Checkpoint receipt under the existing recovery owner;

ParkableResourceSublease
  → specialization/revision of the existing Resource Lease family;

ResolvedExecutionReceipt
  → shared actual-execution payload embedded by PhysicalModelAttemptReceipt,
    InstrumentRun or ML-worker receipt; not a parallel generic receipt owner.
```

These shapes improve observation and recovery without creating new task, authority, lease or receipt roots.

# I15. Security and bypass resistance

## I15.1. Threat model

Assume:

```text
agent/model can hallucinate or ignore instructions;
external content can contain injection;
Tool Definitions can be poisoned;
module/bridge can be buggy or compromised;
agent can attempt direct storage/process bypass;
credentials can leak through logs/env/command line;
stale process can continue after restart;
backup can restore revoked/erased influence;
Human can make mistakes;
security detector can miss attack or false-positive.
```

## I15.2. Principal and Session binding

Principal identity is issued by Kernel, never self-declared.

Binding uses:

```text
launch nonce;
pipe ACL/user/service SID;
bridge installation identity/hash;
host session metadata;
capability token;
Authority Epoch.
```

Unverifiable principal receives read-limited/advisory profile or rejection.

## I15.3. Least privilege processes

```text
Host: service/process management only;
Kernel: ORS, control and generation routing; it may start/route bridges but has no DB or user-subscription credentials;
Store bridge: DB credentials, no agent/model;
Blob service: payload CAS/encryption/compression, no DB credentials or semantic query;
Daemon: domain operations via public store/blob APIs, no DB credentials;
Watchdog: sensors/spool, no canonical write;
User Broker: exact user/session-scoped launches and workspace adapters under one-time leases; no DB, Module Catalog, route-policy or broad-shell authority;
Dreamer/modules: scoped data/tools, no canonical credentials;
UI: loopback API only; exact loopback `Host`/`Origin` validation is mandatory and DNS-rebinding forms are rejected.
```

## I15.4. Secrets

The first Windows line uses Windows Credential Manager/DPAPI-protected `SecretRef` values behind the ELIOT secret-provider facade.

Rules:

```text
secret values never in TOML, CLI args, model packet, logs, canonical memory or blobs;
child receives only needed secret via protected handle/pipe;
secret access has audit receipt without value;
rotation invalidates dependent Sessions/modules;
compromise opens Incident and revokes route.
```

For the Host-managed `surreal.exe` dependency, the immutable process manifest contains only secret references. Host materializes a fresh child-only environment block or another upstream-supported protected one-shot channel immediately before process creation; secret values are never placed in argv, HostStateJournal, Module Catalog, crash command text or reusable environment snapshots. If an upstream version can receive a required secret only through a command-line argument or another observable unsafe channel, that version is not admitted.

The store bridge receives a separate least-privilege database client credential through the same secret-provider boundary. Server bootstrap/admin and normal application credentials are distinct, independently rotatable references. Startup diagnostics may record which reference/version was used, never the value. Sibling processes inherit neither credential.

Future Linux uses secret-service/keyring adapter.

### Data at rest

ELIOT does not invent a database-encryption scheme inside domain code.

```text
installation paths use explicit ACLs and a dedicated service/user identity;
System Survey records whether the containing Windows volume is protected by BitLocker/device encryption;
sensitive WorkScope policy may require an encrypted volume before capture;
portable backups/ECXF exports are encrypted by default with a versioned envelope key protected by the installation/user secret provider;
ORS/blob/export encryption is implemented behind `eliot-crypto`, using audited primitives/libraries and a replaceable format version;
loss of the key is a recovery failure, never a reason to write plaintext silently.
```

The ControlBoard shows the actual at-rest profile. Linux support later maps the same contract to platform volume/key services; it does not change canonical semantics.

## I15.5. Source assurance

Independent fields:

```text
identity/provenance;
integrity;
freshness;
domain competence;
incentives/track record;
independence/common lineage;
privacy class;
instruction injection risk;
deception/exfiltration/persistence risk;
allowed epistemic use;
allowed effects;
required verifier/quarantine.
```

No single trust score.

## I15.6. Instruction/data separation

```text
authenticated Human instruction enters instruction channel in scope;
embedded/pasted/web/tool/document text remains data;
model output remains candidate;
summary/compaction does not clear origin;
retrieved content cannot grant permission;
Tool Definition is versioned cognitive input and integrity-checked.
```

## I15.7. Bounded influence

Even admitted content has effect limits:

```text
may appear as evidence/hypothesis;
may be excluded from instruction/procedure/policy;
may require independent verifier;
may be quarantined from agents but retained for forensics;
dependent influence can be revoked.
```

Final-result filtering is defense in depth, not an access-control boundary. Content that was unauthorized or revoked may already have influenced candidate generation, rank/IDF statistics, counts, diversity, summaries or traces. If such content participated in a retrieval/scoring branch, the whole contaminated branch—including dependent synthesis/model work—is discarded and replanned under the latest grant/policy; deleting only forbidden candidates cannot sanitize the ordering or erase prior influence. A branch proven not to have touched the revoked population may remain. If safe re-execution cannot finish within budget, the result returns the applicable denial/revocation reason and `INCOMPLETE_COVERAGE`, exposing none of the contaminated ranking.

## I15.8. Direct write protection

```text
DB endpoint/credentials not exposed to agents;
network/ACL restricts service;
only storage bridge process permitted;
Watchdog detects unexpected client/process/path activity;
raw DB admin path requires maintenance mode + Human confirmation;
any bypass result is observation, not canonical transition.
```

## I15.9. Source admission and executable supply chain

### Source admission before materialization

Root registration is necessary but not sufficient. Every file/object membership is evaluated before materialization, indexing or model disclosure under one contract compiled from the System Owner baseline and applicable WorkScope Owner/Human-policy narrowing; providers enforce it but do not own or widen it.

```yaml
SourceAdmissionPolicy:
  policy_revision_and_owner:
  admitted_roots_and_final-handle_escape_policy:
  denied_system_locations_and_file_format_classes:
  credential_private_key_and_token_detector_profiles:
  generated_vendor_archive_binary_policy:
  file_archive_and_materialization_limits:
  sensitivity_classes_and_grant_ceiling:
  explicit_override_authority_scope_and_expiry:
  disclosure_logging_and_index_payload_policy:
```

OS/browser credential stores, private-key locations and known token files are deny-by-default. A symlink/reparse/final-handle escape is checked against the resolved target, not the display path. Sensitive repository material requires explicit compatible policy and grant ceiling. Detection returns only a class, bounded coordinate and reason/receipt; it never copies the secret into logs, indexes, vector payloads, diagnostics or model packets. An override is narrow, expiring and auditable and cannot silently widen inference/client disclosure.

### Executable module supply chain

Production artifact requires:

```text
source commit/repository;
Cargo.lock/build toolchain;
license report;
SBOM;
artifact hash/signature;
module manifest;
test/canary receipts;
known vulnerabilities/exceptions;
owner and rollback.
```

Use `cargo deny` or equivalent for license/advisory/source checks. New dependency requires owner/removal boundary.

Default license policy:

```text
permissive licenses (MIT, Apache-2.0, BSD, ISC, Zlib, CC0)
→ ordinary dependency review;

weak copyleft / file-level obligations
→ explicit compatibility review and containment;

AGPL, SSPL, BUSL or BSL, source-available, or another restrictive license
→ is not linked into Kernel or daemon as a library without a separate decision;
→ a separate process bridge is preferred only as engineering isolation,
  but is not treated as a license exemption;
→ redistribution, packaging, hosted use, and network-service obligations receive
  separate legal and license review;
→ replacement and export path and user restrictions are recorded.
```

SurrealDB is an explicit temporary source-available exception, isolated behind the storage bridge and mandatory ECXF export path. The exception does not extend automatically to other dependencies.

## I15.10. Sandboxing

Process modules receive:

```text
restricted working directory;
allowlisted environment;
scoped filesystem roots;
network policy where practical;
Job Object limits;
no inherited handles/secrets except explicit;
separate scratch/worktree for mutating workers.
```

Windows sandboxing limits are documented honestly. Stronger isolation may use Windows Sandbox/VM/container/cloud module for untrusted workloads.

## I15.11. Agent worktrees

Material code workers use dedicated Git worktree by default.

```text
base commit recorded;
write set/path policy;
secrets removed;
result is candidate diff/artifact;
verifier runs in same worktree;
application to integration branch is separate governed action;
base drift checked before apply.
```

## I15.12. External model data firewall

Before send:

```text
resolve data-class policy;
redact secrets/personal data;
minimize bundle;
preserve source labels and instruction taint;
record provider/model/retention/fallback;
enforce cost/time/tool limits;
prevent direct local DB/tool authority.
```

After response:

```text
candidate-only;
store provider receipt/cost;
scan/label output;
validate schema/lineage;
no automatic canonical promotion.
```

## I15.13. Remote Dreamer security

```text
separate gateway process;
explicit principals/scopes;
rate/budget limits;
read bundle precompiled locally;
no arbitrary handle expansion;
no local tools;
redacted output;
Watchdog security events;
emergency disable switch.
```

## I15.14. Privacy erasure

Owner depends on data scope: System Owner for installation data, WorkScope Owner/authorized Human for scope data.

Process:

```text
identify dependency/backup/provider copies;
stop new influence/access;
create purge plan;
remove payload/projections/cache/ORS/provider copy;
update restore purge ledger;
retain non-revealing receipt where lawful;
verify absence/recovery behavior;
notify owner of unavailable external deletion.
```

## I15.15. Break-glass

Recovery Principal can activate only predeclared path:

```text
stop normal writers/agents;
freeze evidence;
work on isolated copy/repair manifest;
rotate credentials and epochs;
verify schema/integrity/privacy;
Human cutover decision;
audit entire operation.
```

Break-glass is not general admin write path.

## I15.16. Security testing

Required for release/load-bearing changes:

```text
prompt/document injection;
tool metadata poisoning;
memory poison and dependency revocation;
direct DB bypass;
stale epoch/split-brain;
secret/log leakage;
remote Dream exfiltration;
backup restore without poison/erasure resurrection;
module tamper/signature failure;
unknown-origin workspace mutation.
```

---

## I15.17. Agent-generated Rust build threat model

Compiling untrusted or newly generated Rust executes native code through `build.rs`, proc macros, linker helpers, test binaries and downloaded tooling. WASM isolation of the eventual component does not sandbox its build.

Build trust classes:

```text
T0 known first-party change
  disposable worktree, dedicated target, no user secrets, Job Object limits;

T1 agent-generated change on admitted dependencies
  restricted testd identity/environment, allowlisted tools, network denied by default,
  write access limited to worktree/target/temp/artifact roots;

T2 new/untrusted dependency, build script, proc macro or foreign native code
  disposable VM/isolated laboratory route, or no local execution until approved.
```

Windows Job Objects control process lifetime and resources but do not isolate filesystem, registry, network, ports or user credentials. Therefore T1/T2 claims require a proven token/ACL/network boundary; if it is unavailable, ELIOT reports the missing guarantee and routes the build to a disposable VM/cloud lab instead of calling the process “sandboxed”.

Minimum build policy:

```text
exact toolchain/lockfile/source provenance;
no inherited broad environment;
no model/provider/DB credentials;
network denied unless dependency acquisition is a separate recorded phase;
dedicated target/cache namespace;
process tree and output limits;
artifact hashes and SBOM/license/advisory report;
cache identity includes trust class and source/lock/toolchain fingerprints;
release artifact attestation references build and test receipts.
```

A build cache is a trust boundary. Artifact reuse across trust classes or mismatched BuildFingerprint is forbidden.


## I15.18. Disclosure, delegation and facet security

Security admission evaluates four independent questions:

```text
is the content/observation epistemically admissible;
is it allowed to influence this decision/action;
is the holder authorized to call the operation;
is the derived result allowed to be disclosed to this recipient/route.
```

No earlier `allow` implies a later one.

### Disclosure gate

Before a packet, model bundle, report, swarm root, artifact or result crosses a principal/route boundary:

```text
resolve Disclosure Dependency Closure;
require complete closure or explicitly local-only/unknown behavior;
match every material domain to recipient/route capability;
apply verified declassification only by receipt;
record DisclosureDecision;
bind the decision to exact State Fence and route/provider retention profile.
```

A missing/inconclusive ACL or sanitizer fails closed for external disclosure while preserving local work where possible.

### Delegation gate

Before use:

```text
validate active CapabilityGrant path;
validate graph revision, epoch, expiry and use budget;
validate exact CapabilityIntroduction and FacetManifest method;
validate credential owner/acting principal;
validate operation/effect/data/disclosure classes.
```

Revocation invalidates new calls before semantic reconciliation, interrupts enforceable live handles and preserves forensic history. An old serialized introduction is not authority after restart/restore.

### Facet attack surface

Tool/resource method definitions are cognitive and security inputs. Method classification is default-deny; unclassified methods are not exported. Facets expose the minimum exact operations and handles needed for one WorkItem/Attempt. Generic raw shell, DB, filesystem, connector catalogs or all-account access are not introduced by default.

Required release/load-bearing tests include:

```text
derived A+B result sent to A-only recipient;
model summary retaining hidden private closure;
verified sanitizer and failed sanitizer;
shared-wave future evidence broadening;
grant diamond and last-path revocation;
cycle insertion;
revocation of active agent/WASM/native handle;
old handle after restore;
unintroduced globally installed resource;
unclassified new public method;
credential inheritance attempt;
same facet conformance across WASM/native/agent proxy.
```

These mechanisms must remain bounded:

```text
policy-sized domains, not per-token labels;
acyclic grant lineage, not arbitrary permission fixed points;
stable facet families + dynamic handles, not per-task schema explosion;
local work not blocked by future multi-user/distributed features.
```


## I15.19. Authenticated origin and supply-chain evidence

A content digest proves byte identity, not who produced or authorized it. Origin-sensitive artifacts use an `OriginAuthenticationReceipt`:

```yaml
OriginAuthenticationReceipt:
  artifact_digest:
  producer_principal_or_service:
  producer_generation_and_epoch:
  source_revision_and_build_identity:
  signing_key_or_os_identity_ref:
  signature_or_attestation:
  nonce_or_replay_binding:
  verification_policy_and_result:
  revocation_and_expiry:
```

Local first-party artifacts may use protected Windows service identity plus installation keys; distributed/vendor artifacts may require signed provenance/attestation. SLSA-like metadata is an admissible mechanism, not a universal Architecture mandate. Failure to authenticate origin returns `ORIGIN_AUTHENTICATION_FAILED` for the dependent promotion/effect; sandboxed output remains candidate even when origin is authenticated.

# I16. Observability, metrics and reports

## I16.1. Four surfaces

### Operational logs

Debugging; rotate/sample; not canonical.

### Metrics

Aggregated performance/health/cost; labels bounded.

### Durable audit

Authority, transitions, receipts, incidents, security, lifecycle; never sampled.

### Reports

Human/agent projections generated from canonical state; prose not truth.

## I16.2. Rust observability stack

DEFAULT:

```text
tracing + tracing-subscriber;
non-blocking rolling file appender;
OpenMetrics endpoint via lightweight Rust metrics exporter;
optional OTLP bridge module, disabled by default;
Windows Event Log for Host/Kernel critical startup/recovery in `system_service` profile;
protected rolling-file/event-spool fallback in `user_mode` and portable profiles;
structured crash report + symbol artifact.
```

## I16.3. Composite run trace context

Every run/event carries the applicable lineage:

```text
trace_id and operation_id;
task/work item/attempt/job;
principal/session/controller;
WorkScope and State Fence;
adapter instance and process/job-object identity;
native session/run and parent-child agent locators;
requested and actual RouteFingerprint receipt;
worktree and ExecutionEnvironmentLease;
module/process generation and Authority Epoch;
event sequence/cursor and normalization version;
impact/recipe/assurance class.
```

Secrets/content are not span labels. Logical run state, process state, provider state and event cursor are independent observables.

## I16.4. Required operational events

```text
process/module/adapter start, handshake, ready, quiesce, stop, crash, restart, restart-intensity exhaustion and quarantine;
capability discovery/probe/admission/expiry and route mismatch;
queue/WIP/quota reservation, defer and Control Reserve pressure;
store transaction/retry/unknown commit;
Session/lease/epoch/continuity transition;
native raw-event append and normalized cursor advance;
hook/integration gap, cancellation request/confirmation and orphan cleanup;
Dreamer/Watchdog/model/agent job start/result/usage/cost;
swarm recipe, assignment, fanout revision, checkpoint, audit and result;
worktree/environment allocation, health and teardown;
no-progress/loop-breaker signal;
backup/restore/migration/security/attention/problem/incident;
verification and finish decision.
```

## I16.5. Metrics groups

### System

```text
process/module/adapter health;
restart/quarantine/rollback;
CPU/memory/handles/process descendants;
startup/idle-drain and time-to-safe-recovery;
control reserve;
queue depth/age/bytes and WIP admission;
store health/latency/retries;
ORS size/reconciliation;
testd queue/build/cache/link/test/simulation pressure and time-to-diagnostic;
WASM compile/instantiate/pool/RSS/trap/host-call/output and generation divergence;
native worker process-tree, cancellation, orphan and restart evidence.
```

### Product and development

```text
accepted Product Identity and identity divergence;
current Product Objective and open causal properties;
time since last verified product delta;
repairs per failure class and Mechanism Review count;
activity artifacts per verified product delta;
zero-test, wrong-scope and stale-generation runs;
local PASS / product FAIL contradictions;
status/certificate invalidations;
feature-freeze scope and escape attempts;
failures that produced no behavioral change.
```

Activity metrics are diagnostic counter-metrics. They are never combined into a progress score without grounded product delta.

### Agent/Harness/Route

```text
active tasks, attempts, native sessions and children;
requested vs actual route and route drift;
capability evidence age/failure/quarantine;
continuity kinds and resume success;
event gaps/cursor lag/normalization loss;
trace completeness and Governance Profile axes;
progress age, repeated tool/error loops and cancellation latency;
finish outcomes and verifier coverage.
```

### Understanding/Memory

```text
cue coverage and exact zero-graph firing;
packet size/exact-evidence/position/profile and tokenizer-estimator error;
stale/conflict/unknown and recall disposition;
retrieval admission/suppression and no-graph/full-context controls;
time to orientation, first action, first safe action, first correct action and verifier;
prediction calibration and rival/probe quality;
memory transformation acceptance/false merge/false deletion/false retention;
negative transfer and Architecture conformance gaps.
```

### Swarm/Portfolio

```text
recipe and plan revisions;
fan-out/depth/active lanes;
unique vs repeated coverage;
Evidence Lineage and independence;
writer/reviewer/arbitration mix;
failed/stale/deferred branches;
synthesis/audit latency;
marginal verified contribution of added lanes;
route/task-class success profile;
environment contention and cleanup.
```

### Human

```text
attention queue age and persistent-item resolution time;
missed critical risk and false-critical rate;
notification count, interruption duration and resumption quality/time;
approval opportunities, pre-exposure prevention, conditional intervention and final harm;
benign false blocks, approval count/latency and abandoned work;
intervention/takeover/recovery success;
task correctness, rework and Human-visible degraded time;
privacy/monitoring burden and field-level access/erasure requests.
```

### Usage and cost

Store separately:

```text
input, cached input, output and exposed reasoning tokens;
request/tool/model/native-child counts;
root vs child vs aggregate scope;
wall time and CPU/RAM/process use;
subscription quota fraction/reset/source;
API billed cost, runtime-reported cost and ELIOT estimate;
retry/replay/compaction/environment cost.
```

Truth hierarchy:

```text
provider invoice/API meter
> provider SDK/account meter
> runtime telemetry
> ELIOT estimate
> unknown/not_exposed.
```

Subscription quota is not converted to currency without a provider contract.

## I16.6. Performance views

Separate:

```text
prefill/TTFT vs decode;
cold vs warm;
p50 vs p95/p99 under contention;
normal latency vs time-to-safe-recovery;
nominal cost vs retry/replay/compaction;
module start vs steady state.
```

No single performance score.

Every canonical-write latency claim is decomposed before protocol or process optimization:

```yaml
CanonicalWriteLatencyProfile:
  exact_product_machine_storage_and_contention_profile:
  payload_bytes_and_encoding:
  bridge_to_kernel_serialization_and_IPC:
  kernel_to_daemon_serialization_and_IPC:
  validation_admission_and_reservation:
  ORS_stage_and_durability:
  daemon_to_store_bridge_serialization_and_IPC:
  store_bridge_to_database_transport:
  database_commit_and_durability:
  receipt_return_ORS_reconciliation_and_outbox:
  p50_p95_p99_max_and_sample_count:
  CPU_allocations_IO_fsync_and_queue_wait:
  bottleneck_and_candidate_change:
```

JSON-first EBP remains a D0/D1 Default until measured boundary cost makes an alternative materially useful. A paper estimate cannot promote Protobuf or remove a process boundary; an observed bottleneck opens the protocol/placement experiment with semantic-equivalence and recovery tests.

Every published performance/capacity claim is a versioned `CapacityEnvelope`:

```yaml
CapacityEnvelope:
  product_and_runtime_identity:
  hardware_os_storage_and_network_fingerprint:
  corpus/storage tier and data shape:
  workload/task/profile and route fingerprint:
  concurrency, queue/backlog and reserve configuration:
  sample count, warmup and error/uncertainty method:
  p50_p95_p99_max and saturation point:
  CPU_RSS_handles_IO_WAL_device-write metrics:
  crash_restart_recovery_backup_restore timings:
  semantic equality/proof ceiling:
  validity, expiry and invalidation conditions:
```

`n=1` is an observation, never percentile evidence. Capacity measured on the old testbed or one small corpus is not inherited by the target runtime.

Corpus scale is represented by a versioned profile rather than universal byte tiers:

```yaml
CorpusScaleProfile:
  profile_id_and_scope:
  source_classes_and_privacy_domains:
  canonical_record_blob_and_index_bytes:
  record_episode_document_log_and_artifact_counts:
  graph_nodes_edges_and_projection_generations:
  history_window_and_active_archive_ratio:
  query_ingest_compaction_backup_and_restore_workloads:
  expected_growth_and_retention:
  applicable_capacity_envelope_refs:
  qualification_uncertainty_expiry_and_kill_condition:
```

A capacity result transfers only to a compatible CorpusScaleProfile. External research, foreign-code or bulk-log use is not product-admitted from a small development corpus merely because the same query succeeds.

## I16.7. Problem-oriented logging and Diagnostic Brief

Operational logs are not bulk semantic memory. They remain rolling files/events; only exact anomaly windows, normalized diagnostics, receipts and selected evidence handles enter canonical/problem state.

`LogWindowRef` records source/process generation, time/sequence range, hash, redaction status and retention. Agent receives no unbounded log dump by default.

Trigger:

```text
Problem opened/updated;
repeated failure/no-progress;
module crash or restart exhaustion;
security/integration gap;
user/agent request;
release/canary failure.
```

Diagnostic compiler joins:

```text
symptom/severity and affected Module/WorkScope/tasks;
causal timeline from receipts/events;
exact LogWindowRef/evidence handles;
correlated code/config/module generation changes;
graph/dependency relations;
prior failures and attempted repairs;
unknowns and observation gaps;
one cheapest useful probe/repair/escalation.
```

Correlation is marked as hypothesis until intervention/verifier. Brief has State Fence and invalidation condition. If telemetry is insufficient, it returns a gap and required observation rather than forcing the agent to search blindly or invent a cause.

## I16.8. Reports

```text
System Health;
Task/Completion;
Understanding/Unknowns;
Memory Health;
Agent/Swarm;
Watchdog Security;
Dreamer Curation;
Cost/Budget;
Backup/Recovery;
Architecture Conformance;
Release Readiness;
Weekly Improvement.
```

`Product Progress` reports the exact Product Identity, Product Objective, verified deltas, open causal gaps and unproven scope. It may not infer readiness from test/report/commit counts.

Reports are versioned artifacts with input revisions.

## I16.9. Retention and telemetry cost

```text
operational logs: rolling policy;
metrics: bounded local retention/downsampling;
durable audit: canonical retention/purge policy;
raw large outputs: BlobStore retention;
security/incident evidence: explicit retention/erasure;
model provider receipts: privacy/cost policy.
```


Telemetry itself consumes the same CPU, memory, I/O, queue and context resources it observes.

```yaml
TelemetryCostProfile:
  event_or_trace_family_and_impact_class:
  capture_mode: FULL | SAMPLED | ON_PROBLEM | DISABLED_WITH_GAP
  sampling_rate_and_denominator:
  CPU_wall_allocations_memory_IO_queue_and_storage_cost:
  hot_path_latency_delta:
  evidence_coverage_and_blind_intervals:
  decision_problem_or_recovery_value_refs:
  privacy_retention_and_disclosure_cost:
  qualification_expiry_and_kill_condition:
```

Material/Critical authority, effect, finish and recovery boundaries retain complete required evidence; optional ranking/suppression detail may use declared sampling when full capture would materially damage the hot path. Missing sampled evidence remains visible and cannot be treated as full coverage.

Every telemetry field or derived trace used outside immediate process debugging has a `TelemetryFieldPolicy`:

```yaml
TelemetryFieldPolicy:
  field_or_event_family:
  purpose_and_decision_supported:
  minimum_required_scope_and_sampling:
  collection_owner_and_truth_limit:
  allowed_recipients_and_visibility:
  redaction_and_disclosure_closure:
  retention_erasure_and_export:
  allowed_downstream_use:
  misuse_and_false-inference risk:
  qualification_or_removal_condition:
```

Richer telemetry is not presumed better. A minimal-versus-rich paired recovery/privacy experiment is required before expanding sensitive collection for a recovery claim. Missing telemetry means missing observability; it is never interpreted as evidence that no event occurred.

## I16.10. Audit integrity

Project/system event chain uses BLAKE3 previous/current hash. Periodic digest anchor is copied to Watchdog failure domain. Anchor proves history continuity, not semantic truth.

## I16.11. No hidden telemetry failure

Critical event path:

```text
normal audit write;
if unavailable → ORS/Watchdog spool;
if unavailable → last-resort control slot/event log;
if all unavailable → visible control-loss state when next channel returns.
```

Silent success is forbidden.


---

## I16.12. Trace completeness

A replayable Material/Critical trace requires:

```text
Task/Action contract and State Fence;
Active View/packet manifest;
principal, Session, leases and policy snapshots;
tool/model/module calls with inputs/outputs or immutable handles;
external-effect attempts and observed side effects;
verifier/artifact results;
canonical receipts;
finish decision;
missing parts explicitly listed.
```

Missing trace does not invent failure or success; it limits replay and may force `DEGRADED_NO_PROOF`.

## I16.13. Influence tracking

Only observable influence is recorded:

```text
item delivered/expanded;
item cited in ActionFrame/decision;
item changed selected action/verifier;
item prevented exact failed path;
item used in DerivedCompletionProof;
item later shown irrelevant/harmful.
```

The influence ledger distinguishes:

```text
delivered;
acknowledged;
expanded;
cited/used;
changed action;
changed verifier;
prevented exact failure;
contradicted by user/tool/outcome;
ignored or bypassed;
counterfactual raw exploration cost;
observed context/tool cost.
```

Unknown acknowledgement or hidden model use remains `unknown`, never `unused`.

ELIOT does not claim access to hidden chain-of-thought. Success after inclusion is not automatically causal credit.

## I16.14. Required report inputs

Every report declares:

```text
source record/revision ranges;
filters/suppression;
missing/degraded capabilities;
model/evaluator route if used;
generation time;
invalidation conditions.
```

Report prose is a projection. Decision owners can expand to evidence/receipts.

## I16.15. Architecture, Implementation and donor coverage reports

`ArchitectureConformanceReport` compares Architecture anchors with accepted Implementation sections and observed owner/mechanism/failure/proof/status.

`ImplementationConformanceReport` compares the accepted Implementation revision with:

```text
current crate/process/module ownership;
wire/schema/config and migration versions;
active DEFAULTs and Research Gates;
code/tests/runtime receipts;
known deviations and unsupported contracts;
source and artifact digests.
```

A report never treats running behavior as an automatic correction of the book. It classifies the mismatch and names the decision owner.

`DonorCoverageManifest` is the machine-readable source for retirement evidence:

```yaml
DonorCoverageManifest:
  manifest_version:
  Architecture_and_Implementation_digests:
  donor_source_digests:
  heading_and_unique_mechanism_inventory:
  disposition_and_active_target_per_item:
  Architecture_conformance_rows:
  unresolved_document_semantics:
  repository_reference_scan_status:
  runtime_data_migration_status:
  archive_bundle_status:
  gate_verdicts:
```

`DonorMigrationReport` renders that manifest and reports:

```text
unmapped headings/mechanisms;
UNKNOWN dispositions;
retained contracts without active target;
stale donor references in code/tasks/config/live state;
independent document, Architecture, repository, runtime and archive gate status.
```

These reports prevent deletion of useful old material without making old books normative forever. They may not infer repository/runtime readiness from document coverage.

`OwnerRequirementTraceReport` preserves the user's normalized requirements without turning chat history into a third normative book:

```yaml
OwnerRequirementTraceReport:
  requirement_source_digest_and_item_id:
  preserved_intent_and_failure_mode:
  current_Architecture_ids:
  current_Architecture_intent_or_anchor:
  current_Implementation_owner_and_sections:
  disposition: preserved | clarified | superseded | challenged | unresolved
  document_support: present | partial | absent
  support_claim_and_snapshot_ref:
  support_observation_state: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
  contract_maturity:
  implementation_support:
  evidence_execution_status:
  failure_or_regression_evidence:
  next_discriminative_artifact:
```

Keyword presence, heading counts and a broad section link do not close a requirement. A trace row must explain the retained intent, current owner, any intentional narrowing and the observable proof. Its maturity, support and evidence fields use the exact I0.5 enums and must equal the bound support claim; `support_observation_state` alone carries observation availability/state and never contains or creates conformance support. The report becomes stale when the source requirement ledger, Architecture, Implementation or bound evidence snapshot digest changes.

## I16.16. No-progress, loop and external telemetry projections

No-progress detector observes evidence/artifact/state deltas, not prose volume. Useful progress includes a new relevant entity, hypothesis with evidence, test/repro result, accepted patch delta, resolved finding or verifier outcome.

Detection ladder:

```text
telemetry warning
→ ask route to report bounded blocker state
→ suspend lane and create Diagnostic Brief
→ Task Controller/Dreamer/Watchdog review
→ cancel and reconcile
→ alternate route or Human escalation.
```

Repeated normalized `(tool, args, error)` tuples, child-spawn cascades, parent waiting on dead child and rising usage without evidence trigger the same bounded breaker. Automatic endless `continue` is forbidden.

OpenTelemetry/OpenInference export is an optional redacted projection of canonical ELIOT events. It is not canonical storage and may not receive prompts, tool arguments, secrets or raw native traces unless policy explicitly permits them.


## I16.17. Instrument Plane observability

Every `InstrumentRun` emits correlated operational events and canonical evidence:

```text
profile/stage/instrument IDs and revisions;
WorkScope/base/candidate/worktree identity;
executable/config/environment identities;
queue, start, first-output, finish and cleanup times;
process tree and resource-limit outcomes;
stdout/stderr bytes, truncation and parser warnings;
facts/unknowns/conflicts and authority/freshness/coverage;
tests discovered/selected/executed/skipped;
target/cache identity and lock wait;
exact rerun and raw evidence handles.
```

Required metrics include:

```text
time_to_first_actionable_failure;
profile overhead excluding tool runtime;
zero-test and inventory-staleness incidents;
parser incompatibility rate;
raw evidence open rate;
negative-result qualification failures;
stale code-intelligence rate;
process cleanup/orphan count;
Cargo lock wait and target-cache effectiveness;
selected-vs-full regression escape;
module-local proof to ProductProof promotion rate.
```

Operational logs never become verifier evidence by themselves. Diagnostic Brief compiles these records so the agent sees the actual failed stage, recurring signature, exact scope and next discriminative action instead of searching raw logs blindly.

## I16.18. Wait-for graph and Failure Capsule

ELIOT maintains a derived wait-for graph for active attempts, jobs and resources:

```text
attempt/job → lease, mailbox, process, provider quota, human approval,
worktree/environment, store scope, artifact or child attempt.
```

It is diagnostic evidence, not a scheduler authority. Cycles, stale holders, oldest wait age and missing heartbeats feed Diagnostic Brief and Watchdog signals.

Any nontrivial failed, timed-out, cancelled-with-effects or unknown-outcome run produces a content-addressed `FailureCapsule` containing:

```text
Product/WorkScope/task/attempt and State Fence;
route/runtime/toolchain/build/test profile identities;
base/candidate/artifact digests;
last causal events and normalized failure signature;
raw log/trace handles and truncation facts;
wait-for graph excerpt;
seed, schedule and failpoint set when simulated;
process/resource/cleanup evidence;
known effects and unknown outcomes;
reproduction command/profile;
current hypothesis, rivals and next discriminator;
privacy/redaction receipt.
```

The capsule is sufficient for replay or bounded diagnosis without sending all raw logs to the model. A retry never overwrites the first capsule; attempts form a lineage.

## I16.19. Reasoning telemetry and step-outcome attribution

Reasoning summaries or content exposed by a provider are optional untrusted telemetry:

```yaml
ReasoningObservation:
  route_attempt_and_event_ref:
  exposed_summary_or_content_handle:
  disclosure_and_retention_class:
  diagnostic_use_only: true
  not_proof: true
  not_authority: true
  not_reward_target: true
  leakage_and_privacy_risk:
```

ELIOT never requires hidden chain-of-thought, reconstructs it from polished prose or treats its absence as a trace failure. Public rationale captured at the decision boundary is a separate governed record.

Every model-judge or learned evaluator declares a `RewardInputBoundary`:

```yaml
RewardInputBoundary:
  evaluator_and_construct:
  allowed_inputs:
  forbidden_inputs:
  answer_author_and_future_state_leakage_checks:
  shared_lineage_and_independence_limits:
  criterion_and_countermetrics:
  effect_on_current_trajectory_or_future_policy:
```

Forbidden by default are hidden reasoning, unavailable answer keys, author self-justification in blind review, future status/outcome fields, secrets and any input that lets the evaluator reproduce the expected label instead of measuring the artifact.

A `StepOutcomeLedger` records observable process evidence without pretending that every successful task has one identifiable cause:

```yaml
StepOutcomeLedger:
  task_attempt_and_state_fence:
  steps:
    - action_or_inquiry_ref:
      expected_observable:
      actual_observable:
      evidence_effect_and_artifact_refs:
      disposition: helped | harmed | no_observed_delta | uncertain | not_executed
      causal_basis: intervention | discriminative_comparison | correlation | unknown
  delayed_or_distributed_credit:
  replay_handles:
```

Step credit can update memory vitality, route profiles, Skill curation and Improvement Candidates only with its stated causal basis. A post-hoc evaluator may change a score or future policy candidate; it cannot become a cause of an already fixed production outcome unless its verdict actually changed the trajectory.



## I16.20. Derived-intelligence, disclosure and capability metrics

Operational views expose without turning them into goals:

```text
code-intelligence owner/generation/coverage/fallback status;
reference-vs-index disagreement and rebuild rate;
ambiguous/unknown/no-map/no-index result rate;
Build/Verifier graph coverage and escaped impacted tests;
SessionEpisode capture/resume/source-availability/privacy tier;
reversible omission expansion success, dangling handles and lost-source count;
tool-surface schema/context budget by role/route;
DisclosureDecision allow/redact/recompute/deny and unknown-closure rate;
grant graph depth/fan-out/alternate paths/revocation latency;
active/stale/revoked introductions and unclassified-method count;
blueprint conformance/instantiation/rollback results.
```

Counter-metrics include:

```text
agent decision/outcome improvement;
context and tool-call reduction;
false confidence from derived indexes;
attention and maintenance cost;
latency added to hot paths;
privacy false deny/false allow;
authority graph or facet ceremony.
```

A mechanism that only creates more records, labels, graphs or reports without improving product proof, recoverability or decision quality is a candidate for removal.

## I16.21. Telemetry purpose, minimization and privacy-benefit gate

Every telemetry field or event family declares:

```text
exact operational/cognitive purpose;
minimum collection scope and trigger;
producer, recipients and allowed downstream uses;
privacy/sensitivity and redaction;
retention, erasure and disclosure closure;
what diagnosis/recovery/product decision it can change;
what happens when unavailable.
```

Rich telemetry is not admitted merely because it may be useful later. When a materially more intrusive profile is proposed, an evaluation compares minimal and rich profiles on the same recovery/context-loss tasks and reports recovery gain, missed diagnosis, privacy exposure, operator burden, cost and false inferences. Until benefit is demonstrated, the richer fields remain experimental/local-only or rejected. Missing telemetry yields an explicit observation gap rather than covert expansion of collection.

## I16.22. Contract and documentation burden

`ContractSurfaceProfile` and `DocumentationBurdenReceipt` make the system's own specification cost visible:

```yaml
ContractSurfaceProfile:
  work_family_and_route_profile:
  applicable_contract_owner_count:
  rendered_instruction_contract_and_tool_tokens:
  expansion_handle_count_and_usage:
  stale_or_conflicting_projection_count:
  contract_change_fanout:
  generated_vs_manual_definition_ratio:
  orientation_time_contract_challenges_and_wrong_owner_events:
  proof_and_product_pulse_dependencies:

DocumentationBurdenReceipt:
  changed_document_and_contract_digests:
  added_removed_or_generated_surface:
  affected_agent_profiles_and_consumers:
  measured_task_or_recovery_delta:
  simplification_merge_or_retirement_candidates:
```

No scalar becomes a target. The purpose is to detect when additional precision increases cognitive/operational burden without improving correctness, recovery or product outcome. In that case the default response is to simplify, merge, generate or remove stale prose — not to add another rule layer.

## I16.23. ELIOT self-quality and feedback observability

The Governor/Diagnostic Compiler owns one problem-oriented `EliotSelfQualityView` projection over the SystemObservationJournal, EliotSystemExperienceBank, AgentFeedbackReceipts and product/runtime evidence. Watchdog/Dreamer/Doctor supply observations and candidates; none edits the projection as a second owner:

```yaml
EliotSelfQualityView:
  agent_loop_and_no_progress:
  observation_coverage_and_integration_gaps:
  context_packet_size_quality_and_feedback:
  memory_growth_staleness_duplicates_false_activation_and_use:
  Dreamer_Watchdog_Doctor_job_utility_and_failures:
  configuration_maintenance_and_update_outcomes:
  orphan_descendant_and_unknown_effect_state:
  ProductPulse_and_user_outcome_delta:
  open_problems_improvement_candidates_and_human_actions:
```

Required counter-metrics include:

```text
context bytes/tokens versus acknowledged usefulness and decision delta;
delivered memory versus use, verification and outcome;
candidate/duplicate/stale growth versus resolved knowledge;
agent/tool activity versus evidence/artifact/product progress;
Dreamer/Watchdog agent cost versus accepted diagnosis/repair delta;
maintenance frequency versus recurring failure and operator burden;
feedback resolution latency and repeated wrong-scope/context complaints.
```

The view does not create one global “ELIOT intelligence score.” It identifies concrete failing contours and the next discriminative observation. A persistent self-quality regression creates a Problem or ImprovementCandidate; it does not let Meta silently rewrite the active system.

The closed self-diagnosis loop is explicit and owner-preserving:

```text
ObservationObligationProfile + actual observations/coverage
→ deterministic Signal or quality delta
→ Problem State when persistence/impact requires ownership
→ bounded Dreamer/Watchdog Agent/Doctor diagnosis candidate
→ Human/Main Agent/Governor decision under existing authority
→ repair, configuration candidate, route change, experiment or abstention
→ applicable verifier/Product Pulse and delayed outcome window
→ retain, narrow, rollback, reopen or escalate
→ SystemObservationJournal + EliotSystemExperienceBank writeback.
```

Each loop instance has one governed receipt:

```yaml
SelfQualityInterventionReceipt:
  intervention_id_and_trigger_observation_refs:
  affected_capability_scope_and_owner:
  causal_hypothesis_rivals_and_discriminator:
  selected_action: observe | repair | configure | reroute | experiment | abstain | escalate
  candidate_change_and_authority_refs:
  proof_ceiling_verifier_and_counter_metrics:
  rollback_and_validity_scope:
  immediate_and_delayed_outcomes:
  terminal_disposition: retained | narrowed | rolled_back | reopened | escalated | inconclusive
  system_observation_and_experience_writeback_refs:
```

Recurring failure without a changed hypothesis or discriminator opens Mechanism Review; activity, summary volume or maintenance completion alone cannot close the loop.

### Learning bottleneck diagnosis

One aggregate self-learning score is prohibited. The observed combination locates the bottleneck:

| Observation | Bottleneck |
|---|---|
| update quality high, activation low | retrieval, cue, trigger, or context budget |
| activation high, adherence low | route competence, instruction wording, or state loss between turns |
| adherence high, no decision delta | update irrelevant or too weak |
| decision delta present, outcome worse | bad lesson, bad evaluator, or unresolved confounder |
| immediate gain, retention regression | overfitting and harness-level forgetting |

Diagnosis selects the intervention: change delivery, route, update, evaluator, or roll back.

# I17. Development sequence

## I17.1. Development doctrine

```text
product objective before implementation activity;
one causal property per reviewable change;
discriminator before repair;
real runtime proof before broad abstraction;
small reversible delta before mass refactor;
current accepted identity before status;
error must change future behavior;
full release proof only at the release boundary.
```

ELIOT development is itself an ELIOT workload. The system must observe its own source, active runtime, decisions, failures and conformance gaps. Work is not successful because an agent followed a plan; it is successful when the Product Objective advanced without violating a Hard Boundary. A plan is a revisable hypothesis about execution, not an authority source; a harmful or stale plan is challenged rather than completed ceremonially.

The feasibility of building ELIOT with a small Human team and agent swarm is itself a falsifiable project hypothesis, not an assumed benefit:

```yaml
ProjectFeasibilityHypothesis:
  target_delivery_depth_and_user_value:
  available_human_capacity_and_decision_attention:
  model_tool_compute_and_money_envelopes:
  current_critical_path_and_parallelizable_cells:
  expected_verified_product_or_recovery_deltas_per_review_window:
  activity_to_verified_delta_and_integration_backlog_countermetrics:
  scope_reduction_or_reuse_options:
  review_stop_or_strategy_change_condition:
  owner_and_next_review:
```

No universal team size or calendar threshold is frozen in this book. The Requester/System Owner sets the current envelope. If activity grows while verified product/recovery deltas do not, the default response is scope reduction, reuse, simplification or mechanism review—not stricter ceremony or a larger speculative backlog.

## I17.2. Current recovery priority and promotion gate

Historical failure audits are regression donors, not the current migration baseline. The only current baseline is the latest `CurrentSystemEvidenceSnapshot` bound to exact source, build, installed runtime, policy, schema, integrations and live store revision. Until that snapshot exists, `support_observation_state = UNKNOWN`; absent exact source/runtime evidence leaves dependent capabilities `TARGET` / `NOT_EXECUTED`, while any previously stronger but invalidated claim is `STALE`. Historical failures remain active candidate regressions where the affected path has not been re-proved.

Until the affected recovery obligations close, the following are prohibited **only on paths that depend on them**:

```text
production promotion or release claim;
new authority or external effect through the defective path;
compatibility fallback inside an authority surface;
report/file projection used as current control state;
`complete`, `certified` or `architecture-complete` status.
```

The recovery sequence is evidence-driven:

1. **CurrentSystemEvidenceSnapshot** — bind exact source, build, runtime, policy, schema, integrations and store revision.
2. **Known-regression discrimination** — replay the strict-finish, payload round-trip, writer-authority, real-verifier and memory-lifecycle probes that apply to the observed topology; a historical failure that does not reproduce is recorded as refuted/stale for that identity, not repaired ceremonially.
3. **Confirmed Hard Boundary repair** — repair only the gaps actually demonstrated on the current identity, preserving the exact old failing path as a regression.
4. **Real verification and Operational Spine Proof** — the governed ProcessExecutor/Instrument path executes the verifier and the real agent/task/effect/restart route closes without synthetic proof.
5. **Live memory lifecycle and benefit evaluation** — demonstrate current admission/retrieval/use/revision and, when claimed, later task benefit.

Parallel development remains allowed through bounded causal work units:

```text
isolated no-effect prototypes;
independent crates/modules;
read-only audits and research;
contract/discriminator/test work;
shadow generations;
repair tooling.
```

A complete impact graph is not a prerequisite for exploration. When dependency evidence is incomplete, the result cannot be promoted or integrated into the affected production owner; it is not grounds for a global stop. The gate protects product authority, not agent activity metrics.

Before canonical memory is available, D0/D1 development evidence is not discarded. `eliot bootstrap brief` writes content-addressed, append-only `BootstrapFailureDraft` / `BootstrapImprovementDraft` artifacts under the repository/external audit evidence root with exact source identity, owner, discriminator and import disposition. They are evidence only, never current truth or authority. When the canonical write path becomes available, an explicit import/rejection receipt reconciles them; filename presence does not auto-promote them.

## I17.3. Canonical Product Identity

A release/candidate identity binds:

```text
source commit and dirty-state hash;
lockfile/toolchain and generated schemas;
binary/package hashes and service/module manifests;
config/policy/credential-profile hashes;
DB schema/migration and canonical revision;
active Host/Kernel/daemon/store/module generations and epochs;
plugin/Skill/hook/adapter hashes;
verifier/test manifest and environment;
installation receipts and invalidation conditions.
```

There is one accepted identity. Branch, worktree, installed runtime, DB state and reports may differ as observations, but cannot all claim to be current. Every status/report/result carries the identity it observed. Dependency change invalidates the corresponding claim automatically.

## I17.4. Causal Change Unit

A normal development unit closes one causal property and is small enough for independent review.

```yaml
CausalChangeUnit:
  product_objective:
  failing_or_missing_property:
  actual_runtime_path:
  hypothesis_and_rivals:
  discriminator_before_code:
  owner_and_scope:
  allowed_changes:
  forbidden_drive_by_changes:
  expected_observable:
  verifier_and_product_effect:
  rollback:
  writeback_if_supported_or_refuted:
```

Rules:

```text
bug repair starts with a discriminator that fails on the exact old path;
no unrelated cleanup/refactor in the same unit;
second repair of the same class requires Mechanism Review;
review challenges scope, authority and causal mechanism before style;
merge requires live proof at the lowest real boundary able to discriminate;
failure produces FailureFingerprint, test, rule/deviation update,
Improvement Candidate or explicit accepted non-action — never report only.
```

## I17.5. Mechanism Review

Triggered by:

```text
second repair of the same failure class;
fix in wrong runtime/provider path;
field-specific escape for a generic defect;
new compatibility branch near authority or data integrity;
local PASS with unchanged product outcome;
large change because the owner boundary is unclear;
repeated false block from the same rule.
```

Review output is short:

```text
actual owner/path;
why the previous discriminator was insufficient;
common causal mechanism;
smallest seam or invariant that closes the class;
new counterexample/holdout;
whether a Guardrail/Default must be narrowed.
```

## I17.6. Operational Spine Proof 1 and later Product Benefit Evaluation

One host, one WorkScope, one task class:

```text
attach or resume an authenticated Session;
retain the original user goal and TaskContract;
resolve current project identity and state;
compile compact exact Active View;
perform one reversible Material edit under current authority;
run verifier on the exact artifact/environment;
finish only through canonical acceptance coverage;
write one evidence-backed reusable lesson;
restart daemon/runtime;
resume without losing goal, effect or proof;
use recalled lesson to improve the next action.
```

The run uses actual source/runtime identity. No marker, answer-shaped prompt, exact handle or prescribed recall query may stand in for memory discovery. This proof establishes existence, continuity, real execution and honest lifecycle on one scope; it does **not** establish population-wide product benefit. A matched memory-free/control arm is required only when claiming cognitive benefit.

### OperationalSpineProofBrief and conditional evaluation depth

Every spine proof starts with a small `OperationalSpineProofBrief`:

```yaml
OperationalSpineProofBrief:
  exact_product_identity_and_contract_revisions:
  user_outcome_and_one_causal_property:
  task_and_environment:
  comparison_basis_and_reason: # exact pre-change behavior, matched control, or explicit not-applicable rationale
  expected_observable_and_exact_verifier:
  counter_metrics_and_known_confounders:
  budget_and_time_envelope:
  stop_kill_rollback_and_claim_boundary:
  delayed_observation_or_recurrence_window:
```

For a deterministic vertical-spine property, this brief plus exact replay/fault cases is sufficient. Fields that do not change the claim are not filled ceremonially.

A later `ProductBenefitEvaluation` uses a full `ProductEvaluationPlan` only when ELIOT makes a stochastic, comparative, population-level, non-inferiority or generalization claim. It extends the brief with:

```yaml
ProductEvaluationPlan:
  target_user_task_population_and_strata:
  immutable_sample_and_cluster_unit:
  pilot_holdout_and_contamination_boundaries:
  comparison_arms_and_budget_equivalence:
  randomization_pairing_blocking_seed_and_order:
  route_model_tool_environment_freeze:
  primary_outcome_quality_floor_and_countermetrics:
  pilot_variance_and_dependence:
  minimum_detectable_effect_or_noninferiority_margin:
  precision_power_or_declared_estimation_policy:
  evaluator_oracle_and_independence_profile:
  leakage_and_prior-run-visibility controls:
  failed_excluded_censored_trial policy:
  delayed outcome and recurrence policy:
  preregistered analysis and final disposition:
```

No universal sample count is imposed. A deterministic contract may require one exact old-path failure, one corrected-path proof and fault/restart cases. A stochastic claim requires enough evidence for its declared uncertainty policy. `UNDERPOWERED`, `INCONCLUSIVE`, contaminated trials or unmeasured budget differences remain visible and cannot be converted to PASS.

### Safety canary versus inferential canary

Two canary purposes are distinct:

```text
Safety canary
  — bounds blast radius, monitors explicit failure/rollback conditions and may use
    a small risk envelope without claiming statistical improvement;

Inferential canary
  — supports a comparative/product claim and therefore requires the applicable
    ProductEvaluationPlan, uncertainty and residual-outcome window.
```

A favorable mean from an underpowered canary does not create product eligibility. Conversely, a safety canary is not blocked by irrelevant power calculations when its purpose is only bounded exposure and fast rollback.

Task `VERIFIED_COMPLETE` and broader product maturity remain separate. Product evidence may be:

```text
CURRENTLY_VERIFIED;
RESIDUAL_WINDOW_OPEN;
MATURED;
REGRESSED;
CENSORED_OR_INCONCLUSIVE.
```

The record retains task/artifact/release refs, recurrence, downstream rework, exposure/censoring, evaluator revision and rollback reconciliation. Later regression narrows or rolls back the product claim without rewriting the original task history.

## I17.7. Memory rehabilitation gate

Before Concept Pyramid expansion, advanced Dreamer or Meta:

```text
one current TaskContract is discoverable through normal state;
one exact EvidenceAtom and matching VerificationRun exist;
one Claim reaches supported/verified only through those records;
one FailureFingerprint prevents a reproduced failure and has reopen conditions;
nonce/smoke/duplicate/stale cohorts are absent from normal active recall;
normal recall is current, bounded and cursor-based;
curation changes normal packet cargo, not only a preview report;
a later task benefits, and restart preserves the lifecycle state.
```

Exact L2 remains available as forensic retrieval, but it does not satisfy this gate by itself.


### Current Instrumental Grounding workline

A real Product Proof cannot rely on the current overlapping/synthetic verifier paths. Source-crate extraction under I2 begins immediately where it reduces ownership/context and enables the proof path; broad **process** extraction remains gated. The following work proceeds inside the current runtime topology while responsibilities move into the first bounded source-extraction wave:

```text
G0 — expose the existing Windows guardian as the single ProcessExecutor contract/reference implementation;
G1 — stream raw output and implement real Clippy/nextest/rustfmt parsers;
G2 — make one `dev-fast` InstrumentProfile serve CLI, agent verifier and CI;
G3 — remove/quarantine synthetic verification and private PatchRunner command maps;
G4 — refactor CodeCortex to consume evidence rather than rerun/parse tools;
G5 — after Operational Spine Proof 1, admit one-shot rust-analyzer/SCIP;
G6 — only after its golden suite, evaluate optional heuristic graph backend.
```

`G0–G3` are recovery-enabling work, not feature expansion. `G4` may be performed only as needed to stop duplicated/wrong-path evidence. `G5–G6` remain D3 depth and cannot delay Operational Spine Proof 1.

## I17.8. Delivery Depth D0 — replaceable runtime and process-grounding skeleton

Two tracks may run in parallel:

```text
Value/recovery track
  repairs the current source/runtime and reaches Operational Spine Proof 1;

Runtime-extraction track
  builds a no-authority Host/Kernel/process skeleton behind stable contracts.
```

D0 therefore does not wait for the current-runtime spine, but it cannot become the production authority or delay recovery work. The tracks converge at D1, where the proven product path is repeated through the new front door. Extract only the **process/deployment** boundaries needed by real consumers. Source crates may already be separated under I2:

```text
bootstrap `eliot system snapshot` and `eliot bootstrap brief` over the exact normative pair;
WorkScopeCandidateSet, ScopeBindingGuard and cold-start readiness over one real repository;
Host/Kernel front door;
ORS and Authority Epoch;
EBP handshake;
replaceable dummy daemon/module;
deterministic Watchdog heartbeat plus persisted self-observation/journal cursor/replay contract;
demand start/idle drain and lightweight SupervisionLease;
one shared ProcessExecutor contract/evidence semantics, instantiated inside the appropriate process-tree owner.
```

Exit proof includes a generated partial/full `CurrentSystemEvidenceSnapshot`, a route-bounded bootstrap brief with explicit normative coverage, one crash/restart/cutover with exactly one active authority lineage, process parent/child/grandchild termination, saturated stdout/stderr without deadlock and zero unaccounted descendants. Canonical semantics need not be reimplemented here.

Before broad D0 swarm fan-out, three representative real work units—bootstrap/document-contract, one process/runtime cell and one verification/product-spine cell—must be executed from the bootstrap brief and produce `ContractSurfaceProfile` plus agent outcome evidence. The earlier document-only preflight is useful for shape and size only; it does not qualify agent comprehension, rule-class accuracy or orientation burden.

## I17.9. Delivery Depth D1 — canonicalized product and verification spine

```text
store-neutral bridge and lossless payload authority;
Session/WorkScope/task/current plan;
observation capture;
basic canonical write/read/receipt;
minimal Active View;
AgentFeedbackReceipt and `eliot_system` self-observation path for the real route;
one real `dev-fast` InstrumentProfile through InstrumentRunner;
actual Cargo/Clippy/nextest/rustfmt evidence with raw handles;
one truth/verifier route bound to that evidence;
strict finish;
Problem/notification path and one maintenance recommendation/execution disposition;
first measured agent route through the approved front door.
```

Exit proof repeats Operational Spine Proof 1 through the new front door, demonstrates local/CI profile parity and survives crash/cancel/unknown outcome. Synthetic verifier records and duplicated command maps are not permitted beyond this depth.

## I17.10. Delivery Depth D2 — hot modules, independent proofs and replacement

```text
Module Catalog / Generation Registry / Capability Registry;
EffectiveMicroModuleManifest projections and BuildTestGraph;
independent module/package tests and consumer/provider contract suites;
independent process generations and canary cutover;
Git/Cargo and deterministic instrument profiles;
Human board and notifications;
Doctor registered repair path;
second provider-neutral agent route;
affected-test planner and profile selection.
```

## I17.11. Delivery Depth D3 — grounded Smart understanding

D3 is delivered in value-bearing subdepths; no later graph/index dependency may delay the first useful orientation service.
D3a may begin after the D1 capture/read/strict-finish loop is reliable; it does not wait for the complete optional breadth of D2. It uses an admitted existing process/co-located contour and later migrates behind the normal Module boundary without changing its public contract.

```text
D3a — Basic Smart orientation and maintenance intelligence
  Dreamer Orientation/Clarification over existing canonical records and exact handles;
  Architecture/Implementation self-model and `eliot_system` experience-bank orientation;
  exact-first current-state and unknown/conflict brief;
  bounded curation/maintenance/configuration/agent-plan candidates;
  no dependency on Concept Pyramid, vector search or a code graph.

D3b — Reactive decision context
  cue/index push;
  Context Compiler and Decision Safety Floor;
  critical attention/conflicts;
  exact file/error/task-boundary firing with zero graph edges.

D3c — Grounded structural/causal depth
  one-shot rust-analyzer/SCIP semantic backend on exact candidates;
  CodeCortex as evidence compositor, not ad-hoc parser;
  optional heuristic/behavioral/concept graphs only after golden admission suites;
  prediction/calibration and selective curation.
```

The first D3 value checkpoint is D3a: a Human or Main Agent asks what ELIOT already knows and receives a bounded, source-linked orientation without knowing database terms or handles in advance. The next checkpoint is D3b: touching an exact file, symbol, error, dependency or task boundary delivers a relevant negative-memory/invariant/module-context item before the next Material action, with a receipt and no model call in the hot path. A strict zero-edge test proves that direct firing works when the behavioral/concept graph is empty; no minimum graph-edge threshold may gate orientation or exact cue delivery. If these slices do not improve orientation or prevent an error, broad concept/pyramid expansion pauses for Mechanism Review.

D3a/D3b are accepted by the applicable ecological understanding/use proof of I12.34. Code-intelligence freshness/coverage proof in I18.18 is required only for claims that depend on the corresponding D3c projection. Marker transport, graph size and lexical graders never prove Smart understanding.

## I17.12. Delivery Depth D4 — resilient Meta

```text
advanced Watchdog semantic/security audits and calibration over the already-operational R0 supervision path;
development drift detection;
Problem/Incident lifecycle depth beyond the basic D0 notification path;
Doctor repair recipes;
backup/restore/revocation closure;
Improvement Candidate and canary/rollback loop.
```

Deterministic liveness, process observation, critical notification and the independent Watchdog spool belong to R0/D0. D4 adds analytical depth and bounded repair; it does not postpone basic supervision until Meta maturity.

## I17.13. Delivery Depth D5 — advanced portfolio, swarm and research

```text
bounded recipes over the proven Host Broker;
Ready Queue and portfolio scheduling;
read-only micro-audit portfolios before many writers;
blind challenge/synthesis with Evidence Lineage;
controller/coordinator recovery;
Researcher-provider and cloud/lab modules when justified.
```

No large autonomous **mutating** swarm is admitted before Operational Spine Proof 1 and the memory rehabilitation gate. Earlier development may still use a bounded number of parallel mutating workers on disjoint FunctionalCapabilityCells when contracts are frozen, worktrees/effect scopes do not overlap, each cell has an independent `ModuleTestCapsule`, and one Integration owner serializes shared-contract changes. Read-only audit/research swarms may also be used earlier when their cost, lineage and synthesis are explicit. One writer per mutable scope or deliverable remains the default; the restriction limits uncontrolled fan-out, not micro-modular parallel development.

## I17.14. Agent Work Unit over a FunctionalCapabilityCell

The primary decomposition unit is a `FunctionalCapabilityCell`; one or more crates are implementation containers, not the source of causal ownership.

```yaml
AgentWorkUnitBrief:
  product_objective_and_causal_property:
  architecture_and_implementation_refs:
  primary_functional_cell:
  implementation_package_and_source_slice_refs:
  effective_micro_module_manifest_ref:
  source_maintenance_owner:
  lifecycle_owner_refs:
  replacement_class_and_iteration_lane:
  proof_latency_profile_ref:
  bounded_support_closure:
  frozen_contract_revision:
  CrateContextCapsule_ref:
  effective_context_profile_and_workset_measurement:
  exact_scope_product_candidate_runtime:
  old_failing_behavior_or_missing_capability:
  hypothesis_and_rivals_if_material:
  discriminator_that_fails_old_behavior:
  ModuleContractKit_and_ModuleTestCapsule:
  one_hop_providers_and_consumers:
  affected_contract_edges:
  BuildFingerprint_and_build_mode:
  allowed_effects_and_non_goals:
  expected_artifact_or_evidence:
  InstrumentProfile_and_proof_ceiling:
  product_pulse_ref:
  budget_stop_and_challenge_path:
  integration_owner:
  writeback:
```

A work unit is small by causal responsibility, authority/effect scope and complete decision context—not by file, crate or support-count quota. The bounded support closure contains exactly the adjacent contracts/source/tests needed to preserve the causal path and is measured by I2.16.

One unit cannot silently change several mutable owners, unrelated public contracts and product status. If a defect crosses owners, Task Compiler creates a Contract/Evidence unit, bounded provider/consumer units, Edge/Integration units and one Product Pulse.

The agent returns `ContractChallenge` when the discriminator measures a proxy, the owner/cell is wrong, the oracle is controlled by the same patch, the complete Decision Safety Floor cannot fit a qualified envelope, or an omitted edge changes the causal explanation. A wider read bundle never grants wider write authority.

## I17.15. Agent Task Compiler and development waves

`AgentDevelopmentPlanner` is a deterministic Agent Coordinator and Governor capability. It does not create a second task graph.

Inputs:

```text
CrateRegistry and CrateFleetReport;
ModuleGraph and ModuleContractKits;
BuildTestGraph and historical escapes;
current Product/WorkScope identity;
Problem/FailureFingerprint evidence;
public-contract and resource overlap;
available agents/routes/budget/context profiles;
integration and Product Pulse dependencies.
```

Output is canonical WorkItems in four bounded waves:

```text
Contract/Evidence wave
  owner, public contract, old path, fixtures, oracle and discriminator;

Module-cell wave
  disjoint FunctionalCapabilityCells implemented and tested in parallel inside bounded source packages;

Edge wave
  actual provider/consumer/process/store boundaries;

Product Pulse
  shortest end-to-end route capable of exposing local-proxy drift.
```

Rules:

```text
contract revision frozen inside a wave;
one mutating writer per declared mutable scope/path claim/contract edge; disjoint cells in one crate may run in parallel only when their source/effect claims do not overlap and one Integration owner reconciles the shared crate;
read-only audits may fan out independently;
workers receive brief/kit/capsule, not the whole Implementation;
Module/Cell Proof creates IntegrationCandidate, not merge or product status;
contract drift invalidates only dependent work;
second failure of one mechanism class triggers Mechanism Review;
Product Pulse occurs before a long chain of local green crates accumulates;
model may propose decomposition, but Governor admits the work graph;
planner opens `ContextScaleReview` when no qualified envelope fits the unit; it prefers decomposition or a tighter projection, but may retain a cohesive unit when exact measurement proves a complete workset and the Task Controller records the scoped decision. I2.16 planning bands alone never create a refusal.
```

## I17.16. Real-use development and live improvement

Preview/candidate builds may learn from real projects only through separated identities and effects.

```text
stable runtime continues serving the project;
real Problem/Improvement Candidate identifies one causal property;
agent changes one crate/cell in isolated worktree;
Instrument Plane builds and tests candidate generation;
shadow/canary receives bounded read-only or separately authorized workload;
outcomes compare candidate with stable generation;
the authorized Module/System promotion owner promotes, rejects or revises; Main Agent and Task Controller provide evidence/recommendation but do not mint deployment authority;
forward cutover uses normal generation/epoch contract;
failed candidate cannot damage stable generation.
```

Real workload supplies evidence; it never promotes an unproven capability automatically. Background compilation/testing uses lower resource priority and cannot starve active ELIOT, Kernel, Watchdog or Product Pulse.

## I17.17. Stop conditions against overengineering

Do not add or preserve a mechanism when:

```text
it does not close a current causal property;
a simpler existing capability meets the objective;
it has no owner/removal boundary;
it increases forms/tests/reports without product delta;
it delays the recovery gate or Operational Spine Proof 1;
its only support is symmetry, elegance or future possibility;
it turns a Guardrail into a Hard Boundary without evidence;
it cannot state an independent `ModuleTestCapsule`;
it requires full-workspace proof for a local property without a real dependency edge;
it delays the next Product Pulse while accumulating only crate-local green results;
it creates a crate with no independent context/test/dependency value;
it preserves a boundary after repeated evidence that no qualified complete workset can be formed and a `MicroModuleTopologyReview` shows that split/merge would reduce failure or coordination cost without degrading the public contract;
it creates a process merely because a crate exists;
it adds a second scheduler, writer, memory or recovery owner.
```

## I17.18. Execution Fabric Proof 2 — one component through all contours

This proof is required before ELIOT permits agent-generated runtime components to receive live traffic. It is not a prerequisite for Operational Spine Proof 1 or unrelated D1 work.

```text
1. Main Agent receives one small pure component cell and frozen contract.
2. Agent changes core in a leased worktree.
3. `eliot-testd` runs crate-local discriminator, unit/property and contract tests.
4. Component builder compiles `wasm32-wasip2` and records WIT/artifact provenance.
5. WASM and native-core outputs pass one differential conformance corpus.
6. Deterministic replay executes recorded cases and fault seeds.
7. `eliot-wasm-host` runs candidate in effect-free shadow mode.
8. Comparator records semantic/resource divergence.
9. A bounded canary receives explicitly eligible traffic.
10. Kernel commits generation cutover and raises Authority Epoch.
11. A forced regression demonstrates automatic routing rollback without loss of task/effect state.
12. Restart Host/Kernel/testd and reproduce the same receipts and active generation.
```

Exit evidence:

```text
no direct shell or DB authority for the agent/component;
no orphan process or unreceipted effect;
byte-addressable artifacts and Failure Capsules;
component can remain WASM or be replaced by an equivalent isolated native generation;
full control-plane release is not required for a component-only iteration.
```

Failure at any stage returns the component to a non-active state and preserves the candidate for diagnosis; it does not trigger broad feature work or a full workspace certification campaign.


## I17.19. Donor adoption order

Donor research is first dispositioned, not automatically promoted into normative contracts. Mechanisms are implemented in dependency order and cannot delay the current recovery objective.

```text
Stage A — research disposition, not contract proliferation
  preserve the donor mechanism, evidence, owner candidate, failure class,
  local discriminator and activation condition in the non-normative donor ledger;
  add a target contract to this book only when the next executable slice needs it
  or when it closes an already-active Hard Boundary gap.

Stage B — after Operational Spine Proof 1, or earlier only for a current safety blocker
  implement one capability-grant/introduction path used by a real Attempt;
  classify only the methods actually exported by that slice;
  prove one live revocation and one selected code-intelligence owner/fallback;
  retain unrelated donor proposals as INACTIVE Research Gates.

Stage C — after component promotion proof and demonstrated product need
  DDC for one real model/swarm bundle;
  one real-runtime Test Namespace;
  governed SessionEpisode retrieval evaluation;
  one small Capability Blueprint instance only if portability is a current goal.

Stage D — only after measured need
  cross-principal live collaboration;
  typed callable continuation;
  external blueprint exchange;
  WASM capability-program experiment;
  vector/learned graph/full generated documentation.
```

Stop or narrow a donor mechanism when it:

```text
creates a second authority/policy/memory owner;
duplicates watchers/index roots;
has no independent discriminator/reference path;
increases prompt/tool surface without measured reduction elsewhere;
cannot explain revocation, restore and privacy behavior;
turns derived navigation into proof;
delays Operational Spine Proof 1 or memory rehabilitation.
```


# I18. Testing and Instrumental Grounding strategy

## I18.1. Purpose, proof scope and canonical owner

Testing exists to distinguish competing explanations of system behavior and to provide grounded evidence to agents. It is not a separate product, a line-count target or a substitute for Architecture.

Every check declares:

```text
property and competing failure it distinguishes;
Product/WorkScope/base/candidate/tool identities;
real execution path;
coverage and freshness;
what PASS proves;
what PASS explicitly does not prove;
normal trigger, owner and retirement condition.
```

Proof levels never promote automatically:

```text
ShapeProof       — syntax/schema/literal/generated shape;
ModuleProof      — one micro-module behind its public contract;
EdgeProof        — provider/consumer or process/protocol edge;
IntegrationProof — affected real owners compose in one environment;
ProductProof     — end-to-end user property on accepted runtime;
ReleaseProof     — supported matrix, recovery, migration and packaging.
```

Canonical execution ownership:

```text
Instrument Registry owns profile definitions;
InstrumentRunner owns deterministic stage execution/aggregation;
ProcessExecutor owns external process semantics;
parsers own normalization only;
Governor owns evidence admission and verifier binding;
FinishService owns task completion;
Justfile/CI/agent surfaces are thin callers of the same profile.
```

A test report, status file or tool exit code is not evidence until it is bound to exact identity, coverage, freshness and raw output.

The normal change path is deliberately small:

```text
old-path discriminator
→ Module Proof
→ affected real Edge/Integration Proof
→ Product Pulse only when the changed property crosses the product path.
```

Sections I18.8–I18.52 form a conditional profile catalogue, not a cumulative checklist. A specialized profile is loaded only through:

```yaml
SpecializedProfileActivationReceipt:
  changed_property_and_impact_evidence:
  selected_profile_and_exact_trigger:
  omitted_profiles_and_why_they_are_irrelevant:
  expected_additional_failure_class_or_proof:
  budget_resource_and_stop_condition:
```

No test exists merely because this book names it. If a profile cannot distinguish a relevant failure or support a declared proof level, it is not selected.

## I18.2. Discriminator-first repair

For a confirmed bug or regression:

```text
1. capture exact failing path, state and identity;
2. state causal hypothesis and at least one rival when material;
3. create the cheapest discriminator that fails on old behavior;
4. implement one Causal Change Unit in one primary FunctionalCapabilityCell and its bounded source packages;
5. run module proof and affected contract-edge proof;
6. run selected live/product proof when the property crosses a real boundary;
7. record outcome and update FailureFingerprint, Skill/Guardrail or Improvement Candidate.
```

A second repair of the same class cannot add another field escape, timeout, wrapper or compatibility branch without Mechanism Review.

No-zero-test rule:

```text
runner records discovered, selected and executed counts;
expected nonzero group with zero execution is failure;
wrong package/feature/target/worktree is harness failure, not product pass;
missing output or parser incompatibility is unknown/failed evidence, not green.
```

## I18.3. Impact graph and selection

`eliot dev` / Instrument Profile Resolver builds the affected graph from:

```text
Git diff and candidate identity;
Cargo package/target/feature/resolve graph;
crate groups, CrateContextProfile and CrateBuildProfile;
MicroModule and OWNER manifests;
public contract/schema dependencies;
process/module manifests;
state/schema/migration/effect markers;
Architecture/Implementation anchors;
latest code-intelligence evidence;
behavioral co-change and historical failures as widening hints.
```

Selection is conservative:

```text
exact known dependencies select mandatory checks;
heuristic/historical edges may widen checks;
stale, incomplete or missing graph never proves non-impact;
unknown impact becomes an explicit plan gap or broader tier;
Human/Main Agent may widen freely;
narrowing a mandatory group requires scoped evidence/deviation.
```

The resulting `ChangeImpactPlan` is stored with reasons for every selected and omitted profile. Its selection-evidence block records:

```text
selector and comparator kind/version;
test/package/binary/feature/configuration granularity;
discovered, selected, reference and actually executed sets;
omitted and extra selections against actual failure/fault outcomes;
stable failure, flaky, infrastructure, parser and unknown labels;
de-flake/retry policy and reference/full-run sampling probability;
selection rate, failed-test/fault recall, set disagreement and uncertainty;
offline analysis, online selection and execution overhead separately.
```

Selected-set agreement with another selector is not safety. A selector may accelerate local feedback, but it never replaces an independent release proof or a sampled/full reference run.

## I18.4. Test tiers

A **proof level** says what a result can establish. A **test tier** says how broadly the current change is checked. They are orthogonal: a narrow T1 real process contract may provide EdgeProof, while a broad T3 collection of weak shape checks still does not provide ProductProof.

```text
T0 — changed crate/micro-module: package-selective compile, static/schema, unit/property/golden;
T1 — module public contract, parser/profile contract and health;
T2 — affected provider/consumer edges and one relevant runtime scenario;
T3 — selected authority/data/security/recovery/concurrency/migration/product path;
T4 — release matrix, long-running recovery, installer/update and full supported profile.
```

A tier says how broadly a change is checked; a **fidelity level** says how well the check represents the target. The two are orthogonal and both travel with the evidence:

```text
F0 schema/syntax/static   F1 unit/property   F2 reduced model or toy simulation
F3 realistic simulation or integration       F4 held-out representative workload
F5 shadow or independent environment         F6 physical/external replication
```

Escalation is budget-aware: a higher fidelity level is used after a cheaper level has narrowed the candidate set, when the remaining uncertainty is decision-relevant, and when expected value exceeds the added cost. Every result carries its fidelity level, represented target, omitted factors, validated range and transfer boundary. A high tier of low-fidelity checks does not become a high-fidelity proof.

T3 is triggered only by relevant load-bearing impact. A UI font/style change runs UI build, template/snapshot and accessibility smoke; it does not run database restore, Kernel split-brain or every route.

A full workspace suite may be requested for diagnosis or release, but it is not the default response to local change.

## I18.5. Composition and proxy resistance

Visible local tests are optimization signals and may be gamed. Long-horizon or cross-module acceptance includes at least one applicable countermeasure:

```text
held-out composition scenario;
independent or blind evaluator;
real downstream consumer/artifact;
metamorphic/property test over unknown inputs;
canary on actual runtime;
cross-feature state interaction;
base/candidate differential proof;
Human acceptance for properties no instrument can measure.
```

The test must fail on the exact old production path, not merely on a fixture created after the repair. Test quantity never compensates for wrong construct, wrong owner or wrong runtime identity.

Oracle separation:

```text
agent changing implementation may add a discriminator that reproduces the old fact;
changing expected business/contract behavior in the same unit requires
  an independent contract/oracle owner or mechanically anchored evidence;
snapshot acceptance is a separate disposition, never an automatic update;
a worker cannot make its implementation pass by weakening the verifier,
  broadening tolerance or changing fixture truth without explicit review.
```

## I18.6. Canonical InstrumentRunner, test discovery and `dev-fast`

All verification profiles execute through I10.8. The first canonical coding profile is:

```text
0. resolve Product/WorkScope/base/candidate/worktree identity;
1. protected-path and allowed-change preflight;
2. Cargo lock/metadata/toolchain/config preflight;
3. discover current tests from nextest JSON;
4. select affected packages/binaries/tests from Impact Graph;
5. run governed Clippy/rustc JSON for affected scope;
6. run selected nextest with JUnit and per-test policy;
7. run rustfmt check as a separately reported low-cost stage;
8. normalize recurrence/progress, facts, unknowns and exact reruns;
9. commit InstrumentRuns and VerificationProfileRun through ELIOT evidence path.
```

A separate governed `cargo check` stage is not part of `dev-fast` when Clippy performs the same compilation. Direct `cargo check` remains available as an exploratory noncanonical instrument.

Test inventory is discovered, not hand-maintained:

```text
cargo nextest list --message-format json
→ parse stable package/binary/test identities
→ join ELIOT metadata overlay.
```

Overlay stores only non-discoverable policy:

```text
risk/criticality;
state/resource class;
required Windows/service fixture;
serial group;
acceptance relation;
coverage/mutation obligation;
known quarantine/flake disposition.
```

Missing overlay target is stale metadata. A discovered critical test lacking required classification produces policy-incomplete status, not a fabricated classification.

Target layout is explicit and worktree-safe:

```text
%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-class>
```

Initial build classes:

```text
interactive;
clippy;
nextest;
rust-analyzer;
coverage;
mutation.
```

ELIOT-owned instruments do not use repository `target/`. Classes may merge only after measured lock/cache/memory evidence.

Every run stores a `TestSelectionReceipt`:

```text
candidate/profile revision;
discovered inventory snapshot;
selected and omitted tests/stages with reasons;
impact evidence and unknown coverage;
expected/executed counts;
resource groups and cache/target identity.
```

The receipt makes false-negative selection auditable and allows replay after an escaped regression.

## I18.7. Independently testable capability cell contract

Owner of this contract is the `FunctionalCapabilityCell`, not the crate; a crate may host several cells and remains only the normal Cargo compilation/publication container.

Every production crate or independently scheduled capability cell has an executable `ModuleTestCapsule`; the package-selective profile is the normal Cargo entrypoint. Private micro-modules inside the crate may have narrower selectors, but the crate is the normal unit of Cargo compilation, contract publication and agent delivery. Mutable-state/lifecycle ownership remains attached to FunctionalCapabilityCell/service contracts rather than inferred from package membership.

Canonical entrypoints are generated through Instrument Plane:

```text
cargo check -p <crate>;
cargo nextest run -p <crate> <selector>;
crate-specific property/model/golden profile;
consumer contract profile;
real-edge profile where applicable.
```

Independence means:

```text
unrelated runtime services are not started;
fixtures and resources are declared;
selected tests have nonzero discovery/execution receipts;
result is attributable to one crate/contract edge;
proof ceiling is explicit;
Cargo may still compile exact dependencies required by that crate.
```

Minimum proof by class:

| Crate/micro-module class | Required local proof |
|---|---|
| `foundation_contract` | schema/serialization/compatibility/property; no runtime |
| `pure_core` | unit, property and adversarial boundary cases |
| `state_machine` | transition model, replay, stale revision/epoch and cancellation |
| `parser_normalizer` | golden corpus, unknown fields, truncation, non-UTF-8 and fuzz |
| `profile_recipe` | fake-executor stage graph plus exact real-tool fixture |
| `stateful_service` | service contract, restart/replay and no hidden state owner |
| `process_adapter` | handshake, identity, streams, cancel, cleanup and fault |
| `projection_renderer` | semantic invariants plus snapshot/accessibility where applicable |
| `thin_binary` | composition/startup/config/health; domain behavior belongs to libraries |

A fake implements the same public contract and exposes unsupported behavior rather than returning success. Fake proof never becomes Edge/ProductProof.

Each fixture corpus is a versioned `ContractFixtureSet` with source lineage, oracle owner, covered property/failure and invalidation dependencies. Provider and consumer crates use the same contract revision. Updating implementation and expected oracle in one work item requires separate oracle review.

Crate tests are sharded with nextest when independent. Cross-crate edge tests live in dedicated edge/scenario crates owned by the relation, not copied into every participant.

## I18.8. Instrument Plane self-tests and fault contracts

### ProcessExecutor

```text
parent-child-grandchild termination;
stdout saturation;
stderr saturation;
both streams saturated;
idle and wall timeout;
cancel/exit race;
helper escape attempt;
Job Object close cleanup;
resource limit and access denial;
exact executable/environment identity;
InstrumentRunner/eliotd death while a tool is active;
reconciliation of process outcome and raw streams after restart;
no blind rerun when effect/output outcome is unknown.
```

### Parsers and normalizers

```text
rustc/Clippy JSON unknown fields and multi-span diagnostics;
Cargo driver error before compiler output;
nextest list/JUnit build, launch, test and timeout failures;
missing/corrupt JUnit;
Windows/Unix/non-ASCII paths;
truncated and non-UTF-8 output;
SCIP unknown records and partial index;
raw evidence retained when normalization fails.
```

### Evidence

```text
stale candidate cannot bind as exact;
partial coverage cannot create negative fact;
contradicted heuristic remains visible but downgraded;
raw handle remains retrievable;
same evidence cannot be rebound to another candidate;
unknown tool/parser version blocks authoritative profile;
profile aggregate cannot hide missing required stage.
```

### Process/module contracts

```text
malformed input;
version mismatch;
deadline and cancel;
quiesce/checkpoint;
stale epoch;
restart/reconcile;
permission/privacy denial;
hot cutover before/after linearization;
unknown external effect;
local degradation without Kernel loss.
```

## I18.9. Hard Boundary discriminators

Before broad feature depth, the current recovery line passes independently:

```text
Forged finish:
  caller prose, `accepted=true`, missing fields and legacy payload cannot produce VERIFIED_COMPLETE;

Lossless payload:
  arbitrary nested JSON is byte-exact through write, restart, read, backup and isolated restore;

One control path:
  report deletion/tampering cannot change authority;
  live CLI/MCP writes use one GovernorRuntime composition;
  stale epoch/principal/revision is denied;

One process path:
  every governed external tool is launched through ProcessExecutor;
  direct spawn lint is clean; cancellation leaves no unaccounted child.
```

A pass on one cannot compensate for another.

## I18.10. Cognitive and memory product tests

Use the proof ladder and ecological A/B contract in I12.34.

Required memory lifecycle checks:

```text
normal state/packet finds useful memory without answer-shaped query;
nonce/smoke/stale duplicates are absent from active recall;
exact EvidenceAtom + matching VerificationRun supports one Claim;
FailureFingerprint prevents a reproduced path and can later reopen;
curation changes normal packet cargo and later action;
restart/rollback preserve and reverse lifecycle state;
Context Compiler exposes relevant instrument facts, conflicts and unknowns;
actual verifier/outcome revises prediction and memory influence.
```

Marker relay and exact-handle readback are transport/forensic proofs only.

When a capability claim depends on a memory type, relation class, graph plane, cue policy or compiled representation, the applicable evaluation includes a type-specific ablation or replacement arm. The type name itself proves no benefit. For forgetting/deletion, the suite measures false deletion/retention, abstention, near-match positive controls, downstream non-inferiority and restore resurrection under the same scope.

## I18.11. Swarm tests

Start with read-only audit portfolios and one writer. Test:

```text
work-item/module ownership and contract freeze;
loss/reassignment and controller restart;
duplicate/late results and stale Authority Epoch;
Evidence Lineage and shared-root poison;
first-pass blind independence and disclosure-boundary contamination;
partial-result preservation;
WIP/quota/environment limits;
parallel module builds without shared target/cache corruption;
one IntegrationLease holder and deterministic merge order;
product proof compared with simpler single-agent recipe.
```

### Coordination ablation

On the same blind long-horizon task distribution, run:

```text
B0  solo route;
L1  fixed partition + isolated workers;
L2  independent mapping + negotiated immutable partition + cross-review;
L3  L2 + admitted live peer delivery at the next route-qualified boundary.
```

Measure:

```text
verified acceptance/rubric coverage;
wrong-partition and cross-boundary miss rate;
rework and duplicated exploration;
helpful versus harmful redirection;
first-pass contamination and disclosure violations;
messages admitted/delivered/used, delivered tokens and context growth;
cost, wall time and Human attention;
downstream verifier/product delta rather than self-reported helpfulness.
```

Promotion law:

```text
L2 must materially improve interdependent tasks over L1 without unacceptable planning cost;
L3 must improve verified outcome or reduce rework over L2 while harmful redirection,
context growth, disclosure loss and cost remain inside the qualified profile;
passive delivery is never inferred from a route that exposes only checkpoint/turn-boundary delivery.
```

Only after read-only qualification does one isolated mutating canary run with disjoint worktrees, exact write claims, frozen contracts and a separate Integration owner. Failure narrows or disables the recipe/delivery profile; it does not add a universal consensus, group chat or automatic semantic subscription system.

New lanes are promoted only when they add unique grounded coverage or improve outcome/cost/recovery.

## I18.12. Canary, holdout and real-use evaluation

Candidate modules, profiles, models and rules use fixed tasks, held-out/composition cases and selected real workloads. Canary has explicit rollback, counter-metrics and dependency-fence invalidation.

Harness assumptions and Skills expire when route/model/tool/profile behavior changes. A plan or test layer that adds ceremony but reduces product outcome is removed or narrowed.


Shadow/canary admission records its exposure unit, variance source, independence assumptions, power/precision or non-inferiority design and eligibility rule. `UNDERPOWERED` and `INCONCLUSIVE` are terminal evaluation dispositions for that plan, not reasons to widen traffic. Replay-only success cannot satisfy the live-transfer criterion; a matched hidden/live observation is required for a live-outcome claim.

## I18.13. Full release gate

ReleaseProof includes:

```text
clean build, lockfile, SBOM/license/source identities;
all supported Module and InstrumentProfile contract suites;
canonical store migration/backup/restore;
Host/Kernel/daemon/module update and rollback;
security/authority/privacy and direct-spawn/write-path checks;
representative agent hosts/routes;
long-running resume and swarm coordinator recovery;
Windows installer/update/uninstall;
local/CI profile parity;
exact Product Identity and evidence manifest.
```

Release gate is infrequent and is not run after every local patch.

## I18.14. Test retirement

Remove or narrow a test when:

```text
contract no longer exists;
a cheaper proof subsumes it;
false failure/maintenance cost exceeds value;
it encodes abandoned implementation rather than behavior;
it duplicates the same discriminator without new coverage;
it cannot fail on the actual production path.
```

Evidence and rationale are retained. Test count is never protected.

## I18.15. Development success and counter-metrics

Primary:

```text
time to scope/task orientation;
time to first safe action;
time to first correct action;
time to first applicable verifier and verified ProductProof;
verified product deltas per time/cost;
first-candidate and first-boundary correctness;
regression escape and recovery success;
repeated-failure reduction;
manual reconstruction/context burden;
module-local test latency and affected-plan precision;
time to first actionable failure.
```

The four early-action times are reported separately. A fast first action may be unsafe or wrong; a fast diagnostic failure may be useful without being a product outcome. Zero-ceremony remains a product hypothesis until matched tasks show equal-or-better correctness and lower orientation/interaction burden.

Counter-metrics:

```text
tokens, commits, LoC, test/report count;
activity/product-delta ratio;
repair attempts per failure class;
full-suite frequency and time;
false blocks and alert/rule friction;
selected-plan false-negative rate;
orphan processes and Cargo lock waits.
```

A counter-metric may reveal waste but never substitutes for outcome.

`AgentInterventionOutcomeProfile` is a derived vector over existing task, Product Pulse, rework, Human-attention and delayed-outcome receipts:

```yaml
AgentInterventionOutcomeProfile:
  window_task_family_route_and_governance_profile:
  verified_product_deltas_and_completion_quality:
  escaped_defects_and_delayed_regressions:
  rework_repair_and_rollback_cost:
  unrelated_or_forbidden_change_surface:
  oracle_or_fixture_changes_needed_to_pass:
  Human_correction_attention_and_recovery_cost:
  time_token_tool_compute_and_storage_cost:
  outcome: IMPROVING | NEUTRAL | DEGRADING | INCONCLUSIVE
  uncertainty_exposure_and_invalidation:
```

No scalar “agent score” is created. Persistent `DEGRADING` narrows autonomy/routing for the exact validity scope and opens an Improvement Candidate; it does not prove that every agent or model is harmful.

## I18.16. Host/route conformance

Provider-free protocol tests and bounded live probes are mandatory for exact `RouteFingerprint`. First route acceptance includes crash/cancel/restart, actual-route receipt, bounded artifacts/effects, no orphan descendants and correct interaction with InstrumentRunner/verifier callbacks.

Native resume/fork/replay/rehydration are tested separately. A route cannot claim independent audit credit when actual provider/model or lineage is unknown.

Translation/route conformance also covers mixed reasoning-visible deltas, malformed/partial streams, reconnect and cancellation after partial output, preservation invalidation, helper APIs that might drop diagnostics, header/error redaction, policy-branch reachability and session-revision races. A buffered restream or provider-specific request mutation must produce an explicit `TranslationReceipt` and RouteFingerprint delta.

## I18.17. Route/recipe evaluation

Evaluate on fixed distributions:

```text
success and verifier coverage;
latency/cost/quota;
continuation/context/tool failures;
cleanup and unknown outcomes;
independence and evidence diversity;
Human attention;
interaction with module ownership and test selection;
product outcome versus simpler recipe.
```

Recipe fan-out is promoted only by marginal grounded value.

Every route used for peer delivery is additionally classified:

```text
EventIntegrated | ToolOnly | OfflineWorker | Unavailable.
```

The qualification test proves the actual boundary at which an admitted message becomes visible, that the current foreground step is not interrupted, that stale/deduplicated messages are not injected, and that unavailable delivery remains queued/visible rather than being reported as passive awareness. Route fingerprint, host schema or tool-surface change invalidates the qualification.

## I18.18. Code-intelligence admission suite

No graph backend is admitted by README or demo. ELIOT maintains a Rust golden repository corpus covering:

```text
free/inherent/trait/generic methods;
associated types/constants;
async items;
macro_rules and proc-macro/derive behavior;
cfg(windows) and feature-gated items;
cross-crate references and re-exports;
build-script generated code;
unit/integration tests;
new/deleted/renamed/case-only files;
non-ASCII Windows paths;
dirty and multiple worktrees.
```

Freshness/failure cases:

```text
edit/new/delete after index;
process killed mid-update;
corrupt/truncated index;
stale long-lived session;
wrong worktree/base/candidate;
empty result from partial coverage;
resource limit exceeded;
cache lock/recovery failure.
```

Compare manual source/Git fixture truth, Cargo metadata, rust-analyzer/SCIP and optional heuristic graph. Measure definition/reference/implementation precision/recall, stale false negatives, negative-answer correctness, worktree identity, time/memory and cleanup.

A heuristic backend is rejected as default if it silently serves stale/incomplete data, emits unqualified empty negatives, selects wrong worktree, leaks processes/locks, breaches resources or cannot bind to exact candidate. It may remain an explicit manual heuristic scout.


Additional graph/projection falsifiers:

```text
exact cue/navigation with all graph edges removed;
GraphRevisionFence mismatch and split-view publication;
stale-edge action that would pass on clean source and fail on stale graph;
scope/disclosure violation introduced at pivot/rerank/community/summary/export;
matched exact/no-graph arm with total construction/query/context cost and outcome;
FULL versus DELTA projection at one source fence with equality oracle;
logical-row versus file/WAL/device-write accounting;
source/reference fallback after index kill or corrupt publication.
```

Graph utility, adoption and latency are reported separately from factual/causal assurance. A graph can be useful and still be unqualified to prove absence, impact or understanding.

### Anchor durability and provenance falsification

The same corpus carries original review/message/diff anchors through:

```text
insertions and formatting;
symbol rename;
function and file move;
rebase/cherry-pick;
semantic-preserving refactor;
semantic-changing refactor;
deletion;
duplicate or near-duplicate blocks;
partial/stale index and missing VCS history.
```

Measure exact/moved/modified resolution, false attachment, correct ambiguous/stale/deleted detection, Human correction rate, latency and evidence cost. False attachment is the critical failure: at uncertainty the resolver must return `ambiguous`/`unavailable`, preserve the historical anchor and refuse silent nearest-match attachment.

`ChangeProvenanceView` tests inject missing and conflicting operation/diff/receipt links. The view must label them `correlated`, `ambiguous` or `unknown`, preserve both directions of navigation where evidence exists and never convert temporal proximity into a causal claim.

## I18.19. Specialized instrument profiles

Profiles are enabled progressively:

```text
Baseline D1:
  compiler, test and rustfmt observation;

D2:
  dependency, snapshot and Windows runtime where required;

D3:
  architecture via Cargo + rust-analyzer/SCIP;

Targeted escalation:
  test-strength, concurrency, unsafe/FFI and performance.
```

Each profile has independent fixtures, parsers, resource policy, coverage semantics and context projection. Adding a profile does not widen every change's test plan.

## I18.20. Test-strength escalation

Test strength is investigated only when risk or evidence justifies it:

```text
1. base/candidate red-green or fault reproduction;
2. changed-line/function coverage on affected scope;
3. selected mutation on critical logic;
4. fuzz/model-check/formal proof on narrow boundary.
```

Coverage proves execution, not correctness. Mutation survivors indicate oracle weakness, not automatically a product bug. Expensive stages are bounded and never default to the entire workspace.


For authority, security, recovery, ordering and prior escaped-regression fixes, the discriminator must also prove that it can fail on the old mechanism (`test-the-test`). At least one applicable method is selected:

```text
merge-base or frozen pre-fix fixture;
mutation/reverted implementation fixture;
feature flag that disables the fix;
modelled bad implementation;
fault injection reproducing the pre-fix boundary.
```

The evidence records the exact old causal branch, the negative mutation and the failure produced. A green test that was never shown to reject the old path has a lower proof ceiling.

Fault points are placed around every irreversible or split-outcome boundary that the changed mechanism owns, including:

```text
before/after authority activation;
after external effect before receipt;
after canonical commit before outbox delivery;
after artifact write before manifest publication;
after old generation fence before new readiness;
after purge before backup/purge-ledger update;
after stage output before stage receipt;
during resource parking/reacquisition;
during partial multi-site transform or generated patch.
```

Multi-site compiler/translation/generated-code transforms declare their expected consumer set, validate every target before mutation, apply into a new immutable generation and post-scan for residual legacy branches. Partial patching fails closed or uses the explicit generic/degraded path.

## I18.21. Local and CI parity

CI builds the ELIOT verifier/runner bootstrap and then calls the same versioned profiles used locally. Justfile/scripts are aliases only.

```text
local profile revision == CI profile revision;
executable/tool identities are pinned or recorded;
external binaries require digest/provenance receipt;
results share one schema and evidence model;
CI-specific environment differences are explicit profile dependencies;
no CI-only hidden verifier command list.
```

The minimal bootstrap build is the only unavoidable pre-run exception.

## I18.22. Flake, hang and recurrence handling

A flake report requires actual repetitions or statistically meaningful historical observations; it is never synthetic.

Distinguish:

```text
build failure;
launch failure;
test assertion failure;
timeout/hang;
infrastructure/resource failure;
parser/evidence failure;
intermittent outcome.
```

Quarantined tests remain visible with owner, reason, expiry/review and replacement proof. Retry cannot turn an initial failure into a clean pass without preserving both attempts and policy.

## I18.23. Agent development test protocol

Before code, the worker receives:

```text
primary micro-module and public contract;
exact old failing behavior or missing property;
selected InstrumentProfile and independent module test command;
affected contract edges and forbidden drive-by changes;
expected observable and stop condition.
```

Worker flow:

```text
run discriminator;
change only declared module/support scope;
run module proof;
return artifact, diff, InstrumentRun handles and unresolved gaps;
do not run full suite unless selected by Impact Plan;
do not alter the test to accept new output without separate oracle review;
if the brief/discriminator is wrong, return ContractChallenge instead of optimizing to it.
```

Integrator runs edge/integration proof. Blind reviewer checks causal property and omitted coverage. The applicable evaluator establishes the proof ceiling; the `Requester / Domain Owner` accepts or rejects the claimed user outcome, while the Task Controller may only propose the task disposition within its delegated acceptance contract.

## I18.24. Failure, partial coverage and unknown

Testing outcomes are not binary when evidence is incomplete:

```text
PASS        — property proven in declared scope;
FAIL        — contradictory observation or missing required stage;
PARTIAL     — some required scope measured, some explicitly uncovered;
UNKNOWN     — tool/parser/freshness/coverage cannot answer;
BLOCKED     — policy/environment/capability prevents required proof;
CANCELLED   — no further effect; prior evidence retained.
```

`UNKNOWN`, `PARTIAL` and `BLOCKED` never become PASS through aggregation. FinishService maps them to task outcomes using acceptance criticality and authority; InstrumentRunner does not decide completion.

## I18.25. Evolution of the testing system

Testing modules improve through the same evidence loop:

```text
escaped defect or false block
→ identify missing/wrong discriminator
→ update module/profile/parser/impact edge candidate
→ run historical replay and held-out case
→ canary on affected task family
→ promote, narrow or reject
→ retire superseded tests.
```

The system must not react to every defect by adding a permanent global test. The preferred repair is the smallest reusable discriminator at the actual owner boundary.

## I18.26. Parallel build and test execution for agent swarms

Parallel agents use Cargo package selection and one InstrumentRunner-controlled build projection. They do not independently launch unrestricted `cargo --workspace` commands.

```text
one work item
  → primary crate + frozen contract + BuildFingerprint + target class;

private crate change
  → `cargo check -p` + applicable `ModuleTestCapsule` + affected edges;

public contract change
  → provider + reverse consumer closure + compatibility fixtures;

identical BuildFingerprint
  → one producer, multiple waiters;

read-only audits on immutable base
  → reuse exact immutable artifacts/evidence;

different toolchain/features/environment/candidate
  → separate build lineage;

unknown cache identity
  → rebuild.
```

Target coordination:

```text
one Cargo producer per target root unless exact tool evidence proves safe concurrency;
worktree/build-class roots follow I2.22;
verification and interactive diagnostics pre-empt background coverage/mutation/indexing;
failed producer wakes waiters with the same evidence;
no silent retry storm;
cancellation preserves raw evidence and quarantines incomplete artifacts;
disk cleanup is lineage- and lease-aware.
```

Test coordination:

```text
nextest inventory is discovered once per exact candidate/profile;
selected tests are partitioned/sharded by stable identity;
resource/serial groups prevent shared-port/DB/profile collision;
all shards contribute to one TestSelectionReceipt;
missing shard, zero-test shard or parser failure prevents aggregate PASS;
retries preserve first failure and retry policy.
```

Build performance is observed, not assumed:

```text
cargo --timings feeds CrateBuildProfile;
private/public change costs are tracked separately;
proc-macro/build-script and link bottlenecks are attributed;
target lock wait and peak memory affect WIP admission;
crate count alone does not trigger a full build or refactor.
```

Local interactive builds use per-worktree incremental state. Shared/CI/swarm reuse is measured separately with non-incremental compilation plus an admitted compiler-cache bridge; incrementally compiled crates are not assumed cacheable. Nextest build archives may be produced once and reused by bounded partitions only under the exact candidate/toolchain/profile/environment identity.

Optional compiler cache is admitted only behind exact fingerprint and supply-chain policy. Cache is a performance aid, never proof. This coordinator remains an InstrumentRunner capability; Durable Jobs, Ready Queue, budgets and task priority remain owned by Governor/Agent Coordinator.

## I18.27. Oracle ownership and test-change governance

Every acceptance oracle has an owner and origin:

```text
Architecture/Implementation contract;
external standard or exact source;
accepted Human/domain decision;
registered deterministic evaluator;
previously accepted artifact baseline;
```

A test author may encode the oracle but cannot create its authority by assertion. Changes to implementation and oracle in one candidate are split unless the oracle is mechanically derived from the same unchanged source. When split is impractical, blind reviewer verifies the oracle delta before implementation result is considered.

Tests may be wrong. A false block creates a `TestOracleProblem`, preserves the conflicting observation and permits scoped deviation; it does not encourage hidden bypass or permanent weakening.

## I18.28. Test-selection validation and sentinel lanes

Affected-test selection is itself fallible. ELIOT validates it through bounded counterchecks:

```text
historical regression/escape corpus;
rotating sample of predicted-unaffected module/edge tests;
contract-consumer tests after public schema/type changes;
periodic broader canary on representative Product Identity;
comparison of selected plan with actual later failures;
release full matrix.
```

A sentinel failure updates BuildTestGraph/Impact rules and may invalidate prior selection evidence. Sentinel sampling is bounded and profile-driven; it is not a hidden full suite after every change.

Selection quality metrics:

```text
false-negative escaped dependency;
false-positive test cost;
selected-plan precision/recall on known changes;
time to first useful failure;
number of unrelated packages/processes started;
```


Every load-bearing selector produces a `TestSelectionValidityReceipt`:

```yaml
TestSelectionValidityReceipt:
  candidate_change_and_selector_profile:
  comparator_kind: FULL_DEPENDENT | FULL_SUITE | HISTORICAL_FAULT |
                   MUTATION | SAMPLED_SENTINEL
  raw_selected_and_reference_sets:
  omitted_and_extra_tests:
  actual_failure_or_fault_outcomes:
  labels: STABLE_FAILURE | FLAKY | INFRA | UNKNOWN
  de_flake_and_retry_policy:
  reference_sampling_probability:
  precision_recall_set_disagreement_and_uncertainty:
  offline_selection_and_online_execution_cost:
  selector_and_verifier_granularity:
```

No published selection percentage becomes a portable threshold. Selection accelerates local feedback; it never replaces an independent release proof, and an unknown/flaky comparator cannot be silently scored as a selector success.

## I18.31. Verification-system self-change bootstrap

A changed verifier cannot be the sole authority proving its own correctness. Changes to ProcessExecutor, InstrumentRunner, profile selection, parsers, evidence normalization, test discovery or FinishService use an asymmetric bootstrap:

```text
last-known-good runner/harness
→ executes the unchanged external discriminator and candidate contract suite;

candidate runner/module
→ processes the same raw fixture/tool evidence in shadow;

comparison
→ checks raw capture, normalized meaning, selection, omissions and outcome;

canary
→ runs bounded real tasks while old generation remains rollback-capable;

cutover
→ occurs only after independent evidence and a new generation receipt.
```

Special cases:

```text
ProcessExecutor change
  → an outer Host/OS-level guardian scenario verifies tree cleanup and evidence;

parser change
  → old raw corpus is replayed through old and candidate parsers;

selection/impact change
  → historical escapes plus sentinel lanes test false negatives;

FinishService/verifier binding change
  → forged/partial proof adversarial suite runs through the last-known-good public front door.
```

The old generation may reject a candidate; it cannot certify that its own mechanism is permanently correct. A Human or independent route decides unresolved oracle conflict. This bootstrap is invoked only for the verification/control surface being changed, not as a full release cycle for unrelated modules.

Documentation/audit tooling uses the same asymmetric rule. `DocumentationEvidenceCheck` is executed from a frozen outer script/generation and verifies the exact bytes it packages. Its negative corpus includes:

```text
post-manifest one-line mutation;
Markdown digest changed but JSON ledger stale;
unresolved template variable in a published audit;
missing referenced artifact;
manifest points to a different versioned copy;
ZIP payload differs from workspace file;
count/table generated from a different source revision;
CURRENT_VERIFIED claim with no executable evidence;
two public contract sections define the same trait/type with different AST or schema digests;
a receipt payload redefines identity/authority/fence/provenance fields owned by `ReceiptEnvelope`;
an unknown additive reason code fails to round-trip under its stable `AgentResponseDisposition`.
```

The candidate documentation generator cannot certify itself solely by emitting a green report. Package re-extraction and digest comparison are mandatory, and any post-package edit creates a new revision.

## I18.32. Stateful test environments

Tests that start databases, services, browsers, ports, user-session tools or other mutable resources receive a `TestEnvironmentLease`, implemented as a testing specialization/view of the existing `ExecutionEnvironmentLease` rather than a second lease owner or table:

```yaml
TestEnvironmentLease:
  environment_id:
  candidate_and_profile_ref:
  owner_and_epoch:
  isolated_paths_and_data_roots:
  namespaces_databases_ports_profiles:
  credential_refs:
  process_job_ref:
  resource_limits:
  serial_or_conflict_group:
  cleanup_and_residue_verifier:
  expiry:
```

Rules:

```text
production data roots, credentials and user profiles are denied by default;
every mutable fixture has a unique or explicitly serialized identity;
fixture services start through ProcessExecutor and remain in a Job Object;
base snapshots may be reused read-only; writable overlays are per environment;
test success requires both property evidence and cleanup/residue disposition;
unknown external effect or failed cleanup quarantines the environment and opens Problem State;
parallel tests sharing a declared resource use one serial/conflict group rather than racing;
stateful isolation is observed, not asserted by a synthetic report.
```

The lease is a testing/resource boundary, not project authority. It cannot grant access to canonical production state or make a test result applicable outside its exact environment.

## I18.33. Crate fleet build and verification economics

Crate topology is verified as a development-system property. Every first-party crate exposes one generated Instrument Plane entrypoint:

```text
eliot dev crate check <package>
```

The command resolves the current `ModuleTestCapsule` and runs only applicable contract/schema/format checks, exact-package Cargo check or Clippy, unit/property/model/golden tests, nextest selectors, declared compile-fail/doctest/parser corpora and local restart/fault cases for service crates. Its receipt records selected/executed counts, `BuildFingerprint`, target root, `CrateContextProfile`, `CrateBuildProfile`, raw/normalized evidence, proof ceiling and mandatory consumer/edge checks not yet run.

Crate-local PASS proves only the crate contract. Public-contract changes schedule direct-consumer compatibility and affected reverse-dependency checks; process/module promotion additionally requires its cohort and real-edge profile.

### Fleet conformance

The generated `crate-fleet` profile checks:

```text
workspace members/default-members and C0–C4 dependency direction;
contract-hub churn, reverse fan-out and measured workset profiles;
FunctionalCapabilityCell and EffectiveMicroModuleManifest coverage;
public contract digests, unique catalogue entries and consumer coverage;
crate-to-runtime-bundle mapping and ModuleReplacementClass;
independent ModuleTestCapsule and ProofLatencyProfile;
zero-test/stale-test metadata and feature/dependency duplication;
proc-macro, build-script and native-link islands;
forbidden direct process/store/vendor calls;
package owner and metadata completeness.
```

Outcomes are `PASS`, `PARTIAL`, `REVIEW_REQUIRED` and `FAIL`. Missing or stale catalogue/manifest/graph/context evidence is PARTIAL; crossed empirical ranges open `CrateScaleReview`; cycles, a second mutable-state owner, missing lifecycle owner/test seam, forbidden layer edges, public vendor leakage or absent required proof fail the applicable admission. A correct but slow proof is `MANUAL_OR_SLOW_LANE`, not semantic invalidity; it leaves the crate eligible for explicit slow/manual proof but blocks automatic interactive scheduling until a measured profile admits it.

### Build modes and cache evidence

ELIOT measures three distinct modes:

```text
interactive incremental
  one worktree/BuildFingerprint target root, Cargo incremental and focused selectors;

shared non-incremental
  incremental off, optional pinned sccache and exact compiler/profile/feature/environment identity;

clean/release
  locked inputs, declared cache state and real codegen/link/runtime proof.
```

A cache hit never substitutes for execution. Each build-mode experiment records cold/warm time, Cargo critical units and parallelism, cache hit/miss/eviction, memory/disk, target-lock wait, representative rebuild fan-out and artifact identity. Incremental and shared-cache paths remain separate empirical profiles; unknown cache identity forces rebuild.

### Test-binary organization and sharding

Default organization per production crate is:

```text
unit/property tests beside private core logic;
one public-contract integration harness at `tests/contract.rs` with submodules under `tests/contract/`;
at most one separate edge harness when the crate owns a real process/store/protocol edge;
large scenarios in dedicated scenario/edge crates;
shared fixture crate only when multiple packages reuse it;
explicit harness/oracle for compile-fail and UI tests.
```

A source file does not automatically become a top-level integration-test binary. Heavy dev-dependencies are isolated; binary crates remain thin; doctests are admitted only for short public examples and nextest does not replace them. Stable test identity drives nextest partitions/shards, and every shard contributes to one `TestSelectionReceipt`; missing, zero-test or parser-failed shards prevent aggregate PASS.

### Many-crate performance profile

Required measurements include Cargo metadata graph/latency, cold/warm package-selective and workspace builds, `cargo --timings` critical path, reverse-dependency fan-out, process link time, proc-macro/build-script cost, incremental target size and lock waits, shared-cache behavior, nextest archive/reuse/partition cost, and rust-analyzer latency/memory.

Representative edits cover leaf implementation, high-fan-out contract, compatible refactor, additive/breaking public contract, feature/dependency, root manifest/lock/toolchain and simultaneous worktrees.

When `WorkspaceScaleProfile` crosses a condition in I2.23, a bounded review may change `default-members`, extract a heavy optional workspace, admit shared non-incremental cache or workspace-hack only after proof, split a compile/context bottleneck, merge ineffective micro-crates, shard CI/nextest or change WIP/resource limits. The change is accepted only when intended context/build/test/ownership outcomes improve without material regression in Product Pulse, dependency clarity, recovery or agent correctness.

## I18.38. Agent-context and crate-size falsification suite

I2.16 profiles are hypotheses about a particular route and task family, not model laws or Module limits. The experiment varies physical topology and delivered workset independently. It samples representative tasks across measured distribution bands rather than fixed universal thresholds:

```text
Loaded Slice:
  small leaf slice; median ordinary slice; upper-tail cohesive slice;
  deliberately incomplete slice; complete slice requiring decomposition or a larger qualified route.

Agent Workset:
  minimum Decision-Safety-Floor packet; ordinary qualified packet; upper-tail packet;
  same workset with one-hop context removed; same workset with irrelevant cargo added;
  route-relative overflow where no qualified envelope fits.
```

Bands are recorded as exact bytes/tokens and quantiles for the tested corpus. No number in the experiment automatically forces a crate split, rejects a Module or becomes a new planning default. The comparison asks which topology and context projection preserve the full causal property with the lowest total build/test/coordination cost and best Product Pulse.

For each exact model/harness/tool profile measure:

```text
task success and exact verifier outcome;
time/tokens to correct owner/path;
missed invariant or consumer edge;
unrelated files opened or changed;
local-expression/proxy patch rate;
ContractChallenge quality;
context expansion/compaction/recovery;
Product Pulse escape rate;
Human/integrator correction cost.
```

Controls:

```text
crate capsule + selected source;
full crate;
real split into subcrates;
arbitrary file chunking;
with/without one-hop contracts and Product Objective;
memory/context-free baseline where applicable.
```

A split is useful only if it reduces reconstruction/build/test cost without increasing cross-crate coordination failures or hiding the product property. A larger cohesive crate may remain after a `CrateScaleReview` records that measured outcomes are better and the Agent Workset stays inside the route-specific Safe Operating Envelope.

## I18.39. OTP-style supervision and hot-replacement fault suite

Every runtime bundle/module declares child restart class and group strategy from I14.10. The suite verifies behavior, not labels.

### `one_for_one`

```text
crash optional child;
only that child generation restarts;
sibling state/service remain available;
old epoch cannot emit new effects;
restart budget and Problem State update.
```

### `rest_for_one`

```text
crash provider in an ordered branch;
explicit downstream dependents quiesce/restart;
predecessors remain alive;
restart order and State Fence refresh are exact.
```

### `one_for_all`

```text
one tightly coupled child fails;
all declared group members terminate/restart;
no old member remains effect-capable;
strategy is rejected unless independent recovery is unsafe.
```

### Child classes

```text
permanent restarts after any non-retirement exit;
transient restarts after abnormal exit;
temporary never restarts automatically.
```

### Restart-intensity cases

```text
burst within admitted budget recovers;
repeated same failure reaches quarantine/escalation;
all attempts remain in logs/Problem State;
no infinite restart storm;
higher supervisors do not multiply attempts beyond their envelope.
```

### Hot upgrade

```text
candidate starts without effect authority;
old admissions quiesce;
state/checkpoint transformation is versioned;
ORS cutover and new Authority Epoch are durable;
old in-flight operations get one disposition;
rollback is a new forward cutover;
crash before/after linearization reconciles differently and correctly;
no orphan descendants remain.
```

Process-level scenarios run through Host/Kernel/ProcessExecutor. Actor-library unit tests cannot prove OS process recovery.

## I18.40. Crate-topology self-improvement tests

Crate split, merge, dependency move and workspace federation are Meta candidates and are evaluated like other mechanism changes.

Before/after evidence:

```text
Agent Workset/context mass and task success;
cold/warm compile critical path;
reverse-dependency fan-out;
package-selective and edge-test duration;
manifest/feature/public-contract overhead;
merge conflicts and parallel-agent throughput;
Product Pulse and escaped regression rate;
process artifact/link/update behavior.
```

Anti-proxy rules:

```text
more crates is not success;
fewer crates is not success;
lower compile time alone is not success;
smaller context alone is not success;
clean dependency graph alone is not success.
```

The accepted outcome is improved product-development throughput and causal reliability under equal or better correctness, recovery and operational complexity.

Repeatedly failed topology advice becomes negative procedural memory. Dreamer cannot re-propose it without new discriminating evidence.

## I18.41. Deterministic simulation and replay

ELIOT tests distributed/control semantics through a pure simulation boundary before relying on live timing.

Virtualized inputs:

```text
logical clock and timers;
seeded RNG and ID generator;
message delivery, duplication, reorder, delay and loss;
process/node lifecycle;
store responses, torn/unknown commits and outbox delivery;
provider/tool/model cassettes;
filesystem/network where the chosen simulator supports them;
failpoints at named transition boundaries.
```

The first owner is `eliot-sim-core`, which drives pure command/event/state transitions without Tokio, DB, model SDK or Wasmtime. Framework adapters are admitted by scope:

```text
Loom
  exhaustive small synchronization primitives;

Shuttle
  larger randomized concurrent state spaces; passing is not proof;

Turmoil
  deterministic Tokio network/filesystem/lifecycle scenarios;

MadSim
  optional broad async/distributed simulation after compatibility proof.
```

Each run creates `SimulationSeedArtifact`:

```text
scenario and code/profile digests;
seed and deterministic config;
event schedule/failpoints/cassettes;
terminal state and invariant results;
minimal failure trace and FailureCapsule ref.
```

Minimum scenarios:

```text
stale lease/fencing token;
duplicate command/effect delivery;
effect committed then acknowledgement lost;
writer/scheduler/Kernel restart;
unknown store outcome;
cancellation vs completion race;
promotion/cutover/rollback race;
mailbox overload and load shedding;
old generation output after epoch change;
Watchdog/testd loss during a run.
```

A simulation PASS proves only the modeled contracts. At least one real-edge/live fault test remains required for Integration/Product/Release proof.

## I18.42. Component conformance and promotion tests

Every multi-contour component shares one conformance corpus across pure core, WASM and native process backends.

Required classes:

```text
contract/WIT schema and interface digest;
unknown-field/version compatibility;
property and differential behavior;
capability denial;
memory/table/stack/output/host-call limits;
epoch/fuel cancellation and trap containment;
deterministic replay;
state export/import and incompatible migration;
shadow divergence;
canary rollback and old-epoch rejection;
AOT/cache compatibility with exact Wasmtime engine.
```

Production promotion consumes a `ComponentPromotionReceipt` that references all required evidence; it cannot infer success from a build or one test suite.

## I18.43. Agent behavior evaluation

Deterministic runtime correctness and probabilistic agent quality are separate proof systems.

Agent eval corpus includes:

```text
small causal implementation tasks;
wrong-owner and misleading-proxy tasks;
instruction conflict and Recoverable Deviation;
unknown/missing evidence;
repeated failure and Mechanism Review;
blind review and poisoned shared-root cases;
long-horizon resume/reconstruction;
context-size and position variants;
tool/route failure and budget exhaustion.
```

A trial records route fingerprint, packet, tools, actions, artifacts, verification, cost, time and outcome. Metrics include verified task success, unnecessary actions, rule violations, false completion, repeated failures, context use, cost/latency and human attention. Multiple trials estimate a distribution; a model judge is never the sole product verifier.

Every blind trial records:

```text
memory_snapshot_id and immutable namespace/branch;
run order and randomization seed;
prior-run visibility: ISOLATED | CUMULATIVE;
read-set digest, write fence and contamination flags;
allowed Tool/Facet manifest and HostObservedComplianceTrace.
```

Leaderboards use the isolated lane with one frozen oracle. A cumulative lane measures adaptation in a growing shared memory and reports order/crossover effects separately. Tool compliance is derived from host events, not the model's chronological prose.

Eval improvements become RouteOutcomeProfile/Improvement Candidates and do not change policy automatically.

Each release-facing agent/tool surface also runs one **model-stratified usability** profile over the same blind corpus where routes are available and budget-approved:

```text
cheap/flash route;
mid route;
frontier route.
```

Primary observations are scope discovery, exact-handle grounding, stale/wrong-scope rejection, schema first-pass success, same-intent correction recovery, candidate receipt, context tokens and latency. The profile remains `INCOMPLETE` when a stratum is unavailable; a frontier model cannot mask an unusable API for cheaper/common routes, and no fixed vendor/model list is architectural.


The corpus also includes:

```text
memory-function/type ablations where a type-specific benefit is claimed;
first-orientation, first-action, first-safe-action and first-correct-action timing;
HandoffCheckpoint versus equal-token flat summary versus no-context;
Concilium/rival-panel versus single-frame work with anchoring and probe-quality measures;
valid negative-memory near matches, obsolete cases and reopen trials.
```

A typed record family is justified as a policy/representation distinction without ablation, but no type-specific capability or outcome gain is claimed until the corresponding comparison passes. Handoff and panel studies grade constraints, unknowns, safe next action, verifier choice, errors, latency and outcome separately.

The agent/Human surface corpus also includes anchored-review trials:

```text
several independent comments on one long public plan/message/diff;
question, correction, objection, missing-evidence, scope and acceptance items;
original target moved/modified/deleted before response;
requested change outside the commenter or agent authority;
conflicting comments from different authorized principals;
response that answers the surrounding message but omits one item.
```

Measure per-item delivery, answer and final disposition; omission rate; false resolution; time to navigate original/current target and linked change/verifier; unauthorized change attempts; review-token/context cost; and Human correction burden. A batch passes only when every item has an explicit disposition and any unresolved/stale/ambiguous item remains visible.

## I18.44. Build sandbox, supply-chain and cache tests

The build plane must prove the guarantees it claims:

```text
build script/proc-macro cannot read a seeded forbidden secret;
network deny or separately authorized acquisition is observable;
worktree/target/temp ACL boundaries hold;
Job Object cancellation removes descendant processes;
cache cannot cross trust/source/toolchain fingerprints;
malicious oversized output cannot deadlock the runner;
SBOM/license/advisory/provenance artifacts bind to release hashes;
VM/lab fallback is selected when local isolation is insufficient.
```

A Job Object-only test cannot claim filesystem/network sandboxing.

## I18.45. Failure Capsule and wait-for diagnostics tests

For every timeout, deadlock, crash, unknown outcome and failed promotion, tests verify that:

```text
one immutable capsule is produced;
raw evidence is referenced, not silently truncated;
process/resource/effect disposition is explicit;
wait-for dependencies identify the blocked owner/resource;
seed/reproduction command reproduces deterministic cases;
retry creates a new attempt lineage;
privacy redaction does not destroy required integrity metadata.
```

The agent-facing Diagnostic Brief is tested against the capsule and may be compact; the capsule itself remains evidence.

## I18.46. Retry, load, soak and overload proof

Performance testing targets the real swarm load classes:

```text
many queued tasks and short model/tool events;
compile/test bursts from parallel worktrees;
large streaming outputs;
lease and heartbeat pressure;
provider quota resets;
shadow duplication;
restart and recovery waves.
```

Admission occurs before spawn. Separate pools protect control, interactive verification, ordinary execution, component build, simulation and background work. Tests prove bounded mailboxes, retry budgets, cancellation propagation, load shedding order and preservation of audit-critical events.

Optimization order remains:

```text
correctness/invariants
→ bounded resources
→ profiling
→ remove accidental copies/allocations
→ batch/cache/pool
→ serialization/allocator/runtime specialization only after evidence.
```

Zero-copy formats, custom allocators, shared memory, thread-per-core runtimes or a second build system are Research Gate decisions, not default remedies.

## I18.47. Evaluator, benchmark, budget and credit-assignment integrity

An evaluator measures a declared property; it does not inherit authority from a benchmark name, model role or report format. Every work item has a verification envelope naming mandatory Module/Edge proof, conditional risk profiles, maximum local attempts before Mechanism Review, Product Pulse trigger, release-only groups and any Human approval required for expensive or destructive proof. Budget exhaustion never converts incomplete proof to PASS: it yields PARTIAL/BLOCKED and the cheapest remaining discriminator.

After a meaningful contract/edge wave—and before many more local units are admitted—ELIOT runs the smallest Product Pulse that crosses the real front door and owner path, produces a real artifact/effect or decision outcome, checks Product Identity and State Fence, avoids answer-shaped fixtures and can fail while all module-local tests are green. Missing, stale or repeatedly failing pulses raise `DevelopmentDriftSignal` and force review of decomposition, contract or mechanism.

Every load-bearing evaluation produces an `EvaluationIntegrityReceipt` with:

```text
property/construct, oracle owner and acceptance relation;
exact task/benchmark subset and sampling procedure;
model, harness, tools, evaluator, environment and budget fingerprints;
inputs visible to worker, evaluator and Human;
reference/answer leakage and contamination checks;
source/evidence independence and shared-lineage limits;
raw results, aggregation method and excluded/failed trials;
criterion/ecological/temporal/transfer limits;
counter-metrics, known shortcuts and invalidation conditions;
production, measurement and optimization-feedback roles;
mutation survivors, historical escapes and OOD set;
false-pass/false-fail evidence;
actual/requested route, resource and oracle dependency;
effective independent evidence N and collusion/shared-lineage limits;
second route and/or Human disposition where required;
BudgetEquivalenceLedger and ComplexityEconomicsDelta;
assertability, ground-truth origin and artifact binding.
```

Rules:

```text
benchmark score is not ProductProof;
post-hoc evaluator change cannot rewrite an observed outcome;
a model judge is not sole proof for factual, authority, safety or completion claims;
blind/reference isolation is verified when required;
visible tests and agent-authored fixtures do not define the full oracle;
zero tests, skipped cases and unknown outcomes remain explicit;
credit is distributed and uncertain rather than automatically assigned to one memory/prompt/agent;
replay or simulation calibrates an oracle but cannot alone promote live Product Proof;
false-pass, false-fail, OOD and collusion evidence are measured separately;
one strong discriminator is preferred over many weak proxies.
```

For ELIOT development, the report names `UserOutcomeObjectiveState`, the causal property it can disprove and its proof ceiling.

### Measured verifier validity

```yaml
MeasuredValidityMatrix:
  status: MEASURED | INCONCLUSIVE | UNKNOWN | STALE
  known_valid_and_known_invalid_sets:
  false_pass_numerator_denominator_and_interval:
  false_fail_numerator_denominator_and_interval:
  OOD_strata_and_shift:
  mutation_survivors_and_historical_escapes:
  adjudicator_and_second_route_or_Human:
  same_patch_or_shared_oracle_dependency:
  task_cluster_and_effective_sample_unit:
  uncertainty_and_invalidation:
```

A missing denominator, inadequate sample or unresolved adjudication is `INCONCLUSIVE/UNKNOWN`, never zero error. Any load-bearing change to model/route, harness/tool schema, evaluator/oracle, task/source subset, environment, policy, budget class or Product Identity marks the dependent result `STALE` until the declared equivalence or re-execution is proved.

### Budget and complexity equivalence

```yaml
BudgetEquivalenceLedger:
  arm_ids_and_exact_product_route_profiles:
  inference_tokens_cache_reasoning_and_model_cost:
  model_calls_retries_search_and_test_time_scaling:
  tool_process_retrieval_index_and_verifier_calls:
  CPU_RAM_GPU_disk_network_and_queue_time:
  wall_clock_and_human_attention:
  hidden_background_curation_and_recovery_cost:
  equivalence: EXACT | TOKEN_MATCHED | COMPUTE_MATCHED | COST_MATCHED | NON_EQUIVALENT | UNKNOWN
  mismatch_and_claim_limit:

ComplexityEconomicsDelta:
  code_config_schema_process_and_contract_surface:
  operator_and_agent_ceremony:
  new_failure_recovery_migration_and_rollback_paths:
  maintenance_security_privacy_and_observability_burden:
  measured_latency_resource_and_product_delta:
  validity_scope_and_retirement_condition:
```

Intentionally unequal budgets may support an operating-point choice, not a causal superiority claim.

`ProductOutcomeObservationWindow` links an accepted task/artifact/release to recurrence, pass-to-pass and fail-to-pass behavior, downstream regressions, rework, maintenance, exposure/censoring, evaluator revision, rollback and irreversible residue. The original receipt remains immutable; the durability claim stays `RESIDUAL_WINDOW_OPEN`, becomes `MATURED`, or is narrowed/rolled back.

### Composite attribution and comparison forms

`EvaluationStackAttribution` records the exact composite path and adaptation mode (`memory_only | parameter_update | mixed`), parameter/memory revisions, task subset/source revision, model/provider/route, harness/Active View/Skills/tools, environment/resources/policy, evaluator boundary, Human intervention and missing capabilities.

`BenchmarkEcologyRecord` records construct, shortcuts/proxies, contamination, harness assumptions, local relevance, transfer limits, primary metric, counter-metrics, falsification, ground-truth origin (`seeded_script | human | extracted | mixed`), answerability/exclusions, synthetic/real boundary, tuning exposure, cluster/replicate unit, horizon controls and artifact digests. A leaderboard name is not capability proof.

`MemoryOutcomeBenchmark` compares a candidate memory/context mechanism with a matched memory-free or prior-policy control and reports stored/available/delivered/acknowledged/used, DecisionDelta or avoided failure, artifact/verifier outcome, latency/cost/context/Human attention and uncertainty/scope.

`SameModelHarnessComparison` holds model, harness, tools, task family and evaluator stable where possible, varies the candidate mechanism and uses held-out/compositional cases. Cross-model comparison answers a routing question and cannot isolate memory benefit.

`ExperiencedColleagueEval` checks whether a cold competent route recovers goal/current path/paused alternatives/next boundary, finds relevant prior decisions without answer-shaped cues, prefers current evidence, selects the verifier, avoids known repeated failure and matches or exceeds the control artifact/outcome. These comparison forms may update empirical profiles or open `ImprovementCandidate` records; none is itself Product Proof, promotion authority or permission to alter the compared mechanism.

### Oracle and evidence-family lineage

```yaml
OracleLineage:
  oracle_id_and_version:
  construct_measured:
  source_of_authority:
  implementation_and_fixture_digests:
  dependency_and_shared_failure_domains:
  historical_escape_and_mutation_refs:
  simulation_or_real_edge_domain:
  applicable_scope_and_proof_ceiling:
  invalidation_conditions:
```

A simulator proves only represented properties. Differential agreement is not independent when both sides share an oracle/parser/source; Product/Release proof requires real-edge corroboration where the claim crosses a real process, store, tool, provider or Human boundary.

`EvidenceFamilyLineage` hashes every material shared prompt/context, dataset/snapshot, harness/tool schema, memory/retrieved evidence, model/route, oracle/environment and prior narrative exposed before first pass. Evidence is grouped by family before aggregation. Blind first pass, source obfuscation and null/random controls are preserved where applicable; effective evidence N is reported only with estimator assumptions, sample unit and uncertainty. Missing lineage is correlated/advisory or unknown, never independent confirmation.

## I18.49. Active conformance obligations

Donor research, historical failures and long test catalogues live in a non-normative cold ledger. They become executable only through an `ActiveConformanceObligation` compiled for the exact current change/product identity:

```yaml
ActiveConformanceObligation:
  obligation_id_and_source_lineage:
  affected_contract_owner_and_property:
  activation_trigger_and_current_support_gap:
  exact_old_failure_or_competing_hypothesis:
  discriminator_or_falsifier:
  selected_module_edge_product_or_recovery_profile:
  oracle_and_evidence_lineage:
  proof_ceiling_and_expected_nonzero_execution:
  budget_resource_and_expiry:
  terminal_disposition_and_writeback:
```

Compilation selects only applicable obligation families:

```text
identity/authority/effect and recovery;
canonical write/read/migration and projection equality;
context/memory/retrieval/influence;
process/instrument/verifier and test-selection validity;
agent route/translation/stream/cancellation;
module/component promotion and rollback;
swarm independence/coordination/integration;
privacy/disclosure/reference/security;
human/product outcome and delayed regressions.
```

Existence in an audit, donor project or backlog does not activate a test. Every selected obligation must explain what additional failure class or proof it can distinguish; otherwise it is omitted. Historical exact IDs and cases are preserved in the external cold backlog for traceability.

## I18.51. External falsification and regression ledger

Detailed audit question IDs, donor-source headings, historical finding numbers and reproduction transcripts live in an external content-addressed evidence ledger, not in this normative book. The active Implementation sees only compiled obligations whose current owner and trigger are known:

```yaml
FalsificationObligation:
  property_and_current_contract_ref:
  source_finding_and_exact_evidence_refs:
  current_product_identity_and_support_status:
  old_failing_path_or_counterexample:
  discriminator_and_expected_observable:
  applicable_proof_ceiling:
  activation_trigger_budget_and_expiry:
  invalidation_and_retirement_condition:
```

An audit inventory or numbered research question does not become a test merely because it exists. The ledger compiler deduplicates obligations by causal property/owner, preserves each source lineage and emits only `ACTIVE` obligations into the affected `ModuleTestCapsule` or `ProductEvaluationPlan`. Historical names such as W4/F/D identifiers remain evidence handles and never appear in the agent hotset unless the current work unit needs the underlying counterexample.

Coverage counts prove only that source findings were dispositioned. Closure requires an executable discriminator on the exact current identity, or an explicit disposition of `ImplementationSupport = TARGET` with `EvidenceExecutionStatus = NOT_EXECUTED`, or `ImplementationSupport = STALE`.


## I18.52. Donor-specific fault corpora

Unsloth, Switchyard, RepoWise, Cloudflare OS and other donors supply negative cases and mechanism hypotheses—not product requirements or standing test suites. Their exact source-level cases remain in the cold backlog and are activated only when the corresponding capability exists on the exact Product Identity.

The current high-value families are:

```text
process origin, challenge-response capability evidence, native-resource TOCTOU and stage recovery;
provider-neutral translation, preservation invalidation, reasoning/content stream order, physical-attempt receipts and transport deadlines;
derived-index coverage/absence honesty, session episodes and reversible omission;
disclosure closure, grant lineage, capability introduction and resource facets.
```

Admission requires pinned source identity, local contract facade, an old-path discriminator, Windows/current-route conformance when relevant, cost/maintenance counter-metrics and removal/rollback. A donor name never raises authority, proof ceiling or implementation priority.

## I18.53. Activity, cold-start, feedback, maintenance and descendant closure suite

The following focused scenarios are mandatory before the corresponding capability can be reported supported:

```text
ACT-1  no Sessions/jobs/effects/policy → RuntimeLease and SupervisionLease expire → Watchdog/Host stop cleanly;
ACT-2  first UI/MCP/agent use from STOPPED → one coalesced activation → Kernel and independent Watchdog ready before admitted Material work;
ACT-3  wake during pre-commit drain cancels drain; wake after DrainCommit creates a new fenced generation;
ACT-4  suspend/hibernate/logoff/resume cannot reuse stale PID, pipe, epoch, UserBroker or lease and records the coverage gap;
ACT-5  registered but dormant WorkScope/repository does not keep Watchdog alive;
ACT-6  files/config changed while ELIOT was fully stopped are detected on next activation, stale dependent state and remain actor/intent-unknown;

COLD-1 two same-name clones with shared remote but different workspace identity remain separate candidates and memories;
COLD-2 copied marker or partial Git metadata cannot authenticate a WorkScope;
COLD-3 two simultaneous attaches single-flight through one OnboardingLease and cannot create duplicate current tasks/scopes;
COLD-4 empty corpus plus missing governing documents yields explicit readiness gaps and safe bounded work, not invented project knowledge;
COLD-5 governing-source change invalidates the old receipt before Material effects;

OBS-1  every claimed event class has a predeclared denominator/coverage profile;
OBS-2  absent event under incomplete coverage remains UNKNOWN;
OBS-3  journal admission does not recursively generate ordinary self-events;
OBS-4  protected journal failure blocks only the exact Hard-Boundary transition; ordinary Meta-import failure degrades observability only;

FDBK-1 wrong-scope feedback is accepted in self-scope and triggers ScopeBindingGuard rather than rejection by the wrong scope;
FDBK-2 route without feedback support is UNKNOWN, not satisfied;
FDBK-3 feedback receives a visible disposition and can repair the current packet without rewriting global policy;
FDBK-4 repeated supported feedback opens one deduplicated Problem/ImprovementCandidate;

CHILD-1 every visible child is registered before launch and appears in DescendantClosureReceipt;
CHILD-2 cancellation/restart cannot orphan process/session/effect descendants;
CHILD-3 opaque native subagents are treated as one parent attempt and never receive false child-level control/independence credit;

MAINT-1 release of the last active obligation deterministically runs EndOfActivityMaintenanceAssessment;
MAINT-2 assessment with no admitted work does not keep ELIOT alive;
MAINT-3 user-session-required maintenance defers/suggests instead of retaining desktop credentials or faking execution;
MAINT-4 Dreamer/maintenance outcome changes the system only through candidate → owner decision → verifier → rollback/retain loop;

RSH-1 unavailable/stale ELIOT Research returns explicit coverage gap and cannot silently substitute an old summary;
RSH-2 Research exchange preserves disclosure lineage and requires governed import before local influence.
```

Each scenario records exact Product/Activation/WorkScope identities, relevant rule and contract revisions, deterministic events, fault points, expected disposition, real evidence and proof ceiling. A document-only fixture does not satisfy a Windows/process/provider scenario.

# I19. Migration from current implementation and documents

## I19.1. Migration doctrine

No big-bang rewrite. Existing ELIOT remains evidence, donor code and possibly temporary runtime. New process tree grows around verified usable components.

```text
inventory
→ classify keep/wrap/extract/replace/retire
→ first side-by-side spine
→ migrate canonical state
→ cut agent path
→ extract modules
→ retire old paths only after receipts and rollback window.
```

## I19.2. Current forensic baseline and refresh rule

Historical audits and live-test artifacts are retained in the external evidence ledger as candidate regressions and donor evidence. They are not the current baseline by filename. Before every repair or migration campaign, `CurrentSystemEvidenceSnapshot` binds the exact selected source head, installed artifacts, live store revision and active integrations; only that snapshot can classify a blocker as current.

Candidate migration blockers that must be rechecked rather than assumed closed or current:

```text
weak legacy finish alongside canonical finish;
lossy generic payload transport;
report-backed shadow authority and multiple writer composition paths;
no enforced single Product Identity;
normal recall/understanding and live curation not operationally proven;
hooks/Skills are partial and host-dependent;
test/status/report activity has repeatedly exceeded product evidence.
```

Before each repair campaign, source facts are refreshed against the exact selected head, installed artifacts, live DB revision and active integrations. A historical audit finding receives one disposition:

```text
CURRENT(owner, discriminator, acceptance);
FIXED(commit/generation, discriminator);
SUPERSEDED(accepted Architecture/Implementation decision);
NOT_REPRODUCIBLE(replay evidence);
FALSE_POSITIVE(reason).
```

No finding disappears because a later report omitted it.

Required outputs:

```text
accepted Product Identity manifest;
component/owner/path inventory;
P0/major finding ledger with dispositions;
current data/integration inventory;
repair impact graph;
first Product Proof plan.
```

## I19.3. Component disposition

Current source-preservation rule:

| Existing source owner | First change | Forbidden duplication |
|---|---|---|
| `eliot-types` | additive host/route/capability/continuity/usage contracts | new parallel agent-domain crate |
| `eliot-engine` | extend Host Broker, admission, route selection and Agent Coordinator | second task DAG, scheduler or budget authority |
| `eliot-store` | store route evidence, raw/native events and receipts | agent/runtime database as canonical state |
| `eliot-windows-ipc` | carry additive typed commands/events | second unauthenticated local control channel |
| `eliot-app` | add `host_runtime` adapters/sidecars and migrate provider-specific launch paths | independent provider launch journals/recovery loops |

```text
KEEP       — conforms and can remain;
WRAP       — useful third-party/current component behind new bridge;
EXTRACT    — move from monolith to module with same behavior;
REWORK     — concept valid, contract wrong;
REPLACE    — incompatible or too costly;
RETIRE     — no value/duplicate;
UNKNOWN    — requires experiment.
```

No deletion before data/behavior owner and replacement proof.

## I19.4. Documentation transition

After this book reaches accepted status:

```text
Architecture + Implementation become normative pair;
old three books become historical donor sources;
all active code tasks cite new sections/ARCH IDs;
old Work Packages/phase gates lose normative force;
useful exact contracts are migrated or linked explicitly;
no Part B/C/D/E precedence remains.
```

## I19.5. Recovery and runtime transition order

No new permanent phase vocabulary is stored. The following order is a migration dependency, not a status system.

### A. Identity and containment

```text
select one source head;
freeze exact installed/runtime/data identities;
separate dirty changes into causal units;
disable or hide weak authority surfaces;
preserve failing fixtures and revisions.
```

### B. Three Hard Boundary repairs

```text
strict canonical finish only;
lossless generic payload authority;
canonical control records and one online writer composition.
```

Each repair is a separate reviewed unit with an adversarial discriminator before code.

### C. Operational Spine Proof 1

Run the real vertical spine of I17.6 on the repaired existing runtime. Do not wait for the entire new process topology if the existing owner path can prove the property safely.

### D. Memory rehabilitation

Close I17.7 on a copy/current corpus: separate smoke from reusable knowledge, promote one evidence-backed claim, create one effective FailureFingerprint, prove normal recall and later benefit.

### E. Runtime extraction

Only after B–D:

```text
minimal Host/Kernel/ORS front door;
canonical store bridge;
new `eliotd` generation;
optional module extraction;
new-only cutover and retirement of legacy owners.
```

At every point exactly one implementation owns attempt idempotency, process containment, output capture, unknown outcome, worktree state and final receipt.

## I19.6. Data migration

```text
create full logical backup/export;
map old records to canonical families preserving IDs/provenance;
mark weak/legacy epistemic status explicitly;
keep raw source/blob;
rebuild derived indexes/capsules/cues;
validate counts/relation endpoints/history;
run dual-read comparison;
cut over to the candidate canonical-store generation through the same fenced route/cutover contract;
retain old DB read-only during rollback window.
```

Unknown legacy semantics become candidates, not invented verified state.

## I19.7. Session/task migration

Existing active tasks receive:

```text
new scope identity;
current plan revision;
known done/open/killed state;
current diff/artifacts;
unknowns/verifiers;
legacy source marker;
new State Fence and Authority Epoch.
```

No old lease/approval survives automatically.

## I19.8. Hook/plugin migration

```text
inventory duplicates;
install one active bridge profile;
disable old direct Surreal/MCP paths;
verify runtime events, not config only;
publish one immutable `ReleaseSurfaceManifest` binding source/commit, generated plugin/Skills/schemas,
  installed cache/config/registration, bridge/binary hashes, hooks, route profiles and active runtime generation;
make Doctor fail on missing surface, digest mismatch or semantic drift between those identities;
keep rollback copy;
watch for old process/config reappearance.
```

```yaml
ReleaseSurfaceManifest:
  product_and_source_identity:
  architecture_and_implementation_digests:
  generated_schema_plugin_skill_hook_and_prompt_digests:
  installed_cache_config_registration_and_bridge_digests:
  executable_package_route_and_module_generation_digests:
  active_service_process_store_and_user_broker_fingerprints:
  capability_and_Governance_Profile_refs:
  migration_and_rollback_refs:
  invalidation_and_expiry:
  release_receipt_and_signing_identity:
```

The manifest is immutable for one installed release. A source-compatible but byte-different installed surface is a different Product Identity. Doctor compares exact fields and reports `MISSING`, `MISMATCH`, `STALE` or `UNKNOWN`; it does not rewrite the manifest to match the observed installation.

## I19.9. Test migration

Tests classified:

```text
behavior proof — keep/adapt;
implementation lock-in — delete or narrow;
redundant phase certification — retire;
critical recovery/security — preserve early;
unknown value — measure runtime/failure history.
```

Do not port hundreds of tests blindly before first new spine.

## I19.10. Cutover criteria

```text
one canonical write path;
no active agent knows DB credentials;
new task/capture/read/verify/finish loop works;
restart/resume proof;
backup/restore proof;
old entrypoint produces explicit rejection/redirect;
ControlBoard shows migration gaps;
rollback plan tested.
```

## I19.11. Rollback

Rollback is generation switch while formats remain compatible. If new write format/migration irreversible, restore isolated backup or forward-repair; do not fake binary rollback.

## I19.12. Migration completion

Completion report lists:

```text
migrated data/components;
retired paths;
remaining bridges;
known degraded capabilities;
old documents status;
compatibility/rollback expiry;
conformance state.
```

---

## I19.13. Donor contract extraction

The authoritative non-normative donor-retirement ledger is content-addressed and bound to exact Architecture, Implementation and donor digests.

A donor item is not considered preserved because its name appears in the new book or because a whole old chapter points to `I0–I20`. For each load-bearing item the retirement ledger records:

```text
source heading/object and exact donor digest;
semantic obligation;
current owner;
current contract/mechanism;
failure behavior;
observable proof;
disposition and rationale;
active-reference/runtime migration status.
```

Before deleting old documentation:

```text
1. Freeze exact source bytes and digests.
2. Inventory every heading, named object, principle, state machine, profile, scenario and unique identifier.
3. Give every load-bearing item exactly one disposition: RETAIN, MERGE, SUPERSEDE, DEFER, REJECT or UNKNOWN.
4. RETAIN/MERGE require an active target with owner, behavior, failure behavior and proof; a chapter-level pointer is insufficient.
5. SUPERSEDE/REJECT record the current conflicting decision and rationale.
6. DEFER preserves the complete unique obligation in an owned Research Gate/backlog artifact; the donor file may not remain its only specification.
7. Verify every Architecture anchor against Implementation owner, mechanism, failure behavior and observable proof.
8. Perform active-reference scans over repository source, tests, schemas, Skills, prompts, configs, CI, generated files and installation manifests.
9. Inspect live schema/data/tasks/integrations for donor paths, obsolete statuses and old authority semantics.
10. Migrate active references; historical citations use an immutable archived URI and digest.
11. Build and restore the archive; compare every source digest.
12. Record explicit System/Architecture Owner cutover approval.
```

The evidence levels are reported separately:

```text
DOCUMENT_INVENTORY_READY;
DOCUMENT_SEMANTICS_READY;
REPOSITORY_REFERENCE_READY;
RUNTIME_DATA_READY;
RECOVERY_ARCHIVE_READY;
AUTHORITY_CUTOVER_READY;
PHYSICAL_DELETION_READY.
```

No lower level implies a higher one.

## I19.14. Old-object compatibility map

Legacy names remain import aliases only where necessary:

```text
CurrentTruthView          → CurrentEpistemicPosition;
MemoryWriteEnvelope       → CanonicalWriteEnvelope / PreparedTransition;
CodeUnderstandingProof    → ActionFrame + CodeCortexReport;
ControlWal                → ORS pending-operation partition;
ProjectProfile            → WorkScopeProfile;
ContextCargoReceipt       → Delivery/Injection/Influence receipts;
SleepCurator/DreamCycle   → Dreamer curation jobs;
```

Additional donor families are represented by active current semantics, not by historical names:

```text
DecisionLocalitySuffix / UncompressedTailState
  → Active Understanding View decision-local tail + HandoffArtifact;

CurrentValueConflictSet / DeterministicFreshnessResolver
  → Current Epistemic Position conflict set + deterministic resolver trace;

MemoryAdmissionGate / QueryTierDecision / FusedRankTrace
  → MemoryAdmissionDecision + exact-first tier and fused-rank evidence;

CapabilityMemoryIndex / CapabilityHotset
  → Capability Registry evidence + ToolSurfaceDecision;

MemoryInfluenceTrace / ContextCargoReceipt / RetrievalAsUseFeedback
  → delivery/influence ladder in I7.6 and I12.21;

ProfessionalWorkflowContract / ArtifactEvaluationContract
  → ProfessionalExecutionContract + Evaluation Contract;

TemporalSceneEvent / ObjectContinuityTrack / WorkflowStepState
  → ContinuityObservation / WorkflowStateView;

RuleSuffocationLint / BypassRoute
  → RuleGovernanceView + Governed Challenge / ImplementationDeviation.
```

Aliases never preserve obsolete authority or semantics. Detailed name-level disposition and historical cross-cutting families live in content-addressed cold ledgers; they are loaded only for exact migration or archaeology questions.

## I19.15. Documentation authority cutover and deletion gate

The new pair becomes active repository authority only through a `DocumentationCutoverRecord`:

```yaml
DocumentationCutoverRecord:
  repository_identity:
  architecture_identity:
  implementation_identity:
  previous_authority_contract_ref:
  new_authority_contract_ref:
  repository_reference_scan_ref:
  skills_prompts_configs_ci_scan_ref:
  runtime_data_scan_ref:
  archive_restore_ref:
  agent_integration_reload_refs:
  owner_approval_ref:
  status: blocked | prepared | active | rolled_back | retired
```

Required cutover order:

```text
1. Commit the exact Architecture and Implementation identities to the intended canonical branch.
2. Update the repository architecture-authority contract to name only the new pair as active normative sources.
3. Update README, AGENTS, Skills, plugin manifests, prompts, config, CI and generated documentation.
4. Run repository-wide reference and semantic-name scans on the exact candidate commit.
5. Inspect and migrate persisted schema/data, active tasks and installed integrations.
6. Reload/reattach agent integrations and prove they receive the new pair identity.
7. Restore the immutable donor archive and verify every digest.
8. Obtain explicit System/Architecture Owner approval.
9. Remove old books from the active tree; keep the immutable archive outside normal retrieval.
```

The normative book does not embed a dated repository verdict. The current `DocumentationCutoverRecord` and `CurrentSystemEvidenceSnapshot` are generated from the exact candidate commit, installed integrations and live data. Until they prove repository references, runtime/data migration, archive recovery and owner approval, authority cutover and physical deletion remain `NOT_READY`. Historical repository snapshots are external evidence and cannot silently become the current deletion decision.

Old books may be treated as superseded only inside a packet/session that explicitly binds to the new pair identity. They may not be removed from the project or ignored by repository agents while the repository authority contract still names them.

Physical deletion is not required for D0/D1 work. It is required before claiming that the repository itself has completed the two-book canonical cutover.

---

## I19.16. Object-level migration disposition and authority cutover

Migration is complete only with a bijective-or-explicit-disposition ledger:

```yaml
MigrationDisposition:
  source_object_identity_and_hash:
  source_semantics_and_owner:
  target_object_identity_and_hash:
  disposition: MIGRATED | MERGED | SUPERSEDED | ARCHIVED | REJECTED | UNRESOLVED
  transform_and_verifier_refs:
  provider_memory_or_external_effect_reconciliation:
  rollback_or_no_return_boundary:
  canonical_cutover_receipt:
```

Every active source object has one disposition; every target object identifies its source or declares it new. Shadow/dual-read is comparison only and cannot create two authorities. One cutover receipt selects the new owner; after the no-return boundary, rollback is a forward repair/migration, not resurrection of the old truth. Missing mappings return `MIGRATION_MAPPING_INCOMPLETE` and block retirement only for the affected scope.

# I20. Future replacement points

## I20.1. Replacement principle

Every strategic dependency has:

```text
facade/protocol;
owned state/export;
compatibility profile;
health/failure translation;
shadow/canary path;
rollback/removal plan.
```

A replacement point is not an invitation to premature abstraction. It exists where abandonment, license, platform or failure risk is material.

## I20.2. Replacement matrix

| Component | Current default | Boundary | Replacement proof |
|---|---|---|---|
| Canonical DB | SurrealDB bridge | Store EBP + ECXF | dual-read/write, migration, restore |
| Host state journal | redb | HostStateStore + installation-state export | activation/dependency lineage and torn-write recovery equivalence |
| Operational WAL | redb | ORS repository trait + export | crash/idempotency/recovery equivalence |
| Actor runtime | plain Tokio through `eliot-runtime`; `ractor` is experimental | runtime facade | supervision/fairness/perf scenarios and zero domain-type leakage |
| MCP SDK/spec | rmcp / MCP 2026-07-28 | eliot-mcp | host profile compatibility |
| Main model/provider | user-selected routes | ModelBridge | task/quality/privacy/cost profile |
| Dreamer model | user policy | Agent Coordinator job | curation/research evaluation |
| Code graph | bridge modules | eliot-graph-api | exact query/impact/health equivalence |
| LSP/IDE | bridge modules | diagnostic/symbol contract | project scenarios |
| Human UI | WinUI 3 / Windows App SDK desktop client | ControlBoard/Operator API | ordinary-user onboarding, Dreamer chat, launcher, accessibility and recovery |
| Windows services | SCM/Job Objects | platform facade | future Linux service tests |
| Notifications | Windows adapter | NotificationBridge | delivery/dedup/ack behavior |
| Blob compression/hash | zstd/BLAKE3 | Blob format version | export/import/content integrity |

## I20.3. Linux adaptation

Not before:

```text
real Linux environment;
service/socket/timer packaging;
permissions/secrets model;
filesystem semantics;
fault/upgrade tests;
agent/tool availability review.
```

Core protocol/contracts remain unchanged; platform modules replaced.

## I20.4. Multi-node/distributed future

Not part of current line. If introduced:

```text
one logical canonical owner and causal order remain;
replicas cannot become independent semantic owners;
network partition/fencing/consensus are explicit new Architecture-impacting work;
local-first single-node path remains supported.
```

## I20.5. Researcher providers and external federation

Researcher is defined in I21. This section states only the replacement boundary of its providers.

```text
P1  manually or bridge-supplied sources
    current accepted line; no additional runtime required;

P2  local search/preparation provider
    separate product and repository; owns source identity/revisions, safe reads,
    materialization, unitization and exact/lexical/structural/semantic projections;
    reached through a typed provider contract, never through canonical credentials;

P3  external research federation
    separate product and repository; owns large corpora, acquisition/OCR/indexing,
    long-running investigations and research publications;
    reached through the current `ResearchExchangeContract` of I21.11.
```

For every admitted source namespace, exactly one component is the authoritative mutable owner of source identity and source revisions. The local provider owns local source namespaces it ingests; an external federation owns its own namespaces; a manual import remains owned by the importing source adapter until an explicit cutover. ELIOT canonical state owns admission, handles, provenance, and allowed influence—not mutation of provider source history. Researcher, Dreamer, Context Compiler, Memory OS, and other providers hold immutable references or derived projections only. Provider replacement requires an explicit source-owner cutover with identity mapping, fencing, compatibility verification, and a receipt; a second mutable source catalogue or revision lineage is prohibited.

No provider is required for the first cognitive spine. A provider supplies candidates, coverage and freshness; it never receives task authority, canonical write access, Context Compiler admission or finish authority. Absence or failure of a provider narrows declared coverage and is reported as a gap; it does not stop the core hot path and does not transfer its responsibility to Dreamer.

A provider is replaced through its own contract, conformance corpus and capability descriptor. Replacing a provider never changes Researcher semantics, evidence grade, dispositions or coverage accounting.

## I20.6. WASM module tier

The current portable component baseline is defined in I14.19. Evolution follows compatibility evidence rather than ecosystem fashion.

```text
current production candidate:
  Wasmtime Component Model + `wasm32-wasip2` + versioned WIT;

laboratory lane:
  WASI 0.3 / `wasm32-wasip3`, async functions, streams and futures;

possible future:
  another component runtime satisfying the same WIT/capability/conformance contract.
```

A runtime change requires:

```text
same component conformance and differential corpus;
Windows startup/latency/RSS/cancellation measurements;
AOT/cache compatibility proof;
state migration and rollback rehearsal;
capability-denial/security tests;
shadow/canary GenerationCutover.
```

The component boundary remains replaceable. Wasmtime types never leak into domain/core crates or canonical records.

## I20.7. Cloud execution

CloudBridge remains optional. It can provide ephemeral agents/labs, not remote canonical owner. Remote output imports as source/evidence/artifact.

## I20.8. Distinct adaptation contracts

ELIOT does not call every improvement “learning”. Nine contracts keep mutable surfaces and proof ceilings distinct:

```text
1. Episodic/canonical memory update
   observations, evidence, episodes, claims, procedures and revisions;

2. Retrieval/context policy adaptation
   ranking, admission, packet layout, trigger and routing candidates;

3. Intra-task strategy and search adaptation
   hypothesis order, probe choice, parent/candidate selection and stop boundary;

4. Decomposition and workflow adaptation
   work-unit shape, recipe choice, wave structure and integration ownership;

5. Tool exposure and middleware adaptation
   advertised surface, invocation strategy, output reducers and evidence handles;

6. Active abstraction adaptation
   the representation the route works in: what is named, grouped and hidden;

7. Route and evaluator-cadence adaptation
   route selection inside policy, verification order and probe frequency;

8. Skill/prompt/procedure and structural harness adaptation
   versioned behavioral artifacts and executable harness structure, with replay,
   holdout, shadow/canary and rollback;

9. Parametric weight training
   future optional training product with its own dataset rights, provenance,
   deduplication, contamination controls, objective, evaluation, rollback and erasure limits.
```

The inner loop may originate scoped updates across contracts 1–8, but it directly changes only admitted task-local surfaces. Canonical memory writes under contract 1 and any reusable, system-wide, production or normative influence under contracts 2–8 remain with their existing owners and the outer promotion loop. Task-local Skill/procedure variants may live in the overlay; their reusable or structural form is contract 8 and requires promotion. Contract 9 remains `DEFERRED`.

Success in one mechanism is not evidence for another. Retrieval benefit is not a weight change; better wording is not acquired capability; a fine-tune does not replace public cognitive inheritance or canonical provenance. Parametric training remains `DEFERRED` until a separately approved product objective and data/evaluation governance exist. Supervised, preference and reward-optimized candidates additionally require an explicit reward/target contract, frozen base/control, dataset and license lineage, contamination and leakage checks, adversarial reward-gaming probes, held-out product evaluation, capability-specific rollback and an external authority boundary. Training score, reward or benchmark gain never grants canonical influence, tool authority, route independence or product acceptance by itself.

## I20.9. Architecture evolution trigger

Architecture review required when:

```text
base models acquire reliable persistent state/authority primitives;
canonical cognition moves into model/runtime;
local single-owner assumption changes;
new security paradigm invalidates bounded influence model;
ELIOT gains autonomous value/goal authority;
current four-plane theory no longer describes actual product.
```

Normal dependency/version replacement updates Implementation only.


## I20.10. Deferred donor experiments

The following ideas remain explicit Research/Experiment candidates and are not production obligations:

### Typed callable continuation endpoint

A bounded task-bound endpoint may expose typed request/response calls to one active agent route without making native session state a task owner. It must preserve `ContinuityKind`, route identity, budget, cancellation, introduction set and durable task receipts. It is considered only after route continuation/recovery is proven.

### WASM capability program

An agent may propose a small per-attempt component/program that calls introduced facets. It runs with:

```text
no ambient resources;
no direct authority;
bounded memory/time/host calls;
proposal-only effects;
recorded source/artifact/interface digest;
replay/shadow before any canary.
```

The discriminator is whether it reduces tool-schema/context cost and improves task success without hiding effects or creating another scripting control plane.

### Learned/vector/generated intelligence

Learned link prediction, vector overlays and full generated documentation are admitted only after exact/full-text/typed-graph paths have measured misses that they solve. Generated prose is always a derived projection and never proof.

### Cross-machine blueprint exchange

External blueprint import/export requires signature, license, supply-chain, disclosure and compatibility policy. Local blueprint instantiation is proven first.



### Pinned Unsloth ML worker and local-model subagent

A future `eliot-ml-unsloth` is an isolated native worker/provider, never a Kernel/Governor dependency. It may provide bounded training, quantization/export or local inference under exact environment/model/tokenizer/template/dataset/resource receipts. The first local-model subagent receives a narrow structured extraction/classification/test-triage task; it does not replace the Main Agent, recursively spawn workers or inherit cloud-agent authority.

Admission requires RGF-AGENT-ROUTES and one Product Pulse showing a useful quality/cost/latency delta against an equal-stack route. Unsloth Studio RAG/Deep Research/Data Recipes remain optional Researcher/dataset contours after core Product Proof.

### Switchyard translation adapter pilot

A pinned Switchyard `protocol + switchyard-translation` dependency may be evaluated behind `eliot-model-codec` and ELIOT-owned types. The pilot begins with translation fixtures and stream semantics, not routing intelligence or server adoption.

The experiment must compare:

```text
pinned dependency;
minimal ELIOT-owned implementation;
possible clean-room rewrite/fork.
```

Evaluation covers semantic fidelity, diagnostics preservation, loss policy, allocations, Windows build/test, update cadence, license/supply-chain, facade stability and rollback. Stage Router/classifier/skill distillation remain shadow research candidates only after translation succeeds and RGF-AGENT-ROUTES passes.

## I20.11. Final implementation formula

```text
Host Supervisor keeps a tiny Kernel recoverable.
Kernel keeps identity, authority, fencing, ORS and canonical boundary alive.
The replaceable Governor daemon owns application state and coordinates modules.
Replaceable service/module generations provide store and blob bridges, tools, graphs, model routes, Dreamer and surfaces; Watchdog remains an independent supervision service.
All durable meaning passes one governed transition path.
Independent work runs concurrently; conflicting state is ordered by scope.
Agents receive bounded understanding and write natural observations.
Dreamer synthesizes candidates; Watchdog observes failures; Doctor performs bounded repair.
Human policy governs goals, risk, privacy, cost and agent/swarm use.
Local changes build and test only affected modules; releases prove the whole system.
Every strategic dependency can be replaced through a thin bridge and verified migration.
```

# I21. Researcher plane, inquiry discipline and evidence grade

## I21.1. Researcher is a plane, not a future module

Researcher is the governed information-work plane of ELIOT. It is **not** a fifth architectural plane: it is a capability plane inside Smart and occupies `R6` in the runtime layer model. It is not a scheduler, a memory owner, a second Governor or an agent framework.

```text
OWNS
  research-domain resolution and revision of the versioned inquiry profile and Evidence Grade
    inside the current Task Controller definition and Governor admission;
  source-admissibility disposition for every external source proposed to an inquiry evidence set;
  source portfolio, coverage denominator and coverage accounting;
  confirmatory/exploratory lane discipline;
  evidence freeze, claim audit and research debts;
  reference firewall and unsupported-precision control;
  research/inquiry dispositions and reopen conditions.

DOES NOT OWN
  interpretation and synthesis                    → Dreamer;
  canonical transition, Current Epistemic Position and finish → Governor through existing canonical/finish paths;
  task objective, work-graph semantics or plan revisions       → Task Controller;
  admitted staffing and execution coordination                 → Agent Coordinator;
  budget policy/ceilings → Requester or System Owner; delegated allocation → Task Controller;
  budget admission/accounting → Governor and Agent Coordinator;
  local corpus preparation and retrieval                        → local search provider;
  large external corpora and investigations                     → research federation;
  verification execution                                        → Instrument Plane.
```

Source admissibility is not canonical promotion. Researcher records whether a source is eligible, ineligible or pending for one inquiry evidence set, with scope, taint, provenance and limits; Governor applies any governed state transition through the sole canonical writer. Researcher never writes canonical state directly and never promotes its own output to Current Epistemic Position. Its output classes are unchanged: governed sources, evidence candidates, bounded briefs and typed dispositions.

Providers are pluggable and none is required for the first cognitive spine (I20.5). Absence of a provider narrows declared coverage and is reported as a gap; it never transfers Researcher responsibility to Dreamer and never blocks unrelated local work.

## I21.2. Evidence grade

Depth of information work is a selected level of rigour, not a separate feature. One contour serves a quick lookup and a full investigation; the difference is the declared grade.

```text
E0 ORIENTING
   bounded exact/cached answer; no claim of coverage; not admissible for a Material decision;

E1 GROUNDED
   every material statement resolves to an exact source handle;
   observation, interpretation and assumption are distinguished;

E2 CORROBORATED
   independent source families or an independent observation route;
   rivals and counterevidence represented; coverage denominator declared;

E3 SCIENCE GRADE
   E2 plus a declared lane, frozen protocol/evaluator where confirmatory,
   evidence freeze before synthesis, claim-level audit and explicit research debts.
```

Selection, not inheritance:

```text
proposed by  Task Controller, Dreamer or the requesting route as part of ExecutionIntent;
resolved by  Researcher into a versioned inquiry profile under the current task definition;
admitted by  Governor together with budget, privacy and route policy;
enforced by  Context Compiler (I12.13), Evaluation Contract (I6.7),
             finish gate (I7.9) and swarm admission (I10.15).
```

A grade may be raised prospectively at any point in a task. Evidence already exposed retains the grade and lane under which it was produced; raising the requirement does not retroactively turn exploratory evidence into confirmation. A confirmatory E3 claim after exposure requires fresh held-out, independent or preregistered evidence, replication, formal proof or another sufficient truth surface. Lowering an already declared grade for an unchanged claim is a supersession with a reason, not a silent adjustment. A claim carries the grade it was produced under; a later reader may not upgrade it by quoting it.

Grade is orthogonal to `EvidenceStatus` (I7.27): grade states how much rigour was **required**, status states what execution, parsing, evaluation, independence and attribution were **observed**. The cognitive proof ladder (I12.34) limits what a result can establish; test tier (I18.4) states breadth; fidelity level (I18.4) states representativeness. None can be inferred from another or collapsed into one scalar.

## I21.3. Inquiry protocol selection

A single generic pipeline for every question is the most common failure of research automation. The protocol is chosen from the structure of the question.

```yaml
InquiryProtocolProfile:
  profile_id_and_revision:
  question_and_intended_decision_or_artifact:
  protocol:
    lookup | evidence_review | causal_diagnosis | formal_proof |
    program_synthesis | architecture_decision | algorithm_search |
    empirical_discovery | theory_development | decision_support
  evidence_grade:
  lane: confirmatory | exploratory | mixed_with_declared_split
  truth_surfaces_and_admissible_providers:
  coverage_goal: exploratory | representative | high_recall | exhaustive
  hypothesis_policy: alternatives_required | counter_search_required | falsification_required
  independence_and_blinding_policy:
  fidelity_ceiling:
  budget_deadline_and_stop_rule:
  output_contract_and_reopen_conditions:
```

Selection inputs are task features, not task vocabulary: sequential dependency, branch independence, shared mutable state, verifier cost and strength, specialist discoverability, horizon, uncertainty and risk. The same inputs feed `RecipePlanner` (I10.15), so protocol and staffing are chosen consistently rather than by two competing heuristics.

Protocol choice is a Default, not a Hard Boundary: it may be changed mid-run with a recorded reason, and the change invalidates only obligations that depended on the previous protocol. In a confirmatory lane, a change outside registered deviations also invalidates the registration; subsequent analysis is exploratory until a new registration is frozen before new outcome exposure.

## I21.4. Confirmatory and exploratory lanes

Executable form of A5.7.

```yaml
LaneRegistration:                    # required for a confirmatory lane or confirmatory partition
  contract_protocol_hypothesis_and_evaluator_digests:
  primary_outcome_and_decision_rule:
  exclusions_and_quality_controls:
  blinded_fields:
  allowed_deviations:
  registered_before_outcome_exposure:
  registered_at_and_state_fence:
```

After registration the run may not change the primary metric, exclude a case without a stated rule, weaken the proposition, replace the evaluator after seeing results or hide failed attempts. Declared deviations are preserved and shown with the result. Any later analysis is labelled exploratory. Acceptance is outcome-neutral: a compliant negative result is a valid confirmatory result.

Exploratory results are stored as `EXPLORATORY_FINDING`. Under `ARCH-EPI-03`, evidence that generated or tuned a hypothesis cannot confirm it on the same exposure. Promotion to a confirmatory claim requires a new holdout, an independent run, a preregistered test, replication, formal proof or another sufficient truth surface. A mixed lane freezes an explicit partition; evidence may not silently cross from the exploratory side into the confirmatory evaluator.

`blinded_fields` names one leakage channel to close, not a universal mask. Typical fields: preferred hypothesis, condition labels, parent conclusion, holdout expected score, candidate author, source prestige. Blinding interacts with the non-ordinal independence profile (I7.27) and with the sealed-mapping phase of `NegotiatedInterdependentInvestigation` (I10.15); it does not create a second independence model.

## I21.5. Inquiry obligations and acceptance certificates

An inquiry item is not a task description but a statement of what must become true and what will show it. Obligations are compiled into the existing work graph by `TaskGraphCompiler` (I10.15); no second graph exists.

```yaml
InquiryObligation:
  obligation_id_and_parent_question:
  goal_and_protocol_ref:
  dependencies_and_assumptions:
  acceptance_certificate_kind:
    kernel_checked_proof | reproducible_build_and_contract_tests |
    immutable_inputs_and_raw_measurements | exact_source_identity_and_passage |
    protocol_compliance_qc_and_raw_data | accepted_evidence_revision_and_authority_signature
  information_boundary:
  responsible_role_and_verifier:
  budget_and_stop_condition:
  status: STUB | READY | RUNNING | BLOCKED | SUBMITTED | VERIFIED |
          REJECTED | INVALIDATED | CANCELLED
  invalidated_by_reason_resources_spent_and_reusable_artifacts:
  reopen_conditions:
```

An obligation is satisfied by its certificate, never by a worker's report that it is done.

Planning is receding-horizon: only obligations that current observations can determine are materialised. Information-dependent futures remain `STUB` and are expanded when the upstream result arrives. Invalidated obligations are not deleted: they retain the invalidating cause, spent resources and any reusable artifacts, so that repeated planning cost becomes visible.

The planner wakes on: depletion of the ready frontier, a new contradiction, a verifier counterexample, a changed contract, a budget phase transition, stale evidence, a new dependency, a repeated local failure, evidence that changes decision ranking, or a Human semantic interrupt. It is not invoked after every tool call.

## I21.6. Source portfolio, coverage denominator and CoverageReceipt

```yaml
SourcePortfolio:
  primary_sources_and_specifications:
  reviews_and_secondary_analyses:
  operational_and_measured_evidence:
  independent_implementations:
  critical_or_negative_sources:
  missing_source_classes_and_reason:
  independence:
    source_family | provider_family | evaluator_family |
    shared_context_ancestor | shared_assumptions
```

Ten pages from one vendor are not ten independent sources. Two outputs are dependent when they share a source, restate one primary work, run on one model family, saw one parent summary, use one evaluator or inherit one mistaken assumption.

```yaml
CoverageReceipt:
  requested_scope_and_frozen_scope_snapshot:
  eligible_represented_cited_and_omitted_sources:
  unknown_coverage_and_reason:
  source_families_and_independence_profile:
  routes_used_stale_and_skipped:
  provider_degradation_and_redacted_dependencies:
  counter_search_status:
  denominator_kind: complete_scope | sampled_with_method | unknown
  budget_limitations:
  terminal_disposition:
```

`denominator_kind = complete_scope` is the only basis on which a scoped absence may be claimed. An indexed top-k result never narrows the denominator of an exact negative claim: it proposes candidates, and completeness is proved on the frozen scope. Retrieval quality and citation quality are separate obligations — see I21.8.

## I21.7. Reference firewall and unsupported precision

Every Dreamer, Researcher, audit, local-model and external-model job receives an `AllowedReferenceManifest` bound to the exact run and State Fence:

```yaml
AllowedReferenceManifest:
  run_job_and_root_context_revision:
  allowed_source_record_evidence_artifact_and_url_handles:
  allowed_tool_definition_and_verifier_refs:
  allowed_anchor_or_coordinate_precision:
  scope_disclosure_and_retention_classes:
  stale_or_revoked_entries:
  expansion_routes:
  manifest_digest_and_state_fence:
```

A model may quote, summarize or select only entries in this manifest. It cannot mint a valid citation, URL, source ID, line range, artifact handle or support relation through prose. A syntactically plausible but absent/stale/wrong-scope reference remains unsupported text and produces a candidate diagnostic rather than an evidence edge.

A newly mentioned external URL or identifier may be captured as an untrusted `ObservationCandidate` for later acquisition, but it is not treated as an allowed source or citation for the current run until an admitted provider resolves and snapshots it, Researcher records its source-admissibility disposition, and Governor applies the resulting `SourceRecord` transition through the sole canonical writer.

```yaml
UnsupportedPrecisionItem:
  asserted_reference_or_coordinate:
  highest_supported_precision:
  source_and_coverage_basis:
  risk_of_false_precision:
  required_probe_or_narrower_wording:
```

A source that supports a file-level or document-level claim does not automatically support a symbol, line, causal mechanism or population-wide statement. Reference validation occurs before candidate promotion and again when a result is packed into a shared packet or exported to another route.

The firewall does not censor model reasoning. It separates free-form hypotheses from support that ELIOT is allowed to represent as anchored evidence.

## I21.8. Evidence freeze, synthesis and claim audit

Before prose synthesis the accepted evidence revision is frozen:

```yaml
EvidenceFreeze:
  freeze_id_and_state_fence:
  contract_and_protocol_digests:
  included_evidence_refs:
  excluded_evidence_and_reasons:
  unresolved_contradictions:
  open_research_debts:
  frozen_at:
```

A synthesis author may not silently acquire a new fact and include it without admission. Any new material reopens the freeze with a recorded reason.

Every material statement of a released artifact carries a resolved chain:

```text
claim → evidence handle → source revision → run/measurement → transformation → statement.
```

`ClaimAudit` checks four independent properties: reference verification, value/measurement verification, specification compliance and method–artifact alignment. Its output classifies each claim as `SUPPORTED`, `PARTIALLY_SUPPORTED`, `UNSUPPORTED`, `CONTRADICTED` or `NOT_VERIFIABLE_IN_SCOPE`; uncertainty and scope limits are preserved rather than smoothed.

Retrieval quality and citation quality are separate obligations and are reported separately:

```text
source_satisfies_requirement    the admitted source genuinely contains the required evidence;
excerpt_supports_requirement    the supplied exact excerpts alone are sufficient for a careful
                                reader to verify the requirement.
```

A result may satisfy the first and fail the second. Failure modes of the second are explicit: fabrication, paraphrase that shifts meaning, stitching across sections, cropping that removes a hedge or negation, a search snippet presented as a page quote, and an excerpt absent from the admitted revision.

A model cannot mint a citation, source ID, URL, line range or support relation through prose; this is the reference firewall of I21.7.

## I21.9. Inquiry dispositions and reopen

Research/inquiry completion is also typed. An empty answer or exhausted search is not silently promoted to “question answered”:

```text
ANSWERED_WITH_SUPPORTED_RESULT;
NO_MATCH_IN_COMPLETE_SCOPE;
NO_NEW_USEFUL_EVIDENCE;
SOURCE_UNAVAILABLE;
STALE_SOURCE_OR_INDEX;
POLICY_OR_DISCLOSURE_DENIED;
INCOMPLETE_COVERAGE;
INCONCLUSIVE;
CANCELLED.
```

The disposition binds query, source portfolio, coverage denominator, reference manifest, State Fence and unresolved precision items. Only `ANSWERED_WITH_SUPPORTED_RESULT` or a properly scoped `NO_MATCH_IN_COMPLETE_SCOPE` may close the corresponding inquiry item; all other outcomes preserve a next probe, narrower claim or explicit unknown.

## I21.10. Local search provider

The local provider prepares and retrieves local data. For each local namespace it admits, it is the sole authoritative mutable owner of source identity and revisions, safe no-execute reads, materialization, unitization, exact, lexical, structural, and optional semantic projections, publication, and coherent readback. ELIOT stores immutable `SourceRevisionRef` values and governed admission or influence records; it does not mint a competing source revision. The provider is a separate product with its own repository, contracts, and delivery gates.

The ELIOT-facing boundary is fixed here:

```text
ELIOT compiles a typed request and a scoped read grant;
the provider returns candidates, coverage, freshness, provider assurance and reason codes;
the provider never receives canonical credentials, task authority, admission or finish authority;
the provider never returns an ELIOT memory disposition;
provider availability is planning information, not permission.
```

A capability descriptor supplies supported recipes, available profiles, visible-scope readiness, observation freshness and degraded reason codes. Coverage claimed by ELIOT is bounded by what the descriptor actually supports; an unavailable provider produces an explicit gap, never a silent narrowing.

## I21.11. Research federation provider

`ELIOT Research` is a separate external cognitive/research system with its own database, acquisition/indexing stack, tools, agents and lifecycle. It is not the Researcher plane or a privileged in-process owner and never shares ELIOT’s canonical database or authority lineage.

The Research endpoint, bridge, protocol and exchange classes are admitted through the normal `RuntimeInstallation`/`HostAdapterManifest`/`CapabilityEvidenceRecord` path. Endpoint reachability or a successful login proves neither source coverage nor permission to disclose a bundle. Each exchange binds the exact Research system/bridge generation, dynamic capability pulse, principal, disclosure policy and retention contract; stale or unqualified evidence blocks only the dependent exchange.

The bridge exposes an ELIOT-owned `ResearchExchangeContract` through a replaceable module/process adapter:

```yaml
ResearchQueryRequest:
  exchange_id_protocol_bridge_and_idempotency:
  requester_principal_authority_and_state_fence:
  question_scope_and_expected_decision:
  source_classes_and_coverage_goal:
  ELIOT evidence/report handles allowed for export:
  privacy_disclosure_retention_and_license:
  budget_deadline_stop_and_progress_contract:
  required result schema_and_citations:

ResearchEvidenceBundle:
  exchange_request_job_system_and_version:
  immutable_bundle_digest_and_origin_authentication:
  source_catalog_snapshots_and_exact_citations:
  claim_counterclaim_and_independence_matrix:
  bounded excerpts_and_artifact_handles:
  coverage_unknowns_and_failed_acquisition:
  synthesis_as_candidate:
  disclosure_and_invalidation:

ResearchExportBundle:
  exchange_id_protocol_and_ELIOT_product_identity:
  large ELIOT report_trace_or_service dossier:
  exact artifact/source handles and redactions:
  purpose_allowed_use_retention_and_return_channel:
  disclosure_decision_and_export_receipt:
```

Dreamer may query Research when local cognitive inheritance lacks external knowledge, and may submit an important large report or service dossier for deeper processing. Returned material enters ELIOT as governed sources, evidence candidates and bounded briefs; it does not become Current Epistemic Position or a procedure automatically. Persistent large documents, corpora, embeddings and document-processing intermediates belong in Research. Main ELIOT BlobStore may retain only bounded operational artifacts/log segments under explicit retention or transfer policy; it is not a long-term research corpus. Main Cognitive Inheritance stores source cards, exact handles, bounded excerpts, decisions, outcomes and the compact knowledge needed for hot work.

A deterministic `CorpusPlacementDecision` prevents accidental corpus growth:

```text
cognitive_hot
  source card, bounded excerpt, claim/decision/failure/procedure needed for current work;

operational_evidence
  immutable artifact/log segment retained for exact proof, replay or transfer;

research_corpus
  source set requiring persistent bulk storage, OCR/parsing, repeated full-text/vector/RAG,
  document-level synthesis or long-horizon research maintenance.
```

The decision is based on purpose, access pattern, processing lifecycle, retention/privacy and expected cognitive use—not one universal byte threshold. A payload placed in Research remains reachable by governed handle and can later yield a compact ELIOT candidate; it is not silently copied back in full.

The federation is asynchronous and durable: jobs expose progress, cancellation, partial results, source coverage and terminal disposition. Research may internally use its own agents/swarms, but ELIOT controls only the admitted external job boundary unless the protocol exposes verifiable descendant lineage. Unobserved internal agents receive no independence credit and cannot create ELIOT authority or proof. Research failure degrades external knowledge only. Direct remote DB access, shared credentials, implicit bidirectional replication and Research-initiated ELIOT writes are forbidden.

When a current task depends on a Research-held source, ELIOT may use only a still-valid bounded excerpt/evidence bundle already admitted under its State Fence. It does not invent the missing content or silently fall back to a stale summary. If the required bundle cannot be fetched or its disclosure/source generation cannot be verified, the dependent inquiry returns `RESEARCH_SOURCE_UNAVAILABLE` or `INCOMPLETE_COVERAGE`, while unrelated local cognitive work continues. Pending exports/imports remain durable exchange jobs and resume by idempotency identity rather than duplicate transfer.

## I21.12. Research debts

An unmet obligation is a typed object, not a caveat at the end of a report.

```text
epistemic       a load-bearing assumption is unverified        blocks a strong claim;
verification    a candidate lacks a sufficient verifier        blocks release;
replication     no independent failure domain                  blocks generalization;
coverage        a material question branch is unclosed         blocks completeness;
contradiction   a conflict is unresolved and unscoped          blocks a unified conclusion;
fidelity        the evaluator poorly represents the target     blocks decision confidence;
provenance      a raw artifact or lineage is missing           blocks audit;
authority       a trade-off was not accepted by its owner      blocks the final decision.
```

Debts are registered in the Problem Registry (I13.9) with owner, review condition and expiry. A release that carries open debts states them; it does not describe them as minor limitations.

## I21.13. Failure, degradation and honest closure

```text
provider unavailable        → declared coverage narrows; dependent inquiry returns a typed gap;
frozen scope unavailable    → no completeness or absence claim; exact-handle work may continue;
evaluator invalid or stale  → confirmatory lane cannot close; exploratory work may continue;
budget exhausted            → checkpoint, partial coverage and next probe are preserved;
contradiction unresolved    → legitimate unresolved state with a named discriminator.
```

An empty answer, an exhausted search, a stopped agent or an approaching budget limit never promote themselves to `ANSWERED_WITH_SUPPORTED_RESULT`. Only that disposition or a properly scoped `NO_MATCH_IN_COMPLETE_SCOPE` may close an inquiry item (I21.9); every other outcome preserves a next probe, a narrower claim or an explicit unknown.

---

# Appendix A. ModuleGeneration lifecycle projection

The normative `ServiceProcessState`, `ModuleGenerationState` and `GenerationCutover` vocabularies live in I14.20. This appendix is a compact rendering/health profile and cannot introduce alternative states.

`ModuleGenerationState` is separate from `ServiceProcessState`: process health answers whether one process is running; generation state answers whether a capability artifact is discovered, staged, active, draining or retired.

## A.1. States

The only normative `ModuleGenerationState` transition set is I14.20. This appendix renders current state and health dimensions; it does not repeat or redefine the machine.

Upgrade is not a `SWITCHING` generation state. It is two generation records plus the separate I14.20 `GenerationCutover` machine and receipt; this prevents process health, artifact lifecycle and route authority from collapsing into one status.

## A.2. Health dimensions

```text
liveness — process responds;
readiness — can accept new work;
freshness — derived state current enough;
compatibility — protocol/contracts match;
integrity — artifact/config/state valid;
capacity — resource budget available.
```

Green “healthy” is not used when one dimension is unknown/degraded.

## A.3. Restart child classes

The canonical restart classes, group strategies, intensity budgets and quarantine rules are defined in I14.10. A Module manifest selects one of those contracts; Appendix A does not create additional restart semantics.

---
# Appendix B. Core EBP service profiles

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_TARGET`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`. The detailed active documentation projection is `docs/generated/ebp-profiles.md`. It is deterministically assembled from the exact pre-extraction appendix snapshot plus an explicit post-integration coverage supplement. It is not evidence that handlers, transport schemas or a runtime catalogue exist.

Owners: I7.1 and the section owning each service boundary. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_B.md`.

Rules that remain normative here:

```text
owning I-sections and an admitted contract catalogue define semantics and authority;
a retained message name is a TARGET vocabulary item, not implemented support;
large streams use immutable Blob handles and bounded summaries;
service output cannot activate its own generation, commit canonical state or create external-effect authority;
unknown or incompatible control variants fail before effects;
process and transport mappings may change without changing semantic ownership;
later-wave capabilities absent from the retained vocabulary are unsupported until explicitly catalogued, never inferred.
```

---

# Appendix C. Default runtime configuration

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_CANDIDATE`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `FORBIDDEN`. The detailed profile is `docs/generated/default-runtime-configuration.md`; the machine candidate is `config/defaults.generated.toml`. Both are deterministically retained planning projections. The TOML contains a mandatory rejection guard and is not an admitted runtime config.

Owners: I2.16, I14.28 and Human policy surfaces. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_C.md`.

Rules that remain normative here:

```text
configuration schema and defaults remain replaceable projections, not Architecture invariants;
effective configuration is immutable, versioned and visible through its snapshot/receipt;
defaults never silently widen authority, privacy, cost, disclosure or external access;
unknown or invalid load-bearing configuration fails to a typed degraded/blocked state;
configuration changes run affected contract, recovery and Product Pulse checks;
measured profiles replace candidate values rather than accumulating prose overrides;
absence of a post-integration feature default means disabled, unqualified or unsupported—not permissive implicit behavior.
```

---

# Appendix D. Reason codes and directive dispositions

> **Projection lifecycle label (artifact-local):** `CURRENT_DOCUMENTATION_PROJECTION`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`. `docs/generated/reason-codes.md` is generated from the exact current I7.20 registry and includes bridge-only migration aliases. The projection proves documentation-set equality, not runtime implementation.

Owner: I7.20. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Historical source: `_REVIEW/baseline_sections/Appendix_D.md`.

Rules that remain normative here:

```text
codes are additive and versioned;
a code is never reused with different meaning;
unknown codes preserve their raw identity and degrade through the stable AgentResponseDisposition;
an unresolved unknown code opens a Problem rather than inventing a lifecycle state;
a directive names the code, preserved state and next admissible action;
legacy aliases are translated only at a bridge boundary and never become canonical names.
```

---

# Appendix E. First convergence backlog

Canonical delivery order is I17.2–I17.13; migration order is I19.5. This appendix intentionally does not duplicate them.

At task creation `eliot dev plan convergence` projects the current backlog from:

```text
CURRENT_SYSTEM_AUDIT;
D0/D1 missing capabilities;
route/host conformance evidence;
active migration state;
Architecture/Implementation conformance gaps;
observed failures and resource limits.
```

Generated items use ordinary WorkItem IDs, owners, evidence, verifier and stop conditions. No separate F/K/C phase state is persisted.

# Appendix G. Research Gate families

This appendix defines the small family vocabulary used by generated `ResearchGateRecord`s. It is not an always-active question bank. Historical detailed questions and legacy `RG-01…RG-67` aliases are retained in the external cold backlog.

```yaml
ResearchGateRecord:
  gate_id_and_family:
  owner_and_affected_decision:
  status: INACTIVE | ACTIVE | BLOCKING | RESOLVED | REJECTED | STALE
  activation_condition_and_current_gap:
  exact_artifact_experiment_or_reproduction_required:
  discriminator_or_decision_boundary:
  budget_time_expiry_and_stop_condition:
  support_and_invalidation_refs:
  decision_unblocked_narrowed_or_rejected_by_result:
```

Only `ACTIVE` and `BLOCKING` gates are shown to the current agent or may block the dependent promotion. `INACTIVE` backlog material creates no obligation.

| Family | Scope |
|---|---|
| `RGF-STORAGE-MIGRATION` | canonical store, engine choice, export, restore and replacement |
| `RGF-RUNTIME-RESILIENCE` | supervision, process identity, cutover, restart, resources and recovery |
| `RGF-PROTOCOL-TRANSPORT` | EBP/MCP/IPC encoding, ordering, reconnect and compatibility |
| `RGF-CONTEXT-MEMORY` | context recipes, retrieval, memory lifecycle, episodes and causal influence |
| `RGF-AGENT-ROUTES` | Codex/OpenCode/Claude/ACP/local-model/translation route competence |
| `RGF-SWARM-ORCHESTRATION` | decomposition, fan-out, independence, synthesis and coordinator recovery |
| `RGF-INSTRUMENT-TESTING` | ProcessExecutor, testd, verifiers, simulation, selection and proof validity |
| `RGF-CRATE-BUILD` | workspace topology, build/cache economics, context and split/merge evidence |
| `RGF-COMPONENT-SANDBOX` | WASM/native contours, build isolation, promotion and rollback |
| `RGF-SECURITY-AUTHORITY` | disclosure, grants, resources, references, secrets and adversarial tests |
| `RGF-CODE-RESEARCH` | code/build/verifier graphs, external corpora, Researcher and donor pilots |
| `RGF-HUMAN-PRODUCT` | usability, attention, economics, product evaluation and delayed outcomes |
| `RGF-PLATFORM-DISTRIBUTION` | Windows packaging, future Linux/multi-device/distribution boundaries |

A family is not a single giant gate. Activation compiles one narrow question for one decision, owner, budget and expiry. Exact old questions remain evidence lineage, not a permanent roadmap.

# Appendix H. Full Architecture conformance map

> **Status: TARGET/CONFORMANCE MAP.** Every row requires current source handles, an observable discriminator, evidence artifact and negative case before support can be `CURRENT_VERIFIED`.

This table is the human-readable normative mapping. `docs/conformance.toml` is its deterministic machine-readable documentation projection generated from the same M1/M2 rows; it is not runtime/source conformance evidence.

| Architecture ID | Primary implementation sections / owner | Observable proof family |
|---|---|---|
| `ARCH-INTENT-01` | I0.4–I0.6; `ImplementationDeviation` | deviation outcome and review receipt |
| `ARCH-CONCIL-01` | I13.2–I13.4; Agent Coordinator | conflict scenario preserves dissent and tests rivals |
| `ARCH-DEV-01` | I17–I18 | D1 real-task demonstration; affected test plan |
| `ARCH-CORE-00` | I7.25, I10.15, I12.24, I12.34, I16.23 | consequential attempt yields an explicit learning delta or justified no-change disposition; next compatible attempt activation/adherence/decision delta is observable |
| `ARCH-CORE-01` | I7, I12; state/context owners | cold/resume task continuity scenario |
| `ARCH-CORE-02` | I1, I2, I12, I16 | four-plane process/state trace forms one loop |
| `ARCH-HELP-01` | I3, I7, I11, I12 | user/agent effort and reconstruction comparison |
| `ARCH-ROLE-01` | I1, I5, I8, I9, I15 | no component combines observation, decision, authority and proof silently |
| `ARCH-ROLE-02` | I6, I8–I11, I10.22 | role/capability/evaluator separation, failure scenarios and explicit owners |
| `ARCH-AUTH-01` | Kernel, I5.5–I5.7, I6.3, I6.15 | stale/missing epoch, grant-lineage narrowing/revocation and introduction-scope denial tests |
| `ARCH-MOD-01` | I1, I2, I14.14–I14.16 | optional module crash while Kernel remains healthy |
| `ARCH-MOD-02` | I2, I14.27, I17–I20 | independently understandable/testable micro-modules, portable blueprints and add/replace without Kernel/state rewrite; size and physical form remain empirical |
| `ARCH-MOD-03` | I2.20, I2.23, I6.4, I18.7 | generated cell registry; independently invokable cell proof; single-owner-per-mutable-state and replacement-boundary negative tests |
| `ARCH-PORT-01` | I2 execution contours, I7 EBP, I10 bridges, I20 | swap provider/tool/store/sandbox contour through the same capability, conformance and migration contracts |
| `ARCH-SCOPE-01` | I4, I12 | wrong-scope reuse rejection/revalidation |
| `ARCH-MEM-01` | I12.2–I12.3 | natural observation accepted as candidate |
| `ARCH-MEM-02` | I5 events, I12.5, I12.20–I12.21, I12.37 | correction/revocation without history loss; episode source availability is separate; delivery/use/outcome influence remains observable |
| `ARCH-LIFE-01` | I5.4–I5.6, I12.3–I12.5 | no model summary directly creates verified/policy state |
| `ARCH-MEM-03` | I9.7, I12.20, I12.25–I12.26 | transformation preserves evidence/lineage; derived state cannot replace or outlive revoked sources |
| `ARCH-MEM-04` | I5.25, I12.5, I12.21 | cache/retrieval/repetition does not increase support and invalidation removes current influence |
| `ARCH-EPI-01` | I12.12 | fresh outlier/conflict and revalidation scenario |
| `ARCH-EPI-02` | I12.18, I12.22, I12.29, I18.47 | theory weight changes through discriminative outcomes, calibrated evidence, evaluator integrity and staleness |
| `ARCH-EPI-03` | I7.27, I12.34, I18.4, I21.2–I21.4, I21.8 | exploratory-origin evidence cannot self-confirm; independent/held-out/preregistered proof is required for promotion |
| `ARCH-EPI-04` | I7.23, I12.13, I21.6, I21.8, I21.13 | coverage/absence is rejected without a frozen recheckable denominator; top-k and budget exhaustion are not completeness |
| `ARCH-UND-01` | I12.1, I12.10–I12.13 | decision reconstructed from public evidence/model/unknowns |
| `ARCH-GROUND-01` | I10.8–I10.10, I10.20–I10.22, I12.9–I12.10, I12.35–I12.37 | exact source/build/test/verifier, professional, multimodal, artifact and episode anchors with explicit coverage/ambiguity |
| `ARCH-UND-02` | I12.18 | discriminative prediction matched to outcome |
| `ARCH-SELF-01` | I4.8, I12.1, I17 | ELIOT change packet contains Architecture and conformance gaps |
| `ARCH-CTX-01` | I7.24–I7.26, I12.13–I12.16 | tool/context surface retains decision-changing distinctions under budget and material omission remains reversible |
| `ARCH-CTX-04` | I12.13, I12.26 | retrieval proposes; admission/suppression is separately traced and reversible |
| `ARCH-CTX-02` | I7.10, I12.6–I12.8 | file/error/task event proactively delivers memory |
| `ARCH-CTX-03` | I7.11, I12.13–I12.18 | route/profile position and decision-local tail tests |
| `ARCH-ATTN-01` | I13.7–I13.8, I11.5 | delivered/acknowledged item remains blocking until disposition |
| `ARCH-SKL-01` | I7.12–I7.13 | skill brevity, ambiguity and cross-route scenario tests |
| `ARCH-WDG-01` | I1, I8 | Watchdog sees daemon failure via independent route |
| `ARCH-WDG-02` | I8.4–I8.8 | missing hooks/bypass/injection becomes evidence-backed signal |
| `ARCH-DRM-01` | I9.1–I9.7 | Dreamer result remains candidate; no direct write |
| `ARCH-DRM-04` | I21, I10 | acquisition/synthesis/governance process separation |
| `ARCH-DRM-02` | I9.3–I9.7 | orientation/research output preserves rivals and unknowns |
| `ARCH-DRM-03` | I3.6, I9.8–I9.10 | denied over-budget/unapproved model or swarm launch |
| `ARCH-ACT-01` | I6.3, I6.6 | deterministic impact classification and authority gate |
| `ARCH-SWM-01` | I10.15, I17, I18.11, I18.49 | bounded context-minimal staged work units, durable evidence/disclosure lineage, exact introduction sets and no shared-chat/vote-as-proof control plane |
| `ARCH-SWM-02` | I10.15, I14.6, I18.11 | agent/controller loss and idempotent reassignment |
| `ARCH-LONG-01` | I10.15, I14.6 | restart/resume long job from checkpoint and durable graph |
| `ARCH-FIN-01` | I7.9, I6.7, I14.7 | exact eight outcomes; only proof yields VERIFIED_COMPLETE |
| `ARCH-HUM-01` | I3, I11 | Human can observe/intervene without per-action micromanagement |
| `ARCH-SEC-01` | I8, I15, I15.18 | injected/compromised component and over-broad disclosure/capability surface are contained, revocable and recoverable |
| `ARCH-SEC-02` | I5, I15.8 | direct DB path absent/detected; one canonical receipt path |
| `ARCH-SEC-03` | I5.26, I12.20, I15.5–I15.7, I15.18 | backward influence and disclosure revocation, declassification evidence and clean restore |
| `ARCH-SEC-04` | I9, I12.3, I15.6 | model output cannot promote itself |
| `ARCH-PRIV-01` | I5.14, I5.26, I15.14, I15.18 | purge/disclosure closure across projections, ORS, backup, provider and model routes without resurrection |
| `ARCH-RES-01` | I1, I13, I14 | local process/module failure preserves independent work |
| `ARCH-RES-02` | I8.12, I13.9–I13.11, I14.14 | bounded repair attempts then quarantine/escalation |
| `ARCH-RES-03` | I5.13, I12.20, I15.14 | restore issues new epochs and respects purge/revocation |
| `ARCH-ORD-01` | I5.7, I14.8 | independent scopes concurrent; conflicting scopes ordered |
| `ARCH-OBS-01` | I16, I18.47 | separate production evidence, measurement, audit, reports and evaluator integrity |
| `ARCH-RES-04` | I7.10, I14.4–I14.12 | degraded capability visible and only dependent effect blocked |
| `ARCH-RES-05` | I13.9–I13.11, I14.25, I12.24 | recovery outcome produces evidence-backed failure/repair/improvement candidate |
| `ARCH-LEARN-01` | I12.18–I12.24, I12.30 | grounded outcome changes external epistemic/procedural/meta inheritance through governed candidates |
| `ARCH-LEARN-02` | I7.25, I10.15, I12.24, I12.34, I16.23, I20.8 | task-local overlay remains bounded and reversible; broader influence requires activation/outcome, retention/transfer where claimed, evaluator validity, Product Pulse, authority and rollback proof |
| `ARCH-META-01` | I12.21, I12.24, I17, I18.12, I18.47 | improvement remains outcome-linked, isolated, advisory/experimental, evaluator-scoped, replayed, canaried and rollbackable; active generation does not rewrite itself |
| `ARCH-ECON-01` | I3.6, I9.8–I9.10, I14.4 | budget denial/checkpoint and disclosed route/cost |
| `ARCH-DEV-02` | I17, I18, I20 | capability depth added through independently testable modules, affected-edge proofs and Product Pulses while core intent/contracts remain |

---

# Appendix I. Dependency selection and containment

| Need | Current candidate | Where contained | Adoption status |
|---|---|---|---|
| async/process I/O | Tokio | runtime/platform facades | required baseline |
| CPU-bound pool | Rayon behind `eliot-cpu` | runtime facade only | candidate DEFAULT after bounded cancellation/memory tests |
| supervised actor tree | plain Tokio baseline; ractor candidate | daemon-only runtime facade | Research Gate RGF-RUNTIME-RESILIENCE |
| MCP | official Rust SDK (`rmcp`) | `eliot-mcp` | primary bridge |
| optional binary EBP encoding | prost | `eliot-protocol` | RGF-PROTOCOL-TRANSPORT candidate; JSON-first remains D0/D1 default |
| host state journal | redb | `eliot-platform` / HostStateStore | primary installation/process lineage store |
| operational recovery DB | redb | `eliot-ors` | primary ORS |
| canonical DB | SurrealDB SDK | separate store bridge process | provisional primary |
| Windows-native UI | WinUI 3 on Windows App SDK stable line; thin C# client | `eliot-ui` user-session adapter | primary Human surface; Rust control plane unchanged |
| filesystem watch | notify | platform/scope bridge | hint source, not truth |
| serialization/schema | serde, serde_json, schemars | foundation contracts and EBP JSON codec | internal/wire schemas; public types remain ELIOT-owned |
| sortable identities | uuid v7 | `eliot-types` ID facade | default; wire format is ELIOT newtype, not crate type |
| path/write-set policy | globset | policy/path facade | default for compiled path sets; canonicalization remains ELIOT-owned |
| HTTP middleware | tower | HTTP/MCP/UI transport facade | default for timeout, concurrency and load-shed layers |
| config hot snapshots | arc-swap | config service | default |
| hashes/content IDs | BLAKE3 | artifact/blob/audit facades | default |
| compression | zstd | blob/export facade | default |
| tracing | tracing + tracing-subscriber; tracing-appender candidate | observability facade | default spans; async file appender contained and replaceable |
| short synchronous locks | std locks first; parking_lot candidate | runtime facade only | adopt only after profiling; never across await/external calls |
| Windows service/API | official windows-rs service/platform crates | platform-windows | primary Windows layer |
| Cargo graph parsing | `cargo_metadata` | Instrument Plane Cargo profile | default structured package/resolve graph |
| test inventory metadata | `nextest-metadata` | Instrument Plane test profile | candidate parser for discovered test inventory |
| test runner | cargo-nextest | dev tooling / Instrument Plane | default affected runner |
| property tests | proptest | dev dependency in contract crates | default for normalization/state/idempotency |
| concurrency model checks | loom | Kernel/write/lease test backend only | targeted load-bearing tests |
| fuzzing | cargo-fuzz/libFuzzer | protocol/parser/import targets | release/security jobs |
| Rust semantic index | pinned rust-analyzer + SCIP Rust bindings | Instrument Plane architecture profile | one-shot candidate profile after RGF-CODE-RESEARCH |
| compiler JSON | Cargo/rustc/Clippy JSON streams | Instrument Plane compiler profile | authoritative parser path |
| code text search | ripgrep JSON | Instrument Plane exact-search profile | exact lexical evidence only |
| snapshots | insta | UI/rendered packets/reports only | scoped, reviewed snapshots |
| benchmarks | criterion | hot-path/store/module benches | empirical profile input |
| fault points | ELIOT `FaultPoint` facade; `fail` crate candidate | dev/fault builds only | experiment behind facade |
| metrics facade | `metrics` + bounded exporter | observability facade | candidate; no domain dependency |
| process inventory hints | `sysinfo` behind Watchdog sensor facade | Watchdog only | advisory; Windows APIs remain authority source |
| Windows service helper | `windows-service` plus `windows-rs` | platform-windows | candidate behind facade |
| optional web compatibility view | axum + Askama | separate UI adapter only | non-primary fallback/experiment; no additional authority |
| terminal dashboard | Ratatui + Crossterm | optional `eliot dashboard` | lightweight projection only; no second state owner |
| WASM components | Wasmtime Component Model | optional module runtime | experiment RGF-COMPONENT-SANDBOX |

Rules:

```text
exact versions pinned in lock/compatibility registry;
license policy or an explicit contained exception is verified before promotion;
third-party public types do not cross ELIOT facade;
removal/replacement test exists for load-bearing dependency;
Kernel dependency set remains minimal.
```

---

# Appendix J. Developer commands

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_TARGET`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`. The detailed candidate catalogue is `docs/generated/developer-commands.md`, assembled from the exact pre-extraction snapshot plus a post-integration support note. It is not compiled help and cannot make a command supported.

Owners: I10.8 and the owning capability contract of each command. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_J.md`.

Rules that remain normative here:

```text
one admitted command catalogue defines supported CLI surfaces;
a command uses the same Kernel/Governor/Instrument contracts as every other front door;
help/schema output and execution receipts identify the exact supported revision;
expiring migration shims cannot define different semantics or authority;
missing command support returns a typed unsupported state rather than a prose promise;
no later-wave capability receives a CLI command merely because the capability is documented.
```

---

# Appendix K. Legacy and target contract inventory pointer

> **Status:** non-authoritative pointer. The former manual inventory has been preserved in a content-addressed cold evidence artifact and removed from the normative book; its extraction lineage records the one de-duplication change relative to the frozen 0.22 base. It was useful for donor retirement and migration vocabulary, but its continued inline presence created a second schema-like surface, prompt cost and a hidden implementation backlog.

Current rules:

```text
owning I-section
  → meaning, owner, behavior and failure semantics;

accepted generated ContractCatalogueEntry / IDL
  → field-level executable contract;

physical schema and Rust interface projections
  → Appendices N/P, TARGET until exact code/tests prove support;

cold legacy/target inventory
  → historical discovery only, loaded by exact handle for migration or archaeology;
  → never part of normal agent hotset, conformance proof or work-item generation.
```

A contract absent from the accepted catalogue remains `TARGET` or `CURRENT_UNVERIFIED` even if an old YAML example exists. Donor name-level dispositions remain in the content-addressed retirement ledger; active behavior is always resolved through the current owner.

# Appendix L. Donor retirement evidence pointer

Detailed heading-, mechanism-, object- and compatibility-level disposition is intentionally outside the normative Implementation in the content-addressed donor/evidence ledger identified by the current normative-pair receipt.

The ledger preserves exact source digests, full inventory and semantic dispositions. A filename or heading match is not enough: active preservation requires owner, behavior, failure behavior and proof. Active behavior lives only in the accepted Architecture, this Implementation and generated accepted contracts; I19.15 independently governs repository/runtime cutover.

# Appendix M. Legacy compatibility evidence pointer

Detailed legacy object and alias disposition is maintained in the same non-normative donor audit. Runtime compatibility remains governed by generated contracts, bridge aliases, migration receipts and exact conformance evidence; a historical name never creates a second active semantic contract.

# Appendix N. First SurrealDB physical schema profile

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_PHYSICAL_PROFILE`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`; the companion `store/schema.generated.sql` policy is `MUST_NOT_APPLY`. The detailed active documentation profile is `docs/generated/surrealdb-physical-schema-profile.md`, including post-integration logical-to-physical ownership mapping. `store/schema.generated.sql` is an intentional rejection sentinel until a real migration/catalogue generator emits executable schema with checksums and proof.

Owners: I5.4–I5.7, I5.17 and the migration role. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_N.md`.

Rules that remain normative here:

```text
only the migration role changes physical schema and only the store bridge holds credentials;
stable fields use generated constraints; flexible payloads require versioned codecs and round-trip/property proof;
large bodies remain in Blob Store and projections/indexes remain explicitly rebuildable;
runtime access uses named parameterized operations produced from PreparedTransition;
no agent-visible operation names a table or field;
additive migration precedes backfill and destructive retirement;
backfill is a checkpointed Durable Job with shadow compatibility and rollback evidence;
old representation retires only after no active or rollback generation requires it;
ECXF export and canonical record identity remain independent of table layout;
the sentinel file must never be applied as DDL.
```

---

# Appendix O. Initial empirical profiles and candidate defaults

> **Status: UNVALIDATED CANDIDATE PROFILES.** Every number requires an EmpiricalParameter record, local experiment, uncertainty and expiry before it affects production admission.

These numbers are starting profiles and benchmark fixtures. They are not Architecture guarantees. Each remains visible, versioned and replaceable through the stated Research Gate.

## O.1. Warm local performance targets

| Operation | Initial p95 target | Disposition |
|---|---:|---|
| stdio/bridge → Kernel IPC round trip | 5 ms | local transport benchmark |
| cached pre-action policy/context decision | 50 ms | hot-path profile |
| current state Q1 | 50 ms | named-read/cache profile |
| exact cue/Q0 lookup | 75 ms | cue-index profile |
| small Q2 evidence fetch | 150 ms | store/read profile |
| warm packet compile | 300 ms | context profile |
| small durable canonical write | 250 ms | store/ORS profile |
| warm task bootstrap | 150 ms | agent integration profile |
| exact CodeCortex report | 1.5 s | adapter profile; deeper work is async |

Failure to meet a target produces a measured profile/degradation or an Improvement Candidate; it does not justify dropping correctness, receipts or provenance. Tail latency under contention and time-to-safe-recovery are recorded separately.

`warm packet compile` is attributed, not permanently partitioned, across exact/optional retrieval, admission/ranking, render/omission, lint/scorecard/tokenization and receipt persistence. Stage budgets are learned EmpiricalParameters; no fixed split becomes a hidden law before measurement. Telemetry overhead is reported as its own stage and participates in the same capacity/kill-condition review. These targets remain `UNVALIDATED` on the current Product Identity until the production projection/read/write paths, p95/p99 under contention and restart/recovery semantics pass the same CapacityEnvelope.

## O.2. Smart hot-path starting profile

```text
CodeCortex initial exact roots: target <= 12;
graph expansion depth: <= 2; report target <= 80 nodes / 160 edges;
full graph payload is never placed in the Active View; deeper exploration is a Durable Job with handles;
cue bindings per captured candidate: target <= 12; excess is a curation smell, not silent loss;
direct firing result: <= 8 items + overflow handle;
negative memory/invariants first;
activation: depth <= 2, fan-out <= 20, max-accumulate, threshold 0.35;
global activation decay: 0.5 after the first hop;
first-hop example weights: card/capsule 0.9, concept implementation 0.8,
  co-change 0.7 × confidence, concept dependency 0.6, static call/dependency 0.5,
  support/verification 0.4;
activation output is advisory unless an exact deterministic rule separately blocks.
```

All weights/thresholds belong to RGF-CONTEXT-MEMORY and are disabled or changed when usefulness/latency/false-activation evidence is poor. No graph-edge count or activation threshold gates exact direct cue delivery.

## O.3. Behavioral graph starting profile

```text
full onboarding window: last 24 months or 5,000 commits, whichever is smaller;
exclude generated/vendor paths by WorkScope Profile;
retain co-change pair when support >= 3 and max directional confidence >= 0.5;
flag hidden coupling when no static edge exists;
churn exponential half-life: 90 days;
fix classifier: deterministic project-configurable commit-message rules;
full mining is onboarding/background work, never a request hot path.
```

These are D3 defaults and must be reprofiled for repositories with unusual history or monorepo structure. They are not graph-value or completeness laws; graph utility is measured against exact/no-graph baselines.

## O.4. Concept Pyramid starting profile

```text
Project Charter target: 200 approximate tokens;
System Map: 600;
Subsystem Capsule: 500;
Module/Workflow Card: 200;
Dreamer-written PURPOSE + BOUNDARIES in one capsule: target <= 120;
all entrypoints/invariants/dangers/decisions/verifiers filled mechanically where possible;
all load-bearing prose cites handles;
dirty projection is visibly stale and rebuilt asynchronously.
```

These are layout defaults, not a reason to omit a distinction that changes action or verification.

## O.5. Reactive delivery starting profile

```text
Session boot target: 1,200 approximate tokens;
PreTool/reactive target: 700 tokens and 8 items for fully event-integrated hosts;
compact tool-only piggyback target: 400 tokens and 3 items;
negative-memory payload cap: 3 exact matches;
hook additional context hard cap: 8 KiB;
repeat delivery suppressed per Session unless invalidated;
critical obligations remain sticky regardless of normal dedup.
```

Host-specific safe operating envelopes override these targets without weakening visible omission/handle paths.

## O.6. Context economy and metacognition starting profile

Historical rollout method retained as an experiment:

```text
compare treatment with memory-free/control tasks inside one task family and route;
measure delivered context against orientation/exploration it replaces;
after a qualified comparison with enough effective samples for its declared uncertainty plan,
  positive net cost may downgrade noncritical payload delivery to handles-only
  and open an Improvement Candidate;
critical information is exempt from token-negativity when it prevents material risk.
```

Savings are reported per model/route/task family as full amortized cost per verified resolution, including read/write/output/cache/storage/retrieval/recovery/Human/wall-clock costs and raw provider token semantics. A single input-token number is not a context-economy claim.

Initial derived coverage heuristics may use:

```text
covered: fresh capsule plus sufficient claims/decisions/episodes;
thin: stale capsule or sparse history;
blind: no applicable capsule/model;
danger: high hotspot/failure density under a versioned profile;
novelty: material share of touched entities lacks evidence/history.
```

Exact thresholds are Empirical Profiles, never universal truth or direct blockers without a separate deterministic rule.

## O.7. Understanding evaluation starting profile

A scheduled/on-demand exam may sample active/stale subsystems and ask exact questions about:

```text
entrypoints and flows;
invariants;
blast radius and mapped verifiers;
rival explanations and expected observations.
```

Ground truth comes from exact graph/verifier/artifact handles where available. Causal/counterfactual action probes and prediction-before-observation are primary; exact-question exams remain diagnostic. Model answer grading cannot mutate epistemic status, policy or completion. Low scores create dirty projections, probes or Improvement Candidates, not automatic doctrine.

## O.8. Agent Execution Fabric starting profile

```text
first production route: one Codex App Server stdio attempt path;
second route only after crash/cancel/reconcile proof;
initial fanout: one lane;
default writers per deliverable: one;
first read-only expansion: one additional lane;
default high-assurance recipe: one writer + one blind independent auditor;
recursive native delegation: disabled unless subtree lease grants it;
mid-attempt silent route failover: forbidden;
capacity exhaustion: DEFERRED_CAPACITY, not failed/running;
route capability evidence expires on fingerprint change;
worktree alone is insufficient for mutable integration lanes.
```

These are DEFAULTS to validate, not Architecture invariants. Task-class outcomes and capacity evidence may change them through the Meta/canary path.

## O.9. Read, payload and maintenance defaults preserved

```text
interactive DB reads: 32; background reads: 4;
inline evidence/blob threshold: 32 KiB;
mailbox inline payload target: 8 KiB;
packet cache: 256 items / 64 MiB;
stable-scope retry: once before visible churn response;
log rotation: 100 MiB; normal retention 14 days; error retention 30 days;
lease sweep: 30 seconds; default Session expiry after inactivity: 10 minutes.
```

These defaults must be changed by profile evidence, not copied mechanically into every machine or workload.

## O.10. Instrument Plane and test-selection starting profile

```text
canonical external process path: one Windows ProcessExecutor;
canonical verification path: one InstrumentRunner;
initial fast profile: identity/preflight → affected selection → Clippy JSON
                      → selected nextest/JUnit → rustfmt observation;
test inventory: nextest discovery + ELIOT policy overlay;
Rust structural base: Git + full Cargo metadata;
Rust semantic backend: one-shot rust-analyzer/SCIP after its golden suite;
heuristic code graph: optional, isolated and never authoritative;
raw output: streamed to governed evidence storage, not buffered as prompt text;
negative code-intelligence answer: UNKNOWN unless freshness, coverage and
                                   absence-proof contract are complete;
normal change proof: micro-module proof + affected-edge proof;
full workspace/release proof: only when ChangeImpactPlan or release policy requires it;
target layout: isolated by workspace, worktree and build class under the ELIOT data root.
```

These are initial implementation defaults. Measurements may merge build classes, admit a live semantic index or change profile composition, but may not create a second process runner, second verification authority or unqualified negative evidence.

---


## O.11. Crate and agent-context profile ownership

Numeric context/source profiles have one owner: I2.16 and its `EmpiricalParameter` / `SerializedContextMeasurement` records. This appendix does not duplicate token, STU or crate-size bands.

There is no target number of crates, support crates or edge count per work item. `WorkspaceScaleProfile` and `EffectiveMicroModuleManifest` measure the actual dependency/build/context/proof closure. The planner assigns one primary FunctionalCapabilityCell plus the bounded support closure required for Decision Safety Floor, one-hop effects, verifier and Product Pulse.

Generated/vendor bodies and large fixtures stay behind exact handles; public contracts and selected evidence remain in the measured workset. Cargo timings, reverse fan-out, agent outcome, false-negative edge selection and Product Pulse determine split/merge decisions.

## O.12. Component, testd and simulation starting profile

These are Empirical starting profiles, not Architecture thresholds.

```text
component guest target:
  `wasm32-wasip2`;

WASM runtime candidate:
  Wasmtime 47.x line, exact patch pinned only after RGF-COMPONENT-SANDBOX and the current security/compatibility receipt;

developer-loop profiles:
  edit-fast = format/static/package shape;
  module-fast = affected package/cell proof;
  module-full = complete public-contract proof;
  component = build + interface + conformance;
  pre-merge = affected workspace/property/simulation subset;

Each lane records measured p50/p95/tail, executed-test count, cache/build identity and proof ceiling on the current machine. Interactive qualification is empirical; a slow correct proof becomes a Durable Job or prompts decomposition/optimization, not an automatic Module failure.

background/deep:
  affected pre-merge, deterministic simulation, Loom/Shuttle,
  Miri/fuzz/mutation/coverage/soak according to impact;

component promotion:
  conformance → deterministic replay → shadow → bounded canary → cutover;

simulation:
  every failure stores a seed and FailureCapsule;

repair-loop default:
  two consecutive attempts with the same normalized signature or root invariant
  stop autonomous patching and trigger Mechanism Review/Concilium;

load:
  build/test/simulation pools cannot consume Kernel Control Reserve.
```

Cached time and divergence targets are measured per machine/module and live in profiles, not hard-coded into the Architecture or global test gate.

# Appendix P. Rust public boundary interfaces

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_CANDIDATE_MAPPING`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`. `docs/generated/rust-boundary-interfaces.md` preserves the detailed pre-extraction candidate mappings, including stable section P.12, plus a post-integration coverage-gap supplement. Candidate Rust syntax is not a normative signature, generated source or implementation proof.

Owners: the I-section owning each boundary and a future admitted `eliot-contracts` catalogue for normalized serialization. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_P.md`.

Rules that remain normative here:

```text
public types carry explicit contract/schema versions and validated newtype identities;
major incompatibility fails before effects; additive minor compatibility is declared explicitly;
authority, scope, effect, privacy, ordering and receipt fields are never silently defaulted;
closed control variants fail when unknown; additive reason/telemetry values preserve Unknown(raw);
canonical hashes use normalized versioned serialization;
public signatures do not leak vendor/upstream types;
in-process and process-boundary implementations must produce equivalent receipts and failures;
no boundary may read implicit global mutable current principal, scope or task state;
later-wave interfaces remain uncovered TARGET gaps until generated from an admitted catalogue and proven against source.
```

---

# Document status

`ELIOT_IMPLEMENTATION.md 0.29-draft` is the current target implementation contract paired with Architecture 4.5-draft.

Current support status:

```text
Architecture meaning:
  current design authority;

Implementation contracts:
  TARGET unless exact current evidence says otherwise;

local current source:
  UNKNOWN until CurrentSystemEvidenceSnapshot;

installed runtime and live store:
  UNKNOWN;

product:
  NOT_ACCEPTED / UNVERIFIED.
```

The document preserves the active decisions needed for:

```text
micro-modular crate-rich/process-sparse development;
component/native/static execution contours;
Erlang-like supervised generations;
one canonical state/authority/effect path;
bounded agent-swarm pipelines;
real Instrument/ProcessExecutor evidence;
context, memory, Dreamer, Watchdog and Meta contracts;
exact WorkScope/cold-start readiness, agent feedback and self-observation;
activity-scoped Watchdog wake/drain, closed maintenance assessment and no-lost-child reconciliation;
Windows-native Human control, external-agent launch and ELIOT Research federation;
recovery, migration and product evaluation.
```

It does not preserve chronological audit prose. Donor inventories, audit traces, compatibility receipts, package manifests and exact source identities are external content-addressed evidence. They cannot override this contract and become stale whenever the bytes they audit change.

Active work is not limited to a single serial campaign. Independent module, research, test and no-authority prototype work may proceed in parallel. Promotion into affected production owners remains blocked until the relevant Hard Boundary, verifier and Product Proof obligations are satisfied.

This file is a reference book, not an agent prompt. An agent receives only the Product Objective, applicable Architecture/Implementation handles, EffectiveMicroModuleManifest, ModuleContractKit, CrateContextCapsule, ModuleTestCapsule, active directives and current evidence.
