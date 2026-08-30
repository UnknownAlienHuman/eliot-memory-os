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

