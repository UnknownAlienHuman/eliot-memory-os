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

