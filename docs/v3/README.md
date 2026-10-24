# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-24 · normative design, not implemented code.**

V1 and V2 are donors. V3 is a greenfield implementation.

## Reading order

1. [Architecture](ARCHITECTURE.md) — purpose, ownership, Base, extensions and non-goals.
2. [Implementation](IMPLEMENTATION.md) — runtime, modules, data, narrow external contracts and implementation order.
3. [Cognition](COGNITION.md) — current-work reconstruction, retrieval, learning, consolidation and self-improvement algorithms.
4. [One-shot inference contract](INFERENCE-CONTRACT.md) — sole Memory↔controller boundary for connections, profiles, disclosure, controlled payloads, readback and all cleanup dispositions.
5. [Active analysis registry](ANALYSIS-REGISTRY.md) — what was checked, exact gaps and the next work queue.
6. [Audit conclusion](AUDIT.md) — evidence, root causes, rejected mechanisms and source limits.
7. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements, audits and donors.

Architecture, Implementation and Cognition describe one product at increasing depth. `INFERENCE-CONTRACT.md` is the narrow cross-repository contract for one selected external boundary; it is not another architecture or workflow layer. The complete target is not a prerequisite for running Base. None of these documents is implemented product code.

`ANALYSIS-REGISTRY.md` is the only active analysis ledger. `AUDIT-MAP.md` is the stable source/decision matrix; new work updates the registry rather than creating another chronological report.

## Selected construction

One local Rust package/codebase, one demand-start supervisor/daemon family, one SurrealDB child and one private Store. Domain/pure logic, application operations, external adapters and host surfaces keep explicit dependency direction without requiring a process, actor, contract crate or pass-through service per concept.

Base captures real host/source events, preserves explicit knowledge/corrections/commitments, supplies exact/lexical context and reopens exact sources after restart. Its maintenance covers the data it actually retains. Base starts without controller, model, encoder, converter or Research credentials.

Learning, vectors, project understanding, documents, Research and additional hosts are independent vertical extensions. They reuse the same records, finite jobs, revision publication, context assembly and maintenance path. A missing extension does not disable Base; disabling a producer does not erase retained readable knowledge. There is no second Lite database or Full memory engine.

## Why V2 stalled and what V3 forbids

The preserved goals were not the main problem. Continuity, correction, provenance, negative memory, project understanding, Dreamer, privacy, recovery and operator control remain useful. The failure came from turning each principle into its own owner, registry, receipt, lifecycle and proof ceremony, then rewarding production of those artifacts instead of integration.

Repository delivery postmortems add a second causal layer: cheap deterministic blockers were checked after expensive preparation; overlapping branches and PRs lacked one queue owner; new sibling work started without backpressure; and documentation/conformance output displaced connected product paths. V3 therefore uses these constraints:

- one live analysis ledger, not another task catalogue, gate, mission database or report database;
- one semantic owner and one current branch/PR disposition for overlapping work;
- cheap admission and configuration failures before expensive build, download or agent dispatch;
- completion only for a real caller → owning operation → durable result or typed unknown → actual consumer → restart/readback path;
- deletion or replacement of superseded authority instead of append-only clarification;
- product code and a connected vertical slice before generalized workflow, plugin, policy or proof infrastructure;
- merged product behavior and closed blockers as progress, not prose, LOC, commits, agents, issues or PRs.

These rules constrain implementation and documentation. A new process artifact is justified only when a concrete product field cannot be represented by the existing owner and the new mechanism replaces or materially simplifies something already present.

## Preserved goals, minimal mechanisms

The old Architecture often stated the right intent: preserve sources, separate observation from interpretation, keep authority explicit, degrade locally, challenge false rules and prefer the simplest reversible mechanism. The later Implementation made many replaceable defaults globally mandatory. V3 keeps the intent and removes machinery that is not needed by a connected product path.

| Preserved goal | V3 minimum | Not carried forward by default |
|---|---|---|
| Resume interrupted work | Stable project/workspace/task address, retained observations and direct reconstruction | Universal Understanding State, route-continuation registry or mandatory checkpoint protocol |
| Preserve source and provenance | Observation + immutable blob/range + exact source/revision handles | Separate EvidenceAtom, Truth Registry, evidence promotion service or receipt for every read |
| Correct memory without rewriting history | One versioned memory item, revision history, grounds and current applicability | Global truth score, promotion ladder or dedicated correction subsystem |
| Prevent repeated mistakes | Scoped negative memory or method revision returned by normal retrieval | FailureFingerprint platform, universal quarantine state or mandatory experiment campaign |
| Deliver useful context | Exact/current-work lookup, lexical candidates, optional vector arm and bounded packet over actual revisions | Separate Context Compiler service, packet database or acknowledgement ceremony |
| Learn from episodes | Finite Memory job, exact recipe revision, narrow one-shot inference, typed result/no-result state and later consumer | Permanent Dreamer process, controller Task/Attempt for one completion or model-owned publication |
| Add optional capabilities safely | Internal module and vertical increment; external process only for a real runtime/failure boundary | Crate/process per noun, mandatory `module.toml`, promotion contour or hot-swap framework for ordinary helpers |
| Protect privacy and secrets | Disclosure propagated with content; authoritative check at actual send owner; finite controlled-copy cleanup | General Governor policy engine, route classifier, approval packet or capability-evidence platform |
| Recover after failure | One Store, source spool, native backup/restore, supervisor and idempotent operation/readback | Second recovery database, Operational Recovery State ontology or global Product Identity graph |
| Keep authority explicit | Narrow application operations and authenticated external boundaries | One universal Governor for ordinary in-process calls or receipt-backed authority for every transition |
| Improve methods from outcomes | Observed result linked to exact method revision and a new revision when evidence changes it | Global intelligence score, StepOutcomeLedger or compulsory model judge |
| Coordinate development | One issue, one branch/PR owner, one integrator and terminal disposition for overlap | Work-unit database, branch manager, generated inventory denominator or agent scheduler |
| Verify product behavior | Lowest connected product edge that distinguishes the property; broader proof only at corresponding boundary | Shape/module proof counted as product completion or full release identity for local change |

A mechanism enters V3 only after its real caller, owner, retained result and consumer are named. Until then the need remains a requirement or test case, not a new type, service, manifest, registry or process.

## Model execution without a second task manager

Dreamer is the cognitive role of a finite Eliot learning job, not a permanent process or controller Task lifecycle.

Successful result path:

```text
retained episode + exact recipe revision + disclosure
→ saved exact Memory request
→ direct authenticated controller IPC
→ controller inference_input + one inference Operation
→ frozen InferenceConnection / InferenceProfile behavior
→ controller inference_result
→ Memory range read + length/digest verification + durable copy
→ purpose-specific decoder
→ ordinary memory revision or valid no-change
→ changed later context
→ inference.release(memory_copy_verified)
```

Terminal no-result path:

```text
rejection / failed attempt without result / queued cancellation
→ explicit operational failure, not cognitive no-change
→ inference.release(terminal_without_result)
→ retained input removed or exact cleanup gap
```

Physical erasure of unresolved work uses `abandon_for_erasure`: controller fences future dispatch/settlement/publication before removing exact controlled copies. This cannot prove that provider execution, storage or billing did not occur.

`eliot-swarm-controller` remains the initial owner of model/provider credentials and external execution. It needs narrow `inference.text`, `inference.embed` and `inference.release` operations that reuse request deduplication and durable result readback **without** creating a controller Task, Requirement, Attempt, workspace, review or acceptance record. Memory owns its job, source coverage, recipe, disclosure reduction, result copy, decoding and publication.

Controller configuration separates transport/secret ownership from behavior selection. A static `InferenceConnection` owns transport, private credential reference, non-secret digest and declared `actual_destination = local | external`. A static `InferenceProfile` selects one versioned adapter, one connection, one requested model, automatic-use permission, finite limits and supported response formats. The resolved profile inherits actual destination from its connection. There is no implicit fallback.

Memory reduces contributing input to `local_only` or `external_allowed`; controller authoritatively checks the resolved destination. Protected input is not silently omitted to make a remote destination pass. Missing usage, cost or account identity remains unknown rather than zero or inferred.

Controller stages exact input before provider I/O and exact visible result when one exists. Input and result cleanup are tracked independently. Aggregate `released` is valid only when every created controller content copy is removed or verified absent. The exact request/result/no-result/abandon lifecycle is defined in [INFERENCE-CONTRACT](INFERENCE-CONTRACT.md).

Real software-agent work with tools and continuation can still use controller Tasks/Attempts. One memory extraction request cannot justify copying that task system into Memory OS.

## Product path

```text
real host/source event
→ durable observation
→ direct current-work and memory retrieval
→ optional finite interpretation
→ versioned lesson/view
→ context at a later decision
→ observed result
→ correction or method improvement
```

Base implements capture, explicit updates and reuse. The first learning extension closes automatic interpretation and later use. Every capability needs a real input, operation, retained result or typed unknown, and consumer. A stored type, receipt, fixture or generated card is not product behavior.

## Development order

[Implementation §14](IMPLEMENTATION.md#14-implementation-sequence) defines connected slices:

1. Store/lifecycle and exact persistence.
2. Useful Base with one host, retrieval/context/source open and maintenance.
3. Controller one-shot inference owner: connection/profile admission, direct IPC, controlled input/optional result, exact readback and per-copy `inference.release` without Task/Attempt.
4. First Memory learning path: disclosure, exact recipe, retained request/result or explicit no-result, decoder/publication, later context and correct cleanup disposition.
5. Independent vector, project-view, document, Research and host increments.
6. Advanced curation and diagnosis after base paths work.

Write production code first. Run minimum relevant build/Clippy after coherent code increments. Do not build speculative test platform or distort production code to satisfy placeholder tests. Full automated suite is built and run after connected product implementation.

For every slice, resolve cheap blockers first, keep one integrator and give overlapping work terminal disposition before opening sibling branch. Leaf compilation, generated documentation or stored receipt does not close a slice.

## Evidence limits

The audit conclusion covers available corpus and records explicit exclusions. Full release ZIP contents and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` were not available as readable source material. Donor findings apply only to exact paths/revisions recorded in registry; no donor is qualified wholesale.

Delivery/process findings use repository issue evidence and current retained process surfaces. They establish recurring failure mechanisms, not a claim that every historical issue, branch or validator was individually wrong.

Work remains under [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). V2 runtime, CI, validators, ACTIVE registry and user data are not modified by these documents.
