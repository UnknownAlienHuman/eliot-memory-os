# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-24 · normative design, not implemented code.**

V1 and V2 are donors. V3 is a greenfield implementation.

## Reading order

1. [Architecture](ARCHITECTURE.md) — purpose, ownership, Base, extensions and non-goals.
2. [Implementation](IMPLEMENTATION.md) — runtime, modules, data, narrow external contracts and implementation order.
3. [Cognition](COGNITION.md) — current-work reconstruction, retrieval, learning, consolidation and self-improvement algorithms.
4. [Active analysis registry](ANALYSIS-REGISTRY.md) — what was checked, exact gaps and the next work queue.
5. [Audit conclusion](AUDIT.md) — evidence, root causes, rejected mechanisms and source limits.
6. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements, audits and donors.

Architecture, Implementation and Cognition describe one product at increasing depth. The complete target is not a prerequisite for running Base. None of these documents is implemented product code.

`ANALYSIS-REGISTRY.md` is the only active analysis ledger. `AUDIT-MAP.md` is the stable source/decision matrix; new work updates the registry rather than creating another chronological report.

## Selected construction

One local Rust codebase, one demand-start supervisor/daemon family, one SurrealDB child and one private Store. Domain/pure logic, application operations, external adapters and host surfaces keep explicit dependency direction without requiring a process, actor, contract crate or pass-through service per concept.

Base captures real host/source events, preserves explicit knowledge/corrections/commitments, supplies exact/lexical context and reopens exact sources after restart. Its maintenance covers the data it actually retains. Base starts without controller, model, encoder, converter or Research credentials.

Learning, vectors, project understanding, documents, Research and additional hosts are independent vertical extensions. They reuse the same records, finite jobs, revision publication, context assembly and maintenance path. A missing extension does not disable Base; disabling a producer does not erase retained readable knowledge. There is no second Lite database or Full memory engine.

## Model execution without a second task manager

Dreamer is the cognitive role of a finite Eliot learning job, not a permanent process or controller Task lifecycle.

The first learning path is:

```text
retained episode + exact recipe revision + disclosure
→ saved inference request
→ one allowed frozen controller inference profile
→ retained exact result
→ Memory copy and controller-copy release
→ purpose-specific decoder
→ ordinary memory revision or valid no-change
→ changed later context
```

`eliot-swarm-controller` remains the initial owner of model/provider credentials and external execution. It needs narrow `inference.text` and `inference.embed` operations that reuse request deduplication and durable result readback **without** creating a controller Task, requirements, Attempt, workspace, review or acceptance record. Memory owns its job, source coverage, recipe, disclosure reduction and publication.

The first controller inference configuration is a small static `InferenceProfile`, not the old Governor route/capability platform and not the agent route's untyped `native_options`. It identifies only adapter/connection/model, `local|external` locality, automatic-use permission, finite input/output/time/concurrency limits and supported response formats. There is no implicit fallback to another provider, model, account, locality or billing path.

Memory reduces contributing input to `local_only` or `external_allowed`. Protected input is not silently omitted to make a remote profile pass. Missing usage or cost remains unknown rather than zero. The controller retains result bytes until Memory confirms a durable copy, then its controlled duplicate must become releasable; erasure is incomplete while that copy remains.

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

Base implements capture, explicit updates and reuse. The first learning extension closes automatic interpretation and later use. Every capability needs a real input, operation, retained result and consumer. A stored type, receipt, fixture or generated card is not product behavior.

## Development order

[Implementation §14](IMPLEMENTATION.md#14-implementation-sequence) defines the connected slices:

1. Store/lifecycle and exact persistence.
2. Useful Base with one host, retrieval/context/source open and maintenance.
3. Controller one-shot inference owner: static profiles, `inference.text`/`inference.embed`, durable readback and cleanup without Task/Attempt.
4. First Memory learning path: disclosure, exact recipe, retained request/result, decoder, publication and later context.
5. Independent vector, project-view, document, Research and host increments.
6. Advanced curation and diagnosis after the base paths work.

Write production code first. Run minimum relevant build/Clippy after coherent code increments. Do not build a speculative test platform or distort production code to satisfy placeholder tests. The full automated suite is built and run after the product implementation is connected, using the observable product paths already specified.

## Evidence limits

The audit conclusion covers the available corpus and records explicit exclusions. The full release ZIP contents and `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` were not available as readable source material. Donor findings apply only to the exact paths/revisions recorded in the registry; no donor is qualified wholesale.

Work remains under [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). V2 runtime, CI, validators, ACTIVE registry and user data are not modified by these documents.
