# Eliot Memory OS V3

**Normative rewrite baseline 1.0-draft · 2026-10-22.**

V1 and V2 are donors. V3 is a greenfield implementation.

## Reading order

1. [Architecture](ARCHITECTURE.md) — purpose, ownership, invariants and explicit non-goals.
2. [Implementation](IMPLEMENTATION.md) — process family, data model, Store operations, integrations and vertical build sequence.
3. [Cognition](COGNITION.md) — current-work reconstruction, revisable knowledge, retrieval, learning and self-improvement algorithms.
4. [Audit conclusion](AUDIT.md) — evidence, root causes, rejected mechanisms and source limits.
5. [Requirements/source map](AUDIT-MAP.md) — dispositions for original requirements, historical audits and donors.

Architecture, Implementation and Cognition are now one coherent design baseline. They are **not implemented product code**.

## Selected baseline

- local-first Rust;
- one demand-start supervisor/daemon process family;
- one SurrealDB server child and one private Store;
- native exact/full-text retrieval with optional compatible vectors;
- actual host events for capture;
- actual controller execution for Dreamer;
- external specialist tools for code/document/research acquisition;
- one finite job mechanism;
- no second swarm, task manager, policy platform, semantic database or proof factory.

## Product path

```text
real host/source event
→ durable observation
→ direct current-work and memory retrieval
→ optional finite Dreamer interpretation
→ versioned lesson/view
→ context at a later decision
→ observed result
→ correction or method improvement
```

Every capability must have a real producer and consumer. A stored type, receipt, test fixture or generated card does not establish product behavior.

## Development sequence

Implementation proceeds by the vertical slices in [Implementation §14](IMPLEMENTATION.md#14-implementation-sequence):

1. Store and local lifecycle;
2. host capture and context;
3. Dreamer and lessons;
4. project understanding and transfer;
5. vectors, documents and research;
6. recovery and advanced improvement.

Follow the owner's order: product code, minimum relevant build/Clippy checks, broader tests after connected behavior exists.

## Evidence limits

The audit conclusion covers the available corpus and records explicit exclusions. The release ZIP and the full `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` were not available as readable source material. Not every donor repository was audited completely. These limits do not turn the selected design into an unimplemented approval gate.

Work remains under [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). V2 runtime, CI, validators, ACTIVE registry and user data are not modified by these documents.
