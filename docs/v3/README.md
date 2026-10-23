# Eliot Memory OS V3

**Layered Base and additive extensions · 2026-10-23 · normative design, not implemented code.**

V1 and V2 are donors. V3 is a greenfield implementation.

## Reading order

1. [Architecture](ARCHITECTURE.md) — purpose, ownership, layers, Base and explicit non-goals.
2. [Implementation](IMPLEMENTATION.md) — concrete dependencies, module integration, data, operations and delivery sequence.
3. [Cognition](COGNITION.md) — current-work reconstruction, revisable knowledge, retrieval, learning and self-improvement algorithms.
4. [Active analysis registry](ANALYSIS-REGISTRY.md) — what is checked, what remains open, exact gaps and the next work queue.
5. [Audit conclusion](AUDIT.md) — evidence, root causes, rejected mechanisms and source limits.
6. [Requirements/source map](AUDIT-MAP.md) — stable dispositions for original requirements, historical audits and donors.

Architecture, Implementation and Cognition describe one product at increasing depth. The complete target is not a prerequisite for running the limited Base. They are **not implemented product code**.

`ANALYSIS-REGISTRY.md` is the only active work ledger. `AUDIT-MAP.md` remains the stable source/decision matrix; new analysis should update the registry instead of starting another chronological report.

## Selected construction

One local Rust codebase, one demand-start supervisor/daemon family, one SurrealDB server child and one private Store. Domain/pure logic, application operations, I/O adapters and host surfaces retain explicit dependency boundaries. They do not each require a process, contract crate or pass-through service.

Base captures actual host/source events, preserves explicit knowledge and corrections, supplies exact/lexical context and reopens sources after restart. Its basic data controls cover the material it actually retains. It starts without model, encoder, converter or Research credentials.

Learning, vectors, project understanding, documents, Research and other hosts add their actual capabilities through the [dependency and integration plan](IMPLEMENTATION.md#2-code-structure). They reuse the same records, publication operations, context assembly and finite jobs. A module's absence does not disable Base, and disabling its producer does not erase retained readable knowledge. There is no second Lite database or separate Full memory engine.

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

Base implements capture, explicit updates and reuse; the first learning extension closes automatic interpretation and later use. Every delivered capability needs a real producer and consumer. A stored type, receipt, test fixture or generated card does not establish product behavior.

## Development sequence

[Implementation §14](IMPLEMENTATION.md#14-implementation-sequence) defines the increments:

1. Assemble Store/lifecycle and the first host/context path into a usable Base, including maintenance of its retained data. Then test Base.
2. Add one real learning path and test the resulting next-context behavior; keep Base working with learning disabled.
3. Add vectors, project views, documents, Research and other hosts according to their actual dependencies, not a compulsory all-module chain. Test each assembled increment and the relevant Base paths.
4. Extend advanced improvement and broader operation over the working product.

During coding use minimum relevant compilation/Clippy. Tests follow assembled behavior rather than precede it as an infrastructure programme; testing Base does not wait for all future modules. Use the same production operations, not success-shaped substitutes. No runtime plugin catalogue, hot-generation framework or second scheduler is selected.

## Evidence limits

The audit conclusion covers the available corpus and records explicit exclusions. The release ZIP and the full `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` were not available as readable source material. Not every donor repository was audited completely. These limits do not turn the selected design into an unimplemented approval gate.

Work remains under [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). V2 runtime, CI, validators, ACTIVE registry and user data are not modified by these documents.
