# `eliot-dreamer-curation` implementation contract

Owning issue: [#684 — A-31 screened exact-one-handler Curation fan-in](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/684).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`I9.2 — Dreamer service responsibilities`](../../../docs/architecture/I09-02-dreamer-service-responsibilities.md#i92-dreamer-service-responsibilities)
- [`I9.3 — Job classes`](../../../docs/architecture/I09-03-job-classes.md#i93-job-classes)
- [`I9.4 — Dreamer input bundle`](../../../docs/architecture/I09-04-dreamer-input-bundle.md#i94-dreamer-input-bundle)
- [`I9.5 — Dream Packet`](../../../docs/architecture/I09-05-dream-packet.md#i95-dream-packet)
- [`I9.6 — Candidate kinds`](../../../docs/architecture/I09-06-candidate-kinds.md#i96-candidate-kinds)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I12.19 — Negative memory`](../../../docs/architecture/I12-19-negative-memory.md#i1219-negative-memory)
- [`I12.20 — Influence revocation`](../../../docs/architecture/I12-20-influence-revocation.md#i1220-influence-revocation)
- [`I12.26 — Memory admission and retrieval trace`](../../../docs/architecture/I12-26-memory-admission-and-retrieval-trace.md#i1226-memory-admission-and-retrieval-trace)
- [`I12.30 — Memory trajectory error registry`](../../../docs/architecture/I12-30-memory-trajectory-error-registry.md#i1230-memory-trajectory-error-registry)
- [`I7.20 — Agent-facing error contract`](../../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract)

## What to implement

Replace the placeholder with the pure typed Curation fan-in: consume an already A-05-validated batch, exact immutable A-19c screen result and injected A-03 registry; dispatch each eligible item to exactly one semantic owner and aggregate its result without fallback or recomputation.

## How

- Preserve the fixed mapping of 11 wire kinds to 10 handler families: Classification, Relation, Episode, Concept, Procedure, Failure, Merge/Split→StructureRepair, Reconsolidation, Accessibility and Repair→MemoryRepair.
- Require exactly ten owner descriptors with complete non-overlapping kind coverage, exact package/schema/revision and stable digest. No `Other`, dynamic discovery, trial decoding or fallback.
- Validate exact job/request/task/attempt/scope/fence/bundle/grounding/validation/screen identities, source/target/evidence denominators, policy and all independent bounds before any handler call.
- Existing mutable targets must be current terminal `Eligible` members of the exact A-19c denominator. Protected/stale/unknown/partial/unprocessed/foreign targets invoke zero handlers.
- Keep mutable targets, immutable evidence and future allocation requests as distinct roles.
- A dispatched item invokes the selected port once; all unselected ports receive zero calls. Handler error, partial result or panic is terminal—never try another handler.
- Validate only the returned envelope bindings and ceilings; do not recompute subtype semantics, rerun A-05/A-20 or repair a handler result.
- Preserve exact all-or-nothing or explicit partial aggregation with accepted/rejected/blocked/unprocessed/frontier accounting.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Exactly 11 kinds and 10 families are represented; Merge and Split stay distinct inputs but share one StructureRepair owner.
- Every eligible dispatched item calls exactly one handler once; every blocked or unselected route calls zero.
- Registry gaps, overlaps, stale descriptors and same-ID changed meaning fail closed.
- Target/evidence/allocation roles cannot be exchanged; protected evidence remains immutable and lineage-bound.
- No fallback, sibling-handler call, semantic recomputation or applied-looking subset after all-or-nothing failure.
- Exact replay and canonical aggregation are deterministic; changed same-ID input/registry/policy conflicts.
- No screening, grounding, common validation, production registry construction, canonical mutation, authority, effect or Finish API exists.
- All 60 `WORK_UNIT_CASE: 684/1..60` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #966 performs serialized workspace admission.
