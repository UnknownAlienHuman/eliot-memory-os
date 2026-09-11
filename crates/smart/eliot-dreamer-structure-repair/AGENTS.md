# `eliot-dreamer-structure-repair` implementation contract

Owning issue: [#665 — A-27 merge, split or false-merge reversal](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/665).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`A4.6 — Memory Transformation`](../../../docs/architecture/A04-06-memory-transformation.md#a46-memory-transformation)
- [`I9.6 — Candidate kinds`](../../../docs/architecture/I09-06-candidate-kinds.md#i96-candidate-kinds)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I12.9 — Graph layer`](../../../docs/architecture/I12-09-graph-layer.md#i129-graph-layer)
- [`I12.21 — Memory ecology and transfer`](../../../docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md#i1221-memory-ecology-residual-experience-and-transfer)
- [`I12.26 — Memory admission and retrieval trace`](../../../docs/architecture/I12-26-memory-admission-and-retrieval-trace.md#i1226-memory-admission-and-retrieval-trace)
- [`I5.18 — Relation registry`](../../../docs/architecture/I05-18-relation-registry.md#i518-relation-registry)
- [`I5.27 — Canonical operation and effect identity`](../../../docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md#i527-canonical-operation-identity-and-effect-identity)

## What to implement

Replace the placeholder with the pure candidate-only owner of exactly one typed Merge, Split or accepted prior false-merge reversal, preserving complete lineage, raw history and every affected dependency.

## How

- Use A-03 Merge/Split discriminators and accepted reversal payload; do not invent a generic StructureRepair kind.
- Validate exact job/task/scope/fence/bundle/grounding/current subject revision, complete member/source/dependency denominators, prior-transition evidence and independent bounds.
- Merge requires grounded semantic equivalence, compatible types/owners/schemas, preserved distinctions/counterexamples/minority evidence and a complete rewrite manifest. Similarity, shared lineage or co-retrieval is insufficient.
- Split requires nonempty pairwise-disjoint partitions where `union(partitions) ∪ residue` equals the exact input member set. Complete means no residue and complete dependency closure.
- Reversal requires the exact prior merge receipt and current ancestry. Later writes require forward repair; unknown effects block rollback.
- New IDs remain external allocation requests. Emit one disposition for every current member and dependent; execute no mutation.
- Preserve independent support, assertability, accessibility, influence, lifecycle, privacy and source-assurance ceilings without scalar compensation.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Exactly one supported repair subtype is selected; wrong/multiple/nonidentity repair inputs fail closed.
- Every member and required dependent is accounted exactly once; partial closure remains partial.
- Merge cannot erase material distinctions or raise support/authority/privacy/influence.
- Split cannot lose or duplicate a member; unresolved residue blocks completeness.
- Reversal cannot claim a historical inverse without an exact prior transition and current compatible ancestry.
- No ID allocation, merge/split/relation mutation, Store/provider/tool execution, authority, effect or Finish API exists.
- All 56 `WORK_UNIT_CASE: 665/1..56` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #966 performs serialized workspace admission.
