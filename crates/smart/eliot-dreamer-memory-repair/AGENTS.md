# `eliot-dreamer-memory-repair` implementation contract

Owning issue: [#671 — A-30 bounded typed memory defect repair](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/671).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`A4.6 — Memory Transformation`](../../../docs/architecture/A04-06-memory-transformation.md#a46-memory-transformation)
- [`A4.7 — Accessibility, Support, Influence, and Erasure`](../../../docs/architecture/A04-07-accessibility-support-influence-and-erasure.md#a47-accessibility-support-influence-and-erasure)
- [`I9.6 — Candidate kinds`](../../../docs/architecture/I09-06-candidate-kinds.md#i96-candidate-kinds)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I12.19 — Negative memory`](../../../docs/architecture/I12-19-negative-memory.md#i1219-negative-memory)
- [`I12.20 — Influence revocation`](../../../docs/architecture/I12-20-influence-revocation.md#i1220-influence-revocation)
- [`I12.21 — Memory ecology and transfer`](../../../docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md#i1221-memory-ecology-residual-experience-and-transfer)
- [`I12.30 — Memory trajectory error registry`](../../../docs/architecture/I12-30-memory-trajectory-error-registry.md#i1230-memory-trajectory-error-registry)
- [`I12.36 — Memory threat handling and Environment Runbooks`](../../../docs/architecture/I12-36-memory-threat-handling-and-environment-runbooks.md#i1236-memory-threat-handling-and-environment-runbooks)
- [`I12.26 — Memory admission and retrieval trace`](../../../docs/architecture/I12-26-memory-admission-and-retrieval-trace.md#i1226-memory-admission-and-retrieval-trace)
- [`I5.18 — Relation registry`](../../../docs/architecture/I05-18-relation-registry.md#i518-relation-registry)

## What to implement

Replace the placeholder with the pure candidate-only owner of exactly one non-identity-surgery repair for one closed defect kind: missing provenance, contaminated influence, false relation, stale derived view or representation gap.

## How

- Use A-03 Repair and its exact five payloads; reject generic repair, prose classification and compound defects.
- Validate exact task/scope/fence/subject/current owner, source/history/trajectory/threat evidence, affected denominator, policy and independent bounds before proposing anything.
- Missing provenance may propose a link only from an authoritative matching source/transition/artifact/receipt; never infer author/time/operation from similarity.
- Contaminated influence requires complete public B-SEC1 closure and review/renewal/inverse owners; partial/stale/unknown closure blocks completeness and cannot erase or silently alter other axes.
- False relation binds exact relation/endpoints/type/revision/source and complete dependents; chronology/correlation/proximity is not causality.
- Stale view preserves old bytes/history and proposes owner-directed invalidate/rebuild/revalidate from a complete source frontier; timestamp alone cannot prove currentness.
- Representation repair binds one existing canonical identity and preserves source/omission/reversibility; it cannot create a second truth/support owner.
- Preserve raw history, negative-memory triggers, counterevidence, minority/conflict material and independent existence/support/accessibility/influence/privacy/erasure/assurance axes.
- Emit one owner-directed inert operation with verifier, inverse/forward correction, expiry/reopen and one disposition per affected member; execute no repair.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests for all five families.
- Exactly one defect kind is accepted; merge/split routes to #665, content reconsolidation to #667, pure axis tuning to #669.
- No fabricated provenance, cleansed taint, stale-as-current view, unsupported causal relation or duplicate truth representation can become complete.
- Every affected source/member/dependent is accounted exactly once; unknown required closure remains blocked/partial.
- Independent memory axes and raw/audit/failure history cannot be changed implicitly.
- Exact replay is deterministic; changed same-ID defect/source/closure/policy conflicts.
- No apply/persist/ID allocation, graph traversal, runbook execution, Store/provider/model/tool/process call, authority, effect or Finish API exists.
- All 66 `WORK_UNIT_CASE: 671/1..66` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #966 performs serialized workspace admission.
