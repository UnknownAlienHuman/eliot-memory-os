# `eliot-dreamer-accessibility` implementation contract

Owning issue: [#669 — A-29 accessibility or allowed-influence adjustment](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/669).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`A4.7 — Accessibility, Support, Influence, and Erasure`](../../../docs/architecture/A04-07-accessibility-support-influence-and-erasure.md#a47-accessibility-support-influence-and-erasure)
- [`I9.6 — Candidate kinds`](../../../docs/architecture/I09-06-candidate-kinds.md#i96-candidate-kinds)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I12.19 — Negative memory`](../../../docs/architecture/I12-19-negative-memory.md#i1219-negative-memory)
- [`I12.20 — Influence revocation`](../../../docs/architecture/I12-20-influence-revocation.md#i1220-influence-revocation)
- [`I12.21 — Memory ecology and transfer`](../../../docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md#i1221-memory-ecology-residual-experience-and-transfer)
- [`I12.26 — Memory admission and retrieval trace`](../../../docs/architecture/I12-26-memory-admission-and-retrieval-trace.md#i1226-memory-admission-and-retrieval-trace)
- [`I12.38 — Causal influence status`](../../../docs/architecture/I12-38-causal-influence-status.md#i1238-causal-influence-status)
- [`I7.25 — Skill lifecycle and execution evidence`](../../../docs/architecture/I07-25-skill-lifecycle-interaction-and-execution-evidence.md#i725-skill-lifecycle-interaction-and-execution-evidence)

## What to implement

Replace the placeholder with the pure candidate-only owner of one reversible adjustment to exactly one axis: accessibility/retrievability/exposure, or allowed influence within an exact scope.

## How

- Use the A-03 Accessibility kind and closed axis/operation payload; reject generic or multi-axis patches.
- Validate exact task/scope/fence/subject/current axis owner, usage/outcome/protection evidence, dependency/closure denominator, policy and independent bounds.
- Keep existence/lifecycle, support/assertability, accessibility, influence, privacy/retention/erasure and source assurance independent. Only the selected axis may differ in a valid proposal.
- Low retrieval, non-use, cost, confidence or model agreement is not weak support, deletion authority or influence evidence. Unknown usage is not non-use.
- Accessibility changes preserve provenance, audit, counterevidence and protected-owner/verifier access and cannot widen privacy/support/influence/effect ceilings.
- Material influence changes require the complete public B-SEC1 closure over every affected derivative, decision, procedure, cue, Context and recovery path. Partial/stale/unknown closure blocks completeness.
- Preserve exact negative-memory triggers until owner-qualified extinction/reopen evidence. Similarity or low use cannot suppress them.
- Emit expected observable, semantic verifier, window, inverse, expiry/renewal and owner-specific dependent dispositions; apply nothing.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Every valid proposal changes exactly one axis; all unselected axes retain exact owner/revision references.
- A complete influence proposal contains complete matching closure and independent review/decision owner evidence.
- Missing protection, closure, inverse or verifier fails closed; no scalar benefit/risk compensation is allowed.
- Accessibility reduction cannot hide required provenance/audit/counterevidence; influence reduction cannot erase or silently alter other axes.
- Exact replay is deterministic; changed same-ID subject, closure, policy or target state conflicts/invalidates identity.
- No graph/index/Context/cue mutation, grant revocation, erasure, Store/provider/model query, authority, effect or Finish API exists.
- All 59 `WORK_UNIT_CASE: 669/1..59` cases execute and pass, including both accessibility and influence halves.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #966 performs serialized workspace admission.
