# `eliot-dreamer-reconsolidation` implementation contract

Owning issue: [#667 — A-28 forward-only derived-memory reconsolidation](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/667).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`A4.6 — Memory Transformation`](../../../docs/architecture/A04-06-memory-transformation.md#a46-memory-transformation)
- [`I9.6 — Candidate kinds`](../../../docs/architecture/I09-06-candidate-kinds.md#i96-candidate-kinds)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I12.18 — Prediction and calibration`](../../../docs/architecture/I12-18-prediction-and-calibration.md#i1218-prediction-and-calibration)
- [`I12.21 — Memory ecology and transfer`](../../../docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md#i1221-memory-ecology-residual-experience-and-transfer)
- [`I12.26 — Memory admission and retrieval trace`](../../../docs/architecture/I12-26-memory-admission-and-retrieval-trace.md#i1226-memory-admission-and-retrieval-trace)
- [`I12.38 — Causal influence status`](../../../docs/architecture/I12-38-causal-influence-status.md#i1238-causal-influence-status)
- [`I7.25 — Skill lifecycle and execution evidence`](../../../docs/architecture/I07-25-skill-lifecycle-interaction-and-execution-evidence.md#i725-skill-lifecycle-interaction-and-execution-evidence)
- [`I5.27 — Canonical operation and effect identity`](../../../docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md#i527-canonical-operation-and-effect-identity)

## What to implement

Replace the placeholder with the pure candidate-only owner of one forward derived-memory child revision after exact externally observed reactivation and genuinely new material evidence or outcome.

## How

- Require one exact current derived parent, complete predecessor/frontier identity, qualifying reactivation receipt and new evidence that is genuinely new relative to the accepted parent baseline.
- Reject raw episodes/artifacts, ambiguous forks, self-parenting, timestamp-selected “latest”, duplicate retrieval, restatement and cosmetic/reordered-only changes.
- Account every parent proposition exactly once as retained, narrowed, qualified, contradicted, withdrawn or unresolved; account additions in a separate new-member denominator.
- Preserve parent/raw/prior revisions, old and new evidence, contradictions, minority/counterexample material and all history. Withdrawal removes only from the proposed child view.
- Preserve support, assertability, accessibility, influence, lifecycle, privacy, retention and source-assurance owner references independently; content revision changes none of them.
- Give every affected dependent an exact retain/revalidate/rebuild/invalidate/retarget/reconcile/blocked disposition.
- Represent the child only as an external allocation request with verifier, inverse/forward-correction, expiry and reopen conditions; execute no persistence or rollback.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- A complete candidate has exactly one current parent, qualifying reactivation, at least one material new item and complete parent/addition/dependency accounting.
- Reactivation without new evidence, availability/index membership or model mention yields no candidate.
- Every parent proposition appears exactly once; no raw/source/history record is rewritten or lost.
- Contradictions retain both sides; unsupported precision or evidence-strength inflation is rejected.
- Unknown required dependents/effects block completeness and blind rollback/retry.
- No canonical revision allocation, persistence, relation/axis mutation, provider/Store/tool execution, authority, effect or Finish API exists.
- All 57 `WORK_UNIT_CASE: 667/1..57` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #966 performs serialized workspace admission.
