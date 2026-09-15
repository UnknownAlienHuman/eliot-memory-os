# `eliot-dreamer-conflict-analysis` implementation contract

Owning issue: [#673 — A-39 bounded conflict analysis](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/673).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`A0.5 — Concilium`](../../../docs/architecture/A00-05-concilium.md#a05-concilium)
- [`I13.1 — Conflict types`](../../../docs/architecture/I13-01-conflict-types.md#i131-conflict-types)
- [`I13.2 — Conflict Set`](../../../docs/architecture/I13-02-conflict-set.md#i132-conflict-set)
- [`I13.4 — Concilium runtime`](../../../docs/architecture/I13-04-concilium-runtime.md#i134-concilium-runtime)
- [`I10.18 — Mailbox, blackboard, live peer delivery and anchored review`](../../../docs/architecture/I10-18-mailbox-blackboard-live-peer-delivery-and-anchored-review.md#i1018-mailbox-blackboard-live-peer-delivery-and-anchored-review)
- [`I9.5 — Dream Packet`](../../../docs/architecture/I09-05-dream-packet.md#i95-dream-packet)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I12.18 — Prediction and calibration`](../../../docs/architecture/I12-18-prediction-and-calibration.md#i1218-prediction-and-calibration)
- [`I12.22 — Theory portfolio and practical weighting`](../../../docs/architecture/I12-22-theory-portfolio-and-practical-weighting.md#i1222-theory-portfolio-and-practical-weighting)
- [`I21.6 — Source portfolio and coverage denominator`](../../../docs/architecture/I21-06-source-portfolio-coverage-denominator-and-coveragereceipt.md#i216-source-portfolio-coverage-denominator-and-coveragereceipt)
- [`I7.20 — Agent-facing error contract`](../../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract)

## What to implement

Replace the placeholder with the pure candidate-only analyzer of one exact bounded `ConflictSet`, preserving every position, objection, source, counterexample, minority view, assumption and unknown without selecting a winner.

## How

- Consume the exact pre-handler A-05-validated input and canonical ConflictSet/evidence/source-independence/probe contracts; do not invoke A-05, peers, Concilium or providers.
- Validate exact job/task/scope/fence/bundle/grounding/receipt/ConflictSet identities, complete-or-partial position/source/objection denominators and all independent bounds.
- Group evidence by actual authoritative lineage roots, not agent/message/citation counts. Unknown lineage is unknown independence.
- Compare only typed subject/entity/scope/time/version/definition/unit/denominator/precision/modality/goal/policy/authority/factual-predictive-causal dimensions and preserve originals.
- Distinguish genuine contradiction from compatible scope/time/definition/entity/authority differences and owner-proved supersession. A newer timestamp is not supersession.
- Preserve multiple applicable conflict classes, dissent, falsifiers, common-mode risks, counterevidence and unresolved assumptions; no confidence or majority vote.
- Recommend only already supplied structured probes whose outcome matrix separates live positions or resolves one load-bearing unknown. Execute/reserve nothing.
- Recommend the exact external decision/evidence/evaluator/Human/Governor/Architecture/security owner; recommendation is not assignment or authority.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Every expected position, objection and source is retained or explicitly unavailable/withheld; minority evidence cannot disappear.
- Independent-source counts never exceed unique authoritative roots; shared model/evaluator/context/route remains common-mode risk.
- Classification never chooses a winner or resolves the conflict; complete analysis remains unresolved without an external resolution receipt.
- Correlation, chronology, topology, confidence, recency or count cannot become causal/truth/authority evidence.
- Every recommended probe has differing outcomes or an exact unknown-resolution criterion plus owner, verifier, cost/risk/privacy/effect bounds.
- No source acquisition, prose entailment, model/tool/Store call, peer transport, Concilium launch, probe execution, mutation, authority, effect or Finish API exists.
- All 68 `WORK_UNIT_CASE: 673/1..68` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #969 performs serialized workspace admission.
