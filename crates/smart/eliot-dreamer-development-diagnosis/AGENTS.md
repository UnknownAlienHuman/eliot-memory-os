# `eliot-dreamer-development-diagnosis` implementation contract

Owning issue: [#675 — A-40 falsifiable anti-proxy development diagnosis](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/675).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`I0.10 — User outcome, recovery invariants and anti-proxy development`](../../../docs/architecture/I00-10-user-outcome-recovery-invariants-and-anti-proxy-development-contract.md#i010-user-outcome-recovery-invariants-and-anti-proxy-development-contract)
- [`I0.5 — Conformance, support and evidence status`](../../../docs/architecture/I00-05-conformance-support-and-evidence-status.md#i05-conformance-support-and-evidence-status)
- [`I9.3 — Job classes`](../../../docs/architecture/I09-03-job-classes.md#i93-job-classes)
- [`I9.4 — Dreamer input bundle`](../../../docs/architecture/I09-04-dreamer-input-bundle.md#i94-dreamer-input-bundle)
- [`I9.5 — Dream Packet`](../../../docs/architecture/I09-05-dream-packet.md#i95-dream-packet)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I17.5 — Mechanism Review`](../../../docs/architecture/I17-05-mechanism-review.md#i175-mechanism-review)
- [`I18.2 — Discriminator-first repair`](../../../docs/architecture/I18-02-discriminator-first-repair.md#i182-discriminator-first-repair)
- [`I18.9 — Hard Boundary discriminators`](../../../docs/architecture/I18-09-hard-boundary-discriminators.md#i189-hard-boundary-discriminators)
- [`I18.22 — Flake, hang and recurrence handling`](../../../docs/architecture/I18-22-flake-hang-and-recurrence-handling.md#i1822-flake-hang-and-recurrence-handling)
- [`I13.2 — Conflict Set`](../../../docs/architecture/I13-02-conflict-set.md#i132-conflict-set)
- [`I12.18 — Prediction and calibration`](../../../docs/architecture/I12-18-prediction-and-calibration.md#i1218-prediction-and-calibration)
- [`I12.38 — Causal influence status`](../../../docs/architecture/I12-38-causal-influence-status.md#i1238-causal-influence-status)

## What to implement

Replace the placeholder with the pure candidate-only owner of one bounded falsifiable `DevelopmentDiagnosis` tied to the actual Product Objective, exact current discriminator, full repair history and explicit rival mechanisms.

## How

- Validate exact Product Objective/acceptance/recovery contract, source/artifact/config/runtime identity, job/task/scope/fence/bundle/grounding/input receipt, discriminator and complete repair-history denominator.
- Establish a user-visible Product gap. Activity, PR/code volume, compile/unit success, liveness and other proxies require an explicit evidence-backed mapping and never substitute for Product outcome.
- Require a current-path discriminator with exact preconditions, expected/observed result, owner, replay contract and coverage. A passing or post-hoc-only discriminator cannot prove current failure.
- Account every prior repair stage and structured mechanism. Cosmetic or load-bearing-equivalent retries under unchanged conditions require `MechanismReviewRequired`, not another attempt.
- Preserve every grounded rival mechanism, prediction, falsifier, assumptions, confounders, support, counterevidence and common-mode lineage. Do not choose by confidence/count/recency.
- Eliminate a rival only when a load-bearing prediction is falsified under compatible conditions; partial/confounded evidence remains unresolved.
- Recommend only the smallest safe experiment from the declared finite alternatives when its complete outcome matrix separates live rivals or resolves one blocking assumption.
- Emit exact external owner/minimal repair surface/forbidden paths/next Edge or Product Pulse evidence; create no issue, work unit, patch or execution.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Every complete diagnosis has an exact Product gap, current failing/insufficient discriminator, complete repair history, at least one falsifiable live rival and a discriminating experiment or explicit insufficiency.
- Proxy progress cannot become Product delta; failed repair cannot falsify an unimplemented/untested mechanism.
- Equivalent failed repair cannot be recommended without a new hypothesis/evidence/discriminator/conditions or justified controlled repetition.
- Every experiment maps success, no-change, regression, unavailable, unknown and instrumentation-failure outcomes to rivals and has owner/verifier/cost/risk/effect/cancel/cleanup/rollback bounds.
- No oracle weakening, source/config mutation, patch/test execution, issue/agent creation, Product promotion, authority, effect or Finish API exists.
- All 51 `WORK_UNIT_CASE: 675/1..51` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #969 performs serialized workspace admission.
