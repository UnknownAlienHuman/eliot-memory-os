## I7.11. Context payload profiles and Decision Safety Floor

The existing byte/token figures are unvalidated planning candidates until a route-specific profile is qualified under I2.16. They guide rendering, not correctness.

Every packet atom has a loss policy:

```yaml
ContextAtomPolicy:
  atom_id:
  class: AUTHORITY | GOAL | SCOPE | ACCEPTANCE | SOURCE | VERIFIER |
         MATERIAL_UNKNOWN | NEGATIVE | SECURITY | OPTIONAL
  loss_policy: NON_DROPPABLE | HANDLE_ONLY | EXTRACTIVE | SUMMARIZABLE
  dependency_and_invalidation_refs:
  applicable_effect_classes:
```

`DecisionSafetyFloor` for a Material/Critical boundary contains all currently applicable non-droppable atoms:

```text
goal/acceptance and current scope;
authority, policy and State Fence;
load-bearing source/provenance and current epistemic status;
material unknowns, conflicts and negative memory;
exact expected effect and applicable verifier;
active recovery/conflict/security directives.
```

The compiler may compact optional narrative, move expandable evidence to handles and decompose work, but it may not silently remove the floor. If the floor cannot be delivered and expanded before the decision, compilation returns `DECISION_CONTEXT_INCOMPLETE`; the allowed response is decomposition, a safer partial action, a different qualified route or Human decision—not continuation with a fluent incomplete packet.

Every Material/Critical action or resumed branch carries the canonical `DecisionExecutionLineageRefs` defined in I12.31. Context compilation validates that its goal/task, evidence, epistemic position, rationale, authority/effect, artifact/verifier/outcome and omission/handoff links are complete for the decision class.

The chain proves traceability and continuity, not causal benefit. Missing, stale, revoked or superseded load-bearing links return `DECISION_CONTEXT_INCOMPLETE` or a narrower safe action. A fluent summary cannot substitute for the chain, and success after delivery does not create causal credit without intervention/counterfactual evidence.

Every compaction emits a field-level loss/omission manifest and reversible handles to retained source. Approximate token estimates never prove preservation.

