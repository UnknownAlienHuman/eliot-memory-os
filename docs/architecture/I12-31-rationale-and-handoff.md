## I12.31. Rationale and handoff

Decision rationale is captured at the decision boundary:

```text
chosen option;
why now;
alternatives and rejection reasons;
confidence/unknowns;
revisit conditions.
```

If missing, record is marked degraded rationale. Dreamer may add a retrospective hypothesis, never rewrite it as original rationale.

`HandoffArtifact` preserves control state, exact anchors, current diff/artifacts, pending verifiers, killed/forbidden resumptions, next action and State Fence. Resume revalidates reality; prose summary alone is insufficient.


Every Material decision/resume exposes typed `DecisionExecutionLineageRefs`:

```yaml
DecisionExecutionLineageRefs:
  governing_goal_acceptance_and_task_revision:
  observations_evidence_and_current_epistemic_position:
  theory_rivals_unknowns_and_rationale:
  decision_and_ActionContract:
  proposed_authorized_and_observed_effect_refs:
  operation_diff_and_change_observation_refs:
  original_and_current_anchor_resolution_refs:
  anchored_review_item_and_disposition_refs:
  artifact_and_verifier_refs:
  outcome_and_memory_revision_refs:
  state_fence_authority_epoch_and_supersession:
  completeness: COMPLETE | PARTIAL | STALE | UNKNOWN
```

A Material resume or claimed continuation fails closed when a load-bearing lineage ref is missing, stale or superseded. The chain proves reconstructable traceability, not causal benefit: outcome improvement still requires intervention, counterfactual or another credible comparison.

The public handoff/review surface exposes the `ChangeProvenanceView` from I12.10, not hidden reasoning. It supports both directions:

```text
public decision/conversation → operation/diff → historical/current code/artifact → verifier/outcome;
current code/artifact → touching operations/attempts → public decisions/reviews → verifier/outcome.
```

Each link is classified `exact`, `receipt_linked`, `correlated`, `ambiguous` or `unknown`. Review, resume and incident diagnosis may use correlated links as inquiry cues, but only exact/receipt-linked evidence may satisfy a claim that one decision produced one change. Original anchors and historical deleted targets remain navigable even when no current anchor can be resolved.

