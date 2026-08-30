## I6.16. Scoped understanding assessment

ELIOT never emits a global `understands=true` or a single understanding score. An assessment is tied to a question/task family and a State Fence:

```yaml
ScopedUnderstandingAssessment:
  subject_route_or_coupled_system:
  question_and_task_family:
  product_and_state_fence:
  current_model_and_rivals:
  material_unknowns:
  pre_probe_predictions:
  selected_discriminator_or_action:
  observed_outcome_and_verifier:
  model_revision_after_outcome:
  counterfactual_or_held_out_evidence:
  transfer_boundary_and_requalification:
  onboarding_slice_and_missing_inputs:
  status: NOT_ONBOARDED | UNTESTED | LOCALLY_ADEQUATE |
          REFUTED | INCONCLUSIVE | STALE
```

Graphs, prose quality, self-report, delivery receipts or agreement among correlated agents cannot set `LOCALLY_ADEQUATE`. The minimum evidence is a public rival-aware model, a prediction fixed before observation, a discriminative probe/action, applicable outcome evidence and revision when prediction fails. Product-level claims additionally require held-out or otherwise leakage-controlled evaluation.

`NOT_ONBOARDED` means that no current Product/State-Fence-bound situation model or sufficient onboarding slice exists; `LOCALLY_ADEQUATE` is forbidden until the missing inputs are resolved. Fixed graph size, edge-count or context thresholds cannot establish understanding. Where applicable, the assessment includes an unanswerable/stale case, counterfactual/intervention or state-update case, held-out/compositional transfer and abstention precision/coverage.

