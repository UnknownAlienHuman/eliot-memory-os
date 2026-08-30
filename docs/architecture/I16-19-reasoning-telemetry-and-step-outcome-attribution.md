## I16.19. Reasoning telemetry and step-outcome attribution

Reasoning summaries or content exposed by a provider are optional untrusted telemetry:

```yaml
ReasoningObservation:
  route_attempt_and_event_ref:
  exposed_summary_or_content_handle:
  disclosure_and_retention_class:
  diagnostic_use_only: true
  not_proof: true
  not_authority: true
  not_reward_target: true
  leakage_and_privacy_risk:
```

ELIOT never requires hidden chain-of-thought, reconstructs it from polished prose or treats its absence as a trace failure. Public rationale captured at the decision boundary is a separate governed record.

Every model-judge or learned evaluator declares a `RewardInputBoundary`:

```yaml
RewardInputBoundary:
  evaluator_and_construct:
  allowed_inputs:
  forbidden_inputs:
  answer_author_and_future_state_leakage_checks:
  shared_lineage_and_independence_limits:
  criterion_and_countermetrics:
  effect_on_current_trajectory_or_future_policy:
```

Forbidden by default are hidden reasoning, unavailable answer keys, author self-justification in blind review, future status/outcome fields, secrets and any input that lets the evaluator reproduce the expected label instead of measuring the artifact.

A `StepOutcomeLedger` records observable process evidence without pretending that every successful task has one identifiable cause:

```yaml
StepOutcomeLedger:
  task_attempt_and_state_fence:
  steps:
    - action_or_inquiry_ref:
      expected_observable:
      actual_observable:
      evidence_effect_and_artifact_refs:
      disposition: helped | harmed | no_observed_delta | uncertain | not_executed
      causal_basis: intervention | discriminative_comparison | correlation | unknown
  delayed_or_distributed_credit:
  replay_handles:
```

Step credit can update memory vitality, route profiles, Skill curation and Improvement Candidates only with its stated causal basis. A post-hoc evaluator may change a score or future policy candidate; it cannot become a cause of an already fixed production outcome unless its verdict actually changed the trajectory.



