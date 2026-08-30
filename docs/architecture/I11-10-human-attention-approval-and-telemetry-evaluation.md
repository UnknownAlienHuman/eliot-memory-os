## I11.10. Human attention, approval and telemetry evaluation

The Human Control Plane is evaluated as a coupled intervention, not by notification volume or approval speed alone. A scoped `HumanAttentionEvaluation` records:

```yaml
HumanAttentionEvaluation:
  policy_and_task_risk_profile:
  notification_approval_and_telemetry_profile:
  missed_critical_and_false_critical_counts:
  pre_exposure_prevention_and_conditional_intervention:
  final_harm_and_residual_risk:
  benign_false_blocks_and_abandoned_work:
  interruption_and_resumption_time_quality:
  task_correctness_rework_and_human_attention:
  overtrust_undertrust_and_recoverability_observations:
  privacy_purpose_retention_and_disclosure_cost:
  evaluator_scope_uncertainty_and_invalidation:
```

A quieter policy is not superior when it misses material risk; a stricter policy is not superior when false blocks and interruption destroy the task outcome. Notification suppression never removes the persistent canonical obligation. Approval experiments retain exact action scope and expiry. Richer telemetry remains experimental unless its incremental recovery/diagnostic value exceeds privacy, attention, storage and false-inference costs on a paired profile.


---

Anchored review and provenance navigation are evaluated separately from notification policy:

```text
per-item delivery and disposition completeness;
missed or silently dropped review obligations;
false attachment versus explicit ambiguous/stale status;
time to locate original and current target;
ability to navigate decision → change → verifier and current code → originating decision;
Human correction rate, reviewer burden and duplicate-note rate;
changes accepted/rejected with exact owner, authority and proof;
privacy exposure from reviewed public artifacts and expansion handles.
```

A fast response that skips one of several independent comments fails review completeness. A resolver that attaches a note to the wrong current fragment is worse than returning `ambiguous`; the UI must preserve the historical target and offer explicit correction rather than invent continuity.

