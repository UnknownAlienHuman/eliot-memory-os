### I8.9.1. Risk accumulation, model escalation and flexible response

Watchdog maintains a multidimensional `RiskEvidenceVector`; the optional numeric score is only a policy projection for triage and route selection, never truth, authority or an automatic universal blocker.

```yaml
RiskEvidenceVector:
  subject_and_scope:
  impact_and_effect_class:
  likelihood_or_recurrence:
  evidence_confidence_and_observation_coverage:
  propagation_and_blast_radius:
  reversibility_and_external_residue:
  persistence_and_compromise_potential:
  uncertainty_and_common_lineage:
  current_damage_and_repair_history:
  supporting_and_counterevidence:

RiskAccumulatorView:
  deduplicated_signal_refs:
  correlated_lineage_groups:
  decayed_and_reopened_risk_pressure:
  policy_score_and_explanation:
  next_action: observe | request_resync | cheap_diagnosis | strong_diagnosis |
               concilium | preauthorized_containment | human_escalation
```

Repeated copies of one event do not add linearly. Many low-severity independent anomalies may justify diagnosis; one Hard Boundary observation may require immediate local containment without waiting for a score. Thresholds and model routes are Human-owned Policy/Empirical Profiles.

When deterministic evidence is insufficient, Watchdog creates a bounded `WatchdogAgentRequest`. Low-complexity classification may use a cheap local route; cross-layer ambiguity, possible compromise or repeated repair failure may use a stronger independent route or Concilium. The agent receives evidence handles, a precise question, no broad mutation authority and an explicit stop condition.

Accumulating damage, failed Doctor recipes, unknown external effects or a widening blind interval raises persistent Human attention. The system narrows only the dependent operation/module when possible; it does not sabotage unrelated work merely because the aggregate score is high.

A derived calibration projection evaluates the risk policy rather than treating its score as self-validating:

```yaml
RiskPolicyCalibration:
  policy_profile_revision_and_validity_scope:
  classified_signal_and_action_samples:
  missed_critical_harm_and_residual_damage:
  false_containment_false_block_and_unnecessary_escalation:
  diagnosis_utility_recovery_time_and_human_attention:
  route_cost_and_independence:
  uncertainty_and_sample_limitations:
  proposed_keep_narrow_rollback_or_experiment:
```

Threshold/profile changes are Improvement Candidates with rollback; a high score that repeatedly predicts nothing is evidence against the risk policy, not evidence that work should be blocked harder.

