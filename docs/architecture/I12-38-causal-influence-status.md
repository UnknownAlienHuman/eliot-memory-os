## I12.38. Causal influence status

The existing influence ladder records observable use stages. Causality is a separate axis:

```yaml
InfluenceEvidence:
  memory_or_context_item_ref:
  delivery_and_ack_refs:
  public_decision_or_action_reference:
  intervention_or_ablation_id:
  control_condition:
  downstream_artifact_delta:
  outcome_delta:
  known_confounders:
  assignment_masking_and_replacement_policy:
  seed_and_held_out_status:
  effect_estimate_and_uncertainty:
  underpowered_disposition:
  causal_status: UNKNOWN | OBSERVED_CORRELATION | ABLATION_SUPPORTED | CONFOUNDED
```

`delivered`, `acknowledged`, `cited` and `decision changed` are progressively stronger observations, but none alone proves benefit. `ABLATION_SUPPORTED` requires a credible intervention/control and applicable outcome measure. Missing acknowledgement remains `unknown`; correlated agents do not create independent causal evidence by repetition.

