## I21.4. Confirmatory and exploratory lanes

Executable form of A5.7.

```yaml
LaneRegistration:                    # required for a confirmatory lane or confirmatory partition
  contract_protocol_hypothesis_and_evaluator_digests:
  primary_outcome_and_decision_rule:
  exclusions_and_quality_controls:
  blinded_fields:
  allowed_deviations:
  registered_before_outcome_exposure:
  registered_at_and_state_fence:
```

After registration the run may not change the primary metric, exclude a case without a stated rule, weaken the proposition, replace the evaluator after seeing results or hide failed attempts. Declared deviations are preserved and shown with the result. Any later analysis is labelled exploratory. Acceptance is outcome-neutral: a compliant negative result is a valid confirmatory result.

Exploratory results are stored as `EXPLORATORY_FINDING`. Under `ARCH-EPI-03`, evidence that generated or tuned a hypothesis cannot confirm it on the same exposure. Promotion to a confirmatory claim requires a new holdout, an independent run, a preregistered test, replication, formal proof or another sufficient truth surface. A mixed lane freezes an explicit partition; evidence may not silently cross from the exploratory side into the confirmatory evaluator.

`blinded_fields` names one leakage channel to close, not a universal mask. Typical fields: preferred hypothesis, condition labels, parent conclusion, holdout expected score, candidate author, source prestige. Blinding interacts with the non-ordinal independence profile (I7.27) and with the sealed-mapping phase of `NegotiatedInterdependentInvestigation` (I10.15); it does not create a second independence model.

