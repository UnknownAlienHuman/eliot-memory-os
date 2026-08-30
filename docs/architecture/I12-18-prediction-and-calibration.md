## I12.18. Prediction and calibration

Material causal/action model records before action:

```text
predicted verifier verdict;
predicted diagnostic change;
predicted effect/blast radius;
expected observable value/range;
confidence or alternatives where useful.
```

Matcher compares with VerificationRun, diagnostics, changed artifacts and real effects.

Outcomes:

```text
hit;
partial;
miss;
unresolvable.
```

Calibration is per scope/subsystem/task family/model-harness route. It informs decisions; it is not a universal understanding score.

Typed relation state prevents topology or co-change from being laundered into causality:

```yaml
CausalRelationEvidence:
  relation_and_endpoints:
  status: STRUCTURAL | BEHAVIORAL_CORRELATION | CAUSAL_HYPOTHESIS |
          PREDICTION_SUPPORTED | INTERVENTION_SUPPORTED | REFUTED | UNKNOWN
  mechanism_and_rival_refs:
  predeclared_predictions:
  intervention_or_discriminator:
  observed_outcome_and_verifier:
  counterfactual_and_confounder_disposition:
  scope_transfer_boundary:
  evidence_lineage_and_state_fence:
```

Only `INTERVENTION_SUPPORTED` or an explicitly qualified natural experiment may support a causal operational claim; `PREDICTION_SUPPORTED` remains defeasible, and structural/behavioral edges remain navigation or hypothesis evidence. Missing confounder/counterfactual information is `UNKNOWN`, never an implicit positive edge. Relation status is revised forward and retains prior evidence.

