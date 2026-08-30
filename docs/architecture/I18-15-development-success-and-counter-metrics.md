## I18.15. Development success and counter-metrics

Primary:

```text
time to scope/task orientation;
time to first safe action;
time to first correct action;
time to first applicable verifier and verified ProductProof;
verified product deltas per time/cost;
first-candidate and first-boundary correctness;
regression escape and recovery success;
repeated-failure reduction;
manual reconstruction/context burden;
module-local test latency and affected-plan precision;
time to first actionable failure.
```

The four early-action times are reported separately. A fast first action may be unsafe or wrong; a fast diagnostic failure may be useful without being a product outcome. Zero-ceremony remains a product hypothesis until matched tasks show equal-or-better correctness and lower orientation/interaction burden.

Counter-metrics:

```text
tokens, commits, LoC, test/report count;
activity/product-delta ratio;
repair attempts per failure class;
full-suite frequency and time;
false blocks and alert/rule friction;
selected-plan false-negative rate;
orphan processes and Cargo lock waits.
```

A counter-metric may reveal waste but never substitutes for outcome.

`AgentInterventionOutcomeProfile` is a derived vector over existing task, Product Pulse, rework, Human-attention and delayed-outcome receipts:

```yaml
AgentInterventionOutcomeProfile:
  window_task_family_route_and_governance_profile:
  verified_product_deltas_and_completion_quality:
  escaped_defects_and_delayed_regressions:
  rework_repair_and_rollback_cost:
  unrelated_or_forbidden_change_surface:
  oracle_or_fixture_changes_needed_to_pass:
  Human_correction_attention_and_recovery_cost:
  time_token_tool_compute_and_storage_cost:
  outcome: IMPROVING | NEUTRAL | DEGRADING | INCONCLUSIVE
  uncertainty_exposure_and_invalidation:
```

No scalar “agent score” is created. Persistent `DEGRADING` narrows autonomy/routing for the exact validity scope and opens an Improvement Candidate; it does not prove that every agent or model is harmful.

