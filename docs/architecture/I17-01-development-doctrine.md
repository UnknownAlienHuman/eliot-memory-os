## I17.1. Development doctrine

```text
product objective before implementation activity;
one causal property per reviewable change;
discriminator before repair;
real runtime proof before broad abstraction;
small reversible delta before mass refactor;
current accepted identity before status;
error must change future behavior;
full release proof only at the release boundary.
```

ELIOT development is itself an ELIOT workload. The system must observe its own source, active runtime, decisions, failures and conformance gaps. Work is not successful because an agent followed a plan; it is successful when the Product Objective advanced without violating a Hard Boundary. A plan is a revisable hypothesis about execution, not an authority source; a harmful or stale plan is challenged rather than completed ceremonially.

The feasibility of building ELIOT with a small Human team and agent swarm is itself a falsifiable project hypothesis, not an assumed benefit:

```yaml
ProjectFeasibilityHypothesis:
  target_delivery_depth_and_user_value:
  available_human_capacity_and_decision_attention:
  model_tool_compute_and_money_envelopes:
  current_critical_path_and_parallelizable_cells:
  expected_verified_product_or_recovery_deltas_per_review_window:
  activity_to_verified_delta_and_integration_backlog_countermetrics:
  scope_reduction_or_reuse_options:
  review_stop_or_strategy_change_condition:
  owner_and_next_review:
```

No universal team size or calendar threshold is frozen in this book. The Requester/System Owner sets the current envelope. If activity grows while verified product/recovery deltas do not, the default response is scope reduction, reuse, simplification or mechanism review—not stricter ceremony or a larger speculative backlog.

