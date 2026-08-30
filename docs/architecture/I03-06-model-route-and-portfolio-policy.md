## I3.6. Model, Route and Portfolio Policy

```yaml
ModelRolePolicy:
  main_agent_route_classes:
  worker_route_classes:
  auditor_route_classes:
  verifier_model_route_classes:
  watchdog_route_classes:
  dreamer_route_classes:
  independent_review_requirements:
  local_only_data_classes:
  external_allowed_data_classes:
  per_job_task_period_budgets:
  active_quota_windows:
  max_active_lanes:
  max_writers_per_deliverable:
  max_swarm_fanout_and_depth:
  native_child_policy:
  auto_launch_job_classes:
  human_approval_classes:
  preview_beta_policy:
```

Human selects **assurance and cost intent**, not a permanent model proportion. Built-in presets:

```text
economy   — one cheap worker; review only on risk/failure;
balanced  — one writer plus conditional independent review;
assurance — one writer plus mandatory blind cross-family audit;
research  — incremental read-only evidence fan-out and synthesis;
incident  — bounded rival-hypothesis lanes, strong logging and escalation.
```

Actual staffing and route mix are plan receipts for a task class, computed from current capability evidence, task outcomes, quotas, machine capacity, privacy and independence. A static global ratio such as “70% model A / 20% model B / 10% model C” is forbidden as a production default.

DEFAULT route classes are capability-based:

```text
bulk_implementation;
architecture_reasoning;
independent_blind_audit;
fast_read_only_scout;
watchdog_diagnostic;
dreamer_curation;
dreamer_orientation;
research_synthesis;
subjective_evaluation.
```

Dreamer, Watchdog, child agents and native runtimes cannot expand this policy or create budget. An unavailable class yields explicit defer/degrade/escalate behavior; it never silently spends more, changes provider mid-attempt or sends a higher privacy class externally.

