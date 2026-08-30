## I14.22. Maintenance jobs

Registered maintenance families:

```text
backup/restore rehearsal;
blob GC/reachability;
outbox/receipt reconciliation;
projection/index rebuild;
cue/concept/graph maintenance;
Dreamer curation;
calibration/understanding exam;
integration/capability survey;
security/dependency scan;
derived-index reference/differential rebuild;
SessionEpisode cursor/retrieval maintenance;
grant/disclosure closure reconciliation;
donor/conformance audit;
self-quality, feedback and maintenance-debt review;
external Research exchange cleanup/requalification.
```

A maintenance job may originate from:

```text
explicit Human UI/CLI request;
accepted Dreamer `MaintenancePlanCandidate`;
Watchdog/Doctor Problem or recovery recipe;
first-run/onboarding recommendation;
Human-approved idle/scheduled policy;
installation/update/migration transaction.
```

Human policy selects one `MaintenanceAutomationMode` per family:

```text
off                — no automatic job or proactive recommendation, except mandatory safety/recovery obligations;
suggest_only       — create/deduplicate a Human-board recommendation;
manual             — run only after explicit request;
idle_only          — run while no conflicting interactive work exists;
scheduled          — run at approved windows through Task Scheduler/Host wake;
continuous_bounded — maintain a small admitted backlog under fixed resource/model ceilings.
```

The Governor-owned `MaintenanceTriggerEvaluator` is the single producer of these decisions. It runs on admitted problem/signal/self-observation events, cold-start completion, idle transition, scheduled wake and startup reconciliation. It is a deterministic capability of `eliotd`, not a second scheduler: it may emit a decision, Human-board item or Durable Job request, while Ready Queue/Agent Coordinator/installer/Doctor retain execution ownership. If the evaluator is unavailable, the relevant trigger remains durable and is surfaced on the next startup; safety/recovery triggers use their existing protected paths.

One derived `AutomationTriggerDecision` makes the start behavior inspectable; it is not a new scheduler or authority:

```yaml
AutomationTriggerDecision:
  trigger_event_and_evidence:
  affected_scope_problem_or_family:
  deterministic_action_now:
  optional_dreamer_watchdog_agent_doctor_or_swarm_job:
  applicable_maintenance_mode_route_budget_and_user_session:
  decision: start | suggest | defer | suppress_duplicate | block | escalate
  durable_job_or_human_attention_ref:
  expiry_reopen_and_outcome_receipt:
```

When the final observable-use obligation is about to release its Runtime/Supervision lease, `MaintenanceTriggerEvaluator` emits one `EndOfActivityMaintenanceAssessment` before drain admission:

```yaml
EndOfActivityMaintenanceAssessment:
  activation_and_scope_set:
  closed_sessions_attempts_jobs_and_effects:
  pending_observations_feedback_projections_and_receipts:
  maintenance_debt_and_due_policy_families:
  eligible_service_safe_routes_and_budget:
  user_session_required_work:
  decision: no_action | start_bounded_job | schedule_wake | suggest_once | defer
  runtime_or_wake_intent_refs:
  shutdown_may_proceed_and_reason:
  expiry_and_outcome_receipt:
```

The assessment does not keep ELIOT alive merely because data exists. Only an admitted bounded job/active repair acquires a new RuntimeLease; otherwise work is scheduled, suggested once or deferred and drain continues. This is the deterministic bridge from normal use to maintenance, not a permanent background “thinking” loop.

| Trigger | Deterministic action | Optional intelligent work | When automation is unavailable/off |
|---|---|---|---|
| unknown/stale WorkScope, first attach or missing task/sources | run resolver, guard and cold-start receipt | Dreamer Orientation/clarification | show one onboarding action; allow bounded read-only discovery |
| repeated failure, loop/no-progress, missing observations or widening blind interval | open/update signal/problem and preserve evidence | Watchdog Agent, Dreamer diagnosis or Concilium selected by risk/complexity | show one Diagnostic Brief; contain only an exact pre-authorized danger |
| memory/context utility degradation or candidate backlog | compute deterministic health/coverage view | DreamCycle/curation agents | show one curation recommendation; do not silently grow context |
| stale/changed agent, model, tool, MCP, DB or code-intelligence capability | invalidate capability evidence and stop unsupported admission | requalification or managed environment plan | show exact install/update/reprobe action; current verified generation remains |
| idle/scheduled maintenance window | start only admitted service-safe jobs | bounded Dreamer/agent job if route/budget policy permits | checkpoint/defer; no fake completion |
| Doctor attempts exhausted, unknown effect persists or damage accumulates | quarantine dependent scope/module and preserve repair history | strong diagnosis/Concilium if policy permits | persistent Human attention and safe manual entrypoint |
| external knowledge gap | create ResearchQueryRequest or local-source plan | Dreamer synthesis after returned evidence | retain explicit unknown/coverage gap |
| user/Dreamer asks to change configuration or launch agents | compile typed candidate and validate owners/policy | Dreamer plan only; daemon/Agent Coordinator executes | present exact confirmation or reason for deferral |

Each execution is a Durable Job with idempotency, lease, checkpoint, budget, cancellation, progress and receipt. Paid model calls, swarms, destructive forgetting/purge, configuration publication, software updates and migrations require their separate route/authority policy even when the maintenance family is automatic. Maintenance cannot starve control, active-agent, interactive verification or Product Pulse classes.

Scheduled/background maintenance may use only service-safe routes and credentials explicitly admitted for unattended operation. Subscription-, IDE-, browser- or desktop-bound agents require an active authenticated User Broker plus a separate `interactive_maintenance` policy; otherwise the job checkpoints/defer and leaves one Human-board action. ELIOT does not retain a user desktop credential merely to make a schedule appear successful and does not fake an interactive logon.

If automation is disabled, the required route is unavailable or budget is exhausted, ELIOT preserves one actionable recommendation with reason, evidence, expected benefit, cost, expiry and safe deferral consequence. It does not repeatedly notify or pretend maintenance occurred. Every maintenance result enters the `eliot_system` observation/experience path and is evaluated against recurrence, product/recovery delta, false changes, cost and operator burden; completion of a maintenance job is not evidence that the maintained subsystem improved.

