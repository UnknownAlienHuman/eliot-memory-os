## I11.12. UserAutomation

`UserAutomation` is a first-class user-owned one-shot or recurring intent/configuration object over the existing Task Scheduler, `WakeIntent` and Durable Job contracts. It is a product capability, not `MaintenanceAutomationMode`, and it creates no scheduler, task graph, attempt journal, route owner, canonical writer or authority path.

```yaml
UserAutomationRevision:
  automation_id_revision_and_supersedes:
  owner_principal_and_workscope:
  natural_language_intent:
  normalized_schedule:
    kind: one_shot | recurring
    expression_and_calendar:
    timezone_and_dst_fold_gap_policy:
    start_end_and_next_occurrence_projection:
  mode: agent | deterministic_process
  task_template_or_qualified_script_ref:
  portable_skill_package_revision_refs:
  workdir_and_workscope_binding:
  route_reasoning_and_cost_policy:
  expected_provider_model_and_adapter_fingerprints_or_allowed_set:
  delivery_target:
  preflight_contract_revision:
  budget_deadline_and_resource_ceiling:
  concurrency_policy: forbid_overlap | queue_one | coalesce_latest
  recursion_policy_and_max_child_depth:
  configuration_state: active | paused | blocked_config | retired
  current_execution_refs:
  execution_history_query_ref:
```

The original natural-language request remains visible, but the normalized schedule is the trigger contract. Before activation the Human surface shows timezone, DST fold/gap behavior, next occurrences, work scope, route/cost ceiling and delivery target. An ambiguous calendar phrase is not silently guessed. An edit creates a new immutable revision and invalidates not-yet-admitted wake intents of the superseded revision.

Every trigger compiles one stable `AutomationOccurrenceIdentity` from the automation revision and exact calendar occurrence; `run-now` uses an explicit manual nonce and does not mutate the schedule. Duplicate wake/restart events resolve to the same occurrence. Task Scheduler may wake Host only from the admitted intent; the `WakeIntent` itself grants no task, route, tool, effect or delivery authority.

Before any model call, a deterministic `AutomationPreflightReceipt` validates:

```text
current configuration state and occurrence claim;
principal, WorkScope, workdir and State Fence;
task template or qualified script identity;
exact trusted/current Skill package revisions and Tool Definitions;
provider/model/adapter fingerprint, credentials and Human route/cost policy;
delivery capability and disclosure policy;
budget, deadline, overlap, recursion and unresolved-prior-effect rules.
```

A configuration failure enters `blocked_config`, makes zero model calls and updates one deduplicated actionable notification. Unexpected provider/model drift fails closed unless the Human policy already admitted the observed compatible set; there is no silent route substitution. Transient capacity failure may defer the occurrence without rewriting configuration truth.

Agent mode creates the normal admitted task/attempt/job path. Deterministic mode executes only a qualified script/process whose capability profile excludes model-provider access; it never calls an LLM directly, indirectly or through a fallback. Exact stdout/stderr are delivered verbatim when within policy/size limits, otherwise through the reversible payload contract of I7.26; neither path uses model summarization, and bytes are evidence rather than implicit truth. In both modes, route/effect authority and verification remain with their existing owners.

Configuration state and execution state are separate. `active` may coexist with one currently running occurrence; `current_execution_refs` is a projection of the canonical Durable Job lifecycle in I14.20, not another lifecycle. The execution history remains immutable Durable Job/effect/receipt history. `pause` stops future admission but does not silently cancel an already admitted job; cancellation is an explicit operation. `remove` retires/tombstones the automation, cancels only unadmitted future wakes and preserves history plus outstanding reconciliation obligations.

Supported user operations are:

```text
create; list/status/history; pause/resume; edit; run-now; remove; inspect last failure.
```

The same occurrence is never blindly rerun after `UNKNOWN_OUTCOME`; I14.21 reconciliation decides its disposition. A later calendar occurrence is a different identity but is blocked when unresolved prior effects violate the declared overlap policy. By default an automation execution cannot create, edit, resume or trigger another automation; scheduling authority requires a separate exact Human-approved operation, so scheduler jobs cannot recursively manufacture scheduler jobs.

Delivery is requested through the declared target and canonical outbox; delivery failure does not rerun the task/model/tool effects and does not rewrite job completion. A repeated failure class updates one persistent notification keyed by automation revision and failure fingerprint. It does not emit one alert per occurrence; a material revision, verified recovery or Human disposition reopens that notification key.

