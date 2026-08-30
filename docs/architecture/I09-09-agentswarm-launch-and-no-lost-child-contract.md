## I9.9. Agent/swarm launch and no-lost-child contract

Dreamer submits `AgentLaunchRequest` or `SwarmPlanRequest` to `eliotd`/Agent Coordinator. It cannot fork processes, invoke a provider, allocate a subscription lane or attach tools by itself.

Every launch origin—Human UI/CLI, Main Agent, Dreamer, schedule, API or recovery recipe—passes one Governor-owned `AgentAdmissionReadinessGate`; no surface may implement a weaker private launch path:

```yaml
AgentAdmissionReadinessDecision:
  request_origin_and_product_identity:
  WorkScopeCandidateSet_and_ScopeBindingGuard:
  OnboardingReadinessReceipt_and_GoverningSourceSet:
  TaskContract_revision_or_exploratory_contract:
  requested_impact_role_tools_effects_and_descendants:
  allowed_mode: READ_ONLY_ORIENTATION | BOUNDED_EXPLORATORY | MATERIAL
  decision: ADMIT | NARROW | NEEDS_SCOPE | NEEDS_TASK | NEEDS_SOURCES |
            NEEDS_CAPABILITY | NEEDS_SUPERVISION | DENY
  exact_missing_input_recovery_and_expiry:
```

`MATERIAL` requires `READY_MATERIAL`, an authenticated scope, current TaskContract/acceptance, applicable governing sources, route/tool capability and the Governance Profile required by the action. `READY_READ_ONLY` may admit orientation, source discovery, safe capture or discriminative probes with no scope-sensitive effect. An external process already doing work uses the attach-reconciliation path rather than retroactive launch admission. This gate is evaluated again after any scope, task, source, route or supervision generation change.

```yaml
AgentLaunchRequest:
  initiating_user_problem_policy_or_dreamer_job_ref:
  objective_task_and_parent_attempt:
  work_units_and_expected_outputs:
  required_competence_and_route_complexity:
  allowed_route_classes_and_native_child_policy:
  RootContextRevision_and_per_attempt_context_budget:
  evidence_tool_and_capability_introductions:
  privacy_cost_time_and_resource_envelope:
  max_depth_fanout_and_cumulative_descendant_budget:
  verifier_synthesis_and_integration_owner:
  cancellation_cleanup_and_escalation:
```

Admission checks:

```text
job class and task decomposition allowed;
provider/model/runtime capability proven on the exact route;
data privacy/disclosure compatible;
budget, context headroom and scarce resources available;
fan-out/depth/cumulative descendants within the parent envelope;
expected value/coverage and stop condition stated;
synthesis, verifier and integration owners present;
Watchdog observation coverage sufficient for the requested impact.
```

Every child is registered as an ELIOT `AgentAttempt` **before** process/provider launch and has exact parentage, route, WorkLease, context/effect envelope, heartbeat/event cursor, usage, cancellation cascade and terminal disposition. Parent termination, route loss or coordinator restart leaves no “lost children”: descendants are cancelled, checkpointed, reassigned or explicitly quarantined/reconciled by identity. A live process or provider session without an admitted attempt is an orphan supervision event and cannot publish effects or proof.

External strong agents may use their native subagent mechanism only when the exact runtime exposes child creation, parentage, route, tool inheritance, cumulative usage, cancellation and results. Otherwise native children are disabled for Material work; the parent must delegate through ELIOT. When a remote/closed runtime cannot expose child-level lifecycle at all, ELIOT may admit only the whole runtime invocation as one **opaque parent attempt** under a top-level cumulative budget, effect ceiling and terminal receipt. It makes no no-lost-child claim below that boundary, gives no independence credit to hidden children and forbids descendant-owned effects/proof. Hidden or unobservable subagents that mutate the workspace or outlive the opaque parent trigger containment/reconciliation and downgrade the route profile.

For Material work, an opaque parent can reach a terminal ELIOT disposition only when capability evidence on the exact runtime fingerprint proves either that the provider terminal event closes all descendant execution, or that every descendant effect is mediated and reconciled through the parent boundary. If this property is absent or contradicted, the route is limited to read-only/candidate work or the attempt remains `UNKNOWN_OUTCOME` through the declared external-effect observation window. A provider “completed” message alone cannot prove that hidden descendants stopped.

Context and budget are enforced per child and cumulatively where the exact runtime exposes an enforcement surface. Children receive only the minimum RootContext overlay and capability facets for their work unit; they do not inherit the parent’s full prompt, credentials or memory. Child swarm cannot expand budget, authority, scope, data class or automatic-launch policy.

Child-resource capability is recorded on separate observation and enforcement axes. A runtime that reports usage but cannot limit it is `OBSERVE_ONLY`: Watchdog may warn, stop/cancel the parent at a visible threshold or deny further children, but ELIOT does not claim a hard context/cost bound. Material/Critical automatic swarm requires either child-level enforcement, a provider/runtime hard cap or an opaque-parent envelope whose worst-case cost/effects are acceptable to Human policy.

