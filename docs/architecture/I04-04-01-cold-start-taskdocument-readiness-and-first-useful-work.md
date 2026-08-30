### I4.4.1. Cold start, task/document readiness and first useful work

An empty ELIOT corpus is a normal explicit state, not permission to guess. `ColdStartController` is a Governor/WorkScopeResolver capability, not a separate daemon. It is triggered automatically by first UI project open, agent attach/launch, first event on an unknown workspace, explicit onboarding request, stale scope generation or resume without a current task. It compiles `OnboardingReadinessReceipt` before the first scope-sensitive work:

```yaml
OnboardingReadinessReceipt:
  scope_resolution: unbound | provisional | authenticated | ambiguous
  repository_lineage_and_workspace_instance:
  task_binding: none | exploratory | current_task_contract | ambiguous | stale
  task_goal_acceptance_and_owner_refs:
  source_document_candidates:
    discovered:
    admitted_authoritative:
    conflicting_or_stale:
    omitted_or_unavailable:
  source_build_runtime_and_store_identity:
  privacy_authority_and_route_profile:
  truth_surface_and_verifier_readiness:
  memory_state: empty | partial | current | contaminated | unknown
  minimum_understanding_seed:
  missing_inputs_and_safe_allowed_actions:
  recommended_onboarding_dreamer_and_maintenance_jobs:
  governing_source_set_ref:
  state_fence_and_expiry:
```

Cold-start compilation is single-flight per exact candidate workspace identity and governing-source generation:

```yaml
OnboardingLease:
  lease_id_and_installation:
  repository_lineage_candidate:
  workspace_instance_candidate:
  governing_source_generation:
  compiler_owner_and_epoch:
  waiting_sessions_attempts_and_requests:
  state: DISCOVERING | RESOLVING | COMPILING | READY | AMBIGUOUS | FAILED | EXPIRED
  candidate_scope_and_task_refs:
  expiry_cancellation_and_terminal_receipt:
```

Compatible concurrent attaches join the same lease and receive the same `OnboardingReadinessReceipt`. Candidates with different filesystem/VCS identity, privacy boundary or governing-source generation never coalesce merely because directory names/remotes are similar. No worker independently creates a second WorkScope or “latest task” while the lease is active. A changed root, dirty-base identity or governing source invalidates the compiled readiness and creates a new revision rather than mutating the old receipt.

The deterministic bootstrap searches only authenticated roots or roots covered by the limited `DiscoveryReadLease` of I4.2 for likely governing sources—task brief, README, AGENTS/instructions, Architecture/Implementation, manifests, build/test documentation, schemas and recent change evidence. File names create candidates, not authority. Conflicting project documents become a Conflict Set; a model summary cannot choose the winner silently.

```yaml
GoverningSourceSet:
  scope_and_task_revision:
  sources:
    - exact_handle_and_digest:
      role: user_task | architecture | implementation | agent_instruction |
            build_test_contract | domain_policy | supporting_reference
      owner_or_authority_basis:
      applicable_scope_and_generation:
      precedence_or_conflict_rule:
      status: admitted | candidate | stale | superseded | conflicted | unavailable
  unresolved_conflicts_and_required_owner:
  coverage_and_explicit_absence:
  state_fence_and_expiry:
```

A source becomes governing because an applicable authority/contract says so, not because of its filename, recency, location or model summary. Architecture/Implementation precedence is used only where the project has declared that normative pair. Other projects may have a different source model. The agent receives the resolved set, conflicts and missing coverage; it never invents precedence locally.

Task intake is explicit. If no current TaskContract exists, UI/agent/host may submit a `TaskIntakeCandidate`:

```yaml
TaskIntakeCandidate:
  proposer_principal_session_and_route:
  user_goal_or_explicit_exploratory_question:
  acceptance_or_expected_artifact:
  constraints_non_goals_and_risk_preferences:
  proposed_scope_and_source_handles:
  decision_owner_and_task_controller_candidate:
  source: human_ui | agent_explicit | host_visible_prompt | resumed_work | import
  confidence_and_missing_fields:
```

Host-visible prompt text is an observation and privacy-bounded candidate, not automatic user authority. A task becomes current only after the applicable Human/Task owner or an existing delegated task binding admits it. An agent-facing `TASK_SELECTION_REQUIRED` response contains the minimal valid intake example and may offer a bounded `exploratory` task that cannot perform scope-sensitive Material effects.

Before a Material project change, ELIOT must have at least:

```text
authenticated WorkScope/workspace identity;
a current TaskContract or an explicit bounded exploratory task;
user goal/acceptance and decision owner;
minimum governing-document/source coverage with exact handles, or an explicit evidence-backed `no governing document found/not applicable` state;
current source/workspace generation;
applicable privacy/authority;
one usable truth surface or an honest no-proof disposition.
```

Read-only orientation, source discovery, safe capture and probes needed to reach that state are allowed earlier. A project is not forced to create a README/Architecture merely to satisfy the scanner: explicit absence or non-applicability is valid when the TaskContract, source and truth surfaces provide sufficient grounding. Missing task data returns `TASK_SELECTION_REQUIRED`; several plausible tasks/scopes return `AMBIGUOUS_RESULT`; missing context/proof returns a typed onboarding directive rather than a generic refusal. The Human or active agent can bind the task and documents directly. Dreamer may synthesize a charter/orientation candidate only after exact sources are admitted and can ask one concise clarification; it cannot invent project purpose or acceptance.

The controller has an explicit readiness lifecycle:

```text
UNSEEN → SCANNING → NEEDS_SCOPE | NEEDS_TASK | NEEDS_SOURCES |
READY_READ_ONLY | READY_MATERIAL | DEGRADED | CONFLICTED.
```

The current state is returned to the agent and Human surface; it is not buried in a setup log. `READY_READ_ONLY` permits orientation/probes/capture but not scope-sensitive mutation. `READY_MATERIAL` is always tied to one TaskContract revision and ScopeBindingGuard receipt. If the user starts an external agent before onboarding completes, ELIOT attaches it in a bounded exploratory role and asks the smallest missing question rather than silently creating a broad task.

The receipt also proposes, but does not silently start, useful first maintenance: Dreamer Orientation, exact code/build map, Skill/bridge registration, backup verification or a code-intelligence pilot. Automatic execution depends on the user’s maintenance/model budget policy. When automation is disabled or no model budget exists, one deduplicated Human-board maintenance recommendation remains visible until accepted, waived or superseded.

