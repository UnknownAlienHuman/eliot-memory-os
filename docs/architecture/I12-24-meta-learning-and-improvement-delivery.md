## I12.24. Meta-learning and improvement delivery

ELIOT improves through evidence-backed advice, agent work and reversible experiments. It never silently rewrites code, policy or memory authority.

Learning has two loops (A14.5). The existing `ImprovementCandidate` pipeline below is the **outer** loop. The inner loop runs inside one active task and is represented by three durable learning records plus one immutable derived state view and one immutable activation receipt in this section. None becomes an owner: both loops reuse Durable Jobs, `AgentAttempt`, canonical records, registered evaluators, Context Compiler delivery and Governor admission. Neither loop creates a second task graph, attempt journal, scheduler, memory owner or authority path.

Mutable behavioral state is layered, and a lower layer never acquires authority over a higher one:

```text
Frozen Constitutional Anchor  user objective, values, Architecture, Hard Boundaries,
                              authority/privacy/cost ceilings, canonical write and finish semantics;
Stable Product Harness        accepted ELIOT generation and contracts;
Task-Family Harness           validated reusable recipe/profile for a compatible task class;
Campaign Overlay              rapidly changing task-local executable/behavioral state;
Attempt Working State         ephemeral reasoning, scratch artifacts and next action.
```

`Frozen` means fixed for the exact campaign/task-definition revision. An authorized change to objective, Architecture, boundaries or ceilings supersedes that baseline, creates a new State Fence and forces revalidation; it does not make Architecture globally immutable.

```yaml
ImprovementCandidate:
  candidate_id:
  trigger_problem_or_metric:
  evidence_and_trace:
  affected_scope/task_family/module:
  root_cause_hypotheses:
  proposed_change:
  expected_delta:
  counter_metrics:
  validity_scope:
  owner_and_decision_authority:
  delivery_target:
  canary_plan:
  rollback:
  stop_condition:
  lifecycle: proposed | triaged | accepted_for_experiment | running |
             supported | narrowed | rejected | rolled_back | stale | archived
```

Triggers:

```text
repeated failure/repair or no-progress loop;
false block/false positive;
context/retrieval/memory-transformation regret;
module/route/recipe drift;
accepted `ImplementationDeviation`;
Human/agent complaint;
security incident;
Architecture/Implementation/runtime conformance gap;
positive surprise with plausible reusable value: unexpected success, cheaper path, correct abstention,
  useful environment discovery, better decomposition or verifier choice;
successful transfer or evidence that an existing procedure is unnecessary;
Dreamer/Watchdog/Concilium suggestion.
```

Pipeline:

```text
instrumental signal/outcome
→ durable Problem or evidence set
→ Dreamer/Concilium analysis only when semantic work adds value
→ deduplicated Improvement Candidate
→ concise Improvement Brief to active Main Agent or Human at a safe boundary
→ decision owner selects reject / investigate / work item / experiment
→ isolated worktree or candidate Module generation
→ fixed replay as diagnostic evidence only
→ affected checks + matched-budget live shadow/canary on untouched work
→ delayed outcome/rework/maintenance window and rollback reconciliation
→ promote, narrow, rollback or archive
→ update external inheritance and route/module profiles.
```

`ImprovementBrief` shows problem, evidence, likely benefit, risk, proposed owner, cost, next reversible step and what remains unknown. The named decision owner does not search raw metrics.

Replay-only evidence cannot promote a policy/module/Skill/retrieval change. The evaluation record binds the single canonical `BudgetEquivalenceLedger` and `ComplexityEconomicsDelta` contracts of I18.47. Actual compute/tool/test-time-scaling/Human costs, frozen same-budget and compute-matched alternatives, replay→live transfer and delayed harms remain visible. An unmatched ledger or inconclusive complexity delta cannot promote the candidate merely because replay or a local metric improved.

Application classes:

```text
advisory
  default; changes nothing until owner acts;

pre-authorized reversible tuning
  bounded parameter/ranking/application-queue profile or `ContextRecipe` inside a declared safe range;
  one experiment per control surface, automatic rollback;
  never changes authority, privacy, finish semantics, Decision Safety Floor, ContextAtomPolicy,
  verifier definition, canonical durability, Kernel/Watchdog reserve or last-resort recovery capacity;

code/module/config change
  normal work item, impact tests, immutable candidate, canary and rollback;

schema/authority/verifier/privacy/Architecture/destructive forgetting
  explicit owner decision and corresponding migration/proof.
```

External research or foreign-project findings enter this pipeline only as `KnowledgeTransferCandidate`, a typed view of `ImprovementCandidate` that binds source scope/population, transfer limits, local discriminator, target task family, expiry and forbidden direct instruction use. It may yield a Skill, procedure, Default, FailureFingerprint or rejected transfer only after local evidence; source repetition or prose quality does not promote it.

### `CampaignLearningStateView`

Compact immutable view from which the next materially comparable attempt is compiled. It is generated from exact existing owner revisions; it is not a transcript, mutable campaign aggregate, scheduler, journal or new semantic owner.

```yaml
CampaignLearningStateView:
  view_id_revision_and_built_at:
  campaign_task_recipe_and_state_fence:
  source_owner_revisions:
    task_controller_objective_acceptance_plan_and_open_items:
    agent_attempt_lineage_and_latest_outcomes:
    governor_admission_authority_epoch_and_policy_snapshot:
    context_compiler_recipe_tool_surface_and_delivery_revision:
    evaluator_contract_holdout_and_result_refs:
    memory_experience_and_artifact_projection_refs:
  frozen_anchor_digest:
  stable_and_task_family_harness_refs:
  active_campaign_overlay_ref:
  current_position:
    objective_acceptance_open_items_and_next_safe_action:
    active_hypotheses_rivals_unknowns_and_confounders:
    active_candidate_parent_branch_and_next_discriminator:
  experience_position:
    attempt_lineage_failure_signatures_and_exact_trace_handles:
    relevant_prior_campaign_or_task_family_learning_refs:
    bounded_campaign_experience_retrieval_plan_refs:
    preserved_success_set_or_constraints_ref:
  adaptation_position:
    latest_attempt_learning_delta_and_changed_surfaces:
    local_updates_pending_revalidation:
    reusable_candidate_and_rejected_or_expired_update_refs:
  evaluation_position:
    applicable_gate_results_noise_uncertainty_and_holdout_integrity:
  economics_and_progress:
    tokens_cost_wallclock_tools_human_attention_and_verified_delta_history:
    equivalent_retry_failure_plateau_and_intervention_state:
  completeness_scope_and_required_fields_ref:
  completeness: COMPLETE_FOR_DECLARED_RECIPE | PARTIAL | STALE | BLOCKED
  missing_or_stale_owner_refs:
  invalidation_expiry_and_rebuild_reason:
```

The history slice is compiled through one or more campaign-scoped `RetrievalPlan` records from I12.26. It may expose exact handles, bounded summaries, diffs or raw slices permitted by disclosure/retention policy, but it never copies the full campaign into a second store. A future object named `CampaignExperienceView` may be admitted only as a read-only generated projection over the same canonical records after its P2 Product Proof; it cannot become a memory owner or mutable campaign aggregate.

`COMPLETE_FOR_DECLARED_RECIPE` means only that every field required by the bound recipe/revision and State Fence is present and current; it never means complete history, complete world knowledge or complete evidence. The view never accepts writes and never resolves disagreement between owners. Context Compiler verifies every load-bearing revision and State Fence before use. `PARTIAL` may support a narrower safe attempt only when omitted fields are explicitly non-load-bearing; `STALE`/`BLOCKED` cannot be silently filled from a transcript, model memory or a convenient current file. A new owner revision rebuilds the view rather than mutating it in place.

### `AttemptLearningDelta`

The durable edge from one consequential attempt to the next materially related attempt. Without this edge an attempt may store a failure, open a candidate and still repeat the same strategy.

```yaml
AttemptLearningDelta:
  delta_id_revision_campaign_attempt_and_state_fence:
  actor_route_overlay_and_artifact_identity:
  before:
    hypothesis_prediction_and_selected_strategy:
    expected_observable_and_verifier:
  observed:
    raw_trace_and_artifact_refs:
    evaluator_outcome_and_actual_effect:
    coverage_noise_and_unknowns:
  interpretation:
    supported_and_contradicted_mechanisms:
    confounders_and_shared_changed_surfaces:
    attribution_ceiling:
  next_behavior_delta:
    changed_hypothesis_strategy_or_abstraction:
    changed_context_memory_skill_tool_or_route_use:
    changed_candidate_parent_verifier_order_or_search_probe_stop_condition:
  retry_relation:
    materially_equivalent_to_prior_attempt: true | false | unknown
    unchanged_retry_reason: replication | noise_estimation | controlled_comparison |
                            exact_reproduction | recovery_proof | verifier_calibration | none
  persistence:
    overlay_revision_ref_and_reusable_candidate_refs:
    activation_scope_expiry_and_rollback_condition:
  disposition: LOCAL_UPDATE_ADMITTED | NEXT_PROBE_CHANGED | REUSABLE_CANDIDATE_OPENED |
               NO_JUSTIFIED_CHANGE | INCONCLUSIVE | INVALID_EVIDENCE
```

Actor/Refiner may propose interpretation and next-behavior fields; immutable attempt/evidence owners supply their references, and Governor admission is required before any behavioral effect. The record is not a second attempt journal and cannot rewrite source evidence, task truth or evaluator state.

A consequential boundary is a material implementation attempt, a verifier outcome, a substantial recovery attempt, a repeated failure signature, a campaign checkpoint or plateau, a route/model handoff, an accepted artifact outcome, a finish/cancel/supersession, or a delayed regression. A `read_file` or `grep` is not consequential. Most fields are derived from existing attempt and evidence records; the agent is not required to author prose after every step.

### `CampaignHarnessOverlay`

Versioned task-local behavioral artifact that the next attempt is compiled from.

```yaml
CampaignHarnessOverlay:
  overlay_id_revision_parent_and_state_fence:
  stable_and_task_family_harness_base_refs:
  task_framing_and_local_context_recipe_delta:
  task_local_memory_and_working_rules:
  local_skills_checklists_and_helpers:
  tool_surface_and_invocation_delta:
  decomposition_route_and_abstraction_delta:
  verification_order_and_search_probe_stop_rules_delta:
  source_attempt_learning_delta_refs:
  changed_surfaces_and_exact_artifact_refs:
  intended_mechanism_predeclared_prediction_and_expected_observable:
  expected_fixed_tasks_or_failure_signatures:
  possible_regressions_confounders_and_co_changes:
  next_discriminator:
  preserved_success_constraints:
  allowed_effect_and_authority_ceiling:
  validation_status_and_results:
  expiry_invalidation_and_rollback:
```

Actor/Refiner proposes the artifact; Governor admits its local effect; Context Compiler activates it for a compatible attempt. Task Controller and Governor retain objective, plan-revision and authority ownership. The artifact has no independent authority. For every nontrivial revision, the changed-artifact, intended-mechanism, prediction, expected-observable, regression/confounder, preserved-success and next-discriminator fields are frozen **before** evaluation. Together with the source `AttemptLearningDelta`, activation receipt and closure lineage, they carry the donor `HarnessChangeManifest` semantics; no separate mutable manifest or second change owner is created.

Lifecycle:

```text
PROPOSED → SHAPE_VALIDATED → LOCAL_ADMITTED → ACTIVE_FOR_NEXT_ATTEMPT → OBSERVED
→ RETAIN_LOCAL | OPEN_REUSABLE_CANDIDATE | REVISE | ROLLBACK | EXPIRE | INVALIDATE
```

Local admission requires the same user objective and acceptance revision, no authority/privacy widening, no evaluator or sealed-holdout modification, reversible local effect, a named source delta and parent, a next discriminator and a rollback path. An overlay is not canonical doctrine and is not visible to unrelated tasks. It cannot change the user objective, Architecture, Hard Boundaries, authority/privacy/cost ceilings, canonical write or finish semantics, the oracle used to promote the same candidate, sealed holdout answers, the stable production generation, provider identity while claiming a same-route comparison, or its own promotion decision. It may open a candidate to change any of these; it may not apply one as a local shortcut.

A local overlay may change only bounded search or probe stopping rules and verification ordering within the current task plan. It cannot change task-level stop, finish, acceptance, cancellation, budget, or authority policy. Any task-level policy change remains an Improvement or plan candidate, requires a Task Controller plan revision plus Governor admission through the normal authority path, and is never applied by Context Compiler alone.

### `HarnessActivationReceipt`

Immutable per-attempt evidence that records whether the admitted learning surface was eligible, compiled, retrieved and delivered, whether qualifying observable activation occurred, and whether its prescription was followed or violated. Receipt existence never implies successful delivery, use, adherence or benefit. It does not grant authority, schedule an attempt or infer causal benefit.

```yaml
HarnessActivationReceipt:
  receipt_id_revision:
  campaign_attempt_actor_route_and_state_fence:
  compiled_from_campaign_learning_state_view_ref:
  context_compiler_and_render_profile_revision:
  exact_stable_task_family_overlay_skill_memory_and_procedure_refs:
  preserved_success_set_or_constraints_ref:
  eligibility_and_retrieval_reason:
  retrieval:
    status: NOT_ELIGIBLE | ELIGIBLE_NOT_RETRIEVED | RETRIEVED | EXPANDED | UNKNOWN
    expansion_or_tool_query_refs:
  delivery:
    status: NOT_DELIVERED | FULL | PARTIAL | MISSING
    packet_position_serialized_digest_bytes_and_actual_tokens:
  activation:
    status: NOT_ASSESSED | NOT_OBSERVED | OBSERVED | UNKNOWN
    acknowledgement_ref:
    observation_limit_reason:
    first_qualifying_observable_use_ref:
  adherence:
    status: NOT_ASSESSED | OBSERVED_FOLLOWED | OBSERVED_PARTIAL | OBSERVED_VIOLATED | UNKNOWN
    early_mid_final_checkpoint_refs:
    prescribed_or_avoided_action_and_required_verifier_refs:
  conflicts_suppression_or_compaction_loss:
  downstream_decision_action_artifact_and_verifier_refs:
  receipt_completeness_and_missing_fields:
  invalidation_expiry_and_missingness:
```

Retrieval, delivery, observable activation, adherence and outcome remain orthogonal; the fields are not a success ladder. A retrieved update may not be delivered, a delivered update may have no qualifying use observation, and an observed use may violate the prescription or be harmful. An acknowledgement is a delivery/attention signal only and never substitutes for `first_qualifying_observable_use_ref`. `activation.status = NOT_OBSERVED` means only that no qualifying activation evidence was observed; it does not prove non-use. No activation receipt proves adherence, attribution, benefit or promotion. Exact downstream benefit remains subject to I7.27 and I12.34. Missing or inconclusive observability remains `UNKNOWN`, never presumed compliance.

### `CampaignLearningClosure`

Terminal or major-checkpoint consolidation for one campaign.

```yaml
CampaignLearningClosure:
  closure_id_revision_campaign_and_state_fence:
  closure_due_at_expiry_and_terminalized_at:
  closure_owner_and_terminalization_policy_ref:
  starting_and_final_harness_stack:
  outcome_summary:
    artifacts_effects_verifiers_and_solved_scope:
    cost_time_and_human_attention:
    delayed_outcome_status:
  learning_summary:
    validated_local_adaptations_and_rejected_updates:
    failure_mechanisms_closed_or_open:
    preserved_success_and_regression_results:
    activation_and_adherence_findings:
    attribution_and_confounders:
  inheritance_actions:
    first_order_epistemic_updates:
    retained_campaign_local_state:
    reusable_and_structural_candidates:
    negative_memory_and_reopen_conditions:
  disposition: LOCAL_LEARNING_RETAINED | REUSABLE_CANDIDATE_OPENED | SCOPED_UPDATE_PROMOTED |
               NO_REUSABLE_DELTA | INCONCLUSIVE | DEFERRED_OUTCOME | REJECTED_TRANSFER | ROLLED_BACK
  future_activation_scope_retention_and_revalidation:
  owner_receipts_and_expiry:
```

Closure is assembled through existing Meta, Memory OS and Governor paths from canonical evidence. Its disposition records, but never performs, a promotion; `SCOPED_UPDATE_PROMOTED` is valid only with the separate authorized owner receipt it references.

`NO_REUSABLE_DELTA` is a legitimate and explicit disposition: one-off external event, insufficient evidence, existing procedure already covered the case, mechanism not identified, update cost above expected value, unsafe transfer, task too unique, or immature product outcome. Silence is not a disposition, because it hides lost learning.

Closure does not block the finish ceremony. A task may reach an honest `FinishDecision` while learning closure completes asynchronously, provided raw evidence is durable, the next task cannot silently use an unclosed candidate, learning debt is visible and an owner/review condition exists. A consequential episode is not learning-closed until it has a disposition.

Before closure, only the exact non-expired `LOCAL_ADMITTED` overlay of the active campaign may influence a compatible attempt. A draft delta, unclosed reusable candidate, expired overlay, or ownerless learning record is ineligible for retrieval, delivery, compilation, or use by another task. Cross-task carryover requires a new governed admission that revalidates scope, authority, retention, evaluator, and rollback. Expiry invalidates influence; it does not silently retain the last behavior.

Active candidate backlog is bounded by target surface and value. Duplicates merge by evidence lineage; stale/ownerless low-value candidates are summarized and archived. Advice quality is measured by adoption, verified delta, regressions, false positives, Human/agent attention cost and rollback rate. Repeatedly disproven advice loses priority; report polish creates no weight.

### D1 named-record disposition and rollout gates

The D1 donor's named objects are not silently dropped or implicitly admitted. The following table is the authoritative disposition for those names; it separates preservation of a mechanism from admission of a new schema/owner.

| D1 name | Disposition | Current normative mechanism | Admission/rollout boundary |
|---|---|---|---|
| `CampaignLearningState` | **MERGED / RENAMED** | immutable generated `CampaignLearningStateView` over exact existing owner revisions | P1 target contract; no mutable aggregate, store, scheduler or journal |
| `CampaignExperienceView` + `ExperienceQuery` | query mechanism **MERGED**; separately named view **DEFERRED** | campaign-scoped `RetrievalPlan` in I12.26 plus bounded result handles in `CampaignLearningStateView` | named read-only view may be admitted at P2 only after measured need/Product Proof; never a canonical memory owner |
| `HarnessChangeManifest` | **MERGED** | pre-evaluation frozen fields on `CampaignHarnessOverlay`, source `AttemptLearningDelta`, activation receipt and closure lineage | no separate mutable manifest or change authority |
| `FailureMechanismCluster` | named schema **DEFERRED** | exact failure signatures, supported/contradicted mechanism hypotheses, rivals, confounders and next discriminators remain in existing attempt/delta/evidence records | P2 only after clustering precision, correction path and owner seam are proved; similarity alone cannot create mechanism truth |
| `PreservedSuccessSet` | mechanism **REQUIRED where applicable**; separately named view **DEFERRED** | `preserved_success_set_or_constraints_ref`, frozen regression constraints and existing evaluator/holdout owners | P3 admission requires a bounded selection rule, sealed-case handling, expiry/requalification and demonstrated forgetting detection |
| `TaskFamilyHarnessPortfolio` | **DEFERRED** | current stable/task-family harness revision references and existing router/profile evidence | P3 only after bidirectional transfer, retention, routing and complexity/cost evidence; no portfolio owner is implied now |
| `LearningPlateauSignal` | **MERGED** | `CampaignLearningStateView.economics_and_progress`, I16.23 no-progress telemetry, Watchdog observation, Task Controller plan revision and Governor admission | no new mutable signal owner; a later generated view must preserve the same owner separation |
| `LiveLearningDevelopmentCampaign` | alias **REJECTED** | canonical recipe name is `LiveLearningCampaign` | a second recipe/task/scheduler identity is forbidden |

`DEFERRED` above applies to the named schema/rollout level, not to the underlying requirement. Exact history access, pre-evaluation change lineage, preserved-success constraints, plateau detection and task-family boundaries remain represented by their current owners. Equivalent fields do not authorize an undeclared root record, table, scheduler, task graph, evaluator, promotion authority or global harness state.

