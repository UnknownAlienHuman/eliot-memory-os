## I12.13. Context Compiler

Pipeline:

```text
Task frame
→ Critical Attention and hard constraints
→ Current Epistemic Position
→ goal/semantic/causal model
→ active plan/continuity
→ invariants and negative memory
→ exact evidence and unknowns
→ available tools/authority
→ next boundary and verifier
→ decision-local tail.
```

Each candidate receives:

```text
scope fit;
freshness;
epistemic support;
source assurance;
expected decision delta;
risk/negative-memory value;
unknown/probe value;
route accessibility;
token/position cost;
distraction/repetition penalty.
```

The ordering, feature configuration, layout and budgets are selected by a versioned `ContextRecipe` owned by Context Compiler:

```yaml
ContextRecipe:
  recipe_id_revision_and_digest:
  applicable_task_route_impact_and_governance_profiles:
  stage_graph_and_order:
  candidate_feature_configuration:
  admission_and_suppression_policy:
  instruction_directive_evidence_tool_and_result_budgets:
  protected_reasoning_review_and_margin_reserve:
  layout_position_and_repetition_policy:
  omission_and_expansion_policy:
  scorecard_blocking_dimensions:
  execution_contour_and_generation:
  empirical_qualification_and_counter_metrics:
  parent_supersession_kill_and_rollback:
```

A recipe cannot weaken Decision Safety Floor, ContextAtomPolicy classes, authority/privacy, active Recovery/Conflict Directives, reversible omission or proof ceilings. It may be changed only as an Improvement Candidate through replay, shadow/canary and rollback. `ContextEconomyReceipt` binds the exact recipe revision.


Each semantic role is budgeted in whole, addressable units rather than arbitrary token slices:

```yaml
ContextSectionBudget:
  semantic_role:
  unit_boundary_kind:
  minimum_required_whole_units:
  protected_floor_or_required_refs:
  planning_maximum_and_route_profile:
  omission_or_handle_policy:
  degradation_behavior:
  disable_feature_when_floor_cannot_be_preserved:
```

Examples of whole units are an EvidenceAtom, ClaimCard, ToolDefinition, source-catalog entry, WorkItem, completed causal stage or Architecture/Implementation anchor. A JSON object, URL, source identity, tool call/result pair or evidence edge may not be cut into a syntactically valid but semantically false fragment.

Before filling optional context, Context Compiler requests the applicable `DownstreamHeadroomReservation` owned by I14.29. A swarm fan-out leaves reducer/verifier budget; acquisition leaves synthesis/output budget; a long packet leaves a decision-local tail and response/tool-result headroom. If required headroom and the Decision Safety Floor cannot coexist, the task is decomposed or narrowed rather than filled to the nominal window.

Compaction and transformation priority are evidence-based, not a permanent list of names:

```yaml
SemanticSensitivityProfile:
  route_task_family_and_context_recipe:
  item_class_or_feature:
  ablation_replay_and_transfer_evidence:
  fidelity_floor_and_failure_signatures:
  allowed_transformations_and_precision_ceiling:
  dependencies_expiry_and_requalification:
```

Goal/acceptance, authority/effect scope, State Fence, primary anchors, strongest counterevidence, exact failure/discriminator, privacy boundary and stop/revisit conditions begin conservatively, but their profile still requires replay/ablation evidence. The same mechanism prevents a verbose early source from consuming every slot before rivals, unknowns and negative evidence are represented.

Decision: include payload, include handle, warn, require revalidation, suppress, quarantine. The synchronous compiler uses only stored/precomputed features and exact relations. An unknown expected decision delta is not negative evidence and cannot by itself justify suppression; uncertain but potentially load-bearing material is kept as a handle, warning or explicit coverage gap.

Each compiled View emits a vector `PacketQualityScorecard`:

```text
acceptance/decision coverage;
causal and operational sufficiency;
exact-anchor/provenance coverage;
freshness and State Fence coherence;
visibility of rivals, conflicts and unknowns;
negative-memory/invariant coverage;
verifier/action readiness;
route-specific accessibility/layout risk;
instruction_sufficiency: governing instructions, active directives, non-goals and applicable negative memory;
payload, handle and reconstruction cost;
known omissions and expansion paths;
telemetry/measurement cost and coverage.
```

No scalar packet score may hide a load-bearing failed dimension.


### Boundary metadata and format-preserving degradation

Packing, batching, compaction and swarm reduction preserve semantic boundaries explicitly:

```yaml
BoundaryMetadataEnvelope:
  logical_units_and_order:
  source_attempt_stage_and_owner:
  scope_task_and_state_fence:
  provenance_disclosure_and_influence_closures:
  exact_start_end_or_member_handles:
  omission_and_expansion_refs:
  completeness_and_precision:
  transformation_revision:
```

A packed representation cannot merge adjacent tasks, documents, tool outputs, source families or causal stages merely because the byte/token shape is convenient. Boundary loss is a visible transformation defect.

Degradation is whole-unit and operation-specific. If a unit's required metadata, source, precision or semantics cannot be preserved, ELIOT chooses one explicit disposition:

```text
retain exact handle only;
return a narrower extractive view;
mark the whole unit incomplete/unsupported;
route to a compatible contour;
block only the dependent decision/effect.
```

It may not silently mix exact and degraded fields in a way that makes the logical unit appear complete. Enrichment is additive: derived summaries, graph hints and generated prose never replace the exact retained source or reduce its disclosure/influence lineage.

For multi-source packets, bounded evidence allocation prevents one verbose source/agent/tool from exhausting the entire view before load-bearing rivals, unknowns or negative evidence are represented. Allocation policy remains a versioned `ContextRecipe` and is evaluated by decision/outcome delta rather than equal-token aesthetics.

### Selection integrity

`ARCH-CTX-04` requires that retrieval proposes and the compiler admits. The risk is that untrusted content changes **membership** rather than instructions: a document that inflates its own relevance, a tool result that displaces a competing source, or a summary that quietly drops the counterexample.

Every membership-changing transformation — ranking, pruning, deduplication, summarization, context compilation and export — appends an immutable stage to one chain receipt:

```yaml
SelectionIntegrityReceipt:
  receipt_identity_root_context_recipe_and_state_fence:
  initial_candidate_count_digest_and_taint_summary:
  transform_stages:
    - ordinal_transformer_identity_and_config_digest:
      input_membership_count_and_digest:
      output_membership_count_and_digest:
      admitted_and_rejected_candidates_with_reason:
      untrusted_input_influenced_membership: true | false | unknown
      suppressed_counterevidence_or_minority_items:
      budget_or_policy_forced_omissions:
  final_selected_set_count_digest_and_packet_or_export_ref:
  expansion_handles:
```

A stage may append but never overwrite an earlier membership decision. `untrusted_input_influenced_membership = unknown` is admissible and is itself a finding: it lowers the claim ceiling of the resulting packet instead of being resolved by assumption.

