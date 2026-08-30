## I5.8. Canonical event and projections

The event journal is the audit and rebuild source, while normal reads use projections.

```yaml
CanonicalEvent:
  event_id:
  operation_id:
  scope_id:
  ordering_links:
    - ordering_scope:
      ordering_sequence:
      previous_event_hash:
      event_hash:
  event_ordinal:
  event_type:
  payload_ref:
  principal:
  authority_epoch:
  state_fence:
  occurred_at:
  committed_at:
```

A transition touching several Ordering Scopes has one immutable semantic event identity and one chain link per affected scope. Each link hashes the same event identity/payload plus its scope, sequence and previous link. This preserves one atomic transition without pretending that several causal streams share one head.

Projection rebuild is a Doctor recipe, not a normal write path.

Every derived projection is published through one `ProjectionPublicationRecord`:

```yaml
ProjectionPublicationRecord:
  projection_kind_and_generation:
  projection_definition_digest:
  dependency_definition_digest:
  source_generation_and_cursor:
  source_revision_heads:
  state_fence:
  publication_mode: FULL | DELTA | REFERENCE_FALLBACK
  selection_basis_and_whole_DAG_cost:
  full_cost_estimate_and_observed_cost:
  delta_cost_estimate_and_observed_cost:
  semantic_equality_oracle_ref:
  atomic_data_and_provenance_commit_ref:
  sink_acceptance_and_readback_refs:
  arrival_and_claim_fences:
  provenance_manifest_ref:
  visible_lag_checkpoint_and_error:
  split_view: NONE | DETECTED | RECONCILING
  assurance_ceiling:
  status: PENDING | CURRENT | STALE | FAILED | INCONCLUSIVE
```

A derived `ProjectionMaintenanceDecision` chooses `FULL`, `DELTA` or the exact/reference fallback from measured whole-dependency cost, equality risk, source churn and recovery cost:

```yaml
ProjectionMaintenanceDecision:
  projection_kind_definition_and_dependency_digest:
  source_and_target_state_fences:
  mode: FULL | DELTA | REFERENCE_FALLBACK
  whole_dependency_DAG_cost_and_tail_profile:
  changed_rewritten_and_logical_row_fraction:
  layered_logical_WAL_file_device_write_evidence:
  same_fence_equality_oracle:
  source_churn_and_recovery_cost:
  deterministic_fallback:
  publication_and_rollback_plan:
  status: SELECTED | INCONCLUSIVE | REJECTED
```

Changed-row count alone is insufficient. Candidate data and provenance become visible atomically; partial provenance, a stale definition, a mismatched source generation or a split view leaves the projection `PENDING/STALE`. Full and delta paths satisfy the same same-fence equality oracle and publish layered logical/WAL/file/device write numerators separately when storage economics are claimed.

For source/build/behavioral/concept graphs, the canonical fence is:

```yaml
GraphRevisionFence:
  source_product_worktree_and_state_fence:
  source_revision_heads_and_dirty_overlay_digest:
  graph_definition_dependency_and_schema_digest:
  parser_LSP_build_profile_and_adapter_generations:
  covered_relation_and_configuration_scope:
  visible_projection_generation_and_publication_receipt:
  publication_status: BUILDING | CURRENT | STALE | SPLIT_VIEW | FAILED
  reference_path_and_fallback:
  assurance_ceiling:
```

A stale or unknown graph may navigate with an explicit ceiling; it cannot prove absence, non-impact, authority or the Current Epistemic Position. Scope, disclosure and influence closure are checked before candidate generation and again at every pivot, rerank, community expansion, summary, compilation, tool call and export. Final packet filtering does not repair an unauthorized or contaminated candidate set.

Projection state is a rebuildable view and never authorizes a write, action or finish.

