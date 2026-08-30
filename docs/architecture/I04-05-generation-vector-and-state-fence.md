## I4.5. Generation vector and State Fence

One global integer generation is prohibited. `StateFence` contains only load-bearing dependencies.

```yaml
StateFence:
  scope_id:
  resource_generations:
  revision_heads:        # exact dependency-key/revision pairs, not one global scope counter
  authority_epoch:
  integration_revision:
  module_generations:
  verifier_generations:
  created_at:
```

Compiler or admission may add a dependency. Removing an observed or policy-required dependency to preserve authority is prohibited.

`ScopeSnapshot` — immutable operation-local resolution of a scope expression for retrieval, research or another bounded information job:

```yaml
ScopeSnapshot:
  snapshot_id_and_revision:
  resolved_scope_expression:
  participant_scope_and_project_generations:
  member_source_revision_refs:
  policy_authority_and_disclosure_closure:
  purge_ledger_revision:
  state_fence_ref:
  digest_created_at_and_expiry:
```

Every model call, artifact and citation that claims this resolved scope binds the snapshot digest. A purge or newly applicable deny invalidates every dependent snapshot immediately. A member revision purged before execution is excluded when the snapshot is refreshed and cannot re-enter through an older index, cache or summary. The snapshot does not mint scope, authority or source admissibility; it records the exact closure selected by existing owners. When load-bearing, its digest enters `StateFence.revision_heads`.

`SourceView` answers what “current” means before planning or readback. It is selected explicitly rather than inferred from whichever bytes happen to be easiest to open:

```yaml
SourceView:
  kind: working_tree_current | git_index | git_commit | imported_snapshot | retained_revision
  workspace_instance_id:
  workspace_view_revision_ref:
  git_commit_oid:
  imported_snapshot_id:
  retained_revision_id:

WorkspaceViewRevision:
  workspace_instance_id:
  root_filesystem_identity:
  repository_lineage_id:
  head_commit_and_branch:
  git_index_identity:
  inventory_revision:
  worktree_observation_cursor:
  authenticated_ide_overlay_revision:
  ignore_and_source_admission_policy_revision:
```

For `working_tree_current`, precedence is authenticated unsaved IDE buffer, then confirmed saved worktree revision, then the selected published base representation. One compound query uses one workspace-view revision across all branches. Drift forces replan or an explicit stale/incomplete result; results from two revisions are never merged as one coherent answer. These view objects are operation-local dependencies inside the existing State Fence, not a second workspace, publication or canonical-state owner.

An authenticated unsaved IDE overlay is an ephemeral read surface. Unless an explicit save or governed admission creates a new `SourceRevision`, `EvidenceHandle`, or `ArtifactRevision` with a receipt, its bytes MUST NOT enter CanonicalStore, BlobStore, Operational Recovery State, backups, telemetry payloads, provider caches, experience corpora, `AttemptLearningDelta`, `CampaignHarnessOverlay`, Skill or procedure candidates, or any promotion input. Policy may retain only non-reconstructive metadata required to fence the view—digest, size, editor or Session identity, and invalidation cursor. Closing, replacing, or losing authentication for the overlay invalidates every dependent view.

