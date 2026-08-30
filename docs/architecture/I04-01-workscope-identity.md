## I4.1. WorkScope identity

`WorkScope` is not an alias for a Git repository. Runtime type:

```yaml
WorkScopeDescriptor:
  scope_id:
  kind: git_repo | directory | document_set | service | remote_system |
        gui_workspace | research_corpus | composite | ad_hoc | eliot_system
  display_name:
  repository_lineage_ref:         # optional for non-repository scopes
  workspace_instance_refs:        # exact local checkouts/worktrees/resources
  owners:
  canonical_resources:
  root_paths:
  external_resource_ids:
  truth_surfaces:
  verifier_ids:
  privacy_profile:
  authority_profile:
  resource_execution_identities: service | interactive_user:<sid> | remote
  generation_vector:
  current_state_fence:
  available_capabilities:
  missing_capabilities:
  lifecycle: provisional | active | suspended | archived
```

Identity fingerprint derives from stable resources, not display name. Git branch and commit belong to the generation, but do not define the WorkScope alone.

### Repository lineage, workspace instance and similar-repository conflicts

Repository identity is split into three layers so that clones, worktrees, forks and similarly named directories cannot be silently merged:

```yaml
RepositoryLineageIdentity:
  lineage_id:
  explicit_eliot_binding_ref:
  vcs_object_store_and_initial_history_evidence:
  normalized_remote_and_fork_relations:
  project_manifest_and_declared_identity_refs:
  known_aliases_relocations_and_supersessions:

WorkspaceInstanceIdentity:
  instance_id:
  installation_and_machine_id:
  root_path_and_filesystem_identity:
  vcs_common_dir_object_store_and_worktree_identity:
  current_head_branch_dirty_generation:
  editor_host_and_process_binding_refs:
  observed_at_and_freshness:

WorkScopeCandidateSet:
  observed_session_cwd_file_and_resource_handles:
  candidate_scope_lineage_and_instance_refs:
  supporting_and_conflicting_evidence:
  exact_memory_task_and_policy_bindings_per_candidate:
  cheapest_disambiguation_question_or_probe:
  disposition: unique | ambiguous | new_scope | stale_binding | conflicted
```

Two checkouts may belong to one repository lineage while remaining different workspace instances. A fork or copied directory may share names and history without sharing ELIOT task/memory authority. `.eliot` markers, remote URLs, folder names and a matching `Cargo.toml` are evidence only; copied markers cannot grant scope authority.

When several similar repositories are present, ELIOT does not union their memory or select the last/nearest/open scope by convenience. It returns `AMBIGUOUS_RESULT`, keeps project-specific memory separated, allows only privacy-bounded read-only discrimination, and asks the Human or active agent the smallest useful question. A confirmed move or additional clone creates a `ScopeRelocationOrAttachReceipt`; it does not rewrite the old root identity or task history.

Memory applicability is also explicit across clones:

```text
lineage_portable
  project charter, stable decision/failure/procedure or source evidence whose scope/generation predicate
  is satisfied by another authenticated instance of the same lineage;

workspace_instance_bound
  dirty-state observations, local paths, running services, generated artifacts and environment facts;

task_bound
  goal, acceptance, current plan, leases, attention and attempt history.
```

A lineage match may propose reuse of `lineage_portable` records, but Context Compiler still checks source generation, branch/config/environment and current evidence. It never transports instance- or task-bound state merely because Git history overlaps.

Legacy records that carry only a display name, old path or repository URL are not attached automatically to a modern lineage. A bounded `ScopeBindingMigrationCandidate` lists the candidate WorkScopes and exact supporting/conflicting evidence. Only an authorized resolution produces a forward `ScopeBindingMigrationReceipt`; unresolved records remain cold/quarantined and are excluded from project-specific automatic context. The old locator remains in provenance so a wrong historical binding can be corrected without rewriting history.

