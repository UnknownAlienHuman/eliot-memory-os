## I4.2. Resolution order

`WorkScopeResolver` uses an evidence-first order:

```text
1. current authenticated Session/Task binding with exact WorkspaceInstance identity;
2. explicit Human/host binding token naming an existing WorkScope revision;
3. resumed durable task with matching repository lineage and current instance evidence;
4. host-observed cwd/open-file/resource handles plus VCS common-dir/worktree identity;
5. previously registered WorkspaceInstance or verified relocation/attach receipt;
6. repository-lineage evidence and exact resource bindings;
7. detected manifest/service boundary as a new-scope candidate;
8. provisional ad_hoc/new scope bound only to the current session.
```

Display name, nearest path, longest prefix, most recently used task and semantic similarity are never sufficient to bind an existing scope. Ambiguous match is not selected silently. Resolver returns the candidate set and the cheapest discriminative question; until resolution, project-specific memory from different candidates is not mixed and Material authority is withheld.

Scope resolution must not depend on already having an authenticated WorkScope. An explicitly user-selected root, an authenticated host cwd/open-file handle or an admitted launcher request may create a short-lived `DiscoveryReadLease`:

```yaml
DiscoveryReadLease:
  proposer_principal_session_and_host:
  candidate_root_handles_and_filesystem_identity:
  allowed_reads: filesystem_identity | vcs_identity | manifest_names_and_hashes |
                 bounded_known_format_headers | governing_source_candidates
  forbidden: project_memory_admission | external_model_delivery | mutation |
             credential_read | broad_neighbor_scan
  privacy_and_retention: ephemeral_local_only
  deadline_and_consumption_limit:
  evidence_and_terminal_disposition:
```

The lease exists only to distinguish candidate roots and discover the sources needed for onboarding. It does not authenticate the candidate as an existing WorkScope, does not allow its content to be mixed with another candidate and does not create project authority. A candidate requiring broader reading is shown to the Human/agent for explicit expansion. This prevents the cold-start circle “scope must be known before the files needed to identify scope can be read.”

