## I19.15. Documentation authority cutover and deletion gate

The new pair becomes active repository authority only through a `DocumentationCutoverRecord`:

```yaml
DocumentationCutoverRecord:
  repository_identity:
  architecture_identity:
  implementation_identity:
  previous_authority_contract_ref:
  new_authority_contract_ref:
  repository_reference_scan_ref:
  skills_prompts_configs_ci_scan_ref:
  runtime_data_scan_ref:
  archive_restore_ref:
  agent_integration_reload_refs:
  owner_approval_ref:
  status: blocked | prepared | active | rolled_back | retired
```

Required cutover order:

```text
1. Commit the exact Architecture and Implementation identities to the intended canonical branch.
2. Update the repository architecture-authority contract to name only the new pair as active normative sources.
3. Update README, AGENTS, Skills, plugin manifests, prompts, config, CI and generated documentation.
4. Run repository-wide reference and semantic-name scans on the exact candidate commit.
5. Inspect and migrate persisted schema/data, active tasks and installed integrations.
6. Reload/reattach agent integrations and prove they receive the new pair identity.
7. Restore the immutable donor archive and verify every digest.
8. Obtain explicit System/Architecture Owner approval.
9. Remove old books from the active tree; keep the immutable archive outside normal retrieval.
```

The normative book does not embed a dated repository verdict. The current `DocumentationCutoverRecord` and `CurrentSystemEvidenceSnapshot` are generated from the exact candidate commit, installed integrations and live data. Until they prove repository references, runtime/data migration, archive recovery and owner approval, authority cutover and physical deletion remain `NOT_READY`. Historical repository snapshots are external evidence and cannot silently become the current deletion decision.

Old books may be treated as superseded only inside a packet/session that explicitly binds to the new pair identity. They may not be removed from the project or ignored by repository agents while the repository authority contract still names them.

Physical deletion is not required for D0/D1 work. It is required before claiming that the repository itself has completed the two-book canonical cutover.

---

