## I7.29. PortableSkillPackage

`PortableSkillPackage` is the user-facing portable packaging contract for one or more Skills. Each package revision is an immutable user-owned artifact; it is not a Skill-utility state, Tool Definition, capability grant, scheduler or authority boundary.

```text
<package>/
  manifest.yaml
  SKILL.md
  references/      optional
  scripts/         optional
  assets/          optional
```

```yaml
PortableSkillPackageRevision:
  package_id_revision_and_supersedes:
  canonical_tree_digest_algorithm_and_value:
  source:
    kind: profile_local | project_local | shared_external_directory |
          git_or_hub_url | eliot_generated_candidate
    locator_retained_snapshot_source_digest_and_lock:
    source_view_workscope_and_provenance:
  manifest_format_and_compatibility_profile:
  skill_entries_bundles_and_optional_short_aliases:
  declared_dependencies_and_required_capability_refs:
  tool_definition_and_configuration_requirements:
  applies_when_where_not_apply_stop_and_escalation:
  verification_entrypoint_ref:
  reference_script_and_asset_inventory:
  write_policy: protected_human_only | governed_candidate_writeback
  package_admission_disposition: DISCOVERED_UNTRUSTED | QUARANTINED |
                                 TRUSTED_SCOPED | REJECTED | RETIRED
  trust_scope_principal_receipt_expiry_and_recheck_rule:
```

Discovery/import pipeline:

```text
resolve SourceAdmissionPolicy and exact SourceView;
capture a retained immutable snapshot of regular package files;
reject path traversal, symlink/reparse escape and mutable external references;
compute a versioned digest over normalized relative path, file type and exact bytes;
validate manifest, dependency/capability names, secrets and executable supply chain;
record provenance/lock data and quarantine or request scoped trust;
compile only the admitted Skill entries for the current route/profile/policy catalogue.
```

A Git/Hub URL is an acquisition locator only; executable use always binds the retained snapshot and digest. Project-local trust binds exact WorkScope/root identity, source-view revision, package digest and trust principal. Any byte, dependency declaration or path-identity change creates a new revision, triggers rescan and does not inherit trust from the old path. Profile-local and shared packages follow the same revision rule; location alone is never trust.

`SKILL.md` becomes eligible instruction content only after package admission. Large `references/` are loaded on demand through the index/body/runtime budget of I7.12 and remain source material, not authority. Presence under `scripts/` does not register a tool or permit execution: every script and verification entrypoint requires an admitted Tool Definition, exact capability grant, sandbox/effect policy and execution receipt. Import/discovery therefore has zero execution authority.

Dependency, host, contract or Tool Definition drift marks the compiled Skill stale under I7.13/I7.25 before Material use; it does not rewrite historical package trust or outcomes. Quarantine/trust describes package admission only. I7.25 remains the sole owner of installed/delivered/executed/useful evidence, and causal-helpfulness still requires the applicable decision/verifier/outcome proof rather than package load, citation or successful transport.

An agent or `/learn` surface may propose a new package or immutable revision from a URL, directory, conversation, notes or document. ELIOT-generated material starts untrusted/quarantined. Writeback is an exact governed diff against the current revision with source provenance, verifier and Human/policy approval; a protected package rejects agent edits. No difficult task, repeated wording or successful import automatically promotes or rewrites a user package.

Retirement prevents future activation but preserves revision history, provenance, execution evidence and rollback/restore inspection. Short aliases and bundles are namespaced surface entries resolved against the active eligible catalogue; alias selection does not widen package trust, capability or task authority.

