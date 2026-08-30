## I3.10. Immutable Config and Policy snapshots

Every admitted operation references immutable:

```text
ConfigSnapshotId;
PolicySnapshotId;
CapabilityRegistryRevision;
ModuleCatalogRevision.
```

Hot reload flow:

```text
watch file/event
→ parse full candidate
→ validate schema, signatures, invariants and dependency compatibility
→ create immutable snapshot
→ compare affected capabilities
→ atomically publish via ArcSwap
→ invalidate dependent views/leases where required
→ retain previous snapshot for rollback.
```

Invalid config never partially updates live state. Secret values are references, not copied into snapshots, logs or model bundles.

A candidate copied from another machine, installation or WorkScope is not activated merely because it passes the schema. `ConfigApplicabilityReceipt` binds it to the observed machine/environment/capability profile and classifies each affected setting as `APPLICABLE`, `NARROWED`, `UNQUALIFIED`, `UNSUPPORTED` or `CONFLICTED`. Only settings whose declared owner and compatibility predicate match the current profile may publish; unqualified performance/resource defaults remain planning evidence, while authority/privacy/effect conflicts reject the dependent snapshot. The previous snapshot remains active and the operator receives the exact incompatible fields and recovery path.

### Dreamer- and UI-initiated configuration changes

The same settings can be changed directly through the Human UI or requested in natural language through Dreamer. Both routes compile to one governed `ConfigurationChangeIntent`; Dreamer does not edit files, registries or live snapshots itself.

```yaml
ConfigurationChangeIntent:
  requester_and_trigger: human | dreamer | watchdog_problem | maintenance_policy
  natural_language_request_and_normalized_delta:
  affected_setting_owners:
  impact: presentation_only | operational_reversible | model_cost_route |
          data_retention | privacy_security_authority | storage_migration
  current_and_candidate_snapshot_refs:
  expected_benefit_and_counter_risks:
  required_capability_budget_and_approval:
  validation_shadow_or_probe:
  rollback_and_review_condition:
```

Execution path:

```text
request
→ Dreamer/UI explanation and candidate delta
→ deterministic owner/schema/applicability validation
→ Watchdog risk observation
→ required Human/System/WorkScope approval or pre-authorized low-impact policy
→ immutable candidate snapshot
→ targeted probe/shadow where applicable
→ atomic publication
→ post-change observation
→ keep, narrow or rollback.
```

Only presentation settings and explicitly pre-authorized, reversible operational settings may publish without a new Human confirmation. Model/provider cost, automatic agent launch, privacy, secrets, authority, storage, remote access and destructive retention changes require the role that owns that boundary. A Dreamer-originated change with no user request, open Problem, accepted maintenance plan or valid scheduled policy is a Watchdog signal; the previous snapshot remains the rollback anchor.

If independent Watchdog coverage is unavailable, presentation-only changes may proceed under normal audit and pre-authorized low-impact changes may proceed only with an explicit degraded-supervision receipt. Model/cost routing, automatic launches, privacy/security/authority, remote access, storage/migration and destructive retention changes pause until supervision is restored or the owning Human explicitly authorizes a narrowly scoped emergency action. Rollback to a previously approved last-known-good snapshot remains available through the recovery path.

