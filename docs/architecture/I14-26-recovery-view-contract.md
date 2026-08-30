## I14.26. Recovery View contract

`RecoveryView` is the smallest inspection surface that survives loss of normal application behavior. It is operational and explicitly stale where evidence is stale; it never becomes a second task/memory projection.

Owner and sources:

```text
Kernel assembles the normal RecoveryView from ORS, active epochs/cutovers,
Host/SCM observations, store-bridge readiness and reconciled Watchdog signals;

when Kernel is unavailable, `eliot recovery status` reads only the authenticated
Host recovery channel plus the independent Watchdog fallback surface;

canonical task goals, claims and decisions are shown only after canonical read access
returns; HostStateJournal, Watchdog spool and ORS are never interpreted as substitutes.
```

Minimum fields:

```yaml
RecoveryView:
  generated_at_and_source_freshness:
  installation_host_kernel_and_watchdog_lineages:
  active_and_candidate_artifacts:
  process_and_store_liveness_vs_semantic_readiness:
  ors_integrity_capacity_and_reconciliation_state:
  active_cutovers_authority_revocations_and_unknown_outcomes:
  unavailable_guarantees_and_current_governance_ceiling:
  pending_nonsemantic_problem_incident_repair_intents:
  last_known_compatible_artifacts_and_backup_classes:
  exact_manual_or_automatic_next_actions:
  evidence_and_receipt_handles:
```

If sources disagree, the view exposes disagreement and blocks only the dependent recovery action. It does not merge by timestamp, infer health from a PID, infer semantic readiness from process liveness or claim that an unobserved tool/effect stopped. Large evidence is referenced by authenticated handles. Recovery-critical CLI commands consume the exact view revision/lineage and fail stale rather than acting on a changed system.

---


