## I3.15. Installation and update transaction

Installation, repair and update are durable Host/installer operations rather than a sequence of best-effort file copies. They do not use Canonical Memory as their control state and do not infer success from directory presence.

```yaml
InstallationTransaction:
  transaction_id_and_installation_epoch:
  profile_and_requested_operation: install | update | repair | remove
  current_active_manifest_and_candidate_manifest:
  immutable_staging_root_and_artifact_digests:
  planned_file_acl_service_task_plugin_and_config_changes:
  precondition_and_ownership_evidence:
  stage:
    PLANNED | STAGING | STATIC_VERIFIED | REGISTERING | ACTIVATING |
    ACTIVE_VERIFIED | CLEANING | COMPLETED | ROLLBACK_REQUIRED |
    ROLLED_BACK | QUARANTINED
  completed_stage_refs_and_pending_external_changes:
  rollback_or_forward_repair_plan:
  last_known_good_and_no_return_boundary:
  observed_postconditions_and_recovery_command:
```

Owner and durable state:

```text
installer/bootstrap owns the transaction while no Host is active;
Host owns activation/recovery once its HostInstallationEpoch is established;
HostStateJournal stores the minimal current transaction/activation lineage;
large logs/packages remain immutable artifacts;
Canonical Store receives only later installation/capability observations and policy decisions,
not the transaction's operational authority.
```

Algorithm:

```text
observe exact current installation/service/task/plugin state
→ create immutable plan and staging root
→ download/copy without touching active generation
→ verify hashes, signatures/licenses, ACL plan and executable/dependency closure
→ register candidate service/tasks/plugins without granting runtime authority
→ switch the applicable activation pointer or SCM configuration through one observed installer operation
→ start and run exact health/conformance challenge
→ mark active only after observed postconditions
→ clean superseded staging after rollback window.
```

Interruption at any stage preserves the old active generation when possible and gives every old/new/partial artifact one explicit disposition. Restart resumes from the last verified stage or performs forward rollback; it never merges a partial candidate into the old tree, adopts an unknown process, reconstructs approval from paths/PIDs or labels a merely present file as installed. A stage that changed an external OS object but lacks acknowledgement remains `UNKNOWN_OUTCOME/ROLLBACK_REQUIRED` until read-back reconciliation.

This contract applies equally to `system_service`, `user_mode`, Module bundles, User Broker packages, Skills/plugins and exact compatibility artifacts. The narrower hot-generation cutovers of I14 reuse their existing owners; `InstallationTransaction` coordinates only installation-level files/registrations and does not become a second ModuleGeneration lifecycle.

---

