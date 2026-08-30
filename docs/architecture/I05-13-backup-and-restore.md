## I5.13. Backup and restore

Backup classes are explicit:

```text
full_recovery
  canonical logical export + referenced blobs + coherent OrsSnapshotFence
  + config/policy/module and approved Host/dependency build manifests
  + integrity anchors + purge ledger
  + a bounded WatchdogSpoolFence for unreconciled critical signals/intents
  + an optional forensic HostStateAuditFence that is never restored as active authority;

canonical_only_degraded
  coherent canonical export and blobs, but no self-consistent ORS snapshot;
  preserves semantic data only and is never advertised as operational recovery;

scope_export
  bounded ECXF transfer for one declared scope; not an installation backup.
```

Restore:

```text
restore to isolated root;
validate format/schema/checksums;
apply privacy purge ledger;
rebuild projections/indexes;
verify receipt/event chain;
issue a new Authority Epoch lineage above all observed epochs;
restore no active SessionBinding, user-broker registration, `UserBrokerEpoch`, launch lease or route continuation as current authority; they return only as historical/suspended recovery evidence;
import restored ORS operations as `suspended_recovery`, never runnable; reconcile canonical receipts and external-effect evidence before any replay;
run semantic and operational recovery checks;
Human/System Owner authorizes cutover;
create a new HostInstallationEpoch/Kernel activation lineage rather than restoring HostStateJournal as active;
retain pre-cutover state until explicit retirement.
```

Backup existence is not recovery proof. Scheduled restore rehearsal is a release/maintenance job.

A portable/full backup may not merely copy installation-encrypted blob files and assume the destination owns the key. It either re-encrypts payloads into the backup envelope or records a separately protected wrapped-key manifest and restoration receipt. The backup contains key lineage and format metadata, never plaintext master/data keys. Missing or unverifiable key material makes the affected blob set unrestorable and fails `full_recovery` proof.

Export and backup never merge blob records solely because their content digests match. Every entry preserves the opaque residency-key digest, versioned content digest, retention/erasure domains and purge-ledger revision. Equal bytes under different obligations remain distinct logical objects; restore applies the current purge ledger and may not coalesce them into a shared residency object.

A `full_recovery` backup receipt requires one manifest binding the ECXF `ExportFence`, every referenced blob residency identity and content digest, a self-consistent `OrsSnapshotFence`, purge-ledger revision, configuration/policy/module and approved Host/dependency build manifests, integrity anchors and any unreconciled critical Watchdog signals/intents under a `WatchdogSpoolFence`. If a `HostStateAuditFence` is attached, it contains only a logical forensic digest/snapshot of installation lineage and observed dispositions; it is optional for recovery because cutover creates a new Host lineage, and it is never restored as active authority. Watchdog/Host operational snapshots restore only as forensic/suspended evidence and never as active supervision or authority. Missing blobs, an unexplained revision gap or an incoherent ORS fence fails that class rather than producing a partial “successful” backup. `canonical_only_degraded` uses a different explicit receipt/status and cannot satisfy normal restore-readiness policy. Incremental backups preserve the base snapshot and exact canonical event interval needed for replay.

`OrsSnapshotFence` is a logical Kernel export, not a copy of a live redb file. It records Host/Kernel authority lineage, last reconciled canonical receipt/event/outbox cursors, pending-operation identities and hashes, job checkpoints, generation cutovers and snapshot time. The ORS and canonical export are not claimed to be one cross-store transaction: the manifest records their relation, and restore imports every ORS item as `suspended_recovery` for receipt/effect reconciliation. If Kernel cannot produce a self-consistent logical ORS snapshot, only a `canonical_only_degraded` receipt may be issued; it preserves canonical data but is not advertised as a full backup or normal operational-recovery point.

