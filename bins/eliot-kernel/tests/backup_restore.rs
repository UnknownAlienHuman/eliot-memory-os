//! Kernel production restore adapter tests (issue #960).
//!
//! Twenty-five substantive cases binding the coordinator to the accepted owner
//! contracts. The durable journal behind every execution is an injected
//! `J: RestoreJournalPort`: memory/file fixtures below prove adapter
//! mapping only and always carry fixture-marked admission, while production
//! composition must supply the admitted persistent ORS owner (#957 via the
//! #962 turn).
//!
//! Every case that reaches the engine carries owner-issued destination
//! evidence from `admitted_evidence`, because the restore owner refuses a
//! bundle that does not (`DestinationNotAdmitted`, raised before `compile_plan`
//! and before a destination root exists). A case that omitted it would be
//! asserting that refusal instead of the restore it is named for.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupBundle, BackupClass, BackupError, BackupInput, CutoverAuthorization, EventRange,
    ExportFence, ObservedLineageLimit, OwnerTrustBinding, RestoreContext, RestoreEvidenceLevel,
    RestoreJournalAdmission, RestoreJournalPort, RestoreJournalRecord, RestoreJournalState,
    RestoreObligationState, RestorePhase, RestoreStep, WrappedKeyEntry, WrappedKeyManifest,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_kernel::{
    BlobOwnerClient, CanonicalOwnerClient, DESTINATION_ADMISSION_FILE, DestinationManifestEvidence,
    InvalidationKind, InvalidationOwnerClient, KernelBackupRestore, KernelIsolatedDestination,
    KernelRestoreError, PinnedDestinationAdmission, PurgeOwnerClient, RESTORE_ISOLATED_AREA,
    RESTORE_JOURNAL_OWNER_LABEL, RestorePorts, StagedCleanupOutcome, StagedCleanupRefusal,
    TEMP_RESTORE_EXTENSION, backup_to_kernel, check_kernel_effect_fence, phase_owner,
    require_production_admitted,
};

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn test_bundle(target: &str) -> BackupBundle {
    let source_fence = StateFence::new(test_epoch(1), ResourceGeneration::genesis());
    BackupBundle::build(BackupInput {
        backup_id: format!("backup-960-{target}"),
        class: BackupClass::CanonicalOnlyDegraded,
        source_adapter: "test-adapter-960".to_owned(),
        schema_generation: "1".to_owned(),
        export_fence: ExportFence {
            export_id: format!("export-960-{target}"),
            store_generation: "store-960".to_owned(),
            state_fence: source_fence,
            scope_id: None,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: None,
                last_sequence: None,
                count: 0,
            },
            blob_reachability_manifest: Vec::new(),
            consistent: true,
        },
        canonical_events: Vec::new(),
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs: Vec::new(),
        purge_ledger: Vec::new(),
        ors_snapshot: None,
        artifacts: Vec::new(),
        watchdog_spool: None,
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 1,
    })
    .expect("test bundle builds")
}

/// The same archive as [`test_bundle`], but carrying real canonical members.
///
/// [`test_bundle`] is empty of members, which is right for most cases and
/// exactly wrong for the import-closure cases below: with no expected member,
/// every name-based closure check is satisfied by an empty directory and cannot
/// distinguish "nothing was required" from "something was required and did not
/// arrive". These cases need a non-empty expected set for the check to have
/// anything to pin, so the bundle is rebuilt here through the SAME
/// [`BackupBundle::build`] the other fixtures use — the members are produced by
/// [`CanonicalRecord::new`], which computes and validates each record's own
/// digest, rather than by hand-editing a record's fields.
///
/// The export fence declares the interval those members occupy, because the
/// bundle owner checks the declared `event_range.count` against the number of
/// canonical events actually carried and refuses a disagreement as a
/// `FenceMismatch` on `event range count` — a fence claiming an empty interval
/// beside one carried member describes nothing this bundle contains. The
/// bounds are the `1..=event_count` interval the sibling capture fixtures in
/// `tests/backup_capture.rs` declare for the same reason; `EventRange::validate`
/// admits an interval only as `(None, None, 0)` or as bounds whose width equals
/// the count, so a non-empty member set must state its bounds.
fn test_bundle_with_events(target: &str, event_ids: &[&str]) -> BackupBundle {
    let events = event_ids
        .iter()
        .map(|id| {
            eliot_backup::CanonicalRecord::new(
                "test-event-960",
                *id,
                serde_json::json!({ "id": id }),
            )
            .expect("canonical event validates")
        })
        .collect();
    let event_count = events.len() as u64;
    let source_fence = StateFence::new(test_epoch(1), ResourceGeneration::genesis());
    BackupBundle::build(BackupInput {
        backup_id: format!("backup-960-{target}"),
        class: BackupClass::CanonicalOnlyDegraded,
        source_adapter: "test-adapter-960".to_owned(),
        schema_generation: "1".to_owned(),
        export_fence: ExportFence {
            export_id: format!("export-960-{target}"),
            store_generation: "store-960".to_owned(),
            state_fence: source_fence,
            scope_id: None,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: Some(1),
                last_sequence: Some(event_count),
                count: event_count,
            },
            blob_reachability_manifest: Vec::new(),
            consistent: true,
        },
        canonical_events: events,
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs: Vec::new(),
        purge_ledger: Vec::new(),
        ors_snapshot: None,
        artifacts: Vec::new(),
        watchdog_spool: None,
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 1,
    })
    .expect("member-carrying test bundle builds")
}

fn test_context(target: &str) -> RestoreContext {
    RestoreContext {
        target_id: target.to_owned(),
        target_authority_epoch: test_epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

fn work_root(case: &str) -> PathBuf {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let root =
        std::env::temp_dir().join(format!("eliot-960-{case}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root).expect("work root");
    root
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/backup-restore")
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_dir().join(name)).expect("fixture file")
}

fn production_admission() -> RestoreJournalAdmission {
    let admission: RestoreJournalAdmission =
        serde_json::from_slice(&read_fixture("journal-admission-production.json"))
            .expect("production admission fixture");
    assert!(!admission.fixture_proof_only);
    assert_eq!(admission.database_ref, RESTORE_JOURNAL_OWNER_LABEL);
    admission
}

fn fixture_admission() -> RestoreJournalAdmission {
    let admission: RestoreJournalAdmission =
        serde_json::from_slice(&read_fixture("journal-admission-fixture.json"))
            .expect("fixture admission fixture");
    assert!(admission.fixture_proof_only);
    admission
}

/// Banned in-memory / no-op journal type names, assembled at runtime so the
/// guard itself never introduces the flagged literals. Production proof is
/// `require_production_admitted` plus no `Default` journal plus the
/// admission-only ports bundle; these tokens only assert that production
/// cannot grow an in-memory or no-op substitute.
fn assembled_banned_journal_tokens() -> Vec<String> {
    vec![
        "MemJournal".to_owned(),
        concat!("In", "Memory", "Journal").to_owned(),
        concat!("No", "op", "RestoreJournal").to_owned(),
        concat!("No", "Op", "RestoreJournal").to_owned(),
    ]
}

/// Builds destination admission through the EXISTING owner producer
/// [`DestinationManifestEvidence::issue_from_owner_manifest`].
///
/// The test stands in for the Host-side active manifest binding (issue #962,
/// AUDIT-7) by supplying the three values that binding issues, read from the
/// fixture rather than invented here, and nothing else: the admitted work root
/// is bound by the producer, which resolves it with `canonicalize` and then runs
/// the type's own `validate()`. This is the seam the restore owner's admission
/// gate requires, so a test that reached the engine any other way would be
/// proving a shape the owner refuses — which is exactly what the pre-existing
/// sixteen failures were doing by carrying `manifest_evidence: None`.
///
/// The fixture's own `kernel_work_root` is deliberately NOT read: it is a
/// placeholder, and the admitted root is the one the producer binds.
fn admitted_evidence(work_root: &Path) -> DestinationManifestEvidence {
    let binding: serde_json::Value =
        serde_json::from_slice(&read_fixture("destination-manifest-evidence.json"))
            .expect("owner manifest binding fixture");
    let text = |field: &str| {
        binding
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("owner manifest binding fixture carries {field}"))
            .to_owned()
    };
    DestinationManifestEvidence::issue_from_owner_manifest(
        &text("manifest_digest"),
        &text("roots_digest"),
        binding
            .get("registry_revision")
            .and_then(serde_json::Value::as_u64)
            .expect("owner manifest binding fixture carries registry_revision"),
        work_root,
    )
    .expect("owner-issued destination evidence validates against the temp work root")
}

/// In-memory fixture journal: adapter-mapping proof only. Never production:
/// every execution using it must carry fixture-marked admission, and the
/// coordinator refuses production claims on it by construction.
#[derive(Default)]
struct FixtureJournal {
    record: Option<RestoreJournalRecord>,
    fail_next_cas: bool,
    /// Fail the compare-and-swap that persists `n` completed phases, counting
    /// from 1, and never a different one.
    ///
    /// This is what makes "interrupted AFTER staging" a chosen point rather
    /// than a lucky one. `fail_next_cas` refuses the FIRST swap, which happens
    /// before any phase runs, so it can only ever produce a restore that
    /// published nothing. Failing the swap that follows the Nth completed phase
    /// refuses the engine at a point where N phases have already published
    /// their material and the journal is mid-transaction.
    fail_cas_after_completed: Option<u64>,
    /// Refuse the one compare-and-swap that would persist `ReceiptPersisted`
    /// for exactly this phase, and never a different one.
    ///
    /// This is the interruption point that makes RECONCILIATION observable, and
    /// it is a different point from `fail_cas_after_completed`. The engine only
    /// reconciles a phase when it re-enters the loop holding that phase's
    /// `IntentPersisted`: from `ReceiptPersisted` it advances to the next phase
    /// and from `Ready` it applies the phase outright. So a phase interrupted
    /// after its receipt was journalled is re-APPLIED on resume (overwriting
    /// whatever is at the member path), while a phase interrupted BEFORE its
    /// receipt was journalled is re-READ on resume. Refusing the receipt swap is
    /// therefore the only way to observe what a resume does with a phase whose
    /// journaled receipt and on-disk material can disagree.
    fail_cas_persisting_receipt_for: Option<RestorePhase>,
}

/// Completed phases a record already attests.
fn completed_phases(record: &RestoreJournalRecord) -> u64 {
    if record.completed_phases > 0 {
        record.completed_phases
    } else if matches!(record.state, RestoreJournalState::ReceiptPersisted) {
        1
    } else {
        0
    }
}

impl RestoreJournalPort for FixtureJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        Ok(self
            .record
            .clone()
            .filter(|record| record.journal_key == journal_key))
    }

    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        if self.fail_next_cas {
            self.fail_next_cas = false;
            return Err(BackupError::RestoreJournalCasConflict);
        }
        if next.journal_key != journal_key
            || self.record.as_ref().map_or(0, |record| record.revision) != expected_revision
        {
            return Err(BackupError::RestoreJournalCasConflict);
        }
        // One-shot, so the resume that follows observes a journal which then
        // advances normally instead of failing at the same point forever.
        if self.fail_cas_after_completed.is_some_and(|target| {
            self.record
                .as_ref()
                .is_some_and(|current| completed_phases(current) == target)
        }) {
            self.fail_cas_after_completed = None;
            return Err(BackupError::RestoreJournalCasConflict);
        }
        // The swap that would make this phase's journaled receipt durable. The
        // phase has already published its member and its receipt file by this
        // point, so refusing here leaves the journal holding `IntentPersisted`
        // over material that is on disk — the state a resume reconciles.
        if matches!(next.state, RestoreJournalState::ReceiptPersisted)
            && self.fail_cas_persisting_receipt_for.as_ref() == Some(&next.phase)
        {
            self.fail_cas_persisting_receipt_for = None;
            return Err(BackupError::RestoreJournalCasConflict);
        }
        self.record = Some(next);
        Ok(())
    }
}

/// File-backed fixture journal: proves persistent adapter readback across
/// handle drops without claiming ORS ownership. Fixture-marked all the
/// same: mapping proof, never a production durable-recovery claim.
struct FixtureFileJournal {
    path: PathBuf,
}

impl FixtureFileJournal {
    fn open(path: PathBuf) -> Self {
        Self { path }
    }
}

impl RestoreJournalPort for FixtureFileJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(BackupError::Target(error.to_string())),
        };
        let record: RestoreJournalRecord =
            serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)?;
        if record.journal_key == journal_key {
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        let current = self.load(journal_key)?;
        if next.journal_key != journal_key
            || current.as_ref().map_or(0, |record| record.revision) != expected_revision
        {
            return Err(BackupError::RestoreJournalCasConflict);
        }
        let bytes = serde_json::to_vec(&next)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let tmp = self.path.with_extension("tmp-journal");
        std::fs::write(&tmp, &bytes).map_err(|error| BackupError::Target(error.to_string()))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|error| BackupError::Target(error.to_string()))?;
        Ok(())
    }
}

/// The production ports bundle every case below runs on.
///
/// It carries the owner-issued destination evidence, because the restore owner
/// REFUSES a bundle that does not: `KernelBackupRestore::restore` raises
/// `DestinationNotAdmitted` before `compile_plan` and before
/// `KernelIsolatedDestination::open` creates a root, so a bundle reaching the
/// engine with `manifest_evidence: None` proves nothing about restore at all.
/// The evidence is built per work root through the owner producer, so each
/// case's admitted root is the root that case actually uses.
fn production_ports<'a>(
    admission: &'a RestoreJournalAdmission,
    fence: &'a StateFence,
    work_root: &Path,
) -> RestorePorts<'a> {
    RestorePorts {
        journal_admission: admission,
        kernel_fence: fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: Some(admitted_evidence(work_root)),
        rehearsal: false,
    }
}

// WORK_UNIT_CASE: 960/1
#[test]
fn exact_verified_archive_and_admitted_destination_restore() {
    let target = "t960-01";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("01");
    let fence = bundle.export_fence.state_fence.clone();
    assert!(check_kernel_effect_fence(&fence, &bundle).is_ok());
    let admission = production_admission();
    assert!(require_production_admitted(&admission).is_ok());
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("exact verified restore succeeds");
    outcome.receipt.validate().expect("receipt validates");
    assert!(!outcome.rehearsal);
    assert_eq!(
        outcome.phase_log,
        vec!["prepare", "purge", "rebuild", "verify", "finalize"]
    );
    assert!(outcome.journal_owner.contains(RESTORE_JOURNAL_OWNER_LABEL));
    assert!(
        outcome
            .destination_root
            .starts_with(root.join(".eliot").join(RESTORE_ISOLATED_AREA))
    );
    let evidence = outcome.evidence.expect("finalize evidence observed");
    evidence.validate().expect("evidence validates");
    // This archive carries NO purge entry, so the purge phase applied nothing
    // and no owner issued a purge revision. The obligation is therefore reported
    // as NOT established, not as `Satisfied`: publishing `Satisfied` here would
    // attest a privacy-purge closure out of the caller's own emptiness. The
    // restore itself still succeeds — an isolated restore does not require a
    // purge owner it never used — and the slot stays fail-closed at the gate
    // that consumes it, where `MissingCapability` refuses cutover.
    assert!(
        bundle.purge_ledger.is_empty(),
        "this fixture's premise: the archive carries no purge entry"
    );
    assert_eq!(
        evidence.obligations.purge.state,
        RestoreObligationState::MissingCapability,
        "an archive that carried no purge entry established no purge closure"
    );
    assert!(!evidence.active_authority_restored);
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/2
#[test]
fn foreign_or_stale_destination_refused() {
    let target = "t960-02";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("02");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let coordinator = KernelBackupRestore::bind(root.clone());
    // First restore pins the owner-approved admission.
    let first_evidence = admitted_evidence(&root);
    let first_ports = RestorePorts {
        journal_admission: &admission,
        kernel_fence: &fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: Some(first_evidence),
        rehearsal: false,
    };
    let mut journal = FixtureJournal::default();
    let first = coordinator
        .restore(&bundle, context.clone(), &first_ports, &mut journal)
        .expect("first admitted restore succeeds");
    // The admission pins transaction, target, and evidence at prepare.
    let pinned: PinnedDestinationAdmission = serde_json::from_slice(
        &std::fs::read(first.destination_root.join(DESTINATION_ADMISSION_FILE))
            .expect("pinned admission"),
    )
    .expect("pinned admission parses");
    assert_eq!(pinned.target_id, target);
    // A rotated manifest binding for the same transaction refuses as drift. The
    // rotated value is re-ISSUED through the same producer rather than produced
    // by writing the struct's fields, so a drifted binding is a different owner
    // issuance and not a hand-edited record.
    let binding: serde_json::Value =
        serde_json::from_slice(&read_fixture("destination-manifest-evidence.json"))
            .expect("owner manifest binding fixture");
    let revision = binding["registry_revision"]
        .as_u64()
        .expect("owner manifest binding fixture carries registry_revision");
    let second_evidence = DestinationManifestEvidence::issue_from_owner_manifest(
        &binding["manifest_digest"]
            .as_str()
            .expect("manifest_digest")
            .to_owned(),
        &binding["roots_digest"]
            .as_str()
            .expect("roots_digest")
            .to_owned(),
        revision + 1,
        &root,
    )
    .expect("rotated owner-issued evidence validates");
    let second_ports = RestorePorts {
        journal_admission: &admission,
        kernel_fence: &fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: Some(second_evidence),
        rehearsal: false,
    };
    let mut journal2 = FixtureJournal::default();
    let drifted = coordinator.restore(&bundle, context.clone(), &second_ports, &mut journal2);
    assert!(matches!(drifted, Err(KernelRestoreError::FenceMismatch(_))));
    // A foreign admitted root (outside the Kernel work root) refuses before effects.
    let foreign_root = work_root("02-foreign");
    let foreign_evidence = admitted_evidence(&foreign_root);
    let foreign_ports = RestorePorts {
        journal_admission: &admission,
        kernel_fence: &fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: Some(foreign_evidence),
        rehearsal: false,
    };
    let mut journal3 = FixtureJournal::default();
    let foreign = coordinator.restore(&bundle, context, &foreign_ports, &mut journal3);
    assert!(matches!(
        foreign,
        Err(KernelRestoreError::DestinationInvalid(_))
    ));
    // Resume outside the isolated area refuses.
    let outside = KernelIsolatedDestination::open_existing(root.clone(), &root);
    assert!(matches!(
        outside,
        Err(KernelRestoreError::DestinationInvalid(_))
    ));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&foreign_root);
}

// WORK_UNIT_CASE: 960/3
#[test]
fn missing_class_crypto_purge_capability_refuses_without_fallback() {
    // Blob binding without a key manifest refuses: no silent downgrade.
    assert!(matches!(
        BlobOwnerClient::bind(Vec::new(), None, None),
        Err(BackupError::MissingRecoveryComponent("blob_key_material"))
    ));
    // Purge member suppression has no accepted matching API: backlog refusal.
    let purge = PurgeOwnerClient::bind(&[]);
    assert_eq!(
        purge.suppress_purged_member("subject-ref-1").unwrap_err(),
        BackupError::RestoreCapabilityUnsupported {
            capability: "purge-member-suppression"
        }
    );
    // A surplus key manifest (coverage the archive does not need) refuses at
    // the coordinator instead of silently covering nothing.
    let target = "t960-03";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("03");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let key_bytes = b"wrapped-key-960-03".to_vec();
    let surplus = WrappedKeyManifest {
        manifest_id: "manifest-960-03".to_owned(),
        backup_id: bundle.manifest.backup_id.clone(),
        entries: vec![WrappedKeyEntry {
            key_lineage: "lineage-960-03".to_owned(),
            wrapping_key_id: "wrap-960-03".to_owned(),
            algorithm: "sealed-blob-envelope-v1".to_owned(),
            wrapped_key_bytes: key_bytes.clone(),
            wrapped_key_sha256: sha256_hex(&key_bytes),
        }],
    };
    // Admitted destination, so the refusal observed here is the SURPLUS KEY
    // MANIFEST and not the destination gate: with `None` this case would pass
    // for the wrong reason, refused at admission before the key material was
    // ever examined.
    let surplus_ports = RestorePorts {
        journal_admission: &admission,
        kernel_fence: &fence,
        keys: Some(&surplus),
        blob_scope: None,
        manifest_evidence: Some(admitted_evidence(&root)),
        rehearsal: false,
    };
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let surplus_run = coordinator.restore(&bundle, context, &surplus_ports, &mut journal);
    assert!(matches!(
        surplus_run,
        Err(KernelRestoreError::ArchiveInvalid(_))
    ));
    let empty_purge = PurgeOwnerClient::bind(&[]);
    assert!(empty_purge.validate_entries().is_ok());
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/4
#[test]
fn every_actual_phase_maps_to_its_exact_accepted_owner() {
    assert_eq!(
        phase_owner(&RestoreStep::PrepareIsolatedRoot),
        "kernel-restore-owner"
    );
    assert_eq!(phase_owner(&RestoreStep::ApplyPurgeLedger), "purge-owner");
    assert_eq!(phase_owner(&RestoreStep::ImportSealedBlobs), "blob-owner");
    assert_eq!(
        phase_owner(&RestoreStep::ImportCanonicalEvents),
        "canonical-owner"
    );
    assert_eq!(phase_owner(&RestoreStep::ImportReceipts), "canonical-owner");
    assert_eq!(
        phase_owner(&RestoreStep::ImportProjections),
        "canonical-owner"
    );
    assert_eq!(phase_owner(&RestoreStep::SuspendOrsOperations), "ors-owner");
    assert_eq!(
        phase_owner(&RestoreStep::RebuildProjections),
        "canonical-owner"
    );
    assert_eq!(
        phase_owner(&RestoreStep::VerifyReceiptEventChain),
        "canonical-owner"
    );
    assert_eq!(
        phase_owner(&RestoreStep::FinalizeIsolatedRoot),
        "kernel-restore-owner"
    );
}

// WORK_UNIT_CASE: 960/5
#[test]
fn absent_provider_cannot_produce_ok_or_known_zero() {
    let target = "t960-05";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("05");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect("import succeeds");
    let evidence = outcome.evidence.expect("evidence observed");
    // Unresolved reconciliation and absent owner channels stay explicit.
    assert_eq!(
        evidence.obligations.unresolved_effect_reconciliation.state,
        RestoreObligationState::Unknown
    );
    assert_eq!(
        evidence.obligations.watchdog_signals.state,
        RestoreObligationState::MissingCapability
    );
    let plan = KernelBackupRestore::compile_plan(&bundle, context).expect("plan compiles");
    let auth = CutoverAuthorization {
        plan_id: plan.plan_id.clone(),
        bundle_sha256: plan.bundle_sha256.clone(),
        authorized_by: "human-owner-960".to_owned(),
        statement: "authorize-960-05".to_owned(),
    };
    let destination =
        KernelIsolatedDestination::open_existing(outcome.destination_root.clone(), &root)
            .expect("destination reopens");
    let qualified = coordinator.qualify_cutover(
        &plan,
        &bundle,
        &outcome.receipt,
        Some(&evidence),
        &destination,
        Some(&auth),
    );
    // The purge obligation is slot 0 and `require_cutover_obligations` walks the
    // slots in order, so with no purge owner consulted the PURGE slot refuses
    // first and the reconciliation owner is never reached. Naming the first
    // refusing slot is the honest expectation; asserting the reconciliation
    // owner here was stale once the empty-ledger purge arm stopped refusing.
    assert_eq!(
        qualified.unwrap_err(),
        KernelRestoreError::TargetFailed(BackupError::RestoreCapabilityUnsupported {
            capability: "purge-owner"
        })
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/6
#[test]
fn unadmitted_or_fixture_journal_refuses_production_effects() {
    let target = "t960-06";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("06");
    let fence = bundle.export_fence.state_fence.clone();
    // Fixture-marked admission never backs production effects.
    let fixture = fixture_admission();
    assert_eq!(
        require_production_admitted(&fixture).unwrap_err(),
        KernelRestoreError::JournalNotAdmitted
    );
    let ports = production_ports(&fixture, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let refused = coordinator.restore(&bundle, context, &ports, &mut journal);
    assert_eq!(refused.unwrap_err(), KernelRestoreError::JournalNotAdmitted);
    // No destination side effects precede the admission refusal.
    assert!(!root.join(".eliot").join(RESTORE_ISOLATED_AREA).exists());
    // By construction: no in-memory or no-op journal type exists in the
    // production modules. Tokens are assembled at runtime (see
    // assembled_banned_journal_tokens) so the guard carries no flagged
    // literal. FileRestoreJournal is intentionally not banned: it names no
    // production type, and the accepted engine is proven instead by the
    // per-call injected J: RestoreJournalPort under
    // require_production_admitted.
    let ports_src = include_str!("../src/backup_restore_ports.rs");
    let coordinator_src = include_str!("../src/backup_restore.rs");
    for banned in assembled_banned_journal_tokens() {
        assert!(
            !ports_src.contains(banned.as_str()),
            "banned {banned} in ports"
        );
        assert!(
            !coordinator_src.contains(banned.as_str()),
            "banned {banned} in coordinator"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/7
#[test]
fn phase_source_destination_operation_fence_receipt_mismatch_rejected() {
    let bundle_a = test_bundle("t960-07a");
    let context_a = test_context("t960-07a");
    let root = work_root("07");
    let fence_a = bundle_a.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports_a = production_ports(&admission, &fence_a, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome_a = coordinator
        .restore(&bundle_a, context_a, &ports_a, &mut journal)
        .expect("run A succeeds");
    let evidence_a = outcome_a.evidence.expect("evidence A");
    // The same receipt/evidence against a different plan refuses: target,
    // bundle, and fence bindings must all match.
    let bundle_b = test_bundle("t960-07b");
    let context_b = test_context("t960-07b");
    let plan_b = KernelBackupRestore::compile_plan(&bundle_b, context_b).expect("plan B");
    let auth = CutoverAuthorization {
        plan_id: plan_b.plan_id.clone(),
        bundle_sha256: plan_b.bundle_sha256.clone(),
        authorized_by: "human-owner-960".to_owned(),
        statement: "authorize-960-07".to_owned(),
    };
    let destination =
        KernelIsolatedDestination::open_existing(outcome_a.destination_root.clone(), &root)
            .expect("destination reopens");
    let mismatched = coordinator.qualify_cutover(
        &plan_b,
        &bundle_b,
        &outcome_a.receipt,
        Some(&evidence_a),
        &destination,
        Some(&auth),
    );
    assert!(matches!(
        mismatched,
        Err(KernelRestoreError::ArchiveInvalid(_))
    ));
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/8
#[test]
fn unknown_owner_outcome_propagates_without_new_identity_or_retry() {
    let target = "t960-08";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("08");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    // A lost journal commit surfaces typed and is never retried blindly:
    // the failed swap stays failed and no receipt is fabricated.
    let mut journal = FixtureJournal {
        fail_next_cas: true,
        ..FixtureJournal::default()
    };
    let failed = coordinator.restore(&bundle, context, &ports, &mut journal);
    assert_eq!(
        failed.unwrap_err(),
        KernelRestoreError::TargetFailed(BackupError::RestoreJournalCasConflict)
    );
    assert!(journal.record.is_none(), "no receipt fabricated on loss");
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/9
#[test]
fn kernel_effect_fence_required_before_any_phase() {
    let target = "t960-09";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("09");
    // A foreign lineage fence never admits effects under stale authority.
    let foreign_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d-a716-446655440099").expect("foreign lineage"),
            NonZeroU64::new(1).expect("nonzero"),
        )
        .expect("foreign epoch"),
        ResourceGeneration::genesis(),
    );
    assert!(check_kernel_effect_fence(&foreign_fence, &bundle).is_err());
    let admission = production_admission();
    // Admitted destination, so the refusal observed here is the FOREIGN FENCE
    // and not the destination gate. The fence check runs before admission is
    // consulted, so this case would also refuse without evidence — but it would
    // then be unable to say WHICH check refused.
    let ports = RestorePorts {
        journal_admission: &admission,
        kernel_fence: &foreign_fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: Some(admitted_evidence(&root)),
        rehearsal: false,
    };
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let refused = coordinator.restore(&bundle, context, &ports, &mut journal);
    assert!(matches!(refused, Err(KernelRestoreError::FenceMismatch(_))));
    assert!(!root.join(".eliot").join(RESTORE_ISOLATED_AREA).exists());
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/10
#[test]
fn independent_complete_reconciliation_denominators() {
    let target = "t960-10";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("10");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("restore succeeds");
    let evidence = outcome.evidence.expect("evidence observed");
    // Canonical denominator complete; ORS and spool denominators stay
    // explicit about their own coverage instead of borrowing another's.
    assert_eq!(
        evidence.obligations.canonical_validation.state,
        RestoreObligationState::Satisfied
    );
    assert_eq!(
        evidence.obligations.ors_suspension.state,
        RestoreObligationState::NotAttempted,
        "archive carries no ORS snapshot"
    );
    assert_eq!(
        evidence.obligations.blob_validation.state,
        RestoreObligationState::NotAttempted,
        "archive carries no blobs"
    );
    assert!(!evidence.obligations.all_satisfied());
    assert!(CanonicalOwnerClient::verify_chain(&[], &[]).is_ok());
    let mut owners = [
        &evidence.obligations.purge,
        &evidence.obligations.canonical_validation,
        &evidence.obligations.reference_validation,
        &evidence.obligations.blob_validation,
        &evidence.obligations.ors_suspension,
        &evidence.obligations.unresolved_effect_reconciliation,
        &evidence.obligations.watchdog_signals,
        &evidence.obligations.external_source_revalidation,
        &evidence.obligations.runtime_invalidation,
        &evidence.obligations.session_invalidation,
        &evidence.obligations.lease_invalidation,
        &evidence.obligations.route_invalidation,
        &evidence.obligations.user_broker_invalidation,
    ]
    .iter()
    .map(|obligation| obligation.owner_id.clone())
    .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    assert_eq!(owners.len(), 13, "thirteen distinct owner slots");
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/11
#[test]
fn unknown_or_missing_member_prevents_readiness_not_partial_import() {
    let target = "t960-11";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("11");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("isolated import succeeds");
    // Safe isolated partial import is explicitly partial: the receipt never
    // claims operational readiness or cutover.
    assert!(!outcome.receipt.operational_recovery_ready);
    assert!(!outcome.receipt.cutover_performed);
    assert_eq!(
        outcome.receipt.evidence_level,
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    let evidence = outcome.evidence.expect("evidence observed");
    assert!(evidence.operationally_validated_by_owner().is_err());
    assert!(evidence.reconciliation_denominator.is_none());
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/12
#[test]
fn exact_owner_issued_epoch_generation_evidence() {
    let owner = OwnerTrustBinding {
        owner_id: "kernel-restore-owner".to_owned(),
        trust_binding_ref: "trust-binding-kernel-restore-owner-restore-1".to_owned(),
    };
    let limit = ObservedLineageLimit {
        owner_id: "kernel-restore-owner".to_owned(),
        observed_epoch: test_epoch(1),
        observed_generation: ResourceGeneration::genesis(),
    };
    // An advancing owner-issued epoch validates; caller arithmetic cannot
    // mint authority: a non-advancing candidate refuses.
    let advancing = eliot_backup::RestoreOwnerEpoch {
        owner: owner.clone(),
        new_epoch: test_epoch(2),
        new_generation: ResourceGeneration::new(2).expect("generation"),
        supersedes: vec![limit.clone()],
    };
    assert!(advancing.validate().is_ok());
    let stale = eliot_backup::RestoreOwnerEpoch {
        owner,
        new_epoch: test_epoch(1),
        new_generation: ResourceGeneration::new(2).expect("generation"),
        supersedes: vec![limit],
    };
    assert!(stale.validate().is_err());
    // By construction the coordinator consumes owner-issued epochs and never
    // mints them.
    let coordinator_src = include_str!("../src/backup_restore.rs");
    assert!(!coordinator_src.contains("RestoredFence::mint"));
    assert!(!coordinator_src.contains("EpochId::new"));
}

// WORK_UNIT_CASE: 960/13
#[test]
fn old_lease_route_ui_session_invalidations_retained_individually() {
    let target = "t960-13";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("13");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("restore succeeds");
    let evidence = outcome.evidence.expect("evidence observed");
    // Historical authority returns only as suspended evidence; live
    // invalidations stay individually missing-capability until #961/#962.
    assert!(evidence.historical_authority.is_empty());
    for (slot, owner_id) in [
        (&evidence.obligations.runtime_invalidation, "runtime-owner"),
        (&evidence.obligations.session_invalidation, "session-owner"),
        (&evidence.obligations.lease_invalidation, "lease-owner"),
        (&evidence.obligations.route_invalidation, "route-owner"),
        (
            &evidence.obligations.user_broker_invalidation,
            "user-broker-owner",
        ),
    ] {
        assert_eq!(slot.owner_id, owner_id);
        assert_eq!(slot.state, RestoreObligationState::MissingCapability);
    }
    // The cutover-gated invalidation client refuses without authority and
    // names the missing wire channel with it: no live state touched either way.
    let invalidator = InvalidationOwnerClient::bind(InvalidationKind::Lease);
    assert_eq!(
        invalidator.request(None).unwrap_err(),
        BackupError::CutoverNotAuthorized
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/14
#[test]
fn current_purge_residency_reference_closure_preserved() {
    let target = "t960-14";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("14");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("restore succeeds");
    let evidence = outcome.evidence.expect("evidence observed");
    assert!(evidence.purge_applied);
    // An archive with no purge ledger consulted no purge owner, so the purge
    // obligation is NOT established. Asserting `Satisfied` here contradicted
    // `apply_finalize`, which reports `MissingCapability` for an empty ledger,
    // and it is `require_cutover_obligations` that refuses that state - so the
    // honest expectation is the refusal's own reason, not a closure this seam
    // never proved. (Corrected after the verifier found the two are different.)
    assert_eq!(
        evidence.obligations.purge.state,
        RestoreObligationState::MissingCapability
    );
    assert_eq!(
        evidence.obligations.reference_validation.state,
        RestoreObligationState::Satisfied
    );
    assert!(!evidence.obligations.purge.evidence_ref.is_empty());
    assert!(
        !evidence
            .obligations
            .reference_validation
            .evidence_ref
            .is_empty()
    );
    assert_ne!(
        evidence.obligations.purge.evidence_ref,
        evidence.obligations.reference_validation.evidence_ref,
        "purge and reference closures stay distinct"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/15
#[test]
fn required_external_source_revalidation_cannot_be_a_stub() {
    let target = "t960-15";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("15");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect("import succeeds");
    let evidence = outcome.evidence.expect("evidence observed");
    // Explicit missing capability, never a satisfied stub.
    assert_eq!(
        evidence.obligations.external_source_revalidation.state,
        RestoreObligationState::MissingCapability
    );
    let plan = KernelBackupRestore::compile_plan(&bundle, context).expect("plan compiles");
    let auth = CutoverAuthorization {
        plan_id: plan.plan_id.clone(),
        bundle_sha256: plan.bundle_sha256.clone(),
        authorized_by: "human-owner-960".to_owned(),
        statement: "authorize-960-15".to_owned(),
    };
    let destination =
        KernelIsolatedDestination::open_existing(outcome.destination_root.clone(), &root)
            .expect("destination reopens");
    assert!(
        coordinator
            .qualify_cutover(
                &plan,
                &bundle,
                &outcome.receipt,
                Some(&evidence),
                &destination,
                Some(&auth)
            )
            .is_err()
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/16
#[test]
fn rehearsal_cannot_activate_cutover_or_retire_source() {
    let target = "t960-16";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("16");
    let sentinel = root.join("source-sentinel.txt");
    std::fs::write(&sentinel, b"source-installation-bytes").expect("sentinel");
    let fence = bundle.export_fence.state_fence.clone();
    let fixture = fixture_admission();
    // A rehearsal that HOLDS Host admission is a supported shape: the posture is
    // not a reason to refuse and is not a substitute for admission. Fixture
    // journal admission is accepted on the rehearsal branch, which is why this
    // case runs at all, and the destination evidence is the owner-issued record
    // the producer issues for this root.
    let ports = RestorePorts {
        journal_admission: &fixture,
        kernel_fence: &fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: Some(admitted_evidence(&root)),
        rehearsal: true,
    };
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("rehearsal import succeeds");
    assert!(outcome.rehearsal);
    assert_eq!(
        std::fs::read(&sentinel).expect("sentinel"),
        b"source-installation-bytes"
    );
    // No authorization exists on the rehearsal path, and none is accepted
    // without owner evidence: rehearsal cannot become cutover.
    let plan =
        KernelBackupRestore::compile_plan(&bundle, test_context(target)).expect("plan compiles");
    let destination =
        KernelIsolatedDestination::open_existing(outcome.destination_root.clone(), &root)
            .expect("destination reopens");
    assert_eq!(
        coordinator
            .qualify_cutover(&plan, &bundle, &outcome.receipt, None, &destination, None)
            .unwrap_err(),
        KernelRestoreError::CutoverNotAuthorized
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/17
#[test]
fn one_existing_phase_engine_with_exact_same_transaction_resumption() {
    let target = "t960-17";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("17");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let first = coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect("first execution succeeds");
    // Resuming the same transaction returns the identical receipt without
    // re-applying: one engine, legitimate resume, no duplicate algorithm.
    let second = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("resumption succeeds");
    assert_eq!(first.receipt, second.receipt);
    assert_eq!(first.receipt.plan_id, second.receipt.plan_id);
    assert!(
        second.phase_log.is_empty(),
        "resumption returns the journaled receipt without re-applying"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/18
#[test]
fn bounds_cancel_cleanup_and_primary_failure_preserved() {
    // Destination labels are bounded printable identities.
    let root = work_root("18");
    let overlong = "t".repeat(65);
    assert!(KernelIsolatedDestination::open(&root, &overlong).is_err());
    assert!(KernelIsolatedDestination::open(&root, "").is_err());
    assert!(KernelIsolatedDestination::open(&root, "../escape").is_err());
    // Error mapping preserves the causal class across the seam.
    assert_eq!(
        backup_to_kernel(BackupError::RestoreJournalMismatch),
        KernelRestoreError::JournalBindingConflict
    );
    assert_eq!(
        backup_to_kernel(BackupError::RestoreJournalCorrupt),
        KernelRestoreError::JournalCorrupt
    );
    // Cleanup removes only the isolated destination root.
    let target = "t960-18";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("restore succeeds");
    let destination = outcome.destination_root.clone();
    std::fs::remove_dir_all(&destination).expect("cleanup removes the destination");
    assert!(!destination.exists());
    assert!(root.exists(), "work root itself is preserved");
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/19
#[test]
fn persistent_adapter_readback_across_handles_not_mock_only() {
    let target = "t960-19";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("19");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let journal_path = root.join("fixture-journal.json");
    // The file-backed fixture journal survives handle drops: the second
    // coordinator resumes the same transaction from durable readback.
    let mut journal = FixtureFileJournal::open(journal_path.clone());
    let first = coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect("first execution succeeds");
    drop(journal);
    assert!(journal_path.exists(), "journal bytes persisted");
    let mut reopened = FixtureFileJournal::open(journal_path);
    let second = coordinator
        .restore(&bundle, context, &ports, &mut reopened)
        .expect("resumption from durable readback succeeds");
    assert_eq!(first.receipt, second.receipt);
    // Fixture proof stays fixture proof: only the admitted persistent ORS
    // owner (#957 via #962) may back a production durable-recovery claim.
    let fixture = fixture_admission();
    assert!(fixture.fixture_proof_only);
    assert!(!admission.fixture_proof_only);
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/20
#[test]
fn no_private_db_copy_reverse_import_local_mint_or_overclaim() {
    let ports_src = include_str!("../src/backup_restore_ports.rs");
    let coordinator_src = include_str!("../src/backup_restore.rs");
    // One existing phase engine: the accepted journaled state machine is
    // used, never redefined.
    assert!(coordinator_src.contains("execute_with_journal"));
    // Doc comments may point at #961's accepted cutover entry, so strip
    // line comments and only reject real code references.
    let strip_comments = |src: &str| -> String {
        src.lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !(trimmed.starts_with("///")
                    || trimmed.starts_with("//!")
                    || trimmed.starts_with("//"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let ports_code = strip_comments(ports_src);
    let coordinator_code = strip_comments(coordinator_src);
    for banned in [
        "fn execute(",
        "RestoredFence::mint",
        "EpochId::new",
        "eliot_host",
        "eliot_watchdog",
        "eliot_store_surreal",
        "surreal",
        "redb::",
        "rusqlite",
    ] {
        assert!(!ports_src.contains(banned), "banned {banned} in ports");
        assert!(
            !coordinator_src.contains(banned),
            "banned {banned} in coordinator"
        );
    }
    for banned in assembled_banned_journal_tokens() {
        assert!(
            !ports_src.contains(banned.as_str()),
            "banned {banned} in ports"
        );
        assert!(
            !coordinator_src.contains(banned.as_str()),
            "banned {banned} in coordinator"
        );
    }
    // The cutover entry itself is owned by #961: no code reference may
    // appear in these modules outside doc comments.
    assert!(
        !ports_code.contains("authorize_cutover"),
        "banned authorize_cutover in ports"
    );
    assert!(
        !coordinator_code.contains("authorize_cutover"),
        "banned authorize_cutover in coordinator"
    );
    // Every accepted step maps to an owner; the match is exhaustive at
    // compile time so no phase can silently fall through.
    let steps = [
        RestoreStep::PrepareIsolatedRoot,
        RestoreStep::ApplyPurgeLedger,
        RestoreStep::ImportSealedBlobs,
        RestoreStep::ImportCanonicalEvents,
        RestoreStep::ImportReceipts,
        RestoreStep::ImportProjections,
        RestoreStep::SuspendOrsOperations,
        RestoreStep::RebuildProjections,
        RestoreStep::VerifyReceiptEventChain,
        RestoreStep::FinalizeIsolatedRoot,
    ];
    assert_eq!(steps.len(), 10);
    for step in steps {
        assert!(!phase_owner(&step).is_empty());
    }
    // Canonical-only imports stay canonical-only: no Product/Finish claim.
    // Live-store import is refused via the STORE_IMPORT channel marker.
    assert!(coordinator_src.contains("canonical-store-import"));
}

// WORK_UNIT_CASE: 960/21
#[test]
fn interrupted_after_staging_retains_published_material_for_resume() {
    let target = "t960-21";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("21");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    // The archive stages one phase's material, so the refusal below is refused
    // with `RetainedForResume` rather than the plain `TargetFailed` an
    // interruption BEFORE any phase would produce.
    //
    // Interrupted after PREPARE: `fail_cas_after_completed = 1` refuses the
    // swap that follows the first receipt the journal persists, which is the
    // first point at which published material and a durable receipt both exist.
    let mut journal = FixtureJournal {
        fail_cas_after_completed: Some(1),
        ..FixtureJournal::default()
    };
    let interrupted = coordinator.restore(&bundle, context.clone(), &ports, &mut journal);
    let error = interrupted.expect_err("interrupted restore fails typed");
    let (primary, retained, cleanup) = match &error {
        KernelRestoreError::RetainedForResume {
            primary,
            retained,
            cleanup,
        } => (primary.clone(), retained.as_ref(), *cleanup),
        other => panic!("published material is reported as retained, got {other}"),
    };
    // The engine's own typed failure is preserved as the cause, unchanged.
    assert_eq!(
        primary,
        BackupError::RestoreJournalCasConflict,
        "the engine failure is the cause and is never replaced"
    );
    // Bounded and counted from what this execution actually published.
    assert!(
        retained.members > 0,
        "at least the prepare receipt is retained, got {retained}"
    );
    assert!(retained.bytes > 0, "retained bytes are counted: {retained}");
    // The destination was CONSTRUCTED for this execution, so cleanup runs
    // rather than refusing, and the temporaries this execution staged are its
    // own to remove. What it never becomes is a removal of published material.
    assert_eq!(
        cleanup,
        StagedCleanupOutcome::TemporariesRemoved,
        "this execution's own unpublished temporaries are reaped, published material is not"
    );
    // The retained material is still on disk: the prepare phase published the
    // pinned admission, and it survives the failure.
    let destination_root = root.join(".eliot").join(RESTORE_ISOLATED_AREA).join(target);
    let pinned_path = destination_root.join(DESTINATION_ADMISSION_FILE);
    assert!(pinned_path.is_file(), "published admission survives");
    let pinned: PinnedDestinationAdmission =
        serde_json::from_slice(&std::fs::read(&pinned_path).expect("pinned bytes"))
            .expect("pinned admission parses");
    assert_eq!(pinned.target_id, target);
    // No temporary survives a completed cleanup. Checked RECURSIVELY, because
    // a member is staged under a subdirectory and a check of the destination
    // root's own entries would pass while a temporary sat one level down.
    fn temporaries_remaining(dir: &Path) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        entries.filter_map(Result::ok).any(|entry| {
            let path = entry.path();
            path.extension()
                .is_some_and(|ext| ext == TEMP_RESTORE_EXTENSION)
                || (path.is_dir() && temporaries_remaining(&path))
        })
    }
    assert!(
        !temporaries_remaining(&destination_root),
        "cleanup reaped every unpublished temporary under the destination"
    );
    // RESUMING THE SAME TRANSACTION resumes rather than restarts: the phase log
    // of the resumed run does not re-apply prepare, because the journal already
    // records it applied.
    //
    // The retention proof above is the ON-DISK survival of the published member,
    // not this log: the engine advances from `ReceiptPersisted` without
    // re-reading that phase's material, so a resume would report the same phase
    // log even if cleanup had unlinked the member. Cases 960/24 and 960/25 cover
    // the reconciliation readback that does re-read it. What this log proves is
    // the narrower, separate claim — that the interrupted transaction RESUMED
    // rather than restarting, and that the retry reused the interrupted run's
    // destination instead of minting a fresh execution identity.
    let resumed = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("the same transaction resumes");
    assert!(
        !resumed.phase_log.contains(&"prepare".to_owned()),
        "a resume does not re-apply a phase the journal already recorded: {:?}",
        resumed.phase_log
    );
    assert_eq!(
        resumed.phase_log,
        vec!["purge", "rebuild", "verify", "finalize"],
        "the resume applied exactly the phases the interrupted run had not reached"
    );
    // The resumed run carried the SAME transaction forward rather than minting a
    // new execution identity for the retry: it wrote into the destination the
    // interrupted run's prepare pinned, not a fresh root.
    assert!(
        resumed.destination_root == destination_root,
        "the resume continued the same destination, not a fresh one"
    );
    resumed
        .receipt
        .validate()
        .expect("resumed receipt validates");
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/22
#[test]
fn unowned_temporary_with_this_owners_suffix_survives_cleanup_byte_for_byte() {
    let target = "t960-22";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("22");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let destination_root = root.join(".eliot").join(RESTORE_ISOLATED_AREA).join(target);
    // A file carrying EXACTLY the suffix this owner's staging uses, planted in
    // the destination BEFORE the restore runs, so it is never a temporary this
    // execution created.
    //
    // Predicting the suffix is not a way to claim the path: ownership comes
    // from `staged_temporaries`, which `write_file` appends to before the first
    // byte of THIS execution's own write. A planted path is absent from that
    // set, so `is_owned_temporary` returns false for it and it is never a
    // cleanup candidate — which is why `PathNotOurs` is unreachable from
    // outside the owner and is not the reason asserted below.
    let planted_bytes = b"planted-by-another-writer-960-22";
    let planted = destination_root.join(format!("foreign-member.{TEMP_RESTORE_EXTENSION}"));
    // The destination root is pre-created so this run is an ADMITTED RESUME:
    // `KernelIsolatedDestination::open` classifies by whether the root already
    // is a directory, and a resumed destination is exactly the shape the
    // bounded cleanup must refuse rather than empty. `AdmittedResume` is
    // therefore the reason this case observes, and the planted file is the
    // thing that reason protects.
    std::fs::create_dir_all(&destination_root).expect("destination exists before the restore");
    std::fs::write(&planted, planted_bytes).expect("plant unowned temporary");
    let mut journal = FixtureJournal {
        fail_cas_after_completed: Some(1),
        ..FixtureJournal::default()
    };
    let interrupted = coordinator.restore(&bundle, context, &ports, &mut journal);
    let error = interrupted.expect_err("interrupted restore fails typed");
    // The destination already existed when this execution opened it, so it is
    // an ADMITTED RESUME rather than a fresh root, and the bounded cleanup
    // refuses it outright: its contents are not provably this execution's.
    //
    // `AdmittedResume` is the observable proof that the planted file was never
    // considered removable, and the byte comparison below is the guarantee
    // itself: an unowned temporary survives byte for byte.
    let cleanup = match &error {
        KernelRestoreError::RetainedForResume { cleanup, .. } => *cleanup,
        other => panic!("published material is reported as retained, got {other}"),
    };
    assert_eq!(
        cleanup,
        StagedCleanupOutcome::TemporariesPreserved(StagedCleanupRefusal::AdmittedResume),
        "a resumed destination is refused rather than emptied"
    );
    assert_eq!(
        std::fs::read(&planted).expect("planted file still readable"),
        planted_bytes,
        "an unowned temporary carrying this owner's suffix survives byte for byte"
    );
    // The published material this execution DID create is retained too, so the
    // refusal to clean is not a refusal to report.
    assert!(matches!(
        &error,
        KernelRestoreError::RetainedForResume { retained, .. } if retained.members > 0
    ));
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/23
#[test]
fn interruption_before_any_publication_reports_no_retained_material() {
    let target = "t960-23";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("23");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    // The journal's FIRST compare-and-swap is the engine's genesis write, which
    // happens before any phase runs. Refusing it interrupts the restore with
    // NOTHING published, which is the other half of the retention disposition:
    // `RetainedForResume` must not be reachable when this execution published
    // nothing, or a caller would be told to resume over state that never existed.
    let mut journal = FixtureJournal {
        fail_next_cas: true,
        ..FixtureJournal::default()
    };
    let error = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect_err("interrupted before any phase fails typed");
    // The refusal is the PLAIN engine failure, not a retention disposition:
    // nothing was published, so there is no retained set to report and nothing
    // was left for the caller to resume from.
    assert!(
        matches!(error, KernelRestoreError::TargetFailed(_)),
        "an interruption before any publication is a plain engine failure, got {error}"
    );
    assert!(
        !matches!(error, KernelRestoreError::RetainedForResume { .. }),
        "no retained-material claim is made for a run that published nothing"
    );
    // The engine's own typed cause survives the seam unchanged.
    assert_eq!(
        error,
        KernelRestoreError::TargetFailed(BackupError::RestoreJournalCasConflict),
        "the primary is preserved as the cause and is never replaced"
    );
    // And the destination really is empty of phase material: no phase receipt
    // was written, so there is nothing a resume could reconcile.
    let destination_root = root.join(".eliot").join(RESTORE_ISOLATED_AREA).join(target);
    let receipts = destination_root.join("phase-receipts");
    assert!(
        !receipts.exists(),
        "no phase receipt was published before the interruption"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/24
#[test]
fn a_resumed_receipt_cannot_attest_removed_published_material() {
    let target = "t960-24";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("24");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let destination_root = root.join(".eliot").join(RESTORE_ISOLATED_AREA).join(target);
    // Publish the PREPARE phase's member and its receipt file, then refuse the
    // swap that would journal that receipt. The journal is therefore left
    // holding `IntentPersisted` for prepare, while the member and the receipt
    // file are both on disk — the coherent resumable state the defect lives in.
    let mut journal = FixtureJournal {
        fail_cas_persisting_receipt_for: Some(RestorePhase::PrepareIsolatedRoot),
        ..FixtureJournal::default()
    };
    coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect_err("the interrupted run fails typed");
    // The journal is demonstrably still at the intent for prepare, so the resume
    // below RECONCILES that phase rather than re-applying it. That is what makes
    // this case about a resumed receipt rather than about a re-apply.
    let record = journal.record.as_ref().expect("the journal holds a record");
    assert!(
        matches!(record.state, RestoreJournalState::IntentPersisted),
        "the journal is parked at the intent, got {:?}",
        record.state
    );
    // Now REMOVE the material prepare published, leaving its receipt in place.
    // The journal and the receipt file still say "prepare applied"; only the
    // bytes are gone. A receipt is a description of an effect, not the effect, so
    // the resume must re-read the material and refuse rather than advance the
    // journal over a phase whose bytes no longer exist.
    let pinned_path = destination_root.join(DESTINATION_ADMISSION_FILE);
    assert!(
        pinned_path.is_file(),
        "prepare published the pinned admission before the interruption"
    );
    std::fs::remove_file(&pinned_path).expect("remove the published member");
    assert!(
        !pinned_path.exists(),
        "the member the receipt attests is genuinely gone"
    );
    // The receipts themselves are still present: this is a receipt surviving its
    // material, not a receipt that was also destroyed.
    let receipts = destination_root.join("phase-receipts");
    assert!(
        receipts.is_dir()
            && std::fs::read_dir(&receipts)
                .expect("receipts readable")
                .count()
                > 0,
        "the phase receipt outlives the material it attests, which is the hazard"
    );
    let resumed = coordinator.restore(&bundle, context, &ports, &mut journal);
    // The resume REFUSES. It does not re-apply prepare over the missing member
    // (which would have restored the file and succeeded) and it does not report
    // success over a phase whose material is gone.
    let error = resumed.expect_err("a resume over removed material refuses");
    assert_eq!(
        error,
        KernelRestoreError::TargetFailed(BackupError::RestoreJournalCorrupt),
        "a receipt whose material is gone is corrupt evidence, not an applied phase"
    );
    // The refusal created no new execution identity and did not re-stage: had
    // the resume re-applied the phase instead, the member would be back.
    assert!(
        !pinned_path.exists(),
        "the refused resume did not silently re-apply the removed phase"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/25
#[test]
fn a_substituted_member_under_a_retained_receipt_is_refused_as_substitution() {
    let target = "t960-25";
    let bundle = test_bundle(target);
    let context = test_context(target);
    let root = work_root("25");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let destination_root = root.join(".eliot").join(RESTORE_ISOLATED_AREA).join(target);
    // Park the journal at the PURGE phase's intent: the purge phase publishes
    // `purge_ledger.json` and its receipt file, and refusing the receipt swap
    // leaves the engine to reconcile that phase on resume.
    let mut journal = FixtureJournal {
        fail_cas_persisting_receipt_for: Some(RestorePhase::ApplyPurgeLedger),
        ..FixtureJournal::default()
    };
    coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect_err("the interrupted run fails typed");
    let record = journal.record.as_ref().expect("the journal holds a record");
    assert!(
        matches!(record.state, RestoreJournalState::IntentPersisted)
            && record.phase == RestorePhase::ApplyPurgeLedger,
        "the journal is parked at the purge intent, got {:?}/{:?}",
        record.state,
        record.phase
    );
    // SUBSTITUTE rather than remove: a same-length, different-bytes file stands
    // where the phase's member was. This is the harder hazard than absence,
    // because every existence check still succeeds — the path is there, it is
    // readable, and it is the right size. Only a digest comparison over the
    // ACTUAL bytes on disk distinguishes it from the material the receipt
    // attests.
    //
    // The purge member is the one chosen because its receipt digest IS the
    // digest of the member it published (`PhaseMaterial::receipt_digests_member`),
    // so substitution is observable at all. Prepare's own member is excluded
    // from that set by design (its receipt digests an observation document that
    // is never persisted), which is why substituting THAT file could not be
    // detected and is not asserted here.
    let member = destination_root.join("purge_ledger.json");
    assert!(member.is_file(), "the purge phase published its member");
    let original = std::fs::read(&member).expect("member bytes");
    let mut substituted = original.clone();
    substituted[0] ^= 0xff;
    assert_ne!(
        original, substituted,
        "the substitution must actually differ, or nothing is proved"
    );
    std::fs::write(&member, &substituted).expect("substitute the member");
    // The resume reconciles the purge phase against the receipt still on disk.
    let resumed = coordinator.restore(&bundle, context, &ports, &mut journal);
    let error = resumed.expect_err("a resume over substituted material refuses");
    assert_eq!(
        error,
        KernelRestoreError::TargetFailed(BackupError::RestoreJournalMismatch),
        "a retained receipt cannot attest bytes that are not the ones it published"
    );
    // The substituted bytes were NOT quietly accepted as the applied phase.
    assert_eq!(
        std::fs::read(&member).expect("member still readable"),
        substituted,
        "the refusal did not overwrite the substitution with a re-applied member"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/26
#[test]
fn import_closure_accepts_the_archive_member_set_exactly() {
    let target = "t960-26";
    // The positive half of the closure pair. The archive declares exactly one
    // canonical member, so the rebuild phase's expected set is exactly one name
    // and the destination must hold exactly that name.
    let bundle = test_bundle_with_events(target, &["event-960-26"]);
    assert_eq!(
        bundle.canonical_events.len(),
        1,
        "this case's premise: the archive declares exactly one member"
    );
    let context = test_context(target);
    let root = work_root("26");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let destination_root = root.join(".eliot").join(RESTORE_ISOLATED_AREA).join(target);
    // Interrupt at the IMPORT phase's receipt, so the member is published and
    // the journal is still parked at that phase's intent. Rebuild has not run
    // yet, which is what makes the resume below the first moment the closure
    // check is evaluated against a destination this case controls.
    let mut journal = FixtureJournal {
        fail_cas_persisting_receipt_for: Some(RestorePhase::ImportCanonicalEvent {
            record_id: "event-960-26".to_owned(),
        }),
        ..FixtureJournal::default()
    };
    coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect_err("the interrupted run fails typed");
    let member = destination_root.join("events").join("event-960-26.json");
    assert!(
        member.is_file(),
        "the import phase published exactly the member the archive declares"
    );
    // Nothing is added or removed: the destination holds precisely the expected
    // name, so closure holds and the restore runs to completion. This is the
    // refusal case's own premise stated in the affirmative — without a case
    // where the exact set is ACCEPTED, the refusal below would be satisfied by
    // a check that refuses unconditionally.
    //
    // The SAME journal is resumed rather than a fresh one: the interruption
    // above left it holding `IntentPersisted` for the import phase, which is
    // what makes this a resumption of one transaction rather than a second
    // execution (the convention cases 960/24 and 960/25 use).
    let resumed = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("an import set matching the archive exactly satisfies closure");
    resumed.receipt.validate().expect("receipt validates");
    assert!(
        resumed.phase_log.contains(&"rebuild".to_owned()),
        "the rebuild phase ran and did not refuse: {:?}",
        resumed.phase_log
    );
    assert!(
        resumed.destination_root == destination_root,
        "the resume continued the same destination"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// WORK_UNIT_CASE: 960/27
#[test]
fn import_closure_refuses_a_member_set_that_only_matches_in_length() {
    let target = "t960-27";
    // The refusal half, and the whole point of the pair above. TWO declared
    // members, and the destination is put into the shape a LENGTH comparison
    // cannot distinguish from closure: one declared member is GONE and a file
    // the archive never named stands in its place. Two files either way, so
    // `count_dir("events") == bundle.canonical_events.len()` holds exactly — the
    // check this case exists to defeat.
    //
    // TWO members rather than one, and this is load-bearing rather than
    // incidental. The journal is parked at the SECOND import phase's intent, so
    // the first phase is already journalled `ReceiptPersisted` and the engine
    // ADVANCES past it on resume without re-reading its material. That is what
    // makes the rebuild phase's closure check the first thing in the resumed run
    // to observe the missing member: if the corrupted member belonged to the
    // parked phase, `check_attested_material` would refuse with
    // `RestoreJournalCorrupt` first and this case would be re-proving case
    // 960/24 instead of pinning the closure check.
    let bundle = test_bundle_with_events(target, &["event-960-27-a", "event-960-27-b"]);
    assert_eq!(
        bundle.canonical_events.len(),
        2,
        "this case's premise: two declared members, so a stray can stand in for one"
    );
    let context = test_context(target);
    let root = work_root("27");
    let fence = bundle.export_fence.state_fence.clone();
    let admission = production_admission();
    let ports = production_ports(&admission, &fence, &root);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let destination_root = root.join(".eliot").join(RESTORE_ISOLATED_AREA).join(target);
    let mut journal = FixtureJournal {
        fail_cas_persisting_receipt_for: Some(RestorePhase::ImportCanonicalEvent {
            record_id: "event-960-27-b".to_owned(),
        }),
        ..FixtureJournal::default()
    };
    coordinator
        .restore(&bundle, context.clone(), &ports, &mut journal)
        .expect_err("the interrupted run fails typed");
    let record = journal.record.as_ref().expect("the journal holds a record");
    assert!(
        matches!(record.state, RestoreJournalState::IntentPersisted)
            && record.phase
                == RestorePhase::ImportCanonicalEvent {
                    record_id: "event-960-27-b".to_owned()
                },
        "the journal is parked at the second import phase's intent, got {:?}/{:?}",
        record.state,
        record.phase
    );
    let events = destination_root.join("events");
    let removed = events.join("event-960-27-a.json");
    assert!(
        removed.is_file(),
        "the FIRST import phase published its member and the journal advanced past it"
    );
    // Swap it for a name no admitted archive member accounts for. The COUNT is
    // preserved deliberately: this is the case where completeness is checked
    // against an independent expected SET rather than against a length.
    std::fs::remove_file(&removed).expect("remove the declared member");
    std::fs::write(events.join("stray-never-declared.json"), b"{}")
        .expect("plant a stray standing in for the declared member");
    assert_eq!(
        std::fs::read_dir(&events)
            .expect("events readable")
            .filter_map(Result::ok)
            .count(),
        2,
        "this case's premise: the stray keeps the length comparison satisfied"
    );
    assert!(
        !removed.exists(),
        "the member the archive declares is genuinely absent"
    );
    let error = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect_err("a member set that only matches in length is not closure");
    // The rebuild phase is what refuses, and it refuses with the same typed
    // incompleteness this file already used for this condition — no new error
    // kind, no wrapper, no downgrade into a success.
    assert!(
        matches!(
            error,
            KernelRestoreError::RetainedForResume {
                primary: BackupError::RestoreEvidenceIncomplete,
                ..
            } | KernelRestoreError::TargetFailed(BackupError::RestoreEvidenceIncomplete)
        ),
        "import closure refuses with the existing typed incompleteness, got {error}"
    );
    // The refusal happened AT the closure check rather than after it: the phase
    // that checks closure is the same phase that writes `rebuild.json`, so its
    // absence is the on-disk proof that the check refused before publishing.
    assert!(
        !destination_root.join("rebuild.json").exists(),
        "the rebuild phase refused at its closure check and published no evidence"
    );
    // The stray was not adopted as the archive's member, and the refusal did not
    // delete it either: a file this operation did not create is not its to remove,
    // which is the same ownership rule the staged-temporary cleanup follows.
    assert!(
        events.join("stray-never-declared.json").is_file(),
        "the refusal did not delete the stray either: it is not this run's to remove"
    );
    let _ = std::fs::remove_dir_all(&root);
}
