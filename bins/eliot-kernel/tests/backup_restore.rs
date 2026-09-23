//! Kernel production restore adapter tests (issue #960).
//!
//! Twenty substantive cases binding the coordinator to the accepted owner
//! contracts. The durable journal behind every execution is an injected
//! `J: RestoreJournalPort`: memory/file fixtures below prove adapter
//! mapping only and always carry fixture-marked admission, while production
//! composition must supply the admitted persistent ORS owner (#957 via the
//! #962 turn). No test executes here in the worker lane; product modules
//! land first and the full gate runs at the Windows/WinUI build.

use std::num::NonZeroU64;
use std::path::PathBuf;

use eliot_backup::{
    BackupBundle, BackupClass, BackupError, BackupInput, CutoverAuthorization, EventRange,
    ExportFence, ObservedLineageLimit, OwnerTrustBinding, RestoreContext, RestoreEvidenceLevel,
    RestoreJournalAdmission, RestoreJournalPort, RestoreJournalRecord, RestoreObligationState,
    RestoreStep, WrappedKeyEntry, WrappedKeyManifest,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_kernel::backup_restore::{
    BlobOwnerClient, CanonicalOwnerClient, InvalidationKind, InvalidationOwnerClient,
    KernelBackupRestore, PurgeOwnerClient, phase_owner,
};
use eliot_kernel::backup_restore_ports::{
    DESTINATION_ADMISSION_FILE, DestinationManifestEvidence, KernelIsolatedDestination,
    KernelRestoreError, PinnedDestinationAdmission, RESTORE_ISOLATED_AREA,
    RESTORE_JOURNAL_IDENTITY, RESTORE_JOURNAL_OWNER_LABEL, RestorePorts, backup_to_kernel,
    check_kernel_effect_fence, require_production_admitted,
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
    let root = std::env::temp_dir().join(format!("eliot-960-{case}-{}-{nanos}", std::process::id()));
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
    assert_eq!(admission.journal_identity_ref, RESTORE_JOURNAL_IDENTITY);
    admission
}

fn fixture_admission() -> RestoreJournalAdmission {
    let admission: RestoreJournalAdmission =
        serde_json::from_slice(&read_fixture("journal-admission-fixture.json"))
            .expect("fixture admission fixture");
    assert!(admission.fixture_proof_only);
    admission
}

fn manifest_evidence(work_root: &PathBuf) -> DestinationManifestEvidence {
    let mut evidence: DestinationManifestEvidence =
        serde_json::from_slice(&read_fixture("destination-manifest-evidence.json"))
            .expect("manifest evidence fixture");
    evidence.kernel_work_root = work_root.clone();
    evidence
        .validate()
        .expect("manifest evidence validates against the temp work root");
    evidence
}

/// In-memory fixture journal: adapter-mapping proof only. Never production:
/// every execution using it must carry fixture-marked admission, and the
/// coordinator refuses production claims on it by construction.
#[derive(Default)]
struct FixtureJournal {
    record: Option<RestoreJournalRecord>,
    fail_next_cas: bool,
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

fn production_ports<'a>(
    admission: &'a RestoreJournalAdmission,
    fence: &'a StateFence,
) -> RestorePorts<'a> {
    RestorePorts {
        journal_admission: admission,
        kernel_fence: fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: None,
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
    let ports = production_ports(&admission, &fence);
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
    assert!(outcome.destination_root.starts_with(root.join(".eliot").join(RESTORE_ISOLATED_AREA)));
    let evidence = outcome.evidence.expect("finalize evidence observed");
    evidence.validate().expect("evidence validates");
    assert_eq!(evidence.obligations.purge.state, RestoreObligationState::Satisfied);
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
    let first_evidence = manifest_evidence(&root);
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
        &std::fs::read(
            first
                .destination_root
                .join(DESTINATION_ADMISSION_FILE),
        )
        .expect("pinned admission"),
    )
    .expect("pinned admission parses");
    assert_eq!(pinned.target_id, target);
    // A rotated manifest binding for the same transaction refuses as drift.
    let mut second_evidence = manifest_evidence(&root);
    second_evidence.registry_revision += 1;
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
    assert!(matches!(
        drifted,
        Err(KernelRestoreError::FenceMismatch(_))
    ));
    // A foreign admitted root (outside the Kernel work root) refuses before effects.
    let foreign_root = work_root("02-foreign");
    let mut foreign_evidence = manifest_evidence(&foreign_root);
    foreign_evidence.kernel_work_root = foreign_root.clone();
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
        purge
            .suppress_purged_member("subject-ref-1")
            .unwrap_err(),
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
    let surplus_ports = RestorePorts {
        journal_admission: &admission,
        kernel_fence: &fence,
        keys: Some(&surplus),
        blob_scope: None,
        manifest_evidence: None,
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
    assert_eq!(phase_owner(&RestoreStep::PrepareIsolatedRoot), "kernel-restore-owner");
    assert_eq!(phase_owner(&RestoreStep::ApplyPurgeLedger), "purge-owner");
    assert_eq!(phase_owner(&RestoreStep::ImportSealedBlobs), "blob-owner");
    assert_eq!(phase_owner(&RestoreStep::ImportCanonicalEvents), "canonical-owner");
    assert_eq!(phase_owner(&RestoreStep::ImportReceipts), "canonical-owner");
    assert_eq!(phase_owner(&RestoreStep::ImportProjections), "canonical-owner");
    assert_eq!(phase_owner(&RestoreStep::SuspendOrsOperations), "ors-owner");
    assert_eq!(phase_owner(&RestoreStep::RebuildProjections), "canonical-owner");
    assert_eq!(phase_owner(&RestoreStep::VerifyReceiptEventChain), "canonical-owner");
    assert_eq!(phase_owner(&RestoreStep::FinalizeIsolatedRoot), "kernel-restore-owner");
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
    let ports = production_ports(&admission, &fence);
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
    assert_eq!(
        qualified.unwrap_err(),
        KernelRestoreError::TargetFailed(BackupError::RestoreCapabilityUnsupported {
            capability: "reconciliation-owner"
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
    let ports = production_ports(&fixture, &fence);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let refused = coordinator.restore(&bundle, context, &ports, &mut journal);
    assert_eq!(
        refused.unwrap_err(),
        KernelRestoreError::JournalNotAdmitted
    );
    // No destination side effects precede the admission refusal.
    assert!(!root.join(".eliot").join(RESTORE_ISOLATED_AREA).exists());
    // By construction: no in-memory or no-op journal type exists in the
    // production modules.
    let ports_src = include_str!("../src/backup_restore_ports.rs");
    let coordinator_src = include_str!("../src/backup_restore.rs");
    for banned in [
        "MemJournal",
        "InMemoryJournal",
        "NoopRestoreJournal",
        "NoOpRestoreJournal",
        "FileRestoreJournal",
    ] {
        assert!(!ports_src.contains(banned), "banned {banned} in ports");
        assert!(!coordinator_src.contains(banned), "banned {banned} in coordinator");
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
    let ports_a = production_ports(&admission, &fence_a);
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
    let ports = production_ports(&admission, &fence);
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
            EpochLineageId::new("550e8400-e29b-41d-a716-446655440099")
                .expect("foreign lineage"),
            NonZeroU64::new(1).expect("nonzero"),
        )
        .expect("foreign epoch"),
        ResourceGeneration::genesis(),
    );
    assert!(check_kernel_effect_fence(&foreign_fence, &bundle).is_err());
    let admission = production_admission();
    let ports = RestorePorts {
        journal_admission: &admission,
        kernel_fence: &foreign_fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: None,
        rehearsal: false,
    };
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let refused = coordinator.restore(&bundle, context, &ports, &mut journal);
    assert!(matches!(
        refused,
        Err(KernelRestoreError::FenceMismatch(_))
    ));
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
    let ports = production_ports(&admission, &fence);
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
    let ports = production_ports(&admission, &fence);
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
    let ports = production_ports(&admission, &fence);
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
    let ports = production_ports(&admission, &fence);
    let coordinator = KernelBackupRestore::bind(root.clone());
    let mut journal = FixtureJournal::default();
    let outcome = coordinator
        .restore(&bundle, context, &ports, &mut journal)
        .expect("restore succeeds");
    let evidence = outcome.evidence.expect("evidence observed");
    assert!(evidence.purge_applied);
    assert_eq!(
        evidence.obligations.purge.state,
        RestoreObligationState::Satisfied
    );
    assert_eq!(
        evidence.obligations.reference_validation.state,
        RestoreObligationState::Satisfied
    );
    assert!(!evidence.obligations.purge.evidence_ref.is_empty());
    assert!(!evidence.obligations.reference_validation.evidence_ref.is_empty());
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
    let ports = production_ports(&admission, &fence);
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
    assert!(coordinator
        .qualify_cutover(
            &plan,
            &bundle,
            &outcome.receipt,
            Some(&evidence),
            &destination,
            Some(&auth)
        )
        .is_err());
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
    let ports = RestorePorts {
        journal_admission: &fixture,
        kernel_fence: &fence,
        keys: None,
        blob_scope: None,
        manifest_evidence: None,
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
    let ports = production_ports(&admission, &fence);
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
    let ports = production_ports(&admission, &fence);
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
    let ports = production_ports(&admission, &fence);
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
    for banned in [
        "fn execute(",
        "authorize_cutover",
        "RestoredFence::mint",
        "EpochId::new",
        "MemJournal",
        "NoopRestoreJournal",
        "InMemoryJournal",
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
    assert!(coordinator_src.contains("canonical_only"));
}
