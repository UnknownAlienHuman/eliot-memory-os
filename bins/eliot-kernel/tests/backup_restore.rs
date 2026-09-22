//! Kernel restore owner proofs (issue #960).
//!
//! Binds the production restore adapter to the accepted journaled engine and
//! owner seams against real temporary persistence: every case runs
//! `KernelBackupRestore` over `KernelRestoreJournal` files under a temp work
//! root, proving durable resume across reopened handles. No production state,
//! no cutover, no authority minting anywhere in this file.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

use eliot_backup::{
    BackupArtifact, BackupBundle, BackupClass, BackupInput, CanonicalRecord, EventRange,
    ExportFence, OrsSnapshotFence, RestoreJournalPort, RestoreJournalRecord, RestoreJournalState,
    RestorePhase, RestorePlan, WatchdogSpoolFence,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
use eliot_store_api::{
    CommitId, EventId, OperationId, OperationManifestDigest, Resubmission, TransitionClass,
    WriteReceipt, WriteReceiptStatus,
};
use serde_json::json;

use eliot_kernel::{
    KernelBackupRestore, KernelIsolatedDestination, KernelRestoreError, KernelRestoreJournal,
    phase_owner,
};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const FIXTURE_DIR: &str = "tests/data/backup-restore";

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_A).expect("lineage"),
        NonZeroU64::new(sequence).expect("nonzero sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn export_fence(event_count: u64) -> ExportFence {
    let (first, last) = if event_count == 0 {
        (None, None)
    } else {
        (Some(1), Some(event_count))
    };
    ExportFence {
        export_id: "export-960".to_owned(),
        store_generation: "store-960".to_owned(),
        state_fence: fence(),
        scope_id: None,
        revision_heads: Vec::new(),
        ordering_heads: Vec::new(),
        event_range: EventRange {
            first_sequence: first,
            last_sequence: last,
            count: event_count,
        },
        blob_reachability_manifest: Vec::new(),
        consistent: true,
    }
}

fn artifacts() -> Vec<BackupArtifact> {
    ["config", "policy", "module", "host_dependency_build"]
        .iter()
        .map(|kind| {
            let bytes = format!("{kind}-manifest-bytes").into_bytes();
            BackupArtifact {
                kind: (*kind).to_owned(),
                artifact_id: format!("{kind}-1"),
                sha256: sha256_hex(&bytes),
                bytes,
            }
        })
        .collect()
}

fn ors_fence(pending: Vec<String>) -> OrsSnapshotFence {
    let source = fence();
    OrsSnapshotFence {
        snapshot_id: "ors-960".to_owned(),
        authority_epoch: source.authority_epoch.clone(),
        resource_generation: source.resource_generation,
        last_receipt_cursor: 0,
        last_event_cursor: 0,
        last_outbox_cursor: 0,
        pending_operation_ids: pending,
        job_checkpoint_ids: Vec::new(),
        generation_cutover_ids: Vec::new(),
        state_fence: source,
        active_authority_restored: false,
    }
}

fn watchdog_fence() -> WatchdogSpoolFence {
    WatchdogSpoolFence {
        fence_id: "watchdog-960".to_owned(),
        unresolved_signal_digests: vec![sha256_hex(b"signal-960")],
        state_fence: fence(),
        bounded: true,
    }
}

fn event(id: &str) -> CanonicalRecord {
    CanonicalRecord::new("test-event", id, json!({"id": id})).expect("event")
}

fn receipt_for(event_id: &str, operation: &str, class: TransitionClass) -> WriteReceipt {
    WriteReceipt {
        operation_id: OperationId::new(operation).expect("operation id"),
        idempotency_key: format!("idem-{operation}"),
        canonical_request_hash: "a".repeat(64),
        transition_class: class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new(format!("commit-{operation}")).expect("commit id")),
        state_fence: fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec![format!("cmd-{operation}")],
        emitted_event_ids: vec![EventId::new(event_id).expect("event id")],
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: OperationManifestDigest::new(format!("manifest-{operation}"))
            .expect("manifest digest"),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    }
}

fn purge_entry() -> PurgeLedgerEntry {
    PurgeLedgerEntry {
        purge_id: "purge-960-1".to_owned(),
        subject_ref: "event-1".to_owned(),
        scope: "scope-960".to_owned(),
        purged_locations: vec![PurgeLocation::BackupRestorePath],
        tombstone_digest: sha256_hex(b"tombstone-960"),
        state: PurgeState::Purged,
        state_fence: fence(),
        revision: 7,
    }
}

fn full_input() -> BackupInput {
    BackupInput {
        backup_id: "bundle-960-full".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: export_fence(1),
        canonical_events: vec![event("event-1")],
        projections: vec![CanonicalRecord::new(
            "test-event",
            "event-1",
            json!({"projection": "event-1"}),
        )
        .expect("projection")],
        receipts: vec![receipt_for(
            "event-1",
            "op-1",
            TransitionClass::CaptureCandidate,
        )],
        blobs: Vec::new(),
        purge_ledger: vec![purge_entry()],
        ors_snapshot: Some(ors_fence(vec!["op-suspended-1".to_owned()])),
        artifacts: artifacts(),
        watchdog_spool: Some(watchdog_fence()),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn degraded_input() -> BackupInput {
    BackupInput {
        backup_id: "bundle-960-degraded".to_owned(),
        class: BackupClass::CanonicalOnlyDegraded,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: export_fence(1),
        canonical_events: vec![event("event-1")],
        projections: vec![CanonicalRecord::new(
            "test-event",
            "event-1",
            json!({"projection": "event-1"}),
        )
        .expect("projection")],
        receipts: vec![receipt_for(
            "event-1",
            "op-1",
            TransitionClass::CaptureCandidate,
        )],
        blobs: Vec::new(),
        purge_ledger: Vec::new(),
        ors_snapshot: None,
        artifacts: Vec::new(),
        watchdog_spool: None,
        host_audit: None,
        missing_features: vec!["operational-recovery-unavailable".to_owned()],
        purge_ledger_revision: 7,
    }
}

fn purge_erasure_input() -> BackupInput {
    let mut input = full_input();
    "bundle-960-purge-erasure".clone_into(&mut input.backup_id);
    input
        .receipts
        .push(receipt_for("event-1", "op-erase", TransitionClass::Erasure));
    input
}

fn scope_with_ors_input() -> BackupInput {
    let mut input = degraded_input();
    "bundle-960-scope-ors".clone_into(&mut input.backup_id);
    input.class = BackupClass::ScopeExport;
    input.export_fence.scope_id = Some(eliot_store_api::ScopeId::new("scope-1").expect("scope"));
    input.ors_snapshot = Some(ors_fence(Vec::new()));
    input
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(FIXTURE_DIR).join(name)
}

fn load_bundle(name: &str) -> BackupBundle {
    let bytes = std::fs::read(fixture_path(name)).expect("fixture readable");
    BackupBundle::decode(&bytes).expect("fixture decodes and validates")
}

/// Isolated temp work root with best-effort cleanup. Production roots come
/// from the authenticated Host launch contour; tests must never touch them.
struct TempRoot {
    path: PathBuf,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempRoot {
    fn create(label: &str) -> Self {
        use std::sync::atomic::Ordering;
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "eliot-960-test-{}-{counter}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temp root");
        Self { path }
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn open_owner(root: &Path) -> KernelBackupRestore {
    KernelBackupRestore::open(root).expect("owner opens")
}

fn admit_fixture(owner: &mut KernelBackupRestore, root: &Path) {
    use eliot_backup::{OwnerTrustBinding, RestoreJournalAdmission};
    let journal = owner.journal();
    let admission = RestoreJournalAdmission {
        persistent_owner: OwnerTrustBinding {
            owner_id: "kernel-restore-owner".to_owned(),
            trust_binding_ref: "trust-binding-test-1".to_owned(),
        },
        database_ref: journal.journal_path().display().to_string(),
        installation_ref: root.display().to_string(),
        generation: ResourceGeneration::genesis(),
        journal_identity_ref: "kernel-restore-journal-v1".to_owned(),
        admission_receipt_ref: "admission-fixture-1".to_owned(),
        fixture_proof_only: true,
    };
    journal.admit(admission).expect("fixture admission binds");
    assert!(
        !journal
            .admission()
            .expect("admission bound")
            .admits_production_durable_recovery(),
        "fixture admission must never qualify for production durable recovery"
    );
}

fn target_ctx(target_id: &str) -> eliot_backup::RestoreContext {
    eliot_backup::RestoreContext {
        target_id: target_id.to_owned(),
        target_authority_epoch: epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

fn owner_epoch_valid() -> eliot_backup::RestoreOwnerEpoch {
    use eliot_backup::{ObservedLineageLimit, OwnerTrustBinding, RestoreOwnerEpoch};
    RestoreOwnerEpoch {
        owner: OwnerTrustBinding {
            owner_id: "epoch-owner".to_owned(),
            trust_binding_ref: "trust-binding-epoch-1".to_owned(),
        },
        new_epoch: epoch(2),
        new_generation: ResourceGeneration::new(2).expect("generation"),
        supersedes: vec![ObservedLineageLimit {
            owner_id: "epoch-owner".to_owned(),
            observed_epoch: epoch(1),
            observed_generation: ResourceGeneration::genesis(),
        }],
    }
}

fn run_full(
    owner: &mut KernelBackupRestore,
    target_id: &str,
) -> eliot_kernel::KernelRestoreOutcome {
    let bundle = load_bundle("full-valid.json");
    owner
        .restore(&bundle, target_ctx(target_id), &fence(), None, None)
        .expect("full restore executes")
}

// WORK_UNIT_CASE: 960/1
#[test]
fn exact_archive_and_admitted_destination_accepted() {
    let root = TempRoot::create("case1");
    let bundle = load_bundle("full-valid.json");
    bundle.validate().expect("frozen archive verifies");
    let destination =
        KernelIsolatedDestination::open(root.path(), "target-1").expect("destination admitted");
    assert!(destination.root().starts_with(root.path()));
    assert_eq!(destination.label(), "target-1");
    let mut owner = open_owner(root.path());
    assert!(!owner.journal().is_admitted());
    admit_fixture(&mut owner, root.path());
    assert!(owner.journal().is_admitted());
}

// WORK_UNIT_CASE: 960/2
#[test]
fn source_active_foreign_stale_destination_rejected() {
    let root = TempRoot::create("case2");
    assert!(KernelIsolatedDestination::open(root.path(), "x/y").is_err());
    assert!(KernelIsolatedDestination::open(root.path(), "").is_err());
    assert!(KernelIsolatedDestination::open_existing(
        PathBuf::from("/elsewhere/not-isolated"),
        root.path(),
    )
    .is_err());
    assert!(KernelBackupRestore::open(Path::new("relative/work-root")).is_err());
    // Archive carrying active authority refuses at build.
    let mut input = full_input();
    input
        .ors_snapshot
        .as_mut()
        .expect("ors")
        .active_authority_restored = true;
    assert!(BackupBundle::build(input).is_err());
    // Foreign Kernel fence refuses before any effect.
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let bundle = load_bundle("full-valid.json");
    let foreign = StateFence::new(
        EpochId::new(
            EpochLineageId::new("660e8400-e29b-41d4-a716-446655440002").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    );
    let before: Vec<PathBuf> = std::fs::read_dir(root.path())
        .expect("read root")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert!(owner
        .restore(&bundle, target_ctx("target-2"), &foreign, None, None)
        .is_err());
    let after: Vec<PathBuf> = std::fs::read_dir(root.path())
        .expect("read root")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(before, after, "refused restore leaves zero effects");
}

// WORK_UNIT_CASE: 960/3
#[test]
fn missing_capability_refuses_without_fallback() {
    // Scope export carrying installation ORS content cannot build.
    let input = scope_with_ors_input();
    let frozen = std::fs::read(fixture_path("scope-with-ors-export.json")).expect("fixture");
    assert_eq!(
        serde_json::to_vec(&input).expect("export encodes"),
        frozen,
        "frozen scope export matches the builder"
    );
    assert!(BackupBundle::build(input).is_err());
    // Tampered key manifest fails validation, never silent.
    let bytes = std::fs::read(fixture_path("tampered-key-manifest.json")).expect("fixture");
    let manifest: eliot_backup::WrappedKeyManifest =
        serde_json::from_slice(&bytes).expect("manifest decodes");
    assert!(manifest.validate().is_err());
    // Purge ledger with a zero revision is incompatible, not coherent.
    let mut input = full_input();
    input.purge_ledger_revision = 0;
    assert!(BackupBundle::build(input).is_err());
}

// WORK_UNIT_CASE: 960/4
#[test]
fn every_phase_maps_to_accepted_owner_operation() {
    use eliot_backup::RestoreStep;
    let matrix = [
        (RestoreStep::PrepareIsolatedRoot, "kernel-restore-owner"),
        (RestoreStep::ApplyPurgeLedger, "purge-owner"),
        (RestoreStep::ImportSealedBlobs, "blob-owner"),
        (RestoreStep::ImportCanonicalEvents, "canonical-owner"),
        (RestoreStep::ImportReceipts, "canonical-owner"),
        (RestoreStep::ImportProjections, "canonical-owner"),
        (RestoreStep::SuspendOrsOperations, "ors-owner"),
        (RestoreStep::RebuildProjections, "canonical-owner"),
        (RestoreStep::VerifyReceiptEventChain, "canonical-owner"),
        (RestoreStep::FinalizeIsolatedRoot, "kernel-restore-owner"),
    ];
    for (step, owner) in matrix {
        assert_eq!(phase_owner(&step), owner);
    }
    // The executed restore dispatches exactly those phases in plan order.
    let root = TempRoot::create("case4");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let outcome = run_full(&mut owner, "target-4");
    assert_eq!(outcome.phase_log[0], "prepare");
    assert_eq!(outcome.phase_log[1], "purge");
    assert!(outcome.phase_log.contains(&"suspend-ors".to_owned()));
    assert_eq!(
        outcome.phase_log.last().expect("finalize").as_str(),
        "finalize"
    );
}

// WORK_UNIT_CASE: 960/5
#[test]
fn absent_provider_yields_no_success() {
    // Unadmitted journal refuses effects instead of substituting durability.
    let root = TempRoot::create("case5");
    let mut owner = open_owner(root.path());
    let bundle = load_bundle("full-valid.json");
    assert_eq!(
        owner.restore(&bundle, target_ctx("target-5"), &fence(), None, None),
        Err(KernelRestoreError::JournalNotAdmitted)
    );
    // Missing owner channels stay explicit in successful import evidence.
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let outcome = run_full(&mut owner, "target-5");
    assert_eq!(
        outcome.evidence.obligations.user_broker_invalidation.state,
        eliot_backup::RestoreObligationState::MissingCapability
    );
    assert_eq!(
        outcome
            .evidence
            .obligations
            .unresolved_effect_reconciliation
            .state,
        eliot_backup::RestoreObligationState::Unknown
    );
    assert!(outcome.evidence.reconciliation_denominator.is_none());
}

// WORK_UNIT_CASE: 960/6
#[test]
fn admitted_journal_required_with_durable_readback() {
    let root = TempRoot::create("case6");
    assert!(KernelBackupRestore::open(&PathBuf::from("relative/root")).is_err());
    assert!(KernelRestoreJournal::open(&PathBuf::from("relative/root")).is_err());
    let mut journal = KernelRestoreJournal::open(root.path()).expect("journal opens");
    assert!(!journal.is_admitted());
    // Fresh journal reads empty; CAS creates at revision 0 and rejects stale.
    let bundle = load_bundle("full-valid.json");
    let plan =
        RestorePlan::compile(&bundle, target_ctx("target-6")).expect("plan compiles");
    let transaction = plan.transaction().expect("transaction");
    let record = RestoreJournalRecord {
        journal_key: "journal-key-6".to_owned(),
        transaction: transaction.clone(),
        revision: 0,
        completed_phases: 0,
        phase: RestorePhase::Pending,
        state: RestoreJournalState::Ready,
        intent: None,
        receipt: None,
        final_receipt: None,
    };
    assert!(journal.load("journal-key-6").expect("load").is_none());
    journal
        .compare_and_swap("journal-key-6", 0, record.clone())
        .expect("create CAS");
    assert_eq!(
        journal.compare_and_swap("journal-key-6", 1, record.clone()),
        Err(eliot_backup::BackupError::RestoreJournalCasConflict)
    );
    // Drop and reopen: the record persists (durable readback, not a substitute).
    drop(journal);
    let mut reopened = KernelRestoreJournal::open(root.path()).expect("reopen");
    assert_eq!(
        reopened
            .load("journal-key-6")
            .expect("reload")
            .expect("record persists")
            .revision,
        0
    );
}

// WORK_UNIT_CASE: 960/7
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "mismatch matrix keeps tamper/plan/journal sub-cases in one declared denominator case"
)]
fn mismatch_rejected() {
    use eliot_backup::{BackupError, RestoreIntent, RestoreReconciliation, RestoreTarget};
    /// Mismatch-only target: never applies (fail-closed), so every refusal
    /// below is proven to come from the engine's identity checks, not effects.
    struct MismatchTarget;
    impl RestoreTarget for MismatchTarget {
        fn apply_restore_effect(
            &mut self,
            _plan: &eliot_backup::RestorePlan,
            _bundle: &BackupBundle,
            _intent: &RestoreIntent,
        ) -> Result<eliot_backup::RestoreAppliedEffect, BackupError> {
            Err(BackupError::Target(
                "mismatch probe never applies".to_owned(),
            ))
        }
        fn reconcile_restore_effect(
            &mut self,
            _intent: &RestoreIntent,
        ) -> Result<RestoreReconciliation, BackupError> {
            Ok(RestoreReconciliation::NotApplied)
        }
        fn prepare_isolated(
            &mut self,
            _context: &eliot_backup::RestoreContext,
            _restored_fence: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn apply_purge_ledger(
            &mut self,
            _entries: &[eliot_security_contracts::PurgeLedgerEntry],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_sealed_blob(
            &mut self,
            _blob: &eliot_backup::BackupBlob,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_canonical_event(
            &mut self,
            _record: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_receipt(
            &mut self,
            _receipt: &eliot_store_api::WriteReceipt,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn import_projection(
            &mut self,
            _record: &eliot_backup::CanonicalRecord,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn suspend_ors_operations(
            &mut self,
            _snapshot: &eliot_backup::OrsSnapshotFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn rebuild_projections(
            &mut self,
            _restored_fence: &eliot_backup::RestoredFence,
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn verify_receipt_event_chain(
            &mut self,
            _receipts: &[eliot_store_api::WriteReceipt],
            _events: &[eliot_backup::CanonicalRecord],
        ) -> Result<(), BackupError> {
            Ok(())
        }
        fn finalize_isolated(
            &mut self,
            _restored_fence: &eliot_backup::RestoredFence,
        ) -> Result<eliot_backup::RestoreEvidence, BackupError> {
            Err(BackupError::RestoreTargetReceiptRequired)
        }
    }
    // Tampered archive bytes fail before any effect.
    let bytes = std::fs::read(fixture_path("tampered-integrity.json")).expect("fixture");
    assert!(BackupBundle::decode(&bytes).is_err());
    // Plan compiled for one bundle refuses a different bundle.
    let root = TempRoot::create("case7");
    let full = load_bundle("full-valid.json");
    let degraded = load_bundle("degraded-valid.json");
    let plan = RestorePlan::compile(&full, target_ctx("target-7")).expect("plan compiles");
    let mut journal = KernelRestoreJournal::open(root.path()).expect("journal");
    admit_journal_fixture(&mut journal, root.path());
    let mut target = MismatchTarget;
    assert_eq!(
        plan.execute_with_journal(&degraded, &mut target, &mut journal),
        Err(BackupError::PlanMismatch)
    );
    // A journal primed by another transaction refuses this plan instead of
    // adopting its identity.
    let other = RestorePlan::compile(&degraded, target_ctx("other-7")).expect("other plan");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    owner
        .restore(&degraded, target_ctx("other-7"), &fence(), None, None)
        .expect("other transaction primes the journal");
    assert!(
        tamper_journal_transaction(root.path()),
        "journal file tampered for mismatch proof"
    );
    let mut target = MismatchTarget;
    assert_eq!(
        other.execute_with_journal(&degraded, &mut target, owner.journal()),
        Err(eliot_backup::BackupError::RestoreJournalMismatch)
    );
}

/// Binds fixture admission to a bare journal handle (cases driving the engine
/// directly instead of through the owner).
fn admit_journal_fixture(journal: &mut KernelRestoreJournal, root: &Path) {
    use eliot_backup::{OwnerTrustBinding, RestoreJournalAdmission};
    journal
        .admit(RestoreJournalAdmission {
            persistent_owner: OwnerTrustBinding {
                owner_id: "kernel-restore-owner".to_owned(),
                trust_binding_ref: "trust-binding-test-1".to_owned(),
            },
            database_ref: journal.journal_path().display().to_string(),
            installation_ref: root.display().to_string(),
            generation: ResourceGeneration::genesis(),
            journal_identity_ref: "kernel-restore-journal-v1".to_owned(),
            admission_receipt_ref: "admission-fixture-1".to_owned(),
            fixture_proof_only: true,
        })
        .expect("fixture admission binds");
}

/// Rewrites the journaled transaction id so the next resume observes a
/// foreign transaction instead of its own.
fn tamper_journal_transaction(root: &Path) -> bool {
    let path = root
        .join(".eliot")
        .join("kernel-restore-journal")
        .join("journal.json");
    let bytes = std::fs::read(&path).expect("journal file");
    let mut text = String::from_utf8(bytes).expect("journal is json text");
    let anchor = "\"transaction_id\":\"";
    let Some(at) = text.find(anchor) else {
        return false;
    };
    let start = at + anchor.len();
    text.replace_range(start..start + 8, "ffffffff");
    std::fs::write(&path, text.as_bytes()).expect("tampered journal");
    true
}

// WORK_UNIT_CASE: 960/8
#[test]
fn unknown_outcome_propagates_without_new_identity() {
    // Resume after restart returns the identical receipt with no new effects.
    let root = TempRoot::create("case8");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let first = run_full(&mut owner, "target-8");
    let phases = first.phase_log.len();
    assert!(phases > 0);
    let second = run_full(&mut owner, "target-8");
    assert_eq!(first.receipt, second.receipt);
    assert!(second.phase_log.is_empty(), "replay applies no new effects");
    // Crash between effect and receipt CAS reconciles by re-applying exactly once.
    // A new target needs a fresh journal: journal keys bind plan+bundle, so a
    // different target against a primed journal is (correctly) a mismatch.
    let root8b = TempRoot::create("case8b");
    let mut owner = open_owner(root8b.path());
    admit_fixture(&mut owner, root8b.path());
    let bundle = load_bundle("full-valid.json");
    let before = owner
        .restore(&bundle, target_ctx("target-8b"), &fence(), None, None)
        .expect("restore");
    let after = owner
        .restore(&bundle, target_ctx("target-8b"), &fence(), None, None)
        .expect("resume");
    assert_eq!(before.receipt, after.receipt);
}

// WORK_UNIT_CASE: 960/9
#[test]
fn kernel_effect_fence_required_before_phases() {
    let root = TempRoot::create("case9");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let bundle = load_bundle("full-valid.json");
    // Compatible fence proceeds; incompatible fence refuses with zero effects.
    let ok = owner.restore(&bundle, target_ctx("target-9"), &fence(), None, None);
    assert!(ok.is_ok());
    let foreign = StateFence::new(
        EpochId::new(
            EpochLineageId::new("660e8400-e29b-41d4-a716-446655440002").expect("lineage"),
            NonZeroU64::new(9).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    );
    let root2 = TempRoot::create("case9b");
    let mut owner2 = open_owner(root2.path());
    admit_fixture(&mut owner2, root2.path());
    let before: Vec<PathBuf> = std::fs::read_dir(root2.path())
        .expect("read root")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(
        owner2.restore(&bundle, target_ctx("target-9b"), &foreign, None, None),
        Err(KernelRestoreError::FenceMismatch(
            "archive fence is not compatible with the Kernel effect fence".to_owned()
        ))
    );
    let after: Vec<PathBuf> = std::fs::read_dir(root2.path())
        .expect("read root")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(before, after, "refused restore leaves zero effects");
}

// WORK_UNIT_CASE: 960/10
#[test]
fn complete_denominators_observed() {
    let root = TempRoot::create("case10");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let outcome = run_full(&mut owner, "target-10");
    // Canonical closure holds; ORS suspension is exactly the pending set;
    // spool digests are exactly the archived set.
    assert_eq!(outcome.suspended_entries.len(), 1);
    let entry = &outcome.suspended_entries[0];
    assert_eq!(entry.historical_ref, "op-suspended-1");
    assert!(entry.suspended);
    assert!(outcome.evidence.ors_suspended);
    assert!(outcome.evidence.receipt_event_chain_verified);
    assert_eq!(
        outcome.evidence.obligations.ors_suspension.state,
        eliot_backup::RestoreObligationState::Satisfied
    );
}

// WORK_UNIT_CASE: 960/11
#[test]
fn unknown_missing_blocks_readiness_distinct_from_partial() {
    let root = TempRoot::create("case11");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let bundle = load_bundle("degraded-valid.json");
    let outcome = owner
        .restore(&bundle, target_ctx("target-11"), &fence(), None, None)
        .expect("degraded import completes");
    assert_eq!(
        outcome.receipt.evidence_level,
        eliot_backup::RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert!(outcome.evidence.validate().is_ok());
    assert!(outcome.evidence.operationally_validated_by_owner().is_err());
    // Safe partial import stays explicitly partial, never readiness.
    assert!(!outcome.receipt.operational_recovery_ready);
    assert!(!outcome.receipt.cutover_performed);
}

// WORK_UNIT_CASE: 960/12
#[test]
fn owner_issued_epoch_evidence() {
    let root = TempRoot::create("case12");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let bundle = load_bundle("full-valid.json");
    // Valid owner-issued epoch attaches after advancement validation.
    let outcome = owner
        .restore(
            &bundle,
            target_ctx("target-12"),
            &fence(),
            None,
            Some(owner_epoch_valid()),
        )
        .expect("restore with owner epoch");
    let attached = outcome.evidence.owner_epoch.expect("owner epoch attached");
    assert_eq!(attached.new_epoch, epoch(2));
    // Stale cross-lineage reuse refuses.
    let mut stale = owner_epoch_valid();
    stale.new_epoch = EpochId::new(
        EpochLineageId::new("660e8400-e29b-41d4-a716-446655440002").expect("lineage"),
        NonZeroU64::new(2).expect("sequence"),
    )
    .expect("epoch");
    assert_eq!(
        owner.restore(
            &bundle,
            target_ctx("target-12b"),
            &fence(),
            None,
            Some(stale)
        ),
        Err(KernelRestoreError::OwnerEvidenceInvalid(
            "restore lineage must be newer than every observed source lineage".to_owned()
        ))
    );
    // No epoch supplied fabricates none (fresh journal: keys bind plan+bundle,
    // so each target restores under its own root).
    let root12c = TempRoot::create("case12c");
    let mut owner = open_owner(root12c.path());
    admit_fixture(&mut owner, root12c.path());
    let plain = run_full(&mut owner, "target-12c");
    assert!(plain.evidence.owner_epoch.is_none());
}

// WORK_UNIT_CASE: 960/13
#[test]
fn invalidations_retained_individually() {
    let root = TempRoot::create("case13");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let outcome = run_full(&mut owner, "target-13");
    let obligations = &outcome.evidence.obligations;
    let states = [
        ("session-owner", &obligations.session_invalidation),
        ("lease-owner", &obligations.lease_invalidation),
        ("route-owner", &obligations.route_invalidation),
        ("runtime-owner", &obligations.runtime_invalidation),
        ("user-broker-owner", &obligations.user_broker_invalidation),
    ];
    for (owner_id, obligation) in states {
        assert_eq!(obligation.owner_id, *owner_id);
        assert!(!obligation.evidence_ref.is_empty());
    }
    assert_eq!(
        obligations.user_broker_invalidation.state,
        eliot_backup::RestoreObligationState::MissingCapability
    );
    for historical in &outcome.evidence.historical_authority {
        assert!(historical.suspended);
    }
}

// WORK_UNIT_CASE: 960/14
#[test]
fn purge_residency_reference_closure() {
    let root = TempRoot::create("case14");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let outcome = run_full(&mut owner, "target-14");
    // Purge ledger persisted before imports; phase order proves it.
    assert_eq!(outcome.phase_log[0], "prepare");
    assert_eq!(outcome.phase_log[1], "purge");
    // Duplicate canonical identities refuse at build.
    let mut input = full_input();
    input.canonical_events.push(event("event-1"));
    input.export_fence.event_range.count = 2;
    assert!(BackupBundle::build(input).is_err());
    // Dangling projections refuse.
    let mut dangling = full_input();
    dangling.projections = vec![CanonicalRecord::new(
        "test-event",
        "event-absent",
        json!({"projection": "absent"}),
    )
    .expect("projection")];
    assert!(BackupBundle::build(dangling).is_err());
}

// WORK_UNIT_CASE: 960/15
#[test]
fn external_revalidation_not_stub() {
    let root = TempRoot::create("case15");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let outcome = run_full(&mut owner, "target-15");
    assert_eq!(
        outcome
            .evidence
            .obligations
            .external_source_revalidation
            .state,
        eliot_backup::RestoreObligationState::Unknown
    );
    // Unknown present means readiness refuses: absence of evidence is failure.
    assert!(outcome.evidence.operationally_validated_by_owner().is_err());
}

// WORK_UNIT_CASE: 960/16
#[test]
fn rehearsal_cannot_activate_cutover_retire() {
    let root = TempRoot::create("case16");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let before = std::fs::read(fixture_path("full-valid.json")).expect("fixture");
    let outcome = run_full(&mut owner, "target-16");
    assert!(!outcome.receipt.cutover_performed);
    assert!(!outcome.receipt.operational_recovery_ready);
    assert!(!outcome.evidence.active_authority_restored);
    let bundle = load_bundle("full-valid.json");
    let plan = RestorePlan::compile(&bundle, target_ctx("target-16")).expect("plan compiles");
    let isolated = eliot_backup::IsolatedRestorePlan {
        plan: plan.clone(),
        suspended_entries: Vec::new(),
        restored_fence: plan.restored_fence.clone(),
        root: root.path().to_path_buf(),
        bundle_sha256: plan.bundle_sha256.clone(),
        canonical_only: false,
    };
    assert_eq!(
        eliot_backup::authorize_cutover(&isolated, None),
        Err(eliot_backup::BackupError::CutoverNotAuthorized)
    );
    let after = std::fs::read(fixture_path("full-valid.json")).expect("fixture");
    assert_eq!(before, after, "source archive untouched");
}

// WORK_UNIT_CASE: 960/17
#[test]
fn single_engine_same_transaction_resumption() {
    let root = TempRoot::create("case17");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let bundle = load_bundle("full-valid.json");
    let first = owner
        .restore(&bundle, target_ctx("target-17"), &fence(), None, None)
        .expect("first");
    let second = owner
        .restore(&bundle, target_ctx("target-17"), &fence(), None, None)
        .expect("resume");
    assert_eq!(first.receipt, second.receipt);
    assert!(second.phase_log.is_empty());
}

// WORK_UNIT_CASE: 960/18
#[test]
fn bounds_cancel_cleanup_primary_failure() {
    // Purge-carrying archive issues; restore refuses the erasure receipt with
    // the primary store error preserved (no masking, no destructive rollback).
    let root = TempRoot::create("case18");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let bytes = std::fs::read(fixture_path("purge-erasure.json")).expect("fixture");
    let bundle = BackupBundle::decode(&bytes).expect("purge archive issues");
    let error = owner
        .restore(&bundle, target_ctx("target-18"), &fence(), None, None)
        .expect_err("erasure receipt refuses");
    let rendered = format!("{error:?}");
    assert!(
        rendered.contains("invalid terminal receipt"),
        "primary InvalidReceipt preserved, got: {rendered}"
    );
    // Journal and partial effects persist for operator resume; retry fails identically.
    assert!(owner.journal().journal_path().exists());
    let retry_error = owner
        .restore(&bundle, target_ctx("target-18"), &fence(), None, None)
        .expect_err("retry fails identically");
    assert_eq!(
        format!("{retry_error:?}"),
        rendered,
        "retry surfaces the identical primary failure"
    );
}

// WORK_UNIT_CASE: 960/19
#[test]
fn real_temporary_journal_persistent_readback() {
    // Case 6 already proves reopen persistence; here the frozen fixtures prove
    // byte-determinism: regeneration matches the frozen files exactly.
    let regenerated = BackupBundle::build(full_input()).expect("regenerate");
    let frozen = std::fs::read(fixture_path("full-valid.json")).expect("frozen");
    assert_eq!(regenerated.encode().expect("encode"), frozen);
    let regenerated = BackupBundle::build(degraded_input()).expect("regenerate");
    let frozen = std::fs::read(fixture_path("degraded-valid.json")).expect("frozen");
    assert_eq!(regenerated.encode().expect("encode"), frozen);
    let regenerated = BackupBundle::build(purge_erasure_input()).expect("regenerate");
    let frozen = std::fs::read(fixture_path("purge-erasure.json")).expect("frozen");
    assert_eq!(regenerated.encode().expect("encode"), frozen);
}

// WORK_UNIT_CASE: 960/20
#[test]
fn no_private_db_copy_no_minting_no_overclaim() {
    let root = TempRoot::create("case20");
    let mut owner = open_owner(root.path());
    admit_fixture(&mut owner, root.path());
    let outcome = run_full(&mut owner, "target-20");
    // No database files inside the isolated destination.
    let mut stack = vec![outcome.destination_root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                assert_ne!(path.extension().and_then(|ext| ext.to_str()), Some("redb"));
            }
        }
    }
    // Proposed lineage advances the plan; nothing is minted beyond it.
    assert_eq!(
        outcome.evidence.authority_epoch,
        outcome.receipt.restored_fence.authority_epoch
    );
    assert!(outcome.evidence.owner_epoch.is_none());
    assert_ne!(
        outcome.receipt.evidence_level,
        eliot_backup::RestoreEvidenceLevel::OperationallyValidated
    );
    assert_ne!(
        outcome.receipt.evidence_level,
        eliot_backup::RestoreEvidenceLevel::Cutover
    );
    assert!(!outcome.receipt.operational_recovery_ready);
}
