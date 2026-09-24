//! Backup/restore class selection with recoverability evidence (issue #1873).
//!
//! Minimal proof only: class selection, class-specific receipts, isolated
//! restore with purge-ledger-first ordering, pending ORS operations imported
//! as suspended recovery, fresh Authority Epoch plus Host Kernel lineage, and
//! session/broker/lease/route authority left non-active. Read-only use of the
//! ECXF BlobStore/ORS fences (no I/O, no key opening, no authority minting).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_backup::{
    BackupArtifact, BackupBundle, BackupClass, BackupError, BackupInput, EventRange, ExportFence,
    OrsSnapshotFence, RestoreContext, RestoreEvidenceLevel, RestoreHistoricalAuthority,
    RestoreHistoricalKind, RestorePlan, RestoredFence, WatchdogSpoolFence,
    suspended_recovery_entries,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

fn epoch_in(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid lineage"),
        NonZeroU64::new(sequence).expect("nonzero sequence"),
    )
    .expect("valid epoch")
}

fn epoch(sequence: u64) -> EpochId {
    epoch_in(LINEAGE_A, sequence)
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn artifact(kind: &str) -> BackupArtifact {
    let bytes = format!("{kind}-manifest-bytes").into_bytes();
    let sha256 = sha256_hex(&bytes);
    BackupArtifact {
        kind: kind.to_owned(),
        artifact_id: format!("{kind}-1"),
        bytes,
        sha256,
    }
}

fn full_input() -> BackupInput {
    let source_fence = fence();
    BackupInput {
        backup_id: "backup-1873-full".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-1873".to_owned(),
            installation_id: "installation-1873".to_owned(),
            schema_generation: "schema-1".to_owned(),
            store_generation: "store-1873".to_owned(),
            state_fence: source_fence.clone(),
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
        ors_snapshot: Some(OrsSnapshotFence {
            snapshot_id: "ors-1873".to_owned(),
            authority_epoch: epoch(1),
            resource_generation: ResourceGeneration::genesis(),
            last_receipt_cursor: 0,
            last_event_cursor: 0,
            last_outbox_cursor: 0,
            pending_operation_ids: Vec::new(),
            job_checkpoint_ids: Vec::new(),
            generation_cutover_ids: Vec::new(),
            state_fence: source_fence.clone(),
            active_authority_restored: false,
        }),
        artifacts: ["config", "policy", "module", "host_dependency_build"]
            .iter()
            .map(|kind| artifact(kind))
            .collect(),
        watchdog_spool: Some(WatchdogSpoolFence {
            fence_id: "watchdog-1873".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-1873")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn target_context(target_id: &str) -> RestoreContext {
    RestoreContext {
        target_id: target_id.to_owned(),
        target_authority_epoch: epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

// WORK_UNIT_CASE: 1873/class-selection
#[test]
fn class_selection_is_explicit_and_structural() {
    assert_eq!(
        BackupClass::select(false, true),
        Ok(BackupClass::FullRecovery)
    );
    assert_eq!(
        BackupClass::select(false, false),
        Ok(BackupClass::CanonicalOnlyDegraded)
    );
    assert_eq!(
        BackupClass::select(true, false),
        Ok(BackupClass::ScopeExport)
    );
    // A scope transfer never carries installation recovery: refuse, never
    // widen into an installation backup or silently drop the snapshot.
    assert_eq!(
        BackupClass::select(true, true),
        Err(BackupError::UnexpectedRecoveryComponent("ors_snapshot"))
    );
}

// WORK_UNIT_CASE: 1873/full-requires-ors
#[test]
fn full_recovery_without_self_consistent_ors_fails_while_same_material_is_degraded() {
    BackupBundle::build(full_input()).expect("full bundle builds");

    // The same material without a self-consistent ORS snapshot cannot claim
    // full recovery.
    let mut without_ors = full_input();
    without_ors.ors_snapshot = None;
    assert_eq!(
        BackupBundle::build(without_ors),
        Err(BackupError::MissingRecoveryComponent("ors_snapshot"))
    );

    // The same material is only a degraded canonical archive: coherent
    // semantic content with explicitly unavailable operational recovery.
    let mut degraded = full_input();
    degraded.class = BackupClass::CanonicalOnlyDegraded;
    degraded.ors_snapshot = None;
    let bundle = BackupBundle::build(degraded).expect("same material builds as degraded");
    bundle.validate().expect("degraded bundle validates");
    assert!(bundle.ors_snapshot.is_none());
    assert_eq!(
        bundle.manifest.class.evidence_level(),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
}

// WORK_UNIT_CASE: 1873/class-receipts
#[test]
fn class_specific_receipts_bind_distinct_proof_ceilings() {
    assert_eq!(
        BackupClass::FullRecovery.evidence_level(),
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert_eq!(
        BackupClass::CanonicalOnlyDegraded.evidence_level(),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert_eq!(
        BackupClass::ScopeExport.evidence_level(),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert!(!BackupClass::FullRecovery.is_canonical_only());
    assert!(BackupClass::CanonicalOnlyDegraded.is_canonical_only());
    assert!(BackupClass::ScopeExport.is_canonical_only());
    for class in [
        BackupClass::FullRecovery,
        BackupClass::CanonicalOnlyDegraded,
        BackupClass::ScopeExport,
    ] {
        assert!(
            !class.evidence_level().permits_operational_readiness(),
            "no class receipt asserts operational readiness"
        );
    }
}

// WORK_UNIT_CASE: 1873/fresh-lineage
#[test]
fn restore_mints_fresh_authority_epoch_plus_host_kernel_lineage() {
    let source = fence();
    let fresh = RestoredFence::mint(&source, epoch(2), ResourceGeneration::new(2).expect("gen"))
        .expect("advancing lineage mints");
    fresh.validate().expect("fresh fence validates");
    assert!(fresh.authority_epoch.is_same_authority(&epoch(2)));

    // Reused source authority never mints.
    assert_eq!(
        RestoredFence::mint(&source, epoch(1), ResourceGeneration::new(2).expect("gen")),
        Err(BackupError::StaleRestoreLineage)
    );
    // A reused Host Kernel generation never mints, even with a newer epoch.
    assert_eq!(
        RestoredFence::mint(&source, epoch(2), ResourceGeneration::genesis()),
        Err(BackupError::StaleRestoreLineage)
    );
    // A globally distinct lineage mints only as genesis at sequence 1.
    RestoredFence::mint(
        &source,
        epoch_in(LINEAGE_B, 1),
        ResourceGeneration::new(2).expect("gen"),
    )
    .expect("distinct genesis lineage mints");
    assert_eq!(
        RestoredFence::mint(
            &source,
            epoch_in(LINEAGE_B, 2),
            ResourceGeneration::new(2).expect("gen")
        ),
        Err(BackupError::StaleRestoreLineage)
    );
}

// WORK_UNIT_CASE: 1873/non-active-authority
#[test]
fn session_broker_lease_route_authority_stays_suspended() {
    for kind in [
        RestoreHistoricalKind::Session,
        RestoreHistoricalKind::Lease,
        RestoreHistoricalKind::Route,
        RestoreHistoricalKind::UserBrokerRegistration,
        RestoreHistoricalKind::AuthorityEpoch,
        RestoreHistoricalKind::OrsOperation,
        RestoreHistoricalKind::WatchdogSignal,
    ] {
        RestoreHistoricalAuthority {
            kind,
            historical_ref: "historical-1873".to_owned(),
            suspended: true,
        }
        .validate()
        .expect("suspended history validates");
        // Activation of old authority is refused, never revived.
        assert_eq!(
            RestoreHistoricalAuthority {
                kind,
                historical_ref: "historical-1873".to_owned(),
                suspended: false,
            }
            .validate(),
            Err(BackupError::HistoricalAuthorityActivated)
        );
    }
}

// WORK_UNIT_CASE: 1873/suspended-recovery
#[test]
fn pending_ors_operations_import_as_suspended_recovery() {
    let mut snapshot = OrsSnapshotFence {
        snapshot_id: "ors-1873".to_owned(),
        authority_epoch: epoch(1),
        resource_generation: ResourceGeneration::genesis(),
        last_receipt_cursor: 0,
        last_event_cursor: 0,
        last_outbox_cursor: 0,
        pending_operation_ids: vec!["op-b".to_owned(), "op-a".to_owned()],
        job_checkpoint_ids: Vec::new(),
        generation_cutover_ids: Vec::new(),
        state_fence: fence(),
        active_authority_restored: false,
    };
    snapshot.validate().expect("snapshot validates");
    let entries = suspended_recovery_entries(&snapshot).expect("suspended recovery imports");
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert_eq!(entry.kind, RestoreHistoricalKind::OrsOperation);
        assert!(entry.suspended);
        entry.validate().expect("entry validates");
    }
    // Deterministic order: pending work never resumes by position.
    assert_eq!(entries[0].historical_ref, "op-a");
    assert_eq!(entries[1].historical_ref, "op-b");

    snapshot.pending_operation_ids = Vec::new();
    assert!(
        suspended_recovery_entries(&snapshot)
            .expect("empty pending imports")
            .is_empty()
    );
}

// WORK_UNIT_CASE: 1873/purge-first
#[test]
fn isolated_restore_applies_purge_ledger_first() {
    let bundle = BackupBundle::build(full_input()).expect("full bundle builds");
    let plan = RestorePlan::compile(&bundle, target_context("target-1873")).expect("plan");
    assert!(plan.steps.len() >= 2);
    assert_eq!(
        plan.steps[0],
        eliot_backup::RestoreStep::PrepareIsolatedRoot
    );
    assert_eq!(plan.steps[1], eliot_backup::RestoreStep::ApplyPurgeLedger);
    assert!(
        plan.steps
            .contains(&eliot_backup::RestoreStep::SuspendOrsOperations),
        "full recovery suspends ORS operations without resuming them"
    );
    plan.restored_fence.validate().expect("fence validates");
}

// WORK_UNIT_CASE: 1873/read-only
#[test]
fn ecxf_blobstore_ors_fences_stay_read_only() {
    let source = std::fs::read(format!("{}/src/lib.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("backup source reads");
    let source_text = String::from_utf8(source).expect("backup source is UTF-8");
    for marker in [
        "std::fs::",
        "std::net::",
        "TcpListener",
        "TcpStream",
        "reqwest::",
        "tokio::net",
        "fn capture",
        "fn open_key",
        "key_service::",
    ] {
        assert!(
            !source_text.contains(marker),
            "backup verification must not expose {marker}"
        );
    }
}
