//! Isolated restore + cutover proofs (issue #1873; A13.7 isolated restore).
//!
//! Minimal proof only: temp-dir isolation (production roots refused, drops
//! clean up), purge-first planning with suspended ORS import and a freshly
//! minted lineage, and cutover authorized only by a separate matching owner
//! authorization — never by default.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_backup::{
    BackupArtifact, BackupBundle, BackupClass, BackupError, BackupInput, CutoverAuthorization,
    EventRange, ExportFence, IsolatedRoot, OrsSnapshotFence, RestoreContext, RestoreStep,
    WatchdogSpoolFence, authorize_cutover, plan_isolated_restore,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_A).expect("valid lineage"),
        NonZeroU64::new(sequence).expect("nonzero sequence"),
    )
    .expect("valid epoch")
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

fn full_input(pending: Vec<String>) -> BackupInput {
    let source_fence = fence();
    BackupInput {
        backup_id: "backup-1873r-full".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-1873r".to_owned(),
            store_generation: "store-1873r".to_owned(),
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
            snapshot_id: "ors-1873r".to_owned(),
            authority_epoch: epoch(1),
            resource_generation: ResourceGeneration::genesis(),
            last_receipt_cursor: 0,
            last_event_cursor: 0,
            last_outbox_cursor: 0,
            pending_operation_ids: pending,
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
            fence_id: "watchdog-1873r".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-1873r")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn degraded_bundle() -> BackupBundle {
    let mut input = full_input(Vec::new());
    "backup-1873r-degraded".clone_into(&mut input.backup_id);
    input.class = BackupClass::CanonicalOnlyDegraded;
    input.ors_snapshot = None;
    BackupBundle::build(input).expect("degraded bundle builds")
}

fn target_context() -> RestoreContext {
    RestoreContext {
        target_id: "target-1873r".to_owned(),
        target_authority_epoch: epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

// WORK_UNIT_CASE: 1873r/isolated-root
#[test]
fn isolated_roots_stay_under_temp_and_clean_up() {
    let root = IsolatedRoot::create("case-1873r").expect("isolated root creates");
    assert!(
        root.path().starts_with(std::env::temp_dir()),
        "isolated root must live under the temp dir"
    );
    assert!(root.path().is_dir(), "isolated root must exist");
    let path = root.path().to_path_buf();
    drop(root);
    assert!(!path.exists(), "dropped isolated root must be removed");
    // A production-looking path never opens as an isolated root.
    assert!(
        matches!(
            IsolatedRoot::open_existing(std::path::PathBuf::from("C:/exa-mple-root-1873r")),
            Err(BackupError::InvalidField { .. })
        ),
        "non-temp roots are refused without touching them"
    );
    // Blank or hostile labels never create.
    assert!(
        IsolatedRoot::create("").is_err(),
        "blank labels are refused"
    );
    assert!(
        IsolatedRoot::create("../escape-1873r").is_err(),
        "path separators are refused"
    );
}

// WORK_UNIT_CASE: 1873r/isolated-plan
#[test]
fn isolated_plan_is_purge_first_suspended_and_fresh() {
    let bundle = BackupBundle::build(full_input(vec![
        "op-1873r-b".to_owned(),
        "op-1873r-a".to_owned(),
    ]))
    .expect("full bundle builds");
    let root = IsolatedRoot::create("plan-1873r").expect("isolated root creates");
    let planned = plan_isolated_restore(
        &bundle,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &root,
    )
    .expect("isolated plan succeeds");
    planned.validate().expect("isolated plan validates");
    assert!(planned.plan.steps.len() >= 2);
    assert_eq!(planned.plan.steps[0], RestoreStep::PrepareIsolatedRoot);
    assert_eq!(planned.plan.steps[1], RestoreStep::ApplyPurgeLedger);
    assert!(
        planned
            .plan
            .steps
            .contains(&RestoreStep::SuspendOrsOperations),
        "full recovery suspends ORS operations without resuming them"
    );
    assert_eq!(planned.suspended_entries.len(), 2);
    for entry in &planned.suspended_entries {
        assert!(entry.suspended, "restored work stays suspended");
    }
    assert_eq!(
        planned.suspended_entries[0].historical_ref, "op-1873r-a",
        "suspended import is deterministic, never positional resume"
    );
    assert_eq!(planned.restored_fence, planned.plan.restored_fence);
    assert!(!planned.canonical_only);
    assert_eq!(planned.root, root.path().to_path_buf());
    // Degraded archives plan without ORS suspension and stay canonical-only.
    let degraded = degraded_bundle();
    let degraded_root = IsolatedRoot::create("plan-degraded-1873r").expect("root creates");
    let degraded_plan = plan_isolated_restore(
        &degraded,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &degraded_root,
    )
    .expect("degraded isolated plan succeeds");
    assert!(degraded_plan.suspended_entries.is_empty());
    assert!(degraded_plan.canonical_only);
}

// WORK_UNIT_CASE: 1873r/cutover-authorized
#[test]
fn cutover_needs_a_matching_owner_authorization() {
    let bundle = BackupBundle::build(full_input(Vec::new())).expect("full bundle builds");
    let root = IsolatedRoot::create("cutover-1873r").expect("isolated root creates");
    let planned = plan_isolated_restore(
        &bundle,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &root,
    )
    .expect("isolated plan succeeds");
    // No authorization: cutover is refused, never performed by default.
    assert_eq!(
        authorize_cutover(&planned, None),
        Err(BackupError::CutoverNotAuthorized)
    );
    let auth = CutoverAuthorization {
        plan_id: planned.plan.plan_id.clone(),
        bundle_sha256: planned.bundle_sha256.clone(),
        authorized_by: "owner-human-1873r".to_owned(),
        statement: "cutover approved after isolated rehearsal".to_owned(),
    };
    let receipt = authorize_cutover(&planned, Some(&auth)).expect("authorized cutover issues");
    receipt.validate().expect("cutover receipt validates");
    assert_eq!(receipt.new_authority_epoch, epoch(2));
    assert_eq!(
        receipt.new_resource_generation,
        ResourceGeneration::new(2).expect("generation")
    );
    assert_eq!(receipt.authorized_by, "owner-human-1873r");
    assert!(
        !receipt.canonical_only,
        "full recovery cuts over operationally"
    );
    // Authorization never transfers between restores.
    let mut foreign = auth.clone();
    foreign.plan_id = "restore-plan-foreign".to_owned();
    assert_eq!(
        authorize_cutover(&planned, Some(&foreign)),
        Err(BackupError::PlanMismatch)
    );
    let mut drifted = auth.clone();
    drifted.bundle_sha256 = "f".repeat(64);
    assert_eq!(
        authorize_cutover(&planned, Some(&drifted)),
        Err(BackupError::PlanMismatch)
    );
}

// WORK_UNIT_CASE: 1873r/cutover-degraded-ceiling
#[test]
fn degraded_cutover_receipts_stay_canonical_only() {
    let degraded = degraded_bundle();
    let root = IsolatedRoot::create("cutover-degraded-1873r").expect("root creates");
    let planned = plan_isolated_restore(
        &degraded,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &root,
    )
    .expect("degraded plan succeeds");
    let auth = CutoverAuthorization {
        plan_id: planned.plan.plan_id.clone(),
        bundle_sha256: planned.bundle_sha256.clone(),
        authorized_by: "owner-human-1873r".to_owned(),
        statement: "degraded import approved".to_owned(),
    };
    let receipt = authorize_cutover(&planned, Some(&auth)).expect("authorized cutover issues");
    assert!(
        receipt.canonical_only,
        "degraded archives can never cut over into operational recovery"
    );
    // Exactly one cutover issuance path exists in the driver: no silent route.
    let source = std::fs::read_to_string(format!(
        "{}/src/isolated_restore.rs",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("driver source reads");
    assert_eq!(
        source.matches("= CutoverReceipt {").count(),
        1,
        "authorize_cutover must stay the sole cutover constructor"
    );
}
