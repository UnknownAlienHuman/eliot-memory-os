//! Product command surface proofs (issue #1873).
//!
//! Minimal proof only: CLI-shaped class strings parse to typed classes,
//! backup-create preview never silently upgrades or downgrades the requested
//! class, and restore preview derives purge-first, ORS-suspension, and
//! class-ceiling bindings from the governed plan without executing.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_backup::{
    BackupArtifact, BackupBundle, BackupClass, BackupCreateArgs, BackupError, BackupInput,
    EventRange, ExportFence, OrsSnapshotFence, RestoreContext, RestoreEvidenceLevel,
    WatchdogSpoolFence, parse_backup_class, preview_backup_create, preview_restore,
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

fn full_input() -> BackupInput {
    let source_fence = fence();
    BackupInput {
        backup_id: "backup-1873c-full".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-1873c".to_owned(),
            installation_id: "installation-1873c".to_owned(),
            schema_generation: "schema-1".to_owned(),
            store_generation: "store-1873c".to_owned(),
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
            snapshot_id: "ors-1873c".to_owned(),
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
            fence_id: "watchdog-1873c".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-1873c")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn target_context() -> RestoreContext {
    RestoreContext {
        target_id: "target-1873c".to_owned(),
        target_authority_epoch: epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

// WORK_UNIT_CASE: 1873c/parse-classes
#[test]
fn class_strings_parse_to_typed_classes() {
    assert_eq!(
        parse_backup_class("full_recovery"),
        Ok(BackupClass::FullRecovery)
    );
    assert_eq!(
        parse_backup_class("canonical_only_degraded"),
        Ok(BackupClass::CanonicalOnlyDegraded)
    );
    assert_eq!(
        parse_backup_class("scope_export"),
        Ok(BackupClass::ScopeExport)
    );
    assert_eq!(
        parse_backup_class("FullRecovery"),
        Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "unknown backup class",
        })
    );
    assert_eq!(
        parse_backup_class(""),
        Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "unknown backup class",
        })
    );
}

// WORK_UNIT_CASE: 1873c/create-preview
#[test]
fn backup_create_preview_never_silently_changes_class() {
    // Requested full with an ORS snapshot: selected full, recovery required.
    let full = preview_backup_create(
        &BackupCreateArgs {
            backup_id: "backup-1873c-full".to_owned(),
            class: "full_recovery".to_owned(),
            scope_id: None,
        },
        true,
    )
    .expect("full preview succeeds");
    assert_eq!(full.selected, BackupClass::FullRecovery);
    assert_eq!(
        full.evidence_level,
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert!(!full.canonical_only);
    assert!(full.ors_required);
    // Requested full without an ORS snapshot: refused, never silently degraded.
    assert_eq!(
        preview_backup_create(
            &BackupCreateArgs {
                backup_id: "backup-1873c-full".to_owned(),
                class: "full_recovery".to_owned(),
                scope_id: None,
            },
            false,
        ),
        Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "requested class does not match structural selection",
        })
    );
    // Requested degraded while an ORS snapshot is present: refused, never
    // silently upgraded into a recovery claim.
    assert_eq!(
        preview_backup_create(
            &BackupCreateArgs {
                backup_id: "backup-1873c-degraded".to_owned(),
                class: "canonical_only_degraded".to_owned(),
                scope_id: None,
            },
            true,
        ),
        Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "requested class does not match structural selection",
        })
    );
    // Requested degraded without one: canonical-only, never recovery-ready.
    let degraded = preview_backup_create(
        &BackupCreateArgs {
            backup_id: "backup-1873c-degraded".to_owned(),
            class: "canonical_only_degraded".to_owned(),
            scope_id: None,
        },
        false,
    )
    .expect("degraded preview succeeds");
    assert!(degraded.canonical_only);
    assert!(!degraded.evidence_level.permits_operational_readiness());
    // Scope transfers select structurally and stay canonical-only.
    let scope = preview_backup_create(
        &BackupCreateArgs {
            backup_id: "backup-1873c-scope".to_owned(),
            class: "scope_export".to_owned(),
            scope_id: Some("scope-1873c".to_owned()),
        },
        false,
    )
    .expect("scope preview succeeds");
    assert_eq!(scope.selected, BackupClass::ScopeExport);
    assert!(scope.canonical_only);
}

// WORK_UNIT_CASE: 1873c/restore-preview
#[test]
fn restore_preview_derives_bindings_without_executing() {
    let bundle = BackupBundle::build(full_input()).expect("full bundle builds");
    let preview = preview_restore(&bundle, &target_context()).expect("restore preview succeeds");
    assert!(!preview.plan_id.is_empty());
    assert!(preview.purge_first, "purge ledger applies first");
    assert!(
        preview.suspends_ors_operations,
        "full recovery suspends ORS operations"
    );
    assert!(!preview.canonical_only);
    assert_eq!(
        preview.evidence_level,
        RestoreEvidenceLevel::ReconciliationRequired
    );
    assert_eq!(
        preview.step_names.first().map(String::as_str),
        Some("PrepareIsolatedRoot")
    );
    // Degraded archives preview without ORS suspension, canonical-only.
    let mut degraded_input = full_input();
    degraded_input.backup_id = "backup-1873c-degraded".to_owned();
    degraded_input.class = BackupClass::CanonicalOnlyDegraded;
    degraded_input.ors_snapshot = None;
    let degraded = BackupBundle::build(degraded_input).expect("degraded bundle builds");
    let degraded_preview =
        preview_restore(&degraded, &target_context()).expect("degraded preview succeeds");
    assert!(!degraded_preview.suspends_ors_operations);
    assert!(degraded_preview.canonical_only);
    assert!(degraded_preview.purge_first);
}
