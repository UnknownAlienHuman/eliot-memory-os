//! Live `eliot backup` CLI proofs (issue #1873).
//!
//! The real binary path end to end on temp-only fixtures: create-preview
//! selection and refusal, restore-preview bindings from a bundle file,
//! key-coverage checks, real issuance with class receipts, and isolated
//! restore runs with fresh lineages. Exit codes plus JSON stdout are asserted;
//! restores execute only into temp-enforced isolated roots with no cutover,
//! and no production state is touched.

use std::{error::Error, fs, path::Path, process::Command};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn run(args: &[&str]) -> TestResult<std::process::Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_eliot"))
        .args(args)
        .output()?)
}

fn stdout_json(output: &std::process::Output) -> TestResult<Value> {
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn path_str(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or("path is not utf8".into())
}

fn write_degraded_bundle(path: &Path) -> TestResult {
    use eliot_backup::{
        BackupArtifact, BackupBundle, BackupClass, BackupInput, EventRange, ExportFence,
        WatchdogSpoolFence,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
    use std::num::NonZeroU64;
    let epoch = EpochId::new(
        EpochLineageId::new(LINEAGE_A).map_err(|error| format!("lineage: {error:?}"))?,
        NonZeroU64::new(1).ok_or("sequence must be nonzero")?,
    )
    .map_err(|error| format!("epoch: {error:?}"))?;
    let source_fence = StateFence::new(epoch, ResourceGeneration::genesis());
    let artifacts: Vec<BackupArtifact> = ["config", "policy", "module", "host_dependency_build"]
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
        .collect();
    let input = BackupInput {
        backup_id: "backup-cli-degraded".to_owned(),
        class: BackupClass::CanonicalOnlyDegraded,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-cli".to_owned(),
            store_generation: "store-cli".to_owned(),
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
        ors_snapshot: None,
        artifacts,
        watchdog_spool: Some(WatchdogSpoolFence {
            fence_id: "watchdog-cli".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-cli")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    };
    let bundle = BackupBundle::build(input)?;
    fs::write(path, bundle.encode()?)?;
    Ok(())
}

fn write_empty_key_manifest(path: &Path) -> TestResult {
    use eliot_backup::WrappedKeyManifest;
    let manifest = WrappedKeyManifest {
        manifest_id: "key-manifest-cli".to_owned(),
        backup_id: "backup-cli-degraded".to_owned(),
        entries: Vec::new(),
    };
    manifest.validate()?;
    fs::write(path, serde_json::to_vec(&manifest)?)?;
    Ok(())
}

// WORK_UNIT_CASE: 1873e/create-preview
#[test]
fn backup_create_preview_reports_selection_and_refuses_mismatch() -> TestResult {
    // Requested full with an ORS snapshot present: selected full, exit 0.
    let output = run(&[
        "backup",
        "create-preview",
        "--backup-id",
        "backup-cli-full",
        "--class",
        "full_recovery",
        "--ors-present",
    ])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output)?;
    assert_eq!(report["selected"], "full_recovery");
    assert_eq!(report["requested_class"], "full_recovery");
    assert_eq!(report["canonical_only"], false);
    assert_eq!(report["ors_required"], true);
    // Requested full without one: refused as invalid, never silently degraded.
    let output = run(&[
        "backup",
        "create-preview",
        "--backup-id",
        "backup-cli-full",
        "--class",
        "full_recovery",
    ])?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output)?;
    assert_eq!(report["status"], "ERROR");
    assert_eq!(report["code"], "BACKUP_CREATE_PREVIEW_INVALID");
    // Unknown class names fail as input errors with the same report shape.
    let output = run(&[
        "backup",
        "create-preview",
        "--backup-id",
        "backup-cli-x",
        "--class",
        "FullRecovery",
    ])?;
    assert_eq!(output.status.code(), Some(2));
    let report = stdout_json(&output)?;
    assert_eq!(report["code"], "BACKUP_CREATE_PREVIEW_INVALID");
    Ok(())
}

// WORK_UNIT_CASE: 1873e/restore-preview
#[test]
fn backup_restore_preview_derives_bindings_from_bundle_file() -> TestResult {
    let temp = tempfile::tempdir()?;
    let bundle_path = temp.path().join("bundle.json");
    write_degraded_bundle(&bundle_path)?;
    let output = run(&[
        "backup",
        "restore-preview",
        "--bundle-json",
        bundle_path.to_str().ok_or("bundle path is not utf8")?,
        "--target-id",
        "target-cli",
        "--target-lineage",
        LINEAGE_A,
        "--target-sequence",
        "2",
        "--target-generation",
        "2",
    ])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output)?;
    assert_eq!(report["purge_first"], true);
    assert_eq!(report["suspends_ors_operations"], false);
    assert_eq!(report["canonical_only"], true);
    assert_eq!(report["evidence_level"], "isolated_import_complete");
    let steps = report["step_names"]
        .as_array()
        .ok_or("restore preview must list steps")?;
    assert!(!steps.is_empty());
    assert_eq!(steps[0], "PrepareIsolatedRoot");
    // A missing bundle file fails nonzero without touching anything.
    let output = run(&[
        "backup",
        "restore-preview",
        "--bundle-json",
        temp.path().join("absent.json").to_str().ok_or("path")?,
        "--target-id",
        "target-cli",
        "--target-lineage",
        LINEAGE_A,
        "--target-sequence",
        "2",
        "--target-generation",
        "2",
    ])?;
    assert_ne!(output.status.code(), Some(0));
    Ok(())
}

// WORK_UNIT_CASE: 1873e/issue-and-restore-run
#[test]
fn backup_issue_and_restore_run_round_trip_isolated() -> TestResult {
    use eliot_backup::{
        BackupArtifact, BackupClass, BackupInput, CanonicalRecord, EventRange, ExportFence,
        OrsSnapshotFence, WatchdogSpoolFence,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
    use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
    use eliot_store_api::{
        CommitId, EventId, OperationId, OperationManifestDigest, Resubmission, TransitionClass,
        WriteReceipt, WriteReceiptStatus,
    };
    use serde_json::json;
    use std::num::NonZeroU64;

    const LINEAGE_NEW: &str = "660e8400-e29b-41d4-a716-446655440002";

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
            operation_manifest_digest: OperationManifestDigest::new(format!(
                "manifest-{operation}"
            ))
            .expect("manifest digest"),
            // Issue #18: standalone fixture carries no transition; digest
            // format placeholders satisfy `WriteReceipt::validate`.
            semantic_source_revisions: Vec::new(),
            admission_digest: "f".repeat(64),
            mutation_plan_digest: "f".repeat(64),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: None,
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
    fn export_fence(event_count: u64) -> ExportFence {
        let (first, last) = if event_count == 0 {
            (None, None)
        } else {
            (Some(1), Some(event_count))
        };
        ExportFence {
            export_id: "export-cli".to_owned(),
            store_generation: "store-cli".to_owned(),
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
    fn full_export(with_ors: bool, with_purge: bool) -> BackupInput {
        let source = fence();
        let mut events = vec![event("event-1")];
        let mut receipts = vec![receipt_for(
            "event-1",
            "op-1",
            TransitionClass::CaptureCandidate,
        )];
        if with_purge {
            events.push(event("event-2"));
            receipts.push(receipt_for("event-2", "op-erase", TransitionClass::Erasure));
        }
        let count = events.len() as u64;
        BackupInput {
            backup_id: "backup-cli-full".to_owned(),
            class: BackupClass::FullRecovery,
            source_adapter: "test-adapter".to_owned(),
            schema_generation: "schema-1".to_owned(),
            export_fence: export_fence(count),
            canonical_events: events,
            projections: vec![
                CanonicalRecord::new("test-event", "event-1", json!({"projection": "event-1"}))
                    .expect("projection"),
            ],
            receipts,
            blobs: Vec::new(),
            purge_ledger: if with_purge {
                vec![PurgeLedgerEntry {
                    purge_id: "purge-cli-1".to_owned(),
                    subject_ref: "event-2".to_owned(),
                    scope: "scope-cli".to_owned(),
                    purged_locations: vec![PurgeLocation::BackupRestorePath],
                    tombstone_digest: sha256_hex(b"tombstone-cli"),
                    state: PurgeState::Purged,
                    state_fence: source.clone(),
                    revision: 7,
                }]
            } else {
                Vec::new()
            },
            ors_snapshot: if with_ors {
                Some(OrsSnapshotFence {
                    snapshot_id: "ors-cli".to_owned(),
                    authority_epoch: source.authority_epoch.clone(),
                    resource_generation: source.resource_generation,
                    last_receipt_cursor: 0,
                    last_event_cursor: 0,
                    last_outbox_cursor: 0,
                    pending_operation_ids: vec!["op-suspended-1".to_owned()],
                    job_checkpoint_ids: Vec::new(),
                    generation_cutover_ids: Vec::new(),
                    state_fence: source.clone(),
                    active_authority_restored: false,
                })
            } else {
                None
            },
            artifacts: artifacts(),
            watchdog_spool: Some(WatchdogSpoolFence {
                fence_id: "watchdog-cli".to_owned(),
                unresolved_signal_digests: vec![sha256_hex(b"signal-cli")],
                state_fence: source,
                bounded: true,
            }),
            host_audit: None,
            missing_features: Vec::new(),
            purge_ledger_revision: 7,
        }
    }

    let temp = tempfile::tempdir()?;

    // Full issuance from coherent exporter material.
    let export_path = temp.path().join("export-full.json");
    fs::write(&export_path, serde_json::to_vec(&full_export(true, false))?)?;
    let out_dir = temp.path().join("out-full");
    let output = run(&[
        "backup",
        "issue",
        "--export-json",
        path_str(&export_path)?,
        "--out-dir",
        path_str(&out_dir)?,
    ])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output)?;
    assert_eq!(report["requested_class"], "full_recovery");
    assert_eq!(report["issued_class"], "full_recovery");
    assert_eq!(report["downgraded"], false);
    assert_eq!(report["canonical_only"], false);
    assert_eq!(report["bundle_sha256"].as_str().ok_or("digest")?.len(), 64);
    let bundle_path = out_dir.join("bundle.json");
    assert!(bundle_path.is_file());

    // Full request without an ORS snapshot fails; explicit degraded re-issues.
    let export_no_ors = temp.path().join("export-noors.json");
    fs::write(
        &export_no_ors,
        serde_json::to_vec(&full_export(false, false))?,
    )?;
    let output = run(&[
        "backup",
        "issue",
        "--export-json",
        path_str(&export_no_ors)?,
        "--out-dir",
        path_str(&temp.path().join("out-noors"))?,
    ])?;
    assert_eq!(output.status.code(), Some(2));
    let report = stdout_json(&output)?;
    assert_eq!(report["code"], "BACKUP_ISSUE_INVALID");
    let output = run(&[
        "backup",
        "issue",
        "--export-json",
        path_str(&export_no_ors)?,
        "--out-dir",
        path_str(&temp.path().join("out-degraded"))?,
        "--allow-degraded",
    ])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output)?;
    assert_eq!(report["issued_class"], "canonical_only_degraded");
    assert_eq!(report["downgraded"], true);
    assert_eq!(report["canonical_only"], true);

    // Isolated restore run mints a fresh genesis lineage, suspends ORS work,
    // applies purge first, and never reports operational readiness or cutover.
    let output = run(&[
        "backup",
        "restore-run",
        "--bundle-json",
        path_str(&bundle_path)?,
        "--target-id",
        "target-cli",
        "--new-lineage",
        LINEAGE_NEW,
    ])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output)?;
    assert_eq!(report["new_authority_lineage"], LINEAGE_NEW);
    assert_eq!(report["new_authority_sequence"], 1);
    assert_eq!(report["new_resource_generation"], 2);
    assert_eq!(report["suspended_ors_operations"], 1);
    assert_eq!(report["first_phases"], json!(["prepare", "purge"]));
    assert_eq!(report["evidence_level"], "reconciliation_required");
    assert_eq!(report["canonical_only"], false);
    assert_eq!(report["operational_recovery_ready"], false);
    assert_eq!(report["cutover_performed"], false);
    assert!(
        report["isolated_root"]
            .as_str()
            .ok_or("root")?
            .contains("eliot-isolated-restore")
    );

    // A purge-carrying archive issues, but restore refuses the erasure receipt.
    let export_purge = temp.path().join("export-purge.json");
    fs::write(&export_purge, serde_json::to_vec(&full_export(true, true))?)?;
    let out_purge = temp.path().join("out-purge");
    let output = run(&[
        "backup",
        "issue",
        "--export-json",
        path_str(&export_purge)?,
        "--out-dir",
        path_str(&out_purge)?,
    ])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = run(&[
        "backup",
        "restore-run",
        "--bundle-json",
        path_str(&out_purge.join("bundle.json"))?,
        "--target-id",
        "target-cli",
        "--new-lineage",
        LINEAGE_NEW,
    ])?;
    assert_eq!(output.status.code(), Some(2));
    let report = stdout_json(&output)?;
    assert_eq!(report["code"], "BACKUP_RESTORE_RUN_INVALID");
    Ok(())
}

// WORK_UNIT_CASE: 1873e/key-coverage
#[test]
fn backup_key_coverage_reports_exact_set_equality() -> TestResult {
    let temp = tempfile::tempdir()?;
    let bundle_path = temp.path().join("bundle.json");
    write_degraded_bundle(&bundle_path)?;
    // Blob-free bundle with an empty manifest: exact empty equality holds.
    let manifest_path = temp.path().join("keys.json");
    write_empty_key_manifest(&manifest_path)?;
    let output = run(&[
        "backup",
        "key-coverage",
        "--bundle-json",
        bundle_path.to_str().ok_or("bundle path is not utf8")?,
        "--key-manifest-json",
        manifest_path.to_str().ok_or("manifest path is not utf8")?,
    ])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output)?;
    assert_eq!(report["covered"], true);
    assert_eq!(report["backup_id"], "backup-cli-degraded");
    // Relative paths are rejected by argument decoding before any file access.
    let output = run(&[
        "backup",
        "key-coverage",
        "--bundle-json",
        "relative/bundle.json",
        "--key-manifest-json",
        manifest_path.to_str().ok_or("manifest path is not utf8")?,
    ])?;
    assert_ne!(output.status.code(), Some(0));
    Ok(())
}
