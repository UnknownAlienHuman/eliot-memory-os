//! Live `eliot backup` CLI proofs (issue #1873).
//!
//! The real binary path end to end on temp-only fixtures: create-preview
//! selection and refusal, restore-preview bindings from a bundle file, and
//! key-coverage checks. Exit codes plus JSON stdout are asserted; nothing
//! executes, issues, or cuts over, and no production state is touched.

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
