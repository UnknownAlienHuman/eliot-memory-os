use eliot_engine::{
    ActionLeaseEvaluation, ActionLeaseService, BackupService, BlobGcService, DataRootService,
    DoctorService, ExportService, ImportService, IncidentService, MaintenanceScheduler,
    PatchRunner, PatchRunnerInput, ProductionCutoverService, RestoreService, SurrealLogicalConfig,
};
use eliot_types::{
    ActionKind, ActionLease, ActionRequest, ActionScope, BackupKind, BlobGcStatus, BlobManifest,
    BlobReachabilityRef, BlobReferenceSnapshot, BlobRetentionClass, BlobRetentionRef, ChangePlan,
    CognitiveGateDecision, CognitiveGateOutcome, CognitiveGateReason, CompletionAcceptanceItem,
    CompletionProof, CompletionStatus, CredentialProviderKind, DataRootMode,
    DataRootValidationStatus, ExportKind, FileChangeIntent, FileChangeKind, ImportKind,
    IncidentKind, IncidentSeverity, IncidentStatus, LeaseDecision, LeaseDenyReason, LeaseStatus,
    MaintenanceJobKind, MaintenanceJobStatus, PatchRequest, PatchRequestId, ProjectId, ReceiptId,
    RestoreStatus, TaintClass, TaskId, UnderstandingProof, UnderstandingProofReceipt, UnifiedDiff,
    VerifierCommandKind, VerifierPlan, VerifierRequirement, WriteId, WriteReceiptRef,
};
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn data_root_validation_dev_profile() -> TestResult {
    let validation =
        DataRootService::new(test_root("dev-profile")?).validate(DataRootMode::TestIsolated)?;
    assert!(matches!(
        validation.status,
        DataRootValidationStatus::Valid | DataRootValidationStatus::ValidWithWarnings
    ));
    Ok(())
}

#[test]
fn data_root_production_rejects_onedrive() -> TestResult {
    let root = test_root("OneDrive-production-root")?;
    let validation = DataRootService::new(root).validate(DataRootMode::ProductionLocal)?;
    assert_eq!(validation.status, DataRootValidationStatus::Invalid);
    Ok(())
}

#[test]
fn data_root_required_dirs_created_or_reported() -> TestResult {
    let root = test_root("required-dirs")?;
    let validation = DataRootService::new(&root).validate(DataRootMode::TestIsolated)?;
    assert!(root.join("backups").is_dir());
    assert!(
        validation
            .checks
            .iter()
            .any(|check| check.name.contains("required_dir"))
    );
    Ok(())
}

#[test]
fn gitignore_excludes_live_roots() {
    assert!(DataRootService::gitignore_excludes_live_roots(&repo_root()));
}

#[test]
fn backup_manifest_generated() -> TestResult {
    let report =
        BackupService::new(test_root("backup-manifest")?).run(BackupKind::LogicalExport, true)?;
    assert!(!report.manifest.backup_id.is_empty());
    Ok(())
}

#[test]
fn backup_manifest_has_checksums() -> TestResult {
    let report =
        BackupService::new(test_root("backup-checksums")?).run(BackupKind::LogicalExport, true)?;
    assert!(!report.manifest.checksums.is_empty());
    Ok(())
}

#[test]
fn backup_does_not_copy_live_db_files() -> TestResult {
    let root = test_root("backup-no-live-db")?;
    std::fs::create_dir_all(root.join("surrealdb-rocks"))?;
    std::fs::write(root.join("surrealdb-rocks").join("CURRENT"), "live")?;
    let report = BackupService::new(root).run(BackupKind::LogicalExport, true)?;
    assert!(!report.manifest.copied_live_db_files);
    Ok(())
}

#[test]
fn backup_receipt_written() -> TestResult {
    let report =
        BackupService::new(test_root("backup-receipt")?).run(BackupKind::LogicalExport, true)?;
    assert!(!report.receipt.manifest_ref.is_empty());
    Ok(())
}

#[test]
fn backup_selector_rejects_path_traversal() -> TestResult {
    let root = test_root("backup-selector")?;
    let service = BackupService::new(root);
    assert!(service.read_manifest("../outside").is_err());
    assert!(service.read_manifest(r"..\outside").is_err());
    assert!(service.read_manifest("C:outside").is_err());
    Ok(())
}

#[test]
fn restore_verify_manifest() -> TestResult {
    let root = test_root("restore-verify")?;
    BackupService::new(&root).run(BackupKind::LogicalExport, true)?;
    let report = RestoreService::new(root).verify("latest")?;
    assert!(report.receipt.verified_manifest);
    Ok(())
}

#[test]
fn restore_rejects_active_root() -> TestResult {
    let root = test_root("restore-active")?;
    BackupService::new(&root).run(BackupKind::LogicalExport, true)?;
    let report = RestoreService::new(&root).run("latest", &root, true)?;
    assert_eq!(report.receipt.status, RestoreStatus::RejectedUnsafeTarget);
    Ok(())
}

#[test]
fn restore_to_new_root_dry_run() -> TestResult {
    let root = test_root("restore-new")?;
    let target = test_root("restore-new-target")?;
    BackupService::new(&root).run(BackupKind::LogicalExport, true)?;
    let report = RestoreService::new(root).run("latest", &target, true)?;
    assert_eq!(report.receipt.status, RestoreStatus::RestoredToNewRoot);
    assert!(report.receipt.dry_run);
    Ok(())
}

#[test]
fn restore_receipt_written() -> TestResult {
    let root = test_root("restore-receipt")?;
    BackupService::new(&root).run(BackupKind::LogicalExport, true)?;
    let report = RestoreService::new(root).verify("latest")?;
    assert!(!report.receipt.restore_receipt_id.is_empty());
    Ok(())
}

#[test]
fn export_reports_only_bundle() -> TestResult {
    let root = test_root("export-reports")?;
    std::fs::create_dir_all(root.join("reports").join("x"))?;
    std::fs::write(root.join("reports").join("x").join("latest.json"), "{}")?;
    let bundle = ExportService::new(root).run(ExportKind::ReportsOnly)?;
    assert_eq!(bundle.export_kind, ExportKind::ReportsOnly);
    assert!(!bundle.payload_refs.is_empty());
    Ok(())
}

#[test]
fn import_validate_tainted_admin_only() -> TestResult {
    let root = test_root("import-taint")?;
    let import_file = root.join("bundle.json");
    std::fs::write(&import_file, "{}")?;
    let plan = ImportService::new(root).validate(&import_file, ImportKind::ReportsBundle, false)?;
    assert!(plan.validation.admin_only);
    assert_eq!(plan.taint, TaintClass::UserProvided);
    Ok(())
}

#[test]
fn import_rejects_raw_surql_without_maintenance_mode() -> TestResult {
    let root = test_root("import-surql")?;
    let import_file = root.join("raw.surql");
    std::fs::write(&import_file, "DEFINE TABLE unsafe;")?;
    let plan =
        ImportService::new(root).validate(&import_file, ImportKind::LegacyEliotExport, false)?;
    assert!(plan.validation.raw_surql_rejected);
    assert!(!plan.validation.accepted);
    Ok(())
}

#[test]
fn import_rejects_raw_surql_even_in_maintenance_mode() -> TestResult {
    let root = test_root("import-surql-maintenance")?;
    let import_file = root.join("raw.surql");
    std::fs::write(&import_file, "DEFINE TABLE unsafe;")?;
    let plan =
        ImportService::new(root).validate(&import_file, ImportKind::LegacyEliotExport, true)?;
    assert!(plan.validation.raw_surql_rejected);
    assert!(!plan.validation.accepted);
    Ok(())
}

#[test]
fn historical_import_preview_is_deterministic_and_quarantines_unknown_kinds() -> TestResult {
    let root = test_root("historical-preview")?;
    let import_file = root.join("history.json");
    std::fs::write(
        &import_file,
        r#"[
            {"artifact_id":"known-1","kind":"evidence","payload":{"fact":"verified"}},
            {"artifact_id":"unknown-1","kind":"opaque","payload":{"x":1}}
        ]"#,
    )?;
    let service = ImportService::new(&root);
    let first = service.preview(&import_file, "isolated|eliot|system")?;
    let second = service.preview(&import_file, "isolated|eliot|system")?;
    assert_eq!(first.plan_hash, second.plan_hash);
    assert_eq!(first.accepted.len(), 1);
    assert_eq!(first.quarantined.len(), 1);
    assert_eq!(
        first.accepted[0].idempotency_key,
        second.accepted[0].idempotency_key
    );
    service.finalize(
        &first,
        &first.plan_hash,
        true,
        vec![WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id: WriteId::new_v7(),
        }],
    )?;
    let replay = service.preview(&import_file, "isolated|eliot|system")?;
    assert!(replay.accepted.is_empty());
    assert_eq!(replay.already_imported.len(), 1);
    Ok(())
}

#[test]
fn blob_manifest_generated() -> TestResult {
    let service = blob_fixture("blob-manifest")?;
    let manifest = service.manifest()?;
    assert!(!manifest.blobs.is_empty());
    Ok(())
}

#[test]
fn blob_gc_plan_marks_reachable() -> TestResult {
    let service = blob_fixture("blob-reachable")?;
    let manifest = service.manifest()?;
    let reachable = manifest.blobs[0].blob_hash.clone();
    let snapshot = reference_snapshot(&manifest, &[&reachable], &[], true);
    let plan = service.gc_plan(&manifest, &snapshot)?;
    assert!(plan.reachable.contains(&reachable));
    Ok(())
}

#[test]
fn blob_gc_dry_run_writes_receipt() -> TestResult {
    let service = blob_fixture("blob-gc-receipt")?;
    let manifest = service.manifest()?;
    let snapshot = reference_snapshot(&manifest, &[], &[], true);
    let plan = service.gc_plan(&manifest, &snapshot)?;
    let receipt = service.gc_run(&plan, &manifest, &snapshot, true)?;
    assert_eq!(receipt.status, BlobGcStatus::DryRun);
    assert!(!receipt.gc_receipt_id.is_empty());
    Ok(())
}

#[test]
fn blob_gc_requires_two_scans_and_exact_approval_before_purge() -> TestResult {
    let root = test_root("blob-two-scan")?;
    let blob = root.join("candidate.blob");
    std::fs::write(&blob, b"candidate")?;
    let service = BlobGcService::new(&root).with_grace_seconds(0);
    let first_manifest = service.manifest()?;
    let snapshot = reference_snapshot(&first_manifest, &[], &[], true);
    let first = service.gc_plan(&first_manifest, &snapshot)?;
    assert!(first.unreachable_deletable.is_empty());
    let second_manifest = service.manifest()?;
    let second = service.gc_plan(&second_manifest, &snapshot)?;
    assert_eq!(second.deletion_candidates.len(), 1);
    let refused =
        service.gc_run_authorized(&second, &second_manifest, &snapshot, "wrong", false, false)?;
    assert_eq!(refused.status, BlobGcStatus::Failed);
    assert!(blob.is_file());
    let purged = service.gc_run_authorized(
        &second,
        &second_manifest,
        &snapshot,
        &second.approval_hash,
        false,
        false,
    )?;
    assert_eq!(purged.status, BlobGcStatus::Succeeded);
    assert!(!blob.exists());
    Ok(())
}

#[test]
fn blob_filename_alone_grants_no_retention() -> TestResult {
    let root = test_root("blob-audit")?;
    std::fs::create_dir_all(root.join("audit"))?;
    std::fs::write(root.join("audit").join("audit.blob"), b"audit")?;
    let service = BlobGcService::new(root).with_grace_seconds(0);
    let manifest = service.manifest()?;
    let snapshot = reference_snapshot(&manifest, &[], &[], true);
    let first = service.gc_plan(&manifest, &snapshot)?;
    assert!(first.protected.is_empty());
    let second_manifest = service.manifest()?;
    let second = service.gc_plan(&second_manifest, &snapshot)?;
    assert_eq!(second.deletion_candidates.len(), 1);
    Ok(())
}

#[test]
fn canonical_references_and_typed_retention_survive_gc() -> TestResult {
    let root = test_root("blob-canonical-reference")?;
    let active = root.join("active.blob");
    let archived = root.join("archived.blob");
    let legal = root.join("legal.blob");
    std::fs::write(&active, b"active")?;
    std::fs::write(&archived, b"archived")?;
    std::fs::write(&legal, b"legal")?;
    let service = BlobGcService::new(root).with_grace_seconds(0);
    let manifest = service.manifest()?;
    let active_hash = hash_for_path(&manifest, &active)?;
    let archived_hash = hash_for_path(&manifest, &archived)?;
    let legal_hash = hash_for_path(&manifest, &legal)?;
    let snapshot = reference_snapshot(
        &manifest,
        &[&active_hash, &archived_hash, &legal_hash],
        &[(&legal_hash, BlobRetentionClass::LegalHold)],
        true,
    );
    let first = service.gc_plan(&manifest, &snapshot)?;
    let second_manifest = service.manifest()?;
    let second = service.gc_plan(&second_manifest, &snapshot)?;
    assert!(first.deletion_candidates.is_empty());
    assert!(second.deletion_candidates.is_empty());
    assert!(second.reachable.contains(&active_hash));
    assert!(second.reachable.contains(&archived_hash));
    assert!(second.protected.contains(&legal_hash));
    assert!(active.is_file() && archived.is_file() && legal.is_file());
    Ok(())
}

#[test]
fn incomplete_or_changed_reference_scan_refuses_purge() -> TestResult {
    let root = test_root("blob-incomplete-scan")?;
    let blob = root.join("orphan.blob");
    std::fs::write(&blob, b"orphan")?;
    let service = BlobGcService::new(&root).with_grace_seconds(0);
    let first_manifest = service.manifest()?;
    let snapshot = reference_snapshot(&first_manifest, &[], &[], true);
    let mut incomplete = snapshot.clone();
    incomplete.complete = false;
    assert!(service.gc_plan(&first_manifest, &incomplete).is_err());
    service.gc_plan(&first_manifest, &snapshot)?;
    let second_manifest = service.manifest()?;
    let plan = service.gc_plan(&second_manifest, &snapshot)?;
    let receipt = service.gc_run_authorized(
        &plan,
        &second_manifest,
        &incomplete,
        &plan.approval_hash,
        false,
        false,
    )?;
    assert_eq!(receipt.status, BlobGcStatus::Failed);
    assert!(blob.is_file());
    let mut stale = snapshot.clone();
    stale.created_at -= time::Duration::minutes(6);
    let stale_receipt = service.gc_run_authorized(
        &plan,
        &second_manifest,
        &stale,
        &plan.approval_hash,
        false,
        false,
    )?;
    assert_eq!(stale_receipt.status, BlobGcStatus::Failed);
    assert!(blob.is_file());
    let mut referenced_after_plan = snapshot.clone();
    referenced_after_plan
        .reachable_refs
        .push(BlobReachabilityRef {
            blob_hash: plan.deletion_candidates[0].blob_hash.clone(),
            canonical_record_ref: "canonical-record-after-plan".to_owned(),
        });
    let newly_referenced = service.gc_run_authorized(
        &plan,
        &second_manifest,
        &referenced_after_plan,
        &plan.approval_hash,
        false,
        false,
    )?;
    assert_eq!(newly_referenced.status, BlobGcStatus::Failed);
    assert!(blob.is_file());
    std::fs::write(&blob, b"changed-after-plan")?;
    let changed_manifest = service.manifest()?;
    let changed = service.gc_run_authorized(
        &plan,
        &changed_manifest,
        &snapshot,
        &plan.approval_hash,
        false,
        false,
    )?;
    assert_eq!(changed.status, BlobGcStatus::Failed);
    assert!(blob.is_file());
    Ok(())
}

#[test]
fn maintenance_job_runs_doctor() -> TestResult {
    let job = MaintenanceScheduler::new(test_root("maintenance-doctor")?)
        .run_one_shot(MaintenanceJobKind::Doctor, true)?;
    assert_eq!(job.job_kind, MaintenanceJobKind::Doctor);
    assert!(matches!(
        job.status,
        MaintenanceJobStatus::Succeeded | MaintenanceJobStatus::SucceededDryRun
    ));
    Ok(())
}

#[test]
fn maintenance_job_receipt_written() -> TestResult {
    let job = MaintenanceScheduler::new(test_root("maintenance-receipt")?)
        .run_one_shot(MaintenanceJobKind::Doctor, true)?;
    assert!(job.receipt_ref.is_some());
    Ok(())
}

#[test]
fn unreadable_incident_state_reports_error_not_absent_lockdown() -> TestResult {
    // A caller that treats this `Err` as "no lockdown" fails open on an
    // `A0.3` boundary. The error must be distinguishable from `Ok(false)`.
    let root = test_root("incident-unreadable")?;
    std::fs::create_dir_all(root.join("incidents"))?;
    std::fs::write(root.join("incidents").join("incidents.json"), b"{ not json")?;

    let service = IncidentService::new(root);
    assert!(
        service.lockdown_active().is_err(),
        "a malformed incident file must not read as an absent lockdown"
    );
    Ok(())
}

#[test]
fn absent_incident_state_reports_no_lockdown() -> TestResult {
    // The other direction: a missing file is a known-empty state, not an error,
    // so the fix above does not turn a clean install into a denial.
    let service = IncidentService::new(test_root("incident-absent")?);
    assert!(
        !service.lockdown_active()?,
        "a missing incident file is a known-empty state, not a lockdown"
    );
    Ok(())
}

#[test]
fn incident_open_ack_close() -> TestResult {
    let service = IncidentService::new(test_root("incident-cycle")?);
    let opened = service.open(
        IncidentKind::DbUnavailable,
        IncidentSeverity::Blocking,
        "incident cycle",
    )?;
    let acknowledged = service.acknowledge(&opened.incident_id)?;
    let closed = service.close(&opened.incident_id)?;
    assert_eq!(opened.status, IncidentStatus::Open);
    assert_eq!(acknowledged.status, IncidentStatus::Acknowledged);
    assert_eq!(closed.status, IncidentStatus::Closed);
    Ok(())
}

#[test]
fn incident_lockdown_blocks_action_lease() {
    assert!(action_lockdown_blocks());
}

#[tokio::test]
async fn incident_lockdown_blocks_patchrunner() -> TestResult {
    assert!(patch_lockdown_blocks().await?);
    Ok(())
}

#[test]
fn incident_lockdown_blocks_done_verified() {
    let decision =
        eliot_engine::CompletionGate::decide_with_incident_context(&completion_proof(), true);
    assert_eq!(decision.final_status, CompletionStatus::UnsafeToFinish);
}

#[test]
fn doctor_report_generated() -> TestResult {
    let report = DoctorService::new(test_root("doctor-report")?, repo_root()).report()?;
    assert_eq!(report.component, "doctor");
    Ok(())
}

#[test]
fn doctor_detects_stale_lock_fixture() -> TestResult {
    let repo = test_root("doctor-lock-repo")?;
    std::fs::create_dir_all(repo.join("target"))?;
    let lock = repo
        .join("target")
        .join("eliot-governor-shared-db-test.lock");
    std::fs::write(&lock, "stale")?;
    let report = DoctorService::new(test_root("doctor-lock")?, &repo).report()?;
    let _ = std::fs::remove_file(lock);
    assert!(
        report
            .stale_locks
            .iter()
            .any(|lock| lock.ends_with("eliot-governor-shared-db-test.lock"))
    );
    Ok(())
}

#[test]
fn operations_doctor_reports_isolated_root_and_required_cli_state() -> TestResult {
    let root = test_root("operations-doctor")?;
    let password_file = root.join("secrets").join("password.txt");
    std::fs::create_dir_all(password_file.parent().ok_or("password parent missing")?)?;
    std::fs::write(&password_file, "isolated-secret")?;
    let report =
        DoctorService::new(&root, repo_root()).operations_report(&SurrealLogicalConfig {
            executable: PathBuf::from("surreal"),
            endpoint: "ws://127.0.0.1:19999/rpc".to_owned(),
            namespace: "eliot".to_owned(),
            database: "system".to_owned(),
            username: "root".to_owned(),
            credential_provider: CredentialProviderKind::LegacyPasswordFile,
            credential_id: String::new(),
            password_file,
            legacy_password_file_authorized: true,
            storage_root: Some(root.join("store")),
        })?;
    let surreal_cli = report
        .checks
        .iter()
        .find(|check| check.name == "surreal_cli")
        .ok_or("surreal_cli check missing")?;
    assert!(surreal_cli.blocking);
    assert_eq!(
        report.status,
        if surreal_cli.passed {
            "degraded"
        } else {
            "blocked"
        },
        "checks={:#?}",
        report.checks
    );
    assert!(report.checks.iter().any(|check| {
        check.name == "operator_protocol_contract" && check.passed && check.blocking
    }));
    assert!(
        report
            .checks
            .iter()
            .any(|check| { check.name == "latest_backup" && !check.passed && !check.blocking })
    );
    Ok(())
}

#[test]
fn operations_doctor_blocks_multiple_owners_sync_storage_and_unreceipted_imports() -> TestResult {
    let root = test_root("operations-doctor-blocked")?;
    let password_file = root.join("secrets").join("password.txt");
    std::fs::create_dir_all(password_file.parent().ok_or("password parent missing")?)?;
    std::fs::write(&password_file, "isolated-secret")?;
    std::fs::create_dir_all(root.join("runtime"))?;
    std::fs::write(
        root.join("runtime/daemon.lock"),
        std::process::id().to_string(),
    )?;
    std::fs::write(
        root.join("runtime/service.lock"),
        std::process::id().to_string(),
    )?;
    std::fs::create_dir_all(root.join("imports/envelopes"))?;
    std::fs::write(root.join("imports/envelopes/unreceipted.json"), "{}")?;
    let report =
        DoctorService::new(&root, repo_root()).operations_report(&SurrealLogicalConfig {
            executable: PathBuf::from("surreal"),
            endpoint: "ws://127.0.0.1:19998/rpc".to_owned(),
            namespace: "eliot".to_owned(),
            database: "system".to_owned(),
            username: "root".to_owned(),
            credential_provider: CredentialProviderKind::LegacyPasswordFile,
            credential_id: String::new(),
            password_file,
            legacy_password_file_authorized: true,
            storage_root: Some(root.join("OneDrive-store")),
        })?;
    assert_eq!(report.status, "blocked");
    assert!(
        report.checks.iter().any(|check| {
            check.name == "single_runtime_owner" && !check.passed && check.blocking
        })
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| { check.name == "storage_sync_root" && !check.passed && check.blocking })
    );
    assert!(report.checks.iter().any(|check| {
        check.name == "unreceipted_historical_imports" && !check.passed && check.blocking
    }));
    Ok(())
}

#[test]
fn cutover_is_manifest_only_and_rejects_sync_roots() -> TestResult {
    let current = test_root("cutover-current")?;
    let proposed = test_root("OneDrive-cutover-target")?;
    let config = current.join("config.toml");
    let executable = current.join("eliot-governor.exe");
    std::fs::write(&config, "schema_version = \"1\"")?;
    std::fs::write(&executable, b"fixture")?;
    let manifest = ProductionCutoverService::plan(&current, &proposed, &config, &executable);
    assert_eq!(manifest.status, "BLOCKED_PREFLIGHT");
    assert!(manifest.dry_run);
    assert!(manifest.approval_required);
    Ok(())
}

#[test]
fn accumulated_capabilities_non_regression() {
    assert!(DataRootService::gitignore_excludes_live_roots(&repo_root()));
}

fn blob_fixture(name: &str) -> TestResult<BlobGcService> {
    let root = test_root(name)?;
    std::fs::write(root.join("standard.blob"), b"standard")?;
    Ok(BlobGcService::new(root))
}

fn reference_snapshot(
    manifest: &BlobManifest,
    reachable_hashes: &[&String],
    retention: &[(&String, BlobRetentionClass)],
    complete: bool,
) -> BlobReferenceSnapshot {
    BlobReferenceSnapshot {
        snapshot_id: format!("snapshot:{}", manifest.blob_root),
        source_store: "isolated-test-store".to_owned(),
        source_revision: "revision-1".to_owned(),
        scope: manifest.blob_root.clone(),
        query_hash: "bounded-canonical-blob-reference-query".to_owned(),
        created_at: time::OffsetDateTime::now_utc(),
        complete,
        records_scanned: u32::try_from(reachable_hashes.len()).unwrap_or(u32::MAX),
        reachable_refs: reachable_hashes
            .iter()
            .enumerate()
            .map(|(index, hash)| BlobReachabilityRef {
                blob_hash: (*hash).clone(),
                canonical_record_ref: format!("canonical-record-{index}"),
            })
            .collect(),
        retention_refs: retention
            .iter()
            .enumerate()
            .map(|(index, (hash, class))| BlobRetentionRef {
                blob_hash: (*hash).clone(),
                canonical_record_ref: format!("canonical-retention-{index}"),
                retention: *class,
            })
            .collect(),
    }
}

fn hash_for_path(manifest: &BlobManifest, path: &Path) -> TestResult<String> {
    manifest
        .blobs
        .iter()
        .find(|blob| blob.path == path.to_string_lossy())
        .map(|blob| blob.blob_hash.clone())
        .ok_or_else(|| format!("blob missing from manifest: {}", path.display()).into())
}

fn action_lockdown_blocks() -> bool {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let agent_id = eliot_types::AgentId::new_v7();
    let request = ActionRequest {
        request_id: eliot_types::ActionRequestId::new_v7(),
        project_id,
        task_id,
        agent_id,
        goal: "lockdown".to_owned(),
        requested_action_kind: ActionKind::ChangePlanOnly,
        understanding_proof_ref: "proof".to_owned(),
        cognitive_gate_ref: "gate".to_owned(),
        codecortex_report_refs: Vec::new(),
        skill_refs: Vec::new(),
        skill_activation_decisions: Vec::new(),
        proposed_change_plan: change_plan(),
        proposed_verifier_plan: verifier_plan(),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let proof = understanding_proof(project_id, task_id);
    let receipt = UnderstandingProofReceipt {
        task_id: task_id.to_string(),
        project_id,
        accepted: true,
        validation_errors: Vec::new(),
        checked_refs: Vec::new(),
        code_task: false,
        codecortex_report_refs: Vec::new(),
        files_to_change: Vec::new(),
        files_to_inspect: Vec::new(),
    };
    let gate = CognitiveGateDecision {
        task_id: task_id.to_string(),
        project_id,
        decision: CognitiveGateOutcome::Allow,
        reasons: vec![CognitiveGateReason::Allowed],
    };
    let lease = ActionLeaseService.evaluate(&ActionLeaseEvaluation {
        request: &request,
        understanding_proof: Some(&proof),
        understanding_receipt: &receipt,
        cognitive_gate_decision: &gate,
        codecortex_reports: &[],
        current_git_head: None,
        work_lease: None,
        incident_lockdown_active: true,
    });
    lease
        .denial_reasons
        .contains(&LeaseDenyReason::IncidentLockdown)
}

async fn patch_lockdown_blocks() -> TestResult<bool> {
    let repo = repo_root();
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let agent_id = eliot_types::AgentId::new_v7();
    let lease = ActionLease {
        lease_id: eliot_types::ActionLeaseId::new_v7(),
        request_id: eliot_types::ActionRequestId::new_v7(),
        project_id,
        task_id,
        agent_id,
        decision: LeaseDecision::AllowPatchExecution,
        status: LeaseStatus::ApprovedForExecution,
        allowed_scope: Some(ActionScope {
            repo_root: repo.display().to_string(),
            git_head: None,
            allowed_files: vec!["README.md".to_owned()],
            allowed_symbols: Vec::new(),
            forbidden_files: Vec::new(),
            max_files: 1,
            max_diff_bytes: 1024,
            max_runtime_seconds: 1,
        }),
        change_plan: None,
        verifier_plan: None,
        skill_refs: Vec::new(),
        denial_reasons: Vec::new(),
        expires_at: Some(time::OffsetDateTime::now_utc() + time::Duration::minutes(5)),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let request = PatchRequest {
        patch_request_id: PatchRequestId::new_v7(),
        project_id,
        task_id,
        agent_id,
        action_lease_id: lease.lease_id,
        repo_root: repo.display().to_string(),
        git_head_before: None,
        codecortex_report_refs: Vec::new(),
        verifier_plan_ref: "verifier".to_owned(),
        diff: UnifiedDiff {
            byte_len: 0,
            text: String::new(),
        },
        created_at: time::OffsetDateTime::now_utc(),
    };
    let run = PatchRunner::new(&repo, None)
        .preflight(&PatchRunnerInput {
            request: &request,
            lease: Some(&lease),
            work_lease: None,
            codecortex_reports: &[],
            verifier_plan: None,
            incident_lockdown_active: true,
        })
        .await?;
    Ok(run
        .failure_reasons
        .iter()
        .any(|reason| reason == "incident_lockdown_active"))
}

fn completion_proof() -> CompletionProof {
    CompletionProof {
        task_id: "h0".to_owned(),
        project_id: ProjectId::new_v7(),
        goal: "lockdown".to_owned(),
        changed_files: Vec::new(),
        memory_refs_used: Vec::new(),
        checks_run: vec!["test".to_owned()],
        checks_not_run: Vec::new(),
        acceptance_items: vec![CompletionAcceptanceItem {
            item: "done".to_owned(),
            status: "verified".to_owned(),
            evidence: "test".to_owned(),
            verifier: "test".to_owned(),
            residual_uncertainty: "none".to_owned(),
        }],
        evidence: vec!["test".to_owned()],
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: "none".to_owned(),
        known_risks: Vec::new(),
    }
}

fn understanding_proof(project_id: ProjectId, task_id: TaskId) -> UnderstandingProof {
    UnderstandingProof {
        task_id: task_id.to_string(),
        project_id,
        goal: "lockdown".to_owned(),
        code_task: false,
        current_truth_refs: vec!["claim".to_owned()],
        evidence_refs: vec!["evidence".to_owned()],
        codecortex_report_refs: Vec::new(),
        files_to_change: Vec::new(),
        files_to_inspect: Vec::new(),
        causal_bridge: "lockdown".to_owned(),
        causal_bridge_from_goal_to_code: String::new(),
        invariants: vec!["lockdown".to_owned()],
        negative_memory_checked: true,
        unknowns: Vec::new(),
        planned_action: "inspect".to_owned(),
        expected_verifiers: vec!["test".to_owned()],
        blast_radius_acknowledged: true,
        skill_refs: Vec::new(),
        skill_application_rationales: Vec::new(),
        skill_anti_scope_acknowledgements: Vec::new(),
        skill_required_inputs: Vec::new(),
        skill_verifier_plan_refs: Vec::new(),
        risk_level: "low".to_owned(),
    }
}

fn change_plan() -> ChangePlan {
    ChangePlan {
        summary: "lockdown".to_owned(),
        files: vec![FileChangeIntent {
            path: "README.md".to_owned(),
            reason: "lockdown".to_owned(),
            expected_change_kind: FileChangeKind::ReadOnly,
            code_evidence_refs: Vec::new(),
        }],
        symbols: Vec::new(),
        invariants_to_preserve: Vec::new(),
        risks: Vec::new(),
        rollback_plan: None,
    }
}

fn verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "test".to_owned(),
            command_kind: VerifierCommandKind::CargoTest,
            command_display: "cargo test".to_owned(),
            scope: vec!["README.md".to_owned()],
            required_for_done: true,
            expected_signal: "test".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["test".to_owned()],
    }
}

fn test_root(name: &str) -> TestResult<PathBuf> {
    let root = std::env::temp_dir().join(format!(
        "eliot-h0-{name}-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
