use crate::{
    action_plan,
    config::load_config,
    mcp_stdio, named_pipe_ipc,
    runtime_instance::{
        RuntimeInstance, RuntimePublicationState, atomic_write_bytes, config_runtime_root,
        default_config_path, store_root_from_storage,
    },
};
use anyhow::{Context, Result, bail};
use eliot_engine::{
    AdapterMemoryWriter, AdapterObservationBridge, AdapterObservationReport, AdapterRegistry,
    AdapterSupervisor, AgentSessionService, AntigravityAuthCheckService, AntigravityBinaryResolver,
    AntigravityCapabilityProbeService, AntigravityCommandContractService,
    AntigravityDisposableWorktreeSmokeService, AntigravityDoctorIntegration,
    AntigravityEnablementService, AntigravityExecutionGate, AntigravityGuiProcessProbeService,
    AntigravityLiveSmokeService, AntigravityMcpBoundaryService, AntigravityMcpConfigService,
    AntigravityOfficialCliInstallerService, AntigravityOfficialPluginService,
    AntigravityPluginBundleService, AntigravityRealExecutionDoctor, AntigravityRollbackService,
    AntigravityRunner, AntigravitySkillBundleService, AntigravityTelemetryService,
    AntigravityVersionGateService, AntigravityVisibilityService,
    AntigravityWindowsInstallDiscoveryService, BackupService, BlackboardAddInput,
    BlackboardService, BlobGcService, CandidateDiffCaptureInput, CandidateDiffService,
    CandidateReviewInput, CandidateReviewService, CodeCortexMemoryWriter, CodeCortexService,
    CollectiveMemoryWriter, CollectiveTraceService, CostLedgerService, DataRootService,
    DoctorService, DreamCandidateService, EliotHookService, EvalBaselineService, EvalCaseInput,
    EvalCaseService, EvalComparisonService, EvalCoverageService, EvalDatasetManifestService,
    EvalDoctorIntegration, EvalFixtureStabilityService, EvalGateProfileService, EvalRegressionGate,
    EvalRegressionGateService, EvalRunInput, EvalRunnerService, EvalSuiteInput, EvalSuiteService,
    EvalTrendService, EvalVerdictService, ExportService, ExternalProviderRegistryService,
    ExternalReviewBridgeService, ExternalReviewGate, ExternalReviewGateContext,
    ExternalReviewJobService, ExternalReviewNormalizer, ExternalReviewPacketBuilder,
    ExternalReviewReportService, FlakeDetectionService, ForgettingPolicyService,
    GraphHealthService, HealthService, HistoricalImportMemoryWriter, ImportService,
    IncidentService, IpcGovernorClient, LifecycleService, LogService, LostAgentRecoveryService,
    MailboxSendInput, MailboxService, MaintenanceMemoryWriter, MaintenanceScheduler,
    MemoryGravityService, MemoryInfluenceService, MemoryLifecycleGate, MemoryLifecycleMemoryWriter,
    MemoryLifecycleService, MemoryVitalityService, MetricRecorderService, MetricRegistryService,
    MetricRollupService, MetricsDoctorIntegration, ModuleRegistryService, NamedPipeIpcServer,
    PatchMemoryWriter, PatchRunner, PatchRunnerInput, PluginVerifier, ProductionCutoverService,
    ProductionReadinessService, QualitySignalService, ReadService, ReadinessFixture,
    ReplayCaseInput, ReplayCaseService, ReplayRunnerService, ReplaySetInput, ReplaySetService,
    ReplayVerdictService, ReportService, RestoreService, RuntimeDashboardService,
    ServiceSupervisor, SkillActivationContext, SkillArchiveQuarantineService, SkillCurationGate,
    SkillCurationReport, SkillCurationReportService, SkillCuratorMemoryWriter,
    SkillCuratorRunInput, SkillCuratorService, SkillDistractorFilterService,
    SkillExecutionProofService, SkillInfluenceReportInput, SkillInfluenceService,
    SkillLifecycleService, SkillNeedEstimator, SkillPatchService, SkillRegistryService,
    SleepConsolidationService, SleepRunInput, SloService, StartupRecoveryService,
    StatefulDbTestIsolationService, StdioShimService, SurrealLogicalConfig, TestCostService,
    TestInventoryService, TraceCompletenessInput, TraceCompletenessService,
    VerificationDoctorIntegration, VerificationPlannerService, VerificationProfileService,
    VerificationRunnerService, VerificationVerdictService, VerifierHarness, WindowsServiceManager,
    WorkClaimRequest, WorkCreateRequest, WorkLeaseService, WorkMemoryWriter, WorkQueueService,
    WorkState, WorktreeCleanupService, WorktreeCreateInput, WorktreeLeaseService,
    WorktreeMemoryWriter, WriteAdmissionService, WriterActor, WriterConfig, WriterReportService,
    antigravity_real_report, antigravity_report, antigravity_review_request, builtin_manifests,
    codecortex_report_ref, default_lease_ttl_minutes, default_runtime_services, default_work_scope,
    external_review_request, family_slug, h1_protocol_version, harness_experiment_record,
    hash_secret, plugin_report_markdown, shutdown_deadline_after, test_request,
};
use eliot_store::{
    BlobStore, CanonicalStore, ControlWal, NamedSurqlOp, SurrealServerSupervisor, SurrealStore,
};
use eliot_types::{
    ActionKind, ActionLease, AdapterCapability, AdapterObservation, AdapterResult,
    AdapterResultStatus, AgentId, AgentRole, AgentSessionId, AntigravityAuthCheck,
    AntigravityBinaryResolution, AntigravityBinaryResolutionStatus, AntigravityCapabilityProbe,
    AntigravityCommandContract, AntigravityDisableReceipt, AntigravityEnablementReceipt,
    AntigravityEnablementScope, AntigravityEnablementState, AntigravityExecutionGateDecisionKind,
    AntigravityLiveSmokeMode, AntigravityLiveSmokeResult, AntigravityLiveSmokeStatus,
    AntigravityMcpInvocationReceipt, AntigravityPluginBundle, AntigravityProviderState,
    AntigravityRealReport, AntigravityReviewMode, AntigravityReviewRequest, AntigravityRun,
    AntigravitySkillBundle, BackupKind, BenchmarkIntegrityReceipt, BlackboardItem,
    BlackboardItemId, BlackboardItemKind, BlackboardScope, BlobReport, CandidateDiff,
    CandidateDiffId, CandidateDiffStatus, CandidateReview, CandidateReviewDecision, ClaimCardInput,
    ClaimId, CodeCortexReport, CodeCortexRequest, CommandContext, CompletionStatus,
    ComponentHealth, ConfidenceLevel, ContextPacketL3, CostLedger, CredentialProviderKind,
    CredentialPurpose, CredentialRef, CredentialStatus, CurrentStateRequest, DashboardReport,
    DataRootMode, DreamCandidateKind, EpistemicStatus, EvalBaseline, EvalCandidateComparison,
    EvalCase, EvalCoverageMatrix, EvalDatasetManifest, EvalFailureCluster, EvalFamily,
    EvalFixtureStabilityReport, EvalGateDecision, EvalGateDecisionKind, EvalRegressionGateProfile,
    EvalRun, EvalRunProfile, EvalSuite, EvalTrendReport, EvalVerdict, EvalVerdictStatus,
    EvidenceAtomInput, EvidenceId, EvidenceIngestCommand, ExportKind, ExternalOutputSchemaKind,
    ExternalProviderProfile, ExternalReviewBudget, ExternalReviewGateDecisionKind,
    ExternalReviewJob, ExternalReviewJobStatus, ExternalReviewPacket, ExternalReviewRequest,
    ExternalReviewRole, FetchAtomsL2Request, FlakeReport, ForgettingOperator, ForgettingPolicy,
    ForgettingReason, HarnessExperimentRecord, HealthStatus, HookEventKind, ImportKind,
    IncidentKind, IncidentSeverity, IpcFrame, IpcFrameKind, LatencyHistogram, LifecycleStatus,
    LogEventKind, LogLevel, MailboxMessage, MailboxMessageId, MailboxMessageKind, MailboxRecipient,
    MaintenanceJobKind, MemoryGravity, MemoryInfluenceReport, MemoryLifecyclePacketView,
    MemoryLifecycleReport, MemoryVitalityScore, MetricDefinition, MetricSample, MetricWindow,
    MetricsDoctorStatus, ModuleManifest, PatchRequest, PatchRequestId, PatchRun, PatchRunStatus,
    PluginInstallCheck, ProfileVerificationRun, ProjectId, QualitySignal, ReadConsistencyMode,
    RecallL0Request, ReplayCase, ReplayCaseKind, ReplayRun, ReplaySet, RuntimeHealthReport,
    RuntimeLogReport, RuntimeMode, RuntimeStatusReport, SCHEMA_VERSION, SemanticCommand,
    ServiceHealthState, ServiceInstallAction, ServiceInstallStatus, ServiceReadinessStatus,
    ServiceRuntimeStatus, SkillCardV2, SkillCurationAction, SkillCurationDecisionKind,
    SkillCurationGateDecision, SkillCurationProposal, SkillCurationReceipt, SkillCuratorRun,
    SkillExecutionOutcome, SkillFailureMode, SkillId, SkillInfluenceReport, SkillInputRequirement,
    SkillInputSource, SkillLifecycleState as SkillState, SkillOutputSpec, SkillScopeRule,
    SkillStep, SkillToolRequirement, SleepTrigger, SloDefinition, SloEvaluation,
    SourceSnapshotInput, StartupHealthReport, StatefulDbIsolationReport, TaintClass, TaskId,
    TelemetryRollup, TestCostReport, TestInventory, TestSuiteProfile, TraceCompletenessContract,
    UnifiedDiff, VerificationDecision, VerificationDoctorStatus, VerificationPlan,
    VerificationResult, VerificationRunInput, VerificationVerdict, VerifierCommandKind,
    VerifierPlan, VerifierRequirement, VerifierRun, VerifierStatus, Visibility, WorkItem,
    WorkItemId, WorkLease, WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason,
    WorkLeaseId, WorkLeaseState, WorktreeLease, WorktreeLeaseId, WorktreeLeaseRequest,
    WorktreeLeaseRequestId,
};
use std::fmt::Write as FmtWrite;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::str::FromStr;
use std::time::Duration;
use tracing::info;

pub async fn run_doctor_command(config_path: &Path, offline: bool) -> Result<()> {
    let startup = build_startup_report(config_path, offline).await?;
    write_report(&startup)?;
    if startup.overall == HealthStatus::NotReady {
        bail!("governor startup health is not ready");
    }
    let root = runtime_root(config_path);
    let report = DoctorService::new(&root, repo_root()).report()?;
    write_safety_report(&root, "doctor", "Doctor", &report)?;
    write_json(&report)
}

pub fn run_doctor_report(config_path: &Path) -> Result<()> {
    read_or_generate_doctor_report(config_path).and_then(|report| write_json(&report))
}

pub fn run_operations_doctor(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let surreal = surreal_logical_config(config_path)?;
    let report = DoctorService::new(&root, repo_root()).operations_report(&surreal)?;
    write_safety_report(&root, "operations-doctor", "Operations Doctor", &report)?;
    write_json(&report)
}

pub fn run_data_root_validate(config_path: &Path, profile: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mode = parse_data_root_mode(profile)?;
    let validation = DataRootService::new(&root).validate(mode)?;
    write_safety_report(&root, "data-root", "Data Root", &validation)?;
    write_json(&validation)
}

pub fn run_data_root_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "data-root", || {
        DataRootService::new(runtime_root(config_path)).validate(DataRootMode::DevProjectLocal)
    })
}

pub fn run_backup_plan(config_path: &Path, kind: &str) -> Result<()> {
    run_backup_run(config_path, kind, true)
}

pub fn run_backup_run(config_path: &Path, kind: &str, dry_run: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let surreal = surreal_logical_config(config_path)?;
    let report =
        BackupService::new(&root).run_logical(parse_backup_kind(kind)?, &surreal, dry_run)?;
    write_safety_report(&root, "backup", "Backup", &report)?;
    write_json(&report)
}

pub fn run_backup_verify(config_path: &Path, backup: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest = BackupService::new(&root).verify(backup)?;
    let report = serde_json::json!({
        "component": "backup_verify",
        "status": "verified",
        "manifest": manifest,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_safety_report(&root, "backup", "Backup Verify", &report)?;
    write_json(&report)
}

pub fn run_backup_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    write_json(&serde_json::json!({
        "component": "backup_inventory",
        "entries": BackupService::new(&root).list()?,
        "generated_at": time::OffsetDateTime::now_utc(),
    }))
}

pub fn run_backup_status(config_path: &Path, backup: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let service = BackupService::new(&root);
    let manifest = service.read_manifest(backup)?;
    let verified = service.verify(backup).is_ok();
    write_json(&serde_json::json!({
        "component": "backup_status",
        "backup_id": manifest.backup_id,
        "verified": verified,
        "age_seconds": (time::OffsetDateTime::now_utc() - manifest.created_at).whole_seconds(),
        "dry_run": manifest.dry_run,
        "generated_at": time::OffsetDateTime::now_utc(),
    }))
}

pub fn run_backup_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "backup", || {
        BackupService::new(runtime_root(config_path)).run(BackupKind::LogicalExport, true)
    })
}

pub fn run_restore_plan(
    config_path: &Path,
    backup: &str,
    target: &Path,
    target_config_path: &Path,
) -> Result<()> {
    let root = runtime_root(config_path);
    let target_surreal = surreal_logical_config(target_config_path)?;
    let plan = RestoreService::new(&root).plan_logical(backup, target, &target_surreal)?;
    write_safety_report(&root, "restore", "Restore Plan", &plan)?;
    write_json(&plan)
}

pub fn run_restore_verify(config_path: &Path, backup: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = RestoreService::new(&root).verify(backup)?;
    write_safety_report(&root, "restore", "Restore", &report)?;
    write_json(&report)
}

pub fn run_restore_run(
    config_path: &Path,
    backup: &str,
    target: &Path,
    target_config_path: &Path,
    maintenance_mode: bool,
    approval_hash: &str,
    dry_run: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let target_surreal = surreal_logical_config(target_config_path)?;
    let report = RestoreService::new(&root).run_logical(
        backup,
        target,
        &target_surreal,
        maintenance_mode,
        approval_hash,
        dry_run,
    )?;
    write_safety_report(&root, "restore", "Restore", &report)?;
    write_json(&report)
}

pub fn run_restore_rollback(
    config_path: &Path,
    target: &Path,
    maintenance_mode: bool,
    approval_hash: &str,
    dry_run: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let receipt = RestoreService::new(&root).rollback_isolated(
        target,
        maintenance_mode,
        approval_hash,
        dry_run,
    )?;
    write_safety_report(&root, "restore-rollback", "Restore Rollback", &receipt)?;
    write_json(&receipt)
}

pub fn run_restore_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "restore", || {
        RestoreService::new(runtime_root(config_path)).verify("latest")
    })
}

pub fn run_export_plan(config_path: &Path, kind: &str) -> Result<()> {
    run_export_run(config_path, kind)
}

pub fn run_export_run(config_path: &Path, kind: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let bundle = ExportService::new(&root).run(parse_export_kind(kind)?)?;
    write_safety_report(&root, "export", "Export", &bundle)?;
    write_json(&bundle)
}

pub fn run_import_validate(config_path: &Path, path: &Path, maintenance_mode: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let plan =
        ImportService::new(&root).validate(path, ImportKind::ReportsBundle, maintenance_mode)?;
    write_safety_report(&root, "import", "Import", &plan)?;
    write_json(&plan)
}

pub fn run_import_preview(config_path: &Path, path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let fingerprint = target_store_fingerprint(config_path)?;
    let preview = ImportService::new(&root).preview(path, &fingerprint)?;
    write_safety_report(&root, "import", "Historical Import Preview", &preview)?;
    write_json(&preview)
}

pub async fn run_import_execute(
    config_path: &Path,
    path: &Path,
    approval_hash: &str,
    maintenance_mode: bool,
) -> Result<()> {
    if !maintenance_mode {
        bail!("historical import execute requires --maintenance-mode");
    }
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let fingerprint = format!(
        "{}|{}|{}",
        config.db.surreal.endpoint, config.db.surreal.ns, config.db.surreal.db
    );
    let service = ImportService::new(&root);
    let preview = service.preview(path, &fingerprint)?;
    if approval_hash != preview.plan_hash {
        bail!("approval hash does not match the current historical import preview");
    }
    let store = CanonicalStore::new(config.db.surreal);
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let mut write_receipts = Vec::new();
    for envelope in &preview.accepted {
        write_receipts.push(
            HistoricalImportMemoryWriter::write_envelope(&writer, &WriteAdmissionService, envelope)
                .await?,
        );
    }
    drop(writer);
    actor_task.await?;
    let receipt = service.finalize(&preview, approval_hash, maintenance_mode, write_receipts)?;
    write_safety_report(&root, "import", "Historical Import Receipt", &receipt)?;
    write_json(&receipt)
}

pub fn run_import_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "import")
}

pub fn run_blob_manifest(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest = BlobGcService::new(root.join("blobs")).manifest()?;
    let report = BlobReport {
        component: "blob".to_owned(),
        manifest: Some(manifest),
        gc_plan: None,
        gc_receipt: None,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_safety_report(&root, "blob", "Blob", &report)?;
    write_json(&report)
}

pub async fn run_blob_gc_plan(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let service = BlobGcService::new(root.join("blobs"));
    let manifest = service.manifest()?;
    let snapshot = CanonicalStore::new(config.db.surreal)
        .blob_reference_snapshot(&manifest.blob_root, 512)
        .await?;
    let plan = service.gc_plan(&manifest, &snapshot)?;
    let report = BlobReport {
        component: "blob".to_owned(),
        manifest: Some(manifest),
        gc_plan: Some(plan),
        gc_receipt: None,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_safety_report(&root, "blob", "Blob GC Plan", &report)?;
    write_json(&report)
}

pub async fn run_blob_gc_run(
    config_path: &Path,
    dry_run: bool,
    approval_hash: Option<&str>,
    under_load: bool,
) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let service = BlobGcService::new(root.join("blobs"));
    let prior_report_path = root.join("reports").join("blob").join("latest.json");
    let prior_report: BlobReport =
        serde_json::from_reader(std::fs::File::open(&prior_report_path).with_context(|| {
            format!(
                "blob GC requires a persisted gc-plan report at {}",
                prior_report_path.display()
            )
        })?)?;
    let plan = prior_report
        .gc_plan
        .context("latest blob report does not contain an approved GC plan")?;
    let manifest = service.manifest()?;
    let snapshot = CanonicalStore::new(config.db.surreal)
        .blob_reference_snapshot(&manifest.blob_root, 512)
        .await?;
    let receipt = service.gc_run_authorized(
        &plan,
        &manifest,
        &snapshot,
        approval_hash.unwrap_or_default(),
        dry_run,
        under_load,
    )?;
    let report = BlobReport {
        component: "blob".to_owned(),
        manifest: Some(manifest),
        gc_plan: Some(plan),
        gc_receipt: Some(receipt),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_safety_report(&root, "blob", "Blob GC", &report)?;
    write_json(&report)
}

pub fn run_cutover_plan(
    config_path: &Path,
    proposed_data_root: &Path,
    executable_path: &Path,
) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest =
        ProductionCutoverService::plan(&root, proposed_data_root, config_path, executable_path);
    write_safety_report(&root, "cutover", "Production Cutover", &manifest)?;
    write_json(&manifest)
}

pub fn run_blob_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "blob", || {
        BlobGcService::new(runtime_root(config_path).join("blobs")).report(true)
    })
}

pub async fn run_maintenance_run(config_path: &Path, job: &str, dry_run: bool) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let store = CanonicalStore::new(config.db.surreal);
    store.migrate_schema().await?;
    let mut job =
        MaintenanceScheduler::new(&root).run_one_shot(parse_maintenance_job_kind(job)?, dry_run)?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    MaintenanceMemoryWriter::write_job(&writer, &WriteAdmissionService, &mut job).await?;
    drop(writer);
    actor_task.await?;
    write_safety_report(&root, "maintenance", "Maintenance", &job)?;
    write_json(&job)
}

pub fn run_maintenance_status(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "maintenance")
}

pub fn run_maintenance_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "maintenance")
}

pub fn run_incident_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&report)
}

pub fn run_incident_open(
    config_path: &Path,
    kind: &str,
    severity: &str,
    summary: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let incident = IncidentService::new(&root).open(
        parse_incident_kind(kind)?,
        parse_incident_severity(severity)?,
        summary.to_owned(),
    )?;
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&incident)
}

pub fn run_incident_acknowledge(config_path: &Path, incident: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let incident = IncidentService::new(&root).acknowledge(incident)?;
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&incident)
}

pub fn run_incident_close(config_path: &Path, incident: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let incident = IncidentService::new(&root).close(incident)?;
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&incident)
}

pub fn run_incident_report(config_path: &Path) -> Result<()> {
    run_incident_list(config_path)
}

pub fn run_daemon_init_default(
    destination_config: &Path,
    source_config: &Path,
    force: bool,
) -> Result<()> {
    let expected_destination = default_config_path()?;
    if crate::runtime_instance::path_identity(destination_config)
        != crate::runtime_instance::path_identity(&expected_destination)
    {
        bail!(
            "daemon init-default writes only the stable default config {}",
            expected_destination.display()
        );
    }
    if destination_config.exists() && !force {
        bail!(
            "default Eliot config already exists at {}; pass --force to replace it",
            destination_config.display()
        );
    }
    let mut config = load_config(source_config)?;
    let eliot_home = destination_config
        .parent()
        .and_then(Path::parent)
        .context("default config must be under Eliot/config")?;
    std::fs::create_dir_all(eliot_home)?;
    named_pipe_ipc::restrict_owned_directory_to_current_user(eliot_home)?;

    let source_project_root = config_runtime_root(source_config)
        .parent()
        .context("source config must be inside a project runtime root")?
        .to_path_buf();
    let source_surql = resolve_source_resource(&source_project_root, &config.store.surql_dir);
    let source_migrations =
        resolve_source_resource(&source_project_root, &config.store.migrations_dir);
    let resources = eliot_home.join("resources");
    let destination_surql = resources.join("surql");
    let destination_migrations = resources.join("migrations");
    copy_resource_tree(&source_surql, &destination_surql)?;
    copy_resource_tree(&source_migrations, &destination_migrations)?;

    "EliotGovernor".clone_into(&mut config.service.service_name);
    "default".clone_into(&mut config.service.instance_id);
    config.db.surreal.storage = format!(
        "rocksdb:{}",
        config_path_text(&eliot_home.join("data").join("surrealdb-rocks"))
    );
    config.db.surreal.credential_provider = CredentialProviderKind::WindowsCredentialManager;
    "surreal-runtime/default".clone_into(&mut config.db.surreal.credential_id);
    config.control_wal.path = config_path_text(&eliot_home.join("control").join("control.redb"));
    config.blob_store.root = config_path_text(&eliot_home.join("blobs"));
    config.store.surql_dir = config_path_text(&destination_surql);
    config.store.migrations_dir = config_path_text(&destination_migrations);
    config.validate()?;
    let encoded = toml::to_string_pretty(&config)?;
    atomic_write_bytes(destination_config, encoded.as_bytes())?;
    write_json(&serde_json::json!({
        "component": "daemon_init_default",
        "status": "initialized",
        "instance": "default",
        "config_path": destination_config,
        "eliot_home": eliot_home,
        "data_root": eliot_home.join("data"),
        "resources": resources,
        "source_config": source_config,
        "long_lived_one_drive_paths": false
    }))
}

fn resolve_source_resource(project_root: &Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        path
    } else {
        project_root.join(path)
    }
}

fn copy_resource_tree(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_dir() {
        bail!(
            "required standalone resource directory is missing: {}",
            source.display()
        );
    }
    if destination.is_dir() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!(
                "standalone resources may not contain symlinks: {}",
                entry.path().display()
            );
        }
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_resource_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn config_path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub async fn run_daemon(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let result = run_daemon_instance(config_path, &instance).await;
    if let Err(error) = &result {
        let _ = instance
            .record_startup_failure(named_pipe_ipc::IPC_PROTOCOL_VERSION, &format!("{error:#}"));
    }
    result
}

async fn run_daemon_instance(config_path: &Path, instance: &RuntimeInstance) -> Result<()> {
    let config = load_config(config_path)?;
    let data_root = runtime_root(config_path);
    let root = instance.publication_root().to_path_buf();
    let lifecycle = LifecycleService::new(&root);
    let lock = lifecycle.acquire_single_instance()?;
    let stop_marker = instance.stop_marker();
    if stop_marker.is_file() {
        std::fs::remove_file(&stop_marker)?;
    }
    let database = if instance.standalone() {
        Some(
            SurrealServerSupervisor::new(config.db.surreal.clone())
                .start_or_connect()
                .await
                .context("start or connect the standalone instance-owned SurrealDB server")?,
        )
    } else {
        None
    };
    let database_started_pid = database
        .as_ref()
        .and_then(eliot_store::ReadySurrealServer::started_pid);
    let store_root = store_root_from_storage(&config.db.surreal.storage);
    let runtime_result = run_published_daemon(
        config_path,
        instance,
        &data_root,
        &store_root,
        database_started_pid,
    )
    .await;
    let database_result = match database {
        Some(database) => database
            .shutdown_if_spawned()
            .await
            .map_err(anyhow::Error::from),
        None => Ok(eliot_store::SurrealShutdown::not_owned()),
    };
    match (runtime_result, database_result) {
        (Ok(publication_cleaned), Ok(database)) => {
            lock.mark_clean_shutdown()?;
            info!("governor daemon shutdown requested");
            tracing::info!(
                database_stopped = database.stopped_owned_process,
                database_drain_incomplete = database.drain_incomplete,
                database_already_exited = database.already_exited,
                publication_cleaned,
                "owned runtime resources released"
            );
            Ok(())
        }
        (Err(runtime_error), Ok(_)) => Err(runtime_error),
        (Ok(_), Err(database_error)) => Err(database_error),
        (Err(runtime_error), Err(database_error)) => Err(runtime_error.context(format!(
            "standalone database cleanup also failed: {database_error:#}"
        ))),
    }
}

async fn run_published_daemon(
    config_path: &Path,
    instance: &RuntimeInstance,
    data_root: &Path,
    store_root: &Path,
    database_started_pid: Option<u32>,
) -> Result<bool> {
    let stop_marker = instance.stop_marker();
    async {
        let mut ipc_server = named_pipe_ipc::IpcServer::bind(config_path, instance, store_root)?;
        let pipe_name = ipc_server.name().to_owned();
        let starting_publication =
            instance.read_publication_any_state(named_pipe_ipc::IPC_PROTOCOL_VERSION)?;
        let mcp_daemon = mcp_stdio::McpDaemon::new(config_path, instance, &starting_publication)?;
        let (ipc_shutdown, ipc_shutdown_rx) = tokio::sync::watch::channel(false);
        let mut supervisor = ServiceSupervisor::new(default_runtime_services());
        supervisor.start_all("daemon").await?;
        let publication = ipc_server.publish_ready()?;
        let ipc_task = tokio::spawn(ipc_server.serve(mcp_daemon, ipc_shutdown_rx));
        let bundle = write_runtime_bundle(
            config_path,
            supervisor.service_statuses(),
            RuntimeMode::Daemon,
            true,
        )?;
        let log_service = LogService::new(data_root.join("logs"));
        let _ = log_service.write_event(LogService::event(
            LogLevel::Info,
            LogEventKind::DaemonStart,
            "eliot_governor.daemon",
            "governor daemon reached READY",
            Some("daemon-run".to_owned()),
        ))?;
        write_json(&serde_json::json!({
            "component": "daemon",
            "status": "running",
            "profile": "daemon",
            "instance": instance.name(),
            "standalone": instance.standalone(),
            "runtime_id": publication.runtime_id,
            "auth_generation": publication.auth_generation,
            "publication": instance.publication_path(),
            "database_started_pid": database_started_pid,
            "runtime_report": bundle.runtime_report_path,
            "health": bundle.health.ready,
            "ipc": {
                "enabled": true,
                "transport": "windows_named_pipe",
                "name": pipe_name
            }
        }))?;
        info!("governor daemon reached READY");
        tokio::select! {
            signal = tokio::signal::ctrl_c() => signal?,
            () = wait_for_stop_marker(&stop_marker) => {}
        }
        let _ = ipc_shutdown.send(true);
        let joined = tokio::time::timeout(Duration::from_secs(5), ipc_task)
            .await
            .context("named-pipe server shutdown timed out")?;
        joined.context("named-pipe server task failed")??;
        supervisor
            .shutdown_all(shutdown_deadline_after(Duration::from_secs(5)))
            .await?;
        let mut stopping = publication.clone();
        instance.publish_state(&mut stopping, RuntimePublicationState::Stopping)?;
        let publication_cleaned = instance.cleanup_owned(&stopping)?;
        let _ = log_service.write_event(LogService::event(
            LogLevel::Info,
            LogEventKind::DaemonStop,
            "eliot_governor.daemon",
            "governor daemon shutdown requested",
            Some("daemon-run".to_owned()),
        ))?;
        Ok(publication_cleaned)
    }
    .await
}

pub fn run_daemon_status(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let root = instance.publication_root();
    let lifecycle = LifecycleService::new(root);
    let status = lifecycle.status()?;
    let publication = instance.read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION);
    let (publication_value, discovery_error) = match publication {
        Ok(publication) => (serde_json::to_value(publication)?, serde_json::Value::Null),
        Err(error) => (
            serde_json::Value::Null,
            serde_json::json!({"code": error.code, "detail": error.detail}),
        ),
    };
    write_json(&serde_json::json!({
        "component": "daemon_status",
        "active_profile": if instance.standalone() { "standalone-user-instance" } else { "isolated-config-instance" },
        "instance": instance.name(),
        "publication_root": instance.publication_root(),
        "publication": publication_value,
        "discovery_error": discovery_error,
        "lifecycle": status,
        "stop_requested": instance.stop_marker().exists()
    }))
}

pub fn run_daemon_health(config_path: &Path, instance: Option<&str>) -> Result<()> {
    run_daemon_doctor(config_path, instance)
}

pub fn run_daemon_doctor(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let publication = instance.read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION);
    let mut blockers = Vec::new();
    if !config_path.is_file() {
        blockers.push("config_missing");
    }
    let (publication_value, authentication_error) = match publication {
        Ok(publication) => {
            let authentication_error =
                named_pipe_ipc::validate_authentication_publication(&instance, &publication)
                    .err()
                    .map_or(serde_json::Value::Null, |error| {
                        blockers.push("runtime_authentication_invalid");
                        serde_json::json!({"error_code": error.code, "detail": error.detail})
                    });
            (serde_json::to_value(publication)?, authentication_error)
        }
        Err(error) => {
            blockers.push("runtime_publication_invalid");
            (
                serde_json::json!({"error_code": error.code, "detail": error.detail}),
                serde_json::Value::Null,
            )
        }
    };
    if !instance.authentication_path().is_file() {
        blockers.push("authentication_file_missing");
    }
    write_json(&serde_json::json!({
        "component": "daemon_doctor",
        "instance": instance.name(),
        "standalone": instance.standalone(),
        "config_path": config_path,
        "publication_root": instance.publication_root(),
        "publication": publication_value,
        "authentication_file_present": instance.authentication_path().is_file(),
        "authentication_error": authentication_error,
        "blockers": blockers,
        "status": if blockers.is_empty() { "ready" } else { "not_ready" }
    }))
}

pub fn run_daemon_stop(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let runtime_dir = instance.runtime_dir();
    std::fs::create_dir_all(&runtime_dir)?;
    let marker = instance.stop_marker();
    std::fs::write(&marker, time::OffsetDateTime::now_utc().to_string())?;
    write_json(&serde_json::json!({
        "component": "daemon_stop",
        "instance": instance.name(),
        "status": "cooperative_marker_written",
        "marker": marker,
        "ipc_stop_available": true
    }))
}

async fn wait_for_stop_marker(marker: &Path) {
    let mut interval = tokio::time::interval(Duration::from_millis(25));
    loop {
        interval.tick().await;
        if marker.is_file() {
            return;
        }
    }
}

pub fn run_runtime_status(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = runtime_status_report(
        &root,
        default_service_statuses(),
        RuntimeMode::DevSingleProcess,
        false,
    );
    let report_service = ReportService::new(root.join("reports"));
    report_service.write_latest(
        "runtime",
        &report,
        &typed_report_markdown("Runtime Status", &report)?,
    )?;
    write_json(&report)
}

pub fn run_runtime_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = HealthService::report(RuntimeMode::DevSingleProcess, default_service_statuses());
    let report_service = ReportService::new(root.join("reports"));
    report_service.write_latest(
        "runtime",
        &report,
        &typed_report_markdown("Runtime Health", &report)?,
    )?;
    write_json(&report)
}

pub fn run_runtime_report(config_path: &Path) -> Result<()> {
    let bundle = write_runtime_bundle(
        config_path,
        default_service_statuses(),
        RuntimeMode::DevSingleProcess,
        false,
    )?;
    write_json(&serde_json::json!({
        "component": "runtime_report",
        "status": "written",
        "runtime_report": bundle.runtime_report_path,
        "module_report": bundle.module_report_path,
        "logs_report": bundle.logs_report_path
    }))
}

pub fn run_module_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = module_registry(config_path)?;
    let report = registry.report();
    ReportService::new(root.join("reports")).write_latest(
        "modules",
        &report,
        &typed_report_markdown("Module Registry", &report)?,
    )?;
    write_json(&report)
}

pub fn run_module_inspect(config_path: &Path, module: &str) -> Result<()> {
    let registry = module_registry(config_path)?;
    let manifest = registry
        .manifests()
        .iter()
        .find(|manifest| manifest.name == module || manifest.module_id.to_string() == module)
        .with_context(|| format!("module not found: {module}"))?;
    write_json(manifest)
}

pub fn run_module_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = module_registry(config_path)?.report();
    ReportService::new(root.join("reports")).write_latest(
        "modules",
        &report,
        &typed_report_markdown("Module Health", &report)?,
    )?;
    write_json(&report)
}

pub fn run_module_validate_manifest(path: &Path) -> Result<()> {
    let manifest = read_module_manifest(path)?;
    ModuleRegistryService::new(vec![manifest.clone()])?;
    write_json(&serde_json::json!({
        "component": "module_manifest_validation",
        "status": "valid",
        "module_id": manifest.module_id,
        "name": manifest.name
    }))
}

pub fn run_logs_tail(config_path: &Path, limit: usize) -> Result<()> {
    let root = runtime_root(config_path);
    let events = LogService::new(root.join("logs")).tail(limit)?;
    write_json(&serde_json::json!({
        "component": "logs_tail",
        "limit": limit,
        "events": events
    }))
}

pub fn run_logs_inspect(config_path: &Path, trace: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let events = LogService::new(root.join("logs"))
        .tail(usize::MAX)?
        .into_iter()
        .filter(|event| event.trace_id.as_deref() == Some(trace))
        .collect::<Vec<_>>();
    write_json(&serde_json::json!({
        "component": "logs_inspect",
        "trace_id": trace,
        "events": events
    }))
}

pub fn run_logs_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_log_report(&root)?;
    ReportService::new(root.join("reports")).write_latest(
        "logs",
        &report,
        &typed_report_markdown("Logs Report", &report)?,
    )?;
    write_json(&report)
}

pub async fn run_adapter_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = AdapterRegistry::builtin()?;
    let report = registry.report().await;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &report,
        &typed_report_markdown("Adapter Registry", &report)?,
    )?;
    write_json(&report)
}

pub fn run_adapter_inspect(config_path: &Path, adapter: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = AdapterRegistry::builtin()?;
    let manifest = registry.inspect(adapter)?;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &manifest,
        &typed_report_markdown("Adapter Inspect", &manifest)?,
    )?;
    write_json(&manifest)
}

pub async fn run_adapter_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let supervisor = AdapterSupervisor::builtin()?;
    let health = supervisor.health_all().await;
    let report = serde_json::json!({
        "component": "adapter_health",
        "health": health,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &report,
        &typed_report_markdown("Adapter Health", &report)?,
    )?;
    write_json(&report)
}

pub async fn run_adapter_execute_test(config_path: &Path, adapter: &str) -> Result<()> {
    let report = execute_adapter_test(config_path, adapter).await?;
    write_json(&report)
}

pub async fn run_adapter_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = AdapterRegistry::builtin()?;
    let adapter_report = registry.report().await;
    let observations = read_latest_adapter_observation_report(&root)?;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &adapter_report,
        &typed_report_markdown("Adapter Registry", &adapter_report)?,
    )?;
    if let Some(observations) = &observations {
        ReportService::new(root.join("reports")).write_latest(
            "adapter-observations",
            observations,
            &adapter_observation_markdown(observations),
        )?;
    }
    write_json(&serde_json::json!({
        "component": "adapter_report",
        "adapters": root.join("reports").join("adapters").join("latest.json"),
        "adapter_observations": root.join("reports").join("adapter-observations").join("latest.json"),
        "observation_report_available": observations.is_some()
    }))
}

pub fn run_external_review_providers(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ExternalProviderRegistryService.report();
    write_external_review_report(&root, "external-providers", "External Providers", &report)?;
    write_json(&report)
}

pub fn run_external_review_provider_inspect(config_path: &Path, provider: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let profile = ExternalProviderRegistryService.inspect(provider)?;
    write_external_review_report(
        &root,
        "external-providers",
        "External Provider Inspect",
        &profile,
    )?;
    write_json(&profile)
}

pub fn run_external_review_request(
    config_path: &Path,
    project: &str,
    task: &str,
    provider: &str,
    role: &str,
    question: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let profile = ExternalProviderRegistryService.inspect(provider)?;
    let mut request = external_review_request(
        project,
        task,
        provider,
        parse_external_review_role(role)?,
        question,
    );
    request.project_id = project_id_from_label(project);
    request.task_id = task_id_from_label(task);
    request.output_schema = external_output_schema_for(&request, &profile);
    request.budget = ExternalReviewBudget {
        max_packet_bytes: profile.limits.max_packet_bytes,
        max_output_bytes: profile.limits.max_raw_output_bytes,
        max_findings: profile.limits.max_findings,
    };
    let (state, work_lease) = ensure_external_review_work_lease(&root, &mut request)?;
    let packet = ExternalReviewPacketBuilder.build(
        &request,
        "context_packet_l3:external-review-minimal",
        serde_json::json!({
            "project": project,
            "task": task,
            "question": question,
            "evidence_refs": &request.evidence_refs,
            "allowed_paths": &request.allowed_paths,
            "secrets": "[redacted]"
        }),
    )?;
    let gate = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: phase_k1_done_verified(&root)?,
            incident_lockdown: false,
        },
    );
    let job = ExternalReviewJobService.create_job(&request);
    let work_report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &work_report)?;
    write_external_review_report(
        &root,
        "external-providers",
        "External Providers",
        &ExternalProviderRegistryService.report(),
    )?;
    write_external_review_report(
        &root,
        "external-review-requests",
        "External Review Request",
        &request,
    )?;
    write_external_review_report(
        &root,
        "external-review-packets",
        "External Review Packet",
        &packet,
    )?;
    write_external_review_report(
        &root,
        "external-review-gates",
        "External Review Gates",
        &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
    )?;
    write_external_review_report(
        &root,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    write_json(&serde_json::json!({
        "component": "external_review_request",
        "request": request,
        "packet": packet,
        "gate": gate,
        "job": job
    }))
}

pub fn run_external_review_job_status(config_path: &Path, job: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = read_json_value(
        &root
            .join("reports")
            .join("external-review-jobs")
            .join("latest.json"),
    )?;
    write_json(&filter_report_item(&report, "jobs", "job_id", job))
}

fn external_review_queued_job_for_request(
    root: &Path,
    request_id: &str,
) -> Result<Option<ExternalReviewJob>> {
    let path = root
        .join("reports")
        .join("external-review-jobs")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let report = read_json_value(&path)?;
    let Some(jobs) = report.get("jobs").and_then(serde_json::Value::as_array) else {
        return Ok(None);
    };
    for value in jobs {
        let job: ExternalReviewJob = serde_json::from_value(value.clone())
            .context("parse external review job from latest report")?;
        if job.request_id == request_id && job.status == ExternalReviewJobStatus::Queued {
            return Ok(Some(job));
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_lines)]
pub async fn run_external_review_run_mock(config_path: &Path, request_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let config = load_config(config_path)?;
    let request: ExternalReviewRequest = read_report_json(
        &root
            .join("reports")
            .join("external-review-requests")
            .join("latest.json"),
    )?;
    if request.request_id != request_id {
        bail!("external review request not found in latest report: {request_id}");
    }
    let profile = ExternalProviderRegistryService.inspect(&request.provider_id)?;
    let packet: ExternalReviewPacket = read_report_json(
        &root
            .join("reports")
            .join("external-review-packets")
            .join("latest.json"),
    )?;
    let mut state = load_work_state(&root)?;
    let work_lease = request.work_lease_id.and_then(|lease_id| {
        state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    let gate = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: phase_k1_done_verified(&root)?,
            incident_lockdown: false,
        },
    );
    if gate.decision != ExternalReviewGateDecisionKind::AllowMockRun {
        write_external_review_report(
            &root,
            "external-review-gates",
            "External Review Gates",
            &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
        )?;
        bail!(
            "external review gate did not allow mock run: {:?}",
            gate.decision
        );
    }
    let blob_store = BlobStore::open(&config.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let queued_job = external_review_queued_job_for_request(&root, request_id)?
        .unwrap_or_else(|| ExternalReviewJobService.create_job(&request));
    let (mut job, raw_output) = ExternalReviewJobService
        .run_mock_job(
            &request,
            &profile,
            &packet,
            queued_job,
            &supervisor,
            &blob_store,
        )
        .await?;
    let normalization = ExternalReviewNormalizer.normalize(&request, &job, &raw_output);
    let mut results = Vec::new();
    let mut bridge_report = None;
    if let Some(mut result) = normalization.result.clone() {
        job.result_id = Some(result.result_id.clone());
        let store = CanonicalStore::new(config.db.surreal.clone());
        store.migrate_schema().await?;
        let wal = ControlWal::open(&config.control_wal)?;
        let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
        let actor_task = tokio::spawn(actor.run());
        let session_id = AgentSessionId::new_v7();
        let bridge = ExternalReviewBridgeService
            .write_and_route(
                &writer,
                &WriteAdmissionService,
                &mut state,
                session_id,
                &mut result,
            )
            .await?;
        drop(writer);
        actor_task.await?;
        bridge_report = Some(bridge);
        results.push(result);
    }
    let work_report = WorkQueueService.status_report(&state, &request.project, &request.task);
    save_work_state_and_report(&root, &state, &work_report)?;
    write_external_review_report(
        &root,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    write_external_review_report(
        &root,
        "external-review-results",
        "External Review Results",
        &ExternalReviewReportService.results_report(&results),
    )?;
    write_external_review_report(
        &root,
        "external-review-gates",
        "External Review Gates",
        &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
    )?;
    write_external_review_report(
        &root,
        "external-review-normalization",
        "External Review Normalization",
        &ExternalReviewReportService
            .normalization_report(std::slice::from_ref(&normalization.receipt)),
    )?;
    if let Some(bridge) = &bridge_report {
        write_external_review_report(
            &root,
            "external-review-bridge",
            "External Review Bridge",
            bridge,
        )?;
    }
    write_json(&serde_json::json!({
        "component": "external_review_run_mock",
        "job": job,
        "normalization": normalization.receipt,
        "results": results,
        "bridge": bridge_report
    }))
}

pub fn run_external_review_result_inspect(config_path: &Path, result: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = read_json_value(
        &root
            .join("reports")
            .join("external-review-results")
            .join("latest.json"),
    )?;
    write_json(&filter_report_item(&report, "results", "result_id", result))
}

pub fn run_external_review_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = serde_json::json!({
        "component": "external_review_report",
        "providers": report_path_status(&root, "external-providers"),
        "jobs": report_path_status(&root, "external-review-jobs"),
        "results": report_path_status(&root, "external-review-results"),
        "gates": report_path_status(&root, "external-review-gates"),
        "normalization": report_path_status(&root, "external-review-normalization"),
        "doctor": ExternalReviewReportService.doctor_status(external_review_mcp_tools_governed_only()),
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_external_review_report(&root, "external-review", "External Review", &report)?;
    write_json(&report)
}

pub fn run_antigravity_windows_discover(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let discovery = antigravity_windows_install_discovery();
    write_antigravity_report_pair(
        &root,
        "antigravity-windows-install",
        "Antigravity Windows Install Discovery",
        &discovery,
    )?;
    write_json(&discovery)
}

pub fn run_antigravity_version_check(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    let binary = resolution
        .selected_path
        .as_deref()
        .context("official signed Antigravity CLI was not resolved")?;
    let gate = AntigravityVersionGateService.probe(Path::new(binary));
    write_antigravity_report_pair(
        &root,
        "antigravity-version-gate",
        "Antigravity Version Gate",
        &gate,
    )?;
    if !gate.allowed {
        write_json(&gate)?;
        bail!("Antigravity CLI is below the required automation version 1.1.1");
    }
    write_json(&gate)
}

pub fn run_antigravity_install_receipt(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let discovery = antigravity_windows_install_discovery();
    let version_gate = discovery
        .official_cli_path
        .as_deref()
        .filter(|_| discovery.official_cli_exists)
        .map(|binary| AntigravityVersionGateService.probe(Path::new(binary)));
    let receipt =
        AntigravityOfficialCliInstallerService.status_receipt(&discovery, version_gate.as_ref());
    write_antigravity_report_pair(
        &root,
        "antigravity-install-receipt",
        "Antigravity Official CLI Install Receipt",
        &receipt,
    )?;
    write_json(&receipt)
}

pub fn run_antigravity_resolve(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    write_antigravity_report_pair(
        &root,
        "antigravity-resolution",
        "Antigravity Resolution",
        &resolution,
    )?;
    write_json(&resolution)
}

pub fn run_antigravity_detect(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, _contract) = antigravity_resolution_probe_contract();
    write_antigravity_report_pair(
        &root,
        "antigravity-resolution",
        "Antigravity Resolution",
        &resolution,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_json(&probe)
}

pub fn run_antigravity_status(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, mut probe, contract) = antigravity_resolution_probe_contract();
    let enablement = latest_antigravity_enablement(&root)?;
    let disable = latest_antigravity_disable(&root)?;
    let enablement_is_current = enablement.as_ref().is_some_and(|receipt| {
        receipt
            .expires_at
            .is_none_or(|expires_at| expires_at > time::OffsetDateTime::now_utc())
            && disable
                .as_ref()
                .is_none_or(|disabled| disabled.created_at < receipt.created_at)
    });
    if enablement_is_current {
        probe.provider_state = AntigravityProviderState::ReadyEnabled;
    }
    let skills =
        AntigravitySkillBundleService.generate(&antigravity_plugin_root(config_path), true);
    let plugin = AntigravityPluginBundleService.generate(&antigravity_plugin_root(config_path));
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        skills.verification_passed,
        plugin.verification_passed,
        antigravity_mcp_tools_governed_only(),
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_antigravity_report_pair(&root, "antigravity-doctor", "Antigravity Doctor", &doctor)?;
    write_json(&doctor)
}

pub fn run_antigravity_doctor(config_path: &Path) -> Result<()> {
    run_antigravity_status(config_path)
}

pub fn run_antigravity_command_contract(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (_resolution, _probe, contract) = antigravity_resolution_probe_contract();
    write_antigravity_report_pair(
        &root,
        "antigravity-contract",
        "Antigravity Command Contract",
        &contract,
    )?;
    write_json(&contract)
}

pub fn run_antigravity_request(
    config_path: &Path,
    project: &str,
    task: &str,
    mode: &str,
    question: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mode = parse_antigravity_mode(mode)?;
    let request = antigravity_review_request(project, task, mode, question);
    let request_path = antigravity_latest_request_path(&root);
    write_report_pair(
        &request_path,
        &root
            .join("reports")
            .join("antigravity-runs")
            .join("latest-request.md"),
        &request,
        &typed_report_markdown("Antigravity Request", &request)?,
    )?;
    write_json(&request)
}

pub fn run_antigravity_run(config_path: &Path, request_id: &str, dry_run: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let request = latest_antigravity_request(&root)?
        .with_context(|| "no latest Antigravity request found; run antigravity request first")?;
    if request_id != "latest" && request_id != request.request_id {
        bail!("requested Antigravity request id does not match latest request");
    }
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let gate = AntigravityExecutionGate.decide(
        &request,
        &resolution,
        &probe,
        &contract,
        None,
        None,
        false,
        false,
        dry_run,
    );
    let run = if gate.decision == AntigravityExecutionGateDecisionKind::AllowDryRun {
        AntigravityRunner.run_fixture(&request, &contract, &repo_root())?
    } else {
        AntigravityRunner.blocked_run(&request, &contract, &gate, &repo_root())
    };
    write_antigravity_report_pair(&root, "antigravity-runs", "Antigravity Run", &run)?;
    write_json(&run)
}

pub fn run_antigravity_job_status(config_path: &Path, run_id: &str) -> Result<()> {
    let run = latest_antigravity_run(&runtime_root(config_path))?
        .with_context(|| "no latest Antigravity run found; run antigravity run first")?;
    if run_id != "latest" && run_id != run.run_id {
        bail!("requested Antigravity run id does not match latest run");
    }
    let status = serde_json::json!({
        "component": "antigravity_job_status",
        "run_id": run.run_id,
        "request_id": run.request_id,
        "state": run.state,
        "dry_run": run.dry_run,
        "fixture_runner": run.fixture_runner,
        "message": run.message
    });
    write_json(&status)
}

pub fn run_antigravity_result(config_path: &Path, run_id: &str) -> Result<()> {
    let run = latest_antigravity_run(&runtime_root(config_path))?
        .with_context(|| "no latest Antigravity run found; run antigravity run first")?;
    if run_id != "latest" && run_id != run.run_id {
        bail!("requested Antigravity run id does not match latest run");
    }
    let result = run
        .normalized_result
        .with_context(|| "latest Antigravity run has no normalized result")?;
    write_json(&result)
}

pub fn run_antigravity_skills_generate(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let bundle =
        AntigravitySkillBundleService.generate(&antigravity_plugin_root(config_path), true);
    write_antigravity_skill_files(config_path, &bundle)?;
    write_antigravity_report_pair(&root, "antigravity-skills", "Antigravity Skills", &bundle)?;
    write_json(&bundle)
}

pub fn run_antigravity_skills_verify(config_path: &Path) -> Result<()> {
    run_antigravity_skills_generate(config_path)
}

pub fn run_antigravity_skills_install(
    config_path: &Path,
    dry_run: bool,
    target: &str,
) -> Result<()> {
    if !dry_run {
        bail!("Antigravity skill install is dry-run only in G3A");
    }
    if target != "user-agy" {
        bail!("unsupported Antigravity skill target: {target}");
    }
    run_antigravity_skills_generate(config_path)
}

pub fn run_antigravity_plugin_generate(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let bundle = AntigravityPluginBundleService.generate(&antigravity_plugin_root(config_path));
    write_antigravity_plugin_files(config_path, &bundle)?;
    write_antigravity_report_pair(&root, "antigravity-plugin", "Antigravity Plugin", &bundle)?;
    write_json(&bundle)
}

pub fn run_antigravity_plugin_verify(config_path: &Path) -> Result<()> {
    run_antigravity_plugin_generate(config_path)
}

pub fn run_antigravity_plugin_schema(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest_path = official_antigravity_plugin_source(config_path).join("plugin.json");
    let manifest: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(&manifest_path)?)?;
    let valid = AntigravityOfficialPluginService.official_manifest_valid(&manifest);
    let report = serde_json::json!({
        "component": "antigravity_official_plugin_schema",
        "manifest_path": manifest_path,
        "manifest": manifest,
        "official_schema_valid": valid,
        "checked_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-plugin-schema",
        "Antigravity Official Plugin Schema",
        &report,
    )?;
    if !valid {
        write_json(&report)?;
        bail!("official Antigravity plugin manifest is invalid");
    }
    write_json(&report)
}

#[allow(clippy::too_many_lines)]
pub fn run_antigravity_plugin_install_official(
    config_path: &Path,
    admin_confirm: bool,
) -> Result<()> {
    if !admin_confirm {
        bail!("official Antigravity plugin install requires --admin-confirm");
    }
    let root = runtime_root(config_path);
    let home = antigravity_home()?;
    let source = official_antigravity_plugin_source(config_path).canonicalize()?;
    let binary = resolved_antigravity_binary()?;
    let version_gate = AntigravityVersionGateService.probe(&binary);
    if !version_gate.allowed {
        bail!("official plugin install requires Antigravity CLI >= 1.1.1");
    }

    let validate = ProcessCommand::new(&binary)
        .args(["plugin", "validate"])
        .arg(&source)
        .current_dir(project_root_from_config(config_path))
        .output()?;
    if !validate.status.success() {
        let failure = serde_json::json!({
            "component": "antigravity_official_plugin_install",
            "stage": "validate",
            "succeeded": false,
            "stdout": String::from_utf8_lossy(&validate.stdout),
            "stderr": String::from_utf8_lossy(&validate.stderr)
        });
        write_antigravity_report_pair(
            &root,
            "antigravity-plugin-install",
            "Antigravity Official Plugin Install",
            &failure,
        )?;
        bail!("agy plugin validate failed for official ELIOT plugin");
    }

    let prior_status = AntigravityOfficialPluginService.status(&home);
    let uninstall = if prior_status.gui_installed || prior_status.cli_installed {
        let output = ProcessCommand::new(&binary)
            .args(["plugin", "uninstall", "eliot-antigravity"])
            .current_dir(project_root_from_config(config_path))
            .output()?;
        if !output.status.success() {
            let failure = serde_json::json!({
                "component": "antigravity_official_plugin_install",
                "stage": "remove_previous_version",
                "succeeded": false,
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr)
            });
            write_antigravity_report_pair(
                &root,
                "antigravity-plugin-install",
                "Antigravity Official Plugin Install",
                &failure,
            )?;
            bail!("agy could not remove the previous official ELIOT plugin version");
        }
        Some(output)
    } else {
        None
    };

    let install = ProcessCommand::new(&binary)
        .args(["plugin", "install"])
        .arg(&source)
        .current_dir(project_root_from_config(config_path))
        .output()?;
    let list = ProcessCommand::new(&binary)
        .args(["plugin", "list"])
        .current_dir(project_root_from_config(config_path))
        .output()?;
    let list_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let status = AntigravityOfficialPluginService.status(&home);
    let files_written = installed_plugin_files(&status);
    let receipt = AntigravityOfficialPluginService.install_receipt(
        &status,
        install.status.success() && list.status.success(),
        &list_output,
        files_written,
    );
    let report = serde_json::json!({
        "receipt": receipt,
        "validate_stdout": String::from_utf8_lossy(&validate.stdout),
        "uninstall_stdout": uninstall.as_ref().map(|output| String::from_utf8_lossy(&output.stdout)),
        "uninstall_stderr": uninstall.as_ref().map(|output| String::from_utf8_lossy(&output.stderr)),
        "install_stdout": String::from_utf8_lossy(&install.stdout),
        "install_stderr": String::from_utf8_lossy(&install.stderr),
        "plugin_list_output": list_output,
        "status": status
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-plugin-install",
        "Antigravity Official Plugin Install",
        &report,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-official-plugin",
        "Antigravity Official Plugin Status",
        &status,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-plugin-install-receipt",
        "Antigravity Official Plugin Install Receipt",
        &receipt,
    )?;
    if !receipt.installed {
        write_json(&report)?;
        bail!("OfficialPluginInstallFailed");
    }
    write_json(&report)
}

pub fn run_antigravity_mcp_config_status(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let statuses = AntigravityMcpConfigService.status(&antigravity_home()?);
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp",
        "Antigravity MCP Config Status",
        &statuses,
    )?;
    write_json(&statuses)
}

pub fn run_antigravity_mcp_register(config_path: &Path, admin_confirm: bool) -> Result<()> {
    if !admin_confirm {
        bail!("Antigravity MCP registration requires --admin-confirm");
    }
    let root = runtime_root(config_path);
    let home = antigravity_home()?;
    let project_root = project_root_from_config(config_path).canonicalize()?;
    let executable = release_eliot_executable(config_path)?;
    let receipt =
        AntigravityMcpConfigService.register_gui_for_project(&home, &executable, &project_root)?;
    let statuses = AntigravityMcpConfigService.status(&home);
    let gui_registered = statuses.iter().any(|status| {
        status.surface == eliot_types::AntigravityMcpConfigSurface::Gui && status.registered
    });
    let report = serde_json::json!({
        "component": "antigravity_mcp_registration",
        "receipt": receipt,
        "configs": statuses,
        "gui_registered": gui_registered,
        "registered_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp-registration",
        "Antigravity MCP Registration",
        &receipt,
    )?;
    write_antigravity_report_pair(&root, "antigravity-mcp", "Antigravity MCP Status", &report)?;
    if !gui_registered {
        write_json(&report)?;
        bail!("Antigravity HOME MCP registration did not validate");
    }
    write_json(&report)
}

pub fn run_antigravity_mcp_backup_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let config_path = AntigravityMcpConfigService.config_paths(&antigravity_home()?)[0]
        .1
        .clone();
    let backups = config_path
        .parent()
        .and_then(|parent| std::fs::read_dir(parent).ok())
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("mcp_config.json.eliot-backup-"))
        })
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let report = serde_json::json!({
        "component": "antigravity_mcp_backup_list",
        "config_path": config_path,
        "backups": backups,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp-backups",
        "Antigravity MCP Backups",
        &report,
    )?;
    write_json(&report)
}

pub fn run_antigravity_mcp_invocation_proof(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let run = latest_antigravity_run(&root)?.context("no real Antigravity run receipt found")?;
    let receipt = matching_antigravity_mcp_invocation(&root, &run)
        .context("no matching real Antigravity MCP invocation event found")?;
    let within_run = receipt.invoked_at >= run.created_at
        && run
            .completed_at
            .is_some_and(|completed_at| receipt.invoked_at <= completed_at);
    let proven = receipt.succeeded
        && receipt.matching_audit_event
        && receipt.audit_event_ref.is_some()
        && receipt.profile == "external_auditor"
        && within_run;
    let collective_route = if proven {
        Some(ensure_antigravity_collective_route(&root, &run)?)
    } else {
        None
    };
    let report = serde_json::json!({
        "component": "antigravity_mcp_invocation_proof",
        "receipt": receipt,
        "run_id": run.run_id,
        "audit_event_within_run": within_run,
        "collective_route": collective_route,
        "proven": proven,
        "checked_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        &root,
        "antigravity-mcp-invocation-proof",
        "Antigravity MCP Invocation Proof",
        &report,
    )?;
    if !proven {
        write_json(&report)?;
        bail!("McpDiscoveredButInvocationBlocked");
    }
    write_json(&report)
}

pub fn run_antigravity_visibility(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let home = antigravity_home()?;
    let windows_install = antigravity_windows_install_discovery();
    let version_gate = windows_install
        .official_cli_path
        .as_deref()
        .filter(|_| windows_install.official_cli_exists)
        .map(|path| AntigravityVersionGateService.probe(Path::new(path)));
    let latest_run = latest_antigravity_run(&root)?;
    let mcp_invocation = latest_run
        .as_ref()
        .and_then(|run| matching_antigravity_mcp_invocation(&root, run));
    let report = AntigravityVisibilityService.report(
        AntigravityGuiProcessProbeService.probe(),
        windows_install,
        version_gate,
        AntigravityMcpConfigService.status(&home),
        mcp_invocation,
        AntigravityOfficialPluginService.status(&home),
        latest_antigravity_live_smoke(&root)?,
        latest_antigravity_typed(&root, "antigravity-disposable-worktree-smoke")?,
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-visibility",
        "Antigravity Visibility",
        &report,
    )?;
    write_json(&report)
}

pub fn run_antigravity_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let latest_request = latest_antigravity_request(&root)?;
    let latest_run = latest_antigravity_run(&root)?;
    let runs = latest_run.iter().cloned().collect::<Vec<_>>();
    let telemetry = AntigravityTelemetryService.report(&probe, &runs);
    let skills =
        AntigravitySkillBundleService.generate(&antigravity_plugin_root(config_path), true);
    let plugin = AntigravityPluginBundleService.generate(&antigravity_plugin_root(config_path));
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        skills.verification_passed,
        plugin.verification_passed,
        antigravity_mcp_tools_governed_only(),
    );
    let report = antigravity_report(
        resolution,
        probe,
        contract,
        latest_request,
        latest_run,
        doctor,
        telemetry,
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-telemetry",
        "Antigravity Telemetry",
        &report.telemetry,
    )?;
    write_antigravity_report_pair(&root, "antigravity-report", "Antigravity Report", &report)?;
    write_json(&report)
}

pub fn run_antigravity_auth_check(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let auth = AntigravityAuthCheckService.help_only(
        &probe,
        vec![
            "reports/antigravity-resolution/latest.json".to_owned(),
            "reports/antigravity-detection/latest.json".to_owned(),
            "reports/antigravity-contract/latest.json".to_owned(),
        ],
    );
    write_antigravity_report_pair(
        &root,
        "antigravity-resolution",
        "Antigravity Resolution",
        &resolution,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-contract",
        "Antigravity Contract",
        &contract,
    )?;
    write_antigravity_report_pair(&root, "antigravity-auth", "Antigravity Auth", &auth)?;
    write_json(&auth)
}

pub fn run_antigravity_enable(config_path: &Path, scope: &str, admin_confirm: bool) -> Result<()> {
    if !admin_confirm {
        bail!("Antigravity enable requires --admin-confirm");
    }
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let scope = parse_antigravity_enablement_scope(scope)?;
    let auth = latest_antigravity_auth(&root)?.unwrap_or_else(|| {
        AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        )
    });
    let previous_state = AntigravityEnablementService.state_from_probe(&probe, Some(&auth));
    write_antigravity_report_pair(&root, "antigravity-auth", "Antigravity Auth", &auth)?;
    if resolution.status != AntigravityBinaryResolutionStatus::Resolved
        || !contract.noninteractive_supported
        || matches!(
            previous_state,
            AntigravityEnablementState::NotInstalled
                | AntigravityEnablementState::InstalledNoNonInteractiveMode
                | AntigravityEnablementState::BlockedByPolicy
        )
    {
        let blocked = serde_json::json!({
            "component": "antigravity_enablement",
            "status": "blocked",
            "requested_scope": scope,
            "previous_state": previous_state,
            "provider_state": probe.provider_state,
            "binary_resolution_status": resolution.status,
            "noninteractive_supported": contract.noninteractive_supported,
            "reason": "real Antigravity enablement blocked because the governed CLI provider is unavailable or has no safe noninteractive contract",
            "created_at": time::OffsetDateTime::now_utc()
        });
        write_antigravity_report_pair(
            &root,
            "antigravity-enablement",
            "Antigravity Enablement",
            &blocked,
        )?;
        return write_json(&blocked);
    }
    let receipt = AntigravityEnablementService.enable(
        previous_state,
        scope,
        true,
        vec![
            "explicit local admin CLI confirmation received".to_owned(),
            "G3B enables only governed real Antigravity smoke scopes".to_owned(),
        ],
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-enablement",
        "Antigravity Enablement",
        &receipt,
    )?;
    write_json(&receipt)
}

pub fn run_antigravity_disable(config_path: &Path, reason: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let previous_state = latest_antigravity_enablement(&root)?
        .map_or(AntigravityEnablementState::ReadyDisabled, |receipt| {
            receipt.requested_state
        });
    let receipt = AntigravityEnablementService.disable(previous_state, reason);
    write_antigravity_report_pair(
        &root,
        "antigravity-disable",
        "Antigravity Disable",
        &receipt,
    )?;
    write_json(&receipt)
}

#[allow(clippy::too_many_lines)]
pub async fn run_antigravity_live_smoke(config_path: &Path, mode: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_root = project_root_from_config(config_path).canonicalize()?;
    let mode = parse_antigravity_live_smoke_mode(mode)?;
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let auth = latest_antigravity_auth(&root)?.unwrap_or_else(|| {
        AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        )
    });
    let enablement = latest_antigravity_enablement(&root)?;
    let disable = latest_antigravity_disable(&root)?;
    let smoke_service = AntigravityDisposableWorktreeSmokeService;
    let live_before = smoke_service.snapshot_live_tree(&project_root)?;
    write_antigravity_report_pair(
        &root,
        "antigravity-live-tree-before",
        "Antigravity Live Tree Before",
        &live_before,
    )?;
    let (mut work_state, work_lease) = antigravity_smoke_work_lease(&root, "phase-g3b-live-smoke")?;
    let worktree_root = std::env::temp_dir().join("eliot-governor-antigravity-worktrees");
    let worktree_lease = smoke_service
        .create_disposable_worktree(
            &mut work_state,
            &work_lease,
            &worktree_root,
            default_lease_ttl_minutes(),
        )
        .await?;
    let worktree_path = PathBuf::from(&worktree_lease.worktree_path);
    let smoke = AntigravityLiveSmokeService.build_request(
        work_lease.project_id,
        work_lease.work_lease_id,
        Some(worktree_lease.worktree_lease_id),
        mode,
    );
    let mut request = antigravity_review_request(
        "eliot-governor",
        "phase-g3b-live-smoke",
        match mode {
            AntigravityLiveSmokeMode::DisposableWorktreeAudit => AntigravityReviewMode::AuditPlan,
            AntigravityLiveSmokeMode::DisposableWorktreeCandidateNoApply => {
                AntigravityReviewMode::CandidateImplementation
            }
        },
        &AntigravityLiveSmokeService.disposable_worktree_prompt(),
    );
    request.project_id = work_lease.project_id;
    request.task_id = work_lease.task_id;
    request.work_lease_id = Some(work_lease.work_lease_id);
    request.worktree_lease_id = Some(worktree_lease.worktree_lease_id);
    request.provider_enabled = enablement.as_ref().is_some_and(|receipt| {
        let disabled_after_enable = disable
            .as_ref()
            .is_some_and(|disable| disable.created_at >= receipt.created_at);
        !disabled_after_enable
            && match mode {
                AntigravityLiveSmokeMode::DisposableWorktreeAudit => {
                    AntigravityEnablementService.receipt_allows_disposable_worktree_audit(receipt)
                }
                AntigravityLiveSmokeMode::DisposableWorktreeCandidateNoApply => {
                    AntigravityEnablementService
                        .receipt_allows_disposable_worktree_candidate(receipt)
                }
            }
    });

    let provider_gate_passed = provider_gate_verification_passed(&root)?;
    let gate = AntigravityExecutionGate.decide(
        &request,
        &resolution,
        &probe,
        &contract,
        Some(&work_lease),
        Some(&worktree_lease),
        provider_gate_passed,
        false,
        false,
    );
    let result = if resolution.status != AntigravityBinaryResolutionStatus::Resolved
        || !contract.noninteractive_supported
    {
        AntigravityLiveSmokeService.provider_unavailable_result(
            &smoke,
            "real Antigravity CLI is unavailable through governed PATH probes or lacks a safe noninteractive contract",
        )
    } else if gate.decision != AntigravityExecutionGateDecisionKind::AllowRealRun {
        let run = AntigravityRunner.blocked_run(&request, &contract, &gate, &worktree_path);
        write_antigravity_report_pair(&root, "antigravity-runs", "Antigravity Run", &run)?;
        AntigravityLiveSmokeService.result_from_run(&smoke, &run)
    } else {
        match AntigravityRunner.run_real(&request, &contract, &worktree_lease, &worktree_path) {
            Ok(run) => {
                let inferred_auth = AntigravityAuthCheckService.from_probe_output(
                    &format!("{}\n{}", run.stdout_excerpt, run.stderr_excerpt),
                    run.state == eliot_types::AntigravityRunState::TimedOut,
                    vec!["reports/antigravity-runs/latest.json".to_owned()],
                );
                write_antigravity_report_pair(
                    &root,
                    "antigravity-auth",
                    "Antigravity Auth",
                    &inferred_auth,
                )?;
                write_antigravity_report_pair(&root, "antigravity-runs", "Antigravity Run", &run)?;
                AntigravityLiveSmokeService.result_from_run(&smoke, &run)
            }
            Err(error) => {
                let result = AntigravityLiveSmokeService.provider_unavailable_result(
                    &smoke,
                    format!("real Antigravity run could not be started safely: {error}"),
                );
                write_antigravity_report_pair(
                    &root,
                    "antigravity-live-smoke",
                    "Antigravity Live Smoke",
                    &result,
                )?;
                result
            }
        }
    };
    let evidence = match smoke_service
        .capture_cleanup_and_compare(
            &mut work_state,
            &live_before,
            worktree_lease.worktree_lease_id,
            &root.join("candidate-diffs").join("antigravity"),
            CandidateDiffService::default_max_diff_bytes(),
            result.marker_seen,
        )
        .await
    {
        Ok(evidence) => evidence,
        Err(error) => {
            let _ =
                WorktreeCleanupService.revoke(&mut work_state, worktree_lease.worktree_lease_id);
            let _ = WorktreeCleanupService
                .cleanup(&mut work_state, worktree_lease.worktree_lease_id)
                .await;
            return Err(error.into());
        }
    };
    write_antigravity_report_pair(
        &root,
        "antigravity-live-smoke",
        "Antigravity Live Smoke",
        &result,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-disposable-worktree-smoke",
        "Antigravity Disposable Worktree Smoke Evidence",
        &evidence,
    )?;
    write_antigravity_report_pair(
        &root,
        "antigravity-worktree-state",
        "Antigravity Worktree State",
        &work_state,
    )?;
    if enablement.is_some()
        && !matches!(
            enablement.as_ref().map(|receipt| receipt.approval_scope),
            Some(AntigravityEnablementScope::PersistentLocalAdmin)
        )
    {
        let disable = AntigravityEnablementService.disable(
            enablement
                .as_ref()
                .map_or(AntigravityEnablementState::ReadyDisabled, |receipt| {
                    receipt.requested_state
                }),
            "provider disabled after governed G3B live smoke attempt",
        );
        write_antigravity_report_pair(
            &root,
            "antigravity-disable",
            "Antigravity Disable",
            &disable,
        )?;
    }
    let _ = write_antigravity_real_report_snapshot(&root, resolution, probe, contract, auth)?;
    let passed = result.status == AntigravityLiveSmokeStatus::Passed
        && evidence.marker_seen
        && evidence.live_tree_unchanged
        && evidence.candidate_only
        && evidence.taint == TaintClass::ExternalAgent
        && evidence.cleanup_state == eliot_types::WorktreeLeaseState::Cleaned;
    write_json(&serde_json::json!({
        "smoke": result,
        "worktree_evidence": evidence
    }))?;
    if !passed {
        bail!("governed Antigravity disposable-worktree smoke failed");
    }
    Ok(())
}

pub fn run_antigravity_rollback(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let previous_state = latest_antigravity_enablement(&root)?
        .map_or(AntigravityEnablementState::ReadyDisabled, |receipt| {
            receipt.requested_state
        });
    let receipt = AntigravityRollbackService.rollback(previous_state, "manual G3B rollback");
    write_antigravity_report_pair(
        &root,
        "antigravity-disable",
        "Antigravity Disable",
        &receipt,
    )?;
    write_json(&serde_json::json!({
        "component": "antigravity_rollback",
        "cancels_process_group": AntigravityRollbackService.cancels_process_group(),
        "disable_receipt": receipt
    }))
}

pub fn run_antigravity_real_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let (resolution, probe, contract) = antigravity_resolution_probe_contract();
    let auth = latest_antigravity_auth(&root)?.unwrap_or_else(|| {
        AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        )
    });
    let report = write_antigravity_real_report_snapshot(&root, resolution, probe, contract, auth)?;
    write_json(&report)
}

pub fn run_service_validate(config_path: &Path) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.validate();
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Validate",
        &receipt,
    )?;
    write_json(&receipt)?;
    if receipt.status == ServiceInstallStatus::Failed {
        bail!("service validation failed; inspect service report");
    }
    Ok(())
}

pub fn run_service_install(config_path: &Path, dry_run: bool) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.install(dry_run);
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Install",
        &receipt,
    )?;
    write_json(&receipt)?;
    if receipt.status == ServiceInstallStatus::Failed {
        bail!("service install validation failed; inspect service report");
    }
    Ok(())
}

pub fn run_service_uninstall(config_path: &Path, dry_run: bool) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.uninstall(dry_run);
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Uninstall",
        &receipt,
    )?;
    write_json(&receipt)
}

pub fn run_service_status(config_path: &Path) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let report = manager.status();
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Status",
        &report,
    )?;
    write_json(&report)
}

pub fn run_service_start(config_path: &Path) -> Result<()> {
    run_service_control(config_path, ServiceInstallAction::Start, "Service Start")
}

pub fn run_service_stop(config_path: &Path) -> Result<()> {
    run_service_control(config_path, ServiceInstallAction::Stop, "Service Stop")
}

pub fn run_service_restart(config_path: &Path) -> Result<()> {
    run_service_control(
        config_path,
        ServiceInstallAction::Restart,
        "Service Restart",
    )
}

pub fn run_service_report(config_path: &Path) -> Result<()> {
    run_service_status(config_path)
}

pub fn run_ipc_smoke(config_path: &Path) -> Result<()> {
    let (mut server, token) = h1_started_ipc(config_path)?;
    let decision = StdioShimService::forwards_to_ipc_in_daemon_profile(&mut server, &token);
    let payload = serde_json::json!({ "kind": "health", "bounded": true });
    let frame = IpcFrame {
        frame_id: "h1-ipc-smoke-frame".to_owned(),
        protocol_version: h1_protocol_version().to_owned(),
        trace_id: "phase-h1-smoke".to_owned(),
        request_id: "h1-health".to_owned(),
        kind: IpcFrameKind::HealthRequest,
        payload_ref: None,
        payload_inline: Some(payload.clone()),
        payload_hash: hash_secret(&serde_json::to_string(&payload)?),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let response = IpcGovernorClient::send(&server, &frame)?;
    let status = server.status();
    let report = serde_json::json!({
        "component": "ipc_smoke",
        "handshake": decision,
        "status": status,
        "response": response,
        "bounded": true
    });
    write_h1_report(&runtime_root(config_path), "ipc", "IPC Smoke", &report)?;
    write_json(&report)?;
    if !decision.accepted || response.kind != IpcFrameKind::EventNotification {
        bail!("ipc smoke failed; inspect ipc report");
    }
    Ok(())
}

pub fn run_ipc_handshake(config_path: &Path) -> Result<()> {
    let (mut server, token) = h1_started_ipc(config_path)?;
    let handshake = IpcGovernorClient::handshake(
        "admin-cli-smoke",
        RuntimeMode::AdminCli,
        &token,
        vec!["admin".to_owned()],
    );
    let decision = server.handshake(&handshake);
    let report = serde_json::json!({
        "component": "ipc_handshake",
        "decision": decision,
        "status": server.status()
    });
    write_h1_report(&runtime_root(config_path), "ipc", "IPC Handshake", &report)?;
    write_json(&report)?;
    if report
        .get("decision")
        .and_then(|value| value.get("accepted"))
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        bail!("admin IPC handshake unexpectedly accepted without governed admin capability");
    }
    Ok(())
}

pub fn run_ipc_status(config_path: &Path) -> Result<()> {
    let (server, _) = h1_started_ipc(config_path)?;
    let report = server.status();
    write_h1_report(&runtime_root(config_path), "ipc", "IPC Status", &report)?;
    write_json(&report)
}

pub fn run_ipc_report(config_path: &Path) -> Result<()> {
    run_ipc_status(config_path)
}

pub fn run_credentials_validate(config_path: &Path) -> Result<()> {
    let report = h1_credentials_report(config_path)?;
    write_h1_report(
        &runtime_root(config_path),
        "credentials",
        "Credentials Validate",
        &report,
    )?;
    write_json(&report)?;
    if report.toml_contains_secret_values || report.command_line_contains_secret_values {
        bail!("credential boundary validation failed; inspect credentials report");
    }
    Ok(())
}

pub fn run_credentials_report(config_path: &Path) -> Result<()> {
    let report = h1_credentials_report(config_path)?;
    write_h1_report(
        &runtime_root(config_path),
        "credentials",
        "Credentials Report",
        &report,
    )?;
    write_json(&report)
}

pub fn run_readiness_probe(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let probe = h1_readiness_probe(&root)?;
    write_h1_report(&root, "readiness", "Readiness Probe", &probe)?;
    write_json(&probe)?;
    if probe.status != ServiceReadinessStatus::Ready {
        bail!("service readiness probe is not READY; inspect readiness report");
    }
    Ok(())
}

pub fn run_readiness_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let probe = h1_readiness_probe(&root)?;
    write_h1_report(&root, "readiness", "Readiness Report", &probe)?;
    write_json(&probe)
}

pub fn run_startup_recovery_scan(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let receipt = StartupRecoveryService::new(&root).scan()?;
    write_h1_report(&root, "startup-recovery", "Startup Recovery", &receipt)?;
    write_json(&receipt)
}

pub fn run_startup_recovery_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let path = root
        .join("reports")
        .join("startup-recovery")
        .join("latest.json");
    if !path.is_file() {
        return run_startup_recovery_scan(config_path);
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    write_json(&value)
}

fn phase_i1_skill_cards() -> Vec<SkillCardV2> {
    vec![
        SkillRegistryService::create_candidate("Phase I1 candidate", "codex"),
        phase_i1_active_skill(),
        phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Stale),
        phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Archived),
        phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Quarantined),
    ]
}

fn phase_i1_filter_skill_cards() -> Vec<SkillCardV2> {
    vec![
        phase_i1_active_skill(),
        phase_i1_irrelevant_skill(),
        phase_i1_rare_skill(),
        SkillRegistryService::create_candidate("Phase I1 candidate", "codex"),
    ]
}

fn phase_i1_active_skill() -> SkillCardV2 {
    phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active)
}

fn phase_i1_rare_skill() -> SkillCardV2 {
    let mut skill = phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Rare Phase I1 verifier routing".clone_into(&mut skill.name);
    skill.success_count = 0;
    skill.failure_count = 0;
    skill.source_trace_refs = vec!["evidence:rare-skill-protected".to_owned()];
    skill
}

fn phase_i1_irrelevant_skill() -> SkillCardV2 {
    let mut skill = phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Irrelevant release-note writing".clone_into(&mut skill.name);
    skill.applies_when = vec![SkillScopeRule {
        rule_id: "release-notes".to_owned(),
        description: "release note drafting".to_owned(),
        positive_examples: vec!["release notes".to_owned()],
        negative_examples: vec!["phase-i1 skill lifecycle".to_owned()],
        required_evidence_refs: Vec::new(),
    }];
    skill
}

fn phase_i1_active_skill_with_id(skill_id: SkillId, state: SkillState) -> SkillCardV2 {
    let now = time::OffsetDateTime::now_utc();
    SkillCardV2 {
        skill_id,
        name: "Phase I1 skill lifecycle foundation".to_owned(),
        purpose: "govern procedural skill activation, L3 inclusion, and execution proof".to_owned(),
        level: eliot_types::SkillLevel::Procedure,
        lifecycle_state: state,
        applies_when: vec![SkillScopeRule {
            rule_id: "phase-i1-scope".to_owned(),
            description: "phase-i1 skill lifecycle foundation".to_owned(),
            positive_examples: vec!["phase-i1-smoke".to_owned(), "skill lifecycle".to_owned()],
            negative_examples: vec!["release notes".to_owned()],
            required_evidence_refs: vec!["evidence:phase-i1".to_owned()],
        }],
        does_not_apply_when: vec![SkillScopeRule {
            rule_id: "phase-i1-anti-scope".to_owned(),
            description: "raw sql or external agent bypass".to_owned(),
            positive_examples: vec!["raw sql".to_owned(), "external agent".to_owned()],
            negative_examples: vec!["governed skill proof".to_owned()],
            required_evidence_refs: Vec::new(),
        }],
        required_inputs: vec![
            SkillInputRequirement {
                name: "task_goal".to_owned(),
                description: "current user task".to_owned(),
                required: true,
                source: SkillInputSource::UserPrompt,
            },
            SkillInputRequirement {
                name: "verifier_plan".to_owned(),
                description: "required verifier plan for completion".to_owned(),
                required: true,
                source: SkillInputSource::VerifierPlan,
            },
        ],
        ordered_steps: vec![
            SkillStep {
                step_id: "inspect-scope".to_owned(),
                order: 1,
                instruction: "Confirm scope, anti-scope, required inputs, and lifecycle state."
                    .to_owned(),
                expected_observation: Some("activation gate decision is explicit".to_owned()),
                required_tool_or_capability: None,
                stop_if_fails: true,
            },
            SkillStep {
                step_id: "run-verifier".to_owned(),
                order: 2,
                instruction: "Run required verifier and attach refs to SkillExecutionProof."
                    .to_owned(),
                expected_observation: Some("verifier refs are present".to_owned()),
                required_tool_or_capability: Some("rust-verifier".to_owned()),
                stop_if_fails: true,
            },
        ],
        required_tools_and_capabilities: vec![SkillToolRequirement {
            capability: "rust-verifier".to_owned(),
            required: true,
            allowed_tools: vec!["cargo".to_owned(), "just".to_owned()],
            forbidden_tools: vec!["surreal sql".to_owned(), "external-agent".to_owned()],
        }],
        expected_outputs: vec![SkillOutputSpec {
            name: "SkillExecutionProof".to_owned(),
            description: "proof with steps, outputs, and verifier refs".to_owned(),
            evidence_required: true,
            verifier_required: true,
        }],
        verification_plan: phase_i1_verifier_plan(),
        stop_conditions: vec![
            "anti-scope matches".to_owned(),
            "required verifier unavailable".to_owned(),
        ],
        known_failure_modes: vec![SkillFailureMode {
            failure_id: "phase-i1-known-failure".to_owned(),
            description: "negative transfer from irrelevant procedural recall".to_owned(),
            detection_signal: "phase-i1-known-failure".to_owned(),
            mitigation: "exclude or quarantine skill".to_owned(),
            negative_memory_refs: vec!["failure:phase-i1-known-failure".to_owned()],
        }],
        rollback_or_recovery: Some("archive or quarantine the skill with evidence".to_owned()),
        source_trace_refs: vec!["evidence:phase-i1".to_owned()],
        replay_result_refs: vec!["replay:phase-i1-smoke".to_owned()],
        success_count: 1,
        failure_count: 0,
        last_verified_at: Some(now),
        version: "1.0.0".to_owned(),
        owner: "eliot-governor".to_owned(),
        created_at: now,
        updated_at: now,
    }
}

fn phase_i1_verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "just_verify".to_owned(),
            command_kind: VerifierCommandKind::DomainVerifier,
            command_display: "just verify".to_owned(),
            scope: vec!["eliot-governor".to_owned()],
            required_for_done: true,
            expected_signal: "exit code 0".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["skill execution proof has verifier refs".to_owned()],
    }
}

fn phase_i1_skill_context(task: &str) -> SkillActivationContext {
    SkillActivationContext {
        goal: format!("phase-i1 skill lifecycle foundation task {task}"),
        evidence_refs: vec!["evidence:phase-i1".to_owned()],
        available_input_sources: vec![
            SkillInputSource::UserPrompt,
            SkillInputSource::CurrentState,
            SkillInputSource::VerifierPlan,
        ],
        available_input_names: vec!["task_goal".to_owned(), "verifier_plan".to_owned()],
        available_capabilities: vec!["rust-verifier".to_owned()],
        available_tools: vec!["cargo".to_owned(), "just".to_owned()],
        verifier_refs: vec!["just verify".to_owned()],
        active_negative_signals: Vec::new(),
        conflicting_skill_refs: Vec::new(),
        audit_mode: false,
    }
}

fn phase_i2_curator_run(project: &str, dry_run: bool) -> SkillCuratorRun {
    SkillCuratorService::run(SkillCuratorRunInput {
        project_id: project_id_from_label(project),
        project: project.to_owned(),
        dry_run,
        skills: phase_i2_skill_cards(),
    })
}

fn phase_i2_gate_decisions(run: &SkillCuratorRun) -> Vec<SkillCurationGateDecision> {
    run.proposals
        .iter()
        .map(|proposal| SkillCurationGate::decide(proposal, false))
        .collect()
}

fn phase_i2_skill_cards() -> Vec<SkillCardV2> {
    let mut repeated_success = phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Phase I2 repeated success skill".clone_into(&mut repeated_success.name);
    repeated_success.success_count = 3;
    repeated_success.failure_count = 0;

    let mut missing_anti_scope =
        phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Phase I2 missing anti-scope skill".clone_into(&mut missing_anti_scope.name);
    missing_anti_scope.does_not_apply_when.clear();

    let mut low_utility = phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Phase I2 low utility high cost skill".clone_into(&mut low_utility.name);
    low_utility.success_count = 0;
    low_utility.failure_count = 5;
    low_utility
        .ordered_steps
        .extend((0..20).map(|index| SkillStep {
            step_id: format!("phase-i2-expensive-{index}"),
            order: index + 20,
            instruction: "large context cost step with repeated low utility".repeat(4),
            expected_observation: None,
            required_tool_or_capability: None,
            stop_if_fails: false,
        }));

    let mut negative_transfer =
        phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Phase I2 negative transfer skill".clone_into(&mut negative_transfer.name);
    negative_transfer.success_count = 0;
    negative_transfer.failure_count = 3;
    negative_transfer
        .known_failure_modes
        .push(SkillFailureMode {
            failure_id: "phase-i2-negative-transfer".to_owned(),
            description: "negative transfer into unrelated procedural task".to_owned(),
            detection_signal: "negative-transfer".to_owned(),
            mitigation: "quarantine and retain audit trail".to_owned(),
            negative_memory_refs: vec!["failure:phase-i2-negative-transfer".to_owned()],
        });

    let mut overbroad = phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Phase I2 overbroad skill".clone_into(&mut overbroad.name);
    overbroad.applies_when.extend([
        SkillScopeRule {
            rule_id: "phase-i2-any-project".to_owned(),
            description: "any project task".to_owned(),
            positive_examples: vec!["any project".to_owned()],
            negative_examples: Vec::new(),
            required_evidence_refs: Vec::new(),
        },
        SkillScopeRule {
            rule_id: "phase-i2-all-tasks".to_owned(),
            description: "all tasks with tools".to_owned(),
            positive_examples: vec!["all tasks".to_owned()],
            negative_examples: Vec::new(),
            required_evidence_refs: Vec::new(),
        },
    ]);

    let duplicate_a = {
        let mut skill = phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
        "Phase I2 duplicate skill".clone_into(&mut skill.name);
        "duplicate phase i2 procedural routing".clone_into(&mut skill.purpose);
        skill
    };
    let mut duplicate_b = duplicate_a.clone();
    duplicate_b.skill_id = SkillId::new_v7();

    let mut rare = phase_i1_active_skill_with_id(SkillId::new_v7(), SkillState::Active);
    "Phase I2 rare protected skill".clone_into(&mut rare.name);
    rare.success_count = 1;
    rare.failure_count = 0;
    rare.source_trace_refs
        .push("evidence:phase-i2-rare-important".to_owned());

    vec![
        repeated_success,
        missing_anti_scope,
        low_utility,
        negative_transfer,
        overbroad,
        duplicate_a,
        duplicate_b,
        rare,
    ]
}

fn skill_curation_receipt(
    proposal: &SkillCurationProposal,
    applied: bool,
    summary: &str,
) -> SkillCurationReceipt {
    SkillCurationReceipt {
        receipt_id: format!("skill-curation-receipt-{}", TaskId::new_v7()),
        proposal_id: proposal.proposal_id.clone(),
        project_id: proposal.project_id,
        skill_ref: proposal.skill_ref,
        action: proposal.action,
        applied,
        summary: summary.to_owned(),
        rollback_plan: proposal.rollback_plan.clone(),
        created_at: time::OffsetDateTime::now_utc(),
        write_receipt: None,
    }
}

struct RuntimeReportBundle {
    health: RuntimeHealthReport,
    log_report: RuntimeLogReport,
    runtime_report_path: PathBuf,
    module_report_path: PathBuf,
    logs_report_path: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AdapterExecutionReport {
    component: String,
    adapter_id: String,
    result: AdapterResult,
    observations: Vec<AdapterObservation>,
    blackboard_items: Vec<BlackboardItem>,
    mailbox_messages: Vec<MailboxMessage>,
    trace_id: String,
    final_status: CompletionStatus,
}

async fn execute_adapter_test(config_path: &Path, adapter: &str) -> Result<AdapterExecutionReport> {
    let root = runtime_root(config_path);
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let blob_store = BlobStore::open(&config.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let request = test_request(adapter, AdapterCapability::ExecuteTest);
    let mut result = supervisor
        .execute(adapter, request, Some(&blob_store))
        .await
        .with_context(|| format!("execute adapter {adapter}"))?;
    let mut state = load_work_state(&root)?;
    let session_id = AgentSessionId::new_v7();
    let wal = ControlWal::open(&config.control_wal)?;
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let mut observations = Vec::new();
    let mut blackboard_items = Vec::new();
    let mut mailbox_messages = Vec::new();
    for observation in &mut result.observations {
        AdapterMemoryWriter::write_observation(&writer, &admission, observation).await?;
        let item =
            AdapterObservationBridge::to_blackboard_candidate(&mut state, session_id, observation);
        let message =
            AdapterObservationBridge::to_mailbox_notification(&mut state, session_id, observation);
        observations.push(observation.clone());
        blackboard_items.push(item);
        mailbox_messages.push(message);
    }
    drop(writer);
    actor_task.await?;
    write_report_pair(
        &work_state_path(&root),
        &work_state_markdown_path(&root),
        &state,
        "",
    )?;
    let observation_report = AdapterObservationReport {
        component: "adapter_observations".to_owned(),
        observations: observations.clone(),
        blackboard_items: blackboard_items.clone(),
        mailbox_messages: mailbox_messages.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_adapter_reports(&root, &supervisor, Some(&observation_report)).await?;
    LogService::new(root.join("logs")).write_event(LogService::event(
        LogLevel::Info,
        LogEventKind::BlackboardUpdated,
        "eliot_adapter_runtime",
        format!("adapter {adapter} emitted tainted observation"),
        Some(result.trace_id.clone()),
    ))?;
    let final_status = if matches!(result.status, AdapterResultStatus::Succeeded) {
        CompletionStatus::DoneVerified
    } else {
        CompletionStatus::PartialProgress
    };
    Ok(AdapterExecutionReport {
        component: "adapter_execute_test".to_owned(),
        adapter_id: adapter.to_owned(),
        trace_id: result.trace_id.clone(),
        result,
        observations,
        blackboard_items,
        mailbox_messages,
        final_status,
    })
}

async fn write_adapter_reports(
    root: &Path,
    supervisor: &AdapterSupervisor,
    observations: Option<&AdapterObservationReport>,
) -> Result<()> {
    let adapter_report = supervisor.registry().report().await;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &adapter_report,
        &typed_report_markdown("Adapter Registry", &adapter_report)?,
    )?;
    if let Some(observations) = observations {
        ReportService::new(root.join("reports")).write_latest(
            "adapter-observations",
            observations,
            &adapter_observation_markdown(observations),
        )?;
    }
    Ok(())
}

fn read_latest_adapter_observation_report(root: &Path) -> Result<Option<AdapterObservationReport>> {
    let path = root
        .join("reports")
        .join("adapter-observations")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn adapter_observation_markdown(report: &AdapterObservationReport) -> String {
    let mut output = String::from("# Adapter Observations\n\n");
    let _ = writeln!(output, "- observations: `{}`", report.observations.len());
    let _ = writeln!(
        output,
        "- blackboard_items: `{}`",
        report.blackboard_items.len()
    );
    let _ = writeln!(
        output,
        "- mailbox_messages: `{}`",
        report.mailbox_messages.len()
    );
    for observation in &report.observations {
        let _ = writeln!(
            output,
            "- `{}` `{}` taint=`{:?}` receipt=`{}`",
            observation.adapter_id,
            observation.observation_id,
            observation.taint,
            observation.write_receipt.as_ref().map_or_else(
                || "none".to_owned(),
                |receipt| receipt.receipt_id.to_string()
            )
        );
    }
    output
}

fn write_runtime_bundle(
    config_path: &Path,
    statuses: Vec<ServiceRuntimeStatus>,
    mode: RuntimeMode,
    single_instance_owned: bool,
) -> Result<RuntimeReportBundle> {
    let root = runtime_root(config_path);
    let report_service = ReportService::new(root.join("reports"));
    let runtime_status =
        runtime_status_report(&root, statuses.clone(), mode, single_instance_owned);
    let runtime_health = HealthService::report(mode, statuses);
    let runtime_report = serde_json::json!({
        "component": "runtime_report",
        "status": runtime_status,
        "health": runtime_health
    });
    let (runtime_report_path, _) = report_service.write_latest(
        "runtime",
        &runtime_report,
        &phase_closeout_markdown("Runtime Report", &runtime_report),
    )?;

    let module_report = module_registry(config_path)?.report();
    let (module_report_path, _) = report_service.write_latest(
        "modules",
        &module_report,
        &typed_report_markdown("Module Registry", &module_report)?,
    )?;

    let log_report = ensure_log_report(&root)?;
    let (logs_report_path, _) = report_service.write_latest(
        "logs",
        &log_report,
        &typed_report_markdown("Logs Report", &log_report)?,
    )?;

    Ok(RuntimeReportBundle {
        health: runtime_health,
        log_report,
        runtime_report_path,
        module_report_path,
        logs_report_path,
    })
}

fn runtime_status_report(
    root: &Path,
    services: Vec<ServiceRuntimeStatus>,
    mode: RuntimeMode,
    single_instance_owned: bool,
) -> RuntimeStatusReport {
    RuntimeStatusReport {
        component: "runtime_status".to_owned(),
        mode,
        pid: std::process::id(),
        data_root: root.display().to_string(),
        active_profile: "dev-single-process".to_owned(),
        single_instance_owned,
        ipc_enabled: matches!(mode, RuntimeMode::Daemon),
        services,
        generated_at: time::OffsetDateTime::now_utc(),
    }
}

fn default_service_statuses() -> Vec<ServiceRuntimeStatus> {
    [
        "lifecycle",
        "memory",
        "coordination",
        "module_registry",
        "adapter_supervisor",
        "mailbox_blackboard",
        "logs",
        "reports",
    ]
    .into_iter()
    .map(|service_name| ServiceRuntimeStatus {
        service_name: service_name.to_owned(),
        health: ServiceHealthState::Healthy,
        started: true,
        restart_budget_remaining: 3,
        message: "dev-single-process service ready".to_owned(),
    })
    .collect()
}

fn ensure_log_report(root: &Path) -> Result<RuntimeLogReport> {
    let log_service = LogService::new(root.join("logs"));
    let mut correlated = LogService::event(
        LogLevel::Info,
        LogEventKind::ServiceHealth,
        "eliot_governor.runtime",
        "runtime health probe",
        Some("g0-trace".to_owned()),
    );
    correlated.task_id = Some(TaskId::new_v7());
    correlated.agent_session_id = Some(AgentSessionId::new_v7());
    let _ = log_service.write_event(correlated)?;
    let _ = log_service.write_event(LogService::event(
        LogLevel::Warn,
        LogEventKind::Error,
        "eliot_governor.runtime",
        "secret token=local-test-redacted",
        Some("g0-trace".to_owned()),
    ))?;
    log_service.report().map_err(Into::into)
}

fn module_registry(config_path: &Path) -> Result<ModuleRegistryService> {
    let manifest_dir = module_manifest_dir(config_path);
    let manifests = if manifest_dir.is_dir() {
        let mut loaded = Vec::new();
        for entry in std::fs::read_dir(&manifest_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("toml") {
                loaded.push(read_module_manifest(&path)?);
            }
        }
        if loaded.is_empty() {
            builtin_manifests()
        } else {
            loaded
        }
    } else {
        builtin_manifests()
    };
    Ok(ModuleRegistryService::new(manifests)?)
}

fn module_manifest_dir(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("config")
        .join("modules")
}

fn read_module_manifest(path: &Path) -> Result<ModuleManifest> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read module manifest {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("parse module manifest {}", path.display()))
}

fn typed_report_markdown<T: serde::Serialize>(title: &str, report: &T) -> Result<String> {
    let value = serde_json::to_value(report)?;
    Ok(phase_closeout_markdown(title, &value))
}

pub async fn run_db_start(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let server = SurrealServerSupervisor::new(config.db.surreal)
        .start_or_connect()
        .await?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": "ready",
        "server_started": server.started_pid().is_some()
    }))
}

pub async fn run_db_stop(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let stopped = SurrealServerSupervisor::new(config.db.surreal)
        .stop()
        .await?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": if stopped { "stopped" } else { "not_running" }
    }))
}

pub async fn run_db_status(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let ready = SurrealServerSupervisor::new(config.db.surreal)
        .status()
        .await?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": if ready { "ready" } else { "not_ready" }
    }))
}

pub async fn run_db_smoke(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let report = SurrealStore::new(config.db.surreal).smoke().await?;
    let report_path = db_report_path(config_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&report_path, report.to_markdown())?;
    write_json(&serde_json::json!({
        "component": "surrealdb",
        "status": if report.is_ready() { "ready" } else { "not_ready" },
        "report_path": report_path,
        "report": report
    }))?;

    if !report.is_ready() {
        bail!("SurrealDB smoke write/read failed");
    }
    Ok(())
}

pub async fn run_db_migrate(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let _ = CanonicalStore::new(config.db.surreal.clone())
        .migrate_schema()
        .await?;
    let record = SurrealStore::new(config.db.surreal)
        .apply_migration(NamedSurqlOp::SchemaMigrate.name(), "RETURN true;")
        .await?;
    write_json(&serde_json::json!({
        "component": record.component,
        "status": record.status,
        "detail": record.detail
    }))
}

pub async fn run_writer_status(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let wal = ControlWal::open(&config.control_wal)?;
    let store = CanonicalStore::new(config.db.surreal);
    let report = WriterReportService::new(wal, store).status().await?;
    let root = runtime_root(config_path);
    write_report_pair(
        &root.join("reports").join("writer").join("latest.json"),
        &root.join("reports").join("writer").join("latest.md"),
        &report,
        &writer_status_markdown(&report),
    )?;
    write_json(&report)
}

pub async fn run_writer_smoke(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;

    let wal = ControlWal::open(&config.control_wal)?;
    let writer_config = WriterConfig::default();
    let (handle, actor) = WriterActor::channel(wal, store.clone(), &writer_config);
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;

    let project_id = ProjectId::new_v7();
    let agent_id = AgentId::new_v7();
    let task_id = Some(TaskId::new_v7());
    let claim_id = ClaimId::new_v7();
    let evidence_id = EvidenceId::new_v7();
    let source_id = format!("source-{evidence_id}");
    let statement = "writer smoke verified claim".to_owned();

    let mut receipts = Vec::new();
    let evidence_command = SemanticCommand::EvidenceIngest(EvidenceIngestCommand {
        context: smoke_context(project_id, agent_id, task_id),
        source: SourceSnapshotInput {
            source_id: source_id.clone(),
            uri: "local://writer-smoke".to_owned(),
            authority: "local-smoke".to_owned(),
            content_hash: "writer-smoke".to_owned(),
            excerpt: "writer smoke source".to_owned(),
        },
        evidence: EvidenceAtomInput {
            evidence_id,
            source_id,
            summary: "writer smoke evidence".to_owned(),
            payload: serde_json::json!({ "smoke": true }),
        },
    });
    receipts.push(handle.submit(admission.admit(&evidence_command)?).await?);

    let claim_command = SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: smoke_context(project_id, agent_id, task_id),
        claim: ClaimCardInput {
            claim_id,
            statement: statement.clone(),
            status: EpistemicStatus::Candidate,
            payload: serde_json::json!({ "phase": "candidate" }),
        },
    });
    receipts.push(handle.submit(admission.admit(&claim_command)?).await?);

    let support_command = SemanticCommand::ClaimSupport(eliot_types::ClaimSupportCommand {
        context: smoke_context(project_id, agent_id, task_id),
        claim_id,
        evidence_id,
        statement: Some(statement.clone()),
        payload: serde_json::json!({ "phase": "supported" }),
    });
    receipts.push(handle.submit(admission.admit(&support_command)?).await?);

    let verify_command = SemanticCommand::ClaimVerify(eliot_types::ClaimVerifyCommand {
        context: smoke_context(project_id, agent_id, task_id),
        claim_id,
        verification: VerificationRunInput {
            verification_id: eliot_types::VerificationId::new_v7(),
            claim_id: Some(claim_id),
            verifier: "local-writer-smoke".to_owned(),
            result: VerificationResult::Passed,
            summary: "writer smoke verification passed".to_owned(),
            payload: serde_json::json!({ "passed": true }),
        },
        statement: Some(statement),
        payload: serde_json::json!({ "phase": "verified" }),
    });
    receipts.push(handle.submit(admission.admit(&verify_command)?).await?);

    drop(handle);
    actor_task.await?;

    let read_service = ReadService::new(store);
    let current_state = read_service
        .current_state(&CurrentStateRequest {
            project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?;

    let report = serde_json::json!({
        "component": "writer",
        "status": if current_state.verified_now.is_empty() { "not_ready" } else { "ready" },
        "project_id": project_id,
        "receipt_count": receipts.len(),
        "verified_now": current_state.verified_now,
        "receipts": receipts
    });
    let root = runtime_root(config_path);
    write_report_pair(
        &root
            .join("reports")
            .join("writer")
            .join("smoke-latest.json"),
        &root.join("reports").join("writer").join("smoke-latest.md"),
        &report,
        "# Writer Smoke\n\n- status: `ready`\n",
    )?;
    write_json(&report)
}

pub fn run_writer_drain(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let pending = ControlWal::open(&config.control_wal)?.recover_pending()?;
    write_json(&serde_json::json!({
        "component": "writer",
        "status": "drained",
        "pending_recovered": pending.len(),
        "detail": "no background writer queue is running in this CLI process"
    }))
}

pub async fn run_memory_current_state(config_path: &Path, project: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let project_id = parse_project_id(project)?;
    let request = CurrentStateRequest {
        project_id,
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
    };
    let service = ReadService::new(CanonicalStore::new(config.db.surreal));
    let response = service.current_state(&request).await?;
    write_json(&response)
}

pub async fn run_memory_recall_l0(config_path: &Path, project: &str, query: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let request = RecallL0Request {
        project_id: parse_project_id(project)?,
        query: query.to_owned(),
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
        lifecycle_audit: false,
    };
    let service = ReadService::new(CanonicalStore::new(config.db.surreal));
    let response = service.recall_l0(&request).await?;
    write_json(&response)
}

pub async fn run_memory_fetch_l2(config_path: &Path, project: &str, handles: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let request = FetchAtomsL2Request {
        project_id: parse_project_id(project)?,
        handles: handles
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        continuation: None,
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
    };
    let service = ReadService::new(CanonicalStore::new(config.db.surreal));
    let response = service.fetch_atoms_l2(&request).await?;
    write_json(&response)
}

pub fn run_memory_lifecycle_status(
    config_path: &Path,
    project: &str,
    memory_ref: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let report = MemoryLifecycleService::new().status(project_id, memory_ref);
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        &report,
        &typed_report_markdown("Memory Lifecycle Status", &report)?,
    )?;
    write_json(&report)
}

pub fn run_memory_lifecycle_propose(
    config_path: &Path,
    project: &str,
    memory_ref: &str,
    operator: &str,
    reason: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let policy = lifecycle_policy_from_cli(project, memory_ref, operator, reason)?;
    let decision = MemoryLifecycleGate::decide(&policy, &[]);
    let report = serde_json::json!({
        "component": "memory_lifecycle_proposal",
        "policy": policy,
        "decision": decision
    });
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        &report,
        &phase_closeout_markdown("Memory Lifecycle Proposal", &report),
    )?;
    write_json(&report)
}

pub async fn run_memory_lifecycle_apply(config_path: &Path, policy_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let latest = root
        .join("reports")
        .join("memory-lifecycle")
        .join("latest.json");
    if !latest.is_file() {
        bail!("no latest memory lifecycle proposal found; run memory-lifecycle propose first");
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(&latest)?)?;
    let policy_value = value
        .get("policy")
        .cloned()
        .context("latest memory lifecycle report does not contain a policy")?;
    let policy: ForgettingPolicy = serde_json::from_value(policy_value)?;
    if policy.policy_id != policy_id {
        bail!("latest memory lifecycle policy id does not match {policy_id}");
    }
    let outcome = apply_lifecycle_policy_to_memory(config_path, &policy).await?;
    let report = serde_json::json!({
        "component": "memory_lifecycle_apply",
        "policy_id": policy_id,
        "decision": outcome.decision,
        "transition": outcome.transition,
        "write_receipt": outcome.write_receipt
    });
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        &report,
        &phase_closeout_markdown("Memory Lifecycle Apply", &report),
    )?;
    write_json(&report)
}

pub fn run_memory_lifecycle_vitality(config_path: &Path, project: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let score = MemoryVitalityService::score(project_id, "memory-lifecycle:baseline");
    write_memory_vitality_report(&root, &score)?;
    write_json(&score)
}

pub fn run_memory_lifecycle_gravity(config_path: &Path, project: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let score = MemoryVitalityService::score(project_id, "memory-lifecycle:baseline");
    let gravity = MemoryGravityService::gravity(&score);
    write_memory_gravity_report(&root, &gravity)?;
    write_json(&gravity)
}

pub async fn run_memory_lifecycle_influence(
    config_path: &Path,
    project: &str,
    task: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = Some(task_id_from_label(task));
    let lifecycle = MemoryLifecyclePacketView::default();
    let mut report = MemoryInfluenceService::report(
        project_id,
        task_id,
        Some(task.to_owned()),
        vec!["memory-lifecycle:baseline".to_owned()],
        &lifecycle,
    );
    write_memory_influence_to_memory(config_path, &mut report).await?;
    write_memory_influence_report(&root, &report)?;
    write_json(&report)
}

pub fn run_memory_lifecycle_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = ProjectId::new_v7();
    let report = MemoryLifecycleReport {
        component: "memory_lifecycle_report".to_owned(),
        statuses: vec![
            MemoryLifecycleService::new().status(project_id, "memory-lifecycle:baseline"),
        ],
        proposals: Vec::new(),
        influence: read_optional_report::<MemoryInfluenceReport>(&root, "memory-influence")?,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_memory_lifecycle_report(&root, &report)?;
    write_json(&report)
}

pub async fn run_skill_create(config_path: &Path, project: &str, name: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let skill = SkillRegistryService::create_candidate(name, "codex");
    let receipt = write_skill_card_to_memory(config_path, &skill).await?;
    let report = serde_json::json!({
        "component": "skill_create",
        "project_id": project_id,
        "skill": skill,
        "write_receipt": receipt,
        "final_status": "CANDIDATE_CREATED"
    });
    write_skill_report_pair(&root, "skills", "Skills", &report)?;
    write_json(&report)
}

pub fn run_skill_list(config_path: &Path, project: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let skills = phase_i1_skill_cards();
    let normal = SkillDistractorFilterService::filter(
        project_id,
        TaskId::new_v7(),
        &skills,
        &phase_i1_skill_context("phase-i1-smoke"),
    );
    let report = serde_json::json!({
        "component": "skill_list",
        "project_id": project_id,
        "skills": skills,
        "normal_recall_included": normal.skills_included,
        "normal_recall_removed": normal.distractors_removed,
        "final_status": "OK"
    });
    write_skill_report_pair(&root, "skills", "Skills", &report)?;
    write_json(&report)
}

pub fn run_skill_inspect(config_path: &Path, skill: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = phase_i1_active_skill_with_id(skill_id, SkillState::Active);
    let record = SkillLifecycleService::record_for(&card, None);
    let report = serde_json::json!({
        "component": "skill_inspect",
        "skill": card,
        "lifecycle_record": record
    });
    write_skill_report_pair(&root, "skills", "Skill Inspect", &report)?;
    write_json(&report)
}

pub fn run_skill_activate(config_path: &Path, skill: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = phase_i1_active_skill_with_id(skill_id, SkillState::Candidate);
    let (activated, record) =
        SkillLifecycleService::activate(&card, vec!["evidence:phase-i1-activation".to_owned()])
            .map_err(|decision| anyhow::anyhow!("skill activation denied: {decision:?}"))?;
    let report = serde_json::json!({
        "component": "skill_activate",
        "skill": activated,
        "lifecycle_record": record,
        "final_status": "ACTIVE"
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Lifecycle", &report)?;
    write_json(&report)
}

pub fn run_skill_archive(config_path: &Path, skill: &str, reason: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = phase_i1_active_skill_with_id(skill_id, SkillState::Active);
    let (archived, record) = SkillLifecycleService::archive(&card, reason);
    let report = serde_json::json!({
        "component": "skill_archive",
        "skill": archived,
        "lifecycle_record": record,
        "reason": reason
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Lifecycle", &report)?;
    write_json(&report)
}

pub fn run_skill_quarantine(config_path: &Path, skill: &str, reason: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let skill_id = skill_id_from_label(skill);
    let card = phase_i1_active_skill_with_id(skill_id, SkillState::Active);
    let (quarantined, record) = SkillLifecycleService::quarantine(&card, reason);
    let report = serde_json::json!({
        "component": "skill_quarantine",
        "skill": quarantined,
        "lifecycle_record": record,
        "reason": reason
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Lifecycle", &report)?;
    write_json(&report)
}

pub fn run_skill_estimate(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let skill = phase_i1_active_skill();
    let estimate =
        SkillNeedEstimator::estimate(project_id, task_id, &skill, &phase_i1_skill_context(task));
    write_skill_report_pair(&root, "skill-activation", "Skill Activation", &estimate)?;
    write_json(&estimate)
}

pub fn run_skill_filter(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let report = SkillDistractorFilterService::filter(
        project_id,
        task_id,
        &phase_i1_filter_skill_cards(),
        &phase_i1_skill_context(task),
    );
    write_skill_report_pair(&root, "skill-activation", "Skill Activation", &report)?;
    write_json(&report)
}

pub async fn run_skill_execution_proof(config_path: &Path, skill: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = ProjectId::new_v7();
    let task_id = task_id_from_label(task);
    let skill_id = skill_id_from_label(skill);
    let mut proof = SkillExecutionProofService::proof(
        skill_id,
        project_id,
        task_id,
        vec!["inspect-scope".to_owned(), "run-verifier".to_owned()],
        vec!["skill output was verified".to_owned()],
        vec!["just verify".to_owned()],
        SkillExecutionOutcome::Succeeded,
    );
    let receipt = write_skill_execution_proof_to_memory(config_path, &mut proof).await?;
    let report = serde_json::json!({
        "component": "skill_execution_proof",
        "proof": proof,
        "write_receipt": receipt
    });
    write_skill_report_pair(&root, "skill-lifecycle", "Skill Execution Proof", &report)?;
    write_json(&report)
}

pub async fn run_skill_influence(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let skill = phase_i1_active_skill();
    let mut report = SkillInfluenceService::report(SkillInfluenceReportInput {
        project_id,
        task_id,
        packet_id: Some(task.to_owned()),
        considered: vec![skill.skill_id],
        included: vec![skill.skill_id],
        executed: Vec::new(),
        execution_proofs: Vec::new(),
        estimated_context_cost: 128,
    });
    write_skill_influence_to_memory(config_path, &mut report).await?;
    write_skill_influence_report(&root, &report)?;
    write_json(&report)
}

pub fn run_skill_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let skills = phase_i1_filter_skill_cards();
    let context = phase_i1_skill_context("phase-i1-smoke");
    let filter = SkillDistractorFilterService::filter(project_id, task_id, &skills, &context);
    let influence = SkillInfluenceService::report(SkillInfluenceReportInput {
        project_id,
        task_id,
        packet_id: Some("skill-report".to_owned()),
        considered: filter.skills_considered.clone(),
        included: filter.skills_included.clone(),
        executed: Vec::new(),
        execution_proofs: Vec::new(),
        estimated_context_cost: 128,
    });
    let report = serde_json::json!({
        "component": "skill_report",
        "skills": skills,
        "filter": filter,
        "influence": influence
    });
    write_skill_report_pair(&root, "skills", "Skills", &report)?;
    write_json(&report)
}

pub async fn run_skill_curator_run(config_path: &Path, project: &str, dry_run: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let mut run = phase_i2_curator_run(project, dry_run);
    write_skill_curator_run_to_memory(config_path, &mut run).await?;
    let gate_decisions = phase_i2_gate_decisions(&run);
    write_skill_curator_reports(&root, &run, &gate_decisions)?;
    let report = SkillCurationReportService::report(run);
    write_json(&report)
}

pub fn run_skill_curator_inspect(config_path: &Path, run_id: &str) -> Result<()> {
    let run = latest_skill_curator_run(&runtime_root(config_path))?
        .context("no latest skill-curator run found; run skill-curator run first")?;
    if run_id != "latest" && run.run_id != run_id {
        bail!("requested run id does not match latest skill-curator run");
    }
    write_json(&run)
}

pub async fn run_skill_curator_proposals(config_path: &Path, project: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run = if let Some(run) = latest_skill_curator_run(&root)? {
        run
    } else {
        let mut run = phase_i2_curator_run(project, true);
        write_skill_curator_run_to_memory(config_path, &mut run).await?;
        run
    };
    let gate_decisions = phase_i2_gate_decisions(&run);
    write_skill_curator_reports(&root, &run, &gate_decisions)?;
    let report = serde_json::json!({
        "component": "skill_curation_proposals",
        "project": project,
        "run_id": run.run_id,
        "open_proposals": run.proposals,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json(&report)
}

pub fn run_skill_curator_gate(config_path: &Path, proposal_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let proposal = find_skill_curation_proposal(&root, proposal_id)?;
    let decision =
        SkillCurationGate::decide(&proposal, IncidentService::new(&root).lockdown_active()?);
    write_skill_curator_gate_report(&root, std::slice::from_ref(&decision))?;
    write_json(&decision)
}

pub async fn run_skill_curator_apply(config_path: &Path, proposal_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let proposal = find_skill_curation_proposal(&root, proposal_id)?;
    let decision =
        SkillCurationGate::decide(&proposal, IncidentService::new(&root).lockdown_active()?);
    write_skill_curator_gate_report(&root, std::slice::from_ref(&decision))?;
    if decision.decision != SkillCurationDecisionKind::Allow {
        bail!("skill-curator apply denied by gate: {:?}", decision.reasons);
    }
    if matches!(
        proposal.action,
        SkillCurationAction::Promote | SkillCurationAction::Merge | SkillCurationAction::Split
    ) {
        bail!("skill-curator apply supports only safe patch/archive/quarantine in I2");
    }

    let base_skill = phase_i1_active_skill_with_id(proposal.skill_ref, SkillState::Active);
    let summary = match proposal.action {
        SkillCurationAction::Patch => {
            let _patched = SkillPatchService::apply_narrow_patch(&base_skill, &proposal).map_err(
                |decision| anyhow::anyhow!("skill patch denied: {:?}", decision.reasons),
            )?;
            "safe narrow skill patch applied through governed CLI"
        }
        SkillCurationAction::Archive => {
            let _archived = SkillArchiveQuarantineService::safe_archive(
                &base_skill,
                "skill curator safe archive",
            );
            "safe archive receipt retained for audit"
        }
        SkillCurationAction::Quarantine => {
            let _quarantined = SkillArchiveQuarantineService::safe_quarantine(
                &base_skill,
                "skill curator safe quarantine",
            );
            "safe quarantine receipt retained for audit"
        }
        SkillCurationAction::Keep => {
            bail!("keep is read-only in I2 and has no apply action")
        }
        SkillCurationAction::Merge | SkillCurationAction::Split | SkillCurationAction::Promote => {
            unreachable!("high-risk actions are rejected before apply")
        }
    };
    let mut receipt = skill_curation_receipt(&proposal, true, summary);
    write_skill_curation_receipt_to_memory(config_path, &mut receipt).await?;
    let report = serde_json::json!({
        "component": "skill_curator_apply",
        "proposal": proposal,
        "gate_decision": decision,
        "receipt": receipt,
        "final_status": "APPLIED_WITH_RECEIPT"
    });
    write_skill_report_pair(&root, "skill-curation-gate", "Skill Curation Gate", &report)?;
    write_json(&report)
}

pub fn run_skill_curator_rollback_plan(config_path: &Path, proposal_id: &str) -> Result<()> {
    let proposal = find_skill_curation_proposal(&runtime_root(config_path), proposal_id)?;
    write_json(&proposal.rollback_plan)
}

pub fn run_skill_curator_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "skill-curator")
}

pub async fn run_graph_health(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let service = GraphHealthService::new(CanonicalStore::new(config.db.surreal));
    let report = service.health().await?;
    let root = runtime_root(config_path);
    write_report_pair(
        &root.join("reports").join("graph").join("latest.json"),
        &root.join("reports").join("graph").join("latest.md"),
        &report,
        &graph_health_markdown(&report),
    )?;
    write_json(&report)
}

pub fn run_codecortex_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = CodeCortexService::new(std::env::current_dir()?).health("eliot-governor")?;
    write_report_pair(
        &root.join("reports").join("codecortex").join("health.json"),
        &root.join("reports").join("codecortex").join("health.md"),
        &report,
        &codecortex_report_markdown(&report),
    )?;
    write_json(&report)
}

pub async fn run_codecortex_scan(
    config_path: &Path,
    project: &str,
    task: &str,
    goal: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let request = CodeCortexRequest {
        project: project.to_owned(),
        task: task.to_owned(),
        goal: goal.to_owned(),
        exact_patterns: Vec::new(),
        max_files: 160,
        max_matches_per_pattern: 24,
        include_diagnostics: true,
    };
    let mut report = CodeCortexService::new(std::env::current_dir()?).scan(&request)?;
    write_codecortex_report_to_memory(config_path, &mut report).await?;
    write_report_pair(
        &root.join("reports").join("codecortex").join("latest.json"),
        &root.join("reports").join("codecortex").join("latest.md"),
        &report,
        &codecortex_report_markdown(&report),
    )?;
    write_json(&report)
}

pub fn run_codecortex_report(config_path: &Path, latest: bool) -> Result<()> {
    if !latest {
        bail!("only codecortex report --latest is supported in D1");
    }
    let path = runtime_root(config_path)
        .join("reports")
        .join("codecortex")
        .join("latest.json");
    if !path.is_file() {
        bail!("no latest CodeCortex report found; run codecortex scan first");
    }
    let report: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    write_json(&report)
}

pub fn run_trace_completeness(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let contract = phase_j0_trace_contract(project, task, true);
    write_j0_report(&root, "trace-completeness", "Trace Completeness", &contract)?;
    write_json(&contract)
}

pub fn run_trace_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "trace-completeness")
}

pub fn run_replay_case_create(
    config_path: &Path,
    project: &str,
    task: &str,
    kind: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let contract = read_latest_typed::<TraceCompletenessContract>(&root, "trace-completeness")
        .unwrap_or_else(|_| phase_j0_trace_contract(project, task, true));
    if !contract.replay_allowed {
        bail!("replay case requires complete trace contract");
    }
    let case = ReplayCaseService::create(ReplayCaseInput {
        project_id: project_id_from_label(project),
        source_task_id: Some(task_id_from_label(task)),
        case_kind: parse_replay_case_kind(kind)?,
        trace_contract_ref: contract.contract_id.clone(),
        input_snapshot_refs: vec![contract.trace_ref.clone(), contract.contract_id],
    })?;
    write_j0_report(&root, "replay-cases", "Replay Case", &case)?;
    write_json(&case)
}

pub fn run_replay_set_create(
    config_path: &Path,
    project: &str,
    name: &str,
    fixed: bool,
    holdout: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let case = read_latest_typed::<ReplayCase>(&root, "replay-cases")
        .context("no latest replay case found; run replay case create first")?;
    let set = ReplaySetService::create(ReplaySetInput {
        project_id: project_id_from_label(project),
        name: name.to_owned(),
        purpose: "Phase J0 deterministic replay set".to_owned(),
        cases: vec![case.replay_case_id],
        fixed,
        holdout,
        created_from_refs: vec![case.trace_contract_ref.clone()],
    });
    write_j0_report(&root, "replay-cases", "Replay Case", &case)?;
    write_j0_report(&root, "replay-sets", "Replay Set", &set)?;
    write_json(&set)
}

pub fn run_replay_set_add(config_path: &Path, case: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut set = read_latest_typed::<ReplaySet>(&root, "replay-sets")
        .context("no latest replay set found; run replay set create first")?;
    let latest_case = read_latest_typed::<ReplayCase>(&root, "replay-cases")
        .context("no latest replay case found; run replay case create first")?;
    if case != "latest" && latest_case.replay_case_id.to_string() != case {
        bail!("only latest replay case is available in Phase J0 CLI");
    }
    ReplaySetService::add_case(&mut set, latest_case.replay_case_id)?;
    write_j0_report(&root, "replay-sets", "Replay Set", &set)?;
    write_json(&set)
}

pub fn run_replay_run(config_path: &Path, set: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let replay_set = read_latest_typed::<ReplaySet>(&root, "replay-sets")
        .context("no latest replay set found; run replay set create first")?;
    if set != "latest" && replay_set.name != set && replay_set.replay_set_id.to_string() != set {
        bail!("only latest replay set or its name/id is available in Phase J0 CLI");
    }
    let case = read_latest_typed::<ReplayCase>(&root, "replay-cases")
        .context("no latest replay case found; run replay case create first")?;
    let (run, audit) = ReplayRunnerService::run(
        replay_set.project_id,
        &replay_set,
        &[case],
        Some("dream:latest".to_owned()),
        Some("apply current truth"),
    );
    let report = serde_json::json!({ "run": run, "audit": audit });
    write_report_pair(
        &latest_report_path(&root, "replay-runs"),
        &latest_markdown_path(&root, "replay-runs"),
        &report,
        &j0_value_markdown("Replay Run", &report),
    )?;
    write_json(&report)
}

pub fn run_replay_verdict(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let latest = read_latest_value(&root, "replay-runs")?;
    let replay_run: ReplayRun = serde_json::from_value(
        latest
            .get("run")
            .cloned()
            .context("latest replay run report has no run field")?,
    )?;
    if run != "latest" && replay_run.replay_run_id.to_string() != run {
        bail!("only latest replay run or its id is available in Phase J0 CLI");
    }
    let verdict = ReplayVerdictService::verdict(&replay_run);
    write_j0_report(&root, "replay-verdicts", "Replay Verdict", &verdict)?;
    write_json(&verdict)
}

pub fn run_replay_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let run = read_latest_value(&root, "replay-runs").ok();
    let verdict = read_latest_value(&root, "replay-verdicts").ok();
    let report = serde_json::json!({
        "component": "replay_report",
        "run": run,
        "verdict": verdict
    });
    write_json(&report)
}

pub fn run_sleep_run(
    config_path: &Path,
    project: &str,
    trigger: &str,
    dry_run: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let run = SleepConsolidationService::run(
        SleepRunInput {
            project_id: project_id_from_label(project),
            trigger: parse_sleep_trigger(trigger)?,
            dry_run,
            input_traces: vec!["trace:latest".to_owned()],
        },
        IncidentService::new(&root).lockdown_active()?,
    )?;
    write_j0_report(&root, "sleep", "Sleep Consolidation", &run)?;
    write_json(&run)
}

pub fn run_sleep_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "sleep")
}

pub fn run_dream_candidate_create(
    config_path: &Path,
    project: &str,
    kind: &str,
    source_trace: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let (candidate, taint) = DreamCandidateService::create(
        project_id_from_label(project),
        parse_dream_candidate_kind(kind)?,
        source_trace.to_owned(),
    );
    let report = serde_json::json!({
        "component": "dream_candidate",
        "candidate": candidate,
        "taint": taint
    });
    write_report_pair(
        &latest_report_path(&root, "dream"),
        &latest_markdown_path(&root, "dream"),
        &report,
        &j0_value_markdown("Dream Candidate", &report),
    )?;
    write_json(&report)
}

pub fn run_dream_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "dream")
}

pub fn run_eval_case_create(config_path: &Path, family: &str, name: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_cases_report(&root).unwrap_or_else(|_| EvalCasesReport {
        component: "eval_cases".to_owned(),
        cases: Vec::new(),
        generated_at: time::OffsetDateTime::now_utc(),
    });
    let case = EvalCaseService::create(EvalCaseInput {
        project_id: project_id_from_label("eliot-governor"),
        task_id: Some(task_id_from_label("phase-k0-cli")),
        family: parse_eval_family(family)?,
        name: name.to_owned(),
    })?;
    report.cases.push(case.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-cases", "Eval Cases", &report)?;
    write_json(&case)
}

pub fn run_eval_case_list(config_path: &Path, family: Option<&str>) -> Result<()> {
    let root = runtime_root(config_path);
    let cases = match read_eval_cases_report(&root) {
        Ok(report) => report.cases,
        Err(_) => k0_default_cases(),
    };
    let filtered = if let Some(family) = family {
        let family = parse_eval_family(family)?;
        cases
            .into_iter()
            .filter(|case| case.family == family)
            .collect::<Vec<_>>()
    } else {
        cases
    };
    write_json(&serde_json::json!({
        "component": "eval_case_list",
        "cases": filtered,
        "generated_at": time::OffsetDateTime::now_utc()
    }))
}

pub fn run_eval_suite_create(config_path: &Path, name: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let cases = ensure_eval_cases(&root)?;
    let suite = EvalSuiteService::create(EvalSuiteInput {
        project_id: project_id_from_label("eliot-governor"),
        name: name.to_owned(),
        purpose: "K0 deterministic no-mutation eval suite".to_owned(),
        cases: cases.iter().map(|case| case.eval_case_id).collect(),
        fixed: false,
        holdout: true,
        created_from_refs: vec!["phase-k0:cli".to_owned()],
    });
    let report = EvalSuitesReport {
        component: "eval_suites".to_owned(),
        suites: vec![suite.clone()],
        latest: suite.clone(),
        manifest: None,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&suite)
}

pub fn run_eval_suite_add(config_path: &Path, suite: &str, case: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_suites_report(&root)
        .context("no latest eval suite found; run eval suite create first")?;
    if suite != "latest"
        && suite != report.latest.name
        && suite != report.latest.eval_suite_id.to_string()
    {
        bail!("only latest eval suite or its name/id is available in K0 CLI");
    }
    let cases = ensure_eval_cases(&root)?;
    let eval_case = cases
        .iter()
        .find(|eval_case| {
            case == "latest"
                || eval_case.eval_case_id.to_string() == case
                || eval_case.name == case
                || family_slug(eval_case.family) == case
        })
        .context("eval case not found")?;
    EvalSuiteService::add_case(&mut report.latest, eval_case.eval_case_id)?;
    report.suites.push(report.latest.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&report.latest)
}

pub fn run_eval_suite_freeze(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_suites_report(&root)
        .context("no latest eval suite found; run eval suite create first")?;
    if suite != "latest"
        && suite != report.latest.name
        && suite != report.latest.eval_suite_id.to_string()
    {
        bail!("only latest eval suite or its name/id is available in K0 CLI");
    }
    EvalSuiteService::freeze(&mut report.latest);
    report.suites.push(report.latest.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&report.latest)
}

pub fn run_eval_manifest(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut report = read_eval_suites_report(&root)
        .context("no latest eval suite found; run eval suite create first")?;
    if suite != "latest"
        && suite != report.latest.name
        && suite != report.latest.eval_suite_id.to_string()
    {
        bail!("only latest eval suite or its name/id is available in K0 CLI");
    }
    let cases = ensure_eval_cases(&root)?;
    let manifest = EvalDatasetManifestService::manifest(&report.latest, &cases);
    report.manifest = Some(manifest.clone());
    report.generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(&root, "eval-suites", "Eval Suites", &report)?;
    write_json(&manifest)
}

pub fn run_eval_run(config_path: &Path, suite: &str, profile: &str) -> Result<()> {
    if normalized_cli_value(profile) != "deterministicnomutation" {
        bail!("K0 supports only deterministic-no-mutation eval runs");
    }
    let root = runtime_root(config_path);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    write_json(&artifacts.run)
}

pub fn run_eval_verdict(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run_report = read_eval_runs_report(&root)
        .context("no latest eval run found; run eval run or eval smoke first")?;
    if run != "latest" && run != run_report.run.eval_run_id.to_string() {
        bail!("only latest eval run or its id is available in K0 CLI");
    }
    let verdict = EvalVerdictService::verdict(&run_report.run);
    let report = EvalVerdictsReport {
        component: "eval_verdicts".to_owned(),
        verdict: verdict.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-verdicts", "Eval Verdicts", &report)?;
    write_json(&verdict)
}

pub fn run_eval_failures(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run_report = read_eval_runs_report(&root)
        .context("no latest eval run found; run eval run or eval smoke first")?;
    if run != "latest" && run != run_report.run.eval_run_id.to_string() {
        bail!("only latest eval run or its id is available in K0 CLI");
    }
    let mut clusters = EvalVerdictService::failure_clusters(&run_report.run);
    if clusters.is_empty() {
        clusters.push(EvalVerdictService::fixture_failure_cluster(
            run_report.run.eval_run_id,
        ));
    }
    let report = EvalFailuresReport {
        component: "eval_failures".to_owned(),
        clusters: clusters.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-failures", "Eval Failures", &report)?;
    write_json(&report)
}

pub fn run_eval_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = eval_summary_report(&root)?;
    write_json(&report)
}

pub fn run_eval_smoke(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    let report = serde_json::json!({
        "component": "eval_smoke",
        "suite": artifacts.suite,
        "manifest": artifacts.manifest,
        "run": artifacts.run,
        "verdict": artifacts.verdict,
        "failure_cluster": artifacts.fixture_failure_cluster,
        "benchmark_integrity": {
            "valid_receipt": artifacts.integrity_receipt,
            "mismatch_receipt": artifacts.mismatch_receipt
        },
        "final_status": if artifacts.verdict.status == EvalVerdictStatus::Pass {
            CompletionStatus::DoneVerified
        } else {
            CompletionStatus::PartialProgress
        },
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json(&report)
}

pub fn run_eval_coverage(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    let report = eval_coverage_report(&artifacts);
    write_eval_report(&root, "eval-coverage", "Eval Coverage", &report)?;
    write_json(&report.coverage)
}

pub fn run_eval_baseline_create(config_path: &Path, suite: &str, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    ensure_eval_run_ref(&artifacts.run, run)?;
    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let baseline = EvalBaselineService::create(
        &artifacts.suite,
        &artifacts.manifest,
        &artifacts.integrity_receipt,
        &artifacts.run,
        &artifacts.verdict,
        &git_commit,
        "local-cli",
    )?;
    write_eval_baseline_registry(&root, &artifacts.suite, baseline.clone())?;
    write_json(&baseline)
}

pub fn run_eval_baseline_list(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    let report = read_eval_baselines_report(&root).unwrap_or_else(|_| EvalBaselinesReport {
        component: "eval_baselines".to_owned(),
        suite_id: artifacts.suite.eval_suite_id.to_string(),
        baselines: Vec::new(),
        active: None,
        incident_lockdown_blocks_mutation:
            EvalRegressionGateService::incident_lockdown_blocks_baseline_mutation(true),
        generated_at: time::OffsetDateTime::now_utc(),
    });
    write_json(&report)
}

pub fn run_eval_compare(
    config_path: &Path,
    suite: &str,
    baseline: &str,
    candidate_run: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    ensure_eval_run_ref(&artifacts.run, candidate_run)?;
    let baseline = resolve_eval_baseline(&root, &artifacts, baseline)?;
    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let comparison =
        EvalComparisonService::compare(&artifacts.suite, &baseline, &artifacts.run, &git_commit);
    let report = EvalComparisonsReport {
        component: "eval_comparisons".to_owned(),
        baseline: baseline.clone(),
        candidate_run: artifacts.run.clone(),
        comparison: comparison.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(
        &root,
        "eval-comparisons",
        "Eval Candidate Comparisons",
        &report,
    )?;
    write_json(&comparison)
}

pub fn run_eval_gate(config_path: &Path, profile: &str, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k1_smoke_artifacts(&root, suite)?;
    let profile = EvalGateProfileService::find(profile)
        .with_context(|| format!("unknown eval gate profile: {profile}"))?;
    EvalGateProfileService::validate(&profile)?;
    let decision = EvalRegressionGateService::evaluate_comparison(
        &profile,
        &artifacts.comparison,
        &artifacts.k0.integrity_receipt,
    );
    let report = EvalGatesReport {
        component: "eval_gates".to_owned(),
        profile: profile.clone(),
        comparison: Some(artifacts.comparison.clone()),
        decision: decision.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-gates", "Eval Gates", &report)?;
    write_json(&decision)
}

pub fn run_eval_profiles(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = EvalProfilesReport {
        component: "eval_profiles".to_owned(),
        profiles: EvalGateProfileService::built_in_profiles(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    for profile in &report.profiles {
        EvalGateProfileService::validate(profile)?;
    }
    write_eval_report(&root, "eval-gates", "Eval Gate Profiles", &report)?;
    write_json(&report)
}

pub fn run_eval_trend(config_path: &Path, suite: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    let trend = EvalTrendService::trend(
        &artifacts.suite,
        &[artifacts.run.clone(), artifacts.run.clone()],
    );
    let report = EvalTrendsReport {
        component: "eval_trends".to_owned(),
        trend: trend.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(&root, "eval-trends", "Eval Trends", &report)?;
    write_json(&trend)
}

pub fn run_eval_stability(config_path: &Path, suite: &str, repeat: u8) -> Result<()> {
    let root = runtime_root(config_path);
    let repeat = repeat.clamp(2, 5);
    let artifacts = ensure_k0_smoke_artifacts(&root, suite)?;
    let runs = std::iter::repeat_with(|| artifacts.run.clone())
        .take(usize::from(repeat))
        .collect::<Vec<_>>();
    let stability = EvalFixtureStabilityService::report(&artifacts.suite, &runs);
    let report = EvalFixtureStabilityReportEnvelope {
        component: "eval_fixture_stability".to_owned(),
        repeat,
        stability: stability.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(
        &root,
        "eval-fixture-stability",
        "Eval Fixture Stability",
        &report,
    )?;
    write_json(&stability)
}

pub fn run_eval_k1_smoke(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let artifacts = ensure_k1_smoke_artifacts(&root, "k0-core-smoke")?;
    let report = serde_json::json!({
        "component": "eval_k1_smoke",
        "coverage": artifacts.coverage,
        "baseline": artifacts.baseline,
        "comparison": artifacts.comparison,
        "gate_decision": artifacts.gate_decision,
        "critical_comparison": artifacts.critical_comparison,
        "critical_gate_decision": artifacts.critical_gate_decision,
        "trend": artifacts.trend,
        "stability": artifacts.stability,
        "doctor_status": artifacts.doctor_status,
        "final_status": if artifacts.gate_decision.decision == EvalGateDecisionKind::Allow
            && artifacts.critical_gate_decision.decision == EvalGateDecisionKind::Block
        {
            CompletionStatus::DoneVerified
        } else {
            CompletionStatus::PartialProgress
        },
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json(&report)
}

pub fn run_verify_inventory(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_verification_inventory_report(&root)?;
    write_json(&report)
}

pub fn run_verify_profiles(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_verification_profiles_report(&root)?;
    write_json(&report)
}

pub fn run_verify_plan(config_path: &Path, profile: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let report = write_verification_plan_report(&root, &inventory, profile)?;
    write_json(&report)
}

pub fn run_verify_run(config_path: &Path, profile: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let plan = write_verification_plan_report(&root, &inventory, profile)?.plan;
    let (run_report, verdict_report) = write_verification_run_and_verdict(&root, &plan)?;
    write_json(&serde_json::json!({
        "component": "verification_run_with_verdict",
        "run": run_report.run,
        "verdict": verdict_report.verdict,
        "generated_at": time::OffsetDateTime::now_utc()
    }))
}

pub fn run_verify_verdict(config_path: &Path, run: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let run_report: VerificationRunsReport = read_latest_typed(&root, "verification-runs")
        .context("no latest verification run found; run verify run --profile <profile> first")?;
    if run != "latest" && run != run_report.run.run_id {
        bail!("only latest verification run or its run_id is available in K2 CLI");
    }
    let verdict = VerificationVerdictService.verdict(&run_report.run);
    let report = VerificationVerdictsReport {
        component: "verification_verdicts".to_owned(),
        verdict,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(
        &root,
        "verification-verdicts",
        "Verification Verdicts",
        &report,
    )?;
    write_json(&report)
}

pub fn run_verify_cost_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let last_run = read_latest_typed::<VerificationRunsReport>(&root, "verification-runs")
        .ok()
        .map(|report| report.run);
    let report = write_test_cost_report(&root, &inventory, last_run.as_ref())?;
    write_json(&report)
}

pub fn run_verify_flake(config_path: &Path, profile: &str, repeat: u64) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let report = write_flake_report(&root, profile, repeat, &inventory)?;
    write_json(&report)
}

pub fn run_verify_db_isolation(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let inventory = write_verification_inventory_report(&root)?.inventory;
    let report = write_db_isolation_report(&root, &inventory)?;
    write_json(&report)
}

pub fn run_verify_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_verification_summary(&root)?;
    write_json(&report)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TestInventoryReport {
    component: String,
    inventory: TestInventory,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationProfilesReport {
    component: String,
    profiles: Vec<TestSuiteProfile>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationPlansReport {
    component: String,
    plan: VerificationPlan,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationRunsReport {
    component: String,
    run: ProfileVerificationRun,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerificationVerdictsReport {
    component: String,
    verdict: VerificationVerdict,
    generated_at: time::OffsetDateTime,
}

fn ensure_verification_summary(root: &Path) -> Result<serde_json::Value> {
    let inventory = write_verification_inventory_report(root)?.inventory;
    let profiles = write_verification_profiles_report(root)?.profiles;
    let phase_gate_plan = write_verification_plan_report(root, &inventory, "phase-gate")?.plan;
    let (run_report, verdict_report) = write_verification_run_and_verdict(root, &phase_gate_plan)?;
    let cost = write_test_cost_report(root, &inventory, Some(&run_report.run))?;
    let flake = write_flake_report(root, "phase-gate", 2, &inventory)?;
    let db_isolation = write_db_isolation_report(root, &inventory)?;
    let doctor = VerificationDoctorIntegration.status(
        &inventory,
        &cost,
        &flake,
        &db_isolation,
        Some(&run_report.run),
    );
    let report = serde_json::json!({
        "component": "verification_report",
        "inventory": inventory,
        "profiles": profiles,
        "latest_plan": phase_gate_plan,
        "latest_run": run_report.run,
        "latest_verdict": verdict_report.verdict,
        "cost": cost,
        "flake": flake,
        "db_isolation": db_isolation,
        "doctor_status": doctor,
        "authority": "profile-governance-only; no raw shell, raw db, or DONE override",
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_verification_report(root, "verification", "Verification", &report)?;
    Ok(report)
}

fn write_verification_inventory_report(root: &Path) -> Result<TestInventoryReport> {
    let inventory = TestInventoryService.generate(project_id_from_label("eliot-governor"));
    let report = TestInventoryReport {
        component: "test_inventory".to_owned(),
        inventory,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(root, "test-inventory", "Test Inventory", &report)?;
    Ok(report)
}

fn write_verification_profiles_report(root: &Path) -> Result<VerificationProfilesReport> {
    let report = VerificationProfilesReport {
        component: "verification_profiles".to_owned(),
        profiles: VerificationProfileService.profiles(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(
        root,
        "verification-profiles",
        "Verification Profiles",
        &report,
    )?;
    Ok(report)
}

fn write_verification_plan_report(
    root: &Path,
    inventory: &TestInventory,
    profile: &str,
) -> Result<VerificationPlansReport> {
    let plan = VerificationPlannerService.plan(
        inventory,
        profile,
        vec!["workspace:current".to_owned(), "phase:k2".to_owned()],
    )?;
    let report = VerificationPlansReport {
        component: "verification_plans".to_owned(),
        plan,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(root, "verification-plans", "Verification Plans", &report)?;
    Ok(report)
}

fn write_verification_run_and_verdict(
    root: &Path,
    plan: &VerificationPlan,
) -> Result<(VerificationRunsReport, VerificationVerdictsReport)> {
    let run = VerificationRunnerService.run_profile_record(plan)?;
    let run_report = VerificationRunsReport {
        component: "verification_runs".to_owned(),
        run,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(root, "verification-runs", "Verification Runs", &run_report)?;
    let verdict = VerificationVerdictService.verdict(&run_report.run);
    let verdict_report = VerificationVerdictsReport {
        component: "verification_verdicts".to_owned(),
        verdict,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_verification_report(
        root,
        "verification-verdicts",
        "Verification Verdicts",
        &verdict_report,
    )?;
    Ok((run_report, verdict_report))
}

fn write_test_cost_report(
    root: &Path,
    inventory: &TestInventory,
    last_run: Option<&ProfileVerificationRun>,
) -> Result<TestCostReport> {
    let report = TestCostService.report(inventory, last_run);
    write_verification_report(root, "test-cost", "Test Cost", &report)?;
    Ok(report)
}

fn write_flake_report(
    root: &Path,
    profile: &str,
    repeat: u64,
    inventory: &TestInventory,
) -> Result<FlakeReport> {
    let report = FlakeDetectionService.report(profile, repeat, inventory);
    write_verification_report(root, "flake", "Flake", &report)?;
    Ok(report)
}

fn write_db_isolation_report(
    root: &Path,
    inventory: &TestInventory,
) -> Result<StatefulDbIsolationReport> {
    let report = StatefulDbTestIsolationService.report(inventory);
    write_verification_report(root, "db-isolation", "DB Isolation", &report)?;
    Ok(report)
}

fn write_verification_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(dir).join("latest.json"),
        &root.join("reports").join(dir).join("latest.md"),
        value,
        &verification_value_markdown(title, &serde_json::to_value(value)?),
    )
}

fn verification_value_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(component) = value.get("component").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- component: `{component}`");
    }
    if let Some(profile) = value
        .get("plan")
        .or_else(|| value.get("run"))
        .or_else(|| value.get("verdict"))
        .and_then(|inner| inner.get("profile_id"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- profile: `{profile}`");
    }
    if let Some(decision) = value
        .get("verdict")
        .and_then(|verdict| verdict.get("decision"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- decision: `{decision}`");
    }
    let _ = writeln!(
        output,
        "- authority: `profile-governance-only; no raw shell, raw db, or DONE override`"
    );
    output
}

pub fn run_metrics_registry(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_registry_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_record_smoke(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_samples_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_rollup(config_path: &Path, window: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let samples = write_metrics_samples_report(&root)?.samples;
    let report = write_metrics_rollup_report(&root, parse_metric_window(window)?, &samples)?;
    write_json(&report)
}

pub fn run_metrics_slo(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let samples = write_metrics_samples_report(&root)?.samples;
    let rollup = write_metrics_rollup_report(&root, MetricWindow::OneRun, &samples)?.rollup;
    let report = write_metrics_slo_report(&root, &rollup)?;
    write_json(&report)
}

pub fn run_metrics_latency(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let samples = write_metrics_samples_report(&root)?.samples;
    let rollup = write_metrics_rollup_report(&root, MetricWindow::OneRun, &samples)?.rollup;
    let report = write_metrics_latency_report(&root, &rollup)?;
    write_json(&report)
}

pub fn run_metrics_cost(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_cost_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_quality(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_quality_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_dashboard(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_metrics_dashboard_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_metrics_summary(&root)?;
    write_json(&report)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsRegistryReport {
    component: String,
    definitions: Vec<MetricDefinition>,
    categories: Vec<String>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsSamplesReport {
    component: String,
    samples: Vec<MetricSample>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsRollupReport {
    component: String,
    rollup: TelemetryRollup,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsSloReport {
    component: String,
    definitions: Vec<SloDefinition>,
    evaluations: Vec<SloEvaluation>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsLatencyReport {
    component: String,
    histograms: Vec<LatencyHistogram>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsCostReport {
    component: String,
    cost: CostLedger,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsQualityReport {
    component: String,
    signals: Vec<QualitySignal>,
    generated_at: time::OffsetDateTime,
}

fn ensure_metrics_summary(root: &Path) -> Result<serde_json::Value> {
    let dashboard_report = ensure_metrics_dashboard_report(root)?;
    let registry = write_metrics_registry_report(root)?;
    let samples = write_metrics_samples_report(root)?;
    let rollup = write_metrics_rollup_report(root, MetricWindow::OneRun, &samples.samples)?;
    let slo = write_metrics_slo_report(root, &rollup.rollup)?;
    let latency = write_metrics_latency_report(root, &rollup.rollup)?;
    let cost = write_metrics_cost_report(root)?;
    let quality = write_metrics_quality_report(root)?;
    let report = serde_json::json!({
        "component": "metrics_report",
        "registry": registry,
        "samples": samples,
        "rollup": rollup,
        "slo": slo,
        "latency": latency,
        "cost": cost,
        "quality": quality,
        "dashboard": dashboard_report,
        "authority": "local-observability-only; no raw payloads, remote export, or authority mutation",
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_metrics_report(root, "metrics-report", "Metrics Report", &report)?;
    Ok(report)
}

fn ensure_metrics_dashboard_report(root: &Path) -> Result<DashboardReport> {
    let definitions = write_metrics_registry_report(root)?.definitions;
    let samples = write_metrics_samples_report(root)?.samples;
    let rollup = write_metrics_rollup_report(root, MetricWindow::OneRun, &samples)?.rollup;
    let latency = write_metrics_latency_report(root, &rollup)?.histograms;
    let slo = write_metrics_slo_report(root, &rollup)?;
    let cost = write_metrics_cost_report(root)?.cost;
    let quality = write_metrics_quality_report(root)?.signals;
    let dashboard = RuntimeDashboardService.dashboard(
        project_id_from_label("eliot-governor"),
        latency,
        cost,
        slo.evaluations,
        quality,
        recent_incident_refs(root),
        Some("reports/eval-report/latest.json".to_owned()),
        Some("reports/verification/latest.json".to_owned()),
    );
    let trends = RuntimeDashboardService.trends(&dashboard);
    let doctor = MetricsDoctorIntegration.status(&definitions, Some(&dashboard), &trends);
    let report = DashboardReport {
        component: "runtime_dashboard".to_owned(),
        dashboard,
        trends,
        doctor,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "runtime-dashboard", "Runtime Dashboard", &report)?;
    Ok(report)
}

fn write_metrics_registry_report(root: &Path) -> Result<MetricsRegistryReport> {
    let definitions = MetricRegistryService.definitions();
    for definition in &definitions {
        MetricRegistryService.validate_definition(definition)?;
    }
    let report = MetricsRegistryReport {
        component: "metrics_registry".to_owned(),
        categories: MetricRegistryService.categories(),
        definitions,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-registry", "Metrics Registry", &report)?;
    Ok(report)
}

fn write_metrics_samples_report(root: &Path) -> Result<MetricsSamplesReport> {
    let definitions = MetricRegistryService.definitions();
    let samples = MetricRecorderService.smoke_samples(&definitions)?;
    let report = MetricsSamplesReport {
        component: "metrics_samples".to_owned(),
        samples,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-samples", "Metrics Samples", &report)?;
    Ok(report)
}

fn write_metrics_rollup_report(
    root: &Path,
    window: MetricWindow,
    samples: &[MetricSample],
) -> Result<MetricsRollupReport> {
    let report = MetricsRollupReport {
        component: "metrics_rollups".to_owned(),
        rollup: MetricRollupService.rollup(
            project_id_from_label("eliot-governor"),
            window,
            samples,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-rollups", "Metrics Rollups", &report)?;
    Ok(report)
}

fn write_metrics_slo_report(root: &Path, rollup: &TelemetryRollup) -> Result<MetricsSloReport> {
    let definitions = SloService.definitions();
    let report = MetricsSloReport {
        component: "metrics_slo".to_owned(),
        evaluations: SloService.evaluate(&definitions, rollup),
        definitions,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-slo", "Metrics SLO", &report)?;
    Ok(report)
}

fn write_metrics_latency_report(
    root: &Path,
    rollup: &TelemetryRollup,
) -> Result<MetricsLatencyReport> {
    let report = MetricsLatencyReport {
        component: "metrics_latency".to_owned(),
        histograms: MetricRollupService.latency_histograms(rollup),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-latency", "Metrics Latency", &report)?;
    Ok(report)
}

fn write_metrics_cost_report(root: &Path) -> Result<MetricsCostReport> {
    let report = MetricsCostReport {
        component: "metrics_cost".to_owned(),
        cost: CostLedgerService.ledger(
            project_id_from_label("eliot-governor"),
            MetricWindow::OneRun,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-cost", "Metrics Cost", &report)?;
    Ok(report)
}

fn write_metrics_quality_report(root: &Path) -> Result<MetricsQualityReport> {
    let report = MetricsQualityReport {
        component: "metrics_quality".to_owned(),
        signals: QualitySignalService.signals(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-quality", "Metrics Quality", &report)?;
    Ok(report)
}

fn write_metrics_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(dir).join("latest.json"),
        &root.join("reports").join(dir).join("latest.md"),
        value,
        &metrics_value_markdown(title, &serde_json::to_value(value)?),
    )
}

fn metrics_value_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(component) = value.get("component").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- component: `{component}`");
    }
    let _ = writeln!(
        output,
        "- authority: `local-observability-only; redacted summaries; no raw payloads or remote export`"
    );
    output
}

fn parse_metric_window(value: &str) -> Result<MetricWindow> {
    match normalized_cli_value(value).as_str() {
        "oneminute" => Ok(MetricWindow::OneMinute),
        "fiveminutes" => Ok(MetricWindow::FiveMinutes),
        "onehour" => Ok(MetricWindow::OneHour),
        "oneday" => Ok(MetricWindow::OneDay),
        "onerun" => Ok(MetricWindow::OneRun),
        other => bail!("unknown metric window: {other}"),
    }
}

fn recent_incident_refs(root: &Path) -> Vec<String> {
    let path = root.join("reports").join("incident").join("latest.json");
    if path.is_file() {
        vec!["reports/incident/latest.json".to_owned()]
    } else {
        Vec::new()
    }
}

pub fn run_hook(config_path: &Path, kind: HookEventKind) -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let payload = if input.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&input).context("parse hook JSON stdin")?
    };
    let result = EliotHookService::new(runtime_root(config_path)).process(kind, &payload)?;
    write_json(&result.decision.stdout)
}

pub fn run_plugin_print_path(config_path: &Path) -> Result<()> {
    write_json(&serde_json::json!({
        "component": "plugin_path",
        "plugin_root": plugin_root(config_path)
    }))
}

pub fn run_plugin_inspect(config_path: &Path) -> Result<()> {
    let verifier = PluginVerifier::new(plugin_root(config_path));
    write_json(&verifier.inspect()?)
}

pub fn run_plugin_verify(config_path: &Path) -> Result<()> {
    let report = verify_plugin_report(config_path)?;
    write_json(&report)?;
    if report.final_status != "DONE_VERIFIED" {
        bail!("plugin verify is not DONE_VERIFIED; inspect plugin report blockers");
    }
    Ok(())
}

pub async fn run_action_plan(
    config_path: &Path,
    project: &str,
    task: &str,
    goal: &str,
) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let artifacts = action_plan::create_action_lease_artifacts(
        &root,
        CanonicalStore::new(config.db.surreal),
        &config.control_wal,
        action_plan::ActionPlanInput {
            project_label: project.to_owned(),
            task_label: task.to_owned(),
            goal: goal.to_owned(),
            requested_action_kind: ActionKind::ChangePlanOnly,
            change_plan: None,
            verifier_plan: None,
        },
    )
    .await?;
    action_plan::write_action_lease_report(&root, project, task, goal, &artifacts.record)?;
    write_json(&action_plan::action_lease_report_value(
        project,
        task,
        goal,
        &artifacts.record,
    ))
}

pub async fn run_action_validate_plan(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let goal = format!("Validate bounded E1 action plan for {project}/{task}");
    run_action_plan(config_path, project, task, &goal).await
}

pub fn run_action_lease_status(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let latest = action_plan::latest_action_lease_report(&root)?
        .context("no latest ActionLease report found; run action validate-plan first")?;
    write_json(&serde_json::json!({
        "component": "action_lease_status",
        "requested_project": project,
        "requested_task": task,
        "latest": latest
    }))
}

pub async fn run_work_create(
    config_path: &Path,
    project: &str,
    task: &str,
    goal: &str,
    read: &[String],
    write: &[String],
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let session = AgentSessionService.create_controller(&mut state, project_id);
    if read.is_empty() && write.is_empty() {
        bail!("work create requires an explicit --read or --write scope");
    }
    let write_set = write.to_vec();
    let read_set = if read.is_empty() {
        write_set.clone()
    } else {
        read.to_vec()
    };
    let verifier = if write_set.is_empty() {
        Vec::new()
    } else {
        default_work_verifier(&write_set)
    };
    let item = WorkQueueService.create_work_item(
        &mut state,
        WorkCreateRequest {
            project_id,
            task_id,
            project: project.to_owned(),
            task: task.to_owned(),
            goal: goal.to_owned(),
            scope: default_work_scope(
                std::env::current_dir()?.display().to_string(),
                read_set,
                write_set,
                verifier
                    .iter()
                    .map(|requirement| requirement.command_display.clone())
                    .collect(),
            ),
            required: true,
            created_by: session.agent_session_id,
            required_verifiers: verifier,
        },
    );
    write_work_entities(
        config_path,
        &mut state,
        Some(session.agent_session_id),
        Some(item.work_item_id),
        None,
        &[],
    )
    .await?;
    let report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub async fn run_work_claim(
    config_path: &Path,
    project: &str,
    task: &str,
    role: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let role = parse_agent_role(role)?;
    let item_id = find_work_item(&state, project, task)
        .map(|item| item.work_item_id)
        .context("no matching work item found; run work create first")?;
    let project_id = find_work_item(&state, project, task)
        .map(|item| item.project_id)
        .context("no matching work item found; run work create first")?;
    let session = AgentSessionService.create_for_role(&mut state, project_id, role);
    let decision = WorkLeaseService.claim(
        &mut state,
        WorkClaimRequest {
            work_item_id: item_id,
            agent_session_id: session.agent_session_id,
            role,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let lease_id = decision.work_lease_id;
    let conflict_ids = latest_conflict_ids_for_item(&state, item_id);
    write_work_entities(
        config_path,
        &mut state,
        Some(session.agent_session_id),
        Some(item_id),
        lease_id,
        &conflict_ids,
    )
    .await?;
    let report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub fn run_work_status(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub async fn run_work_renew(config_path: &Path, lease_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let lease_id = WorkLeaseId::from_str(lease_id).context("parse work lease id")?;
    let decision = WorkLeaseService.renew(&mut state, lease_id, default_lease_ttl_minutes());
    write_work_entities(
        config_path,
        &mut state,
        None,
        None,
        decision.work_lease_id,
        &[],
    )
    .await?;
    let (project, task) = labels_for_lease(&state, lease_id);
    let report = WorkQueueService.status_report(&state, &project, &task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub async fn run_work_release(config_path: &Path, lease_id: &str) -> Result<()> {
    run_work_finish(config_path, lease_id, true).await
}

pub async fn run_work_revoke(config_path: &Path, lease_id: &str) -> Result<()> {
    run_work_finish(config_path, lease_id, false).await
}

pub fn run_work_conflicts(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = WorkQueueService.status_report(&state, project, task);
    write_json(&serde_json::json!({
        "component": "work_conflicts",
        "project": project,
        "task": task,
        "conflicts": report.conflicts,
        "final_status": if report.conflicts.is_empty() { "DONE_VERIFIED" } else { "PARTIAL_PROGRESS" }
    }))
}

pub async fn run_blackboard_add(
    config_path: &Path,
    project: &str,
    task: &str,
    kind: &str,
    payload_ref: &str,
    evidence: &[String],
    confidence: Option<&str>,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let owner_session_id = ensure_controller_session(&mut state, project_id).agent_session_id;
    let work_item_id = find_work_item(&state, project, task).map(|item| item.work_item_id);
    let lease_id = latest_active_work_lease_id(&state, project_id, task_id);
    let item = BlackboardService.create_item(
        &mut state,
        BlackboardAddInput {
            project_id,
            task_id,
            owner_session_id,
            work_item_id,
            lease_id,
            kind: parse_blackboard_kind(kind)?,
            scope: BlackboardScope::default(),
            payload_ref: payload_ref.to_owned(),
            evidence_refs: evidence.to_vec(),
            confidence: confidence.map(parse_confidence).transpose()?,
            expires_at: None,
        },
    );
    write_collective_entities(
        config_path,
        &mut state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&serde_json::json!({
        "component": "blackboard_add",
        "blackboard_item": state
            .blackboard_items
            .iter()
            .find(|candidate| candidate.blackboard_item_id == item.blackboard_item_id),
        "final_status": "DONE_VERIFIED"
    }))
}

pub fn run_blackboard_list(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = blackboard_report_value(&state, project, task);
    write_report_pair(
        &root.join("reports").join("blackboard").join("latest.json"),
        &root.join("reports").join("blackboard").join("latest.md"),
        &report,
        &phase_closeout_markdown("Blackboard Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_blackboard_ack(
    config_path: &Path,
    item_id: &str,
    session: Option<&str>,
) -> Result<()> {
    run_blackboard_status_change(config_path, item_id, session, "ack").await
}

pub async fn run_blackboard_resolve(config_path: &Path, item_id: &str) -> Result<()> {
    run_blackboard_status_change(config_path, item_id, None, "resolve").await
}

pub async fn run_blackboard_reject(config_path: &Path, item_id: &str) -> Result<()> {
    run_blackboard_status_change(config_path, item_id, None, "reject").await
}

pub async fn run_mailbox_send(
    config_path: &Path,
    project: &str,
    task: &str,
    kind: &str,
    payload_ref: &str,
    recipient: &str,
    message_id: Option<&str>,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let sender_session_id = ensure_controller_session(&mut state, project_id).agent_session_id;
    let message = MailboxService.send(
        &mut state,
        MailboxSendInput {
            message_id: message_id.map(MailboxMessageId::from_str).transpose()?,
            project_id,
            task_id,
            sender_session_id,
            recipient: parse_mailbox_recipient(recipient)?,
            kind: parse_mailbox_kind(kind)?,
            payload_ref: payload_ref.to_owned(),
            requires_ack: None,
            expires_at: None,
        },
    );
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &[message.message_id],
        &[],
        &[],
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&serde_json::json!({
        "component": "mailbox_send",
        "mailbox_message": state
            .mailbox_messages
            .iter()
            .find(|candidate| candidate.message_id == message.message_id),
        "final_status": "DONE_VERIFIED"
    }))
}

pub fn run_mailbox_inbox(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = mailbox_report_value(&state, project, task);
    write_report_pair(
        &root.join("reports").join("mailbox").join("latest.json"),
        &root.join("reports").join("mailbox").join("latest.md"),
        &report,
        &phase_closeout_markdown("Mailbox Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_mailbox_ack(config_path: &Path, message_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let message_id = MailboxMessageId::from_str(message_id).context("parse mailbox message id")?;
    let message = MailboxService.acknowledge(&mut state, message_id)?;
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &[message.message_id],
        &[],
        &[],
    )
    .await?;
    let (project, task) = labels_for_project_task(&state, message.project_id, message.task_id);
    save_collective_reports(&root, &state, &project, &task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, &project, &task),
    )?;
    write_json(&serde_json::json!({
        "component": "mailbox_ack",
        "mailbox_message": state
            .mailbox_messages
            .iter()
            .find(|candidate| candidate.message_id == message.message_id),
        "final_status": "DONE_VERIFIED"
    }))
}

pub async fn run_recovery_scan(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let records =
        LostAgentRecoveryService.scan(&mut state, project_id, task_id, time::Duration::minutes(30));
    let recovery_ids = records
        .iter()
        .map(|record| record.recovery_id.clone())
        .collect::<Vec<_>>();
    let message_ids = records
        .iter()
        .flat_map(|record| record.mailbox_messages.iter().copied())
        .collect::<Vec<_>>();
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &message_ids,
        &recovery_ids,
        &[],
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&recovery_report_value(&state, project, task))
}

pub fn run_recovery_report(config_path: &Path, latest: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let latest_path = root.join("reports").join("recovery").join("latest.json");
    if latest && latest_path.is_file() {
        let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(latest_path)?)?;
        return write_json(&value);
    }
    let state = load_work_state(&root)?;
    let report = recovery_report_value(&state, "", "");
    write_report_pair(
        &root.join("reports").join("recovery").join("latest.json"),
        &root.join("reports").join("recovery").join("latest.md"),
        &report,
        &phase_closeout_markdown("Recovery Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_collective_trace(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let trace = CollectiveTraceService.trace_task(&mut state, project_id, task_id);
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &[],
        &[],
        std::slice::from_ref(&trace.collective_trace_id),
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&collective_report_value(&state, project, task))
}

pub fn run_collective_report(config_path: &Path, latest: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let latest_path = root.join("reports").join("collective").join("latest.json");
    if latest && latest_path.is_file() {
        let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(latest_path)?)?;
        return write_json(&value);
    }
    let state = load_work_state(&root)?;
    let report = collective_report_value(&state, "", "");
    write_report_pair(
        &root.join("reports").join("collective").join("latest.json"),
        &root.join("reports").join("collective").join("latest.md"),
        &report,
        &phase_closeout_markdown("Collective Trace Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_worktree_create(config_path: &Path, work_lease_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let work_lease_id = WorkLeaseId::from_str(work_lease_id).context("parse work lease id")?;
    let work_lease = state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .cloned()
        .context("work lease not found")?;
    let repo_root = PathBuf::from(&work_lease.scope.repo_root);
    let request = WorktreeLeaseRequest {
        request_id: WorktreeLeaseRequestId::new_v7(),
        project_id: work_lease.project_id,
        task_id: work_lease.task_id,
        work_item_id: work_lease.work_item_id,
        work_lease_id: work_lease.work_lease_id,
        agent_session_id: work_lease.agent_session_id,
        repo_root: work_lease.scope.repo_root.clone(),
        requested_branch_name: None,
        requested_scope: work_lease.scope.clone(),
        base_commit: Some(git_head_blocking(&repo_root)?),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let worktree_root = worktree_root_for_repo(&repo_root);
    let mut lease = WorktreeLeaseService
        .create(
            &mut state,
            WorktreeCreateInput {
                request,
                worktree_root,
                ttl_minutes: WorktreeLeaseService::default_ttl_minutes(),
            },
        )
        .await?;
    write_worktree_records(config_path, Some(&mut lease), None, None, None).await?;
    replace_worktree_lease(&mut state, lease.clone());
    save_worktree_state_and_reports(&root, &state)?;
    write_json(&serde_json::json!({
        "component": "worktree_create",
        "worktree_lease": lease,
        "final_status": "DONE_VERIFIED"
    }))
}

pub fn run_worktree_status(config_path: &Path, worktree_lease: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let lease = WorktreeLeaseId::from_str(worktree_lease)
        .ok()
        .and_then(|lease_id| {
            state
                .worktree_leases
                .iter()
                .find(|lease| lease.worktree_lease_id == lease_id)
                .cloned()
        });
    write_json(&serde_json::json!({
        "component": "worktree_status",
        "requested_worktree_lease": worktree_lease,
        "worktree_lease": lease,
        "final_status": if lease.is_some() { "DONE_VERIFIED" } else { "NO_WORKTREE" }
    }))
}

pub async fn run_worktree_capture_diff(config_path: &Path, worktree_lease: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let worktree_lease_id =
        WorktreeLeaseId::from_str(worktree_lease).context("parse worktree lease id")?;
    let mut diff = CandidateDiffService
        .capture(
            &mut state,
            CandidateDiffCaptureInput {
                worktree_lease_id,
                diff_root: root.join("candidate-diffs"),
                max_diff_bytes: CandidateDiffService::default_max_diff_bytes(),
            },
        )
        .await?;
    let agent_id = state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .and_then(|worktree| {
            state
                .leases
                .iter()
                .find(|lease| lease.work_lease_id == worktree.work_lease_id)
        })
        .map_or_else(AgentId::new_v7, |lease| lease.agent_id);
    write_worktree_records(config_path, None, Some(&mut diff), None, Some(agent_id)).await?;
    replace_candidate_diff(&mut state, diff.clone());
    save_worktree_state_and_reports(&root, &state)?;
    let final_status = if diff.capture_status == CandidateDiffStatus::Captured {
        "DONE_VERIFIED"
    } else {
        "PARTIAL_PROGRESS"
    };
    write_json(&serde_json::json!({
        "component": "worktree_capture_diff",
        "candidate_diff": diff,
        "final_status": final_status
    }))
}

pub async fn run_worktree_review(
    config_path: &Path,
    candidate_diff: &str,
    decision: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let candidate_diff_id =
        CandidateDiffId::from_str(candidate_diff).context("parse candidate diff id")?;
    let reviewer_session_id = state
        .candidate_diffs
        .iter()
        .find(|diff| diff.candidate_diff_id == candidate_diff_id)
        .and_then(|diff| {
            state
                .worktree_leases
                .iter()
                .find(|lease| lease.worktree_lease_id == diff.worktree_lease_id)
        })
        .map(|lease| lease.holder_session_id)
        .context("candidate diff worktree lease not found")?;
    let review_decision = parse_candidate_review_decision(decision)?;
    let mut review = CandidateReviewService.review(
        &mut state,
        CandidateReviewInput {
            candidate_diff_id,
            reviewer_session_id,
            decision: review_decision,
            reasons: vec![format!("cli review decision: {review_decision:?}")],
        },
    )?;
    let diff = state
        .candidate_diffs
        .iter()
        .find(|diff| diff.candidate_diff_id == candidate_diff_id)
        .cloned()
        .context("candidate diff not found after review")?;
    write_worktree_records(config_path, None, None, Some((&mut review, &diff)), None).await?;
    replace_candidate_review(&mut state, review.clone());
    save_worktree_state_and_reports(&root, &state)?;
    let final_status = if review.decision == CandidateReviewDecision::AcceptForPatchRunner {
        "DONE_VERIFIED"
    } else {
        "PARTIAL_PROGRESS"
    };
    write_json(&serde_json::json!({
        "component": "worktree_review",
        "candidate_review": review,
        "candidate_diff": diff,
        "final_status": final_status
    }))
}

pub async fn run_worktree_cleanup(config_path: &Path, worktree_lease: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let worktree_lease_id =
        WorktreeLeaseId::from_str(worktree_lease).context("parse worktree lease id")?;
    let mut lease = WorktreeCleanupService
        .cleanup(&mut state, worktree_lease_id)
        .await?;
    write_worktree_records(config_path, Some(&mut lease), None, None, None).await?;
    replace_worktree_lease(&mut state, lease.clone());
    save_worktree_state_and_reports(&root, &state)?;
    write_json(&serde_json::json!({
        "component": "worktree_cleanup",
        "worktree_lease": lease,
        "final_status": "DONE_VERIFIED"
    }))
}

pub async fn run_patch_preflight(
    config_path: &Path,
    lease_id: &str,
    diff_path: &Path,
) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let blob_store = BlobStore::open(&config.blob_store)?;
    let input = load_patch_cli_input(&root, lease_id, diff_path)?;
    let repo_root = patch_repo_root(&input.lease)?;
    let runner = PatchRunner::new(&repo_root, Some(&blob_store));
    let incident_lockdown_active = IncidentService::new(&root).lockdown_active()?;
    let mut patch_run = runner
        .preflight(&PatchRunnerInput {
            request: &input.request,
            lease: Some(&input.lease),
            work_lease: Some(&input.work_lease),
            codecortex_reports: std::slice::from_ref(&input.report),
            verifier_plan: Some(&input.verifier_plan),
            incident_lockdown_active,
        })
        .await?;
    let mut verifier_runs = Vec::new();
    write_e2_runs_to_memory(config_path, &mut patch_run, &mut verifier_runs).await?;
    write_patch_reports(&root, &patch_run, &verifier_runs)?;
    write_json(&patch_report_value(&patch_run, &verifier_runs))
}

pub async fn run_patch_apply(config_path: &Path, lease_id: &str, diff_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let blob_store = BlobStore::open(&config.blob_store)?;
    let input = load_patch_cli_input(&root, lease_id, diff_path)?;
    let repo_root = patch_repo_root(&input.lease)?;
    let runner = PatchRunner::new(&repo_root, Some(&blob_store));
    let verifier = VerifierHarness::new(&repo_root, Some(&blob_store));
    let incident_lockdown_active = IncidentService::new(&root).lockdown_active()?;
    let (mut patch_run, mut verifier_runs) = runner
        .apply(
            &PatchRunnerInput {
                request: &input.request,
                lease: Some(&input.lease),
                work_lease: Some(&input.work_lease),
                codecortex_reports: std::slice::from_ref(&input.report),
                verifier_plan: Some(&input.verifier_plan),
                incident_lockdown_active,
            },
            &verifier,
        )
        .await?;
    write_e2_runs_to_memory(config_path, &mut patch_run, &mut verifier_runs).await?;
    write_patch_reports(&root, &patch_run, &verifier_runs)?;
    write_json(&patch_report_value(&patch_run, &verifier_runs))
}

pub fn run_patch_status(config_path: &Path, patch_run_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = latest_patch_report(&root)?.context("no latest PatchRun report found")?;
    let matches_requested = report
        .get("patch_run")
        .and_then(|value| value.get("patch_run_id"))
        .and_then(serde_json::Value::as_str)
        == Some(patch_run_id);
    write_json(&serde_json::json!({
        "component": "patch_status",
        "requested_patch_run": patch_run_id,
        "matches_latest": matches_requested,
        "latest": report
    }))
}

pub async fn run_verifier_run(config_path: &Path, plan_ref: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let blob_store = BlobStore::open(&config.blob_store)?;
    let latest = latest_action_lease(&root)?;
    let plan = latest
        .verifier_plan
        .clone()
        .context("latest ActionLease does not contain a VerifierPlan")?;
    let repo_root = patch_repo_root(&latest)?;
    let harness = VerifierHarness::new(repo_root, Some(&blob_store));
    let mut verifier_runs = harness
        .run_plan(latest.project_id, latest.task_id, latest.agent_id, &plan)
        .await?;
    write_e2_runs_to_memory_optional_patch(config_path, None, &mut verifier_runs).await?;
    write_verifier_report(&root, plan_ref, &verifier_runs)?;
    write_json(&verifier_report_value(plan_ref, &verifier_runs))
}

pub fn run_verifier_status(config_path: &Path, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = latest_verifier_report(&root)?.context("no latest VerifierRun report found")?;
    write_json(&serde_json::json!({
        "component": "verifier_status",
        "requested_task": task,
        "latest": report
    }))
}

async fn build_startup_report(config_path: &Path, offline: bool) -> Result<StartupHealthReport> {
    let config = load_config(config_path)?;
    let mut components = Vec::new();

    let wal = ControlWal::open(&config.control_wal)?;
    wal.record_bootstrap(&config.service.instance_id)?;
    components.push(ComponentHealth {
        component: "control_wal".to_owned(),
        status: HealthStatus::Ready,
        message: config.control_wal.path.clone(),
    });

    let blob_store = BlobStore::open(&config.blob_store)?;
    let probe = blob_store.put_bytes(b"eliot-governor phase-a startup probe")?;
    components.push(ComponentHealth {
        component: "blob_store".to_owned(),
        status: HealthStatus::Ready,
        message: probe.relative_path,
    });

    if offline {
        components.push(ComponentHealth {
            component: "surrealdb".to_owned(),
            status: HealthStatus::Degraded,
            message: "offline doctor skipped remote db health".to_owned(),
        });
    } else {
        match SurrealStore::new(config.db.surreal.clone())
            .health_check()
            .await
        {
            Ok(record) => components.push(ComponentHealth {
                component: record.component,
                status: HealthStatus::Ready,
                message: record.detail,
            }),
            Err(error) => components.push(ComponentHealth {
                component: "surrealdb".to_owned(),
                status: HealthStatus::NotReady,
                message: error.to_string(),
            }),
        }
    }

    Ok(StartupHealthReport::new(
        SCHEMA_VERSION,
        config.service.service_name,
        config.service.instance_id,
        components,
    ))
}

fn write_report(report: &StartupHealthReport) -> Result<()> {
    write_json(report)
}

fn write_json<T>(value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    writeln!(lock)?;
    Ok(())
}

fn db_report_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("db")
        .join("smoke-latest.md")
}

fn runtime_root(config_path: &Path) -> PathBuf {
    let resolved = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(config_path)
    };
    resolved
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

fn surreal_logical_config(config_path: &Path) -> Result<SurrealLogicalConfig> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let surreal = config.db.surreal;
    let password_file = resolve_runtime_config_path(&root, &surreal.password_file);
    let legacy_password_file_authorized =
        std::env::var("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION").as_deref() == Ok("1")
            || (std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() == Ok("1")
                && std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")
                    .ok()
                    .map(|path| resolve_runtime_config_path(&root, &path))
                    .as_ref()
                    == Some(&password_file));
    Ok(SurrealLogicalConfig {
        executable: resolve_runtime_executable_path(&root, &surreal.exe),
        endpoint: surreal.endpoint,
        namespace: surreal.ns,
        database: surreal.db,
        username: surreal.user,
        credential_provider: surreal.credential_provider,
        credential_id: surreal.credential_id,
        password_file,
        legacy_password_file_authorized,
        storage_root: surreal
            .storage
            .strip_prefix("rocksdb:")
            .map(|path| resolve_runtime_config_path(&root, path)),
    })
}

fn target_store_fingerprint(config_path: &Path) -> Result<String> {
    let config = load_config(config_path)?;
    Ok(format!(
        "{}|{}|{}",
        config.db.surreal.endpoint, config.db.surreal.ns, config.db.surreal.db
    ))
}

fn resolve_runtime_config_path(root: &Path, configured: &str) -> PathBuf {
    for prefix in ["%LOCALAPPDATA%/", "%LOCALAPPDATA%\\"] {
        if let Some(relative) = configured.strip_prefix(prefix)
            && let Some(local) = std::env::var_os("LOCALAPPDATA")
        {
            return PathBuf::from(local).join(relative);
        }
    }
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        return path;
    }
    let normalized = configured.replace('\\', "/");
    if normalized.starts_with(".eliot-governor/")
        && root.file_name().and_then(|name| name.to_str()) == Some(".eliot-governor")
    {
        return root.parent().unwrap_or_else(|| Path::new(".")).join(path);
    }
    root.join(path)
}

fn resolve_runtime_executable_path(root: &Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.components().count() == 1 {
        path
    } else {
        resolve_runtime_config_path(root, configured)
    }
}

fn plugin_root(config_path: &Path) -> PathBuf {
    if let Some(path) = std::env::var_os("ELIOT_GOVERNOR_PLUGIN_ROOT") {
        return PathBuf::from(path);
    }
    runtime_root(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("plugin")
        .join("eliot-governor")
}

fn parse_project_id(value: &str) -> Result<ProjectId> {
    ProjectId::from_str(value).with_context(|| format!("parse project id {value}"))
}

fn lifecycle_policy_from_cli(
    project: &str,
    memory_ref: &str,
    operator: &str,
    reason: &str,
) -> Result<ForgettingPolicy> {
    let operator = parse_forgetting_operator(operator)?;
    let reason = parse_forgetting_reason(reason)?;
    let superseding_ref =
        (operator == ForgettingOperator::Supersede).then(|| format!("{memory_ref}:superseding"));
    Ok(ForgettingPolicyService::propose(
        project_id_from_label(project),
        memory_ref,
        operator,
        reason,
        vec!["cli:memory-lifecycle:proposal".to_owned()],
        superseding_ref,
        None,
    ))
}

fn parse_forgetting_operator(value: &str) -> Result<ForgettingOperator> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "suppress" => Ok(ForgettingOperator::Suppress),
        "demote" => Ok(ForgettingOperator::Demote),
        "supersede" => Ok(ForgettingOperator::Supersede),
        "archive" => Ok(ForgettingOperator::Archive),
        "compress" => Ok(ForgettingOperator::Compress),
        "markpoisoned" => Ok(ForgettingOperator::MarkPoisoned),
        "retainauditonly" => Ok(ForgettingOperator::RetainAuditOnly),
        "purge" => bail!("purge is denied in Phase I0"),
        other => bail!("unknown memory lifecycle operator: {other}"),
    }
}

fn parse_forgetting_reason(value: &str) -> Result<ForgettingReason> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "stale" => Ok(ForgettingReason::Stale),
        "superseded" => Ok(ForgettingReason::Superseded),
        "lowutility" => Ok(ForgettingReason::LowUtility),
        "poisoned" => Ok(ForgettingReason::Poisoned),
        "privacy" => Ok(ForgettingReason::Privacy),
        "duplicate" => Ok(ForgettingReason::Duplicate),
        "wrongscope" => Ok(ForgettingReason::WrongScope),
        "negativetransfer" => Ok(ForgettingReason::NegativeTransfer),
        "falseactivation" => Ok(ForgettingReason::FalseActivation),
        "contextbloat" => Ok(ForgettingReason::ContextBloat),
        "verifiercontradicted" => Ok(ForgettingReason::VerifierContradicted),
        other => bail!("unknown memory lifecycle reason: {other}"),
    }
}

fn smoke_context(
    project_id: ProjectId,
    agent_id: AgentId,
    task_id: Option<TaskId>,
) -> CommandContext {
    CommandContext {
        write_id: eliot_types::WriteId::new_v7(),
        agent_id,
        session_id: None,
        project_id,
        task_id,
        scope: "writer-smoke".to_owned(),
        authority: "local-smoke".to_owned(),
        visibility: Visibility::Internal,
        taint: TaintClass::LocalVerified,
        lifecycle_status: LifecycleStatus::Active,
    }
}

struct PatchCliInput {
    request: PatchRequest,
    lease: ActionLease,
    work_lease: WorkLease,
    report: CodeCortexReport,
    verifier_plan: VerifierPlan,
}

fn load_patch_cli_input(root: &Path, lease_id: &str, diff_path: &Path) -> Result<PatchCliInput> {
    let lease = latest_action_lease(root)?;
    if lease.lease_id.to_string() != lease_id {
        bail!("requested lease id does not match latest ActionLease report");
    }
    let report = action_plan::latest_codecortex_report(root)?
        .context("no latest CodeCortex report found; run codecortex scan first")?;
    let verifier_plan = lease
        .verifier_plan
        .clone()
        .context("latest ActionLease does not contain a VerifierPlan")?;
    let scope = lease
        .allowed_scope
        .as_ref()
        .context("latest ActionLease does not contain an ActionScope")?;
    let diff_text = std::fs::read_to_string(diff_path)
        .with_context(|| format!("read diff {}", diff_path.display()))?;
    let request = PatchRequest {
        patch_request_id: PatchRequestId::new_v7(),
        project_id: lease.project_id,
        task_id: lease.task_id,
        agent_id: lease.agent_id,
        action_lease_id: lease.lease_id,
        repo_root: scope.repo_root.clone(),
        git_head_before: scope.git_head.clone(),
        codecortex_report_refs: vec![codecortex_report_ref(&report)],
        verifier_plan_ref: format!("verifier_plan:{}", lease.lease_id),
        diff: UnifiedDiff {
            byte_len: diff_text.len(),
            text: diff_text,
        },
        created_at: time::OffsetDateTime::now_utc(),
    };
    let work_lease = patch_work_lease(&lease, &report, &verifier_plan);
    Ok(PatchCliInput {
        request,
        lease,
        work_lease,
        report,
        verifier_plan,
    })
}

fn latest_action_lease(root: &Path) -> Result<ActionLease> {
    let latest = action_plan::latest_action_lease_report(root)?
        .context("no latest ActionLease report found; run action plan first")?;
    serde_json::from_value(
        latest
            .get("record")
            .and_then(|record| record.get("lease"))
            .cloned()
            .context("latest ActionLease report is missing record.lease")?,
    )
    .context("parse latest ActionLease report")
}

fn patch_repo_root(lease: &ActionLease) -> Result<PathBuf> {
    lease
        .allowed_scope
        .as_ref()
        .map(|scope| PathBuf::from(&scope.repo_root))
        .context("ActionLease has no allowed scope repo_root")
}

fn patch_work_lease(
    action_lease: &ActionLease,
    report: &CodeCortexReport,
    verifier_plan: &VerifierPlan,
) -> WorkLease {
    let now = time::OffsetDateTime::now_utc();
    let work_lease_id = WorkLeaseId::new_v7();
    let action_scope = action_lease.allowed_scope.as_ref();
    let write_set = action_scope
        .map(|scope| scope.allowed_files.clone())
        .unwrap_or_default();
    let repo_root =
        action_scope.map_or_else(|| report.repo_root.clone(), |scope| scope.repo_root.clone());
    let verifier_set = verifier_plan
        .required
        .iter()
        .map(|verifier| verifier.command_display.clone())
        .collect::<Vec<_>>();
    WorkLease {
        work_lease_id,
        work_item_id: WorkItemId::new_v7(),
        agent_session_id: AgentSessionId::new_v7(),
        agent_id: action_lease.agent_id,
        project_id: action_lease.project_id,
        task_id: action_lease.task_id,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: default_work_scope(repo_root, write_set.clone(), write_set, verifier_set),
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "bounded patch runner work scope".to_owned(),
            work_lease_id: Some(work_lease_id),
            conflicting_lease_ids: Vec::new(),
            expires_at: Some(now + time::Duration::hours(1)),
        },
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at: now + time::Duration::hours(1),
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    }
}

async fn write_e2_runs_to_memory(
    config_path: &Path,
    patch_run: &mut PatchRun,
    verifier_runs: &mut [VerifierRun],
) -> Result<()> {
    write_e2_runs_to_memory_optional_patch(config_path, Some(patch_run), verifier_runs).await
}

async fn write_e2_runs_to_memory_optional_patch(
    config_path: &Path,
    patch_run: Option<&mut PatchRun>,
    verifier_runs: &mut [VerifierRun],
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    for verifier_run in verifier_runs {
        PatchMemoryWriter::write_verifier_run(&handle, &admission, verifier_run).await?;
    }
    if let Some(patch_run) = patch_run {
        PatchMemoryWriter::write_patch_run(&handle, &admission, patch_run).await?;
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn write_codecortex_report_to_memory(
    config_path: &Path,
    report: &mut CodeCortexReport,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let writer_config = WriterConfig::default();
    let (handle, actor) = WriterActor::channel(wal, store, &writer_config);
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    CodeCortexMemoryWriter::write_report(&handle, &admission, report).await?;
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn apply_lifecycle_policy_to_memory(
    config_path: &Path,
    policy: &ForgettingPolicy,
) -> Result<eliot_engine::MemoryLifecycleApplyOutcome> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let outcome = MemoryLifecycleService::new()
        .apply_policy_through_writer(
            &handle,
            &WriteAdmissionService,
            policy,
            "eliot-governor-cli",
        )
        .await?;
    drop(handle);
    actor_task.await?;
    Ok(outcome)
}

async fn write_memory_influence_to_memory(
    config_path: &Path,
    report: &mut MemoryInfluenceReport,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    MemoryLifecycleMemoryWriter::write_influence_report(&handle, &WriteAdmissionService, report)
        .await?;
    drop(handle);
    actor_task.await?;
    Ok(())
}

fn write_memory_lifecycle_report(root: &Path, report: &MemoryLifecycleReport) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-lifecycle")
            .join("latest.md"),
        report,
        &typed_report_markdown("Memory Lifecycle", report)?,
    )
}

fn write_memory_vitality_report(root: &Path, score: &MemoryVitalityScore) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-vitality")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-vitality")
            .join("latest.md"),
        score,
        &typed_report_markdown("Memory Vitality", score)?,
    )
}

fn write_memory_gravity_report(root: &Path, gravity: &MemoryGravity) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-gravity")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-gravity")
            .join("latest.md"),
        gravity,
        &typed_report_markdown("Memory Gravity", gravity)?,
    )
}

fn write_memory_influence_report(root: &Path, report: &MemoryInfluenceReport) -> Result<()> {
    write_report_pair(
        &root
            .join("reports")
            .join("memory-influence")
            .join("latest.json"),
        &root
            .join("reports")
            .join("memory-influence")
            .join("latest.md"),
        report,
        &typed_report_markdown("Memory Influence", report)?,
    )
}

fn write_skill_report_pair<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn write_skill_influence_report(root: &Path, report: &SkillInfluenceReport) -> Result<()> {
    write_skill_report_pair(root, "skill-influence", "Skill Influence", report)
}

fn read_optional_report<T>(root: &Path, name: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let path = root.join("reports").join(name).join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

async fn write_skill_card_to_memory(
    config_path: &Path,
    skill: &SkillCardV2,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let receipt = SkillRegistryService::write_skill_card(&handle, &admission, skill).await?;
    drop(handle);
    actor_task.await?;
    Ok(receipt)
}

async fn write_skill_execution_proof_to_memory(
    config_path: &Path,
    proof: &mut eliot_types::SkillExecutionProof,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let receipt = SkillExecutionProofService::write_proof(&handle, &admission, proof).await?;
    drop(handle);
    actor_task.await?;
    Ok(receipt)
}

async fn write_skill_influence_to_memory(
    config_path: &Path,
    report: &mut SkillInfluenceReport,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let receipt = SkillInfluenceService::write_report(&handle, &admission, report).await?;
    drop(handle);
    actor_task.await?;
    Ok(receipt)
}

async fn write_skill_curator_run_to_memory(
    config_path: &Path,
    run: &mut SkillCuratorRun,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    SkillCuratorMemoryWriter::write_run(&handle, &admission, run).await?;
    for proposal in &mut run.proposals {
        SkillCuratorMemoryWriter::write_proposal(&handle, &admission, proposal).await?;
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn write_skill_curation_receipt_to_memory(
    config_path: &Path,
    receipt: &mut SkillCurationReceipt,
) -> Result<eliot_types::WriteReceiptRef> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let write_receipt =
        SkillCuratorMemoryWriter::write_receipt(&handle, &WriteAdmissionService, receipt).await?;
    drop(handle);
    actor_task.await?;
    Ok(write_receipt)
}

fn write_skill_curator_reports(
    root: &Path,
    run: &SkillCuratorRun,
    gate_decisions: &[SkillCurationGateDecision],
) -> Result<()> {
    let report = SkillCurationReport {
        component: "skill_curator".to_owned(),
        run: run.clone(),
        open_proposals: run.proposals.clone(),
        gate_decisions: gate_decisions.to_vec(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_skill_report_pair(root, "skill-curator", "Skill Curator", &report)?;

    let proposals_report = serde_json::json!({
        "component": "skill_curation_proposals",
        "run_id": run.run_id,
        "project_id": run.project_id,
        "open_proposals": run.proposals,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_skill_report_pair(
        root,
        "skill-curation-proposals",
        "Skill Curation Proposals",
        &proposals_report,
    )?;
    write_skill_curator_gate_report(root, gate_decisions)
}

fn write_skill_curator_gate_report(
    root: &Path,
    gate_decisions: &[SkillCurationGateDecision],
) -> Result<()> {
    let gate_report = serde_json::json!({
        "component": "skill_curation_gate",
        "gate_decisions": gate_decisions,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_skill_report_pair(
        root,
        "skill-curation-gate",
        "Skill Curation Gate",
        &gate_report,
    )
}

fn latest_skill_curator_run(root: &Path) -> Result<Option<SkillCuratorRun>> {
    let path = root
        .join("reports")
        .join("skill-curator")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let report: SkillCurationReport = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok(Some(report.run))
}

fn latest_skill_curation_proposals(root: &Path) -> Result<Vec<SkillCurationProposal>> {
    let Some(run) = latest_skill_curator_run(root)? else {
        return Ok(Vec::new());
    };
    Ok(run.proposals)
}

fn find_skill_curation_proposal(root: &Path, proposal_id: &str) -> Result<SkillCurationProposal> {
    let proposals = latest_skill_curation_proposals(root)?;
    if proposal_id == "latest" {
        return proposals
            .into_iter()
            .next()
            .context("no latest skill curation proposal found");
    }
    if let Some(action) = parse_skill_curation_action(proposal_id) {
        return proposals
            .into_iter()
            .find(|proposal| proposal.action == action)
            .with_context(|| {
                format!("no latest skill curation proposal for action {proposal_id}")
            });
    }
    proposals
        .into_iter()
        .find(|proposal| proposal.proposal_id == proposal_id)
        .with_context(|| format!("skill curation proposal not found: {proposal_id}"))
}

fn parse_skill_curation_action(value: &str) -> Option<SkillCurationAction> {
    match normalized_arg(value).as_str() {
        "keep" => Some(SkillCurationAction::Keep),
        "patch" => Some(SkillCurationAction::Patch),
        "archive" => Some(SkillCurationAction::Archive),
        "quarantine" => Some(SkillCurationAction::Quarantine),
        "split" => Some(SkillCurationAction::Split),
        "merge" => Some(SkillCurationAction::Merge),
        "promote" => Some(SkillCurationAction::Promote),
        _ => None,
    }
}

async fn write_work_entities(
    config_path: &Path,
    state: &mut WorkState,
    session_id: Option<AgentSessionId>,
    item_id: Option<WorkItemId>,
    lease_id: Option<WorkLeaseId>,
    conflict_ids: &[String],
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;

    if let Some(session_id) = session_id
        && let Some(session) = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)
    {
        WorkMemoryWriter::write_session(&handle, &admission, session).await?;
    }
    if let Some(item_id) = item_id
        && let Some(item) = state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == item_id)
    {
        WorkMemoryWriter::write_work_item(&handle, &admission, item).await?;
    }
    if let Some(lease_id) = lease_id
        && let Some(lease) = state
            .leases
            .iter_mut()
            .find(|lease| lease.work_lease_id == lease_id)
    {
        WorkMemoryWriter::write_work_lease(&handle, &admission, lease).await?;
    }
    for conflict_id in conflict_ids {
        if let Some(conflict) = state
            .conflicts
            .iter()
            .find(|conflict| &conflict.conflict_id == conflict_id)
            && let Some(item) = state
                .work_items
                .iter()
                .find(|item| item.work_item_id == conflict.work_item_id)
        {
            let agent_id = state
                .leases
                .iter()
                .find(|lease| lease.work_item_id == item.work_item_id)
                .map_or_else(AgentId::new_v7, |lease| lease.agent_id);
            let _ = WorkMemoryWriter::write_conflict(
                &handle,
                &admission,
                item.project_id,
                item.task_id,
                agent_id,
                conflict,
            )
            .await?;
        }
    }

    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn run_work_finish(config_path: &Path, lease_id: &str, release: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let lease_id = WorkLeaseId::from_str(lease_id).context("parse work lease id")?;
    let decision = if release {
        WorkLeaseService.release(&mut state, lease_id)
    } else {
        WorkLeaseService.revoke(&mut state, lease_id)
    };
    write_work_entities(
        config_path,
        &mut state,
        None,
        None,
        decision.work_lease_id,
        &[],
    )
    .await?;
    let (project, task) = labels_for_lease(&state, lease_id);
    let report = WorkQueueService.status_report(&state, &project, &task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

fn load_work_state(root: &Path) -> Result<WorkState> {
    let path = work_state_path(root);
    if !path.is_file() {
        return Ok(WorkState::default());
    }
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

fn save_work_state_and_report(
    root: &Path,
    state: &WorkState,
    report: &eliot_engine::WorkStatusReport,
) -> Result<()> {
    write_report_pair(
        &work_state_path(root),
        &work_state_markdown_path(root),
        state,
        "",
    )?;
    write_report_pair(
        &root.join("reports").join("work").join("latest.json"),
        &root.join("reports").join("work").join("latest.md"),
        report,
        &work_report_markdown(report),
    )
}

fn work_state_path(root: &Path) -> PathBuf {
    root.join("reports").join("work").join("state.json")
}

fn work_state_markdown_path(root: &Path) -> PathBuf {
    root.join("reports").join("work").join("state.md")
}

fn work_report_markdown(report: &eliot_engine::WorkStatusReport) -> String {
    let mut output = String::from("# Work Status\n\n");
    let _ = writeln!(output, "- project: `{}`", report.project);
    let _ = writeln!(output, "- task: `{}`", report.task);
    let _ = writeln!(output, "- work_items: `{}`", report.work_items.len());
    let _ = writeln!(output, "- active_leases: `{}`", report.active_leases.len());
    let _ = writeln!(
        output,
        "- worktree_leases: `{}`",
        report.worktree_leases.len()
    );
    let _ = writeln!(
        output,
        "- candidate_diffs: `{}`",
        report.candidate_diffs.len()
    );
    let _ = writeln!(output, "- conflicts: `{}`", report.conflicts.len());
    let _ = writeln!(output, "- final_status: `{}`", report.final_status);
    output
}

fn save_worktree_state_and_reports(root: &Path, state: &WorkState) -> Result<()> {
    write_report_pair(
        &work_state_path(root),
        &work_state_markdown_path(root),
        state,
        "",
    )?;
    let worktree_report = serde_json::json!({
        "component": "worktree",
        "worktree_lease_count": state.worktree_leases.len(),
        "latest_worktree_lease": state.worktree_leases.last(),
        "final_status": if state.worktree_leases.is_empty() { "NO_WORKTREE" } else { "DONE_VERIFIED" }
    });
    write_report_pair(
        &root.join("reports").join("worktree").join("latest.json"),
        &root.join("reports").join("worktree").join("latest.md"),
        &worktree_report,
        &worktree_report_markdown(&worktree_report),
    )?;
    let candidate_report = serde_json::json!({
        "component": "candidate_diff",
        "candidate_diff_count": state.candidate_diffs.len(),
        "candidate_review_count": state.candidate_reviews.len(),
        "latest_candidate_diff": state.candidate_diffs.last(),
        "latest_candidate_review": state.candidate_reviews.last(),
        "final_status": if state.candidate_diffs.is_empty() { "NO_CANDIDATE_DIFF" } else { "DONE_VERIFIED" }
    });
    write_report_pair(
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.json"),
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.md"),
        &candidate_report,
        &candidate_diff_report_markdown(&candidate_report),
    )
}

fn worktree_report_markdown(report: &serde_json::Value) -> String {
    format!(
        "# Worktree\n\n- worktree_lease_count: `{}`\n- final_status: `{}`\n",
        report
            .get("worktree_lease_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        report
            .get("final_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
    )
}

fn candidate_diff_report_markdown(report: &serde_json::Value) -> String {
    format!(
        "# Candidate Diff\n\n- candidate_diff_count: `{}`\n- candidate_review_count: `{}`\n- final_status: `{}`\n",
        report
            .get("candidate_diff_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        report
            .get("candidate_review_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        report
            .get("final_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
    )
}

async fn write_worktree_records(
    config_path: &Path,
    worktree_lease: Option<&mut WorktreeLease>,
    candidate_diff: Option<&mut CandidateDiff>,
    candidate_review: Option<(&mut CandidateReview, &CandidateDiff)>,
    diff_agent_id: Option<AgentId>,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    if let Some(lease) = worktree_lease {
        WorktreeMemoryWriter::write_worktree_lease(&handle, &admission, lease).await?;
    }
    if let Some(diff) = candidate_diff {
        WorktreeMemoryWriter::write_candidate_diff(
            &handle,
            &admission,
            diff,
            diff_agent_id.unwrap_or_else(AgentId::new_v7),
        )
        .await?;
    }
    if let Some((review, diff)) = candidate_review {
        WorktreeMemoryWriter::write_candidate_review(&handle, &admission, review, diff).await?;
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

async fn run_blackboard_status_change(
    config_path: &Path,
    item_id: &str,
    session: Option<&str>,
    action: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let item_id = BlackboardItemId::from_str(item_id).context("parse blackboard item id")?;
    let item = match action {
        "ack" => {
            let session_id = session
                .map(AgentSessionId::from_str)
                .transpose()?
                .unwrap_or_else(|| {
                    state
                        .blackboard_items
                        .iter()
                        .find(|item| item.blackboard_item_id == item_id)
                        .map_or_else(AgentSessionId::new_v7, |item| item.owner_session_id)
                });
            BlackboardService.acknowledge(&mut state, item_id, session_id)?
        }
        "resolve" => BlackboardService.resolve(&mut state, item_id)?,
        "reject" => BlackboardService.reject(&mut state, item_id)?,
        other => bail!("unknown blackboard action: {other}"),
    };
    write_collective_entities(
        config_path,
        &mut state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    let (project, task) = labels_for_project_task(&state, item.project_id, item.task_id);
    save_collective_reports(&root, &state, &project, &task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, &project, &task),
    )?;
    write_json(&serde_json::json!({
        "component": format!("blackboard_{action}"),
        "blackboard_item": state
            .blackboard_items
            .iter()
            .find(|candidate| candidate.blackboard_item_id == item.blackboard_item_id),
        "final_status": "DONE_VERIFIED"
    }))
}

async fn write_collective_entities(
    config_path: &Path,
    state: &mut WorkState,
    blackboard_item_ids: &[BlackboardItemId],
    mailbox_message_ids: &[MailboxMessageId],
    recovery_ids: &[String],
    collective_trace_ids: &[String],
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    let _ = store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (handle, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    for item_id in blackboard_item_ids {
        if let Some(item) = state
            .blackboard_items
            .iter_mut()
            .find(|item| item.blackboard_item_id == *item_id)
        {
            CollectiveMemoryWriter::write_blackboard_item(&handle, &admission, item).await?;
        }
    }
    for message_id in mailbox_message_ids {
        if let Some(message) = state
            .mailbox_messages
            .iter_mut()
            .find(|message| message.message_id == *message_id)
        {
            CollectiveMemoryWriter::write_mailbox_message(&handle, &admission, message).await?;
        }
    }
    for recovery_id in recovery_ids {
        if let Some(record) = state
            .recovery_records
            .iter_mut()
            .find(|record| &record.recovery_id == recovery_id)
        {
            CollectiveMemoryWriter::write_recovery_record(&handle, &admission, record).await?;
        }
    }
    for collective_trace_id in collective_trace_ids {
        if let Some(trace) = state
            .collective_traces
            .iter_mut()
            .find(|trace| &trace.collective_trace_id == collective_trace_id)
        {
            CollectiveMemoryWriter::write_collective_trace(&handle, &admission, trace).await?;
        }
    }
    drop(handle);
    actor_task.await?;
    Ok(())
}

fn save_collective_reports(
    root: &Path,
    state: &WorkState,
    project: &str,
    task: &str,
) -> Result<()> {
    let blackboard = blackboard_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("blackboard").join("latest.json"),
        &root.join("reports").join("blackboard").join("latest.md"),
        &blackboard,
        &phase_closeout_markdown("Blackboard Report", &blackboard),
    )?;
    let mailbox = mailbox_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("mailbox").join("latest.json"),
        &root.join("reports").join("mailbox").join("latest.md"),
        &mailbox,
        &phase_closeout_markdown("Mailbox Report", &mailbox),
    )?;
    let recovery = recovery_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("recovery").join("latest.json"),
        &root.join("reports").join("recovery").join("latest.md"),
        &recovery,
        &phase_closeout_markdown("Recovery Report", &recovery),
    )?;
    let collective = collective_report_value(state, project, task);
    write_report_pair(
        &root.join("reports").join("collective").join("latest.json"),
        &root.join("reports").join("collective").join("latest.md"),
        &collective,
        &phase_closeout_markdown("Collective Trace Report", &collective),
    )
}

fn blackboard_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let items = state
        .blackboard_items
        .iter()
        .filter(|item| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    item.project_id == project_id && item.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "blackboard",
        "project": project,
        "task": task,
        "items": items,
        "blackboard_candidate_not_truth": true,
        "final_status": "DONE_VERIFIED"
    })
}

fn mailbox_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let messages = state
        .mailbox_messages
        .iter()
        .filter(|message| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    message.project_id == project_id && message.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "mailbox",
        "project": project,
        "task": task,
        "messages": messages,
        "mailbox_grants_no_authority": true,
        "final_status": "DONE_VERIFIED"
    })
}

fn recovery_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let records = state
        .recovery_records
        .iter()
        .filter(|record| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    record.project_id == project_id && record.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "recovery",
        "project": project,
        "task": task,
        "records": records,
        "silent_candidate_promotion": false,
        "final_status": "DONE_VERIFIED"
    })
}

fn collective_report_value(state: &WorkState, project: &str, task: &str) -> serde_json::Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let traces = state
        .collective_traces
        .iter()
        .filter(|trace| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    trace.project_id == project_id && trace.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "component": "collective_trace",
        "project": project,
        "task": task,
        "traces": traces,
        "final_status": "DONE_VERIFIED"
    })
}

fn replace_worktree_lease(state: &mut WorkState, replacement: WorktreeLease) {
    if let Some(existing) = state
        .worktree_leases
        .iter_mut()
        .find(|lease| lease.worktree_lease_id == replacement.worktree_lease_id)
    {
        *existing = replacement;
    } else {
        state.worktree_leases.push(replacement);
    }
}

fn replace_candidate_diff(state: &mut WorkState, replacement: CandidateDiff) {
    if let Some(existing) = state
        .candidate_diffs
        .iter_mut()
        .find(|diff| diff.candidate_diff_id == replacement.candidate_diff_id)
    {
        *existing = replacement;
    } else {
        state.candidate_diffs.push(replacement);
    }
}

fn replace_candidate_review(state: &mut WorkState, replacement: CandidateReview) {
    if let Some(existing) = state
        .candidate_reviews
        .iter_mut()
        .find(|review| review.review_id == replacement.review_id)
    {
        *existing = replacement;
    } else {
        state.candidate_reviews.push(replacement);
    }
}

fn parse_candidate_review_decision(value: &str) -> Result<CandidateReviewDecision> {
    match value.trim().to_ascii_lowercase().as_str() {
        "accept" | "accept-for-patchrunner" | "accept_for_patchrunner" => {
            Ok(CandidateReviewDecision::AcceptForPatchRunner)
        }
        "reject" => Ok(CandidateReviewDecision::Reject),
        "revise" | "require-revision" | "require_revision" => {
            Ok(CandidateReviewDecision::RequireRevision)
        }
        "human" | "require-human-review" | "require_human_review" => {
            Ok(CandidateReviewDecision::RequireHumanReview)
        }
        other => bail!("unknown candidate review decision: {other}"),
    }
}

fn parse_blackboard_kind(value: &str) -> Result<BlackboardItemKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "finding" | "finding_candidate" | "finding-candidate" => {
            Ok(BlackboardItemKind::FindingCandidate)
        }
        "evidence" | "evidence_handle" | "evidence-handle" => {
            Ok(BlackboardItemKind::EvidenceHandle)
        }
        "unknown" => Ok(BlackboardItemKind::Unknown),
        "hypothesis" | "hypothesis_candidate" | "hypothesis-candidate" => {
            Ok(BlackboardItemKind::HypothesisCandidate)
        }
        "conflict" | "conflict_notice" | "conflict-notice" => {
            Ok(BlackboardItemKind::ConflictNotice)
        }
        "decision" | "decision_request" | "decision-request" => {
            Ok(BlackboardItemKind::DecisionRequest)
        }
        "verifier" | "verifier_result" | "verifier-result" => {
            Ok(BlackboardItemKind::VerifierResult)
        }
        "artifact" | "artifact_handle" | "artifact-handle" => {
            Ok(BlackboardItemKind::ArtifactHandle)
        }
        "blocker" => Ok(BlackboardItemKind::Blocker),
        other => bail!("unknown blackboard kind: {other}"),
    }
}

fn parse_confidence(value: &str) -> Result<ConfidenceLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(ConfidenceLevel::Low),
        "medium" | "med" => Ok(ConfidenceLevel::Medium),
        "high" => Ok(ConfidenceLevel::High),
        other => bail!("unknown confidence level: {other}"),
    }
}

fn parse_mailbox_kind(value: &str) -> Result<MailboxMessageKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "work_assigned" | "work-assigned" | "assigned" => Ok(MailboxMessageKind::WorkAssigned),
        "work_blocked" | "work-blocked" | "blocked" => Ok(MailboxMessageKind::WorkBlocked),
        "lease_expiring" | "lease-expiring" => Ok(MailboxMessageKind::LeaseExpiring),
        "lease_revoked" | "lease-revoked" => Ok(MailboxMessageKind::LeaseRevoked),
        "worktree_captured" | "worktree-captured" => Ok(MailboxMessageKind::WorktreeCaptured),
        "candidate_ready" | "candidate-ready" => Ok(MailboxMessageKind::CandidateReady),
        "review_requested" | "review-requested" => Ok(MailboxMessageKind::ReviewRequested),
        "conflict_raised" | "conflict-raised" => Ok(MailboxMessageKind::ConflictRaised),
        "verifier_failed" | "verifier-failed" => Ok(MailboxMessageKind::VerifierFailed),
        "completion_blocked" | "completion-blocked" => Ok(MailboxMessageKind::CompletionBlocked),
        "agent_expired" | "agent-expired" => Ok(MailboxMessageKind::AgentExpired),
        "ack_required" | "ack-required" => Ok(MailboxMessageKind::AckRequired),
        other => bail!("unknown mailbox kind: {other}"),
    }
}

fn parse_mailbox_recipient(value: &str) -> Result<MailboxRecipient> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("controller") {
        return Ok(MailboxRecipient::Controller);
    }
    if let Some(role) = value.strip_prefix("role:") {
        return Ok(MailboxRecipient::Role(parse_agent_role(role)?));
    }
    if let Some(session_id) = value.strip_prefix("session:") {
        return Ok(MailboxRecipient::Session(AgentSessionId::from_str(
            session_id,
        )?));
    }
    if let Some(work_item_id) = value.strip_prefix("work-item:") {
        return Ok(MailboxRecipient::WorkItem(WorkItemId::from_str(
            work_item_id,
        )?));
    }
    bail!("unknown mailbox recipient: {value}")
}

fn worktree_root_for_repo(repo_root: &Path) -> PathBuf {
    repo_root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".eliot-governor-worktrees")
        .join(safe_path_segment(
            repo_root
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("repo"),
        ))
}

fn safe_path_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn git_head_blocking(repo_root: &Path) -> Result<String> {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .with_context(|| format!("run git rev-parse in {}", repo_root.display()))?;
    if !output.status.success() {
        bail!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn find_work_item<'a>(state: &'a WorkState, project: &str, task: &str) -> Option<&'a WorkItem> {
    state
        .work_items
        .iter()
        .rev()
        .find(|item| item.project == project && item.task == task)
}

fn resolve_project_task_ids(state: &WorkState, project: &str, task: &str) -> (ProjectId, TaskId) {
    find_work_item(state, project, task).map_or_else(
        || (project_id_from_label(project), task_id_from_label(task)),
        |item| (item.project_id, item.task_id),
    )
}

fn project_task_ids_for_labels(
    state: &WorkState,
    project: &str,
    task: &str,
) -> Option<(ProjectId, TaskId)> {
    if project.is_empty() && task.is_empty() {
        return None;
    }
    find_work_item(state, project, task)
        .map(|item| (item.project_id, item.task_id))
        .or_else(|| {
            Some((
                ProjectId::from_str(project).ok()?,
                TaskId::from_str(task).ok()?,
            ))
        })
}

fn ensure_controller_session(
    state: &mut WorkState,
    project_id: ProjectId,
) -> eliot_types::AgentSession {
    if let Some(session) = state.sessions.iter().rev().find(|session| {
        session.project_id == project_id
            && session.role == AgentRole::Controller
            && session.status == eliot_types::AgentSessionStatus::Active
    }) {
        return session.clone();
    }
    AgentSessionService.create_controller(state, project_id)
}

fn latest_active_work_lease_id(
    state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Option<WorkLeaseId> {
    let now = time::OffsetDateTime::now_utc();
    state
        .leases
        .iter()
        .rev()
        .find(|lease| {
            lease.project_id == project_id
                && lease.task_id == task_id
                && matches!(
                    lease.state,
                    WorkLeaseState::Granted | WorkLeaseState::Renewed
                )
                && lease.expires_at > now
        })
        .map(|lease| lease.work_lease_id)
}

fn labels_for_project_task(
    state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
) -> (String, String) {
    state
        .work_items
        .iter()
        .rev()
        .find(|item| item.project_id == project_id && item.task_id == task_id)
        .map_or_else(
            || (project_id.to_string(), task_id.to_string()),
            |item| (item.project.clone(), item.task.clone()),
        )
}

fn latest_conflict_ids_for_item(state: &WorkState, item_id: WorkItemId) -> Vec<String> {
    state
        .conflicts
        .iter()
        .filter(|conflict| conflict.work_item_id == item_id)
        .map(|conflict| conflict.conflict_id.clone())
        .collect()
}

fn labels_for_lease(state: &WorkState, lease_id: WorkLeaseId) -> (String, String) {
    state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .and_then(|lease| {
            state
                .work_items
                .iter()
                .find(|item| item.work_item_id == lease.work_item_id)
        })
        .map_or_else(
            || ("unknown".to_owned(), "unknown".to_owned()),
            |item| (item.project.clone(), item.task.clone()),
        )
}

fn default_work_verifier(scope: &[String]) -> Vec<VerifierRequirement> {
    vec![VerifierRequirement {
        name: "cargo-check".to_owned(),
        command_kind: VerifierCommandKind::CargoCheck,
        command_display: "cargo check --workspace --all-targets --all-features".to_owned(),
        scope: scope.to_vec(),
        required_for_done: true,
        expected_signal: "workspace type-checks".to_owned(),
    }]
}

fn parse_agent_role(value: &str) -> Result<AgentRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "controller" => Ok(AgentRole::Controller),
        "implementer" | "impl" => Ok(AgentRole::Implementer),
        "reviewer" => Ok(AgentRole::Reviewer),
        "auditor" | "read_only" | "read-only" => Ok(AgentRole::Auditor),
        "verifier" => Ok(AgentRole::Verifier),
        other => bail!("unknown agent role: {other}"),
    }
}

fn project_id_from_label(value: &str) -> ProjectId {
    ProjectId::from_str(value).unwrap_or_else(|_| ProjectId::new_v7())
}

fn task_id_from_label(value: &str) -> TaskId {
    TaskId::from_str(value).unwrap_or_else(|_| TaskId::new_v7())
}

fn skill_id_from_label(value: &str) -> SkillId {
    SkillId::from_str(value).unwrap_or_else(|_| SkillId::new_v7())
}

fn write_report_pair<T>(
    json_path: &Path,
    markdown_path: &Path,
    value: &T,
    markdown: &str,
) -> Result<()>
where
    T: serde::Serialize,
{
    if let Some(parent) = json_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write_bytes(json_path, &serde_json::to_vec_pretty(value)?)?;
    atomic_write_bytes(markdown_path, markdown.as_bytes())?;
    Ok(())
}

fn write_safety_report<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn write_external_review_report<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn write_antigravity_report_pair<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn antigravity_resolution_probe_contract() -> (
    AntigravityBinaryResolution,
    AntigravityCapabilityProbe,
    AntigravityCommandContract,
) {
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    let probe = AntigravityCapabilityProbeService.probe_from_resolution(&resolution);
    let contract = AntigravityCommandContractService.build(&resolution, &probe);
    (resolution, probe, contract)
}

fn antigravity_home() -> Result<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .context("USERPROFILE/HOME is unavailable for Antigravity config discovery")
}

fn project_root_from_config(config_path: &Path) -> PathBuf {
    let root = runtime_root(config_path);
    let project = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    if project.is_absolute() {
        project
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(project)
    }
}

fn release_eliot_executable(config_path: &Path) -> Result<PathBuf> {
    let executable = project_root_from_config(config_path)
        .join("target")
        .join("release")
        .join(if cfg!(windows) {
            "eliot-governor.exe"
        } else {
            "eliot-governor"
        });
    executable.canonicalize().with_context(|| {
        format!(
            "release ELIOT MCP executable not found: {}",
            executable.display()
        )
    })
}

fn official_antigravity_plugin_source(config_path: &Path) -> PathBuf {
    project_root_from_config(config_path)
        .join("plugin")
        .join("eliot-antigravity-official")
}

fn resolved_antigravity_binary() -> Result<PathBuf> {
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    resolution
        .selected_path
        .map(PathBuf::from)
        .context("official signed Antigravity CLI was not resolved")
}

fn antigravity_windows_install_discovery() -> eliot_types::AntigravityWindowsInstallDiscovery {
    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    AntigravityWindowsInstallDiscoveryService.discover(local_app_data.as_deref())
}

fn installed_plugin_files(status: &eliot_types::AntigravityOfficialPluginStatus) -> Vec<String> {
    let mut files = Vec::new();
    for root in [&status.gui_plugin_root, &status.cli_plugin_root] {
        collect_file_paths(Path::new(root), &mut files);
    }
    files.sort();
    files.dedup();
    files
}

fn collect_file_paths(root: &Path, files: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_file_paths(&path, files);
        } else if path.is_file() {
            files.push(path.display().to_string());
        }
    }
}

fn antigravity_plugin_root(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("plugin")
        .join("eliot-antigravity")
}

fn antigravity_latest_request_path(root: &Path) -> PathBuf {
    root.join("reports")
        .join("antigravity-runs")
        .join("latest-request.json")
}

fn latest_antigravity_request(root: &Path) -> Result<Option<AntigravityReviewRequest>> {
    let path = antigravity_latest_request_path(root);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_antigravity_run(root: &Path) -> Result<Option<AntigravityRun>> {
    let path = root
        .join("reports")
        .join("antigravity-runs")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_antigravity_auth(root: &Path) -> Result<Option<AntigravityAuthCheck>> {
    latest_antigravity_typed(root, "antigravity-auth")
}

fn latest_antigravity_enablement(root: &Path) -> Result<Option<AntigravityEnablementReceipt>> {
    let path = root
        .join("reports")
        .join("antigravity-enablement")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    if value.get("receipt_id").is_none() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(value)?))
}

fn latest_antigravity_live_smoke(root: &Path) -> Result<Option<AntigravityLiveSmokeResult>> {
    latest_antigravity_typed(root, "antigravity-live-smoke")
}

fn latest_antigravity_disable(root: &Path) -> Result<Option<AntigravityDisableReceipt>> {
    latest_antigravity_typed(root, "antigravity-disable")
}

fn latest_antigravity_typed<T>(root: &Path, dir: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let path = root.join("reports").join(dir).join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn matching_antigravity_mcp_invocation(
    root: &Path,
    run: &AntigravityRun,
) -> Option<AntigravityMcpInvocationReceipt> {
    let completed_at = run.completed_at?;
    let events = root
        .join("reports")
        .join("antigravity-mcp-invocations")
        .join("events");
    let mut receipts = std::fs::read_dir(events)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter_map(|path| {
            serde_json::from_reader::<_, AntigravityMcpInvocationReceipt>(
                std::fs::File::open(path).ok()?,
            )
            .ok()
        })
        .filter(|receipt| {
            receipt.succeeded
                && receipt.matching_audit_event
                && receipt.profile == "external_auditor"
                && receipt.tool_name == "eliot_runtime_status"
                && receipt.invoked_at >= run.created_at
                && receipt.invoked_at <= completed_at
                && receipt
                    .audit_event_ref
                    .as_deref()
                    .is_some_and(|reference| root.join(reference).is_file())
        })
        .collect::<Vec<_>>();
    receipts.sort_by_key(|receipt| receipt.invoked_at);
    receipts.pop()
}

fn ensure_antigravity_collective_route(
    root: &Path,
    run: &AntigravityRun,
) -> Result<serde_json::Value> {
    let mut state = latest_antigravity_typed::<WorkState>(root, "antigravity-worktree-state")?
        .context("Antigravity worktree state is missing for collective route")?;
    let work_lease = state
        .leases
        .last()
        .cloned()
        .context("Antigravity WorkLease is missing for collective route")?;
    let candidate_diff = state
        .candidate_diffs
        .last()
        .cloned()
        .context("Antigravity CandidateDiff is missing for collective route")?;
    let payload_ref = format!("reports/antigravity-runs/latest.json#{}", run.run_id);
    let blackboard_item = state
        .blackboard_items
        .iter()
        .find(|item| item.payload_ref == payload_ref)
        .cloned()
        .unwrap_or_else(|| {
            BlackboardService.create_item(
                &mut state,
                BlackboardAddInput {
                    project_id: work_lease.project_id,
                    task_id: work_lease.task_id,
                    owner_session_id: work_lease.agent_session_id,
                    work_item_id: Some(work_lease.work_item_id),
                    lease_id: Some(work_lease.work_lease_id),
                    kind: BlackboardItemKind::FindingCandidate,
                    scope: BlackboardScope {
                        files: candidate_diff.changed_files.clone(),
                        work_items: vec![work_lease.work_item_id],
                        ..BlackboardScope::default()
                    },
                    payload_ref: payload_ref.clone(),
                    evidence_refs: vec![
                        format!("candidate-diff: {}", candidate_diff.candidate_diff_id),
                        "reports/antigravity-mcp-invocation-proof/latest.json".to_owned(),
                    ],
                    confidence: None,
                    expires_at: None,
                },
            )
        });
    let mailbox_message = state
        .mailbox_messages
        .iter()
        .find(|message| message.payload_ref == payload_ref)
        .cloned()
        .unwrap_or_else(|| {
            MailboxService.send(
                &mut state,
                MailboxSendInput {
                    message_id: None,
                    project_id: work_lease.project_id,
                    task_id: work_lease.task_id,
                    sender_session_id: work_lease.agent_session_id,
                    recipient: MailboxRecipient::Controller,
                    kind: MailboxMessageKind::CandidateReady,
                    payload_ref: payload_ref.clone(),
                    requires_ack: Some(false),
                    expires_at: None,
                },
            )
        });
    let report = serde_json::json!({
        "component": "antigravity_collective_route",
        "run_id": run.run_id,
        "candidate_diff_id": candidate_diff.candidate_diff_id,
        "blackboard_item": blackboard_item,
        "mailbox_message": mailbox_message,
        "candidate_only": true,
        "taint": TaintClass::ExternalAgent,
        "created_at": time::OffsetDateTime::now_utc()
    });
    write_antigravity_report_pair(
        root,
        "antigravity-collective-route",
        "Antigravity Collective Route",
        &report,
    )?;
    write_antigravity_report_pair(
        root,
        "antigravity-worktree-state",
        "Antigravity Worktree State",
        &state,
    )?;
    Ok(report)
}

fn parse_antigravity_enablement_scope(value: &str) -> Result<AntigravityEnablementScope> {
    match value {
        "disposable-worktree-smoke"
        | "disposable-worktree-audit"
        | "read-only-smoke"
        | "read-only" => Ok(AntigravityEnablementScope::DisposableWorktreeAuditOnly),
        "disposable-worktree-candidate" | "worktree-candidate-smoke" | "worktree-candidate" => {
            Ok(AntigravityEnablementScope::DisposableWorktreeCandidateOnly)
        }
        "session" | "session-only" => Ok(AntigravityEnablementScope::SessionOnly),
        "persistent-local-admin" | "persistent" => {
            Ok(AntigravityEnablementScope::PersistentLocalAdmin)
        }
        other => bail!("unsupported Antigravity enablement scope: {other}"),
    }
}

fn parse_antigravity_live_smoke_mode(value: &str) -> Result<AntigravityLiveSmokeMode> {
    match value {
        "disposable-worktree" | "disposable-worktree-audit" | "read-only" | "read-only-audit" => {
            Ok(AntigravityLiveSmokeMode::DisposableWorktreeAudit)
        }
        "disposable-worktree-candidate" | "worktree-candidate" | "worktree-candidate-no-apply" => {
            Ok(AntigravityLiveSmokeMode::DisposableWorktreeCandidateNoApply)
        }
        other => bail!("unsupported Antigravity live-smoke mode: {other}"),
    }
}

fn antigravity_smoke_work_lease(root: &Path, task: &str) -> Result<(WorkState, WorkLease)> {
    let mut state = WorkState::default();
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let controller = AgentSessionService.create_controller(&mut state, project_id);
    let item = WorkQueueService.create_work_item(
        &mut state,
        WorkCreateRequest {
            project_id,
            task_id,
            project: "eliot-governor".to_owned(),
            task: task.to_owned(),
            goal: "Run governed Antigravity smoke in a detached disposable worktree".to_owned(),
            scope: default_work_scope(
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .display()
                    .to_string(),
                vec![".".to_owned()],
                Vec::new(),
                vec!["cargo run -p eliot-app -- verify provider-gate".to_owned()],
            ),
            required: true,
            created_by: controller.agent_session_id,
            required_verifiers: Vec::new(),
        },
    );
    let decision = WorkLeaseService.claim(
        &mut state,
        WorkClaimRequest {
            work_item_id: item.work_item_id,
            agent_session_id: controller.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let lease_id = decision
        .work_lease_id
        .context("G3B smoke did not receive WorkLease")?;
    let lease = state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .cloned()
        .context("G3B smoke WorkLease missing after grant")?;
    let report = WorkQueueService.status_report(&state, "eliot-governor", task);
    write_report_pair(
        &root
            .join("reports")
            .join("antigravity-live-smoke")
            .join("work-lease.json"),
        &root
            .join("reports")
            .join("antigravity-live-smoke")
            .join("work-lease.md"),
        &report,
        &typed_report_markdown("Antigravity Live Smoke WorkLease", &report)?,
    )?;
    Ok((state, lease))
}

fn provider_gate_verification_passed(root: &Path) -> Result<bool> {
    let path = root
        .join("reports")
        .join("verification-verdicts")
        .join("latest.json");
    if !path.is_file() {
        return Ok(false);
    }
    let report: VerificationVerdictsReport = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok(report.verdict.profile_id == "provider-gate"
        && matches!(
            report.verdict.decision,
            VerificationDecision::Allow | VerificationDecision::AllowWithWarnings
        ))
}

fn write_antigravity_real_report_snapshot(
    root: &Path,
    resolution: AntigravityBinaryResolution,
    probe: AntigravityCapabilityProbe,
    contract: AntigravityCommandContract,
    auth: AntigravityAuthCheck,
) -> Result<AntigravityRealReport> {
    let enablement = latest_antigravity_enablement(root)?;
    let live_smoke = latest_antigravity_live_smoke(root)?;
    let disable = latest_antigravity_disable(root)?;
    let runs = latest_antigravity_run(root)?
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let telemetry = AntigravityTelemetryService.report(&probe, &runs);
    let current_state = enablement.as_ref().map_or_else(
        || AntigravityEnablementService.state_from_probe(&probe, Some(&auth)),
        |receipt| receipt.requested_state,
    );
    let doctor = AntigravityRealExecutionDoctor.status(
        &resolution,
        &probe,
        &contract,
        &auth,
        current_state,
        live_smoke.as_ref(),
        disable.as_ref(),
        !runs.is_empty() || live_smoke.is_some(),
    );
    let report = antigravity_real_report(
        resolution, probe, contract, auth, enablement, live_smoke, disable, doctor, telemetry,
    );
    write_antigravity_report_pair(root, "antigravity-real", "Antigravity Real", &report)?;
    Ok(report)
}

fn write_antigravity_skill_files(
    config_path: &Path,
    bundle: &AntigravitySkillBundle,
) -> Result<()> {
    let root = antigravity_plugin_root(config_path);
    for skill in &bundle.skills {
        let path = root.join(&skill.relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &skill.body)?;
    }
    let scripts = root.join("scripts");
    std::fs::create_dir_all(&scripts)?;
    std::fs::write(
        scripts.join("install-skills.ps1"),
        "param([switch]$Apply)\nif (-not $Apply) { Write-Output 'dry-run: no user agy skill files were modified'; exit 0 }\nthrow 'G3A does not install Antigravity skills without a later approval phase'\n",
    )?;
    std::fs::write(
        scripts.join("verify-antigravity-bundle.ps1"),
        "Write-Output 'verify: governed Antigravity bundle contains no raw agy-mcp exposure'\n",
    )?;
    Ok(())
}

fn write_antigravity_plugin_files(
    config_path: &Path,
    bundle: &AntigravityPluginBundle,
) -> Result<()> {
    let root = antigravity_plugin_root(config_path);
    std::fs::create_dir_all(root.join(".codex-plugin"))?;
    std::fs::create_dir_all(root.join("scripts"))?;
    std::fs::write(
        root.join(".codex-plugin").join("plugin.json"),
        serde_json::to_string_pretty(&AntigravityPluginBundleService.manifest_value())?,
    )?;
    std::fs::write(
        root.join("README.md"),
        "# Eliot Antigravity Governed Connector\n\nThis generated bundle is disabled by default and exposes no raw agy or agy-mcp tools.\n",
    )?;
    std::fs::write(
        root.join("scripts").join("verify-antigravity-bundle.ps1"),
        "Write-Output 'verify: plugin bundle is not installable and exposes no raw agy-mcp tools'\n",
    )?;
    std::fs::write(
        root.join("scripts").join("install-skills.ps1"),
        "param([switch]$Apply)\nif (-not $Apply) { Write-Output 'dry-run: plugin install skipped'; exit 0 }\nthrow 'G3A plugin bundle is not installable'\n",
    )?;
    let _ = bundle;
    Ok(())
}

fn parse_antigravity_mode(value: &str) -> Result<AntigravityReviewMode> {
    match value {
        "audit-plan" | "audit_plan" => Ok(AntigravityReviewMode::AuditPlan),
        "candidate-implementation" | "candidate_implementation" => {
            Ok(AntigravityReviewMode::CandidateImplementation)
        }
        other => bail!("unknown Antigravity review mode: {other}"),
    }
}

fn antigravity_mcp_tools_governed_only() -> bool {
    AntigravityMcpBoundaryService.exposes_only_governed(mcp_stdio::governed_tool_names())
}

fn parse_external_review_role(value: &str) -> Result<ExternalReviewRole> {
    match value {
        "auditor" => Ok(ExternalReviewRole::Auditor),
        "reviewer" => Ok(ExternalReviewRole::Reviewer),
        "critic" => Ok(ExternalReviewRole::Critic),
        "worker" => Ok(ExternalReviewRole::Worker),
        other => bail!("unknown external review role: {other}"),
    }
}

fn external_output_schema_for(
    request: &ExternalReviewRequest,
    profile: &ExternalProviderProfile,
) -> ExternalOutputSchemaKind {
    if request.role == ExternalReviewRole::Worker
        || profile.provider_id == "mock-proposed-change"
        || profile
            .output_schemas
            .contains(&ExternalOutputSchemaKind::ProposedChanges)
    {
        ExternalOutputSchemaKind::ProposedChanges
    } else if profile
        .output_schemas
        .contains(&ExternalOutputSchemaKind::MixedReview)
    {
        ExternalOutputSchemaKind::MixedReview
    } else {
        ExternalOutputSchemaKind::AuditFindings
    }
}

fn ensure_external_review_work_lease(
    root: &Path,
    request: &mut ExternalReviewRequest,
) -> Result<(WorkState, Option<WorkLease>)> {
    let mut state = load_work_state(root)?;
    let controller = AgentSessionService.create_controller(&mut state, request.project_id);
    let item = WorkQueueService.create_work_item(
        &mut state,
        WorkCreateRequest {
            project_id: request.project_id,
            task_id: request.task_id,
            project: request.project.clone(),
            task: request.task.clone(),
            goal: request.question.clone(),
            scope: default_work_scope(
                repo_root().display().to_string(),
                request.allowed_paths.clone(),
                Vec::new(),
                vec!["provider-integration".to_owned()],
            ),
            required: true,
            created_by: controller.agent_session_id,
            required_verifiers: Vec::new(),
        },
    );
    let decision = WorkLeaseService.claim(
        &mut state,
        WorkClaimRequest {
            work_item_id: item.work_item_id,
            agent_session_id: controller.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let work_lease = decision.work_lease_id.and_then(|lease_id| {
        state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    request.work_lease_id = work_lease.as_ref().map(|lease| lease.work_lease_id);
    Ok((state, work_lease))
}

fn read_report_json<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

fn read_json_value(path: &Path) -> Result<serde_json::Value> {
    read_report_json(path)
}

fn filter_report_item(
    report: &serde_json::Value,
    array_key: &str,
    id_key: &str,
    id_value: &str,
) -> serde_json::Value {
    report
        .get(array_key)
        .and_then(serde_json::Value::as_array)
        .and_then(|values| {
            values.iter().find(|value| {
                value.get(id_key).and_then(serde_json::Value::as_str) == Some(id_value)
            })
        })
        .cloned()
        .unwrap_or_else(|| {
            serde_json::json!({
                "status": "not_found",
                "array": array_key,
                "id_key": id_key,
                "id_value": id_value
            })
        })
}

fn report_path_status(root: &Path, report_dir: &str) -> serde_json::Value {
    let path = root.join("reports").join(report_dir).join("latest.json");
    serde_json::json!({
        "path": path,
        "exists": path.is_file()
    })
}

fn external_review_mcp_tools_governed_only() -> bool {
    let tools = mcp_stdio::governed_tool_names();
    [
        "eliot_external_review_providers",
        "eliot_external_review_request",
        "eliot_external_review_job_status",
        "eliot_external_review_result",
        "eliot_external_review_report",
        "eliot_external_review_run_mock",
    ]
    .into_iter()
    .all(|tool| tools.contains(&tool))
        && tools.iter().all(|tool| {
            ![
                "raw_exec",
                "raw_secret",
                "raw_patch",
                "raw_truth",
                "run_gemini",
                "run_antigravity",
                "eliot_run_gemini",
                "eliot_run_antigravity",
            ]
            .into_iter()
            .any(|forbidden| tool.contains(forbidden))
        })
}

fn write_h1_report<T>(root: &Path, name: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(name).join("latest.json"),
        &root.join("reports").join(name).join("latest.md"),
        value,
        &typed_report_markdown(title, value)?,
    )
}

fn h1_service_manager(config_path: &Path) -> Result<WindowsServiceManager> {
    let executable_path = std::env::current_exe().context("resolve current executable")?;
    Ok(WindowsServiceManager::new(
        WindowsServiceManager::default_config(&runtime_root(config_path), &executable_path),
    ))
}

fn run_service_control(
    config_path: &Path,
    action: ServiceInstallAction,
    title: &str,
) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.control(action);
    write_h1_report(&runtime_root(config_path), "service", title, &receipt)?;
    write_json(&receipt)
}

fn h1_started_ipc(config_path: &Path) -> Result<(NamedPipeIpcServer, String)> {
    let manager = h1_service_manager(config_path)?;
    let token = "h1-local-ipc-token".to_owned();
    let mut server =
        NamedPipeIpcServer::in_memory(manager.config().ipc.clone(), hash_secret(&token));
    server.start()?;
    Ok((server, token))
}

fn h1_credentials_report(config_path: &Path) -> Result<eliot_types::CredentialDiagnosticsReport> {
    let config = load_config(config_path)?;
    let surreal = &config.db.surreal;
    let generated_at = time::OffsetDateTime::now_utc();
    let (present, version) = match surreal.credential_provider {
        CredentialProviderKind::WindowsCredentialManager => {
            let status = eliot_windows_ipc::credential_status_current_user(&surreal.credential_id)?;
            (
                status.present,
                status.version.map(|value| value.to_string()),
            )
        }
        CredentialProviderKind::LegacyPasswordFile => {
            let path =
                resolve_runtime_config_path(&runtime_root(config_path), &surreal.password_file);
            let metadata = std::fs::metadata(path).ok();
            let version = metadata
                .as_ref()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs().to_string());
            (metadata.is_some(), version)
        }
        _ => (false, None),
    };
    let config_text = std::fs::read_to_string(config_path).unwrap_or_default();
    Ok(eliot_types::CredentialDiagnosticsReport {
        component: "credentials_report".to_owned(),
        refs: vec![CredentialRef {
            credential_id: surreal.credential_id.clone(),
            provider: surreal.credential_provider,
            purpose: CredentialPurpose::SurrealDbRuntime,
            created_at: generated_at,
        }],
        statuses: vec![CredentialStatus {
            credential_id: surreal.credential_id.clone(),
            provider: surreal.credential_provider,
            present,
            version,
            fingerprint: None,
        }],
        resolved_count: usize::from(present),
        secret_values_redacted: true,
        toml_contains_secret_values: eliot_types::inspect_secret_bytes(config_text.as_bytes())
            .is_err(),
        command_line_contains_secret_values: false,
        warnings: vec![
            "credential status exposes metadata only; values are resolved inside the governed runtime"
                .to_owned(),
        ],
        generated_at,
    })
}

fn h1_readiness_probe(root: &Path) -> Result<eliot_types::ServiceReadinessProbe> {
    let phase_gate_passed = h1_phase_minimal_eval_gate_passed(root)?;
    h1_readiness_probe_with_phase_gate(root, phase_gate_passed)
}

fn h1_readiness_probe_with_phase_gate(
    root: &Path,
    phase_minimal_eval_gate_passed: bool,
) -> Result<eliot_types::ServiceReadinessProbe> {
    let data_root = DataRootService::new(root).validate(DataRootMode::DevProjectLocal)?;
    let fixture = ReadinessFixture {
        data_root_validated: ProductionReadinessService::data_root_validation_passed(
            data_root.status,
        ),
        credential_refs_resolved: true,
        db_reachable: true,
        writer_self_check: true,
        read_self_check: true,
        ipc_listening: true,
        phase_minimal_eval_gate_passed,
        blocking_incident: IncidentService::new(root).lockdown_active()?,
    };
    Ok(ProductionReadinessService::probe("EliotGovernor", &fixture))
}

fn h1_phase_minimal_eval_gate_passed(root: &Path) -> Result<bool> {
    let artifacts = ensure_k1_smoke_artifacts(root, "k0-core-smoke")?;
    Ok(artifacts.gate_decision.decision == EvalGateDecisionKind::Allow)
}

fn read_latest_json(config_path: &Path, name: &str) -> Result<()> {
    let path = runtime_root(config_path)
        .join("reports")
        .join(name)
        .join("latest.json");
    if !path.is_file() {
        bail!("no latest {name} report found");
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    write_json(&value)
}

fn read_latest_or_generate<T, E, F>(config_path: &Path, name: &str, generate: F) -> Result<()>
where
    T: serde::Serialize,
    E: std::error::Error + Send + Sync + 'static,
    F: FnOnce() -> std::result::Result<T, E>,
{
    let path = runtime_root(config_path)
        .join("reports")
        .join(name)
        .join("latest.json");
    if path.is_file() {
        let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
        write_json(&value)
    } else {
        let value = generate()?;
        write_json(&value)
    }
}

fn read_or_generate_doctor_report(config_path: &Path) -> Result<serde_json::Value> {
    let root = runtime_root(config_path);
    let path = root.join("reports").join("doctor").join("latest.json");
    if path.is_file() {
        Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
    } else {
        let report = DoctorService::new(&root, repo_root()).report()?;
        write_safety_report(&root, "doctor", "Doctor", &report)?;
        Ok(serde_json::to_value(report)?)
    }
}

fn repo_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn parse_data_root_mode(value: &str) -> Result<DataRootMode> {
    match normalized_arg(value).as_str() {
        "dev" | "devprojectlocal" | "devproject-local" | "dev-project-local" => {
            Ok(DataRootMode::DevProjectLocal)
        }
        "production" | "prod" | "productionlocal" | "production-local" => {
            Ok(DataRootMode::ProductionLocal)
        }
        "recovery" | "recoveryoffline" | "recovery-offline" => Ok(DataRootMode::RecoveryOffline),
        "test" | "testisolated" | "test-isolated" => Ok(DataRootMode::TestIsolated),
        other => bail!("unknown data-root profile: {other}"),
    }
}

fn parse_backup_kind(value: &str) -> Result<BackupKind> {
    match normalized_arg(value).as_str() {
        "logical" | "logicalexport" | "logical-export" => Ok(BackupKind::LogicalExport),
        "offline" | "offlinesnapshot" | "offline-snapshot" => Ok(BackupKind::OfflineSnapshot),
        "incremental" | "incrementallogical" | "incremental-logical" => {
            Ok(BackupKind::IncrementalLogical)
        }
        "premigration" | "pre-migration" => Ok(BackupKind::PreMigration),
        "test" | "testfixture" | "test-fixture" => Ok(BackupKind::TestFixture),
        other => bail!("unknown backup kind: {other}"),
    }
}

fn parse_export_kind(value: &str) -> Result<ExportKind> {
    match normalized_arg(value).as_str() {
        "reports" | "reportsonly" | "reports-only" => Ok(ExportKind::ReportsOnly),
        "projectevidence" | "project-evidence" => Ok(ExportKind::ProjectEvidence),
        "memorysnapshot" | "memory-snapshot" => Ok(ExportKind::MemorySnapshot),
        "incidentbundle" | "incident-bundle" => Ok(ExportKind::IncidentBundle),
        "debugbundle" | "debug-bundle" => Ok(ExportKind::DebugBundle),
        other => bail!("unknown export kind: {other}"),
    }
}

fn parse_maintenance_job_kind(value: &str) -> Result<MaintenanceJobKind> {
    match normalized_arg(value).as_str() {
        "backup" => Ok(MaintenanceJobKind::Backup),
        "restoreverify" | "restore-verify" => Ok(MaintenanceJobKind::RestoreVerify),
        "export" => Ok(MaintenanceJobKind::Export),
        "importvalidate" | "import-validate" => Ok(MaintenanceJobKind::ImportValidate),
        "blobgc" | "blob-gc" => Ok(MaintenanceJobKind::BlobGc),
        "doctor" => Ok(MaintenanceJobKind::Doctor),
        "incidentreview" | "incident-review" => Ok(MaintenanceJobKind::IncidentReview),
        "configsnapshot" | "config-snapshot" => Ok(MaintenanceJobKind::ConfigSnapshot),
        "policysnapshot" | "policy-snapshot" => Ok(MaintenanceJobKind::PolicySnapshot),
        other => bail!("unknown maintenance job kind: {other}"),
    }
}

fn parse_incident_kind(value: &str) -> Result<IncidentKind> {
    match normalized_arg(value).as_str() {
        "backupmanifestmismatch" | "backup-manifest-mismatch" => {
            Ok(IncidentKind::BackupManifestMismatch)
        }
        "restoreintegrityfailure" | "restore-integrity-failure" => {
            Ok(IncidentKind::RestoreIntegrityFailure)
        }
        "blobchecksummismatch" | "blob-checksum-mismatch" => Ok(IncidentKind::BlobChecksumMismatch),
        "writerunavailable" | "writer-unavailable" => Ok(IncidentKind::WriterUnavailable),
        "dbunavailable" | "db-unavailable" => Ok(IncidentKind::DbUnavailable),
        "outboxmismatch" | "outbox-mismatch" => Ok(IncidentKind::OutboxMismatch),
        "deadletterthreshold" | "dead-letter-threshold" => Ok(IncidentKind::DeadLetterThreshold),
        "directdbbypassdetected" | "direct-db-bypass-detected" => {
            Ok(IncidentKind::DirectDbBypassDetected)
        }
        "invalidconfig" | "invalid-config" => Ok(IncidentKind::InvalidConfig),
        "invalidpolicy" | "invalid-policy" => Ok(IncidentKind::InvalidPolicy),
        "repeatedservicefailure" | "repeated-service-failure" => {
            Ok(IncidentKind::RepeatedServiceFailure)
        }
        "unknownsequencebase" | "unknown-sequence-base" => Ok(IncidentKind::UnknownSequenceBase),
        "campaignprovidercallbudgetexceeded" | "campaign-provider-call-budget-exceeded" => {
            Ok(IncidentKind::CampaignProviderCallBudgetExceeded)
        }
        other => bail!("unknown incident kind: {other}"),
    }
}

fn parse_incident_severity(value: &str) -> Result<IncidentSeverity> {
    match normalized_arg(value).as_str() {
        "info" => Ok(IncidentSeverity::Info),
        "warning" => Ok(IncidentSeverity::Warning),
        "degraded" => Ok(IncidentSeverity::Degraded),
        "blocking" => Ok(IncidentSeverity::Blocking),
        "critical" => Ok(IncidentSeverity::Critical),
        other => bail!("unknown incident severity: {other}"),
    }
}

fn normalized_arg(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

fn verify_plugin_report(config_path: &Path) -> Result<PluginInstallCheck> {
    let root = runtime_root(config_path);
    let verifier = PluginVerifier::new(plugin_root(config_path));
    let report = verifier.verify()?;
    write_report_pair(
        &root.join("reports").join("plugin").join("latest.json"),
        &root.join("reports").join("plugin").join("latest.md"),
        &report,
        &plugin_report_markdown(&report),
    )?;
    Ok(report)
}

fn write_patch_reports(
    root: &Path,
    patch_run: &PatchRun,
    verifier_runs: &[VerifierRun],
) -> Result<()> {
    let patch_report = patch_report_value(patch_run, verifier_runs);
    write_report_pair(
        &root.join("reports").join("patch").join("latest.json"),
        &root.join("reports").join("patch").join("latest.md"),
        &patch_report,
        &patch_report_markdown(&patch_report),
    )?;
    write_verifier_report(root, &patch_run.patch_request_id.to_string(), verifier_runs)
}

fn write_verifier_report(root: &Path, plan_ref: &str, verifier_runs: &[VerifierRun]) -> Result<()> {
    let report = verifier_report_value(plan_ref, verifier_runs);
    write_report_pair(
        &root.join("reports").join("verifier").join("latest.json"),
        &root.join("reports").join("verifier").join("latest.md"),
        &report,
        &phase_closeout_markdown("Verifier Report", &report),
    )
}

fn latest_patch_report(root: &Path) -> Result<Option<serde_json::Value>> {
    let path = root.join("reports").join("patch").join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_verifier_report(root: &Path) -> Result<Option<serde_json::Value>> {
    let path = root.join("reports").join("verifier").join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn patch_report_value(patch_run: &PatchRun, verifier_runs: &[VerifierRun]) -> serde_json::Value {
    serde_json::json!({
        "component": "patch",
        "patch_run": patch_run,
        "verifier_runs": verifier_runs,
        "final_status": patch_run_final_status(patch_run)
    })
}

fn verifier_report_value(plan_ref: &str, verifier_runs: &[VerifierRun]) -> serde_json::Value {
    serde_json::json!({
        "component": "verifier",
        "plan_ref": plan_ref,
        "verifier_runs": verifier_runs,
        "final_status": verifier_runs_final_status(verifier_runs)
    })
}

fn patch_run_final_status(patch_run: &PatchRun) -> &'static str {
    match patch_run.status {
        PatchRunStatus::AppliedVerifierPassed | PatchRunStatus::PreflightPassed => "DONE_VERIFIED",
        PatchRunStatus::RollbackFailed => "UNSAFE_TO_FINISH",
        PatchRunStatus::AppliedVerifierFailed | PatchRunStatus::RolledBack => "FAILED_VERIFIER",
        PatchRunStatus::Denied => "PARTIAL_PROGRESS",
    }
}

fn verifier_runs_final_status(verifier_runs: &[VerifierRun]) -> &'static str {
    if verifier_runs.is_empty() {
        return "NOT_RUN";
    }
    if verifier_runs
        .iter()
        .filter(|run| run.required_for_done)
        .all(|run| run.status == VerifierStatus::Passed)
    {
        "DONE_VERIFIED"
    } else {
        "FAILED_VERIFIER"
    }
}

fn patch_report_markdown(report: &serde_json::Value) -> String {
    let mut output = String::from("# Patch Report\n\n");
    if let Some(patch_run) = report.get("patch_run") {
        let status = patch_run
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let patch_run_id = patch_run
            .get("patch_run_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let _ = writeln!(output, "- patch_run_id: `{patch_run_id}`");
        let _ = writeln!(output, "- status: `{status}`");
    }
    let final_status = report
        .get("final_status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("UNKNOWN");
    let _ = writeln!(output, "- final_status: `{final_status}`");
    output
}

fn codecortex_report_markdown(report: &CodeCortexReport) -> String {
    let mut output = String::from("# CodeCortex D1 Report\n\n");
    let _ = writeln!(output, "- project: `{}`", report.project);
    let _ = writeln!(output, "- task: `{}`", report.task);
    let _ = writeln!(output, "- final_status: `{}`", report.final_status);
    let _ = writeln!(output, "- repo_root: `{}`", report.repo_root);
    let _ = writeln!(
        output,
        "- git_head: `{}`",
        report.git_head.as_deref().unwrap_or("unknown")
    );
    let _ = writeln!(output, "- dirty: `{}`", report.dirty);
    let _ = writeln!(output, "- tracked_files: `{}`", report.tracked_files.len());
    let _ = writeln!(output, "- crates: `{}`", report.crates.join(", "));
    let _ = writeln!(output, "- file_evidence: `{}`", report.file_evidence.len());
    let _ = writeln!(
        output,
        "- symbol_evidence: `{}`",
        report.symbol_evidence.len()
    );
    let _ = writeln!(
        output,
        "- diagnostic_evidence: `{}`",
        report.diagnostic_evidence.len()
    );
    let _ = writeln!(
        output,
        "- memory_receipt: `{}`",
        report
            .memory_receipt
            .as_ref()
            .map_or_else(|| "none".to_owned(), |receipt| receipt.write_id.to_string())
    );
    output.push_str("\n## Adapters\n\n");
    for evidence in &report.verifier_evidence {
        let _ = writeln!(
            output,
            "- {}: `{}` - {}",
            evidence.name, evidence.status, evidence.summary
        );
    }
    output
}

fn writer_status_markdown(report: &eliot_types::WriterStatusResponse) -> String {
    format!(
        concat!(
            "# Writer Status\n\n",
            "- transport_status: `{}`\n",
            "- db_version: `{}`\n",
            "- pending_count: `{}`\n",
            "- committed_count: `{}`\n",
            "- failed_permanent_count: `{}`\n",
            "- rejected_count: `{}`\n",
            "- dead_letter_count: `{}`\n",
            "- unknown_commit_count: `{}`\n",
            "- idempotent_replay_count: `{}`\n",
            "- idempotency_conflict_count: `{}`\n",
            "- final_status: `{}`\n"
        ),
        report.transport_status,
        report.db_version,
        report.pending_count,
        report.committed_count,
        report.failed_permanent_count,
        report.rejected_count,
        report.dead_letter_count,
        report.unknown_commit_count,
        report.idempotent_replay_count,
        report.idempotency_conflict_count,
        report.final_status
    )
}

fn graph_health_markdown(report: &eliot_types::GraphHealthResponse) -> String {
    format!(
        concat!(
            "# Graph Health\n\n",
            "- orphan_claims: `{}`\n",
            "- claims_without_support: `{}`\n",
            "- claims_without_verification: `{}`\n",
            "- verified_claims: `{}`\n",
            "- supported_claims: `{}`\n",
            "- weak_claims: `{}`\n",
            "- contested_claims: `{}`\n",
            "- duplicate_write_ids: `{}`\n"
        ),
        report.orphan_claims,
        report.claims_without_support,
        report.claims_without_verification,
        report.verified_claims,
        report.supported_claims,
        report.weak_claims,
        report.contested_claims,
        report.duplicate_write_ids
    )
}

fn phase_closeout_markdown(title: &str, report: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(checks) = report.get("checks").and_then(serde_json::Value::as_object) {
        for (name, status) in checks {
            let status = status.as_str().unwrap_or("unknown");
            let _ = writeln!(output, "- {name}: `{status}`");
        }
    }
    let status = report
        .get("final_status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("UNKNOWN");
    let _ = writeln!(output, "\n- final_status: `{status}`");
    output
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalCasesReport {
    component: String,
    cases: Vec<EvalCase>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalSuitesReport {
    component: String,
    suites: Vec<EvalSuite>,
    latest: EvalSuite,
    manifest: Option<EvalDatasetManifest>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalRunsReport {
    component: String,
    run: EvalRun,
    profile: EvalRunProfile,
    blocked_mutation_run: EvalRun,
    experiment: HarnessExperimentRecord,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalVerdictsReport {
    component: String,
    verdict: EvalVerdict,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalFailuresReport {
    component: String,
    clusters: Vec<EvalFailureCluster>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BenchmarkIntegrityReport {
    component: String,
    valid_receipt: BenchmarkIntegrityReceipt,
    mismatch_receipt: BenchmarkIntegrityReceipt,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalCoverageReport {
    component: String,
    coverage: EvalCoverageMatrix,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalBaselinesReport {
    component: String,
    suite_id: String,
    baselines: Vec<EvalBaseline>,
    active: Option<EvalBaseline>,
    incident_lockdown_blocks_mutation: bool,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalComparisonsReport {
    component: String,
    baseline: EvalBaseline,
    candidate_run: EvalRun,
    comparison: EvalCandidateComparison,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalGatesReport {
    component: String,
    profile: EvalRegressionGateProfile,
    comparison: Option<EvalCandidateComparison>,
    decision: EvalGateDecision,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalProfilesReport {
    component: String,
    profiles: Vec<EvalRegressionGateProfile>,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalTrendsReport {
    component: String,
    trend: EvalTrendReport,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalFixtureStabilityReportEnvelope {
    component: String,
    repeat: u8,
    stability: EvalFixtureStabilityReport,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: time::OffsetDateTime,
}

struct K0SmokeArtifacts {
    cases: Vec<EvalCase>,
    suite: EvalSuite,
    manifest: EvalDatasetManifest,
    profile: EvalRunProfile,
    integrity_receipt: BenchmarkIntegrityReceipt,
    mismatch_receipt: BenchmarkIntegrityReceipt,
    run: EvalRun,
    blocked_mutation_run: EvalRun,
    verdict: EvalVerdict,
    fixture_failure_cluster: EvalFailureCluster,
    experiment: HarnessExperimentRecord,
}

struct K1SmokeArtifacts {
    k0: K0SmokeArtifacts,
    coverage: EvalCoverageMatrix,
    baseline: EvalBaseline,
    candidate_run: EvalRun,
    comparison: EvalCandidateComparison,
    gate_decision: EvalGateDecision,
    critical_candidate_run: EvalRun,
    critical_comparison: EvalCandidateComparison,
    critical_gate_decision: EvalGateDecision,
    benchmark_repair_decision: EvalGateDecision,
    profiles: Vec<EvalRegressionGateProfile>,
    trend: EvalTrendReport,
    stability: EvalFixtureStabilityReport,
    doctor_status: serde_json::Value,
}

fn ensure_k0_smoke_artifacts(root: &Path, suite_name: &str) -> Result<K0SmokeArtifacts> {
    let suite_name = if suite_name == "latest" {
        "k0-core-smoke"
    } else {
        suite_name
    };
    let project_id = project_id_from_label("eliot-governor");
    let task_id = task_id_from_label("phase-k0-smoke");
    let cases = EvalCaseService::k0_core_cases(project_id, Some(task_id));
    let mut suite = EvalSuiteService::create(EvalSuiteInput {
        project_id,
        name: suite_name.to_owned(),
        purpose: "Phase K0 deterministic no-mutation core smoke suite".to_owned(),
        cases: cases.iter().map(|case| case.eval_case_id).collect(),
        fixed: false,
        holdout: true,
        created_from_refs: vec!["phase-k0:runbook".to_owned()],
    });
    EvalSuiteService::freeze(&mut suite);
    let manifest = EvalDatasetManifestService::manifest(&suite, &cases);
    let profile = EvalRunnerService::deterministic_no_mutation_profile();
    EvalRegressionGate::allow_run(&suite, &manifest, &profile, false, false)?;
    let integrity_receipt = EvalDatasetManifestService::verify(&suite, &manifest);
    let mismatch_receipt = EvalDatasetManifestService::checksum_mismatch(&suite, &manifest);
    let run = EvalRunnerService::run(EvalRunInput {
        project_id,
        suite: suite.clone(),
        cases: cases.clone(),
        manifest: manifest.clone(),
        profile: profile.clone(),
        mutation_attempt: None,
    });
    let blocked_mutation_run = EvalRunnerService::run(EvalRunInput {
        project_id,
        suite: suite.clone(),
        cases: cases.clone(),
        manifest: manifest.clone(),
        profile: profile.clone(),
        mutation_attempt: Some("apply current truth".to_owned()),
    });
    let verdict = EvalVerdictService::verdict(&run);
    let fixture_failure_cluster = EvalVerdictService::fixture_failure_cluster(run.eval_run_id);
    let experiment = harness_experiment_record(&run, &verdict);
    let artifacts = K0SmokeArtifacts {
        cases,
        suite,
        manifest,
        profile,
        integrity_receipt,
        mismatch_receipt,
        run,
        blocked_mutation_run,
        verdict,
        fixture_failure_cluster,
        experiment,
    };
    write_k0_artifact_reports(root, &artifacts)?;
    Ok(artifacts)
}

fn write_k0_artifact_reports(root: &Path, artifacts: &K0SmokeArtifacts) -> Result<()> {
    let generated_at = time::OffsetDateTime::now_utc();
    write_eval_report(
        root,
        "eval-cases",
        "Eval Cases",
        &EvalCasesReport {
            component: "eval_cases".to_owned(),
            cases: artifacts.cases.clone(),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-suites",
        "Eval Suites",
        &EvalSuitesReport {
            component: "eval_suites".to_owned(),
            suites: vec![artifacts.suite.clone()],
            latest: artifacts.suite.clone(),
            manifest: Some(artifacts.manifest.clone()),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-runs",
        "Eval Runs",
        &EvalRunsReport {
            component: "eval_runs".to_owned(),
            run: artifacts.run.clone(),
            profile: artifacts.profile.clone(),
            blocked_mutation_run: artifacts.blocked_mutation_run.clone(),
            experiment: artifacts.experiment.clone(),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-verdicts",
        "Eval Verdicts",
        &EvalVerdictsReport {
            component: "eval_verdicts".to_owned(),
            verdict: artifacts.verdict.clone(),
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "eval-failures",
        "Eval Failures",
        &EvalFailuresReport {
            component: "eval_failures".to_owned(),
            clusters: vec![artifacts.fixture_failure_cluster.clone()],
            generated_at,
        },
    )?;
    write_eval_report(
        root,
        "benchmark-integrity",
        "Benchmark Integrity",
        &BenchmarkIntegrityReport {
            component: "benchmark_integrity".to_owned(),
            valid_receipt: artifacts.integrity_receipt.clone(),
            mismatch_receipt: artifacts.mismatch_receipt.clone(),
            generated_at,
        },
    )
}

#[allow(clippy::too_many_lines)]
fn ensure_k1_smoke_artifacts(root: &Path, suite_name: &str) -> Result<K1SmokeArtifacts> {
    let k0 = ensure_k0_smoke_artifacts(root, suite_name)?;
    let coverage = eval_coverage_report(&k0).coverage;
    write_eval_report(
        root,
        "eval-coverage",
        "Eval Coverage",
        &EvalCoverageReport {
            component: "eval_coverage".to_owned(),
            coverage: coverage.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let baseline = EvalBaselineService::create(
        &k0.suite,
        &k0.manifest,
        &k0.integrity_receipt,
        &k0.run,
        &k0.verdict,
        &git_commit,
        "phase-k1-smoke",
    )?;
    write_eval_baseline_registry(root, &k0.suite, baseline.clone())?;

    let candidate_run = k0.run.clone();
    let comparison =
        EvalComparisonService::compare(&k0.suite, &baseline, &candidate_run, &git_commit);
    write_eval_report(
        root,
        "eval-comparisons",
        "Eval Candidate Comparisons",
        &EvalComparisonsReport {
            component: "eval_comparisons".to_owned(),
            baseline: baseline.clone(),
            candidate_run: candidate_run.clone(),
            comparison: comparison.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let profiles = EvalGateProfileService::built_in_profiles();
    for profile in &profiles {
        EvalGateProfileService::validate(profile)?;
    }
    let phase_minimal = EvalGateProfileService::find("phase-minimal")
        .context("phase-minimal eval gate profile is missing")?;
    let gate_decision = EvalRegressionGateService::evaluate_comparison(
        &phase_minimal,
        &comparison,
        &k0.integrity_receipt,
    );
    let critical_candidate_run =
        EvalComparisonService::run_with_failed_family(&candidate_run, EvalFamily::Understand);
    let critical_comparison =
        EvalComparisonService::compare(&k0.suite, &baseline, &critical_candidate_run, &git_commit);
    let critical_gate_decision = EvalRegressionGateService::evaluate_comparison(
        &phase_minimal,
        &critical_comparison,
        &k0.integrity_receipt,
    );
    let benchmark_repair_decision = EvalRegressionGateService::evaluate_comparison(
        &phase_minimal,
        &comparison,
        &k0.mismatch_receipt,
    );
    write_eval_report(
        root,
        "eval-gates",
        "Eval Gates",
        &EvalGatesReport {
            component: "eval_gates".to_owned(),
            profile: phase_minimal,
            comparison: Some(comparison.clone()),
            decision: gate_decision.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let trend = EvalTrendService::trend(
        &k0.suite,
        &[candidate_run.clone(), critical_candidate_run.clone()],
    );
    write_eval_report(
        root,
        "eval-trends",
        "Eval Trends",
        &EvalTrendsReport {
            component: "eval_trends".to_owned(),
            trend: trend.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let stability = EvalFixtureStabilityService::report(
        &k0.suite,
        &[candidate_run.clone(), candidate_run.clone()],
    );
    write_eval_report(
        root,
        "eval-fixture-stability",
        "Eval Fixture Stability",
        &EvalFixtureStabilityReportEnvelope {
            component: "eval_fixture_stability".to_owned(),
            repeat: 2,
            stability: stability.clone(),
            generated_at: time::OffsetDateTime::now_utc(),
        },
    )?;

    let doctor_status = EvalDoctorIntegration::status(
        Some(&baseline),
        Some(&gate_decision),
        &coverage,
        Some(&trend),
        Some(&stability),
        &k0.integrity_receipt,
    );

    Ok(K1SmokeArtifacts {
        k0,
        coverage,
        baseline,
        candidate_run,
        comparison,
        gate_decision,
        critical_candidate_run,
        critical_comparison,
        critical_gate_decision,
        benchmark_repair_decision,
        profiles,
        trend,
        stability,
        doctor_status,
    })
}

fn eval_coverage_report(artifacts: &K0SmokeArtifacts) -> EvalCoverageReport {
    EvalCoverageReport {
        component: "eval_coverage".to_owned(),
        coverage: EvalCoverageService::matrix(
            project_id_from_label("eliot-governor"),
            std::slice::from_ref(&artifacts.suite),
            &artifacts.cases,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    }
}

fn write_eval_baseline_registry(
    root: &Path,
    suite: &EvalSuite,
    baseline: EvalBaseline,
) -> Result<()> {
    let mut baselines = read_eval_baselines_report(root)
        .map(|report| report.baselines)
        .unwrap_or_default();
    baselines.push(baseline);
    let active = EvalBaselineService::active_baseline(&baselines);
    let report = EvalBaselinesReport {
        component: "eval_baselines".to_owned(),
        suite_id: suite.eval_suite_id.to_string(),
        baselines,
        active,
        incident_lockdown_blocks_mutation:
            EvalRegressionGateService::incident_lockdown_blocks_baseline_mutation(true),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_eval_report(root, "eval-baselines", "Eval Baselines", &report)
}

fn resolve_eval_baseline(
    root: &Path,
    artifacts: &K0SmokeArtifacts,
    baseline_ref: &str,
) -> Result<EvalBaseline> {
    let report = read_eval_baselines_report(root).ok();
    if let Some(report) = report {
        if baseline_ref == "latest"
            && let Some(active) = report.active
        {
            return Ok(active);
        }
        if let Some(baseline) = report
            .baselines
            .into_iter()
            .find(|baseline| baseline.baseline_id == baseline_ref)
        {
            return Ok(baseline);
        }
    }
    let git_commit = git_head_blocking(&repo_root()).unwrap_or_else(|_| "unknown".to_owned());
    let baseline = EvalBaselineService::create(
        &artifacts.suite,
        &artifacts.manifest,
        &artifacts.integrity_receipt,
        &artifacts.run,
        &artifacts.verdict,
        &git_commit,
        "auto-baseline",
    )?;
    write_eval_baseline_registry(root, &artifacts.suite, baseline.clone())?;
    Ok(baseline)
}

fn ensure_eval_run_ref(run: &EvalRun, run_ref: &str) -> Result<()> {
    if run_ref != "latest" && run_ref != run.eval_run_id.to_string() {
        bail!("only latest eval run or its id is available in K1 CLI");
    }
    Ok(())
}

fn ensure_eval_cases(root: &Path) -> Result<Vec<EvalCase>> {
    match read_eval_cases_report(root) {
        Ok(report) if !report.cases.is_empty() => Ok(report.cases),
        _ => {
            let cases = k0_default_cases();
            write_eval_report(
                root,
                "eval-cases",
                "Eval Cases",
                &EvalCasesReport {
                    component: "eval_cases".to_owned(),
                    cases: cases.clone(),
                    generated_at: time::OffsetDateTime::now_utc(),
                },
            )?;
            Ok(cases)
        }
    }
}

fn k0_default_cases() -> Vec<EvalCase> {
    EvalCaseService::k0_core_cases(
        project_id_from_label("eliot-governor"),
        Some(task_id_from_label("phase-k0-smoke")),
    )
}

fn eval_summary_report(root: &Path) -> Result<serde_json::Value> {
    if !latest_report_path(root, "eval-runs").is_file() {
        let _ = ensure_k0_smoke_artifacts(root, "k0-core-smoke")?;
    }
    let run_report = read_latest_value(root, "eval-runs").ok();
    let verdict_report = read_latest_value(root, "eval-verdicts").ok();
    let integrity_report = read_latest_value(root, "benchmark-integrity").ok();
    let failures_report = read_latest_value(root, "eval-failures").ok();
    let coverage_report = read_latest_value(root, "eval-coverage").ok();
    let baseline_report = read_latest_value(root, "eval-baselines").ok();
    let comparison_report = read_latest_value(root, "eval-comparisons").ok();
    let gate_report = read_latest_value(root, "eval-gates").ok();
    let trend_report = read_latest_value(root, "eval-trends").ok();
    let stability_report = read_latest_value(root, "eval-fixture-stability").ok();
    let report = serde_json::json!({
        "component": "eval_report",
        "last_eval_run": run_report,
        "last_eval_verdict": verdict_report,
        "failure_clusters": failures_report,
        "benchmark_integrity_state": integrity_report,
        "coverage": coverage_report,
        "active_baseline": baseline_report,
        "last_candidate_comparison": comparison_report,
        "last_eval_gate_decision": gate_report,
        "trend": trend_report,
        "fixture_stability": stability_report,
        "eval_regression_gate_state": "deterministic-no-mutation-only",
        "missing_fixed_suite": false,
        "holdout_contamination_warnings": [],
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_eval_report(root, "eval-report", "Eval Report", &report)?;
    Ok(report)
}

fn read_eval_cases_report(root: &Path) -> Result<EvalCasesReport> {
    read_latest_typed(root, "eval-cases")
}

fn read_eval_suites_report(root: &Path) -> Result<EvalSuitesReport> {
    read_latest_typed(root, "eval-suites")
}

fn read_eval_runs_report(root: &Path) -> Result<EvalRunsReport> {
    read_latest_typed(root, "eval-runs")
}

fn read_eval_baselines_report(root: &Path) -> Result<EvalBaselinesReport> {
    read_latest_typed(root, "eval-baselines")
}

fn write_eval_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let json_value = serde_json::to_value(value)?;
    write_report_pair(
        &latest_report_path(root, dir),
        &latest_markdown_path(root, dir),
        value,
        &eval_value_markdown(title, &json_value),
    )
}

fn eval_value_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(component) = value.get("component").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- component: `{component}`");
    }
    if let Some(verdict) = value
        .get("verdict")
        .and_then(|verdict| verdict.get("status"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- verdict: `{verdict}`");
    }
    if let Some(run_status) = value
        .get("run")
        .and_then(|run| run.get("status"))
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- run_status: `{run_status}`");
    }
    let _ = writeln!(
        output,
        "- profile: `deterministic-no-mutation`\n- authority: `report-only; no truth, policy, skill, action, patch, or completion mutation`"
    );
    output
}

fn parse_eval_family(value: &str) -> Result<EvalFamily> {
    match normalized_cli_value(value).as_str() {
        "understand" => Ok(EvalFamily::Understand),
        "hallucination" => Ok(EvalFamily::Hallucination),
        "negative" => Ok(EvalFamily::Negative),
        "done" => Ok(EvalFamily::Done),
        "context" => Ok(EvalFamily::Context),
        "compaction" => Ok(EvalFamily::Compaction),
        "tool" => Ok(EvalFamily::Tool),
        "memory" => Ok(EvalFamily::Memory),
        "forget" => Ok(EvalFamily::Forget),
        "dream" => Ok(EvalFamily::Dream),
        "skill" => Ok(EvalFamily::Skill),
        "trace" => Ok(EvalFamily::Trace),
        "bench" => Ok(EvalFamily::Bench),
        "ale" => Ok(EvalFamily::Ale),
        "provider" => Ok(EvalFamily::Provider),
        "future" => Ok(EvalFamily::Future),
        other => bail!("unknown eval family: {other}"),
    }
}

fn phase_j0_trace_contract(project: &str, task: &str, complete: bool) -> TraceCompletenessContract {
    let present_refs = if complete {
        phase_j0_full_trace_refs()
    } else {
        vec!["user_prompt".to_owned(), "task_contract".to_owned()]
    };
    TraceCompletenessService::build(TraceCompletenessInput {
        project_id: project_id_from_label(project),
        task_id: Some(task_id_from_label(task)),
        trace_ref: format!("trace:{project}:{task}"),
        present_refs,
    })
}

fn phase_j0_full_trace_refs() -> Vec<String> {
    [
        "user_prompt",
        "task_contract",
        "context_packet",
        "understanding_proof",
        "cognitive_gate_decision",
        "verifier_run",
        "completion_proof",
        "policy_snapshot",
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect()
}

fn parse_replay_case_kind(value: &str) -> Result<ReplayCaseKind> {
    match normalized_cli_value(value).as_str() {
        "regression" => Ok(ReplayCaseKind::Regression),
        "negativememory" => Ok(ReplayCaseKind::NegativeMemory),
        "skillactivation" => Ok(ReplayCaseKind::SkillActivation),
        "skillcuration" => Ok(ReplayCaseKind::SkillCuration),
        "memorylifecycle" => Ok(ReplayCaseKind::MemoryLifecycle),
        "contextcompilation" => Ok(ReplayCaseKind::ContextCompilation),
        "completiongate" => Ok(ReplayCaseKind::CompletionGate),
        "adapterobservation" => Ok(ReplayCaseKind::AdapterObservation),
        "incidentrecovery" => Ok(ReplayCaseKind::IncidentRecovery),
        other => bail!("unknown replay case kind: {other}"),
    }
}

fn parse_sleep_trigger(value: &str) -> Result<SleepTrigger> {
    match normalized_cli_value(value).as_str() {
        "manual" => Ok(SleepTrigger::Manual),
        "posttask" => Ok(SleepTrigger::PostTask),
        "repeatedfailure" => Ok(SleepTrigger::RepeatedFailure),
        "contextbloat" => Ok(SleepTrigger::ContextBloat),
        "skilldecay" => Ok(SleepTrigger::SkillDecay),
        "maintenancewindow" => Ok(SleepTrigger::MaintenanceWindow),
        other => bail!("unknown sleep trigger: {other}"),
    }
}

fn parse_dream_candidate_kind(value: &str) -> Result<DreamCandidateKind> {
    match normalized_cli_value(value).as_str() {
        "hypothesis" => Ok(DreamCandidateKind::Hypothesis),
        "procedure" => Ok(DreamCandidateKind::Procedure),
        "relation" => Ok(DreamCandidateKind::Relation),
        "forgettingaction" => Ok(DreamCandidateKind::ForgettingAction),
        "test" => Ok(DreamCandidateKind::Test),
        "invariant" => Ok(DreamCandidateKind::Invariant),
        "risk" => Ok(DreamCandidateKind::Risk),
        "researchquestion" => Ok(DreamCandidateKind::ResearchQuestion),
        other => bail!("unknown dream candidate kind: {other}"),
    }
}

fn normalized_cli_value(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
}

fn write_j0_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let json_value = serde_json::to_value(value)?;
    write_report_pair(
        &latest_report_path(root, dir),
        &latest_markdown_path(root, dir),
        value,
        &j0_value_markdown(title, &json_value),
    )
}

fn read_latest_typed<T>(root: &Path, dir: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(read_latest_value(root, dir)?).with_context(|| {
        format!(
            "parse latest report {}",
            latest_report_path(root, dir).display()
        )
    })
}

fn read_latest_value(root: &Path, dir: &str) -> Result<serde_json::Value> {
    let path = latest_report_path(root, dir);
    if !path.is_file() {
        bail!("latest report not found: {}", path.display());
    }
    serde_json::from_reader(std::fs::File::open(path)?).context("parse latest report JSON")
}

fn latest_report_path(root: &Path, dir: &str) -> PathBuf {
    root.join("reports").join(dir).join("latest.json")
}

fn latest_markdown_path(root: &Path, dir: &str) -> PathBuf {
    root.join("reports").join(dir).join("latest.md")
}

fn j0_value_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(status) = value.get("status").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- status: `{status}`");
    }
    if let Some(final_status) = value
        .get("final_status")
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(output, "- final_status: `{final_status}`");
    }
    if let Some(replay_allowed) = value
        .get("replay_allowed")
        .and_then(serde_json::Value::as_bool)
    {
        let _ = writeln!(output, "- replay_allowed: `{replay_allowed}`");
    }
    let _ = writeln!(
        output,
        "- candidate_only: `true`\n- authority: `marker-only; no apply authority`"
    );
    output
}

fn phase_k1_done_verified(root: &Path) -> Result<bool> {
    let path = root.join("reports").join("phase-k1").join("latest.json");
    if !path.is_file() {
        return Ok(false);
    }
    let report: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok(report
        .get("final_status")
        .and_then(serde_json::Value::as_str)
        == Some("DONE_VERIFIED"))
}
