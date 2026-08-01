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
    AntigravityRealExecutionDoctor, AntigravityRollbackService, AntigravityRunner,
    AntigravityTelemetryService, AntigravityVersionGateService, AntigravityVisibilityService,
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
    MemoryDistillationService, MemoryGravityService, MemoryInfluenceService, MemoryLifecycleGate,
    MemoryLifecycleMemoryWriter, MemoryLifecycleService, MetricRecorderService,
    MetricRegistryService, MetricRollupService, MetricsDoctorIntegration, ModuleRegistryService,
    NamedPipeIpcServer, PatchMemoryWriter, PatchRunner, PatchRunnerInput, ProductionCutoverService,
    ProductionReadinessService, QualitySignalService, ReadService, ReadinessFixture,
    ReplayCaseInput, ReplayCaseService, ReplayRunnerService, ReplaySetInput, ReplaySetService,
    ReplayVerdictService, ReportService, RestoreService, RuntimeDashboardService,
    ServiceSupervisor, SkillActivationContext, SkillArchiveQuarantineService, SkillCurationGate,
    SkillCurationReport, SkillCurationReportService, SkillCuratorMemoryWriter,
    SkillCuratorRunInput, SkillCuratorService, SkillDistractorFilterService,
    SkillExecutionProofService, SkillInfluenceReportInput, SkillInfluenceService,
    SkillLifecycleService, SkillNeedEstimator, SkillPackService, SkillPatchService,
    SkillRegistryService, SleepConsolidationService, SleepRunInput, SloService,
    StartupRecoveryService, StatefulDbTestIsolationService, StdioShimService, SurrealLogicalConfig,
    TestCostService, TestInventoryService, TraceCompletenessInput, TraceCompletenessService,
    VerificationDoctorIntegration, VerificationPlannerService, VerificationProfileService,
    VerificationRunnerService, VerificationVerdictService, VerifierHarness, WindowsServiceManager,
    WorkClaimRequest, WorkCreateRequest, WorkLeaseService, WorkMemoryWriter, WorkQueueService,
    WorkState, WorktreeCleanupService, WorktreeCreateInput, WorktreeLeaseService,
    WorktreeMemoryWriter, WriteAdmissionService, WriterActor, WriterConfig, WriterReportService,
    antigravity_real_report, antigravity_report, antigravity_review_request, builtin_manifests,
    codecortex_report_ref, default_lease_ttl_minutes, default_runtime_services, default_work_scope,
    external_review_request, family_slug, h1_protocol_version, harness_experiment_record,
    hash_secret, shutdown_deadline_after, test_request,
};
use eliot_store::{
    BlobStore, CanonicalRecord, CanonicalStore, ControlWal, NamedSurqlOp, SurrealServerSupervisor,
    SurrealStore,
};
use eliot_types::{
    ActionKind, ActionLease, AdapterCapability, AdapterObservation, AdapterResult,
    AdapterResultStatus, AgentId, AgentRole, AgentSessionId, AntigravityAuthCheck,
    AntigravityBinaryResolution, AntigravityBinaryResolutionStatus, AntigravityCapabilityProbe,
    AntigravityCommandContract, AntigravityDisableReceipt, AntigravityEnablementReceipt,
    AntigravityEnablementScope, AntigravityEnablementState, AntigravityExecutionGateDecisionKind,
    AntigravityLiveSmokeMode, AntigravityLiveSmokeResult, AntigravityLiveSmokeStatus,
    AntigravityMcpInvocationReceipt, AntigravityProviderState, AntigravityRealReport,
    AntigravityReviewMode, AntigravityReviewRequest, AntigravityRun, BackupKind,
    BenchmarkIntegrityReceipt, BlackboardItem, BlackboardItemId, BlackboardItemKind,
    BlackboardScope, BlobReport, CandidateDiff, CandidateDiffId, CandidateDiffStatus,
    CandidateReview, CandidateReviewDecision, ClaimCardInput, ClaimId, CodeCortexReport,
    CodeCortexRequest, CommandContext, ComponentHealth, ConfidenceLevel, CostLedger,
    CredentialProviderKind, CredentialPurpose, CredentialRef, CredentialStatus,
    CurrentStateRequest, DashboardReport, DataRootMode, DreamCandidateKind, EpistemicStatus,
    EvalBaseline, EvalCandidateComparison, EvalCase, EvalCoverageMatrix, EvalDatasetManifest,
    EvalFailureCluster, EvalFamily, EvalFixtureStabilityReport, EvalGateDecision,
    EvalGateDecisionKind, EvalRegressionGateProfile, EvalRun, EvalRunProfile, EvalSuite,
    EvalTrendReport, EvalVerdict, EvalVerdictStatus, EvidenceAtomInput, EvidenceId,
    EvidenceIngestCommand, ExportKind, ExternalOutputSchemaKind, ExternalProviderProfile,
    ExternalReviewBudget, ExternalReviewGateDecisionKind, ExternalReviewJob,
    ExternalReviewJobStatus, ExternalReviewPacket, ExternalReviewRequest, ExternalReviewRole,
    FetchAtomsL2Request, FlakeReport, ForgettingOperator, ForgettingPolicy, ForgettingReason,
    HarnessExperimentRecord, HealthStatus, HookEventKind, ImportKind, IncidentKind,
    IncidentSeverity, IpcFrame, IpcFrameKind, LatencyHistogram, LifecycleStatus, LogEventKind,
    LogLevel, MailboxMessage, MailboxMessageId, MailboxMessageKind, MailboxRecipient,
    MaintenanceJobKind, MemoryDistillationInput, MemoryDistillationPlan,
    MemoryDistillationScheduleRequest, MemoryDistillationTrigger, MemoryGravity,
    MemoryInfluenceReport, MemoryLifecyclePacketView, MemoryLifecycleReport, MemoryRevision,
    MemoryStateTransition, MemoryVitalityScore, MetricDefinition, MetricSample, MetricWindow,
    ModuleManifest, OperationStatus, PatchRequest, PatchRequestId, PatchRun, PatchRunStatus,
    ProfileVerificationRun, ProjectId, QualitySignal, ReadConsistencyMode, RecallL0Request,
    ReplayCase, ReplayCaseKind, ReplayRun, ReplaySet, RuntimeHealthReport, RuntimeLogReport,
    RuntimeMode, RuntimeStatusReport, SCHEMA_VERSION, SemanticCommand, ServiceHealthState,
    ServiceInstallAction, ServiceInstallStatus, ServiceReadinessStatus, ServiceRuntimeStatus,
    SkillCardV2, SkillCurationAction, SkillCurationDecisionKind, SkillCurationGateDecision,
    SkillCurationProposal, SkillCurationReceipt, SkillCuratorRun, SkillExecutionOutcome,
    SkillFailureMode, SkillId, SkillInfluenceReport, SkillInputRequirement, SkillInputSource,
    SkillLifecycleState as SkillState, SkillOutputSpec, SkillScopeRule, SkillStep,
    SkillToolRequirement, SleepTrigger, SloDefinition, SloEvaluation, SourceSnapshotInput,
    StartupHealthReport, StatefulDbIsolationReport, TaintClass, TaskId, TelemetryRollup,
    TestCostReport, TestInventory, TestSuiteProfile, TraceCompletenessContract, UlInjectionMode,
    UlTaskClassPolicy, UnifiedDiff, VerificationDecision, VerificationPlan, VerificationResult,
    VerificationRunInput, VerificationVerdict, VerifierCommandKind, VerifierPlan,
    VerifierRequirement, VerifierRun, VerifierStatus, Visibility, WorkItem, WorkItemId, WorkLease,
    WorkLeaseDecision, WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState,
    WorktreeLease, WorktreeLeaseId, WorktreeLeaseRequest, WorktreeLeaseRequestId, WriteId,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Write as FmtWrite;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::str::FromStr;
use std::time::Duration;
use tracing::info;

mod antigravity;
mod eval;
mod skill_fixtures;

pub use antigravity::*;
pub use eval::*;
#[allow(clippy::wildcard_imports)]
use skill_fixtures::*;

include!("commands/operations.rs");

include!("commands/data_and_memory.rs");

include!("commands/execution.rs");

include!("commands/support.rs");

include!("commands/ul.rs");
