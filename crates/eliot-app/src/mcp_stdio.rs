use crate::{
    action_plan, calibration_runtime,
    config::load_config,
    delegation_runtime, named_pipe_ipc,
    runtime_instance::{RuntimeInstance, RuntimePublication, atomic_write_json},
};
use anyhow::{Context, Result};
use eliot_engine::{
    AdapterMemoryWriter, AdapterObservationBridge, AdapterObservationReport, AdapterRegistry,
    AdapterSupervisor, AgentSessionService, AntigravityAuthCheckService, AntigravityBinaryResolver,
    AntigravityCapabilityProbeService, AntigravityCommandContractService,
    AntigravityDoctorIntegration, AntigravityEnablementService, AntigravityMcpBoundaryService,
    AntigravityMcpConfigService, AntigravityOfficialPluginService, AntigravityPluginBundleService,
    AntigravityRealExecutionDoctor, AntigravitySkillBundleService, AntigravityTelemetryService,
    AutonomyBudgetLedger, AutonomyLeaseBinding, AutonomyRecoveryReceipt, AutonomyRunService,
    AutonomyStepIntent, AutonomyTransitionRequest, AutonomyTripwireKind, AutonomyTripwirePolicy,
    AutonomyTripwireRecord, AutonomyWorkItem, BackupService, BlackboardAddInput, BlackboardService,
    BlobGcService, BoundedAutonomyRuntime, CandidateDiffCaptureInput, CandidateDiffService,
    CandidateReviewInput, CandidateReviewService, CanonicalMetaExperimentAssessment,
    CanonicalMetaExperimentInput, CanonicalR3ApprovalAuthorization, CanonicalReplayExecutionInput,
    CanonicalTraceCompletenessInput, CodeCortexMemoryWriter, CodeCortexService,
    CognitiveBeginPrecondition, CognitiveGate, CognitiveMemoryWriter,
    CognitiveTerminalPrecondition, CognitiveTransferLabService, CollectiveMemoryWriter,
    CollectiveTraceService, CompletionGate, ContextCompiler, ContextReinstatementService,
    ContourRouteRequest, ContourRoutingService, ContrastiveAbstractionService, CorpusProfileInput,
    CorpusProfileService, CostLedgerService, CredentialProviderService, DataRootService,
    DoctorService, EvalBaselineService, EvalCaseService, EvalComparisonService,
    EvalCoverageService, EvalDatasetManifestService, EvalGateProfileService,
    EvalRegressionGateService, EvalRunInput, EvalRunnerService, EvalSuiteInput, EvalSuiteService,
    EvalTrendService, EvalVerdictService, ExperienceFormationService, ExperienceRetrievalService,
    ExternalProviderRegistryService, ExternalReviewBridgeService, ExternalReviewGate,
    ExternalReviewGateContext, ExternalReviewJobService, ExternalReviewNormalizer,
    ExternalReviewPacketBuilder, ExternalReviewReportService, FlakeDetectionService,
    ForgettingPolicyService, HealthService, HostBrokerService, HostProfileService, ImportService,
    IncidentService, LogService, LostAgentRecoveryService, MailboxSendInput, MailboxService,
    MaintenanceScheduler, MaturityGateService, MemoryGravityService, MemoryInfluenceService,
    MemoryLifecycleGate, MemoryLifecycleMemoryWriter, MemoryLifecycleService, MemoryNeedService,
    MemoryVitalityService, MetaDispositionRequest, MetaDispositionService,
    MetaExperimentAssessment, MetaHarnessService, MetaPolicyExecutor, MetricRecorderService,
    MetricRegistryService, MetricRollupService, MetricsDoctorIntegration, ModuleRegistryService,
    NegativeTransferService, PatchMemoryWriter, PatchRunner, PatchRunnerInput,
    ProductionReadinessService, QualitySignalService, ReadService, ReadinessFixture,
    ReplayCaseInput, ReplayCaseService, ReplayRunnerService, ReplaySealInput, ReplaySealService,
    ReplaySetInput, ReplaySetService, ReplayVerdictService, RestoreService,
    RuntimeDashboardService, SkillActivationContext, SkillCurationGate, SkillCurationReport,
    SkillCurationReportService, SkillCuratorMemoryWriter, SkillCuratorRunInput,
    SkillCuratorService, SkillDistractorFilterService, SkillExecutionProofService,
    SkillInfluenceReportInput, SkillInfluenceService, SkillLifecycleService, SkillNeedEstimator,
    SkillRegistryService, SleepConsolidationService, SleepRunInput, SloService,
    StatefulDbTestIsolationService, TaskMeaningService, TestCostService, TestInventoryService,
    TraceCompletenessService, TransferValidationEvidence, UnderstandingProofValidator,
    VerificationDoctorIntegration, VerificationPlannerService, VerificationProfileService,
    VerificationRunnerService, VerificationVerdictService, VerifierHarness, WindowsServiceManager,
    WorkClaimRequest, WorkCreateRequest, WorkLeaseService, WorkMemoryWriter, WorkQueueService,
    WorkState, WorktreeCleanupService, WorktreeCreateInput, WorktreeLeaseService,
    WorktreeMemoryWriter, WriteAdmissionService, WriterActor, WriterConfig, WriterHandle,
    antigravity_real_report, antigravity_report, antigravity_review_request, builtin_manifests,
    deduplicate_experience_cases, deduplicate_experience_patterns, default_lease_ttl_minutes,
    default_work_scope, external_review_request, filter_required_exact_l2_response,
    harness_experiment_record, resolve_canonical_case_dispositions, test_request,
};
use eliot_store::{BlobStore, CanonicalClaimCard, CanonicalRecord, CanonicalStore, ControlWal};
use eliot_types::{
    ActionKind, ActionLease, ActionLeaseId, ActionProvenanceSet, ActionSourceScope,
    AdapterCapability, AgentCapabilityEnvelope, AgentHostId, AgentId, AgentInvocationRequest,
    AgentResultDisposition, AgentResultDispositionKind, AgentResultEnvelope,
    AgentResultRecordCommand, AgentResultStatus, AgentRole, AgentRoutingView, AgentSessionId,
    AntigravityAuthCheck, AntigravityBinaryResolution, AntigravityCapabilityProbe,
    AntigravityCommandContract, AntigravityDisableReceipt, AntigravityEnablementReceipt,
    AntigravityLiveSmokeResult, AntigravityMcpInvocationReceipt, AntigravityReviewMode,
    AntigravityRun, ApprovalView, AutonomyRunContract, AutonomyRunState, BenchmarkIntegrityReceipt,
    BlackboardItemId, BlackboardItemKind, BlackboardScope, BlobStoreConfig,
    COGNITIVE_RUN_EXACT_CALLS, COGNITIVE_RUN_RAW_VERIFIER_CALLS, COGNITIVE_RUN_SCHEMA_VERSION,
    CandidateDiff, CandidateDiffId, CandidateDiffStatus, CandidateReview, CandidateReviewDecision,
    CanonicalCaseDisposition, CanonicalReplayAuthority, CanonicalReplayExecutionRecord,
    CanonicalReplayObservationEvidence, CanonicalTraceCompletenessContract, CanonicalTraceEvidence,
    CanonicalTraceEvidenceKind, CanonicalTraceEvidenceSource, CanonicalTraceReceiptBinding,
    ChangePlan, ClaimCardInput, ClaimId, CodeCortexReport, CodeCortexRequest,
    CognitiveCandidateCapability, CognitiveCaseSpec, CognitiveExecutionSeal,
    CognitiveFailureLocalizationReport, CognitiveGateRequest, CognitiveHostObservation,
    CognitiveInvocationRole, CognitiveRawVerifierEvidence, CognitiveReaderAnswer,
    CognitiveRunAttempt, CognitiveRunCallPlan, CognitiveRunCallStatus, CognitiveRunContract,
    CognitiveRunTerminal, CognitiveSharedGateBinding, CognitiveToolObservation, CommandContext,
    CompilePacketL3Request, CompletionDecisionMemory, CompletionMemoryAdmission,
    CompletionMemoryRequest, CompletionProof, ConfidenceLevel, ContextPacketL3,
    ContrastiveAbstractionResult, ControlWalConfig, ControllerCommitHandoff, CostLedger,
    CredentialPurpose, CurrentStateRequest, DashboardReport, DataRootMode, EpistemicStatus,
    EvalBaseline, EvalCase, EvalDatasetManifest, EvalFailureCluster, EvalFamily, EvalRun,
    EvalRunId, EvalRunProfile, EvalSuite, EvalVerdict, EvalVerdictStatus, EvidenceAtomInput,
    EvidenceId, ExperienceCase, ExperienceFormationResult, ExperiencePattern,
    ExperienceRecallRequest, ExperimentalMetaPolicyPayload, ExperimentalMetaPolicyState,
    ExternalOutputSchemaKind, ExternalProviderProfile, ExternalReviewBudget,
    ExternalReviewGateDecisionKind, ExternalReviewPacket, ExternalReviewRequest,
    ExternalReviewRole, FetchAtomsL2Request, FetchAtomsL2Response, ForgettingOperator,
    ForgettingReason, LatencyHistogram, LifecycleStatus, MailboxMessageId, MailboxMessageKind,
    MailboxRecipient, MaintenanceJobKind, MaterialPacketFrame, MemoryCurationCandidate,
    MemoryCurationCorpusProfile, MemoryCurationFindingKind, MemoryCurationPreviewRequest,
    MemoryCurationPreviewResponse, MemoryExposurePolicy, MemoryInfluenceReport,
    MemoryInfluenceTrace, MemoryInspectorView, MemoryLifecyclePacketView, MemoryLifecycleState,
    MemoryNeed, MemoryRevision, MemoryWriteEnvelope, MetaCandidateChangeClass,
    MetaExperimentDecision, MetaIsolationFence, MetaPolicyAuthorization, MetaPolicyExecutionAction,
    MetricDefinition, MetricSample, MetricWindow, MinorityPressureRecord, MinorityPressureStatus,
    NegativeTransferHarm, OPERATOR_CONTRACT_MANIFEST, OPERATOR_IPC_PROTOCOL_VERSION,
    OPERATOR_SCHEMA_VERSION, OperationJob, OperationJobState, OperatorActionView, OperatorCommand,
    OperatorCommandReceipt, OperatorControlRequest, OperatorFieldView, OperatorProjectionFilter,
    OperatorProjectionKind, OperatorProjectionPage, OperatorQueryOperation, OperatorQueryRequest,
    OperatorRecordView, OperatorRelationshipView, OperatorSnapshot, PatchRequest, PatchRequestId,
    ProcedurePromotionOutcome, ProfileVerificationRun, ProjectId, QualitySignal,
    ReactivationCondition, ReadConsistencyMode, RecallL0Request, RecallL0Response, ReceiptId,
    ReplayCaseKind, ReplayInputSnapshot, ReplaySetRole, ReplayThresholdPolicyV1, RuntimeMode,
    SealedReplaySetRecord, SemanticCommand, SemanticCommandKind, ServiceHealthState,
    ServiceRuntimeStatus, SessionId, SkillCardV2, SkillCurationAction, SkillCurationGateDecision,
    SkillCurationProposal, SkillCuratorRun, SkillExecutionOutcome, SkillFailureMode, SkillId,
    SkillInputRequirement, SkillInputSource, SkillLifecycleRecord, SkillLifecycleState,
    SkillOutputSpec, SkillScopeRule, SkillStep, SkillToolRequirement, SleepCandidateArtifactKind,
    SleepConsolidationBundle, SleepTrigger, SloDefinition, SloEvaluation, SourceSnapshotInput,
    TaintClass, TaskAcceptanceEvidenceKind, TaskAcceptanceItem, TaskCognitionView, TaskContract,
    TaskContractInput, TaskContractStatus, TaskContractWriteCommand, TaskId, TaskMeaningFrame,
    TelemetryRollup, TestInventory, ToolObservationInput, ToolObservationRecordCommand,
    TraceTimelineView, UnderstandingOutcomeRecord, UnderstandingProof, UnifiedDiff, VerificationId,
    VerificationPlan, VerificationResult, VerificationRun, VerificationRunInput,
    VerificationVerdict, VerifiedEpisodeProjection, VerifierArtifactRef, VerifierArtifactScope,
    VerifierCommandKind, VerifierPlan, VerifierRequirement, VerifierRun, Visibility, WorkItem,
    WorkItemId, WorkItemStatus, WorkLease, WorkLeaseDecision, WorkLeaseDecisionKind,
    WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState, WorktreeLease, WorktreeLeaseId,
    WorktreeLeaseRequest, WorktreeLeaseRequestId, WorktreeLeaseState, WriteId, WriteReceiptRef,
    WriteStatus, operator_contract_hash,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex, OnceLock as StdOnceLock};
use tokio::sync::{Mutex, OnceCell};

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const COGNITIVE_RUN_EXACT_CALLS_U8: u8 = 18;
const COGNITIVE_RUN_RAW_VERIFIER_CALLS_U8: u8 = 16;
const COGNITIVE_TOOL_OBSERVATION_MAX: usize = 64;
const COGNITIVE_TOOL_OBSERVATION_QUERY_LIMIT: u16 = 128;
const ACTION_PROVENANCE_RESOLVER_VERSION: &str = "eliot-l3-provenance-v1";
const RECEIPT_VERIFIER_ID: &str = "daemon-receipt-resolution";
const DOGFOOD_BLOB_VERIFIER_ID: &str = "cargo-eliot-store-blob-integrity";
const CARGO_WORKSPACE_CHECK_VERIFIER_ID: &str = "cargo-workspace-check";
const VERIFIER_VERSION: &str = "1";
const DOGFOOD_BLOB_ARTIFACT: &str = "crates/eliot-store/src/blob_store.rs";
const DOGFOOD_BLOB_TEST: &str =
    "blob_store::tests::rejects_corrupt_existing_content_addressed_blob";
const OPERATOR_CURSOR_SIGNING_KEY_BYTES: usize = 32;
const OPERATOR_CURSOR_SIGNING_KEY_FILE: &str = "operator-cursor-signing.key";
const LEGACY_OPERATOR_CURSOR_TEST_OVERRIDE: &str =
    "ELIOT_TEST_ALLOW_LEGACY_OPERATOR_CURSOR_KEY_FILE";
const BUILD_SOURCE_COMMIT: &str = env!("ELIOT_BUILD_SOURCE_COMMIT");

#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct AuthenticatedRequestContext {
    session_id: SessionId,
    bound_project_id: Option<ProjectId>,
    bound_task_id: Option<TaskId>,
}

#[derive(Clone, Debug)]
pub(crate) struct CognitivePrincipalClaims {
    pub capability: CognitiveCandidateCapability,
    pub attempt_receipt: WriteReceiptRef,
    pub capability_file: PathBuf,
}

#[derive(Clone, Debug)]
struct CognitiveRuntimePaths {
    runtime_dir: PathBuf,
    publication_path: PathBuf,
}

mod autonomy;
mod cognition;
mod verification;
use cognition::*;
use verification::*;
mod catalog;
mod delegation;
mod dispatch;
mod evaluation;
mod experiment;
mod memory;
mod operator;
mod replay;
mod skill;
mod work;
use autonomy::*;
use delegation::*;
use dispatch::*;
use evaluation::*;
use experiment::*;
use memory::*;
use operator::*;
use replay::*;
use skill::*;
use work::*;

pub(crate) use catalog::claude_surface_catalog;
use catalog::{prompt_definitions, prompt_get, tool_definitions_for_profile};

const GOVERNED_TOOLS: &[&str] = &[
    "eliot_task_contract_create",
    "eliot_task_state",
    "eliot_task_action_request",
    "eliot_task_observation_record",
    "eliot_agent_candidate_submit",
    "eliot_task_verification_run",
    "eliot_host_session_status",
    "eliot_project_identity",
    "eliot_current_state",
    "eliot_recall_l0",
    "eliot_fetch_l2",
    "eliot_compile_packet_l3",
    "eliot_understanding_outcome_record",
    "eliot_memory_influence_trace",
    "eliot_context_cargo_receipt",
    "eliot_task_meaning",
    "eliot_memory_corpus_profile",
    "eliot_memory_curation_preview",
    "eliot_experience_recall",
    "eliot_experience_reinstate",
    "eliot_experience_form",
    "eliot_experience_abstract",
    "eliot_experience_maturity_transition",
    "eliot_negative_transfer_record",
    "eliot_cognitive_lab_evaluate",
    "eliot_cognitive_failure_localization_record",
    "eliot_submit_understanding_proof",
    "eliot_cognitive_gate",
    "eliot_submit_completion_proof",
    "eliot_codecortex_scan",
    "eliot_codecortex_latest",
    "eliot_external_review_providers",
    "eliot_external_review_request",
    "eliot_external_review_job_status",
    "eliot_external_review_result",
    "eliot_external_review_report",
    "eliot_external_review_run_mock",
    "eliot_delegate_review",
    "eliot_delegate_status",
    "eliot_delegate_result",
    "eliot_delegate_report",
    "eliot_agent_delegate",
    "eliot_agent_job_claim",
    "eliot_agent_job_status",
    "eliot_agent_result_submit",
    "eliot_agent_result_finalize",
    "eliot_agent_result",
    "eliot_agent_result_disposition",
    "eliot_delegation_calibration_status",
    "eliot_delegation_calibration_report",
    "eliot_delegation_policy_candidate",
    "eliot_delegation_promotion_status",
    "eliot_antigravity_visibility",
    "eliot_antigravity_mcp_status",
    "eliot_antigravity_plugin_status",
    "eliot_antigravity_live_smoke_status",
    "eliot_antigravity_real_report",
    "eliot_eval_case_list",
    "eliot_eval_suite_list",
    "eliot_eval_run",
    "eliot_eval_verdict",
    "eliot_eval_report",
    "eliot_eval_smoke",
    "eliot_eval_coverage",
    "eliot_eval_baseline_list",
    "eliot_eval_compare",
    "eliot_eval_gate",
    "eliot_eval_profiles",
    "eliot_eval_trend",
    "eliot_verify_profiles",
    "eliot_verify_inventory",
    "eliot_verify_plan",
    "eliot_verify_report",
    "eliot_verify_cost_report",
    "eliot_verify_last_verdict",
    "eliot_metrics_registry",
    "eliot_metrics_dashboard",
    "eliot_metrics_slo",
    "eliot_metrics_latency",
    "eliot_metrics_cost",
    "eliot_metrics_quality",
    "eliot_metrics_report",
    "eliot_trace_completeness",
    "eliot_replay_case_create",
    "eliot_replay_set_create",
    "eliot_replay_run",
    "eliot_replay_report",
    "eliot_sleep_run",
    "eliot_sleep_report",
    "eliot_dream_candidate_create",
    "eliot_dream_report",
    "eliot_meta_experiment_run",
    "eliot_meta_experiment_disposition",
    "eliot_l11_status",
    "eliot_action_plan",
    "eliot_action_lease_status",
    "eliot_patch_preflight",
    "eliot_patch_apply",
    "eliot_patch_status",
    "eliot_verifier_status",
    "eliot_work_create",
    "eliot_work_claim",
    "eliot_work_status",
    "eliot_work_renew",
    "eliot_work_release",
    "eliot_work_conflicts",
    "eliot_worktree_create",
    "eliot_worktree_status",
    "eliot_worktree_capture_diff",
    "eliot_worktree_review",
    "eliot_worktree_cleanup",
    "eliot_blackboard_add",
    "eliot_blackboard_list",
    "eliot_blackboard_ack",
    "eliot_mailbox_send",
    "eliot_mailbox_inbox",
    "eliot_mailbox_ack",
    "eliot_recovery_scan",
    "eliot_collective_trace",
    "eliot_runtime_status",
    "eliot_autonomy_run_status",
    "eliot_autonomy_contract_write",
    "eliot_autonomy_approval_request",
    "eliot_autonomy_runtime_action",
    "eliot_runtime_health",
    "eliot_module_list",
    "eliot_module_health",
    "eliot_logs_query",
    "eliot_service_status",
    "eliot_ipc_status",
    "eliot_readiness_report",
    "eliot_startup_recovery_report",
    "eliot_credentials_report",
    "eliot_adapter_list",
    "eliot_adapter_health",
    "eliot_adapter_inspect",
    "eliot_adapter_execute_test",
    "eliot_doctor_report",
    "eliot_data_root_status",
    "eliot_backup_report",
    "eliot_restore_report",
    "eliot_blob_report",
    "eliot_maintenance_status",
    "eliot_incident_list",
    "eliot_memory_lifecycle_status",
    "eliot_memory_lifecycle_propose",
    "eliot_memory_lifecycle_vitality",
    "eliot_memory_lifecycle_gravity",
    "eliot_memory_lifecycle_influence",
    "eliot_skill_list",
    "eliot_skill_inspect",
    "eliot_skill_estimate",
    "eliot_skill_filter",
    "eliot_skill_influence",
    "eliot_skill_execution_proof",
    "eliot_skill_create_candidate",
    "eliot_skill_curator_run",
    "eliot_skill_curator_proposals",
    "eliot_skill_curator_inspect",
    "eliot_skill_curator_report",
    "eliot_skill_curator_gate",
];

const READ_ONLY_TOOLS: &[&str] = &[
    "eliot_host_session_status",
    "eliot_project_identity",
    "eliot_task_state",
    "eliot_current_state",
    "eliot_recall_l0",
    "eliot_fetch_l2",
    "eliot_compile_packet_l3",
    "eliot_task_meaning",
    "eliot_memory_corpus_profile",
    "eliot_memory_curation_preview",
    "eliot_experience_recall",
    "eliot_experience_reinstate",
    "eliot_codecortex_latest",
    "eliot_external_review_report",
    "eliot_antigravity_visibility",
    "eliot_antigravity_mcp_status",
    "eliot_antigravity_plugin_status",
    "eliot_antigravity_live_smoke_status",
    "eliot_antigravity_real_report",
    "eliot_l11_status",
    "eliot_memory_lifecycle_vitality",
    "eliot_memory_lifecycle_gravity",
    "eliot_skill_list",
    "eliot_skill_inspect",
    "eliot_runtime_status",
    "eliot_autonomy_run_status",
    "eliot_runtime_health",
    "eliot_doctor_report",
];

const BOUND_PROJECT_DEFAULT_TOOLS: &[&str] = &[
    "eliot_task_state",
    "eliot_current_state",
    "eliot_recall_l0",
    "eliot_fetch_l2",
    "eliot_compile_packet_l3",
    "eliot_memory_corpus_profile",
    "eliot_memory_curation_preview",
    "eliot_experience_recall",
    "eliot_experience_reinstate",
    "eliot_agent_candidate_submit",
];

const BOUND_TASK_DEFAULT_TOOLS: &[&str] = &[
    "eliot_task_state",
    "eliot_compile_packet_l3",
    "eliot_agent_candidate_submit",
];

const BOUND_PROJECT_ALIAS_DEFAULT_TOOLS: &[&str] = &["eliot_skill_list"];

const CLAUDE_DESKTOP_TOOLS: &[&str] = &[
    "eliot_host_session_status",
    "eliot_project_identity",
    "eliot_task_state",
    "eliot_current_state",
    "eliot_recall_l0",
    "eliot_fetch_l2",
    "eliot_compile_packet_l3",
    "eliot_memory_influence_trace",
    "eliot_agent_candidate_submit",
    "eliot_agent_delegate",
    "eliot_agent_result",
    "eliot_agent_result_disposition",
];

const OPERATOR_TOOLS: &[&str] = &[
    "eliot_operator_contract",
    "eliot_operator_snapshot",
    "eliot_operator_query",
    "eliot_memory_curation_preview",
    "eliot_autonomy_run_status",
    "eliot_operator_command",
    "eliot_procedure_candidate_create",
    "eliot_procedure_candidate_disposition",
    "eliot_contour_route_preview",
    "eliot_autonomy_contract_write",
    "eliot_autonomy_transition",
    "eliot_autonomy_approval_decide",
    "eliot_autonomy_runtime_action",
    "eliot_trace_completeness",
    "eliot_replay_run",
    "eliot_sleep_run",
    "eliot_meta_experiment_run",
    "eliot_meta_experiment_disposition",
    "eliot_l11_status",
    "eliot_worktree_review",
];

fn is_l11_control_mutation(name: &str) -> bool {
    matches!(
        name,
        "eliot_trace_completeness"
            | "eliot_replay_run"
            | "eliot_sleep_run"
            | "eliot_meta_experiment_run"
            | "eliot_meta_experiment_disposition"
    )
}

fn require_l11_controller_authority(state: &McpState) -> Result<()> {
    if !matches!(
        state.profile,
        McpAccessProfile::CodexController | McpAccessProfile::HumanOperator
    ) {
        anyhow::bail!(
            "L11 canonical mutation requires codex_controller or human_operator authority"
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum McpAccessProfile {
    CognitiveGovernor,
    HostGovernor,
    CognitiveChild,
    CognitiveControl,
    DynamicAgent,
    ClaudeGoverned,
    CodexController,
    CodexWorker,
    ExternalAuditor,
    Verifier,
    HumanOperator,
    HumanReadonly,
}

impl McpAccessProfile {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "cognitive_governor" => Ok(Self::CognitiveGovernor),
            "host_governor" => Ok(Self::HostGovernor),
            "cognitive_child" => Ok(Self::CognitiveChild),
            "cognitive_control" => Ok(Self::CognitiveControl),
            "dynamic_agent" | "agent_host" => Ok(Self::DynamicAgent),
            // `claude_desktop` is the retired spelling. Claude Code shares this
            // profile with Claude Desktop, so naming it after one UI product
            // misdescribed the other. Still parsed: it is present in persisted
            // session bindings and receipts written before the rename.
            "claude_governed" | "claude_desktop" => Ok(Self::ClaudeGoverned),
            "default" | "codex_controller" => Ok(Self::CodexController),
            "codex_worker" => Ok(Self::CodexWorker),
            "antigravity-auditor" | "external_auditor" => Ok(Self::ExternalAuditor),
            "verifier" => Ok(Self::Verifier),
            "human_operator" => Ok(Self::HumanOperator),
            "human_readonly" => Ok(Self::HumanReadonly),
            other => anyhow::bail!("unsupported MCP access profile: {other}"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::CognitiveGovernor => "cognitive_governor",
            Self::HostGovernor => "host_governor",
            Self::CognitiveChild => "cognitive_child",
            Self::CognitiveControl => "cognitive_control",
            Self::DynamicAgent => "dynamic_agent",
            Self::ClaudeGoverned => "claude_governed",
            Self::CodexController => "codex_controller",
            Self::CodexWorker => "codex_worker",
            Self::ExternalAuditor => "external_auditor",
            Self::Verifier => "verifier",
            Self::HumanOperator => "human_operator",
            Self::HumanReadonly => "human_readonly",
        }
    }

    fn allows(self, name: &str) -> bool {
        match self {
            Self::CognitiveChild => matches!(
                name,
                "eliot_cognitive_job_fetch"
                    | "eliot_agent_candidate_submit"
                    | "eliot_recall_l0"
                    | "eliot_fetch_l2"
            ),
            Self::CognitiveGovernor | Self::HostGovernor | Self::CognitiveControl => false,
            Self::DynamicAgent => {
                GOVERNED_TOOLS.contains(&name)
                    && !is_l11_control_mutation(name)
                    && !matches!(
                        name,
                        "eliot_agent_result_finalize"
                            | "eliot_autonomy_contract_write"
                            | "eliot_autonomy_approval_request"
                            | "eliot_autonomy_runtime_action"
                            | "eliot_worktree_review"
                    )
            }
            Self::CodexController => GOVERNED_TOOLS.contains(&name),
            Self::ClaudeGoverned => CLAUDE_DESKTOP_TOOLS.contains(&name),
            Self::CodexWorker => {
                GOVERNED_TOOLS.contains(&name)
                    && !is_l11_control_mutation(name)
                    && !matches!(
                        name,
                        "eliot_agent_result_finalize"
                            | "eliot_submit_completion_proof"
                            | "eliot_patch_apply"
                            | "eliot_delegate_review"
                            | "eliot_worktree_review"
                            | "eliot_autonomy_contract_write"
                            | "eliot_autonomy_approval_request"
                            | "eliot_autonomy_runtime_action"
                    )
            }
            Self::ExternalAuditor => {
                READ_ONLY_TOOLS.contains(&name)
                    || matches!(name, "eliot_agent_candidate_submit" | "eliot_agent_result")
            }
            Self::Verifier => READ_ONLY_TOOLS.contains(&name),
            Self::HumanOperator => OPERATOR_TOOLS.contains(&name),
            Self::HumanReadonly => {
                READ_ONLY_TOOLS.contains(&name)
                    || matches!(
                        name,
                        "eliot_operator_contract"
                            | "eliot_operator_snapshot"
                            | "eliot_operator_query"
                    )
            }
        }
    }
}

pub async fn run(
    config_path: &Path,
    profile: &str,
    host: Option<&str>,
    instance: Option<&str>,
) -> Result<()> {
    if let Some(name) =
        inherited_database_credential_variable(std::env::vars_os().map(|(name, _)| name))
    {
        anyhow::bail!("stdio MCP facade rejected inherited database credential variable {name}");
    }
    if let Some(capability_path) = std::env::var_os("ELIOT_COGNITIVE_CAPABILITY_FILE") {
        // Installed host bundles keep their ordinary `--host` flag. The protected
        // capability and canonical attempt, not that CLI hint, select and verify host authority.
        return named_pipe_ipc::run_cognitive_stdio_client(Path::new(&capability_path)).await;
    }
    if let Some(host) = host
        && !matches!(
            host,
            "codex" | "antigravity" | "opencode" | "claude" | "claude-desktop"
        )
    {
        anyhow::bail!("unsupported agent host: {host}");
    }
    let effective_profile = if std::env::var_os("ELIOT_COGNITIVE_CONTROL").is_some() {
        "cognitive_control"
    } else {
        match host {
            Some("claude" | "claude-desktop") => "claude_governed",
            Some(_) => "dynamic_agent",
            None => profile,
        }
    };
    let profile = McpAccessProfile::parse(effective_profile)?;
    if matches!(
        profile,
        McpAccessProfile::CognitiveGovernor
            | McpAccessProfile::HostGovernor
            | McpAccessProfile::CognitiveChild
    ) {
        anyhow::bail!(
            "private Governor profiles require the exact internal RPC or a run-scoped capability handshake"
        );
    }
    let requested_scope = scoped_host_session_from_env(config_path, host, profile)?;
    let instance = RuntimeInstance::select(config_path, instance)?;
    if instance.standalone() {
        let governor = std::env::current_exe().context("resolve Eliot MCP facade executable")?;
        crate::runtime_bootstrap::ensure_daemon_ready(
            config_path,
            &governor,
            named_pipe_ipc::IPC_PROTOCOL_VERSION,
            "mcp_stdio",
            instance.name(),
        )
        .await?;
    }
    named_pipe_ipc::run_stdio_client(&instance, profile.as_str(), requested_scope).await
}

fn inherited_database_credential_variable(
    names: impl IntoIterator<Item = std::ffi::OsString>,
) -> Option<String> {
    const FORBIDDEN: &[&str] = &[
        "SURREAL_PASS",
        "SURREAL_TOKEN",
        "ELIOT_DB_PASSWORD",
        "ELIOT_DB_TOKEN",
    ];
    names.into_iter().find_map(|name| {
        let name = name.to_string_lossy();
        FORBIDDEN
            .iter()
            .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
            .then(|| name.into_owned())
    })
}

fn scoped_host_session_from_env(
    config_path: &Path,
    host: Option<&str>,
    profile: McpAccessProfile,
) -> Result<Option<named_pipe_ipc::RequestedSessionScope>> {
    let Some(raw_session_id) = std::env::var_os("ELIOT_AGENT_SESSION_ID") else {
        return Ok(None);
    };
    let host_id = host
        .map(|host| host_id_from_client_kind(host).context("unsupported ELIOT agent host"))
        .transpose()?;
    if host_id.is_none()
        && !matches!(
            profile,
            McpAccessProfile::CodexController | McpAccessProfile::HumanOperator
        )
    {
        anyhow::bail!("scoped MCP session without --host requires a controller/operator profile");
    }
    let session_id = SessionId::from_str(&raw_session_id.to_string_lossy())
        .context("parse ELIOT_AGENT_SESSION_ID")?;
    let agent_session_id = AgentSessionId::from_uuid(session_id.as_uuid());
    let role_lease_id = std::env::var("ELIOT_ROLE_LEASE_ID")
        .context("ELIOT_AGENT_SESSION_ID requires ELIOT_ROLE_LEASE_ID")?;
    let task_id = TaskId::from_str(
        &std::env::var("ELIOT_TASK_ID").context("ELIOT_AGENT_SESSION_ID requires ELIOT_TASK_ID")?,
    )
    .context("parse ELIOT_TASK_ID")?;
    let presented_project_id = std::env::var("ELIOT_PROJECT_ID")
        .ok()
        .map(|value| ProjectId::from_str(&value).context("parse ELIOT_PROJECT_ID"))
        .transpose()?;
    let broker_state =
        delegation_runtime::load_state(&delegation_runtime::root_from_config(config_path))?;
    let binding = broker_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == agent_session_id)
        .context("ELIOT_AGENT_SESSION_ID has no registered host binding")?;
    if host_id.is_some_and(|host_id| binding.host_identity.host_id != host_id) {
        anyhow::bail!("ELIOT_AGENT_SESSION_ID is bound to a different host");
    }
    let project_id = binding
        .bound_project_id
        .context("ELIOT scoped MCP session has no Governor-bound project")?;
    if presented_project_id.is_some_and(|presented| presented != project_id) {
        anyhow::bail!("PROJECT_SCOPE_MISMATCH: ELIOT_PROJECT_ID differs from the Governor binding");
    }
    if binding.bound_task_id != Some(task_id) {
        anyhow::bail!("TASK_SCOPE_MISMATCH: host session is not bound to ELIOT_TASK_ID");
    }
    let now = time::OffsetDateTime::now_utc();
    let role_is_active = broker_state.task_role_leases.iter().any(|lease| {
        lease.role_lease_id == role_lease_id
            && lease.agent_session_id == agent_session_id
            && lease.task_id == task_id
            && lease.expires_at > now
    });
    if !role_is_active {
        anyhow::bail!("ELIOT scoped MCP session has no active matching TaskRoleLease");
    }
    Ok(Some(named_pipe_ipc::RequestedSessionScope {
        session_id,
        project_id,
        task_id,
    }))
}

fn validate_canonical_host_scope(
    broker_state: &eliot_types::DelegationState,
    session_id: SessionId,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<()> {
    let agent_session_id = AgentSessionId::from_uuid(session_id.as_uuid());
    let binding = broker_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == agent_session_id)
        .context("ELIOT_AGENT_SESSION_ID has no canonical host binding")?;
    if binding.bound_project_id != Some(project_id) {
        anyhow::bail!(
            "PROJECT_SCOPE_MISMATCH: requested project differs from canonical host binding"
        );
    }
    if binding.bound_task_id != Some(task_id) {
        anyhow::bail!("TASK_SCOPE_MISMATCH: requested task differs from canonical host binding");
    }
    let now = time::OffsetDateTime::now_utc();
    let active_role = broker_state.task_role_leases.iter().any(|lease| {
        lease.agent_session_id == agent_session_id
            && lease.task_id == task_id
            && lease.expires_at > now
            && binding.task_role_lease_refs.contains(&lease.role_lease_id)
    });
    if !active_role {
        anyhow::bail!("Governor-bound host scope has no active matching TaskRoleLease");
    }
    Ok(())
}

pub(crate) struct McpDaemon {
    host_governor_authority: Mutex<()>,
    cognitive_governor: McpState,
    host_governor: McpState,
    cognitive_child: McpState,
    cognitive_control: McpState,
    dynamic_agent: McpState,
    claude_desktop: McpState,
    codex_controller: McpState,
    codex_worker: McpState,
    external_auditor: McpState,
    verifier: McpState,
    human_operator: McpState,
    human_readonly: McpState,
}

impl McpDaemon {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn new(
        config_path: &Path,
        instance: &RuntimeInstance,
        publication: &RuntimePublication,
    ) -> Result<Arc<Self>> {
        let config = load_config(config_path)?;
        let root = runtime_root(config_path);
        let pipe_name = instance.pipe_name();
        let store = CanonicalStore::new(config.db.surreal.clone());
        let wal = ControlWal::open(&config.control_wal)?;
        let (writer, actor) = WriterActor::channel(wal, store.clone(), &WriterConfig::default());
        let cursor_signing_key = load_or_create_operator_cursor_signing_key(instance)?;
        let cognitive_runtime = Arc::new(CognitiveRuntimePaths {
            runtime_dir: instance.runtime_dir(),
            publication_path: instance.publication_path(),
        });
        let cognitive_principals = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(actor.run());
        Ok(Arc::new(Self {
            host_governor_authority: Mutex::new(()),
            cognitive_governor: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::CognitiveGovernor,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            host_governor: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::HostGovernor,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            cognitive_child: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::CognitiveChild,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            cognitive_control: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::CognitiveControl,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            dynamic_agent: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::DynamicAgent,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            claude_desktop: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::ClaudeGoverned,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            codex_controller: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::CodexController,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            codex_worker: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::CodexWorker,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            external_auditor: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::ExternalAuditor,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            verifier: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::Verifier,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            human_operator: McpState {
                root: root.clone(),
                store: store.clone(),
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal.clone(),
                blob_store: config.blob_store.clone(),
                profile: McpAccessProfile::HumanOperator,
                writer: writer.clone(),
                pipe_name: pipe_name.clone(),
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime: Arc::clone(&cognitive_runtime),
                cognitive_principals: Arc::clone(&cognitive_principals),
            },
            human_readonly: McpState {
                root,
                store,
                schema_ready: OnceCell::new(),
                control_wal: config.control_wal,
                blob_store: config.blob_store,
                profile: McpAccessProfile::HumanReadonly,
                writer,
                pipe_name,
                instance_name: publication.instance_name.clone(),
                runtime_id: publication.runtime_id.clone(),
                auth_generation: publication.auth_generation.clone(),
                cursor_signing_key,
                cognitive_runtime,
                cognitive_principals,
            },
        }))
    }

    pub(crate) async fn handle_line(
        &self,
        profile: &str,
        session_id: SessionId,
        bound_project_id: Option<ProjectId>,
        bound_task_id: Option<TaskId>,
        line: &str,
    ) -> Result<Option<String>> {
        let profile = McpAccessProfile::parse(profile)?;
        let _host_governor_authority = if profile == McpAccessProfile::HostGovernor {
            Some(self.host_governor_authority.lock().await)
        } else {
            None
        };
        let state = match profile {
            McpAccessProfile::CognitiveGovernor => &self.cognitive_governor,
            McpAccessProfile::HostGovernor => &self.host_governor,
            McpAccessProfile::CognitiveChild => &self.cognitive_child,
            McpAccessProfile::CognitiveControl => &self.cognitive_control,
            McpAccessProfile::DynamicAgent => &self.dynamic_agent,
            McpAccessProfile::ClaudeGoverned => &self.claude_desktop,
            McpAccessProfile::CodexController => &self.codex_controller,
            McpAccessProfile::CodexWorker => &self.codex_worker,
            McpAccessProfile::ExternalAuditor => &self.external_auditor,
            McpAccessProfile::Verifier => &self.verifier,
            McpAccessProfile::HumanOperator => &self.human_operator,
            McpAccessProfile::HumanReadonly => &self.human_readonly,
        };
        let request: Value =
            serde_json::from_str(line).with_context(|| "parse authenticated named-pipe request")?;
        Ok(handle_message(
            state,
            AuthenticatedRequestContext {
                session_id,
                bound_project_id,
                bound_task_id,
            },
            request,
        )
        .await
        .map(|response| serde_json::to_string(&response))
        .transpose()?)
    }

    pub(crate) fn authoritative_host_scope(
        &self,
        session_id: SessionId,
        requested_project_id: Option<ProjectId>,
        requested_task_id: Option<TaskId>,
    ) -> Result<(Option<ProjectId>, Option<TaskId>)> {
        match (requested_project_id, requested_task_id) {
            (None, None) => Ok((None, None)),
            (Some(project_id), Some(task_id)) => {
                let broker_state = delegation_runtime::load_state(&self.dynamic_agent.root)?;
                validate_canonical_host_scope(&broker_state, session_id, project_id, task_id)?;
                Ok((Some(project_id), Some(task_id)))
            }
            _ => {
                anyhow::bail!("Governor-bound host scope must contain both project_id and task_id")
            }
        }
    }
}

pub fn governed_tool_names() -> &'static [&'static str] {
    GOVERNED_TOOLS
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveSealInput {
    harness_version: String,
    instance_name: String,
    run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    harness_script_sha256: String,
    cases_sha256: String,
    exposure_map_sha256: String,
    output_contract_sha256: String,
    models_sha256: String,
    source_commit: String,
    policy_snapshot_id: String,
    output_root: String,
    timeout_seconds: u64,
    exact_plan: Vec<CognitiveRunCallPlan>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct CognitiveStatusInput {
    run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveBeginInput {
    run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    call_number: u8,
    execution: CognitiveExecutionSeal,
    job_packet: String,
    #[serde(default)]
    shared_gate: Option<CognitiveSharedGateBinding>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveTerminalInput {
    run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    call_number: u8,
    status: CognitiveRunCallStatus,
    execution: CognitiveExecutionSeal,
    #[serde(default)]
    process_sha256: Option<String>,
    #[serde(default)]
    stdout_sha256: Option<String>,
    #[serde(default)]
    stderr_sha256: Option<String>,
    #[serde(default)]
    provider_output_sha256: Option<String>,
    #[serde(default)]
    candidate_receipt: Option<WriteReceiptRef>,
    #[serde(default)]
    host_observation: Option<CognitiveHostObservation>,
    #[serde(default)]
    raw_verifier: Option<CognitiveRawVerifierInput>,
    reason: String,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveRawVerifierInput {
    verifier_version: String,
    checks_sha256: String,
    #[serde(default, rename = "passed")]
    _passed: Option<bool>,
}

fn require_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{field} must be a 64-character hexadecimal SHA-256 digest");
    }
    Ok(())
}

fn sha256_json<T: serde::Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("serialize canonical cognitive JSON")?;
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(encoded)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(serde::Serialize)]
struct CognitiveExposureProjection<'a> {
    revision: &'a str,
    handles: &'a [String],
}

#[cfg(test)]
mod cognitive_contract_tests;

fn same_seal_request(existing: &CognitiveRunContract, input: &CognitiveSealInput) -> bool {
    existing.schema_version == COGNITIVE_RUN_SCHEMA_VERSION
        && existing.harness_version == input.harness_version
        && existing.instance_name == input.instance_name
        && existing.run_id == input.run_id
        && existing.project_id == input.project_id
        && existing.task_id == input.task_id
        && existing.harness_script_sha256 == input.harness_script_sha256
        && existing.cases_sha256 == input.cases_sha256
        && existing.exposure_map_sha256 == input.exposure_map_sha256
        && existing.output_contract_sha256 == input.output_contract_sha256
        && existing.models_sha256 == input.models_sha256
        && existing.source_commit == input.source_commit
        && existing.policy_snapshot_id == input.policy_snapshot_id
        && existing.output_root == input.output_root
        && existing.timeout_seconds == input.timeout_seconds
        && existing.exact_plan == input.exact_plan
        && existing.hard_provider_call_cap == COGNITIVE_RUN_EXACT_CALLS_U8
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct CognitiveCapabilityFile {
    pub schema_version: String,
    pub publication_path: PathBuf,
    pub instance_name: String,
    pub capability_token: String,
    pub capability: CognitiveCandidateCapability,
    pub job_packet: String,
}

static COGNITIVE_COMMIT_SERIALIZER: StdOnceLock<tokio::sync::Mutex<()>> = StdOnceLock::new();
static TASK_COMMIT_SERIALIZER: StdOnceLock<tokio::sync::Mutex<()>> = StdOnceLock::new();

fn task_commit_serializer() -> &'static tokio::sync::Mutex<()> {
    TASK_COMMIT_SERIALIZER.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn require_valid_receipt(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    receipt_ref: &WriteReceiptRef,
) -> Result<()> {
    let receipt = state
        .store
        .write_receipt_by_id(&receipt_ref.write_id)
        .await?
        .context("canonical receipt does not exist")?;
    if receipt.receipt_id != receipt_ref.receipt_id
        || receipt.write_id != receipt_ref.write_id
        || receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        || receipt.rejected_reason.is_some()
    {
        anyhow::bail!("canonical receipt binding is invalid");
    }
    Ok(())
}

async fn require_exact_reciprocal_promotion(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    source_attempt: &CanonicalRecord<CognitiveRunAttempt>,
    candidate_write_id: WriteId,
    receipt_ref: &WriteReceiptRef,
) -> Result<u64> {
    require_valid_receipt(state, project_id, task_id, receipt_ref).await?;
    let receipt = state
        .store
        .write_receipt_by_id(&receipt_ref.write_id)
        .await?
        .context("reciprocal promotion receipt disappeared")?;
    if receipt.command_kind != SemanticCommandKind::ClaimVerify {
        anyhow::bail!("reciprocal disposition must be an atomic ClaimVerify promotion");
    }
    let candidate_id = ClaimId::from_uuid(candidate_write_id.as_uuid());
    let verification = state
        .store
        .verification_run_by_id(VerificationId::from_uuid(receipt_ref.write_id.as_uuid()))
        .await?
        .context("reciprocal promotion has no canonical verification run")?;
    if verification.result != VerificationResult::Passed
        || verification.claim_id != Some(candidate_id)
        || verification
            .payload
            .get("authority")
            .and_then(Value::as_str)
            != Some("human_operator")
        || verification.payload.get("project_id") != Some(&json!(project_id))
        || verification.payload.get("task_id") != Some(&json!(task_id))
        || verification.payload.get("candidate_original_write_id")
            != Some(&json!(candidate_write_id))
        || verification
            .payload
            .get("disposition")
            .and_then(Value::as_str)
            != Some("promote")
    {
        anyhow::bail!("reciprocal promotion verification differs from the exact source candidate");
    }
    let claim = state
        .store
        .claim_card_by_id(project_id, candidate_id)
        .await?
        .context("reciprocal promoted claim is absent")?;
    if claim.status != EpistemicStatus::Verified
        || claim.write_id != receipt_ref.write_id
        || claim.payload.get("candidate_only").and_then(Value::as_bool) != Some(false)
        || claim
            .payload
            .get("admitted_by_operator")
            .and_then(Value::as_bool)
            != Some(true)
        || claim.payload.get("cognitive_run_id") != Some(&json!(source_attempt.receipt_body.run_id))
        || claim.payload.get("cognitive_call_id")
            != Some(&json!(source_attempt.receipt_body.call_id))
        || claim.payload.get("cognitive_call_number")
            != Some(&json!(source_attempt.receipt_body.call_number))
        || claim.payload.get("cognitive_host")
            != source_attempt
                .receipt_body
                .capability
                .as_ref()
                .map(|capability| json!(capability.host))
                .as_ref()
        || claim.payload.get("cognitive_session_id")
            != source_attempt
                .receipt_body
                .capability
                .as_ref()
                .map(|capability| json!(capability.session_id))
                .as_ref()
        || claim.payload.get("cognitive_body_sha256")
            != source_attempt
                .receipt_body
                .capability
                .as_ref()
                .map(|capability| json!(capability.expected_body_sha256))
                .as_ref()
        || claim.payload.get("cognitive_attempt_receipt")
            != Some(&json!(source_attempt.canonical_receipt))
    {
        anyhow::bail!("reciprocal promoted claim is not the exact verified cognitive source");
    }
    Ok(receipt
        .memory_revision
        .context("reciprocal promotion receipt has no memory revision")?
        .value())
}

impl McpDaemon {
    pub(crate) async fn authenticate_cognitive_child(
        &self,
        capability_path: &Path,
        presented_token: &str,
    ) -> Result<SessionId> {
        self.cognitive_child.ensure_schema().await?;
        let file = read_cognitive_capability_file(capability_path)?;
        let capability = &file.capability;
        if file.schema_version != COGNITIVE_RUN_SCHEMA_VERSION
            || file.instance_name != self.cognitive_child.instance_name
            || file.publication_path != self.cognitive_child.cognitive_runtime.publication_path
            || capability_path != cognitive_capability_path(&self.cognitive_child, capability)
            || presented_token.is_empty()
            || file.capability_token != presented_token
            || capability.expires_at <= time::OffsetDateTime::now_utc()
        {
            anyhow::bail!("cognitive capability instance, path, token, or expiry is invalid");
        }
        let mut token_hash = String::with_capacity(64);
        for byte in Sha256::digest(presented_token.as_bytes()) {
            let _ = write!(&mut token_hash, "{byte:02x}");
        }
        if token_hash != capability.token_sha256 {
            anyhow::bail!("cognitive capability token hash differs from canonical authority");
        }
        if !(1..=COGNITIVE_RUN_EXACT_CALLS_U8).contains(&capability.call_number) {
            anyhow::bail!("cognitive capability call_number is outside the exact plan");
        }
        let attempt_revision = u64::from(capability.call_number) * 2 - 1;
        let attempt = cognitive_record_by_revision::<CognitiveRunAttempt>(
            &self.cognitive_child,
            capability.project_id,
            capability.task_id,
            &capability.run_id,
            attempt_revision,
            CanonicalReceiptKind::CognitiveRunAttempt,
        )
        .await?
        .context("cognitive capability has no canonical attempt")?;
        if attempt.receipt_body.status != CognitiveRunCallStatus::Attempting
            || attempt.receipt_body.capability.as_ref() != Some(capability)
            || attempt.receipt_body.candidate_write_id != capability.expected_write_id
        {
            anyhow::bail!("cognitive capability differs from the canonical attempting call");
        }
        if cognitive_record_by_revision::<CognitiveRunTerminal>(
            &self.cognitive_child,
            capability.project_id,
            capability.task_id,
            &capability.run_id,
            attempt_revision + 1,
            CanonicalReceiptKind::CognitiveRunTerminal,
        )
        .await?
        .is_some()
        {
            anyhow::bail!("cognitive capability is revoked by the canonical terminal");
        }
        let contract = load_cognitive_contract(
            &self.cognitive_child,
            &CognitiveStatusInput {
                run_id: capability.run_id.clone(),
                project_id: capability.project_id,
                task_id: capability.task_id,
            },
        )
        .await?;
        let call = contract
            .receipt_body
            .exact_plan
            .get(usize::from(capability.call_number - 1))
            .context("cognitive capability call is outside the contract")?;
        if contract.receipt_body.contract_sha256 != capability.contract_sha256
            || call.call_id != capability.call_id
            || call.host != capability.host
            || call.invocation_role != capability.invocation_role
            || call.expected_truth_revision != capability.expected_truth_revision
            || call.expected_exposure_handles != capability.expected_exposure_handles
            || call.candidate_write_id != capability.expected_write_id
            || call.candidate_body_sha256 != capability.expected_body_sha256
            || sha256_bytes(file.job_packet.as_bytes()) != call.prompt_sha256
        {
            anyhow::bail!("cognitive capability is not bound to its sealed plan call");
        }
        self.cognitive_child
            .cognitive_principals
            .lock()
            .await
            .insert(
                capability.session_id,
                CognitivePrincipalClaims {
                    capability: capability.clone(),
                    attempt_receipt: attempt.canonical_receipt,
                    capability_file: capability_path.to_path_buf(),
                },
            );
        Ok(capability.session_id)
    }
}

fn dispatch_runtime_status(state: &McpState) -> Value {
    serde_json::json!({
        "component": "runtime_status",
        "mode": RuntimeMode::Daemon,
        "active_profile": "daemon",
        "canonical_state_owner": "daemon",
        "runtime_id": state.runtime_id,
        "auth_generation": state.auth_generation,
        "identity_semantics": {
            "runtime_id": "daemon runtime generation; never an AgentSessionId",
            "auth_generation": "IPC auth generation; never a role or role status"
        },
        "ipc_enabled": true,
        "ipc_transport": "windows-named-pipe",
        "ipc_name": state.pipe_name,
        "services": runtime_service_statuses(),
        "report_ref": state.root.join("reports").join("runtime").join("latest.json")
    })
}

fn dispatch_runtime_health(state: &McpState) -> Result<Value> {
    let health = HealthService::report(RuntimeMode::Daemon, runtime_service_statuses());
    write_json_report(
        &state
            .root
            .join("reports")
            .join("runtime-health")
            .join("latest.json"),
        &health,
    )?;
    serde_json::to_value(health).map_err(Into::into)
}

fn dispatch_module_list() -> Result<Value> {
    let registry = ModuleRegistryService::new(builtin_manifests())?;
    serde_json::to_value(registry.report()).map_err(Into::into)
}

fn dispatch_module_health() -> Result<Value> {
    dispatch_module_list()
}

fn dispatch_logs_query(state: &McpState, arguments: Value) -> Result<Value> {
    let input: LogsQueryInput = serde_json::from_value(arguments)?;
    let limit = input.limit.unwrap_or(20).clamp(1, 100);
    let mut events = LogService::new(state.root.join("logs")).tail(limit)?;
    if let Some(trace_id) = input.trace_id.as_deref() {
        events.retain(|event| event.trace_id.as_deref() == Some(trace_id));
    }
    Ok(json!({
        "component": "logs_query",
        "bounded": true,
        "limit": limit,
        "returned": events.len(),
        "events": events
    }))
}

fn dispatch_service_status(state: &McpState) -> Result<Value> {
    let manager = mcp_service_manager(state)?;
    let report = manager.status();
    let report_ref = state
        .root
        .join("reports")
        .join("service")
        .join("latest.json");
    write_json_report(&report_ref, &report)?;
    Ok(json!({
        "component": "service_status",
        "service_name": report.config.service_name,
        "installed": report.installed,
        "running": report.running,
        "install_status": report.install_receipt.status,
        "config_ref": report.install_receipt.config_ref,
        "warnings": report.install_receipt.warnings,
        "report_ref": report_ref
    }))
}

fn dispatch_ipc_status(state: &McpState) -> Result<Value> {
    let report_ref = state.root.join("reports").join("ipc").join("latest.json");
    let report = json!({
        "component": "ipc_status",
        "transport": "windows-named-pipe",
        "listening": true,
        "bind_local_only": true,
        "pipe_name": state.pipe_name,
        "max_frame_bytes": named_pipe_ipc::MAX_FRAME_BYTES,
        "max_connections": named_pipe_ipc::MAX_CONNECTIONS,
        "handshake_required": true,
        "warnings": [],
        "report_ref": report_ref
    });
    write_json_report(&report_ref, &report)?;
    Ok(report)
}

fn dispatch_readiness_report(state: &McpState) -> Result<Value> {
    let report_ref = state
        .root
        .join("reports")
        .join("readiness")
        .join("latest.json");
    let report: Value = if report_ref.is_file() {
        serde_json::from_reader(std::fs::File::open(&report_ref)?)?
    } else {
        let data_root =
            DataRootService::new(&state.root).validate(DataRootMode::DevProjectLocal)?;
        let probe = ProductionReadinessService::probe(
            "EliotGovernor",
            &ReadinessFixture {
                data_root_validated: ProductionReadinessService::data_root_validation_passed(
                    data_root.status,
                ),
                credential_refs_resolved: true,
                db_reachable: true,
                writer_self_check: true,
                read_self_check: true,
                ipc_listening: true,
                phase_minimal_eval_gate_passed: true,
                blocking_incident: IncidentService::new(&state.root).lockdown_active()?,
            },
        );
        write_json_report(&report_ref, &probe)?;
        serde_json::to_value(probe)?
    };
    Ok(json!({
        "component": "readiness_report",
        "status": report.get("status").cloned().unwrap_or(Value::Null),
        "checks_count": report
            .get("checks")
            .and_then(Value::as_array)
            .map_or(0, std::vec::Vec::len),
        "report_ref": report_ref
    }))
}

fn dispatch_startup_recovery_report(state: &McpState) -> Result<Value> {
    let report_ref = state
        .root
        .join("reports")
        .join("startup-recovery")
        .join("latest.json");
    if !report_ref.is_file() {
        return Ok(json!({
            "component": "startup_recovery_report",
            "status": "unavailable",
            "report_available": false,
            "reason": "startup recovery scan is admin CLI only in H1"
        }));
    }
    let report: Value = serde_json::from_reader(std::fs::File::open(&report_ref)?)?;
    Ok(json!({
        "component": "startup_recovery_report",
        "status": report.get("status").cloned().unwrap_or(Value::Null),
        "unclean_shutdown_detected": report
            .get("unclean_shutdown_detected")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "report_available": true,
        "report_ref": report_ref
    }))
}

fn dispatch_credentials_report(state: &McpState) -> Result<Value> {
    let mut provider = CredentialProviderService::new();
    let _ = provider.put_test_secret(
        "credential:ipc-handshake-token",
        CredentialPurpose::IpcHandshakeToken,
        "mcp-status-token",
    );
    let _ = provider.put_test_secret(
        "credential:surreal-runtime",
        CredentialPurpose::SurrealDbRuntime,
        "mcp-db-secret-fixture",
    );
    let report = provider.report("", &["eliot-app".to_owned(), "mcp".to_owned()]);
    let report_ref = state
        .root
        .join("reports")
        .join("credentials")
        .join("latest.json");
    write_json_report(&report_ref, &report)?;
    Ok(json!({
        "component": "credentials_report",
        "refs_count": report.refs.len(),
        "resolved_count": report.resolved_count,
        "secret_values_redacted": report.secret_values_redacted,
        "toml_contains_secret_values": report.toml_contains_secret_values,
        "command_line_contains_secret_values": report.command_line_contains_secret_values,
        "warnings": report.warnings,
        "report_ref": report_ref
    }))
}

fn mcp_service_manager(state: &McpState) -> Result<WindowsServiceManager> {
    let executable_path = std::env::current_exe().context("resolve current executable")?;
    Ok(WindowsServiceManager::new(
        WindowsServiceManager::default_config(&state.root, &executable_path),
    ))
}

async fn dispatch_adapter_list() -> Result<Value> {
    let registry = AdapterRegistry::builtin()?;
    serde_json::to_value(registry.report().await).map_err(Into::into)
}

async fn dispatch_adapter_health() -> Result<Value> {
    let supervisor = AdapterSupervisor::builtin()?;
    let health = supervisor.health_all().await;
    Ok(json!({
        "component": "adapter_health",
        "health": health,
        "bounded": true
    }))
}

fn dispatch_adapter_inspect(arguments: Value) -> Result<Value> {
    let input: AdapterInspectInput = serde_json::from_value(arguments)?;
    let registry = AdapterRegistry::builtin()?;
    serde_json::to_value(registry.inspect(&input.adapter)?).map_err(Into::into)
}

fn dispatch_doctor_report(state: &McpState) -> Result<Value> {
    let report = DoctorService::new(&state.root, std::env::current_dir()?).report()?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("doctor")
            .join("latest.json"),
        &report,
    )?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_data_root_status(state: &McpState) -> Result<Value> {
    let validation = DataRootService::new(&state.root).validate(DataRootMode::DevProjectLocal)?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("data-root")
            .join("latest.json"),
        &validation,
    )?;
    serde_json::to_value(validation).map_err(Into::into)
}

fn dispatch_blob_report(state: &McpState) -> Result<Value> {
    let report = BlobGcService::new(state.root.join("blobs")).report(true)?;
    write_json_report(
        &state.root.join("reports").join("blob").join("latest.json"),
        &report,
    )?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_incident_list(state: &McpState) -> Result<Value> {
    let report = IncidentService::new(&state.root).report()?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("incidents")
            .join("latest.json"),
        &report,
    )?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_latest_report_or_value<T: serde::Serialize>(
    state: &McpState,
    report_name: &str,
    fallback: T,
) -> Result<Value> {
    let path = state
        .root
        .join("reports")
        .join(report_name)
        .join("latest.json");
    if path.is_file() {
        return Ok(serde_json::from_reader(std::fs::File::open(path)?)?);
    }
    write_json_report(&path, &fallback)?;
    serde_json::to_value(fallback).map_err(Into::into)
}

async fn dispatch_adapter_execute_test(state: &McpState, arguments: Value) -> Result<Value> {
    let input: AdapterInspectInput = serde_json::from_value(arguments)?;
    let blob_store = BlobStore::open(&state.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let request = test_request(&input.adapter, AdapterCapability::ExecuteTest);
    let mut result = supervisor
        .execute(&input.adapter, request, Some(&blob_store))
        .await?;
    let writer = state.writer.clone();
    let admission = WriteAdmissionService;
    let mut work_state = load_work_state(&state.root)?;
    let session_id = AgentSessionId::new_v7();
    let mut observations = Vec::new();
    let mut blackboard_items = Vec::new();
    let mut mailbox_messages = Vec::new();
    for observation in &mut result.observations {
        AdapterMemoryWriter::write_observation(&writer, &admission, observation).await?;
        let item = AdapterObservationBridge::to_blackboard_candidate(
            &mut work_state,
            session_id,
            observation,
        );
        let message = AdapterObservationBridge::to_mailbox_notification(
            &mut work_state,
            session_id,
            observation,
        );
        observations.push(observation.clone());
        blackboard_items.push(item);
        mailbox_messages.push(message);
    }
    let project_label = result
        .observations
        .first()
        .map_or_else(ProjectId::new_v7, |observation| observation.project_id)
        .to_string();
    let task_label = result
        .observations
        .first()
        .map_or_else(TaskId::new_v7, |observation| observation.task_id)
        .to_string();
    let report = WorkQueueService.status_report(&work_state, &project_label, &task_label);
    save_work_state_and_report(&state.root, &work_state, &report)?;
    let observation_report = AdapterObservationReport {
        component: "adapter_observations".to_owned(),
        observations,
        blackboard_items,
        mailbox_messages,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_json_report(
        &state
            .root
            .join("reports")
            .join("adapter-observations")
            .join("latest.json"),
        &observation_report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("adapter-observations")
            .join("latest.md"),
        "# Adapter Observations\n",
    )?;
    Ok(json!({
        "component": "adapter_execute_test",
        "adapter": input.adapter,
        "result": result,
        "bounded": true
    }))
}

fn runtime_service_statuses() -> Vec<ServiceRuntimeStatus> {
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

async fn dispatch_task_contract_create(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskContractCreateToolInput = serde_json::from_value(arguments)?;
    if input.acceptance_items.len() != 2 {
        anyhow::bail!("First Working Loop TaskContract requires exactly two acceptance items");
    }
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    if state.store.task_contract_by_id(task_id).await?.is_some()
        && state.store.write_receipt_by_id(&write_id).await?.is_none()
    {
        anyhow::bail!("TaskContract already exists");
    }
    let mut ids = std::collections::BTreeSet::new();
    let acceptance_items = input
        .acceptance_items
        .into_iter()
        .map(|item| {
            if item.item_id.trim().is_empty()
                || item.description.trim().is_empty()
                || !ids.insert(item.item_id.clone())
            {
                anyhow::bail!("acceptance items require unique non-empty ids and descriptions");
            }
            Ok(TaskAcceptanceItem {
                item_id: item.item_id,
                description: item.description,
                required_evidence: item.required_evidence,
                satisfied: false,
                observation_id: None,
                verification_id: None,
                verification_scope_hash: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let observation_requirements = acceptance_items
        .iter()
        .filter(|item| item.required_evidence == TaskAcceptanceEvidenceKind::Observation)
        .count();
    let verification_requirements = acceptance_items
        .iter()
        .filter(|item| item.required_evidence == TaskAcceptanceEvidenceKind::Verification)
        .count();
    if observation_requirements != 1 || verification_requirements != 1 {
        anyhow::bail!(
            "First Working Loop TaskContract requires one observation and one verification item"
        );
    }
    let contract = TaskContractInput {
        task_id,
        title: input.title,
        status: TaskContractStatus::Open,
        acceptance_items,
        expected_revision: None,
        action_lease_id: None,
        understanding_proof_hash: None,
        action_provenance: None,
        observation_ids: Vec::new(),
        verification_ids: Vec::new(),
        verification_scopes: Vec::new(),
        completion_write_id: None,
    };
    let (receipt, contract) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "controller-task-contract",
        TaintClass::LocalTool,
        TaskTransitionEvidence::default(),
    )
    .await?;
    Ok(json!({ "status": "created", "task_contract": contract, "write_receipt": receipt }))
}

async fn dispatch_task_state(state: &McpState, arguments: Value) -> Result<Value> {
    let input: TaskStateToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let contract = require_task(state, project_id, task_id).await?;
    Ok(json!({
        "status": "current",
        "current_vs_recalled": "current_canonical_task_state",
        "revision_fence": contract.memory_revision,
        "task_contract": contract
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegisteredTaskVerifier {
    ReceiptResolution,
    DogfoodBlobIntegrity,
    CargoWorkspaceCheck,
}

impl RegisteredTaskVerifier {
    const ALL: [Self; 3] = [
        Self::ReceiptResolution,
        Self::DogfoodBlobIntegrity,
        Self::CargoWorkspaceCheck,
    ];

    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::ReceiptResolution => RECEIPT_VERIFIER_ID,
            Self::DogfoodBlobIntegrity => DOGFOOD_BLOB_VERIFIER_ID,
            Self::CargoWorkspaceCheck => CARGO_WORKSPACE_CHECK_VERIFIER_ID,
        }
    }

    const fn source_kind(self) -> &'static str {
        match self {
            Self::ReceiptResolution => "canonical_task",
            Self::DogfoodBlobIntegrity | Self::CargoWorkspaceCheck => "git_worktree",
        }
    }

    const fn command_display(self) -> &'static str {
        match self {
            Self::ReceiptResolution => "resolve canonical observation receipt",
            Self::DogfoodBlobIntegrity => {
                "cargo test --offline -p eliot-store blob_store::tests::rejects_corrupt_existing_content_addressed_blob -- --exact --test-threads=1"
            }
            Self::CargoWorkspaceCheck => {
                "cargo check --workspace --all-targets --all-features --offline"
            }
        }
    }

    fn profile_ref(self) -> String {
        format!("eliot/verifier-profile/{}@{VERIFIER_VERSION}", self.id())
    }

    pub(crate) fn config_hash(self) -> String {
        let material = match self {
            Self::ReceiptResolution => json!({
                "id": self.id(),
                "version": VERIFIER_VERSION,
                "operation": "resolve_observation_write_receipt_in_exact_task_scope"
            }),
            Self::DogfoodBlobIntegrity => json!({
                "id": self.id(),
                "version": VERIFIER_VERSION,
                "program": "cargo",
                "args": [
                    "test", "--offline", "-p", "eliot-store", DOGFOOD_BLOB_TEST,
                    "--", "--exact", "--test-threads=1"
                ],
                "artifact_paths": [DOGFOOD_BLOB_ARTIFACT],
                "timeout_seconds": 120,
                "provider_kill_switch": true
            }),
            Self::CargoWorkspaceCheck => json!({
                "id": self.id(),
                "version": VERIFIER_VERSION,
                "program": "cargo",
                "args": [
                    "check", "--workspace", "--all-targets", "--all-features", "--offline"
                ],
                "artifact_scope": "action_leased_exact_changed_paths",
                "timeout_seconds": 300,
                "provider_kill_switch": true
            }),
        };
        let bytes =
            serde_json::to_vec(&material).unwrap_or_else(|_| material.to_string().into_bytes());
        blake3::hash(&bytes).to_hex().to_string()
    }

    pub(crate) fn reference(self) -> String {
        format!(
            "eliot/verifier/{}@{}#blake3:{}",
            self.id(),
            VERIFIER_VERSION,
            self.config_hash()
        )
    }

    pub(crate) fn from_reference(reference: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.reference() == reference)
    }

    fn descriptor(self) -> Value {
        json!({
            "verifier_id": self.id(),
            "verifier_version": VERIFIER_VERSION,
            "config_hash": self.config_hash(),
            "verifier_ref": self.reference(),
            "source_kind": self.source_kind(),
            "profile_ref": self.profile_ref(),
            "command": self.command_display()
        })
    }
}

struct CanonicalPacketRefs {
    packet_id: String,
    packet_revision_fence: MemoryRevision,
    task_contract_ref: String,
    negative_memory_check_ref: String,
}

async fn canonical_packet_refs(
    state: &McpState,
    task: &TaskContract,
) -> Result<CanonicalPacketRefs> {
    let current = state
        .store
        .current_state(&CurrentStateRequest {
            project_id: task.project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?;
    let task_contract_ref = format!(
        "eliot/task/{}@{}",
        task.task_id,
        task.memory_revision.value()
    );
    let material = json!({
        "project_id": task.project_id,
        "task_id": task.task_id,
        "task_revision": task.memory_revision,
        "task_write_id": task.write_id,
        "task_status": task.status,
        "acceptance_items": task.acceptance_items,
        "task_contract_ref": task_contract_ref,
        "project_memory_revision": current.memory_revision,
        "project_sequence": current.project_sequence,
        "weak_or_candidate": current.weak_or_candidate,
        "contested_now": current.contested_now,
        "do_not_use": current.do_not_use,
        "recent_failures": current.recent_failures
    });
    let packet_id = format!(
        "eliot/packet/{}",
        blake3::hash(&serde_json::to_vec(&material)?).to_hex()
    );
    let negative_memory_check_ref = format!("eliot/negative-memory/{packet_id}");
    Ok(CanonicalPacketRefs {
        packet_id,
        packet_revision_fence: current.memory_revision,
        task_contract_ref,
        negative_memory_check_ref,
    })
}

struct GitArtifactSnapshot {
    root: PathBuf,
    branch: String,
    commit: String,
    dirty_state_hash: String,
    clean: bool,
    artifact_refs: Vec<VerifierArtifactRef>,
}

async fn run_git(worktree: &Path, args: &[&str]) -> Result<std::process::Output> {
    let output = tokio::process::Command::new("git")
        .args(args)
        .current_dir(worktree)
        .env_remove("SURREAL_USER")
        .env_remove("SURREAL_PASS")
        .env_remove("ELIOT_TEST_SURREAL_ENDPOINT")
        .output()
        .await
        .with_context(|| format!("run git {} in {}", args.join(" "), worktree.display()))?;
    Ok(output)
}

fn checked_command_text(output: std::process::Output, operation: &str) -> Result<String> {
    if !output.status.success() {
        anyhow::bail!("{operation} failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

async fn resolve_git_artifact_snapshot(
    worktree_ref: &str,
    artifact_paths: &[String],
) -> Result<GitArtifactSnapshot> {
    if worktree_ref.trim().is_empty() || artifact_paths.is_empty() {
        anyhow::bail!("git verifier requires a worktree and artifact paths");
    }
    let root = tokio::fs::canonicalize(worktree_ref)
        .await
        .with_context(|| "canonicalize verifier worktree")?;
    let lower = root.to_string_lossy().to_ascii_lowercase();
    if lower.contains("onedrive")
        || lower.contains("dropbox")
        || lower.contains("google drive")
        || root.components().any(|component| {
            component
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(".git")
        })
    {
        anyhow::bail!("verifier worktree must be outside sync roots and .git");
    }
    let top_level = checked_command_text(
        run_git(&root, &["rev-parse", "--show-toplevel"]).await?,
        "resolve git worktree root",
    )?;
    let top_level = tokio::fs::canonicalize(top_level).await?;
    if top_level != root {
        anyhow::bail!("worktree_ref must name the exact Git worktree root");
    }
    let branch = checked_command_text(
        run_git(&root, &["symbolic-ref", "--quiet", "--short", "HEAD"]).await?,
        "resolve verifier branch",
    )?;
    let commit = checked_command_text(
        run_git(&root, &["rev-parse", "HEAD"]).await?,
        "resolve verifier commit",
    )?;
    let status = run_git(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    .await?;
    if !status.status.success() {
        anyhow::bail!("resolve verifier dirty state failed");
    }
    let dirty_state_hash = blake3::hash(&status.stdout).to_hex().to_string();
    let clean = status.stdout.is_empty();

    let mut canonical_paths = artifact_paths.to_vec();
    canonical_paths.sort();
    canonical_paths.dedup();
    if canonical_paths.len() != artifact_paths.len() {
        anyhow::bail!("artifact paths must be unique");
    }
    let mut artifact_refs = Vec::with_capacity(canonical_paths.len());
    for relative in canonical_paths {
        let relative_path = Path::new(&relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            anyhow::bail!("artifact path must be a normalized relative path");
        }
        let resolved = tokio::fs::canonicalize(root.join(relative_path))
            .await
            .with_context(|| format!("resolve verifier artifact {relative}"))?;
        if !resolved.starts_with(&root) || !resolved.is_file() {
            anyhow::bail!("verifier artifact escapes the worktree or is not a file");
        }
        let bytes = tokio::fs::read(&resolved).await?;
        artifact_refs.push(VerifierArtifactRef {
            resource_ref: relative.replace('\\', "/"),
            content_hash: blake3::hash(&bytes).to_hex().to_string(),
        });
    }
    Ok(GitArtifactSnapshot {
        root,
        branch,
        commit,
        dirty_state_hash,
        clean,
        artifact_refs,
    })
}

async fn resolve_packet_git_scope(
    worktree: &Path,
    project_id: ProjectId,
) -> Result<eliot_types::memory::GovernedGitScope> {
    let root = tokio::fs::canonicalize(worktree)
        .await
        .context("canonicalize packet Git worktree")?;
    let top_level = checked_command_text(
        run_git(&root, &["rev-parse", "--show-toplevel"]).await?,
        "resolve packet Git worktree root",
    )?;
    if tokio::fs::canonicalize(top_level).await? != root {
        anyhow::bail!("packet runtime root must name the exact Git worktree root");
    }
    let branch = checked_command_text(
        run_git(&root, &["symbolic-ref", "--quiet", "--short", "HEAD"]).await?,
        "resolve packet Git branch",
    )?;
    let commit = checked_command_text(
        run_git(&root, &["rev-parse", "HEAD"]).await?,
        "resolve packet Git commit",
    )?;
    let status = run_git(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    .await?;
    if !status.status.success() {
        anyhow::bail!("resolve packet Git dirty state failed");
    }
    let ancestors = checked_command_text(
        run_git(&root, &["rev-list", "HEAD"]).await?,
        "resolve packet Git ancestry",
    )?;
    let ancestor_commits = ancestors
        .lines()
        .filter(|candidate| *candidate != commit)
        .map(str::to_owned)
        .collect();
    let tracked = run_git(&root, &["ls-files", "-z"]).await?;
    if !tracked.status.success() {
        anyhow::bail!("resolve packet tracked files failed");
    }
    let mut artifact_refs = Vec::new();
    for relative in String::from_utf8(tracked.stdout)?.split('\0') {
        if relative.is_empty() {
            continue;
        }
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            anyhow::bail!("tracked packet artifact path is not normalized");
        }
        let candidate = root.join(relative_path);
        let Ok(resolved) = tokio::fs::canonicalize(&candidate).await else {
            continue;
        };
        if !resolved.starts_with(&root) || !resolved.is_file() {
            continue;
        }
        let bytes = tokio::fs::read(resolved).await?;
        artifact_refs.push(VerifierArtifactRef {
            resource_ref: relative.replace('\\', "/"),
            content_hash: blake3::hash(&bytes).to_hex().to_string(),
        });
    }
    artifact_refs.sort_by(|left, right| left.resource_ref.cmp(&right.resource_ref));
    Ok(eliot_types::memory::GovernedGitScope {
        project_id,
        branch,
        commit,
        clean: status.stdout.is_empty(),
        ancestor_commits,
        artifact_refs,
    })
}

async fn resolve_action_source_scope(
    verifier: RegisteredTaskVerifier,
    input: &TaskActionToolInput,
) -> Result<ActionSourceScope> {
    match verifier {
        RegisteredTaskVerifier::ReceiptResolution => {
            if input.worktree_ref.is_some() || !input.artifact_paths.is_empty() {
                anyhow::bail!("receipt verifier does not accept caller artifact scope");
            }
            Ok(ActionSourceScope {
                kind: verifier.source_kind().to_owned(),
                worktree_ref: None,
                branch: None,
                baseline_commit: None,
                baseline_dirty_state_hash: None,
                artifact_paths: Vec::new(),
            })
        }
        RegisteredTaskVerifier::DogfoodBlobIntegrity
        | RegisteredTaskVerifier::CargoWorkspaceCheck => {
            if verifier == RegisteredTaskVerifier::DogfoodBlobIntegrity
                && input.artifact_paths != [DOGFOOD_BLOB_ARTIFACT]
            {
                anyhow::bail!("dogfood verifier artifact scope does not match its registry entry");
            }
            let worktree_ref = input
                .worktree_ref
                .as_deref()
                .context("git verifier requires worktree_ref")?;
            let snapshot =
                resolve_git_artifact_snapshot(worktree_ref, &input.artifact_paths).await?;
            if !snapshot.clean {
                anyhow::bail!("action source worktree must be clean at lease issuance");
            }
            Ok(ActionSourceScope {
                kind: verifier.source_kind().to_owned(),
                worktree_ref: Some(snapshot.root.display().to_string()),
                branch: Some(snapshot.branch),
                baseline_commit: Some(snapshot.commit),
                baseline_dirty_state_hash: Some(snapshot.dirty_state_hash),
                artifact_paths: input.artifact_paths.clone(),
            })
        }
    }
}

async fn resolve_action_provenance(
    state: &McpState,
    project_id: ProjectId,
    task: &TaskContract,
    action_write_id: WriteId,
    input: &TaskActionToolInput,
) -> Result<(ActionProvenanceSet, RegisteredTaskVerifier)> {
    let packet = canonical_packet_refs(state, task).await?;
    if input.packet_id != packet.packet_id
        || input.packet_revision_fence != packet.packet_revision_fence.value()
        || input.task_contract_ref != packet.task_contract_ref
        || input.current_truth_refs != [packet.task_contract_ref.clone()]
        || input.negative_memory_check_ref != packet.negative_memory_check_ref
    {
        anyhow::bail!("packet or current-truth reference is missing, stale, or fabricated");
    }
    let verifier = RegisteredTaskVerifier::from_reference(&input.planned_verifier_ref)
        .context("planned verifier reference is not registered or has a stale config hash")?;
    let source_scope = resolve_action_source_scope(verifier, input).await?;

    let mut exact_evidence_refs = Vec::new();
    let mut resolves_current_task_write = false;
    for handle in &input.provenance_handles {
        let write_id = WriteId::from_str(handle)
            .context("provenance handle is not a WriteReceipt reference")?;
        let receipt = state
            .store
            .write_receipt_by_id(&write_id)
            .await?
            .context("provenance WriteReceipt does not resolve")?;
        if receipt.project_id != project_id
            || receipt.task_id != Some(task.task_id)
            || !matches!(
                receipt.status,
                WriteStatus::Committed | WriteStatus::IdempotentReplay
            )
            || receipt
                .memory_revision
                .is_none_or(|revision| revision > task.memory_revision)
        {
            anyhow::bail!("provenance WriteReceipt has wrong task, project, state, or revision");
        }
        resolves_current_task_write |= receipt.write_id == task.write_id;
        exact_evidence_refs.push(receipt.receipt_id.to_string());
    }
    exact_evidence_refs.sort();
    exact_evidence_refs.dedup();
    if exact_evidence_refs.is_empty() || !resolves_current_task_write {
        anyhow::bail!("provenance must resolve the current TaskContract write");
    }

    let mut provenance = ActionProvenanceSet {
        provenance_set_id: format!("eliot/provenance-set/{action_write_id}"),
        task_id: task.task_id,
        packet_id: packet.packet_id,
        packet_revision_fence: packet.packet_revision_fence,
        task_contract_ref: packet.task_contract_ref.clone(),
        current_truth_refs: vec![packet.task_contract_ref],
        exact_evidence_refs,
        negative_memory_check_ref: packet.negative_memory_check_ref,
        planned_verifier_ref: verifier.reference(),
        source_scope,
        resolved_at: time::OffsetDateTime::now_utc(),
        resolver_version: ACTION_PROVENANCE_RESOLVER_VERSION.to_owned(),
        hash: String::new(),
    };
    provenance.hash = canonical_struct_hash(&provenance)?;
    Ok((provenance, verifier))
}

fn canonical_struct_hash<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}

async fn dispatch_task_action_request(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskActionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    let mut task = require_task(state, project_id, task_id).await?;
    ensure_expected_revision_or_replay(state, &task, input.expected_revision, write_id).await?;

    let mut missing = Vec::new();
    if input.packet_id.trim().is_empty() {
        missing.push("packet_id");
    }
    if input.packet_revision_fence == 0 {
        missing.push("packet_revision_fence");
    }
    if input.task_contract_ref.trim().is_empty() {
        missing.push("task_contract_ref");
    }
    if input.current_truth_refs.is_empty() {
        missing.push("current_truth_refs");
    }
    if input.provenance_handles.is_empty() {
        missing.push("provenance_handles");
    }
    if !input.negative_memory_checked {
        missing.push("negative_memory_checked");
    }
    if input.negative_memory_check_ref.trim().is_empty() {
        missing.push("negative_memory_check_ref");
    }
    if input.planned_action.trim().is_empty() {
        missing.push("planned_action");
    }
    if input.planned_verifier_ref.trim().is_empty() {
        missing.push("planned_verifier_ref");
    }
    if !missing.is_empty() {
        return Ok(json!({
            "status": "denied_requires_probe",
            "decision": "deny",
            "missing": missing,
            "write_receipt": Value::Null
        }));
    }

    let (provenance, verifier) =
        match resolve_action_provenance(state, project_id, &task, write_id, &input).await {
            Ok(resolved) => resolved,
            Err(error) => {
                return Ok(json!({
                    "status": "denied_invalid_provenance",
                    "decision": "deny",
                    "reason": error.to_string(),
                    "write_receipt": Value::Null
                }));
            }
        };
    let proof_hash = canonical_struct_hash(&json!({
        "planned_action": input.planned_action,
        "provenance_set_hash": provenance.hash
    }))?;
    let lease_id = ActionLeaseId::from_uuid(write_id.as_uuid());
    task.status = TaskContractStatus::Active;
    task.action_lease_id = Some(lease_id);
    task.understanding_proof_hash = Some(proof_hash.clone());
    task.action_provenance = Some(provenance.clone());
    let contract = task_input(&task, Some(MemoryRevision::new(input.expected_revision)));
    let (receipt, task) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "daemon-cognitive-gate",
        TaintClass::LocalTool,
        TaskTransitionEvidence::default(),
    )
    .await?;
    Ok(json!({
        "status": "allowed_bounded",
        "decision": "allow",
        "action_lease": {
            "lease_id": lease_id,
            "task_id": task_id,
            "at_revision": input.expected_revision,
            "scope": provenance.source_scope,
            "planned_action": input.planned_action,
            "planned_verifier_ref": provenance.planned_verifier_ref,
            "verifier_config_hash": verifier.config_hash(),
            "understanding_proof_hash": proof_hash,
            "provenance_set_hash": provenance.hash
        },
        "task_contract": task,
        "write_receipt": receipt
    }))
}

async fn dispatch_task_observation_record(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskObservationToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    let lease_id = ActionLeaseId::from_str(&input.action_lease_id).context("parse lease id")?;
    let mut task = require_task(state, project_id, task_id).await?;
    ensure_expected_revision_or_replay(state, &task, input.expected_revision, write_id).await?;
    if task.action_lease_id != Some(lease_id) {
        anyhow::bail!("observation requires the active task ActionLease");
    }
    if task.write_id != WriteId::from_uuid(lease_id.as_uuid()) {
        anyhow::bail!("ActionLease was invalidated by a later task transition");
    }
    let provenance = task
        .action_provenance
        .clone()
        .context("observation requires resolved canonical action provenance")?;
    if input.provenance_set_hash != provenance.hash {
        anyhow::bail!("observation provenance hash does not match the active ActionLease");
    }
    let expected_scope = format!("eliot/task/{task_id}/acceptance/{}", input.item_id);
    if input.scope != expected_scope || input.provenance_handles != [task.write_id.to_string()] {
        anyhow::bail!("observation scope or action receipt reference is not canonical");
    }
    let action_receipt = state
        .store
        .write_receipt_by_id(&task.write_id)
        .await?
        .context("active ActionLease WriteReceipt does not resolve")?;
    if action_receipt.project_id != project_id || action_receipt.task_id != Some(task_id) {
        anyhow::bail!("active ActionLease WriteReceipt scope mismatch");
    }
    let observation_id = write_id.to_string();
    let item = task
        .acceptance_items
        .iter_mut()
        .find(|item| item.item_id == input.item_id)
        .context("observation acceptance item not found")?;
    if item.required_evidence != TaskAcceptanceEvidenceKind::Observation {
        anyhow::bail!("acceptance item requires verification evidence");
    }
    item.satisfied = input.status == "passed";
    item.observation_id = Some(observation_id.clone());
    if !task.observation_ids.contains(&observation_id) {
        task.observation_ids.push(observation_id.clone());
    }
    let observation = ToolObservationInput {
        observation_id: observation_id.clone(),
        tool_name: input.tool_name,
        observation: input.observation,
        payload: json!({
            "status": input.status,
            "scope": input.scope,
            "action_receipt_ref": action_receipt.receipt_id,
            "action_lease_id": lease_id,
            "provenance_set_hash": provenance.hash,
            "planned_verifier_ref": provenance.planned_verifier_ref,
            "task_revision": input.expected_revision,
            "candidate_only": true
        }),
    };
    let contract = task_input(&task, Some(MemoryRevision::new(input.expected_revision)));
    let (receipt, task) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "daemon-tool-observer",
        TaintClass::LocalTool,
        TaskTransitionEvidence {
            observation: Some(observation),
            verification: None,
        },
    )
    .await?;
    Ok(json!({
        "status": "observed_candidate",
        "observation_id": observation_id,
        "task_contract": task,
        "write_receipt": receipt
    }))
}

const MAX_COMPLETION_DECISION_BYTES: usize = 512;

fn deterministic_completion_uuid(completion_write_id: WriteId, domain: &str) -> uuid::Uuid {
    let digest = blake3::hash(format!("{completion_write_id}:{domain}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

fn completion_agent_result_write_id(completion_write_id: WriteId) -> WriteId {
    WriteId::from_uuid(deterministic_completion_uuid(
        completion_write_id,
        "agent-result",
    ))
}

fn completion_memory_outcome(memory: Option<&CompletionMemoryRequest>) -> &'static str {
    match memory {
        Some(CompletionMemoryRequest::SaveDecision { .. }) => "saved_decision",
        Some(CompletionMemoryRequest::NothingToSave) => "nothing_to_save",
        None => "not_requested",
    }
}

fn derive_completion_agent_result_command(
    request_context: AuthenticatedRequestContext,
    task: &TaskContract,
    completion_write_id: WriteId,
    verification_receipt_ids: Vec<ReceiptId>,
    requested_memory: Option<&CompletionMemoryRequest>,
) -> Result<AgentResultRecordCommand> {
    let provenance = task
        .action_provenance
        .as_ref()
        .context("completion memory requires canonical action provenance")?;
    let action_lease_id = task
        .action_lease_id
        .context("completion memory requires the accepted ActionLease")?;
    let base_commit = provenance
        .source_scope
        .baseline_commit
        .clone()
        .context("completion memory requires the leased base commit")?;
    let branch = provenance
        .source_scope
        .branch
        .clone()
        .context("completion memory requires the leased branch")?;
    let accepted_write_set = provenance.source_scope.artifact_paths.clone();
    let first_scope = task
        .verification_scopes
        .first()
        .context("completion memory requires canonical verifier scope")?;
    if task.verification_ids.len() != verification_receipt_ids.len()
        || task.verification_ids.len() != task.verification_scopes.len()
        || task.verification_ids.iter().any(|verification_id| {
            !task
                .verification_scopes
                .iter()
                .any(|scope| scope.verification_id == *verification_id)
        })
        || task.verification_scopes.iter().any(|scope| {
            scope.branch != branch
                || scope.commit != first_scope.commit
                || scope.project_id != task.project_id
                || scope.task_id != task.task_id
                || scope
                    .artifact_refs
                    .iter()
                    .any(|artifact| !accepted_write_set.contains(&artifact.resource_ref))
        })
    {
        anyhow::bail!("completion memory verifier lineage is not exact");
    }
    let agent_result_write_id = completion_agent_result_write_id(completion_write_id);
    let mut canonical_artifact_refs = task
        .verification_scopes
        .iter()
        .flat_map(|scope| scope.artifact_refs.clone())
        .collect::<Vec<_>>();
    canonical_artifact_refs.sort_by(|left, right| {
        (&left.resource_ref, &left.content_hash).cmp(&(&right.resource_ref, &right.content_hash))
    });
    canonical_artifact_refs.dedup_by(|left, right| {
        left.resource_ref == right.resource_ref && left.content_hash == right.content_hash
    });
    let lineage = ControllerCommitHandoff {
        child_session_id: request_context.session_id,
        task_id: task.task_id,
        action_lease_id,
        base_commit: base_commit.clone(),
        candidate_artifact_or_diff_ref: format!("git-diff:{base_commit}..{}", first_scope.commit),
        accepted_write_set: accepted_write_set.clone(),
        branch: branch.clone(),
        verification_ids: task.verification_ids.clone(),
        verification_receipt_ids,
        canonical_artifact_refs,
        resulting_controller_commit: first_scope.commit.clone(),
        controller_receipt_id: ReceiptId::from_uuid(agent_result_write_id.as_uuid()),
        provenance_set_hash: provenance.hash.clone(),
    };
    let memory = derive_completion_memory(
        task,
        completion_write_id,
        agent_result_write_id,
        first_scope,
        &lineage,
        requested_memory,
    )?;
    Ok(AgentResultRecordCommand {
        context: CommandContext {
            write_id: agent_result_write_id,
            agent_id: AgentId::from_uuid(request_context.session_id.as_uuid()),
            session_id: Some(request_context.session_id),
            project_id: task.project_id,
            task_id: Some(task.task_id),
            scope: format!("task:{}", task.task_id),
            authority: "daemon-finish-gate".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        lineage,
        memory,
    })
}

fn derive_completion_memory(
    task: &TaskContract,
    completion_write_id: WriteId,
    agent_result_write_id: WriteId,
    first_scope: &VerifierArtifactScope,
    lineage: &ControllerCommitHandoff,
    requested_memory: Option<&CompletionMemoryRequest>,
) -> Result<CompletionMemoryAdmission> {
    Ok(match requested_memory {
        Some(CompletionMemoryRequest::SaveDecision { statement }) => {
            let statement = statement.trim();
            if statement.is_empty() || statement.len() > MAX_COMPLETION_DECISION_BYTES {
                anyhow::bail!(
                    "completion decision must contain 1..={MAX_COMPLETION_DECISION_BYTES} bytes"
                );
            }
            let where_applicable = std::iter::once(format!("project:{}", task.project_id))
                .chain(std::iter::once(format!("task:{}", task.task_id)))
                .chain(std::iter::once(format!("branch:{}", lineage.branch)))
                .chain(std::iter::once(format!("commit:{}", first_scope.commit)))
                .chain(
                    lineage
                        .accepted_write_set
                        .iter()
                        .map(|path| format!("accepted_artifact:{path}")),
                )
                .collect::<Vec<_>>();
            let where_not_applicable = vec![
                "other projects or tasks".to_owned(),
                "artifact paths outside the accepted ActionLease write set".to_owned(),
                format!("branches other than {}", lineage.branch),
                format!(
                    "commits other than {} unless canonically revalidated",
                    first_scope.commit
                ),
            ];
            let freshness_rule = format!(
                "revalidate when task revision, action provenance, accepted artifact content, branch, commit, verifier configuration, or original verification IDs [{}] change",
                task.verification_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let source_id = format!("completion:{}:{}", task.task_id, agent_result_write_id);
            let evidence_id = EvidenceId::from_uuid(deterministic_completion_uuid(
                completion_write_id,
                "completion-evidence",
            ));
            let claim_id = ClaimId::from_uuid(deterministic_completion_uuid(
                completion_write_id,
                "completion-claim",
            ));
            let source_material = json!({
                "statement": statement,
                "lineage": &lineage,
                "where_applicable": &where_applicable,
                "where_not_applicable": &where_not_applicable,
                "freshness_rule": &freshness_rule,
            });
            let content_hash = canonical_struct_hash(&source_material)?;
            let source = SourceSnapshotInput {
                source_id: source_id.clone(),
                uri: format!(
                    "git+{}?branch={}#{}",
                    first_scope.worktree_ref, lineage.branch, first_scope.commit
                ),
                authority: "daemon-finish-gate".to_owned(),
                content_hash,
                excerpt: statement.to_owned(),
            };
            let evidence = EvidenceAtomInput {
                evidence_id,
                source_id: source_id.clone(),
                summary: "exact completion decision and canonical controller handoff lineage"
                    .to_owned(),
                payload: source_material.clone(),
            };
            let claim = ClaimCardInput {
                claim_id,
                statement: statement.to_owned(),
                status: eliot_types::EpistemicStatus::Verified,
                payload: json!({
                    "source_id": source_id,
                    "evidence_id": evidence_id,
                    "lineage": &lineage,
                    "where_applicable": &where_applicable,
                    "where_not_applicable": &where_not_applicable,
                    "freshness_rule": &freshness_rule,
                }),
            };
            CompletionMemoryAdmission::SaveDecision {
                decision: Box::new(CompletionDecisionMemory {
                    source,
                    evidence,
                    claim,
                    where_applicable,
                    where_not_applicable,
                    freshness_rule,
                }),
            }
        }
        Some(CompletionMemoryRequest::NothingToSave) | None => {
            CompletionMemoryAdmission::NothingToSave
        }
    })
}

async fn submit_completion_agent_result(
    state: &McpState,
    request_context: AuthenticatedRequestContext,
    task: &TaskContract,
    completion_write_id: WriteId,
    requested_memory: Option<&CompletionMemoryRequest>,
) -> Result<Option<eliot_types::WriteReceipt>> {
    let git_handoff = task
        .action_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.source_scope.kind == "git_worktree");
    if !git_handoff {
        if matches!(
            requested_memory,
            Some(CompletionMemoryRequest::SaveDecision { .. })
        ) {
            anyhow::bail!("saved completion memory requires canonical Git handoff lineage");
        }
        return Ok(None);
    }
    let agent_result_write_id = completion_agent_result_write_id(completion_write_id);
    if let Some(receipt) = state
        .store
        .write_receipt_by_id(&agent_result_write_id)
        .await?
    {
        if receipt.project_id != task.project_id
            || receipt.task_id != Some(task.task_id)
            || receipt.command_kind != eliot_types::SemanticCommandKind::AgentResultRecord
            || !matches!(
                receipt.status,
                WriteStatus::Committed | WriteStatus::IdempotentReplay
            )
        {
            anyhow::bail!("completion AgentResult receipt has incompatible canonical scope");
        }
        let claim_id = ClaimId::from_uuid(deterministic_completion_uuid(
            completion_write_id,
            "completion-claim",
        ));
        let existing_saved_decision = receipt.created_records.contains(&claim_id.to_string());
        match requested_memory {
            Some(CompletionMemoryRequest::SaveDecision { .. }) if !existing_saved_decision => {
                anyhow::bail!("completion memory was already finalized as nothing_to_save");
            }
            Some(CompletionMemoryRequest::NothingToSave) if existing_saved_decision => {
                anyhow::bail!("completion memory was already finalized as save_decision");
            }
            _ => {}
        }
        // The first accepted AgentResult is immutable. A later authenticated IPC
        // session returns its canonical receipt instead of rebuilding an envelope
        // whose session-bound audit fields would change the idempotency hash.
        return Ok(Some(receipt));
    }
    let mut verification_receipt_ids = Vec::with_capacity(task.verification_ids.len());
    for verification_id in &task.verification_ids {
        let verification_write_id = WriteId::from_uuid(verification_id.as_uuid());
        let receipt = state
            .store
            .write_receipt_by_id(&verification_write_id)
            .await?
            .context("completion memory verification receipt does not resolve")?;
        if receipt.project_id != task.project_id || receipt.task_id != Some(task.task_id) {
            anyhow::bail!("completion memory verification receipt scope mismatch");
        }
        verification_receipt_ids.push(receipt.receipt_id);
    }
    let command = SemanticCommand::AgentResultRecord(derive_completion_agent_result_command(
        request_context,
        task,
        completion_write_id,
        verification_receipt_ids,
        requested_memory,
    )?);
    let envelope = WriteAdmissionService.admit(&command)?;
    state
        .writer
        .submit(envelope)
        .await
        .map(Some)
        .map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
async fn dispatch_task_completion(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: TaskCompletionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    let mut task = require_task(state, project_id, task_id).await?;
    if let Some(receipt) = state.store.write_receipt_by_id(&write_id).await? {
        if task.status == TaskContractStatus::DoneVerified
            && task.completion_write_id == Some(write_id)
            && receipt.project_id == project_id
            && receipt.task_id == Some(task_id)
        {
            let agent_result_receipt = submit_completion_agent_result(
                state,
                context,
                &task,
                write_id,
                input.memory.as_ref(),
            )
            .await?;
            return Ok(json!({
                "status": "done_verified",
                "decision": "DONE_VERIFIED",
                "task_contract": task,
                "write_receipt": receipt,
                "agent_result_receipt": agent_result_receipt,
                "memory_outcome": completion_memory_outcome(input.memory.as_ref())
            }));
        }
        anyhow::bail!("completion write_id already belongs to another transition");
    }
    ensure_expected_revision_or_replay(state, &task, input.expected_revision, write_id).await?;

    let mut uncovered = Vec::new();
    if task.status != TaskContractStatus::Active {
        uncovered.push("task:not_active".to_owned());
    }
    match task.action_provenance.as_ref() {
        Some(provenance) => {
            let expected = provenance.hash.clone();
            let mut material = provenance.clone();
            material.hash.clear();
            if canonical_struct_hash(&material)? != expected {
                uncovered.push("action_provenance:invalid_hash".to_owned());
            }
        }
        None => uncovered.push("action_provenance:required".to_owned()),
    }

    let requested_acceptance = input
        .acceptance_item_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let stored_acceptance = task
        .acceptance_items
        .iter()
        .map(|item| item.item_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if requested_acceptance != stored_acceptance
        || requested_acceptance.len() != input.acceptance_item_ids.len()
    {
        uncovered.push("acceptance_mapping:not_exact".to_owned());
    }
    let requested_observations = input
        .observation_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let stored_observations = task
        .observation_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if requested_observations != stored_observations
        || requested_observations.len() != input.observation_ids.len()
    {
        uncovered.push("observation_mapping:not_exact".to_owned());
    }
    let requested_verifications = input
        .verification_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let stored_verifications = task
        .verification_ids
        .iter()
        .map(ToString::to_string)
        .collect::<std::collections::BTreeSet<_>>();
    if requested_verifications != stored_verifications
        || requested_verifications.len() != input.verification_ids.len()
    {
        uncovered.push("verification_mapping:not_exact".to_owned());
    }
    for item in &task.acceptance_items {
        let required_evidence_present = match item.required_evidence {
            TaskAcceptanceEvidenceKind::Observation => item
                .observation_id
                .as_ref()
                .is_some_and(|id| input.observation_ids.contains(id)),
            TaskAcceptanceEvidenceKind::Verification => item
                .verification_id
                .is_some_and(|id| input.verification_ids.contains(&id.to_string())),
        };
        if !item.satisfied
            || !required_evidence_present
            || !input.acceptance_item_ids.contains(&item.item_id)
        {
            uncovered.push(item.item_id.clone());
        }
    }
    if task.observation_ids.is_empty() {
        uncovered.push("observation:required".to_owned());
    }
    if task.verification_ids.is_empty() {
        uncovered.push("verification:required".to_owned());
    }
    for observation_id in &task.observation_ids {
        if input.observation_ids.contains(observation_id) {
            let observation_write_id = WriteId::from_str(observation_id)?;
            let receipt = state
                .store
                .write_receipt_by_id(&observation_write_id)
                .await?;
            if receipt.as_ref().is_none_or(|receipt| {
                receipt.project_id != project_id || receipt.task_id != Some(task_id)
            }) {
                uncovered.push(format!("observation_receipt:{observation_id}"));
            }
        } else {
            uncovered.push(format!("observation:{observation_id}"));
        }
    }
    for verification_id in &task.verification_ids {
        let id = verification_id.to_string();
        if input.verification_ids.contains(&id) {
            let verification_write_id = WriteId::from_uuid(verification_id.as_uuid());
            let receipt = state
                .store
                .write_receipt_by_id(&verification_write_id)
                .await?;
            if receipt.as_ref().is_none_or(|receipt| {
                receipt.project_id != project_id || receipt.task_id != Some(task_id)
            }) {
                uncovered.push(format!("verification_receipt:{id}"));
            }
            let Some(scope) = task
                .verification_scopes
                .iter()
                .find(|scope| scope.verification_id == *verification_id)
            else {
                uncovered.push(format!("verification_scope:{id}:missing"));
                continue;
            };
            let item_scope_matches = task.acceptance_items.iter().any(|item| {
                item.required_evidence == TaskAcceptanceEvidenceKind::Verification
                    && item.verification_id == Some(*verification_id)
                    && item.verification_scope_hash.as_deref()
                        == Some(scope.canonical_scope_hash.as_str())
                    && scope.acceptance_item_ids == [item.item_id.clone()]
            });
            if !item_scope_matches {
                uncovered.push(format!("verification_scope:{id}:acceptance_mismatch"));
            }
            match state.store.verification_run_by_id(*verification_id).await? {
                Some(run) if run.result == VerificationResult::Passed => {
                    let stored_scope =
                        run.payload
                            .get("artifact_scope")
                            .cloned()
                            .and_then(|value| {
                                serde_json::from_value::<VerifierArtifactScope>(value).ok()
                            });
                    if stored_scope.as_ref() != Some(scope) {
                        uncovered.push(format!("verification_scope:{id}:record_mismatch"));
                    }
                }
                _ => uncovered.push(format!("verification_run:{id}:not_passed")),
            }
            if let Err(error) = revalidate_verifier_scope(state, &task, scope).await {
                uncovered.push(format!("verification_scope:{id}:{error}"));
            }
        } else {
            uncovered.push(format!("verification:{id}"));
        }
    }
    if !uncovered.is_empty() {
        return Ok(json!({
            "status": "denied_incomplete",
            "decision": "deny",
            "uncovered_items": uncovered,
            "write_receipt": Value::Null
        }));
    }

    task.status = TaskContractStatus::DoneVerified;
    task.completion_write_id = Some(write_id);
    let contract = task_input(&task, Some(MemoryRevision::new(input.expected_revision)));
    let (receipt, task) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "daemon-finish-gate",
        TaintClass::LocalVerified,
        TaskTransitionEvidence::default(),
    )
    .await?;
    // Bind durable handoff/memory to the canonical finish transition. If this second,
    // idempotent write is interrupted, replay enters the DONE_VERIFIED branch above
    // and repairs it without ever publishing completion memory ahead of task truth.
    let agent_result_receipt =
        submit_completion_agent_result(state, context, &task, write_id, input.memory.as_ref())
            .await?;
    Ok(json!({
        "status": "done_verified",
        "decision": "DONE_VERIFIED",
        "task_contract": task,
        "write_receipt": receipt,
        "agent_result_receipt": agent_result_receipt,
        "memory_outcome": completion_memory_outcome(input.memory.as_ref())
    }))
}

#[derive(Default)]
struct TaskTransitionEvidence {
    observation: Option<ToolObservationInput>,
    verification: Option<VerificationRunInput>,
}

#[allow(clippy::too_many_arguments)]
async fn submit_task_transition(
    state: &McpState,
    request_context: AuthenticatedRequestContext,
    project_id: ProjectId,
    write_id: WriteId,
    contract: TaskContractInput,
    authority: &str,
    taint: TaintClass,
    evidence: TaskTransitionEvidence,
) -> Result<(eliot_types::WriteReceipt, TaskContract)> {
    let task_id = contract.task_id;
    let command = SemanticCommand::TaskContractWrite(TaskContractWriteCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(request_context.session_id.as_uuid()),
            session_id: Some(request_context.session_id),
            project_id,
            task_id: Some(task_id),
            scope: format!("task:{task_id}"),
            authority: authority.to_owned(),
            visibility: Visibility::Project,
            taint,
            lifecycle_status: LifecycleStatus::Active,
        },
        contract,
        observation: evidence.observation,
        verification: evidence.verification,
    });
    let envelope = WriteAdmissionService.admit(&command)?;
    let receipt = state.writer.submit(envelope).await?;
    let contract = require_task(state, project_id, task_id).await?;
    Ok((receipt, contract))
}

async fn require_task(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<TaskContract> {
    let task = state
        .store
        .task_contract_by_id(task_id)
        .await?
        .context("TaskContract not found")?;
    if task.project_id != project_id {
        anyhow::bail!("TaskContract project scope mismatch");
    }
    Ok(task)
}

async fn ensure_expected_revision_or_replay(
    state: &McpState,
    task: &TaskContract,
    expected_revision: u64,
    write_id: WriteId,
) -> Result<()> {
    if state.store.write_receipt_by_id(&write_id).await?.is_some() {
        return Ok(());
    }
    if task.memory_revision != MemoryRevision::new(expected_revision) {
        anyhow::bail!(
            "stale task revision: expected {expected_revision}, current {}",
            task.memory_revision.value()
        );
    }
    Ok(())
}

fn task_input(task: &TaskContract, expected_revision: Option<MemoryRevision>) -> TaskContractInput {
    TaskContractInput {
        task_id: task.task_id,
        title: task.title.clone(),
        status: task.status,
        acceptance_items: task.acceptance_items.clone(),
        expected_revision,
        action_lease_id: task.action_lease_id,
        understanding_proof_hash: task.understanding_proof_hash.clone(),
        action_provenance: task.action_provenance.clone(),
        observation_ids: task.observation_ids.clone(),
        verification_ids: task.verification_ids.clone(),
        verification_scopes: task.verification_scopes.clone(),
        completion_write_id: task.completion_write_id,
    }
}

#[allow(clippy::too_many_lines)]
async fn dispatch_compile_packet_l3(state: &McpState, arguments: Value) -> Result<Value> {
    let input: CompilePacketToolInput = serde_json::from_value(arguments)?;
    let request = input.request;
    let packet_task = if let Ok(packet_task_id) = TaskId::from_str(&request.task_id) {
        state.store.task_contract_by_id(packet_task_id).await?
    } else {
        None
    };
    let codecortex_reports = latest_codecortex_report(&state.root)?
        .into_iter()
        .collect::<Vec<_>>();
    let current_git_scope =
        resolve_governed_packet_git_scope(&request, packet_task.as_ref(), &codecortex_reports)
            .await?;
    let compiler = ContextCompiler::new(ReadService::new(state.store.clone()));
    let mut packet = match (current_git_scope.as_ref(), input.material_frame.as_ref()) {
        (Some(scope), Some(frame)) => {
            Box::pin(compiler.compile_material_with_governed_git_scope(
                &request,
                &codecortex_reports,
                scope,
                frame,
            ))
            .await?
        }
        (Some(scope), None) => {
            Box::pin(compiler.compile_with_governed_git_scope(&request, &codecortex_reports, scope))
                .await?
        }
        (None, Some(frame)) => {
            Box::pin(compiler.compile_material(&request, &codecortex_reports, frame)).await?
        }
        (None, None) => {
            Box::pin(compiler.compile_with_codecortex(&request, &codecortex_reports)).await?
        }
    };
    let task_frame = TaskMeaningFrame {
        task_id: request.task_id.clone(),
        user_goal: request.goal.clone(),
        normalized_goal: request.goal.to_ascii_lowercase(),
        task_or_action_type: "governed_task".to_owned(),
        desired_state_transition: request.goal.clone(),
        problem_or_failure_signature: packet.open_questions.join(" "),
        project_module_boundary: packet
            .codecortex
            .as_ref()
            .map_or_else(Vec::new, |view| view.report_refs.clone()),
        files_symbols_config: packet.codecortex.as_ref().map_or_else(Vec::new, |view| {
            view.file_evidence
                .iter()
                .map(|evidence| evidence.path.clone())
                .collect()
        }),
        control_data_state_path: packet
            .causal_bridge
            .iter()
            .map(|hop| format!("{} -> {} -> {}", hop.from, hop.relation, hop.to))
            .collect(),
        constraints: input
            .material_frame
            .as_ref()
            .map_or_else(Vec::new, |frame| frame.killed_paths.clone()),
        invariants: input
            .material_frame
            .as_ref()
            .map_or_else(Vec::new, |frame| frame.acceptance_items.clone()),
        current_evidence: packet.exact_handles.clone(),
        material_unknowns: packet.open_questions.clone(),
        expected_artifact: input
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.next_allowed_action.clone()),
        predicted_observable: input
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.expected_observable.clone()),
        verifier_need: input
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.verifier.clone()),
        abstraction_level_needed: "auto".to_owned(),
        codecortex_report_ref: codecortex_reports
            .first()
            .map(|report| format!("codecortex:{}:{}", report.project, report.task)),
        ..TaskMeaningFrame::default()
    };
    let memory_need = MemoryNeedService::decide(&task_frame, None);
    let cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, request.project_id, "experience_case").await?,
    );
    let exposure_policy = MemoryExposurePolicy {
        mode: input.memory_mode.unwrap_or_default(),
        packet_cache_partition: format!(
            "{:?}:{}",
            input.memory_mode.unwrap_or_default(),
            request.task_id
        )
        .to_ascii_lowercase(),
        ..MemoryExposurePolicy::default()
    };
    let experience = ExperienceRetrievalService::recall(
        &ExperienceRecallRequest {
            project_id: request.project_id,
            task_frame,
            need: memory_need.clone(),
            exposure_policy,
        },
        &cases,
    );
    packet.memory_need_decision = Some(memory_need);
    packet.experience_priors = experience.experience_priors;
    if let Some(task) = &packet_task {
        packet.memory_applicability.inclusion_reasons.push(format!(
            "eliot/task/{}@{}:canonical_task_state",
            task.task_id,
            task.memory_revision.value()
        ));
        packet.memory_applicability.inclusion_reasons.sort();
        packet.memory_applicability.inclusion_reasons.dedup();
    }
    write_json_report(
        &state
            .root
            .join("reports")
            .join("context-packets")
            .join("latest.json"),
        &packet,
    )?;
    let mut value = serde_json::to_value(packet)?;
    if let Some(task) = packet_task.as_ref() {
        enrich_packet_with_task(state, &mut value, task).await?;
    }
    Ok(value)
}

async fn dispatch_understanding_outcome_record(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let mut input: UnderstandingOutcomeToolInput = serde_json::from_value(arguments)?;
    CognitiveMemoryWriter::write_understanding_outcome(
        &state.writer,
        &WriteAdmissionService,
        parse_project_id(&input.project_id)?,
        &mut input.record,
    )
    .await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("cognition")
            .join("understanding-outcome-latest.json"),
        &input.record,
    )?;
    serde_json::to_value(input.record).map_err(Into::into)
}

async fn dispatch_memory_influence_trace(state: &McpState, arguments: Value) -> Result<Value> {
    let mut input: MemoryInfluenceTraceToolInput = serde_json::from_value(arguments)?;
    CognitiveMemoryWriter::write_memory_influence_trace(
        &state.writer,
        &WriteAdmissionService,
        parse_project_id(&input.project_id)?,
        &mut input.trace,
    )
    .await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("cognition")
            .join("memory-influence-latest.json"),
        &input.trace,
    )?;
    serde_json::to_value(input.trace).map_err(Into::into)
}

async fn dispatch_context_cargo_receipt(state: &McpState, arguments: Value) -> Result<Value> {
    let mut input: ContextCargoReceiptToolInput = serde_json::from_value(arguments)?;
    CognitiveMemoryWriter::write_context_cargo_receipt(
        &state.writer,
        &WriteAdmissionService,
        parse_project_id(&input.project_id)?,
        &mut input.receipt,
    )
    .await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("cognition")
            .join("context-cargo-latest.json"),
        &input.receipt,
    )?;
    serde_json::to_value(input.receipt).map_err(Into::into)
}

fn dispatch_task_meaning(arguments: Value) -> Result<Value> {
    let input: TaskMeaningToolInput = serde_json::from_value(arguments)?;
    let bridge_quality = TaskMeaningService::bridge_quality(&input.frame);
    let memory_need = MemoryNeedService::decide(&input.frame, input.requested_need);
    Ok(json!({
        "task_meaning_frame": input.frame,
        "causal_bridge_quality": bridge_quality,
        "memory_need_decision": memory_need,
        "authority": "current-task model only; no memory grants current truth or action authority"
    }))
}

async fn semantic_records<T>(
    state: &McpState,
    project_id: ProjectId,
    receipt_kind: &str,
) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    state
        .store
        .semantic_records_by_kind(project_id, receipt_kind)
        .await?
        .into_iter()
        .map(|observation| {
            serde_json::from_value(
                observation
                    .payload
                    .get("receipt_body")
                    .cloned()
                    .context("canonical semantic observation has no receipt_body")?,
            )
            .map_err(Into::into)
        })
        .collect()
}

async fn dispatch_experience_recall(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExperienceRecallToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?,
    );
    let need = MemoryNeedService::decide(&input.frame, input.requested_need);
    let request = ExperienceRecallRequest {
        project_id,
        task_frame: input.frame,
        need,
        exposure_policy: input.exposure_policy.unwrap_or_default(),
    };
    serde_json::to_value(ExperienceRetrievalService::recall(&request, &cases)).map_err(Into::into)
}

async fn dispatch_experience_reinstate(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExperienceReinstateToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?,
    );
    let experience_case = cases
        .iter()
        .find(|case| case.case_id == input.case_id)
        .context("experience case does not exist")?;
    serde_json::to_value(ContextReinstatementService::bundle(experience_case)).map_err(Into::into)
}

async fn dispatch_experience_form(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: ExperienceFormToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    if input.episode.project_id != project_id {
        anyhow::bail!("experience episode belongs to a different project");
    }
    let task_id = TaskId::from_str(&input.task_id).context("parse experience task_id")?;
    let result = ExperienceFormationService::reconstruct(input.episode)?;
    match result {
        ExperienceFormationResult::Formed {
            mut experience_case,
        } => {
            if let Some(existing) =
                semantic_records::<ExperienceCase>(state, project_id, "experience_case")
                    .await?
                    .into_iter()
                    .find(|existing| existing.case_id == experience_case.case_id)
            {
                let mut value = serde_json::to_value(ExperienceFormationResult::Formed {
                    experience_case: Box::new(existing),
                })?;
                value["idempotent_replay"] = Value::Bool(true);
                return Ok(value);
            }
            let receipt = CognitiveMemoryWriter::write_semantic_record(
                &state.writer,
                &WriteAdmissionService,
                project_id,
                task_id,
                AgentSessionId::from_uuid(context.session_id.as_uuid()),
                "experience_case",
                &experience_case,
            )
            .await?;
            experience_case.authority.canonical_receipt = Some(receipt);
            let mut value =
                serde_json::to_value(ExperienceFormationResult::Formed { experience_case })?;
            value["idempotent_replay"] = Value::Bool(false);
            Ok(value)
        }
        nothing @ ExperienceFormationResult::NothingToLearn { .. } => {
            serde_json::to_value(nothing).map_err(Into::into)
        }
    }
}

async fn dispatch_experience_abstract(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: ExperienceAbstractToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse abstraction task_id")?;
    let all_cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?,
    );
    let cases = input
        .case_refs
        .iter()
        .map(|case_ref| {
            all_cases
                .iter()
                .find(|case| case.case_id == *case_ref)
                .cloned()
                .with_context(|| format!("experience case {case_ref} does not exist"))
        })
        .collect::<Result<Vec<_>>>()?;
    let result = ContrastiveAbstractionService::abstract_cases(project_id, &cases)?;
    match result {
        ContrastiveAbstractionResult::Formed { mut pattern } => {
            if let Some(existing) =
                semantic_records::<ExperiencePattern>(state, project_id, "experience_pattern")
                    .await?
                    .into_iter()
                    .find(|existing| existing.pattern_id == pattern.pattern_id)
            {
                let mut value = serde_json::to_value(ContrastiveAbstractionResult::Formed {
                    pattern: Box::new(existing),
                })?;
                value["idempotent_replay"] = Value::Bool(true);
                return Ok(value);
            }
            let receipt = CognitiveMemoryWriter::write_semantic_record(
                &state.writer,
                &WriteAdmissionService,
                project_id,
                task_id,
                AgentSessionId::from_uuid(context.session_id.as_uuid()),
                "experience_pattern",
                &pattern,
            )
            .await?;
            pattern.authority.canonical_receipt = Some(receipt);
            let mut value = serde_json::to_value(ContrastiveAbstractionResult::Formed { pattern })?;
            value["idempotent_replay"] = Value::Bool(false);
            Ok(value)
        }
        none @ ContrastiveAbstractionResult::NoLearnablePattern { .. } => {
            serde_json::to_value(none).map_err(Into::into)
        }
    }
}

async fn dispatch_experience_maturity_transition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: ExperienceMaturityTransitionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse maturity task_id")?;
    let physical_patterns =
        semantic_records::<ExperiencePattern>(state, project_id, "experience_pattern").await?;
    let mut transfer_evidence = input.evidence.independent_host_refs.clone();
    transfer_evidence.extend(input.evidence.verified_decision_delta_refs.clone());
    transfer_evidence.sort();
    transfer_evidence.dedup();
    if let Some(existing) = physical_patterns.iter().find(|existing| {
        existing.pattern_id == input.pattern_id
            && existing.maturity.state == input.target_state
            && existing.transfer_evidence == transfer_evidence
    }) {
        let mut value = serde_json::to_value(existing)?;
        value["idempotent_replay"] = Value::Bool(true);
        return Ok(value);
    }
    let mut pattern = deduplicate_experience_patterns(physical_patterns.clone())
        .into_iter()
        .find(|pattern| pattern.pattern_id == input.pattern_id)
        .context("experience pattern does not exist in the active logical projection")?;
    let next_maturity =
        MaturityGateService::transition(&pattern.maturity, input.target_state, &input.evidence)?;
    pattern.maturity = next_maturity;
    pattern.transfer_evidence = transfer_evidence.clone();
    pattern.authority.review_refs.extend(transfer_evidence);
    pattern.authority.review_refs.sort();
    pattern.authority.review_refs.dedup();
    let receipt = CognitiveMemoryWriter::write_semantic_record(
        &state.writer,
        &WriteAdmissionService,
        project_id,
        task_id,
        AgentSessionId::from_uuid(context.session_id.as_uuid()),
        "experience_pattern",
        &pattern,
    )
    .await?;
    pattern.authority.canonical_receipt = Some(receipt);
    let mut value = serde_json::to_value(pattern)?;
    value["idempotent_replay"] = Value::Bool(false);
    Ok(value)
}

async fn dispatch_negative_transfer_record(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: NegativeTransferToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse negative-transfer task_id")?;
    let mut record = NegativeTransferService::record(
        input.experiment_ref,
        input.memory_handles,
        input.task_id,
        input.harm,
        input.root_cause_stage,
        input.source_has_reconstructable_episode,
    );
    if let Some(existing) = semantic_records::<eliot_types::NegativeTransferRecord>(
        state,
        project_id,
        "negative_transfer_record",
    )
    .await?
    .into_iter()
    .find(|existing| existing.record_id == record.record_id)
    {
        let mut value = serde_json::to_value(existing)?;
        value["idempotent_replay"] = Value::Bool(true);
        return Ok(value);
    }
    let receipt = CognitiveMemoryWriter::write_semantic_record(
        &state.writer,
        &WriteAdmissionService,
        project_id,
        task_id,
        AgentSessionId::from_uuid(context.session_id.as_uuid()),
        "negative_transfer_record",
        &record,
    )
    .await?;
    record.receipt = Some(receipt);
    let mut value = serde_json::to_value(record)?;
    value["idempotent_replay"] = Value::Bool(false);
    Ok(value)
}

fn latest_task_packet(state: &McpState, task_id: TaskId) -> Result<Option<ContextPacketL3>> {
    let path = state
        .root
        .join("reports")
        .join("context-packets")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let packet: ContextPacketL3 = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok((packet.task_id == task_id.to_string()).then_some(packet))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyHostBinding {
    work_item_id: WorkItemId,
    host_id: String,
    lease_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AutonomyApprovalDecisionKind {
    Granted,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutonomyApprovalRequestRecord {
    approval_id: String,
    request_write_id: WriteId,
    autonomy_run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    requested_by_session_id: SessionId,
    exact_action_hash: String,
    approval_revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    requested_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutonomyApprovalDecisionRecord {
    approval_id: String,
    request_write_id: WriteId,
    decision_write_id: WriteId,
    autonomy_run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    exact_action_hash: String,
    decision: AutonomyApprovalDecisionKind,
    reason: String,
    approval_revision: u64,
    decided_by_session_id: SessionId,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    decided_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutonomyApprovalConsumptionRecord {
    approval_id: String,
    decision_write_id: WriteId,
    consumption_write_id: WriteId,
    autonomy_run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    exact_action_hash: String,
    approval_revision: u64,
    consumed_by_session_id: SessionId,
    aggregate_write_id: String,
    #[serde(with = "time::serde::rfc3339")]
    consumed_at: time::OffsetDateTime,
}

#[derive(serde::Serialize)]
struct AutonomyCompletionApprovalScope<'a> {
    action: &'static str,
    project_id: ProjectId,
    task_id: TaskId,
    autonomy_run_id: &'a str,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    completion_proof_hash: String,
    reason: &'a str,
    risk_tier: &'static str,
    verifier_refs: &'a [String],
}

struct AutonomyCompletionApprovalInput<'a> {
    project_id: ProjectId,
    task_id: TaskId,
    autonomy_run_id: &'a str,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    completion_proof: &'a CompletionProof,
    reason: &'a str,
    verifier_refs: &'a [String],
}

struct CanonicalR3ApprovalResolution<'a> {
    loaded: &'a LoadedAutonomyRuntime,
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &'a str,
    exact_action_hash: &'a str,
    aggregate_write_id: WriteId,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyWorkGraphRecord {
    #[serde(default)]
    aggregate_schema_version: Option<String>,
    #[serde(default)]
    authoritative_commit: Option<AutonomyActionCommit>,
    #[serde(default)]
    runtime_snapshot: Option<Value>,
    #[serde(default)]
    transition_snapshots: Vec<eliot_types::AutonomyRunTransitionReceipt>,
    #[serde(default)]
    recovery_snapshots: Vec<AutonomyRecoveryReceipt>,
    #[serde(default)]
    secondary_transition_snapshots: Vec<eliot_types::AutonomyRunTransitionReceipt>,
    #[serde(default)]
    secondary_recovery_snapshots: Vec<AutonomyRecoveryReceipt>,
    #[serde(default)]
    tripwire_snapshots: Vec<AutonomyTripwireEnvelope>,
    #[serde(default)]
    budget_snapshot: Option<AutonomyBudgetRecord>,
    #[serde(default)]
    action_result: Value,
    #[serde(default)]
    host_result_chains: Vec<AutonomyHostResultChain>,
    #[serde(default)]
    approval_consumption: Option<AutonomyApprovalConsumptionRecord>,
    autonomy_run_id: String,
    runtime_revision: u64,
    action: String,
    action_fingerprint: String,
    tripwire_policy: AutonomyTripwirePolicy,
    work_items: Vec<AutonomyWorkItem>,
    host_bindings: Vec<AutonomyHostBinding>,
    transition_refs: Vec<String>,
    recovery_refs: Vec<String>,
    completion_proof: Option<CompletionProof>,
}

const AUTONOMY_ACTION_AGGREGATE_SCHEMA: &str = "eliot-autonomy-action-aggregate-v1";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyActionCommit {
    aggregate_write_id: String,
    idempotency_key: String,
    action: String,
    action_fingerprint: String,
    committed_state: AutonomyRunState,
    committed_state_revision: u64,
    committed_runtime_revision: u64,
    completion_proof_hash: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyHostResultChain {
    work_item_id: WorkItemId,
    host_id: AgentHostId,
    agent_session_id: AgentSessionId,
    role_lease_id: String,
    work_lease_id: WorkLeaseId,
    invocation_id: String,
    result_id: String,
    disposition_id: String,
    candidate_diff_ref: String,
    candidate_review_ref: String,
    commit_ref: String,
    changed_files: Vec<String>,
    verifier_refs: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyBudgetRecord {
    autonomy_run_id: String,
    runtime_revision: u64,
    ledger: AutonomyBudgetLedger,
    usage_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyTripwireEnvelope {
    autonomy_run_id: String,
    runtime_revision: u64,
    work_item_id: WorkItemId,
    evidence_ref: String,
    tripwire: AutonomyTripwireRecord,
}

struct LoadedAutonomyRuntime {
    runtime: BoundedAutonomyRuntime,
    graph: AutonomyWorkGraphRecord,
    canonical: eliot_store::CanonicalAutonomyRunView,
    integrity_status: String,
}

// The daemon is the sole autonomy writer for one runtime instance. A process-wide
// async mutex deliberately serializes every autonomy contract/transition/action
// compare-and-commit section across named-pipe profiles. The guard is never acquired
// by WriterActor or re-entered from an action path, so awaiting the canonical write
// while holding it cannot form an ordering cycle.
static AUTONOMY_COMMIT_SERIALIZER: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

struct PreparedOperatorQuery {
    projection: OperatorProjectionKind,
    exact_evidence_target: Option<String>,
    records: Vec<OperatorRecordView>,
}

struct OperatorQueryPageData {
    records: Vec<OperatorRecordView>,
    next_cursor: Option<String>,
    total_matching: usize,
    total_is_exact: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OperatorCursorState {
    base_offset: u64,
    canonical_start: u64,
    matched_seen: u64,
}

fn dispatch_contour_route_preview(arguments: Value) -> Result<Value> {
    let input: ContourRoutePreviewToolInput = serde_json::from_value(arguments)?;
    let decision = ContourRoutingService::resolve(&ContourRouteRequest {
        project_id: parse_project_id(&input.project_id)?,
        task_id: TaskId::from_str(&input.task_id).context("parse contour task_id")?,
        work_item_id: WorkItemId::from_str(&input.work_item_id)
            .context("parse contour work_item_id")?,
        contour: input.contour,
        policies: &input.policies,
        live_routes: &input.live_routes,
        now: time::OffsetDateTime::now_utc(),
    })?;
    serde_json::to_value(decision).map_err(Into::into)
}

// Every variant is intentionally closed and allowlisted even where the current typed
// execution caller lives outside this MCP module. This prevents a generic raw kind tool.
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum CanonicalReceiptKind {
    StateTransition,
    MemoryTrajectoryCorrectness,
    MinorityPressureRecord,
    TraceCompletenessContract,
    ReplaySet,
    ReplayCase,
    ReplayInputSnapshot,
    SealedReplayRun,
    ReplayRun,
    ReplayAudit,
    HarnessExperiment,
    HarnessDisposition,
    MetaMetricEvidence,
    MetaIsolationRejection,
    ExperimentalPolicyCandidate,
    MetaPolicyPromotion,
    MetaPolicyRollback,
    SleepConsolidationBundle,
    SleepConsolidationRun,
    ProcedureCandidate,
    ProcedureSkillCandidate,
    ProcedurePromotionDisposition,
    ForgettingCandidate,
    TestCandidate,
    ReplayCaseCandidate,
    DreamCandidate,
    AutonomyRunContract,
    AutonomyRunTransition,
    AutonomyBudgetLedger,
    AutonomyWorkGraph,
    AutonomyTripwire,
    AutonomyRecovery,
    AutonomyApprovalRequest,
    AutonomyApprovalDecision,
    AutonomyApprovalConsumption,
    CandidateDiff,
    CandidateReview,
    AgentResult,
    AgentResultDisposition,
    WorktreeLease,
    WorkLease,
    ControllerLease,
    OperationJob,
    AgentInvocationRequest,
    ManagedFinalizationIntent,
    ManagedFinalizationAggregate,
    OperatorControlRequest,
    CognitiveRunContract,
    CognitiveRunAttempt,
    CognitiveToolObservation,
    CognitiveRawVerifier,
    CognitiveRunTerminal,
}

impl CanonicalReceiptKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::MemoryTrajectoryCorrectness => "memory_trajectory_correctness",
            Self::MinorityPressureRecord => "minority_pressure_record",
            Self::TraceCompletenessContract => "trace_completeness_contract",
            Self::ReplaySet => "replay_set",
            Self::ReplayCase => "replay_case",
            Self::ReplayInputSnapshot => "replay_input_snapshot",
            Self::SealedReplayRun => "sealed_replay_run",
            Self::ReplayRun => "replay_run",
            Self::ReplayAudit => "replay_audit",
            Self::HarnessExperiment => "harness_experiment",
            Self::HarnessDisposition => "harness_disposition",
            Self::MetaMetricEvidence => "meta_metric_evidence",
            Self::MetaIsolationRejection => "meta_isolation_rejection",
            Self::ExperimentalPolicyCandidate => "experimental_policy_candidate",
            Self::MetaPolicyPromotion => "meta_policy_promotion",
            Self::MetaPolicyRollback => "meta_policy_rollback",
            Self::SleepConsolidationBundle => "sleep_consolidation_bundle",
            Self::SleepConsolidationRun => "sleep_consolidation_run",
            Self::ProcedureCandidate => "procedure_candidate",
            Self::ProcedureSkillCandidate => "procedure_skill_candidate",
            Self::ProcedurePromotionDisposition => "procedure_promotion_disposition",
            Self::ForgettingCandidate => "forgetting_candidate",
            Self::TestCandidate => "test_candidate",
            Self::ReplayCaseCandidate => "replay_case_candidate",
            Self::DreamCandidate => "dream_candidate",
            Self::AutonomyRunContract => "autonomy_run_contract",
            Self::AutonomyRunTransition => "autonomy_run_transition",
            Self::AutonomyBudgetLedger => "autonomy_budget_ledger",
            Self::AutonomyWorkGraph => "autonomy_work_graph",
            Self::AutonomyTripwire => "autonomy_tripwire",
            Self::AutonomyRecovery => "autonomy_recovery",
            Self::AutonomyApprovalRequest => "autonomy_approval_request",
            Self::AutonomyApprovalDecision => "autonomy_approval_decision",
            Self::AutonomyApprovalConsumption => "autonomy_approval_consumption",
            Self::CandidateDiff => "candidate_diff",
            Self::CandidateReview => "candidate_review",
            Self::AgentResult => "agent_result",
            Self::AgentResultDisposition => "agent_result_disposition",
            Self::WorktreeLease => "worktree_lease",
            Self::WorkLease => "work_lease",
            Self::ControllerLease => "controller_lease",
            Self::OperationJob => "operation_job",
            Self::AgentInvocationRequest => "agent_invocation_request",
            Self::ManagedFinalizationIntent => "managed_finalization_intent",
            Self::ManagedFinalizationAggregate => "managed_finalization_aggregate",
            Self::OperatorControlRequest => "operator_control_request",
            Self::CognitiveRunContract => "cognitive_run_contract",
            Self::CognitiveRunAttempt => "cognitive_run_attempt",
            Self::CognitiveToolObservation => "cognitive_tool_observation",
            Self::CognitiveRawVerifier => "cognitive_raw_verifier",
            Self::CognitiveRunTerminal => "cognitive_run_terminal",
        }
    }
}

fn deterministic_canonical_write_id(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    _kind: CanonicalReceiptKind,
    idempotency_key: &str,
) -> WriteId {
    let digest = blake3::hash(
        format!(
            "canonical-mcp:{project_id}:{}:{idempotency_key}",
            task_id.map_or_else(|| "project".to_owned(), |task_id| task_id.to_string()),
        )
        .as_bytes(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

async fn write_canonical_observation<T: serde::Serialize>(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    kind: CanonicalReceiptKind,
    idempotency_key: &str,
    body: &T,
) -> Result<(WriteReceiptRef, WriteStatus)> {
    let envelope =
        canonical_observation_envelope(context, project_id, task_id, kind, idempotency_key, body)?;
    let receipt = state.writer.submit(envelope).await?;
    Ok((
        WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        },
        receipt.status,
    ))
}

fn canonical_observation_envelope<T: serde::Serialize>(
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    kind: CanonicalReceiptKind,
    idempotency_key: &str,
    body: &T,
) -> Result<MemoryWriteEnvelope> {
    if idempotency_key.trim().is_empty() {
        anyhow::bail!("canonical MCP idempotency key must not be empty");
    }
    let write_id = deterministic_canonical_write_id(project_id, task_id, kind, idempotency_key);
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(context.session_id.as_uuid()),
            session_id: Some(context.session_id),
            project_id,
            task_id,
            scope: "canonical product record".to_owned(),
            authority: "authenticated governor MCP typed action".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot-governor-mcp".to_owned(),
        observation: format!("canonical {} record", kind.as_str()),
        payload: json!({
            "receipt_kind": kind.as_str(),
            "receipt_body": body,
            "writer_path": "mcp_stdio::write_canonical_observation"
        }),
    });
    WriteAdmissionService.admit(&command).map_err(Into::into)
}

#[derive(Clone, Debug, serde::Serialize)]
struct CanonicalAutonomyVerifierEvidence {
    verification_id: VerificationId,
    canonical_ref: String,
    registered_name: String,
    profile_ref: String,
    command: String,
    version: String,
    artifact_scope_hash: String,
    artifact_refs: Vec<String>,
    acceptance_item_ids: Vec<String>,
    commit_ref: String,
    verifier_ref: String,
}

fn require_two_real_host_chains(
    contract: &AutonomyRunContract,
    chains: &[AutonomyHostResultChain],
) -> Result<()> {
    if !autonomy_contract_requires_two_hosts(contract) {
        return Ok(());
    }
    let distinct_results = chains
        .iter()
        .map(|chain| chain.result_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_hosts = chains
        .iter()
        .map(|chain| chain.host_id)
        .collect::<std::collections::BTreeSet<_>>();
    if distinct_results.len() < 2
        || !distinct_hosts.contains(&AgentHostId::OpenCode)
        || !distinct_hosts.contains(&AgentHostId::Antigravity)
    {
        anyhow::bail!(
            "two-host autonomy completion requires distinct real OpenCode and Antigravity result chains"
        );
    }
    Ok(())
}

fn approval_request_write_id(approval_id: &str) -> Result<WriteId> {
    let raw = approval_id
        .strip_prefix("autonomy-approval:")
        .context("approval_id is not a canonical autonomy approval id")?;
    WriteId::from_str(raw).context("approval_id does not contain a valid canonical write id")
}

fn approval_decision_write_id(
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &str,
) -> WriteId {
    deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyApprovalDecision,
        &format!("approval-decision:{approval_id}"),
    )
}

fn approval_consumption_write_id(
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &str,
) -> WriteId {
    deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyApprovalConsumption,
        &format!("approval-consumption:{approval_id}"),
    )
}

async fn canonical_approval_was_consumed(
    state: &McpState,
    loaded: &LoadedAutonomyRuntime,
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &str,
) -> Result<bool> {
    let write_id = approval_consumption_write_id(project_id, task_id, approval_id);
    let exact_record_exists = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalConsumptionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalConsumption.as_str()],
            write_id,
        )
        .await?
        .is_some();
    let aggregate_contains_consumption = loaded.canonical.work_graphs.iter().any(|record| {
        serde_json::from_value::<AutonomyWorkGraphRecord>(record.receipt_body.clone()).is_ok_and(
            |graph| {
                graph
                    .approval_consumption
                    .as_ref()
                    .is_some_and(|consumption| consumption.approval_id == approval_id)
            },
        )
    });
    Ok(exact_record_exists || aggregate_contains_consumption)
}

async fn resolve_canonical_r3_approval(
    state: &McpState,
    context: AuthenticatedRequestContext,
    resolution: CanonicalR3ApprovalResolution<'_>,
) -> Result<(
    CanonicalR3ApprovalAuthorization,
    AutonomyApprovalConsumptionRecord,
)> {
    let CanonicalR3ApprovalResolution {
        loaded,
        project_id,
        task_id,
        approval_id,
        exact_action_hash,
        aggregate_write_id,
    } = resolution;
    let request_write_id = approval_request_write_id(approval_id)?;
    let consumption_write_id = approval_consumption_write_id(project_id, task_id, approval_id);
    if canonical_approval_was_consumed(state, loaded, project_id, task_id, approval_id).await? {
        anyhow::bail!("R3 approval was already consumed");
    }
    let request_record = exact_autonomy_approval_request(
        state,
        project_id,
        task_id,
        &loaded.runtime.contract.autonomy_run_id,
        approval_id,
    )
    .await?
    .context("R3 approval request is missing")?;
    let request = &request_record.receipt_body;
    if request.project_id != project_id
        || request.task_id != task_id
        || request.autonomy_run_id != loaded.runtime.contract.autonomy_run_id
        || request.expected_state_revision != loaded.runtime.contract.state_revision
        || request.expected_runtime_revision != loaded.runtime.runtime_revision
        || request.requested_by_session_id != context.session_id
        || request.exact_action_hash != exact_action_hash
        || request.approval_revision != 0
        || request.expires_at <= time::OffsetDateTime::now_utc()
    {
        anyhow::bail!("R3 approval is stale, principal-mismatched, or action-mismatched");
    }
    let decision_write_id = approval_decision_write_id(project_id, task_id, approval_id);
    let decision = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalDecisionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalDecision.as_str()],
            decision_write_id,
        )
        .await?
        .context("R3 approval has no canonical HumanOperator decision")?;
    if decision.receipt_body.decision != AutonomyApprovalDecisionKind::Granted
        || decision.receipt_body.approval_revision != 1
        || decision.receipt_body.exact_action_hash != request.exact_action_hash
        || decision.receipt_body.project_id != project_id
        || decision.receipt_body.task_id != task_id
        || decision.receipt_body.expires_at != request.expires_at
        || decision.receipt_body.approval_id != approval_id
        || decision.receipt_body.request_write_id != request_write_id
        || decision.receipt_body.decision_write_id != decision_write_id
        || decision.canonical_receipt.write_id != decision_write_id
        || decision.receipt_body.expires_at <= time::OffsetDateTime::now_utc()
    {
        anyhow::bail!("R3 approval was denied, expired, or does not bind the exact request");
    }
    let authorization = CanonicalR3ApprovalAuthorization {
        approval_id: approval_id.to_owned(),
        exact_action_hash: exact_action_hash.to_owned(),
        decision_receipt: decision.canonical_receipt.clone(),
        approved_by: decision.receipt_body.decided_by_session_id,
        expires_at: decision.receipt_body.expires_at,
    };
    let consumption = AutonomyApprovalConsumptionRecord {
        approval_id: approval_id.to_owned(),
        decision_write_id,
        consumption_write_id,
        autonomy_run_id: loaded.runtime.contract.autonomy_run_id.clone(),
        project_id,
        task_id,
        exact_action_hash: exact_action_hash.to_owned(),
        approval_revision: decision.receipt_body.approval_revision.saturating_add(1),
        consumed_by_session_id: context.session_id,
        aggregate_write_id: aggregate_write_id.to_string(),
        consumed_at: time::OffsetDateTime::now_utc(),
    };
    Ok((authorization, consumption))
}

#[derive(Debug, Eq, PartialEq, serde::Serialize)]
struct OperatorLifecycleBinding {
    evidence_refs: Vec<String>,
    precondition_refs: Vec<String>,
    approval_ref: Option<String>,
}

impl OperatorLifecycleBinding {
    fn unbound(evidence_refs: Vec<String>) -> Self {
        Self {
            evidence_refs,
            precondition_refs: Vec::new(),
            approval_ref: None,
        }
    }
}

struct OperatorControlRequestDraft<'a> {
    project_id: ProjectId,
    task_id: TaskId,
    operation: &'a str,
    target_ref: &'a str,
    disposition: &'a str,
    exact_action_hash: Option<String>,
    reason_or_evidence_refs: Vec<String>,
    idempotency_key: &'a str,
}

struct OperatorAutonomyApprovalDecision<'a> {
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &'a str,
    exact_action_hash: &'a str,
    decision: AutonomyApprovalDecisionKind,
    reason: &'a str,
    idempotency_key: &'a str,
}

struct CandidateDispositionActor {
    role_lease_id: String,
    controller_lease_id: Option<String>,
}

struct CandidatePromotion<'a> {
    task: &'a TaskContract,
    candidate: &'a CanonicalClaimCard,
    evidence_refs: &'a [String],
    source_provenance_refs: Vec<String>,
    idempotency_key: &'a str,
    actor: &'a CandidateDispositionActor,
}

async fn resolve_exact_procedure_pattern(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    pattern_ref: &str,
) -> Result<(ExperiencePattern, String, String, WriteReceiptRef)> {
    let pattern_id = pattern_ref
        .strip_prefix("experience-pattern:")
        .filter(|value| !value.trim().is_empty())
        .context("pattern_ref must be experience-pattern:<exact-pattern-id>")?;
    let observations = state
        .store
        .experience_pattern_revisions_by_id(project_id, task_id, pattern_id)
        .await?;
    // ExperiencePattern history is immutable: maturity transitions append a
    // new physical observation for the same logical pattern. This exact,
    // bounded store query orders matching revisions newest-first.
    let observation = observations
        .into_iter()
        .max_by_key(|observation| (observation.memory_revision, observation.project_sequence))
        .context("pattern_ref does not resolve to a canonical ExperiencePattern")?;
    let pattern = serde_json::from_value::<ExperiencePattern>(
        observation
            .payload
            .get("receipt_body")
            .cloned()
            .context("canonical ExperiencePattern observation has no receipt_body")?,
    )
    .context("parse canonical ExperiencePattern observation")?;
    if pattern.pattern_id != pattern_id {
        anyhow::bail!("canonical ExperiencePattern id differs from pattern_ref");
    }
    if pattern.project_id != project_id
        || observation.project_id != project_id
        || observation.task_id != Some(task_id)
    {
        anyhow::bail!("ExperiencePattern project differs from requested project");
    }
    let write_id = observation.write_id;
    let receipt = state
        .store
        .write_receipt_by_id(&write_id)
        .await?
        .context("canonical ExperiencePattern observation has no WriterActor receipt")?;
    if receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || receipt.command_kind != eliot_types::SemanticCommandKind::ToolObservationRecord
        || receipt.memory_revision != Some(observation.memory_revision)
        || receipt.project_sequence != Some(observation.project_sequence)
        || !receipt
            .created_records
            .contains(&observation.observation_id)
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
    {
        anyhow::bail!("canonical ExperiencePattern receipt scope or status differs");
    }
    Ok((
        pattern.clone(),
        sha256_json(&pattern)?,
        observation.observation_id,
        WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        },
    ))
}

fn task_evidence_refs(task: &TaskContract) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    for observation_id in &task.observation_ids {
        refs.insert(observation_id.clone());
        refs.insert(format!("observation:{observation_id}"));
    }
    for verification_id in &task.verification_ids {
        refs.insert(verification_id.to_string());
        refs.insert(format!("verification:{verification_id}"));
    }
    for scope in &task.verification_scopes {
        refs.insert(scope.verification_id.to_string());
        refs.insert(format!("verification:{}", scope.verification_id));
        refs.insert(scope.verifier_id.clone());
        refs.insert(format!("verifier:{}", scope.verifier_id));
        refs.insert(scope.worktree_ref.clone());
        refs.insert(scope.path_or_resource_scope.clone());
        for artifact in &scope.artifact_refs {
            refs.insert(artifact.resource_ref.clone());
        }
    }
    refs.retain(|value| !value.trim().is_empty());
    refs
}

async fn validated_negative_transfer_refs(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    requested: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let records = semantic_records::<eliot_types::NegativeTransferRecord>(
        state,
        project_id,
        "negative_transfer_record",
    )
    .await?;
    let task_refs = [task_id.to_string(), format!("task:{task_id}")];
    let mut validated = Vec::new();
    let mut unresolved = Vec::new();
    for reference in requested {
        let record_id = reference
            .strip_prefix("negative-transfer:")
            .unwrap_or(reference);
        if records
            .iter()
            .any(|record| record.record_id == record_id && task_refs.contains(&record.task_ref))
        {
            validated.push(reference.clone());
        } else {
            unresolved.push(reference.clone());
        }
    }
    Ok((validated, unresolved))
}

async fn validate_procedure_disposition_evidence(
    state: &McpState,
    task: &TaskContract,
    input: &ProcedureCandidateDispositionToolInput,
) -> Result<(Vec<String>, Vec<String>)> {
    let task_artifacts = task_verifier_artifacts(task);
    if input
        .holdout_evidence
        .iter()
        .any(|requested| !task_artifacts.iter().any(|artifact| artifact == requested))
    {
        anyhow::bail!(
            "every holdout_evidence item must resolve to an exact canonical current-task verifier artifact"
        );
    }
    let holdout_refs = input
        .holdout_evidence
        .iter()
        .map(|artifact| artifact.resource_ref.clone())
        .collect::<Vec<_>>();
    let (negative_refs, unresolved) = validated_negative_transfer_refs(
        state,
        task.project_id,
        task.task_id,
        &input.negative_transfer_refs,
    )
    .await?;
    if !unresolved.is_empty() {
        anyhow::bail!(
            "every negative_transfer_ref must resolve to an exact canonical current-task negative-transfer record"
        );
    }
    Ok((holdout_refs, negative_refs))
}

fn procedure_disposition_fingerprint(
    input: &ProcedureCandidateDispositionToolInput,
    task: &TaskContract,
    pattern_sha256: &str,
    pattern_observation_ref: &str,
    pattern_receipt: &WriteReceiptRef,
    candidate: &CanonicalRecord<CanonicalProcedureSkillCandidate>,
) -> Result<String> {
    sha256_json(&json!({
        "project_id": task.project_id,
        "task_id": task.task_id,
        "task_revision": input.expected_revision,
        "pattern_ref": input.pattern_ref,
        "pattern_observation_ref": pattern_observation_ref,
        "pattern_receipt": pattern_receipt,
        "pattern_sha256": pattern_sha256,
        "candidate_ref": input.candidate_ref,
        "candidate_receipt": candidate.canonical_receipt,
        "candidate_sha256": candidate.receipt_body.candidate_sha256,
        "holdout_evidence": input.holdout_evidence,
        "negative_transfer_refs": input.negative_transfer_refs,
    }))
}

fn evaluate_procedure_disposition(
    pattern: &ExperiencePattern,
    candidate: &SkillCardV2,
    holdout_refs: &[String],
    negative_refs: &[String],
    has_generic_holdout: bool,
) -> Result<(
    SkillLifecycleRecord,
    ProcedurePromotionOutcome,
    String,
    Vec<String>,
)> {
    let mut lifecycle = SkillLifecycleService::procedure_promotion_disposition(
        pattern,
        candidate,
        holdout_refs,
        negative_refs,
    );
    lifecycle.write_receipt = None;
    let engine_outcome = lifecycle
        .promotion_outcome
        .context("procedure promotion engine returned no disposition")?;
    let mut reasons = vec![if has_generic_holdout {
        "generic_task_verifier_artifact_is_not_procedure_holdout_authority".to_owned()
    } else {
        "missing_independent_procedure_holdout".to_owned()
    }];
    let outcome = if engine_outcome == ProcedurePromotionOutcome::Promoted {
        lifecycle.state = SkillLifecycleState::Candidate;
        lifecycle.promotion_outcome = Some(ProcedurePromotionOutcome::NotReadyForProcedure);
        reasons.push("procedure_holdout_semantic_kind_is_unavailable_in_v1".to_owned());
        ProcedurePromotionOutcome::NotReadyForProcedure
    } else {
        engine_outcome
    };
    let pattern_disposition = if outcome == ProcedurePromotionOutcome::Demoted {
        "candidate_quarantined_pattern_retained"
    } else {
        "kept_transfer_validated"
    };
    Ok((lifecycle, outcome, pattern_disposition.to_owned(), reasons))
}

fn procedure_disposition_response(
    record: &CanonicalProcedurePromotionDisposition,
    canonical_receipt: &WriteReceiptRef,
    write_status: Option<WriteStatus>,
    idempotent_replay: bool,
) -> Value {
    json!({
        "component": "procedure_promotion_disposition",
        "disposition": record,
        "canonical_receipt": canonical_receipt,
        "write_status": write_status,
        "idempotent_replay": idempotent_replay,
    })
}

async fn persist_procedure_disposition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    idempotency_key: &str,
    record: CanonicalProcedurePromotionDisposition,
) -> Result<Value> {
    let (receipt, status) = write_canonical_observation(
        state,
        context,
        record.project_id,
        Some(record.task_id),
        CanonicalReceiptKind::ProcedurePromotionDisposition,
        idempotency_key,
        &record,
    )
    .await?;
    Ok(procedure_disposition_response(
        &record,
        &receipt,
        Some(status),
        matches!(status, WriteStatus::IdempotentReplay),
    ))
}

async fn resolve_governed_packet_git_scope(
    input: &CompilePacketL3Request,
    task: Option<&TaskContract>,
    codecortex_reports: &[CodeCortexReport],
) -> Result<Option<eliot_types::memory::GovernedGitScope>> {
    let Some(provenance) = task
        .and_then(|task| task.action_provenance.as_ref())
        .filter(|provenance| provenance.source_scope.kind == "git_worktree")
    else {
        return Ok(None);
    };
    let report = codecortex_reports
        .iter()
        .rev()
        .find(|report| report.task == input.task_id)
        .context("governed Git-scoped packet requires a task-matched CodeCortex report")?;
    let expected_worktree = provenance
        .source_scope
        .worktree_ref
        .as_deref()
        .context("governed Git-scoped task has no worktree identity")?;
    let report_root = tokio::fs::canonicalize(&report.repo_root).await?;
    let expected_root = tokio::fs::canonicalize(expected_worktree).await?;
    if report_root != expected_root {
        anyhow::bail!("CodeCortex report worktree differs from canonical action provenance");
    }
    let scope = resolve_packet_git_scope(&report_root, input.project_id).await?;
    if report.git_head.as_deref() != Some(scope.commit.as_str()) || report.dirty == scope.clean {
        anyhow::bail!("task-matched CodeCortex report is stale for the resolved Git scope");
    }
    Ok(Some(scope))
}

async fn enrich_packet_with_task(
    state: &McpState,
    value: &mut Value,
    task: &TaskContract,
) -> Result<()> {
    let Value::Object(object) = value else {
        return Ok(());
    };
    let refs = canonical_packet_refs(state, task).await?;
    let current_receipt = state
        .store
        .write_receipt_by_id(&task.write_id)
        .await?
        .context("current TaskContract WriteReceipt does not resolve")?;
    object.insert("task_contract".to_owned(), serde_json::to_value(task)?);
    object.insert(
        "task_truth_status".to_owned(),
        Value::String("current_canonical".to_owned()),
    );
    object.insert(
        "task_revision_fence".to_owned(),
        serde_json::to_value(task.memory_revision)?,
    );
    object.insert(
        "packet_revision_fence".to_owned(),
        serde_json::to_value(refs.packet_revision_fence)?,
    );
    object.insert("packet_id".to_owned(), Value::String(refs.packet_id));
    object.insert(
        "task_contract_ref".to_owned(),
        Value::String(refs.task_contract_ref.clone()),
    );
    object.insert(
        "current_truth_refs".to_owned(),
        json!([refs.task_contract_ref]),
    );
    object.insert(
        "exact_evidence_refs".to_owned(),
        json!([current_receipt.receipt_id]),
    );
    object.insert(
        "negative_memory_check_ref".to_owned(),
        Value::String(refs.negative_memory_check_ref),
    );
    object.insert(
        "negative_stale_exclusions".to_owned(),
        json!(["candidate observations are not verifier authority"]),
    );
    object.insert(
        "registered_verifiers".to_owned(),
        Value::Array(
            RegisteredTaskVerifier::ALL
                .into_iter()
                .map(RegisteredTaskVerifier::descriptor)
                .collect(),
        ),
    );
    Ok(())
}

async fn dispatch_understanding_proof(state: &McpState, arguments: Value) -> Result<Value> {
    let proof: UnderstandingProof = serde_json::from_value(arguments)?;
    let codecortex_reports = latest_codecortex_report(&state.root)?
        .into_iter()
        .collect::<Vec<_>>();
    let receipt = UnderstandingProofValidator::new(ReadService::new(state.store.clone()))
        .validate_with_codecortex(&proof, &codecortex_reports)
        .await?;
    serde_json::to_value(receipt).map_err(Into::into)
}

async fn dispatch_codecortex_scan(state: &McpState, arguments: Value) -> Result<Value> {
    let input: CodeCortexScanToolInput = serde_json::from_value(arguments)?;
    let request = CodeCortexRequest {
        project: input.project,
        task: input.task,
        goal: input.goal,
        exact_patterns: input.exact_patterns.unwrap_or_default(),
        max_files: input.max_files.unwrap_or(160),
        max_matches_per_pattern: input.max_matches_per_pattern.unwrap_or(24),
        include_diagnostics: input.include_diagnostics.unwrap_or(true),
    };
    let mut report = CodeCortexService::new(std::env::current_dir()?).scan(&request)?;
    write_codecortex_report_to_memory(state, &mut report).await?;
    write_json_report(&codecortex_latest_path(&state.root), &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_codecortex_latest(state: &McpState) -> Result<Value> {
    let report = latest_codecortex_report(&state.root)?
        .context("no latest CodeCortex report found; call eliot_codecortex_scan first")?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_external_review_providers(state: &McpState) -> Result<Value> {
    let report = ExternalProviderRegistryService.report();
    write_external_review_mcp_report(state, "external-providers", "External Providers", &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

async fn dispatch_external_review_request(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewRequestToolInput = serde_json::from_value(arguments)?;
    let provider = ExternalProviderRegistryService.inspect(&input.provider)?;
    let mut request = external_review_request(
        &input.project,
        &input.task,
        &input.provider,
        parse_external_review_role(input.role.as_deref().unwrap_or("auditor"))?,
        &input.question,
    );
    request.project_id = project_id_from_label(&input.project);
    request.task_id = task_id_from_label(&input.task);
    request.output_schema = external_output_schema_for(&request, &provider);
    request.budget = ExternalReviewBudget {
        max_packet_bytes: provider.limits.max_packet_bytes,
        max_output_bytes: provider.limits.max_raw_output_bytes,
        max_findings: provider.limits.max_findings,
    };
    let (mut work_state, work_lease) = ensure_external_review_work_lease(state, &mut request)?;
    let packet = ExternalReviewPacketBuilder.build(
        &request,
        "context_packet_l3:mcp-external-review",
        json!({
            "project": input.project,
            "task": input.task,
            "question": input.question,
            "allowed_paths": &request.allowed_paths,
            "evidence_refs": &request.evidence_refs,
            "credential": "redacted"
        }),
    )?;
    let gate = ExternalReviewGate.decide(
        &request,
        &provider,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: IncidentService::new(&state.root).lockdown_active()?,
        },
    );
    let job = ExternalReviewJobService.create_job(&request);
    let work_report = WorkQueueService.status_report(&work_state, &request.project, &request.task);
    save_work_state_and_report(&state.root, &work_state, &work_report)?;
    write_work_entities(
        state,
        &mut work_state,
        work_lease.as_ref().map(|lease| lease.agent_session_id),
        work_lease.as_ref().map(|lease| lease.work_item_id),
        work_lease.as_ref().map(|lease| lease.work_lease_id),
        &[],
    )
    .await?;
    write_external_review_mcp_report(
        state,
        "external-review-requests",
        "External Review Request",
        &request,
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-packets",
        "External Review Packet",
        &packet,
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-gates",
        "External Review Gates",
        &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    serde_json::to_value(json!({
        "component": "external_review_request",
        "request": request,
        "packet": packet,
        "gate": gate,
        "job": job
    }))
    .map_err(Into::into)
}

fn dispatch_external_review_job_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewJobStatusToolInput = serde_json::from_value(arguments)?;
    let report = latest_json_report(&external_review_latest_path(
        &state.root,
        "external-review-jobs",
    ))?
    .context("no external review jobs report found")?;
    Ok(filter_report_item(&report, "jobs", "job_id", &input.job))
}

fn dispatch_external_review_result(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewResultToolInput = serde_json::from_value(arguments)?;
    let report = latest_json_report(&external_review_latest_path(
        &state.root,
        "external-review-results",
    ))?
    .context("no external review results report found")?;
    Ok(filter_report_item(
        &report,
        "results",
        "result_id",
        &input.result,
    ))
}

fn dispatch_external_review_report(state: &McpState) -> Result<Value> {
    let report = json!({
        "component": "external_review_report",
        "providers": external_review_report_status(&state.root, "external-providers"),
        "jobs": external_review_report_status(&state.root, "external-review-jobs"),
        "results": external_review_report_status(&state.root, "external-review-results"),
        "gates": external_review_report_status(&state.root, "external-review-gates"),
        "normalization": external_review_report_status(&state.root, "external-review-normalization"),
        "doctor": ExternalReviewReportService.doctor_status(external_review_tools_governed_only()),
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_external_review_mcp_report(state, "external-review", "External Review", &report)?;
    Ok(report)
}

fn dispatch_antigravity_status(state: &McpState) -> Result<Value> {
    let (resolution, probe, contract) = mcp_antigravity_resolution_probe_contract();
    let skills = AntigravitySkillBundleService.generate(&mcp_antigravity_plugin_root(state), true);
    let plugin = AntigravityPluginBundleService.generate(&mcp_antigravity_plugin_root(state));
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        skills.verification_passed,
        plugin.verification_passed,
        mcp_antigravity_tools_governed_only(),
    );
    write_antigravity_mcp_report(
        state,
        "antigravity-detection",
        "Antigravity Detection",
        &probe,
    )?;
    write_antigravity_mcp_report(state, "antigravity-doctor", "Antigravity Doctor", &doctor)?;
    serde_json::to_value(doctor).map_err(Into::into)
}

fn dispatch_antigravity_doctor(state: &McpState) -> Result<Value> {
    dispatch_antigravity_status(state)
}

fn dispatch_antigravity_request(arguments: Value) -> Result<Value> {
    let input: AntigravityRequestToolInput = serde_json::from_value(arguments)?;
    let request = antigravity_review_request(
        &input.project,
        &input.task,
        parse_antigravity_mode(input.mode.as_deref().unwrap_or("audit-plan"))?,
        &input.question,
    );
    serde_json::to_value(request).map_err(Into::into)
}

fn dispatch_antigravity_job_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: AntigravityRunRefToolInput = serde_json::from_value(arguments)?;
    let run = latest_antigravity_mcp_run(state)?;
    if let Some(run) = run {
        if input
            .run
            .as_deref()
            .is_some_and(|run_id| run_id != run.run_id)
        {
            return Ok(json!({ "status": "not_found", "run": input.run }));
        }
        Ok(json!({
            "component": "antigravity_job_status",
            "run_id": run.run_id,
            "state": run.state,
            "dry_run": run.dry_run,
            "fixture_runner": run.fixture_runner,
            "message": run.message
        }))
    } else {
        Ok(json!({ "component": "antigravity_job_status", "status": "not_found" }))
    }
}

fn dispatch_antigravity_result(state: &McpState, arguments: Value) -> Result<Value> {
    let input: AntigravityRunRefToolInput = serde_json::from_value(arguments)?;
    let run = latest_antigravity_mcp_run(state)?;
    if let Some(run) = run {
        if input
            .run
            .as_deref()
            .is_some_and(|run_id| run_id != run.run_id)
        {
            return Ok(json!({ "status": "not_found", "run": input.run }));
        }
        serde_json::to_value(run.normalized_result).map_err(Into::into)
    } else {
        Ok(json!({ "component": "antigravity_result", "status": "not_found" }))
    }
}

fn dispatch_antigravity_report(state: &McpState) -> Result<Value> {
    let (resolution, probe, contract) = mcp_antigravity_resolution_probe_contract();
    let latest_run = latest_antigravity_mcp_run(state)?;
    let runs = latest_run.iter().cloned().collect::<Vec<_>>();
    let telemetry = AntigravityTelemetryService.report(&probe, &runs);
    let skills = AntigravitySkillBundleService.generate(&mcp_antigravity_plugin_root(state), true);
    let plugin = AntigravityPluginBundleService.generate(&mcp_antigravity_plugin_root(state));
    let doctor = AntigravityDoctorIntegration.status(
        &resolution,
        &probe,
        &contract,
        skills.verification_passed,
        plugin.verification_passed,
        mcp_antigravity_tools_governed_only(),
    );
    let report = antigravity_report(
        resolution, probe, contract, None, latest_run, doctor, telemetry,
    );
    write_antigravity_mcp_report(state, "antigravity-report", "Antigravity Report", &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

fn dispatch_antigravity_skills(state: &McpState) -> Result<Value> {
    let bundle = AntigravitySkillBundleService.generate(&mcp_antigravity_plugin_root(state), true);
    write_antigravity_mcp_report(state, "antigravity-skills", "Antigravity Skills", &bundle)?;
    serde_json::to_value(bundle).map_err(Into::into)
}

fn dispatch_antigravity_plugin(state: &McpState) -> Result<Value> {
    let bundle = AntigravityPluginBundleService.generate(&mcp_antigravity_plugin_root(state));
    write_antigravity_mcp_report(state, "antigravity-plugin", "Antigravity Plugin", &bundle)?;
    serde_json::to_value(bundle).map_err(Into::into)
}

fn dispatch_antigravity_auth_status(state: &McpState) -> Result<Value> {
    let (_resolution, probe, _contract) = mcp_antigravity_resolution_probe_contract();
    let auth = AntigravityAuthCheckService.help_only(
        &probe,
        vec!["reports/antigravity-detection/latest.json".to_owned()],
    );
    write_antigravity_mcp_report(state, "antigravity-auth", "Antigravity Auth", &auth)?;
    serde_json::to_value(auth).map_err(Into::into)
}

fn dispatch_antigravity_enablement_status(state: &McpState) -> Result<Value> {
    if let Some(value) = latest_json_report(&antigravity_latest_path(
        &state.root,
        "antigravity-enablement",
    ))? {
        Ok(value)
    } else {
        let (_resolution, probe, _contract) = mcp_antigravity_resolution_probe_contract();
        let auth = AntigravityAuthCheckService.help_only(
            &probe,
            vec!["reports/antigravity-detection/latest.json".to_owned()],
        );
        let state_value = AntigravityEnablementService.state_from_probe(&probe, Some(&auth));
        Ok(json!({
            "component": "antigravity_enablement_status",
            "status": "not_enabled",
            "state": state_value,
            "authority": "status-only; MCP cannot enable real Antigravity"
        }))
    }
}

fn dispatch_antigravity_visibility(state: &McpState) -> Result<Value> {
    let mut visibility = latest_json_report(&antigravity_latest_path(
        &state.root,
        "antigravity-visibility",
    ))?
    .unwrap_or_else(|| {
        json!({
            "component": "antigravity_visibility",
            "status": "not_reported",
            "authority": "status-only; MCP cannot install, configure, enable, or invoke Antigravity"
        })
    });
    if let Some(object) = visibility.as_object_mut() {
        object.insert(
            "current_role_authority".to_owned(),
            Value::String(
                "not_a_role_source; use eliot_host_session_status for the authenticated caller"
                    .to_owned(),
            ),
        );
    }
    Ok(visibility)
}

fn dispatch_antigravity_mcp_status(state: &McpState) -> Result<Value> {
    let home = antigravity_user_home()?;
    let previous_invocation = latest_antigravity_mcp_typed::<AntigravityMcpInvocationReceipt>(
        state,
        "antigravity-mcp-invocations",
    )?;
    Ok(antigravity_mcp_live_status(
        &home,
        previous_invocation.as_ref(),
    ))
}

fn dispatch_antigravity_plugin_status(state: &McpState) -> Result<Value> {
    let _ = state;
    Ok(antigravity_plugin_live_status(&antigravity_user_home()?))
}

fn antigravity_user_home() -> Result<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .context("USERPROFILE/HOME is unavailable for Antigravity config discovery")
}

fn antigravity_mcp_live_status(
    home: &Path,
    previous_invocation: Option<&AntigravityMcpInvocationReceipt>,
) -> Value {
    let configs = AntigravityMcpConfigService.status(home);
    let registered = configs.iter().any(|status| status.registered);
    let invocation_succeeded = previous_invocation
        .is_some_and(|receipt| receipt.succeeded && receipt.matching_audit_event);
    json!({
        "component": "antigravity_mcp_status",
        "registered": registered,
        "invocation_succeeded": invocation_succeeded,
        "configs": configs,
        "source": "live-user-config",
        "authority": "status-only; MCP cannot mutate Antigravity configuration"
    })
}

fn antigravity_plugin_live_status(home: &Path) -> Value {
    let status = AntigravityOfficialPluginService.status(home);
    let installed = status.gui_installed || status.cli_installed;
    let Value::Object(mut fields) = json!(status) else {
        return json!({
            "component": "antigravity_plugin_status",
            "installed": false,
            "source": "live-user-config",
            "authority": "status-only; MCP cannot install plugins",
            "error": "Antigravity plugin status serialization did not produce an object"
        });
    };
    fields.insert("component".to_owned(), json!("antigravity_plugin_status"));
    fields.insert("installed".to_owned(), json!(installed));
    fields.insert("source".to_owned(), json!("live-user-config"));
    fields.insert(
        "authority".to_owned(),
        json!("status-only; MCP cannot install plugins"),
    );
    Value::Object(fields)
}

fn dispatch_antigravity_live_smoke_status(state: &McpState) -> Result<Value> {
    latest_json_report(&antigravity_latest_path(
        &state.root,
        "antigravity-live-smoke",
    ))?
    .map_or_else(
        || {
            Ok(json!({
                "component": "antigravity_live_smoke_status",
                "status": "not_attempted",
                "authority": "status-only; MCP cannot run real Antigravity"
            }))
        },
        Ok,
    )
}

fn dispatch_antigravity_real_report(state: &McpState) -> Result<Value> {
    let (resolution, probe, contract) = mcp_antigravity_resolution_probe_contract();
    let auth = latest_antigravity_mcp_typed::<AntigravityAuthCheck>(state, "antigravity-auth")?
        .unwrap_or_else(|| {
            AntigravityAuthCheckService.help_only(
                &probe,
                vec!["reports/antigravity-detection/latest.json".to_owned()],
            )
        });
    let enablement = latest_antigravity_mcp_typed::<AntigravityEnablementReceipt>(
        state,
        "antigravity-enablement",
    )?;
    let live_smoke = latest_antigravity_mcp_typed::<AntigravityLiveSmokeResult>(
        state,
        "antigravity-live-smoke",
    )?;
    let disable =
        latest_antigravity_mcp_typed::<AntigravityDisableReceipt>(state, "antigravity-disable")?;
    let latest_run = latest_antigravity_mcp_run(state)?;
    let runs = latest_run.iter().cloned().collect::<Vec<_>>();
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
    write_antigravity_mcp_report(state, "antigravity-real", "Antigravity Real", &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
async fn dispatch_external_review_run_mock(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExternalReviewRunMockToolInput = serde_json::from_value(arguments)?;
    let request: ExternalReviewRequest = read_json_file(&external_review_latest_path(
        &state.root,
        "external-review-requests",
    ))?;
    if request.request_id != input.request {
        return Ok(json!({
            "status": "not_found",
            "request": input.request
        }));
    }
    let provider = ExternalProviderRegistryService.inspect(&request.provider_id)?;
    let packet: ExternalReviewPacket = read_json_file(&external_review_latest_path(
        &state.root,
        "external-review-packets",
    ))?;
    let mut work_state = load_work_state(&state.root)?;
    let work_lease = request.work_lease_id.and_then(|lease_id| {
        work_state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    let gate = ExternalReviewGate.decide(
        &request,
        &provider,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: true,
            incident_lockdown: IncidentService::new(&state.root).lockdown_active()?,
        },
    );
    if gate.decision != ExternalReviewGateDecisionKind::AllowMockRun {
        write_external_review_mcp_report(
            state,
            "external-review-gates",
            "External Review Gates",
            &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
        )?;
        return Ok(json!({ "status": "blocked", "gate": gate }));
    }
    let blob_store = BlobStore::open(&state.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let (mut job, raw_output) = ExternalReviewJobService
        .run_mock(&request, &provider, &packet, &supervisor, &blob_store)
        .await?;
    let normalization = ExternalReviewNormalizer.normalize(&request, &job, &raw_output);
    let mut results = Vec::new();
    if let Some(mut result) = normalization.result.clone() {
        job.result_id = Some(result.result_id.clone());
        let writer = state.writer.clone();
        let bridge = ExternalReviewBridgeService
            .write_and_route(
                &writer,
                &WriteAdmissionService,
                &mut work_state,
                AgentSessionId::new_v7(),
                &mut result,
            )
            .await?;
        write_external_review_mcp_report(
            state,
            "external-review-bridge",
            "External Review Bridge",
            &bridge,
        )?;
        results.push(result);
    }
    let work_report = WorkQueueService.status_report(&work_state, &request.project, &request.task);
    save_work_state_and_report(&state.root, &work_state, &work_report)?;
    write_external_review_mcp_report(
        state,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-results",
        "External Review Results",
        &ExternalReviewReportService.results_report(&results),
    )?;
    write_external_review_mcp_report(
        state,
        "external-review-normalization",
        "External Review Normalization",
        &ExternalReviewReportService
            .normalization_report(std::slice::from_ref(&normalization.receipt)),
    )?;
    serde_json::to_value(json!({
        "component": "external_review_run_mock",
        "job": job,
        "normalization": normalization.receipt,
        "results": results
    }))
    .map_err(Into::into)
}

fn l11_idempotency_key(base: &str, suffix: &str) -> Result<String> {
    let base = base.trim();
    if base.is_empty() {
        anyhow::bail!("L11 idempotency_key must not be empty");
    }
    Ok(format!("l11:{base}:{suffix}"))
}

fn l11_fingerprint_marker(fingerprint: &str) -> String {
    format!("mcp_input_fingerprint={fingerprint}")
}

fn trace_ref_value<'a>(value: &'a str, category: &str) -> Result<&'a str> {
    let value = value.trim();
    let reference = value
        .strip_prefix(category)
        .and_then(|suffix| {
            suffix
                .strip_prefix(':')
                .or_else(|| suffix.strip_prefix('='))
        })
        .filter(|reference| !reference.trim().is_empty())
        .with_context(|| format!("{category} must use {category}:<canonical-ref>"))?;
    Ok(reference)
}

async fn require_l11_task(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    expected_revision: u64,
) -> Result<TaskContract> {
    let task = require_task(state, project_id, task_id).await?;
    if task.memory_revision != MemoryRevision::new(expected_revision) {
        anyhow::bail!(
            "stale L11 task revision: expected {expected_revision}, current {}",
            task.memory_revision.value()
        );
    }
    Ok(task)
}

async fn l11_trace_records(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<Vec<CanonicalRecord<CanonicalTraceCompletenessContract>>> {
    Ok(state
        .store
        .replay_view(project_id, Some(task_id), 128)
        .await?
        .trace_contracts)
}

async fn require_registered_trace(
    state: &McpState,
    task: &TaskContract,
    trace_ref: &str,
) -> Result<CanonicalRecord<CanonicalTraceCompletenessContract>> {
    let record = state
        .store
        .canonical_trace_by_trace_ref(task.project_id, task.task_id, trace_ref)
        .await?
        .with_context(|| format!("canonical complete trace is not registered: {trace_ref}"))?;
    revalidate_canonical_trace(state, task, &record.receipt_body).await?;
    Ok(record)
}

async fn canonical_source_binding(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
    source_content_hash: String,
    label: &str,
) -> Result<CanonicalTraceReceiptBinding> {
    let receipt = state
        .store
        .write_receipt_by_id(&write_id)
        .await?
        .with_context(|| format!("{label} has no canonical write receipt"))?;
    if receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        || !is_canonical_hash(&receipt.input_hash)
        || !is_canonical_hash(&source_content_hash)
    {
        anyhow::bail!("{label} canonical receipt scope, status, or hash is invalid");
    }
    Ok(CanonicalTraceReceiptBinding {
        receipt: WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        },
        command_kind: receipt.command_kind,
        input_hash: receipt.input_hash,
        source_content_hash,
    })
}

async fn resolve_canonical_trace_evidence(
    state: &McpState,
    input: &TraceCompletenessToolInput,
    task: &TaskContract,
) -> Result<Vec<CanonicalTraceEvidence>> {
    let (observation_id, verification_id, artifact) = validate_trace_source_refs(input, task)?;
    let observation_write_id = WriteId::from_str(&observation_id)
        .context("actual observation id must be its canonical write id")?;
    let verifier_write_id = WriteId::from_uuid(verification_id.as_uuid());
    let observation = state
        .store
        .tool_observation_by_id(&observation_id)
        .await?
        .context("actual observation record is not canonical")?;
    let verification = state
        .store
        .verification_run_by_id(verification_id)
        .await?
        .context("registered verifier run is not canonical")?;
    if verification.result != VerificationResult::Passed {
        anyhow::bail!("trace registration requires a passed canonical verifier run");
    }
    let task_binding = canonical_source_binding(
        state,
        task.project_id,
        task.task_id,
        task.write_id,
        canonical_struct_hash(task)?,
        "task contract",
    )
    .await?;
    let observation_binding = canonical_source_binding(
        state,
        task.project_id,
        task.task_id,
        observation_write_id,
        canonical_struct_hash(&observation)?,
        "actual observation",
    )
    .await?;
    let verifier_binding = canonical_source_binding(
        state,
        task.project_id,
        task.task_id,
        verifier_write_id,
        canonical_struct_hash(&verification)?,
        "verifier run",
    )
    .await?;
    let task_ref = format!("task_contract:{}", task.task_id);
    let actual_ref = format!("actual_observation:{observation_id}");
    let verifier_ref = format!("verifier_run:{verification_id}");
    let receipt_sources = [
        (
            CanonicalTraceEvidenceKind::TaskContract,
            task_ref.clone(),
            task_binding.clone(),
        ),
        (
            CanonicalTraceEvidenceKind::ActualObservation,
            actual_ref.clone(),
            observation_binding.clone(),
        ),
        (
            CanonicalTraceEvidenceKind::VerifierRun,
            verifier_ref.clone(),
            verifier_binding.clone(),
        ),
    ];
    let mut evidence = canonical_receipt_trace_evidence(task, &receipt_sources)?;
    let input_refs = vec![task_ref, actual_ref, verifier_ref];
    let input_hashes = vec![
        task_binding.input_hash,
        observation_binding.input_hash,
        verifier_binding.input_hash,
    ];
    for (kind, reference) in canonical_derived_trace_references(
        task,
        &observation_id,
        verification_id,
        &artifact,
        state.profile.as_str(),
    ) {
        evidence.push(TraceCompletenessService::derivation_evidence(
            kind,
            task.project_id,
            task.task_id,
            task.memory_revision,
            reference,
            "eliot-l11-canonical-resolution-v1".to_owned(),
            input_refs.clone(),
            input_hashes.clone(),
            TaintClass::LocalVerified,
        )?);
    }
    Ok(evidence)
}

fn canonical_receipt_trace_evidence(
    task: &TaskContract,
    sources: &[(
        CanonicalTraceEvidenceKind,
        String,
        CanonicalTraceReceiptBinding,
    )],
) -> Result<Vec<CanonicalTraceEvidence>> {
    sources
        .iter()
        .map(|(kind, reference, binding)| {
            TraceCompletenessService::receipt_evidence(
                *kind,
                task.project_id,
                task.task_id,
                task.memory_revision,
                reference.clone(),
                binding.clone(),
                TaintClass::LocalVerified,
            )
            .map_err(Into::into)
        })
        .collect()
}

async fn revalidate_canonical_trace(
    state: &McpState,
    task: &TaskContract,
    contract: &CanonicalTraceCompletenessContract,
) -> Result<()> {
    if contract.project_id != task.project_id
        || contract.task_id != task.task_id
        || contract.source_task_revision != task.memory_revision
    {
        anyhow::bail!("canonical trace is stale or outside the current task scope");
    }
    TraceCompletenessService::validate_canonical_contract(contract)?;
    for evidence in &contract.evidence {
        let CanonicalTraceEvidenceSource::CanonicalReceipt { binding } = &evidence.source else {
            continue;
        };
        let current = current_trace_receipt_binding(state, task, evidence).await?;
        if *binding != current {
            anyhow::bail!("canonical trace receipt binding changed or was fabricated");
        }
    }
    Ok(())
}

async fn current_trace_receipt_binding(
    state: &McpState,
    task: &TaskContract,
    evidence: &CanonicalTraceEvidence,
) -> Result<CanonicalTraceReceiptBinding> {
    match evidence.kind {
        CanonicalTraceEvidenceKind::TaskContract => {
            if evidence.reference != format!("task_contract:{}", task.task_id) {
                anyhow::bail!("task contract evidence reference is not canonical");
            }
            canonical_source_binding(
                state,
                task.project_id,
                task.task_id,
                task.write_id,
                canonical_struct_hash(task)?,
                "task contract",
            )
            .await
        }
        CanonicalTraceEvidenceKind::ActualObservation => {
            let observation_id = trace_ref_value(&evidence.reference, "actual_observation")?;
            if !task
                .observation_ids
                .iter()
                .any(|value| value == observation_id)
            {
                anyhow::bail!("actual observation evidence is no longer attached to the task");
            }
            let observation = state
                .store
                .tool_observation_by_id(observation_id)
                .await?
                .context("actual observation evidence no longer resolves")?;
            canonical_source_binding(
                state,
                task.project_id,
                task.task_id,
                WriteId::from_str(observation_id)?,
                canonical_struct_hash(&observation)?,
                "actual observation",
            )
            .await
        }
        CanonicalTraceEvidenceKind::VerifierRun => {
            let verification_id =
                VerificationId::from_str(trace_ref_value(&evidence.reference, "verifier_run")?)?;
            if !task.verification_ids.contains(&verification_id) {
                anyhow::bail!("verifier evidence is no longer attached to the task");
            }
            let verification = state
                .store
                .verification_run_by_id(verification_id)
                .await?
                .context("verifier evidence no longer resolves")?;
            if verification.result != VerificationResult::Passed {
                anyhow::bail!("canonical verifier evidence is no longer passed");
            }
            canonical_source_binding(
                state,
                task.project_id,
                task.task_id,
                WriteId::from_uuid(verification_id.as_uuid()),
                canonical_struct_hash(&verification)?,
                "verifier run",
            )
            .await
        }
        _ => anyhow::bail!("derived trace evidence cannot carry a canonical receipt binding"),
    }
}

fn is_canonical_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_trace_source_refs(
    input: &TraceCompletenessToolInput,
    task: &TaskContract,
) -> Result<(String, VerificationId, String)> {
    let observation_id =
        trace_ref_value(&input.actual_observation_ref, "actual_observation")?.to_owned();
    if !task
        .observation_ids
        .iter()
        .any(|candidate| candidate == &observation_id)
    {
        anyhow::bail!("actual_observation_ref is not attached to the canonical task");
    }
    let verification_id =
        VerificationId::from_str(trace_ref_value(&input.verifier_run_ref, "verifier_run")?)
            .context("parse verifier_run verification id")?;
    if !task.verification_ids.contains(&verification_id) {
        anyhow::bail!("verifier_run_ref is not attached to the canonical task");
    }
    let artifact = trace_ref_value(&input.artifact_ref, "artifact_ref")?.to_owned();
    let artifact_is_scoped = task.verification_scopes.iter().any(|scope| {
        scope.verification_id == verification_id
            && scope.artifact_refs.iter().any(|candidate| {
                candidate.resource_ref == artifact || candidate.content_hash == artifact
            })
    });
    if !artifact_is_scoped {
        anyhow::bail!("artifact_ref is not covered by the canonical verifier scope");
    }
    if input.source_route.trim().is_empty()
        || input.source_tool.trim().is_empty()
        || input.source_verifier.trim().is_empty()
        || input.outcome.trim().is_empty()
    {
        anyhow::bail!("trace source route, tool, verifier, and outcome must be explicit");
    }
    Ok((observation_id, verification_id, artifact))
}

fn canonical_derived_trace_references(
    task: &TaskContract,
    observation_id: &str,
    verification_id: VerificationId,
    artifact: &str,
    profile: &str,
) -> [(CanonicalTraceEvidenceKind, String); 10] {
    [
        (
            CanonicalTraceEvidenceKind::ContextPacket,
            format!(
                "context_packet:{}:{}",
                task.task_id,
                task.memory_revision.value()
            ),
        ),
        (
            CanonicalTraceEvidenceKind::CurrentTruthRevision,
            format!("current_truth_revision:{}", task.memory_revision.value()),
        ),
        (
            CanonicalTraceEvidenceKind::MemoryExposureSet,
            format!(
                "memory_exposure_set:{}:{}",
                task.task_id,
                task.project_sequence.value()
            ),
        ),
        (
            CanonicalTraceEvidenceKind::AgentToolEvents,
            format!("agent_tool_events:{observation_id}"),
        ),
        (
            CanonicalTraceEvidenceKind::ExpectedObservation,
            format!("expected_observation:verification:{verification_id}:passed"),
        ),
        (
            CanonicalTraceEvidenceKind::ArtifactRef,
            format!("artifact_ref:{artifact}"),
        ),
        (
            CanonicalTraceEvidenceKind::FinishDecision,
            format!("finish_decision:{}:{:?}", task.write_id, task.status),
        ),
        (
            CanonicalTraceEvidenceKind::PolicySnapshot,
            "policy_snapshot:eliot-l11-canonical-v1".to_owned(),
        ),
        (
            CanonicalTraceEvidenceKind::ModelRoute,
            format!("model_route:{profile}"),
        ),
        (
            CanonicalTraceEvidenceKind::OutcomeAndCost,
            format!("outcome_and_cost:{observation_id}:{verification_id}"),
        ),
    ]
}

fn dispatch_latest_report(state: &McpState, dir: &str) -> Result<Value> {
    read_j0_latest_value(&state.root, dir)
}

async fn dispatch_blackboard_add(state: &McpState, arguments: Value) -> Result<Value> {
    let input: BlackboardAddToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let owner_session_id = ensure_controller_session(&mut work_state, project_id).agent_session_id;
    let work_item_id =
        find_work_item(&work_state, &input.project, &input.task).map(|item| item.work_item_id);
    let lease_id = latest_active_work_lease_id(&work_state, project_id, task_id);
    let item = BlackboardService.create_item(
        &mut work_state,
        BlackboardAddInput {
            project_id,
            task_id,
            owner_session_id,
            work_item_id,
            lease_id,
            kind: parse_blackboard_kind(input.kind.as_deref().unwrap_or("finding"))?,
            scope: BlackboardScope::default(),
            payload_ref: input.payload_ref,
            evidence_refs: input.evidence.unwrap_or_default(),
            confidence: input
                .confidence
                .map(|value| parse_confidence(&value))
                .transpose()?,
            expires_at: None,
        },
    );
    write_collective_memory(
        state,
        &mut work_state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(blackboard_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}

fn dispatch_blackboard_list(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let work_state = load_work_state(&state.root)?;
    let report = blackboard_report_value(&work_state, &input.project, &input.task);
    write_json_report(
        &state
            .root
            .join("reports")
            .join("blackboard")
            .join("latest.json"),
        &report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("blackboard")
            .join("latest.md"),
        &collective_report_markdown("Blackboard Report", &report),
    )?;
    Ok(report)
}

async fn dispatch_blackboard_ack(state: &McpState, arguments: Value) -> Result<Value> {
    let input: BlackboardAckToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let item_id = input
        .item
        .or(input.item_id)
        .context("item or item_id is required")?;
    let item_id = BlackboardItemId::from_str(&item_id).context("parse blackboard item id")?;
    let session_id = input
        .session
        .map(|value| AgentSessionId::from_str(&value))
        .transpose()?
        .unwrap_or_else(|| {
            work_state
                .blackboard_items
                .iter()
                .find(|item| item.blackboard_item_id == item_id)
                .map_or_else(AgentSessionId::new_v7, |item| item.owner_session_id)
        });
    let item = BlackboardService.acknowledge(&mut work_state, item_id, session_id)?;
    write_collective_memory(
        state,
        &mut work_state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    let (project, task) = labels_for_project_task(&work_state, item.project_id, item.task_id);
    save_collective_reports(&state.root, &work_state, &project, &task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &project, &task),
    )?;
    Ok(blackboard_report_value(&work_state, &project, &task))
}

async fn dispatch_mailbox_send(state: &McpState, arguments: Value) -> Result<Value> {
    let input: MailboxSendToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let sender_session_id = ensure_controller_session(&mut work_state, project_id).agent_session_id;
    let message = MailboxService.send(
        &mut work_state,
        MailboxSendInput {
            message_id: input
                .message_id
                .map(|value| MailboxMessageId::from_str(&value))
                .transpose()?,
            project_id,
            task_id,
            sender_session_id,
            recipient: parse_mailbox_recipient(input.recipient.as_deref().unwrap_or("controller"))?,
            kind: parse_mailbox_kind(input.kind.as_deref().unwrap_or("ack-required"))?,
            payload_ref: input.payload_ref,
            requires_ack: None,
            expires_at: None,
        },
    );
    write_collective_memory(state, &mut work_state, &[], &[message.message_id], &[], &[]).await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(mailbox_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}

fn dispatch_mailbox_inbox(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let work_state = load_work_state(&state.root)?;
    let report = mailbox_report_value(&work_state, &input.project, &input.task);
    write_json_report(
        &state
            .root
            .join("reports")
            .join("mailbox")
            .join("latest.json"),
        &report,
    )?;
    write_markdown_report(
        &state.root.join("reports").join("mailbox").join("latest.md"),
        &collective_report_markdown("Mailbox Report", &report),
    )?;
    Ok(report)
}

async fn dispatch_mailbox_ack(state: &McpState, arguments: Value) -> Result<Value> {
    let input: MailboxAckToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let message_id = input
        .message
        .or(input.message_id)
        .context("message or message_id is required")?;
    let message_id = MailboxMessageId::from_str(&message_id).context("parse mailbox message id")?;
    let message = MailboxService.acknowledge(&mut work_state, message_id)?;
    write_collective_memory(state, &mut work_state, &[], &[message.message_id], &[], &[]).await?;
    let (project, task) = labels_for_project_task(&work_state, message.project_id, message.task_id);
    save_collective_reports(&state.root, &work_state, &project, &task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &project, &task),
    )?;
    Ok(mailbox_report_value(&work_state, &project, &task))
}

async fn dispatch_recovery_scan(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let records = LostAgentRecoveryService.scan(
        &mut work_state,
        project_id,
        task_id,
        time::Duration::minutes(30),
    );
    let recovery_ids = records
        .iter()
        .map(|record| record.recovery_id.clone())
        .collect::<Vec<_>>();
    let message_ids = records
        .iter()
        .flat_map(|record| record.mailbox_messages.iter().copied())
        .collect::<Vec<_>>();
    write_collective_memory(
        state,
        &mut work_state,
        &[],
        &message_ids,
        &recovery_ids,
        &[],
    )
    .await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(recovery_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}

async fn dispatch_collective_trace(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let trace = CollectiveTraceService.trace_task(&mut work_state, project_id, task_id);
    write_collective_memory(
        state,
        &mut work_state,
        &[],
        &[],
        &[],
        std::slice::from_ref(&trace.collective_trace_id),
    )
    .await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(collective_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}

fn initialize_result(profile: McpAccessProfile, session: &Value) -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false },
            "prompts": { "listChanged": false }
        },
        "serverInfo": {
            "name": "eliot-governor",
            "title": "Eliot Governor",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": profile_instructions(profile),
        "experimental": {
            "eliotAgentSession": session
        }
    })
}

fn profile_instructions(profile: McpAccessProfile) -> String {
    let proactive_memory = match profile {
        McpAccessProfile::HumanOperator | McpAccessProfile::HumanReadonly => {
            "Use the bounded operator projections and typed commands only. The Governor remains the sole business-rule and memory authority; do not request raw records, database access, credentials, shell, or hidden reasoning."
        }
        McpAccessProfile::ClaudeGoverned => {
            "For a material project task, resolve one stable project identity, read task/current state, and expand only the exact memory or packet handles needed for the decision. Record cross-memory influence explicitly and submit only novel candidate evidence with a retry-stable write ID. Use delegation and disposition tools only when the current task-scoped role lease authorizes them; this compact profile intentionally omits direct patch, provider, database, and completion authority."
        }
        _ => {
            "For every nontrivial project task, use Eliot before searching local memory files. First call eliot_host_session_status. If it reports governor_bound_scope_active, call eliot_project_identity with no key and let the Governor default all supported project/task fields; never derive or restate those identifiers from a case label, current directory, playground, or host UI. Otherwise call eliot_project_identity with one stable repository key. Then use eliot_task_state, eliot_recall_l0, and eliot_fetch_l2 as needed. Explicit scope must match the Governor binding or it is rejected as PROJECT_SCOPE_MISMATCH or TASK_SCOPE_MISMATCH. Recover daemon runtime_id and auth_generation only from eliot_runtime_status, and bounded autonomy only from eliot_autonomy_run_status; never substitute an AgentSession, role status, or verification run for those canonical identities. Call MCP tools from their live definitions; never read generated MCP JSON schema or report/output files. A recall-only or status-only task needs no handoff write, and an existing recalled claim must never be copied into a new candidate. Submit only a novel reusable finding created by the current material work. Use one eliot_agent_candidate_submit call with one retry-stable UUID write_id, topic, statement, all three array fields where_applicable/where_not_applicable/negative_constraints (empty arrays are valid), non-empty provenance_refs, and freshness_rule; a bound session may omit project_id/task_id. For memory recall, do not call CodeCortex or Antigravity connector reports/smokes unless the task explicitly requires them."
        }
    };
    let authority = match profile {
        McpAccessProfile::CognitiveGovernor => {
            "This private profile admits and advances one canonical cognitive run through sealed Governor RPCs only."
        }
        McpAccessProfile::HostGovernor => {
            "This attested private profile admits host authority mutations through sealed Governor RPCs only."
        }
        McpAccessProfile::CognitiveChild => {
            "This private profile is confined to one capability-bound candidate submission and has no global IPC authority."
        }
        McpAccessProfile::CognitiveControl => {
            "This sealed memory-free control profile exposes an empty MCP tool catalog."
        }
        McpAccessProfile::DynamicAgent | McpAccessProfile::ClaudeGoverned => {
            "Your host identity grants no controller, worker, auditor, verifier, patch, or completion role. Any such role is task-scoped and must be evidenced by eliot_host_session_status plus a current Eliot role/work lease. When that status reports governor_bound_scope_active, call project identity and task/current-memory tools without inventing or restating project/task identifiers; the Governor supplies the bound scope and rejects PROJECT_SCOPE_MISMATCH or TASK_SCOPE_MISMATCH. Never derive scope from a case label, current directory, playground, or host UI. Never infer your role from host-specific Antigravity visibility, provider status, old invocation receipts, or memory history. Use the governed tools directly for proactive recall, candidate writeback, and task work; do not wait for repeated user prompting."
        }
        McpAccessProfile::ExternalAuditor => {
            "You are an external_auditor: recalled state and your writes are candidate evidence only; never claim truth promotion, patch, lease, provider, or completion authority."
        }
        McpAccessProfile::HumanReadonly | McpAccessProfile::Verifier => {
            "This profile is read-only; never claim write, patch, lease, provider, or completion authority."
        }
        McpAccessProfile::HumanOperator => {
            "This is a human operator session. Only typed operator commands are allowed; every mutation remains subject to Governor policy and must return a canonical receipt."
        }
        McpAccessProfile::CodexWorker => {
            "This worker profile cannot apply patches, delegate reviews, or claim completion."
        }
        McpAccessProfile::CodexController => {
            "Controller authority remains governed by task contracts, action leases, and verifier evidence."
        }
    };
    format!(
        "MCP profile {} exposes only governed Eliot tools. {proactive_memory} {authority} No raw SQL, raw shell, raw file, or credential surface is available.",
        profile.as_str()
    )
}

fn tool(name: &str, title: &str, description: &str, input_schema: &Value) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input_schema.clone()
    })
}

fn json_schema(properties: &[(&str, &str)], required: &[&str]) -> Value {
    let props = properties
        .iter()
        .map(|(name, ty)| ((*name).to_owned(), json!({ "type": ty })))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "type": "object",
        "properties": props,
        "required": required
    })
}

fn compile_packet_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "project_id": {"type": "string"},
            "task_id": {"type": "string"},
            "goal": {"type": "string"},
            "candidate_handles": {"type": "array", "items": {"type": "string"}},
            "max_tokens": {"type": "integer", "minimum": 1},
            "memory_mode": {
                "type": "string",
                "enum": [
                    "current_truth_only", "memory_free_control", "mature_experience_only",
                    "include_case_candidates", "full_audit"
                ]
            },
            "material_frame": {
                "type": "object",
                "description": "Required for material work; omitted packets are honestly rated insufficient.",
                "properties": {
                    "acceptance_items": {"type": "array", "items": {"type": "string"}},
                    "environment": {"type": "array", "items": {"type": "string"}},
                    "active_plan": {"type": "array", "items": {"type": "string"}},
                    "completed_work": {"type": "array", "items": {"type": "string"}},
                    "killed_paths": {"type": "array", "items": {"type": "string"}},
                    "causal_bridge": {"type": "array", "items": {"type": "object"}},
                    "negative_memory_checked": {"type": "boolean"},
                    "exact_load_bearing_atoms": {"type": "array", "items": {"type": "string"}},
                    "cheapest_discriminative_probes": {"type": "array", "items": {"type": "string"}},
                    "responsibility_contour_route_refs": {"type": "array", "items": {"type": "string"}},
                    "next_allowed_action": {"type": "string"},
                    "expected_observable": {"type": "string"},
                    "verifier": {"type": "string"},
                    "stop_condition": {"type": "string"},
                    "tool_schema_bytes_visible": {"type": "integer", "minimum": 0},
                    "instruction_hotset_size": {"type": "integer", "minimum": 0}
                },
                "required": [
                    "acceptance_items", "environment", "causal_bridge",
                    "negative_memory_checked", "exact_load_bearing_atoms",
                    "cheapest_discriminative_probes", "responsibility_contour_route_refs",
                    "next_allowed_action", "expected_observable", "verifier", "stop_condition",
                    "tool_schema_bytes_visible", "instruction_hotset_size"
                ]
            }
        },
        "required": ["project_id", "task_id", "goal", "candidate_handles", "max_tokens"]
    })
}

fn understanding_proof_schema() -> Value {
    json_schema(
        &[
            ("task_id", "string"),
            ("project_id", "string"),
            ("goal", "string"),
            ("code_task", "boolean"),
            ("current_truth_refs", "array"),
            ("evidence_refs", "array"),
            ("codecortex_report_refs", "array"),
            ("files_to_change", "array"),
            ("files_to_inspect", "array"),
            ("causal_bridge", "string"),
            ("causal_bridge_from_goal_to_code", "string"),
            ("invariants", "array"),
            ("negative_memory_checked", "boolean"),
            ("unknowns", "array"),
            ("planned_action", "string"),
            ("expected_verifiers", "array"),
            ("blast_radius_acknowledged", "boolean"),
            ("risk_level", "string"),
        ],
        &[
            "task_id",
            "project_id",
            "goal",
            "current_truth_refs",
            "evidence_refs",
            "causal_bridge",
            "invariants",
            "negative_memory_checked",
            "unknowns",
            "planned_action",
            "expected_verifiers",
            "risk_level",
        ],
    )
}

fn codecortex_scan_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("goal", "string"),
            ("exact_patterns", "array"),
            ("max_files", "integer"),
            ("max_matches_per_pattern", "integer"),
            ("include_diagnostics", "boolean"),
        ],
        &["project", "task", "goal"],
    )
}

fn action_plan_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("project_id", "string"),
            ("task", "string"),
            ("task_id", "string"),
            ("goal", "string"),
            ("requested_action_kind", "string"),
            ("change_plan", "object"),
            ("verifier_plan", "object"),
        ],
        &["goal"],
    )
}

fn action_lease_status_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("project_id", "string"),
            ("task", "string"),
            ("task_id", "string"),
        ],
        &[],
    )
}

fn patch_apply_schema() -> Value {
    json_schema(
        &[("lease_id", "string"), ("diff_text", "string")],
        &["lease_id", "diff_text"],
    )
}

fn work_create_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("goal", "string"),
            ("read", "array"),
            ("write", "array"),
        ],
        &["project", "task", "goal"],
    )
}

fn work_claim_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("role", "string"),
        ],
        &["project", "task"],
    )
}

fn work_status_schema() -> Value {
    json_schema(
        &[("project", "string"), ("task", "string")],
        &["project", "task"],
    )
}

fn work_lease_schema() -> Value {
    json_schema(&[("lease_id", "string")], &["lease_id"])
}

fn worktree_create_schema() -> Value {
    json_schema(&[("lease_id", "string")], &["lease_id"])
}

fn worktree_status_schema() -> Value {
    json_schema(
        &[
            ("worktree_lease", "string"),
            ("worktree_lease_id", "string"),
        ],
        &[],
    )
}

fn worktree_lease_schema() -> Value {
    json_schema(&[("worktree_lease", "string")], &["worktree_lease"])
}

fn worktree_review_schema() -> Value {
    json_schema(
        &[("candidate_diff", "string"), ("decision", "string")],
        &["candidate_diff", "decision"],
    )
}

fn blackboard_add_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("kind", "string"),
            ("payload_ref", "string"),
            ("evidence", "array"),
            ("confidence", "string"),
        ],
        &["project", "task", "payload_ref"],
    )
}

fn blackboard_ack_schema() -> Value {
    json_schema(
        &[
            ("item", "string"),
            ("item_id", "string"),
            ("session", "string"),
        ],
        &[],
    )
}

fn mailbox_send_schema() -> Value {
    json_schema(
        &[
            ("project", "string"),
            ("task", "string"),
            ("kind", "string"),
            ("payload_ref", "string"),
            ("recipient", "string"),
            ("message_id", "string"),
        ],
        &["project", "task", "payload_ref"],
    )
}

fn mailbox_ack_schema() -> Value {
    json_schema(&[("message", "string"), ("message_id", "string")], &[])
}

fn tool_success(structured: &Value) -> Result<Value> {
    Ok(json!({
        "content": [{ "type": "text", "text": serde_json::to_string(&structured)? }],
        "structuredContent": structured.clone(),
        "isError": false
    }))
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn canonical_project_key(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("project id or stable project key must not be empty");
    }
    let without_extended_prefix = trimmed.strip_prefix("\\\\?\\").unwrap_or(trimmed);
    let normalized = without_extended_prefix
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 512 {
        anyhow::bail!("canonical project key must contain 1..=512 bytes");
    }
    Ok(normalized)
}

fn project_id_from_canonical_key(value: &str) -> ProjectId {
    let identity = format!("eliot://project/{value}");
    let digest = blake3::hash(identity.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ProjectId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

fn parse_project_id(value: &str) -> Result<ProjectId> {
    ProjectId::from_str(value)
        .or_else(|_| canonical_project_key(value).map(|key| project_id_from_canonical_key(&key)))
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
        "purge" => anyhow::bail!("purge is denied in Phase I0"),
        other => anyhow::bail!("unknown memory lifecycle operator: {other}"),
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
        other => anyhow::bail!("unknown memory lifecycle reason: {other}"),
    }
}

fn consistency(at_least_revision: Option<u64>) -> ReadConsistencyMode {
    at_least_revision.map_or(ReadConsistencyMode::Latest, |_| {
        ReadConsistencyMode::AtLeastRevision
    })
}

fn revision(at_least_revision: Option<u64>) -> Option<MemoryRevision> {
    at_least_revision.map(MemoryRevision::new)
}

fn write_json_report<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    Ok(())
}

async fn write_codecortex_report_to_memory(
    state: &McpState,
    report: &mut CodeCortexReport,
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    CodeCortexMemoryWriter::write_report(&handle, &admission, report).await?;
    Ok(())
}

async fn write_memory_influence_to_memory(
    state: &McpState,
    report: &mut MemoryInfluenceReport,
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    MemoryLifecycleMemoryWriter::write_influence_report(&handle, &admission, report).await?;
    Ok(())
}

async fn write_skill_card_to_memory(
    state: &McpState,
    skill: &SkillCardV2,
) -> Result<eliot_types::WriteReceiptRef> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    let receipt = SkillRegistryService::write_skill_card(&handle, &admission, skill).await?;
    Ok(receipt)
}

async fn write_skill_execution_proof_to_memory(
    state: &McpState,
    proof: &mut eliot_types::SkillExecutionProof,
) -> Result<eliot_types::WriteReceiptRef> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    let receipt = SkillExecutionProofService::write_proof(&handle, &admission, proof).await?;
    Ok(receipt)
}

async fn write_skill_curator_run_to_memory(
    state: &McpState,
    run: &mut SkillCuratorRun,
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    SkillCuratorMemoryWriter::write_run(&handle, &admission, run).await?;
    for proposal in &mut run.proposals {
        SkillCuratorMemoryWriter::write_proposal(&handle, &admission, proposal).await?;
    }
    Ok(())
}

fn write_skill_curator_reports(state: &McpState, report: &SkillCurationReport) -> Result<()> {
    write_json_report(
        &state
            .root
            .join("reports")
            .join("skill-curator")
            .join("latest.json"),
        report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("skill-curator")
            .join("latest.md"),
        &typed_report_markdown("Skill Curator", report)?,
    )?;
    let proposals_report = json!({
        "component": "skill_curation_proposals",
        "run_id": report.run.run_id,
        "open_proposals": report.open_proposals,
        "generated_at": report.generated_at
    });
    write_json_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-proposals")
            .join("latest.json"),
        &proposals_report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-proposals")
            .join("latest.md"),
        &typed_report_markdown("Skill Curation Proposals", &proposals_report)?,
    )?;
    write_skill_curator_gate_report(state, &report.gate_decisions)
}

fn write_skill_curator_gate_report(
    state: &McpState,
    gate_decisions: &[SkillCurationGateDecision],
) -> Result<()> {
    let gate_report = json!({
        "component": "skill_curation_gate",
        "gate_decisions": gate_decisions,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_json_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-gate")
            .join("latest.json"),
        &gate_report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("skill-curation-gate")
            .join("latest.md"),
        &typed_report_markdown("Skill Curation Gate", &gate_report)?,
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

fn find_skill_curation_proposal(root: &Path, proposal_id: &str) -> Result<SkillCurationProposal> {
    let run = latest_skill_curator_run(root)?
        .context("no latest skill-curator run found; call eliot_skill_curator_run first")?;
    if proposal_id == "latest" {
        return run
            .proposals
            .into_iter()
            .next()
            .context("no latest skill curation proposal found");
    }
    if let Some(action) = parse_skill_curation_action(proposal_id) {
        return run
            .proposals
            .into_iter()
            .find(|proposal| proposal.action == action)
            .with_context(|| format!("no skill curation proposal for action {proposal_id}"));
    }
    run.proposals
        .into_iter()
        .find(|proposal| proposal.proposal_id == proposal_id)
        .with_context(|| format!("skill curation proposal not found: {proposal_id}"))
}

fn parse_skill_curation_action(value: &str) -> Option<SkillCurationAction> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
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

async fn write_patch_memory(
    state: &McpState,
    patch_run: &mut eliot_types::PatchRun,
    verifier_runs: &mut [VerifierRun],
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    for verifier_run in verifier_runs {
        PatchMemoryWriter::write_verifier_run(&handle, &admission, verifier_run).await?;
    }
    PatchMemoryWriter::write_patch_run(&handle, &admission, patch_run).await?;
    Ok(())
}

fn patch_request_from_input(
    root: &Path,
    lease_id: &str,
    diff_text: String,
) -> Result<(PatchRequest, ActionLease, CodeCortexReport, VerifierPlan)> {
    let lease = latest_action_lease(root)?;
    if lease.lease_id.to_string() != lease_id {
        anyhow::bail!("requested lease_id does not match latest ActionLease report");
    }
    let report = latest_codecortex_report(root)?
        .context("no latest CodeCortex report found; call eliot_codecortex_scan first")?;
    let verifier_plan = lease
        .verifier_plan
        .clone()
        .context("latest ActionLease has no VerifierPlan")?;
    let scope = lease
        .allowed_scope
        .as_ref()
        .context("latest ActionLease has no ActionScope")?;
    let request = PatchRequest {
        patch_request_id: PatchRequestId::new_v7(),
        project_id: lease.project_id,
        task_id: lease.task_id,
        agent_id: lease.agent_id,
        action_lease_id: lease.lease_id,
        repo_root: scope.repo_root.clone(),
        git_head_before: scope.git_head.clone(),
        codecortex_report_refs: vec![eliot_engine::codecortex_report_ref(&report)],
        verifier_plan_ref: format!("verifier_plan:{}", lease.lease_id),
        diff: UnifiedDiff {
            byte_len: diff_text.len(),
            text: diff_text,
        },
        created_at: time::OffsetDateTime::now_utc(),
    };
    Ok((request, lease, report, verifier_plan))
}

fn latest_action_lease(root: &Path) -> Result<ActionLease> {
    let latest = action_plan::latest_action_lease_report(root)?
        .context("no latest ActionLease report found; call eliot_action_plan first")?;
    serde_json::from_value(
        latest
            .get("record")
            .and_then(|record| record.get("lease"))
            .cloned()
            .context("latest ActionLease report is missing record.lease")?,
    )
    .map_err(Into::into)
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
            message: "bounded MCP patch work scope".to_owned(),
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

fn codecortex_latest_path(root: &Path) -> PathBuf {
    root.join("reports").join("codecortex").join("latest.json")
}

fn patch_latest_path(root: &Path) -> PathBuf {
    root.join("reports").join("patch").join("latest.json")
}

fn latest_codecortex_report(root: &Path) -> Result<Option<CodeCortexReport>> {
    let path = codecortex_latest_path(root);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn latest_json_report(path: &Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn external_review_latest_path(root: &Path, report_dir: &str) -> PathBuf {
    root.join("reports").join(report_dir).join("latest.json")
}

fn antigravity_latest_path(root: &Path, report_dir: &str) -> PathBuf {
    root.join("reports").join(report_dir).join("latest.json")
}

fn write_external_review_mcp_report<T>(
    state: &McpState,
    report_dir: &str,
    title: &str,
    value: &T,
) -> Result<()>
where
    T: serde::Serialize,
{
    let json_path = external_review_latest_path(&state.root, report_dir);
    write_json_report(&json_path, value)?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join(report_dir)
            .join("latest.md"),
        &typed_report_markdown(title, value)?,
    )
}

fn write_antigravity_mcp_report<T>(
    state: &McpState,
    report_dir: &str,
    title: &str,
    value: &T,
) -> Result<()>
where
    T: serde::Serialize,
{
    let json_path = antigravity_latest_path(&state.root, report_dir);
    write_json_report(&json_path, value)?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join(report_dir)
            .join("latest.md"),
        &typed_report_markdown(title, value)?,
    )
}

fn write_antigravity_mcp_invocation_receipt(state: &McpState, tool_name: &str) -> Result<()> {
    let event_id = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let audit_event_ref = format!("reports/antigravity-mcp-invocations/events/{event_id}.json");
    let receipt = AntigravityMcpBoundaryService.invocation_receipt_with_audit(
        state.profile.as_str(),
        tool_name,
        true,
        Some(&audit_event_ref),
    )?;
    write_antigravity_mcp_report(
        state,
        "antigravity-mcp-invocations",
        "Antigravity MCP Invocation",
        &receipt,
    )?;
    let event_path = state.root.join(&audit_event_ref);
    write_json_report(&event_path, &receipt)?;
    write_markdown_report(
        &event_path.with_extension("md"),
        &typed_report_markdown("Antigravity MCP Invocation Event", &receipt)?,
    )
}

fn mcp_antigravity_resolution_probe_contract() -> (
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

fn mcp_antigravity_plugin_root(state: &McpState) -> PathBuf {
    state
        .root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("plugin")
        .join("eliot-antigravity")
}

fn latest_antigravity_mcp_run(state: &McpState) -> Result<Option<AntigravityRun>> {
    latest_json_report(&antigravity_latest_path(&state.root, "antigravity-runs"))?
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

fn latest_antigravity_mcp_typed<T>(state: &McpState, report_dir: &str) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    Ok(
        latest_json_report(&antigravity_latest_path(&state.root, report_dir))?
            .and_then(|value| serde_json::from_value(value).ok()),
    )
}

fn parse_antigravity_mode(value: &str) -> Result<AntigravityReviewMode> {
    match value {
        "audit-plan" | "audit_plan" => Ok(AntigravityReviewMode::AuditPlan),
        "candidate-implementation" | "candidate_implementation" => {
            Ok(AntigravityReviewMode::CandidateImplementation)
        }
        other => anyhow::bail!("unknown Antigravity review mode: {other}"),
    }
}

fn mcp_antigravity_tools_governed_only() -> bool {
    AntigravityMcpBoundaryService.exposes_only_governed(governed_tool_names())
}

fn parse_external_review_role(value: &str) -> Result<ExternalReviewRole> {
    match value {
        "auditor" => Ok(ExternalReviewRole::Auditor),
        "reviewer" => Ok(ExternalReviewRole::Reviewer),
        "critic" => Ok(ExternalReviewRole::Critic),
        "worker" => Ok(ExternalReviewRole::Worker),
        other => anyhow::bail!("unknown external review role: {other}"),
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
    state: &McpState,
    request: &mut ExternalReviewRequest,
) -> Result<(WorkState, Option<WorkLease>)> {
    let mut work_state = load_work_state(&state.root)?;
    let controller = AgentSessionService.create_controller(&mut work_state, request.project_id);
    let item = WorkQueueService.create_work_item(
        &mut work_state,
        WorkCreateRequest {
            project_id: request.project_id,
            task_id: request.task_id,
            project: request.project.clone(),
            task: request.task.clone(),
            goal: request.question.clone(),
            scope: default_work_scope(
                std::env::current_dir()?.display().to_string(),
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
        &mut work_state,
        WorkClaimRequest {
            work_item_id: item.work_item_id,
            agent_session_id: controller.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let work_lease = decision.work_lease_id.and_then(|lease_id| {
        work_state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    request.work_lease_id = work_lease.as_ref().map(|lease| lease.work_lease_id);
    Ok((work_state, work_lease))
}

fn external_review_report_status(root: &Path, report_dir: &str) -> Value {
    let path = external_review_latest_path(root, report_dir);
    json!({
        "path": path,
        "exists": path.is_file()
    })
}

fn external_review_tools_governed_only() -> bool {
    [
        "eliot_external_review_providers",
        "eliot_external_review_request",
        "eliot_external_review_job_status",
        "eliot_external_review_result",
        "eliot_external_review_report",
        "eliot_external_review_run_mock",
    ]
    .into_iter()
    .all(|tool| GOVERNED_TOOLS.contains(&tool))
        && GOVERNED_TOOLS.iter().all(|tool| {
            ![
                "raw_exec",
                "raw_secret",
                "raw_patch",
                "raw_truth",
                "run_gemini",
                "run_antigravity",
            ]
            .into_iter()
            .any(|forbidden| tool.contains(forbidden))
        })
}

fn filter_report_item(report: &Value, array_key: &str, id_key: &str, id_value: &str) -> Value {
    report
        .get(array_key)
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .find(|value| value.get(id_key).and_then(Value::as_str) == Some(id_value))
        })
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "status": "not_found",
                "array": array_key,
                "id_key": id_key,
                "id_value": id_value
            })
        })
}

fn read_json_file<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

async fn write_work_entities(
    state: &McpState,
    work_state: &mut WorkState,
    session_id: Option<AgentSessionId>,
    item_id: Option<WorkItemId>,
    lease_id: Option<WorkLeaseId>,
    conflict_ids: &[String],
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    if let Some(session_id) = session_id
        && let Some(session) = work_state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)
    {
        WorkMemoryWriter::write_session(&handle, &admission, session).await?;
    }
    if let Some(item_id) = item_id
        && let Some(item) = work_state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == item_id)
    {
        WorkMemoryWriter::write_work_item(&handle, &admission, item).await?;
    }
    if let Some(lease_id) = lease_id
        && let Some(lease) = work_state
            .leases
            .iter_mut()
            .find(|lease| lease.work_lease_id == lease_id)
    {
        WorkMemoryWriter::write_work_lease(&handle, &admission, lease).await?;
    }
    for conflict_id in conflict_ids {
        if let Some(conflict) = work_state
            .conflicts
            .iter()
            .find(|conflict| &conflict.conflict_id == conflict_id)
            && let Some(item) = work_state
                .work_items
                .iter()
                .find(|item| item.work_item_id == conflict.work_item_id)
        {
            let agent_id = work_state
                .leases
                .iter()
                .find(|lease| lease.work_item_id == item.work_item_id)
                .map_or_else(eliot_types::AgentId::new_v7, |lease| lease.agent_id);
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
    Ok(())
}

fn load_work_state(root: &Path) -> Result<WorkState> {
    let path = root.join("reports").join("work").join("state.json");
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
    let work_dir = root.join("reports").join("work");
    std::fs::create_dir_all(&work_dir)?;
    serde_json::to_writer_pretty(std::fs::File::create(work_dir.join("state.json"))?, state)?;
    std::fs::write(work_dir.join("state.md"), "# Work State\n")?;
    write_json_report(&work_dir.join("latest.json"), report)?;
    std::fs::write(work_dir.join("latest.md"), work_report_markdown(report))?;
    Ok(())
}

fn save_worktree_state_and_reports(root: &Path, state: &WorkState) -> Result<()> {
    let work_dir = root.join("reports").join("work");
    std::fs::create_dir_all(&work_dir)?;
    serde_json::to_writer_pretty(std::fs::File::create(work_dir.join("state.json"))?, state)?;
    std::fs::write(work_dir.join("state.md"), "# Work State\n")?;

    let worktree_report = json!({
        "component": "worktree",
        "worktree_lease_count": state.worktree_leases.len(),
        "latest_worktree_lease": state.worktree_leases.last(),
        "final_status": if state.worktree_leases.is_empty() { "NO_WORKTREE" } else { "DONE_VERIFIED" }
    });
    write_json_report(
        &root.join("reports").join("worktree").join("latest.json"),
        &worktree_report,
    )?;
    write_markdown_report(
        &root.join("reports").join("worktree").join("latest.md"),
        &worktree_report_markdown(&worktree_report),
    )?;

    let candidate_report = json!({
        "component": "candidate_diff",
        "candidate_diff_count": state.candidate_diffs.len(),
        "candidate_review_count": state.candidate_reviews.len(),
        "latest_candidate_diff": state.candidate_diffs.last(),
        "latest_candidate_review": state.candidate_reviews.last(),
        "final_status": if state.candidate_diffs.is_empty() { "NO_CANDIDATE_DIFF" } else { "DONE_VERIFIED" }
    });
    write_json_report(
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.json"),
        &candidate_report,
    )?;
    write_markdown_report(
        &root
            .join("reports")
            .join("candidate-diff")
            .join("latest.md"),
        &candidate_diff_report_markdown(&candidate_report),
    )?;
    Ok(())
}

fn write_markdown_report(path: &Path, markdown: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, markdown)?;
    Ok(())
}

fn typed_report_markdown<T: serde::Serialize>(title: &str, report: &T) -> Result<String> {
    Ok(format!(
        "# {title}\n\n```json\n{}\n```\n",
        serde_json::to_string_pretty(report)?
    ))
}

fn worktree_report_markdown(report: &Value) -> String {
    format!(
        "# Worktree\n\n- worktree_lease_count: `{}`\n- final_status: `{}`\n",
        report
            .get("worktree_lease_count")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        report
            .get("final_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    )
}

async fn write_worktree_memory(
    state: &McpState,
    worktree_lease: Option<&mut WorktreeLease>,
    candidate_diff: Option<&mut CandidateDiff>,
    candidate_review: Option<(&mut CandidateReview, &CandidateDiff)>,
    diff_agent_id: Option<AgentId>,
) -> Result<()> {
    let handle = state.writer.clone();
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
    Ok(())
}

async fn write_canonical_worktree_lease(
    state: &McpState,
    context: AuthenticatedRequestContext,
    lease: &mut WorktreeLease,
    idempotency_key: &str,
) -> Result<()> {
    lease.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        lease.project_id,
        Some(lease.task_id),
        CanonicalReceiptKind::WorktreeLease,
        idempotency_key,
        lease,
    )
    .await?;
    lease.write_receipt = Some(receipt);
    Ok(())
}

async fn write_canonical_work_lease(
    state: &McpState,
    context: AuthenticatedRequestContext,
    lease: &mut WorkLease,
    idempotency_key: &str,
) -> Result<()> {
    lease.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        lease.project_id,
        Some(lease.task_id),
        CanonicalReceiptKind::WorkLease,
        idempotency_key,
        lease,
    )
    .await?;
    lease.write_receipt = Some(receipt);
    Ok(())
}

async fn write_collective_memory(
    state: &McpState,
    work_state: &mut WorkState,
    blackboard_item_ids: &[BlackboardItemId],
    mailbox_message_ids: &[MailboxMessageId],
    recovery_ids: &[String],
    collective_trace_ids: &[String],
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    for item_id in blackboard_item_ids {
        if let Some(item) = work_state
            .blackboard_items
            .iter_mut()
            .find(|item| item.blackboard_item_id == *item_id)
        {
            CollectiveMemoryWriter::write_blackboard_item(&handle, &admission, item).await?;
        }
    }
    for message_id in mailbox_message_ids {
        if let Some(message) = work_state
            .mailbox_messages
            .iter_mut()
            .find(|message| message.message_id == *message_id)
        {
            CollectiveMemoryWriter::write_mailbox_message(&handle, &admission, message).await?;
        }
    }
    for recovery_id in recovery_ids {
        if let Some(record) = work_state
            .recovery_records
            .iter_mut()
            .find(|record| &record.recovery_id == recovery_id)
        {
            CollectiveMemoryWriter::write_recovery_record(&handle, &admission, record).await?;
        }
    }
    for collective_trace_id in collective_trace_ids {
        if let Some(trace) = work_state
            .collective_traces
            .iter_mut()
            .find(|trace| &trace.collective_trace_id == collective_trace_id)
        {
            CollectiveMemoryWriter::write_collective_trace(&handle, &admission, trace).await?;
        }
    }
    Ok(())
}

fn save_collective_reports(
    root: &Path,
    state: &WorkState,
    project: &str,
    task: &str,
) -> Result<()> {
    let blackboard = blackboard_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("blackboard").join("latest.json"),
        &blackboard,
    )?;
    write_markdown_report(
        &root.join("reports").join("blackboard").join("latest.md"),
        &collective_report_markdown("Blackboard Report", &blackboard),
    )?;
    let mailbox = mailbox_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("mailbox").join("latest.json"),
        &mailbox,
    )?;
    write_markdown_report(
        &root.join("reports").join("mailbox").join("latest.md"),
        &collective_report_markdown("Mailbox Report", &mailbox),
    )?;
    let recovery = recovery_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("recovery").join("latest.json"),
        &recovery,
    )?;
    write_markdown_report(
        &root.join("reports").join("recovery").join("latest.md"),
        &collective_report_markdown("Recovery Report", &recovery),
    )?;
    let collective = collective_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("collective").join("latest.json"),
        &collective,
    )?;
    write_markdown_report(
        &root.join("reports").join("collective").join("latest.md"),
        &collective_report_markdown("Collective Trace Report", &collective),
    )
}

fn blackboard_report_value(state: &WorkState, project: &str, task: &str) -> Value {
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
    json!({
        "component": "blackboard",
        "project": project,
        "task": task,
        "items": items,
        "blackboard_candidate_not_truth": true,
        "final_status": "DONE_VERIFIED"
    })
}

fn mailbox_report_value(state: &WorkState, project: &str, task: &str) -> Value {
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
    json!({
        "component": "mailbox",
        "project": project,
        "task": task,
        "messages": messages,
        "mailbox_grants_no_authority": true,
        "final_status": "DONE_VERIFIED"
    })
}

fn recovery_report_value(state: &WorkState, project: &str, task: &str) -> Value {
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
    json!({
        "component": "recovery",
        "project": project,
        "task": task,
        "records": records,
        "silent_candidate_promotion": false,
        "final_status": "DONE_VERIFIED"
    })
}

fn collective_report_value(state: &WorkState, project: &str, task: &str) -> Value {
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
    json!({
        "component": "collective_trace",
        "project": project,
        "task": task,
        "traces": traces,
        "final_status": "DONE_VERIFIED"
    })
}

fn collective_report_markdown(title: &str, report: &Value) -> String {
    let status = report
        .get("final_status")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    format!("# {title}\n\n- final_status: `{status}`\n")
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

fn agent_id_for_worktree(state: &WorkState, worktree_lease_id: WorktreeLeaseId) -> AgentId {
    state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .and_then(|worktree| {
            state
                .leases
                .iter()
                .find(|lease| lease.work_lease_id == worktree.work_lease_id)
        })
        .map_or_else(AgentId::new_v7, |lease| lease.agent_id)
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
        other => anyhow::bail!("unknown blackboard kind: {other}"),
    }
}

fn parse_confidence(value: &str) -> Result<ConfidenceLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(ConfidenceLevel::Low),
        "medium" | "med" => Ok(ConfidenceLevel::Medium),
        "high" => Ok(ConfidenceLevel::High),
        other => anyhow::bail!("unknown confidence level: {other}"),
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
        other => anyhow::bail!("unknown mailbox kind: {other}"),
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
    anyhow::bail!("unknown mailbox recipient: {value}")
}

fn production_worktree_root(
    repo_root: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    work_lease_id: WorkLeaseId,
) -> Result<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is required for production WorktreeLease roots")?;
    let sync_roots = [
        std::env::var_os("OneDrive"),
        std::env::var_os("OneDriveCommercial"),
    ]
    .into_iter()
    .flatten()
    .map(PathBuf::from)
    .collect::<Vec<_>>();
    production_worktree_root_from(
        repo_root,
        &local_app_data,
        &sync_roots,
        project_id,
        task_id,
        work_lease_id,
    )
}

fn production_worktree_root_from(
    repo_root: &Path,
    local_app_data: &Path,
    sync_roots: &[PathBuf],
    project_id: ProjectId,
    task_id: TaskId,
    work_lease_id: WorkLeaseId,
) -> Result<PathBuf> {
    if !local_app_data.is_absolute() {
        anyhow::bail!("LOCALAPPDATA must be absolute for production WorktreeLease roots");
    }
    for sync_root in sync_roots {
        if local_app_data.starts_with(sync_root) {
            anyhow::bail!("LOCALAPPDATA WorktreeLease root must not be inside a sync root");
        }
    }
    let root = local_app_data
        .join("Eliot")
        .join("worktrees")
        .join(authority_path_segment("p", &project_id.to_string()))
        .join(authority_path_segment("t", &task_id.to_string()))
        .join(authority_path_segment("l", &work_lease_id.to_string()));
    if root.starts_with(repo_root) || repo_root.starts_with(&root) {
        anyhow::bail!("production WorktreeLease root must be isolated from the source repository");
    }
    Ok(root)
}

fn authority_path_segment(prefix: &str, authority_id: &str) -> String {
    let digest = blake3::hash(authority_id.as_bytes()).to_hex();
    format!("{prefix}-{}", &digest[..16])
}

struct TerminalChainContext<'a> {
    state: &'a McpState,
    broker: &'a eliot_types::DelegationState,
    work: &'a WorkState,
    project_id: ProjectId,
    task_id: TaskId,
}

struct CanonicalAuthorityScope<'a> {
    state: &'a McpState,
    project_id: ProjectId,
    task_id: TaskId,
}

struct AuthorityProjection<'a, T> {
    entity_kind: &'a str,
    entity_ref: String,
    payload_field: &'a str,
    receipt: Option<&'a WriteReceiptRef>,
    projected: &'a T,
}

struct CurrentChainProjections<'a> {
    result: &'a AgentResultEnvelope,
    disposition: &'a eliot_types::AgentResultDisposition,
    diff: &'a CandidateDiff,
    review: &'a CandidateReview,
    worktree: &'a WorktreeLease,
    work_lease: &'a WorkLease,
}

struct CanonicalTerminalEntities {
    result: AgentResultEnvelope,
    disposition: eliot_types::AgentResultDisposition,
    diff: CandidateDiff,
    review: CandidateReview,
    worktree: WorktreeLease,
    work_lease: WorkLease,
}

fn persist_rehydrated_terminal_chain(
    state: &McpState,
    context: &TerminalChainContext<'_>,
    chain: &AutonomyHostResultChain,
) -> Result<()> {
    let entities = resolve_current_chain_projections(context, chain)?;
    let mut broker = delegation_runtime::load_state(&state.root)?;
    broker
        .agent_results
        .retain(|item| item.result_id != entities.result.result_id);
    broker.agent_results.push(entities.result.clone());
    broker.agent_result_dispositions.retain(|item| {
        item.disposition_id != entities.disposition.disposition_id
            && item.result_id != entities.disposition.result_id
    });
    broker
        .agent_result_dispositions
        .push(entities.disposition.clone());
    delegation_runtime::save_host_broker_state(&state.root, &broker)?;

    let mut work = load_work_state(&state.root)?;
    replace_candidate_diff(&mut work, entities.diff.clone());
    replace_candidate_review(&mut work, entities.review.clone());
    replace_worktree_lease(&mut work, entities.worktree.clone());
    if let Some(stored) = work
        .leases
        .iter_mut()
        .find(|item| item.work_lease_id == entities.work_lease.work_lease_id)
    {
        *stored = entities.work_lease.clone();
    } else {
        work.leases.push(entities.work_lease.clone());
    }
    save_worktree_state_and_reports(&state.root, &work)
}

async fn rehydrate_terminal_chain(
    context: &TerminalChainContext<'_>,
    work_item_id: WorkItemId,
    host_label: &str,
    lease: &AutonomyLeaseBinding,
) -> Result<(eliot_types::DelegationState, WorkState)> {
    let host_id = parse_real_autonomy_host(host_label)?;
    let work_lease_id = work_lease_id_from_autonomy_ref(&lease.lease_ref)?;
    let request = context
        .broker
        .agent_invocations
        .iter()
        .rev()
        .find(|request| {
            request.project_id == context.project_id
                && request.task_id == context.task_id
                && request.work_item_id == work_item_id
                && request.work_lease_id == Some(work_lease_id)
        })
        .context("terminal authority has no governed invocation")?;
    let result_id = context
        .broker
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == request.invocation_id && job.host_id == host_id)
        .and_then(|job| job.result_ref.as_deref())
        .context("terminal authority job has no canonical result_ref")?;
    let entities = load_canonical_terminal_entities(
        context.state,
        context.project_id,
        context.task_id,
        result_id,
        work_lease_id,
    )
    .await?;
    let mut broker = context.broker.clone();
    broker
        .agent_results
        .retain(|item| item.result_id != entities.result.result_id);
    broker.agent_results.push(entities.result);
    broker.agent_result_dispositions.retain(|item| {
        item.disposition_id != entities.disposition.disposition_id
            && item.result_id != entities.disposition.result_id
    });
    broker.agent_result_dispositions.push(entities.disposition);
    let mut work = context.work.clone();
    work.candidate_diffs
        .retain(|item| item.candidate_diff_id != entities.diff.candidate_diff_id);
    work.candidate_diffs.push(entities.diff);
    work.candidate_reviews
        .retain(|item| item.review_id != entities.review.review_id);
    work.candidate_reviews.push(entities.review);
    work.worktree_leases
        .retain(|item| item.worktree_lease_id != entities.worktree.worktree_lease_id);
    work.worktree_leases.push(entities.worktree);
    work.leases
        .retain(|item| item.work_lease_id != entities.work_lease.work_lease_id);
    work.leases.push(entities.work_lease);
    Ok((broker, work))
}

async fn load_canonical_terminal_entities(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    result_id: &str,
    work_lease_id: WorkLeaseId,
) -> Result<CanonicalTerminalEntities> {
    let scope = Some(task_id);
    let (result, disposition) =
        load_canonical_broker_entities(state, project_id, task_id, result_id).await?;
    let diff_id = result
        .artifact_refs
        .iter()
        .find_map(|reference| reference.strip_prefix("candidate-diff-id:"))
        .context("canonical terminal AgentResult lacks candidate-diff ID binding")?;
    let mut diff_record = state
        .store
        .canonical_records_by_subject_ref::<CandidateDiff>(
            project_id,
            scope,
            &["candidate_diff"],
            diff_id,
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal CandidateDiff is absent")?;
    diff_record.receipt_body.write_receipt = Some(diff_record.canonical_receipt);
    let diff = diff_record.receipt_body;
    let mut review_record = state
        .store
        .canonical_records_by_subject_ref::<CandidateReview>(
            project_id,
            scope,
            &["candidate_review"],
            &diff.candidate_diff_id.to_string(),
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal CandidateReview is absent")?;
    review_record.receipt_body.write_receipt = Some(review_record.canonical_receipt);
    let review = review_record.receipt_body;
    let mut worktree_record = state
        .store
        .canonical_records_by_subject_ref::<WorktreeLease>(
            project_id,
            scope,
            &["worktree_lease"],
            &diff.worktree_lease_id.to_string(),
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal WorktreeLease is absent")?;
    worktree_record.receipt_body.write_receipt = Some(worktree_record.canonical_receipt);
    let worktree = worktree_record.receipt_body;
    let mut work_lease_record = state
        .store
        .canonical_records_by_subject_ref::<WorkLease>(
            project_id,
            scope,
            &["work_lease"],
            &work_lease_id.to_string(),
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal WorkLease is absent")?;
    work_lease_record.receipt_body.write_receipt = Some(work_lease_record.canonical_receipt);
    Ok(CanonicalTerminalEntities {
        result,
        disposition,
        diff,
        review,
        worktree,
        work_lease: work_lease_record.receipt_body,
    })
}

async fn load_canonical_broker_entities(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    result_id: &str,
) -> Result<(AgentResultEnvelope, eliot_types::AgentResultDisposition)> {
    let mut result_record = state
        .store
        .canonical_records_by_subject_ref::<AgentResultEnvelope>(
            project_id,
            Some(task_id),
            &["agent_result"],
            result_id,
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal AgentResult is absent")?;
    result_record.receipt_body.canonical_receipt = Some(result_record.canonical_receipt);
    let result = result_record.receipt_body;
    let mut disposition_record = state
        .store
        .canonical_records_by_subject_ref::<eliot_types::AgentResultDisposition>(
            project_id,
            Some(task_id),
            &["agent_result_disposition"],
            &result.result_id,
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal AgentResultDisposition is absent")?;
    disposition_record.receipt_body.canonical_receipt = Some(disposition_record.canonical_receipt);
    Ok((result, disposition_record.receipt_body))
}

async fn validate_current_chain_projections(
    context: &TerminalChainContext<'_>,
    chain: &AutonomyHostResultChain,
) -> Result<()> {
    let CurrentChainProjections {
        result,
        disposition,
        diff,
        review,
        worktree,
        work_lease,
    } = resolve_current_chain_projections(context, chain)?;
    let scope = CanonicalAuthorityScope {
        state: context.state,
        project_id: context.project_id,
        task_id: context.task_id,
    };
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "agent_result",
            entity_ref: result.result_id.clone(),
            payload_field: "receipt_body",
            receipt: result.canonical_receipt.as_ref(),
            projected: result,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "agent_result_disposition",
            entity_ref: result.result_id.clone(),
            payload_field: "receipt_body",
            receipt: disposition.canonical_receipt.as_ref(),
            projected: disposition,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "candidate_diff",
            entity_ref: diff.candidate_diff_id.to_string(),
            payload_field: "receipt_body",
            receipt: diff.write_receipt.as_ref(),
            projected: diff,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "candidate_review",
            entity_ref: diff.candidate_diff_id.to_string(),
            payload_field: "receipt_body",
            receipt: review.write_receipt.as_ref(),
            projected: review,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "worktree_lease",
            entity_ref: worktree.worktree_lease_id.to_string(),
            payload_field: "receipt_body",
            receipt: worktree.write_receipt.as_ref(),
            projected: worktree,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "work_lease",
            entity_ref: work_lease.work_lease_id.to_string(),
            payload_field: "receipt_body",
            receipt: work_lease.write_receipt.as_ref(),
            projected: work_lease,
        },
    )
    .await
}

fn resolve_current_chain_projections<'a>(
    context: &'a TerminalChainContext<'_>,
    chain: &AutonomyHostResultChain,
) -> Result<CurrentChainProjections<'a>> {
    let result = context
        .broker
        .agent_results
        .iter()
        .find(|item| item.result_id == chain.result_id)
        .context("terminal result projection disappeared")?;
    let disposition = context
        .broker
        .agent_result_dispositions
        .iter()
        .find(|item| item.disposition_id == chain.disposition_id)
        .context("terminal disposition projection disappeared")?;
    let diff = context
        .work
        .candidate_diffs
        .iter()
        .find(|item| item.diff_ref == chain.candidate_diff_ref)
        .context("terminal CandidateDiff projection disappeared")?;
    let review = context
        .work
        .candidate_reviews
        .iter()
        .find(|item| item.review_id == chain.candidate_review_ref)
        .context("terminal CandidateReview projection disappeared")?;
    let worktree = context
        .work
        .worktree_leases
        .iter()
        .find(|item| item.worktree_lease_id == diff.worktree_lease_id)
        .context("terminal WorktreeLease projection disappeared")?;
    let work_lease = context
        .work
        .leases
        .iter()
        .find(|item| item.work_lease_id == chain.work_lease_id)
        .context("terminal WorkLease projection disappeared")?;
    Ok(CurrentChainProjections {
        result,
        disposition,
        diff,
        review,
        worktree,
        work_lease,
    })
}

async fn exact_current_authority_body<T: serde::Serialize>(
    scope: &CanonicalAuthorityScope<'_>,
    projection: AuthorityProjection<'_, T>,
) -> Result<()> {
    let receipt = projection
        .receipt
        .context("terminal projection lacks its canonical receipt")?;
    let observations = scope
        .state
        .store
        .latest_authority_observations_by_entity(
            scope.project_id,
            Some(scope.task_id),
            projection.entity_kind,
            &projection.entity_ref,
        )
        .await?;
    let current = observations.first().with_context(|| {
        format!(
            "terminal canonical authority record is absent for {} {}",
            projection.entity_kind, projection.entity_ref
        )
    })?;
    if current.write_id != receipt.write_id {
        anyhow::bail!("terminal projection is stale relative to current canonical authority");
    }
    if observations.get(1).is_some_and(|previous| {
        previous.memory_revision == current.memory_revision
            && previous.project_sequence == current.project_sequence
    }) {
        anyhow::bail!("terminal canonical authority is ambiguous");
    }
    let mut expected = serde_json::to_value(projection.projected)?;
    if let Some(object) = expected.as_object_mut() {
        if object.contains_key("write_receipt") {
            object.insert("write_receipt".to_owned(), Value::Null);
        }
        if object.contains_key("canonical_receipt") {
            object.insert("canonical_receipt".to_owned(), Value::Null);
        }
    }
    let actual = if projection.payload_field == "receipt_body" {
        state_lossless_canonical_body(scope, &projection, receipt).await?
    } else {
        current
            .payload
            .get(projection.payload_field)
            .cloned()
            .context("terminal canonical authority payload is malformed")?
    };
    if actual != expected {
        anyhow::bail!(
            "terminal local {} projection differs from current canonical authority",
            projection.entity_kind
        );
    }
    let receipt_row = scope
        .state
        .store
        .write_receipt_by_id(&receipt.write_id)
        .await?
        .context("terminal canonical write receipt is absent")?;
    if receipt_row.write_id != receipt.write_id
        || !matches!(
            receipt_row.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
    {
        anyhow::bail!("terminal canonical authority receipt is not committed");
    }
    Ok(())
}

async fn state_lossless_canonical_body<T>(
    scope: &CanonicalAuthorityScope<'_>,
    projection: &AuthorityProjection<'_, T>,
    receipt: &WriteReceiptRef,
) -> Result<Value> {
    let record = scope
        .state
        .store
        .canonical_record_by_write_id::<Value>(
            scope.project_id,
            Some(scope.task_id),
            &[projection.entity_kind],
            receipt.write_id,
        )
        .await?
        .context("terminal lossless canonical authority body is absent")?;
    Ok(record.receipt_body)
}

fn canonical_projection_value<T: serde::Serialize>(value: &T) -> Result<Value> {
    let mut value = serde_json::to_value(value)?;
    if let Some(object) = value.as_object_mut() {
        if object.contains_key("write_receipt") {
            object.insert("write_receipt".to_owned(), Value::Null);
        }
        if object.contains_key("canonical_receipt") {
            object.insert("canonical_receipt".to_owned(), Value::Null);
        }
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
async fn require_exact_current_projection<T>(
    state: &McpState,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    entity_kind: &str,
    entity_ref: &str,
    payload_field: &str,
    expected_receipt_kind: Option<&str>,
    projected: &T,
) -> Result<WriteReceiptRef>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let observations = state
        .store
        .latest_authority_observations_by_entity(project_id, task_id, entity_kind, entity_ref)
        .await?;
    let current = observations
        .first()
        .with_context(|| format!("{entity_kind} has no current canonical authority"))?;
    if observations.get(1).is_some_and(|previous| {
        previous.memory_revision == current.memory_revision
            && previous.project_sequence == current.project_sequence
    }) {
        anyhow::bail!("{entity_kind} current canonical authority is ambiguous");
    }
    if let Some(kind) = expected_receipt_kind {
        let actual = current.payload.get("receipt_kind").and_then(Value::as_str);
        if actual != Some(kind) {
            anyhow::bail!(
                "{entity_kind} current canonical receipt kind differs: expected={kind} actual={}",
                actual.unwrap_or("missing")
            );
        }
    }
    let actual = current
        .payload
        .get(payload_field)
        .cloned()
        .with_context(|| format!("{entity_kind} current canonical body is absent"))?;
    let actual: T = serde_json::from_value(actual)
        .with_context(|| format!("{entity_kind} current canonical body has the wrong type"))?;
    let actual = canonical_projection_value(&actual)?;
    let expected = canonical_projection_value(projected)?;
    if actual != expected {
        anyhow::bail!(
            "local {entity_kind} projection differs from current canonical authority: actual={actual} expected={expected}"
        );
    }
    let receipt = state
        .store
        .write_receipt_by_id(&current.write_id)
        .await?
        .with_context(|| format!("{entity_kind} current canonical WriteReceipt is absent"))?;
    if receipt.project_id != project_id
        || receipt.task_id != task_id
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        || receipt.rejected_reason.is_some()
        || !receipt
            .created_records
            .iter()
            .any(|record| record == &current.observation_id)
    {
        anyhow::bail!("{entity_kind} current canonical WriteReceipt is invalid");
    }
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

struct ManagedFinalizationAuthority {
    managed: crate::host_runtime::ManagedControllerCandidate,
    controller_session_id: AgentSessionId,
    broker: eliot_types::DelegationState,
    work: WorkState,
    provider_result: AgentResultEnvelope,
    actual_verifier_refs: Vec<String>,
    task_revision: MemoryRevision,
    task_write_id: WriteId,
    authority_receipts: BTreeMap<String, WriteReceiptRef>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ManagedFinalizationIntent {
    schema_version: String,
    finalization_id: String,
    invocation_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    task_revision: MemoryRevision,
    task_write_id: WriteId,
    work_item_id: WorkItemId,
    controller_session_id: AgentSessionId,
    provider_result_id: String,
    provider_output_hash: String,
    candidate_diff_hash: String,
    verifier_refs: Vec<String>,
    candidate_diff_id: CandidateDiffId,
    review_id: String,
    result_id: String,
    disposition_id: String,
    work_lease_id: WorkLeaseId,
    worktree_lease_id: WorktreeLeaseId,
    baseline_commit: String,
    changed_files: Vec<String>,
    added_files: Vec<String>,
    modified_files: Vec<String>,
    deleted_files: Vec<String>,
    authority_receipts: BTreeMap<String, WriteReceiptRef>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ManagedFinalizationAggregate {
    schema_version: String,
    finalization_id: String,
    invocation_id: String,
    provider_output_hash: String,
    verifier_refs: Vec<String>,
    candidate_diff: CandidateDiff,
    candidate_review: CandidateReview,
    result: AgentResultEnvelope,
    disposition: eliot_types::AgentResultDisposition,
    worktree_lease: WorktreeLease,
    work_lease: WorkLease,
    operation_job: OperationJob,
    commit_ref: String,
}

struct FinalizedCandidateArtifacts {
    diff: CandidateDiff,
    review: CandidateReview,
    commit_ref: String,
}

struct FinalizedBrokerRecords {
    result: AgentResultEnvelope,
    disposition: eliot_types::AgentResultDisposition,
}

struct ManagedFinalizationProcessLock {
    path: PathBuf,
    record: Vec<u8>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ManagedFinalizationProcessLockRecord {
    schema_version: String,
    invocation_id: String,
    owner_pid: u32,
    created_unix_seconds: i64,
}

struct TaskTransitionProcessLock {
    path: PathBuf,
    record: Vec<u8>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TaskTransitionProcessLockRecord {
    schema_version: String,
    task_id: TaskId,
    owner_pid: u32,
    created_unix_seconds: i64,
}

impl Drop for TaskTransitionProcessLock {
    fn drop(&mut self) {
        if std::fs::read(&self.path).is_ok_and(|bytes| bytes == self.record) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for ManagedFinalizationProcessLock {
    fn drop(&mut self) {
        if std::fs::read(&self.path).is_ok_and(|bytes| bytes == self.record) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn managed_finalization_mutex(invocation_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: StdOnceLock<StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        StdOnceLock::new();
    let locks = LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut locks = locks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks
        .entry(invocation_id.to_owned())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

async fn acquire_managed_finalization_process_lock(
    root: &Path,
    invocation_id: &str,
) -> Result<ManagedFinalizationProcessLock> {
    let lock_root = root.join("reports").join("managed-finalizations");
    std::fs::create_dir_all(&lock_root)?;
    let path = lock_root.join(format!(
        "{}.lock",
        blake3::hash(invocation_id.as_bytes()).to_hex()
    ));
    let started = std::time::Instant::now();
    loop {
        let record = serde_json::to_vec(&ManagedFinalizationProcessLockRecord {
            schema_version: "eliot-managed-finalization-process-lock-v1".to_owned(),
            invocation_id: invocation_id.to_owned(),
            owner_pid: std::process::id(),
            created_unix_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
        })?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(&record)?;
                file.sync_all()?;
                return Ok(ManagedFinalizationProcessLock { path, record });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read(&path).unwrap_or_default();
                let metadata_age = std::fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
                    .unwrap_or_default();
                let active =
                    serde_json::from_slice::<ManagedFinalizationProcessLockRecord>(&existing)
                        .ok()
                        .filter(|record| {
                            record.schema_version == "eliot-managed-finalization-process-lock-v1"
                                && record.invocation_id == invocation_id
                                && record.owner_pid != 0
                        })
                        .is_some_and(|record| {
                            eliot_windows_ipc::process_is_alive(record.owner_pid).unwrap_or(true)
                        });
                if !active
                    && metadata_age >= std::time::Duration::from_secs(2)
                    && std::fs::read(&path).is_ok_and(|bytes| bytes == existing)
                {
                    match std::fs::remove_file(&path) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => {}
                    }
                }
                if started.elapsed() >= std::time::Duration::from_secs(180) {
                    anyhow::bail!(
                        "timed out waiting for managed finalization process lock for {invocation_id}"
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn acquire_task_transition_process_lock(
    root: &Path,
    task_id: TaskId,
) -> Result<TaskTransitionProcessLock> {
    const SCHEMA: &str = "eliot-task-transition-process-lock-v1";
    let lock_root = root.join("reports").join("task-transitions");
    std::fs::create_dir_all(&lock_root)?;
    let path = lock_root.join(format!("{task_id}.lock"));
    let started = std::time::Instant::now();
    loop {
        let record = serde_json::to_vec(&TaskTransitionProcessLockRecord {
            schema_version: SCHEMA.to_owned(),
            task_id,
            owner_pid: std::process::id(),
            created_unix_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
        })?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(&record)?;
                file.sync_all()?;
                return Ok(TaskTransitionProcessLock { path, record });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read(&path).unwrap_or_default();
                let metadata_age = std::fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
                    .unwrap_or_default();
                let active = serde_json::from_slice::<TaskTransitionProcessLockRecord>(&existing)
                    .ok()
                    .filter(|record| {
                        record.schema_version == SCHEMA
                            && record.task_id == task_id
                            && record.owner_pid != 0
                    })
                    .is_some_and(|record| {
                        eliot_windows_ipc::process_is_alive(record.owner_pid).unwrap_or(true)
                    });
                if !active
                    && metadata_age >= std::time::Duration::from_secs(2)
                    && std::fs::read(&path).is_ok_and(|bytes| bytes == existing)
                {
                    match std::fs::remove_file(&path) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => {}
                    }
                }
                if started.elapsed() >= std::time::Duration::from_secs(180) {
                    anyhow::bail!("timed out waiting for task transition lock for {task_id}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn deterministic_managed_uuid(label: &str, finalization_id: &str) -> uuid::Uuid {
    let digest = blake3::hash(format!("{label}:{finalization_id}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

fn managed_finalization_id(invocation_id: &str, provider_output_hash: &str) -> String {
    format!(
        "managed-finalization:{}",
        blake3::hash(format!("{invocation_id}:{provider_output_hash}").as_bytes()).to_hex()
    )
}

fn managed_finalization_key(intent: &ManagedFinalizationIntent, suffix: &str) -> String {
    format!("{}:{suffix}", intent.finalization_id)
}

fn managed_finalization_failure(stage: &str) -> Result<()> {
    if std::env::var("ELIOT_TEST_MANAGED_FINALIZATION_FAIL_AFTER").as_deref() == Ok(stage) {
        anyhow::bail!("injected managed finalization failure after {stage}");
    }
    Ok(())
}

async fn managed_finalization_test_pause_after_authority(root: &Path) -> Result<()> {
    let Ok(raw_millis) = std::env::var("ELIOT_TEST_MANAGED_FINALIZATION_PAUSE_AFTER_AUTHORITY_MS")
    else {
        return Ok(());
    };
    let millis = raw_millis
        .parse::<u64>()
        .context("parse managed finalization test pause")?;
    if millis == 0 || millis > 10_000 {
        anyhow::bail!("managed finalization test pause must be within 1..=10000 milliseconds");
    }
    let reports = root.join("reports");
    std::fs::create_dir_all(&reports)?;
    std::fs::write(
        reports.join("managed-finalization-authority-held.marker"),
        std::process::id().to_string(),
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
    Ok(())
}

async fn load_managed_finalization_authority(
    state: &McpState,
    context: AuthenticatedRequestContext,
    input: &AgentResultFinalizeToolInput,
) -> Result<ManagedFinalizationAuthority> {
    if state.profile != McpAccessProfile::CodexController {
        anyhow::bail!("managed AgentResult finalization is controller-only");
    }
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    validate_broker_refs("verifier_refs", &input.verifier_refs)?;
    let managed = crate::host_runtime::load_managed_controller_candidate(
        &state.root,
        &state.store,
        &input.invocation_id,
        &input.expected_provider_output_hash,
    )
    .await?;
    let (actual_verifier_refs, task) =
        validate_managed_actual_verifier_refs(state, &managed, &input.verifier_refs, true).await?;
    let controller_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let broker = delegation_runtime::load_state(&state.root)?;
    let work = load_work_state(&state.root)?;
    let (provider_result, authority_receipts) =
        validate_managed_broker_authority(state, &broker, &work, &managed, controller_session_id)
            .await?;
    Ok(ManagedFinalizationAuthority {
        managed,
        controller_session_id,
        broker,
        work,
        provider_result,
        actual_verifier_refs,
        task_revision: task.memory_revision,
        task_write_id: task.write_id,
        authority_receipts,
    })
}

#[allow(clippy::too_many_lines)]
async fn validate_managed_broker_authority(
    state: &McpState,
    broker: &eliot_types::DelegationState,
    work: &WorkState,
    managed: &crate::host_runtime::ManagedControllerCandidate,
    controller_session_id: AgentSessionId,
) -> Result<(AgentResultEnvelope, BTreeMap<String, WriteReceiptRef>)> {
    let request = broker
        .agent_invocations
        .iter()
        .find(|item| item.invocation_id == managed.invocation_id)
        .context("managed invocation has no broker request")?;
    if request.invocation_id != managed.invocation_id
        || request.idempotency_key != managed.idempotency_key
        || request.project_id != managed.project_id
        || request.task_id != managed.task_id
        || request.work_item_id != managed.work_item_id
        || request.role_lease_id != managed.role_lease_id
        || request.work_lease_id != Some(managed.work_lease_id)
        || request.verifier_ref != managed.planned_verifier_ref
    {
        anyhow::bail!("managed result scope differs from the canonical broker request");
    }
    let provider_result = broker
        .agent_results
        .iter()
        .find(|item| item.result_id == managed.provider_result_id)
        .cloned()
        .context("managed provider result is absent from the broker")?;
    if provider_result.invocation_id != managed.invocation_id
        || provider_result.host_id != managed.provider_host_id
        || provider_result.host_session_id.as_deref()
            != Some(managed.provider_host_session_id.as_str())
        || provider_result.status != AgentResultStatus::Succeeded
        || !provider_result.candidate_only
        || !provider_result.verifier_refs.is_empty()
    {
        anyhow::bail!("broker provider result does not match managed execution evidence");
    }
    let job = broker
        .operation_jobs
        .iter()
        .find(|item| item.invocation_id == managed.invocation_id)
        .context("managed provider result has no broker job")?;
    if job.job_id != managed.broker_job_id
        || job.host_id != managed.provider_host_id
        || job.idempotency_key != managed.idempotency_key
        || job.resume_session_id.as_deref() != Some(managed.provider_host_session_id.as_str())
        || job.state != OperationJobState::Completed
        || job.result_ref.as_deref() != Some(managed.provider_result_id.as_str())
    {
        anyhow::bail!("broker job is not bound to the managed provider result");
    }
    let now = time::OffsetDateTime::now_utc();
    let controller = broker
        .controller_leases
        .iter()
        .find(|lease| {
            lease.task_id == managed.task_id
                && lease.agent_session_id == controller_session_id
                && lease.expires_at > now
        })
        .context("managed finalization requires the active ControllerLease")?;
    let controller_role = broker
        .task_role_leases
        .iter()
        .find(|role| {
            role.task_id == managed.task_id
                && role.agent_session_id == controller_session_id
                && role.role == AgentRole::Controller
                && role.expires_at > now
                && role
                    .capability_scope
                    .iter()
                    .any(|capability| capability == "review")
                && role
                    .capability_scope
                    .iter()
                    .any(|capability| capability == "verify")
        })
        .context(
            "managed finalization requires current controller review and verify capabilities",
        )?;
    let provider_role = broker
        .task_role_leases
        .iter()
        .find(|role| role.role_lease_id == request.role_lease_id)
        .context("managed provider TaskRoleLease is absent")?;
    if provider_role.role_lease_id != managed.role_lease_id
        || provider_role.task_id != managed.task_id
        || provider_role.agent_session_id != managed.agent_session_id
        || provider_role.expires_at <= now
        || provider_role.role == AgentRole::Controller
        || request
            .requested_capabilities
            .iter()
            .any(|capability| !provider_role.capability_scope.contains(capability))
    {
        anyhow::bail!("managed provider TaskRoleLease is stale or scope-mismatched");
    }
    let host_binding = broker
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == managed.agent_session_id)
        .context("managed provider host binding is absent")?;
    if host_binding.host_identity.host_id != managed.provider_host_id
        || host_binding.host_identity.client_instance_id != managed.provider_host_session_id
        || provider_result.host_id != host_binding.host_identity.host_id
        || provider_result.host_session_id.as_deref()
            != Some(host_binding.host_identity.client_instance_id.as_str())
    {
        anyhow::bail!("managed provider result host identity differs from the canonical binding");
    }
    let provider_session = work
        .sessions
        .iter()
        .find(|session| session.agent_session_id == managed.agent_session_id)
        .context("managed provider AgentSession projection is absent")?;
    let controller_session = work
        .sessions
        .iter()
        .find(|session| session.agent_session_id == controller_session_id)
        .context("managed controller AgentSession projection is absent")?;
    let work_lease = work
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == managed.work_lease_id)
        .context("managed result WorkLease is absent")?;
    let worktree = work
        .worktree_leases
        .iter()
        .find(|item| item.worktree_lease_id == managed.worktree_lease_id)
        .context("managed result WorktreeLease is absent")?;
    assert_production_worktree_cleanup_path(worktree)?;
    if work_lease.project_id != managed.project_id
        || work_lease.task_id != managed.task_id
        || work_lease.work_item_id != managed.work_item_id
        || work_lease.agent_session_id != managed.agent_session_id
        || !eliot_engine::work_lease_is_active(work_lease)
        || worktree.project_id != managed.project_id
        || worktree.task_id != managed.task_id
        || worktree.work_item_id != managed.work_item_id
        || worktree.work_lease_id != managed.work_lease_id
        || worktree.holder_session_id != managed.agent_session_id
        || Path::new(&worktree.worktree_path) != managed.worktree_path
        || worktree.allowed_write_set != managed.allowed_paths
        || worktree.state != WorktreeLeaseState::Active
        || worktree.expires_at <= now
    {
        anyhow::bail!("managed result is not bound to current active work authority");
    }
    let mut receipts = BTreeMap::new();
    macro_rules! current {
        ($key:literal, $task:expr, $entity:literal, $reference:expr, $field:literal, $kind:expr, $body:expr) => {{
            let receipt = require_exact_current_projection(
                state,
                managed.project_id,
                $task,
                $entity,
                $reference,
                $field,
                $kind,
                $body,
            )
            .await?;
            receipts.insert($key.to_owned(), receipt.clone());
            receipt
        }};
    }
    current!(
        "agent_invocation_request",
        Some(managed.task_id),
        "agent_invocation_request",
        &managed.invocation_id,
        "receipt_body",
        Some("agent_invocation_request"),
        request
    );
    let provider_receipt = current!(
        "provider_result",
        Some(managed.task_id),
        "agent_result",
        &provider_result.result_id,
        "receipt_body",
        Some("agent_result"),
        &provider_result
    );
    if provider_result.canonical_receipt.as_ref() != Some(&provider_receipt) {
        anyhow::bail!("managed provider result local receipt is stale");
    }
    current!(
        "operation_job",
        Some(managed.task_id),
        "operation_job",
        &job.job_id,
        "receipt_body",
        Some("operation_job"),
        job
    );
    current!(
        "controller_lease",
        Some(managed.task_id),
        "controller_lease",
        &controller.controller_lease_id,
        "receipt_body",
        Some("controller_lease"),
        controller
    );
    current!(
        "controller_role",
        Some(managed.task_id),
        "task_role_lease",
        &controller_role.role_lease_id,
        "receipt_body",
        Some("host_role_lease_authority"),
        controller_role
    );
    current!(
        "provider_role",
        Some(managed.task_id),
        "task_role_lease",
        &provider_role.role_lease_id,
        "receipt_body",
        Some("host_role_lease_authority"),
        provider_role
    );
    current!(
        "host_binding",
        Some(managed.task_id),
        "host_binding",
        &managed.agent_session_id.to_string(),
        "receipt_body",
        Some("host_binding_authority"),
        host_binding
    );
    current!(
        "provider_session",
        None,
        "agent_session",
        &managed.agent_session_id.to_string(),
        "agent_session",
        None,
        provider_session
    );
    current!(
        "controller_session",
        None,
        "agent_session",
        &controller_session_id.to_string(),
        "agent_session",
        None,
        controller_session
    );
    let work_receipt = current!(
        "work_lease",
        Some(managed.task_id),
        "work_lease",
        &managed.work_lease_id.to_string(),
        "work_lease",
        None,
        work_lease
    );
    if work_lease.write_receipt.as_ref() != Some(&work_receipt) {
        anyhow::bail!("managed WorkLease local receipt is stale");
    }
    let worktree_receipt = current!(
        "worktree_lease",
        Some(managed.task_id),
        "worktree_lease",
        &managed.worktree_lease_id.to_string(),
        "worktree_lease",
        None,
        worktree
    );
    if worktree.write_receipt.as_ref() != Some(&worktree_receipt) {
        anyhow::bail!("managed WorktreeLease local receipt is stale");
    }
    receipts.insert(
        "managed_result".to_owned(),
        managed.managed_result_receipt.clone(),
    );
    Ok((provider_result, receipts))
}

async fn finalize_managed_broker_records(
    state: &McpState,
    context: AuthenticatedRequestContext,
    intent: &ManagedFinalizationIntent,
    authority: &mut ManagedFinalizationAuthority,
    artifacts: &FinalizedCandidateArtifacts,
) -> Result<FinalizedBrokerRecords> {
    let mut result = build_finalized_agent_result(authority, artifacts, intent);
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        authority.managed.project_id,
        Some(authority.managed.task_id),
        CanonicalReceiptKind::AgentResult,
        &managed_finalization_key(intent, "agent-result"),
        &result,
    )
    .await?;
    result.canonical_receipt = Some(receipt);
    let mut disposition = build_finalized_agent_result_disposition(authority, artifacts, intent);
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        authority.managed.project_id,
        Some(authority.managed.task_id),
        CanonicalReceiptKind::AgentResultDisposition,
        &managed_finalization_key(intent, "agent-result-disposition"),
        &disposition,
    )
    .await?;
    disposition.canonical_receipt = Some(receipt);
    Ok(FinalizedBrokerRecords {
        result,
        disposition,
    })
}

fn build_finalized_agent_result(
    authority: &ManagedFinalizationAuthority,
    artifacts: &FinalizedCandidateArtifacts,
    intent: &ManagedFinalizationIntent,
) -> AgentResultEnvelope {
    let managed = &authority.managed;
    AgentResultEnvelope {
        result_id: intent.result_id.clone(),
        invocation_id: managed.invocation_id.clone(),
        host_id: authority.provider_result.host_id,
        host_session_id: authority.provider_result.host_session_id.clone(),
        status: AgentResultStatus::Succeeded,
        summary: "controller finalized exact managed provider CandidateDiff".to_owned(),
        artifact_refs: vec![
            artifacts.diff.diff_ref.clone(),
            format!("commit:{}", artifacts.commit_ref),
            format!("candidate-diff-id:{}", artifacts.diff.candidate_diff_id),
        ],
        evidence_refs: vec![
            format!("managed-provider-output:{}", managed.provider_output_hash),
            format!("candidate-review:{}", artifacts.review.review_id),
            format!(
                "managed-result-write:{}",
                managed.managed_result_receipt.write_id
            ),
        ],
        verifier_refs: intent.verifier_refs.clone(),
        candidate_only: true,
        exit_status: authority.provider_result.exit_status,
        token_or_cost_telemetry: authority.provider_result.token_or_cost_telemetry.clone(),
        unknown_outcome_evidence_refs: Vec::new(),
        supersedes_result_id: Some(managed.provider_result_id.clone()),
        provider_output_hash: Some(managed.provider_output_hash.clone()),
        canonical_receipt: None,
    }
}

fn replace_finalized_agent_result(
    broker: &mut eliot_types::DelegationState,
    result: AgentResultEnvelope,
) -> Result<()> {
    let stored = broker
        .agent_results
        .iter_mut()
        .find(|item| item.result_id == result.result_id)
        .context("finalized AgentResult disappeared before canonical receipt binding")?;
    *stored = result;
    Ok(())
}

fn build_finalized_agent_result_disposition(
    authority: &ManagedFinalizationAuthority,
    artifacts: &FinalizedCandidateArtifacts,
    intent: &ManagedFinalizationIntent,
) -> eliot_types::AgentResultDisposition {
    eliot_types::AgentResultDisposition {
        disposition_id: intent.disposition_id.clone(),
        result_id: intent.result_id.clone(),
        invocation_id: intent.invocation_id.clone(),
        task_id: intent.task_id,
        controller_session_id: authority.controller_session_id,
        kind: AgentResultDispositionKind::Accepted,
        reason: "accepted exact diff and commit bound to managed provider output".to_owned(),
        evidence_refs: vec![
            artifacts.diff.diff_ref.clone(),
            format!("commit:{}", artifacts.commit_ref),
            authority.managed.provider_output_hash.clone(),
        ],
        idempotency_key: managed_finalization_key(intent, "agent-result-disposition"),
        created_at: intent.created_at,
        canonical_receipt: None,
    }
}

struct ManagedCandidateFileSets {
    changed: Vec<String>,
    added: Vec<String>,
    modified: Vec<String>,
    deleted: Vec<String>,
}

fn new_managed_finalization_intent(
    authority: &ManagedFinalizationAuthority,
) -> Result<ManagedFinalizationIntent> {
    let managed = &authority.managed;
    let finalization_id =
        managed_finalization_id(&managed.invocation_id, &managed.provider_output_hash);
    let files = managed_candidate_file_sets(&managed.candidate_diff)?;
    let baseline_commit = authority
        .work
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == managed.worktree_lease_id)
        .context("managed WorktreeLease disappeared before intent")?
        .base_commit
        .clone();
    Ok(ManagedFinalizationIntent {
        schema_version: "eliot-managed-finalization-intent-v2".to_owned(),
        finalization_id: finalization_id.clone(),
        invocation_id: managed.invocation_id.clone(),
        project_id: managed.project_id,
        task_id: managed.task_id,
        task_revision: authority.task_revision,
        task_write_id: authority.task_write_id,
        work_item_id: managed.work_item_id,
        controller_session_id: authority.controller_session_id,
        provider_result_id: managed.provider_result_id.clone(),
        provider_output_hash: managed.provider_output_hash.clone(),
        candidate_diff_hash: managed.candidate_diff_hash.clone(),
        verifier_refs: authority.actual_verifier_refs.clone(),
        candidate_diff_id: CandidateDiffId::from_uuid(deterministic_managed_uuid(
            "candidate-diff",
            &finalization_id,
        )),
        review_id: format!(
            "candidate_review:{}",
            deterministic_managed_uuid("candidate-review", &finalization_id)
        ),
        result_id: format!(
            "agent-result-final:{}",
            deterministic_managed_uuid("agent-result", &finalization_id)
        ),
        disposition_id: format!(
            "agent-result-disposition:{}",
            deterministic_managed_uuid("agent-result-disposition", &finalization_id)
        ),
        work_lease_id: managed.work_lease_id,
        worktree_lease_id: managed.worktree_lease_id,
        baseline_commit,
        changed_files: files.changed,
        added_files: files.added,
        modified_files: files.modified,
        deleted_files: files.deleted,
        authority_receipts: authority.authority_receipts.clone(),
        created_at: managed.completed_at,
    })
}

async fn load_or_write_managed_finalization_intent(
    state: &McpState,
    context: AuthenticatedRequestContext,
    authority: &ManagedFinalizationAuthority,
) -> Result<(ManagedFinalizationIntent, WriteReceiptRef)> {
    let proposed = new_managed_finalization_intent(authority)?;
    let key = managed_finalization_key(&proposed, "intent");
    let write_id = deterministic_canonical_write_id(
        proposed.project_id,
        Some(proposed.task_id),
        CanonicalReceiptKind::ManagedFinalizationIntent,
        &key,
    );
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<ManagedFinalizationIntent>(
            proposed.project_id,
            Some(proposed.task_id),
            &["managed_finalization_intent"],
            write_id,
        )
        .await?
    {
        let immutable_matches = existing.receipt_body.finalization_id == proposed.finalization_id
            && existing.receipt_body.schema_version == "eliot-managed-finalization-intent-v2"
            && existing.receipt_body.invocation_id == proposed.invocation_id
            && existing.receipt_body.project_id == proposed.project_id
            && existing.receipt_body.task_id == proposed.task_id
            && existing.receipt_body.task_revision == proposed.task_revision
            && existing.receipt_body.task_write_id == proposed.task_write_id
            && existing.receipt_body.controller_session_id == proposed.controller_session_id
            && existing.receipt_body.provider_result_id == proposed.provider_result_id
            && existing.receipt_body.provider_output_hash == proposed.provider_output_hash
            && existing.receipt_body.candidate_diff_hash == proposed.candidate_diff_hash
            && existing.receipt_body.verifier_refs == proposed.verifier_refs
            && existing.receipt_body.baseline_commit == proposed.baseline_commit
            && existing.receipt_body.changed_files == proposed.changed_files
            && existing.receipt_body.added_files == proposed.added_files
            && existing.receipt_body.modified_files == proposed.modified_files
            && existing.receipt_body.deleted_files == proposed.deleted_files
            && existing.receipt_body.authority_receipts == proposed.authority_receipts;
        if !immutable_matches {
            anyhow::bail!("managed finalization intent CAS conflicts with current authority");
        }
        return Ok((existing.receipt_body, existing.canonical_receipt));
    }
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        proposed.project_id,
        Some(proposed.task_id),
        CanonicalReceiptKind::ManagedFinalizationIntent,
        &key,
        &proposed,
    )
    .await?;
    Ok((proposed, receipt))
}

async fn load_managed_finalization_intent(
    state: &McpState,
    managed: &crate::host_runtime::ManagedControllerCandidate,
) -> Result<ManagedFinalizationIntent> {
    let finalization_id =
        managed_finalization_id(&managed.invocation_id, &managed.provider_output_hash);
    let key = format!("{finalization_id}:intent");
    let write_id = deterministic_canonical_write_id(
        managed.project_id,
        Some(managed.task_id),
        CanonicalReceiptKind::ManagedFinalizationIntent,
        &key,
    );
    let record = state
        .store
        .canonical_record_by_write_id::<ManagedFinalizationIntent>(
            managed.project_id,
            Some(managed.task_id),
            &["managed_finalization_intent"],
            write_id,
        )
        .await?
        .context("managed finalization aggregate has no canonical intent")?;
    let intent = record.receipt_body;
    if intent.schema_version != "eliot-managed-finalization-intent-v2"
        || intent.finalization_id != finalization_id
        || intent.invocation_id != managed.invocation_id
        || intent.project_id != managed.project_id
        || intent.task_id != managed.task_id
        || intent.work_item_id != managed.work_item_id
        || intent.provider_result_id != managed.provider_result_id
        || intent.provider_output_hash != managed.provider_output_hash
        || intent.candidate_diff_hash != managed.candidate_diff_hash
        || intent.work_lease_id != managed.work_lease_id
        || intent.worktree_lease_id != managed.worktree_lease_id
        || !intent
            .authority_receipts
            .contains_key("agent_invocation_request")
    {
        anyhow::bail!("managed finalization intent differs from exact managed authority");
    }
    Ok(intent)
}

async fn load_managed_finalization_aggregate(
    state: &McpState,
    managed: &crate::host_runtime::ManagedControllerCandidate,
) -> Result<Option<(ManagedFinalizationAggregate, WriteReceiptRef)>> {
    let finalization_id =
        managed_finalization_id(&managed.invocation_id, &managed.provider_output_hash);
    let key = format!("{finalization_id}:aggregate");
    let write_id = deterministic_canonical_write_id(
        managed.project_id,
        Some(managed.task_id),
        CanonicalReceiptKind::ManagedFinalizationAggregate,
        &key,
    );
    let Some(record) = state
        .store
        .canonical_record_by_write_id::<ManagedFinalizationAggregate>(
            managed.project_id,
            Some(managed.task_id),
            &["managed_finalization_aggregate"],
            write_id,
        )
        .await?
    else {
        return Ok(None);
    };
    if record.receipt_body.finalization_id != finalization_id
        || record.receipt_body.invocation_id != managed.invocation_id
        || record.receipt_body.provider_output_hash != managed.provider_output_hash
    {
        anyhow::bail!("managed finalization aggregate identity differs");
    }
    Ok(Some((record.receipt_body, record.canonical_receipt)))
}

fn finalized_authority_projections(
    authority: &ManagedFinalizationAuthority,
    intent: &ManagedFinalizationIntent,
    records: &FinalizedBrokerRecords,
) -> Result<(WorktreeLease, WorkLease, OperationJob)> {
    let mut worktree = authority
        .work
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == intent.worktree_lease_id)
        .cloned()
        .context("managed WorktreeLease disappeared before aggregate")?;
    worktree.state = WorktreeLeaseState::Accepted;
    worktree.write_receipt = None;
    let mut work_lease = authority
        .work
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == intent.work_lease_id)
        .cloned()
        .context("managed WorkLease disappeared before aggregate")?;
    work_lease.write_receipt = None;
    let mut job = authority
        .broker
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == intent.invocation_id)
        .cloned()
        .context("managed OperationJob disappeared before aggregate")?;
    job.result_ref = Some(records.result.result_id.clone());
    job.updated_at = intent.created_at;
    Ok((worktree, work_lease, job))
}

fn upsert_managed_finalization_projections(
    authority: &mut ManagedFinalizationAuthority,
    aggregate: &ManagedFinalizationAggregate,
) {
    replace_candidate_diff(&mut authority.work, aggregate.candidate_diff.clone());
    replace_candidate_review(&mut authority.work, aggregate.candidate_review.clone());
    replace_worktree_lease(&mut authority.work, aggregate.worktree_lease.clone());
    if let Some(lease) = authority
        .work
        .leases
        .iter_mut()
        .find(|lease| lease.work_lease_id == aggregate.work_lease.work_lease_id)
    {
        *lease = aggregate.work_lease.clone();
    } else {
        authority.work.leases.push(aggregate.work_lease.clone());
    }
    if let Some(result) = authority
        .broker
        .agent_results
        .iter_mut()
        .find(|result| result.result_id == aggregate.result.result_id)
    {
        *result = aggregate.result.clone();
    } else {
        authority
            .broker
            .agent_results
            .push(aggregate.result.clone());
    }
    if let Some(disposition) = authority
        .broker
        .agent_result_dispositions
        .iter_mut()
        .find(|item| item.disposition_id == aggregate.disposition.disposition_id)
    {
        *disposition = aggregate.disposition.clone();
    } else {
        authority
            .broker
            .agent_result_dispositions
            .push(aggregate.disposition.clone());
    }
    if let Some(job) = authority
        .broker
        .operation_jobs
        .iter_mut()
        .find(|job| job.job_id == aggregate.operation_job.job_id)
    {
        *job = aggregate.operation_job.clone();
    } else {
        authority
            .broker
            .operation_jobs
            .push(aggregate.operation_job.clone());
    }
}

async fn heal_managed_finalization(
    state: &McpState,
    context: AuthenticatedRequestContext,
    authority: &mut ManagedFinalizationAuthority,
    aggregate: &mut ManagedFinalizationAggregate,
) -> Result<()> {
    let key = |suffix| format!("{}:{suffix}", aggregate.finalization_id);
    let mut diff = aggregate.candidate_diff.clone();
    diff.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::CandidateDiff,
        &key("candidate-diff"),
        &diff,
    )
    .await?;
    if aggregate.candidate_diff.write_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate CandidateDiff receipt differs from exact write");
    }
    let mut review = aggregate.candidate_review.clone();
    review.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::CandidateReview,
        &key("candidate-review"),
        &review,
    )
    .await?;
    if aggregate.candidate_review.write_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate CandidateReview receipt differs from exact write");
    }
    let mut result = aggregate.result.clone();
    result.canonical_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::AgentResult,
        &key("agent-result"),
        &result,
    )
    .await?;
    if aggregate.result.canonical_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate AgentResult receipt differs from exact write");
    }
    let mut disposition = aggregate.disposition.clone();
    disposition.canonical_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::AgentResultDisposition,
        &key("agent-result-disposition"),
        &disposition,
    )
    .await?;
    if aggregate.disposition.canonical_receipt.as_ref() != Some(&receipt) {
        anyhow::bail!("managed aggregate disposition receipt differs from exact write");
    }
    let mut worktree = aggregate.worktree_lease.clone();
    write_canonical_worktree_lease(state, context, &mut worktree, &key("worktree-lease")).await?;
    aggregate.worktree_lease = worktree;
    let mut work_lease = aggregate.work_lease.clone();
    write_canonical_work_lease(state, context, &mut work_lease, &key("work-lease")).await?;
    aggregate.work_lease = work_lease;
    write_canonical_observation(
        state,
        context,
        aggregate.worktree_lease.project_id,
        Some(aggregate.worktree_lease.task_id),
        CanonicalReceiptKind::OperationJob,
        &key("operation-job"),
        &aggregate.operation_job,
    )
    .await?;
    managed_finalization_failure("authority_secondaries")?;
    upsert_managed_finalization_projections(authority, aggregate);
    managed_finalization_failure("local_save")?;
    save_worktree_state_and_reports(&state.root, &authority.work)?;
    delegation_runtime::save_host_broker_state(&state.root, &authority.broker)?;
    Ok(())
}

fn managed_finalization_response(
    aggregate: &ManagedFinalizationAggregate,
    aggregate_receipt: &WriteReceiptRef,
) -> Value {
    json!({
        "schema_version": "eliot-agent-result-finalize-v2",
        "finalization_id": aggregate.finalization_id,
        "candidate_diff": aggregate.candidate_diff,
        "candidate_review": aggregate.candidate_review,
        "result": aggregate.result,
        "disposition": aggregate.disposition,
        "commit_ref": aggregate.commit_ref,
        "provider_output_hash": aggregate.provider_output_hash,
        "canonical_aggregate_receipt": aggregate_receipt,
        "completion_authority_granted": false
    })
}

#[allow(clippy::too_many_lines)]
async fn dispatch_agent_result_finalize(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentResultFinalizeToolInput = serde_json::from_value(arguments)?;
    if state.profile != McpAccessProfile::CodexController {
        anyhow::bail!("managed AgentResult finalization is controller-only");
    }
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    let lock = managed_finalization_mutex(&input.invocation_id);
    let _guard = lock.lock().await;
    let _process_guard =
        acquire_managed_finalization_process_lock(&state.root, &input.invocation_id).await?;
    let managed = crate::host_runtime::load_managed_controller_candidate(
        &state.root,
        &state.store,
        &input.invocation_id,
        &input.expected_provider_output_hash,
    )
    .await?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard =
        acquire_task_transition_process_lock(&state.root, managed.task_id).await?;
    if let Some((mut aggregate, receipt)) =
        load_managed_finalization_aggregate(state, &managed).await?
    {
        let intent = load_managed_finalization_intent(state, &managed).await?;
        if intent.verifier_refs != input.verifier_refs
            || aggregate.verifier_refs != input.verifier_refs
        {
            anyhow::bail!(
                "managed finalization replay verifier refs differ from the sealed intent"
            );
        }
        let (actual_verifier_refs, _) =
            validate_managed_actual_verifier_refs(state, &managed, &input.verifier_refs, false)
                .await?;
        validate_managed_finalization_aggregate_replay(&managed, &intent, &aggregate)?;
        let controller_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
        if aggregate.disposition.controller_session_id != controller_session_id {
            anyhow::bail!("managed finalization replay belongs to another controller session");
        }
        let broker = delegation_runtime::load_state(&state.root)?;
        let work = load_work_state(&state.root)?;
        let mut authority = ManagedFinalizationAuthority {
            managed,
            controller_session_id,
            broker,
            work,
            // Terminal replay is authorized by the canonical aggregate. The
            // original mutable provider projection may have been lost; this
            // placeholder is never consulted by the healing path.
            provider_result: aggregate.result.clone(),
            actual_verifier_refs,
            task_revision: intent.task_revision,
            task_write_id: intent.task_write_id,
            authority_receipts: BTreeMap::new(),
        };
        heal_managed_finalization(state, context, &mut authority, &mut aggregate).await?;
        return Ok(managed_finalization_response(&aggregate, &receipt));
    }
    let mut authority = load_managed_finalization_authority(state, context, &input).await?;
    managed_finalization_test_pause_after_authority(&state.root).await?;
    let (intent, _intent_receipt) =
        load_or_write_managed_finalization_intent(state, context, &authority).await?;
    managed_finalization_failure("intent")?;
    let mut artifacts = materialize_managed_candidate(state, &intent, &mut authority)?;
    canonicalize_candidate_artifacts(state, context, &intent, &authority, &mut artifacts).await?;
    managed_finalization_failure("candidate_secondaries")?;
    let records =
        finalize_managed_broker_records(state, context, &intent, &mut authority, &artifacts)
            .await?;
    managed_finalization_failure("result_secondaries")?;
    let (worktree_lease, work_lease, operation_job) =
        finalized_authority_projections(&authority, &intent, &records)?;
    let mut aggregate = ManagedFinalizationAggregate {
        schema_version: "eliot-managed-finalization-aggregate-v2".to_owned(),
        finalization_id: intent.finalization_id.clone(),
        invocation_id: intent.invocation_id.clone(),
        provider_output_hash: intent.provider_output_hash.clone(),
        verifier_refs: intent.verifier_refs.clone(),
        candidate_diff: artifacts.diff,
        candidate_review: artifacts.review,
        result: records.result,
        disposition: records.disposition,
        worktree_lease,
        work_lease,
        operation_job,
        commit_ref: artifacts.commit_ref,
    };
    let (aggregate_receipt, _) = write_canonical_observation(
        state,
        context,
        intent.project_id,
        Some(intent.task_id),
        CanonicalReceiptKind::ManagedFinalizationAggregate,
        &managed_finalization_key(&intent, "aggregate"),
        &aggregate,
    )
    .await?;
    managed_finalization_failure("aggregate")?;
    heal_managed_finalization(state, context, &mut authority, &mut aggregate).await?;
    Ok(managed_finalization_response(
        &aggregate,
        &aggregate_receipt,
    ))
}

fn git_managed_bytes(worktree: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_managed_stdout(worktree: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_managed_bytes(worktree, args)?)?
        .trim()
        .to_owned())
}

fn managed_finalization_commit_message(intent: &ManagedFinalizationIntent) -> String {
    format!(
        "eliot: finalize {}\n\nEliot-Finalization-Id: {}\nEliot-Provider-Output-Hash: {}\nEliot-Candidate-Diff-Hash: {}",
        intent.invocation_id,
        intent.finalization_id,
        intent.provider_output_hash,
        intent.candidate_diff_hash
    )
}

fn validate_managed_finalization_commit(
    worktree: &Path,
    intent: &ManagedFinalizationIntent,
    commit_ref: &str,
) -> Result<()> {
    let parent = git_managed_stdout(worktree, &["rev-parse", &format!("{commit_ref}^")])?;
    let message = git_managed_stdout(worktree, &["show", "-s", "--format=%B", commit_ref])?;
    let diff = git_managed_bytes(
        worktree,
        &[
            "diff",
            "--binary",
            "--no-ext-diff",
            &intent.baseline_commit,
            commit_ref,
            "--",
        ],
    )?;
    let status = git_managed_stdout(worktree, &["status", "--porcelain=v1"])?;
    if parent != intent.baseline_commit
        || message != managed_finalization_commit_message(intent)
        || managed_candidate_hash(&diff) != intent.candidate_diff_hash
        || !status.is_empty()
    {
        anyhow::bail!("existing managed finalization commit differs from exact intent");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_managed_finalization_aggregate_replay(
    managed: &crate::host_runtime::ManagedControllerCandidate,
    intent: &ManagedFinalizationIntent,
    aggregate: &ManagedFinalizationAggregate,
) -> Result<()> {
    let expected_diff_hash = intent
        .candidate_diff_hash
        .strip_prefix("blake3:")
        .unwrap_or(&intent.candidate_diff_hash);
    if aggregate.schema_version != "eliot-managed-finalization-aggregate-v2"
        || aggregate.finalization_id != intent.finalization_id
        || aggregate.invocation_id != intent.invocation_id
        || aggregate.provider_output_hash != intent.provider_output_hash
        || aggregate.verifier_refs != intent.verifier_refs
        || aggregate.commit_ref.is_empty()
        || aggregate.candidate_diff.candidate_diff_id != intent.candidate_diff_id
        || aggregate.candidate_diff.worktree_lease_id != intent.worktree_lease_id
        || aggregate.candidate_diff.project_id != intent.project_id
        || aggregate.candidate_diff.task_id != intent.task_id
        || aggregate.candidate_diff.work_item_id != intent.work_item_id
        || aggregate.candidate_diff.base_commit != intent.baseline_commit
        || aggregate.candidate_diff.worktree_head.as_deref() != Some(aggregate.commit_ref.as_str())
        || aggregate.candidate_diff.diff_hash != expected_diff_hash
        || aggregate.candidate_diff.changed_files != intent.changed_files
        || aggregate.candidate_diff.added_files != intent.added_files
        || aggregate.candidate_diff.modified_files != intent.modified_files
        || aggregate.candidate_diff.deleted_files != intent.deleted_files
        || aggregate.candidate_diff.capture_status != CandidateDiffStatus::AcceptedForPatchRunner
        || aggregate.candidate_review.review_id != intent.review_id
        || aggregate.candidate_review.candidate_diff_id != intent.candidate_diff_id
        || aggregate.candidate_review.reviewer_session_id != intent.controller_session_id
        || aggregate.candidate_review.decision != CandidateReviewDecision::AcceptForPatchRunner
        || aggregate.result.result_id != intent.result_id
        || aggregate.result.invocation_id != intent.invocation_id
        || aggregate.result.host_id != managed.provider_host_id
        || aggregate.result.host_session_id.as_deref()
            != Some(managed.provider_host_session_id.as_str())
        || aggregate.result.provider_output_hash.as_deref()
            != Some(intent.provider_output_hash.as_str())
        || aggregate.result.supersedes_result_id.as_deref()
            != Some(intent.provider_result_id.as_str())
        || aggregate.result.verifier_refs != intent.verifier_refs
        || aggregate.disposition.disposition_id != intent.disposition_id
        || aggregate.disposition.result_id != intent.result_id
        || aggregate.disposition.invocation_id != intent.invocation_id
        || aggregate.disposition.task_id != intent.task_id
        || aggregate.disposition.controller_session_id != intent.controller_session_id
        || aggregate.disposition.kind != AgentResultDispositionKind::Accepted
        || aggregate.worktree_lease.worktree_lease_id != intent.worktree_lease_id
        || aggregate.worktree_lease.project_id != intent.project_id
        || aggregate.worktree_lease.task_id != intent.task_id
        || aggregate.worktree_lease.work_item_id != intent.work_item_id
        || aggregate.worktree_lease.work_lease_id != intent.work_lease_id
        || aggregate.worktree_lease.holder_session_id != managed.agent_session_id
        || Path::new(&aggregate.worktree_lease.worktree_path) != managed.worktree_path
        || aggregate.worktree_lease.base_commit != intent.baseline_commit
        || aggregate.worktree_lease.allowed_write_set != managed.allowed_paths
        || aggregate.worktree_lease.state != WorktreeLeaseState::Accepted
        || aggregate.work_lease.work_lease_id != intent.work_lease_id
        || aggregate.work_lease.project_id != intent.project_id
        || aggregate.work_lease.task_id != intent.task_id
        || aggregate.work_lease.work_item_id != intent.work_item_id
        || aggregate.work_lease.agent_session_id != managed.agent_session_id
        || aggregate.operation_job.job_id != managed.broker_job_id
        || aggregate.operation_job.invocation_id != intent.invocation_id
        || aggregate.operation_job.host_id != managed.provider_host_id
        || aggregate.operation_job.result_ref.as_deref() != Some(intent.result_id.as_str())
    {
        anyhow::bail!("managed finalization aggregate differs from exact intent authority");
    }
    let persisted_diff = std::fs::read(&aggregate.candidate_diff.diff_ref)
        .context("managed finalization CandidateDiff artifact is absent")?;
    if persisted_diff != managed.candidate_diff
        || aggregate.candidate_diff.byte_len != persisted_diff.len()
        || aggregate.candidate_diff.file_count != intent.changed_files.len()
        || managed_candidate_hash(&persisted_diff) != intent.candidate_diff_hash
    {
        anyhow::bail!("managed finalization CandidateDiff artifact differs from exact intent");
    }
    let head = git_managed_stdout(&managed.worktree_path, &["rev-parse", "HEAD"])?;
    if head != aggregate.commit_ref {
        anyhow::bail!("managed finalization worktree HEAD differs from the canonical aggregate");
    }
    validate_managed_finalization_commit(&managed.worktree_path, intent, &aggregate.commit_ref)?;
    Ok(())
}

fn assert_production_worktree_cleanup_path(lease: &WorktreeLease) -> Result<()> {
    let expected_root = production_worktree_root(
        Path::new(&lease.repo_root),
        lease.project_id,
        lease.task_id,
        lease.work_lease_id,
    )?;
    let expected = expected_root.join(lease.worktree_lease_id.to_string());
    let actual = PathBuf::from(&lease.worktree_path);
    let expected_leaf = lease.worktree_lease_id.to_string();
    if actual != expected
        || actual.parent() != Some(expected_root.as_path())
        || actual.file_name().and_then(|name| name.to_str()) != Some(expected_leaf.as_str())
    {
        anyhow::bail!("refuse WorktreeLease cleanup outside its exact LocalAppData authority root");
    }
    Ok(())
}

fn git_head_blocking(repo_root: &Path) -> Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .with_context(|| format!("run git rev-parse in {}", repo_root.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn work_report_markdown(report: &eliot_engine::WorkStatusReport) -> String {
    let mut output = String::from("# Work Status\n\n");
    let _ = writeln!(output, "- project: `{}`", report.project);
    let _ = writeln!(output, "- task: `{}`", report.task);
    let _ = writeln!(output, "- work_items: `{}`", report.work_items.len());
    let _ = writeln!(output, "- active_leases: `{}`", report.active_leases.len());
    let _ = writeln!(output, "- conflicts: `{}`", report.conflicts.len());
    let _ = writeln!(output, "- final_status: `{}`", report.final_status);
    output
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

fn parse_agent_role(value: &str) -> Result<AgentRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "controller" => Ok(AgentRole::Controller),
        "implementer" | "impl" => Ok(AgentRole::Implementer),
        "reviewer" => Ok(AgentRole::Reviewer),
        "auditor" | "read_only" | "read-only" => Ok(AgentRole::Auditor),
        "verifier" => Ok(AgentRole::Verifier),
        other => anyhow::bail!("unknown agent role: {other}"),
    }
}

fn project_id_from_label(value: &str) -> ProjectId {
    parse_project_id(value)
        .unwrap_or_else(|_| project_id_from_canonical_key("invalid-or-empty-project-label"))
}

fn task_id_from_label(value: &str) -> TaskId {
    TaskId::from_str(value).unwrap_or_else(|_| TaskId::new_v7())
}

fn normalized_cli_value(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
}

fn read_j0_latest_value(root: &Path, dir: &str) -> Result<Value> {
    let path = j0_latest_path(root, dir);
    if !path.is_file() {
        anyhow::bail!("latest J0 report not found: {}", path.display());
    }
    serde_json::from_reader(std::fs::File::open(path)?).context("parse latest J0 report JSON")
}

fn j0_latest_path(root: &Path, dir: &str) -> PathBuf {
    root.join("reports").join(dir).join("latest.json")
}

fn parse_skill_id_or_new(value: &str) -> SkillId {
    SkillId::from_str(value).unwrap_or_else(|_| SkillId::new_v7())
}

fn mcp_skill_curator_run(project: &str, dry_run: bool) -> SkillCuratorRun {
    SkillCuratorService::run(SkillCuratorRunInput {
        project_id: project_id_from_label(project),
        project: project.to_owned(),
        dry_run,
        skills: mcp_skill_curator_cards(),
    })
}

fn mcp_skill_curator_cards() -> Vec<SkillCardV2> {
    let mut repeated = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator repeated success".clone_into(&mut repeated.name);
    repeated.success_count = 3;
    repeated.failure_count = 0;

    let mut missing_anti_scope = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator missing anti-scope".clone_into(&mut missing_anti_scope.name);
    missing_anti_scope.does_not_apply_when.clear();

    let mut low_utility = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator low utility high cost".clone_into(&mut low_utility.name);
    low_utility.success_count = 0;
    low_utility.failure_count = 5;
    low_utility
        .ordered_steps
        .extend((0..20).map(|index| SkillStep {
            step_id: format!("mcp-curator-expensive-{index}"),
            order: index + 10,
            instruction: "large context cost step with repeated low utility".repeat(4),
            expected_observation: None,
            required_tool_or_capability: None,
            stop_if_fails: false,
        }));

    let mut negative_transfer = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator negative transfer".clone_into(&mut negative_transfer.name);
    negative_transfer.success_count = 0;
    negative_transfer.failure_count = 2;
    negative_transfer
        .known_failure_modes
        .push(SkillFailureMode {
            failure_id: "mcp-negative-transfer".to_owned(),
            description: "negative transfer into unrelated task".to_owned(),
            detection_signal: "negative-transfer".to_owned(),
            mitigation: "quarantine and retain audit trail".to_owned(),
            negative_memory_refs: vec!["failure:mcp-negative-transfer".to_owned()],
        });

    let mut overbroad = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator overbroad".clone_into(&mut overbroad.name);
    overbroad.applies_when.push(SkillScopeRule {
        rule_id: "mcp-any-project".to_owned(),
        description: "any project task".to_owned(),
        positive_examples: vec!["any project".to_owned()],
        negative_examples: Vec::new(),
        required_evidence_refs: Vec::new(),
    });
    overbroad.applies_when.push(SkillScopeRule {
        rule_id: "mcp-all-tasks".to_owned(),
        description: "all tasks with tools".to_owned(),
        positive_examples: vec!["all tasks".to_owned()],
        negative_examples: Vec::new(),
        required_evidence_refs: Vec::new(),
    });

    let mut duplicate_a = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator duplicate".clone_into(&mut duplicate_a.name);
    "duplicate MCP curator routing".clone_into(&mut duplicate_a.purpose);
    let mut duplicate_b = duplicate_a.clone();
    duplicate_b.skill_id = SkillId::new_v7();

    vec![
        repeated,
        missing_anti_scope,
        low_utility,
        negative_transfer,
        overbroad,
        duplicate_a,
        duplicate_b,
    ]
}

fn mcp_active_skill(skill_id: SkillId, lifecycle_state: SkillLifecycleState) -> SkillCardV2 {
    let now = time::OffsetDateTime::now_utc();
    SkillCardV2 {
        skill_id,
        name: "MCP Skill Lifecycle Foundation".to_owned(),
        purpose: "govern skill activation and execution proof".to_owned(),
        level: eliot_types::SkillLevel::Procedure,
        lifecycle_state,
        applies_when: vec![SkillScopeRule {
            rule_id: "mcp-skill-scope".to_owned(),
            description: "skill lifecycle".to_owned(),
            positive_examples: vec!["skill lifecycle".to_owned()],
            negative_examples: vec!["release notes".to_owned()],
            required_evidence_refs: vec!["evidence:skill".to_owned()],
        }],
        does_not_apply_when: vec![SkillScopeRule {
            rule_id: "mcp-skill-anti-scope".to_owned(),
            description: "raw sql or external agent".to_owned(),
            positive_examples: vec!["raw sql".to_owned(), "external agent".to_owned()],
            negative_examples: vec!["governed skill proof".to_owned()],
            required_evidence_refs: Vec::new(),
        }],
        required_inputs: vec![SkillInputRequirement {
            name: "task_goal".to_owned(),
            description: "current task goal".to_owned(),
            required: true,
            source: SkillInputSource::UserPrompt,
        }],
        ordered_steps: vec![SkillStep {
            step_id: "inspect-scope".to_owned(),
            order: 1,
            instruction: "Inspect scope and verifier availability.".to_owned(),
            expected_observation: Some("activation decision is explicit".to_owned()),
            required_tool_or_capability: None,
            stop_if_fails: true,
        }],
        required_tools_and_capabilities: vec![SkillToolRequirement {
            capability: "rust-verifier".to_owned(),
            required: true,
            allowed_tools: vec!["cargo".to_owned(), "just".to_owned()],
            forbidden_tools: vec!["surreal sql".to_owned()],
        }],
        expected_outputs: vec![SkillOutputSpec {
            name: "SkillExecutionProof".to_owned(),
            description: "proof with verifier refs".to_owned(),
            evidence_required: true,
            verifier_required: true,
        }],
        verification_plan: VerifierPlan {
            required: vec![VerifierRequirement {
                name: "just_verify".to_owned(),
                command_kind: VerifierCommandKind::DomainVerifier,
                command_display: "just verify".to_owned(),
                scope: vec!["eliot-governor".to_owned()],
                required_for_done: true,
                expected_signal: "exit code 0".to_owned(),
            }],
            optional: Vec::new(),
            acceptance_items: vec!["skill proof has verifier refs".to_owned()],
        },
        stop_conditions: vec!["anti-scope matches".to_owned()],
        known_failure_modes: Vec::new(),
        rollback_or_recovery: Some("archive or quarantine with evidence".to_owned()),
        source_trace_refs: vec!["evidence:skill".to_owned()],
        replay_result_refs: Vec::new(),
        success_count: 1,
        failure_count: 0,
        last_verified_at: Some(now),
        version: "1.0.0".to_owned(),
        owner: "eliot-governor".to_owned(),
        created_at: now,
        updated_at: now,
    }
}

fn mcp_skill_context(task: &str) -> SkillActivationContext {
    SkillActivationContext {
        goal: format!("skill lifecycle {task}"),
        evidence_refs: vec!["evidence:skill".to_owned()],
        available_input_sources: vec![SkillInputSource::UserPrompt],
        available_input_names: vec!["task_goal".to_owned()],
        available_capabilities: vec!["rust-verifier".to_owned()],
        available_tools: vec!["cargo".to_owned(), "just".to_owned()],
        verifier_refs: vec!["just verify".to_owned()],
        active_negative_signals: Vec::new(),
        conflicting_skill_refs: Vec::new(),
        audit_mode: false,
    }
}

fn runtime_root(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskMeaningToolInput {
    frame: TaskMeaningFrame,
    #[serde(default)]
    requested_need: Option<MemoryNeed>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectSemanticToolInput {
    project_id: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExperienceRecallToolInput {
    project_id: String,
    frame: TaskMeaningFrame,
    #[serde(default)]
    requested_need: Option<MemoryNeed>,
    #[serde(default)]
    exposure_policy: Option<MemoryExposurePolicy>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExperienceReinstateToolInput {
    project_id: String,
    case_id: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExperienceFormToolInput {
    project_id: String,
    task_id: String,
    episode: VerifiedEpisodeProjection,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExperienceAbstractToolInput {
    project_id: String,
    task_id: String,
    case_refs: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExperienceMaturityTransitionToolInput {
    project_id: String,
    task_id: String,
    pattern_id: String,
    target_state: eliot_types::ExperienceMaturityState,
    evidence: TransferValidationEvidence,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeTransferToolInput {
    project_id: String,
    task_id: String,
    experiment_ref: String,
    memory_handles: Vec<String>,
    harm: NegativeTransferHarm,
    root_cause_stage: String,
    #[serde(default)]
    source_has_reconstructable_episode: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveLabToolInput {
    project_id: String,
    task_id: String,
    run_id: String,
    cases: Vec<CognitiveCaseSpec>,
    answers: Vec<CognitiveReaderAnswer>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveFailureLocalizationToolInput {
    project_id: String,
    task_id: String,
    report: CognitiveFailureLocalizationReport,
}

#[derive(serde::Deserialize)]
struct CurrentStateToolInput {
    project_id: String,
    #[allow(dead_code)]
    scope: Option<String>,
    at_least_revision: Option<u64>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectIdentityToolInput {
    #[serde(default)]
    project_key: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentCandidateSubmitInput {
    project_id: String,
    task_id: String,
    write_id: String,
    topic: String,
    statement: String,
    #[serde(default)]
    where_applicable: Vec<String>,
    #[serde(default)]
    where_not_applicable: Vec<String>,
    #[serde(default)]
    negative_constraints: Vec<String>,
    provenance_refs: Vec<String>,
    freshness_rule: String,
    #[serde(default)]
    curation: Option<AgentCandidateCurationInput>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Flat wire schema preserves explicit curator evidence flags.
struct AgentCandidateCurationInput {
    handle: String,
    #[serde(default)]
    duplicate_of: Option<String>,
    #[serde(default)]
    semantic_duplicate_of: Option<String>,
    #[serde(default)]
    semantic_equivalence_verified: bool,
    #[serde(default)]
    scope_match: Option<bool>,
    #[serde(default)]
    wrong_scope_for: Vec<String>,
    #[serde(default)]
    utility_score: Option<u8>,
    #[serde(default)]
    utility_delta: Option<i16>,
    #[serde(default)]
    repeat_count: Option<u16>,
    #[serde(default)]
    repeated_with: Vec<String>,
    #[serde(default)]
    evidence_sufficient: Option<bool>,
    #[serde(default)]
    superseded_by: Option<String>,
    #[serde(default)]
    stale_reason_ref: Option<String>,
    #[serde(default)]
    protected: bool,
    #[serde(default)]
    current_truth: bool,
    #[serde(default)]
    audit_required: bool,
    #[serde(default)]
    reopen_condition_met: Option<bool>,
    #[serde(default)]
    unsafe_instruction: bool,
    #[serde(default)]
    unsafe_evidence_refs: Vec<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    lifecycle: Option<String>,
    #[serde(default)]
    authority: Option<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
    #[serde(default)]
    counterevidence_refs: Vec<String>,
}

#[derive(serde::Deserialize)]
struct DelegationRefToolInput {
    delegation_id: String,
}

#[derive(serde::Deserialize)]
struct AgentDelegateToolInput {
    project_id: String,
    task_id: String,
    work_item_id: String,
    target_host: AgentHostId,
    target_role_lease_id: String,
    work_lease_id: String,
    requested_capabilities: Vec<String>,
    #[serde(default)]
    packet_refs: Vec<String>,
    expected_result_kind: String,
    verifier_ref: String,
    idempotency_key: String,
}

#[derive(serde::Deserialize)]
struct AgentInvocationRefToolInput {
    invocation_id: String,
}

#[derive(serde::Deserialize)]
struct AgentResultSubmitToolInput {
    result_id: String,
    invocation_id: String,
    status: AgentResultStatus,
    summary: String,
    #[serde(default)]
    artifact_refs: Vec<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
    #[serde(default)]
    verifier_refs: Vec<String>,
    #[serde(default)]
    exit_status: Option<i32>,
    #[serde(default)]
    token_or_cost_telemetry: Option<String>,
    #[serde(default)]
    unknown_outcome_evidence_refs: Vec<String>,
}

#[derive(serde::Deserialize)]
struct AgentResultRefToolInput {
    result_id: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentResultFinalizeToolInput {
    invocation_id: String,
    expected_provider_output_hash: String,
    idempotency_key: String,
    verifier_refs: Vec<String>,
}

#[derive(serde::Deserialize)]
struct AgentResultDispositionToolInput {
    result_id: String,
    kind: AgentResultDispositionKind,
    reason: String,
    #[serde(default)]
    evidence_refs: Vec<String>,
    idempotency_key: String,
}

#[derive(serde::Deserialize)]
struct RecallL0ToolInput {
    project_id: String,
    query: String,
    #[allow(dead_code)]
    scope: Option<String>,
    limit: Option<usize>,
}

#[derive(serde::Deserialize)]
struct FetchL2ToolInput {
    project_id: String,
    handles: Vec<String>,
    #[serde(default)]
    continuation: Option<String>,
    at_least_revision: Option<u64>,
}

#[derive(serde::Deserialize)]
struct CompilePacketToolInput {
    #[serde(flatten)]
    request: CompilePacketL3Request,
    #[serde(default)]
    material_frame: Option<MaterialPacketFrame>,
    #[serde(default)]
    memory_mode: Option<eliot_types::MemoryExposureMode>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UnderstandingOutcomeToolInput {
    project_id: String,
    record: UnderstandingOutcomeRecord,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryInfluenceTraceToolInput {
    project_id: String,
    trace: MemoryInfluenceTrace,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextCargoReceiptToolInput {
    project_id: String,
    receipt: eliot_types::ContextCargoReceipt,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorSnapshotToolInput {
    project_id: Option<String>,
    task_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorCommandToolInput {
    project_id: String,
    task_id: String,
    expected_revision: u64,
    idempotency_key: String,
    command: OperatorCommand,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcedureCandidateCreateToolInput {
    project_id: String,
    task_id: String,
    expected_revision: u64,
    idempotency_key: String,
    pattern_ref: String,
    candidate_skill: SkillCardV2,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcedureCandidateDispositionToolInput {
    project_id: String,
    task_id: String,
    expected_revision: u64,
    idempotency_key: String,
    pattern_ref: String,
    candidate_ref: String,
    holdout_evidence: Vec<VerifierArtifactRef>,
    negative_transfer_refs: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CanonicalProcedureSkillCandidate {
    schema_version: String,
    project_id: ProjectId,
    task_id: TaskId,
    task_revision: u64,
    pattern_ref: String,
    pattern_observation_ref: String,
    pattern_receipt: WriteReceiptRef,
    pattern_sha256: String,
    candidate_ref: String,
    candidate_sha256: String,
    candidate_skill: SkillCardV2,
    input_fingerprint: String,
    candidate_only: bool,
    activation_applied: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CanonicalProcedurePromotionDisposition {
    schema_version: String,
    disposition_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    task_revision: u64,
    pattern_ref: String,
    pattern_observation_ref: String,
    pattern_receipt: WriteReceiptRef,
    pattern_sha256: String,
    candidate_ref: String,
    candidate_receipt: WriteReceiptRef,
    candidate_sha256: String,
    holdout_evidence: Vec<VerifierArtifactRef>,
    validated_holdout_evidence_refs: Vec<String>,
    negative_transfer_refs: Vec<String>,
    validated_negative_transfer_refs: Vec<String>,
    unresolved_evidence_refs: Vec<String>,
    lifecycle_record: SkillLifecycleRecord,
    promotion_outcome: ProcedurePromotionOutcome,
    pattern_disposition: String,
    not_ready_reasons: Vec<String>,
    input_fingerprint: String,
    candidate_only: bool,
    activation_applied: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ContourRoutePreviewToolInput {
    project_id: String,
    task_id: String,
    work_item_id: String,
    contour: eliot_types::ResponsibilityContour,
    policies: Vec<eliot_types::ContourRoutePolicy>,
    live_routes: Vec<eliot_types::LiveContourRoute>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct AutonomyRunStatusToolInput {
    project_id: String,
    task_id: String,
    #[serde(default)]
    autonomy_run_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyContractWriteToolInput {
    contract: AutonomyRunContract,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyTransitionToolInput {
    project_id: String,
    task_id: String,
    autonomy_run_id: String,
    expected_state_revision: u64,
    target: AutonomyRunState,
    reason: String,
    risk_tier: String,
    verifier_refs: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyApprovalRequestToolInput {
    project_id: String,
    task_id: String,
    autonomy_run_id: String,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    idempotency_key: String,
    completion_proof: CompletionProof,
    reason: String,
    verifier_refs: Vec<String>,
    ttl_minutes: i64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyApprovalDecisionToolInput {
    project_id: String,
    task_id: String,
    autonomy_run_id: String,
    approval_id: String,
    expected_approval_revision: u64,
    decision: AutonomyApprovalDecisionKind,
    reason: String,
    idempotency_key: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum AutonomyRuntimeAction {
    CreateWorkPlan {
        tripwire_policy: AutonomyTripwirePolicy,
        work_items: Vec<AutonomyWorkItem>,
    },
    Advance {
        target: AutonomyRunState,
        reason: String,
        risk_tier: String,
        verifier_refs: Vec<String>,
    },
    AssignWork {
        work_item_id: WorkItemId,
        host_id: String,
        lease: AutonomyLeaseBinding,
    },
    ChargeUsage {
        work_item_id: WorkItemId,
        lease_ref: String,
        usage_evidence_ref: String,
        intent: AutonomyStepIntent,
    },
    CompleteWorkItem {
        work_item_id: WorkItemId,
        lease_ref: String,
        #[serde(default, rename = "verifier_names")]
        _verifier_names: Vec<String>,
        verifier_refs: Vec<String>,
    },
    ReassignWork {
        work_item_id: WorkItemId,
        host_id: String,
        work_lease_ref: String,
        reason: String,
    },
    RecordTripwire {
        work_item_id: WorkItemId,
        kind: AutonomyTripwireKind,
        signature: Option<String>,
        reason: String,
        evidence_ref: String,
    },
    PauseForRecovery {
        work_item_id: WorkItemId,
        tripwire_id: String,
        reason: String,
    },
    ResumeAfterRecovery {
        work_item_id: WorkItemId,
        reason: String,
    },
    CompleteRun {
        completion_proof: CompletionProof,
        reason: String,
        approval_id: String,
        verifier_refs: Vec<String>,
    },
}

impl AutonomyRuntimeAction {
    const fn name(&self) -> &'static str {
        match self {
            Self::CreateWorkPlan { .. } => "create_work_plan",
            Self::Advance { .. } => "advance",
            Self::AssignWork { .. } => "assign_work",
            Self::ChargeUsage { .. } => "charge_usage",
            Self::CompleteWorkItem { .. } => "complete_work_item",
            Self::ReassignWork { .. } => "reassign_work",
            Self::RecordTripwire { .. } => "record_tripwire",
            Self::PauseForRecovery { .. } => "pause_for_recovery",
            Self::ResumeAfterRecovery { .. } => "resume_after_recovery",
            Self::CompleteRun { .. } => "complete_run",
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyRuntimeActionToolInput {
    project_id: String,
    task_id: String,
    autonomy_run_id: String,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    idempotency_key: String,
    action: AutonomyRuntimeAction,
}

#[derive(serde::Deserialize)]
struct CodeCortexScanToolInput {
    project: String,
    task: String,
    goal: String,
    exact_patterns: Option<Vec<String>>,
    max_files: Option<usize>,
    max_matches_per_pattern: Option<usize>,
    include_diagnostics: Option<bool>,
}

#[derive(serde::Deserialize)]
struct ExternalReviewRequestToolInput {
    project: String,
    task: String,
    provider: String,
    role: Option<String>,
    question: String,
}

#[derive(serde::Deserialize)]
struct ExternalReviewJobStatusToolInput {
    job: String,
}

#[derive(serde::Deserialize)]
struct ExternalReviewResultToolInput {
    result: String,
}

#[derive(serde::Deserialize)]
struct ExternalReviewRunMockToolInput {
    request: String,
}

#[derive(serde::Deserialize)]
struct AntigravityRequestToolInput {
    project: String,
    task: String,
    mode: Option<String>,
    question: String,
}

#[derive(serde::Deserialize)]
struct AntigravityRunRefToolInput {
    run: Option<String>,
}

#[derive(serde::Deserialize)]
struct EvalFamilyToolInput {
    family: Option<String>,
}

#[derive(serde::Deserialize)]
struct EvalSuiteToolInput {
    suite: Option<String>,
}

#[derive(serde::Deserialize)]
struct EvalRunToolInput {
    suite: Option<String>,
    profile: Option<String>,
}

#[derive(serde::Deserialize)]
struct EvalRunRefToolInput {
    run: Option<String>,
}

#[derive(serde::Deserialize)]
struct EvalCompareToolInput {
    suite: Option<String>,
    baseline: Option<String>,
    candidate_run: Option<String>,
}

#[derive(serde::Deserialize)]
struct EvalGateToolInput {
    profile: Option<String>,
    suite: Option<String>,
}

#[derive(serde::Deserialize)]
struct VerifyPlanToolInput {
    profile: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TraceCompletenessToolInput {
    project_id: String,
    task_id: String,
    expected_task_revision: u64,
    idempotency_key: String,
    trace_ref: String,
    actual_observation_ref: String,
    verifier_run_ref: String,
    artifact_ref: String,
    source_route: String,
    source_tool: String,
    source_verifier: String,
    outcome: String,
    taint: TaintClass,
}

fn exact_meta_authorization(
    input: &MetaDispositionToolInput,
    expected_hash: &str,
) -> Result<MetaPolicyAuthorization> {
    if input.operator_command_ref.trim().is_empty() || input.expected_action_hash != expected_hash {
        anyhow::bail!("meta policy action requires the exact engine-derived action hash");
    }
    Ok(MetaPolicyAuthorization {
        operator_command_ref: input.operator_command_ref.clone(),
        expected_action_hash: expected_hash.to_owned(),
        exact_action_hash: input.expected_action_hash.clone(),
    })
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReplayRunToolInput {
    project_id: String,
    task_id: String,
    expected_task_revision: u64,
    idempotency_key: String,
    trace_refs: Vec<String>,
    set_name: String,
    set_role: String,
    set_version: u64,
    case_kind: ReplayCaseKind,
    baseline_policy: ReplayThresholdPolicyV1,
    candidate_policy: ReplayThresholdPolicyV1,
    baseline_version: String,
    candidate_version: String,
    sealed_context_version: String,
    evaluator_version: String,
    #[serde(default)]
    mutation_attempt: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SleepRunToolInput {
    project_id: String,
    task_id: String,
    expected_task_revision: u64,
    idempotency_key: String,
    trigger: SleepTrigger,
    dry_run: bool,
    trace_refs: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct MetaExperimentToolInput {
    project_id: String,
    task_id: String,
    expected_task_revision: u64,
    idempotency_key: String,
    eval_run_id: String,
    change_class: MetaCandidateChangeClass,
    changed_variables: Vec<String>,
    #[serde(default)]
    coupled_change_rationale: Option<String>,
    baseline_policy: ReplayThresholdPolicyV1,
    candidate_policy: ReplayThresholdPolicyV1,
    fixed_baseline_execution_id: String,
    fixed_candidate_execution_id: String,
    holdout_baseline_execution_id: String,
    holdout_candidate_execution_id: String,
    #[serde(default)]
    attempted_fence: Option<MetaIsolationFence>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct MetaDispositionToolInput {
    project_id: String,
    task_id: String,
    expected_task_revision: u64,
    idempotency_key: String,
    experiment_id: String,
    expected_experiment_revision: u64,
    decision: MetaExperimentDecision,
    #[serde(default)]
    rollback_requested: bool,
    #[serde(default)]
    operator_command_ref: String,
    #[serde(default)]
    expected_action_hash: String,
}

#[derive(serde::Deserialize)]
struct L11StatusToolInput {
    project_id: String,
    task_id: String,
}

#[derive(serde::Deserialize)]
struct MemoryLifecycleStatusToolInput {
    project: String,
    #[serde(alias = "ref")]
    memory_ref: String,
}

#[derive(serde::Deserialize)]
struct MemoryLifecycleProposeToolInput {
    project: String,
    #[serde(alias = "ref")]
    memory_ref: String,
    operator: String,
    reason: String,
}

#[derive(serde::Deserialize)]
struct MemoryLifecycleProjectToolInput {
    project: String,
    #[serde(default, alias = "ref")]
    memory_ref: Option<String>,
}

#[derive(serde::Deserialize)]
struct MemoryLifecycleInfluenceToolInput {
    project: String,
    task: Option<String>,
    included_refs: Option<Vec<String>>,
    #[serde(default)]
    outcome: Option<eliot_types::lifecycle::MemoryInfluenceOutcome>,
}

#[derive(serde::Deserialize)]
struct SkillProjectToolInput {
    project: String,
}

#[derive(serde::Deserialize)]
struct SkillInspectToolInput {
    skill: String,
}

#[derive(serde::Deserialize)]
struct SkillTaskToolInput {
    project: String,
    task: String,
}

#[derive(serde::Deserialize)]
struct SkillExecutionProofToolInput {
    skill: String,
    task: String,
}

#[derive(serde::Deserialize)]
struct SkillCreateCandidateToolInput {
    project: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct SkillCuratorRunToolInput {
    project: String,
    dry_run: Option<bool>,
}

#[derive(serde::Deserialize)]
struct SkillCuratorInspectToolInput {
    run: String,
}

#[derive(serde::Deserialize)]
struct SkillCuratorGateToolInput {
    proposal: String,
}

#[derive(serde::Deserialize)]
struct ActionPlanToolInput {
    project: Option<String>,
    project_id: Option<String>,
    task: Option<String>,
    task_id: Option<String>,
    goal: String,
    requested_action_kind: Option<ActionKind>,
    change_plan: Option<ChangePlan>,
    verifier_plan: Option<VerifierPlan>,
}

#[derive(serde::Deserialize)]
struct ActionLeaseStatusToolInput {
    project: Option<String>,
    project_id: Option<String>,
    task: Option<String>,
    task_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct PatchToolInput {
    lease_id: String,
    diff_text: String,
}

#[derive(serde::Deserialize)]
struct PatchStatusToolInput {
    patch_run_id: String,
}

#[derive(serde::Deserialize)]
struct VerifierStatusToolInput {
    task: Option<String>,
    task_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct LogsQueryInput {
    trace_id: Option<String>,
    limit: Option<usize>,
}

#[derive(serde::Deserialize)]
struct AdapterInspectInput {
    adapter: String,
}

#[derive(serde::Deserialize)]
struct WorkCreateToolInput {
    project: String,
    task: String,
    goal: String,
    read: Option<Vec<String>>,
    write: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct WorkClaimToolInput {
    project: String,
    task: String,
    role: Option<String>,
}

#[derive(serde::Deserialize)]
struct WorkStatusToolInput {
    project: String,
    task: String,
}

#[derive(serde::Deserialize)]
struct WorkLeaseToolInput {
    lease_id: String,
}

#[derive(serde::Deserialize)]
struct WorktreeCreateToolInput {
    lease_id: String,
}

#[derive(serde::Deserialize)]
struct WorktreeStatusToolInput {
    worktree_lease: Option<String>,
    worktree_lease_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct WorktreeLeaseToolInput {
    worktree_lease: String,
}

#[derive(serde::Deserialize)]
struct WorktreeReviewToolInput {
    candidate_diff: String,
    decision: String,
}

#[derive(serde::Deserialize)]
struct BlackboardAddToolInput {
    project: String,
    task: String,
    kind: Option<String>,
    payload_ref: String,
    evidence: Option<Vec<String>>,
    confidence: Option<String>,
}

#[derive(serde::Deserialize)]
struct BlackboardAckToolInput {
    item: Option<String>,
    item_id: Option<String>,
    session: Option<String>,
}

#[derive(serde::Deserialize)]
struct MailboxSendToolInput {
    project: String,
    task: String,
    kind: Option<String>,
    payload_ref: String,
    recipient: Option<String>,
    message_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct MailboxAckToolInput {
    message: Option<String>,
    message_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct TaskContractCreateToolInput {
    project_id: String,
    task_id: String,
    write_id: String,
    title: String,
    acceptance_items: Vec<TaskAcceptanceToolInput>,
}

#[derive(serde::Deserialize)]
struct TaskAcceptanceToolInput {
    item_id: String,
    description: String,
    required_evidence: TaskAcceptanceEvidenceKind,
}

#[derive(serde::Deserialize)]
struct TaskStateToolInput {
    project_id: String,
    task_id: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TaskActionToolInput {
    project_id: String,
    task_id: String,
    write_id: String,
    expected_revision: u64,
    #[serde(default)]
    packet_id: String,
    #[serde(default)]
    packet_revision_fence: u64,
    #[serde(default)]
    task_contract_ref: String,
    #[serde(default)]
    current_truth_refs: Vec<String>,
    #[serde(default)]
    provenance_handles: Vec<String>,
    #[serde(default)]
    negative_memory_checked: bool,
    #[serde(default)]
    negative_memory_check_ref: String,
    #[serde(default)]
    planned_action: String,
    #[serde(default, alias = "next_verifier")]
    planned_verifier_ref: String,
    #[serde(default)]
    worktree_ref: Option<String>,
    #[serde(default)]
    artifact_paths: Vec<String>,
}

#[derive(serde::Deserialize)]
struct TaskObservationToolInput {
    project_id: String,
    task_id: String,
    write_id: String,
    expected_revision: u64,
    action_lease_id: String,
    item_id: String,
    tool_name: String,
    observation: String,
    status: String,
    scope: String,
    provenance_handles: Vec<String>,
    #[serde(default)]
    provenance_set_hash: String,
}

#[derive(serde::Deserialize)]
struct TaskVerificationToolInput {
    project_id: String,
    task_id: String,
    write_id: String,
    expected_revision: u64,
    item_id: String,
    observation_id: String,
    #[serde(default, rename = "artifact_scope")]
    _artifact_scope: Option<String>,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    verifier_ref: String,
    #[serde(default)]
    verifier_config_hash: String,
    #[serde(default)]
    provenance_set_hash: String,
    #[serde(default)]
    worktree_ref: Option<String>,
    #[serde(default)]
    artifact_paths: Vec<String>,
    #[serde(default)]
    acceptance_item_ids: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskCompletionToolInput {
    project_id: String,
    task_id: String,
    write_id: String,
    expected_revision: u64,
    acceptance_item_ids: Vec<String>,
    observation_ids: Vec<String>,
    verification_ids: Vec<String>,
    #[serde(default)]
    memory: Option<CompletionMemoryRequest>,
}

struct McpState {
    root: PathBuf,
    store: CanonicalStore,
    schema_ready: OnceCell<()>,
    control_wal: ControlWalConfig,
    blob_store: BlobStoreConfig,
    profile: McpAccessProfile,
    writer: WriterHandle,
    pipe_name: String,
    instance_name: String,
    runtime_id: String,
    auth_generation: String,
    cursor_signing_key: [u8; 32],
    cognitive_runtime: Arc<CognitiveRuntimePaths>,
    cognitive_principals: Arc<Mutex<HashMap<SessionId, CognitivePrincipalClaims>>>,
}

impl McpState {
    async fn ensure_schema(&self) -> Result<()> {
        self.schema_ready
            .get_or_try_init(|| async {
                self.store.migrate_schema().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod protocol_tests;

#[cfg(test)]
mod catalog_parity_tests;
