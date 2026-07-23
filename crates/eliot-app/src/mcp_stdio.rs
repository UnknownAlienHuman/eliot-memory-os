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
    AntigravityMcpConfigService, AntigravityOfficialPluginService, AntigravityRealExecutionDoctor,
    AntigravityTelemetryService, AutonomyBudgetLedger, AutonomyLeaseBinding,
    AutonomyRecoveryReceipt, AutonomyRunService, AutonomyStepIntent, AutonomyTransitionRequest,
    AutonomyTripwireKind, AutonomyTripwirePolicy, AutonomyTripwireRecord, AutonomyWorkItem,
    BackupService, BlackboardAddInput, BlackboardService, BlobGcService, BoundedAutonomyRuntime,
    CandidateDiffCaptureInput, CandidateDiffService, CandidateReviewInput, CandidateReviewService,
    CanonicalMetaExperimentAssessment, CanonicalMetaExperimentInput,
    CanonicalR3ApprovalAuthorization, CanonicalReplayExecutionInput,
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
    AdapterCapability, AgentCandidateCurationInput, AgentCandidateSubmitInput,
    AgentCapabilityEnvelope, AgentHostId, AgentId, AgentInvocationRequest, AgentResultDisposition,
    AgentResultDispositionKind, AgentResultEnvelope, AgentResultRecordCommand, AgentResultStatus,
    AgentRole, AgentRoutingView, AgentSessionId, AntigravityAuthCheck, AntigravityBinaryResolution,
    AntigravityCapabilityProbe, AntigravityCommandContract, AntigravityDisableReceipt,
    AntigravityEnablementReceipt, AntigravityLiveSmokeResult, AntigravityMcpInvocationReceipt,
    AntigravityReviewMode, AntigravityRun, ApprovalView, AutonomyRunContract, AutonomyRunState,
    BenchmarkIntegrityReceipt, BlackboardItemId, BlackboardItemKind, BlackboardScope,
    BlobStoreConfig, COGNITIVE_RUN_EXACT_CALLS, COGNITIVE_RUN_RAW_VERIFIER_CALLS,
    COGNITIVE_RUN_SCHEMA_VERSION, CandidateDiff, CandidateDiffId, CandidateDiffStatus,
    CandidateReview, CandidateReviewDecision, CanonicalCaseDisposition, CanonicalReplayAuthority,
    CanonicalReplayExecutionRecord, CanonicalReplayObservationEvidence,
    CanonicalTraceCompletenessContract, CanonicalTraceEvidence, CanonicalTraceEvidenceKind,
    CanonicalTraceEvidenceSource, CanonicalTraceReceiptBinding, ChangePlan, ClaimCardInput,
    ClaimId, CodeCortexReport, CodeCortexRequest, CognitiveCandidateCapability, CognitiveCaseSpec,
    CognitiveExecutionSeal, CognitiveFailureLocalizationReport, CognitiveGateRequest,
    CognitiveHostObservation, CognitiveInvocationRole, CognitiveRawVerifierEvidence,
    CognitiveReaderAnswer, CognitiveRunAttempt, CognitiveRunCallPlan, CognitiveRunCallStatus,
    CognitiveRunContract, CognitiveRunTerminal, CognitiveSharedGateBinding,
    CognitiveToolObservation, CommandContext, CompilePacketL3Request, CompletionDecisionMemory,
    CompletionMemoryAdmission, CompletionMemoryRequest, CompletionProof, ConfidenceLevel,
    ContextPacketL3, ContrastiveAbstractionResult, ControlWalConfig, ControllerCommitHandoff,
    CostLedger, CredentialPurpose, CurrentStateRequest, DashboardReport, DataRootMode,
    EpistemicStatus, EvalBaseline, EvalCase, EvalDatasetManifest, EvalFailureCluster, EvalFamily,
    EvalRun, EvalRunId, EvalRunProfile, EvalSuite, EvalVerdict, EvalVerdictStatus,
    EvidenceAtomInput, EvidenceId, ExperienceCase, ExperienceFormationResult, ExperiencePattern,
    ExperienceRecallRequest, ExperimentalMetaPolicyPayload, ExperimentalMetaPolicyState,
    ExternalOutputSchemaKind, ExternalProviderProfile, ExternalReviewBudget,
    ExternalReviewGateDecisionKind, ExternalReviewPacket, ExternalReviewRequest,
    ExternalReviewRole, FetchAtomsL2Request, FetchAtomsL2Response, ForgettingOperator,
    ForgettingReason, LatencyHistogram, LifecycleStatus, MailboxMessageId, MailboxMessageKind,
    MailboxRecipient, MaintenanceJobKind, MaterialPacketFrame, MemoryAdmissionDecision,
    MemoryCurationCandidate, MemoryCurationCorpusProfile, MemoryCurationFindingKind,
    MemoryCurationPreviewRequest, MemoryCurationPreviewResponse, MemoryExposurePolicy,
    MemoryInfluenceClass, MemoryInfluenceReport, MemoryInfluenceToolInput, MemoryInfluenceTrace,
    MemoryInfluenceTraceWriteResult, MemoryInspectorView, MemoryLifecyclePacketView,
    MemoryLifecycleState, MemoryNeed, MemoryRevision, MemoryWriteEnvelope,
    MetaCandidateChangeClass, MetaExperimentDecision, MetaIsolationFence, MetaPolicyAuthorization,
    MetaPolicyExecutionAction, MetricDefinition, MetricSample, MetricWindow,
    MinorityPressureRecord, MinorityPressureStatus, NegativeTransferHarm,
    OPERATOR_CONTRACT_MANIFEST, OPERATOR_IPC_PROTOCOL_VERSION, OPERATOR_SCHEMA_VERSION,
    OperationJob, OperationJobState, OperatorActionView, OperatorCommand, OperatorCommandReceipt,
    OperatorControlRequest, OperatorFieldView, OperatorProjectionFilter, OperatorProjectionKind,
    OperatorProjectionPage, OperatorQueryOperation, OperatorQueryRequest, OperatorRecordView,
    OperatorRelationshipView, OperatorSnapshot, PatchRequest, PatchRequestId,
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
#[allow(clippy::wildcard_imports)]
use cognition::*;
#[allow(clippy::wildcard_imports)]
use verification::*;
mod catalog;
mod delegation;
mod dispatch;
mod evaluation;
mod experiment;
mod finalization;
mod input_validation;
mod memory;
mod operator;
mod replay;
mod skill;
mod task;
mod ul;
mod work;
#[allow(clippy::wildcard_imports)]
use autonomy::*;
#[allow(clippy::wildcard_imports)]
use delegation::*;
#[allow(clippy::wildcard_imports)]
use dispatch::*;
#[allow(clippy::wildcard_imports)]
use evaluation::*;
#[allow(clippy::wildcard_imports)]
use experiment::*;
#[allow(clippy::wildcard_imports)]
use finalization::*;
#[allow(clippy::wildcard_imports)]
use memory::*;
#[allow(clippy::wildcard_imports)]
use operator::*;
#[allow(clippy::wildcard_imports)]
use replay::*;
#[allow(clippy::wildcard_imports)]
use skill::*;
#[allow(clippy::wildcard_imports)]
use task::*;
use ul::UlRuntime;
#[allow(clippy::wildcard_imports)]
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
    "eliot_canonical_status",
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
    "eliot_canonical_status",
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
    "eliot_canonical_status",
    "eliot_worktree_review",
];

fn is_canonical_control_mutation(name: &str) -> bool {
    matches!(
        name,
        "eliot_trace_completeness"
            | "eliot_replay_run"
            | "eliot_sleep_run"
            | "eliot_meta_experiment_run"
            | "eliot_meta_experiment_disposition"
    )
}

fn require_canonical_controller_authority(state: &McpState) -> Result<()> {
    if !matches!(
        state.profile,
        McpAccessProfile::CodexController | McpAccessProfile::HumanOperator
    ) {
        anyhow::bail!("canonical mutation requires codex_controller or human_operator authority");
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
                    && !is_canonical_control_mutation(name)
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
                    && !is_canonical_control_mutation(name)
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
        let ul = Arc::new(UlRuntime::new(store.clone(), writer.clone()));
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul: Arc::clone(&ul),
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
                ul,
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

include!("mcp_stdio/runtime_handlers.rs");

include!("mcp_stdio/task_handlers.rs");

include!("mcp_stdio/provider_handlers.rs");

include!("mcp_stdio/coordination_handlers.rs");

include!("mcp_stdio/protocol_support.rs");

include!("mcp_stdio/work_support.rs");

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
#[serde(deny_unknown_fields)]
struct UnderstandingOutcomeToolInput {
    project_id: String,
    record: UnderstandingOutcomeRecord,
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
struct CanonicalStatusToolInput {
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
    ul: Arc<UlRuntime>,
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
