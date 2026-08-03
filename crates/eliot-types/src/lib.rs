#![forbid(unsafe_code)]

pub mod adapter;
pub mod antigravity;
pub mod cognition;
pub mod cognitive_field;
pub mod cognitive_run;
pub mod config;
pub mod delegation;
pub mod delegation_calibration;
pub mod distillation;
pub mod error;
pub mod eval;
pub mod external_agent;
pub mod external_review;
pub mod health;
pub mod host;
pub mod ids;
pub mod lifecycle;
pub mod mcp_contract;
pub mod memory;
pub mod metrics;
pub mod observability;
pub mod project_understanding;
pub mod provider_invocation;
pub mod records;
pub mod replay;
pub mod runtime;
pub mod runtime_supervision;
pub mod safety;
pub mod secret_boundary;
pub mod semantic_memory;
pub mod service;
pub mod skill;
pub mod task_execution;
pub mod ul;
pub mod verification;

pub use adapter::{
    AdapterAuthorityProfile, AdapterCapability, AdapterClass, AdapterContext, AdapterError,
    AdapterHealth, AdapterLimits, AdapterObservation, AdapterRequest, AdapterResult,
    AdapterResultStatus, AdapterState, CapabilityManifest, ProcessExecutionPolicy,
};
pub use antigravity::{
    AntigravityArgvPolicy, AntigravityAuthCheck, AntigravityAuthCheckMethod, AntigravityAuthStatus,
    AntigravityBinaryCandidate, AntigravityBinaryCandidateSource, AntigravityBinaryResolution,
    AntigravityBinaryResolutionStatus, AntigravityBinaryResolverConfig,
    AntigravityBinarySignatureStatus, AntigravityCapabilities, AntigravityCapabilityProbe,
    AntigravityCommandContract, AntigravityContractSource, AntigravityDisableReceipt,
    AntigravityDisposableWorktreeSmokeEvidence, AntigravityDoctorStatus,
    AntigravityEnablementReceipt, AntigravityEnablementScope, AntigravityEnablementState,
    AntigravityEnvPolicy, AntigravityExecutionGateDecision, AntigravityExecutionGateDecisionKind,
    AntigravityGuiProcessProbe, AntigravityLiveSmokeMode, AntigravityLiveSmokeRequest,
    AntigravityLiveSmokeResult, AntigravityLiveSmokeStatus, AntigravityLiveTreeSnapshot,
    AntigravityLogFilePolicy, AntigravityMcpConfigStatus, AntigravityMcpConfigSurface,
    AntigravityMcpInvocationReceipt, AntigravityMcpRegistrationReceipt,
    AntigravityNormalizedResult, AntigravityOfficialCliInstallerReceipt,
    AntigravityOfficialPluginInstallReceipt, AntigravityOfficialPluginStatus,
    AntigravityOutputMode, AntigravityOutputRedactionReceipt, AntigravityPromptPolicy,
    AntigravityProviderState, AntigravityRealDoctorStatus, AntigravityRealReport,
    AntigravityReport, AntigravityReviewMode, AntigravityReviewRequest, AntigravityRun,
    AntigravityRunState, AntigravitySafetyReceipt, AntigravitySandboxPolicy,
    AntigravitySensitivePathPolicy, AntigravitySessionPolicy, AntigravityStdinMode,
    AntigravityTelemetryReport, AntigravityTrustReceipt, AntigravityVersionGateResult,
    AntigravityVersionGateStatus, AntigravityVisibilityReport, AntigravityWindowsInstallDiscovery,
    AntigravityWorkdirPolicy,
};
pub use cognition::{
    ActiveDecisionState, AgentRoutingView, ApprovalView, AutonomyRecoveryRecord,
    AutonomyRunContract, AutonomyRunState, AutonomyRunTransitionReceipt, AutonomyRunView,
    AutonomyTripwireKind, CausalBridgeHop, ContextCargoReceipt, ContourPolicyScope,
    ContourPreferredRoute, ContourRouteDecision, ContourRoutePolicy, CurrentTruthSnapshot,
    DecisionLocalitySuffix, EpistemicPacketState, LiveContourRoute, MaterialPacketFrame,
    MemoryAdmissionDecision, MemoryCurationCandidate, MemoryCurationCorpusProfile,
    MemoryCurationFindingKind, MemoryCurationPreviewRequest, MemoryCurationPreviewResponse,
    MemoryDecisionReceipt, MemoryInfluenceClass, MemoryInfluenceTrace, MemoryInspectorView,
    MemoryValueComparison, MemoryValueExperiment, NegativeMemoryDecision,
    NegativeMemoryDecisionReceipt, NegativeMemoryGateInput, OPERATOR_CONTRACT_MANIFEST,
    OPERATOR_IPC_PROTOCOL_VERSION, OPERATOR_SCHEMA_VERSION, OperatorActionView, OperatorCommand,
    OperatorCommandReceipt, OperatorControlRequest, OperatorFieldView, OperatorProjectionFilter,
    OperatorProjectionKind, OperatorProjectionPage, OperatorQueryOperation, OperatorQueryRequest,
    OperatorRecordView, OperatorRelationshipView, OperatorResultMode, OperatorSnapshot,
    PacketQualityReport, PacketQualityResult, PlanningDecisionRecord, PredictionConfidence,
    ResponsibilityContour, TaskCognitionView, TraceTimelineView, UnderstandingOutcome,
    UnderstandingOutcomeRecord, WaivedInvariant, operator_contract_hash,
};
pub use cognitive_field::{
    COGNITIVE_CORE_CONTINUATION_EXPECTED_PROVIDER_CALLS,
    COGNITIVE_CORE_CONTINUATION_MAX_PROVIDER_CALLS, COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION,
    COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS, COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
    COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION,
    COGNITIVE_FIELD_MAX_PROVIDER_CALLS, COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION,
    COGNITIVE_FIELD_PLAN_SCHEMA_VERSION, COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION,
    COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION,
    COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION, COGNITIVE_FIELD_SUITE_SCHEMA_VERSION,
    COGNITIVE_FIELD_V2_HARNESS_VERSION, COGNITIVE_FIELD_WORKER_SCHEMA_VERSION,
    COGNITIVE_JUDGE_SCHEMA_VERSION, COGNITIVE_UNDERSTANDING_SCHEMA_VERSION,
    CognitiveDeterministicEvidenceReceipt, CognitiveDeterministicReport, CognitiveFieldCase,
    CognitiveFieldCaseGrade, CognitiveFieldCausalHop, CognitiveFieldExecutionKey,
    CognitiveFieldFamily, CognitiveFieldPlan, CognitiveFieldPlanItem,
    CognitiveFieldProviderCallPlan, CognitiveFieldProviderEvidenceReceipt,
    CognitiveFieldProviderOutputProjection, CognitiveFieldProviderOutputReceipt,
    CognitiveFieldProviderPlan, CognitiveFieldProviderProjection, CognitiveFieldRole,
    CognitiveFieldRunContract, CognitiveFieldSuite, CognitiveFieldTier,
    CognitiveFieldValidationReport, CognitiveHardGateEvidence, CognitiveHardGateKind,
    CognitiveJudgeDiscrepancy, CognitiveJudgeResult, CognitiveJudgeScores,
    CognitiveMemoryCondition, CognitiveOracleLeakFinding, CognitiveOracleLeakReport,
    CognitiveRepositoryCondition, CognitiveSecondRepositoryPolicy, CognitiveUnderstandingAnswer,
    CognitiveVerifierCommandReceipt, CognitiveWorkerResult, TaskIntentOracle,
    cognitive_judge_result_schema, cognitive_understanding_answer_schema,
    cognitive_worker_result_schema, minimal_cognitive_judge_result,
    minimal_cognitive_understanding_answer,
};
pub use cognitive_run::{
    COGNITIVE_RUN_EXACT_CALLS, COGNITIVE_RUN_RAW_VERIFIER_CALLS, COGNITIVE_RUN_SCHEMA_VERSION,
    CanonicalCaseDisposition, CognitiveCandidateCapability, CognitiveExecutionSeal,
    CognitiveHostObservation, CognitiveInvocationRole, CognitiveRawVerifierEvidence,
    CognitiveRunAttempt, CognitiveRunCallPlan, CognitiveRunCallStatus, CognitiveRunContract,
    CognitiveRunTerminal, CognitiveSharedGateBinding, CognitiveToolObservation,
};
pub use config::{
    BlobStoreConfig, ControlWalConfig, DbConfig, DbMode, DelegationCalibrationConfig,
    GovernorConfig, RuntimeSupervisionConfig, ServiceConfig, StoreConfig, SurrealCapabilities,
    SurrealServerConfig, UlActivationConfig, UlConfig,
};
pub use delegation::{
    DelegationBudget, DelegationDecision, DelegationDecisionKind, DelegationJob,
    DelegationJobState, DelegationOrigin, DelegationOriginChain, DelegationOutcome,
    DelegationOutcomeStatus, DelegationProviderPreference, DelegationPublicStatus,
    DelegationReason, DelegationRequest, DelegationReviewKind, DelegationReviewResponse,
    DelegationRootOrigin, DelegationState, ProviderCallBudgetState, ProviderCallLedger,
    ProviderCallReservation, ProviderCallReservationState,
};
pub use delegation_calibration::{
    CalibrationCompleteness, CalibrationCorpusEligibility, CalibrationCorpusSampleKind,
    CalibrationEvidenceClass, CalibrationEvidenceCounts, CalibrationEvidenceGapReport,
    CalibrationExcludedCounts, CalibrationIntegrityStatus, CampaignIntegrityIncidentDetails,
    CampaignIntegrityIncidentStatus, CampaignIntegrityRootCauseStatus, DelegationBudgetChange,
    DelegationCalibrationCampaign, DelegationCalibrationCampaignBudget,
    DelegationCalibrationCampaignCloseoutStatus, DelegationCalibrationCampaignState,
    DelegationCalibrationCampaignTransition, DelegationCalibrationCosts,
    DelegationCalibrationLabels, DelegationCalibrationReadiness, DelegationCalibrationSample,
    DelegationCalibrationState, DelegationCalibrationTaskFamily, DelegationCounterfactualKind,
    DelegationCounterfactualLabel, DelegationEvidenceFloorSnapshot, DelegationFamilyCalibration,
    DelegationFindingMateriality, DelegationPolicyCandidate, DelegationPolicyCandidateStatus,
    DelegationPolicyPromotionDecision, DelegationPolicyPromotionDecisionKind,
    DelegationPolicyPromotionReason, DelegationPromotionReadinessVerdict,
    DelegationShadowDecisionKind, DelegationShadowRecord, DelegationTriggerChange,
    DelegationTriggerChangeKind, ExecutedProviderReview, ExecutedProviderReviewStatus,
    FrozenInputDigest, IndependentEvidenceContaminationChecks, IndependentEvidenceKind,
    IndependentEvidenceResult, IndependentOutcomeEvidence, ProviderCallLineage,
    ProviderCallLineageTerminalState, ProviderFindingDisposition, ProviderFindingMateriality,
    ProviderFindingNovelty, ProviderFindingVerdict, ProviderReviewPreRegistration,
    ProviderUtilityAssessment, ProviderUtilityReason,
};
pub use distillation::{
    CanonicalMemoryUtilityLedger, MemoryCompressionArtifact, MemoryDistillationAction,
    MemoryDistillationApplyReceipt, MemoryDistillationApplySelection, MemoryDistillationCandidate,
    MemoryDistillationCheckpoint, MemoryDistillationCorpusItem, MemoryDistillationCorpusProfile,
    MemoryDistillationFinding, MemoryDistillationInput, MemoryDistillationPlan,
    MemoryDistillationScheduleRequest, MemoryDistillationTrigger, MemoryTier,
    MemoryUtilityLedgerEntry, MemoryUtilitySignalKind, MemoryUtilitySourceRecord,
    memory_compression_artifact_schema, memory_distillation_plan_schema,
    memory_distillation_schedule_schema,
};
pub use error::ConfigError;
pub use eval::{
    BenchmarkIntegrityReceipt, CanonicalMetaExperimentRecordSet, CanonicalMetaMetricEvidence,
    EvalBaseline, EvalBudget, EvalCandidateComparison, EvalCase, EvalCaseResult, EvalCaseStatus,
    EvalComparisonVerdict, EvalComponentCoverage, EvalCoverageMatrix, EvalCoverageStatus,
    EvalCriterion, EvalDatasetManifest, EvalFailureCluster, EvalFamily, EvalFamilyCoverage,
    EvalFamilyDelta, EvalFamilyScore, EvalFamilyThreshold, EvalFamilyTrend, EvalFixtureChecksum,
    EvalFixtureStabilityReport, EvalGateDecision, EvalGateDecisionKind, EvalMeasurementKind,
    EvalMeasurementResult, EvalMeasurementSpec, EvalRegressionGateProfile, EvalRegressionSeverity,
    EvalRiskCoverage, EvalRun, EvalRunProfile, EvalRunStatus, EvalSuite, EvalTrendDirection,
    EvalTrendReport, EvalVerdict, EvalVerdictStatus, ExperimentalMetaPolicyCandidate,
    ExperimentalMetaPolicyPayload, ExperimentalMetaPolicyState, HarnessExperimentRecord,
    MetaCandidateChangeClass, MetaExperimentDecision, MetaIsolationFence,
    MetaIsolationRejectionRecord, MetaPolicyAuthorization, MetaPolicyExecutionAction,
    MetaPolicyExecutionReceipt, ReplayThresholdPolicyV1,
};
pub use external_agent::{
    ExternalAgentExecutionRequest, ExternalAgentPurpose, OPERATION_AUTHORITY_SCHEMA_VERSION,
    OperationAuthorityCloseReceipt, OperationAuthorityCloseRequest, OperationAuthorityOpenReceipt,
    OperationAuthorityOpenRequest, OperationAuthorityTerminalOutcome,
    PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION, PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
    ProviderAuthenticationState, ProviderExecutionEvidence, ProviderMcpServerContract,
    ProviderMcpToolProfileBinding, ProviderRuntimeContract, ProviderRuntimePreflightReceipt,
    ProviderStructuredOutputMode,
};
pub use external_review::{
    ExternalCitationStatus, ExternalClaimStatus, ExternalEvidenceCitation, ExternalFindingSeverity,
    ExternalForbiddenAction, ExternalOutputSchemaKind, ExternalProposedChange,
    ExternalProposedChangeKind, ExternalProviderAuthority, ExternalProviderKind,
    ExternalProviderLimits, ExternalProviderProfile, ExternalProviderTransport,
    ExternalReviewBudget, ExternalReviewFinding, ExternalReviewGateDecision,
    ExternalReviewGateDecisionKind, ExternalReviewGateReason, ExternalReviewJob,
    ExternalReviewJobStatus, ExternalReviewNormalizationReceipt, ExternalReviewPacket,
    ExternalReviewRequest, ExternalReviewResult, ExternalReviewResultStatus, ExternalReviewRole,
    ExternalUncertainty, ExternalVerifierSuggestion,
};
pub use health::{ComponentHealth, HealthStatus, StartupHealthReport};
pub use host::{
    AgentCapabilityEnvelope, AgentHostId, AgentHostIdentity, AgentHostRuntimeProfile,
    AgentInvocationRequest, AgentResultDisposition, AgentResultDispositionKind,
    AgentResultEnvelope, AgentResultStatus, AgentSessionHostBinding, AgentSessionState,
    AuthorityLeaseLifetime, AuthorityLeaseState, AuthorityRevocationReceipt, ClaudeSurface,
    ControllerLease, HostContextFootprintReport, HostEventEnvelope, HostIntegrationReceipt,
    HostLaunchContract, HostLaunchScope, HostMode, HostProfileStatus, HostProtocolSurfaces,
    OperationJob, OperationJobState, TaskRoleLease,
};
pub use ids::{
    ActionLeaseId, ActionRequestId, AgentId, AgentRunId, AgentSessionId,
    BenchmarkIntegrityReceiptId, BlackboardItemId, CandidateDiffId, ClaimId, DreamCandidateId,
    EvalCaseId, EvalDatasetManifestId, EvalFailureClusterId, EvalRunId, EvalSuiteId, EvalVerdictId,
    EvidenceId, HarnessExperimentRecordId, MailboxMessageId, MemoryRevision, ModuleId, OperationId,
    PatchRequestId, PatchRunId, ProjectId, ProjectSequence, ReceiptId, ReplayCaseId, ReplayRunId,
    ReplaySetId, SessionId, SkillId, TaskId, VerificationId, VerifierRunId, WorkItemId,
    WorkLeaseId, WorktreeLeaseId, WorktreeLeaseRequestId, WriteId,
};
pub use lifecycle::{
    ArchiveReceipt, CapabilityMemoryIndex, DecisionDeltaRecord, DemotionReceipt,
    ForgettingOperator, ForgettingPolicy, ForgettingReason, MemoryAuditSuspension,
    MemoryEcologyDecision, MemoryGravity, MemoryInfluenceReport, MemoryLifecycleApplyReport,
    MemoryLifecycleDecision, MemoryLifecyclePacketView, MemoryLifecycleProposalReport,
    MemoryLifecycleReport, MemoryLifecycleState, MemoryLifecycleStatusReport, MemoryPressureReport,
    MemoryStateTransition, MemoryTrajectoryCorrectness, MemoryVitalityScore,
    MinorityPressureRecord, MinorityPressureStatus, ReactivationCondition, RevisionOperator,
    SupersessionReceipt, SuppressionReceipt,
};
pub use mcp_contract::{
    AgentCandidateCurationInput, AgentCandidateSubmitInput, CompilePacketToolInput, InvalidField,
    ToolInputError, ToolInputErrorData, agent_candidate_input_schema, compile_packet_input_schema,
    compile_packet_minimal_example,
};
pub use memory::{
    ActionKind, ActionLease, ActionLeaseRecord, ActionProvenanceSet, ActionRequest, ActionScope,
    ActionSourceScope, ActiveDecisionTransitionCommand, AgentContributionTrace,
    AgentResultRecordCommand, AgentRole, AgentRun, AgentRunStatus, AgentSession,
    AgentSessionStatus, AgentTransport, AuthorityPermission, AuthorityProfile, BlackboardItem,
    BlackboardItemKind, BlackboardItemStatus, BlackboardScope, BlastRadiusView, CandidateDiff,
    CandidateDiffStatus, CandidateReview, CandidateReviewDecision, ChangePlan, ClaimCard,
    ClaimCardInput, ClaimProposeCommand, ClaimSummary, ClaimSupportCommand, ClaimVerifyCommand,
    CodeCortexPacketView, CodeCortexReport, CodeCortexRequest, CodeCortexScopeBinding,
    CodeEvidenceSource, CognitiveGateDecision, CognitiveGateOutcome, CognitiveGateReason,
    CognitiveGateRequest, CognitiveProjectionReadState, CollectiveTrace, CommandContext,
    CompilePacketL3Request, CompletionAcceptanceItem, CompletionDecisionMemory,
    CompletionGateDecision, CompletionMemoryAdmission, CompletionMemoryRequest, CompletionProof,
    CompletionProofSubmitCommand, CompletionStatus, ConfidenceLevel, ContextPacketL3,
    ContributionEffect, ControllerCommitHandoff, CountByName, CurrentStateRequest,
    CurrentStateResponse, DiagnosticBatchRecordCommand, DiagnosticEvidence, EliotHookEvent,
    EpistemicStatus, EvidenceAtom, EvidenceAtomInput, EvidenceIngestCommand, FailureFingerprint,
    FailureFingerprintInput, FailureRecordCommand, FailureSummary, FetchAtomsL2Request,
    FetchAtomsL2Response, FileChangeIntent, FileChangeKind, FileEvidence, GraphHealthResponse,
    HookDecision, HookDecisionReason, HookEventKind, HookProcessingStatus, HookSpoolRecord,
    IdempotencyOptions, InvariantCard, L0CollapsedDuplicateTrace, L0FeatureScore, L0RankTrace,
    L0SuppressionTrace, LeaseDecision, LeaseDenyReason, LeaseStatus, LifecycleStatus,
    LifecycleWriteOptions, LostAgentRecoveryRecord, MailboxMessage, MailboxMessageKind,
    MailboxMessageStatus, MailboxRecipient, MemoryConfidence, MemoryHandlePreview,
    MemoryWriteEnvelope, MemoryWriteEnvelopeInput, MemoryWriteEnvelopeValidated, OperationStatus,
    PatchRequest, PatchRun, PatchRunStatus, PathRef, ProbeRecordCommand, ProjectRevisionSummary,
    ReadConsistencyMode, RecallL0Request, RecallL0Response, RecoveryAction, RejectedCandidateTrace,
    RelationInput, RelationSummary, RelationType, RiskTier, SemanticCommand, SemanticCommandKind,
    SourceSnapshotInput, SymbolChangeIntent, SymbolEvidence, TaintClass,
    TaskAcceptanceEvidenceKind, TaskAcceptanceItem, TaskContract, TaskContractInput,
    TaskContractStatus, TaskContractWriteCommand, TokenBudgetReport, ToolObservation,
    ToolObservationInput, ToolObservationRecordCommand, TruncationInfo,
    UlArtifactBatchRecordCommand, UlMemoryArtifact, UnderstandingProof, UnderstandingProofReceipt,
    UnifiedDiff, VerificationRecordCommand, VerificationResult, VerificationRun,
    VerificationRunInput, VerifierArtifactRef, VerifierArtifactScope, VerifierCommandKind,
    VerifierEffectTrace, VerifierEvidence, VerifierPlan, VerifierRequirement, VerifierRun,
    VerifierRunRef, VerifierStatus, Visibility, WorkConflict, WorkConflictKind,
    WorkConflictResolution, WorkItem, WorkItemStatus, WorkLease, WorkLeaseDecision,
    WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseState, WorkScope, WorktreeLease,
    WorktreeLeaseRequest, WorktreeLeaseState, WriteReceipt, WriteReceiptRef, WriteRejectReason,
    WriteStatus, WriterStatusResponse,
};
pub use metrics::{
    CostLedger, CostLedgerEntry, DashboardHealthStatus, DashboardHealthSummary, DashboardReport,
    LatencyHistogram, MetricDefinition, MetricKind, MetricLabel, MetricLabelDefinition,
    MetricRedactionPolicy, MetricRetentionPolicy, MetricRollup, MetricSample, MetricSeries,
    MetricUnit, MetricWindow, MetricsDoctorStatus, OperationalTrend, OperationalTrendDirection,
    QualitySignal, QualitySignalKind, RuntimeDashboard, SloBreachSeverity, SloDefinition,
    SloEvaluation, SloObjective, TelemetryEvent, TelemetryEventKind, TelemetryRollup,
};
pub use observability::{
    MemoryInfluenceToolInput, MemoryInfluenceTraceWriteInput, MemoryInfluenceTraceWriteResult,
    OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind, ObservabilityWriteEnvelope,
    ObservabilityWriteReceipt, ObservabilityWriteStatus, memory_influence_trace_write_input_schema,
};
pub use project_understanding::{
    CausalHopKind, CausalHopStatus, ContinuityAcceptanceState, ContinuityGitState,
    PROJECT_UNDERSTANDING_SCHEMA_VERSION, ProjectCausalHop, ProjectCausalModel,
    ProjectContinuityState, ProjectUnderstandingEvidence, ProjectUnderstandingIntent,
    ProjectUnderstandingModel, ProjectUnderstandingSystem,
};
pub use provider_invocation::{
    ExternalResultCompletenessReceipt, ProviderDeclaredBudget, ProviderFailureIncident,
    ProviderIdentityCheck, ProviderInvocationAttempt, ProviderInvocationOutcome,
    ProviderInvocationOutcomeClass, ProviderInvocationState, ProviderInvocationTransition,
    ProviderReconciliationMethod, ProviderReconciliationRecord, ProviderResultCompleteness,
    ProviderRootCauseStatus, ProviderRoutePolicy, ProviderRoutePolicyBinding,
    ProviderRouteReadinessGate, ProviderRouteReadinessVerdict, ProviderTimeoutClass,
    ProviderTimeoutProfile,
};
pub use records::{
    BlobRef, CANONICAL_MEMORY_SCHEMA_VERSION, CANONICAL_MEMORY_SEGMENT_TARGET_BYTES,
    CanonicalMemoryL2Page, CanonicalMemoryManifest, CanonicalMemorySegment,
    CanonicalMemorySegmentRef, HealthRecord, MigrationRecord,
};
pub use replay::{
    CANONICAL_TRACE_EVIDENCE_PART_COUNT, CanonicalReplayAuthority, CanonicalReplayExecutionRecord,
    CanonicalReplayObservationEvidence, CanonicalTraceCompletenessContract,
    CanonicalTraceDerivation, CanonicalTraceEvidence, CanonicalTraceEvidenceKind,
    CanonicalTraceEvidenceSource, CanonicalTraceReceiptBinding, DreamCandidate, DreamCandidateKind,
    MemorySynthesisTaint, MemorySynthesisTaintReason, MissingTracePart, ProhibitedDreamEffect,
    ReplayAudit, ReplayCase, ReplayCaseKind, ReplayCaseResult, ReplayCaseStatus, ReplayDecision,
    ReplayInputSnapshot, ReplayMeasurement, ReplayMeasurementResult, ReplayRun, ReplayRunProfile,
    ReplayRunStatus, ReplaySet, ReplaySetRole, ReplaySuccessCriterion, ReplayVerdict,
    SealedReplayCaseRecord, SealedReplayInputSnapshotRecord, SealedReplaySetRecord,
    SleepCandidateArtifact, SleepCandidateArtifactKind, SleepConsolidationBundle,
    SleepConsolidationRun, SleepConsolidationStatus, SleepInputScope, SleepOutputKind,
    SleepOutputRef, SleepTrigger, TraceCompletenessContract,
};
pub use runtime::{
    AuthorityHeader, CausalityHeader, EliotExchangeEnvelope, EliotLogEvent, EndpointDirection,
    ExchangeKind, ExchangeParty, LogEventKind, LogLevel, ModuleAuthorityProfile, ModuleCapability,
    ModuleEndpoint, ModuleHealth, ModuleKind, ModuleManifest, ModuleRegistryReport,
    ModuleResourceLimits, ModuleTransport, RedactionInfo, RuntimeConfig, RuntimeHealthReport,
    RuntimeIpcConfig, RuntimeLocalConfig, RuntimeLogReport, RuntimeLoggingConfig, RuntimeMode,
    RuntimeModulesConfig, RuntimeStatusReport, SchemaRef, ServiceHealthState, ServiceRuntimeStatus,
};
pub use runtime_supervision::{
    AdapterCircuitState, OPERATION_RESTART_WINDOW_SCHEMA_VERSION,
    OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION, OperationCancellationState, OperationPhase,
    OperationReconciliationState, OperationRestartWindow, OperationRuntimeCheckpoint,
    ProcessReapReceipt, ProviderDispatchState, RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION,
    RuntimeAdapterHealth, RuntimeAuthorityIntegrity, RuntimeCoreHealth, RuntimeIntegrityHealth,
    RuntimeOperationDetail, RuntimeOperationHealth, RuntimeOverallStatus, RuntimeReconcileDecision,
    RuntimeReconcileDryRun, RuntimeSupervisionReport, SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION,
    SealStagingCheckpoint, SealStagingState,
};
pub use safety::{
    BackupBlobEntry, BackupChecksum, BackupInventoryEntry, BackupKind, BackupManifest,
    BackupReceipt, BackupReport, BackupStatus, BlobDeletionCandidate, BlobGcPlan, BlobGcReceipt,
    BlobGcStatus, BlobManifest, BlobManifestEntry, BlobReachabilityRef, BlobReferenceSnapshot,
    BlobReport, BlobRetentionClass, BlobRetentionRef, DataRootCheck, DataRootCheckStatus,
    DataRootMode, DataRootProfile, DataRootValidation, DataRootValidationStatus, DoctorReport,
    ExportBundle, ExportKind, HistoricalImportEnvelope, HistoricalImportPreview,
    HistoricalImportQuarantine, HistoricalImportReceipt, HistoricalImportStatus, ImportKind,
    ImportPlan, ImportValidation, IncidentKind, IncidentRecord, IncidentReport, IncidentSeverity,
    IncidentStatus, MaintenanceJob, MaintenanceJobKind, MaintenanceJobStatus, OperationsCheck,
    OperationsDoctorReport, ProductionCutoverManifest, RedactionProfile, RestoreCheck, RestoreMode,
    RestorePlan, RestoreReceipt, RestoreReport, RestoreRollbackReceipt, RestoreStatus,
};
pub use secret_boundary::{
    MAX_SECRET_BOUNDARY_BYTES, SecretBoundaryRule, SecretBoundaryViolation, inspect_secret_bytes,
};
pub use semantic_memory::{
    ApplicabilityVerdict, CandidateReasoningJobOutput, CausalBridgeQualityReport,
    CognitiveCaseResult, CognitiveCaseSpec, CognitiveFailureLocalizationReport,
    CognitiveFailureStage, CognitiveHiddenEssence, CognitiveReaderAnswer,
    CognitiveTransferLabReport, CognitiveTransferMetrics, ContextReinstatementBundle,
    ContrastiveAbstractionResult, ExperienceAuthority, ExperienceBrief, ExperienceCase,
    ExperienceCausalModel, ExperienceFormationResult, ExperienceInterventionOutcome,
    ExperienceMaturity, ExperienceMaturityState, ExperiencePattern, ExperienceProblemFrame,
    ExperienceRecallRequest, ExperienceRecallResponse, ExperienceTransferBoundary,
    ExperienceUseOutcome, FusedRankRoute, FusedRankTrace, MemoryApplicabilityDecision,
    MemoryCorpusProfile, MemoryExposureMode, MemoryExposurePolicy, MemoryKind, MemoryNeed,
    MemoryNeedDecision, NegativeTransferHarm, NegativeTransferLifecycleAction,
    NegativeTransferRecord, ReasoningJobKind, SourceBranchCommitEnvironment, TaskMeaningFrame,
    VerifiedEpisodeProjection,
};
pub use service::{
    CredentialDiagnosticsReport, CredentialProviderKind, CredentialPurpose, CredentialRef,
    CredentialStatus, IpcAuthenticationProfile, IpcConfig, IpcFrame, IpcFrameKind, IpcHandshake,
    IpcHandshakeDecision, IpcHandshakeReason, IpcStatusReport, ServiceAccountRef,
    ServiceInstallAction, ServiceInstallReceipt, ServiceInstallStatus, ServiceReadinessCheck,
    ServiceReadinessProbe, ServiceReadinessStatus, ServiceRestartPolicy, ServiceRestartReason,
    ServiceRestartReceipt, ServiceRestartStatus, ServiceStartType, ServiceStatusReport,
    StartupRecoveryReceipt, StartupRecoveryStatus, WindowsServiceConfig,
};
pub use skill::{
    ProceduralSkillPacketView, ProcedurePromotionOutcome, SkillActivationDecision,
    SkillActivationRecord, SkillArchiveProposal, SkillCardV2, SkillConflict, SkillCurationAction,
    SkillCurationDecisionKind, SkillCurationExpectedEffect, SkillCurationGateDecision,
    SkillCurationGateReason, SkillCurationProposal, SkillCurationReason, SkillCurationReceipt,
    SkillCurationRejectedAction, SkillCurationRisk, SkillCurationRollbackPlan, SkillCuratorRun,
    SkillCuratorRunStatus, SkillDistractorFilter, SkillExecutionOutcome, SkillExecutionProof,
    SkillFailureMode, SkillInfluenceReport, SkillInputRequirement, SkillInputSource,
    SkillInteractionMatrix, SkillLevel, SkillLifecycleRecord, SkillLifecycleState,
    SkillMergeProposal, SkillNeedEstimate, SkillNeedVerdict, SkillOrderingRule, SkillOutputSpec,
    SkillPatchProposal, SkillQuarantineProposal, SkillReplayRequirement, SkillScopeRule,
    SkillSplitProposal, SkillStep, SkillToolRequirement,
};
pub use task_execution::{
    TaskExecutionAction, TaskExecutionArtifact, TaskExecutionClass, TaskExecutionClassSource,
    TaskExecutionDomain,
};
pub use ul::activation::{
    ACTIVATION_SCALE, ACTIVATION_THRESHOLD, ActivationEdgeKind, ActivationNode, ActivationTrace,
    SuppressedActivation, UlActivationGraphEdge, UlActivationGraphRows,
};
pub use ul::artifact::UlArtifact;
pub use ul::behavior::{
    CoChangeEdge, FIX_CLASSIFIER_VERSION, HotspotScore, MiningConfig, MiningRun,
};
pub use ul::concept::{
    CapsuleBuild, CapsuleFreshness, ConceptKind, ConceptNode, DependencyManifest, FileDependency,
    ModuleCard, ProjectCharter, PyramidBuildStatus, PyramidTargetKind, SubsystemCapsule,
    SystemFlow, SystemMap,
};
pub use ul::concept::{CoverageClass, DangerPath, SubsystemCoverage, UlMetacognitionView};
pub use ul::cross_agent::{
    UL_CROSS_AGENT_CONFIRMATION_TOKEN, UL_CROSS_AGENT_EXACT_CALLS, UL_CROSS_AGENT_EXACT_CALLS_U8,
    UL_CROSS_AGENT_REPORT_SCHEMA_VERSION, UL_CROSS_AGENT_SCHEMA_VERSION, UlCrossAgentCase,
    UlCrossAgentContaminationReceipt, UlCrossAgentDirection, UlCrossAgentDirectionEvidence,
    UlCrossAgentDirectionScore, UlCrossAgentDispatchDecision, UlCrossAgentInputDigest,
    UlCrossAgentInvocationState, UlCrossAgentMemoryMode, UlCrossAgentPlan, UlCrossAgentPlannedCall,
    UlCrossAgentReaderOutput, UlCrossAgentReport, UlCrossAgentRole, UlCrossAgentScoreCheck,
    UlCrossAgentSuite, UlCrossAgentWriterOutput, scan_ul_cross_agent_reader_inputs,
    ul_cross_agent_dispatch_decision,
};
pub use ul::cue::{
    CueBinding, CueBindingError, CueBindingPage, CueIndexRow, CueKind, CueMatchMode,
    CueRecordSource, CueStrength, MAX_CUE_BINDING_PAGE_BYTES, MAX_CUE_BINDINGS_PER_PAGE,
    cue_binding_page_id, cue_binding_page_set_hash, cue_row_id, normalize_binding,
    normalize_binding_pages, normalize_bindings, ul_token_estimate,
};
pub use ul::dependency::{
    UlArtifactDirtyState, UlDependencyKind, UlDependencyRebuildReport, UlDependencyRef,
    UlDirtyReason, UlMaintenanceReport, UlReverseDependencyRow,
};
pub use ul::exam::{
    UlExamAnswer, UlExamGrade, UlExamQuestion, UlExamQuestionKind, UlExamRecord,
    UlReasoningRequest, UlReasoningRoute,
};
pub use ul::guard::{TextEncodingViolation, inspect_text_encoding, mojibake};
pub use ul::injection::{
    InjectionReceipt, MAX_DURABLE_PENDING_INJECTIONS_PER_SESSION, MemoryInfluenceAckInput,
    ObservedCue, PENDING_INJECTION_BATCH_SCHEMA_VERSION, PendingInjectionBatch,
    PendingInjectionItem, UlFiredBlock, UlFiredItem, pending_injection_batch_write_id,
    pending_injection_write_id,
};
pub use ul::measurement::{
    UL_FIELD_VALIDATION_BASELINE_COMMIT, UL_FIELD_VALIDATION_SCHEMA_VERSION, UlArtifactInventory,
    UlExperimentArm, UlFeatureReadiness, UlFieldEvidenceSummary, UlFieldTaskAnnotation,
    UlFieldValidationManifest, UlGraphInventory, UlHostSurfaceIncident, UlInjectionMode,
    UlLedgerDelta, UlPredictionInventory, UlProseFailureSignal, UlReadinessInventory,
    UlReadinessSnapshot, UlReadinessState, UlSecondRepositoryValidation, UlTask08Readiness,
    UlTaskClass, UlTaskClassPolicy, UlTaskExperimentAssignment, UlTaskLedger, UlUseReport,
};
pub use ul::normalize::{
    command_pattern, error_signature, normalize_observed_path, normalize_path,
    normalize_query_tokens, normalize_symbol, normalize_unicode_lowercase, path_cue_tokens,
    path_matches_boundary,
};
pub use ul::onboarding::{
    ManifestPackage, OnboardingCheckpoint, OnboardingJob, OnboardingReport, OnboardingStage,
    OnboardingTestHook,
};
pub use ul::prediction::{
    BlastScore, CalibrationScore, CalibrationTrend, DiagnosticExpectation, PredictionExpectation,
    PredictionRecord, PredictionResolution, UlPrediction, UlPredictionActual,
};
pub use verification::{
    FlakeReport, SkippedTest, SkippedTestReason, StatefulDbIsolationReport, TestCostClass,
    TestCostReport, TestCountByCost, TestCountByIntent, TestCountByKind, TestIntent, TestInventory,
    TestKind, TestMetadata, TestStatefulness, TestSuiteProfile, VerificationCommandResult,
    VerificationCommandStatus, VerificationDecision, VerificationDoctorStatus, VerificationPlan,
    VerificationRun as ProfileVerificationRun, VerificationRunStatus, VerificationRuntimeClass,
    VerificationVerdict,
};

pub const SCHEMA_VERSION: &str = "1";
