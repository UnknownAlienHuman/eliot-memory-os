#![forbid(unsafe_code)]

pub mod action;
pub mod adapter;
pub mod admission;
pub mod antigravity;
pub mod codecortex;
pub mod cognition;
pub mod cognitive_disposition;
pub mod cognitive_field;
pub mod cognitive_projection;
pub mod collective;
pub mod context;
pub mod control_plane;
pub mod delegation;
pub mod delegation_calibration;
pub mod error;
pub mod eval;
pub mod external_agent;
pub mod external_review;
pub mod host;
pub mod lifecycle;
pub mod memory_distillation;
pub mod memory_lifecycle;
pub mod metrics;
pub mod patch;
pub mod plugin;
pub mod project_understanding;
pub mod provider_invocation;
pub mod read;
pub mod readiness;
pub mod replay;
pub mod reports;
pub mod runtime;
pub mod runtime_supervision;
pub mod safety;
pub mod semantic_memory;
pub mod service;
pub mod skill;
pub mod skill_curator;
pub mod task_execution;
pub mod ul;
pub mod verification;
pub mod work;
pub mod worktree;
pub mod writer;

pub use action::{ActionLeaseEvaluation, ActionLeaseService};
pub use adapter::{
    Adapter, AdapterMemoryWriter, AdapterObservationBridge, AdapterObservationReport,
    AdapterRegistry, AdapterRegistryReport, AdapterSupervisor, BoxAdapterFuture, HealthAdapter,
    TestEchoAdapter, TestFailingAdapter, TestLargeOutputAdapter, TestSlowAdapter,
    normalize_result_to_observation, test_request,
};
pub use admission::WriteAdmissionService;
pub use antigravity::{
    AgyMcpCompatibilityAuditService, AntigravityAuthCheckService, AntigravityBinaryResolver,
    AntigravityCapabilityProbeService, AntigravityCommandContractService,
    AntigravityDisposableWorktreeSmokeService, AntigravityDoctorIntegration,
    AntigravityEnablementService, AntigravityEnvPolicyService, AntigravityExecutionGate,
    AntigravityGuiProcessProbeService, AntigravityLiveSmokeService, AntigravityMcpBoundaryService,
    AntigravityMcpConfigService, AntigravityOfficialCliInstallerService,
    AntigravityOfficialPluginService, AntigravityRealExecutionDoctor, AntigravityRollbackService,
    AntigravityRunner, AntigravitySafetyPolicy, AntigravityTelemetryService,
    AntigravityTextOutputNormalizer, AntigravityVersionGateService, AntigravityVisibilityService,
    AntigravityWindowsInstallDiscoveryService, BoxProviderProcessFuture, ProviderProcessOutcome,
    ProviderProcessRunner, ProviderProcessSpec, antigravity_real_report, antigravity_report,
    antigravity_review_request,
};
pub use codecortex::{CodeCortexMemoryWriter, CodeCortexService};
pub use cognition::{
    CognitiveExperimentService, CognitiveMemoryWriter, ContextCargoService,
    MemoryInfluenceTraceService, UnderstandingOutcomeService,
};
pub use cognitive_disposition::resolve_canonical_case_dispositions;
pub use cognitive_field::CognitiveFieldGradingService;
pub use cognitive_projection::{
    CognitiveProjectionCoordinator, CognitiveProjectionCoordinatorConfig,
    CognitiveProjectionCoordinatorHandle, CognitiveProjectionMetrics,
    CognitiveProjectionMetricsSnapshot, CognitiveProjectionShutdownHandle,
};
pub use collective::{
    BlackboardAddInput, BlackboardService, CollectiveMemoryWriter, CollectiveTraceService,
    LostAgentRecoveryService, MailboxSendInput, MailboxService, StopCoordinationDecision,
    StopCoordinationGate,
};
pub use context::{
    CognitiveGate, CompletionGate, ContextCompiler, DEFAULT_PACKET_HARD_CEILING_TOKENS,
    PacketAdmissionDecision, PacketAdmissionStatus, PacketBudgetDecision, PacketBudgetPolicy,
    PacketCandidateOutcome, PacketCompileAudit, PacketCompileAuditContext,
    PacketCompileAuditReport, PacketCompileError, PacketCompileMode, PacketCompilePlan,
    PacketCompilePlanInvalid, PacketCompileResult, PacketExperienceSource, PacketGateCandidate,
    PacketGateReason, PacketGateStatus, PacketHardCeilingExceeded, PacketMeasurementView,
    PacketPredictionIntent, PacketPyramidSnapshot, PacketPyramidSource, PacketQualityService,
    PacketRenderMode, PacketRenderOutcome, PacketResolvedCues, PacketSourceReadAudit,
    PacketTaskReceiptMetadata, UnderstandingProofValidator, codecortex_report_ref,
    finalize_packet_candidate, finalize_packet_candidate_with_policy,
    finalize_packet_candidate_with_policy_and_audit_context, packet_return_metadata_tokens,
    packet_section_accounting, refinalize_compiled_packet, resolve_packet_scope_paths,
    serialized_supplement_tokens,
};
pub use control_plane::{
    AutonomyBudgetDecision, AutonomyBudgetLedger, AutonomyLeaseBinding, AutonomyRecoveryAction,
    AutonomyRecoveryReceipt, AutonomyRunService, AutonomyStepIntent, AutonomyTransitionRequest,
    AutonomyTripwireKind, AutonomyTripwirePolicy, AutonomyTripwireRecord, AutonomyWorkItem,
    BoundedAutonomyRuntime, CanonicalR3ApprovalAuthorization, ContourRouteRequest,
    ContourRoutingService, ControlPlaneMemoryWriter,
};
pub use delegation::{
    DelegationBudgetReservation, DelegationBudgetService, DelegationDoctorIntegration,
    DelegationExecutionService, DelegationHealth, DelegationHealthService,
    DelegationOutcomeService, DelegationPolicyContext, DelegationPolicyService,
    DelegationReportService, ProviderCallCampaignRequest, ProviderCallReservationDecision,
    ProviderCallReservationOwner, ProviderCallReservationRequest,
};
pub use delegation_calibration::{
    CalibrationEvidenceGapService, CampaignIntegrityReconciliationService,
    DelegationCalibrationCampaignService, DelegationCalibrationDoctorIntegration,
    DelegationCalibrationIngestService, DelegationCalibrationRollupService,
    DelegationCounterfactualService, DelegationOutcomeEvidence, DelegationOutcomeLabelService,
    DelegationPolicyCandidateService, DelegationPromotionGateService,
    DelegationShadowEvaluationService, IndependentOutcomeEvidenceService,
    PreregisteredCorpusEligibilityService, ProviderReviewPreRegistrationService,
    ProviderUtilityAssessmentService,
};
pub use error::EngineError;
pub use eval::{
    CanonicalMetaExperimentAssessment, CanonicalMetaExperimentInput, EvalBaselineService,
    EvalCaseInput, EvalCaseService, EvalComparisonService, EvalCoverageService,
    EvalDatasetManifestService, EvalDoctorIntegration, EvalFixtureStabilityService,
    EvalGateProfileService, EvalMeasurementService, EvalMemoryWriter, EvalRegressionGate,
    EvalRegressionGateService, EvalRunInput, EvalRunnerService, EvalSuiteInput, EvalSuiteService,
    EvalTrendService, EvalVerdictService, MetaDispositionRequest, MetaDispositionService,
    MetaExperimentAssessment, MetaExperimentGate, MetaExperimentGateResult, MetaExperimentInput,
    MetaHarnessService, MetaIsolationSnapshot, MetaMetricDirection, MetaMetricObservation,
    MetaPolicyExecutor, family_slug, harness_experiment_record, runnable_k0_families,
};
pub use external_agent::{
    AntigravityCommandInput, ClaudeCodeCommandInput, OpenCodeCommandInput, ProviderCommandPlan,
    ProviderTerminalResult, build_antigravity_command, build_claude_code_command,
    build_opencode_command, computed_provider_runtime_contract_sha256,
    normalize_provider_runtime_contract, parse_antigravity_output, parse_claude_code_stream,
    parse_opencode_stream, reject_raw_database_surface, seal_provider_runtime_contract,
    validate_external_agent_execution_request, validate_json_schema_instance,
    validate_provider_runtime_contract,
};
pub use external_review::{
    ExternalProviderRegistryReport, ExternalProviderRegistryService, ExternalReviewBridgeReport,
    ExternalReviewBridgeService, ExternalReviewDoctorStatus, ExternalReviewGate,
    ExternalReviewGateContext, ExternalReviewJobService, ExternalReviewNormalizationOutcome,
    ExternalReviewNormalizer, ExternalReviewPacketBuilder, ExternalReviewReportService,
    ExternalReviewTaintPolicy, external_review_request,
};
pub use host::{
    AgentResultAdmission, AuthorityCleanupReport, DERIVED_SKILL_PACKAGES, ELIOT_SKILL_NAMES,
    HostBrokerService, HostEventService, HostLaunchContractService, HostProfileService,
    PendingRoleGrant, SkillPackEntryReport, SkillPackLintReport, SkillPackService,
    SkillPackSyncReport, bundle_hash, bundle_root, host_generated_bundle_entry,
    host_profile_fingerprint,
};
pub use lifecycle::{BoxServiceFuture, ServiceContext, ServiceHandle, ServiceLifecycle};
pub use memory_distillation::{MEMORY_DISTILLATION_RULESET_VERSION, MemoryDistillationService};
pub use memory_lifecycle::{
    ForgettingPolicyService, MemoryGravityService, MemoryInfluenceService,
    MemoryLifecycleApplyOutcome, MemoryLifecycleGate, MemoryLifecycleMemoryWriter,
    MemoryLifecycleService, MemoryVitalityService, NegativeMemoryGate, NegativeMemoryGateReport,
    memory_pressure_report,
};
pub use metrics::{
    CostLedgerService, MetricRecorderService, MetricRegistryService, MetricRollupService,
    MetricsDoctorIntegration, MetricsMcpBoundaryService, QualitySignalService,
    RuntimeDashboardService, SloService, TelemetryEventService,
};
pub use patch::{PatchMemoryWriter, PatchRunner, PatchRunnerInput, VerifierHarness};
pub use plugin::{EliotHookService, HookProcessingResult};
pub use project_understanding::{ProjectContinuityService, ProjectUnderstandingCompiler};
pub use provider_invocation::{
    ExternalResultCompletenessService, ProviderCompletenessInput, ProviderInvocationJournal,
    ProviderInvocationLifecycleService, ProviderOutputCapture, ProviderOutputSpool,
    ProviderReadinessInput, ProviderReconciliationInput, ProviderReconciliationResult,
    ProviderReconciliationService, ProviderRouteReadinessService, antigravity_plan_route_policy,
};
pub use read::{
    GraphHealthService, ReadService, filter_exact_l2_response, filter_required_exact_l2_response,
};
pub use readiness::classify_startup;
pub use replay::{
    CanonicalReplayExecutionInput, CanonicalTraceCompletenessInput, DreamCandidateService,
    ReplayCaseInput, ReplayCaseObservation, ReplayCaseService, ReplayMemoryWriter,
    ReplayRunnerService, ReplaySafetyGate, ReplaySealBundle, ReplaySealInput, ReplaySealService,
    ReplaySetInput, ReplaySetService, ReplayVerdictService, SealedReplayInput,
    SleepConsolidationService, SleepRunInput, TraceCompletenessInput, TraceCompletenessService,
};
pub use reports::WriterReportService;
pub use runtime::{
    ExchangeEnvelopeService, HealthService, LifecycleService, LogService, ModuleRegistryService,
    ReportService, RuntimeLock, ServiceSupervisor, StaticRuntimeService, builtin_manifests,
    default_runtime_services, shutdown_deadline_after,
};
pub use runtime_supervision::{
    AdapterExecutionContext, CancellationToken, OperationSupervisor, RestartDecision,
    classify_restart,
};
pub use safety::{
    BackupService, BlobGcService, DataRootService, DoctorService, ExportService,
    HistoricalImportMemoryWriter, ImportService, IncidentService, MaintenanceMemoryWriter,
    MaintenanceScheduler, ProductionCutoverService, RestoreService, SurrealLogicalConfig,
    SurrealLogicalService, incident_blocks_unsafe_surfaces,
};
pub use semantic_memory::{
    ApplicabilityService, CognitiveTransferLabService, ContextReinstatementService,
    ContrastiveAbstractionService, CorpusProfileInput, CorpusProfileService,
    ExperienceFormationService, ExperienceRetrievalService, MaturityGateService,
    MemoryKindCompatibilityService, MemoryNeedService, NegativeTransferService, TaskMeaningService,
    TransferValidationEvidence, deduplicate_experience_cases, deduplicate_experience_patterns,
};
pub use service::{
    CredentialProviderService, HookIpcForwarder, IpcGovernorClient, NamedPipeIpcServer,
    ProductionReadinessService, ReadinessFixture, RestartBudgetService, ServiceDoctorIntegration,
    StartupRecoveryService, StdioShimService, WindowsServiceManager, default_ipc_config,
    h1_protocol_version, hash_secret,
};
pub use skill::{
    SkillActivationContext, SkillActivationGate, SkillDistractorFilterService,
    SkillExecutionProofService, SkillInfluenceReportInput, SkillInfluenceService,
    SkillLifecycleService, SkillNeedEstimator, SkillRegistryService,
};
pub use skill_curator::{
    SkillArchiveQuarantineService, SkillCurationGate, SkillCurationReport,
    SkillCurationReportService, SkillCuratorMemoryWriter, SkillCuratorRunInput,
    SkillCuratorService, SkillMergeSplitService, SkillPatchService,
};
pub use task_execution::TaskExecutionClassifier;
pub use ul::{
    ActivationEngine, BoxUlReasoningFuture, BoxUlRefinementFuture, CalibrationService,
    CapsuleEvidence, ConceptSeedResult, CueIndexService, FiredMemory, FiringResult,
    GitMiningArtifacts, GitMiningService, GitMiningStatus, InjectionPlanner, MetacognitionService,
    ModuleCardService, ObservedCue, OnboardingService, PredictionCapture, PredictionCaptureInput,
    PredictionFrameCaptureInput, PredictionMatcherService, PredictionService, PromotedPyramid,
    PyramidBuilder, PyramidDecision, PyramidDependency, PyramidFailure, TouchedCue,
    TouchedSetRegistry, UlArtifactWriteReport, UlArtifactWriterService, UlDependencyService,
    UlExamPlan, UlExamService, UlFieldValidationLoad, UlLedgerAccumulator, UlLedgerService,
    UlMaintenanceService, UlReadinessService, UlReasoningOutcome, UlReasoningRunner,
    UlRefinedProse, UlRefinementAnchor, UlRefinementOutcome, UlRefinementRunner,
    UlRefinementService, UlRefinementTrigger, UlTokenPolicyService, UlToolMeasurement,
    blast_fraction_milli, blast_score, build_cold_exam_request, build_exam_plan, calibration_trend,
    canonical_project_root, capsule_freshness, confidence_probability_milli, dependency_refs,
    diagnostic_expectation_matches, evaluate_task08_readiness, failure_bindings_by_path,
    field_validation_manifest_path, grade_exam, invoke_reasoner_once, is_mutation_tool,
    is_read_class_tool, load_field_validation_manifest, normalize_diagnostic_signature,
    normalize_diagnostic_signatures, normalize_exam_reference, normalize_verifier,
    parse_expected_observable, precision_recall_f1, prediction_id, prediction_id_for,
    refine_capsule_prose, refinement_route, render_capsule, render_capsule_with_dirty,
    resolve_prediction, summarize_field_evidence, validate_refinement_candidate, weekly_exam_due,
    weekly_exam_route,
};
pub use verification::{
    FlakeDetectionService, StatefulDbTestIsolationService, TestCostService, TestInventoryService,
    VerificationDoctorIntegration, VerificationPlannerService, VerificationProfileService,
    VerificationRunnerService, VerificationVerdictService,
};
pub use work::{
    AgentSessionService, WorkClaimRequest, WorkConflictService, WorkCreateRequest,
    WorkLeaseGuardError, WorkLeaseService, WorkMemoryWriter, WorkQueueService, WorkSessionEvent,
    WorkState, WorkStatusReport, default_lease_ttl_minutes, default_work_scope,
    guard_work_lease_for_files, path_in_scope, work_completion_satisfied, work_lease_is_active,
};
pub use worktree::{
    CandidateCompletionContext, CandidateDiffCaptureInput, CandidateDiffService,
    CandidatePatchRequestInput, CandidateReviewInput, CandidateReviewService, WorktreeAdoptInput,
    WorktreeCleanupService, WorktreeCreateInput, WorktreeLeaseService, WorktreeMemoryWriter,
};
pub use writer::{
    CognitiveBeginPrecondition, CognitiveTerminalPrecondition, OperationRuntimeHandle,
    OperationRuntimeProxy, OperationRuntimeRequest, OperationRuntimeResponse, WriterActor,
    WriterConfig, WriterHandle, WriterMetricsSnapshot, WriterRequest, WriterShutdownHandle,
    default_writer_lane_count,
};
