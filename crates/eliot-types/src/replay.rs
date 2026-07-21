use crate::{
    DreamCandidateId, MemoryRevision, ProjectId, ReplayCaseId, ReplayRunId, ReplaySetId,
    SemanticCommandKind, SkillId, SkillReplayRequirement, TaintClass, TaskId, WriteId,
    WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceCompletenessContract {
    pub contract_id: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub trace_ref: String,
    pub required_inputs: Vec<String>,
    pub required_context_snapshot: Vec<String>,
    pub required_tool_records: Vec<String>,
    pub required_verifier_records: Vec<String>,
    pub required_artifact_refs: Vec<String>,
    pub required_policy_refs: Vec<String>,
    pub missing_trace_parts: Vec<MissingTracePart>,
    pub replay_allowed: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingTracePart {
    UserPrompt,
    TaskContract,
    ContextPacket,
    UnderstandingProof,
    CognitiveGateDecision,
    CodeCortexReport,
    WorkLease,
    ActionLease,
    PatchRun,
    VerifierRun,
    CompletionProof,
    CompletionGateDecision,
    ArtifactRef,
    PolicySnapshot,
    SkillExecutionProof,
    MemoryInfluenceReport,
    SkillInfluenceReport,
    CurrentTruthRevision,
    MemoryExposureSet,
    AgentToolEvents,
    ModelRoute,
    OutcomeAndCost,
    FinishDecision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayCase {
    pub replay_case_id: ReplayCaseId,
    pub project_id: ProjectId,
    pub source_task_id: Option<TaskId>,
    pub case_kind: ReplayCaseKind,
    pub input_snapshot_refs: Vec<String>,
    pub expected_observation_refs: Vec<String>,
    pub expected_verifier_refs: Vec<String>,
    pub forbidden_output_patterns: Vec<String>,
    pub success_criteria: Vec<ReplaySuccessCriterion>,
    pub trace_contract_ref: String,
    pub taint: TaintClass,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCaseKind {
    Regression,
    NegativeMemory,
    SkillActivation,
    SkillCuration,
    MemoryLifecycle,
    ContextCompilation,
    CompletionGate,
    AdapterObservation,
    IncidentRecovery,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplaySuccessCriterion {
    pub criterion_id: String,
    pub description: String,
    pub required: bool,
    pub measurement: ReplayMeasurement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMeasurement {
    MustIncludeRef(String),
    MustExcludeRef(String),
    MustDenyAction(String),
    MustRequireVerifier(String),
    MustProduceGateDecision(String),
    MustNotPromoteCandidate,
    MustNotReturnDoneVerified,
    MustPreserveTaint,
    MustGenerateReport(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplaySet {
    pub replay_set_id: ReplaySetId,
    pub project_id: ProjectId,
    pub name: String,
    pub purpose: String,
    pub cases: Vec<ReplayCaseId>,
    pub fixed: bool,
    pub holdout: bool,
    pub created_from_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayInputSnapshot {
    pub snapshot_id: String,
    pub replay_case_id: ReplayCaseId,
    pub context_packet_ref: Option<String>,
    pub memory_refs: Vec<String>,
    pub skill_refs: Vec<SkillId>,
    pub policy_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayRun {
    pub replay_run_id: ReplayRunId,
    pub project_id: ProjectId,
    pub replay_set_id: ReplaySetId,
    pub candidate_ref: Option<String>,
    pub baseline_ref: Option<String>,
    pub run_profile: ReplayRunProfile,
    pub case_results: Vec<ReplayCaseResult>,
    #[serde(default)]
    pub sealed_input_hash: String,
    #[serde(default)]
    pub reproducibility_hash: String,
    #[serde(default)]
    pub uncertainty: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
    pub status: ReplayRunStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayRunProfile {
    pub profile_id: String,
    pub deterministic: bool,
    pub no_external_network: bool,
    pub no_mutation: bool,
    pub max_runtime_seconds: u64,
    pub allowed_services: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayRunStatus {
    Started,
    Completed,
    Failed,
    Cancelled,
    BlockedMissingTrace,
    BlockedUnsafeProfile,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayCaseResult {
    pub result_id: String,
    pub replay_case_id: ReplayCaseId,
    pub status: ReplayCaseStatus,
    pub measurements: Vec<ReplayMeasurementResult>,
    pub produced_refs: Vec<String>,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCaseStatus {
    Passed,
    Failed,
    Skipped,
    Blocked,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayMeasurementResult {
    pub criterion_id: String,
    pub passed: bool,
    pub observed: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayVerdict {
    pub verdict_id: String,
    pub replay_run_id: ReplayRunId,
    pub candidate_ref: Option<String>,
    pub decision: ReplayDecision,
    pub reasons: Vec<String>,
    pub required_followups: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDecision {
    Pass,
    Fail,
    Inconclusive,
    RequiresMoreCases,
    RequiresHumanReview,
    UnsafeToPromote,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayAudit {
    pub audit_id: String,
    pub replay_run_id: ReplayRunId,
    pub trace_contract_refs: Vec<String>,
    pub missing_trace_parts: Vec<MissingTracePart>,
    pub mutation_attempts_blocked: Vec<String>,
    pub taint_preserved: bool,
    pub authority_mutation_blocked: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SleepConsolidationRun {
    pub sleep_run_id: String,
    pub project_id: ProjectId,
    pub trigger: SleepTrigger,
    pub input_scope: SleepInputScope,
    pub input_traces: Vec<String>,
    pub recent_failures: Vec<String>,
    pub repeated_patterns: Vec<String>,
    pub outputs: Vec<SleepOutputRef>,
    #[serde(default)]
    pub excluded_trace_contract_refs: Vec<String>,
    #[serde(default)]
    pub reasoning_route_ref: String,
    pub replay_requirement: SkillReplayRequirement,
    pub taint: TaintClass,
    pub status: SleepConsolidationStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SleepTrigger {
    Manual,
    PostTask,
    RepeatedFailure,
    ContextBloat,
    SkillDecay,
    MaintenanceWindow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SleepInputScope {
    pub project_id: ProjectId,
    pub task_ids: Vec<TaskId>,
    pub memory_refs: Vec<String>,
    pub skill_refs: Vec<SkillId>,
    pub max_trace_count: usize,
    pub max_age_days: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SleepOutputRef {
    pub output_ref: String,
    pub output_kind: SleepOutputKind,
    pub candidate_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SleepOutputKind {
    DreamCandidate,
    MemorySynthesisCandidate,
    ReplayCase,
    ProposedForgettingAction,
    ProposedSkillPatch,
    ProposedTest,
    ProposedInvariant,
    ProposedRisk,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SleepConsolidationStatus {
    Started,
    ProposedCandidates,
    ReplayRequired,
    CompletedCandidateOnly,
    Failed,
    RejectedUnsafeOutput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DreamCandidate {
    pub dream_candidate_id: DreamCandidateId,
    pub project_id: ProjectId,
    pub candidate_kind: DreamCandidateKind,
    pub source_traces: Vec<String>,
    #[serde(default)]
    pub source_trace_contract_refs: Vec<String>,
    #[serde(default)]
    pub reasoning_route_ref: String,
    pub rationale: String,
    pub proposed_refs: Vec<String>,
    pub support_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub required_reconciliation: Vec<String>,
    pub required_replay: Option<SkillReplayRequirement>,
    pub prohibited_direct_effects: Vec<ProhibitedDreamEffect>,
    pub taint: TaintClass,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DreamCandidateKind {
    Hypothesis,
    Procedure,
    Relation,
    ForgettingAction,
    Test,
    Invariant,
    Risk,
    ResearchQuestion,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProhibitedDreamEffect {
    CurrentTruth,
    ActivePolicy,
    Permission,
    Completion,
    SkillPromotion,
    MemorySuppression,
    PatchApplication,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemorySynthesisTaint {
    pub taint_id: String,
    pub candidate_ref: String,
    pub reason: MemorySynthesisTaintReason,
    pub promotion_block: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySynthesisTaintReason {
    ModelGenerated,
    IndirectReasoning,
    UnverifiedInference,
    CrossDomainAnalogy,
    OfflineConsolidation,
}

/// The production L11 trace contract is exactly these thirteen evidence parts.
pub const CANONICAL_TRACE_EVIDENCE_PART_COUNT: usize = 13;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalTraceEvidenceKind {
    TaskContract,
    ContextPacket,
    CurrentTruthRevision,
    MemoryExposureSet,
    AgentToolEvents,
    ExpectedObservation,
    ActualObservation,
    VerifierRun,
    ArtifactRef,
    FinishDecision,
    PolicySnapshot,
    ModelRoute,
    OutcomeAndCost,
}

impl CanonicalTraceEvidenceKind {
    pub const ALL: [Self; CANONICAL_TRACE_EVIDENCE_PART_COUNT] = [
        Self::TaskContract,
        Self::ContextPacket,
        Self::CurrentTruthRevision,
        Self::MemoryExposureSet,
        Self::AgentToolEvents,
        Self::ExpectedObservation,
        Self::ActualObservation,
        Self::VerifierRun,
        Self::ArtifactRef,
        Self::FinishDecision,
        Self::PolicySnapshot,
        Self::ModelRoute,
        Self::OutcomeAndCost,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskContract => "task_contract",
            Self::ContextPacket => "context_packet",
            Self::CurrentTruthRevision => "current_truth_revision",
            Self::MemoryExposureSet => "memory_exposure_set",
            Self::AgentToolEvents => "agent_tool_events",
            Self::ExpectedObservation => "expected_observation",
            Self::ActualObservation => "actual_observation",
            Self::VerifierRun => "verifier_run",
            Self::ArtifactRef => "artifact_ref",
            Self::FinishDecision => "finish_decision",
            Self::PolicySnapshot => "policy_snapshot",
            Self::ModelRoute => "model_route",
            Self::OutcomeAndCost => "outcome_and_cost",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalTraceDerivation {
    pub algorithm_version: String,
    pub input_refs: Vec<String>,
    pub input_hashes: Vec<String>,
    pub output_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalTraceReceiptBinding {
    pub receipt: WriteReceiptRef,
    pub command_kind: SemanticCommandKind,
    pub input_hash: String,
    pub source_content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CanonicalTraceEvidenceSource {
    CanonicalReceipt {
        binding: CanonicalTraceReceiptBinding,
    },
    EngineDerivation {
        derivation: CanonicalTraceDerivation,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalTraceEvidence {
    pub kind: CanonicalTraceEvidenceKind,
    pub canonical_kind: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub memory_revision: MemoryRevision,
    pub reference: String,
    pub content_hash: String,
    pub taint: TaintClass,
    pub source: CanonicalTraceEvidenceSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalTraceCompletenessContract {
    pub contract_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub source_task_revision: MemoryRevision,
    pub trace_ref: String,
    pub evidence: Vec<CanonicalTraceEvidence>,
    pub evidence_manifest_hash: String,
    pub replay_allowed: bool,
    pub rejected_reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySetRole {
    Fixed,
    Holdout,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SealedReplayCaseRecord {
    pub record_id: String,
    pub replay_set_id: ReplaySetId,
    pub case: ReplayCase,
    pub content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SealedReplayInputSnapshotRecord {
    pub record_id: String,
    pub replay_set_id: ReplaySetId,
    pub snapshot: ReplayInputSnapshot,
    pub content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SealedReplaySetRecord {
    pub record_id: String,
    pub set: ReplaySet,
    pub role: ReplaySetRole,
    pub version: u64,
    pub evaluator_version: String,
    pub evaluator_hash: String,
    pub profile_hash: String,
    pub context_version: String,
    pub context_hash: String,
    pub case_hashes: Vec<String>,
    pub snapshot_hashes: Vec<String>,
    pub sealed_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalReplayObservationEvidence {
    pub replay_case_id: ReplayCaseId,
    pub snapshot_hash: String,
    pub evidence: Vec<CanonicalTraceEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalReplayExecutionRecord {
    pub execution_id: String,
    pub sealed_set_ref: String,
    pub sealed_set_hash: String,
    pub evaluator_hash: String,
    pub profile_hash: String,
    pub context_hash: String,
    pub observation_evidence_hash: String,
    pub run: ReplayRun,
    pub audit: ReplayAudit,
    #[serde(default)]
    pub authoritative_replay: Option<Box<CanonicalReplayAuthority>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalReplayAuthority {
    pub input_fingerprint: String,
    pub sealed_set: SealedReplaySetRecord,
    pub cases: Vec<SealedReplayCaseRecord>,
    pub snapshots: Vec<SealedReplayInputSnapshotRecord>,
    pub candidate_execution: CanonicalReplayExecutionRecord,
    pub expected_baseline_write_id: WriteId,
    pub expected_candidate_write_id: WriteId,
    pub expected_set_write_id: WriteId,
    pub expected_case_write_ids: Vec<WriteId>,
    pub expected_snapshot_write_ids: Vec<WriteId>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SleepCandidateArtifactKind {
    Procedure,
    ForgettingAction,
    Test,
    ReplayCase,
    Dream,
}

impl SleepCandidateArtifactKind {
    pub const fn receipt_kind(self) -> &'static str {
        match self {
            Self::Procedure => "procedure_candidate",
            Self::ForgettingAction => "forgetting_candidate",
            Self::Test => "test_candidate",
            Self::ReplayCase => "replay_case_candidate",
            Self::Dream => "dream_candidate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SleepCandidateArtifact {
    pub artifact_id: String,
    pub project_id: ProjectId,
    pub artifact_kind: SleepCandidateArtifactKind,
    pub source_trace_ref: String,
    pub source_trace_contract_ref: String,
    pub body: Value,
    pub candidate_only: bool,
    pub taint: TaintClass,
    pub prohibited_direct_effects: Vec<ProhibitedDreamEffect>,
    pub required_replay: SkillReplayRequirement,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SleepConsolidationBundle {
    pub bundle_id: String,
    pub bundle_hash: String,
    pub run: SleepConsolidationRun,
    pub artifacts: Vec<SleepCandidateArtifact>,
}
