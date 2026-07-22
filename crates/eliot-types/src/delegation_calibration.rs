use crate::{
    DelegationDecisionKind, DelegationOrigin, DelegationReason, DelegationReviewKind, ProjectId,
    TaskId, safety::IncidentRecord,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationEvidenceClass {
    RealExecutedTask,
    RealNoProviderTask,
    ShadowOnlyRealTask,
    DeterministicFixture,
    HistoricalImportedRecord,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationCalibrationTaskFamily {
    SecurityBoundary,
    ExternalIntegration,
    ArchitectureDesign,
    BroadDiffReview,
    VerifierDesign,
    RepeatedFailureDiagnosis,
    EvidenceGapReview,
    TrivialDeterministicTask,
    Other,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationCalibrationLabels {
    pub provider_called: bool,
    pub provider_useful: Option<bool>,
    pub changed_controller_decision: Option<bool>,
    pub unique_findings: u32,
    pub accepted_findings: u32,
    pub rejected_findings: u32,
    pub duplicate_findings: u32,
    pub false_positive_findings: u32,
    pub malformed_findings: u32,
    pub authority_violations: u32,
    pub live_tree_violations: u32,
    pub routing_false_positive: Option<bool>,
    pub routing_false_negative: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DelegationCalibrationCosts {
    pub provider_runtime_ms: Option<u64>,
    pub end_to_end_runtime_ms: Option<u64>,
    pub reconciliation_runtime_ms: Option<u64>,
    pub provider_call_count: u32,
    pub input_bytes: Option<u64>,
    pub output_bytes: Option<u64>,
    pub quota_signal: Option<String>,
    pub monetary_cost_known: bool,
    pub monetary_cost: Option<f64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CalibrationCompleteness {
    pub route_decision_present: bool,
    pub final_task_outcome_present: bool,
    pub provider_result_present: bool,
    pub verifier_or_human_evidence_present: bool,
    pub worktree_cleanup_present: bool,
    pub live_tree_integrity_present: bool,
    pub complete_for_provider_quality: bool,
    pub complete_for_routing_quality: bool,
    pub missing_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationCalibrationSample {
    pub sample_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub task_family: DelegationCalibrationTaskFamily,
    pub evidence_class: CalibrationEvidenceClass,
    pub delegation_origin: DelegationOrigin,
    pub review_kind: DelegationReviewKind,
    pub route_decision_ref: String,
    pub delegation_outcome_ref: Option<String>,
    pub provider_result_ref: Option<String>,
    pub controller_outcome_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub shadow_decision_ref: Option<String>,
    pub labels: DelegationCalibrationLabels,
    pub costs: DelegationCalibrationCosts,
    pub completeness: CalibrationCompleteness,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationShadowDecisionKind {
    WouldExecute,
    WouldNotExecute,
    InsufficientEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationShadowRecord {
    pub shadow_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub task_family: DelegationCalibrationTaskFamily,
    pub observed_l0_decision: DelegationDecisionKind,
    pub shadow_candidate_policy_ref: String,
    pub shadow_decision: DelegationShadowDecisionKind,
    pub reasons: Vec<DelegationReason>,
    pub provider_was_actually_called: bool,
    pub final_outcome_known: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationCounterfactualKind {
    CorrectCall,
    CorrectNoCall,
    PossibleFalsePositive,
    PossibleFalseNegative,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationCounterfactualLabel {
    pub label_id: String,
    pub shadow_ref: String,
    pub label: DelegationCounterfactualKind,
    pub evidence_refs: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationCalibrationReadiness {
    InsufficientData,
    DataQualityBlocked,
    ShadowOnly,
    CandidatePolicyReady,
    PromotionBlockedBySafety,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationFamilyCalibration {
    pub calibration_id: String,
    pub task_family: DelegationCalibrationTaskFamily,
    pub real_task_count: u32,
    pub real_provider_call_count: u32,
    pub shadow_task_count: u32,
    pub complete_provider_quality_samples: u32,
    pub complete_routing_quality_samples: u32,
    pub accepted_finding_count: u32,
    pub unique_finding_count: u32,
    pub duplicate_finding_count: u32,
    pub false_positive_count: u32,
    pub useful_outcome_count: u32,
    pub redundant_outcome_count: u32,
    pub provider_failure_count: u32,
    pub median_provider_runtime_ms: Option<u64>,
    pub p95_provider_runtime_ms: Option<u64>,
    pub readiness: DelegationCalibrationReadiness,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPolicyCandidateStatus {
    Draft,
    InsufficientData,
    ReadyForEvaluation,
    Rejected,
    Archived,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationTriggerChangeKind {
    KeepShadowOnly,
    ConsiderAutoReview,
    TightenCodexRequested,
    RelaxCodexRequested,
    DisableReview,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationTriggerChange {
    pub task_family: DelegationCalibrationTaskFamily,
    pub change: DelegationTriggerChangeKind,
    pub reason: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationBudgetChange {
    pub task_family: DelegationCalibrationTaskFamily,
    pub change: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationPolicyCandidate {
    pub candidate_id: String,
    pub base_policy_ref: String,
    pub version: String,
    pub enabled_families: Vec<DelegationCalibrationTaskFamily>,
    pub disabled_families: Vec<DelegationCalibrationTaskFamily>,
    pub proposed_trigger_changes: Vec<DelegationTriggerChange>,
    pub proposed_budget_changes: Vec<DelegationBudgetChange>,
    pub evidence_refs: Vec<String>,
    pub safety_constraints: Vec<String>,
    pub status: DelegationPolicyCandidateStatus,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPolicyPromotionDecisionKind {
    InsufficientData,
    RequireMoreRealTasks,
    RequireMoreExecutedReviews,
    RequireHumanReview,
    #[serde(alias = "ready_for_l1_b_experiment")]
    ReadyForProviderExperiment,
    DenySafetyViolation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPolicyPromotionReason {
    RealTaskCountTooLow,
    ShadowTaskCountTooLow,
    ExecutedReviewCountTooLow,
    IncompleteOutcomeEvidence,
    HighFalsePositiveRate,
    HighDuplicateRate,
    ProviderFailureRateTooHigh,
    UtilityNotDemonstrated,
    AuthorityViolationObserved,
    LiveTreeViolationObserved,
    RecursiveExecutionObserved,
    DataQualitySufficient,
    FamilySpecificBenefitObserved,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationPolicyPromotionDecision {
    pub decision_id: String,
    pub candidate_ref: String,
    pub decision: DelegationPolicyPromotionDecisionKind,
    pub reasons: Vec<DelegationPolicyPromotionReason>,
    pub required_followups: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationCalibrationCampaignState {
    Draft,
    Preregistered,
    Ready,
    Reserved,
    Dispatching,
    ProviderExecuting,
    ProviderExecuted,
    AwaitingIndependentEvidence,
    Attributed,
    EligibilityDecided,
    RolledUp,
    Closed,
    ReleasedPreDispatch,
    UnknownOutcome,
    GateDenied,
    BlockedProviderUnavailable,
    BlockedQuota,
    FailedProvider,
    Inconclusive,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationCalibrationCampaignTransition {
    pub from: DelegationCalibrationCampaignState,
    pub to: DelegationCalibrationCampaignState,
    pub evidence_ref: Option<String>,
    pub transitioned_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationCalibrationCampaignCloseoutStatus {
    Open,
    DoneVerified,
    FailedVerifier,
    BlockedExternalDependency,
    Inconclusive,
    Cancelled,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DelegationCalibrationCampaignBudget {
    pub max_provider_calls: u32,
    pub max_cost_if_known: Option<f64>,
    pub max_wall_time_seconds: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DelegationEvidenceFloorSnapshot {
    pub minimum_real_tasks_total: u32,
    pub minimum_real_tasks_per_family: u32,
    pub minimum_executed_reviews_total: u32,
    pub minimum_executed_reviews_per_candidate_family: u32,
    pub minimum_complete_outcome_fraction: f64,
    pub minimum_shadow_tasks_total: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationCalibrationCampaign {
    pub campaign_id: String,
    pub project_id: ProjectId,
    pub schema_version: String,
    pub created_at: OffsetDateTime,
    pub closed_at: Option<OffsetDateTime>,
    pub baseline_commit: String,
    pub policy_snapshot_id: String,
    pub provider_route: String,
    pub task_family: DelegationCalibrationTaskFamily,
    pub selection_rule: String,
    pub budget: DelegationCalibrationCampaignBudget,
    pub evidence_floor_snapshot: DelegationEvidenceFloorSnapshot,
    pub selected_task_ids: Vec<TaskId>,
    pub frozen_input_refs: Vec<String>,
    pub baseline_state_hash: String,
    #[serde(default)]
    pub observed_provider_calls: u32,
    #[serde(default)]
    pub integrity_violations: Vec<String>,
    pub executed_review_ids: Vec<String>,
    pub independent_evidence_ids: Vec<String>,
    pub shadow_evaluation_ids: Vec<String>,
    pub state: DelegationCalibrationCampaignState,
    pub closeout_status: DelegationCalibrationCampaignCloseoutStatus,
    #[serde(default)]
    pub transition_history: Vec<DelegationCalibrationCampaignTransition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrozenInputDigest {
    pub source_ref: String,
    pub content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderReviewPreRegistration {
    pub preregistration_id: String,
    pub campaign_id: String,
    pub project_id: ProjectId,
    pub real_task_id: TaskId,
    pub provider: String,
    pub task_family: DelegationCalibrationTaskFamily,
    pub baseline_commit: String,
    pub comparison_base_commit: String,
    pub frozen_input_refs: Vec<String>,
    pub frozen_input_digests: Vec<FrozenInputDigest>,
    pub frozen_input_hash: String,
    pub review_questions: Vec<String>,
    pub materiality_rule: String,
    pub independent_evidence_plan: Vec<String>,
    pub utility_attribution_rule_version: String,
    pub max_provider_calls: u32,
    pub idempotency_key: String,
    pub execution_token_hash: String,
    pub historical_exclusions_hash: String,
    pub forbidden_effects: Vec<String>,
    pub expected_terminal_states: Vec<String>,
    pub created_at: OffsetDateTime,
    pub sealed_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub reservation_ref: Option<String>,
    pub invocation_ref: Option<String>,
    pub review_ref: Option<String>,
    pub supersedes_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFindingMateriality {
    Material,
    Minor,
    NonActionable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFindingNovelty {
    Novel,
    Duplicate,
    AlreadyCovered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFindingVerdict {
    Confirmed,
    Refuted,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderFindingDisposition {
    pub campaign_id: String,
    pub review_id: String,
    pub finding_id: String,
    pub materiality: ProviderFindingMateriality,
    pub novelty: ProviderFindingNovelty,
    pub independent_evidence_refs: Vec<String>,
    pub verdict: ProviderFindingVerdict,
    pub action_delta: String,
    pub verifier_delta: String,
    pub outcome_delta: String,
    pub decided_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignIntegrityRootCauseStatus {
    Verified,
    Supported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignIntegrityIncidentStatus {
    Open,
    Contained,
    Resolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCallLineageTerminalState {
    Completed,
    Failed,
    UnknownOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderCallLineage {
    pub invocation_index: u32,
    pub trigger_command_or_target: String,
    pub idempotency_key_if_any: Option<String>,
    pub reservation_ref_if_any: Option<String>,
    pub gate_ref: String,
    pub dispatch_started_at: OffsetDateTime,
    pub provider_request_or_process_ref: String,
    pub review_ref: String,
    pub terminal_state: ProviderCallLineageTerminalState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CampaignIntegrityIncidentDetails {
    pub phase: String,
    pub campaign_id: String,
    pub invariant: String,
    pub campaign_limit: u32,
    pub observed_calls: u32,
    pub gate_decision_refs: Vec<String>,
    pub review_refs: Vec<String>,
    pub call_lineage: Vec<ProviderCallLineage>,
    pub root_cause_status: CampaignIntegrityRootCauseStatus,
    pub root_cause: String,
    pub contributing_conditions: Vec<String>,
    pub failed_control_boundary: String,
    pub affected_reports: Vec<String>,
    pub promotion_eligibility_effect: String,
    pub containment: Vec<String>,
    pub permanent_prevention: Vec<String>,
    pub regression_test_refs: Vec<String>,
    pub resolved_at: Option<OffsetDateTime>,
    pub status: CampaignIntegrityIncidentStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutedProviderReviewStatus {
    Succeeded,
    Failed,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutedProviderReview {
    pub review_id: String,
    pub campaign_id: String,
    pub real_task_id: TaskId,
    pub provider: String,
    pub model_route_if_known: Option<String>,
    pub request_ref: String,
    pub frozen_input_refs: Vec<String>,
    pub baseline_state_hash: String,
    pub provider_gate_decision_ref: String,
    pub quota_or_cost_receipt: String,
    pub started_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub status: ExecutedProviderReviewStatus,
    pub raw_output_ref: String,
    pub normalized_findings: Vec<String>,
    pub proposed_changes: Vec<String>,
    pub candidate_only: bool,
    pub trace_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependentEvidenceKind {
    Verifier,
    Human,
    Artifact,
    Runtime,
    AcceptedDiff,
    RejectedDiff,
    MeasuredCost,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationFindingMateriality {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependentEvidenceResult {
    Confirmed,
    Refuted,
    Inconclusive,
    Contradictory,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct IndependentEvidenceContaminationChecks {
    pub producer_is_provider: bool,
    pub criteria_added_after_provider_output: bool,
    pub provider_output_used_as_verifier_input: bool,
    pub scope_matches_review: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct IndependentOutcomeEvidence {
    pub evidence_id: String,
    pub campaign_id: String,
    pub review_id: String,
    pub task_id: TaskId,
    pub evidence_kind: IndependentEvidenceKind,
    pub producer_identity: String,
    pub independent_from_provider: bool,
    pub scope: String,
    pub observed_at: OffsetDateTime,
    pub exact_anchor_refs: Vec<String>,
    pub result: IndependentEvidenceResult,
    pub materiality: DelegationFindingMateriality,
    pub supports_provider_finding_ids: Vec<String>,
    pub refutes_provider_finding_ids: Vec<String>,
    pub unresolved_provider_finding_ids: Vec<String>,
    pub contamination_checks: IndependentEvidenceContaminationChecks,
    pub authority: String,
    pub changed_controller_action: bool,
    pub prevented_verified_failure: bool,
    pub unnecessary_work: bool,
    pub verified_quality_delta: i32,
    pub verified_cost_or_latency_delta: i64,
    pub trace_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderUtilityReason {
    ConfirmedMaterialNovelFinding,
    ConfirmedMaterialActionChange,
    ConfirmedFailurePrevention,
    VerifiedCostOrLatencyBenefit,
    RefutedOrFalsePositiveOutput,
    NoMaterialOutcomeDelta,
    MissingIndependentEvidence,
    InconclusiveEvidence,
    ContaminatedEvidence,
    ContradictoryEvidence,
    BelowMaterialityThreshold,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderUtilityAssessment {
    pub assessment_id: String,
    pub campaign_id: String,
    pub review_id: String,
    pub provider_useful: Option<bool>,
    pub reason: ProviderUtilityReason,
    pub material_findings_confirmed: u32,
    pub material_findings_refuted: u32,
    pub novel_confirmed_findings: u32,
    pub duplicate_confirmed_findings: u32,
    pub false_positive_findings: u32,
    pub missed_material_issues_if_known: Option<u32>,
    pub verified_quality_delta: i32,
    pub verified_cost_or_latency_delta: i64,
    pub residual_uncertainty: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub attribution_rule_version: String,
    pub decided_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationCorpusSampleKind {
    ProviderCall,
    ExecutedReview,
    UtilityAssessment,
    ShadowEvaluation,
    CalibrationSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationIntegrityStatus {
    Valid,
    OverBudget,
    DispatchAmbiguous,
    Incomplete,
    Contaminated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CalibrationCorpusEligibility {
    pub sample_ref: String,
    pub sample_kind: CalibrationCorpusSampleKind,
    pub observed: bool,
    pub integrity_status: CalibrationIntegrityStatus,
    pub promotion_eligible: bool,
    pub exclusion_reasons: Vec<String>,
    pub decided_by_rule_version: String,
    pub evidence_refs: Vec<String>,
    pub decided_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPromotionReadinessVerdict {
    InsufficientData,
    EligibleForPromotion,
    RejectedByEvidence,
    BlockedByIntegrity,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CalibrationEvidenceCounts {
    pub real_tasks: u32,
    pub executed_reviews: u32,
    pub shadow_tasks: u32,
    pub complete_outcomes: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CalibrationExcludedCounts {
    pub over_budget_calls: u32,
    pub unknown_dispatch_calls: u32,
    pub incomplete_samples: u32,
    pub contaminated_samples: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CalibrationEvidenceGapReport {
    pub current_counts: CalibrationEvidenceCounts,
    #[serde(default)]
    pub observed_counts: CalibrationEvidenceCounts,
    #[serde(default)]
    pub promotion_eligible_counts: CalibrationEvidenceCounts,
    #[serde(default)]
    pub excluded_counts: CalibrationExcludedCounts,
    pub required_floors: DelegationEvidenceFloorSnapshot,
    pub completeness: f64,
    pub missing_task_families: Vec<DelegationCalibrationTaskFamily>,
    pub missing_independent_evidence: Vec<String>,
    pub null_utility_causes: Vec<ProviderUtilityReason>,
    pub next_highest_value_sample: String,
    pub estimated_provider_calls_to_floor: u32,
    pub promotion_readiness: DelegationPromotionReadinessVerdict,
    #[serde(default)]
    pub campaign_integrity: String,
    #[serde(default)]
    pub promotion_corpus_integrity: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DelegationCalibrationState {
    pub samples: Vec<DelegationCalibrationSample>,
    pub shadows: Vec<DelegationShadowRecord>,
    pub counterfactual_labels: Vec<DelegationCounterfactualLabel>,
    pub families: Vec<DelegationFamilyCalibration>,
    pub policy_candidate: Option<DelegationPolicyCandidate>,
    pub promotion_decision: Option<DelegationPolicyPromotionDecision>,
    pub campaigns: Vec<DelegationCalibrationCampaign>,
    pub executed_reviews: Vec<ExecutedProviderReview>,
    pub independent_evidence: Vec<IndependentOutcomeEvidence>,
    pub utility_assessments: Vec<ProviderUtilityAssessment>,
    pub evidence_gap_report: Option<CalibrationEvidenceGapReport>,
    pub integrity_incidents: Vec<IncidentRecord>,
    pub corpus_eligibility: Vec<CalibrationCorpusEligibility>,
    pub preregistrations: Vec<ProviderReviewPreRegistration>,
    pub finding_dispositions: Vec<ProviderFindingDisposition>,
}
