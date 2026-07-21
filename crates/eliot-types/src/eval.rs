use crate::{
    EvalCaseId, EvalDatasetManifestId, EvalFailureClusterId, EvalRunId, EvalSuiteId, EvalVerdictId,
    HarnessExperimentRecordId, ProjectId, TaskId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalFamily {
    Understand,
    Hallucination,
    Negative,
    Done,
    Context,
    Compaction,
    Tool,
    Memory,
    Forget,
    Dream,
    Skill,
    Trace,
    Bench,
    Ale,
    Provider,
    Future,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalCase {
    pub eval_case_id: EvalCaseId,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub family: EvalFamily,
    pub name: String,
    pub description: String,
    pub fixture_ref: String,
    pub holdout: bool,
    pub criteria: Vec<EvalCriterion>,
    pub measurement_specs: Vec<EvalMeasurementSpec>,
    pub budget: EvalBudget,
    pub expected_evidence_refs: Vec<String>,
    pub forbidden_effects: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalCriterion {
    pub criterion_id: String,
    pub description: String,
    pub required: bool,
    pub measurement_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalMeasurementSpec {
    pub measurement_id: String,
    pub description: String,
    pub kind: EvalMeasurementKind,
    pub expected_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalMeasurementKind {
    MustIncludeEvidence,
    MustExcludeEvidence,
    MustBlockAction,
    MustRequireVerifier,
    MustPreserveTaint,
    MustNotMutate,
    MustGenerateVerdict,
    MustDetectChecksumMismatch,
    NotYetImplemented,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalBudget {
    pub max_runtime_ms: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_tool_calls: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalSuite {
    pub eval_suite_id: EvalSuiteId,
    pub project_id: ProjectId,
    pub name: String,
    pub purpose: String,
    pub cases: Vec<EvalCaseId>,
    pub fixed: bool,
    pub holdout: bool,
    pub integrity_checksum: String,
    pub created_from_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub frozen_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalDatasetManifest {
    pub eval_dataset_manifest_id: EvalDatasetManifestId,
    pub suite_id: EvalSuiteId,
    pub suite_name: String,
    pub case_count: usize,
    pub fixture_checksums: Vec<EvalFixtureChecksum>,
    pub manifest_checksum: String,
    pub holdout_preserved: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalFixtureChecksum {
    pub fixture_ref: String,
    pub checksum: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalRun {
    pub eval_run_id: EvalRunId,
    pub project_id: ProjectId,
    pub suite_id: EvalSuiteId,
    pub dataset_manifest_id: EvalDatasetManifestId,
    pub profile: EvalRunProfile,
    pub status: EvalRunStatus,
    pub case_results: Vec<EvalCaseResult>,
    pub mutation_attempts_blocked: Vec<String>,
    pub blocked_reason: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalRunProfile {
    pub profile_id: String,
    pub deterministic: bool,
    pub no_external_network: bool,
    pub no_mutation: bool,
    pub max_runtime_seconds: u64,
    pub allowed_services: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalRunStatus {
    Planned,
    Running,
    Completed,
    Failed,
    BlockedInvalidDataset,
    BlockedMutationAttempt,
    BlockedUnsafeProfile,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalCaseResult {
    pub result_id: String,
    pub eval_case_id: EvalCaseId,
    pub family: EvalFamily,
    pub status: EvalCaseStatus,
    pub measurements: Vec<EvalMeasurementResult>,
    pub produced_refs: Vec<String>,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalCaseStatus {
    Passed,
    Failed,
    Skipped,
    Blocked,
    NotYetImplemented,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalMeasurementResult {
    pub measurement_id: String,
    pub passed: bool,
    pub observed: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct EvalVerdict {
    pub eval_verdict_id: EvalVerdictId,
    pub eval_run_id: EvalRunId,
    pub status: EvalVerdictStatus,
    pub family_scores: Vec<EvalFamilyScore>,
    pub failure_clusters: Vec<EvalFailureCluster>,
    pub grants_authority: bool,
    pub mutates_current_truth: bool,
    pub mutates_memory_lifecycle: bool,
    pub mutates_skills: bool,
    pub mutates_policy: bool,
    pub mutates_action_permissions: bool,
    pub mutates_completion_state: bool,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalVerdictStatus {
    Pass,
    Fail,
    Inconclusive,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalFamilyScore {
    pub family: EvalFamily,
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
    pub total: u32,
    pub score_percent: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalFailureCluster {
    pub eval_failure_cluster_id: EvalFailureClusterId,
    pub eval_run_id: EvalRunId,
    pub family: EvalFamily,
    pub case_refs: Vec<EvalCaseId>,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkIntegrityReceipt {
    pub benchmark_integrity_receipt_id: crate::BenchmarkIntegrityReceiptId,
    pub suite_id: EvalSuiteId,
    pub manifest_checksum: String,
    pub expected_checksum: String,
    pub actual_checksum: String,
    pub valid: bool,
    pub mismatch_detected: bool,
    pub blocked_run: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HarnessExperimentRecord {
    pub harness_experiment_record_id: HarnessExperimentRecordId,
    pub eval_run_id: EvalRunId,
    pub profile_id: String,
    pub verdict_id: Option<EvalVerdictId>,
    pub notes: Vec<String>,
    pub no_mutation_confirmed: bool,
    #[serde(default)]
    pub project_id: Option<ProjectId>,
    #[serde(default)]
    pub candidate_ref: String,
    #[serde(default)]
    pub change_class: MetaCandidateChangeClass,
    #[serde(default)]
    pub changed_variables: Vec<String>,
    #[serde(default)]
    pub evaluator_snapshot_ref: String,
    #[serde(default)]
    pub baseline_policy_hash: String,
    #[serde(default)]
    pub candidate_policy_hash: String,
    #[serde(default)]
    pub fixed_replay_set_ref: String,
    #[serde(default)]
    pub holdout_set_ref: String,
    #[serde(default)]
    pub replay_run_refs: Vec<String>,
    #[serde(default)]
    pub holdout_run_refs: Vec<String>,
    #[serde(default)]
    pub primary_metric_refs: Vec<String>,
    #[serde(default)]
    pub counter_metric_refs: Vec<String>,
    #[serde(default)]
    pub reproducibility_hash: String,
    #[serde(default)]
    pub uncertainty: String,
    #[serde(default)]
    pub decision: MetaExperimentDecision,
    #[serde(default)]
    pub authorized_command_ref: Option<String>,
    #[serde(default)]
    pub rollback_target_ref: String,
    #[serde(default)]
    pub rollback_command_ref: String,
    #[serde(default)]
    pub authoritative_metric_evidence: Vec<CanonicalMetaMetricEvidence>,
    #[serde(default)]
    pub authoritative_isolation_rejection: Option<MetaIsolationRejectionRecord>,
    #[serde(default)]
    pub authoritative_policy_candidate: Option<ExperimentalMetaPolicyCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition_receipt: Option<WriteReceiptRef>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaCandidateChangeClass {
    #[default]
    AdmissionRule,
    ExperienceBrief,
    DecisionLocalityLayout,
    NegativeMemoryActivation,
    ForgettingThreshold,
    SkillApplicability,
    ToolExposure,
    AgentRoute,
    VerificationMap,
    RecoveryTripwire,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetaExperimentDecision {
    Promoted,
    Rejected,
    KeptExperimental,
    #[default]
    InsufficientEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayThresholdPolicyV1 {
    pub schema_version: String,
    pub evaluator_version: String,
    pub minimum_pass_basis_points: u16,
    pub maximum_counter_regressions: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "policy_kind", rename_all = "snake_case")]
pub enum ExperimentalMetaPolicyPayload {
    ReplayThresholdV1 { policy: ReplayThresholdPolicyV1 },
    Unsupported { kind: String, payload: Value },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentalMetaPolicyState {
    Experimental,
    Promoted,
    RolledBack,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperimentalMetaPolicyCandidate {
    pub candidate_id: String,
    pub project_id: ProjectId,
    pub baseline: ExperimentalMetaPolicyPayload,
    pub candidate: ExperimentalMetaPolicyPayload,
    pub baseline_hash: String,
    pub candidate_hash: String,
    pub state: ExperimentalMetaPolicyState,
    pub source_experiment_ref: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetaIsolationFence {
    pub evaluator_version: String,
    pub evaluator_hash: String,
    pub threshold_version: String,
    pub threshold_hash: String,
    pub fixed_replay_set_hash: String,
    pub holdout_replay_set_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMetaMetricEvidence {
    pub metric_name: String,
    pub fixed_replay_run_ref: String,
    pub fixed_result_hash: String,
    pub holdout_replay_run_ref: String,
    pub holdout_result_hash: String,
    pub baseline_value: i64,
    pub candidate_value: i64,
    pub allowed_regression: u64,
    pub higher_is_better: bool,
    pub evidence_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetaIsolationRejectionRecord {
    pub rejection_id: String,
    pub project_id: ProjectId,
    #[serde(default)]
    pub source_experiment_ref: String,
    pub candidate_ref: String,
    pub derived_fence: MetaIsolationFence,
    pub attempted_fence_hash: String,
    pub reasons: Vec<String>,
    pub decision: MetaExperimentDecision,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMetaExperimentRecordSet {
    pub experiment: HarnessExperimentRecord,
    pub metric_evidence: Vec<CanonicalMetaMetricEvidence>,
    pub isolation_rejection: Option<MetaIsolationRejectionRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaPolicyExecutionAction {
    Promote,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetaPolicyAuthorization {
    pub operator_command_ref: String,
    pub expected_action_hash: String,
    pub exact_action_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetaPolicyExecutionReceipt {
    pub execution_id: String,
    pub candidate_id: String,
    #[serde(default)]
    pub operator_command_ref: String,
    pub action: MetaPolicyExecutionAction,
    pub before_hash: String,
    pub after_hash: String,
    pub rollback_target_hash: String,
    pub exact_action_hash: String,
    pub active_policy: ExperimentalMetaPolicyPayload,
    #[serde(default)]
    pub resulting_candidate: Option<ExperimentalMetaPolicyCandidate>,
    #[serde(with = "time::serde::rfc3339")]
    pub executed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalCoverageMatrix {
    pub matrix_id: String,
    pub project_id: ProjectId,
    pub suite_ids: Vec<String>,
    pub family_coverage: Vec<EvalFamilyCoverage>,
    pub component_coverage: Vec<EvalComponentCoverage>,
    pub risk_coverage: Vec<EvalRiskCoverage>,
    pub uncovered_risks: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalFamilyCoverage {
    pub family: EvalFamily,
    pub case_count: u64,
    pub required_case_count: u64,
    pub fixed_case_count: u64,
    pub holdout_case_count: u64,
    pub coverage_status: EvalCoverageStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalCoverageStatus {
    Sufficient,
    Minimal,
    Insufficient,
    PlaceholderOnly,
    NotImplemented,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalComponentCoverage {
    pub component: String,
    pub eval_case_refs: Vec<String>,
    pub covered_failure_modes: Vec<String>,
    pub uncovered_failure_modes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalRiskCoverage {
    pub risk_id: String,
    pub description: String,
    pub severity: EvalRegressionSeverity,
    pub eval_case_refs: Vec<String>,
    pub status: EvalCoverageStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalBaseline {
    pub baseline_id: String,
    pub suite_id: String,
    pub eval_run_id: String,
    pub git_commit: String,
    pub manifest_ref: String,
    pub family_scores: Vec<EvalFamilyScore>,
    pub overall_status: EvalVerdictStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub approved_at: OffsetDateTime,
    pub approved_by: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalCandidateComparison {
    pub comparison_id: String,
    pub suite_id: String,
    pub baseline_id: String,
    pub candidate_run_id: String,
    pub candidate_git_commit: String,
    pub family_deltas: Vec<EvalFamilyDelta>,
    pub newly_failed_cases: Vec<String>,
    pub newly_passing_cases: Vec<String>,
    pub flaky_cases: Vec<String>,
    pub verdict: EvalComparisonVerdict,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalFamilyDelta {
    pub family: EvalFamily,
    pub baseline_score: f64,
    pub candidate_score: f64,
    pub delta: f64,
    pub severity: EvalRegressionSeverity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalRegressionSeverity {
    Info,
    Warning,
    Blocking,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalComparisonVerdict {
    Improved,
    Equivalent,
    RegressedWarning,
    RegressedBlocking,
    RegressedCritical,
    Inconclusive,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalRegressionGateProfile {
    pub profile_id: String,
    pub name: String,
    pub description: String,
    pub suite_ids: Vec<String>,
    pub required_families: Vec<EvalFamily>,
    pub blocking_families: Vec<EvalFamily>,
    pub min_family_scores: Vec<EvalFamilyThreshold>,
    pub allow_inconclusive: bool,
    pub max_new_failures: u64,
    pub require_benchmark_integrity: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalFamilyThreshold {
    pub family: EvalFamily,
    pub min_score: f64,
    pub severity_if_below: EvalRegressionSeverity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalGateDecision {
    pub decision_id: String,
    pub profile_id: String,
    pub comparison_ref: Option<String>,
    pub eval_run_ref: String,
    pub decision: EvalGateDecisionKind,
    pub blocking_reasons: Vec<String>,
    pub warnings: Vec<String>,
    pub required_followups: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalGateDecisionKind {
    Allow,
    AllowWithWarnings,
    Block,
    RequireMoreCoverage,
    RequireBenchmarkRepair,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalTrendReport {
    pub trend_report_id: String,
    pub suite_id: String,
    pub recent_run_refs: Vec<String>,
    pub family_trends: Vec<EvalFamilyTrend>,
    pub flaky_cases: Vec<String>,
    pub persistent_failures: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvalFamilyTrend {
    pub family: EvalFamily,
    pub scores: Vec<f64>,
    pub direction: EvalTrendDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalTrendDirection {
    Improving,
    Stable,
    Degrading,
    InsufficientData,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvalFixtureStabilityReport {
    pub report_id: String,
    pub suite_id: String,
    pub repeated_run_refs: Vec<String>,
    pub stable_cases: Vec<String>,
    pub flaky_cases: Vec<String>,
    pub blocked_cases: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
