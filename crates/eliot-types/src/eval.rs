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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct EvalCriterion {
    pub criterion_id: String,
    pub description: String,
    pub required: bool,
    pub measurement_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct EvalBudget {
    pub max_runtime_ms: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_tool_calls: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct EvalFixtureChecksum {
    pub fixture_ref: String,
    pub checksum: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
pub struct EvalIntegrityFingerprintSet {
    pub harness_fingerprint: String,
    pub evaluator_fingerprint: String,
    pub environment_fingerprint: String,
    pub actual_route: String,
    pub requested_route: String,
    pub acceptance_relation: String,
    pub oracle_owner: String,
}

impl EvalIntegrityFingerprintSet {
    /// True when any recorded fingerprint differs from current identity.
    /// Exact string equality; no normalization, no partial credit. A
    /// mismatch means the recorded result predates current evaluator
    /// identity and must be treated as stale, never as fresh evidence.
    pub fn is_stale_against(&self, current: &Self) -> bool {
        self != current
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCaseResult {
    pub result_id: String,
    pub eval_case_id: EvalCaseId,
    pub family: EvalFamily,
    pub status: EvalCaseStatus,
    pub measurements: Vec<EvalMeasurementResult>,
    pub produced_refs: Vec<String>,
    pub errors: Vec<String>,
    pub duration_ms: u64,
    /// Integrity fingerprints recorded when this result was produced.
    /// `None` for results predating fingerprint retention: unknown, never
    /// a freshness claim and never stale-proven. Compared against current
    /// evaluator identity by consumers to mark stale results; retention
    /// alone never grants measured validity.
    #[serde(default)]
    pub integrity_fingerprints: Option<EvalIntegrityFingerprintSet>,
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
#[serde(deny_unknown_fields)]
pub struct EvalMeasurementResult {
    pub measurement_id: String,
    pub passed: bool,
    pub observed: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct EvalFamilyScore {
    pub family: EvalFamily,
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
    pub total: u32,
    pub score_percent: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Sealed evaluation-integrity receipt for the replay-exact path (issue #1922 W6a).
///
/// I18.47 requires every load-bearing evaluation to produce an integrity
/// receipt and states that the original receipt remains immutable: a post-hoc
/// change cannot rewrite an observed outcome. This receipt is the sealed,
/// carried form of that requirement for canonical sealed replay. The producer
/// seals the body with `compute_seal`, the run report carries it, and the
/// consumer fails closed when `verify_seal` or the run binding does not hold.
/// Runs without canonical sealed inputs carry no receipt (`None`); absence is
/// unknown provenance, never a validity claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEvaluationIntegrityReceipt {
    /// Seal-bound identifier: `replay-evaluation-integrity:{seal}`.
    pub receipt_id: String,
    /// Evaluated path kind. Always `replay-exact`: this receipt states a
    /// replay/modelled-path result, never a live product observation.
    pub path_kind: String,
    /// Evidence class. Always `replay-only`: replay evidence calibrates an
    /// oracle but cannot alone promote live product proof (I18.47).
    pub evidence_origin: String,
    /// Precise evaluated property: the replay-exact outcome of the sealed set.
    pub property: String,
    /// Product Identity under evaluation, per replay run project.
    pub product_identity: String,
    /// Owner of the deciding oracle: the sealed replay evaluator.
    pub oracle_owner: String,
    /// Acceptance relation between measurements and sealed evidence.
    pub acceptance_relation: String,
    /// Evidence family instance: `replay-exact:{sealed_input_hash}`.
    pub evidence_family: String,
    /// Shared lineage inputs this result depends on (evaluator, profile,
    /// context, and observation evidence hashes).
    pub shared_dependencies: Vec<String>,
    /// Source artifact bindings: sealed set, case, and snapshot record ids.
    pub artifact_binding: Vec<String>,
    /// Route that produced this receipt (the canonical replay entrypoint).
    pub actual_route: String,
    /// Declared resource envelope of the producing run profile.
    pub resource_fingerprint: String,
    /// Non-product proof ceiling. Always `REPLAY_ONLY`.
    pub proof_ceiling: String,
    /// Measured-validity state. Always `INCONCLUSIVE`: no known-valid or
    /// known-invalid runtime sets exist, and a missing denominator is never
    /// zero error (I18.47).
    pub status: String,
    /// Deterministic creation time, derived from sealed execution content.
    /// Rides outside the seal like sealed replay record timestamps.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Tamper-evident blake3 seal over the seal projection.
    pub seal: String,
}

impl ReplayEvaluationIntegrityReceipt {
    /// Seal-bound receipt identifier shared by producer and verifier.
    pub fn receipt_id_for_seal(seal: &str) -> String {
        format!("replay-evaluation-integrity:{seal}")
    }

    /// Canonical projection of the sealed body fields. Single source for both
    /// sealing and verification; field order is fixed.
    pub fn seal_projection(&self) -> Value {
        serde_json::json!({
            "path_kind": self.path_kind,
            "evidence_origin": self.evidence_origin,
            "property": self.property,
            "product_identity": self.product_identity,
            "oracle_owner": self.oracle_owner,
            "acceptance_relation": self.acceptance_relation,
            "evidence_family": self.evidence_family,
            "shared_dependencies": self.shared_dependencies,
            "artifact_binding": self.artifact_binding,
            "actual_route": self.actual_route,
            "resource_fingerprint": self.resource_fingerprint,
            "proof_ceiling": self.proof_ceiling,
            "status": self.status,
        })
    }

    /// Compute the tamper-evident blake3 seal over the seal projection.
    pub fn compute_seal(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&self.seal_projection())?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// True only when the seal matches the current body and the receipt id is
    /// bound to that seal. Any post-hoc body mutation fails.
    pub fn verify_seal(&self) -> bool {
        match self.compute_seal() {
            Ok(seal) => seal == self.seal && self.receipt_id == Self::receipt_id_for_seal(&seal),
            Err(_) => false,
        }
    }
}

/// Decoder: derived and closed. The `#[serde(default)]` meta fields keep
/// pre-meta harness records readable and decode as absent or explicitly
/// uncertain (`InsufficientEvidence`); none of them can promote a candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Decoder: derived and closed. Version meaning stays with the owner
/// (`eliot-engine` `validate_replay_threshold_policy` pins `schema_version`
/// and rejects an empty `evaluator_version`); the decoder only fixes the key
/// set and refuses unknown tags, wrong payloads and duplicate keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayThresholdPolicyV1 {
    pub schema_version: String,
    pub evaluator_version: String,
    pub minimum_pass_basis_points: u16,
    pub maximum_counter_regressions: u16,
}

/// Decoder: internally tagged on `policy_kind`; an unknown tag or a mismatched
/// payload shape is refused, and unknown keys inside either variant are refused
/// too. `Unsupported.payload` stays a free-form `Value` by wire contract: bytes
/// inside that payload are not certified duplicate-free here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "policy_kind", rename_all = "snake_case", deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct MetaIsolationFence {
    pub evaluator_version: String,
    pub evaluator_hash: String,
    pub threshold_version: String,
    pub threshold_hash: String,
    pub fixed_replay_set_hash: String,
    pub holdout_replay_set_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct MetaPolicyAuthorization {
    pub operator_command_ref: String,
    pub expected_action_hash: String,
    pub exact_action_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct EvalComponentCoverage {
    pub component: String,
    pub eval_case_refs: Vec<String>,
    pub covered_failure_modes: Vec<String>,
    pub uncovered_failure_modes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRiskCoverage {
    pub risk_id: String,
    pub description: String,
    pub severity: EvalRegressionSeverity,
    pub eval_case_refs: Vec<String>,
    pub status: EvalCoverageStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Retained evaluator identity for the run this baseline approves, when
    /// every contributing case result carries one identical set. `None`
    /// means unknown provenance (pre-retention baselines, empty or mixed
    /// runs) and is non-evidence downstream. Additive optional field per
    /// I5.22: old payloads parse with `None`; no existing field changes.
    #[serde(default)]
    pub integrity_fingerprints: Option<EvalIntegrityFingerprintSet>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct EvalFamilyThreshold {
    pub family: EvalFamily,
    pub min_score: f64,
    pub severity_if_below: EvalRegressionSeverity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
