use crate::{AgentHostId, ProjectId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub use crate::external_agent::{
    CognitiveProviderMcpServer, CognitiveProviderRuntimeContract, CognitiveRuntimePreflightReceipt,
};

pub const COGNITIVE_FIELD_SUITE_SCHEMA_VERSION: &str = "eliot-cognitive-field-suite-v2";
pub const COGNITIVE_FIELD_V2_HARNESS_VERSION: &str = "cognitive-field-v2";
pub const COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION: &str = "cognitive-core-qualification-v1";
pub const COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS: u8 = 12;
pub const COGNITIVE_CORE_CONTINUATION_EXPECTED_PROVIDER_CALLS: u8 = 8;
pub const COGNITIVE_CORE_CONTINUATION_MAX_PROVIDER_CALLS: u8 = 9;
pub const COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION: &str = "eliot-task-intent-oracle-v1";
pub const COGNITIVE_UNDERSTANDING_SCHEMA_VERSION: &str = "eliot-cognitive-understanding-answer-v1";
pub const COGNITIVE_JUDGE_SCHEMA_VERSION: &str = "eliot-cognitive-judge-result-v1";
pub const COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION: &str =
    "eliot-cognitive-deterministic-report-v1";
pub const COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION: &str =
    "eliot-cognitive-deterministic-evidence-v1";
pub const COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION: &str = "eliot-cognitive-field-contract-v1";
pub const COGNITIVE_FIELD_PLAN_SCHEMA_VERSION: &str = "eliot-cognitive-field-plan-v1";
pub const COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION: &str =
    "eliot-cognitive-field-provider-plan-v1";
pub const COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION: &str =
    "eliot-cognitive-field-provider-evidence-v1";
pub const COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION: &str =
    "eliot-cognitive-field-provider-projection-v1";
pub const COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION: &str = "eliot-cognitive-provider-runtime-v1";
pub const COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION: &str = "eliot-cognitive-runtime-preflight-v1";
pub const COGNITIVE_FIELD_WORKER_SCHEMA_VERSION: &str = "eliot-cognitive-worker-result-v1";
pub const COGNITIVE_FIELD_MAX_PROVIDER_CALLS: u8 = 24;

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub enum CognitiveFieldFamily {
    U,
    M,
    D,
    A,
    H,
    R,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveFieldTier {
    Deterministic,
    Integration,
    ProviderSmoke,
    FieldCertification,
    Longitudinal,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveFieldRole {
    CodexWorker,
    UnderstandingReader,
    CodexJudge,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveMemoryCondition {
    Treatment,
    MemoryFreeControl,
    RawCorpus,
    DistilledCorpus,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveRepositoryCondition {
    PrimaryRepository,
    SecondRepository,
    SyntheticEdgeCase,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveHardGateKind {
    InvalidBinding,
    FabricatedOrCrossProjectHandle,
    HistoricalMemoryPresentedAsCurrent,
    MissingCausalHopEvidence,
    MissingOrWrongScopeVerifier,
    EmptyExpectedObservable,
    ContradictoryPredictionFrame,
    ControllerSubstitution,
    MemoryFreeControlContamination,
    ObservabilityMovedTruthRevision,
    SecretPrivateMarkerOrOracleLeak,
    UnauthorizedCandidatePromotion,
    FalseDone,
    UnreconciledProviderUnknownOutcome,
}

impl CognitiveHardGateKind {
    pub const ALL: [Self; 14] = [
        Self::InvalidBinding,
        Self::FabricatedOrCrossProjectHandle,
        Self::HistoricalMemoryPresentedAsCurrent,
        Self::MissingCausalHopEvidence,
        Self::MissingOrWrongScopeVerifier,
        Self::EmptyExpectedObservable,
        Self::ContradictoryPredictionFrame,
        Self::ControllerSubstitution,
        Self::MemoryFreeControlContamination,
        Self::ObservabilityMovedTruthRevision,
        Self::SecretPrivateMarkerOrOracleLeak,
        Self::UnauthorizedCandidatePromotion,
        Self::FalseDone,
        Self::UnreconciledProviderUnknownOutcome,
    ];
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CognitiveSecondRepositoryPolicy {
    pub environment_variable: String,
    pub allow_network_clone: bool,
    pub require_real_repository: bool,
    pub require_permissive_license: bool,
    pub synthetic_fixture_satisfies_portability: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldCase {
    pub ordinal: u8,
    pub case_id: String,
    pub family: CognitiveFieldFamily,
    pub title: String,
    pub tier: CognitiveFieldTier,
    pub model_backed: bool,
    pub repository_condition: CognitiveRepositoryCondition,
    pub memory_conditions: Vec<CognitiveMemoryCondition>,
    pub required_roles: Vec<CognitiveFieldRole>,
    pub oracle_ref: String,
    pub reader_prompt_ref: String,
    pub deterministic_verifier_refs: Vec<String>,
    pub contamination_rules: Vec<String>,
    pub hard_gates: Vec<CognitiveHardGateKind>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldSuite {
    pub schema_version: String,
    pub harness_version: String,
    pub hard_provider_call_cap: u8,
    pub second_repository: CognitiveSecondRepositoryPolicy,
    pub reader_output_schema_ref: String,
    pub judge_output_schema_ref: String,
    pub shared_contamination_rules: Vec<String>,
    pub shared_hard_gates: Vec<CognitiveHardGateKind>,
    pub cases: Vec<CognitiveFieldCase>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIntentOracle {
    pub schema_version: String,
    pub oracle_id: String,
    pub exact_user_prompt_hash: String,
    pub exact_user_prompt_ref: String,
    pub source_commit: String,
    pub normalized_goal: String,
    pub desired_state: Vec<String>,
    pub acceptance_items: Vec<String>,
    pub non_goals: Vec<String>,
    pub architecture_constraints: Vec<String>,
    pub expected_subsystem_set: Vec<String>,
    pub acceptable_owner_file_symbol_alternatives: Vec<String>,
    pub required_invariant_refs: Vec<String>,
    pub required_verifier_refs: Vec<String>,
    pub forbidden_conclusions: Vec<String>,
    pub authoritative_source_refs: Vec<String>,
    pub oracle_hash: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldCausalHop {
    pub hop_kind: String,
    pub from: String,
    pub relation: String,
    pub to: String,
    pub evidence_refs: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveUnderstandingAnswer {
    pub schema_version: String,
    pub case_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub memory_condition: CognitiveMemoryCondition,
    pub user_goal: String,
    pub desired_state: Vec<String>,
    pub non_goals: Vec<String>,
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
    pub files_to_inspect: Vec<String>,
    pub files_to_change: Vec<String>,
    pub causal_hops: Vec<CognitiveFieldCausalHop>,
    pub invariants: Vec<String>,
    pub known_failures: Vec<String>,
    pub current_truth_refs: Vec<String>,
    pub stale_or_rejected_memory_refs: Vec<String>,
    pub open_unknowns: Vec<String>,
    pub cheapest_discriminative_probes: Vec<String>,
    pub predicted_changed_paths: Vec<String>,
    pub predicted_failing_verifiers: Vec<String>,
    pub next_action: String,
    pub expected_observable: String,
    pub verifier_ref: String,
    pub stop_condition: String,
    pub memory_handles_received: Vec<String>,
    pub memory_handles_expanded: Vec<String>,
    pub memory_handles_used: Vec<String>,
    pub influence_receipt_refs: Vec<String>,
    pub confidence_by_section: BTreeMap<String, u8>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveJudgeScores {
    pub intent_fidelity: u8,
    pub system_boundary: u8,
    pub causal_mechanism: u8,
    pub evidence_validity: u8,
    pub current_truth_accuracy: u8,
    pub stale_memory_rejection: u8,
    pub invariant_and_non_goal_coverage: u8,
    pub unknown_honesty: u8,
    pub action_quality: u8,
    pub verifier_quality: u8,
}

impl CognitiveJudgeScores {
    pub const fn values(&self) -> [u8; 10] {
        [
            self.intent_fidelity,
            self.system_boundary,
            self.causal_mechanism,
            self.evidence_validity,
            self.current_truth_accuracy,
            self.stale_memory_rejection,
            self.invariant_and_non_goal_coverage,
            self.unknown_honesty,
            self.action_quality,
            self.verifier_quality,
        ]
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveJudgeDiscrepancy {
    pub category: String,
    pub expected_refs: Vec<String>,
    pub observed_refs: Vec<String>,
    pub explanation: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveJudgeResult {
    pub schema_version: String,
    pub case_id: String,
    pub oracle_hash: String,
    pub reader_output_hash: String,
    pub deterministic_report_hash: String,
    pub scores: CognitiveJudgeScores,
    pub exact_discrepancies: Vec<CognitiveJudgeDiscrepancy>,
    pub forbidden_conclusion_detected: bool,
    pub semantic_pass: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveHardGateEvidence {
    pub gate: CognitiveHardGateKind,
    pub passed: bool,
    pub evidence_refs: Vec<String>,
    pub explanation: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveDeterministicReport {
    pub schema_version: String,
    pub case_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub source_commit: String,
    pub verifier_refs: Vec<String>,
    pub hard_gate_evidence: Vec<CognitiveHardGateEvidence>,
    pub controller_provider_calls: u8,
    pub truth_revision_before: String,
    pub truth_revision_after_observability: String,
    pub report_hash: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveVerifierCommandReceipt {
    pub command_ref: String,
    pub arguments_sha256: String,
    pub exit_code: i32,
    pub elapsed_ms: u64,
    pub stdout_path: String,
    pub stdout_sha256: String,
    pub stderr_path: String,
    pub stderr_sha256: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveDeterministicEvidenceReceipt {
    pub schema_version: String,
    pub run_id: String,
    pub case_id: String,
    pub memory_condition: CognitiveMemoryCondition,
    pub source_commit: String,
    pub verifier_refs: Vec<String>,
    pub commands: Vec<CognitiveVerifierCommandReceipt>,
    pub controller_provider_calls: u8,
    pub truth_revision_before: String,
    pub truth_revision_after_observability: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldExecutionKey {
    pub case_id: String,
    pub memory_condition: CognitiveMemoryCondition,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldProviderCallPlan {
    pub call_number: u8,
    pub call_id: String,
    pub role: CognitiveFieldRole,
    #[schemars(with = "String")]
    pub host: AgentHostId,
    pub requested_model: String,
    pub expected_provider_executable_sha256: String,
    pub prompt_ref: String,
    pub prompt_sha256: String,
    pub canonical_schema_sha256: String,
    pub provider_schema_sha256: String,
    pub provider_smoke: bool,
    pub counts_against_cap: bool,
    pub executions: Vec<CognitiveFieldExecutionKey>,
    #[serde(default)]
    pub runtime_contract_ref: String,
    #[serde(default)]
    pub runtime_contract_sha256: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldProviderPlan {
    pub schema_version: String,
    pub run_id: String,
    pub contract_hash: String,
    pub calls: Vec<CognitiveFieldProviderCallPlan>,
    pub planned_provider_calls: u8,
    pub planned_smoke_calls: u8,
    #[serde(default)]
    pub planned_reused_roles: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_evidence_plan_hash: Option<String>,
    pub plan_hash: String,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub sealed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveWorkerResult {
    pub schema_version: String,
    pub case_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub memory_condition: CognitiveMemoryCondition,
    pub simulated: bool,
    pub work_summary: String,
    pub current_truth_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub failure_refs: Vec<String>,
    pub decision_refs: Vec<String>,
    pub memory_handles_used: Vec<String>,
    pub influence_receipt_refs: Vec<String>,
    pub next_state_ref: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldProviderOutputReceipt {
    pub execution: CognitiveFieldExecutionKey,
    pub output_path: String,
    pub output_sha256: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CognitiveFieldProviderEvidenceReceipt {
    pub schema_version: String,
    pub run_id: String,
    pub contract_hash: String,
    pub provider_plan_hash: String,
    pub source_commit: String,
    pub call_id: String,
    pub role: CognitiveFieldRole,
    #[schemars(with = "String")]
    pub host: AgentHostId,
    pub requested_model: String,
    pub resolved_model: String,
    pub provider_session_id: String,
    pub provider_receipt_ref: String,
    pub provider_executable: String,
    pub provider_executable_sha256: String,
    pub prompt_path: String,
    pub prompt_sha256: String,
    pub raw_stdout_path: String,
    pub raw_stdout_sha256: String,
    pub raw_stderr_path: String,
    pub raw_stderr_sha256: String,
    pub outputs: Vec<CognitiveFieldProviderOutputReceipt>,
    pub provider_calls: u8,
    pub exit_code: i32,
    pub elapsed_ms: u64,
    pub timed_out: bool,
    pub unknown_outcome: bool,
    pub controller_substitution: bool,
    pub oracle_exposed: bool,
    pub worker_transcript_exposed: bool,
    pub read_only: bool,
    #[serde(default)]
    pub runtime_contract_sha256: String,
    #[serde(default)]
    pub observed_mcp_server_names: Vec<String>,
    #[serde(default)]
    pub observed_mcp_tool_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldProviderOutputProjection {
    pub execution: CognitiveFieldExecutionKey,
    pub output_sha256: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldProviderProjection {
    pub schema_version: String,
    pub run_id: String,
    pub contract_hash: String,
    pub provider_plan_hash: String,
    pub source_commit: String,
    pub call_id: String,
    pub role: CognitiveFieldRole,
    #[schemars(with = "String")]
    pub host: AgentHostId,
    pub requested_model: String,
    pub resolved_model: String,
    pub provider_session_id: String,
    pub provider_receipt_ref: String,
    pub provider_executable_sha256: String,
    pub prompt_sha256: String,
    pub raw_stdout_sha256: String,
    pub raw_stderr_sha256: String,
    pub outputs: Vec<CognitiveFieldProviderOutputProjection>,
    pub provider_smoke: bool,
    pub counts_against_cap: bool,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub runtime_contract_sha256: String,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
    pub case_count: usize,
    pub family_counts: BTreeMap<CognitiveFieldFamily, usize>,
    pub model_backed_case_count: usize,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveOracleLeakFinding {
    pub surface: String,
    pub field: String,
    pub value_hash: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveOracleLeakReport {
    pub clean: bool,
    pub scanned_surfaces: Vec<String>,
    pub findings: Vec<CognitiveOracleLeakFinding>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldCaseGrade {
    pub case_id: String,
    pub deterministic_pass: bool,
    pub semantic_pass: bool,
    pub semantic_average_milli: u16,
    pub passed: bool,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldRunContract {
    pub schema_version: String,
    pub run_id: String,
    pub suite_sha256: String,
    pub source_commit: String,
    pub primary_repository: String,
    pub second_repository: String,
    pub second_repository_commit: String,
    pub output_root: String,
    pub private_root_sha256: String,
    pub hard_provider_call_cap: u8,
    pub contract_hash: String,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub sealed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldPlanItem {
    pub case_id: String,
    pub tier: CognitiveFieldTier,
    pub model_backed: bool,
    pub roles: Vec<CognitiveFieldRole>,
    pub memory_conditions: Vec<CognitiveMemoryCondition>,
    pub oracle_ref: String,
    pub deterministic_verifier_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveFieldPlan {
    pub schema_version: String,
    pub run_id: String,
    pub contract_hash: String,
    pub items: Vec<CognitiveFieldPlanItem>,
    pub planned_provider_calls: u8,
    pub hard_provider_call_cap: u8,
    pub plan_hash: String,
}

#[allow(clippy::expect_used)]
pub fn cognitive_understanding_answer_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(CognitiveUnderstandingAnswer))
        .expect("CognitiveUnderstandingAnswer schema must serialize")
}

pub fn cognitive_judge_result_schema() -> Result<Value, serde_json::Error> {
    serde_json::to_value(schemars::schema_for!(CognitiveJudgeResult))
}

pub fn cognitive_worker_result_schema() -> Result<Value, serde_json::Error> {
    serde_json::to_value(schemars::schema_for!(CognitiveWorkerResult))
}

pub fn minimal_cognitive_understanding_answer() -> CognitiveUnderstandingAnswer {
    CognitiveUnderstandingAnswer {
        schema_version: COGNITIVE_UNDERSTANDING_SCHEMA_VERSION.to_owned(),
        case_id: "U01".to_owned(),
        project_id: ProjectId::new_v7(),
        task_id: TaskId::new_v7(),
        memory_condition: CognitiveMemoryCondition::Treatment,
        user_goal: "Identify the current project purpose".to_owned(),
        desired_state: vec!["Project purpose is evidence-backed".to_owned()],
        non_goals: vec!["Do not modify source".to_owned()],
        project_purpose: "Evidence-governed local memory runtime".to_owned(),
        subsystem_refs: vec!["module:project-understanding".to_owned()],
        owner_modules: vec!["crates/eliot-engine/src/project_understanding.rs".to_owned()],
        entrypoint_refs: vec!["symbol:ProjectUnderstandingCompiler".to_owned()],
        files_to_inspect: vec!["Cargo.toml".to_owned()],
        files_to_change: Vec::new(),
        causal_hops: vec![CognitiveFieldCausalHop {
            hop_kind: "intent_to_concept".to_owned(),
            from: "goal:identify-purpose".to_owned(),
            relation: "maps_to".to_owned(),
            to: "concept:project-purpose".to_owned(),
            evidence_refs: vec!["source:README.md".to_owned()],
            status: "verified".to_owned(),
        }],
        invariants: vec!["current source outranks memory".to_owned()],
        known_failures: Vec::new(),
        current_truth_refs: vec!["source:Cargo.toml".to_owned()],
        stale_or_rejected_memory_refs: Vec::new(),
        open_unknowns: Vec::new(),
        cheapest_discriminative_probes: vec!["cargo metadata --no-deps".to_owned()],
        predicted_changed_paths: Vec::new(),
        predicted_failing_verifiers: Vec::new(),
        next_action: "Inspect the exact source anchors".to_owned(),
        expected_observable: "Purpose and owners cite current files".to_owned(),
        verifier_ref: "verifier:cognitive-field-contract".to_owned(),
        stop_condition: "Required purpose and invariant refs are present".to_owned(),
        memory_handles_received: Vec::new(),
        memory_handles_expanded: Vec::new(),
        memory_handles_used: Vec::new(),
        influence_receipt_refs: Vec::new(),
        confidence_by_section: BTreeMap::from([("project_purpose".to_owned(), 4)]),
    }
}

pub fn minimal_cognitive_judge_result() -> CognitiveJudgeResult {
    CognitiveJudgeResult {
        schema_version: COGNITIVE_JUDGE_SCHEMA_VERSION.to_owned(),
        case_id: "U01".to_owned(),
        oracle_hash: "blake3:oracle".to_owned(),
        reader_output_hash: "blake3:reader".to_owned(),
        deterministic_report_hash: "blake3:deterministic".to_owned(),
        scores: CognitiveJudgeScores {
            intent_fidelity: 4,
            system_boundary: 4,
            causal_mechanism: 4,
            evidence_validity: 4,
            current_truth_accuracy: 4,
            stale_memory_rejection: 4,
            invariant_and_non_goal_coverage: 4,
            unknown_honesty: 4,
            action_quality: 4,
            verifier_quality: 4,
        },
        exact_discrepancies: Vec::new(),
        forbidden_conclusion_detected: false,
        semantic_pass: true,
    }
}
