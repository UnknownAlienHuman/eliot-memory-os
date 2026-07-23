//! Versioned cognitive-memory, responsibility-routing, autonomy, and operator contracts.

use crate::semantic_memory::{
    CognitiveFailureLocalizationReport, CognitiveTransferLabReport, ExperienceBrief,
    ExperienceCase, ExperiencePattern, MemoryApplicabilityDecision, MemoryCorpusProfile,
    NegativeTransferRecord, TaskMeaningFrame,
};
use crate::{
    AgentResultDisposition, AgentResultEnvelope, AgentSessionHostBinding, AgentSessionId,
    BackupInventoryEntry, ClaimCard, ClaimSummary, CompletionProof, ControllerLease,
    IncidentRecord, MemoryLifecyclePacketView, MemoryRevision, OperationJob,
    ProceduralSkillPacketView, ProjectId, RecoveryAction, TaskContract, TaskId, TaskRoleLease,
    VerificationResult, WorkConflict, WorkItem, WorkItemId, WorkLease, WorktreeLease,
    WriteReceiptRef,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub const OPERATOR_SCHEMA_VERSION: &str = "eliot-operator-contract-v1";
pub const OPERATOR_IPC_PROTOCOL_VERSION: &str = "eliot-ipc-l3-v1";
pub const OPERATOR_CONTRACT_MANIFEST: &str = include_str!("../schema/operator-contract-v1.json");

pub fn operator_contract_hash() -> String {
    operator_contract_hash_for_manifest(OPERATOR_CONTRACT_MANIFEST)
}

fn operator_contract_hash_for_manifest(manifest: &str) -> String {
    let parsed = match serde_json::from_str::<Value>(manifest) {
        Ok(parsed) => parsed,
        Err(error) => panic!("embedded operator contract manifest must be valid JSON: {error}"),
    };
    let canonical = canonicalize_json_value(&parsed);
    let canonical_bytes = match serde_json::to_vec(&canonical) {
        Ok(bytes) => bytes,
        Err(error) => panic!("operator contract JSON must serialize canonically: {error}"),
    };
    blake3::hash(&canonical_bytes).to_hex().to_string()
}

fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json_value).collect()),
        Value::Object(fields) => {
            let mut entries = fields.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonicalize_json_value(value)))
                    .collect(),
            )
        }
        scalar => scalar.clone(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketQualityResult {
    Sufficient,
    Degraded,
    Insufficient,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PacketQualityReport {
    pub packet_id: String,
    pub task_id: String,
    pub revision_fence: MemoryRevision,
    pub structured_bytes: usize,
    pub estimated_tokens: usize,
    pub task_frame_present: bool,
    pub current_truth_coverage: f32,
    pub causal_bridge_hops: usize,
    pub causal_bridge_missing_hops: Vec<String>,
    pub negative_memory_checked: bool,
    pub exact_atoms_count: usize,
    pub material_unknowns: usize,
    pub verifier_present: bool,
    pub stale_items_suppressed: usize,
    pub wrong_scope_items_suppressed: usize,
    pub tool_schema_bytes_visible: usize,
    pub instruction_hotset_size: usize,
    pub signal_density: f32,
    pub result: PacketQualityResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CurrentTruthSnapshot {
    pub project_id: ProjectId,
    pub task_id: String,
    pub branch: String,
    pub commit: String,
    pub environment: Vec<String>,
    pub revision_fence: MemoryRevision,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CausalBridgeHop {
    pub from: String,
    pub relation: String,
    pub to: String,
    pub evidence_ref: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpistemicPacketState {
    pub supported: Vec<String>,
    pub assumed: Vec<String>,
    pub conflicted: Vec<String>,
    pub unknown: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionLocalitySuffix {
    pub exact_load_bearing_atoms: Vec<String>,
    pub open_unknowns: Vec<String>,
    pub cheapest_discriminative_probes: Vec<String>,
    pub responsibility_contour_route_refs: Vec<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier: String,
    pub stop_condition: String,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MaterialPacketFrame {
    pub acceptance_items: Vec<String>,
    pub environment: Vec<String>,
    pub active_plan: Vec<String>,
    pub completed_work: Vec<String>,
    pub killed_paths: Vec<String>,
    pub causal_bridge: Vec<CausalBridgeHop>,
    pub negative_memory_checked: bool,
    pub exact_load_bearing_atoms: Vec<String>,
    pub cheapest_discriminative_probes: Vec<String>,
    pub responsibility_contour_route_refs: Vec<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier: String,
    pub stop_condition: String,
    pub tool_schema_bytes_visible: usize,
    pub instruction_hotset_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnderstandingOutcome {
    Validated,
    Revised,
    Refuted,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnderstandingOutcomeRecord {
    pub task_id: TaskId,
    pub session_id: AgentSessionId,
    pub packet_id: String,
    pub expected_owner_or_module: String,
    pub selected_owner_or_module: String,
    pub proposed_causal_bridge: Vec<CausalBridgeHop>,
    pub exact_handles_used: Vec<String>,
    pub predicted_observable: String,
    pub selected_probe_or_action: String,
    pub selected_write_set: Vec<String>,
    pub selected_verifier: String,
    pub actual_changed_artifacts: Vec<String>,
    pub actual_observation: String,
    pub verifier_result: VerificationResult,
    pub causal_bridge_validated: bool,
    pub wrong_path_attempts: u32,
    pub avoidable_tool_calls: u32,
    pub revision_required: bool,
    pub outcome: UnderstandingOutcome,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAdmissionDecision {
    IncludeVerified,
    IncludeSupported,
    RequireRevalidation,
    PreserveConflict,
    SuppressStale,
    SuppressWrongScope,
    RejectTainted,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryInfluenceClass {
    UsedAndChangedAction,
    UsedForVerification,
    PreventedRepeatedFailure,
    SuppressedAsStale,
    SuppressedAsWrongScope,
    SeenButNotUsed,
    LoadedWithoutDelta,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct MemoryInfluenceTrace {
    pub task_id: TaskId,
    pub session_id: AgentSessionId,
    pub memory_handle: String,
    pub packet_id: String,
    pub admission_decision: MemoryAdmissionDecision,
    pub inclusion_or_suppression_reason: String,
    pub epistemic_status_at_use: String,
    pub cited_in_understanding_proof: bool,
    pub action_or_probe_changed: bool,
    pub write_set_changed: bool,
    pub verifier_changed: bool,
    pub repeated_failure_prevented: bool,
    pub suppressed_as_stale_or_wrong_scope: bool,
    pub downstream_outcome_ref: Option<String>,
    pub influence_class: MemoryInfluenceClass,
    #[schemars(with = "Option<serde_json::Value>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryDecisionReceipt {
    pub task_id: TaskId,
    pub memory_handle: String,
    pub source_and_anchor: String,
    pub scope: Vec<String>,
    pub status: String,
    pub freshness: String,
    pub authority: String,
    pub conflicts: Vec<String>,
    pub admission: MemoryAdmissionDecision,
    pub action_effect: String,
    pub verifier_effect: String,
    pub future_activation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextCargoReceipt {
    pub receipt_id: String,
    pub task_id: TaskId,
    pub session_id: AgentSessionId,
    pub memory_handle: String,
    pub packet_load_count: u32,
    pub decision_delta_count: u32,
    pub verifier_delta_count: u32,
    pub disposition: MemoryInfluenceClass,
    pub demotion_candidate: bool,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryValueExperiment {
    pub task_b_hash: String,
    pub host_model_harness: String,
    pub current_truth_snapshot: CurrentTruthSnapshot,
    pub reusable_memory_handles: Vec<String>,
    pub stale_or_wrong_scope_control_handles: Vec<String>,
    pub expected_decision_delta: Vec<String>,
    pub primary_metrics: Vec<String>,
    pub counter_metrics: Vec<String>,
    pub contamination_controls: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlanningDecisionRecord {
    pub first_action_or_probe: String,
    pub selected_owner_or_module: String,
    pub selected_write_set: Vec<String>,
    pub selected_verifier: String,
    pub wrong_path_attempts: u32,
    pub tool_calls_before_correct_boundary: u32,
    pub material_unknowns: Vec<String>,
    pub confidence: f32,
    pub estimated_tokens: usize,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryValueComparison {
    pub task_b_hash: String,
    pub control: PlanningDecisionRecord,
    pub treatment: PlanningDecisionRecord,
    pub changed_dimensions: Vec<String>,
    pub observable_decision_delta: bool,
    pub treatment_preferred: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NegativeMemoryDecision {
    Allow,
    BlockRepeatedFailure,
    RequireDiscriminativeProbe,
    Reopen,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NegativeMemoryGateInput {
    pub fingerprint: String,
    pub repeated_count: u64,
    pub scope_matches: bool,
    pub reopen_conditions: Vec<String>,
    pub satisfied_reopen_conditions: Vec<String>,
    pub discriminative_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NegativeMemoryDecisionReceipt {
    pub receipt_id: String,
    pub fingerprint: String,
    pub decision: NegativeMemoryDecision,
    pub reasons: Vec<String>,
    pub reopen_conditions: Vec<String>,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsibilityContour {
    Framing,
    Planning,
    Understanding,
    Research,
    Implementation,
    Audit,
    Verification,
    Recovery,
    MemoryCuration,
    OperatorApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContourPolicyScope {
    System,
    Project,
    Task,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContourPreferredRoute {
    pub host_id: String,
    pub model_route_optional: Option<String>,
    pub requested_role: String,
    pub capability_requirements: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContourRoutePolicy {
    pub policy_id: String,
    pub scope: ContourPolicyScope,
    pub project_id: Option<ProjectId>,
    pub task_id: Option<TaskId>,
    pub contour: ResponsibilityContour,
    pub preferred_routes: Vec<ContourPreferredRoute>,
    pub allowed_fallbacks: Vec<ContourPreferredRoute>,
    pub deterministic_adapter_preference: bool,
    pub max_parallelism: u32,
    pub cost_or_token_budget: Option<String>,
    pub wall_time_budget_seconds: u64,
    pub required_evidence: Vec<String>,
    pub required_verifier: Vec<String>,
    pub escalation_route: Option<ContourPreferredRoute>,
    #[serde(with = "time::serde::rfc3339")]
    pub effective_from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub policy_snapshot_id: String,
    pub owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContourRouteDecision {
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub contour: ResponsibilityContour,
    pub candidate_routes: Vec<ContourPreferredRoute>,
    pub selected_route: ContourPreferredRoute,
    pub capability_evidence: Vec<String>,
    pub availability_evidence: Vec<String>,
    pub policy_refs: Vec<String>,
    pub cost_latency_estimate: String,
    pub fallback: Option<ContourPreferredRoute>,
    pub decision_receipt: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LiveContourRoute {
    pub route: ContourPreferredRoute,
    pub available: bool,
    pub retention_allowed: bool,
    pub capability_evidence: Vec<String>,
    pub availability_evidence: Vec<String>,
    pub cost_latency_estimate: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutonomyRunState {
    Draft,
    Ready,
    Running,
    Verifying,
    DoneVerified,
    PausedByOperator,
    BlockedByUnknown,
    BlockedByApproval,
    Degraded,
    PartialProgress,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyRunContract {
    pub autonomy_run_id: String,
    pub project_id: ProjectId,
    pub root_task_id: TaskId,
    pub user_goal: String,
    pub acceptance_items: Vec<String>,
    pub contour_route_policy_ref: String,
    #[serde(default)]
    pub allowed_projects: Vec<ProjectId>,
    pub max_work_items: u32,
    pub max_active_agents: u32,
    pub max_model_invocations: u32,
    #[serde(default = "default_max_tool_calls")]
    pub max_tool_calls: u32,
    pub max_wall_time_seconds: u64,
    pub cost_or_token_budget: Option<String>,
    pub allowed_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
    #[serde(default)]
    pub forbidden_effects: Vec<String>,
    pub allowed_risk_tiers: Vec<String>,
    pub required_verifiers: Vec<String>,
    pub approval_boundaries: Vec<String>,
    pub pause_conditions: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub fallback_routes: Vec<ContourPreferredRoute>,
    #[serde(default = "default_recovery_policy_ref")]
    pub recovery_policy_ref: String,
    pub policy_snapshot_id: String,
    pub created_by: String,
    pub state: AutonomyRunState,
    pub state_revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyRunTransitionReceipt {
    pub transition_id: String,
    pub autonomy_run_id: String,
    pub from: AutonomyRunState,
    pub to: AutonomyRunState,
    pub state_revision: u64,
    pub reason: String,
    pub risk_tier: String,
    pub exact_approval_hash: Option<String>,
    pub verifier_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub transitioned_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActiveDecisionState {
    pub task_id: TaskId,
    pub packet_id: String,
    pub revision_fence: MemoryRevision,
    pub selected_owner_or_module: Option<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier: String,
    pub stop_condition: String,
    pub killed_paths: Vec<String>,
    pub open_unknowns: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskCognitionView {
    pub task_contract: TaskContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_meaning: Option<TaskMeaningFrame>,
    pub active_decision_state: Option<ActiveDecisionState>,
    pub current_truth: Vec<ClaimSummary>,
    pub epistemic_state: EpistemicPacketState,
    pub causal_bridge: Vec<CausalBridgeHop>,
    #[serde(default)]
    pub experience_priors: Vec<ExperienceBrief>,
    #[serde(default)]
    pub negative_memory: Vec<ClaimCard>,
    pub selected_memory: Vec<MemoryDecisionReceipt>,
    pub suppressed_memory: Vec<MemoryDecisionReceipt>,
    #[serde(default)]
    pub procedural_skills: ProceduralSkillPacketView,
    pub packet_quality: Option<PacketQualityReport>,
    pub understanding_outcomes: Vec<UnderstandingOutcomeRecord>,
    pub completion_proof: Option<CompletionProof>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryInspectorView {
    pub project_id: ProjectId,
    pub active_current_claim_refs: Vec<String>,
    pub recalled_candidate_refs: Vec<String>,
    pub stale_or_superseded_refs: Vec<String>,
    pub support_and_counterevidence_refs: Vec<String>,
    pub decisions: Vec<MemoryDecisionReceipt>,
    pub influence: Vec<MemoryInfluenceTrace>,
    pub cargo: Vec<ContextCargoReceipt>,
    #[serde(default)]
    pub lifecycle: MemoryLifecyclePacketView,
    #[serde(default)]
    pub experience_cases: Vec<ExperienceCase>,
    #[serde(default)]
    pub experience_patterns: Vec<ExperiencePattern>,
    #[serde(default)]
    pub applicability_decisions: Vec<MemoryApplicabilityDecision>,
    #[serde(default)]
    pub negative_transfer: Vec<NegativeTransferRecord>,
    #[serde(default)]
    pub cognitive_lab_results: Vec<CognitiveTransferLabReport>,
    #[serde(default)]
    pub failure_localization: Vec<CognitiveFailureLocalizationReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_profile: Option<MemoryCorpusProfile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRoutingView {
    pub host_session_refs: Vec<String>,
    pub task_role_lease_refs: Vec<String>,
    pub work_or_action_lease_refs: Vec<String>,
    pub route_policies: Vec<ContourRoutePolicy>,
    pub route_decisions: Vec<ContourRouteDecision>,
    #[serde(default)]
    pub host_sessions: Vec<AgentSessionHostBinding>,
    #[serde(default)]
    pub task_role_leases: Vec<TaskRoleLease>,
    #[serde(default)]
    pub controller_leases: Vec<ControllerLease>,
    #[serde(default)]
    pub operation_jobs: Vec<OperationJob>,
    #[serde(default)]
    pub agent_results: Vec<AgentResultEnvelope>,
    #[serde(default)]
    pub agent_result_dispositions: Vec<AgentResultDisposition>,
    #[serde(default)]
    pub work_items: Vec<WorkItem>,
    #[serde(default)]
    pub work_leases: Vec<WorkLease>,
    #[serde(default)]
    pub worktree_leases: Vec<WorktreeLease>,
    #[serde(default)]
    pub work_conflicts: Vec<WorkConflict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutonomyRunView {
    pub contract: AutonomyRunContract,
    pub work_item_refs: Vec<String>,
    pub assignment_refs: Vec<String>,
    pub verifier_result_refs: Vec<String>,
    #[serde(default)]
    pub route_decision_refs: Vec<String>,
    #[serde(default)]
    pub recovery_event_refs: Vec<String>,
    #[serde(default)]
    pub model_invocations_used: u32,
    #[serde(default)]
    pub tool_calls_used: u32,
    #[serde(default)]
    pub wall_time_used_seconds: u64,
    #[serde(default)]
    pub cost_or_tokens_used: Option<String>,
    #[serde(default)]
    pub pause_resume_reassignment_refs: Vec<String>,
    #[serde(default)]
    pub completion_proof: Option<CompletionProof>,
    pub finish_status: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyTripwireKind {
    RepeatedFailureSignature,
    NoNovelty,
    ContextSqueeze,
    CalibrationCollapse,
    RepeatedRefutation,
    ProviderFailure,
    LeaseExpiry,
    WriteSetConflict,
    VerifierFailure,
    BudgetExhaustion,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutonomyRecoveryRecord {
    pub recovery_id: String,
    pub autonomy_run_id: String,
    pub work_item_id: Option<WorkItemId>,
    pub tripwire: AutonomyTripwireKind,
    pub actions_taken: Vec<RecoveryAction>,
    pub prior_route_ref: Option<String>,
    pub next_route_ref: Option<String>,
    pub preserved_artifact_refs: Vec<String>,
    pub state_revision: u64,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

const fn default_max_tool_calls() -> u32 {
    64
}

fn default_recovery_policy_ref() -> String {
    "recovery-policy:legacy-safe-default".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub approval_id: String,
    pub exact_action_hash: String,
    pub risk_tier: String,
    pub write_or_resource_set: Vec<String>,
    pub reason_summary: String,
    pub verifier: String,
    pub rollback_or_compensation: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub decision_receipt: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceTimelineView {
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub event_refs: Vec<String>,
    pub incident_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSnapshot {
    pub schema_version: String,
    pub protocol_version: String,
    pub protocol_hash: String,
    pub runtime_id: String,
    pub auth_generation: String,
    pub health_refs: Vec<String>,
    pub task_cognition: Vec<TaskCognitionView>,
    pub memory_inspector: Option<MemoryInspectorView>,
    pub routing: AgentRoutingView,
    pub runs: Vec<AutonomyRunView>,
    pub approvals: Vec<ApprovalView>,
    pub timeline: TraceTimelineView,
    #[serde(default)]
    pub project_refs: Vec<String>,
    #[serde(default)]
    pub backup_inventory: Vec<BackupInventoryEntry>,
    #[serde(default)]
    pub incidents: Vec<IncidentRecord>,
    #[serde(default)]
    pub log_handles: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorProjectionKind {
    Overview,
    TasksWork,
    TaskCognition,
    MemoryExplorer,
    CausalProvenance,
    SchemaContracts,
    QueryLab,
    ExperienceSkills,
    SleepMeta,
    AgentsRouting,
    Autonomy,
    Approvals,
    TimelineOperations,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProjectionFilter {
    pub search: Option<String>,
    pub record_kind: Option<String>,
    pub status: Option<String>,
    pub lifecycle: Option<String>,
    pub authority: Option<String>,
    pub observed_after: Option<String>,
    pub observed_before: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorQueryRequest {
    pub projection: OperatorProjectionKind,
    pub project_id: Option<ProjectId>,
    pub task_id: Option<TaskId>,
    #[serde(default)]
    pub filter: OperatorProjectionFilter,
    pub cursor: Option<String>,
    pub page_size: u32,
    #[serde(default)]
    pub query_operation: Option<OperatorQueryOperation>,
    #[serde(default)]
    pub query_parameters: Option<Value>,
    #[serde(default)]
    pub result_mode: OperatorResultMode,
    #[serde(default)]
    pub selected_ref: Option<String>,
    #[serde(default = "default_operator_graph_depth")]
    pub expand_depth: u8,
}

const fn default_operator_graph_depth() -> u8 {
    1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorQueryOperation {
    CurrentState,
    RecallPreview,
    ExactEvidence,
    RelationshipSlice,
    TraceReplay,
    HealthReport,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorResultMode {
    #[default]
    Human,
    Json,
    Graph,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperatorFieldView {
    pub label: String,
    pub value: String,
    pub copyable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperatorRelationshipView {
    pub relation: String,
    pub target_ref: String,
    pub evidence_ref: Option<String>,
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperatorActionView {
    pub command: String,
    pub label: String,
    pub risk_tier: String,
    pub requires_reason: bool,
    pub requires_exact_action_hash: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperatorRecordView {
    pub record_ref: String,
    pub record_kind: String,
    pub title: String,
    pub summary: String,
    pub status: String,
    pub lifecycle: Option<String>,
    pub authority: String,
    pub observed_at: Option<String>,
    pub fields: Vec<OperatorFieldView>,
    pub relationships: Vec<OperatorRelationshipView>,
    pub actions: Vec<OperatorActionView>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperatorProjectionPage {
    pub schema_version: String,
    pub runtime_id: String,
    pub auth_generation: String,
    pub projection: OperatorProjectionKind,
    pub project_id: Option<ProjectId>,
    pub task_id: Option<TaskId>,
    pub task_revision: Option<MemoryRevision>,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub page_size: u32,
    pub returned: usize,
    pub total_matching: usize,
    pub total_is_exact: bool,
    pub truncated: bool,
    pub records: Vec<OperatorRecordView>,
    pub result_mode: OperatorResultMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_payload: Option<Value>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCurationPreviewRequest {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub at_revision: MemoryRevision,
    pub ruleset_version: String,
    pub cursor: Option<String>,
    pub page_size: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryCurationCorpusProfile {
    pub scanned_records: usize,
    pub scan_limit: usize,
    pub scan_truncated: bool,
    pub receipt_kind_counts: BTreeMap<String, usize>,
    pub lifecycle_counts: BTreeMap<String, usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCurationFindingKind {
    Duplicate,
    SemanticDuplicate,
    WrongScope,
    LowUtility,
    LowUtilityInsufficientEvidence,
    RepeatedLowDelta,
    StaleSuperseded,
    UnsafeInstruction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryCurationCandidate {
    pub handle: String,
    pub kind: String,
    pub lifecycle: String,
    pub authority: String,
    pub finding_kind: MemoryCurationFindingKind,
    pub evidence_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub confidence: u16,
    pub proposed_reversible_action: String,
    pub restore_requirements: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryCurationPreviewResponse {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub snapshot_revision: MemoryRevision,
    pub ruleset_version: String,
    pub read_only: bool,
    pub corpus_profile: MemoryCurationCorpusProfile,
    pub candidates: Vec<MemoryCurationCandidate>,
    pub protected_refs: Vec<String>,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub total_matching: usize,
    pub total_is_exact: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorCommand {
    SelectTask {
        task_id: TaskId,
    },
    RefreshPacket {
        task_id: TaskId,
    },
    RequestRevalidation {
        task_id: TaskId,
        memory_handle: String,
    },
    CreateAutonomyRun {
        contract: Box<AutonomyRunContract>,
    },
    PreviewAutonomyEdit {
        autonomy_run_id: String,
        proposed_contract: Box<AutonomyRunContract>,
    },
    StartRun {
        autonomy_run_id: String,
    },
    PauseRun {
        autonomy_run_id: String,
        reason: String,
    },
    ResumeRun {
        autonomy_run_id: String,
    },
    CancelRun {
        autonomy_run_id: String,
        reason: String,
    },
    DispositionAgentResult {
        result_id: String,
        disposition: String,
    },
    ContestMemory {
        task_id: TaskId,
        memory_handle: String,
        evidence_refs: Vec<String>,
    },
    SuppressMemory {
        task_id: TaskId,
        memory_handle: String,
        reason: String,
    },
    ArchiveMemory {
        task_id: TaskId,
        memory_handle: String,
        reason: String,
    },
    RestoreMemory {
        task_id: TaskId,
        memory_handle: String,
        evidence_refs: Vec<String>,
    },
    ReviewCandidate {
        task_id: TaskId,
        candidate_ref: String,
        disposition: String,
        evidence_refs: Vec<String>,
    },
    TriggerBackupValidation {
        task_id: TaskId,
    },
    RequestImportPreview {
        task_id: TaskId,
        source_ref: String,
    },
    GrantApproval {
        approval_id: String,
        exact_action_hash: String,
    },
    DenyApproval {
        approval_id: String,
        exact_action_hash: String,
        reason: String,
    },
    FinishGapPreview {
        task_id: TaskId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorCommandReceipt {
    pub command_id: String,
    pub accepted: bool,
    pub executed: bool,
    pub outcome: String,
    pub task_id: Option<TaskId>,
    pub action: String,
    pub revision: Option<MemoryRevision>,
    pub reasons: Vec<String>,
    pub canonical_receipt: Option<WriteReceiptRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperatorControlRequest {
    pub request_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub operation: String,
    pub target_ref: String,
    pub disposition: String,
    pub exact_action_hash: Option<String>,
    pub reason_or_evidence_refs: Vec<String>,
    pub requested_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn operator_contract_manifest_is_parseable_and_hash_pinned() -> Result<(), serde_json::Error> {
        let manifest: serde_json::Value = serde_json::from_str(OPERATOR_CONTRACT_MANIFEST)?;
        assert_eq!(
            manifest
                .get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some(OPERATOR_SCHEMA_VERSION)
        );
        let hash = operator_contract_hash();
        assert_eq!(
            hash,
            "3c1a50d6581e90838a2375fadd70f6868a499d48f4e83223613a0a5fdedf2278"
        );
        let lf = OPERATOR_CONTRACT_MANIFEST.replace("\r\n", "\n");
        let crlf = lf.replace('\n', "\r\n");
        let pretty = serde_json::to_string_pretty(&manifest)?;
        let compact = serde_json::to_string(&manifest)?;
        for equivalent_manifest in [&lf, &crlf, &pretty, &compact] {
            assert_eq!(
                operator_contract_hash_for_manifest(equivalent_manifest),
                hash
            );
        }
        Ok(())
    }
}
