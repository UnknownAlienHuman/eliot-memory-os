use crate::{
    AgentInvocationRequest, AgentResultDisposition, AgentResultEnvelope, AgentSessionHostBinding,
    ControllerLease, OperationJob, ProjectId, TaskId, TaskRoleLease, WorkLeaseId, WorktreeLeaseId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationOrigin {
    UserDirected,
    CodexRequested,
    PolicyShadow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationRootOrigin {
    User,
    Codex,
    GovernorShadow,
    ExternalProvider,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationOriginChain {
    pub root_origin: DelegationRootOrigin,
    pub provider_chain: Vec<String>,
    pub delegation_depth: u8,
    pub parent_delegation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationReviewKind {
    ArchitectureAudit,
    RiskReview,
    DiffAudit,
    VerifierAdvice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationProviderPreference {
    Auto,
    Antigravity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationRequest {
    pub delegation_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub origin: DelegationOrigin,
    pub origin_chain: DelegationOriginChain,
    pub review_kind: DelegationReviewKind,
    pub question: String,
    pub work_lease_id: WorkLeaseId,
    pub evidence_refs: Vec<String>,
    pub preferred_provider: DelegationProviderPreference,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationDecisionKind {
    Execute,
    NoExternalReview,
    ShadowRecommend,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationReason {
    ExplicitUserRequest,
    SecurityBoundary,
    ExternalIntegration,
    MultiModuleImpact,
    RepeatedFailure,
    VerifierDisagreement,
    EvidenceGap,
    HighAmbiguity,
    BroadDiff,
    IndependentCompletionAudit,
    TrivialDeterministicTask,
    FreshEquivalentReview,
    DuplicateEvidencePacket,
    RecursiveProviderCall,
    IncidentLockdown,
    ForbiddenDataExposure,
    ProviderUnavailable,
    ProviderUnhealthy,
    ProviderVersionBelow1_1_1,
    PluginOrMcpIntegrationNotVerified,
    MissingWorkLease,
    BudgetExceeded,
    MissingCampaignReservation,
    CampaignClosed,
    CooldownActive,
    UnsupportedReviewKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationDecision {
    pub decision_id: String,
    pub delegation_id: String,
    pub kind: DelegationDecisionKind,
    pub provider_id: Option<String>,
    pub reasons: Vec<DelegationReason>,
    pub constraints: Vec<String>,
    pub budget_id: Option<String>,
    pub provider_health_ref: Option<String>,
    pub external_review_request_ref: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationBudget {
    pub budget_id: String,
    pub task_id: TaskId,
    pub provider_id: String,
    pub user_directed_limit: u32,
    pub codex_requested_limit: u32,
    pub user_directed_used: u32,
    pub codex_requested_used: u32,
    pub transient_retry_limit: u32,
    pub transient_retries_used: u32,
    pub cooldown_seconds: u64,
    pub last_execution_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderCallBudgetState {
    pub campaign_id: String,
    pub schema_version: String,
    pub max_calls: u32,
    pub next_slot_index: u32,
    pub reserved_slots: u32,
    pub dispatched_slots: u32,
    pub terminal_slots: u32,
    pub remaining_calls: u32,
    pub revision: u64,
    pub closed: bool,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCallReservationState {
    Reserved,
    ReleasedPreDispatch,
    Dispatching,
    Dispatched,
    Completed,
    Failed,
    UnknownOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderCallReservation {
    pub reservation_id: String,
    pub campaign_id: String,
    pub task_id: TaskId,
    pub provider: String,
    pub idempotency_key: String,
    pub slot_index: u32,
    pub budget_revision: u64,
    pub gate_decision_ref: String,
    pub state: ProviderCallReservationState,
    pub reserved_at: OffsetDateTime,
    pub dispatch_started_at: Option<OffsetDateTime>,
    pub external_invocation_ref: Option<String>,
    pub review_ref: Option<String>,
    pub terminal_at: Option<OffsetDateTime>,
    pub consumes_budget: bool,
    pub release_or_failure_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderCallLedger {
    pub budgets: Vec<ProviderCallBudgetState>,
    pub reservations: Vec<ProviderCallReservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationJobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationJob {
    pub job_id: String,
    pub delegation_id: String,
    pub decision_id: String,
    pub provider_id: String,
    pub worktree_lease_id: WorktreeLeaseId,
    pub external_review_job_ref: String,
    pub state: DelegationJobState,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationOutcomeStatus {
    Useful,
    PartiallyUseful,
    Redundant,
    NoUsefulResult,
    HarmfulCandidateRejected,
    ProviderFailed,
    PolicyDenied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationOutcome {
    pub outcome_id: String,
    pub delegation_id: String,
    pub result_ref: Option<String>,
    pub status: DelegationOutcomeStatus,
    pub unique_findings: u32,
    pub accepted_findings: u32,
    pub rejected_findings: u32,
    pub duplicate_findings: u32,
    pub verifier_refs: Vec<String>,
    pub changed_controller_decision: bool,
    pub actual_runtime_ms: u64,
    pub provider_call_count: u32,
    pub monetary_cost_known: bool,
    #[serde(default)]
    pub integrity_evidence_present: bool,
    #[serde(default)]
    pub authority_violations: u32,
    #[serde(default)]
    pub live_tree_violations: u32,
    pub notes: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DelegationState {
    pub requests: Vec<DelegationRequest>,
    pub decisions: Vec<DelegationDecision>,
    pub budgets: Vec<DelegationBudget>,
    pub jobs: Vec<DelegationJob>,
    pub outcomes: Vec<DelegationOutcome>,
    #[serde(default)]
    pub provider_call_budgets: Vec<ProviderCallBudgetState>,
    #[serde(default)]
    pub provider_call_reservations: Vec<ProviderCallReservation>,
    #[serde(default)]
    pub agent_host_sessions: Vec<AgentSessionHostBinding>,
    #[serde(default)]
    pub task_role_leases: Vec<TaskRoleLease>,
    #[serde(default)]
    pub controller_leases: Vec<ControllerLease>,
    #[serde(default)]
    pub operation_jobs: Vec<OperationJob>,
    #[serde(default)]
    pub agent_invocations: Vec<AgentInvocationRequest>,
    #[serde(default)]
    pub agent_results: Vec<AgentResultEnvelope>,
    #[serde(default)]
    pub agent_result_dispositions: Vec<AgentResultDisposition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPublicStatus {
    Queued,
    Running,
    Completed,
    Denied,
    Shadow,
    NoExternalReview,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationReviewResponse {
    pub delegation_id: String,
    pub decision: DelegationDecisionKind,
    pub provider: Option<String>,
    pub reasons: Vec<DelegationReason>,
    pub job_id: Option<String>,
    pub constraints: Vec<String>,
    pub status: DelegationPublicStatus,
}
