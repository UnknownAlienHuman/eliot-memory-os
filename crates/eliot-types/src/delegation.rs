use crate::{
    AgentInvocationRequest, AgentResultDisposition, AgentResultEnvelope, AgentSessionHostBinding,
    ControllerLease, OperationJob, ProjectId, TaskId, TaskRoleLease, WorkLeaseId, WorktreeLeaseId,
};
use serde::{Deserialize, Deserializer, Serialize, de};
use time::OffsetDateTime;

/// The only provider-call campaign ledger schema this build writes and owns.
///
/// A `ProviderCallBudgetState` is the record a campaign's remaining call
/// budget is read from, so a budget written under any other version is not a
/// weaker current state: it is an unknown one, and it must refuse at the
/// decoder instead of decoding as "no reservations, no consumed budget".
/// The constant is the single owner of that spelling for both the decoder
/// below and `eliot-engine`'s writer and ledger validator.
pub const PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION: &str = "provider-call-campaign-v1";

// Bounded refusal for a provider-call schema version this build does not own.
// The message is fixed and never echoes the received version back onto an
// operator surface.
fn unsupported_schema_version<E>(expected: &str) -> E
where
    E: de::Error,
{
    E::custom(format!("unsupported schema version; expected {expected}"))
}

fn deserialize_provider_call_schema_version<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(
            PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION,
        ))
    }
}

// Bounded refusal for a protected delegation identity that decoded empty.
//
// The campaign, reservation, delegation, decision, job, outcome and review-job
// identities below are what a provider call is reserved, gated, dispatched,
// matched, transitioned and reported by, and the evidence and parent
// references are what a record is attributed to. An empty string is not a
// weaker identity, it is an absent one: it decodes as a valid key that any
// later record can match, so it must refuse at the decoder. Absence already
// refuses through the missing-field path; this closes the spelled-out-empty
// spelling of the same defect. The message is fixed and never echoes the
// received value onto an operator surface.
fn empty_protected_identifier<E>(field: &'static str) -> E
where
    E: de::Error,
{
    E::custom(format!("empty protected identifier: {field}"))
}

fn deserialize_protected_string<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(empty_protected_identifier(field));
    }
    Ok(value)
}

/// The same bound for a reference that may be absent: absence still decodes to
/// `None`, but a present reference may not be an empty string.
fn deserialize_optional_protected_ref<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if value.as_ref().is_some_and(String::is_empty) {
        return Err(empty_protected_identifier(field));
    }
    Ok(value)
}

/// The same bound across a reference list: an empty list is a real "nothing
/// recorded" state, but an empty member inside it is an absent reference
/// presented as a recorded one.
fn deserialize_protected_refs<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.iter().any(String::is_empty) {
        return Err(empty_protected_identifier(field));
    }
    Ok(values)
}

fn deserialize_campaign_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "campaign_id")
}

fn deserialize_reservation_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "reservation_id")
}

fn deserialize_provider<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "provider")
}

fn deserialize_idempotency_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "idempotency_key")
}

fn deserialize_gate_decision_ref<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "gate_decision_ref")
}

fn deserialize_delegation_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "delegation_id")
}

fn deserialize_parent_delegation_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_optional_protected_ref(deserializer, "parent_delegation_id")
}

fn deserialize_evidence_refs<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_refs(deserializer, "evidence_refs")
}

fn deserialize_decision_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "decision_id")
}

fn deserialize_job_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "job_id")
}

fn deserialize_external_review_job_ref<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "external_review_job_ref")
}

fn deserialize_outcome_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_protected_string(deserializer, "outcome_id")
}

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
#[serde(deny_unknown_fields)]
pub struct DelegationOriginChain {
    pub root_origin: DelegationRootOrigin,
    pub provider_chain: Vec<String>,
    pub delegation_depth: u8,
    #[serde(deserialize_with = "deserialize_parent_delegation_id")]
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
#[serde(deny_unknown_fields)]
pub struct DelegationRequest {
    #[serde(deserialize_with = "deserialize_delegation_id")]
    pub delegation_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub origin: DelegationOrigin,
    pub origin_chain: DelegationOriginChain,
    pub review_kind: DelegationReviewKind,
    pub question: String,
    pub work_lease_id: WorkLeaseId,
    #[serde(deserialize_with = "deserialize_evidence_refs")]
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
#[serde(deny_unknown_fields)]
pub struct DelegationDecision {
    #[serde(deserialize_with = "deserialize_decision_id")]
    pub decision_id: String,
    #[serde(deserialize_with = "deserialize_delegation_id")]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ProviderCallBudgetState {
    #[serde(deserialize_with = "deserialize_campaign_id")]
    pub campaign_id: String,
    #[serde(deserialize_with = "deserialize_provider_call_schema_version")]
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
#[serde(deny_unknown_fields)]
pub struct ProviderCallReservation {
    #[serde(deserialize_with = "deserialize_reservation_id")]
    pub reservation_id: String,
    #[serde(deserialize_with = "deserialize_campaign_id")]
    pub campaign_id: String,
    pub task_id: TaskId,
    #[serde(deserialize_with = "deserialize_provider")]
    pub provider: String,
    #[serde(deserialize_with = "deserialize_idempotency_key")]
    pub idempotency_key: String,
    pub slot_index: u32,
    pub budget_revision: u64,
    #[serde(deserialize_with = "deserialize_gate_decision_ref")]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct DelegationJob {
    #[serde(deserialize_with = "deserialize_job_id")]
    pub job_id: String,
    #[serde(deserialize_with = "deserialize_delegation_id")]
    pub delegation_id: String,
    #[serde(deserialize_with = "deserialize_decision_id")]
    pub decision_id: String,
    pub provider_id: String,
    pub worktree_lease_id: WorktreeLeaseId,
    #[serde(deserialize_with = "deserialize_external_review_job_ref")]
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
#[serde(deny_unknown_fields)]
pub struct DelegationOutcome {
    #[serde(deserialize_with = "deserialize_outcome_id")]
    pub outcome_id: String,
    #[serde(deserialize_with = "deserialize_delegation_id")]
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
    pub integrity_evidence_present: bool,
    pub authority_violations: u32,
    pub live_tree_violations: u32,
    pub notes: Vec<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationState {
    pub requests: Vec<DelegationRequest>,
    pub decisions: Vec<DelegationDecision>,
    pub budgets: Vec<DelegationBudget>,
    pub jobs: Vec<DelegationJob>,
    pub outcomes: Vec<DelegationOutcome>,
    pub provider_call_budgets: Vec<ProviderCallBudgetState>,
    pub provider_call_reservations: Vec<ProviderCallReservation>,
    pub agent_host_sessions: Vec<AgentSessionHostBinding>,
    pub task_role_leases: Vec<TaskRoleLease>,
    pub controller_leases: Vec<ControllerLease>,
    pub operation_jobs: Vec<OperationJob>,
    pub agent_invocations: Vec<AgentInvocationRequest>,
    pub agent_results: Vec<AgentResultEnvelope>,
    pub agent_result_dispositions: Vec<AgentResultDisposition>,
    pub authority_revocation_receipts: Vec<crate::AuthorityRevocationReceipt>,
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
#[serde(deny_unknown_fields)]
pub struct DelegationReviewResponse {
    pub delegation_id: String,
    pub decision: DelegationDecisionKind,
    pub provider: Option<String>,
    pub reasons: Vec<DelegationReason>,
    pub job_id: Option<String>,
    pub constraints: Vec<String>,
    pub status: DelegationPublicStatus,
}
