use crate::{
    AgentInvocationRequest, AgentResultDisposition, AgentResultEnvelope, AgentSessionHostBinding,
    ControllerLease, OperationJob, ProjectId, TaskId, TaskRoleLease, WorkLeaseId, WorktreeLeaseId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// The single provider-call campaign schema version this build owns.
///
/// A campaign budget minted by this build carries exactly this version, so
/// exactly one version decodes. A ledger written by another generation is
/// refused at the decoder instead of being budgeted, deduplicated and
/// reconciled on counters whose meaning that generation may not share. The
/// constant is public because the minting path and the decoder must not be
/// able to disagree about which version is current.
pub const PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION: &str = "provider-call-campaign-v1";

/// Character ceiling for one protected delegation identity or reference.
///
/// Campaign, reservation, delegation, decision, job and outcome identity is what
/// a provider call is budgeted, deduplicated, dispatched and reconciled by. An
/// identity that is empty, blank or unbounded is not a weaker key, it is an
/// unusable one, so the ceiling is enforced by the decoder below and re-proved
/// by the ledger validator.
pub const PROTECTED_DELEGATION_IDENTITY_MAX_CHARS: usize = 512;

/// Single predicate for a protected delegation identity or reference.
///
/// Both the decoder and the engine's request guard call this one predicate so a
/// value refused on the decode path can never be minted on the construction
/// path, and vice versa.
#[must_use]
pub fn protected_delegation_identity_is_valid(value: &str) -> bool {
    !value.trim().is_empty() && value.chars().count() <= PROTECTED_DELEGATION_IDENTITY_MAX_CHARS
}

/// Bounded refusal for a protected delegation identity that decoded empty.
///
/// Absence already refuses through the missing-field path; this closes the
/// spelled-out-empty spelling of the same defect on the identity a delegation,
/// a provider call budget and its outcome are trusted by. The message names the
/// field and never echoes the received value onto an operator surface.
///
/// This is the same bounded refusal the `runtime` and `runtime_supervision`
/// decoders use, repeated per module because those helpers are private to their
/// modules and sharing them is outside the write scope of this repair.
fn empty_protected_identifier<E>(field: &'static str) -> E
where
    E: serde::de::Error,
{
    E::custom(format!("empty protected identifier: {field}"))
}

/// Bounded refusal for a protected delegation identity that decoded beyond the
/// character ceiling.
///
/// An unbounded identity is an unbounded key into every budget, replay and
/// reconciliation path that reads it, so it refuses at the decoder instead of
/// becoming one. The message names the field and never echoes the received
/// value.
fn unbounded_protected_identifier<E>(field: &'static str) -> E
where
    E: serde::de::Error,
{
    E::custom(format!("unbounded protected identifier: {field}"))
}

/// Bounded refusal for a provider-call campaign schema version this build does
/// not own. The message names the expected version and never echoes the
/// received one, mirroring the envelope and control-wal refusals in `runtime`
/// and `runtime_supervision`.
fn unsupported_provider_call_schema_version<E>(expected: &str) -> E
where
    E: serde::de::Error,
{
    E::custom(format!(
        "unsupported provider call schema version; expected {expected}"
    ))
}

fn require_protected_delegation_identity<E>(field: &'static str, value: &str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if protected_delegation_identity_is_valid(value) {
        return Ok(());
    }
    Err(if value.trim().is_empty() {
        empty_protected_identifier(field)
    } else {
        unbounded_protected_identifier(field)
    })
}

fn deserialize_protected_delegation_identity<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    require_protected_delegation_identity(field, &value)?;
    Ok(value)
}

fn deserialize_optional_protected_delegation_identity<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(text) = &value {
        require_protected_delegation_identity(field, text)?;
    }
    Ok(value)
}

fn deserialize_protected_delegation_identity_list<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    for value in &values {
        require_protected_delegation_identity(field, value)?;
    }
    Ok(values)
}

fn deserialize_provider_call_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_provider_call_schema_version(
            PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION,
        ))
    }
}

fn deserialize_parent_delegation_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "parent_delegation_id")
}

fn deserialize_delegation_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "delegation_id")
}

fn deserialize_evidence_refs<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity_list(deserializer, "evidence_refs")
}

fn deserialize_decision_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "decision_id")
}

fn deserialize_budget_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "budget_id")
}

fn deserialize_optional_budget_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "budget_id")
}

fn deserialize_provider_health_ref<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "provider_health_ref")
}

fn deserialize_external_review_request_ref<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "external_review_request_ref")
}

fn deserialize_provider_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "provider_id")
}

fn deserialize_campaign_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "campaign_id")
}

fn deserialize_reservation_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "reservation_id")
}

fn deserialize_provider_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "provider")
}

fn deserialize_optional_provider_name<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "provider")
}

fn deserialize_idempotency_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "idempotency_key")
}

fn deserialize_gate_decision_ref<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "gate_decision_ref")
}

fn deserialize_external_invocation_ref<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "external_invocation_ref")
}

fn deserialize_review_ref<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "review_ref")
}

fn deserialize_job_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "job_id")
}

fn deserialize_optional_job_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "job_id")
}

fn deserialize_external_review_job_ref<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "external_review_job_ref")
}

fn deserialize_outcome_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity(deserializer, "outcome_id")
}

fn deserialize_result_ref<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_protected_delegation_identity(deserializer, "result_ref")
}

fn deserialize_verifier_refs<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_protected_delegation_identity_list(deserializer, "verifier_refs")
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
    #[serde(deserialize_with = "deserialize_optional_budget_id")]
    pub budget_id: Option<String>,
    #[serde(deserialize_with = "deserialize_provider_health_ref")]
    pub provider_health_ref: Option<String>,
    #[serde(deserialize_with = "deserialize_external_review_request_ref")]
    pub external_review_request_ref: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationBudget {
    #[serde(deserialize_with = "deserialize_budget_id")]
    pub budget_id: String,
    pub task_id: TaskId,
    #[serde(deserialize_with = "deserialize_provider_id")]
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
    #[serde(deserialize_with = "deserialize_provider_name")]
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
    #[serde(deserialize_with = "deserialize_external_invocation_ref")]
    pub external_invocation_ref: Option<String>,
    #[serde(deserialize_with = "deserialize_review_ref")]
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
    #[serde(deserialize_with = "deserialize_provider_id")]
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
    #[serde(deserialize_with = "deserialize_result_ref")]
    pub result_ref: Option<String>,
    pub status: DelegationOutcomeStatus,
    pub unique_findings: u32,
    pub accepted_findings: u32,
    pub rejected_findings: u32,
    pub duplicate_findings: u32,
    #[serde(deserialize_with = "deserialize_verifier_refs")]
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
    #[serde(deserialize_with = "deserialize_delegation_id")]
    pub delegation_id: String,
    pub decision: DelegationDecisionKind,
    #[serde(deserialize_with = "deserialize_optional_provider_name")]
    pub provider: Option<String>,
    pub reasons: Vec<DelegationReason>,
    #[serde(deserialize_with = "deserialize_optional_job_id")]
    pub job_id: Option<String>,
    pub constraints: Vec<String>,
    pub status: DelegationPublicStatus,
}
