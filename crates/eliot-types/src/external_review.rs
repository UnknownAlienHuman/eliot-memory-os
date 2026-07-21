use crate::service::CredentialRef;
use crate::{
    BlobRef, CandidateDiffId, ProjectId, TaintClass, TaskId, WorkLeaseId, WorktreeLeaseId,
    WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProviderKind {
    Mock,
    AntigravityCli,
    GeminiCli,
    GeminiApi,
}

impl ExternalProviderKind {
    #[must_use]
    pub const fn is_real(self) -> bool {
        !matches!(self, Self::Mock)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProviderTransport {
    InternalMock,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReviewRole {
    Auditor,
    Reviewer,
    Critic,
    Worker,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExternalProviderAuthority {
    pub candidate_only: bool,
    pub tainted_by_default: bool,
    pub can_write_truth: bool,
    pub can_apply_patch: bool,
    pub can_grant_actions: bool,
    pub can_finish_tasks: bool,
    pub can_enter_normal_l3_as_instruction: bool,
    pub can_propose_candidate_diff: bool,
}

impl Default for ExternalProviderAuthority {
    fn default() -> Self {
        Self {
            candidate_only: true,
            tainted_by_default: true,
            can_write_truth: false,
            can_apply_patch: false,
            can_grant_actions: false,
            can_finish_tasks: false,
            can_enter_normal_l3_as_instruction: false,
            can_propose_candidate_diff: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalProviderLimits {
    pub timeout_ms: u64,
    pub max_packet_bytes: usize,
    pub max_raw_output_bytes: usize,
    pub max_findings: usize,
}

impl Default for ExternalProviderLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 500,
            max_packet_bytes: 32 * 1024,
            max_raw_output_bytes: 32 * 1024,
            max_findings: 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalProviderProfile {
    pub provider_id: String,
    pub display_name: String,
    pub kind: ExternalProviderKind,
    pub transport: ExternalProviderTransport,
    pub enabled: bool,
    pub roles: Vec<ExternalReviewRole>,
    pub output_schemas: Vec<ExternalOutputSchemaKind>,
    pub authority: ExternalProviderAuthority,
    pub limits: ExternalProviderLimits,
    pub credential_ref: Option<CredentialRef>,
    pub disabled_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalForbiddenAction {
    WriteTruth,
    ApplyPatch,
    GrantAction,
    FinishTask,
    EnterNormalL3AsInstruction,
    RevealSecret,
    RawExec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalOutputSchemaKind {
    AuditFindings,
    ProposedChanges,
    MixedReview,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReviewBudget {
    pub max_packet_bytes: usize,
    pub max_output_bytes: usize,
    pub max_findings: usize,
}

impl Default for ExternalReviewBudget {
    fn default() -> Self {
        Self {
            max_packet_bytes: ExternalProviderLimits::default().max_packet_bytes,
            max_output_bytes: ExternalProviderLimits::default().max_raw_output_bytes,
            max_findings: ExternalProviderLimits::default().max_findings,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReviewRequest {
    pub request_id: String,
    pub project: String,
    pub project_id: ProjectId,
    pub task: String,
    pub task_id: TaskId,
    pub provider_id: String,
    pub role: ExternalReviewRole,
    pub question: String,
    pub output_schema: ExternalOutputSchemaKind,
    pub budget: ExternalReviewBudget,
    pub work_lease_id: Option<WorkLeaseId>,
    pub worktree_lease_id: Option<WorktreeLeaseId>,
    pub allowed_paths: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub forbidden_actions: Vec<ExternalForbiddenAction>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReviewJobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReviewJob {
    pub job_id: String,
    pub request_id: String,
    pub provider_id: String,
    pub status: ExternalReviewJobStatus,
    pub adapter_request_id: Option<String>,
    pub adapter_result_id: Option<String>,
    pub result_id: Option<String>,
    pub raw_output_blob_ref: Option<BlobRef>,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReviewResultStatus {
    AcceptedCandidate,
    RejectedMalformed,
    RejectedAuthorityViolation,
    RejectedMissingEvidence,
    RejectedVerifiedClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalClaimStatus {
    Candidate,
    Unverified,
    Contested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalFindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCitationStatus {
    Cited,
    Missing,
    OutOfScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalEvidenceCitation {
    pub citation_id: String,
    pub evidence_ref: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub status: ExternalCitationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReviewFinding {
    pub finding_id: String,
    pub title: String,
    pub detail: String,
    pub severity: ExternalFindingSeverity,
    pub claim_status: ExternalClaimStatus,
    pub citations: Vec<ExternalEvidenceCitation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProposedChangeKind {
    CandidateDiffOnly,
    VerifierOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalProposedChange {
    pub change_id: String,
    pub kind: ExternalProposedChangeKind,
    pub summary: String,
    pub files: Vec<String>,
    pub candidate_diff_id: Option<CandidateDiffId>,
    pub candidate_diff_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalVerifierSuggestion {
    pub verifier_id: String,
    pub command: String,
    pub reason: String,
    pub candidate_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalUncertainty {
    pub uncertainty_id: String,
    pub summary: String,
    pub evidence_needed: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalReviewResult {
    pub result_id: String,
    pub request_id: String,
    pub job_id: String,
    pub provider_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub status: ExternalReviewResultStatus,
    pub candidate_only: bool,
    pub taint: TaintClass,
    pub raw_output_blob_ref: Option<BlobRef>,
    pub findings: Vec<ExternalReviewFinding>,
    pub proposed_changes: Vec<ExternalProposedChange>,
    pub verifier_suggestions: Vec<ExternalVerifierSuggestion>,
    pub uncertainties: Vec<ExternalUncertainty>,
    pub write_receipt: Option<WriteReceiptRef>,
    pub blackboard_item_refs: Vec<String>,
    pub mailbox_message_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReviewGateDecisionKind {
    AllowMockRun,
    RequireWorkLease,
    RequireWorktreeLease,
    RequireProviderIntegrationEvalGate,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReviewGateReason {
    AllowedMockProvider,
    MissingWorkLease,
    MissingWorktreeLease,
    RealProviderExecutionDisabledInG2,
    ProviderDisabled,
    UnsupportedRole,
    UnsupportedOutputSchema,
    ProviderIntegrationGateMissing,
    IncidentLockdown,
    AuthorityViolation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReviewGateDecision {
    pub request_id: String,
    pub provider_id: String,
    pub decision: ExternalReviewGateDecisionKind,
    pub reasons: Vec<ExternalReviewGateReason>,
    pub message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalReviewNormalizationReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub job_id: String,
    pub provider_id: String,
    pub accepted: bool,
    pub status: ExternalReviewResultStatus,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExternalReviewPacket {
    pub packet_id: String,
    pub request_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub provider_id: String,
    pub question: String,
    pub context_ref: String,
    pub allowed_paths: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub redacted_refs: Vec<String>,
    pub forbidden_actions: Vec<ExternalForbiddenAction>,
    pub max_packet_bytes: usize,
    pub byte_len: usize,
    pub payload: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
