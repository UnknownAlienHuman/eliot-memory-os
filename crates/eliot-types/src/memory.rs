use crate::cognition::{
    CausalBridgeHop, CurrentTruthSnapshot, DecisionLocalitySuffix, EpistemicPacketState,
    MemoryDecisionReceipt, PacketQualityReport,
};
use crate::lifecycle::{MemoryLifecyclePacketView, MemoryLifecycleState};
use crate::records::{BlobRef, CanonicalMemoryL2Page};
use crate::semantic_memory::{ExperienceBrief, MemoryNeedDecision};
use crate::skill::{ProceduralSkillPacketView, SkillActivationRecord};
use crate::ul::artifact::UlArtifact;
use crate::{
    ActionLeaseId, ActionRequestId, AgentId, AgentRunId, AgentSessionId, BlackboardItemId,
    CandidateDiffId, ClaimId, EvidenceId, MailboxMessageId, MemoryRevision, OperationId,
    PatchRequestId, PatchRunId, ProjectId, ProjectSequence, ReceiptId, SessionId, SkillId, TaskId,
    VerificationId, VerifierRunId, WorkItemId, WorkLeaseId, WorktreeLeaseId,
    WorktreeLeaseRequestId, WriteId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCommandKind {
    TaskContractWrite,
    EvidenceIngest,
    ToolObservationRecord,
    DiagnosticBatchRecord,
    ClaimPropose,
    ClaimSupport,
    ClaimVerify,
    FailureRecord,
    ActiveDecisionTransition,
    ProbeRecord,
    VerificationRecord,
    AgentResultRecord,
    CompletionProofSubmit,
    UlArtifactBatchRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    Observed,
    Candidate,
    Supported,
    Verified,
    Contested,
    Superseded,
    Stale,
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    Active,
    Dormant,
    Suppressed,
    Archived,
    Quarantined,
    Forgotten,
    Restored,
    HardDeleted,
    Superseded,
    Stale,
    Deleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Internal,
    Project,
    Private,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintClass {
    LocalVerified,
    LocalTool,
    ExternalAgent,
    UserProvided,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteStatus {
    Received,
    Validated,
    Staged,
    Assigned,
    Applying,
    Committed,
    IdempotentReplay,
    Rejected,
    FailedRetryable,
    FailedPermanent,
    UnknownCommit,
    DeadLetter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteRejectReason {
    InvalidEnvelope,
    MissingRequiredField,
    PayloadTooLarge,
    RawDbAccessRejected,
    InvalidEpistemicTransition,
    IdempotencyConflict,
    WriteIdInputHashConflict,
    NotImplemented,
    Backpressure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadConsistencyMode {
    Latest,
    AtLeastRevision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
// Commands are serialized at the single-writer boundary. Boxing the largest
// variant would add API churn without reducing the persisted representation.
#[allow(clippy::large_enum_variant)]
pub enum SemanticCommand {
    TaskContractWrite(TaskContractWriteCommand),
    EvidenceIngest(EvidenceIngestCommand),
    ToolObservationRecord(ToolObservationRecordCommand),
    DiagnosticBatchRecord(DiagnosticBatchRecordCommand),
    ClaimPropose(ClaimProposeCommand),
    ClaimSupport(ClaimSupportCommand),
    ClaimVerify(ClaimVerifyCommand),
    FailureRecord(FailureRecordCommand),
    ActiveDecisionTransition(ActiveDecisionTransitionCommand),
    ProbeRecord(ProbeRecordCommand),
    VerificationRecord(VerificationRecordCommand),
    AgentResultRecord(AgentResultRecordCommand),
    CompletionProofSubmit(CompletionProofSubmitCommand),
    UlArtifactBatchRecord(UlArtifactBatchRecordCommand),
}

impl SemanticCommand {
    pub const fn kind(&self) -> SemanticCommandKind {
        match self {
            Self::TaskContractWrite(_) => SemanticCommandKind::TaskContractWrite,
            Self::EvidenceIngest(_) => SemanticCommandKind::EvidenceIngest,
            Self::ToolObservationRecord(_) => SemanticCommandKind::ToolObservationRecord,
            Self::DiagnosticBatchRecord(_) => SemanticCommandKind::DiagnosticBatchRecord,
            Self::ClaimPropose(_) => SemanticCommandKind::ClaimPropose,
            Self::ClaimSupport(_) => SemanticCommandKind::ClaimSupport,
            Self::ClaimVerify(_) => SemanticCommandKind::ClaimVerify,
            Self::FailureRecord(_) => SemanticCommandKind::FailureRecord,
            Self::ActiveDecisionTransition(_) => SemanticCommandKind::ActiveDecisionTransition,
            Self::ProbeRecord(_) => SemanticCommandKind::ProbeRecord,
            Self::VerificationRecord(_) => SemanticCommandKind::VerificationRecord,
            Self::AgentResultRecord(_) => SemanticCommandKind::AgentResultRecord,
            Self::CompletionProofSubmit(_) => SemanticCommandKind::CompletionProofSubmit,
            Self::UlArtifactBatchRecord(_) => SemanticCommandKind::UlArtifactBatchRecord,
        }
    }

    pub const fn context(&self) -> &CommandContext {
        match self {
            Self::TaskContractWrite(command) => &command.context,
            Self::EvidenceIngest(command) => &command.context,
            Self::ToolObservationRecord(command) => &command.context,
            Self::DiagnosticBatchRecord(command) => &command.context,
            Self::ClaimPropose(command) => &command.context,
            Self::ClaimSupport(command) => &command.context,
            Self::ClaimVerify(command) => &command.context,
            Self::FailureRecord(command) => &command.context,
            Self::ActiveDecisionTransition(command) => &command.context,
            Self::ProbeRecord(command) => &command.context,
            Self::VerificationRecord(command) => &command.context,
            Self::AgentResultRecord(command) => &command.context,
            Self::CompletionProofSubmit(command) => &command.context,
            Self::UlArtifactBatchRecord(command) => &command.context,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskContractStatus {
    Open,
    Active,
    DoneVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAcceptanceEvidenceKind {
    Observation,
    Verification,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskAcceptanceItem {
    pub item_id: String,
    pub description: String,
    pub required_evidence: TaskAcceptanceEvidenceKind,
    pub satisfied: bool,
    pub observation_id: Option<String>,
    pub verification_id: Option<VerificationId>,
    #[serde(default)]
    pub verification_scope_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionSourceScope {
    pub kind: String,
    pub worktree_ref: Option<PathRef>,
    pub branch: Option<String>,
    pub baseline_commit: Option<String>,
    pub baseline_dirty_state_hash: Option<String>,
    #[serde(default)]
    pub artifact_paths: Vec<PathRef>,
}

/// A server-resolved memory delivery that the acting agent cited when asking
/// for an `ActionLease`.
///
/// This is deliberately weaker than a causal influence claim. It proves that
/// the named memory was durably delivered to the authenticated session before
/// the action request and that the agent cited it for that action. It does not
/// by itself prove that the memory changed the agent's decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionMemoryDeliveryRef {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub delivery_kind: ActionMemoryDeliveryKind,
    pub delivery_id: String,
    pub memory_handle: String,
    pub delivery_surface: String,
    pub source_fingerprint: String,
    #[serde(with = "time::serde::rfc3339")]
    pub delivery_receipt_resolved_at: OffsetDateTime,
    pub evidence_class: ActionMemoryEvidenceClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionMemoryDeliveryKind {
    ContextPacketExperiencePrior,
    InjectionReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionMemoryEvidenceClass {
    AgentDeclaredUseAfterServerDelivery,
}

pub const ACTION_MEMORY_GRANT_REF_SCHEMA_VERSION: &str = "eliot.action-memory-grant-ref.v1";
pub const ACTION_MEMORY_GRANT_REDEMPTION_SCHEMA_VERSION: &str =
    "eliot.action-memory-grant-redemption.v1";

/// A server-resolved opaque memory offer returned by the same authenticated
/// task session in its `ActionRequest`.
///
/// This is a transport acknowledgement plus an agent-declared use binding. It
/// does not reveal an exact memory handle and does not claim that the offered
/// guidance causally changed the action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionMemoryGrantRef {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub grant_id: String,
    pub offer_write_id: WriteId,
    pub packet_id: String,
    pub packet_revision_fence: MemoryRevision,
    pub task_memory_revision: MemoryRevision,
    pub task_contract_ref: String,
    pub prior_fingerprint: String,
    pub guidance_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub redeemed_at: OffsetDateTime,
    pub evidence_class: ActionMemoryGrantEvidenceClass,
}

/// The append-only task-local consumption record for an opaque memory grant.
///
/// This record is committed in the same `TaskContract` transaction as the
/// `ActionRequest` that consumed the grant. It therefore proves a durable
/// offer-return-to-action binding without claiming that the memory changed the
/// agent's decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionMemoryGrantRedemption {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub grant_id: String,
    pub offer_write_id: WriteId,
    pub action_write_id: WriteId,
    pub action_request_hash: String,
    pub provenance_set_id: String,
    pub provenance_set_hash: String,
    pub packet_id: String,
    pub packet_revision_fence: MemoryRevision,
    pub task_memory_revision: MemoryRevision,
    pub task_contract_ref: String,
    pub prior_fingerprint: String,
    pub guidance_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub redeemed_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionMemoryGrantEvidenceClass {
    AgentReturnedOpaqueGrantAfterServerOffer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionProvenanceSet {
    pub provenance_set_id: String,
    pub task_id: TaskId,
    pub packet_id: String,
    pub packet_revision_fence: MemoryRevision,
    pub task_contract_ref: String,
    pub current_truth_refs: Vec<String>,
    pub exact_evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_delivery_refs: Vec<ActionMemoryDeliveryRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_grant_refs: Vec<ActionMemoryGrantRef>,
    pub negative_memory_check_ref: String,
    pub planned_verifier_ref: String,
    pub source_scope: ActionSourceScope,
    #[serde(with = "time::serde::rfc3339")]
    pub resolved_at: OffsetDateTime,
    pub resolver_version: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierArtifactRef {
    pub resource_ref: String,
    pub content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierArtifactScope {
    pub verification_id: VerificationId,
    pub verifier_id: String,
    pub verifier_version: String,
    pub config_hash: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub worktree_ref: String,
    pub artifact_refs: Vec<VerifierArtifactRef>,
    pub path_or_resource_scope: String,
    pub acceptance_item_ids: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub expires_or_invalidates_on: Vec<String>,
    pub canonical_scope_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskContractInput {
    pub task_id: TaskId,
    pub title: String,
    pub status: TaskContractStatus,
    pub acceptance_items: Vec<TaskAcceptanceItem>,
    pub expected_revision: Option<MemoryRevision>,
    pub action_lease_id: Option<ActionLeaseId>,
    pub understanding_proof_hash: Option<String>,
    #[serde(default)]
    pub action_provenance: Option<ActionProvenanceSet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_grant_redemptions: Vec<ActionMemoryGrantRedemption>,
    pub observation_ids: Vec<String>,
    pub verification_ids: Vec<VerificationId>,
    #[serde(default)]
    pub verification_scopes: Vec<VerifierArtifactScope>,
    #[serde(default)]
    pub completion_proof: Option<CompletionProof>,
    pub completion_write_id: Option<WriteId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskContractWriteCommand {
    pub context: CommandContext,
    pub contract: TaskContractInput,
    pub observation: Option<ToolObservationInput>,
    pub verification: Option<VerificationRunInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskContract {
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub title: String,
    pub status: TaskContractStatus,
    pub acceptance_items: Vec<TaskAcceptanceItem>,
    pub action_lease_id: Option<ActionLeaseId>,
    pub understanding_proof_hash: Option<String>,
    #[serde(default)]
    pub action_provenance: Option<ActionProvenanceSet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_grant_redemptions: Vec<ActionMemoryGrantRedemption>,
    pub observation_ids: Vec<String>,
    pub verification_ids: Vec<VerificationId>,
    #[serde(default)]
    pub verification_scopes: Vec<VerifierArtifactScope>,
    #[serde(default)]
    pub completion_proof: Option<CompletionProof>,
    pub completion_write_id: Option<WriteId>,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub write_id: WriteId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandContext {
    pub write_id: WriteId,
    pub agent_id: AgentId,
    pub session_id: Option<SessionId>,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub scope: String,
    pub authority: String,
    pub visibility: Visibility,
    pub taint: TaintClass,
    pub lifecycle_status: LifecycleStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceIngestCommand {
    pub context: CommandContext,
    pub source: SourceSnapshotInput,
    pub evidence: EvidenceAtomInput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolObservationRecordCommand {
    pub context: CommandContext,
    pub tool_name: String,
    pub observation: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticBatchRecordCommand {
    pub context: CommandContext,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimProposeCommand {
    pub context: CommandContext,
    pub claim: ClaimCardInput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimSupportCommand {
    pub context: CommandContext,
    pub claim_id: ClaimId,
    pub evidence_id: EvidenceId,
    pub statement: Option<String>,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimVerifyCommand {
    pub context: CommandContext,
    pub claim_id: ClaimId,
    pub verification: VerificationRunInput,
    pub statement: Option<String>,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureRecordCommand {
    pub context: CommandContext,
    pub fingerprint: String,
    pub summary: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveDecisionTransitionCommand {
    pub context: CommandContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeRecordCommand {
    pub context: CommandContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationRecordCommand {
    pub context: CommandContext,
    pub verification: VerificationRunInput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompletionMemoryRequest {
    NothingToSave,
    SaveDecision { statement: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerCommitHandoff {
    pub child_session_id: SessionId,
    pub task_id: TaskId,
    pub action_lease_id: ActionLeaseId,
    pub base_commit: String,
    pub candidate_artifact_or_diff_ref: String,
    pub accepted_write_set: Vec<PathRef>,
    pub branch: String,
    pub verification_ids: Vec<VerificationId>,
    pub verification_receipt_ids: Vec<ReceiptId>,
    pub canonical_artifact_refs: Vec<VerifierArtifactRef>,
    pub resulting_controller_commit: String,
    pub controller_receipt_id: ReceiptId,
    pub provenance_set_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletionDecisionMemory {
    pub source: SourceSnapshotInput,
    pub evidence: EvidenceAtomInput,
    pub claim: ClaimCardInput,
    pub where_applicable: Vec<String>,
    pub where_not_applicable: Vec<String>,
    pub freshness_rule: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CompletionMemoryAdmission {
    NothingToSave,
    SaveDecision {
        decision: Box<CompletionDecisionMemory>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentResultRecordCommand {
    pub context: CommandContext,
    pub lineage: ControllerCommitHandoff,
    pub memory: CompletionMemoryAdmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletionProofSubmitCommand {
    pub context: CommandContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UlArtifactBatchRecordCommand {
    pub context: CommandContext,
    pub artifacts: Vec<UlArtifact>,
    pub relations: Vec<RelationInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryWriteEnvelopeInput {
    pub command: SemanticCommand,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryWriteEnvelopeValidated {
    pub envelope: MemoryWriteEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryWriteEnvelope {
    pub write_id: WriteId,
    pub operation_id: OperationId,
    pub agent_id: AgentId,
    pub session_id: Option<SessionId>,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub command_kind: SemanticCommandKind,
    pub input_hash: String,
    pub policy_snapshot_id: Option<String>,
    pub project_sequence_hint: Option<ProjectSequence>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub scope: String,
    pub authority: String,
    pub task_contracts: Vec<TaskContractInput>,
    pub source_snapshots: Vec<SourceSnapshotInput>,
    pub evidence_atoms: Vec<EvidenceAtomInput>,
    pub tool_observations: Vec<ToolObservationInput>,
    pub failures: Vec<FailureFingerprintInput>,
    pub claims: Vec<ClaimCardInput>,
    pub verification_runs: Vec<VerificationRunInput>,
    pub relations: Vec<RelationInput>,
    pub lifecycle: LifecycleWriteOptions,
    pub idempotency: IdempotencyOptions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceSnapshotInput {
    pub source_id: String,
    pub uri: String,
    pub authority: String,
    pub content_hash: String,
    pub excerpt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceAtomInput {
    pub evidence_id: EvidenceId,
    pub source_id: String,
    pub summary: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolObservationInput {
    pub observation_id: String,
    pub tool_name: String,
    pub observation: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimCardInput {
    pub claim_id: ClaimId,
    pub statement: String,
    pub status: EpistemicStatus,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationRunInput {
    pub verification_id: VerificationId,
    pub claim_id: Option<ClaimId>,
    pub verifier: String,
    pub result: VerificationResult,
    pub summary: String,
    pub payload: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelationInput {
    pub relation_type: RelationType,
    pub from: String,
    pub to: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationType {
    Supports,
    VerifiedBy,
    Contradicts,
    Supersedes,
    Mentions,
    BelongsTo,
    Produces,
    InvalidatedBy,
    CoChange,
    ConceptImplementedBy,
    ConceptDependsOn,
    CapsuleCovers,
    CardCovers,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureFingerprintInput {
    pub fingerprint: String,
    pub summary: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleWriteOptions {
    pub status: LifecycleStatus,
    pub visibility: Visibility,
    pub taint: TaintClass,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdempotencyOptions {
    pub allow_replay: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteReceipt {
    pub receipt_id: ReceiptId,
    pub write_id: WriteId,
    pub input_hash: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub command_kind: SemanticCommandKind,
    pub status: WriteStatus,
    pub memory_revision: Option<MemoryRevision>,
    pub project_sequence: Option<ProjectSequence>,
    pub created_records: Vec<String>,
    pub created_relations: Vec<String>,
    pub weak_records: Vec<String>,
    pub rejected_reason: Option<WriteRejectReason>,
    pub db_operation_id: Option<OperationId>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriteReceiptRef {
    pub receipt_id: ReceiptId,
    pub write_id: WriteId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CurrentStateRequest {
    pub project_id: ProjectId,
    pub consistency: ReadConsistencyMode,
    pub at_least_revision: Option<MemoryRevision>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CurrentStateResponse {
    pub project_id: ProjectId,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub verified_now: Vec<ClaimSummary>,
    pub supported_now: Vec<ClaimSummary>,
    pub weak_or_candidate: Vec<ClaimSummary>,
    pub contested_now: Vec<ClaimSummary>,
    pub do_not_use: Vec<ClaimSummary>,
    pub recent_failures: Vec<FailureSummary>,
    pub truncation: TruncationInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecallL0Request {
    pub project_id: ProjectId,
    pub query: String,
    pub consistency: ReadConsistencyMode,
    pub at_least_revision: Option<MemoryRevision>,
    #[serde(default)]
    pub lifecycle_audit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    #[serde(default)]
    pub task_class_cues: Vec<String>,
    #[serde(default)]
    pub scope_refs: Vec<String>,
    #[serde(default)]
    pub concept_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecallL0Response {
    pub project_id: ProjectId,
    pub at_revision: MemoryRevision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_revision: Option<MemoryRevision>,
    #[serde(default)]
    pub projection_state: CognitiveProjectionReadState,
    pub handles: Vec<MemoryHandlePreview>,
    #[serde(default)]
    pub memory_confidence: MemoryConfidence,
    pub query_mode: String,
    #[serde(default)]
    pub rank_trace: L0RankTrace,
    pub truncation: TruncationInfo,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveProjectionReadState {
    Published,
    Stale,
    Blocked,
    #[default]
    Unavailable,
}

impl CognitiveProjectionReadState {
    #[must_use]
    pub const fn is_published(self) -> bool {
        matches!(self, Self::Published)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryConfidence {
    Found,
    Weak,
    #[default]
    None,
}

impl MemoryConfidence {
    #[must_use]
    pub const fn from_top_score(top_score: Option<i32>) -> Self {
        match top_score {
            Some(score) if score >= 200 => Self::Found,
            Some(score) if score >= 80 => Self::Weak,
            _ => Self::None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct L0RankTrace {
    pub query: String,
    pub normalized_query: String,
    pub candidates_considered: usize,
    pub candidates_returned: usize,
    pub feature_scores: Vec<L0FeatureScore>,
    pub lifecycle_suppressions: Vec<L0SuppressionTrace>,
    pub scope_suppressions: Vec<L0SuppressionTrace>,
    #[serde(default)]
    pub collapsed_duplicates: Vec<L0CollapsedDuplicateTrace>,
    pub no_useful_memory: bool,
    pub query_mode: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct L0FeatureScore {
    pub handle: String,
    pub exact_identifier: i32,
    pub subject_identity: i32,
    pub lexical_overlap: i32,
    pub task_relation: i32,
    pub scope_fit: i32,
    pub lifecycle_fit: i32,
    pub evidence_authority: i32,
    pub prior_decision_delta: i32,
    #[serde(default)]
    pub exact_cue: i32,
    #[serde(default)]
    pub concept_relation: i32,
    #[serde(default)]
    pub freshness_fit: i32,
    #[serde(default)]
    pub negative_memory_value: i32,
    #[serde(default)]
    pub known_decision_delta: i32,
    #[serde(default)]
    pub prior_beneficial_use: i32,
    #[serde(default)]
    pub verification_value: i32,
    #[serde(default)]
    pub context_cost: i32,
    #[serde(default)]
    pub stale_penalty: i32,
    #[serde(default)]
    pub contradiction_penalty: i32,
    #[serde(default)]
    pub harm_penalty: i32,
    #[serde(default)]
    pub repetition_penalty: i32,
    #[serde(default)]
    pub distraction_penalty: i32,
    pub total: i32,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct L0SuppressionTrace {
    pub handle: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct L0CollapsedDuplicateTrace {
    pub authoritative_handle: String,
    pub collapsed_record_refs: Vec<String>,
    pub reason: String,
}

/// I7.17 closed canonical recall disposition.
///
/// Exactly nine variants. The value is always derived server-side from
/// retrieval, scope policy, projection freshness, coverage, and conflict
/// state (see [`derive_recall_disposition`]); it is never accepted from
/// bridge or model output, and an agent must never invent
/// [`RecallDisposition::NoUsefulMemory`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecallDisposition {
    AdmittedStrong,
    AdmittedWeak,
    NoMatch,
    NoUsefulMemory,
    EmptyCorpus,
    ScopeSuppressed,
    StaleProjection,
    Conflicted,
    IncompleteCoverage,
}

impl RecallDisposition {
    /// Canonical wire value for this disposition.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::AdmittedStrong => "ADMITTED_STRONG",
            Self::AdmittedWeak => "ADMITTED_WEAK",
            Self::NoMatch => "NO_MATCH",
            Self::NoUsefulMemory => "NO_USEFUL_MEMORY",
            Self::EmptyCorpus => "EMPTY_CORPUS",
            Self::ScopeSuppressed => "SCOPE_SUPPRESSED",
            Self::StaleProjection => "STALE_PROJECTION",
            Self::Conflicted => "CONFLICTED",
            Self::IncompleteCoverage => "INCOMPLETE_COVERAGE",
        }
    }

    /// The exact nine canonical wire values, in contract order.
    #[must_use]
    pub const fn canonical_set() -> [&'static str; 9] {
        [
            "ADMITTED_STRONG",
            "ADMITTED_WEAK",
            "NO_MATCH",
            "NO_USEFUL_MEMORY",
            "EMPTY_CORPUS",
            "SCOPE_SUPPRESSED",
            "STALE_PROJECTION",
            "CONFLICTED",
            "INCOMPLETE_COVERAGE",
        ]
    }
}

/// Server-observed inputs for [`derive_recall_disposition`].
///
/// Every field is resolved by the memory/packet response owner from
/// retrieval results, scope policy, projection freshness, coverage, and
/// conflict state. Callers cannot inject a disposition through this struct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecallDispositionInputs {
    /// The corpus holds no records at all when the response owner has
    /// authoritative cardinality evidence. That evidence is a complete
    /// unfiltered corpus scan: `Some(true)` only when such a scan considered
    /// zero records, and any considered record is `Some(false)`. A
    /// query-filtered result set is never cardinality evidence, so an empty
    /// such set stays `None`. `None` preserves an unavailable observation and
    /// cannot be coerced to `false`.
    pub corpus_empty: Option<bool>,
    /// Retrieval candidates considered before scope/lifecycle policy.
    pub candidates_considered: usize,
    /// Admitted handles returned to the agent.
    pub visible_count: usize,
    /// Matches suppressed by scope policy. `SCOPE_SUPPRESSED` is emitted only
    /// when this equals every candidate considered and coverage is complete.
    pub scope_suppressed_count: usize,
    /// Current projection freshness.
    pub projection_state: CognitiveProjectionReadState,
    /// Retrieval covered the corpus without truncation or scan gaps.
    pub coverage_complete: bool,
    /// Conflicting evidence blocks admission when observed by the response
    /// owner. That observation must cover the candidates the owner actually
    /// weighed; a path that never inspected conflict state keeps `None` and
    /// `None` preserves an unavailable observation.
    pub conflicted: Option<bool>,
    /// Best admitted total score, when any handle was admitted.
    pub top_score: Option<i32>,
}

/// Derives the canonical [`RecallDisposition`] server-side.
///
/// Deterministic priority: empty corpus, then projection freshness, then
/// conflict, then admission strength, then coverage, then all-candidate scope
/// suppression, then server-observed uselessness, and finally no match. If a
/// required owner observation is unavailable, derivation returns
/// `INCOMPLETE_COVERAGE` rather than coercing unknown state to a boolean.
/// `NO_USEFUL_MEMORY` is returned only here, never by an agent.
#[must_use]
pub const fn derive_recall_disposition(
    inputs: &RecallDispositionInputs,
) -> (RecallDisposition, &'static str) {
    if let Some(true) = inputs.corpus_empty {
        return (RecallDisposition::EmptyCorpus, "corpus contains no records");
    }
    if !inputs.projection_state.is_published() {
        let reason = match inputs.projection_state {
            CognitiveProjectionReadState::Stale => "projection is stale",
            CognitiveProjectionReadState::Blocked => "projection is blocked",
            CognitiveProjectionReadState::Unavailable => "projection is unavailable",
            CognitiveProjectionReadState::Published => "projection is unpublished",
        };
        return (RecallDisposition::StaleProjection, reason);
    }
    if let Some(true) = inputs.conflicted {
        return (
            RecallDisposition::Conflicted,
            "conflicting evidence blocks admission",
        );
    }
    if let (None, _) | (_, None) = (inputs.corpus_empty, inputs.conflicted) {
        return (
            RecallDisposition::IncompleteCoverage,
            "required server observation unavailable",
        );
    }
    if inputs.visible_count > 0 {
        return match inputs.top_score {
            Some(score) if score >= 200 => (
                RecallDisposition::AdmittedStrong,
                "top handle admitted with strong score",
            ),
            _ => (
                RecallDisposition::AdmittedWeak,
                "top handle admitted with weak score",
            ),
        };
    }
    if !inputs.coverage_complete {
        return (
            RecallDisposition::IncompleteCoverage,
            "coverage incomplete with no admissible handle",
        );
    }
    if inputs.scope_suppressed_count > 0
        && inputs.scope_suppressed_count == inputs.candidates_considered
    {
        return (
            RecallDisposition::ScopeSuppressed,
            "all matches suppressed by scope",
        );
    }
    if inputs.candidates_considered > 0 {
        return (
            RecallDisposition::NoUsefulMemory,
            "candidates considered but none admissible",
        );
    }
    (RecallDisposition::NoMatch, "no matching records")
}

/// Maximum opaque-text length accepted on a server-issued recall receipt.
pub const RECALL_RECEIPT_TEXT_LIMIT: usize = 256;
/// Maximum concise-reason length accepted on a server-issued recall receipt.
pub const RECALL_RECEIPT_REASON_LIMIT: usize = 280;

fn validate_receipt_text(value: &str, limit: usize) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err("must not contain control characters".to_owned());
    }
    if value.chars().count() > limit {
        return Err("exceeds the receipt text limit".to_owned());
    }
    Ok(())
}

/// Server-issued recall receipt binding scope, revisions, State Fence,
/// visible/suppressed counts, freshness, and a concise reason.
///
/// The receipt is minted by the memory/packet response owner alongside the
/// derived [`RecallDisposition`]; agents receive it but never author it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallReceipt {
    /// Bound scope for this recall; empty means corpus-wide.
    pub scope: String,
    /// Source revision the recall read from.
    pub source_revision: MemoryRevision,
    /// Projection revision the ranking was computed against, when known.
    pub projection_revision: Option<MemoryRevision>,
    /// Opaque server-issued State Fence reference binding this recall.
    pub state_fence: String,
    /// Admitted handles visible to the agent.
    pub visible_count: u32,
    /// Candidates suppressed by scope/lifecycle policy.
    pub suppressed_count: u32,
    /// Projection freshness at issue time.
    pub freshness: CognitiveProjectionReadState,
    /// Concise server-authored reason for the disposition.
    pub reason: String,
}

impl RecallReceipt {
    /// Mints a server-issued receipt after validating its bindings.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        scope: &str,
        source_revision: MemoryRevision,
        projection_revision: Option<MemoryRevision>,
        state_fence: &str,
        visible_count: u32,
        suppressed_count: u32,
        freshness: CognitiveProjectionReadState,
        reason: &str,
    ) -> Result<Self, String> {
        validate_receipt_text(scope, RECALL_RECEIPT_TEXT_LIMIT)
            .map_err(|error| format!("receipt scope {error}"))?;
        if state_fence.trim().is_empty() {
            return Err("receipt state_fence must be non-blank".to_owned());
        }
        validate_receipt_text(state_fence, RECALL_RECEIPT_TEXT_LIMIT)
            .map_err(|error| format!("receipt state_fence {error}"))?;
        if reason.trim().is_empty() {
            return Err("receipt reason must be non-blank".to_owned());
        }
        validate_receipt_text(reason, RECALL_RECEIPT_REASON_LIMIT)
            .map_err(|error| format!("receipt reason {error}"))?;
        Ok(Self {
            scope: scope.to_owned(),
            source_revision,
            projection_revision,
            state_fence: state_fence.to_owned(),
            visible_count,
            suppressed_count,
            freshness,
            reason: reason.to_owned(),
        })
    }
}

/// Server-issued recall verdict: derived disposition, binding receipt, and
/// the rank-trace handle resolving to exactly the delivered ranking.
///
/// The handle is content-addressed over the disposition, receipt binding, and
/// complete delivered rank trace, so swapping any bound fact invalidates the
/// handle. Packet responses reuse this verdict shape with packet-side inputs;
/// only the response owner may issue it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerRecallVerdict {
    pub disposition: RecallDisposition,
    pub receipt: RecallReceipt,
    pub rank_trace_handle: String,
}

fn hash_rank_trace_field(hasher: &mut blake3::Hasher, value: &str) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(&length.to_le_bytes());
    hasher.update(value.as_bytes());
}

impl ServerRecallVerdict {
    /// Issues the verdict for callers that already hold authoritative boolean
    /// observations. New production paths should use
    /// [`Self::issue_for_l0_response_with_observations`] so unavailable
    /// owner facts remain unknown.
    pub fn issue_for_l0_response(
        response: &RecallL0Response,
        scope: &str,
        state_fence: &str,
        corpus_empty: bool,
        coverage_complete: bool,
        conflicted: bool,
    ) -> Result<Self, String> {
        Self::issue_for_l0_response_with_observations(
            response,
            scope,
            state_fence,
            Some(corpus_empty),
            coverage_complete,
            Some(conflicted),
        )
    }

    /// Issues the verdict from explicit owner observations. `None` means the
    /// response owner has not supplied that fact; it is never coerced to
    /// `false`. The disposition is derived, never accepted from bridge/model
    /// output.
    pub fn issue_for_l0_response_with_observations(
        response: &RecallL0Response,
        scope: &str,
        state_fence: &str,
        corpus_empty: Option<bool>,
        coverage_complete: bool,
        conflicted: Option<bool>,
    ) -> Result<Self, String> {
        let visible_count = u32::try_from(response.handles.len())
            .map_err(|_| "visible handle count overflows u32".to_owned())?;
        let suppressed_count = u32::try_from(response.suppressed_count())
            .map_err(|_| "suppressed count overflows u32".to_owned())?;
        let scope_suppressed_count = response.rank_trace.scope_suppressions.len();
        let top_score = response
            .rank_trace
            .feature_scores
            .iter()
            .map(|score| score.total)
            .max();
        let inputs = RecallDispositionInputs {
            corpus_empty,
            candidates_considered: response.rank_trace.candidates_considered,
            visible_count: response.handles.len(),
            scope_suppressed_count,
            projection_state: response.projection_state,
            coverage_complete,
            conflicted,
            top_score,
        };
        let (disposition, reason) = derive_recall_disposition(&inputs);
        let receipt = RecallReceipt::issue(
            scope,
            response.at_revision,
            response.projection_revision,
            state_fence,
            visible_count,
            suppressed_count,
            response.projection_state,
            reason,
        )?;
        let rank_trace_handle = Self::rank_trace_handle_for(
            disposition,
            response.at_revision,
            response.projection_revision,
            visible_count,
            suppressed_count,
            &response.rank_trace,
            &receipt,
        );
        Ok(Self {
            disposition,
            receipt,
            rank_trace_handle,
        })
    }

    /// Derives the deterministic delivery handle for one ranking.
    ///
    /// The handle is content-addressed (`rank-trace:<blake3>`) over the
    /// disposition, receipt scope/fence/reason, revision binding, counts, and
    /// the complete ordered `L0RankTrace`. Every feature component, query
    /// field, suppression, duplicate-collapse record, and reason is covered;
    /// changing any delivered fact changes the handle.
    #[must_use]
    pub fn rank_trace_handle_for(
        disposition: RecallDisposition,
        source_revision: MemoryRevision,
        projection_revision: Option<MemoryRevision>,
        visible_count: u32,
        suppressed_count: u32,
        rank_trace: &L0RankTrace,
        receipt: &RecallReceipt,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hash_rank_trace_field(&mut hasher, "rank-trace-v2");
        hash_rank_trace_field(&mut hasher, disposition.as_wire_str());
        hash_rank_trace_field(&mut hasher, &source_revision.value().to_string());
        hash_rank_trace_field(
            &mut hasher,
            &projection_revision.map_or_else(
                || "none".to_owned(),
                |revision| revision.value().to_string(),
            ),
        );
        hash_rank_trace_field(&mut hasher, &visible_count.to_string());
        hash_rank_trace_field(&mut hasher, &suppressed_count.to_string());
        hash_rank_trace_field(
            &mut hasher,
            match receipt.freshness {
                CognitiveProjectionReadState::Published => "published",
                CognitiveProjectionReadState::Stale => "stale",
                CognitiveProjectionReadState::Blocked => "blocked",
                CognitiveProjectionReadState::Unavailable => "unavailable",
            },
        );
        hash_rank_trace_field(&mut hasher, &receipt.scope);
        hash_rank_trace_field(&mut hasher, &receipt.state_fence);
        hash_rank_trace_field(&mut hasher, &receipt.reason);

        hash_rank_trace_field(&mut hasher, &rank_trace.query);
        hash_rank_trace_field(&mut hasher, &rank_trace.normalized_query);
        hash_rank_trace_field(&mut hasher, &rank_trace.candidates_considered.to_string());
        hash_rank_trace_field(&mut hasher, &rank_trace.candidates_returned.to_string());
        hash_rank_trace_field(&mut hasher, &rank_trace.query_mode);
        hash_rank_trace_field(
            &mut hasher,
            if rank_trace.no_useful_memory {
                "true"
            } else {
                "false"
            },
        );

        hash_rank_trace_field(&mut hasher, &rank_trace.feature_scores.len().to_string());
        for score in &rank_trace.feature_scores {
            hash_rank_trace_field(&mut hasher, &score.handle);
            for value in [
                score.exact_identifier,
                score.subject_identity,
                score.lexical_overlap,
                score.task_relation,
                score.scope_fit,
                score.lifecycle_fit,
                score.evidence_authority,
                score.prior_decision_delta,
                score.exact_cue,
                score.concept_relation,
                score.freshness_fit,
                score.negative_memory_value,
                score.known_decision_delta,
                score.prior_beneficial_use,
                score.verification_value,
                score.context_cost,
                score.stale_penalty,
                score.contradiction_penalty,
                score.harm_penalty,
                score.repetition_penalty,
                score.distraction_penalty,
                score.total,
            ] {
                hash_rank_trace_field(&mut hasher, &value.to_string());
            }
            hash_rank_trace_field(&mut hasher, &score.reasons.len().to_string());
            for score_reason in &score.reasons {
                hash_rank_trace_field(&mut hasher, score_reason);
            }
        }

        for (label, traces) in [
            ("lifecycle", &rank_trace.lifecycle_suppressions),
            ("scope", &rank_trace.scope_suppressions),
        ] {
            hash_rank_trace_field(&mut hasher, label);
            hash_rank_trace_field(&mut hasher, &traces.len().to_string());
            for trace in traces {
                hash_rank_trace_field(&mut hasher, &trace.handle);
                hash_rank_trace_field(&mut hasher, &trace.reason);
            }
        }

        hash_rank_trace_field(
            &mut hasher,
            &rank_trace.collapsed_duplicates.len().to_string(),
        );
        for duplicate in &rank_trace.collapsed_duplicates {
            hash_rank_trace_field(&mut hasher, &duplicate.authoritative_handle);
            hash_rank_trace_field(
                &mut hasher,
                &duplicate.collapsed_record_refs.len().to_string(),
            );
            for record_ref in &duplicate.collapsed_record_refs {
                hash_rank_trace_field(&mut hasher, record_ref);
            }
            hash_rank_trace_field(&mut hasher, &duplicate.reason);
        }
        format!("rank-trace:{}", hasher.finalize().to_hex())
    }

    /// Fail-closed check binding the verdict to the carried L0 response.
    ///
    /// Rejects a delivery whose handle does not resolve to the carried
    /// disposition, receipt binding, revision binding, counts, and complete
    /// ranking/suppression trace; whose counts disagree with the visible
    /// handles and suppression traces; or whose receipt binding disagrees with
    /// the response revisions and freshness. A forged or agent-invented
    /// disposition fails this check because the handle covers the derived
    /// disposition.
    pub fn validate_for_l0_response(&self, response: &RecallL0Response) -> Result<(), String> {
        let visible_count = u32::try_from(response.handles.len())
            .map_err(|_| "visible handle count overflows u32".to_owned())?;
        if self.receipt.visible_count != visible_count {
            return Err("receipt visible_count does not match the delivered handles".to_owned());
        }
        let suppressed_count = u32::try_from(response.suppressed_count())
            .map_err(|_| "suppressed count overflows u32".to_owned())?;
        if self.receipt.suppressed_count != suppressed_count {
            return Err(
                "receipt suppressed_count does not match the suppression traces".to_owned(),
            );
        }
        if self.receipt.source_revision != response.at_revision
            || self.receipt.projection_revision != response.projection_revision
            || self.receipt.freshness != response.projection_state
        {
            return Err("receipt does not bind the response revisions and freshness".to_owned());
        }
        let expected = Self::rank_trace_handle_for(
            self.disposition,
            response.at_revision,
            response.projection_revision,
            visible_count,
            suppressed_count,
            &response.rank_trace,
            &self.receipt,
        );
        if self.rank_trace_handle != expected {
            return Err(
                "rank_trace_handle does not resolve to the delivered ranking and verdict"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

impl RecallL0Response {
    /// Suppressed candidates: lifecycle plus scope suppression traces.
    #[must_use]
    pub fn suppressed_count(&self) -> usize {
        self.rank_trace
            .lifecycle_suppressions
            .len()
            .saturating_add(self.rank_trace.scope_suppressions.len())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchAtomsL2Request {
    pub project_id: ProjectId,
    pub handles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
    pub consistency: ReadConsistencyMode,
    pub at_least_revision: Option<MemoryRevision>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchAtomsL2Response {
    pub project_id: ProjectId,
    pub at_revision: MemoryRevision,
    pub evidence_atoms: Vec<EvidenceAtom>,
    pub claims: Vec<ClaimCard>,
    pub verification_runs: Vec<VerificationRun>,
    pub tool_observations: Vec<ToolObservation>,
    pub failure_fingerprints: Vec<FailureFingerprint>,
    #[serde(default)]
    pub ul_artifacts: Vec<UlMemoryArtifact>,
    #[serde(default)]
    pub canonical_memory_pages: Vec<CanonicalMemoryL2Page>,
    pub relations: Vec<RelationSummary>,
    #[serde(default)]
    pub requested_handles: Vec<String>,
    #[serde(default)]
    pub returned_handles: Vec<String>,
    #[serde(default)]
    pub missing_handles: Vec<String>,
    #[serde(default)]
    pub forbidden_handles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
    pub truncation: TruncationInfo,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UlMemoryArtifact {
    pub handle: String,
    pub record_type: String,
    pub body_md: String,
    pub source_refs: Vec<String>,
    pub freshness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphHealthResponse {
    pub project_id: ProjectId,
    pub scan_limit: u64,
    pub scan_truncated: bool,
    pub unsupported_relation_families: Vec<String>,
    pub scope_head_supported: bool,
    pub orphan_claims: u64,
    pub claims_without_support: u64,
    pub claims_without_verification: u64,
    pub verified_claims: u64,
    pub supported_claims: u64,
    pub weak_claims: u64,
    pub contested_claims: u64,
    pub orphan_evidence: u64,
    pub orphan_verifications: u64,
    pub duplicate_write_ids: u64,
    pub relation_count_by_type: Vec<CountByName>,
    pub records_by_lifecycle_status: Vec<CountByName>,
    pub records_by_visibility: Vec<CountByName>,
    pub latest_memory_revision_by_project: Vec<ProjectRevisionSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriterStatusResponse {
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    pub transport_status: String,
    pub db_version: String,
    pub pending_count: u64,
    pub committed_count: u64,
    pub failed_retryable_count: u64,
    pub failed_permanent_count: u64,
    pub rejected_count: u64,
    pub dead_letter_count: u64,
    pub duplicate_write_count: u64,
    pub idempotent_replay_count: u64,
    pub idempotency_conflict_count: u64,
    pub unknown_commit_count: u64,
    pub latest_project_sequence: Option<ProjectSequence>,
    pub latest_memory_revision: Option<MemoryRevision>,
    pub project_heads: Vec<ProjectRevisionSummary>,
    pub last_receipts: Vec<WriteReceipt>,
    #[serde(rename = "final_status")]
    pub operation_status: OperationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimSummary {
    pub claim_id: ClaimId,
    pub statement: String,
    pub status: EpistemicStatus,
    pub memory_revision: MemoryRevision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureSummary {
    pub fingerprint: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryHandlePreview {
    pub handle: String,
    pub record_type: String,
    pub preview: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<MemoryLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_badge: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceAtom {
    pub evidence_id: EvidenceId,
    pub summary: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimCard {
    pub claim_id: ClaimId,
    pub statement: String,
    pub status: EpistemicStatus,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationRun {
    pub verification_id: VerificationId,
    #[serde(default)]
    pub claim_id: Option<ClaimId>,
    #[serde(default)]
    pub project_id: Option<ProjectId>,
    #[serde(default)]
    pub task_id: Option<TaskId>,
    #[serde(default)]
    pub write_id: Option<WriteId>,
    #[serde(default)]
    pub memory_revision: Option<MemoryRevision>,
    #[serde(default)]
    pub verifier: String,
    pub result: VerificationResult,
    pub summary: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolObservation {
    pub observation_id: String,
    pub tool_name: String,
    pub observation: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_id: Option<WriteId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureFingerprint {
    pub fingerprint: String,
    pub summary: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelationSummary {
    pub relation_type: RelationType,
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TruncationInfo {
    pub truncated: bool,
    pub limit: usize,
    pub returned: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CountByName {
    pub name: String,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectRevisionSummary {
    pub project_id: ProjectId,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
pub struct CompilePacketL3Request {
    pub project_id: ProjectId,
    pub task_id: String,
    pub goal: String,
    pub candidate_handles: Vec<String>,
    /// Optional caller-preferred target for the complete rendered context
    /// surface. This is neither a strict cap nor an exact mandatory floor: the
    /// Governor trims optional sections first and may expand to the computed
    /// mandatory floor up to its independently owned hard ceiling.
    #[serde(default = "default_context_packet_preferred_tokens")]
    pub max_tokens: usize,
}

pub const DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS: usize = 1_800;

const fn default_context_packet_preferred_tokens() -> usize {
    DEFAULT_CONTEXT_PACKET_PREFERRED_TOKENS
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GovernedGitScope {
    pub project_id: ProjectId,
    pub branch: String,
    pub commit: String,
    pub clean: bool,
    #[serde(default)]
    pub ancestor_commits: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<VerifierArtifactRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CurrentGitScopeView {
    pub project_id: ProjectId,
    pub branch: String,
    pub commit: String,
    pub clean: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryApplicabilityDisposition {
    VerifiedNow,
    RevalidatedNow,
    SuppressedHistorical,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryProvenanceView {
    pub source_id: Option<String>,
    pub project_scope: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<VerifierArtifactRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryApplicabilityDecision {
    pub memory_ref: String,
    pub disposition: MemoryApplicabilityDisposition,
    pub provenance: MemoryProvenanceView,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryApplicabilityPacketView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_git_scope: Option<CurrentGitScopeView>,
    #[serde(default)]
    pub decisions: Vec<MemoryApplicabilityDecision>,
    #[serde(default)]
    pub inclusion_reasons: Vec<String>,
    #[serde(default)]
    pub suppression_reasons: Vec<String>,
    #[serde(default)]
    pub revalidation_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextPacketL3 {
    #[serde(default)]
    pub packet_id: String,
    pub project_id: ProjectId,
    pub task_id: String,
    pub goal: String,
    #[serde(default)]
    pub task_execution_class: crate::TaskExecutionClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_understanding: Option<crate::ProjectUnderstandingModel>,
    #[serde(default)]
    pub memory_confidence: MemoryConfidence,
    #[serde(default)]
    pub acceptance_items: Vec<String>,
    pub at_revision: MemoryRevision,
    pub current_truth: Vec<ClaimSummary>,
    pub relevant_verified_claims: Vec<ClaimCard>,
    pub relevant_supported_claims: Vec<ClaimCard>,
    pub weak_claims_warning: Vec<ClaimCard>,
    pub negative_memory: Vec<ClaimCard>,
    pub recent_failures: Vec<FailureFingerprint>,
    pub known_decisions: Vec<ClaimCard>,
    pub open_questions: Vec<String>,
    pub exact_handles: Vec<String>,
    pub source_receipts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_truth_snapshot: Option<CurrentTruthSnapshot>,
    #[serde(default)]
    pub epistemic_state: EpistemicPacketState,
    #[serde(default)]
    pub active_plan: Vec<String>,
    #[serde(default)]
    pub completed_work: Vec<String>,
    #[serde(default)]
    pub killed_paths: Vec<String>,
    #[serde(default)]
    pub causal_bridge: Vec<CausalBridgeHop>,
    #[serde(default)]
    pub memory_decisions: Vec<MemoryDecisionReceipt>,
    #[serde(default)]
    pub experience_priors: Vec<ExperienceBrief>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_need_decision: Option<MemoryNeedDecision>,
    #[serde(default)]
    pub decision_locality_suffix: DecisionLocalitySuffix,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_quality: Option<PacketQualityReport>,
    #[serde(default)]
    pub memory_applicability: MemoryApplicabilityPacketView,
    #[serde(default)]
    pub historical_memory: Vec<ClaimCard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codecortex: Option<CodeCortexPacketView>,
    #[serde(default)]
    pub memory_lifecycle: MemoryLifecyclePacketView,
    #[serde(default)]
    pub procedural_skills: ProceduralSkillPacketView,
    pub token_budget_report: TokenBudgetReport,
    pub truncation: TruncationInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeCortexPacketView {
    pub report_refs: Vec<String>,
    pub git_head: Option<String>,
    #[serde(default)]
    pub scope_binding: CodeCortexScopeBinding,
    pub file_evidence: Vec<FileEvidence>,
    pub symbol_evidence: Vec<SymbolEvidence>,
    pub diagnostic_evidence: Vec<DiagnosticEvidence>,
    pub verifier_map: Vec<VerifierEvidence>,
    pub blast_radius: BlastRadiusView,
    pub unknowns: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBudgetReport {
    pub max_tokens: usize,
    pub estimated_tokens: usize,
    pub truncated: bool,
    pub sections_truncated: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnderstandingProof {
    pub task_id: String,
    pub project_id: ProjectId,
    pub goal: String,
    #[serde(default)]
    pub code_task: bool,
    pub current_truth_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub codecortex_report_refs: Vec<String>,
    #[serde(default)]
    pub files_to_change: Vec<String>,
    #[serde(default)]
    pub files_to_inspect: Vec<String>,
    pub causal_bridge: String,
    #[serde(default)]
    pub causal_bridge_from_goal_to_code: String,
    pub invariants: Vec<String>,
    pub negative_memory_checked: bool,
    pub unknowns: Vec<String>,
    pub planned_action: String,
    pub expected_verifiers: Vec<String>,
    #[serde(default)]
    pub blast_radius_acknowledged: bool,
    #[serde(default)]
    pub skill_refs: Vec<SkillId>,
    #[serde(default)]
    pub skill_application_rationales: Vec<String>,
    #[serde(default)]
    pub skill_anti_scope_acknowledgements: Vec<String>,
    #[serde(default)]
    pub skill_required_inputs: Vec<String>,
    #[serde(default)]
    pub skill_verifier_plan_refs: Vec<String>,
    pub risk_level: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnderstandingProofReceipt {
    pub task_id: String,
    pub project_id: ProjectId,
    pub accepted: bool,
    pub validation_errors: Vec<CognitiveGateReason>,
    pub checked_refs: Vec<String>,
    #[serde(default)]
    pub code_task: bool,
    #[serde(default)]
    pub codecortex_report_refs: Vec<String>,
    #[serde(default)]
    pub files_to_change: Vec<String>,
    #[serde(default)]
    pub files_to_inspect: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CognitiveGateRequest {
    pub receipt: UnderstandingProofReceipt,
    pub requested_action: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveGateOutcome {
    Allow,
    AllowReadOnly,
    RequireProbe,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveGateReason {
    MissingCurrentTruth,
    MissingEvidence,
    MissingCodeCortexReport,
    StaleCodeCortexReport,
    MissingCodeFileRefs,
    CodeFileNotInReport,
    WeakClaimUsedAsTruth,
    KnownFailureNotAddressed,
    InsufficientCausalBridge,
    MissingCodeCausalBridge,
    BlastRadiusNotAcknowledged,
    UnsafeActionScope,
    VerifierMissing,
    SkillBadLifecycle,
    SkillNotApplicable,
    SkillMissingInputs,
    SkillMissingVerifier,
    SkillConflict,
    SkillKnownFailureActive,
    SkillExecutionProofMissing,
    Allowed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CognitiveGateDecision {
    pub task_id: String,
    pub project_id: ProjectId,
    pub decision: CognitiveGateOutcome,
    pub reasons: Vec<CognitiveGateReason>,
}

pub type PathRef = String;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    ReadOnlyInspect,
    ProbePlan,
    ChangePlanOnly,
    PatchExecution,
    ShellExecution,
    ExternalAgentDelegation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseDecision {
    AllowReadOnly,
    AllowProbePlan,
    AllowChangePlanOnly,
    AllowPatchExecution,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    PlannedOnly,
    ApprovedForExecution,
    ReadOnly,
    ProbeOnly,
    Denied,
    Expired,
    Revoked,
    Superseded,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseDenyReason {
    MissingUnderstandingProof,
    MissingCognitiveGateDecision,
    CognitiveGateNotAllowingAction,
    MissingCodeCortexReport,
    StaleGitHead,
    FileOutsideCodeCortexReport,
    SymbolOutsideCodeCortexReport,
    MissingCausalBridge,
    MissingVerifierPlan,
    WeakClaimUsedAsTruth,
    UnboundedFileScope,
    RawShellRequested,
    PatchExecutionNotAllowedInE1,
    ExternalAgentNotAllowedInE1,
    ScopeTooLarge,
    MissingWorkLease,
    WorkLeaseInactive,
    WorkLeaseMismatch,
    FileOutsideWorkLease,
    IncidentLockdown,
    SkillActivationNotAllowed,
    SkillWouldBypassGate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionRequest {
    pub request_id: ActionRequestId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub goal: String,
    pub requested_action_kind: ActionKind,
    pub understanding_proof_ref: String,
    pub cognitive_gate_ref: String,
    pub codecortex_report_refs: Vec<String>,
    #[serde(default)]
    pub skill_refs: Vec<SkillId>,
    #[serde(default)]
    pub skill_activation_decisions: Vec<SkillActivationRecord>,
    pub proposed_change_plan: ChangePlan,
    pub proposed_verifier_plan: VerifierPlan,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionLease {
    pub lease_id: ActionLeaseId,
    pub request_id: ActionRequestId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub decision: LeaseDecision,
    pub status: LeaseStatus,
    pub allowed_scope: Option<ActionScope>,
    pub change_plan: Option<ChangePlan>,
    pub verifier_plan: Option<VerifierPlan>,
    #[serde(default)]
    pub skill_refs: Vec<SkillId>,
    pub denial_reasons: Vec<LeaseDenyReason>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionLeaseRecord {
    pub lease: ActionLease,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionScope {
    pub repo_root: PathRef,
    pub git_head: Option<String>,
    pub allowed_files: Vec<PathRef>,
    pub allowed_symbols: Vec<String>,
    pub forbidden_files: Vec<PathRef>,
    pub max_files: usize,
    pub max_diff_bytes: usize,
    pub max_runtime_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangePlan {
    pub summary: String,
    pub files: Vec<FileChangeIntent>,
    pub symbols: Vec<SymbolChangeIntent>,
    pub invariants_to_preserve: Vec<String>,
    pub risks: Vec<String>,
    pub rollback_plan: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileChangeIntent {
    pub path: PathRef,
    pub reason: String,
    pub expected_change_kind: FileChangeKind,
    pub code_evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    ReadOnly,
    Add,
    Modify,
    Delete,
    Rename,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolChangeIntent {
    pub symbol: String,
    pub reason: String,
    pub expected_change_kind: FileChangeKind,
    pub code_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierPlan {
    pub required: Vec<VerifierRequirement>,
    pub optional: Vec<VerifierRequirement>,
    pub acceptance_items: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierRequirement {
    pub name: String,
    pub command_kind: VerifierCommandKind,
    pub command_display: String,
    pub scope: Vec<PathRef>,
    pub required_for_done: bool,
    pub expected_signal: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierCommandKind {
    CargoFmtCheck,
    CargoCheck,
    CargoClippy,
    CargoTest,
    CargoNextest,
    CargoAudit,
    CargoDeny,
    DomainVerifier,
    ManualReview,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedDiff {
    pub text: String,
    pub byte_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchRequest {
    pub patch_request_id: PatchRequestId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub action_lease_id: ActionLeaseId,
    pub repo_root: PathRef,
    pub git_head_before: Option<String>,
    pub codecortex_report_refs: Vec<String>,
    pub verifier_plan_ref: String,
    pub diff: UnifiedDiff,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchRunStatus {
    Denied,
    PreflightPassed,
    AppliedVerifierPassed,
    AppliedVerifierFailed,
    RolledBack,
    RollbackFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierStatus {
    Passed,
    Failed,
    TimedOut,
    Skipped,
    NotAllowed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierRunRef {
    pub verifier_run_id: VerifierRunId,
    pub name: String,
    pub status: VerifierStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchRun {
    pub patch_run_id: PatchRunId,
    pub patch_request_id: PatchRequestId,
    pub action_lease_id: ActionLeaseId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub status: PatchRunStatus,
    pub repo_root: PathRef,
    pub git_head_before: Option<String>,
    pub git_head_after: Option<String>,
    pub changed_files: Vec<PathRef>,
    pub verifier_runs: Vec<VerifierRunRef>,
    pub failure_reasons: Vec<String>,
    pub stdout_blob: Option<BlobRef>,
    pub stderr_blob: Option<BlobRef>,
    pub rollback_ref: Option<String>,
    pub write_receipt: Option<WriteReceiptRef>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierRun {
    pub verifier_run_id: VerifierRunId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub name: String,
    pub command_kind: VerifierCommandKind,
    pub command_display: String,
    pub status: VerifierStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub stdout_blob: Option<BlobRef>,
    pub stderr_blob: Option<BlobRef>,
    pub summary: String,
    pub required_for_done: bool,
    pub write_receipt: Option<WriteReceiptRef>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletionProof {
    pub task_id: String,
    pub project_id: ProjectId,
    pub goal: String,
    pub changed_files: Vec<String>,
    pub memory_refs_used: Vec<String>,
    pub checks_run: Vec<String>,
    pub checks_not_run: Vec<String>,
    pub acceptance_items: Vec<CompletionAcceptanceItem>,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub skill_refs: Vec<SkillId>,
    #[serde(default)]
    pub skill_execution_proof_refs: Vec<String>,
    pub residual_uncertainty: String,
    pub known_risks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletionAcceptanceItem {
    pub item: String,
    pub status: String,
    pub evidence: String,
    pub verifier: String,
    pub residual_uncertainty: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletionStatus {
    DoneVerified,
    PartialProgress,
    BlockedByUnknown,
    FailedVerifier,
    UnsafeToFinish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationStatus {
    OperationCompleted,
    Active,
    Blocked,
    Failed,
}

impl OperationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperationCompleted => "OPERATION_COMPLETED",
            Self::Active => "ACTIVE",
            Self::Blocked => "BLOCKED",
            Self::Failed => "FAILED",
        }
    }
}

impl std::fmt::Display for OperationStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletionGateDecision {
    pub task_id: String,
    pub project_id: ProjectId,
    pub final_status: CompletionStatus,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeCortexRequest {
    pub project: String,
    pub task: String,
    pub goal: String,
    pub exact_patterns: Vec<String>,
    pub max_files: usize,
    pub max_matches_per_pattern: usize,
    pub include_diagnostics: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeCortexReport {
    pub project: String,
    pub task: String,
    pub goal: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub repo_root: String,
    pub git_head: Option<String>,
    pub dirty: bool,
    #[serde(default)]
    pub scope_binding: CodeCortexScopeBinding,
    pub tracked_files: Vec<FileEvidence>,
    pub workspace_members: Vec<String>,
    pub crates: Vec<String>,
    pub targets: Vec<String>,
    pub file_evidence: Vec<FileEvidence>,
    pub symbol_evidence: Vec<SymbolEvidence>,
    pub diagnostic_evidence: Vec<DiagnosticEvidence>,
    pub verifier_evidence: Vec<VerifierEvidence>,
    pub blast_radius: BlastRadiusView,
    pub invariant_cards: Vec<InvariantCard>,
    pub evidence_sources: Vec<CodeEvidenceSource>,
    pub adapter_notes: Vec<String>,
    pub memory_receipt: Option<WriteReceiptRef>,
    #[serde(rename = "final_status")]
    pub operation_status: OperationStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodeCortexScopeBinding {
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub adapter_versions: BTreeMap<String, String>,
    pub verifier_config_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEvidence {
    pub path: String,
    pub content_hash: Option<String>,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub excerpt: String,
    pub source: CodeEvidenceSource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolEvidence {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub line: Option<u32>,
    pub source: CodeEvidenceSource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticEvidence {
    pub source: CodeEvidenceSource,
    pub status: String,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierEvidence {
    pub name: String,
    pub command: String,
    pub status: String,
    pub summary: String,
    pub source: CodeEvidenceSource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlastRadiusView {
    pub files: Vec<String>,
    pub crates: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvariantCard {
    pub name: String,
    pub status: String,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeEvidenceSource {
    Git,
    CargoMetadata,
    Rg,
    AstGrep,
    Diagnostics,
    CodebaseMemory,
    DomainApi,
    MemoryWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Controller,
    Implementer,
    Reviewer,
    Auditor,
    Verifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransport {
    LocalCli,
    CodexHook,
    McpTool,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionStatus {
    Active,
    Idle,
    Stopped,
    Expired,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSession {
    pub agent_session_id: AgentSessionId,
    pub agent_id: AgentId,
    pub project_id: ProjectId,
    pub role: AgentRole,
    pub transport: AgentTransport,
    pub status: AgentSessionStatus,
    pub parent_session_id: Option<AgentSessionId>,
    pub current_work_item_id: Option<WorkItemId>,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_heartbeat_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub stopped_at: Option<OffsetDateTime>,
    pub unavailable_reason: Option<String>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkItemStatus {
    Open,
    Active,
    Blocked,
    Completed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityPermission {
    Read,
    Write,
    Patch,
    DelegateExternal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityProfile {
    pub permissions: BTreeSet<AuthorityPermission>,
}

impl AuthorityProfile {
    pub fn read_only() -> Self {
        let mut permissions = BTreeSet::new();
        permissions.insert(AuthorityPermission::Read);
        Self { permissions }
    }

    pub fn bounded_write() -> Self {
        let mut permissions = BTreeSet::new();
        permissions.insert(AuthorityPermission::Read);
        permissions.insert(AuthorityPermission::Write);
        Self { permissions }
    }

    pub fn allows(&self, permission: AuthorityPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn allows_write(&self) -> bool {
        self.allows(AuthorityPermission::Write)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkScope {
    pub repo_root: PathRef,
    pub read_set: Vec<PathRef>,
    pub write_set: Vec<PathRef>,
    pub verifier_set: Vec<String>,
    pub authority: AuthorityProfile,
    pub risk_tier: RiskTier,
    pub max_files: usize,
    pub requires_active_work_lease: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkItem {
    pub work_item_id: WorkItemId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub project: String,
    pub task: String,
    pub goal: String,
    pub scope: WorkScope,
    pub status: WorkItemStatus,
    pub required: bool,
    pub allowed_roles: Vec<AgentRole>,
    pub required_verifiers: Vec<VerifierRequirement>,
    #[serde(default)]
    pub verifier_run_refs: Vec<VerifierRunRef>,
    #[serde(default)]
    pub candidate_review_refs: Vec<String>,
    pub created_by: AgentSessionId,
    pub active_lease_id: Option<WorkLeaseId>,
    pub lease_refs: Vec<WorkLeaseId>,
    pub conflict_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkLeaseState {
    Granted,
    Renewed,
    Released,
    Revoked,
    Expired,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkLeaseDecisionKind {
    Granted,
    Denied,
    Renewed,
    Released,
    Revoked,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkLeaseDecisionReason {
    NoConflict,
    ReadOnlyOverlapAllowed,
    UnknownWorkItem,
    InactiveSession,
    MissingVerifier,
    OverlappingWriteScope,
    ScopeOutsideWorkItem,
    LeaseNotFound,
    ExpiredLease,
    ReleasedLease,
    RevokedLease,
    WorkItemNotSatisfied,
    AlreadyCompleted,
    UnavailableAdapter,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkLeaseDecision {
    pub kind: WorkLeaseDecisionKind,
    pub reason: WorkLeaseDecisionReason,
    pub message: String,
    pub work_lease_id: Option<WorkLeaseId>,
    pub conflicting_lease_ids: Vec<WorkLeaseId>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkLease {
    pub work_lease_id: WorkLeaseId,
    pub work_item_id: WorkItemId,
    pub agent_session_id: AgentSessionId,
    pub agent_id: AgentId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub role: AgentRole,
    pub state: WorkLeaseState,
    pub epoch: u64,
    pub scope: WorkScope,
    pub decision: WorkLeaseDecision,
    pub conflict_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub granted_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub renewed_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub released_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkConflictKind {
    OverlappingWriteScope,
    ExpiredLease,
    RevokedLease,
    MissingVerifier,
    OutsideScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkConflictResolution {
    Denied,
    Released,
    Revoked,
    Completed,
    WaivedReadOnlyOverlap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkConflict {
    pub conflict_id: String,
    pub work_item_id: WorkItemId,
    pub work_lease_id: WorkLeaseId,
    pub conflicting_work_lease_id: Option<WorkLeaseId>,
    pub kind: WorkConflictKind,
    pub paths: Vec<PathRef>,
    pub resolution: Option<WorkConflictResolution>,
    pub detail: String,
    #[serde(with = "time::serde::rfc3339")]
    pub detected_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    Running,
    Completed,
    Failed,
    Stopped,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRun {
    pub agent_run_id: AgentRunId,
    pub agent_session_id: AgentSessionId,
    pub work_item_id: Option<WorkItemId>,
    pub work_lease_id: Option<WorkLeaseId>,
    pub status: AgentRunStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
    pub summary: Option<String>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorktreeLeaseRequest {
    pub request_id: WorktreeLeaseRequestId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub work_lease_id: WorkLeaseId,
    pub agent_session_id: AgentSessionId,
    pub repo_root: PathRef,
    pub requested_branch_name: Option<String>,
    pub requested_scope: WorkScope,
    pub base_commit: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeLeaseState {
    Requested,
    Created,
    Active,
    Captured,
    Accepted,
    Rejected,
    Revoked,
    Expired,
    Cleaned,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeLeaseKind {
    #[default]
    LinkedGitWorktree,
    IndependentClone,
}

impl WorktreeLeaseKind {
    #[must_use]
    pub const fn is_linked_git_worktree(&self) -> bool {
        matches!(self, Self::LinkedGitWorktree)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorktreeLease {
    pub worktree_lease_id: WorktreeLeaseId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub work_lease_id: WorkLeaseId,
    pub holder_session_id: AgentSessionId,
    pub repo_root: PathRef,
    pub worktree_path: PathRef,
    pub branch_name: String,
    pub base_commit: String,
    pub allowed_read_set: Vec<PathRef>,
    pub allowed_write_set: Vec<PathRef>,
    #[serde(
        default,
        skip_serializing_if = "WorktreeLeaseKind::is_linked_git_worktree"
    )]
    pub kind: WorktreeLeaseKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_root: Option<PathRef>,
    pub state: WorktreeLeaseState,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub cleaned_at: Option<OffsetDateTime>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDiffStatus {
    Captured,
    Empty,
    OutOfScope,
    TooLarge,
    BaseDrift,
    DirtyTarget,
    Rejected,
    AcceptedForPatchRunner,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateDiff {
    pub candidate_diff_id: CandidateDiffId,
    pub worktree_lease_id: WorktreeLeaseId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub base_commit: String,
    pub worktree_head: Option<String>,
    pub diff_hash: String,
    pub diff_ref: String,
    pub changed_files: Vec<PathRef>,
    pub added_files: Vec<PathRef>,
    pub modified_files: Vec<PathRef>,
    pub deleted_files: Vec<PathRef>,
    pub byte_len: usize,
    pub file_count: usize,
    pub capture_status: CandidateDiffStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateReviewDecision {
    AcceptForPatchRunner,
    Reject,
    RequireRevision,
    RequireHumanReview,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateReview {
    pub review_id: String,
    pub candidate_diff_id: CandidateDiffId,
    pub reviewer_session_id: AgentSessionId,
    pub decision: CandidateReviewDecision,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub patch_request_id: Option<PatchRequestId>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlackboardItemKind {
    FindingCandidate,
    EvidenceHandle,
    Unknown,
    HypothesisCandidate,
    ConflictNotice,
    DecisionRequest,
    VerifierResult,
    ArtifactHandle,
    Blocker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlackboardItemStatus {
    Open,
    Acknowledged,
    Superseded,
    Resolved,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlackboardScope {
    pub memory_scope: Vec<String>,
    pub files: Vec<PathRef>,
    pub symbols: Vec<String>,
    pub work_items: Vec<WorkItemId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlackboardItem {
    pub blackboard_item_id: BlackboardItemId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub owner_session_id: AgentSessionId,
    pub work_item_id: Option<WorkItemId>,
    pub lease_id: Option<WorkLeaseId>,
    pub kind: BlackboardItemKind,
    pub scope: BlackboardScope,
    pub payload_ref: String,
    pub evidence_refs: Vec<String>,
    pub status: BlackboardItemStatus,
    pub confidence: Option<ConfidenceLevel>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub acknowledged_by: Vec<AgentSessionId>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxRecipient {
    Session(AgentSessionId),
    Role(AgentRole),
    Controller,
    WorkItem(WorkItemId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxMessageKind {
    WorkAssigned,
    WorkBlocked,
    LeaseExpiring,
    LeaseRevoked,
    WorktreeCaptured,
    CandidateReady,
    ReviewRequested,
    ConflictRaised,
    VerifierFailed,
    CompletionBlocked,
    AgentExpired,
    AckRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxMessageStatus {
    Pending,
    Delivered,
    Acknowledged,
    Expired,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub message_id: MailboxMessageId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub sender_session_id: AgentSessionId,
    pub recipient: MailboxRecipient,
    pub sequence: u64,
    pub kind: MailboxMessageKind,
    pub payload_ref: String,
    pub requires_ack: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub acknowledged_at: Option<OffsetDateTime>,
    pub status: MailboxMessageStatus,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    MarkAgentExpired,
    RevokeActionLease,
    RevokeOrExpireWorkLease,
    RetainWorktreeForInspection,
    NotifyController,
    MarkWorkItemResumable,
    MarkWorkItemBlocked,
    AdvanceLeaseEpoch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LostAgentRecoveryRecord {
    pub recovery_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    #[serde(with = "time::serde::rfc3339")]
    pub detected_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_heartbeat_at: Option<OffsetDateTime>,
    pub active_work_leases: Vec<WorkLeaseId>,
    pub active_action_leases: Vec<ActionLeaseId>,
    pub active_worktree_leases: Vec<WorktreeLeaseId>,
    pub actions_taken: Vec<RecoveryAction>,
    pub mailbox_messages: Vec<MailboxMessageId>,
    pub resulting_work_status: Vec<WorkItemStatus>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionEffect {
    ChangedAction,
    ChangedDecision,
    KilledHypothesis,
    ConfirmedVerifier,
    ProducedUnusedCandidate,
    CausedRework,
    NoObservableEffect,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentContributionTrace {
    pub agent_session_id: AgentSessionId,
    pub role: AgentRole,
    pub work_item_id: Option<WorkItemId>,
    pub contribution_refs: Vec<String>,
    pub effect: ContributionEffect,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectedCandidateTrace {
    pub candidate_ref: String,
    pub reviewer_session_id: Option<AgentSessionId>,
    pub reason: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierEffectTrace {
    pub verifier_ref: String,
    pub effect: ContributionEffect,
    pub killed_hypothesis_ref: Option<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectiveTrace {
    pub collective_trace_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    #[serde(with = "time::serde::rfc3339")]
    pub closed_at: OffsetDateTime,
    pub agent_contributions: Vec<AgentContributionTrace>,
    pub rejected_candidates: Vec<RejectedCandidateTrace>,
    pub verifier_effects: Vec<VerifierEffectTrace>,
    pub unused_context_items: Vec<String>,
    pub candidate_learning_refs: Vec<String>,
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EliotHookEvent {
    pub kind: HookEventKind,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    pub event_id: String,
    pub payload_hash: String,
    pub payload_size_bytes: usize,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    pub tool_name: Option<String>,
    pub prompt_excerpt: Option<String>,
    pub payload: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum HookEventKind {
    SessionStart,
    UserPromptSubmit,
    SubagentStart,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PreCompact,
    PostCompact,
    SubagentStop,
    Stop,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HookDecision {
    pub event_id: String,
    pub kind: HookEventKind,
    pub processing_status: HookProcessingStatus,
    pub allow: bool,
    pub reasons: Vec<HookDecisionReason>,
    pub spool_path: Option<String>,
    pub stdout: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HookDecisionReason {
    pub code: String,
    pub severity: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HookSpoolRecord {
    pub event: EliotHookEvent,
    pub decision: HookDecision,
    #[serde(with = "time::serde::rfc3339")]
    pub written_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookProcessingStatus {
    SpoolingPending,
    Committed,
    FailedOpen,
    FailedClosed,
    Blocked,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod recall_disposition_tests {
    use super::*;

    fn test_response() -> RecallL0Response {
        RecallL0Response {
            project_id: ProjectId::from_uuid(uuid::Uuid::nil()),
            at_revision: MemoryRevision::new(7),
            projection_revision: Some(MemoryRevision::new(7)),
            projection_state: CognitiveProjectionReadState::Published,
            handles: Vec::new(),
            memory_confidence: MemoryConfidence::None,
            query_mode: "test".to_owned(),
            rank_trace: L0RankTrace::default(),
            truncation: TruncationInfo {
                truncated: false,
                limit: 12,
                returned: 0,
            },
        }
    }

    fn suppression(handle: &str) -> L0SuppressionTrace {
        L0SuppressionTrace {
            handle: handle.to_owned(),
            reason: "scope_mismatch".to_owned(),
        }
    }

    #[test]
    fn closed_disposition_set_has_exactly_nine_wire_values() {
        assert_eq!(
            RecallDisposition::canonical_set(),
            [
                "ADMITTED_STRONG",
                "ADMITTED_WEAK",
                "NO_MATCH",
                "NO_USEFUL_MEMORY",
                "EMPTY_CORPUS",
                "SCOPE_SUPPRESSED",
                "STALE_PROJECTION",
                "CONFLICTED",
                "INCOMPLETE_COVERAGE",
            ]
        );
        for wire in RecallDisposition::canonical_set() {
            let round: RecallDisposition =
                serde_json::from_value(serde_json::Value::String(wire.to_owned()))
                    .expect("canonical wire value deserializes");
            assert_eq!(round.as_wire_str(), wire);
        }
    }

    #[test]
    fn all_scope_suppressed_returns_scope_suppressed_with_counts_and_no_content() {
        let mut response = test_response();
        response.rank_trace.candidates_considered = 3;
        response.rank_trace.scope_suppressions = vec![
            suppression("claim:a"),
            suppression("claim:b"),
            suppression("claim:c"),
        ];
        let verdict = ServerRecallVerdict::issue_for_l0_response(
            &response,
            "project/a",
            "fence-1",
            false,
            true,
            false,
        )
        .expect("server issues verdict");
        assert_eq!(verdict.disposition, RecallDisposition::ScopeSuppressed);
        assert_eq!(verdict.receipt.visible_count, 0);
        assert_eq!(verdict.receipt.suppressed_count, 3);
        assert!(response.handles.is_empty());
        assert!(!verdict.rank_trace_handle.is_empty());
        verdict
            .validate_for_l0_response(&response)
            .expect("server verdict binds response");
    }

    #[test]
    fn stale_projection_and_empty_corpus_map_to_their_dispositions() {
        let mut stale = test_response();
        stale.projection_state = CognitiveProjectionReadState::Stale;
        let stale_verdict =
            ServerRecallVerdict::issue_for_l0_response(&stale, "", "fence-1", false, true, false)
                .expect("server issues verdict");
        assert_eq!(
            stale_verdict.disposition,
            RecallDisposition::StaleProjection
        );

        let empty = test_response();
        let empty_verdict =
            ServerRecallVerdict::issue_for_l0_response(&empty, "", "fence-1", true, true, false)
                .expect("server issues verdict");
        assert_eq!(empty_verdict.disposition, RecallDisposition::EmptyCorpus);
    }

    #[test]
    fn agent_invented_disposition_fails_receipt_validation() {
        let mut response = test_response();
        response.rank_trace.candidates_considered = 2;
        let verdict = ServerRecallVerdict::issue_for_l0_response(
            &response, "", "fence-1", false, true, false,
        )
        .expect("server issues verdict");
        assert_eq!(verdict.disposition, RecallDisposition::NoUsefulMemory);
        let mut forged = verdict.clone();
        forged.disposition = RecallDisposition::NoMatch;
        assert!(forged.validate_for_l0_response(&response).is_err());
        let mut forged_handle = verdict;
        forged_handle.rank_trace_handle = "rank-trace:0".repeat(8);
        assert!(forged_handle.validate_for_l0_response(&response).is_err());
    }
}
