//! Inert result vocabulary emitted by the reactive planning cell.

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{
    AttentionAcknowledgement, AttentionResolution, CapacityLimits, CoverageEvidence,
    DecisionContextIncomplete, OmissionRecord, ReactiveDeliveryMode, SerializedContextMeasurement,
    SnapshotCompleteness, SnapshotDenominator,
};
use eliot_contracts::{
    ArtifactId, ClockReading, ContractIdentity, OperationId, RequestId, StateFence, TaskId,
};
use eliot_cue_contracts::ActivationResult;
use eliot_protocol::{ReactiveContextContentRef, ReactiveContextPrivacy};
use eliot_receipts::{ProofCeiling, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One closed disposition for every considered semantic or Attention member.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryDisposition {
    EventPlan,
    ToolOnlyAdvisory,
    DeliveredDuplicate,
    InFlight,
    StickyPendingResolution,
    DelayedBackpressure,
    WithheldPrivacy,
    WithheldProfile,
    WithheldBudget,
    UnsupportedCapability,
    StaleInvalidated,
    ExplicitNotSelected,
    OmissionReferenceOnly,
    AmbiguousUnknown,
    BoundedOutFrontier,
}

/// Which retained A10 evidence reaches one semantic target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationEvidenceKind {
    Direct,
    Derived,
    DirectAndDerived,
}

/// Semantic kind of one accounted item; identity is never inferred from text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlannedItemKind {
    Context,
    Attention,
    Omission,
}

/// Opaque Attention identity and owner state retained for downstream handling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlannedAttentionBinding {
    pub attention_id: ArtifactId,
    pub claim_artifact_id: ArtifactId,
    pub claim_digest: String,
    pub source_revision: String,
    pub projection_digest: String,
    /// The member owner remains distinct from any authority that issued a
    /// terminal waiver or supersession decision.
    pub member_owner_id: String,
    pub resolution_owner: String,
    pub waiver_authority: Option<String>,
    pub superseded_by: Option<ReactiveContextContentRef>,
    pub acknowledgement: AttentionAcknowledgement,
    pub resolution: AttentionResolution,
    pub sticky: bool,
    pub proof_ceiling: ProofCeiling,
}

/// Stable response family for typed planning failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanningErrorDisposition {
    InvalidRequest,
    StaleOrConflict,
    NeedsEvidence,
    UnavailableOrCapacity,
    Failed,
}

/// Typed cause retained with a bounded diagnostic and no provider content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanningErrorKind {
    InvalidIdentity,
    InvalidSchema,
    BindingMismatch,
    IdentityConflict,
    StaleInput,
    CoverageUnverified,
    AttentionClosureInvalid,
    UnknownRequiredCost,
    Overflow,
    Cancellation,
    InternalContract,
}

/// A bounded, agent-facing planning error.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextPlanningError {
    pub disposition: PlanningErrorDisposition,
    pub kind: PlanningErrorKind,
    pub reason_code: String,
    pub operation_id: Option<OperationId>,
    pub request_id: Option<RequestId>,
    pub input_digest: Option<String>,
    pub detail: String,
}

/// Exact immutable cost and denominator ledger for one plan attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanningAccounting {
    pub considered: u64,
    pub planned: u64,
    pub deduped: u64,
    pub delayed: u64,
    pub withheld: u64,
    /// Count of unresolved sticky obligations, independent of selected items.
    pub sticky: u64,
    pub unsupported: u64,
    pub frontier: u64,
    pub input_bytes: u64,
    pub references: u64,
    pub work: u64,
    pub selected_delivery_bytes: u64,
    pub selected_delivery_stu: Option<u64>,
    pub fixed_reserve: u64,
    pub protocol_reserve: u64,
    pub output_reserve: u64,
    pub review_reserve: u64,
    pub delivery_reserve: u64,
    pub required_floor_bytes: u64,
    pub required_attention_bytes: u64,
    pub budget_fit: bool,
}

/// Exact view representation plus owner-neutral handles for one item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlannedContextItem {
    pub item_id: String,
    pub kind: PlannedItemKind,
    /// The exact rendered atom is retained so role, privacy, proof, authority,
    /// measurement, and dependency semantics cannot be reconstructed loosely.
    pub rendered: Option<eliot_context_contracts::RenderedAtom>,
    pub content: Vec<ReactiveContextContentRef>,
    pub source: Vec<ReactiveContextContentRef>,
    pub profile: ReactiveContextContentRef,
    pub activation_kind: Option<ActivationEvidenceKind>,
    pub activation_targets: Vec<eliot_cue_contracts::TargetHandle>,
    pub attention_kind: Option<String>,
    pub attention: Option<PlannedAttentionBinding>,
    pub omission: Option<OmissionRecord>,
    pub disposition: DeliveryDisposition,
    pub byte_cost: u64,
    pub stu_cost: Option<u64>,
    pub reason: String,
}

/// Locally typed request for a downstream owner to perform delivery later.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InertDeliveryRequest {
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub plan_id: ArtifactId,
    pub target_event_id: Option<ArtifactId>,
    pub target_event: String,
    pub delivery_profile: ReactiveContextContentRef,
    pub delivery_contract: ContractIdentity,
    pub mode: ReactiveDeliveryMode,
    pub session_id: eliot_contracts::SessionId,
    pub principal_id: String,
    pub recipient_id: String,
    pub runtime_id: String,
    pub host_id: String,
    pub runtime_generation: eliot_contracts::ResourceGeneration,
    pub host_generation: eliot_contracts::ResourceGeneration,
    pub task_id: TaskId,
    pub attempt_id: AgentAttemptId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub observed_at: ClockReading,
    pub deadline_ms: Option<i64>,
    pub privacy_ceiling: ReactiveContextPrivacy,
    pub proof_ceiling: ProofCeiling,
    pub items: Vec<PlannedContextItem>,
    pub request_digest: String,
    pub serialized_bytes: u64,
}

/// Complete pending plan; its request is inert and has no execution receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PendingContextInjectionPlan {
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub plan_id: ArtifactId,
    pub input_digest: String,
    pub result_digest: String,
    pub view_digest: String,
    pub admitted_set_digest: String,
    pub assembly_digest: String,
    pub activation_digest: String,
    pub activation_result: ActivationResult,
    pub session_snapshot_digest: String,
    pub attention_projection_digest: String,
    pub coverage_profile_digest: String,
    pub coverage_completeness: SnapshotCompleteness,
    pub coverage_gaps: Vec<String>,
    pub selected_event_evidence: Vec<CoverageEvidence>,
    pub session_completeness: SnapshotCompleteness,
    pub session_denominator: SnapshotDenominator,
    pub context_measurement: SerializedContextMeasurement,
    pub floor_capacity: CapacityLimits,
    pub floor_incomplete: Option<DecisionContextIncomplete>,
    pub policy_digest: String,
    pub mode: ReactiveDeliveryMode,
    pub items: Vec<PlannedContextItem>,
    pub accounting: PlanningAccounting,
    pub frontier: Vec<String>,
    pub invalidation: Vec<String>,
    pub request: InertDeliveryRequest,
}

/// Explicit no-op with the same complete item and budget accounting as a plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoInjectionDisposition {
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub plan_id: ArtifactId,
    pub input_digest: String,
    pub result_digest: String,
    pub view_digest: String,
    pub admitted_set_digest: String,
    pub assembly_digest: String,
    pub activation_digest: String,
    pub activation_result: ActivationResult,
    pub session_snapshot_digest: String,
    pub attention_projection_digest: String,
    pub coverage_profile_digest: String,
    pub coverage_completeness: SnapshotCompleteness,
    pub coverage_gaps: Vec<String>,
    pub selected_event_evidence: Vec<CoverageEvidence>,
    pub session_completeness: SnapshotCompleteness,
    pub session_denominator: SnapshotDenominator,
    pub context_measurement: SerializedContextMeasurement,
    pub floor_capacity: CapacityLimits,
    pub floor_incomplete: Option<DecisionContextIncomplete>,
    pub policy_digest: String,
    pub reason: String,
    pub items: Vec<PlannedContextItem>,
    pub accounting: PlanningAccounting,
    pub frontier: Vec<String>,
    pub invalidation: Vec<String>,
}

/// The operation's three possible outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "result",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ReactiveContextPlanResult {
    Pending(PendingContextInjectionPlan),
    NoInjection(NoInjectionDisposition),
    Error(ReactiveContextPlanningError),
}
