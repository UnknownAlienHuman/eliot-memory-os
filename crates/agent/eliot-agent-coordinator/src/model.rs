use eliot_agent_api::{
    ActualRouteReceipt, AgentLaunchRequest, AgentResult, AttemptId, AuthorityEpoch, BudgetEnvelope,
    CancelReason, LaunchRequestId, ResultDisposition, RouteFingerprint, StateFence, TaskId,
    WorkLeaseId, WorkUnitId,
};
use eliot_agent_contracts::{
    DescendantClosureReceipt, LivePeerMessage, LivePeerMessageState, MessageId,
    ParentFinishCeiling, RevisionId,
};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::PrivacyClass;
use serde::{Deserialize, Serialize};
use thiserror::Error;

macro_rules! local_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CoordinatorError> {
                let value = value.into();
                validate_text(&value, stringify!($name))?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = CoordinatorError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = CoordinatorError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

local_id!(CandidateId);
local_id!(AdmissionId);
local_id!(RecipeId);
local_id!(RoleProfileId);
local_id!(WorkerId);
local_id!(OperationId);
local_id!(SubmissionId);
local_id!(ObservationId);
local_id!(ReassignmentId);
local_id!(CancellationReconciliationId);
local_id!(OutcomeReconciliationId);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorConfig {
    pub max_ready_items: usize,
    pub max_admitted_attempts: usize,
    pub max_active_per_route: usize,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
}

impl CoordinatorConfig {
    pub fn validate(&self) -> Result<(), CoordinatorError> {
        for (field, value) in [
            ("max_ready_items", self.max_ready_items),
            ("max_admitted_attempts", self.max_admitted_attempts),
            ("max_active_per_route", self.max_active_per_route),
        ] {
            if value == 0 {
                return Err(CoordinatorError::InvalidField(field));
            }
        }
        validate_text(&self.capacity_identity, "capacity_identity")?;
        validate_text(self.capacity_revision.as_str(), "capacity_revision")
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "provider",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum PlanGap {
    #[error("PLAN_GAP: A-01 provider authority is unaccepted at {contract_version}: {reason}")]
    A01Unaccepted {
        contract_version: String,
        reason: String,
    },
    #[error("PLAN_GAP: live G-11 durable-job/admission provider is unavailable: {reason}")]
    G11Unavailable { reason: String },
}

impl PlanGap {
    pub(crate) fn validate(&self) -> Result<(), CoordinatorError> {
        match self {
            Self::A01Unaccepted {
                contract_version,
                reason,
            } => {
                validate_text(contract_version, "a01_contract_version")?;
                validate_text(reason, "a01_gap_reason")
            }
            Self::G11Unavailable { reason } => validate_text(reason, "g11_gap_reason"),
        }
    }
}

/// Identity returned by a sealed provider verifier. Possessing this serializable
/// projection does not grant authority; every effecting method calls the
/// injected verifier again.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    pub verifier_identity: String,
    pub a01_acceptance_receipt_ref: String,
    pub a01_contract_revision: String,
    pub g11_provider_revision: String,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
}

impl ProviderIdentity {
    pub(crate) fn validate(&self) -> Result<(), CoordinatorError> {
        for (value, field) in [
            (self.verifier_identity.as_str(), "verifier_identity"),
            (
                self.a01_acceptance_receipt_ref.as_str(),
                "a01_acceptance_receipt_ref",
            ),
            (self.a01_contract_revision.as_str(), "a01_contract_revision"),
            (self.g11_provider_revision.as_str(), "g11_provider_revision"),
            (self.capacity_identity.as_str(), "capacity_identity"),
            (self.capacity_revision.as_str(), "capacity_revision"),
        ] {
            validate_text(value, field)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ProviderBindingSnapshot {
    Gap { gap: PlanGap },
    Verified { identity: ProviderIdentity },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleProfileManifest {
    pub role_id: RoleProfileId,
    pub manifest_revision: RevisionId,
    pub required_competence: Vec<String>,
    pub allowed_route_classes: Vec<String>,
    pub mutation_capable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeManifest {
    pub recipe_id: RecipeId,
    pub manifest_revision: RevisionId,
    pub route_policy_revision: RevisionId,
    pub max_lanes: usize,
    pub max_descendants: u32,
    pub role_profiles: Vec<RoleProfileManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCandidateEvidence {
    pub route: RouteFingerprint,
    pub preference_rank: u16,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
    pub capacity_limit: usize,
    pub budget_evidence: BudgetEvidence,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteRejectionReason {
    LowerDeterministicRank,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedRoute {
    pub route: RouteFingerprint,
    pub reason: RouteRejectionReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingReceipt {
    pub selected_route: RouteFingerprint,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
    pub capacity_limit: usize,
    pub budget_evidence: BudgetEvidence,
    pub evidence_refs: Vec<String>,
    pub rejected_alternatives: Vec<RejectedRoute>,
    pub proof_ceiling: ProofCeiling,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingLaneRequest {
    pub work_unit_id: WorkUnitId,
    pub role_id: RoleProfileId,
    pub route_candidates: Vec<RouteCandidateEvidence>,
    pub budget: BudgetEnvelope,
    pub priority: u16,
    pub mutation_scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingPlanRequest {
    pub candidate_id: CandidateId,
    pub launch: AgentLaunchRequest,
    pub recipe: RecipeManifest,
    pub task_revision: String,
    pub plan_revision: RevisionId,
    pub state_fence: StateFence,
    pub privacy_class: PrivacyClass,
    pub lanes: Vec<StaffingLaneRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingLaneCandidate {
    pub work_unit_id: WorkUnitId,
    pub role_id: RoleProfileId,
    pub role_revision: RevisionId,
    pub routing: RoutingReceipt,
    pub budget: BudgetEnvelope,
    pub priority: u16,
    pub mutation_scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingPlanCandidate {
    pub candidate_id: CandidateId,
    pub task_id: TaskId,
    pub launch_request_id: LaunchRequestId,
    pub recipe_id: RecipeId,
    pub recipe_revision: RevisionId,
    pub task_revision: String,
    pub plan_revision: RevisionId,
    pub state_fence: StateFence,
    pub privacy_class: PrivacyClass,
    pub lanes: Vec<StaffingLaneCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedLaneReceipt {
    pub work_unit_id: WorkUnitId,
    pub role_id: RoleProfileId,
    pub role_revision: RevisionId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub worker_id: WorkerId,
    pub route: RouteFingerprint,
    pub routing_receipt_digest: String,
    pub budget: BudgetEnvelope,
    pub priority: u16,
    pub mutation_scope: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdmissionReceipt {
    pub admission_id: AdmissionId,
    pub candidate_id: CandidateId,
    pub launch_request_id: LaunchRequestId,
    pub recipe_id: RecipeId,
    pub recipe_revision: RevisionId,
    pub task_id: TaskId,
    pub task_revision: String,
    pub plan_revision: RevisionId,
    pub state_fence: StateFence,
    pub controller_epoch: AuthorityEpoch,
    pub coordinator_lease: WorkLeaseId,
    pub provider_identity: ProviderIdentity,
    pub g11_admission_receipt_ref: String,
    pub durable_job_ref: String,
    pub admitted_lanes: Vec<AdmittedLaneReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContext {
    pub admission_id: AdmissionId,
    pub task_revision: String,
    pub plan_revision: RevisionId,
    pub state_fence: StateFence,
    pub controller_epoch: AuthorityEpoch,
    pub coordinator_lease: WorkLeaseId,
}

impl From<&ProviderAdmissionReceipt> for ExecutionContext {
    fn from(receipt: &ProviderAdmissionReceipt) -> Self {
        Self {
            admission_id: receipt.admission_id.clone(),
            task_revision: receipt.task_revision.clone(),
            plan_revision: receipt.plan_revision.clone(),
            state_fence: receipt.state_fence.clone(),
            controller_epoch: receipt.controller_epoch,
            coordinator_lease: receipt.coordinator_lease.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoordinatedAttemptState {
    Admitted,
    Running,
    CancellationRequested,
    LostFenced,
    UnknownOutcome,
    Cancelled,
    CandidateResultSubmitted,
}

impl CoordinatedAttemptState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::LostFenced | Self::Cancelled | Self::CandidateResultSubmitted
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    pub admission_id: AdmissionId,
    pub launch_request_id: LaunchRequestId,
    pub parent_attempt_id: Option<AttemptId>,
    pub recipe_id: RecipeId,
    pub recipe_revision: RevisionId,
    pub task_id: TaskId,
    pub task_revision: String,
    pub plan_revision: RevisionId,
    pub state_fence: StateFence,
    pub work_unit_id: WorkUnitId,
    pub role_id: RoleProfileId,
    pub role_revision: RevisionId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub worker_id: WorkerId,
    pub route: RouteFingerprint,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
    pub capacity_limit: usize,
    pub budget: BudgetEnvelope,
    pub priority: u16,
    pub mutation_scope: Option<String>,
    pub state: CoordinatedAttemptState,
    pub superseded_by: Option<AttemptId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelCommand {
    pub operation_id: OperationId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub worker_id: WorkerId,
    pub reason: CancelReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReceipt {
    pub operation_id: OperationId,
    pub attempt_id: AttemptId,
    pub state: CoordinatedAttemptState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCancellationReconciliation {
    pub reconciliation_id: CancellationReconciliationId,
    pub request_operation_id: OperationId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub worker_id: WorkerId,
    pub provider_identity: ProviderIdentity,
    pub no_effect_or_cleanup_receipt_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationFinalReceipt {
    pub reconciliation_id: CancellationReconciliationId,
    pub attempt_id: AttemptId,
    pub state: CoordinatedAttemptState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderWorkerFenceReceipt {
    pub observation_id: ObservationId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub worker_id: WorkerId,
    pub provider_identity: ProviderIdentity,
    pub fence_receipt_ref: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LostWorkerReceipt {
    pub observation_id: ObservationId,
    pub attempt_id: AttemptId,
    pub state: CoordinatedAttemptState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReassignmentReceipt {
    pub reassignment_id: ReassignmentId,
    pub provider_identity: ProviderIdentity,
    pub g11_receipt_ref: String,
    pub old_attempt_id: AttemptId,
    pub old_lease_id: WorkLeaseId,
    pub new_attempt_id: AttemptId,
    pub new_lease_id: WorkLeaseId,
    pub new_worker_id: WorkerId,
    pub route: RouteFingerprint,
    pub budget: BudgetEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReassignmentReceipt {
    pub reassignment_id: ReassignmentId,
    pub old_attempt_id: AttemptId,
    pub new_attempt_id: AttemptId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSubmission {
    pub submission_id: SubmissionId,
    pub lease_id: WorkLeaseId,
    pub worker_id: WorkerId,
    pub provider_identity: ProviderIdentity,
    pub provider_result_receipt_ref: String,
    pub result: AgentResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateResultReceipt {
    pub submission_id: SubmissionId,
    pub attempt_id: AttemptId,
    pub provider_disposition: ResultDisposition,
    pub proof_ceiling: ProofCeiling,
    pub actual_route: ActualRouteReceipt,
    pub evidence_refs: Vec<String>,
    pub proposed_effect_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnknownOutcomeResolution {
    NoEffect,
    ReconciledCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderUnknownOutcomeReconciliation {
    pub reconciliation_id: OutcomeReconciliationId,
    pub submission_id: SubmissionId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub worker_id: WorkerId,
    pub provider_identity: ProviderIdentity,
    pub resolution: UnknownOutcomeResolution,
    pub effect_reconciliation_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownOutcomeFinalReceipt {
    pub reconciliation_id: OutcomeReconciliationId,
    pub attempt_id: AttemptId,
    pub resolution: UnknownOutcomeResolution,
    pub state: CoordinatedAttemptState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantClosureSubmission {
    pub operation_id: OperationId,
    pub parent_attempt_id: AttemptId,
    pub receipt: DescendantClosureReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantClosureCandidateReceipt {
    pub operation_id: OperationId,
    pub parent_attempt_id: AttemptId,
    pub parent_finish_ceiling: ParentFinishCeiling,
    pub proof_ceiling: ProofCeiling,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerMessageReceipt {
    pub message_id: MessageId,
    pub state: LivePeerMessageState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryBoundaryReceipt {
    pub message_id: MessageId,
    pub recipient_attempt_id: AttemptId,
    pub state: LivePeerMessageState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CoordinatorEvent {
    PlanCreated {
        request: Box<StaffingPlanRequest>,
    },
    PlanAdmitted {
        receipt: Box<ProviderAdmissionReceipt>,
    },
    AttemptStarted {
        context: ExecutionContext,
        attempt_id: AttemptId,
    },
    CancellationRequested {
        context: ExecutionContext,
        command: Box<CancelCommand>,
    },
    CancellationReconciled {
        context: ExecutionContext,
        receipt: Box<ProviderCancellationReconciliation>,
    },
    WorkerFenced {
        context: ExecutionContext,
        receipt: Box<ProviderWorkerFenceReceipt>,
    },
    Reassigned {
        context: ExecutionContext,
        receipt: Box<ProviderReassignmentReceipt>,
    },
    ResultSubmitted {
        context: ExecutionContext,
        submission: Box<ResultSubmission>,
    },
    UnknownOutcomeReconciled {
        context: ExecutionContext,
        receipt: Box<ProviderUnknownOutcomeReconciliation>,
    },
    DescendantsReconciled {
        context: ExecutionContext,
        submission: Box<DescendantClosureSubmission>,
    },
    PeerMessageQueued {
        context: ExecutionContext,
        message: Box<LivePeerMessage>,
    },
    PeerMessageDelivered {
        context: ExecutionContext,
        recipient_attempt_id: AttemptId,
        message_id: MessageId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorSnapshot {
    pub schema_version: String,
    pub config: CoordinatorConfig,
    pub provider_binding: ProviderBindingSnapshot,
    pub event_sequence: u64,
    pub event_digest: String,
    pub events: Vec<CoordinatorEvent>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CoordinatorError {
    #[error("invalid coordinator field: {0}")]
    InvalidField(&'static str),
    #[error("invalid provider contract: {0}")]
    ProviderContract(String),
    #[error("provider evidence verification failed: {0}")]
    ProviderVerification(String),
    #[error(transparent)]
    PlanGap(#[from] PlanGap),
    #[error("unknown staffing candidate")]
    UnknownCandidate,
    #[error("unknown provider admission")]
    UnknownAdmission,
    #[error("unknown attempt")]
    UnknownAttempt,
    #[error("unknown peer message")]
    UnknownMessage,
    #[error("identity conflict for {0}")]
    IdentityConflict(&'static str),
    #[error("duplicate identity for {0}")]
    DuplicateIdentity(&'static str),
    #[error("stale task revision")]
    StaleTaskRevision,
    #[error("stale plan revision")]
    StalePlanRevision,
    #[error("stale state fence")]
    StaleFence,
    #[error("stale controller epoch or coordinator lease")]
    StaleController,
    #[error("stale worker")]
    StaleWorker,
    #[error("stale work lease")]
    StaleLease,
    #[error("stale result")]
    StaleResult,
    #[error("route receipt does not match the admitted route")]
    RouteMismatch,
    #[error("route evidence is missing or stale")]
    RouteEvidence,
    #[error("budget is wider than the admitted budget")]
    BudgetExceeded,
    #[error("one mutating holder already owns scope {0}")]
    MutatingWriterConflict(String),
    #[error(
        "bounded coordinator capacity reached: active {active}, requested {requested}, limit {limit}"
    )]
    Backpressure {
        active: usize,
        requested: usize,
        limit: usize,
    },
    #[error("attempt state {0:?} does not admit this operation")]
    InvalidAttemptState(CoordinatedAttemptState),
    #[error("result already exists for this attempt")]
    DuplicateResult,
    #[error("idempotency identity was reused with different canonical input")]
    IdempotencyConflict,
    #[error("unknown outcome requires authenticated reconciliation")]
    UnknownOutcomeRequiresReconciliation,
    #[error("descendant closure is incomplete or mismatched")]
    IncompleteDescendantClosure,
    #[error("delivery capability is unavailable at this boundary")]
    DeliveryUnavailable,
    #[error("snapshot schema is unsupported")]
    UnsupportedSnapshot,
    #[error("snapshot event sequence is stale or inconsistent")]
    SnapshotRollback,
    #[error("snapshot digest does not bind its state")]
    SnapshotDigest,
    #[error("live capacity identity or revision changed")]
    StaleCapacity,
    #[error("persisted provider binding does not match current live provider evidence")]
    StaleProviderBinding,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), CoordinatorError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoordinatorError::InvalidField(field));
    }
    Ok(())
}
