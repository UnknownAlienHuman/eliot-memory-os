use eliot_agent_api::{
    AdmittedRouteReceipt, AgentLaunchRequest, AgentResult, AttemptId, BudgetEnvelope, CancelReason,
    EpochId, EventId, HostEventNormalizationReceipt, HostEventQuarantineReason, LaunchRequestId,
    NormalizedHostEventEnvelope, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
    ResultDisposition, RouteFingerprint, RouteSelectionCandidate, StateFence, TaskId, WorkLeaseId,
    WorkUnitId,
};
use eliot_agent_contracts::{
    DescendantClosureReceipt, LivePeerMessage, LivePeerMessageState, MessageId,
    ParentFinishCeiling, RevisionId,
};
use eliot_contracts::LowercaseSha256;
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_kernel_core::NormalWorkClass;
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

/// Staffing-lane capacity/budget/rank evidence stays in this lane.
/// Route selection itself is the imported single-owner
/// [`RouteSelectionCandidate`]; there is no second shared routing receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingLaneRequest {
    pub work_unit_id: WorkUnitId,
    pub role_id: RoleProfileId,
    /// I14.1 work class (issue #1698) carried verbatim as its canonical
    /// `snake_case` spelling. Validated closed at plan time against the Kernel
    /// taxonomy ([`NormalWorkClass`] plus the protected `control` partition);
    /// absent or unknown is rejected, never defaulted.
    pub work_class: String,
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
    /// I14.1 work class for the whole plan (issue #1698). Every lane must
    /// carry this same class; a mixed-class plan is rejected so one
    /// definition, reservation and admission bind exactly one class.
    pub work_class: String,
    pub lanes: Vec<StaffingLaneRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingLaneCandidate {
    pub work_unit_id: WorkUnitId,
    pub role_id: RoleProfileId,
    pub role_revision: RevisionId,
    /// I14.1 work class threaded from the requesting lane (issue #1698):
    /// deterministic recipe/route/admission policy input, echoed verbatim.
    pub work_class: String,
    pub routing: RouteSelectionCandidate,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
    pub capacity_limit: usize,
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
    /// I14.1 work class threaded from the requesting plan (issue #1698).
    pub work_class: String,
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
    /// I14.1 work class echoed from the admitted candidate lane (issue
    /// #1698). Checked for exact equality at admission; a mismatch or an
    /// unknown value rejects, never downgrades.
    pub work_class: String,
    pub route: RouteFingerprint,
    /// Recomputed candidate identity: `candidate_digest_for` of the admitted
    /// `RouteSelectionCandidate` bytes (canonical JSON + SHA-256 hex, typed).
    /// Validators recompute; an unchecked copy is rejected at admission.
    pub routing_receipt_digest: LowercaseSha256,
    pub budget: BudgetEnvelope,
    pub priority: u16,
    pub mutation_scope: Option<String>,
    /// Externally-issued admitted route decision for this lane (issue #370
    /// S5). The external admission owner issues the receipt; the coordinator
    /// only stores and validates it, never mints. `None` is a legacy or
    /// unresolved launch and is rejected for binding closure (fail-closed).
    /// The `#[serde(default)]` keeps pre-S5 wire readable (additive, cf. S2
    /// `provider_binding`).
    #[serde(default)]
    pub admitted_route: Option<AdmittedRouteReceipt>,
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
    pub controller_epoch: EpochId,
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
    pub controller_epoch: EpochId,
    pub coordinator_lease: WorkLeaseId,
}

impl From<&ProviderAdmissionReceipt> for ExecutionContext {
    fn from(receipt: &ProviderAdmissionReceipt) -> Self {
        Self {
            admission_id: receipt.admission_id.clone(),
            task_revision: receipt.task_revision.clone(),
            plan_revision: receipt.plan_revision.clone(),
            state_fence: receipt.state_fence.clone(),
            controller_epoch: receipt.controller_epoch.clone(),
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
    /// I14.1 work class carried from the admitted lane (issue #1698). The
    /// scheduler routes/selects on this class before priority.
    pub work_class: String,
    pub route: RouteFingerprint,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
    pub capacity_limit: usize,
    pub budget: BudgetEnvelope,
    pub priority: u16,
    pub mutation_scope: Option<String>,
    pub state: CoordinatedAttemptState,
    pub superseded_by: Option<AttemptId>,
    /// Immutable provider-execution binding for this attempt (issue #361 S2).
    /// Set once by `bind_provider_execution`; `None` is an unresolved or
    /// legacy launch and is rejected for attribution (fail-closed). The
    /// `#[serde(default)]` keeps pre-S2 wire readable (additive).
    #[serde(default)]
    pub provider_binding: Option<ProviderExecutionBinding>,
    /// Stored admitted route decision for this attempt (issue #370 S5).
    /// Set from the admitted lane at admission; `None` is a legacy or
    /// unresolved launch (including reassigned attempts awaiting a new
    /// external decision for their new attempt identity) and is rejected for
    /// binding closure (fail-closed). The `#[serde(default)]` keeps pre-S5
    /// wire readable (additive, cf. S2 `provider_binding`).
    #[serde(default)]
    pub admitted_route: Option<AdmittedRouteReceipt>,
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

/// Provider-execution binding submission for one admitted attempt (issue #361
/// S2). It carries the shared `eliot_agent_api::ProviderExecutionBinding` plus
/// the existing provider identity/proof-reference pattern from
/// [`ResultSubmission`]: the sealed verifier authenticates the exact start
/// correlation (`provider_start_receipt_ref` over the canonical submission).
/// No credential, catalogue-as-admission, or session/login bridge is carried.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionBindingSubmission {
    pub binding: ProviderExecutionBinding,
    pub provider_identity: ProviderIdentity,
    pub provider_start_receipt_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateResultReceipt {
    pub submission_id: SubmissionId,
    pub attempt_id: AttemptId,
    pub provider_disposition: ResultDisposition,
    pub proof_ceiling: ProofCeiling,
    pub actual_route: PhysicalRouteObservationReceipt,
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
    /// A provider-execution binding was bound to an admitted attempt. The
    /// submission carries the attempt identity (via `binding.attempt_id`) and
    /// the canonical provider identity/proof, so replay re-verifies the exact
    /// canonical input and reconstructs the binding; a missing event leaves
    /// the attempt unresolved and attribution fails closed.
    ProviderExecutionBound {
        context: ExecutionContext,
        submission: Box<ProviderExecutionBindingSubmission>,
    },
    /// A closed v7 provider host event was observed under exact recorded
    /// lineage (issue #371 S7-partial). The envelope carries the attempt
    /// identity via its execution-unit lineage (or no attempt identity for
    /// session-only observations); replay re-validates the exact canonical
    /// input and rebuilds the observation index plus per-attempt sequencing
    /// without duplicating effects. Gap markers carry no independent
    /// mutation and rebuild deterministically from the observed stream.
    ProviderHostEventObserved {
        context: ExecutionContext,
        event: Box<NormalizedHostEventEnvelope>,
        normalization: Box<HostEventNormalizationReceipt>,
    },
    /// An explicit sequence gap precedes one observed host event. Ordering
    /// evidence only: it advances no cursor and synthesizes nothing.
    ProviderHostEventGap {
        context: ExecutionContext,
        attempt_id: AttemptId,
        event_id: EventId,
        expected_sequence: u64,
        observed_sequence: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedHostEventSummary {
    /// Observed event identity.
    pub event_id: EventId,
    /// Attempt scope for execution-unit observations; `None` for
    /// session-only observations, which mutate no attempt state.
    pub attempt_id: Option<AttemptId>,
    /// Observed sequence within the attempt scope.
    pub sequence: u64,
    /// Canonical output digest of the accepted envelope.
    pub output_digest: LowercaseSha256,
}

/// Stored summary of one observed v7 provider host event (issue #371
/// S7-partial). The canonical input binds the exact envelope plus receipt
/// bytes for idempotent replay; the summary carries the attempt scope (when
/// any), sequence, and output digest for ordering and conflict checks.

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
    #[error("unknown work class: {0}")]
    UnknownWorkClass(String),
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
    #[error("host event quarantined with conflicting {0:?}")]
    HostEventQuarantine(HostEventQuarantineReason),
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

/// I14.1 protected-partition work class (issue #1698). This is the single
/// non-normal value: it draws only from protected control capacity owned by
/// the Kernel (`eliot_kernel_core::ControlOperationClass` family) and can
/// never be served from the normal partition.
pub(crate) const WORK_CLASS_CONTROL: &str = "control";

/// Maps one I14.1 wire spelling to its Kernel normal-work owner (issue
/// #1698). Every [`NormalWorkClass`] variant is named explicitly so the
/// mapping is reviewable against the Kernel source; anything else (including
/// the protected `control` class and unknown values) is `None`, and only
/// `control` is additionally accepted by [`validate_work_class`]. A
/// Kernel-side taxonomy change is pinned by the exhaustive coupling test,
/// never by a silent parallel vocabulary here.
pub(crate) fn normal_work_class_from_wire(value: &str) -> Option<NormalWorkClass> {
    match value {
        "interactive" => Some(NormalWorkClass::Interactive),
        "verification" => Some(NormalWorkClass::Verification),
        "canonical_write" => Some(NormalWorkClass::CanonicalWrite),
        "normal_background" => Some(NormalWorkClass::NormalBackground),
        // I14.1 spells the model class `model_jobs`; the frozen
        // control-reserve vocabulary spells it `MODEL_JOB`.
        "model_jobs" => Some(NormalWorkClass::ModelJob),
        "swarm" => Some(NormalWorkClass::Swarm),
        "reporting" => Some(NormalWorkClass::Reporting),
        "maintenance" => Some(NormalWorkClass::Maintenance),
        _ => None,
    }
}

/// Validates one closed I14.1 work-class value (issue #1698): exactly the
/// nine canonical spellings. Blank, absent-shaped, or unknown values are
/// rejected with [`CoordinatorError::UnknownWorkClass`]; the caller never
/// substitutes a less restrictive class.
pub(crate) fn validate_work_class(value: &str) -> Result<(), CoordinatorError> {
    if value == WORK_CLASS_CONTROL || normal_work_class_from_wire(value).is_some() {
        Ok(())
    } else {
        Err(CoordinatorError::UnknownWorkClass(value.to_owned()))
    }
}

/// Deterministic scheduler rank for one validated work class (issue #1698):
/// protected `control` first (the reserve exists so control is never crowded
/// out by normal work), then the eight normal classes in I14.1 document
/// order. Unvalidated values sort last; admission never produces them, so
/// this arm is defensive ordering, not a silent default.
pub(crate) fn work_class_rank(value: &str) -> u8 {
    if value == WORK_CLASS_CONTROL {
        return 0;
    }
    match normal_work_class_from_wire(value) {
        Some(NormalWorkClass::Interactive) => 1,
        Some(NormalWorkClass::Verification) => 2,
        Some(NormalWorkClass::CanonicalWrite) => 3,
        Some(NormalWorkClass::NormalBackground) => 4,
        Some(NormalWorkClass::ModelJob) => 5,
        Some(NormalWorkClass::Swarm) => 6,
        Some(NormalWorkClass::Reporting) => 7,
        Some(NormalWorkClass::Maintenance) => 8,
        None => u8::MAX,
    }
}
