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
use std::collections::BTreeSet;
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
    /// I14.1 work class (issue #1698) as the closed boundary type. The wire
    /// carries exactly the nine lowercase spellings; `Deserialize` converts
    /// through [`WorkClass::parse_wire`] so an unknown value rejects at
    /// decode ingress and every in-memory value is validated by
    /// construction. Absent or unknown is rejected, never defaulted.
    pub work_class: WorkClass,
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
    /// I14.1 work class for the whole plan (issue #1698) as the closed
    /// boundary type. Every lane must carry this same class; a mixed-class
    /// plan is rejected so one definition, reservation and admission bind
    /// exactly one class.
    pub work_class: WorkClass,
    pub lanes: Vec<StaffingLaneRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingLaneCandidate {
    pub work_unit_id: WorkUnitId,
    pub role_id: RoleProfileId,
    pub role_revision: RevisionId,
    /// I14.1 work class threaded from the requesting lane (issue #1698) as
    /// the closed boundary type: deterministic recipe/route/admission policy
    /// input, echoed exactly.
    pub work_class: WorkClass,
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
    /// I14.1 work class threaded from the requesting plan (issue #1698) as
    /// the closed boundary type.
    pub work_class: WorkClass,
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
    /// #1698) as the closed boundary type. Checked for exact equality at
    /// admission; a mismatch rejects, never downgrades. Unknown values are
    /// unrepresentable: `Deserialize` rejects them at decode ingress.
    pub work_class: WorkClass,
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
    /// I14.1 work class carried from the admitted lane (issue #1698) as the
    /// closed boundary type. The scheduler routes/selects on this class
    /// before priority; only validated values can be stored here.
    pub work_class: WorkClass,
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

/// Candidate-only result receipt (issue #370 S5). The ceiling is fixed at
/// construction and on the wire: fields are private so a returned receipt
/// cannot be mutated into a stronger proof, and deserialization rejects any
/// ceiling other than `CANDIDATE_ARTIFACT`. No amount of artifacts, evidence
/// refs, or rationale can raise this receipt above candidate proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateResultReceipt {
    submission_id: SubmissionId,
    attempt_id: AttemptId,
    provider_disposition: ResultDisposition,
    #[serde(deserialize_with = "deserialize_candidate_artifact_ceiling")]
    proof_ceiling: ProofCeiling,
    actual_route: PhysicalRouteObservationReceipt,
    evidence_refs: Vec<String>,
    proposed_effect_count: usize,
}

/// Rejects any candidate-receipt wire whose ceiling is not exactly
/// `CANDIDATE_ARTIFACT` (issue #370 W4/A5). Stronger ceilings
/// (`SCOPED_VERIFICATION`, `OBSERVED_EXTERNAL_EFFECT`) fail closed here
/// instead of deserializing into a receipt that claims them.
fn deserialize_candidate_artifact_ceiling<'de, D>(deserializer: D) -> Result<ProofCeiling, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ceiling = ProofCeiling::deserialize(deserializer)?;
    if ceiling != ProofCeiling::CandidateArtifact {
        return Err(serde::de::Error::custom(
            "candidate result receipt proof ceiling must be CANDIDATE_ARTIFACT",
        ));
    }
    Ok(ceiling)
}

impl CandidateResultReceipt {
    /// Builds the sole production receipt shape: the ceiling is always
    /// [`ProofCeiling::CandidateArtifact`], independent of disposition,
    /// evidence volume, or rationale. There is no constructor that accepts
    /// a ceiling.
    #[must_use]
    pub fn new(
        submission_id: SubmissionId,
        attempt_id: AttemptId,
        provider_disposition: ResultDisposition,
        actual_route: PhysicalRouteObservationReceipt,
        evidence_refs: Vec<String>,
        proposed_effect_count: usize,
    ) -> Self {
        Self {
            submission_id,
            attempt_id,
            provider_disposition,
            proof_ceiling: ProofCeiling::CandidateArtifact,
            actual_route,
            evidence_refs,
            proposed_effect_count,
        }
    }

    #[must_use]
    pub fn submission_id(&self) -> &SubmissionId {
        &self.submission_id
    }

    #[must_use]
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }

    #[must_use]
    pub const fn provider_disposition(&self) -> ResultDisposition {
        self.provider_disposition
    }

    #[must_use]
    pub const fn proof_ceiling(&self) -> ProofCeiling {
        self.proof_ceiling
    }

    #[must_use]
    pub fn actual_route(&self) -> &PhysicalRouteObservationReceipt {
        &self.actual_route
    }

    #[must_use]
    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    #[must_use]
    pub const fn proposed_effect_count(&self) -> usize {
        self.proposed_effect_count
    }
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
    #[error("no stored provider execution binding admits this attempt result")]
    MissingExecutionBinding,
    #[error("legacy result wire is rejected without migration: {0:?}")]
    LegacyResultWire(LegacyResultWireKind),
    #[error("serialization failed: {0}")]
    Serialization(String),
}

/// Classifies a persisted or presented result wire that predates the
/// candidate-only contract (issue #370 W24). A legacy wire is rejected with
/// this typed kind at the snapshot ingress; it is never silently migrated
/// into candidate success and never flattened into a generic serialization
/// string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyResultWireKind {
    /// A `VERIFIED_COMPLETE` (or completion-alias) disposition literal.
    VerifiedCompleteDisposition,
    /// A provider-supplied authoritative `effect_receipts` field.
    ProviderEffectReceipts,
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), CoordinatorError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoordinatorError::InvalidField(field));
    }
    Ok(())
}

/// I14.1 closed work-class boundary type (issue #1698). This is the SOLE
/// in-memory representation of the class: exactly the protected `control`
/// partition plus the eight Kernel normal-work classes. The wire carries
/// solely the nine lowercase I14.1 spellings; `Deserialize` converts
/// immediately through [`WorkClass::parse_wire`], so an unknown, blank, or
/// absent-shaped value rejects at decode ingress and `next_ready` plus every
/// queue/projection read can only ever observe validated values (anything
/// else is unrepresentable). There is no second enum, alias, or string
/// bridge for this vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkClass {
    /// Protected control partition: draws only from protected control
    /// capacity owned by the Kernel (`ControlOperationClass` family), never
    /// from the normal partition.
    Control,
    /// Ordinary workload class owned by the Kernel taxonomy.
    Normal(NormalWorkClass),
}

impl WorkClass {
    /// The nine canonical I14.1 wire spellings in scheduler order (control
    /// first, then normal classes in I14.1 document order).
    pub const ALL_WIRE_SPELLINGS: [&'static str; 9] = [
        "control",
        "interactive",
        "verification",
        "canonical_write",
        "normal_background",
        "model_jobs",
        "swarm",
        "reporting",
        "maintenance",
    ];

    /// Returns the exact lowercase I14.1 wire spelling for this class.
    /// Every [`NormalWorkClass`] variant is named explicitly so the mapping
    /// is reviewable against the Kernel source; a Kernel-side addition fails
    /// compilation here, never silently.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Normal(NormalWorkClass::Interactive) => "interactive",
            Self::Normal(NormalWorkClass::Verification) => "verification",
            Self::Normal(NormalWorkClass::CanonicalWrite) => "canonical_write",
            Self::Normal(NormalWorkClass::NormalBackground) => "normal_background",
            // I14.1 spells the model class `model_jobs`; the frozen
            // control-reserve vocabulary spells it `MODEL_JOB`.
            Self::Normal(NormalWorkClass::ModelJob) => "model_jobs",
            Self::Normal(NormalWorkClass::Swarm) => "swarm",
            Self::Normal(NormalWorkClass::Reporting) => "reporting",
            Self::Normal(NormalWorkClass::Maintenance) => "maintenance",
        }
    }

    /// Converts one wire spelling to the boundary type (issue #1698): exactly
    /// the nine canonical spellings. Blank or unknown values reject with the
    /// typed [`CoordinatorError::UnknownWorkClass`]; the caller never
    /// substitutes a less restrictive class. This is the SOLE validated
    /// constructor from the wire `String`.
    pub fn parse_wire(value: &str) -> Result<Self, CoordinatorError> {
        match value {
            "control" => Ok(Self::Control),
            "interactive" => Ok(Self::Normal(NormalWorkClass::Interactive)),
            "verification" => Ok(Self::Normal(NormalWorkClass::Verification)),
            "canonical_write" => Ok(Self::Normal(NormalWorkClass::CanonicalWrite)),
            "normal_background" => Ok(Self::Normal(NormalWorkClass::NormalBackground)),
            "model_jobs" => Ok(Self::Normal(NormalWorkClass::ModelJob)),
            "swarm" => Ok(Self::Normal(NormalWorkClass::Swarm)),
            "reporting" => Ok(Self::Normal(NormalWorkClass::Reporting)),
            "maintenance" => Ok(Self::Normal(NormalWorkClass::Maintenance)),
            _ => Err(CoordinatorError::UnknownWorkClass(value.to_owned())),
        }
    }

    /// The nine I14.1 classes in scheduler rank order. This is the closed
    /// denominator every per-class profile set, per-class report and weight
    /// table is indexed by, so a class can never be added, dropped or
    /// reordered without a compile-time change here.
    pub const ALL: [Self; 9] = [
        Self::Control,
        Self::Normal(NormalWorkClass::Interactive),
        Self::Normal(NormalWorkClass::Verification),
        Self::Normal(NormalWorkClass::CanonicalWrite),
        Self::Normal(NormalWorkClass::NormalBackground),
        Self::Normal(NormalWorkClass::ModelJob),
        Self::Normal(NormalWorkClass::Swarm),
        Self::Normal(NormalWorkClass::Reporting),
        Self::Normal(NormalWorkClass::Maintenance),
    ];

    /// Whether the I14.2 table binds a byte cap to this class. Only canonical
    /// writes carry one (`2048 + byte cap`); every other class may still
    /// declare a byte cap, but canonical writes may not omit it.
    pub const fn requires_byte_cap(self) -> bool {
        matches!(self, Self::Normal(NormalWorkClass::CanonicalWrite))
    }

    /// Deterministic scheduler rank (issue #1698): protected `control` first
    /// (the reserve exists so control is never crowded out by normal work),
    /// then the eight normal classes in I14.1 document order. There is no
    /// invalid arm: invalid values are unrepresentable in this type.
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Normal(NormalWorkClass::Interactive) => 1,
            Self::Normal(NormalWorkClass::Verification) => 2,
            Self::Normal(NormalWorkClass::CanonicalWrite) => 3,
            Self::Normal(NormalWorkClass::NormalBackground) => 4,
            Self::Normal(NormalWorkClass::ModelJob) => 5,
            Self::Normal(NormalWorkClass::Swarm) => 6,
            Self::Normal(NormalWorkClass::Reporting) => 7,
            Self::Normal(NormalWorkClass::Maintenance) => 8,
        }
    }
}

impl std::str::FromStr for WorkClass {
    type Err = CoordinatorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_wire(value)
    }
}

impl TryFrom<String> for WorkClass {
    type Error = CoordinatorError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse_wire(&value)
    }
}

impl TryFrom<&str> for WorkClass {
    type Error = CoordinatorError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse_wire(value)
    }
}

impl Serialize for WorkClass {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire_str())
    }
}

impl<'de> Deserialize<'de> for WorkClass {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse_wire(&value).map_err(serde::de::Error::custom)
    }
}

// -------------------------------------------------------------------------
// Issue #1683: I14.2/I14.8 per-class scheduling policy and the pull outcome.
//
// The nine I14.1 classes, their closed `WorkClass` boundary type and the
// existing `WorkClass::rank` order are reused unchanged. Nothing here adds a
// second class vocabulary, a second capacity owner, a scheduler service, a
// process launcher, a task store or a poll loop: this is policy input plus the
// deterministic outcome projection of one pull.
// -------------------------------------------------------------------------

/// Normalization unit of the weighted fair pull (issue #1683 W2).
///
/// It is a pure scaling constant that turns integer profile weights into
/// integer virtual times. It is not a capacity, a limit, a credit budget or a
/// timeout. The credit of a class that participates in one pull is a virtual
/// time difference and is at most this value, so scheduler credit state cannot
/// grow without bound.
pub const FAIRNESS_QUANTUM: u64 = 1_000_000;

/// Name of the frozen selection algorithm recorded in every pull outcome,
/// including the frozen within-class age rule it implements.
///
/// The age rule is `oldest-canonical-enqueue-first` and its clock domain is the
/// durable canonical enqueue ordinal assigned when an attempt is admitted or
/// reassigned, not a wall clock: replaying the event log re-derives the same
/// ordinal, so neither a projection rebuild nor a coordinator restart can renew
/// an item's age, and no caller-supplied clock participates in the decision.
/// The ordinal is unique per attempt, so the within-class order is total and
/// no further tie-break exists.
pub const FAIR_PULL_ALGORITHM: &str =
    "eliot-agent-coordinator/smooth-weighted-fair-pull-v1/oldest-canonical-enqueue-first";

/// I14.8 WIP partition dimension, restricted to the dimensions a stored
/// `AttemptRecord` can actually derive.
///
/// I14.8 names per-principal, per-module, per-swarm, per-route and
/// per-auth-profile WIP limits. The attempt projection carries a route, a task
/// and the executing worker, so only those three dimensions are representable.
/// Principal, module, swarm and auth-profile partitions stay BLOCKED-BY until an
/// admitted attempt carries those exact identities; declaring them here would be
/// a partition over a value this projection does not have.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WipPartitionKey {
    /// `RouteFingerprint` of the attempt, compared through the same canonical
    /// key the route-capacity check uses.
    Route,
    /// `TaskId` of the attempt.
    Task,
    /// `WorkerId` executing the attempt.
    Worker,
}

/// One I14.8 WIP partition limit inside a class profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WipPartitionLimit {
    pub key: WipPartitionKey,
    /// Positive in-flight ceiling for this partition inside this class. Zero
    /// is rejected: it would close the partition permanently.
    pub max_in_flight: usize,
}

/// I14.2/I14.8 profile of exactly one I14.1 work class.
///
/// Limits are counted per class, so a saturated class cannot consume another
/// class's byte, concurrency or WIP partition; the item ceiling bounds that
/// class's own scan window. Every value is positive; a missing or zero value is
/// rejected instead of being read as unlimited.
///
/// Deliberate narrowing of issue #1683 W1, which lists an "age rule" per class:
/// the within-class age rule is **not** per-class policy here. I14.8 fixes
/// "weighted fair polling and age within class" and the issue fixes the
/// within-class order to the oldest eligible canonical enqueue ordinal, so there
/// is exactly one rule. A per-class field able to hold only that one value
/// would be a declaration that steers nothing, so the rule lives in
/// [`FAIR_PULL_ALGORITHM`] and in the ordering itself instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkClassProfile {
    pub work_class: WorkClass,
    /// I14.2 item ceiling for this class.
    pub max_items: usize,
    /// I14.2 byte cap. Required for canonical writes; optional elsewhere.
    pub max_bytes: Option<u64>,
    /// I14.2 concurrency ceiling for this class.
    pub max_concurrency: usize,
    /// I14.1 deadline ceiling for this class. An admitted item whose own
    /// `wall_time_ms` budget exceeds it is not serviceable by this class.
    pub deadline_ms: u64,
    /// I14.8 weight of this class in the weighted fair pull.
    pub weight: u32,
    pub wip_partitions: Vec<WipPartitionLimit>,
}

impl WorkClassProfile {
    pub fn validate(&self) -> Result<(), CoordinatorError> {
        if self.max_items == 0 {
            return Err(CoordinatorError::InvalidField("max_items"));
        }
        if self.max_concurrency == 0 {
            return Err(CoordinatorError::InvalidField("max_concurrency"));
        }
        if self.deadline_ms == 0 {
            return Err(CoordinatorError::InvalidField("deadline_ms"));
        }
        if self.weight == 0 || u64::from(self.weight) > FAIRNESS_QUANTUM {
            return Err(CoordinatorError::InvalidField("weight"));
        }
        if self.max_bytes == Some(0) {
            return Err(CoordinatorError::InvalidField("max_bytes"));
        }
        if self.work_class.requires_byte_cap() && self.max_bytes.is_none() {
            return Err(CoordinatorError::InvalidField("max_bytes"));
        }
        if self.wip_partitions.is_empty() {
            return Err(CoordinatorError::InvalidField("wip_partitions"));
        }
        let mut keys = BTreeSet::new();
        for partition in &self.wip_partitions {
            if partition.max_in_flight == 0 {
                return Err(CoordinatorError::InvalidField("wip_max_in_flight"));
            }
            if !keys.insert(partition.key) {
                return Err(CoordinatorError::DuplicateIdentity("wip_partition_key"));
            }
        }
        Ok(())
    }
}

/// The I14.2 values the fragment does not fix, supplied by the policy owner.
///
/// I14.2 fixes no concurrency, deadline, byte, weight or WIP value for any
/// class, and fixes no item ceiling at all for `control`, `model_jobs`,
/// `swarm` and `maintenance`; those stay required inputs here instead of being
/// invented by this crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBoundClassLimits {
    pub work_class: WorkClass,
    /// Required (`Some`) for the four classes I14.2 leaves to policy and
    /// rejected (`None`) for the five classes whose item ceiling I14.2 fixes.
    pub max_items: Option<usize>,
    /// Required for `canonical_write`, optional for every other class.
    pub max_bytes: Option<u64>,
    pub max_concurrency: usize,
    pub deadline_ms: u64,
    pub weight: u32,
    pub wip_partitions: Vec<WipPartitionLimit>,
}

/// Versioned per-class scheduling policy: exactly one [`WorkClassProfile`] for
/// each of the nine I14.1 classes.
///
/// The age rule is deliberately not a field of this set. It is fixed by the
/// governing fragment and the issue to the oldest canonical enqueue ordinal and
/// is recorded once in [`FAIR_PULL_ALGORITHM`], which every pull outcome
/// publishes; see [`WorkClassProfile`] for the narrowing note.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulingProfile {
    /// Caller-owned version of this policy set. It is recorded in every pull
    /// outcome so a decision can be attributed to the exact profile revision.
    pub profile_revision: String,
    pub classes: Vec<WorkClassProfile>,
}

impl SchedulingProfile {
    /// I14.2 initial item ceilings, verbatim: interactive 512, verification
    /// 512, canonical writes 2048, background 1024, reports 128. `None` marks
    /// the classes whose ceiling I14.2 leaves to policy.
    fn fixed_items(work_class: WorkClass) -> Option<usize> {
        match work_class {
            WorkClass::Normal(NormalWorkClass::Interactive | NormalWorkClass::Verification) => {
                Some(512)
            }
            WorkClass::Normal(NormalWorkClass::CanonicalWrite) => Some(2048),
            WorkClass::Normal(NormalWorkClass::NormalBackground) => Some(1024),
            WorkClass::Normal(NormalWorkClass::Reporting) => Some(128),
            // I14.2 names no item ceiling for these four; they stay policy-bound
            // and are required from the caller. Every I14.1 class is listed, so
            // a Kernel-side addition fails to compile here instead of silently
            // inheriting a ceiling.
            WorkClass::Control
            | WorkClass::Normal(
                NormalWorkClass::ModelJob | NormalWorkClass::Swarm | NormalWorkClass::Maintenance,
            ) => None,
        }
    }

    /// Builds the I14.2 initial profile: the fixed item ceilings above plus a
    /// required canonical-write byte cap, with every remaining value taken from
    /// `policy`.
    ///
    /// This is not a second configuration source. It reads no file, no
    /// environment variable and no working directory; the Kernel runtime
    /// profile loader that produces these values is a separate owner
    /// (#1679 item 2, #1687) and is not wired here.
    pub fn i14_2_initial(
        profile_revision: impl Into<String>,
        policy: &[PolicyBoundClassLimits],
    ) -> Result<Self, CoordinatorError> {
        let mut classes = Vec::with_capacity(WorkClass::ALL.len());
        for work_class in WorkClass::ALL {
            let mut supplied = policy.iter().filter(|entry| entry.work_class == work_class);
            let entry = supplied
                .next()
                .ok_or(CoordinatorError::IdentityConflict("work_class_profile"))?;
            if supplied.next().is_some() {
                return Err(CoordinatorError::DuplicateIdentity("work_class_profile"));
            }
            let max_items = match Self::fixed_items(work_class) {
                Some(fixed) => {
                    if entry.max_items.is_some() {
                        return Err(CoordinatorError::IdentityConflict("max_items"));
                    }
                    fixed
                }
                None => entry
                    .max_items
                    .ok_or(CoordinatorError::InvalidField("max_items"))?,
            };
            let max_bytes = if work_class.requires_byte_cap() {
                Some(
                    entry
                        .max_bytes
                        .ok_or(CoordinatorError::InvalidField("max_bytes"))?,
                )
            } else {
                entry.max_bytes
            };
            classes.push(WorkClassProfile {
                work_class,
                max_items,
                max_bytes,
                max_concurrency: entry.max_concurrency,
                deadline_ms: entry.deadline_ms,
                weight: entry.weight,
                wip_partitions: entry.wip_partitions.clone(),
            });
        }
        let profile = Self {
            profile_revision: profile_revision.into(),
            classes,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), CoordinatorError> {
        validate_text(&self.profile_revision, "profile_revision")?;
        if self.classes.len() != WorkClass::ALL.len() {
            return Err(CoordinatorError::InvalidField("classes"));
        }
        for work_class in WorkClass::ALL {
            let mut matching = self
                .classes
                .iter()
                .filter(|profile| profile.work_class == work_class);
            let profile = matching
                .next()
                .ok_or(CoordinatorError::IdentityConflict("work_class_profile"))?;
            if matching.next().is_some() {
                return Err(CoordinatorError::DuplicateIdentity("work_class_profile"));
            }
            profile.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn class_profile(&self, work_class: WorkClass) -> Option<&WorkClassProfile> {
        self.classes
            .iter()
            .find(|profile| profile.work_class == work_class)
    }
}

/// Why one ready item was passed over inside its class during a pull.
///
/// A passed-over item is retained: it stays admitted and keeps its canonical
/// enqueue ordinal, so skipping it never re-queues or re-ages it.
///
/// One writer per deliverable is not a member of this set: it is enforced once
/// at the owning transition (`plan`, `admit`, `reassign`) on the Work/Action
/// lease identity and cannot be violated from the selection side, so no
/// unreachable reason is published here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadyItemSkipReason {
    /// The item's own `wall_time_ms` budget exceeds the class deadline
    /// ceiling. This is not a temporary condition, so no service is promised
    /// for it by this selector; the item is reported as infeasible instead.
    ClassDeadlineCeiling,
    /// One more item's `output_bytes` budget would cross the class byte cap.
    ClassByteCapReached,
    /// A declared WIP partition of this class already holds
    /// `max_in_flight` started items with the same partition value.
    WipPartitionAtLimit,
}

/// Why one class offered no work to a pull.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClassSkipReason {
    /// The class already holds `max_concurrency` in-flight items.
    ClassConcurrencyAtLimit,
    /// Every admitted item inside the scan window was passed over.
    AllReadyItemsSkipped,
}

/// The per-class capacity dimension that closed admission for one class.
///
/// The I14.2 item ceiling is deliberately absent: it bounds the per-class scan
/// window and belongs to admission, not to a pull, so this selector never
/// reports it as the limiting dimension of a refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityLimitDimension {
    ClassConcurrency,
    ClassBytes,
    WipPartition,
}

/// The live capacity view a deferral is reset by: a new identity or revision is
/// what re-opens a closed class, so the refusal names the exact source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityResetSource {
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
}

/// Exact capacity disposition of one class for one pull (issue #1683 W7).
///
/// This is the selector's own read-only projection of the measurement it just
/// made: the limiting per-class dimension, the exact observed value and the
/// exact limit, and the live capacity view a new revision of which re-opens the
/// dimension. It mints no recovery directive. The accepted #1679 directive
/// fields that describe the *admission* consequence — cause, accepted/staged
/// outcome, poll-versus-retry action, earliest condition and safe alternative —
/// stay with that owner and are not restated here: a pull declines to start one
/// item, which is not a durable `DEFERRED_CAPACITY` admission transition, and
/// restating the directive vocabulary locally would create a second authority
/// for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityDeferral {
    pub work_class: WorkClass,
    /// The exact per-class dimension that closed admission.
    pub limiting_dimension: CapacityLimitDimension,
    /// Observed value of that dimension for this class right now.
    pub dimension_value: u64,
    /// The profile limit that was reached.
    pub dimension_limit: u64,
    pub reset_source: CapacityResetSource,
}

impl CapacityDeferral {
    pub(crate) fn new(
        work_class: WorkClass,
        limiting_dimension: CapacityLimitDimension,
        dimension_value: u64,
        dimension_limit: u64,
        reset_source: &CapacityResetSource,
    ) -> Self {
        Self {
            work_class,
            limiting_dimension,
            dimension_value,
            dimension_limit,
            reset_source: reset_source.clone(),
        }
    }
}

/// Per-class result of one pull, in scheduler rank order.
///
/// Every ceiling is `None` on the profile-free peek path, which applies no
/// per-class limit at all; that absence is published rather than presented as
/// an unlimited default.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkClassSelectionReport {
    pub work_class: WorkClass,
    /// Admitted items of this class.
    pub ready_items: usize,
    /// Non-terminal items of this class that have started (`Running` or
    /// `CancellationRequested`): the set that holds a concurrency slot.
    pub in_flight_items: usize,
    /// Sum of the `output_bytes` budgets of this class's in-flight items.
    pub in_flight_bytes: u64,
    pub item_ceiling: Option<u64>,
    pub concurrency_ceiling: Option<u64>,
    pub byte_ceiling: Option<u64>,
    /// Admitted items actually examined. The scan is bounded by the item
    /// ceiling (or by the whole class on the profile-free path) and walks the
    /// items in ascending canonical enqueue ordinal, so a truncated window can
    /// only leave later items unserved, never displace an older one.
    pub scanned_ready_items: usize,
    /// Canonical enqueue ordinal of the oldest admitted item, if any, under the
    /// frozen age rule named in [`FAIR_PULL_ALGORITHM`]. This is the age of the
    /// oldest ready work in this class's clock domain: the durable enqueue
    /// ordinal, unique per attempt and not wall-clock milliseconds.
    pub oldest_ready_enqueue_sequence: Option<u64>,
    /// The item this class offered, if any.
    pub offered_attempt_id: Option<AttemptId>,
    /// Credit the class carried into this pull. `None` when the class did not
    /// participate, in which case the pull did not schedule it at all.
    pub scheduled_credit: Option<u64>,
    pub class_skip_reason: Option<ClassSkipReason>,
    /// Admitted items passed over inside this class, retained and not re-queued.
    pub skipped_ready_items: usize,
    /// Passed-over items that are not temporarily closed and therefore get no
    /// service promise from this selector.
    pub infeasible_items: usize,
}

/// Published claim state of one deliverable (mutation scope) that currently
/// holds admitted work.
///
/// This is published state for the caller, not a gate: the one-writer property
/// is enforced at the owning transition (`plan`, `admit`, `reassign`) on the
/// Work/Action lease identity, so a second concurrent holder of one scope is
/// rejected there and `ready_items` above one is unreachable. What this
/// publishes is the identity and state of the current holder.
///
/// `writer_holders` is rebuilt by replaying this coordinator's own admissions,
/// so the exclusion it reflects holds only within one snapshot lineage; it is
/// not a canonical one-writer authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverableClaim {
    pub mutation_scope: String,
    pub holder_attempt_id: Option<AttemptId>,
    pub holder_state: Option<CoordinatedAttemptState>,
    /// Admitted items declaring this scope, including the holder. Always one
    /// today, because the owning transition rejects a second holder.
    pub ready_items: usize,
}

/// Exact outcome of one fair pull (issue #1683 W7).
///
/// Diagnostics only: nothing here is an authority, and no field re-decides
/// admission, ordering or capacity. It derives `Serialize` only because it is a
/// published projection, never an input wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReadySelectionOutcome {
    /// Always [`FAIR_PULL_ALGORITHM`], which also names the frozen within-class
    /// age rule and its clock domain.
    pub algorithm: &'static str,
    /// Profile revision the per-class partitions were taken from, or `None` on
    /// the profile-free [`AgentCoordinator::next_ready`](crate::AgentCoordinator::next_ready)
    /// path, which applies no per-class I14.2 partition at all.
    pub profile_revision: Option<String>,
    pub capacity_identity: String,
    pub capacity_revision: RevisionId,
    pub selected_attempt_id: Option<AttemptId>,
    pub selected_work_class: Option<WorkClass>,
    /// Canonical enqueue ordinal of the selected item, under the age rule named
    /// in `algorithm`. The ordinal is unique per attempt, so in that clock
    /// domain it is the item's exact age rather than an approximation of one.
    /// It is not a wall-clock duration.
    pub selected_enqueue_sequence: Option<u64>,
    /// Canonical enqueue ordinal of the oldest admitted item overall, under the
    /// same age rule.
    pub oldest_ready_enqueue_sequence: Option<u64>,
    /// Exactly nine entries in scheduler rank order.
    pub classes: Vec<WorkClassSelectionReport>,
    pub deliverable_claims: Vec<DeliverableClaim>,
    /// One entry per class that held ready work and was closed, in scheduler
    /// rank order. Empty when a class offered work.
    pub deferrals: Vec<CapacityDeferral>,
}
