use eliot_agent_api::{
    AdmittedRouteReceipt, AgentLaunchRequest, AgentResult, AttemptId, BudgetEnvelope, CancelReason,
    EffectCeiling, EpochId, EventId, HostEventNormalizationReceipt, HostEventQuarantineReason,
    LaunchRequestId, NormalizedHostEventEnvelope, PhysicalRouteObservationReceipt,
    ProviderExecutionBinding, ResultDisposition, RouteFingerprint, RouteSelectionCandidate,
    StateFence, TaskId, WorkLeaseId, WorkUnitId,
};
use eliot_agent_contracts::{
    DescendantClosureReceipt, LivePeerMessage, LivePeerMessageState, MessageId,
    ParentFinishCeiling, PublicReference, RevisionId,
};
use eliot_contracts::{ContractIdentity, LowercaseSha256};
use eliot_evaluation_contracts::BudgetEvidence;
use eliot_kernel_core::{CapacityClass, NormalWorkClass};
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

/// Closed learning responsibility from I10.15. The role name is semantic and
/// independent from any provider, model, or route identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningRole {
    Actor,
    Refiner,
    Evaluator,
    PromotionOwner,
    NotApplicable,
}

/// Role profile contract. `manifest_revision` is its opaque version;
/// `schema_identity` and `content_digest` are separate declared identities.
/// The digest type checks its lowercase SHA-256 shape, but this inline
/// candidate has no source bytes from which to recompute or approve it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleProfileManifest {
    pub role_id: RoleProfileId,
    pub manifest_revision: RevisionId,
    pub schema_identity: ContractIdentity,
    pub content_digest: LowercaseSha256,
    pub required_competence: Vec<String>,
    pub allowed_operations: Vec<PublicReference>,
    pub allowed_effects: EffectCeiling,
    pub independence_requirement: PublicReference,
    pub input_schemas: Vec<PublicReference>,
    pub output_schemas: Vec<PublicReference>,
    pub visibility_policy: PublicReference,
    pub learning_role: LearningRole,
    pub stop_condition: PublicReference,
    pub escalation_policy: PublicReference,
    pub allowed_route_classes: Vec<String>,
    pub mutation_capable: bool,
}

/// Recipe manifest contract. The revision is opaque and separate from the
/// schema identity and content digest. The digest is shape-checked only; it
/// is not recomputed from source bytes or treated as owner approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeManifest {
    pub recipe_id: RecipeId,
    pub manifest_revision: RevisionId,
    pub schema_identity: ContractIdentity,
    pub content_digest: LowercaseSha256,
    pub route_policy_revision: RevisionId,
    pub max_lanes: usize,
    pub max_descendants: u32,
    pub stage_templates: Vec<PublicReference>,
    pub work_item_templates: Vec<PublicReference>,
    pub dependency_templates: Vec<PublicReference>,
    pub merge_templates: Vec<PublicReference>,
    pub eligible_route_classes: Vec<String>,
    pub expansion_conditions: Vec<PublicReference>,
    pub contraction_conditions: Vec<PublicReference>,
    pub verifier_requirements: Vec<PublicReference>,
    pub audit_requirements: Vec<PublicReference>,
    pub budget: BudgetEnvelope,
    pub partial_result_behavior: PublicReference,
    pub failure_behavior: PublicReference,
    /// The profiles in this list are the role set eligible for the recipe.
    pub role_profiles: Vec<RoleProfileManifest>,
}

/// Human-selected staffing policy, carried unchanged with the frozen plan
/// request. The budget is cost intent; lane budgets remain the task's ask and
/// are checked against this ceiling by the daemon staffing policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanStaffingIntent {
    pub preset: StaffingPreset,
    pub per_job_budget: BudgetEnvelope,
}

/// I3.6 Human-selectable staffing decision presets. These select route and
/// independence policy, never a provider allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StaffingPreset {
    Economy,
    Balanced,
    Assurance,
    Research,
    Incident,
}

impl StaffingPreset {
    /// Canonical wire spelling.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Economy => "economy",
            Self::Balanced => "balanced",
            Self::Assurance => "assurance",
            Self::Research => "research",
            Self::Incident => "incident",
        }
    }
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
    /// Owner-reported capability classes for this exact route. These are
    /// intersected with recipe, role, and launch declarations by staffing.
    pub route_classes: Vec<String>,
    pub route_class_evidence_refs: Vec<String>,
    /// The route's owner-supplied I3.4 data classes. This is route-local
    /// evidence, distinct from the task's requested privacy class.
    pub privacy_classes: Vec<PrivacyClass>,
    pub privacy_evidence_refs: Vec<String>,
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
    /// Explicit Task-Controller/Human policy input. There is no preset default
    /// or recipe-shape inference at the staffing boundary.
    pub human_staffing_intent: HumanStaffingIntent,
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
    /// Owner-issued expiry of this admission, in Unix milliseconds (I6.10
    /// "issued/expires/heartbeat" on the admission that authorizes work; I14.6
    /// `expires_at_and_release_reason` on the matching canonical admission).
    ///
    /// This is the time bound the receipt owner issues with the admission, not
    /// one a consumer invents: a zero value is an unissued bound and is
    /// refused, never treated as "never expires". Spelling and type match the
    /// sibling adapters' owner-issued bounds
    /// (`ModelCatalogueSnapshot::expires_at_unix_ms`,
    /// `BillingEvidence::expires_at_unix_ms`), so every owner-issued bound in
    /// the agent slice is compared the same way.
    ///
    /// The external admission owner populates this field; the coordinator only
    /// stores and validates it. No production issuer exists in this tree yet,
    /// so every construction site is a test fixture — see
    /// `swarm_admission_bind`'s module doc.
    pub expires_at_unix_ms: u64,
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
    /// The swarm admission a call presented is no longer the one that admits
    /// its wave: the old wave's recorded [`eliot_agent_contracts::OldWaveDisposition`]
    /// is `CANCEL` or `SUPERSEDE`, or the definition revision it named has
    /// already left `FROZEN` (issue #1702 A2/A3).
    ///
    /// This is NOT [`Self::StalePlanRevision`], which refuses a caller holding
    /// an old Task Controller draft/frozen *definition* revision — here the
    /// definition is current and the ADMISSION under it is revoked, so the
    /// caller's records are individually correct and only their combination is
    /// no longer admitted. It is NOT [`Self::StaleController`], which refuses a
    /// presenter outside the current coordinator *lease* — an exactly-current
    /// holder still gets this one, because the lease stays valid while the wave
    /// it would advance has been explicitly dispositioned. It is NOT
    /// [`Self::StaleFence`], which refuses a stale attempt state fence at this
    /// crate's own attempt boundary. The distinction matters because the remedy
    /// differs: a stale admission requires a NEW admission for the replacement
    /// definition, which no amount of re-presentation, re-lease or re-fencing
    /// can substitute for.
    ///
    /// Like the other stale variants this is a pure refusal against the
    /// caller's own records: it changes no definition, admission, execution
    /// revision, lease or wave.
    #[error("stale swarm admission")]
    StaleAdmission,
    #[error("stale result")]
    StaleResult,
    #[error("route receipt does not match the admitted route")]
    RouteMismatch,
    #[error("unknown work class: {0}")]
    UnknownWorkClass(String),
    #[error("route evidence is missing or stale")]
    RouteEvidence,
    /// A budget is wider than the budget that admits it (issue #1683 A8).
    ///
    /// `field` names the exact dimension the comparison refused. It is carried
    /// through from the comparing owner's own `ChildBudgetExceeded { field }`
    /// rather than re-derived here, because `eliot_agent_api` owns the
    /// `BudgetEnvelope` dimension vocabulary: this names the dimension the
    /// owner compared instead of leaving a caller to infer it. A caller reading
    /// this variant therefore learns which *envelope* field was too wide — and
    /// nothing beyond that. In particular it does not also report
    /// `eliot_swarm`'s independent per-dimension account, which is a different
    /// budget over different values and names its own dimension in its own
    /// refusal; see the `swarm_error` mapping in
    /// `swarm_definition_admission.rs`.
    ///
    /// This refusal changes no task: it is produced by a pure comparison over
    /// the caller's own envelopes and returns before any attempt, priority,
    /// deadline or class is written.
    #[error("budget is wider than the admitted budget at {field}")]
    BudgetExceeded { field: &'static str },
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
    /// The Kernel runtime configuration surface refused its input. Used only
    /// by the `runtime_profile` loader (#1687 W2); it exists because the
    /// existing field-level variants cannot express a file that is absent,
    /// unreadable or not a valid runtime profile document, and a second error
    /// enum for the same crate boundary would be a second authority.
    #[error(transparent)]
    RuntimeProfileRejected(#[from] crate::runtime_profile::RuntimeProfileRejection),
    /// A coordinator execution update or retained-work record would change
    /// frozen swarm semantics (issue #1702 A2/A6).
    ///
    /// `field` names the exact contract owner field the comparison refused. It
    /// is carried through from
    /// [`eliot_agent_contracts::ContractError::SemanticDrift`] rather than
    /// re-derived here, because the frozen definition/admission/execution
    /// vocabulary is owned by that contract, not by this crate. A caller
    /// reading this variant therefore learns WHICH frozen field was changed and
    /// nothing beyond that.
    ///
    /// This is a narrowing refusal: it changes no revision, no lease and no
    /// wave, and it is produced by a pure comparison over the caller's own
    /// records before any replacement, rebind or state advance is written.
    #[error("execution update or retained record changes frozen swarm semantics for {0}")]
    SemanticDrift(&'static str),
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

    /// The Kernel capacity partition this class is structurally able to draw
    /// from (issue #1683 W4).
    ///
    /// I14.3 states "Normal workload cannot consume it", and the Kernel already
    /// enforces that as a physical partition in
    /// `eliot_kernel_core::ControlReserve` (`try_acquire_normal` and
    /// `try_acquire_protected` increment disjoint counters). What was missing
    /// was the *selection-side* half: the fair pull ranked the nine classes by
    /// weight alone, so a `control` item was merely a weighted competitor in the
    /// same rotation as `normal_background`, and nothing stopped saturated bulk
    /// work from occupying the pulls a control item needed. `WorkClass::Control`
    /// claimed the protected partition in its own doc comment but no code read
    /// that claim.
    ///
    /// This method is the one place that claim becomes checkable. It reuses the
    /// existing `eliot_kernel_core::CapacityClass` (re-exported from
    /// `eliot_runtime_contracts`, the frozen vocabulary the front door already
    /// switches on) rather than introducing a coordinator-local partition type,
    /// so there is exactly one capacity vocabulary in the tree.
    ///
    /// The mapping is total and has no invalid arm: `Control` names the
    /// protected partition and every `Normal` class names the normal partition,
    /// so a class can never be admitted by a path that lets it draw from the
    /// other one.
    ///
    /// Which exhaustiveness is load-bearing, precisely: the **outer** `match` on
    /// `WorkClass` is the compile-time gate, and it must stay a no-wildcard
    /// match. A new work class is a new partition decision, so a new
    /// `WorkClass` variant has to fail to compile here until someone says which
    /// partition it draws from. The `Self::Normal(_)` arm is the second variant
    /// of that same gate, not a wildcard on the type: because `WorkClass` has
    /// exactly two top-level shapes today, naming the second one exhaustively
    /// over the outer enum is what makes the match total. The *inner*
    /// `NormalWorkClass` taxonomy is deliberately not enumerated, because there
    /// is no per-variant decision here to fail on — a new `NormalWorkClass`
    /// inherits `NormalWorkload`, which is the correct answer for anything named
    /// `Normal`, so enumerating the eight would guard nothing and only invite
    /// eight identical arms to drift. Should a future variant need a partition
    /// other than `NormalWorkload`, the type must gain a third `WorkClass` shape
    /// for it, and the outer match here will not compile until that shape is
    /// given a partition explicitly.
    #[must_use]
    pub const fn capacity_class(self) -> CapacityClass {
        match self {
            Self::Control => CapacityClass::ProtectedControl,
            Self::Normal(_) => CapacityClass::NormalWorkload,
        }
    }

    /// Returns whether this class draws only the protected control partition.
    ///
    /// A member of the protected partition is a reservation, not a preference:
    /// I14.8 requires "strong reviewer/arbitration reserve protected from bulk
    /// workers", and I14.3 requires that normal workload cannot consume it. A
    /// protected class therefore takes no part in the weighted rotation and
    /// cannot be crowded out by it; see
    /// [`crate::AgentCoordinator::pull_next`].
    #[must_use]
    pub const fn is_protected_partition(self) -> bool {
        matches!(self.capacity_class(), CapacityClass::ProtectedControl)
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
/// timeout.
///
/// What it does bound is the *credit* a class carries into a pull: a class's
/// virtual time is at most its stride `FAIRNESS_QUANTUM / weight` above the
/// winner's, and every weight is at least 1, so a credit lies in
/// `0..=FAIRNESS_QUANTUM]`. The bound is tight, and a sweep of 32x32 weight
/// pairs over 5000 pulls observed exactly this value and never more. It does
/// **not** bound the stored virtual times themselves: one of them advances by a
/// stride on every pull, so those grow until they saturate at `u64::MAX` after
/// roughly `u64::MAX / FAIRNESS_QUANTUM` pulls, after which the rotation
/// degrades to class-index tie-breaks.
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
///
/// # Production readers
///
/// This constant is read on the coordinator's real selection path, and the
/// readers are named here in `path.rs::symbol` form because a file path is not a
/// checkable citation. Measured with `git grep` over `origin/main`: exactly two
/// non-doc reads exist, both of which assign the value into a published pull
/// outcome rather than merely mentioning it.
///
/// - `core.rs::AgentCoordinator::drive_fair_pull` — writes
///   `FairPullOutcome::algorithm` for the drive that publishes
///   [`crate::FairPullOutcome::started`] and `last_selection`. It is reached from
///   production by `agent_fabric.rs::AgentFabric::drive_fair_pull`, which is
///   itself called from `solo_agent_driver.rs::drive_fair_pull_after_release` and
///   `solo_agent_driver.rs::solo_fair_pull_recovery`, the latter driven every tick
///   by `daemon_runtime.rs::maybe_start_fair_pull_recovery`.
/// - `core.rs::AgentCoordinator::select_ready` — writes
///   `ReadySelectionOutcome::algorithm` for every single pull, including the
///   ones the drive makes. In production it is reached only from that drive; the
///   two single-shot wrappers `core.rs::AgentCoordinator::pull_next` and
///   `core.rs::AgentCoordinator::next_ready` also call it, but neither wrapper
///   has a production caller, so they are not counted as production readers of
///   this constant. See the note on `core.rs::pull_next` for that measurement.
///
/// The constant is therefore live, not decorative: removing either reader would
/// leave a published outcome unable to name the rule its own ordering
/// implements. It is a `pub` item, so a reader outside this crate may also name
/// it in a receipt; that is a naming affordance and is deliberately not counted
/// as the caller, because an external naming of the constant proves nothing
/// about whether the coordinator's own selection path runs.
pub const FAIR_PULL_ALGORITHM: &str =
    "eliot-agent-coordinator/smooth-weighted-fair-pull-v1/oldest-canonical-enqueue-first";

/// I14.8 WIP partition dimension, restricted to the dimensions a stored
/// `AttemptRecord` can actually derive.
///
/// I14.8 names per-principal, per-module, per-swarm, per-route and
/// per-auth-profile WIP limits. Of those, this projection can derive route,
/// task, worker and scope. It **cannot** derive principal, module or swarm:
/// `AttemptRecord` has no principal identity, no module identity and no swarm
/// or plan identity, and a partition over a value the record does not carry
/// would be a partition over nothing. Those three stay BLOCKED-BY until an
/// admitted attempt carries those exact identities.
///
/// Auth-profile is also not represented, and the reason is narrower than
/// "missing field": the record carries `role_id`/`role_revision`, which identify
/// a *role manifest*, not an authentication profile. Naming that dimension
/// `AuthProfile` would be a claim the value cannot support. If the projection
/// owner adds a real auth-profile identity to the admitted attempt, the variant
/// belongs here; adding it is that owner's change, not this crate's.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WipPartitionKey {
    /// `RouteFingerprint` of the attempt, compared through the same canonical
    /// key the route-capacity check uses.
    Route,
    /// The attempt's `mutation_scope`, the deliverable scope. This is the
    /// closest available analogue of I5.7's `scope:<scope_id>` ordering scope;
    /// the coordinator holds no typed `OrderingScope`.
    Scope,
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
    /// Byte cap for this class. I14.1 requires a bounded byte profile for *every*
    /// class, and I14.2 states a number only for canonical writes, so this is a
    /// required policy input for all nine classes: [`WorkClassProfile::validate`]
    /// rejects zero, and no class is byte-unbounded. This crate does not supply a
    /// number for the eight classes I14.2 leaves open, because inventing one would
    /// be an invented limit.
    pub max_bytes: u64,
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
        if self.max_bytes == 0 {
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
/// class, and fixes no item ceiling at all for `control`, `model_jobs`, `swarm`
/// and `maintenance`; those stay required inputs here instead of being invented
/// by this crate. I14.1 nevertheless requires a bounded byte profile for every
/// class, so `max_bytes` is a required input for all nine and no class may be
/// constructed without one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBoundClassLimits {
    pub work_class: WorkClass,
    /// The item ceiling for this class. `None` means "use the I14.2 documented
    /// initial default" and is accepted only for the five classes that have
    /// one; it is required for `control`, `model_jobs`, `swarm` and
    /// `maintenance`. A `Some` value always wins, because I14.2 states its
    /// numbers are defaults in `runtime.toml` and not Architecture.
    pub max_items: Option<usize>,
    /// Byte ceiling for this class. Required and positive for all nine classes.
    pub max_bytes: u64,
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

    /// Builds the I14.2 initial profile: the documented initial item ceilings
    /// above, overridable by policy, with every remaining value — including the
    /// byte ceiling of all nine classes — taken from `policy`.
    ///
    /// A class whose `max_items` is `None` gets the I14.2 documented default; a
    /// class that supplies one gets that value instead. I14.2 states its numbers
    /// are defaults in `runtime.toml` and not Architecture, so refusing an
    /// override would make this crate's table outrank the fragment.
    ///
    /// A class with no `max_items` default in I14.2 (`control`, `model_jobs`,
    /// `swarm`, `maintenance`) must supply one, and **every** class must supply a
    /// positive `max_bytes`, because I14.1 requires a bounded byte profile for
    /// each of the nine. A missing value is a typed refusal, never a default.
    ///
    /// This is not a second configuration source. It reads no file, no
    /// environment variable and no working directory; the Kernel runtime
    /// profile loader that produces these values is
    /// [`crate::runtime_profile`] (#1679 item 2, #1687), which decodes the
    /// Kernel-owned `runtime.toml` into exactly this `Option` contract. That
    /// loader is not wired into a production composition yet; see its module
    /// documentation for the measured reason.
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
            let max_items = entry
                .max_items
                .or_else(|| Self::fixed_items(work_class))
                .ok_or(CoordinatorError::InvalidField("max_items"))?;
            classes.push(WorkClassProfile {
                work_class,
                max_items,
                max_bytes: entry.max_bytes,
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
/// One writer per deliverable is not a member of this set: it is enforced where
/// the Work/Action lease is taken (`admit` and `reassign`) and cannot be
/// violated from the selection side, so no unreachable reason is published here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadyItemSkipReason {
    /// The item's own `wall_time_ms` budget exceeds the class deadline
    /// ceiling. This is not a temporary condition, so no service is promised
    /// for it by this selector; the item is reported as infeasible instead.
    /// It is also stepped over without consuming the class's bounded scan
    /// window, so it cannot block the eligible items queued behind it; its
    /// disposition belongs to admission.
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
/// reports it as the limiting dimension of a refusal. A deadline-ceiling
/// mismatch is absent for the same reason: it is a property of the item, not a
/// saturated class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityLimitDimension {
    ClassConcurrency,
    ClassBytes,
    /// A declared WIP partition of the class, named so a caller can tell which
    /// partition closed rather than only how full it was.
    WipPartition {
        key: WipPartitionKey,
    },
}

/// Exact capacity disposition of one class for one pull (issue #1683 W7).
///
/// This is the selector's own read-only projection of the measurement it just
/// made: the limiting per-class dimension, the exact observed value, the exact
/// limit, and the scheduling-policy revision the limit came from.
///
/// The reset source is `profile_revision`, deliberately. Every limit this record
/// reports comes from the [`SchedulingProfile`] — `max_concurrency`,
/// `max_bytes`, a WIP partition's `max_in_flight` — so a new profile revision is
/// the only thing that re-opens them. The coordinator's route capacity view
/// (`capacity_identity`/`capacity_revision`) re-opens none of them and is not
/// repeated here; it is published once on the outcome as the live capacity view
/// the whole decision was taken under.
///
/// It mints no recovery directive. The accepted #1679 directive fields that
/// describe the *admission* consequence — cause, accepted/staged outcome,
/// poll-versus-retry action, earliest condition and safe alternative — stay with
/// that owner and are not restated here: a pull declines to start one item,
/// which is not a durable `DEFERRED_CAPACITY` admission transition, and restating
/// the directive vocabulary locally would create a second authority for it.
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
    /// The scheduling-policy revision this refusal is measured against, and the
    /// value whose change re-opens the dimension.
    pub profile_revision: String,
}

impl CapacityDeferral {
    pub(crate) fn new(
        work_class: WorkClass,
        limiting_dimension: CapacityLimitDimension,
        dimension_value: u64,
        dimension_limit: u64,
        profile_revision: &str,
    ) -> Self {
        Self {
            work_class,
            limiting_dimension,
            dimension_value,
            dimension_limit,
            profile_revision: profile_revision.to_owned(),
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
    /// The Kernel capacity partition this class draws from
    /// ([`WorkClass::capacity_class`]), published so a caller can see which
    /// partition a selected item is charged against without re-deriving the
    /// class-to-partition mapping, and so a report of the protected partition
    /// is distinguishable from a report of normal work.
    ///
    /// It is published state, not a second authority: the front door still
    /// decides the partition at acquisition from the same `CapacityClass`
    /// vocabulary. This field exists so the selector's decision is auditable,
    /// not so a caller can bypass the front door.
    pub capacity_partition: CapacityClass,
    /// Admitted items of this class.
    pub ready_items: usize,
    /// Non-terminal items of this class that are not queued: `Running`,
    /// `CancellationRequested` and `UnknownOutcome`. This is the set that holds a
    /// concurrency slot, contributes bytes and occupies a WIP partition.
    /// `UnknownOutcome` is included deliberately — issue #1683 W4 requires that
    /// "unknown old execution keeps exclusion until reconciliation", so an
    /// unreconciled unknown-outcome attempt keeps holding its resources.
    pub in_flight_items: usize,
    /// Sum of the `output_bytes` budgets of this class's in-flight items.
    pub in_flight_bytes: u64,
    pub item_ceiling: Option<u64>,
    pub concurrency_ceiling: Option<u64>,
    pub byte_ceiling: Option<u64>,
    /// Admitted items actually examined, in ascending canonical enqueue order.
    /// The scan walks the per-class admitted list at most once, and the item
    /// ceiling bounds the items a capacity dimension currently closes, so a
    /// truncated window can only leave later items unserved, never displace an
    /// older one. An item over the class deadline ceiling is examined and
    /// reported but does not consume that window, because it is permanently
    /// rather than temporarily ineligible; this count can therefore exceed
    /// `item_ceiling` when a class holds over-ceiling items.
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

/// Published claim state of one deliverable (mutation scope) that currently has
/// a live writer.
///
/// This is published state for the caller, not a gate: the one-writer property
/// is enforced at the owning transitions (`admit` and `reassign`) on the
/// Work/Action lease identity, so a second concurrent holder of one scope is
/// rejected there. `plan` does **not** enforce it — it takes no scope holder
/// decision and admits nothing — so a claim is never a statement about a plan.
/// What this record answers is which attempt holds the deliverable, under which
/// lease, and in what state, which is what tells a caller why the scope is not
/// available. There is deliberately no count of waiting items: a second holder
/// is rejected on admission, so such a count could only ever be one.
///
/// `writer_holders` is rebuilt by replaying this coordinator's own admissions,
/// so the exclusion it reflects holds only within one snapshot lineage; it is
/// not a canonical one-writer authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverableClaim {
    pub mutation_scope: String,
    /// Always present: a claim is only published for a scope that has a holder.
    pub holder_attempt_id: AttemptId,
    /// The holder's own Work/Action lease identity, read from its stored record.
    ///
    /// Issue #1683 W4 requires deliverable ownership to rest on that lease
    /// identity rather than on a raw path string or a process-local holder
    /// alone, so the claim names the lease that owns the deliverable. It is
    /// never synthesized from the scope or recomputed from the attempt; it is
    /// the same value `validate_attempt_binding` and every release site compare
    /// against, so a caller can act on the lease without re-deriving one.
    pub holder_lease_id: WorkLeaseId,
    /// The holder's state. Any non-terminal state appears here — `Admitted`,
    /// `Running`, `CancellationRequested` and `UnknownOutcome` — because a
    /// non-terminal holder keeps the claim, including under an unknown outcome
    /// that has not been reconciled. No terminal state appears: a terminal holder
    /// releases the scope in the same transition that makes it terminal.
    pub holder_state: CoordinatedAttemptState,
}

/// Exact outcome of one fair pull (issue #1683 W7).
///
/// Diagnostics only: nothing here is an authority, and no field re-decides
/// admission, ordering or capacity. It derives `Serialize` only because it is a
/// published projection, never an input wire.
///
/// What this record does **not** carry, stated so a reader does not infer it:
/// I5.7's starvation diagnostics ask for oldest-ready *age*, per-scope *wait* and
/// head retries in a wall-clock unit. This projection has no durable enqueue
/// timestamp — the admission event records no clock — so it publishes the
/// canonical enqueue ordinal, per-class counts and ceilings, and the identity
/// and state of each deliverable's holder. The wait half of W7 is therefore not
/// implemented, and no field here is a substitute for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReadySelectionOutcome {
    /// Always [`FAIR_PULL_ALGORITHM`], which also names the frozen within-class
    /// age rule and its clock domain.
    pub algorithm: &'static str,
    /// Profile revision the per-class limits were taken from, or `None` on the
    /// profile-free [`AgentCoordinator::next_ready`](crate::AgentCoordinator::next_ready)
    /// path, which applies no per-class limit at all.
    pub profile_revision: Option<String>,
    /// The live route capacity view this decision was taken under. The
    /// coordinator refuses to run when its configured view and the admitted
    /// provider's view disagree, so this is the view in force. It re-opens
    /// nothing in this record: every per-class limit comes from
    /// `profile_revision`, which is why each [`CapacityDeferral`] names the
    /// profile revision instead.
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
