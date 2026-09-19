//! A-07 bounded swarm coordination core.
//!
//! The cell is deliberately stateless. It validates immutable proposals and
//! provider-issued receipts, but owns no process, route, task, authority, or
//! persistence state. Provider and checkpoint availability are injected.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{AgentAttempt as LaunchAttempt, EffectKind, WorkLeaseId};
use eliot_agent_contracts::{
    AgentAttempt, AgentAttemptId, CoordinationEntry, CoordinationMapView, RevisionId, RouteId,
    WorkItem, WorkItemId, WorkItemState,
};
use eliot_evidence::EvidenceEnvelope;
use eliot_receipts::{EffectClass, ProofCeiling, ReceiptDisposition, ReceiptEnvelope};
use eliot_security_contracts::{
    EffectCeiling as SourceEffectCeiling, FreshnessStatus, IndependenceLevel, IntegrityStatus,
    SourceAssurance,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Immutable recipe implemented by this cell.
pub const RECIPE: &str = "NegotiatedInterdependentInvestigation";
/// The strongest interpretation of a synthesis emitted here.
pub const SYNTHESIS_PROOF_CEILING: ProofCeiling = ProofCeiling::CandidateArtifact;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a non-blank opaque identity.
            pub fn new(value: impl Into<String>) -> Result<Self, SwarmError> {
                let value = value.into();
                validate_text(&value, stringify!($name))?;
                Ok(Self(value))
            }

            /// Returns the stable text form.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = SwarmError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

id_type!(LaneId);
id_type!(RoleId);
id_type!(RootContextRevision);
id_type!(ControllerId);
id_type!(BranchId);
id_type!(ClaimId);
id_type!(SnapshotId);

/// A required composition-time provider.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredProvider {
    /// A-02 route/admission provider.
    A02,
    /// M-04 durable checkpoint provider.
    M04,
    /// Trusted receipt authenticity/issuer verifier.
    ReceiptVerifier,
    /// Durable staged-work record owner (issue #698 persistence port).
    DurabilityStore,
    /// External child-launch/observe/cancel owner (issue #698 executor port).
    WorkExecutor,
    /// Accepted route catalogue/admission path projection (issue #694 consumer).
    RouteCatalogue,
    /// Mailbox/blackboard peer-delivery projection (issue #696 consumer).
    PeerChannel,
}

/// Provider failures remain typed and never become successful local fallbacks.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("provider unavailable")]
    Unavailable,
    #[error("provider permission denied")]
    PermissionDenied,
    #[error("provider rejected an invalid request")]
    Invalid,
    #[error("provider timed out")]
    Timeout,
    #[error("provider operation failed")]
    Failed,
    #[error("provider outcome is unknown")]
    Unknown,
}

/// Fail-closed validation and coordination errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SwarmError {
    #[error("PLAN_GAP: required provider {0:?} is absent")]
    PlanGap(RequiredProvider),
    #[error("provider {provider:?} failed: {source}")]
    Provider {
        provider: RequiredProvider,
        source: ProviderError,
    },
    #[error("{0} must not be blank")]
    Blank(&'static str),
    #[error("{0} contains a control character")]
    ControlCharacter(&'static str),
    #[error("{0} must contain at least one item")]
    Empty(&'static str),
    #[error("{0} contains a duplicate identity")]
    Duplicate(&'static str),
    #[error("a required lane was omitted")]
    OmittedLane,
    #[error("the proposal targets the wrong partition")]
    WrongPartition,
    #[error("the proposal has stale or mismatched lineage")]
    StaleLineage,
    #[error("the receipt is forged, mismatched, or exceeds its proof ceiling")]
    InvalidReceipt,
    #[error("the receipt does not carry exact task/session/work-scope/fence bindings")]
    BindingMismatch,
    #[error("the assignment violates task/work/role/route/lease/fence/revision binding")]
    AssignmentMismatch,
    #[error("global WIP ceiling exceeded")]
    GlobalWipExceeded,
    #[error("route WIP ceiling exceeded")]
    RouteWipExceeded,
    #[error("the admitted dependency graph contains a cycle")]
    DependencyCycle,
    #[error("a wave dependency has not reached completed state")]
    DependencyNotReady,
    #[error("the provider-owned replay cursor rejected stale state")]
    ReplayDetected,
    #[error("the review is not bound to an independent admitted reviewer")]
    ReviewMismatch,
    #[error("lineage provenance does not match its sealed provider outcome")]
    LineageMismatch,
    #[error("only affected branches may change during selective replan")]
    UnaffectedBranchMutation,
    #[error("first-pass independence was contaminated")]
    BlindAuditContaminated,
    #[error("reduction input exceeds the bounded fan-in")]
    FanInExceeded,
    #[error("controller snapshot sequence or digest is invalid")]
    InvalidSnapshot,
    #[error("dependency contract rejected the value")]
    Contract,
    #[error("canonical serialization failed")]
    Serialization,
    #[error("unknown durable work unit identity")]
    WorkUnitUnknown,
    #[error("scope already has an overlapping writer")]
    ScopeWriterConflict,
    #[error("same identity carries a changed payload digest")]
    PayloadConflict,
    #[error("work unit already has a singular owner")]
    OwnershipConflict,
    #[error("transition is not legal from the current durable phase")]
    IllegalTransition,
    #[error("possible effect is unresolved; the scope stays blocked")]
    EffectUnresolved,
    #[error("independent budget bound exceeded")]
    BudgetExceeded,
    #[error("operation identity was already applied")]
    DuplicateOperation,
    #[error("admitted route is unavailable or stale; no local fallback")]
    RouteBlocked,
    #[error("completion requires evidence")]
    EvidenceMissing,
    #[error("a required review prevents closure")]
    ReviewBlocksClosure,
    #[error("unknown review identity")]
    ReviewUnknown,
    #[error("parent closure requires one disposition per child")]
    ChildDenominatorOpen,
}

fn validate_text(value: &str, field: &'static str) -> Result<(), SwarmError> {
    if value.trim().is_empty() {
        return Err(SwarmError::Blank(field));
    }
    if value.chars().any(char::is_control) {
        return Err(SwarmError::ControlCharacter(field));
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<String, SwarmError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SwarmError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Exact authority and work identity that an injected provider must seal.
///
/// This value is an inert request projection.  It becomes usable only when the
/// injected provider returns an authentic receipt whose canonical fields and
/// artifact source revision bind every field below.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBinding {
    pub task_id: String,
    pub session_id: String,
    pub work_scope_id: String,
    pub work_scope_digest: String,
    pub state_fence_digest: String,
    pub authority_fence_digest: String,
    pub root_context_revision: RootContextRevision,
    pub task_revision: String,
    pub plan_revision: RevisionId,
    pub receipt_contract_revision: String,
    pub work_contract_revision: String,
    pub work_item_id: WorkItemId,
    pub role_id: RoleId,
    pub route_id: String,
    pub lease_id: WorkLeaseId,
    pub reviewer_attempt_id: Option<AgentAttemptId>,
    pub affected_branch: Option<BranchId>,
}

impl ProviderBinding {
    fn validate_text_fields(&self) -> Result<(), SwarmError> {
        for (field, value) in [
            ("task_id", self.task_id.as_str()),
            ("session_id", self.session_id.as_str()),
            ("work_scope_id", self.work_scope_id.as_str()),
            ("work_scope_digest", self.work_scope_digest.as_str()),
            ("state_fence_digest", self.state_fence_digest.as_str()),
            (
                "authority_fence_digest",
                self.authority_fence_digest.as_str(),
            ),
            ("task_revision", self.task_revision.as_str()),
            (
                "receipt_contract_revision",
                self.receipt_contract_revision.as_str(),
            ),
            (
                "work_contract_revision",
                self.work_contract_revision.as_str(),
            ),
            ("route_id", self.route_id.as_str()),
        ] {
            validate_text(value, field)?;
        }
        // lease_id is the canonical `WorkLeaseId` (re-exported owner via
        // `eliot-agent-api`): non-blank/control/boundary/length is already
        // enforced by Deserialize; provenance and equality are enforced via
        // `==` against `AgentAttempt::lease` / `AuthorityEnvelope::lease`.
        Ok(())
    }

    fn same_coordination_scope(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.session_id == other.session_id
            && self.work_scope_id == other.work_scope_id
            && self.work_scope_digest == other.work_scope_digest
            && self.state_fence_digest == other.state_fence_digest
            && self.authority_fence_digest == other.authority_fence_digest
            && self.root_context_revision == other.root_context_revision
            && self.task_revision == other.task_revision
            && self.plan_revision == other.plan_revision
            && self.receipt_contract_revision == other.receipt_contract_revision
    }
}

/// Provider-owned replay cursor for state-changing streams.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBinding {
    pub stream_id: String,
    pub prior_cursor: u64,
    pub next_cursor: u64,
}

/// Exact operation to be sealed by the injected provider.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub operation_kind: String,
    pub artifact_digest: String,
    pub binding: ProviderBinding,
    pub replay: Option<ReplayBinding>,
}

/// Provider-only facts used for first-pass independence and provenance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ProviderAttestation {
    None,
    Independent {
        source_assurance: Box<SourceAssurance>,
        evidence: Box<EvidenceEnvelope>,
        sealed_before_peer_disclosure: bool,
        all_disclosures_predate_candidate: bool,
        no_sibling_finding_disclosed: bool,
    },
    Lineage {
        lineage_digest: String,
        provenance_digest: String,
    },
}

/// Outcome returned directly by the injected provider.  Callers cannot pass an
/// outcome into an admission function; only a provider invocation can supply it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderOutcome {
    pub receipt: ReceiptEnvelope,
    pub attestation: ProviderAttestation,
    pub committed_cursor: Option<u64>,
}

/// Injected A-02 route/admission boundary. The core never launches a process.
pub trait AgentRouteProvider: Send + Sync {
    /// Returns the durable cursor currently owned by one provider stream.
    fn current_cursor(&self, stream_id: &str) -> Result<u64, ProviderError>;
    /// Returns an immutable provider outcome for the exact request.
    fn seal(&self, request: &ProviderRequest) -> Result<ProviderOutcome, ProviderError>;
}

/// Injected trusted verification boundary for receipt authenticity and issuer.
pub trait ReceiptVerificationPort: Send + Sync {
    /// Verifies cryptographic authenticity/trust of an already canonical receipt.
    fn verify(&self, receipt: &ReceiptEnvelope) -> Result<(), ProviderError>;
}

/// Injected M-04 durability boundary. Restart safety belongs to this provider.
pub trait SwarmCheckpointProvider: Send + Sync {
    /// Stable provider identity used to reject a snapshot from another owner.
    fn provider_identity(&self) -> &str;
    /// Returns the provider-owned current cursor and monotonic rollback floor.
    fn cursor(&self) -> Result<CheckpointCursor, ProviderError>;
    /// Persists one immutable controller snapshot and returns the committed view.
    fn persist(&self, snapshot: &ControllerSnapshot) -> Result<CheckpointCommit, ProviderError>;
    /// Loads one snapshot plus the provider-owned cursor and exact restore receipt.
    fn restore(&self, snapshot_id: &SnapshotId) -> Result<CheckpointCommit, ProviderError>;
}

fn require_port<T: ?Sized>(port: Option<&T>, provider: RequiredProvider) -> Result<&T, SwarmError> {
    port.ok_or(SwarmError::PlanGap(provider))
}

fn provider_error(provider: RequiredProvider, source: ProviderError) -> SwarmError {
    SwarmError::Provider { provider, source }
}

fn validate_receipt(
    receipt: &ReceiptEnvelope,
    verifier: Option<&dyn ReceiptVerificationPort>,
    owner: &str,
    request: &ProviderRequest,
) -> Result<(), SwarmError> {
    request.binding.validate_text_fields()?;
    validate_text(&request.operation_kind, "operation_kind")?;
    validate_text(&request.artifact_digest, "artifact_digest")?;
    if let Some(replay) = &request.replay {
        validate_text(&replay.stream_id, "stream_id")?;
        if replay.next_cursor != replay.prior_cursor.saturating_add(1) {
            return Err(SwarmError::InvalidReceipt);
        }
    }
    receipt.validate().map_err(|_| SwarmError::InvalidReceipt)?;
    require_port(verifier, RequiredProvider::ReceiptVerifier)?
        .verify(receipt)
        .map_err(|error| provider_error(RequiredProvider::ReceiptVerifier, error))?;

    let core = &receipt.core;
    let ReceiptDisposition::Success { proof } = core.disposition else {
        return Err(SwarmError::InvalidReceipt);
    };
    let task = core.task.as_ref().ok_or(SwarmError::BindingMismatch)?;
    let session = core.session.as_ref().ok_or(SwarmError::BindingMismatch)?;
    let binding_digest = digest(request)?;
    if proof != ProofCeiling::ScopedVerification
        || core.authority.proof_ceiling != ProofCeiling::ScopedVerification
        || core.authority.authority_owner != owner
        || core.authority.allowed_effect != EffectClass::Read
        || core.operation.effect != EffectClass::Read
        || core.operation.operation_kind != request.operation_kind
        || core.verifier.is_none()
        || !core.artifacts.iter().any(|artifact| {
            artifact.sha256 == request.artifact_digest
                && artifact.source_revision.as_deref() == Some(binding_digest.as_str())
        })
    {
        return Err(SwarmError::InvalidReceipt);
    }
    if core.request.state_fence != core.work_scope.state_fence
        || core.operation.state_fence != core.work_scope.state_fence
        || core.authority.state_fence != core.work_scope.state_fence
        || task.state_fence != core.work_scope.state_fence
        || session.state_fence != core.work_scope.state_fence
        || core
            .request
            .metadata
            .task_id
            .as_ref()
            .map(ToString::to_string)
            != Some(request.binding.task_id.clone())
        || core
            .request
            .metadata
            .session_id
            .as_ref()
            .map(ToString::to_string)
            != Some(request.binding.session_id.clone())
        || task.task_id.to_string() != request.binding.task_id
        || session.session_id.to_string() != request.binding.session_id
        || core.work_scope.scope_id.as_str() != request.binding.work_scope_id
        || digest(&core.work_scope)? != request.binding.work_scope_digest
        || digest(&core.work_scope.state_fence)? != request.binding.state_fence_digest
        || digest(&core.authority.state_fence)? != request.binding.authority_fence_digest
        || task.task_revision.value().to_string() != request.binding.task_revision
        || core.contract.version.to_string() != request.binding.receipt_contract_revision
    {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(())
}

fn validate_provider_outcome(
    outcome: &ProviderOutcome,
    verifier: Option<&dyn ReceiptVerificationPort>,
    owner: &str,
    request: &ProviderRequest,
) -> Result<(), SwarmError> {
    validate_receipt(&outcome.receipt, verifier, owner, request)?;
    if !matches!(&outcome.attestation, ProviderAttestation::None) {
        let attestation_digest = digest(&outcome.attestation)?;
        let request_digest = digest(request)?;
        if !outcome.receipt.core.artifacts.iter().any(|artifact| {
            artifact.sha256 == attestation_digest
                && artifact.source_revision.as_deref() == Some(request_digest.as_str())
        }) {
            return Err(SwarmError::InvalidReceipt);
        }
    }
    match (&request.replay, outcome.committed_cursor) {
        (Some(replay), Some(cursor)) if cursor == replay.next_cursor => Ok(()),
        (None, None) => Ok(()),
        _ => Err(SwarmError::InvalidReceipt),
    }
}

fn same_receipt_binding(left: &ReceiptEnvelope, right: &ReceiptEnvelope) -> bool {
    left.core.work_scope == right.core.work_scope
        && left.core.task == right.core.task
        && left.core.session == right.core.session
        && left.core.request.metadata.task_id == right.core.request.metadata.task_id
        && left.core.request.metadata.session_id == right.core.request.metadata.session_id
        && left.core.authority.state_fence == right.core.authority.state_fence
        && left.core.authority.authority_epoch == right.core.authority.authority_epoch
}

/// One lane's sealed-first-pass dependency sketch input.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentMapSubmission {
    pub lane_id: LaneId,
    pub root_context_revision: RootContextRevision,
    pub dependency_sketch: Vec<LaneId>,
    pub unknowns: Vec<String>,
    pub candidate_subquestions: Vec<String>,
    pub likely_overlaps: Vec<LaneId>,
    pub provider_binding: ProviderBinding,
}

/// P1 result. Fields are private and the type is serialize-only; callers can
/// copy an accepted result but cannot construct one through the public API.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SealedIndependentMaps {
    expected_lanes: Vec<LaneId>,
    maps: Vec<IndependentMapSubmission>,
    attestations: Vec<ProviderAttestation>,
    receipts: Vec<ReceiptEnvelope>,
    digest: String,
}

impl SealedIndependentMaps {
    /// Content digest used by P2 admission.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Required lane identities in deterministic order.
    #[must_use]
    pub fn lanes(&self) -> &[LaneId] {
        &self.expected_lanes
    }

    fn coordination_binding(&self) -> &ProviderBinding {
        &self.maps[0].provider_binding
    }
}

fn validate_map_submissions(
    expected_lanes: &[LaneId],
    submissions: &[IndependentMapSubmission],
) -> Result<(), SwarmError> {
    if expected_lanes.is_empty() {
        return Err(SwarmError::Empty("expected_lanes"));
    }
    let expected = expected_lanes.iter().cloned().collect::<BTreeSet<_>>();
    if expected.len() != expected_lanes.len() {
        return Err(SwarmError::Duplicate("expected_lanes"));
    }
    let actual = submissions
        .iter()
        .map(|submission| submission.lane_id.clone())
        .collect::<BTreeSet<_>>();
    if actual.len() != submissions.len() {
        return Err(SwarmError::Duplicate("map_submissions"));
    }
    if actual != expected {
        return Err(SwarmError::OmittedLane);
    }
    for submission in submissions {
        let dependencies = submission
            .dependency_sketch
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let overlaps = submission
            .likely_overlaps
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if dependencies.len() != submission.dependency_sketch.len()
            || overlaps.len() != submission.likely_overlaps.len()
            || dependencies.contains(&submission.lane_id)
            || overlaps.contains(&submission.lane_id)
            || !dependencies.is_subset(&expected)
            || !overlaps.is_subset(&expected)
        {
            return Err(SwarmError::WrongPartition);
        }
    }
    let root = &submissions[0].root_context_revision;
    if submissions
        .iter()
        .any(|submission| &submission.root_context_revision != root)
    {
        return Err(SwarmError::StaleLineage);
    }
    Ok(())
}

fn validate_independence_outcome(outcome: &ProviderOutcome) -> Result<(), SwarmError> {
    let ProviderAttestation::Independent {
        source_assurance,
        evidence,
        sealed_before_peer_disclosure,
        all_disclosures_predate_candidate,
        no_sibling_finding_disclosed,
    } = &outcome.attestation
    else {
        return Err(SwarmError::BlindAuditContaminated);
    };
    source_assurance
        .validate()
        .map_err(|_| SwarmError::Contract)?;
    evidence.validate().map_err(|_| SwarmError::Contract)?;
    if source_assurance.integrity != IntegrityStatus::Verified
        || source_assurance.freshness != FreshnessStatus::Current
        || source_assurance.independence != IndependenceLevel::Independent
        || !source_assurance
            .allowed_effects
            .contains(&SourceEffectCeiling::NoExternalEffect)
        || source_assurance.state_fence != evidence.state_fence
        || evidence.state_fence != outcome.receipt.core.work_scope.state_fence
        || !sealed_before_peer_disclosure
        || !all_disclosures_predate_candidate
        || !no_sibling_finding_disclosed
    {
        return Err(SwarmError::BlindAuditContaminated);
    }
    Ok(())
}

/// P1: independently seals every required map before any sibling disclosure.
pub fn collect_independent_maps(
    expected_lanes: Vec<LaneId>,
    submissions: Vec<IndependentMapSubmission>,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<SealedIndependentMaps, SwarmError> {
    validate_map_submissions(&expected_lanes, &submissions)?;
    let a02 = require_port(a02, RequiredProvider::A02)?;
    let mut ordered = submissions;
    ordered.sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    let mut receipts = Vec::with_capacity(ordered.len());
    let mut attestations = Vec::with_capacity(ordered.len());
    for submission in &ordered {
        submission.provider_binding.validate_text_fields()?;
        if submission.lane_id.as_str() != submission.provider_binding.work_item_id.as_str()
            || submission.root_context_revision != submission.provider_binding.root_context_revision
            || !submission
                .provider_binding
                .same_coordination_scope(&ordered[0].provider_binding)
        {
            return Err(SwarmError::BindingMismatch);
        }
        let request = ProviderRequest {
            operation_kind: "swarm.map.seal".to_owned(),
            artifact_digest: digest(submission)?,
            binding: submission.provider_binding.clone(),
            replay: None,
        };
        let outcome = a02
            .seal(&request)
            .map_err(|error| provider_error(RequiredProvider::A02, error))?;
        validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
        validate_independence_outcome(&outcome)?;
        if receipts
            .first()
            .is_some_and(|first| !same_receipt_binding(first, &outcome.receipt))
        {
            return Err(SwarmError::BindingMismatch);
        }
        attestations.push(outcome.attestation);
        receipts.push(outcome.receipt);
    }
    let receipt_identities = receipts
        .iter()
        .map(|receipt| receipt.identity.clone())
        .collect::<Vec<_>>();
    let digest = digest(&(&ordered, &attestations, receipt_identities))?;
    let mut expected_lanes = expected_lanes;
    expected_lanes.sort();
    Ok(SealedIndependentMaps {
        expected_lanes,
        maps: ordered,
        attestations,
        receipts,
        digest,
    })
}

/// Immutable P2 partition proposal. It is inert until admitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmPlanProposal {
    pub plan_revision: RevisionId,
    pub root_context_revision: RootContextRevision,
    pub work_items: Vec<WorkItem>,
    pub branch_roots: BTreeMap<BranchId, WorkItemId>,
    pub global_wip: u32,
    pub per_route_wip: u32,
    pub reduction_fan_in: u32,
    pub preserved_partition_dissent: Vec<String>,
}

/// Admitted P2 plan. It cannot be deserialized or publicly constructed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AdmittedSwarmPlan {
    proposal: SwarmPlanProposal,
    mapping_digest: String,
    provider_binding: ProviderBinding,
    admission_receipt: ReceiptEnvelope,
}

impl AdmittedSwarmPlan {
    /// Frozen plan revision.
    #[must_use]
    pub fn revision(&self) -> &RevisionId {
        &self.proposal.plan_revision
    }

    /// Sealed Governor coordination binding carried by the admission.
    #[must_use]
    pub fn provider_binding(&self) -> &ProviderBinding {
        &self.provider_binding
    }

    /// Governor admission receipt that admitted this exact revision.
    #[must_use]
    pub fn admission_receipt(&self) -> &ReceiptEnvelope {
        &self.admission_receipt
    }

    /// Frozen work graph.
    #[must_use]
    pub fn work_items(&self) -> &[WorkItem] {
        &self.proposal.work_items
    }

    /// Derived read-only addressing view; it owns no plan state.
    pub fn coordination_map_view(&self) -> Result<CoordinationMapView, SwarmError> {
        let wave_revision = self
            .proposal
            .work_items
            .first()
            .ok_or(SwarmError::Empty("work_items"))?
            .wave_revision
            .clone();
        let view = CoordinationMapView {
            plan_revision: self.proposal.plan_revision.clone(),
            wave_revision,
            entries: self
                .proposal
                .work_items
                .iter()
                .map(|item| CoordinationEntry {
                    work_item_id: item.work_item_id.clone(),
                    responsibility: item.responsibility.clone(),
                    dependency_ids: item.dependency_ids.clone(),
                    overlap_ids: item.overlap_ids.clone(),
                    assigned_attempt_id: item.assigned_attempt_id.clone(),
                    assigned_role: item.assigned_role.clone(),
                    mailbox_route_handle: item.mailbox_route_handle.clone(),
                })
                .collect(),
        };
        view.validate().map_err(|_| SwarmError::Contract)?;
        Ok(view)
    }

    fn binding_for_work(
        &self,
        work_item_id: WorkItemId,
        role_id: RoleId,
        route_id: String,
        lease_id: WorkLeaseId,
        work_contract_revision: String,
    ) -> ProviderBinding {
        let mut binding = self.provider_binding.clone();
        binding.work_item_id = work_item_id;
        binding.role_id = role_id;
        binding.route_id = route_id;
        binding.lease_id = lease_id;
        binding.work_contract_revision = work_contract_revision;
        binding.reviewer_attempt_id = None;
        binding.affected_branch = None;
        binding
    }
}

fn validate_plan_graph(proposal: &SwarmPlanProposal) -> Result<(), SwarmError> {
    let work_ids = proposal
        .work_items
        .iter()
        .map(|item| item.work_item_id.clone())
        .collect::<BTreeSet<_>>();
    if work_ids.len() != proposal.work_items.len() {
        return Err(SwarmError::Duplicate("work_items"));
    }
    let dependency_roots = proposal
        .work_items
        .iter()
        .filter(|item| item.dependency_ids.is_empty())
        .map(|item| item.work_item_id.clone())
        .collect::<BTreeSet<_>>();
    let declared_roots = proposal
        .branch_roots
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared_roots.len() != proposal.branch_roots.len() || declared_roots != dependency_roots {
        return Err(SwarmError::WrongPartition);
    }

    let mut remaining = proposal
        .work_items
        .iter()
        .map(|item| (item.work_item_id.clone(), item.dependency_ids.len()))
        .collect::<BTreeMap<_, _>>();
    let mut descendants = BTreeMap::<WorkItemId, Vec<WorkItemId>>::new();
    for item in &proposal.work_items {
        item.validate().map_err(|_| SwarmError::Contract)?;
        if item.state != WorkItemState::Planned {
            return Err(SwarmError::Contract);
        }
        if item.plan_revision != proposal.plan_revision {
            return Err(SwarmError::StaleLineage);
        }
        if item
            .dependency_ids
            .iter()
            .chain(&item.overlap_ids)
            .any(|id| !work_ids.contains(id))
        {
            return Err(SwarmError::WrongPartition);
        }
        for dependency in &item.dependency_ids {
            descendants
                .entry(dependency.clone())
                .or_default()
                .push(item.work_item_id.clone());
        }
    }

    let mut ready = remaining
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(id.clone()))
        .collect::<Vec<_>>();
    let mut visited = 0usize;
    while let Some(id) = ready.pop() {
        visited += 1;
        if let Some(children) = descendants.get(&id) {
            for child in children {
                let count = remaining.get_mut(child).ok_or(SwarmError::WrongPartition)?;
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.push(child.clone());
                }
            }
        }
    }
    if visited != proposal.work_items.len() {
        return Err(SwarmError::DependencyCycle);
    }
    Ok(())
}

/// Builds the exact Governor request that must accompany P2 admission.
pub fn plan_admission_request(
    proposal: &SwarmPlanProposal,
    maps: &SealedIndependentMaps,
) -> Result<ProviderRequest, SwarmError> {
    let mut binding = maps.coordination_binding().clone();
    binding.root_context_revision = proposal.root_context_revision.clone();
    binding.plan_revision = proposal.plan_revision.clone();
    binding.reviewer_attempt_id = None;
    binding.affected_branch = None;
    Ok(ProviderRequest {
        operation_kind: "swarm.plan.admit".to_owned(),
        artifact_digest: digest(&(proposal, maps.digest()))?,
        binding,
        replay: None,
    })
}

/// P2: validates and admits one immutable partition revision.
pub fn admit_plan(
    proposal: SwarmPlanProposal,
    maps: &SealedIndependentMaps,
    admission_receipt: ReceiptEnvelope,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<AdmittedSwarmPlan, SwarmError> {
    if proposal.work_items.is_empty() {
        return Err(SwarmError::Empty("work_items"));
    }
    if proposal.global_wip == 0 || proposal.per_route_wip == 0 || proposal.reduction_fan_in == 0 {
        return Err(SwarmError::Empty("wip_or_fan_in"));
    }
    if proposal.root_context_revision != maps.coordination_binding().root_context_revision
        || proposal.plan_revision != maps.coordination_binding().plan_revision
    {
        return Err(SwarmError::StaleLineage);
    }
    let map_lanes = maps
        .lanes()
        .iter()
        .map(LaneId::as_str)
        .collect::<BTreeSet<_>>();
    let work_lanes = proposal
        .work_items
        .iter()
        .map(|item| item.work_item_id.as_str())
        .collect::<BTreeSet<_>>();
    if map_lanes != work_lanes {
        return Err(SwarmError::WrongPartition);
    }
    validate_plan_graph(&proposal)?;
    let mut wave = None;
    for item in &proposal.work_items {
        if let Some(current) = &wave {
            if current != &item.wave_revision {
                return Err(SwarmError::StaleLineage);
            }
        } else {
            wave = Some(item.wave_revision.clone());
        }
        let map = maps
            .maps
            .iter()
            .find(|map| map.lane_id.as_str() == item.work_item_id.as_str())
            .ok_or(SwarmError::WrongPartition)?;
        let mapped_dependencies = map
            .dependency_sketch
            .iter()
            .map(LaneId::as_str)
            .collect::<BTreeSet<_>>();
        let item_dependencies = item
            .dependency_ids
            .iter()
            .map(WorkItemId::as_str)
            .collect::<BTreeSet<_>>();
        let mapped_overlaps = map
            .likely_overlaps
            .iter()
            .map(LaneId::as_str)
            .collect::<BTreeSet<_>>();
        let item_overlaps = item
            .overlap_ids
            .iter()
            .map(WorkItemId::as_str)
            .collect::<BTreeSet<_>>();
        if mapped_dependencies != item_dependencies || mapped_overlaps != item_overlaps {
            return Err(SwarmError::WrongPartition);
        }
    }
    let request = plan_admission_request(&proposal, maps)?;
    validate_receipt(&admission_receipt, verifier, "Governor", &request)?;
    if !same_receipt_binding(&maps.receipts[0], &admission_receipt) {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(AdmittedSwarmPlan {
        proposal,
        mapping_digest: maps.digest.clone(),
        provider_binding: request.binding,
        admission_receipt,
    })
}

/// One exact P3 assignment binding both canonical contract surfaces.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaveAssignment {
    pub work_item: WorkItem,
    pub attempt: AgentAttempt,
    pub launch_attempt: LaunchAttempt,
    pub role_id: RoleId,
}

/// Whether a reservation still consumes WIP after an observed terminal update.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReservationStatus {
    Active,
    UnknownOutcome,
    Released,
}

/// One provider-sealed assignment retained for replay and reviewer binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedAssignment {
    assignment: WaveAssignment,
    receipt: ReceiptEnvelope,
    status: ReservationStatus,
}

/// Terminal observation for one exact attempt. Unknown outcome remains active.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalDisposition {
    Completed,
    Partial,
    Failed,
    Cancelled,
    UnknownOutcome,
}

/// Inert terminal proposal; A-02 must seal it before WIP is released.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalWorkUpdate {
    pub work_item_id: WorkItemId,
    pub attempt_id: AgentAttemptId,
    pub disposition: TerminalDisposition,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalRecord {
    update: TerminalWorkUpdate,
    receipt: ReceiptEnvelope,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionStateCore {
    plan_revision: RevisionId,
    root_context_revision: RootContextRevision,
    transition_sequence: u64,
    last_operation_kind: String,
    reservations: Vec<ReservedAssignment>,
    completed_work_items: BTreeSet<WorkItemId>,
    terminal_records: Vec<TerminalRecord>,
}

/// Immutable provider-sealed execution state carried across P3 calls.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionState {
    core: ExecutionStateCore,
    digest: String,
    receipt: ReceiptEnvelope,
    committed_cursor: u64,
}

impl ExecutionState {
    /// Provider-owned transition sequence represented by this state.
    #[must_use]
    pub const fn transition_sequence(&self) -> u64 {
        self.core.transition_sequence
    }

    /// Completed dependency identities.
    #[must_use]
    pub fn completed_work_items(&self) -> &BTreeSet<WorkItemId> {
        &self.core.completed_work_items
    }

    fn active_reservations(&self) -> impl Iterator<Item = &ReservedAssignment> {
        self.core.reservations.iter().filter(|reservation| {
            matches!(
                reservation.status,
                ReservationStatus::Active | ReservationStatus::UnknownOutcome
            )
        })
    }
}

/// Admitted staged wave; fields remain private and serialize-only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AdmittedWave {
    plan_revision: RevisionId,
    wave_revision: RevisionId,
    assignments: Vec<WaveAssignment>,
    receipts: Vec<ReceiptEnvelope>,
    transition_sequence: u64,
}

impl AdmittedWave {
    /// Exact admitted assignments.
    #[must_use]
    pub fn assignments(&self) -> &[WaveAssignment] {
        &self.assignments
    }

    /// Frozen wave revision.
    #[must_use]
    pub fn wave_revision(&self) -> &RevisionId {
        &self.wave_revision
    }
}

/// Atomic P3 result: the wave and the new immutable cumulative state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct WaveAdmission {
    wave: AdmittedWave,
    state: ExecutionState,
}

impl WaveAdmission {
    #[must_use]
    pub const fn wave(&self) -> &AdmittedWave {
        &self.wave
    }

    #[must_use]
    pub const fn state(&self) -> &ExecutionState {
        &self.state
    }

    #[must_use]
    pub fn into_state(self) -> ExecutionState {
        self.state
    }
}

fn execution_stream(plan: &AdmittedSwarmPlan) -> String {
    format!("swarm.execution:{}", plan.proposal.plan_revision.as_str())
}

fn execution_state_digest(core: &ExecutionStateCore) -> Result<String, SwarmError> {
    digest(core)
}

fn execution_request(
    plan: &AdmittedSwarmPlan,
    core: &ExecutionStateCore,
    artifact_digest: String,
) -> ProviderRequest {
    ProviderRequest {
        operation_kind: core.last_operation_kind.clone(),
        artifact_digest,
        binding: plan.provider_binding.clone(),
        replay: Some(ReplayBinding {
            stream_id: execution_stream(plan),
            prior_cursor: core.transition_sequence.saturating_sub(1),
            next_cursor: core.transition_sequence,
        }),
    }
}

fn validate_execution_state(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<(), SwarmError> {
    if state.core.plan_revision != plan.proposal.plan_revision
        || state.core.root_context_revision != plan.proposal.root_context_revision
        || state.core.transition_sequence == 0
        || state.committed_cursor != state.core.transition_sequence
        || state.digest != execution_state_digest(&state.core)?
    {
        return Err(SwarmError::ReplayDetected);
    }
    let request = execution_request(plan, &state.core, state.digest.clone());
    validate_provider_outcome(
        &ProviderOutcome {
            receipt: state.receipt.clone(),
            attestation: ProviderAttestation::None,
            committed_cursor: Some(state.committed_cursor),
        },
        verifier,
        "A-02",
        &request,
    )?;
    if !same_receipt_binding(&plan.admission_receipt, &state.receipt) {
        return Err(SwarmError::BindingMismatch);
    }

    let plan_ids = plan
        .proposal
        .work_items
        .iter()
        .map(|item| item.work_item_id.clone())
        .collect::<BTreeSet<_>>();
    if !state.core.completed_work_items.is_subset(&plan_ids) {
        return Err(SwarmError::WrongPartition);
    }
    let mut reservation_ids = BTreeSet::new();
    for reservation in &state.core.reservations {
        validate_assignment(plan, &reservation.assignment)?;
        if !reservation_ids.insert(reservation.assignment.work_item.work_item_id.clone()) {
            return Err(SwarmError::Duplicate("reservations"));
        }
        let request = assignment_request(
            plan,
            &reservation.assignment,
            "swarm.wave.admit",
            digest(&reservation.assignment)?,
        );
        validate_receipt(&reservation.receipt, verifier, "A-02", &request)?;
    }
    if state.active_reservations().any(|reservation| {
        state
            .core
            .completed_work_items
            .contains(&reservation.assignment.work_item.work_item_id)
    }) {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(())
}

fn seal_execution_state(
    plan: &AdmittedSwarmPlan,
    core: ExecutionStateCore,
    a02: &dyn AgentRouteProvider,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<ExecutionState, SwarmError> {
    let stream = execution_stream(plan);
    let current = a02
        .current_cursor(&stream)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    if current.saturating_add(1) != core.transition_sequence {
        return Err(SwarmError::ReplayDetected);
    }
    let state_digest = execution_state_digest(&core)?;
    let request = execution_request(plan, &core, state_digest.clone());
    let outcome = a02
        .seal(&request)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
    if !matches!(outcome.attestation, ProviderAttestation::None)
        || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
    {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(ExecutionState {
        core,
        digest: state_digest,
        receipt: outcome.receipt,
        committed_cursor: outcome.committed_cursor.ok_or(SwarmError::ReplayDetected)?,
    })
}

/// Starts a provider-owned P3 state stream. Replaying begin on an existing
/// stream is rejected by the provider cursor.
pub fn begin_execution(
    plan: &AdmittedSwarmPlan,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<ExecutionState, SwarmError> {
    let a02 = require_port(a02, RequiredProvider::A02)?;
    seal_execution_state(
        plan,
        ExecutionStateCore {
            plan_revision: plan.proposal.plan_revision.clone(),
            root_context_revision: plan.proposal.root_context_revision.clone(),
            transition_sequence: 1,
            last_operation_kind: "swarm.execution.begin".to_owned(),
            reservations: Vec::new(),
            completed_work_items: BTreeSet::new(),
            terminal_records: Vec::new(),
        },
        a02,
        verifier,
    )
}

fn validate_assignment(plan: &AdmittedSwarmPlan, value: &WaveAssignment) -> Result<(), SwarmError> {
    value
        .attempt
        .validate()
        .map_err(|_| SwarmError::AssignmentMismatch)?;
    value
        .launch_attempt
        .validate()
        .map_err(|_| SwarmError::AssignmentMismatch)?;
    let frozen = plan
        .proposal
        .work_items
        .iter()
        .find(|item| item.work_item_id == value.work_item.work_item_id)
        .ok_or(SwarmError::WrongPartition)?;
    let task = plan
        .admission_receipt
        .core
        .task
        .as_ref()
        .ok_or(SwarmError::BindingMismatch)?;
    let session = plan
        .admission_receipt
        .core
        .session
        .as_ref()
        .ok_or(SwarmError::BindingMismatch)?;
    let route_digest = digest(&value.launch_attempt.route)?;
    let mut immutable_projection = value.work_item.clone();
    immutable_projection
        .assigned_attempt_id
        .clone_from(&frozen.assigned_attempt_id);
    immutable_projection
        .assigned_role
        .clone_from(&frozen.assigned_role);
    immutable_projection
        .mailbox_route_handle
        .clone_from(&frozen.mailbox_route_handle);
    immutable_projection.state = frozen.state;
    if &immutable_projection != frozen
        || value.work_item.state != WorkItemState::Assigned
        || value.work_item.plan_revision != plan.proposal.plan_revision
        || value.work_item.assigned_attempt_id.as_ref() != Some(&value.attempt.attempt_id)
        || value.work_item.assigned_role.as_deref() != Some(value.role_id.as_str())
        || value.work_item.mailbox_route_handle.as_deref()
            != Some(value.attempt.route.route_id.as_str())
        || value.attempt.work_item_id != value.work_item.work_item_id
        || value.attempt.state_fence != task.state_fence
        || value.launch_attempt.id.as_str() != value.attempt.attempt_id.as_str()
        || value.launch_attempt.work_unit.id.as_str() != value.work_item.work_item_id.as_str()
        || value.launch_attempt.task_id.as_str() != task.task_id.to_string()
        || value
            .launch_attempt
            .session
            .as_ref()
            .is_none_or(|id| id.as_str() != session.session_id.to_string())
        || value.launch_attempt.authority.lease != value.launch_attempt.lease
        || value.launch_attempt.work_unit.contract_revision
            != plan.provider_binding.work_contract_revision
        || value.launch_attempt.work_unit.scope_ref
            != plan.admission_receipt.core.work_scope.scope_id.as_str()
        || value.launch_attempt.authority.scope_ref
            != plan.admission_receipt.core.work_scope.scope_id.as_str()
        || value.launch_attempt.authority.effect_ceiling.scope_ref
            != plan.admission_receipt.core.work_scope.scope_id.as_str()
        || value.launch_attempt.authority.state_fence
            != plan.admission_receipt.core.work_scope.state_fence
        || value.launch_attempt.authority.epoch
            != plan.admission_receipt.core.authority.authority_epoch
        || value.launch_attempt.authority.effect_ceiling
            != value.launch_attempt.work_unit.effect_ceiling
        || !value
            .launch_attempt
            .authority
            .effect_ceiling
            .allowed
            .contains(&EffectKind::Observe)
        || value.attempt.route.fingerprint != route_digest
    {
        return Err(SwarmError::AssignmentMismatch);
    }
    Ok(())
}

fn assignment_request(
    plan: &AdmittedSwarmPlan,
    assignment: &WaveAssignment,
    operation_kind: &str,
    artifact_digest: String,
) -> ProviderRequest {
    ProviderRequest {
        operation_kind: operation_kind.to_owned(),
        artifact_digest,
        binding: plan.binding_for_work(
            assignment.work_item.work_item_id.clone(),
            assignment.role_id.clone(),
            assignment.attempt.route.route_id.as_str().to_owned(),
            assignment.launch_attempt.lease.clone(),
            assignment
                .launch_attempt
                .work_unit
                .contract_revision
                .clone(),
        ),
        replay: None,
    }
}

/// P3: admits one staged wave under global and per-route WIP ceilings.
pub fn admit_wave(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    assignments: Vec<WaveAssignment>,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<WaveAdmission, SwarmError> {
    validate_execution_state(plan, state, verifier)?;
    let a02 = require_port(a02, RequiredProvider::A02)?;
    let stream = execution_stream(plan);
    let provider_cursor = a02
        .current_cursor(&stream)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    if provider_cursor != state.core.transition_sequence {
        return Err(SwarmError::ReplayDetected);
    }
    if assignments.is_empty() {
        return Err(SwarmError::Empty("assignments"));
    }
    let active_count = state.active_reservations().count();
    if active_count + assignments.len() > plan.proposal.global_wip as usize {
        return Err(SwarmError::GlobalWipExceeded);
    }
    let identities = assignments
        .iter()
        .map(|assignment| assignment.work_item.work_item_id.clone())
        .collect::<BTreeSet<_>>();
    if identities.len() != assignments.len() {
        return Err(SwarmError::Duplicate("wave_assignments"));
    }
    let mut per_route = BTreeMap::<RouteId, usize>::new();
    for reservation in state.active_reservations() {
        *per_route
            .entry(reservation.assignment.attempt.route.route_id.clone())
            .or_default() += 1;
    }
    for assignment in &assignments {
        validate_assignment(plan, assignment)?;
        let work_item_id = &assignment.work_item.work_item_id;
        if state
            .core
            .reservations
            .iter()
            .any(|reservation| &reservation.assignment.work_item.work_item_id == work_item_id)
            || state.core.completed_work_items.contains(work_item_id)
            || assignment
                .work_item
                .dependency_ids
                .iter()
                .any(|dependency| !state.core.completed_work_items.contains(dependency))
        {
            return Err(SwarmError::DependencyNotReady);
        }
        *per_route
            .entry(assignment.attempt.route.route_id.clone())
            .or_default() += 1;
    }
    if per_route
        .values()
        .any(|count| *count > plan.proposal.per_route_wip as usize)
    {
        return Err(SwarmError::RouteWipExceeded);
    }
    let mut receipts = Vec::with_capacity(assignments.len());
    for assignment in &assignments {
        let request = assignment_request(plan, assignment, "swarm.wave.admit", digest(assignment)?);
        let outcome = a02
            .seal(&request)
            .map_err(|error| provider_error(RequiredProvider::A02, error))?;
        validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
        if !matches!(outcome.attestation, ProviderAttestation::None)
            || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
        {
            return Err(SwarmError::BindingMismatch);
        }
        receipts.push(outcome.receipt);
    }
    let wave = AdmittedWave {
        plan_revision: plan.proposal.plan_revision.clone(),
        wave_revision: assignments[0].work_item.wave_revision.clone(),
        assignments: assignments.clone(),
        receipts: receipts.clone(),
        transition_sequence: state.core.transition_sequence.saturating_add(1),
    };
    let mut core = state.core.clone();
    core.transition_sequence = core.transition_sequence.saturating_add(1);
    "swarm.execution.wave-admit".clone_into(&mut core.last_operation_kind);
    core.reservations.extend(
        assignments
            .into_iter()
            .zip(receipts)
            .map(|(assignment, receipt)| ReservedAssignment {
                assignment,
                receipt,
                status: ReservationStatus::Active,
            }),
    );
    let next_state = seal_execution_state(plan, core, a02, verifier)?;
    Ok(WaveAdmission {
        wave,
        state: next_state,
    })
}

/// Applies provider-sealed terminal observations and releases only known
/// terminal attempts. Unknown outcomes remain WIP-consuming reservations.
pub fn apply_terminal_updates(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    updates: Vec<TerminalWorkUpdate>,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<ExecutionState, SwarmError> {
    validate_execution_state(plan, state, verifier)?;
    if updates.is_empty() {
        return Err(SwarmError::Empty("terminal_updates"));
    }
    let update_ids = updates
        .iter()
        .map(|update| update.work_item_id.clone())
        .collect::<BTreeSet<_>>();
    if update_ids.len() != updates.len() {
        return Err(SwarmError::Duplicate("terminal_updates"));
    }
    let a02 = require_port(a02, RequiredProvider::A02)?;
    let provider_cursor = a02
        .current_cursor(&execution_stream(plan))
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    if provider_cursor != state.core.transition_sequence {
        return Err(SwarmError::ReplayDetected);
    }
    let mut core = state.core.clone();
    for update in updates {
        validate_text(&update.evidence_digest, "evidence_digest")?;
        let reservation = core
            .reservations
            .iter_mut()
            .find(|reservation| {
                reservation.assignment.work_item.work_item_id == update.work_item_id
                    && matches!(
                        reservation.status,
                        ReservationStatus::Active | ReservationStatus::UnknownOutcome
                    )
            })
            .ok_or(SwarmError::AssignmentMismatch)?;
        if reservation.assignment.attempt.attempt_id != update.attempt_id {
            return Err(SwarmError::AssignmentMismatch);
        }
        let request = assignment_request(
            plan,
            &reservation.assignment,
            "swarm.wave.terminal",
            digest(&update)?,
        );
        let outcome = a02
            .seal(&request)
            .map_err(|error| provider_error(RequiredProvider::A02, error))?;
        validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
        if !matches!(outcome.attestation, ProviderAttestation::None)
            || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
        {
            return Err(SwarmError::BindingMismatch);
        }
        match update.disposition {
            TerminalDisposition::Completed => {
                reservation.status = ReservationStatus::Released;
                core.completed_work_items
                    .insert(update.work_item_id.clone());
            }
            TerminalDisposition::UnknownOutcome => {
                reservation.status = ReservationStatus::UnknownOutcome;
            }
            TerminalDisposition::Partial
            | TerminalDisposition::Failed
            | TerminalDisposition::Cancelled => {
                reservation.status = ReservationStatus::Released;
            }
        }
        core.terminal_records.push(TerminalRecord {
            update,
            receipt: outcome.receipt,
        });
    }
    core.transition_sequence = core.transition_sequence.saturating_add(1);
    "swarm.execution.terminal-update".clone_into(&mut core.last_operation_kind);
    seal_execution_state(plan, core, a02, verifier)
}

/// Why a review can reopen one branch.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewCause {
    FactualConflict,
    ThinEvidence,
    InvalidatedAssumption,
    OmittedObservation,
}

/// Inert P4 review proposal.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossReviewProposal {
    pub plan_revision: RevisionId,
    pub work_item_id: WorkItemId,
    pub reviewer_attempt_id: AgentAttemptId,
    pub cause: ReviewCause,
    pub finding: EvidenceEnvelope,
    pub affected_branch: BranchId,
    pub proposed_next_work: String,
}

/// Sealed P4 review, constructible only through [`accept_cross_review`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AcceptedCrossReview {
    proposal: CrossReviewProposal,
    reviewer_work_item_id: WorkItemId,
    request: ProviderRequest,
    receipt: ReceiptEnvelope,
}

/// Accepts one lineage-bound cross-review after A-02 receipt validation.
pub fn accept_cross_review(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    proposal: CrossReviewProposal,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<AcceptedCrossReview, SwarmError> {
    validate_execution_state(plan, state, verifier)?;
    proposal
        .finding
        .validate()
        .map_err(|_| SwarmError::Contract)?;
    validate_text(&proposal.proposed_next_work, "proposed_next_work")?;
    if proposal.plan_revision != plan.proposal.plan_revision
        || !plan
            .proposal
            .work_items
            .iter()
            .any(|item| item.work_item_id == proposal.work_item_id)
    {
        return Err(SwarmError::StaleLineage);
    }
    if plan.proposal.branch_roots.get(&proposal.affected_branch) != Some(&proposal.work_item_id) {
        return Err(SwarmError::ReviewMismatch);
    }
    let reviewer = state
        .core
        .reservations
        .iter()
        .find(|reservation| {
            reservation.assignment.attempt.attempt_id == proposal.reviewer_attempt_id
        })
        .ok_or(SwarmError::ReviewMismatch)?;
    if reviewer.assignment.work_item.work_item_id == proposal.work_item_id {
        return Err(SwarmError::ReviewMismatch);
    }
    let target = state
        .core
        .reservations
        .iter()
        .find(|reservation| reservation.assignment.work_item.work_item_id == proposal.work_item_id)
        .ok_or(SwarmError::ReviewMismatch)?;
    if target.assignment.role_id == reviewer.assignment.role_id
        || target.assignment.attempt.route.route_id == reviewer.assignment.attempt.route.route_id
    {
        return Err(SwarmError::ReviewMismatch);
    }
    if proposal.finding.state_fence != plan.admission_receipt.core.work_scope.state_fence {
        return Err(SwarmError::BindingMismatch);
    }
    let mut binding = plan.binding_for_work(
        proposal.work_item_id.clone(),
        reviewer.assignment.role_id.clone(),
        reviewer
            .assignment
            .attempt
            .route
            .route_id
            .as_str()
            .to_owned(),
        reviewer.assignment.launch_attempt.lease.clone(),
        reviewer
            .assignment
            .launch_attempt
            .work_unit
            .contract_revision
            .clone(),
    );
    binding.reviewer_attempt_id = Some(proposal.reviewer_attempt_id.clone());
    binding.affected_branch = Some(proposal.affected_branch.clone());
    let request = ProviderRequest {
        operation_kind: "swarm.cross-review.accept".to_owned(),
        artifact_digest: digest(&proposal)?,
        binding,
        replay: None,
    };
    let outcome = require_port(a02, RequiredProvider::A02)?
        .seal(&request)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
    if !matches!(outcome.attestation, ProviderAttestation::None)
        || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
    {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(AcceptedCrossReview {
        reviewer_work_item_id: reviewer.assignment.work_item.work_item_id.clone(),
        proposal,
        request,
        receipt: outcome.receipt,
    })
}

/// Inert selective-replan proposal.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectiveReplanProposal {
    pub prior_revision: RevisionId,
    pub next_revision: RevisionId,
    pub replacements: Vec<WorkItem>,
}

fn affected_branch_closure(
    plan: &AdmittedSwarmPlan,
    branch: &BranchId,
) -> Result<BTreeSet<WorkItemId>, SwarmError> {
    let root = plan
        .proposal
        .branch_roots
        .get(branch)
        .cloned()
        .ok_or(SwarmError::ReviewMismatch)?;
    let mut affected = BTreeSet::from([root]);
    loop {
        let before = affected.len();
        for item in &plan.proposal.work_items {
            if item
                .dependency_ids
                .iter()
                .any(|dependency| affected.contains(dependency))
            {
                affected.insert(item.work_item_id.clone());
            }
        }
        if affected.len() == before {
            break;
        }
    }
    Ok(affected)
}

/// Builds the exact Governor request for one immutable selective replan.
pub fn replan_admission_request(
    prior: &AdmittedSwarmPlan,
    reviews: &[AcceptedCrossReview],
    proposal: &SelectiveReplanProposal,
) -> Result<ProviderRequest, SwarmError> {
    let review_digests = reviews
        .iter()
        .map(|review| review.request.artifact_digest.clone())
        .collect::<Vec<_>>();
    let artifact_digest = digest(&(
        proposal,
        review_digests,
        &prior.proposal,
        &prior.mapping_digest,
    ))?;
    let mut binding = prior.provider_binding.clone();
    binding.plan_revision = proposal.next_revision.clone();
    binding.reviewer_attempt_id = None;
    binding.affected_branch = None;
    Ok(ProviderRequest {
        operation_kind: "swarm.plan.replan-admit".to_owned(),
        artifact_digest,
        binding,
        replay: None,
    })
}

/// P4: returns a new immutable definition and rejects any unaffected mutation.
pub fn selectively_replan(
    prior: &AdmittedSwarmPlan,
    reviews: &[AcceptedCrossReview],
    proposal: &SelectiveReplanProposal,
    admission_receipt: ReceiptEnvelope,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<AdmittedSwarmPlan, SwarmError> {
    if proposal.prior_revision != prior.proposal.plan_revision
        || proposal.next_revision == proposal.prior_revision
    {
        return Err(SwarmError::StaleLineage);
    }
    if reviews.is_empty() || proposal.replacements.is_empty() {
        return Err(SwarmError::Empty("reviews_or_replacements"));
    }
    let mut affected = BTreeSet::new();
    for review in reviews {
        if review.proposal.plan_revision != prior.proposal.plan_revision
            || prior
                .proposal
                .branch_roots
                .get(&review.proposal.affected_branch)
                != Some(&review.proposal.work_item_id)
            || review.reviewer_work_item_id == review.proposal.work_item_id
            || review.request.artifact_digest != digest(&review.proposal)?
            || review.request.binding.plan_revision != prior.proposal.plan_revision
            || review.request.binding.affected_branch.as_ref()
                != Some(&review.proposal.affected_branch)
            || review.request.binding.reviewer_attempt_id.as_ref()
                != Some(&review.proposal.reviewer_attempt_id)
        {
            return Err(SwarmError::ReviewMismatch);
        }
        validate_receipt(&review.receipt, verifier, "A-02", &review.request)?;
        if !same_receipt_binding(&prior.admission_receipt, &review.receipt) {
            return Err(SwarmError::BindingMismatch);
        }
        affected.extend(affected_branch_closure(
            prior,
            &review.proposal.affected_branch,
        )?);
    }
    let replacements = proposal
        .replacements
        .iter()
        .map(|item| (item.work_item_id.clone(), item.clone()))
        .collect::<BTreeMap<_, _>>();
    if replacements.len() != proposal.replacements.len() {
        return Err(SwarmError::Duplicate("replacements"));
    }
    if replacements.keys().cloned().collect::<BTreeSet<_>>() != affected {
        return Err(SwarmError::UnaffectedBranchMutation);
    }
    let mut next_items = prior.proposal.work_items.clone();
    for item in &mut next_items {
        if let Some(replacement) = replacements.get(&item.work_item_id) {
            if replacement.plan_revision != proposal.next_revision {
                return Err(SwarmError::StaleLineage);
            }
            *item = replacement.clone();
        } else {
            item.plan_revision = proposal.next_revision.clone();
        }
    }
    let next = SwarmPlanProposal {
        plan_revision: proposal.next_revision.clone(),
        root_context_revision: prior.proposal.root_context_revision.clone(),
        work_items: next_items,
        branch_roots: prior.proposal.branch_roots.clone(),
        global_wip: prior.proposal.global_wip,
        per_route_wip: prior.proposal.per_route_wip,
        reduction_fan_in: prior.proposal.reduction_fan_in,
        preserved_partition_dissent: prior.proposal.preserved_partition_dissent.clone(),
    };
    validate_plan_graph(&next)?;
    for (old, new) in prior.proposal.work_items.iter().zip(&next.work_items) {
        if !affected.contains(&old.work_item_id) {
            let mut normalized = new.clone();
            normalized.plan_revision = old.plan_revision.clone();
            if &normalized != old {
                return Err(SwarmError::UnaffectedBranchMutation);
            }
        }
    }
    let request = replan_admission_request(prior, reviews, proposal)?;
    validate_receipt(&admission_receipt, verifier, "Governor", &request)?;
    if !same_receipt_binding(&prior.admission_receipt, &admission_receipt) {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(AdmittedSwarmPlan {
        proposal: next,
        mapping_digest: prior.mapping_digest.clone(),
        provider_binding: request.binding,
        admission_receipt,
    })
}

/// One first-pass disclosure fact. Candidate/sibling-created information is
/// forbidden until the result has been sealed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureFact {
    pub reference: String,
}

/// Minimal first-pass audit packet. It intentionally has no author rationale,
/// confidence, prose summary, sibling result, or attempt-created memory field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindAuditPacket {
    pub plan_revision: RevisionId,
    pub root_context_revision: RootContextRevision,
    pub work_item_id: WorkItemId,
    pub acceptance_ref: String,
    pub candidate_digest: String,
    pub verifier_state_ref: String,
    pub preexisting_invariants: Vec<DisclosureFact>,
    pub coverage_gaps: Vec<String>,
}

/// Sealed blind first-pass result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AcceptedBlindAudit {
    packet: BlindAuditPacket,
    finding: EvidenceEnvelope,
    receipt: ReceiptEnvelope,
}

/// Seals a blind first pass while rejecting disclosure-boundary contamination.
pub fn accept_blind_audit(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    auditor_attempt_id: &AgentAttemptId,
    packet: BlindAuditPacket,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<AcceptedBlindAudit, SwarmError> {
    validate_execution_state(plan, state, verifier)?;
    if packet.plan_revision != plan.proposal.plan_revision
        || packet.root_context_revision != plan.proposal.root_context_revision
        || !plan
            .proposal
            .work_items
            .iter()
            .any(|item| item.work_item_id == packet.work_item_id)
    {
        return Err(SwarmError::StaleLineage);
    }
    let auditor = state
        .core
        .reservations
        .iter()
        .find(|reservation| &reservation.assignment.attempt.attempt_id == auditor_attempt_id)
        .ok_or(SwarmError::ReviewMismatch)?;
    if auditor.assignment.work_item.work_item_id == packet.work_item_id {
        return Err(SwarmError::BlindAuditContaminated);
    }
    for fact in &packet.preexisting_invariants {
        validate_text(&fact.reference, "disclosure_reference")?;
    }
    validate_text(&packet.acceptance_ref, "acceptance_ref")?;
    validate_text(&packet.candidate_digest, "candidate_digest")?;
    validate_text(&packet.verifier_state_ref, "verifier_state_ref")?;
    let mut binding = plan.binding_for_work(
        packet.work_item_id.clone(),
        auditor.assignment.role_id.clone(),
        auditor
            .assignment
            .attempt
            .route
            .route_id
            .as_str()
            .to_owned(),
        auditor.assignment.launch_attempt.lease.clone(),
        auditor
            .assignment
            .launch_attempt
            .work_unit
            .contract_revision
            .clone(),
    );
    binding.reviewer_attempt_id = Some(auditor_attempt_id.clone());
    let request = ProviderRequest {
        operation_kind: "swarm.blind-audit.seal".to_owned(),
        artifact_digest: digest(&packet)?,
        binding,
        replay: None,
    };
    let outcome = require_port(a02, RequiredProvider::A02)?
        .seal(&request)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
    let ProviderAttestation::Independent {
        source_assurance,
        evidence,
        sealed_before_peer_disclosure,
        all_disclosures_predate_candidate,
        no_sibling_finding_disclosed,
    } = outcome.attestation
    else {
        return Err(SwarmError::BlindAuditContaminated);
    };
    source_assurance
        .validate()
        .map_err(|_| SwarmError::Contract)?;
    evidence.validate().map_err(|_| SwarmError::Contract)?;
    if source_assurance.integrity != IntegrityStatus::Verified
        || source_assurance.freshness != FreshnessStatus::Current
        || source_assurance.independence != IndependenceLevel::Independent
        || !source_assurance
            .allowed_effects
            .contains(&SourceEffectCeiling::NoExternalEffect)
        || source_assurance.state_fence != evidence.state_fence
        || evidence.state_fence != outcome.receipt.core.work_scope.state_fence
        || !sealed_before_peer_disclosure
        || !all_disclosures_predate_candidate
        || !no_sibling_finding_disclosed
        || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
    {
        return Err(SwarmError::BlindAuditContaminated);
    }
    Ok(AcceptedBlindAudit {
        packet,
        finding: *evidence,
        receipt: outcome.receipt,
    })
}

/// A stance is preserved as lineage-bearing evidence, never counted as truth.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Stance {
    Support,
    Oppose,
    Abstain,
}

/// One inert P5 lane contribution proposal. Lineage is supplied only by A-02.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynthesisContribution {
    pub work_item_id: WorkItemId,
    pub plan_revision: RevisionId,
    pub claim_id: ClaimId,
    pub stance: Stance,
    pub evidence: EvidenceEnvelope,
}

/// Provider-sealed contribution with non-caller-mintable lineage provenance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AcceptedSynthesisContribution {
    proposal: SynthesisContribution,
    lineage_digest: String,
    request: ProviderRequest,
    receipt: ReceiptEnvelope,
}

/// Descriptive agreement only. No variant is a truth or completion verdict.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgreementShape {
    UnanimousSupport,
    MajoritySupport,
    NoMajority,
}

/// One claim group with dissent and uncertainty preserved.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SynthesizedClaim {
    claim_id: ClaimId,
    agreement: AgreementShape,
    support: Vec<SynthesisContribution>,
    dissent: Vec<SynthesisContribution>,
    abstentions: Vec<SynthesisContribution>,
    distinct_lineage_count: usize,
}

/// P5 synthesis candidate. It is never a task/release/acceptance result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SynthesisCandidate {
    plan_revision: RevisionId,
    claims: Vec<SynthesizedClaim>,
    coverage_gaps: Vec<WorkItemId>,
    covered_work_items: BTreeSet<WorkItemId>,
    lineage_digests: BTreeSet<String>,
    proof_ceiling: ProofCeiling,
    request: ProviderRequest,
    receipt: ReceiptEnvelope,
}

/// Seals one contribution and obtains its lineage only from the injected A-02
/// outcome. The proposal itself carries no lineage authority.
pub fn accept_synthesis_contribution(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    proposal: SynthesisContribution,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<AcceptedSynthesisContribution, SwarmError> {
    validate_execution_state(plan, state, verifier)?;
    proposal
        .evidence
        .validate()
        .map_err(|_| SwarmError::Contract)?;
    if proposal.plan_revision != plan.proposal.plan_revision
        || proposal.evidence.state_fence != plan.admission_receipt.core.work_scope.state_fence
        || !state
            .core
            .completed_work_items
            .contains(&proposal.work_item_id)
    {
        return Err(SwarmError::StaleLineage);
    }
    let reservation = state
        .core
        .reservations
        .iter()
        .find(|reservation| reservation.assignment.work_item.work_item_id == proposal.work_item_id)
        .ok_or(SwarmError::AssignmentMismatch)?;
    let request = assignment_request(
        plan,
        &reservation.assignment,
        "swarm.synthesis.contribution",
        digest(&proposal)?,
    );
    let outcome = require_port(a02, RequiredProvider::A02)?
        .seal(&request)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
    let ProviderAttestation::Lineage {
        lineage_digest,
        provenance_digest,
    } = outcome.attestation
    else {
        return Err(SwarmError::LineageMismatch);
    };
    validate_text(&lineage_digest, "lineage_digest")?;
    if provenance_digest != request.artifact_digest
        || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
    {
        return Err(SwarmError::LineageMismatch);
    }
    Ok(AcceptedSynthesisContribution {
        proposal,
        lineage_digest,
        request,
        receipt: outcome.receipt,
    })
}

impl SynthesisCandidate {
    /// Claim groups including preserved dissent.
    #[must_use]
    pub fn claims(&self) -> &[SynthesizedClaim] {
        &self.claims
    }

    /// Fixed candidate-only proof ceiling.
    #[must_use]
    pub const fn proof_ceiling(&self) -> ProofCeiling {
        self.proof_ceiling
    }
}

fn validate_synthesis_contribution(
    plan: &AdmittedSwarmPlan,
    contribution: &AcceptedSynthesisContribution,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<(), SwarmError> {
    contribution
        .proposal
        .evidence
        .validate()
        .map_err(|_| SwarmError::Contract)?;
    validate_text(&contribution.lineage_digest, "lineage_digest")?;
    if contribution.proposal.plan_revision != plan.proposal.plan_revision
        || contribution.request.artifact_digest != digest(&contribution.proposal)?
        || contribution.request.binding.work_item_id != contribution.proposal.work_item_id
    {
        return Err(SwarmError::StaleLineage);
    }
    if contribution.proposal.evidence.state_fence
        != plan.admission_receipt.core.work_scope.state_fence
    {
        return Err(SwarmError::BindingMismatch);
    }
    validate_receipt(
        &contribution.receipt,
        verifier,
        "A-02",
        &contribution.request,
    )?;
    if !same_receipt_binding(&plan.admission_receipt, &contribution.receipt) {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(())
}

fn reduce_claim(claim_id: ClaimId, items: Vec<&AcceptedSynthesisContribution>) -> SynthesizedClaim {
    let mut support = Vec::new();
    let mut dissent = Vec::new();
    let mut abstentions = Vec::new();
    let mut by_lineage = BTreeMap::<String, Vec<&AcceptedSynthesisContribution>>::new();
    for item in items {
        match item.proposal.stance {
            Stance::Support => support.push(item.proposal.clone()),
            Stance::Oppose => dissent.push(item.proposal.clone()),
            Stance::Abstain => abstentions.push(item.proposal.clone()),
        }
        by_lineage
            .entry(item.lineage_digest.clone())
            .or_default()
            .push(item);
    }
    let mut support_lineages = 0usize;
    let mut dissent_lineages = 0usize;
    let mut abstaining_lineages = 0usize;
    for lineage_items in by_lineage.values() {
        let stances = lineage_items
            .iter()
            .map(|item| item.proposal.stance)
            .collect::<BTreeSet<_>>();
        if stances.len() == 1 && stances.contains(&Stance::Support) {
            support_lineages += 1;
        } else if stances.len() == 1 && stances.contains(&Stance::Oppose) {
            dissent_lineages += 1;
        } else {
            abstaining_lineages += 1;
        }
    }
    let distinct_lineage_count = by_lineage.len();
    let considered = support_lineages + dissent_lineages;
    let agreement = if support_lineages >= 2 && dissent_lineages == 0 && abstaining_lineages == 0 {
        AgreementShape::UnanimousSupport
    } else if support_lineages >= 2
        && support_lineages > dissent_lineages
        && support_lineages * 2 > considered
    {
        AgreementShape::MajoritySupport
    } else {
        AgreementShape::NoMajority
    };
    SynthesizedClaim {
        claim_id,
        agreement,
        support,
        dissent,
        abstentions,
        distinct_lineage_count,
    }
}

/// P5: performs bounded lineage-aware grouping without majority-as-truth.
pub fn synthesize(
    plan: &AdmittedSwarmPlan,
    contributions: &[AcceptedSynthesisContribution],
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<SynthesisCandidate, SwarmError> {
    if contributions.len() > plan.proposal.reduction_fan_in as usize {
        return Err(SwarmError::FanInExceeded);
    }
    let expected = plan
        .proposal
        .work_items
        .iter()
        .map(|item| item.work_item_id.clone())
        .collect::<BTreeSet<_>>();
    let actual = contributions
        .iter()
        .map(|item| item.proposal.work_item_id.clone())
        .collect::<BTreeSet<_>>();
    if actual.len() != contributions.len() {
        return Err(SwarmError::Duplicate("synthesis_lanes"));
    }
    if actual != expected {
        return Err(SwarmError::OmittedLane);
    }
    let mut grouped = BTreeMap::<ClaimId, Vec<&AcceptedSynthesisContribution>>::new();
    let mut all_lineages = BTreeSet::new();
    for contribution in contributions {
        validate_synthesis_contribution(plan, contribution, verifier)?;
        all_lineages.insert(contribution.lineage_digest.clone());
        grouped
            .entry(contribution.proposal.claim_id.clone())
            .or_default()
            .push(contribution);
    }
    let claims = grouped
        .into_iter()
        .map(|(claim_id, items)| reduce_claim(claim_id, items))
        .collect();
    let request = ProviderRequest {
        operation_kind: "swarm.synthesis.verify".to_owned(),
        artifact_digest: digest(&contributions)?,
        binding: plan.provider_binding.clone(),
        replay: None,
    };
    let outcome = require_port(a02, RequiredProvider::A02)?
        .seal(&request)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    validate_provider_outcome(&outcome, verifier, "A-02", &request)?;
    if !matches!(outcome.attestation, ProviderAttestation::None)
        || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
    {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(SynthesisCandidate {
        plan_revision: plan.proposal.plan_revision.clone(),
        claims,
        coverage_gaps: Vec::new(),
        covered_work_items: actual,
        lineage_digests: all_lineages,
        proof_ceiling: SYNTHESIS_PROOF_CEILING,
        request,
        receipt: outcome.receipt,
    })
}

/// Minimal disagreement packet for a bounded Concilium comparison.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConciliumRequest {
    pub plan_revision: RevisionId,
    pub claim_id: ClaimId,
    pub rival_lineage_digests: Vec<String>,
    pub maximum_panel_size: u16,
}

/// Concilium output is only proposed next observation plus residual dissent.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ConciliumCandidate {
    claim_id: ClaimId,
    next_observation: String,
    residual_dissent: Vec<String>,
    receipt: ReceiptEnvelope,
}

/// Runs the bounded comparison admission; it never tallies a truth vote.
pub fn admit_concilium(
    plan: &AdmittedSwarmPlan,
    synthesis: &SynthesisCandidate,
    request: ConciliumRequest,
    next_observation: String,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<ConciliumCandidate, SwarmError> {
    if request.plan_revision != plan.proposal.plan_revision
        || synthesis.plan_revision != plan.proposal.plan_revision
        || !synthesis
            .claims
            .iter()
            .any(|claim| claim.claim_id == request.claim_id)
    {
        return Err(SwarmError::StaleLineage);
    }
    validate_receipt(&synthesis.receipt, verifier, "A-02", &synthesis.request)?;
    if !same_receipt_binding(&plan.admission_receipt, &synthesis.receipt) {
        return Err(SwarmError::BindingMismatch);
    }
    if request.maximum_panel_size == 0
        || u32::from(request.maximum_panel_size) > plan.proposal.reduction_fan_in
        || request.rival_lineage_digests.len() > usize::from(request.maximum_panel_size)
    {
        return Err(SwarmError::FanInExceeded);
    }
    validate_text(&next_observation, "next_observation")?;
    let distinct_rivals = request
        .rival_lineage_digests
        .iter()
        .collect::<BTreeSet<_>>();
    if distinct_rivals.len() != request.rival_lineage_digests.len() {
        return Err(SwarmError::Duplicate("concilium_lineages"));
    }
    for lineage in &request.rival_lineage_digests {
        validate_text(lineage, "rival_lineage_digest")?;
        if !synthesis.lineage_digests.contains(lineage) {
            return Err(SwarmError::LineageMismatch);
        }
    }
    let provider_request = ProviderRequest {
        operation_kind: "swarm.concilium.admit".to_owned(),
        artifact_digest: digest(&(&request, &synthesis.receipt.identity))?,
        binding: plan.provider_binding.clone(),
        replay: None,
    };
    let outcome = require_port(a02, RequiredProvider::A02)?
        .seal(&provider_request)
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    validate_provider_outcome(&outcome, verifier, "A-02", &provider_request)?;
    if !matches!(outcome.attestation, ProviderAttestation::None)
        || !same_receipt_binding(&plan.admission_receipt, &outcome.receipt)
    {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(ConciliumCandidate {
        claim_id: request.claim_id,
        next_observation,
        residual_dissent: request.rival_lineage_digests,
        receipt: outcome.receipt,
    })
}

/// Provider-owned cursor and monotonic rollback floor.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCursor {
    pub current: u64,
    pub monotonic_floor: u64,
}

/// Reduction/coverage facts derived from an accepted synthesis, never caller
/// supplied checkpoint authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionSnapshot {
    synthesis_digest: String,
    covered_work_items: BTreeSet<WorkItemId>,
    lineage_digests: BTreeSet<String>,
    no_majority_claims: BTreeSet<ClaimId>,
}

/// Serializable restart state. Acceptance still requires the exact injected
/// M-04 provider receipt and its current provider-owned cursor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerSnapshot {
    pub snapshot_id: SnapshotId,
    pub controller_id: ControllerId,
    pub sequence: u64,
    pub provider_cursor: u64,
    pub monotonic_floor: u64,
    pub binding: ProviderBinding,
    pub execution_state: ExecutionState,
    pub wave_revision: Option<RevisionId>,
    pub completed_work_items: BTreeSet<WorkItemId>,
    pub reduction: Option<ReductionSnapshot>,
    pub provider_identity: String,
    pub digest: String,
}

/// Provider-returned immutable checkpoint plus the receipt/cursor that bind it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCommit {
    pub snapshot: ControllerSnapshot,
    pub receipt: ReceiptEnvelope,
    pub cursor: CheckpointCursor,
}

/// Caller can choose identities only; all causal state is derived and sealed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerCheckpointInput {
    pub snapshot_id: SnapshotId,
    pub controller_id: ControllerId,
}

/// Injected providers used by one checkpoint transition.
#[derive(Clone, Copy)]
pub struct CheckpointProviders<'a> {
    pub a02: Option<&'a dyn AgentRouteProvider>,
    pub m04: Option<&'a dyn SwarmCheckpointProvider>,
    pub verifier: Option<&'a dyn ReceiptVerificationPort>,
}

fn snapshot_digest(snapshot: &ControllerSnapshot) -> Result<String, SwarmError> {
    let mut unsigned = snapshot.clone();
    unsigned.digest.clear();
    digest(&unsigned)
}

fn checkpoint_request(
    plan: &AdmittedSwarmPlan,
    operation_kind: &str,
    snapshot: &ControllerSnapshot,
) -> ProviderRequest {
    ProviderRequest {
        operation_kind: operation_kind.to_owned(),
        artifact_digest: snapshot.digest.clone(),
        binding: plan.provider_binding.clone(),
        replay: Some(ReplayBinding {
            stream_id: format!("swarm.checkpoint:{}", snapshot.provider_identity),
            prior_cursor: snapshot.sequence.saturating_sub(1),
            next_cursor: snapshot.sequence,
        }),
    }
}

fn validate_snapshot(
    plan: &AdmittedSwarmPlan,
    snapshot: &ControllerSnapshot,
    cursor: CheckpointCursor,
    a02: &dyn AgentRouteProvider,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<(), SwarmError> {
    if snapshot.sequence == 0
        || snapshot.sequence != snapshot.provider_cursor
        || snapshot.sequence != cursor.current
        || snapshot.monotonic_floor != cursor.monotonic_floor
        || cursor.monotonic_floor > cursor.current
        || snapshot.binding != plan.provider_binding
        || snapshot.binding.plan_revision != plan.proposal.plan_revision
        || snapshot.binding.root_context_revision != plan.proposal.root_context_revision
        || snapshot.digest != snapshot_digest(snapshot)?
        || snapshot.completed_work_items != snapshot.execution_state.core.completed_work_items
    {
        return Err(SwarmError::InvalidSnapshot);
    }
    validate_execution_state(plan, &snapshot.execution_state, verifier)?;
    let execution_cursor = a02
        .current_cursor(&execution_stream(plan))
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    if execution_cursor != snapshot.execution_state.core.transition_sequence {
        return Err(SwarmError::ReplayDetected);
    }
    if let Some(reduction) = &snapshot.reduction {
        let plan_ids = plan
            .proposal
            .work_items
            .iter()
            .map(|item| item.work_item_id.clone())
            .collect::<BTreeSet<_>>();
        if !reduction.covered_work_items.is_subset(&plan_ids)
            || reduction.lineage_digests.is_empty()
        {
            return Err(SwarmError::InvalidSnapshot);
        }
    }
    Ok(())
}

/// Creates and durably seals a complete restart checkpoint through M-04.
pub fn checkpoint_controller(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    wave: Option<&AdmittedWave>,
    synthesis: Option<&SynthesisCandidate>,
    input: ControllerCheckpointInput,
    providers: CheckpointProviders<'_>,
) -> Result<ControllerSnapshot, SwarmError> {
    let a02 = require_port(providers.a02, RequiredProvider::A02)?;
    validate_execution_state(plan, state, providers.verifier)?;
    let execution_cursor = a02
        .current_cursor(&execution_stream(plan))
        .map_err(|error| provider_error(RequiredProvider::A02, error))?;
    if execution_cursor != state.core.transition_sequence {
        return Err(SwarmError::ReplayDetected);
    }
    if wave.is_some_and(|wave| {
        wave.plan_revision != plan.proposal.plan_revision
            || wave.transition_sequence > state.core.transition_sequence
            || wave.assignments.iter().any(|assignment| {
                !state.core.reservations.iter().any(|reservation| {
                    reservation.assignment.attempt.attempt_id == assignment.attempt.attempt_id
                })
            })
    }) {
        return Err(SwarmError::InvalidSnapshot);
    }
    if let Some(candidate) = synthesis {
        validate_receipt(
            &candidate.receipt,
            providers.verifier,
            "A-02",
            &candidate.request,
        )?;
        if candidate.plan_revision != plan.proposal.plan_revision
            || !same_receipt_binding(&plan.admission_receipt, &candidate.receipt)
        {
            return Err(SwarmError::BindingMismatch);
        }
    }
    let m04 = require_port(providers.m04, RequiredProvider::M04)?;
    validate_text(m04.provider_identity(), "provider_identity")?;
    let prior = m04
        .cursor()
        .map_err(|error| provider_error(RequiredProvider::M04, error))?;
    if prior.monotonic_floor > prior.current {
        return Err(SwarmError::InvalidSnapshot);
    }
    let sequence = prior
        .current
        .checked_add(1)
        .ok_or(SwarmError::InvalidSnapshot)?;
    let reduction = synthesis.map(|candidate| ReductionSnapshot {
        synthesis_digest: candidate.request.artifact_digest.clone(),
        covered_work_items: candidate.covered_work_items.clone(),
        lineage_digests: candidate.lineage_digests.clone(),
        no_majority_claims: candidate
            .claims
            .iter()
            .filter_map(|claim| {
                (claim.agreement == AgreementShape::NoMajority).then_some(claim.claim_id.clone())
            })
            .collect(),
    });
    let mut snapshot = ControllerSnapshot {
        snapshot_id: input.snapshot_id,
        controller_id: input.controller_id,
        sequence,
        provider_cursor: sequence,
        monotonic_floor: prior.monotonic_floor,
        binding: plan.provider_binding.clone(),
        execution_state: state.clone(),
        wave_revision: wave.map(|value| value.wave_revision.clone()),
        completed_work_items: state.core.completed_work_items.clone(),
        reduction,
        provider_identity: m04.provider_identity().to_owned(),
        digest: String::new(),
    };
    snapshot.digest = snapshot_digest(&snapshot)?;
    let commit = m04
        .persist(&snapshot)
        .map_err(|error| provider_error(RequiredProvider::M04, error))?;
    if commit.snapshot != snapshot
        || commit.cursor.current != sequence
        || commit.cursor.monotonic_floor != snapshot.monotonic_floor
        || commit.cursor.monotonic_floor > commit.cursor.current
    {
        return Err(SwarmError::InvalidSnapshot);
    }
    let request = checkpoint_request(plan, "swarm.controller.checkpoint", &snapshot);
    validate_receipt(&commit.receipt, providers.verifier, "M-04", &request)?;
    if !same_receipt_binding(&plan.admission_receipt, &commit.receipt) {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(snapshot)
}

/// Restores the provider's current snapshot; no caller-supplied replay floor is
/// accepted as authority.
pub fn restore_controller(
    plan: &AdmittedSwarmPlan,
    snapshot_id: &SnapshotId,
    a02: Option<&dyn AgentRouteProvider>,
    m04: Option<&dyn SwarmCheckpointProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<ControllerSnapshot, SwarmError> {
    let a02 = require_port(a02, RequiredProvider::A02)?;
    let m04 = require_port(m04, RequiredProvider::M04)?;
    let commit = m04
        .restore(snapshot_id)
        .map_err(|error| provider_error(RequiredProvider::M04, error))?;
    let current = m04
        .cursor()
        .map_err(|error| provider_error(RequiredProvider::M04, error))?;
    let snapshot = &commit.snapshot;
    if &snapshot.snapshot_id != snapshot_id
        || snapshot.provider_identity != m04.provider_identity()
        || commit.cursor != current
        || snapshot.sequence != current.current
        || snapshot.sequence < current.monotonic_floor
    {
        return Err(SwarmError::InvalidSnapshot);
    }
    validate_snapshot(plan, snapshot, current, a02, verifier)?;
    let request = checkpoint_request(plan, "swarm.controller.restore", snapshot);
    validate_receipt(&commit.receipt, verifier, "M-04", &request)?;
    if !same_receipt_binding(&plan.admission_receipt, &commit.receipt) {
        return Err(SwarmError::BindingMismatch);
    }
    Ok(snapshot.clone())
}

/// Durable staged work and the no-lost-child state machine (issue #698).
///
/// Caller: an [`durable_work::AdmittedWorkDefinition`] (admitted definition
/// plus Governor admission receipt) together with the accepted #694 route
/// path and #696 peer contracts projected as injected ports. Implementation:
/// this module — admitted-not-staged → staged-not-assigned → singular
/// assigned ownership → launch-requested/unknown → launched/attached/running
/// with lease → heartbeat/renewal → checkpoint → cancellation/drain/handoff →
/// completion candidate awaiting external verification → exact terminal,
/// proved-no-effect, possible-effect-uncertain, or lost-child reconciliation.
/// Consumer: `tests/durable_work.rs` (deterministic fake owners) and, later,
/// the #872 durable control wire.
///
/// Durable-job attachment and admitted child-dispatch lineage (issue #1126).
/// See [`durable_dispatch`] for the binding rules.
pub mod durable_dispatch;
/// Production swarm consumption of Governor-owned plan attachment (issue
/// #2017 item 6). New production callers attach through
/// [`swarm_plan_attachment_consumer`] over a Governor-vended consumer port;
/// [`durable_dispatch`] remains the in-crate primitive over a caller-supplied
/// ledger.
pub mod swarm_plan_attachment_consumer;
/// The cell stays stateless: [`durable_work::DurableWorkMachine`] is a
/// transient interpreter over records owned by the injected
/// [`durable_work::DurableWorkStore`]. It owns no process, route, task,
/// authority, or persistence state. Every durable transition is appended to
/// the store before it becomes visible, and the stable launch operation plus
/// `AgentAttempt` registration are persisted before the injected
/// [`durable_work::WorkExecutor`] is ever called, so a crash between intent
/// and outcome always reconciles by stable operation/process identity instead
/// of losing the child or inventing completion.
pub mod durable_work {
    use std::collections::{BTreeMap, BTreeSet};

    use eliot_agent_api::WorkLeaseId;
    use eliot_agent_contracts::AgentAttemptId;
    use eliot_receipts::{EffectClass, ProofCeiling, ReceiptDisposition, ReceiptEnvelope};
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    use super::{
        ClaimId, ProviderError, ReceiptVerificationPort, RequiredProvider, SwarmError, digest,
        validate_text,
    };

    /// Schema version pinned into every durable record. A reload that observes
    /// any other version quarantines instead of guessing.
    pub const DURABLE_WORK_SCHEMA_VERSION: u32 = 1;
    /// Proof ceiling of an emitted execution candidate: candidate only, never
    /// a task finish or verified artifact.
    pub const WORK_CANDIDATE_CEILING: ProofCeiling = ProofCeiling::CandidateArtifact;
    /// Digest chained before the first record of a work unit.
    pub const GENESIS_DIGEST: &str = "genesis";
    /// Operation kind sealed by the Governor admission receipt.
    pub const ADMIT_OPERATION_KIND: &str = "durable.work.admit";
    /// Owner recorded on every admission receipt consumed here.
    pub const ADMISSION_OWNER: &str = "Governor";

    /// Opaque durable work-unit identity.
    #[derive(
        Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(try_from = "String", into = "String")]
    pub struct WorkUnitId(String);

    impl WorkUnitId {
        /// Creates a non-blank opaque identity.
        pub fn new(value: impl Into<String>) -> Result<Self, SwarmError> {
            let value = value.into();
            validate_text(&value, "WorkUnitId")?;
            Ok(Self(value))
        }

        /// Returns the stable text form.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl TryFrom<String> for WorkUnitId {
        type Error = SwarmError;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            Self::new(value)
        }
    }

    impl From<WorkUnitId> for String {
        fn from(value: WorkUnitId) -> Self {
            value.0
        }
    }

    /// One durable lifecycle phase. Planning facts, cancellation requests and
    /// completion candidates are orthogonal facts, never invented competing
    /// canonical job states; the canonical I14.20 counterpart of each phase is
    /// listed in [`phase_inventory`].
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum WorkUnitPhase {
        AdmittedNotStaged,
        StagedNotAssigned,
        Assigned,
        LaunchRequested,
        LaunchNotAttempted,
        Running,
        Checkpointed,
        CancellationRequested,
        CompletionCandidate,
        Terminal,
        UnknownOutcome,
        Quarantined,
    }

    impl WorkUnitPhase {
        /// Whether the phase ends the normal lifecycle. `UnknownOutcome` and
        /// `Quarantined` are not terminal: they stay blocked for reconcile or
        /// safe restart instead of freeing anything.
        #[must_use]
        pub const fn is_terminal(self) -> bool {
            matches!(self, Self::LaunchNotAttempted | Self::Terminal)
        }
    }

    /// Exact terminal outcome. One terminal flag never erases the distinctions
    /// below: proved-no-effect, exhaustion, pre-launch versus post-effect
    /// cancellation, and partial coverage stay separate.
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum TerminalKind {
        Completed,
        FailedProvedNoEffect,
        FailedExhausted,
        CancelledBeforeLaunch,
        CancelledAfterEffect,
        Partial,
    }

    /// Certainty about effects the child may have produced. Ambiguous effect
    /// stays [`EffectCertainty::PossibleEffect`] until reconciliation proves
    /// otherwise; it never defaults to no-effect.
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum EffectCertainty {
        NoEffect,
        ProvedNoEffect,
        PossibleEffect,
    }

    impl EffectCertainty {
        /// Monotonic rank used by the seeded-sequence invariant: certainty may
        /// only move from none toward proved or possible, never back.
        #[must_use]
        pub const fn rank(self) -> u8 {
            match self {
                Self::NoEffect => 0,
                Self::ProvedNoEffect | Self::PossibleEffect => 1,
            }
        }
    }

    /// Independent budget dimension. Spent, reserved and remaining are tracked
    /// separately per dimension; one dimension over by one still rejects even
    /// when the others are untouched.
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum BudgetDimension {
        ComputeSteps,
        CostMicrounits,
        EvidenceBytes,
    }

    /// Admitted budget bound for one dimension.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BudgetSpec {
        pub dimension: BudgetDimension,
        pub limit: u64,
    }

    /// Live account for one dimension.
    #[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BudgetAccount {
        pub limit: u64,
        pub reserved: u64,
        pub spent: u64,
    }

    impl BudgetAccount {
        fn remaining(self) -> u64 {
            self.limit
                .saturating_sub(self.reserved)
                .saturating_sub(self.spent)
        }
    }

    /// Singular owner bound through its real owner: worker, process and lease.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OwnerBinding {
        pub worker_id: String,
        pub process_id: String,
        pub lease: WorkLeaseId,
    }

    /// One dependency that must carry accepted evidence before staging. A
    /// candidate or closed issue without evidence cannot satisfy it.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DependencyRef {
        pub work_id: WorkUnitId,
        pub evidence_digest: String,
    }

    /// Caller-side admitted definition plus the Governor admission receipt.
    /// This is the only entry point: stage/assign only after the exact
    /// admitted definition, accepted dependency evidence, scope/fence and
    /// budgets.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AdmittedWorkDefinition {
        pub work_id: WorkUnitId,
        pub parent_task_id: String,
        pub cell_id: String,
        pub attempt_ref: String,
        pub task_id: String,
        pub session_id: String,
        pub task_revision: String,
        pub payload_digest: String,
        pub input_revision: String,
        pub scope_id: String,
        pub state_fence_digest: String,
        pub authority_epoch: u64,
        pub term: u64,
        pub dependencies: Vec<DependencyRef>,
        pub budgets: Vec<BudgetSpec>,
        pub route_class: String,
        pub max_retries: u32,
        pub max_children: u32,
        pub max_depth: u32,
        pub max_pending_reviews: u32,
        pub evidence_required: bool,
        pub receipt_contract_revision: String,
        pub admission_receipt: ReceiptEnvelope,
    }

    /// Route grant consumed from the accepted #694 search/admission path. The
    /// machine looks each distinct request up once and persists the exact
    /// grant; staleness blocks launch without any local fallback.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RouteGrant {
        pub route_id: String,
        pub fingerprint: String,
        pub evidence_digest: String,
        pub generation: u64,
        pub stale: bool,
    }

    /// Route lookup request projected from the accepted catalogue path.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RouteRequest {
        pub route_class: String,
        pub requirements_digest: String,
        pub fence_digest: String,
        pub epoch: u64,
    }

    /// Accepted route catalogue/admission path (issue #694 consumer port).
    /// Implementations must serve the catalogue owner; this cell never invents
    /// a temporary route owner or a local model switch.
    pub trait RouteCatalogue: Send + Sync {
        /// Returns the current grant for one exact route request.
        fn lookup(&self, request: &RouteRequest) -> Result<RouteGrant, ProviderError>;
    }

    /// Stable launch operation plus `AgentAttempt` registration. Persisted
    /// before the external executor call; reconciliation keys off this stable
    /// identity, never off a guessed child handle.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LaunchIntent {
        pub operation_id: String,
        pub attempt_id: AgentAttemptId,
        pub work_id: WorkUnitId,
        pub route_id: String,
        pub route_fingerprint: String,
        pub lease: WorkLeaseId,
        pub term: u64,
        pub epoch: u64,
        pub fence_digest: String,
    }

    /// Stable external child identity: operation-stable child id plus the
    /// process/session identity observed at the executor boundary.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ChildHandle {
        pub child_id: String,
        pub process_identity: String,
    }

    /// What the executor boundary reported about effects on exit. A returned
    /// process status is never semantic completion on its own.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum ExitEffects {
        ProvedNoEffect { proof_digest: String },
        PossibleEffect { detail: String },
        CleanWithArtifacts { artifacts_digest: String },
    }

    /// Observed process exit: status plus effect evidence.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ExitRecord {
        pub child: ChildHandle,
        pub process_status: u32,
        pub effects: ExitEffects,
    }

    /// Executor launch outcome. Refused/not-attempted, started and unknown
    /// stay distinct: only unknown keeps the scope blocked for reconcile.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum LaunchOutcome {
        Refused { reason: String },
        Started { child: ChildHandle },
        Unknown,
    }

    /// Executor observation outcome.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum ObserveOutcome {
        Running { child: ChildHandle },
        Exited { exit: ExitRecord },
        Unknown,
    }

    /// Executor cancellation outcome.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum CancelOutcome {
        CancelledBeforeStart,
        CancelRequested { child: ChildHandle },
        Unknown,
    }

    /// External child-launch/observe/cancel owner (issue #698 executor port).
    /// The cell never forks a process or invokes a provider itself.
    pub trait WorkExecutor: Send + Sync {
        /// Attempts one launch for a previously persisted intent.
        fn launch(&self, intent: &LaunchIntent) -> Result<LaunchOutcome, ProviderError>;
        /// Observes one child by stable handle.
        fn observe(&self, child: &ChildHandle) -> Result<ObserveOutcome, ProviderError>;
        /// Observes by stable operation/attempt identity (lost-handle path).
        fn observe_attempt(
            &self,
            attempt_id: &AgentAttemptId,
        ) -> Result<ObserveOutcome, ProviderError>;
        /// Requests cancellation through the external cancel owner.
        fn cancel(&self, child: &ChildHandle) -> Result<CancelOutcome, ProviderError>;
    }

    /// Durable receipt echoed by the persistence owner for one appended record.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct StoreReceipt {
        pub sequence: u64,
        pub digest: String,
    }

    /// Existing persistence owner port (durable staged-work store). Restart
    /// safety belongs to this owner; deterministic fake owners prove the state
    /// protocol, not disk behavior.
    pub trait DurableWorkStore: Send + Sync {
        /// Appends one immutable record and echoes its durable identity.
        fn append(&self, record: &DurableWorkRecord) -> Result<StoreReceipt, ProviderError>;
        /// Loads the full ordered record log for one work unit.
        fn load(&self, work_id: &WorkUnitId) -> Result<Vec<DurableWorkRecord>, ProviderError>;
    }

    /// Peer message kind (issue #696 consumer projection).
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum PeerMessageKind {
        Finding,
        ResultNotice,
        ReviewItem,
        CancelNotice,
    }

    /// Peer message bound to exact work/artifact/revision/sequence.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PeerMessage {
        pub work_id: WorkUnitId,
        pub artifact_id: String,
        pub artifact_revision: String,
        pub sequence: u64,
        pub kind: PeerMessageKind,
        pub payload_digest: String,
    }

    /// Peer delivery receipt. Acknowledgement grants no scope and no finish.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PeerReceipt {
        pub message_id: String,
        pub sequence: u64,
    }

    /// Mailbox/blackboard peer-delivery projection (issue #696 consumer port).
    pub trait PeerChannel: Send + Sync {
        /// Durably admits one peer message and returns its delivery receipt.
        fn post(&self, message: &PeerMessage) -> Result<PeerReceipt, ProviderError>;
    }

    /// Anchored review lifecycle (I10.18 projection). Delivery or answer never
    /// implies resolution; expired/overflowed required reviews stay visible
    /// and can prevent closure.
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum ReviewState {
        Delivered,
        Answered,
        Resolved,
        RejectedWithReason,
        Stale,
        Superseded,
        Expired,
        Overflowed,
    }

    /// One anchored review item bound to an exact artifact revision.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReviewRecord {
        pub review_id: ClaimId,
        pub artifact_id: String,
        pub artifact_revision: String,
        pub required: bool,
        pub state: ReviewState,
    }

    /// Review proposal posted through the peer channel.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReviewProposal {
        pub review_id: ClaimId,
        pub artifact_id: String,
        pub artifact_revision: String,
        pub required: bool,
        pub content_digest: String,
    }

    /// Posted peer message plus its delivery receipt.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PostedPeerMessage {
        pub message: PeerMessage,
        pub receipt: PeerReceipt,
    }

    /// Cancellation phase: a request is persisted first, then the external
    /// cancel owner is called and observed. Before-launch cancellation is
    /// distinct from possible execution.
    #[derive(
        Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
    )]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum CancellationPhase {
        NotRequested,
        Requested,
        Observed,
    }

    /// Launch registration persisted before the executor call.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PersistedLaunch {
        pub operation_id: String,
        pub attempt_id: AgentAttemptId,
        pub child: Option<ChildHandle>,
        pub executor_called: bool,
    }

    /// Checkpoint binding all input/route/tool/scope/fence/revision plus the
    /// exact remaining work, evidence, budgets and digest.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WorkCheckpoint {
        pub checkpoint_id: String,
        pub input_digest: String,
        pub route_fingerprint: String,
        pub revision: String,
        pub remaining_work: Vec<String>,
        pub evidence_digest: String,
    }

    /// Heartbeat/renewal signal. Requires the exact current worker, lease,
    /// term, epoch and fence plus a monotonic replay-safe sequence.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatSignal {
        pub worker_id: String,
        pub lease: WorkLeaseId,
        pub term: u64,
        pub epoch: u64,
        pub fence_digest: String,
        pub sequence: u64,
    }

    /// Worker result submission. Binds the exact current lease and term so a
    /// stale result can never complete a new ownership; the accepted result
    /// becomes a verification candidate, never completion or finish.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WorkerResult {
        pub lease: WorkLeaseId,
        pub term: u64,
        pub artifacts_digest: String,
        pub evidence_digest: Option<String>,
        pub output_ref: String,
    }

    /// One immutable durable record. Closed records reject unknown
    /// fields/versions; every transition binds plan, work unit, cell,
    /// parent-task, attempt, child, mutable-claim digest, scope, fence,
    /// epoch, term, monotonic sequence, operation idempotency, admitted route
    /// receipt, owner-issued worker/process/lease, budgets, input/artifact/
    /// source revision, checkpoint/predecessor, effect certainty,
    /// cancel/deadline and evidence digest.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DurableWorkRecord {
        pub schema_version: u32,
        pub work_id: WorkUnitId,
        pub sequence: u64,
        pub phase: WorkUnitPhase,
        pub terminal: Option<TerminalKind>,
        pub definition_digest: String,
        pub payload_digest: String,
        pub parent_task_id: String,
        pub cell_id: String,
        pub attempt_ref: String,
        pub task_id: String,
        pub session_id: String,
        pub scope_id: String,
        pub state_fence_digest: String,
        pub authority_epoch: u64,
        pub term: u64,
        pub owner: Option<OwnerBinding>,
        pub route: Option<RouteGrant>,
        pub route_class: String,
        pub dependencies: Vec<DependencyRef>,
        pub launch: Option<PersistedLaunch>,
        pub effect: EffectCertainty,
        pub budgets: BTreeMap<BudgetDimension, BudgetAccount>,
        pub max_retries: u32,
        pub max_children: u32,
        pub max_depth: u32,
        pub max_pending_reviews: u32,
        pub evidence_required: bool,
        pub depth: u32,
        pub retry_count: u32,
        pub timeout_count: u32,
        pub heartbeat_sequence: u64,
        pub checkpoint: Option<WorkCheckpoint>,
        pub cancellation: CancellationPhase,
        pub parent: Option<WorkUnitId>,
        pub children: BTreeSet<WorkUnitId>,
        pub reviews: Vec<ReviewRecord>,
        pub messages: Vec<PostedPeerMessage>,
        pub last_exit: Option<ExitRecord>,
        pub result_digest: Option<String>,
        pub message_sequence: u64,
        pub prev_digest: String,
        pub digest: String,
        pub operation_key: String,
    }

    /// Injected owners used by one durable work machine.
    #[derive(Clone, Copy)]
    pub struct DurablePorts<'a> {
        pub store: Option<&'a dyn DurableWorkStore>,
        pub executor: Option<&'a dyn WorkExecutor>,
        pub catalogue: Option<&'a dyn RouteCatalogue>,
        pub peer: Option<&'a dyn PeerChannel>,
        pub verifier: Option<&'a dyn ReceiptVerificationPort>,
    }

    /// Child disposition derived from the live child record: terminal kinds
    /// pass through, live or unreachable children stay open, and possible
    /// effect stays blocked.
    #[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum ChildDisposition {
        Running,
        Terminal(TerminalKind),
        UnknownBlocked,
        Stale,
    }

    /// Parent execution candidate emitted only over a complete child
    /// denominator with one disposition per child. Candidate only: never a
    /// task finish.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ParentCandidate {
        pub parent_id: WorkUnitId,
        pub denominator: BTreeMap<WorkUnitId, TerminalKind>,
        pub candidate_digest: String,
        pub proof_ceiling: ProofCeiling,
    }

    /// Bounded retry outcome.
    #[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum RetryOutcome {
        Scheduled,
        Exhausted,
    }

    /// External verification verdict over a completion candidate. Only the
    /// external verifier owns this disposition; the cell only records it.
    #[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum ExternalVerdict {
        VerifiedComplete,
        PartialCoverage,
        FailedVerification,
        CancelledExternal,
    }

    /// Lost-child reconciliation outcome keyed by stable operation/process
    /// identity.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum ReconcileOutcome {
        Reattached,
        ExitedApplied,
        ProvedNoEffectTerminal,
        StillUnknownBlocked,
        StaleIgnored,
        AlreadyApplied,
        AlreadyTerminal,
        NoChildToReconcile,
    }

    /// Recovery outcome after an uncertain persistence response.
    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum UncertainPersistOutcome {
        Recovered,
    }

    /// Canonical I14.20 counterpart of every durable phase. Planning facts,
    /// cancellation requests and completion candidates are orthogonal facts,
    /// not competing canonical job states.
    #[must_use]
    pub fn phase_inventory() -> Vec<(WorkUnitPhase, &'static str)> {
        vec![
            (
                WorkUnitPhase::AdmittedNotStaged,
                "I14.20 RunAttempt:ADMITTED (admitted, not provisioned)",
            ),
            (
                WorkUnitPhase::StagedNotAssigned,
                "I14.20 ReadyWorkItem:ADMITTED + AdmissionReservation:STAGED_INACTIVE",
            ),
            (
                WorkUnitPhase::Assigned,
                "I14.20 AdmissionReservation:ACTIVE (ownership bound, pre-provisioning)",
            ),
            (
                WorkUnitPhase::LaunchRequested,
                "I14.20 RunAttempt:LAUNCHING (intent persisted, outcome unknown)",
            ),
            (
                WorkUnitPhase::LaunchNotAttempted,
                "I14.20 orthogonal fact: refused pre-provisioning, terminal not-attempted",
            ),
            (
                WorkUnitPhase::Running,
                "I14.20 RunAttempt:RUNNING (lease-bound)",
            ),
            (
                WorkUnitPhase::Checkpointed,
                "I14.20 DurableJob:CHECKPOINTED overlay on RunAttempt:RUNNING",
            ),
            (
                WorkUnitPhase::CancellationRequested,
                "I14.20 orthogonal fact on RunAttempt:RUNNING (requested, not observed)",
            ),
            (
                WorkUnitPhase::CompletionCandidate,
                "I14.20 IntegrationCandidate:PROPOSED (awaiting external verification)",
            ),
            (
                WorkUnitPhase::Terminal,
                "I14.20 RunAttempt terminal history (COMPLETED/PARTIAL/FAILED/CANCELLED)",
            ),
            (
                WorkUnitPhase::UnknownOutcome,
                "I14.20 ORS Operation:UNKNOWN_OUTCOME then RECONCILING (scope blocked)",
            ),
            (
                WorkUnitPhase::Quarantined,
                "I14.20 Problem/Incident:QUARANTINED overlay (stale/ownership/checkpoint)",
            ),
        ]
    }

    /// Canonical counterpart of every exact terminal kind.
    #[must_use]
    pub fn terminal_inventory() -> Vec<(TerminalKind, &'static str)> {
        vec![
            (
                TerminalKind::Completed,
                "I14.20 RunAttempt:COMPLETED (immutable history)",
            ),
            (
                TerminalKind::FailedProvedNoEffect,
                "I14.20 RunAttempt:FAILED with proved-no-effect receipt",
            ),
            (
                TerminalKind::FailedExhausted,
                "I14.20 RunAttempt:FAILED (bounded retry exhausted)",
            ),
            (
                TerminalKind::CancelledBeforeLaunch,
                "I14.20 ORS Operation:RESOLVED(cancelled) with proven no-effect",
            ),
            (
                TerminalKind::CancelledAfterEffect,
                "I14.20 RunAttempt:CANCELLED after observed effect",
            ),
            (
                TerminalKind::Partial,
                "I14.20 RunAttempt:PARTIAL with explicit coverage",
            ),
        ]
    }

    fn definition_digest(definition: &AdmittedWorkDefinition) -> Result<String, SwarmError> {
        digest(&(
            (
                &definition.work_id,
                &definition.parent_task_id,
                &definition.cell_id,
                &definition.attempt_ref,
                &definition.task_id,
                &definition.session_id,
                &definition.task_revision,
                &definition.payload_digest,
            ),
            (
                &definition.input_revision,
                &definition.scope_id,
                &definition.state_fence_digest,
                definition.authority_epoch,
                definition.term,
                &definition.dependencies,
                &definition.budgets,
                &definition.route_class,
            ),
            (
                definition.max_retries,
                definition.max_children,
                definition.max_depth,
                definition.max_pending_reviews,
                definition.evidence_required,
                &definition.receipt_contract_revision,
            ),
        ))
    }

    fn validate_definition_text(definition: &AdmittedWorkDefinition) -> Result<(), SwarmError> {
        for (field, value) in [
            ("parent_task_id", definition.parent_task_id.as_str()),
            ("cell_id", definition.cell_id.as_str()),
            ("attempt_ref", definition.attempt_ref.as_str()),
            ("task_id", definition.task_id.as_str()),
            ("session_id", definition.session_id.as_str()),
            ("task_revision", definition.task_revision.as_str()),
            ("payload_digest", definition.payload_digest.as_str()),
            ("input_revision", definition.input_revision.as_str()),
            ("scope_id", definition.scope_id.as_str()),
            ("state_fence_digest", definition.state_fence_digest.as_str()),
            ("route_class", definition.route_class.as_str()),
            (
                "receipt_contract_revision",
                definition.receipt_contract_revision.as_str(),
            ),
        ] {
            validate_text(value, field)?;
        }
        if definition.budgets.is_empty() {
            return Err(SwarmError::Empty("budgets"));
        }
        let dimensions = definition
            .budgets
            .iter()
            .map(|spec| spec.dimension)
            .collect::<BTreeSet<_>>();
        if dimensions.len() != definition.budgets.len() {
            return Err(SwarmError::Duplicate("budgets"));
        }
        for spec in &definition.budgets {
            if spec.limit == 0 {
                return Err(SwarmError::Contract);
            }
        }
        // Dependency evidence is deliberately NOT checked here: an admitted
        // definition with an incomplete dependency is retained, and staging
        // blocks until accepted evidence arrives.
        Ok(())
    }

    fn validate_admission_receipt(
        definition: &AdmittedWorkDefinition,
        verifier: Option<&dyn ReceiptVerificationPort>,
    ) -> Result<(), SwarmError> {
        let receipt = &definition.admission_receipt;
        receipt.validate().map_err(|_| SwarmError::InvalidReceipt)?;
        let verifier = verifier.ok_or(SwarmError::PlanGap(RequiredProvider::ReceiptVerifier))?;
        verifier
            .verify(receipt)
            .map_err(|error| SwarmError::Provider {
                provider: RequiredProvider::ReceiptVerifier,
                source: error,
            })?;
        let core = &receipt.core;
        let ReceiptDisposition::Success { proof } = core.disposition else {
            return Err(SwarmError::InvalidReceipt);
        };
        let task = core.task.as_ref().ok_or(SwarmError::BindingMismatch)?;
        let session = core.session.as_ref().ok_or(SwarmError::BindingMismatch)?;
        if proof != ProofCeiling::ScopedVerification
            || core.authority.authority_owner != ADMISSION_OWNER
            || core.authority.allowed_effect != EffectClass::Read
            || core.operation.effect != EffectClass::Read
            || core.operation.operation_kind != ADMIT_OPERATION_KIND
            || core.verifier.is_none()
            || task.task_id.to_string() != definition.task_id
            || task.task_revision.value().to_string() != definition.task_revision
            || session.session_id.to_string() != definition.session_id
            || core.work_scope.scope_id.as_str() != definition.scope_id
            || digest(&core.work_scope.state_fence)? != definition.state_fence_digest
            || core.contract.version.to_string() != definition.receipt_contract_revision
            || core
                .request
                .metadata
                .task_id
                .as_ref()
                .map(ToString::to_string)
                != Some(definition.task_id.clone())
            || core
                .request
                .metadata
                .session_id
                .as_ref()
                .map(ToString::to_string)
                != Some(definition.session_id.clone())
            || !core
                .artifacts
                .iter()
                .any(|artifact| artifact.sha256 == definition.payload_digest)
        {
            return Err(SwarmError::BindingMismatch);
        }
        Ok(())
    }

    fn record_digest(record: &DurableWorkRecord) -> Result<String, SwarmError> {
        let mut unsigned = record.clone();
        unsigned.digest.clear();
        digest(&unsigned)
    }

    /// Replays an ordered record log into its tip. Duplicate trailing delivery
    /// of the exact tip is idempotent; gaps, reorders, digest breaks, schema
    /// drift or a changed definition digest all fail closed.
    pub fn replay_records(records: &[DurableWorkRecord]) -> Result<DurableWorkRecord, SwarmError> {
        let Some(first) = records.first() else {
            return Err(SwarmError::InvalidSnapshot);
        };
        if first.sequence != 1
            || first.prev_digest != GENESIS_DIGEST
            || first.schema_version != DURABLE_WORK_SCHEMA_VERSION
        {
            return Err(SwarmError::InvalidSnapshot);
        }
        let mut tip = first.clone();
        if record_digest(&tip)? != tip.digest {
            return Err(SwarmError::InvalidSnapshot);
        }
        for record in &records[1..] {
            if record.sequence == tip.sequence && record.digest == tip.digest {
                continue;
            }
            if record.sequence != tip.sequence.saturating_add(1)
                || record.prev_digest != tip.digest
                || record.schema_version != DURABLE_WORK_SCHEMA_VERSION
                || record.work_id != tip.work_id
                || record.definition_digest != tip.definition_digest
            {
                return Err(SwarmError::InvalidSnapshot);
            }
            if record_digest(record)? != record.digest {
                return Err(SwarmError::InvalidSnapshot);
            }
            tip = record.clone();
        }
        Ok(tip)
    }

    /// Transient interpreter over provider-owned durable staged-work records.
    pub struct DurableWorkMachine<'a> {
        ports: DurablePorts<'a>,
        units: BTreeMap<WorkUnitId, DurableWorkRecord>,
        scope_writer: BTreeMap<String, WorkUnitId>,
        applied_operations: BTreeSet<String>,
        route_cache: BTreeMap<String, RouteGrant>,
    }

    impl<'a> DurableWorkMachine<'a> {
        /// Creates a machine over the injected owners. The machine itself owns
        /// no durable state; crash recovery reloads from the store owner.
        #[must_use]
        pub const fn new(ports: DurablePorts<'a>) -> Self {
            Self {
                ports,
                units: BTreeMap::new(),
                scope_writer: BTreeMap::new(),
                applied_operations: BTreeSet::new(),
                route_cache: BTreeMap::new(),
            }
        }

        /// All records currently held by this machine.
        #[must_use]
        pub fn all_records(&self) -> Vec<DurableWorkRecord> {
            self.units.values().cloned().collect()
        }

        /// Current scope-to-singular-writer map.
        #[must_use]
        pub fn scope_holders(&self) -> BTreeMap<String, WorkUnitId> {
            self.scope_writer.clone()
        }

        /// Current record for one work unit.
        #[must_use]
        pub fn record(&self, work_id: &WorkUnitId) -> Option<DurableWorkRecord> {
            self.units.get(work_id).cloned()
        }

        fn store(&self) -> Result<&'a dyn DurableWorkStore, SwarmError> {
            self.ports
                .store
                .ok_or(SwarmError::PlanGap(RequiredProvider::DurabilityStore))
        }

        fn executor(&self) -> Result<&'a dyn WorkExecutor, SwarmError> {
            self.ports
                .executor
                .ok_or(SwarmError::PlanGap(RequiredProvider::WorkExecutor))
        }

        fn catalogue(&self) -> Result<&'a dyn RouteCatalogue, SwarmError> {
            self.ports
                .catalogue
                .ok_or(SwarmError::PlanGap(RequiredProvider::RouteCatalogue))
        }

        fn peer(&self) -> Result<&'a dyn PeerChannel, SwarmError> {
            self.ports
                .peer
                .ok_or(SwarmError::PlanGap(RequiredProvider::PeerChannel))
        }

        fn check_operation(&self, operation_key: &str) -> Result<(), SwarmError> {
            validate_text(operation_key, "operation_key")?;
            if self.applied_operations.contains(operation_key) {
                return Err(SwarmError::DuplicateOperation);
            }
            Ok(())
        }

        fn get(&self, work_id: &WorkUnitId) -> Result<DurableWorkRecord, SwarmError> {
            self.units
                .get(work_id)
                .cloned()
                .ok_or(SwarmError::WorkUnitUnknown)
        }

        fn begin_transition(
            current: &DurableWorkRecord,
            phase: WorkUnitPhase,
            operation_key: String,
        ) -> DurableWorkRecord {
            let mut next = current.clone();
            next.sequence = current.sequence.saturating_add(1);
            next.prev_digest.clone_from(&current.digest);
            next.phase = phase;
            next.operation_key = operation_key;
            next.digest.clear();
            next
        }

        fn commit(
            &mut self,
            mut record: DurableWorkRecord,
        ) -> Result<DurableWorkRecord, SwarmError> {
            record.digest = record_digest(&record)?;
            let receipt = self
                .store()?
                .append(&record)
                .map_err(|error| SwarmError::Provider {
                    provider: RequiredProvider::DurabilityStore,
                    source: error,
                })?;
            if receipt.sequence != record.sequence || receipt.digest != record.digest {
                return Err(SwarmError::InvalidSnapshot);
            }
            self.applied_operations.insert(record.operation_key.clone());
            self.units.insert(record.work_id.clone(), record.clone());
            Ok(record)
        }

        fn release_scope(&mut self, record: &DurableWorkRecord) {
            if self
                .scope_writer
                .get(&record.scope_id)
                .is_some_and(|holder| holder == &record.work_id)
            {
                self.scope_writer.remove(&record.scope_id);
            }
        }

        fn route_request_key(
            route_class: &str,
            fence_digest: &str,
            epoch: u64,
        ) -> Result<String, SwarmError> {
            digest(&(route_class, fence_digest, epoch))
        }

        fn lookup_route(&mut self, record: &DurableWorkRecord) -> Result<RouteGrant, SwarmError> {
            let key = Self::route_request_key(
                record.route_class.as_str(),
                record.state_fence_digest.as_str(),
                record.authority_epoch,
            )?;
            if let Some(grant) = self.route_cache.get(&key) {
                return Ok(grant.clone());
            }
            let request = RouteRequest {
                route_class: record.route_class.clone(),
                requirements_digest: digest(&(&record.payload_digest, &record.budgets))?,
                fence_digest: record.state_fence_digest.clone(),
                epoch: record.authority_epoch,
            };
            let grant =
                self.catalogue()?
                    .lookup(&request)
                    .map_err(|error| SwarmError::Provider {
                        provider: RequiredProvider::RouteCatalogue,
                        source: error,
                    })?;
            if grant.route_id.trim().is_empty()
                || grant.fingerprint.trim().is_empty()
                || grant.evidence_digest.trim().is_empty()
            {
                return Err(SwarmError::RouteBlocked);
            }
            self.route_cache.insert(key, grant.clone());
            Ok(grant)
        }

        /// Admits one exact admitted definition. The admitted-not-staged fact
        /// is persisted before anything else; a changed same-ID payload
        /// conflicts and an overlapping scope writer is rejected.
        pub fn admit(
            &mut self,
            definition: AdmittedWorkDefinition,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            validate_definition_text(&definition)?;
            let definition_hash = definition_digest(&definition)?;
            if let Some(existing) = self.units.get(&definition.work_id) {
                if existing.definition_digest == definition_hash {
                    return Ok(existing.clone());
                }
                return Err(SwarmError::PayloadConflict);
            }
            if self.scope_writer.contains_key(&definition.scope_id) {
                return Err(SwarmError::ScopeWriterConflict);
            }
            validate_admission_receipt(&definition, self.ports.verifier)?;
            let mut budgets = BTreeMap::new();
            for spec in &definition.budgets {
                budgets.insert(
                    spec.dimension,
                    BudgetAccount {
                        limit: spec.limit,
                        reserved: 0,
                        spent: 0,
                    },
                );
            }
            let record = DurableWorkRecord {
                schema_version: DURABLE_WORK_SCHEMA_VERSION,
                work_id: definition.work_id,
                sequence: 1,
                phase: WorkUnitPhase::AdmittedNotStaged,
                terminal: None,
                definition_digest: definition_hash,
                payload_digest: definition.payload_digest,
                parent_task_id: definition.parent_task_id,
                cell_id: definition.cell_id,
                attempt_ref: definition.attempt_ref,
                task_id: definition.task_id,
                session_id: definition.session_id,
                scope_id: definition.scope_id,
                state_fence_digest: definition.state_fence_digest,
                authority_epoch: definition.authority_epoch,
                term: definition.term,
                owner: None,
                route: None,
                route_class: definition.route_class,
                dependencies: definition.dependencies,
                launch: None,
                effect: EffectCertainty::NoEffect,
                budgets,
                max_retries: definition.max_retries,
                max_children: definition.max_children,
                max_depth: definition.max_depth,
                max_pending_reviews: definition.max_pending_reviews,
                evidence_required: definition.evidence_required,
                depth: 0,
                retry_count: 0,
                timeout_count: 0,
                heartbeat_sequence: 0,
                checkpoint: None,
                cancellation: CancellationPhase::NotRequested,
                parent: None,
                children: BTreeSet::new(),
                reviews: Vec::new(),
                messages: Vec::new(),
                last_exit: None,
                result_digest: None,
                message_sequence: 0,
                prev_digest: GENESIS_DIGEST.to_owned(),
                digest: String::new(),
                operation_key,
            };
            let committed = self.commit(record)?;
            self.scope_writer
                .insert(committed.scope_id.clone(), committed.work_id.clone());
            Ok(committed)
        }

        /// Stages admitted work: dependency evidence, scope/fence, budgets and
        /// the exact #694 route are bound and persisted before assignment.
        /// Incomplete dependencies block staging; catalogue failure blocks the
        /// route without any local fallback.
        pub fn stage_work(
            &mut self,
            work_id: &WorkUnitId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            if current.phase != WorkUnitPhase::AdmittedNotStaged {
                return Err(SwarmError::IllegalTransition);
            }
            for dependency in &current.dependencies {
                validate_text(&dependency.evidence_digest, "dependency_evidence_digest")?;
            }
            let route = self.lookup_route(&current).map_err(|error| {
                if matches!(
                    error,
                    SwarmError::Provider {
                        provider: RequiredProvider::RouteCatalogue,
                        ..
                    }
                ) {
                    SwarmError::RouteBlocked
                } else {
                    error
                }
            })?;
            let mut next =
                Self::begin_transition(&current, WorkUnitPhase::StagedNotAssigned, operation_key);
            next.route = Some(route);
            self.commit(next)
        }

        /// Assigns the singular owner. Only a persisted staged record can be
        /// assigned; a second distinct owner is rejected.
        pub fn assign(
            &mut self,
            work_id: &WorkUnitId,
            owner: OwnerBinding,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            validate_text(&owner.worker_id, "worker_id")?;
            validate_text(&owner.process_id, "process_id")?;
            let current = self.get(work_id)?;
            if current.phase != WorkUnitPhase::StagedNotAssigned {
                if current.owner.is_some() {
                    return Err(SwarmError::OwnershipConflict);
                }
                return Err(SwarmError::IllegalTransition);
            }
            if current.route.is_none() {
                return Err(SwarmError::IllegalTransition);
            }
            let mut next = Self::begin_transition(&current, WorkUnitPhase::Assigned, operation_key);
            next.owner = Some(owner);
            self.commit(next)
        }

        /// Persists the stable launch operation plus `AgentAttempt`
        /// registration, then calls the external executor exactly once.
        /// Refused becomes not-attempted; unknown (lost response, timeout, or
        /// unknown provider outcome) becomes unknown-outcome with the scope
        /// blocked; any other provider failure leaves the persisted intent in
        /// place and reports the error for later reconcile.
        pub fn request_launch(
            &mut self,
            work_id: &WorkUnitId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            if current.phase != WorkUnitPhase::Assigned {
                return Err(SwarmError::IllegalTransition);
            }
            let owner = current.owner.clone().ok_or(SwarmError::OwnershipConflict)?;
            let route = current.route.clone().ok_or(SwarmError::RouteBlocked)?;
            if route.stale {
                return Err(SwarmError::RouteBlocked);
            }
            let attempt_id = AgentAttemptId::new(format!("{}-attempt", work_id.as_str()))
                .map_err(|_| SwarmError::Contract)?;
            let operation_id = format!("{}:launch:{}", work_id.as_str(), current.sequence + 1);
            let intent = LaunchIntent {
                operation_id: operation_id.clone(),
                attempt_id: attempt_id.clone(),
                work_id: work_id.clone(),
                route_id: route.route_id.clone(),
                route_fingerprint: route.fingerprint.clone(),
                lease: owner.lease.clone(),
                term: current.term,
                epoch: current.authority_epoch,
                fence_digest: current.state_fence_digest.clone(),
            };
            let mut intent_record =
                Self::begin_transition(&current, WorkUnitPhase::LaunchRequested, operation_key);
            intent_record.launch = Some(PersistedLaunch {
                operation_id: operation_id.clone(),
                attempt_id: attempt_id.clone(),
                child: None,
                executor_called: false,
            });
            let intent_record = self.commit(intent_record)?;
            let outcome = self.executor()?.launch(&intent);
            match outcome {
                Ok(LaunchOutcome::Started { child }) => {
                    validate_text(&child.child_id, "child_id")?;
                    validate_text(&child.process_identity, "process_identity")?;
                    let mut next = Self::begin_transition(
                        &intent_record,
                        WorkUnitPhase::Running,
                        format!("{operation_id}:started"),
                    );
                    next.launch = Some(PersistedLaunch {
                        operation_id,
                        attempt_id,
                        child: Some(child),
                        executor_called: true,
                    });
                    self.commit(next)
                }
                Ok(LaunchOutcome::Refused { reason }) => {
                    validate_text(&reason, "refusal_reason")?;
                    let mut next = Self::begin_transition(
                        &intent_record,
                        WorkUnitPhase::LaunchNotAttempted,
                        format!("{operation_id}:refused"),
                    );
                    next.terminal = None;
                    next.launch = Some(PersistedLaunch {
                        operation_id,
                        attempt_id,
                        child: None,
                        executor_called: true,
                    });
                    let committed = self.commit(next)?;
                    self.release_scope(&committed);
                    Ok(committed)
                }
                Ok(LaunchOutcome::Unknown)
                | Err(
                    ProviderError::Unknown
                    | ProviderError::Timeout
                    | ProviderError::Failed
                    | ProviderError::Unavailable,
                ) => {
                    let mut next = Self::begin_transition(
                        &intent_record,
                        WorkUnitPhase::UnknownOutcome,
                        format!("{operation_id}:unknown"),
                    );
                    next.effect = EffectCertainty::PossibleEffect;
                    next.launch = Some(PersistedLaunch {
                        operation_id,
                        attempt_id,
                        child: None,
                        executor_called: true,
                    });
                    self.commit(next)
                }
                Err(error) => Err(SwarmError::Provider {
                    provider: RequiredProvider::WorkExecutor,
                    source: error,
                }),
            }
        }

        /// Applies a heartbeat/renewal. Requires the exact current worker,
        /// lease, term, epoch and fence plus the next monotonic sequence.
        /// Exact redelivery of the current beat is idempotent; stale, foreign
        /// or gapped beats are rejected without touching durable state.
        /// Expiry never frees an uncertain-effect scope: that stays blocked.
        pub fn heartbeat(
            &mut self,
            work_id: &WorkUnitId,
            signal: &HeartbeatSignal,
        ) -> Result<DurableWorkRecord, SwarmError> {
            validate_text(&signal.worker_id, "worker_id")?;
            validate_text(&signal.fence_digest, "fence_digest")?;
            let current = self.get(work_id)?;
            if !matches!(
                current.phase,
                WorkUnitPhase::Running | WorkUnitPhase::Checkpointed
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            let owner = current.owner.clone().ok_or(SwarmError::OwnershipConflict)?;
            if signal.sequence == current.heartbeat_sequence
                && signal.lease == owner.lease
                && signal.term == current.term
                && signal.epoch == current.authority_epoch
                && signal.fence_digest == current.state_fence_digest
                && signal.worker_id == owner.worker_id
            {
                return Ok(current);
            }
            if signal.lease != owner.lease
                || signal.term != current.term
                || signal.epoch != current.authority_epoch
                || signal.fence_digest != current.state_fence_digest
                || signal.worker_id != owner.worker_id
            {
                return Err(SwarmError::BindingMismatch);
            }
            if signal.sequence != current.heartbeat_sequence.saturating_add(1) {
                return Err(SwarmError::ReplayDetected);
            }
            let mut next = Self::begin_transition(
                &current,
                current.phase,
                format!("{}:heartbeat:{}", work_id.as_str(), signal.sequence),
            );
            next.heartbeat_sequence = signal.sequence;
            self.commit(next)
        }

        /// Persists a checkpoint binding all input/route/tool/scope/fence/
        /// revision, remaining work, evidence and digest. Stale input, route
        /// or fence is rejected without reviving anything.
        pub fn checkpoint(
            &mut self,
            work_id: &WorkUnitId,
            checkpoint: WorkCheckpoint,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            validate_text(&checkpoint.checkpoint_id, "checkpoint_id")?;
            validate_text(&checkpoint.input_digest, "input_digest")?;
            validate_text(&checkpoint.route_fingerprint, "route_fingerprint")?;
            validate_text(&checkpoint.revision, "revision")?;
            validate_text(&checkpoint.evidence_digest, "evidence_digest")?;
            let current = self.get(work_id)?;
            if !matches!(
                current.phase,
                WorkUnitPhase::Running | WorkUnitPhase::Checkpointed
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            let route = current.route.clone().ok_or(SwarmError::RouteBlocked)?;
            if checkpoint.route_fingerprint != route.fingerprint
                || checkpoint.input_digest != current.payload_digest
            {
                return Err(SwarmError::BindingMismatch);
            }
            let mut next =
                Self::begin_transition(&current, WorkUnitPhase::Checkpointed, operation_key);
            next.checkpoint = Some(checkpoint);
            self.commit(next)
        }

        /// Resumes from the persisted checkpoint onto the exact remaining
        /// work. Resume needs resolved effects and a still-compatible
        /// input/route/fence; otherwise the unit quarantines (persisted) or
        /// stays blocked — never latest-checkpoint guessing.
        pub fn resume(
            &mut self,
            work_id: &WorkUnitId,
            remaining_work: &[String],
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            if current.phase != WorkUnitPhase::Checkpointed {
                return Err(SwarmError::IllegalTransition);
            }
            if current.effect == EffectCertainty::PossibleEffect {
                return Err(SwarmError::EffectUnresolved);
            }
            let checkpoint = current.checkpoint.clone().ok_or(SwarmError::Contract)?;
            let route = current.route.clone().ok_or(SwarmError::RouteBlocked)?;
            if checkpoint.remaining_work != remaining_work
                || checkpoint.input_digest != current.payload_digest
                || checkpoint.route_fingerprint != route.fingerprint
            {
                let mut quarantined =
                    Self::begin_transition(&current, WorkUnitPhase::Quarantined, operation_key);
                quarantined.checkpoint = Some(checkpoint);
                let committed = self.commit(quarantined)?;
                if committed.effect != EffectCertainty::PossibleEffect {
                    self.release_scope(&committed);
                }
                return Err(SwarmError::StaleLineage);
            }
            let next = Self::begin_transition(&current, WorkUnitPhase::Running, operation_key);
            self.commit(next)
        }

        /// Externally admitted safe restart out of quarantine: a fresh
        /// admission receipt is validated again and the unit returns to
        /// staged-not-assigned with ownership, launch, heartbeat and
        /// checkpoint cleared. Children and reviews stay accounted.
        pub fn request_safe_restart(
            &mut self,
            definition: AdmittedWorkDefinition,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            validate_definition_text(&definition)?;
            let current = self.get(&definition.work_id)?;
            if current.phase != WorkUnitPhase::Quarantined {
                return Err(SwarmError::IllegalTransition);
            }
            if definition.scope_id != current.scope_id {
                return Err(SwarmError::ScopeWriterConflict);
            }
            validate_admission_receipt(&definition, self.ports.verifier)?;
            let route = self.lookup_route_from_definition(&definition)?;
            let mut next =
                Self::begin_transition(&current, WorkUnitPhase::StagedNotAssigned, operation_key);
            next.definition_digest = definition_digest(&definition)?;
            next.payload_digest = definition.payload_digest;
            next.parent_task_id = definition.parent_task_id;
            next.cell_id = definition.cell_id;
            next.attempt_ref = definition.attempt_ref;
            next.task_id = definition.task_id;
            next.session_id = definition.session_id;
            next.state_fence_digest = definition.state_fence_digest;
            next.authority_epoch = definition.authority_epoch;
            next.term = definition.term;
            next.owner = None;
            next.route = Some(route);
            next.route_class = definition.route_class;
            next.dependencies = definition.dependencies;
            next.launch = None;
            next.effect = EffectCertainty::NoEffect;
            next.heartbeat_sequence = 0;
            next.checkpoint = None;
            next.cancellation = CancellationPhase::NotRequested;
            next.last_exit = None;
            next.result_digest = None;
            let mut budgets = BTreeMap::new();
            for spec in &definition.budgets {
                budgets.insert(
                    spec.dimension,
                    BudgetAccount {
                        limit: spec.limit,
                        reserved: 0,
                        spent: 0,
                    },
                );
            }
            next.budgets = budgets;
            next.max_retries = definition.max_retries;
            next.max_children = definition.max_children;
            next.max_depth = definition.max_depth;
            next.max_pending_reviews = definition.max_pending_reviews;
            next.evidence_required = definition.evidence_required;
            let committed = self.commit(next)?;
            self.scope_writer
                .insert(committed.scope_id.clone(), committed.work_id.clone());
            Ok(committed)
        }

        fn lookup_route_from_definition(
            &mut self,
            definition: &AdmittedWorkDefinition,
        ) -> Result<RouteGrant, SwarmError> {
            let key = Self::route_request_key(
                definition.route_class.as_str(),
                definition.state_fence_digest.as_str(),
                definition.authority_epoch,
            )?;
            if let Some(grant) = self.route_cache.get(&key) {
                return Ok(grant.clone());
            }
            let request = RouteRequest {
                route_class: definition.route_class.clone(),
                requirements_digest: digest(&(&definition.payload_digest, &definition.budgets))?,
                fence_digest: definition.state_fence_digest.clone(),
                epoch: definition.authority_epoch,
            };
            let grant =
                self.catalogue()?
                    .lookup(&request)
                    .map_err(|error| SwarmError::Provider {
                        provider: RequiredProvider::RouteCatalogue,
                        source: error,
                    })?;
            if grant.route_id.trim().is_empty()
                || grant.fingerprint.trim().is_empty()
                || grant.evidence_digest.trim().is_empty()
            {
                return Err(SwarmError::RouteBlocked);
            }
            self.route_cache.insert(key, grant.clone());
            Ok(grant)
        }

        /// Requests cancellation. The request is persisted first then the
        /// external cancel owner is called and observed. Before-launch units
        /// terminate with proved no-effect and never create a process;
        /// possible execution reconciles instead, and an unconfirmed cancel
        /// with possible effect stays unknown-outcome with the scope blocked.
        pub fn request_cancel(
            &mut self,
            work_id: &WorkUnitId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            match current.phase {
                WorkUnitPhase::AdmittedNotStaged
                | WorkUnitPhase::StagedNotAssigned
                | WorkUnitPhase::Assigned => {
                    let mut next =
                        Self::begin_transition(&current, WorkUnitPhase::Terminal, operation_key);
                    next.terminal = Some(TerminalKind::CancelledBeforeLaunch);
                    next.effect = EffectCertainty::ProvedNoEffect;
                    next.cancellation = CancellationPhase::Observed;
                    let committed = self.commit(next)?;
                    self.release_scope(&committed);
                    Ok(committed)
                }
                WorkUnitPhase::Running
                | WorkUnitPhase::Checkpointed
                | WorkUnitPhase::LaunchRequested
                | WorkUnitPhase::UnknownOutcome => {
                    let mut requested = Self::begin_transition(
                        &current,
                        WorkUnitPhase::CancellationRequested,
                        operation_key,
                    );
                    requested.cancellation = CancellationPhase::Requested;
                    let requested = self.commit(requested)?;
                    self.observe_cancellation(&requested)
                }
                _ => Err(SwarmError::IllegalTransition),
            }
        }

        fn observe_cancellation(
            &mut self,
            requested: &DurableWorkRecord,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let launch = requested.launch.clone().unwrap_or(PersistedLaunch {
                operation_id: format!("{}:no-launch", requested.work_id.as_str()),
                attempt_id: AgentAttemptId::new(format!("{}-attempt", requested.work_id.as_str()))
                    .map_err(|_| SwarmError::Contract)?,
                child: None,
                executor_called: false,
            });
            let Some(child) = launch.child.clone() else {
                if launch.executor_called {
                    let mut next = Self::begin_transition(
                        requested,
                        WorkUnitPhase::UnknownOutcome,
                        format!("{}:cancel-uncertain", requested.work_id.as_str()),
                    );
                    next.effect = EffectCertainty::PossibleEffect;
                    return self.commit(next);
                }
                let mut next = Self::begin_transition(
                    requested,
                    WorkUnitPhase::Terminal,
                    format!("{}:cancel-before-start", requested.work_id.as_str()),
                );
                next.terminal = Some(TerminalKind::CancelledBeforeLaunch);
                next.effect = EffectCertainty::ProvedNoEffect;
                next.cancellation = CancellationPhase::Observed;
                let committed = self.commit(next)?;
                self.release_scope(&committed);
                return Ok(committed);
            };
            let cancel_outcome = self.executor()?.cancel(&child);
            match cancel_outcome {
                Ok(CancelOutcome::CancelledBeforeStart) => {
                    let mut next = Self::begin_transition(
                        requested,
                        WorkUnitPhase::Terminal,
                        format!("{}:cancel-before-start", requested.work_id.as_str()),
                    );
                    next.terminal = Some(TerminalKind::CancelledBeforeLaunch);
                    next.effect = EffectCertainty::ProvedNoEffect;
                    next.cancellation = CancellationPhase::Observed;
                    let committed = self.commit(next)?;
                    self.release_scope(&committed);
                    Ok(committed)
                }
                Ok(CancelOutcome::CancelRequested { .. } | CancelOutcome::Unknown)
                | Err(ProviderError::Unknown | ProviderError::Timeout) => {
                    self.observe_after_cancel(requested, Some(&child))
                }
                Err(error) => Err(SwarmError::Provider {
                    provider: RequiredProvider::WorkExecutor,
                    source: error,
                }),
            }
        }

        fn observe_after_cancel(
            &mut self,
            requested: &DurableWorkRecord,
            child: Option<&ChildHandle>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let observed = if let Some(handle) = child {
                self.executor()?.observe(handle)
            } else {
                Ok(ObserveOutcome::Unknown)
            };
            match observed {
                Ok(ObserveOutcome::Exited { exit }) => {
                    validate_text(&exit.child.process_identity, "process_identity")?;
                    match &exit.effects {
                        ExitEffects::PossibleEffect { .. } => {
                            let mut next = Self::begin_transition(
                                requested,
                                WorkUnitPhase::UnknownOutcome,
                                format!("{}:cancel-uncertain", requested.work_id.as_str()),
                            );
                            next.effect = EffectCertainty::PossibleEffect;
                            next.last_exit = Some(exit);
                            self.commit(next)
                        }
                        ExitEffects::ProvedNoEffect { .. }
                        | ExitEffects::CleanWithArtifacts { .. } => {
                            let mut next = Self::begin_transition(
                                requested,
                                WorkUnitPhase::Terminal,
                                format!("{}:cancel-after-effect", requested.work_id.as_str()),
                            );
                            next.terminal = Some(TerminalKind::CancelledAfterEffect);
                            next.effect = EffectCertainty::ProvedNoEffect;
                            next.cancellation = CancellationPhase::Observed;
                            next.last_exit = Some(exit);
                            let committed = self.commit(next)?;
                            self.release_scope(&committed);
                            Ok(committed)
                        }
                    }
                }
                Ok(ObserveOutcome::Running { .. }) => Ok(requested.clone()),
                Ok(ObserveOutcome::Unknown)
                | Err(ProviderError::Unknown | ProviderError::Timeout) => {
                    let mut next = Self::begin_transition(
                        requested,
                        WorkUnitPhase::UnknownOutcome,
                        format!("{}:cancel-uncertain", requested.work_id.as_str()),
                    );
                    next.effect = EffectCertainty::PossibleEffect;
                    self.commit(next)
                }
                Err(error) => Err(SwarmError::Provider {
                    provider: RequiredProvider::WorkExecutor,
                    source: error,
                }),
            }
        }

        /// Observes the child through the external owner. A clean exit with
        /// artifacts becomes a verification candidate — never completion. A
        /// proved-no-effect exit follows the exact safe terminal path.
        /// Possible effect or silence stays unknown-outcome with the scope
        /// blocked. No-change observations are idempotent and persist nothing.
        pub fn observe_child(
            &mut self,
            work_id: &WorkUnitId,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let current = self.get(work_id)?;
            if !matches!(
                current.phase,
                WorkUnitPhase::Running
                    | WorkUnitPhase::Checkpointed
                    | WorkUnitPhase::CancellationRequested
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            let launch = current
                .launch
                .clone()
                .ok_or(SwarmError::IllegalTransition)?;
            let Some(child) = launch.child.clone() else {
                return Err(SwarmError::IllegalTransition);
            };
            let observed = self.executor()?.observe(&child).map_err(|error| {
                if matches!(error, ProviderError::Unknown | ProviderError::Timeout) {
                    SwarmError::Provider {
                        provider: RequiredProvider::WorkExecutor,
                        source: ProviderError::Unknown,
                    }
                } else {
                    SwarmError::Provider {
                        provider: RequiredProvider::WorkExecutor,
                        source: error,
                    }
                }
            });
            match observed {
                Ok(ObserveOutcome::Running { child: seen }) => {
                    if seen != child {
                        return Ok(current);
                    }
                    Ok(current)
                }
                Ok(ObserveOutcome::Exited { exit }) => self.apply_exit(&current, exit),
                Ok(ObserveOutcome::Unknown) => self.apply_unknown(&current),
                Err(error) => {
                    if matches!(
                        error,
                        SwarmError::Provider {
                            source: ProviderError::Unknown,
                            ..
                        }
                    ) {
                        self.apply_unknown(&current)
                    } else {
                        Err(error)
                    }
                }
            }
        }

        fn apply_exit(
            &mut self,
            current: &DurableWorkRecord,
            exit: ExitRecord,
        ) -> Result<DurableWorkRecord, SwarmError> {
            validate_text(&exit.child.process_identity, "process_identity")?;
            if current.last_exit.as_ref() == Some(&exit) {
                return Ok(current.clone());
            }
            if let Some(recorded) = current
                .launch
                .as_ref()
                .and_then(|bound| bound.child.as_ref())
                && recorded.process_identity != exit.child.process_identity
            {
                return Ok(current.clone());
            }
            match &exit.effects {
                ExitEffects::CleanWithArtifacts { artifacts_digest } => {
                    validate_text(artifacts_digest, "artifacts_digest")?;
                    let mut next = Self::begin_transition(
                        current,
                        WorkUnitPhase::CompletionCandidate,
                        format!("{}:exit-candidate", current.work_id.as_str()),
                    );
                    next.result_digest = Some(artifacts_digest.clone());
                    next.last_exit = Some(exit);
                    next.cancellation = CancellationPhase::Observed;
                    self.commit(next)
                }
                ExitEffects::ProvedNoEffect { proof_digest } => {
                    validate_text(proof_digest, "proof_digest")?;
                    let mut next = Self::begin_transition(
                        current,
                        WorkUnitPhase::Terminal,
                        format!("{}:exit-no-effect", current.work_id.as_str()),
                    );
                    next.terminal = Some(TerminalKind::FailedProvedNoEffect);
                    next.effect = EffectCertainty::ProvedNoEffect;
                    next.last_exit = Some(exit);
                    let committed = self.commit(next)?;
                    self.release_scope(&committed);
                    Ok(committed)
                }
                ExitEffects::PossibleEffect { detail } => {
                    validate_text(detail, "effect_detail")?;
                    let mut next = Self::begin_transition(
                        current,
                        WorkUnitPhase::UnknownOutcome,
                        format!("{}:exit-uncertain", current.work_id.as_str()),
                    );
                    next.effect = EffectCertainty::PossibleEffect;
                    next.last_exit = Some(exit);
                    self.commit(next)
                }
            }
        }

        fn apply_unknown(
            &mut self,
            current: &DurableWorkRecord,
        ) -> Result<DurableWorkRecord, SwarmError> {
            if current.phase == WorkUnitPhase::UnknownOutcome {
                return Ok(current.clone());
            }
            let mut next = Self::begin_transition(
                current,
                WorkUnitPhase::UnknownOutcome,
                format!("{}:observed-unknown", current.work_id.as_str()),
            );
            next.effect = EffectCertainty::PossibleEffect;
            self.commit(next)
        }

        /// Submits a worker result bound to the exact current lease and term.
        /// A stale result can never complete a new ownership. Without the
        /// required evidence the candidate is insufficient. The accepted
        /// result is only a verification candidate: provider/process terminal
        /// state is never task finish, and this surface cannot emit one.
        pub fn submit_result(
            &mut self,
            work_id: &WorkUnitId,
            result: WorkerResult,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            validate_text(&result.artifacts_digest, "artifacts_digest")?;
            validate_text(&result.output_ref, "output_ref")?;
            let current = self.get(work_id)?;
            if !matches!(
                current.phase,
                WorkUnitPhase::Running | WorkUnitPhase::Checkpointed
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            let owner = current.owner.clone().ok_or(SwarmError::OwnershipConflict)?;
            if result.lease != owner.lease || result.term != current.term {
                return Err(SwarmError::StaleLineage);
            }
            if current.evidence_required && result.evidence_digest.is_none() {
                return Err(SwarmError::EvidenceMissing);
            }
            if let Some(evidence) = &result.evidence_digest {
                validate_text(evidence, "evidence_digest")?;
            }
            let mut next =
                Self::begin_transition(&current, WorkUnitPhase::CompletionCandidate, operation_key);
            next.result_digest = Some(result.artifacts_digest);
            self.commit(next)
        }

        /// Reconciles one unit by stable operation/process identity after a
        /// crash, a lost launch response, or a lost child. A running child
        /// reattaches; an exit observed while the parent was down applies
        /// exactly once; proved no-effect follows the safe terminal path;
        /// possible effect stays unresolved with the scope blocked; stale
        /// identities are ignored without reviving obsolete ownership.
        pub fn reconcile(
            &mut self,
            work_id: &WorkUnitId,
        ) -> Result<(DurableWorkRecord, ReconcileOutcome), SwarmError> {
            let current = self.get(work_id)?;
            if current.phase.is_terminal() {
                return Ok((current, ReconcileOutcome::AlreadyTerminal));
            }
            let launch = current.launch.clone();
            let observed = match launch {
                None => return Ok((current, ReconcileOutcome::NoChildToReconcile)),
                Some(bound) if !bound.executor_called => {
                    return Ok((current, ReconcileOutcome::NoChildToReconcile));
                }
                Some(bound) => match bound.child.clone() {
                    Some(child) => self.executor()?.observe(&child),
                    None => self.executor()?.observe_attempt(&bound.attempt_id),
                },
            };
            match observed {
                Ok(ObserveOutcome::Running { child }) => {
                    let recorded = current
                        .launch
                        .as_ref()
                        .and_then(|bound| bound.child.as_ref());
                    if let Some(known) = recorded
                        && *known != child
                    {
                        return Ok((current, ReconcileOutcome::StaleIgnored));
                    }
                    if matches!(
                        current.phase,
                        WorkUnitPhase::Running
                            | WorkUnitPhase::Checkpointed
                            | WorkUnitPhase::CancellationRequested
                    ) {
                        return Ok((current, ReconcileOutcome::Reattached));
                    }
                    let target = match current.phase {
                        WorkUnitPhase::Running
                        | WorkUnitPhase::Checkpointed
                        | WorkUnitPhase::CancellationRequested => current.phase,
                        _ => WorkUnitPhase::Running,
                    };
                    let mut next = Self::begin_transition(
                        &current,
                        target,
                        format!("{}:reattached", work_id.as_str()),
                    );
                    if let Some(bound) = next.launch.as_mut() {
                        bound.child = Some(child);
                        bound.executor_called = true;
                    }
                    let committed = self.commit(next)?;
                    Ok((committed, ReconcileOutcome::Reattached))
                }
                Ok(ObserveOutcome::Exited { exit }) => {
                    if current.last_exit.as_ref() == Some(&exit) {
                        return Ok((current, ReconcileOutcome::AlreadyApplied));
                    }
                    let recorded_identity = current
                        .launch
                        .as_ref()
                        .and_then(|bound| bound.child.as_ref())
                        .map(|child| child.process_identity.clone());
                    if let Some(known) = recorded_identity
                        && known != exit.child.process_identity
                    {
                        return Ok((current, ReconcileOutcome::StaleIgnored));
                    }
                    let committed = self.apply_exit(&current, exit)?;
                    let outcome = if committed.digest == current.digest {
                        ReconcileOutcome::AlreadyApplied
                    } else if committed.phase == WorkUnitPhase::Terminal {
                        ReconcileOutcome::ProvedNoEffectTerminal
                    } else {
                        ReconcileOutcome::ExitedApplied
                    };
                    Ok((committed, outcome))
                }
                Ok(ObserveOutcome::Unknown)
                | Err(ProviderError::Unknown | ProviderError::Timeout) => {
                    if current.phase == WorkUnitPhase::UnknownOutcome {
                        return Ok((current, ReconcileOutcome::StillUnknownBlocked));
                    }
                    let committed = self.apply_unknown(&current)?;
                    Ok((committed, ReconcileOutcome::StillUnknownBlocked))
                }
                Err(error) => Err(SwarmError::Provider {
                    provider: RequiredProvider::WorkExecutor,
                    source: error,
                }),
            }
        }

        /// Registers a staged child under a running parent within the
        /// admitted fanout/depth bounds. Retry, fanout and depth are finite:
        /// exceeding them terminates instead of looping.
        pub fn register_child(
            &mut self,
            parent_id: &WorkUnitId,
            child_id: &WorkUnitId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let parent = self.get(parent_id)?;
            let child = self.get(child_id)?;
            if !matches!(
                parent.phase,
                WorkUnitPhase::Running
                    | WorkUnitPhase::Checkpointed
                    | WorkUnitPhase::CompletionCandidate
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            if child.phase != WorkUnitPhase::StagedNotAssigned {
                return Err(SwarmError::IllegalTransition);
            }
            if child.parent.is_some() || parent.children.contains(child_id) {
                if child.parent.as_ref() == Some(parent_id) && !parent.children.contains(child_id) {
                    let mut next_parent =
                        Self::begin_transition(&parent, parent.phase, operation_key);
                    next_parent.children.insert(child_id.clone());
                    return self.commit(next_parent);
                }
                return Err(SwarmError::Duplicate("parent_child"));
            }
            if parent.children.len() >= parent.max_children as usize {
                return Err(SwarmError::IllegalTransition);
            }
            let child_depth = parent.depth.saturating_add(1);
            if child_depth > parent.max_depth {
                return Err(SwarmError::IllegalTransition);
            }
            let mut next_child = Self::begin_transition(
                &child,
                child.phase,
                format!("{}:adopted", child_id.as_str()),
            );
            next_child.parent = Some(parent_id.clone());
            next_child.depth = child_depth;
            self.commit(next_child)?;
            let mut next_parent = Self::begin_transition(&parent, parent.phase, operation_key);
            next_parent.children.insert(child_id.clone());
            self.commit(next_parent)
        }

        /// Derives one disposition per registered child from the live child
        /// records held by this machine. A missing child record leaves the
        /// denominator open rather than guessed.
        fn child_dispositions(
            &self,
            parent: &DurableWorkRecord,
        ) -> Result<BTreeMap<WorkUnitId, ChildDisposition>, SwarmError> {
            let mut dispositions = BTreeMap::new();
            for child_id in &parent.children {
                let Some(child) = self.units.get(child_id) else {
                    return Err(SwarmError::ChildDenominatorOpen);
                };
                let disposition = match child.phase {
                    WorkUnitPhase::Terminal => child
                        .terminal
                        .map(ChildDisposition::Terminal)
                        .ok_or(SwarmError::Contract)?,
                    WorkUnitPhase::LaunchNotAttempted => {
                        ChildDisposition::Terminal(TerminalKind::CancelledBeforeLaunch)
                    }
                    WorkUnitPhase::UnknownOutcome => ChildDisposition::UnknownBlocked,
                    WorkUnitPhase::Quarantined => ChildDisposition::Stale,
                    _ => ChildDisposition::Running,
                };
                dispositions.insert(child_id.clone(), disposition);
            }
            Ok(dispositions)
        }

        /// Emits the parent execution candidate over a complete child
        /// denominator: every registered child terminal with one disposition
        /// each, every required review resolved, and no unresolved effect.
        /// One unresolved or unconsumed child blocks the parent; late evidence
        /// is retained without completing the wrong attempt.
        pub fn close_parent(&self, parent_id: &WorkUnitId) -> Result<ParentCandidate, SwarmError> {
            let parent = self.get(parent_id)?;
            if parent.phase != WorkUnitPhase::CompletionCandidate {
                return Err(SwarmError::IllegalTransition);
            }
            if parent.effect == EffectCertainty::PossibleEffect {
                return Err(SwarmError::EffectUnresolved);
            }
            for review in &parent.reviews {
                if review.required
                    && !matches!(
                        review.state,
                        ReviewState::Resolved | ReviewState::Superseded
                    )
                {
                    return Err(SwarmError::ReviewBlocksClosure);
                }
            }
            let dispositions = self.child_dispositions(&parent)?;
            let mut denominator = BTreeMap::new();
            for (child_id, disposition) in dispositions {
                let ChildDisposition::Terminal(kind) = disposition else {
                    return Err(SwarmError::ChildDenominatorOpen);
                };
                denominator.insert(child_id, kind);
            }
            let candidate_digest = digest(&(&parent.work_id, &parent.digest, &denominator))?;
            Ok(ParentCandidate {
                parent_id: parent_id.clone(),
                denominator,
                candidate_digest,
                proof_ceiling: WORK_CANDIDATE_CEILING,
            })
        }

        /// Verifies a parent candidate against the current durable records.
        pub fn verify_parent_candidate(
            &self,
            candidate: &ParentCandidate,
        ) -> Result<(), SwarmError> {
            let parent = self.get(&candidate.parent_id)?;
            if candidate.proof_ceiling != WORK_CANDIDATE_CEILING {
                return Err(SwarmError::InvalidReceipt);
            }
            let dispositions = self.child_dispositions(&parent)?;
            let mut denominator = BTreeMap::new();
            for (child_id, disposition) in dispositions {
                let ChildDisposition::Terminal(kind) = disposition else {
                    return Err(SwarmError::ChildDenominatorOpen);
                };
                denominator.insert(child_id, kind);
            }
            if denominator != candidate.denominator {
                return Err(SwarmError::ChildDenominatorOpen);
            }
            let expected = digest(&(&parent.work_id, &parent.digest, &denominator))?;
            if expected != candidate.candidate_digest {
                return Err(SwarmError::InvalidSnapshot);
            }
            Ok(())
        }

        /// Records a timeout without relaunching blindly and without orphaning
        /// ownership: the phase, owner and child binding are retained.
        pub fn note_timeout(
            &mut self,
            work_id: &WorkUnitId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            if !matches!(
                current.phase,
                WorkUnitPhase::Running
                    | WorkUnitPhase::Checkpointed
                    | WorkUnitPhase::UnknownOutcome
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            next.timeout_count = current.timeout_count.saturating_add(1);
            self.commit(next)
        }

        /// Records a bounded retry. Exhaustion terminates with the exact
        /// exhausted kind instead of looping forever.
        pub fn note_retry(
            &mut self,
            work_id: &WorkUnitId,
            operation_key: impl Into<String>,
        ) -> Result<(DurableWorkRecord, RetryOutcome), SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            if !matches!(
                current.phase,
                WorkUnitPhase::Running
                    | WorkUnitPhase::Checkpointed
                    | WorkUnitPhase::UnknownOutcome
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            if current.retry_count < current.max_retries {
                let mut next = Self::begin_transition(&current, current.phase, operation_key);
                next.retry_count = current.retry_count.saturating_add(1);
                let committed = self.commit(next)?;
                Ok((committed, RetryOutcome::Scheduled))
            } else {
                let mut next =
                    Self::begin_transition(&current, WorkUnitPhase::Terminal, operation_key);
                next.terminal = Some(TerminalKind::FailedExhausted);
                let committed = self.commit(next)?;
                self.release_scope(&committed);
                Ok((committed, RetryOutcome::Exhausted))
            }
        }

        fn budget_account_mut(
            current: &mut DurableWorkRecord,
            dimension: BudgetDimension,
        ) -> Result<&mut BudgetAccount, SwarmError> {
            current
                .budgets
                .get_mut(&dimension)
                .ok_or(SwarmError::Contract)
        }

        fn require_live(current: &DurableWorkRecord) -> Result<(), SwarmError> {
            if current.phase.is_terminal() {
                return Err(SwarmError::IllegalTransition);
            }
            Ok(())
        }

        /// Spends from one independent budget dimension under an idempotency
        /// key, so replay can never double-spend.
        pub fn consume_budget(
            &mut self,
            work_id: &WorkUnitId,
            dimension: BudgetDimension,
            amount: u64,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            if amount == 0 {
                return Err(SwarmError::Contract);
            }
            let current = self.get(work_id)?;
            Self::require_live(&current)?;
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            let account = Self::budget_account_mut(&mut next, dimension)?;
            if amount > account.remaining() {
                return Err(SwarmError::BudgetExceeded);
            }
            account.spent = account.spent.saturating_add(amount);
            self.commit(next)
        }

        /// Reserves budget for a future child without spending it.
        pub fn reserve_budget(
            &mut self,
            work_id: &WorkUnitId,
            dimension: BudgetDimension,
            amount: u64,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            if amount == 0 {
                return Err(SwarmError::Contract);
            }
            let current = self.get(work_id)?;
            Self::require_live(&current)?;
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            let account = Self::budget_account_mut(&mut next, dimension)?;
            if amount > account.remaining() {
                return Err(SwarmError::BudgetExceeded);
            }
            account.reserved = account.reserved.saturating_add(amount);
            self.commit(next)
        }

        /// Releases a prior reservation back to remaining.
        pub fn release_budget(
            &mut self,
            work_id: &WorkUnitId,
            dimension: BudgetDimension,
            amount: u64,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            if amount == 0 {
                return Err(SwarmError::Contract);
            }
            let current = self.get(work_id)?;
            Self::require_live(&current)?;
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            let account = Self::budget_account_mut(&mut next, dimension)?;
            if amount > account.reserved {
                return Err(SwarmError::Contract);
            }
            account.reserved = account.reserved.saturating_sub(amount);
            self.commit(next)
        }

        /// Posts a review/message bound to the exact artifact revision through
        /// the peer channel. Past the pending cap the item stays visible as
        /// overflowed instead of disappearing.
        pub fn post_review(
            &mut self,
            work_id: &WorkUnitId,
            proposal: ReviewProposal,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            validate_text(&proposal.artifact_id, "artifact_id")?;
            validate_text(&proposal.artifact_revision, "artifact_revision")?;
            validate_text(&proposal.content_digest, "content_digest")?;
            let current = self.get(work_id)?;
            Self::require_live(&current)?;
            if current
                .reviews
                .iter()
                .any(|review| review.review_id == proposal.review_id)
            {
                return Err(SwarmError::Duplicate("review_id"));
            }
            let pending = current
                .reviews
                .iter()
                .filter(|review| {
                    matches!(review.state, ReviewState::Delivered | ReviewState::Answered)
                })
                .count();
            let state = if pending >= current.max_pending_reviews as usize {
                ReviewState::Overflowed
            } else {
                ReviewState::Delivered
            };
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            next.message_sequence = next.message_sequence.saturating_add(1);
            let message = PeerMessage {
                work_id: work_id.clone(),
                artifact_id: proposal.artifact_id.clone(),
                artifact_revision: proposal.artifact_revision.clone(),
                sequence: next.message_sequence,
                kind: PeerMessageKind::ReviewItem,
                payload_digest: proposal.content_digest.clone(),
            };
            let receipt = self
                .peer()?
                .post(&message)
                .map_err(|error| SwarmError::Provider {
                    provider: RequiredProvider::PeerChannel,
                    source: error,
                })?;
            if receipt.sequence != message.sequence {
                return Err(SwarmError::InvalidSnapshot);
            }
            next.messages.push(PostedPeerMessage { message, receipt });
            next.reviews.push(ReviewRecord {
                review_id: proposal.review_id,
                artifact_id: proposal.artifact_id,
                artifact_revision: proposal.artifact_revision,
                required: proposal.required,
                state,
            });
            self.commit(next)
        }

        fn review_transition(
            &mut self,
            work_id: &WorkUnitId,
            review_id: &ClaimId,
            from: &[ReviewState],
            to: ReviewState,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            Self::require_live(&current)?;
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            let Some(review) = next
                .reviews
                .iter_mut()
                .find(|review| &review.review_id == review_id)
            else {
                return Err(SwarmError::ReviewUnknown);
            };
            if !from.contains(&review.state) {
                return Err(SwarmError::IllegalTransition);
            }
            review.state = to;
            self.commit(next)
        }

        /// Answers a delivered review. Answer is distinct from resolution.
        pub fn answer_review(
            &mut self,
            work_id: &WorkUnitId,
            review_id: &ClaimId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            self.review_transition(
                work_id,
                review_id,
                &[ReviewState::Delivered],
                ReviewState::Answered,
                operation_key,
            )
        }

        /// Resolves an answered review through the normal owner path.
        pub fn resolve_review(
            &mut self,
            work_id: &WorkUnitId,
            review_id: &ClaimId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            self.review_transition(
                work_id,
                review_id,
                &[ReviewState::Answered],
                ReviewState::Resolved,
                operation_key,
            )
        }

        /// Rejects a review with reason; the item stays visible.
        pub fn reject_review(
            &mut self,
            work_id: &WorkUnitId,
            review_id: &ClaimId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            self.review_transition(
                work_id,
                review_id,
                &[ReviewState::Delivered, ReviewState::Answered],
                ReviewState::RejectedWithReason,
                operation_key,
            )
        }

        /// Marks a delivered or answered review expired. A required
        /// expired review keeps preventing closure.
        pub fn expire_review(
            &mut self,
            work_id: &WorkUnitId,
            review_id: &ClaimId,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            self.review_transition(
                work_id,
                review_id,
                &[ReviewState::Delivered, ReviewState::Answered],
                ReviewState::Expired,
                operation_key,
            )
        }

        /// Supersedes a visible review obligation with a replacement item.
        /// The old item stays retained as superseded and the replacement is
        /// posted through the peer channel; only a resolved required
        /// replacement unblocks closure.
        pub fn supersede_review(
            &mut self,
            work_id: &WorkUnitId,
            old_review_id: &ClaimId,
            replacement: ReviewProposal,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            validate_text(&replacement.artifact_id, "artifact_id")?;
            validate_text(&replacement.artifact_revision, "artifact_revision")?;
            validate_text(&replacement.content_digest, "content_digest")?;
            let current = self.get(work_id)?;
            Self::require_live(&current)?;
            if current
                .reviews
                .iter()
                .any(|review| review.review_id == replacement.review_id)
            {
                return Err(SwarmError::Duplicate("review_id"));
            }
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            let Some(old) = next
                .reviews
                .iter_mut()
                .find(|review| &review.review_id == old_review_id)
            else {
                return Err(SwarmError::ReviewUnknown);
            };
            if !matches!(
                old.state,
                ReviewState::Delivered
                    | ReviewState::Answered
                    | ReviewState::Expired
                    | ReviewState::Overflowed
            ) {
                return Err(SwarmError::IllegalTransition);
            }
            if old.required && !replacement.required {
                return Err(SwarmError::Contract);
            }
            old.state = ReviewState::Superseded;
            let pending = next
                .reviews
                .iter()
                .filter(|review| {
                    matches!(review.state, ReviewState::Delivered | ReviewState::Answered)
                })
                .count();
            let state = if pending >= next.max_pending_reviews as usize {
                ReviewState::Overflowed
            } else {
                ReviewState::Delivered
            };
            next.message_sequence = next.message_sequence.saturating_add(1);
            let message = PeerMessage {
                work_id: work_id.clone(),
                artifact_id: replacement.artifact_id.clone(),
                artifact_revision: replacement.artifact_revision.clone(),
                sequence: next.message_sequence,
                kind: PeerMessageKind::ReviewItem,
                payload_digest: replacement.content_digest.clone(),
            };
            let receipt = self
                .peer()?
                .post(&message)
                .map_err(|error| SwarmError::Provider {
                    provider: RequiredProvider::PeerChannel,
                    source: error,
                })?;
            if receipt.sequence != message.sequence {
                return Err(SwarmError::InvalidSnapshot);
            }
            next.messages.push(PostedPeerMessage { message, receipt });
            next.reviews.push(ReviewRecord {
                review_id: replacement.review_id,
                artifact_id: replacement.artifact_id,
                artifact_revision: replacement.artifact_revision,
                required: replacement.required,
                state,
            });
            self.commit(next)
        }

        /// Acknowledges a posted peer message. Acknowledgement changes
        /// nothing: it grants no scope and no finish.
        pub fn acknowledge(
            &self,
            work_id: &WorkUnitId,
            message_id: &str,
        ) -> Result<(), SwarmError> {
            let current = self.get(work_id)?;
            if current
                .messages
                .iter()
                .any(|posted| posted.receipt.message_id == message_id)
            {
                Ok(())
            } else {
                Err(SwarmError::Contract)
            }
        }

        /// Posts a non-review peer message (finding, result notice or
        /// cancellation notice) bound to the exact artifact revision.
        /// Review items must travel through [`Self::post_review`] instead.
        #[allow(clippy::too_many_arguments)]
        pub fn post_message(
            &mut self,
            work_id: &WorkUnitId,
            kind: PeerMessageKind,
            artifact_id: String,
            artifact_revision: String,
            payload_digest: String,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            if kind == PeerMessageKind::ReviewItem {
                return Err(SwarmError::IllegalTransition);
            }
            validate_text(&artifact_id, "artifact_id")?;
            validate_text(&artifact_revision, "artifact_revision")?;
            validate_text(&payload_digest, "payload_digest")?;
            let current = self.get(work_id)?;
            Self::require_live(&current)?;
            let mut next = Self::begin_transition(&current, current.phase, operation_key);
            next.message_sequence = next.message_sequence.saturating_add(1);
            let message = PeerMessage {
                work_id: work_id.clone(),
                artifact_id,
                artifact_revision,
                sequence: next.message_sequence,
                kind,
                payload_digest,
            };
            let receipt = self
                .peer()?
                .post(&message)
                .map_err(|error| SwarmError::Provider {
                    provider: RequiredProvider::PeerChannel,
                    source: error,
                })?;
            if receipt.sequence != message.sequence {
                return Err(SwarmError::InvalidSnapshot);
            }
            next.messages.push(PostedPeerMessage { message, receipt });
            self.commit(next)
        }

        /// Records the external verifier's verdict over a completion
        /// candidate. Verified-complete and partial coverage terminate with
        /// the exact kind; failed verification returns the unit to running
        /// for corrective work; an externally cancelled unit with possible
        /// effect stays blocked instead of closing over uncertainty.
        pub fn record_external_verdict(
            &mut self,
            work_id: &WorkUnitId,
            verdict: ExternalVerdict,
            operation_key: impl Into<String>,
        ) -> Result<DurableWorkRecord, SwarmError> {
            let operation_key = operation_key.into();
            self.check_operation(&operation_key)?;
            let current = self.get(work_id)?;
            if current.phase != WorkUnitPhase::CompletionCandidate {
                return Err(SwarmError::IllegalTransition);
            }
            match verdict {
                ExternalVerdict::VerifiedComplete => {
                    if current.effect == EffectCertainty::PossibleEffect
                        || current.result_digest.is_none()
                    {
                        return Err(SwarmError::EffectUnresolved);
                    }
                    let mut next =
                        Self::begin_transition(&current, WorkUnitPhase::Terminal, operation_key);
                    next.terminal = Some(TerminalKind::Completed);
                    let committed = self.commit(next)?;
                    self.release_scope(&committed);
                    Ok(committed)
                }
                ExternalVerdict::PartialCoverage => {
                    if current.effect == EffectCertainty::PossibleEffect
                        || current.result_digest.is_none()
                    {
                        return Err(SwarmError::EffectUnresolved);
                    }
                    let mut next =
                        Self::begin_transition(&current, WorkUnitPhase::Terminal, operation_key);
                    next.terminal = Some(TerminalKind::Partial);
                    let committed = self.commit(next)?;
                    self.release_scope(&committed);
                    Ok(committed)
                }
                ExternalVerdict::FailedVerification => {
                    let mut next =
                        Self::begin_transition(&current, WorkUnitPhase::Running, operation_key);
                    next.result_digest = None;
                    self.commit(next)
                }
                ExternalVerdict::CancelledExternal => {
                    if current.effect == EffectCertainty::PossibleEffect {
                        return Err(SwarmError::EffectUnresolved);
                    }
                    let mut next =
                        Self::begin_transition(&current, WorkUnitPhase::Terminal, operation_key);
                    next.terminal = Some(TerminalKind::CancelledAfterEffect);
                    next.cancellation = CancellationPhase::Observed;
                    let committed = self.commit(next)?;
                    self.release_scope(&committed);
                    Ok(committed)
                }
            }
        }

        /// Recovers after an uncertain persistence response (the append may
        /// have landed while its receipt was lost). Reloads the owner log and
        /// adopts the tip only when it exactly matches the expected sequence
        /// and digest chain; otherwise reports the store as still unknown so
        /// the caller can safely retry the same operation identity.
        pub fn recover_after_uncertain_persist(
            &mut self,
            work_id: &WorkUnitId,
            expected_sequence: u64,
            operation_key: impl Into<String>,
        ) -> Result<(DurableWorkRecord, UncertainPersistOutcome), SwarmError> {
            let operation_key = operation_key.into();
            if self.applied_operations.contains(&operation_key) {
                return Err(SwarmError::DuplicateOperation);
            }
            let log = self
                .store()?
                .load(work_id)
                .map_err(|error| SwarmError::Provider {
                    provider: RequiredProvider::DurabilityStore,
                    source: error,
                })?;
            let tip = replay_records(&log)?;
            if tip.sequence > expected_sequence {
                return Err(SwarmError::ReplayDetected);
            }
            if tip.sequence < expected_sequence {
                return Err(SwarmError::Provider {
                    provider: RequiredProvider::DurabilityStore,
                    source: ProviderError::Unknown,
                });
            }
            self.applied_operations.insert(operation_key);
            if self
                .scope_writer
                .get(&tip.scope_id)
                .is_none_or(|holder| holder == &tip.work_id)
                && !tip.phase.is_terminal()
            {
                self.scope_writer
                    .insert(tip.scope_id.clone(), tip.work_id.clone());
            }
            self.units.insert(tip.work_id.clone(), tip.clone());
            Ok((tip, UncertainPersistOutcome::Recovered))
        }

        /// Reloads one unit from the persistence owner after a crash:
        /// verifies schema, digest chain and order, rehydrates ownership,
        /// budgets, children, checkpoints, uncertainty and reviews, and keeps
        /// uncertain scopes blocked.
        pub fn reload(&mut self, work_id: &WorkUnitId) -> Result<DurableWorkRecord, SwarmError> {
            let log = self
                .store()?
                .load(work_id)
                .map_err(|error| SwarmError::Provider {
                    provider: RequiredProvider::DurabilityStore,
                    source: error,
                })?;
            let tip = replay_records(&log)?;
            if !tip.phase.is_terminal()
                && self
                    .scope_writer
                    .get(&tip.scope_id)
                    .is_some_and(|holder| holder != &tip.work_id)
            {
                return Err(SwarmError::ScopeWriterConflict);
            }
            if !tip.phase.is_terminal() {
                self.scope_writer
                    .insert(tip.scope_id.clone(), tip.work_id.clone());
            }
            self.units.insert(tip.work_id.clone(), tip.clone());
            Ok(tip)
        }
    }
}

#[cfg(test)]
#[path = "repair_tests.rs"]
mod tests;
