//! A-07 bounded swarm coordination core.
//!
//! The cell is deliberately stateless. It validates immutable proposals and
//! provider-issued receipts, but owns no process, route, task, authority, or
//! persistence state. Provider and checkpoint availability are injected.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{AgentAttempt as LaunchAttempt, EffectKind};
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
    pub lease_id: String,
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
            ("lease_id", self.lease_id.as_str()),
        ] {
            validate_text(value, field)?;
        }
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
        lease_id: String,
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
    let expected_fence_digest = digest(&plan.admission_receipt.core.work_scope.state_fence)?;
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
        || value.launch_attempt.authority.state_fence != expected_fence_digest
        || value.launch_attempt.authority.epoch.as_str()
            != plan
                .admission_receipt
                .core
                .authority
                .authority_epoch
                .value()
                .to_string()
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
            assignment.launch_attempt.lease.as_str().to_owned(),
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
        reviewer.assignment.launch_attempt.lease.as_str().to_owned(),
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
        auditor.assignment.launch_attempt.lease.as_str().to_owned(),
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

#[cfg(test)]
#[path = "repair_tests.rs"]
mod tests;
