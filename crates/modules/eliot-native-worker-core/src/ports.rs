use std::collections::BTreeSet;

use eliot_agent_api::{
    AttemptId, AuthorityEnvelope, AuthorizedEffect, ProposedEffect, WorkLeaseId,
};
use eliot_contracts::{EpochId, StateFence};
use eliot_process::{
    FencingToken, Generation, OperationId, ProcessRequest, ProcessTreeId, ResourceLimits,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::WorkerError;
use crate::protocol::{
    EventAckReceipt, NativeWorkerClaim, NativeWorkerReadiness, NativeWorkerRegistration,
    WorkerEventDraft, WorkerEventEnvelope, WorkerHello,
};

/// A-13's inert post-start binding.  `ProcessRequest` is authority-bearing and
/// consumed by `ProcessExecutor::start`; this snapshot carries only the
/// identity needed for later observation, cancellation, reconciliation, and
/// checkpoint binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessBindingSnapshot {
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    generation: Generation,
    executable_sha256: String,
    fence: FencingToken,
    request_digest: String,
}

impl ProcessBindingSnapshot {
    pub(crate) fn from_request(process: &ProcessRequest) -> Self {
        Self {
            operation_id: process.operation_id().clone(),
            process_tree_id: process.process_tree_id().clone(),
            generation: process.generation(),
            executable_sha256: process.executable_sha256().to_owned(),
            fence: process.fence().clone(),
            request_digest: process.invocation_digest().to_owned(),
        }
    }

    pub(crate) const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub(crate) const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    pub(crate) fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    pub(crate) const fn fence(&self) -> &FencingToken {
        &self.fence
    }

    pub(crate) fn request_digest(&self) -> &str {
        &self.request_digest
    }
}

/// Opaque provider failure. It carries no authority and is never interpreted as success.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("provider {provider} failed: {detail}")]
pub struct ProviderFailure {
    pub provider: &'static str,
    pub detail: String,
}

impl ProviderFailure {
    #[must_use]
    pub fn new(provider: &'static str, detail: impl Into<String>) -> Self {
        Self {
            provider,
            detail: detail.into(),
        }
    }
}

/// Exact launch projection submitted to the G-01-facing admission owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAdmissionRequest {
    hello: WorkerHello,
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    process_generation: Generation,
    process_fence: FencingToken,
    process_request_digest: String,
    resource_limits: ResourceLimits,
    /// Exact claim presentation this launch is bound to, when the claimed
    /// start path is used.
    ///
    /// `None` preserves the pre-claim wire shape: `skip_serializing_if`
    /// keeps `from_start` projections byte-identical on the wire, while
    /// `default` still accepts older payloads that carry no claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claim: Option<ClaimAdmissionRequest>,
}

impl CapabilityAdmissionRequest {
    pub(crate) fn from_start(hello: &WorkerHello, process: &ProcessRequest) -> Self {
        Self {
            hello: hello.clone(),
            operation_id: process.operation_id().clone(),
            process_tree_id: process.process_tree_id().clone(),
            process_generation: process.generation(),
            process_fence: process.fence().clone(),
            process_request_digest: process.invocation_digest().to_owned(),
            resource_limits: *process.resource_limits(),
            claim: None,
        }
    }

    /// Checked join of one exact claim presentation with the owner-supplied
    /// handshake and process request. Verifies the claim halves against each
    /// other and then against `hello`/`process`, and carries the claim into
    /// the admission projection. Invents nothing: no `ProcessRequest` is
    /// minted, no grant is sealed, `route_class` is never equated with a
    /// full route fingerprint, and no defaults are fabricated for
    /// `WorkerHello` fields. The claim's `attempt_id` has no start-time
    /// counterpart, so it is carried digest-bound rather than equated.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for a malformed half or an
    /// identity/generation/operation mismatch, [`WorkerError::StaleEpoch`]
    /// or [`WorkerError::StaleFence`] for epoch/fence disagreement, and
    /// [`WorkerError::DeadlineExpired`] when the handshake outlives the
    /// claim deadline.
    pub fn from_claim(
        claim: &ClaimAdmissionRequest,
        hello: &WorkerHello,
        process: &ProcessRequest,
    ) -> Result<Self, WorkerError> {
        claim.validate_binding()?;
        let presented = claim.claim();
        let registration = claim.registration();
        if presented.registration_id != registration.registration_id {
            return Err(WorkerError::InvalidRequest("registration_binding"));
        }
        if presented.worker_generation != registration.worker_generation {
            return Err(WorkerError::InvalidRequest("generation_binding"));
        }
        if !presented
            .authority_epoch
            .is_same_authority(&registration.authority_epoch) {
            return Err(WorkerError::StaleEpoch);
        }
        if presented.state_fence != registration.state_fence {
            return Err(WorkerError::StaleFence);
        }
        if presented.worker_generation != hello.worker_generation
            || presented.worker_generation != process.generation().get()
        {
            return Err(WorkerError::InvalidRequest("generation_binding"));
        }
        if !presented.authority_epoch.is_same_authority(&hello.authority_epoch) {
            return Err(WorkerError::StaleEpoch);
        }
        if presented.state_fence != hello.state_fence {
            return Err(WorkerError::StaleFence);
        }
        if presented.operation_id != *process.operation_id() {
            return Err(WorkerError::InvalidRequest("claim_operation"));
        }
        if hello.deadline_unix_ms > presented.deadline_unix_ms {
            return Err(WorkerError::DeadlineExpired);
        }
        Ok(Self {
            hello: hello.clone(),
            operation_id: process.operation_id().clone(),
            process_tree_id: process.process_tree_id().clone(),
            process_generation: process.generation(),
            process_fence: process.fence().clone(),
            process_request_digest: process.invocation_digest().to_owned(),
            resource_limits: *process.resource_limits(),
            claim: Some(claim.clone()),
        })
    }

    #[must_use]
    pub const fn hello(&self) -> &WorkerHello {
        &self.hello
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    #[must_use]
    pub const fn process_generation(&self) -> Generation {
        self.process_generation
    }

    #[must_use]
    pub const fn process_fence(&self) -> &FencingToken {
        &self.process_fence
    }

    #[must_use]
    pub fn process_request_digest(&self) -> &str {
        &self.process_request_digest
    }

    #[must_use]
    pub const fn resource_limits(&self) -> &ResourceLimits {
        &self.resource_limits
    }

    /// Returns the exact claim presentation this launch is bound to, if any.
    ///
    /// `None` marks the pre-claim start path; `Some` marks a `from_claim`
    /// join that the admission owner must validate against current owner
    /// state before any process start.
    #[must_use]
    pub const fn claim(&self) -> Option<&ClaimAdmissionRequest> {
        self.claim.as_ref()
    }
}

/// Provider assertion. `WorkerCore` cross-validates it before sealing an internal grant.
///
/// Positive authority is deliberately serialize-only and the sealed grant is not public.
///
/// ```compile_fail
/// let json = "{}";
/// let _: eliot_native_worker_core::CapabilityAdmissionFacts =
///     serde_json::from_str(json).expect("positive grants are not deserializable");
/// ```
///
/// ```compile_fail
/// use eliot_native_worker_core::CapabilityGrant;
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAdmissionFacts {
    admission_id: String,
    admission_revision: String,
    revocation_revision: u64,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    stream_id: String,
    producer_id: String,
    route_ref: String,
    artifact_manifest_digest: String,
    worker_generation: u64,
    authority: AuthorityEnvelope,
    capabilities: BTreeSet<String>,
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    process_generation: Generation,
    process_fence: FencingToken,
    process_request_digest: String,
    resource_limits: ResourceLimits,
    /// Echo of the exact claim binding digest the owner admitted, when the
    /// launch was presented under a claim.
    ///
    /// `None` preserves the pre-claim wire shape. A present claim echo
    /// carries no authority by itself: `WorkerCore` re-checks it against
    /// the presented claim before any process start.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_binding_digest: Option<String>,
    /// Echo of the exact attempt bound to the admitted claim, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_attempt_id: Option<AttemptId>,
    /// Echo of the exact operation bound to the admitted claim, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_operation_id: Option<OperationId>,
}

impl CapabilityAdmissionFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_id: impl Into<String>,
        admission_revision: impl Into<String>,
        revocation_revision: u64,
        observed_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        stream_id: impl Into<String>,
        producer_id: impl Into<String>,
        route_ref: impl Into<String>,
        artifact_manifest_digest: impl Into<String>,
        worker_generation: u64,
        authority: AuthorityEnvelope,
        capabilities: BTreeSet<String>,
        operation_id: OperationId,
        process_tree_id: ProcessTreeId,
        process_generation: Generation,
        process_fence: FencingToken,
        process_request_digest: impl Into<String>,
        resource_limits: ResourceLimits,
    ) -> Self {
        Self {
            admission_id: admission_id.into(),
            admission_revision: admission_revision.into(),
            revocation_revision,
            observed_at_unix_ms,
            expires_at_unix_ms,
            stream_id: stream_id.into(),
            producer_id: producer_id.into(),
            route_ref: route_ref.into(),
            artifact_manifest_digest: artifact_manifest_digest.into(),
            worker_generation,
            authority,
            capabilities,
            operation_id,
            process_tree_id,
            process_generation,
            process_fence,
            process_request_digest: process_request_digest.into(),
            resource_limits,
            claim_binding_digest: None,
            claim_attempt_id: None,
            claim_operation_id: None,
        }
    }

    /// Attaches the owner's echo of the exact admitted claim binding.
    ///
    /// Records the claim digest, attempt, and operation the owner admitted
    /// alongside this launch. The echo is inert data: a missing or
    /// disagreeing echo fails closed at grant validation.
    #[must_use]
    pub fn with_claim_binding(mut self, claim: &NativeWorkerClaim) -> Self {
        self.claim_binding_digest = Some(claim.binding_digest.clone());
        self.claim_attempt_id = Some(claim.attempt_id.clone());
        self.claim_operation_id = Some(claim.operation_id.clone());
        self
    }

    #[must_use]
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }

    #[must_use]
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }

    #[must_use]
    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }

    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    #[must_use]
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    #[must_use]
    pub fn route_ref(&self) -> &str {
        &self.route_ref
    }

    #[must_use]
    pub fn artifact_manifest_digest(&self) -> &str {
        &self.artifact_manifest_digest
    }

    #[must_use]
    pub const fn worker_generation(&self) -> u64 {
        self.worker_generation
    }

    #[must_use]
    pub const fn authority(&self) -> &AuthorityEnvelope {
        &self.authority
    }

    #[must_use]
    pub const fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn process_tree_id(&self) -> &ProcessTreeId {
        &self.process_tree_id
    }

    #[must_use]
    pub const fn process_generation(&self) -> Generation {
        self.process_generation
    }

    #[must_use]
    pub const fn process_fence(&self) -> &FencingToken {
        &self.process_fence
    }

    #[must_use]
    pub fn process_request_digest(&self) -> &str {
        &self.process_request_digest
    }

    #[must_use]
    pub const fn resource_limits(&self) -> &ResourceLimits {
        &self.resource_limits
    }

    /// Returns the owner's echo of the admitted claim binding digest, if any.
    #[must_use]
    pub fn claim_binding_digest(&self) -> Option<&str> {
        self.claim_binding_digest.as_deref()
    }

    /// Returns the owner's echo of the attempt bound to the admitted claim.
    #[must_use]
    pub const fn claim_attempt_id(&self) -> Option<&AttemptId> {
        self.claim_attempt_id.as_ref()
    }

    /// Returns the owner's echo of the operation bound to the admitted claim.
    #[must_use]
    pub const fn claim_operation_id(&self) -> Option<&OperationId> {
        self.claim_operation_id.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityGrant(CapabilityAdmissionFacts);

impl CapabilityGrant {
    pub(crate) const fn seal(facts: CapabilityAdmissionFacts) -> Self {
        Self(facts)
    }
}

impl std::ops::Deref for CapabilityGrant {
    type Target = CapabilityAdmissionFacts;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum CapabilityAdmissionOutcome {
    Admitted(Box<CapabilityAdmissionFacts>),
    Rejected { reason: String },
    Revoked { revision: String },
}

/// Provider liveness facts; cached admission is not authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionLivenessFacts {
    admission_id: String,
    admission_revision: String,
    revocation_revision: u64,
    lease: WorkLeaseId,
    authority_epoch: EpochId,
    state_fence: StateFence,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    revoked: bool,
}

impl AdmissionLivenessFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_id: impl Into<String>,
        admission_revision: impl Into<String>,
        revocation_revision: u64,
        lease: WorkLeaseId,
        authority_epoch: EpochId,
        state_fence: StateFence,
        observed_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        revoked: bool,
    ) -> Self {
        Self {
            admission_id: admission_id.into(),
            admission_revision: admission_revision.into(),
            revocation_revision,
            lease,
            authority_epoch,
            state_fence,
            observed_at_unix_ms,
            expires_at_unix_ms,
            revoked,
        }
    }

    #[must_use]
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }
    #[must_use]
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }
    #[must_use]
    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }
    #[must_use]
    pub const fn lease(&self) -> &WorkLeaseId {
        &self.lease
    }
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    #[must_use]
    pub const fn revoked(&self) -> bool {
        self.revoked
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionLiveness(AdmissionLivenessFacts);

impl AdmissionLiveness {
    pub(crate) const fn seal(facts: AdmissionLivenessFacts) -> Self {
        Self(facts)
    }
}

impl std::ops::Deref for AdmissionLiveness {
    type Target = AdmissionLivenessFacts;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum AdmissionLivenessOutcome {
    Live(AdmissionLivenessFacts),
    Rejected { reason: String },
    Revoked { revision: String },
}

/// Inert liveness query derived from the currently sealed grant.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLivenessRequest {
    admission_id: String,
    admission_revision: String,
    revocation_revision: u64,
    lease: WorkLeaseId,
    authority_epoch: EpochId,
    state_fence: StateFence,
}

impl CapabilityLivenessRequest {
    pub(crate) fn from_grant(grant: &CapabilityGrant) -> Self {
        Self {
            admission_id: grant.admission_id().to_owned(),
            admission_revision: grant.admission_revision().to_owned(),
            revocation_revision: grant.revocation_revision(),
            lease: grant.authority().lease.clone(),
            authority_epoch: grant.authority().epoch.clone(),
            state_fence: grant.authority().state_fence.clone(),
        }
    }

    #[must_use]
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }
    #[must_use]
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }
    #[must_use]
    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }
    #[must_use]
    pub const fn lease(&self) -> &WorkLeaseId {
        &self.lease
    }
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
}

/// Created by `WorkerCore`; public callers cannot send it as a worker request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAdmissionRequest {
    proposal: ProposedEffect,
    attempt_id: AttemptId,
    admission_id: String,
    admission_revision: String,
    revocation_revision: u64,
    lease: WorkLeaseId,
    authority_epoch: EpochId,
    state_fence: StateFence,
}

impl EffectAdmissionRequest {
    pub(crate) fn new(
        proposal: ProposedEffect,
        attempt_id: AttemptId,
        grant: &CapabilityGrant,
    ) -> Self {
        Self {
            proposal,
            attempt_id,
            admission_id: grant.admission_id.clone(),
            admission_revision: grant.admission_revision.clone(),
            revocation_revision: grant.revocation_revision,
            lease: grant.authority.lease.clone(),
            authority_epoch: grant.authority.epoch.clone(),
            state_fence: grant.authority.state_fence.clone(),
        }
    }

    #[must_use]
    pub const fn proposal(&self) -> &ProposedEffect {
        &self.proposal
    }

    #[must_use]
    pub const fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }

    #[must_use]
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }

    #[must_use]
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }

    #[must_use]
    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }

    #[must_use]
    pub const fn lease(&self) -> &WorkLeaseId {
        &self.lease
    }

    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
}

/// Provider effect facts. A-13 validates them before sealing a candidate-only grant.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAdmissionFacts {
    authorized_effect: AuthorizedEffect,
    lease: WorkLeaseId,
    state_fence: StateFence,
    admission_revision: String,
    revocation_revision: u64,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    revoked: bool,
}

impl EffectAdmissionFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorized_effect: AuthorizedEffect,
        lease: WorkLeaseId,
        state_fence: StateFence,
        admission_revision: impl Into<String>,
        revocation_revision: u64,
        observed_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        revoked: bool,
    ) -> Self {
        Self {
            authorized_effect,
            lease,
            state_fence,
            admission_revision: admission_revision.into(),
            revocation_revision,
            observed_at_unix_ms,
            expires_at_unix_ms,
            revoked,
        }
    }

    #[must_use]
    pub const fn authorized_effect(&self) -> &AuthorizedEffect {
        &self.authorized_effect
    }
    #[must_use]
    pub const fn lease(&self) -> &WorkLeaseId {
        &self.lease
    }
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
    #[must_use]
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }
    #[must_use]
    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    #[must_use]
    pub const fn revoked(&self) -> bool {
        self.revoked
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectAdmissionGrant(EffectAdmissionFacts);

impl EffectAdmissionGrant {
    pub(crate) const fn seal(facts: EffectAdmissionFacts) -> Self {
        Self(facts)
    }
}

impl std::ops::Deref for EffectAdmissionGrant {
    type Target = EffectAdmissionFacts;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum EffectAdmissionOutcome {
    Authorized(Box<EffectAdmissionFacts>),
    Rejected { reason: String },
    Revoked { revision: String },
}

/// G-01-facing admission boundary selected only by composition.
pub trait CapabilityAdmissionPort: Send {
    fn admit(
        &mut self,
        request: &CapabilityAdmissionRequest,
    ) -> Result<CapabilityAdmissionOutcome, ProviderFailure>;

    fn revalidate(
        &mut self,
        request: &CapabilityLivenessRequest,
    ) -> Result<AdmissionLivenessOutcome, ProviderFailure>;

    fn authorize_effect(
        &mut self,
        request: &EffectAdmissionRequest,
    ) -> Result<EffectAdmissionOutcome, ProviderFailure>;
}

/// Inert checkpoint command derived from the live worker/process binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableCheckpointRequest {
    checkpoint_ref: String,
    request_id: String,
    stream_id: String,
    producer_generation: u64,
    authority_epoch: EpochId,
    state_fence: StateFence,
    admission_revision: String,
    operation_id: OperationId,
    process_request_digest: String,
}

impl DurableCheckpointRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        checkpoint_ref: String,
        request_id: String,
        grant: &CapabilityGrant,
        process: &ProcessBindingSnapshot,
    ) -> Self {
        Self {
            checkpoint_ref,
            request_id,
            stream_id: grant.stream_id().to_owned(),
            producer_generation: grant.worker_generation(),
            authority_epoch: grant.authority().epoch.clone(),
            state_fence: grant.authority().state_fence.clone(),
            admission_revision: grant.admission_revision().to_owned(),
            operation_id: process.operation_id().clone(),
            process_request_digest: process.request_digest().to_owned(),
        }
    }

    #[must_use]
    pub fn checkpoint_ref(&self) -> &str {
        &self.checkpoint_ref
    }
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
    #[must_use]
    pub const fn producer_generation(&self) -> u64 {
        self.producer_generation
    }
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
    #[must_use]
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
    #[must_use]
    pub fn process_request_digest(&self) -> &str {
        &self.process_request_digest
    }
}

/// Provider facts for an already durable checkpoint receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReceiptFacts {
    receipt_id: String,
    checkpoint_ref: String,
    request_id: String,
    stream_id: String,
    producer_generation: u64,
    authority_epoch: EpochId,
    state_fence: StateFence,
    admission_revision: String,
    operation_id: OperationId,
    process_request_digest: String,
    durable_at_unix_ms: u64,
}

impl CheckpointReceiptFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_id: impl Into<String>,
        checkpoint_ref: impl Into<String>,
        request_id: impl Into<String>,
        stream_id: impl Into<String>,
        producer_generation: u64,
        authority_epoch: EpochId,
        state_fence: StateFence,
        admission_revision: impl Into<String>,
        operation_id: OperationId,
        process_request_digest: impl Into<String>,
        durable_at_unix_ms: u64,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            checkpoint_ref: checkpoint_ref.into(),
            request_id: request_id.into(),
            stream_id: stream_id.into(),
            producer_generation,
            authority_epoch,
            state_fence,
            admission_revision: admission_revision.into(),
            operation_id,
            process_request_digest: process_request_digest.into(),
            durable_at_unix_ms,
        }
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }
    #[must_use]
    pub fn checkpoint_ref(&self) -> &str {
        &self.checkpoint_ref
    }
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
    #[must_use]
    pub const fn producer_generation(&self) -> u64 {
        self.producer_generation
    }
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
    #[must_use]
    pub fn admission_revision(&self) -> &str {
        &self.admission_revision
    }
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
    #[must_use]
    pub fn process_request_digest(&self) -> &str {
        &self.process_request_digest
    }
    #[must_use]
    pub const fn durable_at_unix_ms(&self) -> u64 {
        self.durable_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum CheckpointProviderOutcome {
    Stored(Box<CheckpointReceiptFacts>),
    Rejected { reason: String },
}

/// Durable checkpoint owner; A-13 never persists checkpoint state itself.
pub trait DurableCheckpointPort: Send {
    fn persist_checkpoint(
        &mut self,
        request: &DurableCheckpointRequest,
    ) -> Result<CheckpointProviderOutcome, ProviderFailure>;
}

/// Durable idempotency decision. Replay returns the same logical event identities.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum DurableRequestDecision {
    New,
    Replay(Vec<WorkerEventEnvelope>),
    Conflict,
}

/// Durable event/replay/cursor/ack boundary; A-13 owns no private durable journal.
pub trait DurableReplayPort: Send {
    /// Looks up an existing durable identity without claiming a new request.
    fn lookup_request(
        &mut self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure>;

    /// Atomically claims a validated request or returns a concurrent replay/conflict.
    fn begin_request(
        &mut self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure>;

    fn append(&mut self, draft: WorkerEventDraft) -> Result<WorkerEventEnvelope, ProviderFailure>;

    fn replay(
        &mut self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerEventEnvelope>, ProviderFailure>;

    fn acknowledge(&mut self, receipt: &EventAckReceipt) -> Result<(), ProviderFailure>;
}

// ---------------------------------------------------------------------------
// Wave A (issue #872): claim/readiness port projections.
//
// `ClaimAdmissionRequest` presents one claim under one registration to the
// Kernel admission owner; `ReadinessSubmission` carries one typed
// ready-or-blocked result for one admitted claim. Both are inert
// projections: they validate bindings but issue no authority, persist
// nothing, and select no provider.
// ---------------------------------------------------------------------------

/// Exact claim presentation submitted to the Kernel admission owner.
///
/// Binds one validated registration to one validated claim. The Kernel
/// persists the claim transition and returns one immutable claim receipt
/// (Wave B) before the worker may initialize a provider adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimAdmissionRequest {
    registration: NativeWorkerRegistration,
    claim: NativeWorkerClaim,
}

impl ClaimAdmissionRequest {
    /// Returns the registration the claim is presented under.
    #[must_use]
    pub const fn registration(&self) -> &NativeWorkerRegistration {
        &self.registration
    }

    /// Returns the presented claim.
    #[must_use]
    pub const fn claim(&self) -> &NativeWorkerClaim {
        &self.claim
    }

    /// Validates both halves and their cross-binding.
    ///
    /// The claim must reference this exact registration, carry the same
    /// worker generation, and agree on authority epoch and state fence. A
    /// stale or fenced generation, or a claim rewired onto a different
    /// registration, fails here before any Kernel admission owner sees it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for a malformed half or a
    /// registration/generation mismatch, [`WorkerError::StaleEpoch`] or
    /// [`WorkerError::StaleFence`] for epoch/fence disagreement.
    pub fn validate_binding(&self) -> Result<(), WorkerError> {
        self.registration.validate()?;
        self.claim.validate()?;
        if self.claim.registration_id != self.registration.registration_id {
            return Err(WorkerError::InvalidRequest("registration_binding"));
        }
        if self.claim.worker_generation != self.registration.worker_generation {
            return Err(WorkerError::InvalidRequest("generation_binding"));
        }
        if !self
            .claim
            .authority_epoch
            .is_same_authority(&self.registration.authority_epoch) {
            return Err(WorkerError::StaleEpoch);
        }
        if self.claim.state_fence != self.registration.state_fence {
            return Err(WorkerError::StaleFence);
        }
        Ok(())
    }
}

/// One typed ready-or-blocked submission for one admitted claim.
///
/// Carries the worker's readiness verdict to the Kernel admission owner
/// (Wave B). Transport health alone never satisfies this submission: the
/// enclosed [`NativeWorkerReadiness`] binds generation, claim digest,
/// adapter-registry revision, credential references, deadline, and fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessSubmission {
    claim: NativeWorkerClaim,
    readiness: NativeWorkerReadiness,
}

impl ReadinessSubmission {
    /// Returns the admitted claim this submission answers.
    #[must_use]
    pub const fn claim(&self) -> &NativeWorkerClaim {
        &self.claim
    }

    /// Returns the readiness verdict.
    #[must_use]
    pub const fn readiness(&self) -> &NativeWorkerReadiness {
        &self.readiness
    }

    /// Validates the claim and the readiness verdict bound to it.
    ///
    /// Ready reports additionally require the claim deadline to hold at
    /// `now_unix_ms`; blocked reports never fail on an expired deadline
    /// because blocking on expiry is itself a legitimate verdict.
    ///
    /// # Errors
    ///
    /// Returns the underlying claim or readiness validation failure,
    /// including [`WorkerError::DeadlineExpired`] for a ready report past
    /// the claim deadline.
    pub fn validate_binding(&self, now_unix_ms: u64) -> Result<(), WorkerError> {
        self.claim.validate()?;
        match &self.readiness {
            NativeWorkerReadiness::Ready(report) => {
                report.validate_for_claim(&self.claim, now_unix_ms)
            }
            NativeWorkerReadiness::Blocked(report) => report.validate_for_claim(&self.claim),
        }
    }
}
