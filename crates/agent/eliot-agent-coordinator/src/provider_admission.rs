//! Closed production provider verifier (T9-05, issue #1108).
//!
//! Composes the sealed [`ProviderVerifier`](crate::core::ProviderVerifier) on
//! the T9-04 Kernel-supplied capability (`eliot-kernel-service`
//! `protocol::provider_capability`, wire contour
//! `eliot-kernel-provider-capability/v2`): the daemon resolves the presented
//! claim material from the operation at hand plus the owner currentness it
//! observed over its authenticated Kernel session (live fence/epoch, Governor
//! expectation, session binding), hands both halves here as plain validated
//! data, and every `verify` call re-runs the pure T9-04 owner verifier. The
//! coordinator performs no I/O, launches nothing, mints no authority, and
//! never accepts a serialized `Verified` label: restore rebuilds the verifier
//! from freshly supplied capability data and replays every event through it,
//! so stale, revoked, foreign, or conflicting evidence fails closed.
//!
//! Presented versus owner, enforced at construction: the capability carries
//! the ingress-presented claim material ([`PresentedClaimMaterial`]) apart
//! from the session-observed owner currentness ([`OwnerCurrentness`]).
//! [`AdmittedProviderCapability::new`] fails closed unless the presented
//! route/capacity revisions equal the Governor-observed expectation, the
//! presented and expected authority epochs agree with the live session fence
//! epoch, the presented and live resource generations agree, and the pure
//! verifier accepts the whole tuple. Digest equality between the presented
//! binding digests and the durable ORS row is enforced Kernel-side per
//! effecting operation through the authenticated capability wire operation;
//! the coordinator never mistakes its stored presented values for loaded
//! owner evidence.
//!
//! Catalogue, quota, and liveness observations (issue #265) ride only as
//! [`ProviderSelectionHealth`]: selection/health input, never admission. The
//! verifier never reads that field.
//!
//! Binding M1/M2/M3 (issue #22): Kernel supplies, no signing or tokens, the
//! verifier capability is built only in daemon composition from the
//! authenticated Kernel client, and restore re-queries Kernel through a fresh
//! [`AdmittedProviderCapability`].

use eliot_agent_api::{EpochId, StateFence};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_kernel_service::{
    ProviderCapabilityError, ProviderCapabilityExpectation, ProviderCapabilityRequest,
    ProviderProofKind as KernelProofKind, verify_provider_capability,
};

use crate::core::{ProviderProofKind, ProviderVerifier};
use crate::model::{CoordinatorError, ProviderBindingSnapshot, ProviderIdentity, validate_text};

/// Ingress-presented claim material for one provider admission (T9-05
/// presented half, issue #1108).
///
/// Values as claimed by the operation at hand (admission receipt refs, lane
/// claim presentation): validated for shape here, bound to owner currentness
/// by [`AdmittedProviderCapability::new`], and bound to the durable ORS row
/// Kernel-side per effecting operation. Nothing here is trusted by value.
#[derive(Clone, Debug)]
pub struct PresentedClaimMaterial {
    claim_id: String,
    attempt_id: String,
    operation_id: String,
    binding_digest: String,
    executable_digest: String,
    route_revision: String,
    capacity_revision: String,
    worker_generation: u64,
    presented_fence: StateFence,
}

impl PresentedClaimMaterial {
    /// Builds the presented half from the operation at hand.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::InvalidField`] for blank or
    /// control-bearing text, a non-lowercase-SHA-256 digest, or a zero worker
    /// generation, or [`CoordinatorError::ProviderContract`] for an invalid
    /// presented fence.
    #[allow(
        clippy::too_many_arguments,
        reason = "the presented claim is one flat ingress tuple: claim/attempt/operation identities, durable digests, presented revisions, claiming-worker generation, and operation fence; grouping them would invent a second contract beside the T9-04 owner request"
    )]
    pub fn new(
        claim_id: String,
        attempt_id: String,
        operation_id: String,
        binding_digest: String,
        executable_digest: String,
        route_revision: String,
        capacity_revision: String,
        worker_generation: u64,
        presented_fence: StateFence,
    ) -> Result<Self, CoordinatorError> {
        validate_text(&claim_id, "claim_id")?;
        validate_text(&attempt_id, "claim_attempt_id")?;
        validate_text(&operation_id, "claim_operation_id")?;
        require_digest(&binding_digest, "binding_digest")?;
        require_digest(&executable_digest, "executable_digest")?;
        validate_text(&route_revision, "route_revision")?;
        validate_text(&capacity_revision, "capacity_revision")?;
        if worker_generation == 0 {
            return Err(CoordinatorError::InvalidField("worker_generation"));
        }
        presented_fence
            .validate()
            .map_err(|error| CoordinatorError::ProviderContract(error.to_string()))?;
        Ok(Self {
            claim_id,
            attempt_id,
            operation_id,
            binding_digest,
            executable_digest,
            route_revision,
            capacity_revision,
            worker_generation,
            presented_fence,
        })
    }

    /// Recomputes the canonical fence digest over the presented fence bytes.
    ///
    /// Same recipe the Kernel owner uses for the durable `fence_digest`
    /// (canonical JSON plus SHA-256 hex), so the presented fence travels to
    /// the owner as a digest it can compare against the durable row.
    fn fence_digest(&self) -> Result<String, CoordinatorError> {
        let bytes = canonical_json_bytes(&self.presented_fence)
            .map_err(|error| CoordinatorError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Session-observed owner currentness for one provider admission (T9-05 owner
/// half, issue #1108).
///
/// Values the daemon observed over its authenticated Kernel session: the
/// Governor currentness it holds, the live fence it re-queried, and the
/// Kernel-issued session binding it presented under. Carries no secret
/// material (revisions, epoch, fence, identity refs only).
#[derive(Clone, Debug)]
pub struct OwnerCurrentness {
    expectation: ProviderCapabilityExpectation,
    live_fence: StateFence,
    session_binding: String,
}

impl OwnerCurrentness {
    /// Builds the owner half from session-observed currentness.
    ///
    /// The `live_fence` must be freshly re-queried (the daemon's live Kernel
    /// fence), never a cached copy: currency is re-checked on every
    /// coordinator `verify` call against these stored owner values, and
    /// freshness itself arrives by rebuilding this value per construction,
    /// per restore, and per daemon operation resolution.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::InvalidField`] for a blank or
    /// control-bearing session binding, or
    /// [`CoordinatorError::ProviderContract`] for a malformed current
    /// expectation shape or an invalid live fence.
    pub fn new(
        expectation: ProviderCapabilityExpectation,
        live_fence: StateFence,
        session_binding: String,
    ) -> Result<Self, CoordinatorError> {
        expectation
            .validate()
            .map_err(|error| CoordinatorError::ProviderContract(error.to_string()))?;
        live_fence
            .validate()
            .map_err(|error| CoordinatorError::ProviderContract(error.to_string()))?;
        validate_text(&session_binding, "session_binding")?;
        Ok(Self {
            expectation,
            live_fence,
            session_binding,
        })
    }

    /// Returns the session-observed live authority epoch.
    fn live_epoch(&self) -> EpochId {
        self.live_fence.authority_epoch.clone()
    }
}

/// Issue #265 catalogue/quota/liveness observation as selection/health input
/// only.
///
/// Opaque validated references resolved from the current-account catalogue
/// and health owners. The verifier never reads this field, and it never
/// mints admission: it is context for route selection and health projection,
/// carried alongside the admission so selection input and admission evidence
/// cannot be confused.
#[derive(Clone, Debug)]
pub struct ProviderSelectionHealth {
    catalogue_revision: String,
    quota_knowledge_ref: String,
    liveness_observation_ref: String,
}

impl ProviderSelectionHealth {
    /// Builds the input-only health observation from owner references.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::InvalidField`] for blank or
    /// control-bearing text.
    pub fn new(
        catalogue_revision: String,
        quota_knowledge_ref: String,
        liveness_observation_ref: String,
    ) -> Result<Self, CoordinatorError> {
        validate_text(&catalogue_revision, "catalogue_revision")?;
        validate_text(&quota_knowledge_ref, "quota_knowledge_ref")?;
        validate_text(&liveness_observation_ref, "liveness_observation_ref")?;
        Ok(Self {
            catalogue_revision,
            quota_knowledge_ref,
            liveness_observation_ref,
        })
    }

    /// Returns the catalogue revision this observation was resolved under.
    ///
    /// Selection/health input only: reading it never affects admission.
    #[must_use]
    pub fn catalogue_revision(&self) -> &str {
        &self.catalogue_revision
    }

    /// Returns the quota-knowledge reference this observation carries.
    ///
    /// Selection/health input only: reading it never affects admission.
    #[must_use]
    pub fn quota_knowledge_ref(&self) -> &str {
        &self.quota_knowledge_ref
    }

    /// Returns the liveness-observation reference this observation carries.
    ///
    /// Selection/health input only: reading it never affects admission.
    #[must_use]
    pub fn liveness_observation_ref(&self) -> &str {
        &self.liveness_observation_ref
    }
}

/// Daemon-supplied Kernel admission for one provider claim (T9-05 closed
/// production verifier input, issue #1108).
///
/// Plain validated data only: the ingress-presented claim material plus the
/// session-observed owner currentness. Construction fails closed unless the
/// presented half agrees with the owner half (route/capacity revisions,
/// authority epoch, resource generation) and the pure T9-04 verifier accepts
/// the tuple. The coordinator performs no I/O and launches nothing; every
/// proof re-runs the same coherence check plus the pure verifier, and
/// restore requires a freshly supplied value, so a replayed snapshot without
/// live durable backing still fails closed.
///
/// Never serialized: possessing a `Verified` snapshot label grants nothing;
/// only this in-memory value, rebuilt per construction and per restore from
/// exact owner records, admits effects.
#[derive(Clone, Debug)]
pub struct AdmittedProviderCapability {
    identity: ProviderIdentity,
    presented: PresentedClaimMaterial,
    currentness: OwnerCurrentness,
    health: Option<ProviderSelectionHealth>,
    minimum_event_sequence: u64,
}

impl AdmittedProviderCapability {
    /// Builds the admitted capability from presented ingress material plus
    /// session-observed owner currentness.
    ///
    /// The daemon resolves the presented half from the operation at hand and
    /// the owner half over its authenticated Kernel session (live fence plus
    /// Governor currentness): disagreement between the halves fails closed
    /// here, never at first effect. Currency is re-checked on every `verify`
    /// call, never cached; freshness arrives by rebuilding this value per
    /// construction, per restore, and per daemon operation resolution.
    ///
    /// # Errors
    ///
    /// Returns the stored identity error for a malformed provider identity,
    /// [`CoordinatorError::RouteEvidence`] for a presented route revision
    /// disagreeing with the Governor-observed current revision,
    /// [`CoordinatorError::StaleCapacity`] for a presented capacity revision
    /// disagreeing with the Governor-observed current revision,
    /// [`CoordinatorError::StaleController`] for a presented or expected
    /// authority epoch disagreeing with the live session fence epoch,
    /// [`CoordinatorError::StaleFence`] for a presented resource generation
    /// disagreeing with the live session fence generation, or the mapped
    /// owner rejection (stale binding, revoked, malformed) unchanged.
    pub fn new(
        identity: ProviderIdentity,
        presented: PresentedClaimMaterial,
        currentness: OwnerCurrentness,
        health: Option<ProviderSelectionHealth>,
        minimum_event_sequence: u64,
    ) -> Result<Self, CoordinatorError> {
        identity.validate()?;
        let capability = Self {
            identity,
            presented,
            currentness,
            health,
            minimum_event_sequence,
        };
        capability.check_currentness()?;
        capability.check_owner_tuple()?;
        Ok(capability)
    }

    /// Returns the input-only selection/health observation, if any.
    ///
    /// Route selection and health projection read this; the verifier never
    /// does, and it never mints admission.
    #[must_use]
    pub fn health(&self) -> Option<&ProviderSelectionHealth> {
        self.health.as_ref()
    }

    /// Re-checks presented-versus-owner coherence: revisions, epoch, and
    /// generation agreement between the ingress half and the session half.
    fn check_currentness(&self) -> Result<(), CoordinatorError> {
        if self.presented.route_revision != self.currentness.expectation.current_route_revision {
            return Err(CoordinatorError::RouteEvidence);
        }
        if self.presented.capacity_revision
            != self.currentness.expectation.current_capacity_revision
        {
            return Err(CoordinatorError::StaleCapacity);
        }
        if !self
            .currentness
            .expectation
            .live_authority_epoch
            .is_same_authority(&self.currentness.live_epoch())
        {
            return Err(CoordinatorError::StaleController);
        }
        if !self
            .presented
            .presented_fence
            .authority_epoch
            .is_same_authority(&self.currentness.live_epoch())
        {
            return Err(CoordinatorError::StaleController);
        }
        if self.presented.presented_fence.resource_generation
            != self.currentness.live_fence.resource_generation
        {
            return Err(CoordinatorError::StaleFence);
        }
        Ok(())
    }

    /// Runs the pure T9-04 owner verifier over the presented tuple.
    ///
    /// This is a construction-time coherence probe, not a provider proof:
    /// the presenter is the daemon session itself (its session binding rides
    /// as the presenter reference) binding the presented fence digest. The
    /// presented digests travel as both request and loaded evidence here:
    /// digest equality against the durable ORS row is enforced Kernel-side
    /// per effecting operation through the authenticated capability wire
    /// operation, which loads the row itself. This check enforces shape,
    /// revocation, revision agreement, epoch currency, generation form, and
    /// fence-digest form before any effect.
    fn check_owner_tuple(&self) -> Result<(), CoordinatorError> {
        let fence_digest = self.presented.fence_digest()?;
        let request = ProviderCapabilityRequest {
            claim_id: self.presented.claim_id.clone(),
            attempt_id: self.presented.attempt_id.clone(),
            operation_id: self.presented.operation_id.clone(),
            proof_kind: KernelProofKind::Binding,
            proof_ref: self.currentness.session_binding.clone(),
            canonical_payload_sha256: fence_digest.clone(),
            binding_digest: self.presented.binding_digest.clone(),
            executable_binding_digest: self.presented.executable_digest.clone(),
            route_revision: self.presented.route_revision.clone(),
            capacity_revision: self.presented.capacity_revision.clone(),
            worker_generation: self.presented.worker_generation,
            fence_digest,
        };
        verify_provider_capability(
            &request,
            &self.currentness.expectation,
            &self.presented.attempt_id,
            &self.presented.operation_id,
            &self.presented.binding_digest,
            &self.presented.executable_digest,
            self.presented.worker_generation,
            &request.fence_digest,
            &self.currentness.live_epoch(),
        )
        .map_err(map_capability_error)
    }
}

/// Kernel-backed [`ProviderVerifier`]: joins every presented proof with the
/// daemon-supplied admitted capability and re-runs the T9-04 pure verifier.
/// Constructed only through
/// [`AgentCoordinator::new_with_admitted_provider`](crate::core::AgentCoordinator::new_with_admitted_provider)
/// and
/// [`AgentCoordinator::restore_with_admitted_provider`](crate::core::AgentCoordinator::restore_with_admitted_provider);
/// never public, never caller-implementable.
pub(crate) struct KernelProviderVerifier {
    capability: AdmittedProviderCapability,
}

impl KernelProviderVerifier {
    pub(crate) fn new(capability: AdmittedProviderCapability) -> Self {
        Self { capability }
    }
}

impl ProviderVerifier for KernelProviderVerifier {
    fn binding(&self) -> ProviderBindingSnapshot {
        // Conditional by construction: this value exists only because
        // `AdmittedProviderCapability::new` proved presented-versus-owner
        // coherence through the pure verifier. A serialized `Verified`
        // label alone still grants nothing: restore rebuilds this verifier
        // from freshly supplied capability data and replays every event.
        ProviderBindingSnapshot::Verified {
            identity: self.capability.identity.clone(),
        }
    }

    fn minimum_event_sequence(&self) -> u64 {
        self.capability.minimum_event_sequence
    }

    fn verify(
        &self,
        kind: ProviderProofKind,
        identity: &ProviderIdentity,
        proof_ref: &str,
        canonical_payload: &str,
    ) -> Result<(), CoordinatorError> {
        identity.validate()?;
        if identity != &self.capability.identity {
            return Err(CoordinatorError::StaleProviderBinding);
        }
        validate_text(proof_ref, "provider_proof_ref")?;
        if canonical_payload.is_empty() {
            return Err(CoordinatorError::InvalidField("canonical_payload"));
        }
        // The receipt at hand is bound to the admitted provider identity
        // above; its attempt/operation correlation travels in the canonical
        // payload the coordinator itself hashes here, and digest equality
        // against the durable row is enforced Kernel-side per effecting
        // operation. This call re-proves currentness coherence plus the pure
        // owner tuple, so a capability built under stale currentness cannot
        // verify even before the Kernel is consulted.
        self.capability.check_currentness()?;
        let presented = &self.capability.presented;
        let currentness = &self.capability.currentness;
        let fence_digest = presented.fence_digest()?;
        let request = ProviderCapabilityRequest {
            claim_id: presented.claim_id.clone(),
            attempt_id: presented.attempt_id.clone(),
            operation_id: presented.operation_id.clone(),
            proof_kind: map_proof_kind(kind),
            proof_ref: proof_ref.to_owned(),
            canonical_payload_sha256: sha256_hex(canonical_payload.as_bytes()),
            binding_digest: presented.binding_digest.clone(),
            executable_binding_digest: presented.executable_digest.clone(),
            route_revision: presented.route_revision.clone(),
            capacity_revision: presented.capacity_revision.clone(),
            worker_generation: presented.worker_generation,
            fence_digest,
        };
        verify_provider_capability(
            &request,
            &currentness.expectation,
            &presented.attempt_id,
            &presented.operation_id,
            &presented.binding_digest,
            &presented.executable_digest,
            presented.worker_generation,
            &request.fence_digest,
            &currentness.live_epoch(),
        )
        .map_err(map_capability_error)
    }
}

/// Maps the sealed coordinator proof slot onto the Kernel-owned proof kind.
/// All seven slots verify; there is no plan-only or always-verified kind.
fn map_proof_kind(kind: ProviderProofKind) -> KernelProofKind {
    match kind {
        ProviderProofKind::Admission => KernelProofKind::Admission,
        ProviderProofKind::Cancellation => KernelProofKind::Cancellation,
        ProviderProofKind::WorkerFence => KernelProofKind::WorkerFence,
        ProviderProofKind::Reassignment => KernelProofKind::Reassignment,
        ProviderProofKind::Result => KernelProofKind::Result,
        ProviderProofKind::UnknownOutcome => KernelProofKind::UnknownOutcome,
        ProviderProofKind::Binding => KernelProofKind::Binding,
    }
}

/// Maps the Kernel owner rejection onto the closed coordinator vocabulary.
/// Every stale, foreign, withdrawn, or mismatched presentation fails closed;
/// no owner variant default-accepts.
fn map_capability_error(error: ProviderCapabilityError) -> CoordinatorError {
    match error {
        ProviderCapabilityError::UnknownClaim => {
            CoordinatorError::ProviderVerification("unknown provider claim".to_owned())
        }
        // A presentation bound to another claim, disagreeing with durable
        // digest material, or withdrawn by current records never verifies:
        // the persisted binding no longer matches live provider evidence.
        ProviderCapabilityError::ForeignAttempt
        | ProviderCapabilityError::ForeignOperation
        | ProviderCapabilityError::DigestMismatch
        | ProviderCapabilityError::StaleGeneration
        | ProviderCapabilityError::Revoked => CoordinatorError::StaleProviderBinding,
        ProviderCapabilityError::StaleEpoch => CoordinatorError::StaleController,
        ProviderCapabilityError::StaleRoute => CoordinatorError::RouteEvidence,
        ProviderCapabilityError::StaleCapacity => CoordinatorError::StaleCapacity,
        ProviderCapabilityError::InvalidPayloadDigest
        | ProviderCapabilityError::MalformedRequest => {
            CoordinatorError::ProviderVerification(error.to_string())
        }
    }
}

/// Requires one lowercase SHA-256 digest without carrying secret material.
fn require_digest(value: &str, field: &'static str) -> Result<(), CoordinatorError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(CoordinatorError::InvalidField(field))
    }
}
