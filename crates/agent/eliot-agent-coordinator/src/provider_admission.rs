//! Provider claim context and verifier boundary (T9-05, issue #1108).
//!
//! This module composes the sealed
//! [`ProviderVerifier`](crate::core::ProviderVerifier) with plain data
//! supplied by daemon composition: ingress-presented claim material plus
//! session-observed currentness from an authenticated Kernel session. The
//! current coordinator value does not carry an authenticated,
//! operation-specific owner receipt or an original proof record. Its local
//! pure tuple check therefore cannot establish effect authority. Every
//! effecting `verify` call remains a typed failure until the daemon supplies
//! and this boundary validates such an owner receipt. The plan-only
//! constructor continues to use its typed `PLAN_GAP` verifier.
//!
//! [`AdmittedProviderCapability::new`] validates shape and compares presented
//! route/capacity revisions, authority epoch and resource generation with the
//! supplied Governor/session observations. The construction-time pure check
//! reuses presented tuple values as both request and expected values; it is a
//! coherence check only, not an authenticated ORS-row read or proof of an
//! operation payload. Restoring a snapshot rebuilds this context from fresh
//! daemon-supplied data, but does not make historical or new effecting proofs
//! verifiable without the missing operation-specific owner receipt path.
//!
//! The coordinator performs no I/O, launches nothing and mints no authority.
//! A serialized `Verified` identity label is not authority; all effecting
//! operations fail closed through [`KernelProviderVerifier::verify`] while
//! owner receipt verification is unavailable.
//!
//! Catalogue, quota, and liveness observations (issue #265) ride only as
//! [`ProviderSelectionHealth`]: selection/health input, never admission. The
//! verifier never reads that field; route selection projects its refs into
//! the selection lineage through
//! [`ProviderVerifier::selection_health`](crate::core::ProviderVerifier).
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
use crate::model::{
    CoordinatorError, PlanGap, ProviderBindingSnapshot, ProviderIdentity, validate_text,
};

/// Ingress-presented claim material for one provider admission (T9-05
/// presented half, issue #1108).
///
/// Values as claimed by the operation at hand (admission receipt refs, lane
/// claim presentation): validated for shape here and checked against the
/// supplied session currentness by [`AdmittedProviderCapability::new`]. They
/// remain presentation data; this type does not load an ORS row or authorize
/// any effecting proof by itself.
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

    /// Computes the canonical fence digest over the presented fence bytes.
    ///
    /// The digest is request input only; the local coordinator does not load
    /// or authenticate the owner row that contains its expected value.
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

/// Daemon-supplied provider claim context (T9-05, issue #1108).
///
/// Plain validated data only: the ingress-presented claim material plus the
/// session-observed owner currentness. Construction fails closed unless the
/// presented half agrees with the supplied currentness observations
/// (route/capacity revisions, authority epoch, resource generation). Its
/// construction-time pure tuple check is not an authenticated owner receipt.
/// The coordinator performs no I/O and launches nothing; until an
/// operation-specific owner receipt is supplied and verified, every effecting
/// proof returns a typed failure. Restore requires a freshly supplied value,
/// but freshness of this context does not prove historical operation payloads.
///
/// Never serialized: possessing a `Verified` snapshot label grants nothing;
/// this in-memory value records a claim identity/currentness context only and
/// does not itself admit effects.
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
        capability.check_presented_tuple()?;
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

    /// Checks the presented tuple's local shape and currentness coherence.
    ///
    /// This local pure check is not an owner receipt: presented values are
    /// supplied as both request and expected evidence, and no durable ORS row
    /// or operation-specific proof record is loaded here. It can reject
    /// malformed or incoherent input, but it never authorizes an effect.
    fn check_presented_tuple(&self) -> Result<(), CoordinatorError> {
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

/// Kernel-backed [`ProviderVerifier`] context. It checks identity, input
/// shape and supplied currentness, but has no authenticated
/// operation-specific owner receipt to verify. Every effecting proof kind
/// therefore fails closed until that receipt verifier is wired. Constructed
/// only through
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
        // No operation-specific owner receipt is available, so expose an
        // explicit typed gap instead of a misleading Verified label.
        ProviderBindingSnapshot::Gap {
            gap: operation_owner_receipt_gap(),
        }
    }

    fn minimum_event_sequence(&self) -> u64 {
        self.capability.minimum_event_sequence
    }

    fn selection_health(&self) -> Option<&ProviderSelectionHealth> {
        self.capability.health()
    }

    fn verify(
        &self,
        _kind: ProviderProofKind,
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
        // Recheck only the currentness values supplied at construction. This
        // detects stale local observations but does not query Kernel or load
        // the original ORS proof record. No proof kind can authorize an
        // effect until its authenticated, operation-specific owner receipt
        // is available here.
        self.capability.check_currentness()?;
        Err(operation_owner_receipt_gap().into())
    }
}

fn operation_owner_receipt_gap() -> PlanGap {
    PlanGap::G11Unavailable {
        reason: "operation-specific authenticated provider owner receipt verifier is not wired"
            .to_owned(),
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
