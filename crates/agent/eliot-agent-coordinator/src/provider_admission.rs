//! Closed production provider verifier (T9-05, issue #1108).
//!
//! Composes the sealed [`ProviderVerifier`](crate::core::ProviderVerifier) on
//! the T9-04 Kernel-supplied capability (`eliot-kernel-service`
//! `protocol::provider_capability`, wire contour
//! `eliot-kernel-provider-capability/v1`): the daemon extracts the durable
//! claim row plus the current Governor expectation over its authenticated
//! Kernel session, hands them here as plain validated data, and every
//! `verify` call re-runs the pure T9-04 owner verifier. The coordinator
//! performs no I/O, launches nothing, mints no authority, and never accepts
//! a serialized `Verified` label: restore rebuilds the verifier from freshly
//! supplied capability data and replays every event through it, so stale,
//! revoked, foreign, or conflicting evidence fails closed.
//!
//! Binding M1/M2/M3 (issue #22): Kernel supplies, no signing or tokens, the
//! verifier capability is built only in daemon composition from the
//! authenticated Kernel client, and restore re-queries Kernel through a fresh
//! [`AdmittedProviderCapability`].

use eliot_contracts::{EpochId, sha256_hex};
use eliot_kernel_service::{
    ProviderCapabilityError, ProviderCapabilityExpectation, ProviderCapabilityRequest,
    ProviderProofKind as KernelProofKind, verify_provider_capability,
};

use crate::core::{ProviderProofKind, ProviderVerifier};
use crate::model::{CoordinatorError, ProviderBindingSnapshot, ProviderIdentity, validate_text};

/// Daemon-supplied Kernel admission for one provider claim (T9-05 closed
/// production verifier input, issue #1108).
///
/// Plain validated data only, extracted by the daemon caller from its
/// authenticated Kernel session (durable ORS claim row) plus the Governor
/// currentness it observed: claim/attempt/operation identities, durable
/// binding and executable digests, presented route/capacity revisions, the
/// caller-supplied current [`ProviderCapabilityExpectation`], the live epoch
/// source, and the minimum replayed event sequence. The coordinator performs
/// no I/O and launches nothing; every proof re-runs the T9-04 pure verifier
/// against this data, and restore requires a freshly supplied value, so a
/// replayed snapshot without live durable backing still fails closed.
///
/// Never serialized: possessing a `Verified` snapshot label grants nothing;
/// only this in-memory value, rebuilt per construction and per restore from
/// exact owner records, admits effects.
#[derive(Clone, Debug)]
pub struct AdmittedProviderCapability {
    identity: ProviderIdentity,
    claim_id: String,
    attempt_id: String,
    operation_id: String,
    binding_digest: String,
    executable_digest: String,
    route_revision: String,
    capacity_revision: String,
    expectation: ProviderCapabilityExpectation,
    live_epoch: EpochId,
    minimum_event_sequence: u64,
}

impl AdmittedProviderCapability {
    /// Builds the admitted capability from exact owner records.
    ///
    /// The daemon resolves the durable claim row through the ORS read
    /// projection, presents the Governor revisions it observed, and passes
    /// the live authority epoch it holds: nothing here is trusted by value,
    /// and currency is re-checked on every `verify` call, never cached.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::InvalidField`] for a blank or
    /// control-bearing identity or a non-lowercase-SHA-256 digest, the
    /// stored identity error for a malformed provider identity, or
    /// [`CoordinatorError::ProviderContract`] for a malformed current
    /// expectation shape.
    #[allow(
        clippy::too_many_arguments,
        reason = "the admitted capability is one flat owner tuple: claim/attempt/operation identities, durable digests, presented revisions, current expectation, live epoch, and replay floor; grouping them would invent a second contract beside the T9-04 owner types"
    )]
    pub fn new(
        identity: ProviderIdentity,
        claim_id: String,
        attempt_id: String,
        operation_id: String,
        binding_digest: String,
        executable_digest: String,
        route_revision: String,
        capacity_revision: String,
        expectation: ProviderCapabilityExpectation,
        live_epoch: EpochId,
        minimum_event_sequence: u64,
    ) -> Result<Self, CoordinatorError> {
        identity.validate()?;
        validate_text(&claim_id, "claim_id")?;
        validate_text(&attempt_id, "claim_attempt_id")?;
        validate_text(&operation_id, "claim_operation_id")?;
        require_digest(&binding_digest, "binding_digest")?;
        require_digest(&executable_digest, "executable_digest")?;
        validate_text(&route_revision, "route_revision")?;
        validate_text(&capacity_revision, "capacity_revision")?;
        expectation
            .validate()
            .map_err(|error| CoordinatorError::ProviderContract(error.to_string()))?;
        Ok(Self {
            identity,
            claim_id,
            attempt_id,
            operation_id,
            binding_digest,
            executable_digest,
            route_revision,
            capacity_revision,
            expectation,
            live_epoch,
            minimum_event_sequence,
        })
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
        let request = ProviderCapabilityRequest {
            claim_id: self.capability.claim_id.clone(),
            attempt_id: self.capability.attempt_id.clone(),
            operation_id: self.capability.operation_id.clone(),
            proof_kind: map_proof_kind(kind),
            proof_ref: proof_ref.to_owned(),
            canonical_payload_sha256: sha256_hex(canonical_payload.as_bytes()),
            binding_digest: self.capability.binding_digest.clone(),
            executable_binding_digest: self.capability.executable_digest.clone(),
            route_revision: self.capability.route_revision.clone(),
            capacity_revision: self.capability.capacity_revision.clone(),
        };
        verify_provider_capability(
            &request,
            &self.capability.expectation,
            &self.capability.attempt_id,
            &self.capability.operation_id,
            &self.capability.binding_digest,
            &self.capability.executable_digest,
            &self.capability.live_epoch,
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
