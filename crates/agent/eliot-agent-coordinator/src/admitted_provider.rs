//! Closed owner-witnessed admitted-provider factory (issue #1108, item A4).
//!
//! Production construction path from daemon-resolved claim material to the
//! coordinator's closed admission. The factory's constructor itself requires
//! exact owner evidence: an [`OwnerLoadedClaimRow`] carrying the durable
//! Kernel/ORS claim-row fields the daemon loaded under the exact `claim_id`
//! key plus the attempt/operation reverse projection (T9-04), never the
//! ingress-presented values. Arbitrary caller halves and proof strings alone
//! cannot mint a capability through this path: [`AdmittedProviderFactory::admit`]
//! fails closed with [`CoordinatorError::StaleProviderBinding`] unless every
//! presented identity, digest, generation, and fence digest exactly equals the
//! loaded owner row.
//!
//! Supplier (M2, issue #22): the supplier is Kernel over the authenticated
//! front-door session plus ORS operation records bound to the exact attempt;
//! no new signing or token service. ARCH-AUTH-01: authority is explicit,
//! scoped, and fenced — content, model confidence, and role names never create
//! a right to perform a transition or effect. I15.2: principal identity is
//! issued by Kernel, never self-declared. Accordingly this factory never
//! accepts a caller string, boolean, or self-declared session value as the
//! owner side: the owner side is the separately-typed loaded row, and the
//! presented side must agree with it field for field.
//!
//! Reuse, not a second scheme: presented/currentness shape validation stays
//! with the existing owners ([`PresentedClaimMaterial::new`],
//! [`OwnerCurrentness::new`]), the fence-digest recipe stays the canonical
//! JSON plus SHA-256 hex the Kernel owner uses for the durable `fence_digest`,
//! and the capability itself is still built by
//! [`AdmittedProviderCapability::new`]. The agreement gate added here is what
//! makes that existing construction sound: once presented values are proven
//! equal to the daemon-loaded owner row, the coherence and pure-verifier
//! probes inside the existing constructor no longer compare a half against
//! itself.
//!
//! Catalogue, quota, and liveness observations (issue #265) ride only as the
//! existing input-only health half: this factory never reads it, and it never
//! mints admission.

use eliot_agent_api::StateFence;
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_kernel_service::ProviderCapabilityExpectation;

use crate::core::ProviderProofKind;
use crate::model::{CoordinatorError, ProviderIdentity, validate_text};
use crate::provider_admission::{
    AdmittedProviderCapability, OwnerCurrentness, PresentedClaimMaterial, ProviderSelectionHealth,
};

/// Daemon-loaded durable owner row for one provider claim (issue #1108, A4
/// owner side).
///
/// The exact durable fields the daemon resolved from the Kernel/ORS claim
/// read projection under the exact `claim_id` key plus the attempt/operation
/// reverse projection (T9-04): the loaded attempt, operation, binding and
/// executable digests, claiming-worker generation, and fence digest, plus
/// the owner-retained per-receipt canonical-payload digests (issue #1108,
/// A5) the sealed verifier passes as the loaded payload leg. Carries
/// no secret material (identities, digests, generation only); the live fence
/// and Governor currentness travel alongside through [`OwnerCurrentness`],
/// never inside this row.
#[derive(Clone, Debug)]
pub struct OwnerLoadedClaimRow {
    claim_id: String,
    attempt_id: String,
    operation_id: String,
    binding_digest: String,
    executable_digest: String,
    worker_generation: u64,
    fence_digest: String,
    /// Owner-retained canonical-payload digest of the admission receipt, if
    /// recorded on the durable row yet.
    admission_payload_sha256: Option<String>,
    /// Owner-retained canonical-payload digest of the cancellation receipt,
    /// if recorded on the durable row yet.
    cancellation_payload_sha256: Option<String>,
    /// Owner-retained canonical-payload digest of the worker-fence receipt,
    /// if recorded on the durable row yet.
    worker_fence_payload_sha256: Option<String>,
    /// Owner-retained canonical-payload digest of the reassignment receipt,
    /// if recorded on the durable row yet.
    reassignment_payload_sha256: Option<String>,
    /// Owner-retained canonical-payload digest of the result submission, if
    /// recorded on the durable row yet.
    result_payload_sha256: Option<String>,
    /// Owner-retained canonical-payload digest of the unknown-outcome
    /// receipt, if recorded on the durable row yet.
    unknown_outcome_payload_sha256: Option<String>,
}

impl OwnerLoadedClaimRow {
    /// Builds the owner side from daemon-loaded durable row fields.
    ///
    /// Shape validation only: proving these values are the live durable row
    /// is the daemon's lookup (exact `claim_id` key plus the attempt/operation
    /// reverse projection), and proving the presented half agrees with them is
    /// [`AdmittedProviderFactory::admit`]. Nothing here is trusted by value.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::InvalidField`] for blank or
    /// control-bearing identities, a non-lowercase-SHA-256 digest, or a zero
    /// worker generation.
    #[allow(
        clippy::too_many_arguments,
        reason = "the owner row is one flat durable tuple: claim/attempt/operation identities, durable digests, claiming-worker generation, and fence digest; grouping them would invent a second contract beside the T9-04 loaded parameters"
    )]
    pub fn new(
        claim_id: String,
        attempt_id: String,
        operation_id: String,
        binding_digest: String,
        executable_digest: String,
        worker_generation: u64,
        fence_digest: String,
    ) -> Result<Self, CoordinatorError> {
        validate_text(&claim_id, "loaded_claim_id")?;
        validate_text(&attempt_id, "loaded_claim_attempt_id")?;
        validate_text(&operation_id, "loaded_claim_operation_id")?;
        require_loaded_digest(&binding_digest, "loaded_binding_digest")?;
        require_loaded_digest(&executable_digest, "loaded_executable_digest")?;
        require_loaded_digest(&fence_digest, "loaded_fence_digest")?;
        if worker_generation == 0 {
            return Err(CoordinatorError::InvalidField("loaded_worker_generation"));
        }
        Ok(Self {
            claim_id,
            attempt_id,
            operation_id,
            binding_digest,
            executable_digest,
            worker_generation,
            fence_digest,
            // No per-kind payload evidence yet: the daemon attaches the
            // witnessed slots through `with_receipt_payloads` once it holds
            // the Kernel claim-row projection, so a row built without that
            // projection carries no owner evidence on the payload leg and the
            // owner passes that leg until the recorder lands.
            admission_payload_sha256: None,
            cancellation_payload_sha256: None,
            worker_fence_payload_sha256: None,
            reassignment_payload_sha256: None,
            result_payload_sha256: None,
            unknown_outcome_payload_sha256: None,
        })
    }

    /// Attaches the owner-retained per-receipt payload digests witnessed on
    /// the durable row (issue #1108, A5 carrier).
    ///
    /// Called only by the daemon row loader with the six slots exactly as
    /// the Kernel claim-row projection returned them: a slot is `None`
    /// until its kind's payload is recorded (pre-column rows decode
    /// all-`None`). Shape validation reuses the existing loaded-digest rule;
    /// a malformed retained digest fails closed here and never verifies.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::InvalidField`] for a retained payload
    /// digest that is not a lowercase SHA-256.
    pub fn with_receipt_payloads(
        mut self,
        admission_payload_sha256: Option<String>,
        cancellation_payload_sha256: Option<String>,
        worker_fence_payload_sha256: Option<String>,
        reassignment_payload_sha256: Option<String>,
        result_payload_sha256: Option<String>,
        unknown_outcome_payload_sha256: Option<String>,
    ) -> Result<Self, CoordinatorError> {
        for (slot, field) in [
            (&admission_payload_sha256, "loaded_admission_payload_sha256"),
            (
                &cancellation_payload_sha256,
                "loaded_cancellation_payload_sha256",
            ),
            (
                &worker_fence_payload_sha256,
                "loaded_worker_fence_payload_sha256",
            ),
            (
                &reassignment_payload_sha256,
                "loaded_reassignment_payload_sha256",
            ),
            (&result_payload_sha256, "loaded_result_payload_sha256"),
            (
                &unknown_outcome_payload_sha256,
                "loaded_unknown_outcome_payload_sha256",
            ),
        ] {
            if let Some(digest) = slot {
                require_loaded_digest(digest, field)?;
            }
        }
        self.admission_payload_sha256 = admission_payload_sha256;
        self.cancellation_payload_sha256 = cancellation_payload_sha256;
        self.worker_fence_payload_sha256 = worker_fence_payload_sha256;
        self.reassignment_payload_sha256 = reassignment_payload_sha256;
        self.result_payload_sha256 = result_payload_sha256;
        self.unknown_outcome_payload_sha256 = unknown_outcome_payload_sha256;
        Ok(self)
    }

    /// Requires the ingress-presented half to equal this loaded owner row
    /// field for field.
    ///
    /// Claim, attempt, operation, both digests, worker generation, and the
    /// recomputed presented fence digest must each exactly equal the
    /// daemon-loaded value. Any disagreement fails closed: the persisted
    /// binding no longer matches live provider evidence, which needs a new
    /// admission, never a local repair.
    #[allow(
        clippy::too_many_arguments,
        reason = "the agreement gate compares the exact presented tuple against the row one field per parameter so a partial comparison cannot silently pass"
    )]
    fn require_presented_agreement(
        &self,
        claim_id: &str,
        attempt_id: &str,
        operation_id: &str,
        binding_digest: &str,
        executable_digest: &str,
        worker_generation: u64,
        presented_fence_digest: &str,
    ) -> Result<(), CoordinatorError> {
        if self.claim_id != claim_id
            || self.attempt_id != attempt_id
            || self.operation_id != operation_id
            || self.binding_digest != binding_digest
            || self.executable_digest != executable_digest
            || self.worker_generation != worker_generation
            || self.fence_digest != presented_fence_digest
        {
            return Err(CoordinatorError::StaleProviderBinding);
        }
        Ok(())
    }

    /// Returns the loaded attempt identity this row was read under.
    ///
    /// Crate-internal: the sealed verifier reads the witnessed row back
    /// through these accessors on every proof, so the loaded legs never alias
    /// the presented half once the factory witnessed them.
    pub(crate) fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Returns the loaded operation identity this row was read under.
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the loaded claim binding digest.
    pub(crate) fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    /// Returns the loaded executable binding digest.
    pub(crate) fn executable_digest(&self) -> &str {
        &self.executable_digest
    }

    /// Returns the loaded claiming-worker generation.
    pub(crate) fn worker_generation(&self) -> u64 {
        self.worker_generation
    }

    /// Returns the witnessed retained payload digest for one proof kind
    /// (issue #1108, A5 carrier).
    ///
    /// Crate-internal: the sealed verifier passes this as the loaded
    /// canonical-payload leg, so it never aliases the presented half. A
    /// kind with no retained slot (`Binding`, which the ORS column does not
    /// cover) or with no recorded payload yet yields empty, which the owner
    /// treats as "no evidence on this leg"; a retained digest that
    /// disagrees with the presented payload fails closed in the owner.
    pub(crate) fn receipt_payload_for_kind(&self, kind: &ProviderProofKind) -> &str {
        match kind {
            ProviderProofKind::Admission => self.admission_payload_sha256.as_deref(),
            ProviderProofKind::Cancellation => self.cancellation_payload_sha256.as_deref(),
            ProviderProofKind::WorkerFence => self.worker_fence_payload_sha256.as_deref(),
            ProviderProofKind::Reassignment => self.reassignment_payload_sha256.as_deref(),
            ProviderProofKind::Result => self.result_payload_sha256.as_deref(),
            ProviderProofKind::UnknownOutcome => self.unknown_outcome_payload_sha256.as_deref(),
            ProviderProofKind::Binding => None,
        }
        .unwrap_or("")
    }
}

/// Closed admitted-provider factory bound to one loaded owner row (issue
/// #1108, A4 production port).
///
/// Closed port, not a trait: there is no caller-implementable verifier hook.
/// The value exists only because the constructor was given the daemon-loaded
/// owner row; [`admit`](Self::admit) then proves the ingress-presented half
/// agrees with that row before any existing validator observes either half.
/// The coordinator still performs no I/O, launches nothing, and mints no
/// authority.
#[derive(Clone, Debug)]
pub struct AdmittedProviderFactory {
    loaded: OwnerLoadedClaimRow,
}

impl AdmittedProviderFactory {
    /// Binds the factory to the daemon-loaded owner row.
    ///
    /// The `loaded` row must come from the daemon's Kernel/ORS claim read
    /// projection (exact `claim_id` key plus the attempt/operation reverse
    /// projection) for this exact construction. Caller halves alone cannot
    /// satisfy this constructor: it takes no bare strings, only the
    /// explicitly owner-typed row.
    #[must_use]
    pub fn new(loaded: OwnerLoadedClaimRow) -> Self {
        Self { loaded }
    }

    /// Admits one provider capability from presented ingress material plus the
    /// session-observed owner currentness, witnessed against the loaded row.
    ///
    /// The daemon resolves the presented values from the operation at hand
    /// and the currentness triple over its authenticated Kernel session (live
    /// fence plus Governor currentness plus session binding). This call first
    /// proves the presented identities, digests, generation, and fence digest
    /// equal the bound owner row, then builds both halves through their
    /// existing owners and the existing capability constructor, so the
    /// downstream coherence and pure-verifier probes judge values already
    /// proven equal to owner-loaded evidence.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::StaleProviderBinding`] when any presented
    /// value disagrees with the loaded owner row; otherwise returns the
    /// existing half- and capability-construction errors unchanged (malformed
    /// identity, stale route/capacity/epoch/fence, revoked or mismatched
    /// owner tuple).
    #[allow(
        clippy::too_many_arguments,
        reason = "the factory carries the exact ingress-presented tuple, the session-observed currentness triple, and the bound owner row to one construction so a single source builds both halves; splitting them would let a caller present one tuple for agreement and another for construction"
    )]
    pub fn admit(
        &self,
        identity: ProviderIdentity,
        claim_id: String,
        attempt_id: String,
        operation_id: String,
        binding_digest: String,
        executable_digest: String,
        route_revision: String,
        capacity_revision: String,
        worker_generation: u64,
        presented_fence: StateFence,
        expectation: ProviderCapabilityExpectation,
        live_fence: StateFence,
        health: Option<ProviderSelectionHealth>,
        minimum_event_sequence: u64,
    ) -> Result<AdmittedProviderCapability, CoordinatorError> {
        // Same recipe the Kernel owner uses for the durable `fence_digest`
        // (canonical JSON plus SHA-256 hex): the presented fence travels to
        // the agreement gate as a digest the loaded row can be compared
        // against, never as bare fence bytes.
        let presented_fence_digest = sha256_hex(
            &canonical_json_bytes(&presented_fence)
                .map_err(|error| CoordinatorError::Serialization(error.to_string()))?,
        );
        self.loaded.require_presented_agreement(
            &claim_id,
            &attempt_id,
            &operation_id,
            &binding_digest,
            &executable_digest,
            worker_generation,
            &presented_fence_digest,
        )?;
        let presented = PresentedClaimMaterial::new(
            claim_id,
            attempt_id,
            operation_id,
            binding_digest,
            executable_digest,
            route_revision,
            capacity_revision,
            worker_generation,
            presented_fence,
        )?;
        let currentness = OwnerCurrentness::new(expectation, live_fence)?;
        // The witnessed row travels into the capability with the halves it
        // just agreed with, so every later proof re-proves presented values
        // against this retained durable evidence instead of aliasing the
        // presented half.
        AdmittedProviderCapability::new_with_witnessed_row(
            identity,
            presented,
            currentness,
            health,
            minimum_event_sequence,
            self.loaded.clone(),
        )
    }
}

/// Requires one lowercase SHA-256 digest without carrying secret material.
///
/// Same wire-shape rule the presented-half owner enforces for binding,
/// executable, and fence digests: 64 lowercase hex characters.
fn require_loaded_digest(value: &str, field: &'static str) -> Result<(), CoordinatorError> {
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
