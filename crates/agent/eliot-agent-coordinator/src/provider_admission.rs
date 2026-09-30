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
//! Presented versus owner, separated at construction and joined at proof:
//! the capability carries the ingress-presented claim material
//! ([`PresentedClaimMaterial`]) apart from the session-observed owner
//! currentness ([`OwnerCurrentness`]). [`AdmittedProviderCapability::new`]
//! validates shape only (identity plus each half's own closed shape), so a
//! stale or revoked pairing still constructs and can never report `Verified`
//! on its own. Every `verify` joins the halves through the pure T9-04
//! verifier: the presented route/capacity revisions must equal the
//! Governor-observed expectation, the presented and expected authority
//! epochs must agree with the live session fence epoch, the presented and
//! live resource generations must agree, the presented fence digest must
//! equal the digest recomputed from the live session fence, and revocation
//! refuses the proof. Stale, revoked, foreign, or conflicting evidence
//! therefore fails closed at the operation boundary without mutation.
//! Digest equality of the remaining presented legs against the durable ORS
//! row is enforced Kernel-side per effecting operation through the
//! authenticated capability wire operation, which loads the row itself; the
//! coordinator never mistakes its stored presented values for loaded owner
//! evidence.
//!
//! Residual STITCH (issue #1108 A5): the loaded legs passed to the pure owner
//! verifier in [`KernelProviderVerifier::verify`] alias the presented half
//! (attempt, operation, digests, generation); only the fence leg rides
//! owner-observed evidence (the live-fence digest) while attempt/operation
//! mismatch is caught receipt-side from the ORIGINAL bytes. Binding the
//! digest legs against the durable row per effecting operation demands the
//! factory-witnessed row retained in this capability (producer:
//! [`AdmittedProviderFactory::admit`]) plus a daemon row source that no seam
//! returns today. Until both land, the owner digest/generation gates re-prove
//! construction-time coherence, not a fresh row read.
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

use std::sync::atomic::{AtomicBool, Ordering};

use eliot_agent_api::{EpochId, StateFence};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_kernel_service::{
    ProviderCapabilityError, ProviderCapabilityExpectation, ProviderCapabilityRequest,
    ProviderProofKind as KernelProofKind, verify_provider_capability,
};

use crate::core::{ProviderProofKind, ProviderVerifier};
use crate::model::{
    CoordinatorError, PlanGap, ProviderAdmissionReceipt, ProviderBindingSnapshot,
    ProviderCancellationReconciliation, ProviderExecutionBindingSubmission, ProviderIdentity,
    ProviderReassignmentReceipt, ProviderUnknownOutcomeReconciliation, ProviderWorkerFenceReceipt,
    ResultSubmission, validate_text,
};

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
/// Governor currentness it holds and the live fence it re-queried.
/// Carries no secret material (revisions, epoch, fence, identity refs only).
///
/// The owner half retains no caller-supplied proof strings: session proof
/// material is resolved live by the daemon at each construction and is never
/// stored here, so a retained string can never mint trust.
#[derive(Clone, Debug)]
pub struct OwnerCurrentness {
    expectation: ProviderCapabilityExpectation,
    live_fence: StateFence,
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
    /// Returns [`CoordinatorError::ProviderContract`] for a malformed current
    /// expectation shape or an invalid live fence.
    pub fn new(
        expectation: ProviderCapabilityExpectation,
        live_fence: StateFence,
    ) -> Result<Self, CoordinatorError> {
        expectation
            .validate()
            .map_err(|error| CoordinatorError::ProviderContract(error.to_string()))?;
        live_fence
            .validate()
            .map_err(|error| CoordinatorError::ProviderContract(error.to_string()))?;
        Ok(Self {
            expectation,
            live_fence,
        })
    }

    /// Returns the session-observed live authority epoch.
    fn live_epoch(&self) -> EpochId {
        self.live_fence.authority_epoch.clone()
    }

    /// Recomputes the canonical fence digest over the session-observed live
    /// fence bytes.
    ///
    /// Same recipe as the presented side
    /// ([`PresentedClaimMaterial::fence_digest`]): the live fence the daemon
    /// freshly re-queried over its authenticated Kernel session, so the
    /// loaded fence-digest side of the owner tuple is owner-observed
    /// evidence, never a presented echo.
    fn live_fence_digest(&self) -> Result<String, CoordinatorError> {
        let bytes = canonical_json_bytes(&self.live_fence)
            .map_err(|error| CoordinatorError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
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
/// session-observed owner currentness. Construction validates shape only;
/// presented-versus-owner coherence and revocation are judged on every
/// `verify` through the pure T9-04 verifier, so stale, revoked, foreign, or
/// conflicting evidence fails closed at the operation boundary without
/// mutation. The coordinator performs no I/O and launches nothing; every
/// proof re-runs the coherence check plus the pure verifier, and
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
    /// Construction validates shape only: the provider identity plus each
    /// half's own closed shape (claim/attempt/operation text, digest form,
    /// nonzero generation, fence validity, expectation shape, session
    /// binding text). Presented-versus-owner coherence — route/capacity
    /// revisions, authority epoch, resource generation, live fence digest —
    /// plus revocation is judged on every `verify` call through the pure
    /// T9-04 verifier, so stale, revoked, foreign, or conflicting evidence
    /// fails closed at the operation boundary without mutation, and a merely
    /// constructed capability never reports `Verified` until its first
    /// successful proof. The daemon resolves the presented half from the
    /// operation at hand and the owner half over its authenticated Kernel
    /// session (live fence plus Governor currentness) before calling here;
    /// freshness arrives by rebuilding this value per construction, per
    /// restore, and per daemon operation resolution.
    ///
    /// # Errors
    ///
    /// Returns the stored identity error for a malformed provider identity.
    pub fn new(
        identity: ProviderIdentity,
        presented: PresentedClaimMaterial,
        currentness: OwnerCurrentness,
        health: Option<ProviderSelectionHealth>,
        minimum_event_sequence: u64,
    ) -> Result<Self, CoordinatorError> {
        identity.validate()?;
        Ok(Self {
            identity,
            presented,
            currentness,
            health,
            minimum_event_sequence,
        })
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
    ///
    /// Runs at the head of every `verify`, never at construction, so stale
    /// or revoked evidence fails closed at the operation boundary without
    /// mutation: construction validates shape only.
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
}

/// Kernel-backed [`ProviderVerifier`]: joins every presented proof with the
/// daemon-supplied admitted capability and re-runs the T9-04 pure verifier.
/// Constructed only through
/// [`AgentCoordinator::new_with_admitted_provider`](crate::core::AgentCoordinator::new_with_admitted_provider)
/// and
/// [`AgentCoordinator::restore_with_admitted_provider`](crate::core::AgentCoordinator::restore_with_admitted_provider);
/// never public, never caller-implementable.
///
/// Closed until owner-proved: construction alone (including factory-gated
/// construction through
/// [`AdmittedProviderFactory::admit`](crate::admitted_provider::AdmittedProviderFactory::admit))
/// never reports `Verified`. The binding stays a typed `PLAN_GAP` until one
/// `verify` call on this instance succeeds through the owner verifier, and
/// only that success flips it. A constructed-but-unverified capability
/// therefore cannot mint `Verified`.
pub(crate) struct KernelProviderVerifier {
    capability: AdmittedProviderCapability,
    /// Flipped exactly once a `verify` call on this instance returns owner
    /// `Ok`. `AtomicBool` (not `Cell`/`RefCell`: the sealed
    /// [`ProviderVerifier`](crate::core::ProviderVerifier) is `Send + Sync`,
    /// and this file otherwise carries no interior-mutability idiom) because
    /// `verify` borrows `&self` while the trait signature stays frozen.
    verified: AtomicBool,
}

/// Typed `PLAN_GAP` reason reported while this verifier instance has no
/// successful owner verification yet. A fixed string, so pre-verification
/// snapshots compare equal across construction and restore.
const UNVERIFIED_GAP_REASON: &str =
    "provider admission unverified: no successful owner verification on this verifier instance";

impl KernelProviderVerifier {
    pub(crate) fn new(capability: AdmittedProviderCapability) -> Self {
        Self {
            capability,
            verified: AtomicBool::new(false),
        }
    }
}

impl ProviderVerifier for KernelProviderVerifier {
    fn binding(&self) -> ProviderBindingSnapshot {
        // Closed by instance state, not by construction: this value reports
        // `Verified` only after a `verify` call on THIS instance succeeded
        // through the owner verifier. Before that it is a typed `PLAN_GAP`,
        // so a merely constructed capability cannot impersonate production
        // execution readiness, and a serialized `Verified` label alone still
        // grants nothing: restore rebuilds this verifier from freshly
        // supplied capability data and replays every event through it.
        if self.verified.load(Ordering::SeqCst) {
            ProviderBindingSnapshot::Verified {
                identity: self.capability.identity.clone(),
            }
        } else {
            ProviderBindingSnapshot::Gap {
                gap: PlanGap::G11Unavailable {
                    reason: UNVERIFIED_GAP_REASON.to_owned(),
                },
            }
        }
    }

    fn minimum_event_sequence(&self) -> u64 {
        self.capability.minimum_event_sequence
    }

    /// Sole reader of the input-only issue #265 observation: route selection
    /// and health projection read this; [`verify`](ProviderVerifier::verify)
    /// below never does, and it never mints admission.
    fn selection_health(&self) -> Option<&ProviderSelectionHealth> {
        self.capability.health()
    }

    /// Verifies one presented proof of any receipt kind through the T9-04
    /// pure owner verifier over the admitted presented/owner halves.
    ///
    /// Health-input boundary (issue #265, W6): this call never reads the
    /// capability `health` half. Catalogue, quota, and liveness observations
    /// reach route selection only through `selection_health` above, so
    /// changing or dropping them cannot change a verify outcome; human
    /// detail, provider names, and liveness never decide validity.
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
        // above; its per-kind attempt/operation identity is read from the
        // ORIGINAL canonical bytes (typed per-kind receipt schemas, never an
        // opaque string path and never a recomputed stand-in) and carried as
        // the owner request, while the admitted claim rides as the loaded
        // durable row. A receipt naming an attempt or operation the claim
        // never covered fails closed through the owner as `ForeignAttempt` /
        // `ForeignOperation` (typed `StaleProviderBinding`, the same typed
        // error a revoked or mismatched binding yields); only cancellation
        // receipts carry an operation identity, so every other kind rides the
        // claim operation explicitly and there is no receipt-side operation
        // to drift. The fence leg is owner-grounded both sides of the
        // comparison: the request carries the presented fence digest while
        // the loaded side carries the digest recomputed from the live fence
        // the daemon freshly re-queried over its authenticated session, so a
        // proof presented under a moved fence fails closed here even when
        // the epoch value and resource generation alone still agree. Digest
        // equality of the remaining legs against the durable ORS row stays
        // enforced Kernel-side per effecting operation through the
        // authenticated capability wire operation, and the payload-digest
        // slot carries the true digest of these original receipt bytes
        // because the owner wire requires digest form (the pure owner
        // shape-checks it; per-receipt payload content equality under one
        // identity is enforced by the coordinator's own per-kind replay
        // checks and the daemon's durable envelopes, since the ORS claim row
        // carries no per-receipt payload column in this slice). Currency is
        // re-proved on every call, so a capability built under stale
        // currentness cannot verify even before the Kernel owner tuple runs.
        self.capability.check_currentness()?;
        let presented = &self.capability.presented;
        let currentness = &self.capability.currentness;
        let (receipt_attempt_id, receipt_operation_id) =
            receipt_proof_identity(kind, canonical_payload, &presented.operation_id)?;
        let fence_digest = presented.fence_digest()?;
        let live_fence_digest = currentness.live_fence_digest()?;
        let request = ProviderCapabilityRequest {
            claim_id: presented.claim_id.clone(),
            attempt_id: receipt_attempt_id,
            operation_id: receipt_operation_id,
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
        // Validates the ORIGINAL assembled request via the existing owner
        // validator before delegating: shape, revocation, exact
        // receipt-versus-claim attempt/operation match, epoch currency,
        // revision agreement, digest equality, generation and fence binding
        // are all owner-checked below against the loaded claim row.
        request.validate().map_err(map_capability_error)?;
        verify_provider_capability(
            &request,
            &currentness.expectation,
            &presented.attempt_id,
            &presented.operation_id,
            &presented.binding_digest,
            &presented.executable_digest,
            presented.worker_generation,
            &live_fence_digest,
            &currentness.live_epoch(),
        )
        .map_err(map_capability_error)?;
        // Only a successful owner verification on this instance flips the
        // binding: every `Err` above returns before this store, so a failed
        // or stale proof never mints `Verified`, and the flag is never set
        // from a recomputed stand-in, only from the owner `Ok` just observed.
        self.verified.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// Reads the receipt-claimed attempt/operation identity for one proof kind
/// from the receipt's ORIGINAL canonical bytes (issue #1108 A5).
///
/// Each kind names its exact identity fields explicitly through the existing
/// typed receipt schemas (all `deny_unknown_fields`): admission binds every
/// admitted lane attempt (one admission receipt under a single-attempt claim
/// names one attempt; a receipt spreading lanes across attempts is an
/// `IdentityConflict`, never silently narrowed to the first lane); binding,
/// worker fence, result, and unknown-outcome bind the covered attempt;
/// cancellation binds the covered attempt plus the requesting operation;
/// reassignment binds the covered old attempt (the new identity is
/// core-validated fresh, never claim-bound). Only cancellation receipts carry
/// an operation identity (`request_operation_id`); no other receipt schema
/// carries one, so those kinds ride the admitted claim's operation
/// (`claim_operation_id`) explicitly and there is no receipt-side operation
/// to drift. The returned pair feeds the owner request while the admitted
/// claim rides as the loaded durable row, so a receipt naming an attempt or
/// operation the claim never covered fails closed through the owner as
/// `ForeignAttempt` / `ForeignOperation`.
///
/// # Errors
///
/// Returns [`CoordinatorError::InvalidField`] when the canonical bytes are
/// not a receipt of the claimed kind or admit no lanes, or
/// [`CoordinatorError::IdentityConflict`] when one admission receipt names
/// attempts beyond a single identity.
fn receipt_proof_identity(
    kind: ProviderProofKind,
    canonical_payload: &str,
    claim_operation_id: &str,
) -> Result<(String, String), CoordinatorError> {
    match kind {
        ProviderProofKind::Admission => {
            let receipt = serde_json::from_str::<ProviderAdmissionReceipt>(canonical_payload)
                .map_err(|_| CoordinatorError::InvalidField("canonical_payload"))?;
            let first = receipt
                .admitted_lanes
                .first()
                .ok_or(CoordinatorError::InvalidField("admitted_lanes"))?;
            let attempt_id = first.attempt_id.as_str();
            if receipt
                .admitted_lanes
                .iter()
                .any(|lane| lane.attempt_id.as_str() != attempt_id)
            {
                return Err(CoordinatorError::IdentityConflict("admitted_lanes"));
            }
            Ok((attempt_id.to_owned(), claim_operation_id.to_owned()))
        }
        ProviderProofKind::Binding => {
            let submission =
                serde_json::from_str::<ProviderExecutionBindingSubmission>(canonical_payload)
                    .map_err(|_| CoordinatorError::InvalidField("canonical_payload"))?;
            Ok((
                submission.binding.attempt_id.as_str().to_owned(),
                claim_operation_id.to_owned(),
            ))
        }
        ProviderProofKind::Cancellation => {
            let receipt =
                serde_json::from_str::<ProviderCancellationReconciliation>(canonical_payload)
                    .map_err(|_| CoordinatorError::InvalidField("canonical_payload"))?;
            Ok((
                receipt.attempt_id.as_str().to_owned(),
                receipt.request_operation_id.as_str().to_owned(),
            ))
        }
        ProviderProofKind::WorkerFence => {
            let receipt = serde_json::from_str::<ProviderWorkerFenceReceipt>(canonical_payload)
                .map_err(|_| CoordinatorError::InvalidField("canonical_payload"))?;
            Ok((
                receipt.attempt_id.as_str().to_owned(),
                claim_operation_id.to_owned(),
            ))
        }
        ProviderProofKind::Reassignment => {
            let receipt = serde_json::from_str::<ProviderReassignmentReceipt>(canonical_payload)
                .map_err(|_| CoordinatorError::InvalidField("canonical_payload"))?;
            Ok((
                receipt.old_attempt_id.as_str().to_owned(),
                claim_operation_id.to_owned(),
            ))
        }
        ProviderProofKind::Result => {
            let submission = serde_json::from_str::<ResultSubmission>(canonical_payload)
                .map_err(|_| CoordinatorError::InvalidField("canonical_payload"))?;
            Ok((
                submission.result.attempt_id.as_str().to_owned(),
                claim_operation_id.to_owned(),
            ))
        }
        ProviderProofKind::UnknownOutcome => {
            let receipt =
                serde_json::from_str::<ProviderUnknownOutcomeReconciliation>(canonical_payload)
                    .map_err(|_| CoordinatorError::InvalidField("canonical_payload"))?;
            Ok((
                receipt.attempt_id.as_str().to_owned(),
                claim_operation_id.to_owned(),
            ))
        }
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
