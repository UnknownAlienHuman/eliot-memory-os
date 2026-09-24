//! Governor-owned learning-record commit path (issue #1868).
//!
//! Integration-seam contract: the learning crates (`eliot-learning-delta`
//! and its companions) are candidate-only persistence systems. They derive
//! and validate durable record shapes, but they own no durability and no
//! effectiveness:
//!
//! - Durability ONLY through the single named Kernel mutation
//!   `RecordLearningRecord` (transition class `CaptureCandidate`,
//!   `Candidate` ceiling — the same family as the experience legs of issue
//!   #223), invoked through
//!   [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical).
//!   The closed wire shape (the `record_kind` discriminator, the complete
//!   kind/handle/digest/scope/fence/expiry identity, and the direct-write
//!   guard) is owned by the `learning_store` seam module in
//!   `eliot-store-api`; the typed constructors here build requests only
//!   through that seam's builders and never invent a store operation.
//! - Effectiveness ONLY through verified Governor admission (I12.24 line
//!   179: Governor admission is required before any behavioral effect; line
//!   209: the artifact has no independent authority). A durable record
//!   without a live verified admission stays non-effective; see
//!   [`learning_effective_under_admission`].
//! - Source-owner separation: learning records reference Task Controller,
//!   evaluator, attempt, memory, artifact, and Governor data only as opaque
//!   digests (`scope_digest`, `fence_digest`, owner revision strings);
//!   learning dispatch writes only the learning tables and never rewrites
//!   owner records.
//! - Revision rule: the complete kind/handle/record-digest/scope/fence/
//!   expiry tuple is the immutable revision identity. A new complete
//!   identity is a new row (never an in-place rewrite); identical replays
//!   converge (`IdentityConflict` on divergent rewrite). A new owner
//!   revision rebuilds the view rather than mutating it in place
//!   (I12.24 line 143).
//!
//! Envelope field provenance for [`commit_learning_record`] (every field
//! bound, none synthesized; mirrors `commit_experience_bank`):
//!
//! ```text
//! operation_id            derived deterministically from the exact
//!                         kind/handle/record-digest/scope/fence/expiry
//!                         identity (stable across retries, unique per
//!                         immutable record identity)
//! request                 the caller-supplied request metadata, cloned
//!                         verbatim
//! idempotency_key         the named request's deterministic key, checked
//!                         equal to the caller identity key
//! scope_id                caller-addressed scope carried into the envelope
//! task_id                 none: a stored delta carries campaign/attempt
//!                         lineage, never a task binding
//! transition_class        CaptureCandidate; ceiling Candidate
//! admission_contract_set_digest
//!                         the exact kind/handle/digest/scope/fence/expiry
//!                         identity digest from the decoded named request
//! operation_manifest_digest
//!                         computed live from
//!                         `generated_operation_manifests`
//! semantic_commands       the single named learning command, guarded by
//!                         `reject_direct_learning_write` before use
//! event/projection/relation intents
//!                         empty: a candidate record commit persists rows;
//!                         projections and relations publish separately
//! security                default context: retention/provenance travel
//!                         inside the record document and commit
//!                         parameters, not the envelope security block
//! required_proof_and_approval_refs
//!                         caller-supplied proof refs, passed through
//!                         (uniqueness/shape enforced by envelope validation)
//! expected revision/ordering heads
//!                         caller-supplied live owner expectations, each
//!                         bound to the request fence (enforced by
//!                         envelope validation)
//! ```
//!
//! Fail-closed checks before any commit: the named-operation guard, closed
//! parameter decode, request-identity validity, and idempotency agreement
//! between the caller identity and the named request key. Record-content
//! validation is store-side: the store re-validates the decoded parameters
//! at apply. The owner re-validates the envelope, fence, identity, and
//! heads again downstream.
//!
//! The M1 product caller (eliotd) drives the typed proposal and exact
//! admission path with its retained neutral Kernel port and live head
//! expectations; this module never accepts a caller-created
//! `PreparedTransition` (there is no such parameter), never invents a
//! record digest, and never reinterprets the receipt.

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, StateFence};
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate, CampaignLearningStateView,
    ClosureHandoff, HarnessActivationReceiptCandidate, LearningStateViewRecipe,
};
use eliot_learning_delta::{LearningDeltaError, StoredLearningDelta};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, LearningRecordIdentity, LearningRecordKind,
    NamedMutationRequest, OrderingHeadExpectation, RevisionHeadExpectation, ScopeId,
    SecurityContext, TransitionClass, WriteReceipt, WriteReceiptStatus, canonical_json_bytes,
    decode_learning_mutation, generated_operation_manifests, learning_fence_digest,
    learning_record_commit_params_from_identity, learning_record_mutation_request,
    learning_scope_digest, operation_manifest_set_digest, reject_direct_learning_write,
};
use serde::Serialize;

use crate::Governor;
use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};
use crate::learning_admission::{
    LearningAdmissionClaim, LearningAdmissionPermit, LearningRecordAdmissionClaim,
    verify_learning_record_admission,
};

/// A typed, immutable learning-record proposal ready for the named Kernel
/// mutation. The identity is carried separately from the opaque request so
/// admission, operation identity, row identity, and effectiveness all compare
/// the same tuple.
#[derive(Clone, Debug, PartialEq)]
pub struct LearningRecordProposal {
    /// Exact record identity, including scope, State Fence, and expiry.
    pub identity: LearningRecordIdentity,
    /// Closed `RecordLearningRecord` request built from the identity.
    pub request: NamedMutationRequest,
}

impl LearningRecordProposal {
    /// Re-decode and cross-check the request against the typed identity.
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.identity
            .validate()
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        reject_direct_learning_write(&self.request)
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        let decoded = decode_learning_mutation(self.request.operation, &self.request.parameters)
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        if decoded.record_kind != self.identity.record_kind
            || decoded.handle != self.identity.handle
            || decoded.record_digest != self.identity.record_digest
            || decoded.expires_at_unix_ms != self.identity.expires_at_unix_ms
            || decoded.scope_digest
                != learning_scope_digest(&self.identity.scope_id)
                    .map_err(|error| CompositionError::Owner(error.to_string()))?
            || decoded.fence_digest
                != learning_fence_digest(&self.identity.state_fence)
                    .map_err(|error| CompositionError::Owner(error.to_string()))?
        {
            return Err(CompositionError::Owner(
                "learning request does not match its exact record identity".to_owned(),
            ));
        }
        Ok(())
    }

    /// Attach the ordinary owner claim to this exact record identity.
    pub fn admission_claim(
        &self,
        admission: LearningAdmissionClaim,
    ) -> LearningRecordAdmissionClaim {
        LearningRecordAdmissionClaim {
            admission,
            record: crate::learning_admission::LearningRecordAdmissionBinding::from_identity(
                &self.identity,
            ),
        }
    }
}

/// Build a typed proposal for an owner-defined serializable learning record.
///
/// The caller supplies a typed Rust value and the record kind/handle; the
/// Governor computes the exact presented digest from canonical bytes. This is
/// the production escape hatch for a record family whose contract is already
/// owned by another first-party module, without permitting a raw store write.
pub fn learning_record_proposal_from_serializable<T: Serialize>(
    kind: LearningRecordKind,
    handle: String,
    record: &T,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    let bytes =
        canonical_json_bytes(record).map_err(|error| CompositionError::Owner(error.to_string()))?;
    let record_digest = eliot_contracts::sha256_hex(&bytes);
    proposal_from_record(
        kind,
        handle,
        record_digest,
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
}

/// Build a typed proposal from a validated serializable learning contract.
#[allow(
    clippy::too_many_arguments,
    reason = "the exact identity, document, and idempotency fields are one closed handoff"
)]
fn proposal_from_record<T: Serialize>(
    kind: LearningRecordKind,
    handle: String,
    record_digest: String,
    record: &T,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    let record_json =
        canonical_json_bytes(record).map_err(|error| CompositionError::Owner(error.to_string()))?;
    let record_json = String::from_utf8(record_json)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let identity = LearningRecordIdentity {
        record_kind: kind,
        handle,
        record_digest,
        scope_id: scope_id.as_str().to_owned(),
        state_fence: state_fence.clone(),
        expires_at_unix_ms,
    };
    let parameters =
        learning_record_commit_params_from_identity(&identity, record_json, idempotency_key)
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let request = learning_record_mutation_request(parameters);
    let proposal = LearningRecordProposal { identity, request };
    proposal.validate()?;
    Ok(proposal)
}

/// Build the exact proposal for a stored learning delta.
pub fn learning_record_proposal_for_delta(
    record: &StoredLearningDelta,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    record
        .validate()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    if record.state_fence != *state_fence {
        return Err(CompositionError::Owner(
            "stored delta fence differs from the proposal fence".to_owned(),
        ));
    }
    proposal_from_record(
        LearningRecordKind::Delta,
        record.delta_artifact.as_str().to_owned(),
        record.delta_digest.clone(),
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
}

/// Build the exact proposal for a governed overlay candidate.
pub fn learning_record_proposal_for_overlay(
    record: &CampaignHarnessOverlayCandidate,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    record
        .validate()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    if record.binding.scope.as_str() != scope_id.as_str() {
        return Err(CompositionError::Owner(
            "overlay scope differs from the proposal scope".to_owned(),
        ));
    }
    if record.binding.state_fence != *state_fence {
        return Err(CompositionError::Owner(
            "overlay fence differs from the proposal fence".to_owned(),
        ));
    }
    proposal_from_record(
        LearningRecordKind::Overlay,
        record.overlay_id.as_str().to_owned(),
        record.canonical_digest.clone(),
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
}

/// Build the exact proposal for a closure handoff candidate.
pub fn learning_record_proposal_for_closure(
    record: &ClosureHandoff,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    record
        .validate()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    if record.binding.scope.as_str() != scope_id.as_str() {
        return Err(CompositionError::Owner(
            "closure scope differs from the proposal scope".to_owned(),
        ));
    }
    if record.binding.state_fence != *state_fence {
        return Err(CompositionError::Owner(
            "closure fence differs from the proposal fence".to_owned(),
        ));
    }
    proposal_from_record(
        LearningRecordKind::Closure,
        record.assessment_id.as_str().to_owned(),
        record.canonical_digest.clone(),
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
}

/// Build the exact proposal for an activation receipt candidate.
pub fn learning_record_proposal_for_activation_receipt(
    record: &HarnessActivationReceiptCandidate,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    record
        .validate()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    if record.binding.scope.as_str() != scope_id.as_str() {
        return Err(CompositionError::Owner(
            "activation receipt scope differs from the proposal scope".to_owned(),
        ));
    }
    if record.binding.state_fence != *state_fence {
        return Err(CompositionError::Owner(
            "activation receipt fence differs from the proposal fence".to_owned(),
        ));
    }
    proposal_from_record(
        LearningRecordKind::ActivationReceipt,
        record.activation_id.as_str().to_owned(),
        record.canonical_digest.clone(),
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
}

/// Build the exact proposal for a reusable learning candidate.
pub fn learning_record_proposal_for_candidate(
    record: &AttemptLearningDeltaCandidate,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    record
        .validate()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    if record.binding.scope.as_str() != scope_id.as_str() {
        return Err(CompositionError::Owner(
            "candidate scope differs from the proposal scope".to_owned(),
        ));
    }
    if record.binding.state_fence != *state_fence {
        return Err(CompositionError::Owner(
            "candidate fence differs from the proposal fence".to_owned(),
        ));
    }
    proposal_from_record(
        LearningRecordKind::Candidate,
        record.delta_id.as_str().to_owned(),
        record.canonical_digest.clone(),
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
}

/// Build the exact proposal for an immutable learning-state view reference.
pub fn learning_record_proposal_for_view_ref(
    record: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<LearningRecordProposal, CompositionError> {
    record
        .validate_against(recipe)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    if record.binding.scope.as_str() != scope_id.as_str() {
        return Err(CompositionError::Owner(
            "learning view scope differs from the proposal scope".to_owned(),
        ));
    }
    if record.binding.state_fence != *state_fence {
        return Err(CompositionError::Owner(
            "learning view fence differs from the proposal fence".to_owned(),
        ));
    }
    proposal_from_record(
        LearningRecordKind::ViewRef,
        record.view_id.as_str().to_owned(),
        record.canonical_digest.clone(),
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
}

/// Closed typed dispatch used by production owners to select one of the six
/// learning record contracts without constructing a raw store command.
pub enum LearningRecordPayload<'a> {
    /// Stored attempt delta.
    Delta(&'a StoredLearningDelta),
    /// Task-local overlay candidate.
    Overlay(&'a CampaignHarnessOverlayCandidate),
    /// Closure handoff candidate.
    Closure(&'a ClosureHandoff),
    /// Activation receipt candidate.
    ActivationReceipt(&'a HarnessActivationReceiptCandidate),
    /// Reusable learning candidate.
    Candidate(&'a AttemptLearningDeltaCandidate),
    /// Immutable state-view reference.
    ViewRef(&'a CampaignLearningStateView, &'a LearningStateViewRecipe),
    /// A typed owner-defined record that already has a first-party Rust
    /// contract outside this module (for example the daemon's terminal
    /// observation receipt). The Governor still computes the canonical
    /// digest and builds the same named request.
    OwnerDefined {
        /// Closed record kind.
        kind: LearningRecordKind,
        /// Stable owner handle.
        handle: String,
        /// Typed serializable record value.
        record: &'a serde_json::Value,
    },
}

impl LearningRecordPayload<'_> {
    /// Convert the typed payload into one exact named-operation proposal.
    pub fn into_proposal(
        self,
        scope_id: &ScopeId,
        state_fence: &StateFence,
        expires_at_unix_ms: u64,
        idempotency_key: String,
    ) -> Result<LearningRecordProposal, CompositionError> {
        match self {
            Self::Delta(record) => learning_record_proposal_for_delta(
                record,
                scope_id,
                state_fence,
                expires_at_unix_ms,
                idempotency_key,
            ),
            Self::Overlay(record) => learning_record_proposal_for_overlay(
                record,
                scope_id,
                state_fence,
                expires_at_unix_ms,
                idempotency_key,
            ),
            Self::Closure(record) => learning_record_proposal_for_closure(
                record,
                scope_id,
                state_fence,
                expires_at_unix_ms,
                idempotency_key,
            ),
            Self::ActivationReceipt(record) => learning_record_proposal_for_activation_receipt(
                record,
                scope_id,
                state_fence,
                expires_at_unix_ms,
                idempotency_key,
            ),
            Self::Candidate(record) => learning_record_proposal_for_candidate(
                record,
                scope_id,
                state_fence,
                expires_at_unix_ms,
                idempotency_key,
            ),
            Self::ViewRef(record, recipe) => learning_record_proposal_for_view_ref(
                record,
                recipe,
                scope_id,
                state_fence,
                expires_at_unix_ms,
                idempotency_key,
            ),
            Self::OwnerDefined {
                kind,
                handle,
                record,
            } => learning_record_proposal_from_serializable(
                kind,
                handle,
                record,
                scope_id,
                state_fence,
                expires_at_unix_ms,
                idempotency_key,
            ),
        }
    }
}

///
/// Builds the exact named request for a stored delta. The scope, State Fence,
/// and expiry are required inputs; there is no unbounded or unbound legacy
/// construction path.
pub fn learning_record_mutation_request_for_delta(
    record: &StoredLearningDelta,
    scope_id: &ScopeId,
    state_fence: &StateFence,
    expires_at_unix_ms: u64,
    idempotency_key: String,
) -> Result<NamedMutationRequest, LearningDeltaError> {
    learning_record_proposal_for_delta(
        record,
        scope_id,
        state_fence,
        expires_at_unix_ms,
        idempotency_key,
    )
    .map(|proposal| proposal.request)
    .map_err(|_| LearningDeltaError::InvalidInput {
        field: "stored.learning_identity",
    })
}

/// Report whether a durable learning record is locally effective under a
/// Governor admission.
///
/// The permit is checked against the exact record identity and current
/// owner/fence/time. Caller-provided admission booleans are deliberately not
/// accepted: presence of a receipt-shaped value is not authentication.
pub fn learning_effective_under_admission(
    governor: &Governor,
    permit: Option<&LearningAdmissionPermit>,
    current_fence: &StateFence,
    identity: &LearningRecordIdentity,
    now_unix_ms: u64,
) -> bool {
    let Some(permit) = permit else {
        return false;
    };
    verify_learning_record_admission(governor, permit, current_fence, identity, now_unix_ms).is_ok()
}

/// Fail-closed freshness check over the owner-returned receipt (issue #223
/// P2 discipline: a stale projection must never surface as a healthy
/// commit).
///
/// Same rule as the experience-leg check: receipt validity and
/// terminal-status pairing come from [`WriteReceipt::validate`],
/// identity/fence agreement mirrors the store's own receipt-identity rule,
/// and head agreement follows the owner CAS contract (expectations are
/// validated against current store state at execution; both providers then
/// advance heads as `before = current`, `after = before + 1`). The fence
/// compared here is the committed envelope fence (cloned from the caller
/// request metadata); the record-fence-vs-request-fence equality that the
/// experience legs check against an admitted record has no admitted-record
/// counterpart on this candidate-only path — durability here never implies
/// effectiveness, which only [`learning_effective_under_admission`]
/// decides.
fn check_learning_commit_freshness(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    idempotency_key: &str,
    envelope_fence: &StateFence,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), CompositionError> {
    receipt.validate().map_err(|error| {
        CompositionError::Owner(format!("learning commit receipt invalid: {error}"))
    })?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(CompositionError::Owner(
            "learning commit receipt is not committed; stale projection refused".to_owned(),
        ));
    }
    if receipt.operation_id != *operation_id || receipt.idempotency_key != idempotency_key {
        return Err(CompositionError::Owner(
            "learning commit receipt identity does not match the committed envelope".to_owned(),
        ));
    }
    if receipt.state_fence != *envelope_fence {
        return Err(CompositionError::Owner(
            "learning commit receipt fence does not match the committed envelope fence".to_owned(),
        ));
    }
    for expected in expected_revision_heads {
        if let Some(delta) = receipt
            .revision_before_after
            .iter()
            .find(|delta| delta.key == expected.key)
            && delta.before != expected.expected_revision
        {
            return Err(CompositionError::Owner(format!(
                "learning commit receipt revision is stale for {}: expected base {}, observed {}",
                expected.key.as_str(),
                expected.expected_revision,
                delta.before,
            )));
        }
    }
    for expected in expected_ordering_heads {
        if let Some(head) = receipt
            .ordering_sequences
            .iter()
            .find(|head| head.scope == expected.scope)
            && head.sequence <= expected.expected_sequence
        {
            return Err(CompositionError::Owner(format!(
                "learning commit receipt ordering is stale for {}: expected advance past {}, observed {}",
                expected.scope.as_str(),
                expected.expected_sequence,
                head.sequence,
            )));
        }
    }
    Ok(())
}

/// Decode the exact identity carried by one closed learning mutation.
pub fn learning_record_identity_from_request(
    request: &NamedMutationRequest,
    scope_id: &ScopeId,
    state_fence: &StateFence,
) -> Result<LearningRecordIdentity, CompositionError> {
    reject_direct_learning_write(request)
        .map_err(|error| CompositionError::Owner(format!("learning commit guard: {error}")))?;
    let decoded = decode_learning_mutation(request.operation, &request.parameters)
        .map_err(|error| CompositionError::Owner(format!("learning commit parameters: {error}")))?;
    let identity = LearningRecordIdentity {
        record_kind: decoded.record_kind,
        handle: decoded.handle,
        record_digest: decoded.record_digest,
        scope_id: scope_id.as_str().to_owned(),
        state_fence: state_fence.clone(),
        expires_at_unix_ms: decoded.expires_at_unix_ms,
    };
    identity
        .validate()
        .map_err(|error| CompositionError::Owner(format!("learning identity invalid: {error}")))?;
    Ok(identity)
}

/// Commits one prebuilt named learning-record request through the canonical
/// owner.
///
/// Derives the real [`CanonicalWriteEnvelope`] from the caller identity
/// (request metadata, fence, idempotency agreement), the decoded closed
/// parameters of the single named learning command (kind, handle, presented
/// digest, idempotency key), the caller-addressed scope, proof refs, live
/// head expectations, and the live store manifest digest — then invokes
/// [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical),
/// checks the returned receipt for freshness (never a stale projection
/// reported healthy), and returns it unmodified. Never accepts a
/// caller-created `PreparedTransition` (there is no such parameter) and
/// never reinterprets the receipt.
///
/// Fail-closed before any commit: `reject_direct_learning_write` refuses a
/// request that is not the closed learning operation; the closed parameter
/// decode refuses malformed legs (record-content validation itself stays
/// store-side at apply); caller identity validity and idempotency
/// agreement with the named request key are enforced here.
#[allow(
    clippy::too_many_arguments,
    reason = "the commit caller joins every handoff-required envelope input in one typed call"
)]
pub async fn commit_learning_record<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    request: NamedMutationRequest,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<WriteReceipt, CompositionError> {
    reject_direct_learning_write(&request)
        .map_err(|error| CompositionError::Owner(format!("learning commit guard: {error}")))?;
    let decoded = decode_learning_mutation(request.operation, &request.parameters)
        .map_err(|error| CompositionError::Owner(format!("learning commit parameters: {error}")))?;
    identity.validate().map_err(|error| {
        CompositionError::Owner(format!("learning commit identity invalid: {error}"))
    })?;
    if identity.idempotency_key != decoded.idempotency_key {
        return Err(CompositionError::Owner(
            "learning commit idempotency key does not match the named request key".to_owned(),
        ));
    }
    let envelope_fence = identity.request.metadata.state_fence.clone();
    let record_identity = LearningRecordIdentity {
        record_kind: decoded.record_kind,
        handle: decoded.handle.clone(),
        record_digest: decoded.record_digest.clone(),
        scope_id: scope_id.as_str().to_owned(),
        state_fence: envelope_fence.clone(),
        expires_at_unix_ms: decoded.expires_at_unix_ms,
    };
    record_identity
        .validate()
        .map_err(|error| CompositionError::Owner(format!("learning identity invalid: {error}")))?;
    let expected_scope_digest = learning_scope_digest(scope_id.as_str()).map_err(|error| {
        CompositionError::Owner(format!("learning scope digest invalid: {error}"))
    })?;
    let expected_fence_digest = learning_fence_digest(&envelope_fence).map_err(|error| {
        CompositionError::Owner(format!("learning fence digest invalid: {error}"))
    })?;
    if decoded.scope_digest != expected_scope_digest
        || decoded.fence_digest != expected_fence_digest
    {
        return Err(CompositionError::Owner(
            "learning record scope/fence digest does not match the canonical envelope".to_owned(),
        ));
    }
    let record_identity_digest = record_identity
        .identity_digest()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let operation_id = OperationId::new(format!("learning-record-v2-{record_identity_digest}"))
        .map_err(|error| {
            CompositionError::Owner(format!("learning operation identity invalid: {error}"))
        })?;
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            CompositionError::Owner(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| CompositionError::Owner(format!("operation manifest digest: {error}")))?;
    let revision_expectations = expected_revision_heads.clone();
    let ordering_expectations = expected_ordering_heads.clone();
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: decoded.idempotency_key.clone(),
        scope_id,
        task_id: None,
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: record_identity_digest,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![request],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: proof_refs,
        expected_revision_heads,
        expected_ordering_heads,
    };
    let receipt = composition.commit_canonical(identity, envelope).await?;
    check_learning_commit_freshness(
        &receipt,
        &operation_id,
        &decoded.idempotency_key,
        &envelope_fence,
        &revision_expectations,
        &ordering_expectations,
    )?;
    Ok(receipt)
}

/// Commit and optionally authenticate one exact learning-record proposal.
///
/// A supplied permit is checked against the same identity before the owner
/// receives the request. The permit is never used as a substitute for the
/// request's scope/fence/digest fields; both sides must agree.
#[allow(
    clippy::too_many_arguments,
    reason = "the exact commit caller carries the complete owner handoff"
)]
pub async fn commit_learning_record_with_admission<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    request_identity: &RequestIdentity,
    proposal: &LearningRecordProposal,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
    permit: Option<&LearningAdmissionPermit>,
    now_unix_ms: u64,
) -> Result<WriteReceipt, CompositionError> {
    proposal.validate()?;
    let live_fence = request_identity.request.state_fence.clone();
    if proposal.identity.state_fence != live_fence {
        return Err(CompositionError::Owner(
            "learning proposal fence differs from the request fence".to_owned(),
        ));
    }
    if let Some(permit) = permit {
        verify_learning_record_admission(
            composition.governor(),
            permit,
            &live_fence,
            &proposal.identity,
            now_unix_ms,
        )
        .map_err(|error| CompositionError::Owner(format!("learning admission refused: {error}")))?;
    }
    commit_learning_record(
        composition,
        request_identity,
        proposal.request.clone(),
        ScopeId::new(proposal.identity.scope_id.clone()).map_err(|error| {
            CompositionError::Owner(format!("learning scope identity invalid: {error}"))
        })?,
        proof_refs,
        expected_revision_heads,
        expected_ordering_heads,
    )
    .await
}
