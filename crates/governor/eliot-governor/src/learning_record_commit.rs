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
//!   The closed wire shape (the `record_kind` discriminator, the
//!   `(record_kind, handle, record_digest)` key, opaque owner-reference
//!   digests, and the direct-write guard) is owned by the `learning_store`
//!   seam module in `eliot-store-api`
//!   (`crates/storage/eliot-store-api/src/learning_store.rs`); the
//!   constructors here build requests only through that seam's builders
//!   (`learning_record_commit_params`, `learning_record_mutation_request`,
//!   `reject_direct_learning_write`) and never invent a store operation.
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
//! - Revision rule: the `record_digest` IS the immutable revision identity.
//!   A new digest is a new row (never an in-place rewrite); identical
//!   replays converge (`IdentityConflict` on divergent rewrite). A new
//!   owner revision rebuilds the view rather than mutating it in place
//!   (I12.24 line 143).
//!
//! Envelope field provenance for [`commit_learning_record`] (every field
//! bound, none synthesized; mirrors `commit_experience_bank`):
//!
//! ```text
//! operation_id            derived deterministically as
//!                         `learning-record:{kind}:{handle}:{record_digest}`
//!                         (stable across retries, unique per record
//!                         revision: the digest IS the revision identity)
//! request                 the caller-supplied request metadata, cloned
//!                         verbatim
//! idempotency_key         the named request's deterministic key, checked
//!                         equal to the caller identity key
//! scope_id                caller-addressed scope carried into the envelope
//! task_id                 none: a stored delta carries campaign/attempt
//!                         lineage, never a task binding
//! transition_class        CaptureCandidate; ceiling Candidate
//! admission_contract_set_digest
//!                         the presented record digest from the decoded
//!                         named request
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
//! The M1 product caller (eliotd) drives these functions with its retained
//! neutral Kernel port and live head expectations; this module never
//! accepts a caller-created `PreparedTransition` (there is no such
//! parameter), never invents digests (owner `scope_digest`/`fence_digest`
//! refs arrive opaque from the caller), and never reinterprets the
//! receipt.

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, StateFence};
use eliot_learning_delta::{LearningDeltaError, StoredLearningDelta};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, LearningRecordKind, NamedMutationRequest,
    OrderingHeadExpectation, RevisionHeadExpectation, ScopeId, SecurityContext, TransitionClass,
    WriteReceipt, WriteReceiptStatus, canonical_json_bytes, decode_learning_mutation,
    generated_operation_manifests, learning_record_commit_params, learning_record_mutation_request,
    operation_manifest_set_digest, reject_direct_learning_write,
};

use crate::Governor;
use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};
use crate::learning_admission::{LearningAdmissionPermit, verify_learning_admission};

/// Builds the closed `RecordLearningRecord` mutation request for one
/// validated stored delta.
///
/// Validates the record first (`record.validate()?`, which enforces the
/// admitted-disposition receipt rule); binds kind `Delta`, the
/// `delta_artifact` handle, the canonical JSON of the record document, and
/// the already-hex64 `delta_digest`; threads the caller-supplied opaque
/// owner `scope_digest`/`fence_digest` refs through untouched; then asserts
/// the built output travels the named operation via
/// `reject_direct_learning_write` (defense in depth: our own output must
/// pass our own guard) before returning.
pub fn learning_record_mutation_request_for_delta(
    record: &StoredLearningDelta,
    scope_digest: &str,
    fence_digest: &str,
    idempotency_key: String,
) -> Result<NamedMutationRequest, LearningDeltaError> {
    record.validate()?;
    let record_json = String::from_utf8(canonical_json_bytes(record).map_err(|_| {
        LearningDeltaError::InvalidInput {
            field: "stored.record_json",
        }
    })?)
    .map_err(|_| LearningDeltaError::InvalidInput {
        field: "stored.record_json",
    })?;
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Delta,
        record.delta_artifact.as_str().to_owned(),
        record_json,
        record.delta_digest.clone(),
        scope_digest.to_owned(),
        fence_digest.to_owned(),
        idempotency_key,
    ));
    reject_direct_learning_write(&request).map_err(|_| LearningDeltaError::InvalidInput {
        field: "learning.operation",
    })?;
    Ok(request)
}

/// Report whether a durable learning record is locally effective under a
/// Governor admission.
///
/// A durable-but-unadmitted record (or a stale permit) stays non-effective
/// (A3): returns `true` only when the caller-observed `admitted` flag and
/// admission-receipt presence both hold AND `permit` is present AND
/// [`verify_learning_admission`] rebinds it to the live owner
/// epoch/generation and `current_fence`. Any refusal means no behavioral
/// effect, even though the record itself remains durable. Delivery still
/// travels the existing `delivery_allowed` / `delta_delivery_allowed` path.
pub fn learning_effective_under_admission(
    governor: &Governor,
    permit: Option<&LearningAdmissionPermit>,
    current_fence: &StateFence,
    admitted: bool,
    admission_receipt_present: bool,
) -> bool {
    if !admitted || !admission_receipt_present {
        return false;
    }
    let Some(permit) = permit else {
        return false;
    };
    verify_learning_admission(governor, permit, current_fence).is_ok()
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
    let operation_id = OperationId::new(format!(
        "learning-record-{}-{}-{}",
        decoded.record_kind.as_str(),
        decoded.handle,
        decoded.record_digest,
    ))
    .map_err(|error| {
        CompositionError::Owner(format!("learning operation identity invalid: {error}"))
    })?;
    let envelope_fence = identity.request.metadata.state_fence.clone();
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
        admission_contract_set_digest: decoded.record_digest.clone(),
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
