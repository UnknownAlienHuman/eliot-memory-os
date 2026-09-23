//! Canonical Bank/Feedback commit caller (issue #223).
//!
//! This module is the reusable canonical producer-to-commit join for
//! experience records. It derives a real [`CanonicalWriteEnvelope`]
//! from admitted Governor ingress plus durable domain-owner state, then
//! invokes the existing owner path
//! [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical).
//! It creates no second admission, minting, or transition path:
//! admission stays with `eliot-observation::bank_admission`, the
//! transition is derived by `CanonicalWriteEnvelope::prepare`, and the
//! receipt comes back unmodified from the owner.
//!
//! Envelope field provenance (every field bound, none synthesized):
//!
//! ```text
//! operation_id            derived deterministically as
//!                         `experience-bank|feedback:{handle}:{revision}`
//!                         (stable across retries, unique per record
//!                         revision; mirrors the derived child identity
//!                         rule of the observation recovery envelope)
//! request                 the admitted ingress metadata, cloned verbatim
//! idempotency_key         the commit payload's deterministic key
//!                         (`bank|feedback:{handle}:{revision}`), checked
//!                         equal to the ingress idempotency key
//! scope_id                daemon-addressed scope, checked equal to the
//!                         admitted record scope (same validated string in
//!                         both id types, mirroring the observation path
//!                         which addresses both scopes identically)
//! task_id                 the admitted record scope's task binding;
//!                         the envelope validator cross-checks it against
//!                         the ingress metadata binding
//! transition_class        CaptureCandidate; ceiling Candidate
//! admission_contract_set_digest
//!                         the admitted record digest: the admission
//!                         decision digest over the exact admitted bytes,
//!                         mirroring the observation path which digests
//!                         the admitted submission
//! operation_manifest_digest
//!                         computed live from
//!                         `generated_operation_manifests`
//! semantic_commands       the single commit leg rebuilt from the commit
//!                         payload through the closed store-api builders
//! event/projection/relation intents
//!                         empty: a candidate record commit persists rows;
//!                         projections and relations publish separately
//! security                default context: retention/provenance travel
//!                         inside the record document and commit
//!                         parameters, not the envelope security block
//! required_proof_and_approval_refs
//!                         caller-supplied admitted-action proof refs,
//!                         passed through (uniqueness/shape enforced by
//!                         envelope validation)
//! expected revision/ordering heads
//!                         caller-supplied live owner expectations, each
//!                         bound to the request fence (enforced by
//!                         envelope validation)
//! ```
//!
//! Fail-closed owner checks before any commit: ingress identity
//! validity, exact request-fence equality with the record fence,
//! scope-id equality with the admitted record scope, and idempotency
//! agreement between ingress and commit payload. Anything else is
//! rejected here with an exact owner error; the owner re-validates the
//! envelope, fence, identity, and heads again downstream.
//!
//! The M1 product caller drives these functions with live admitted
//! ingress in its own copy; this module never invents ingress,
//! sessions, tasks, heads, or proof refs.

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::OperationId;
use eliot_observation::bank_admission::{
    ExperienceRevisionLedger, produce_bank_commit, produce_feedback_commit,
};
use eliot_observation_contracts::{AgentFeedbackRecord, ExperienceBankRecord};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationRequest, OrderingHeadExpectation,
    RevisionHeadExpectation, ScopeId, SecurityContext, TransitionClass, WriteReceipt,
    experience_bank_commit_params, experience_bank_mutation_request,
    experience_feedback_commit_params, experience_feedback_mutation_request,
    generated_operation_manifests, operation_manifest_set_digest,
};

use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};

/// Closed commit leg plus its deterministic idempotency key.
struct CommitLeg {
    /// Single named operation the transition carries.
    mutation: NamedMutationRequest,
    /// Deterministic key shared with the ingress check.
    idempotency_key: String,
}

/// Builds the closed bank commit leg from Governor-produced parts.
fn bank_commit_leg(
    record: &ExperienceBankRecord,
    ledger: &ExperienceRevisionLedger,
) -> Result<CommitLeg, CompositionError> {
    let commit = produce_bank_commit(ledger, record)
        .map_err(|error| CompositionError::Owner(format!("bank commit payload: {error}")))?;
    let record_json = serde_json::to_string(record)
        .map_err(|error| CompositionError::Owner(format!("bank record encode: {error}")))?;
    let mutation = experience_bank_mutation_request(experience_bank_commit_params(
        record_json,
        commit.record_digest,
        commit.record_revision,
        commit.scope_digest,
        commit.fence_digest,
        commit.idempotency_key.clone(),
    ));
    Ok(CommitLeg {
        mutation,
        idempotency_key: commit.idempotency_key,
    })
}

/// Builds the closed feedback commit leg. Same rule as the bank leg.
fn feedback_commit_leg(
    record: &AgentFeedbackRecord,
    ledger: &ExperienceRevisionLedger,
) -> Result<CommitLeg, CompositionError> {
    let commit = produce_feedback_commit(ledger, record)
        .map_err(|error| CompositionError::Owner(format!("feedback commit payload: {error}")))?;
    let record_json = serde_json::to_string(record)
        .map_err(|error| CompositionError::Owner(format!("feedback record encode: {error}")))?;
    let mutation = experience_feedback_mutation_request(experience_feedback_commit_params(
        record_json,
        commit.record_digest,
        commit.record_revision,
        commit.scope_digest,
        commit.fence_digest,
        commit.idempotency_key.clone(),
    ));
    Ok(CommitLeg {
        mutation,
        idempotency_key: commit.idempotency_key,
    })
}

/// Binds one admitted record to the exact admitted ingress identity.
///
/// Verifies, in order: ingress identity validity; exact request-fence
/// equality with the record fence; scope-id equality with the admitted
/// record scope; idempotency agreement between the ingress key and the
/// owner-derived commit key. Returns the envelope operation identity.
/// Any mismatch fails closed here, before any transition exists.
#[allow(
    clippy::too_many_arguments,
    reason = "identity binding joins every owner check in one typed call"
)]
fn bind_commit_identity(
    identity: &RequestIdentity,
    record_fence: &eliot_contracts::StateFence,
    record_scope: &str,
    record_revision: u64,
    family: &str,
    handle: &str,
    commit_idempotency_key: &str,
    scope_id: &ScopeId,
) -> Result<OperationId, CompositionError> {
    identity
        .validate()
        .map_err(|error| CompositionError::Owner(format!("admitted ingress invalid: {error}")))?;
    if identity.request.metadata.state_fence != *record_fence {
        return Err(CompositionError::Owner(
            "ingress fence does not equal the admitted record fence".to_owned(),
        ));
    }
    if scope_id.as_str() != record_scope {
        return Err(CompositionError::Owner(
            "transition scope does not equal the admitted record scope".to_owned(),
        ));
    }
    if identity.idempotency_key != commit_idempotency_key {
        return Err(CompositionError::Owner(
            "ingress idempotency key does not match the commit payload key".to_owned(),
        ));
    }
    OperationId::new(format!("experience-{family}-{handle}-{record_revision}"))
        .map_err(|error| CompositionError::Owner(format!("operation identity invalid: {error}")))
}

/// Commits one ledger-sequenced bank record through the canonical owner.
///
/// Derives the real [`CanonicalWriteEnvelope`] from the admitted record
/// (shape, digest, revision, scope, fence, retention), the ledger proof
/// (exact tracked revision), the admitted ingress (`identity`, scope
/// addressing, proof refs, live head expectations), and the live store
/// manifest digest — then invokes
/// [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical)
/// and returns its receipt unmodified. Never accepts a caller-created
/// `PreparedTransition` (there is no such parameter) and never
/// reinterprets the receipt.
#[allow(
    clippy::too_many_arguments,
    reason = "the commit caller joins every handoff-required envelope input in one typed call"
)]
pub async fn commit_experience_bank<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    ledger: &ExperienceRevisionLedger,
    record: &ExperienceBankRecord,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<WriteReceipt, CompositionError> {
    let leg = bank_commit_leg(record, ledger)?;
    let operation_id = bind_commit_identity(
        identity,
        &record.fence,
        record.scope.work_scope.as_str(),
        record.bank_revision,
        "bank",
        record.handle.as_str(),
        &leg.idempotency_key,
        &scope_id,
    )?;
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            CompositionError::Owner(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| CompositionError::Owner(format!("operation manifest digest: {error}")))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: leg.idempotency_key,
        scope_id,
        task_id: record.scope.task_ref.clone(),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: record.digest.clone(),
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![leg.mutation],
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
    composition.commit_canonical(identity, envelope).await
}

/// Commits one ledger-sequenced feedback record through the canonical
/// owner. Same derivation and invocation rule as
/// [`commit_experience_bank`].
#[allow(
    clippy::too_many_arguments,
    reason = "the commit caller joins every handoff-required envelope input in one typed call"
)]
pub async fn commit_experience_feedback<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    ledger: &ExperienceRevisionLedger,
    record: &AgentFeedbackRecord,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<WriteReceipt, CompositionError> {
    let leg = feedback_commit_leg(record, ledger)?;
    let operation_id = bind_commit_identity(
        identity,
        &record.fence,
        record.scope.work_scope.as_str(),
        record.feedback_revision,
        "feedback",
        record.handle.as_str(),
        &leg.idempotency_key,
        &scope_id,
    )?;
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            CompositionError::Owner(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| CompositionError::Owner(format!("operation manifest digest: {error}")))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: leg.idempotency_key,
        scope_id,
        task_id: record.scope.task_ref.clone(),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: record.digest.clone(),
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![leg.mutation],
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
    composition.commit_canonical(identity, envelope).await
}
