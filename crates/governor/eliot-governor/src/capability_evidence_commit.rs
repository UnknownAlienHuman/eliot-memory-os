//! Governor-owned durable capability-evidence commit path (issue #1773, I3.4).
//!
//! Integration seam: the capability-evidence registry is a **Governor-owned
//! view**, and the only way a qualifying record survives a daemon restart is the
//! single named Kernel mutation `RecordCapabilityEvidenceRecord`, invoked
//! through [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical).
//!
//! The closed wire shape (the deterministic `(skill_id, scope_key)` row
//! address, the opaque `record_json` document, the presented `record_digest`,
//! the asserted `expected_canonical_revision` CAS predecessor, and the
//! idempotency key) is owned by the `capability_evidence_store` seam module in
//! `eliot-store-api`
//! (`crates/storage/eliot-store-api/src/capability_evidence_store.rs`); the
//! constructors here build requests only through that seam's builders and never
//! invent a store operation.
//!
//! Envelope field provenance for [`commit_capability_evidence_record`] (every
//! field bound, none synthesized; mirrors `commit_learning_record`):
//!
//! ```text
//! operation_id            derived deterministically as
//!                         `capability-evidence-{skill_id}:{scope_key}:{record_digest}`
//!                         (stable across retries, unique per evidence
//!                         revision: the presented digest is the immutable
//!                         record identity)
//! request                 the caller-supplied request metadata, cloned verbatim
//! idempotency_key         the named request's deterministic key, checked equal
//!                         to the caller identity key
//! scope_id                caller-addressed scope carried into the envelope
//! task_id                 none: an evidence record is scope-addressed, never
//!                         task-bound
//! transition_class        CaptureCandidate; ceiling Candidate
//! admission_contract_set_digest
//!                         the presented record digest from the decoded named
//!                         request
//! operation_manifest_digest
//!                         computed live from `generated_operation_manifests`
//! semantic_commands       the single named evidence command, guarded by
//!                         `reject_direct_capability_evidence_write` before use
//! event/projection/relation intents
//!                         empty: a durable evidence row is not a projection or
//!                         relation; the registry is a rebuildable view
//! security                default context: the record document travels inside
//!                         the command parameters, not the envelope security
//!                         block
//! required_proof_and_approval_refs
//!                         caller-supplied probe/observation refs, passed through
//! expected revision/ordering heads
//!                         caller-supplied live owner expectations, each bound to
//!                         the request fence
//! ```
//!
//! Owner-issued revision — and exactly where the value comes from.
//!
//! The canonical store arbitrates the evidence row's fenced revision under a
//! compare-and-set and issues `expected + 1`. **This module does not read that
//! value back from the store.** It re-derives the same arithmetic from the
//! predecessor the owner itself asserted, so the value the registry orders by is
//! correct only because it is a **store contract**, not because this module
//! observed the store.
//!
//! The two endpoints of that contract, both of which must issue exactly
//! `expected + 1`:
//!
//! * memory — `crates/storage/eliot-store-memory/src/lib.rs`
//!   `dispatch_apply_capability_evidence`, which refuses a stale predecessor with
//!   `StoreError::RevisionConflict` and then writes
//!   `expected_canonical_revision.checked_add(1)`;
//! * Surreal — `crates/storage/eliot-store-surreal-adapter/src/schema.rs`
//!   `TX_CAPABILITY_EVIDENCE_OWNER`, driven by
//!   `append_capability_evidence_owner_statements` in that crate's
//!   `apply/atomic_write.rs`, which throws `capability_evidence_cas_conflict` on a
//!   stale predecessor and binds `revision` to the same `expected + 1`.
//!
//! A provider that issued anything other than `expected + 1` would therefore
//! break the registry's ordering, and this code would not detect it: the
//! derivation and the store would disagree silently. That coupling is the price
//! of not adding a readback round trip on a path that has no production caller
//! yet; it is stated here rather than papered over. The readback half of the
//! leg does exist and does not share this weakness — the paged range read
//! projects the store's own `revision` column, so a hydrated record is ordered
//! by the revision the store actually holds.
//!
//! Fail-closed checks before any commit: the named-operation guard, closed
//! parameter decode, request-identity validity, and idempotency agreement
//! between the caller identity and the named request key.
//!
//! Production caller status: **none, and that is a measured fact rather than an
//! oversight.** This repository contains no capability-probe producer. A whole-
//! tree search for `RouteScopeFingerprint {` outside `#[cfg(test)]` returns
//! exactly two sites: the legacy importer (which yields an all-`None` scope and
//! a `declared` status) and `ActualRouteReceipt::current_scope`, which itself
//! needs an `ActualRouteReceipt` that no production path supplies. The single
//! missing producer is therefore a route/capability observation yielding a
//! `RouteScopeFingerprint`, a probed status, and the owner-issued evidence
//! reference — and the same absence is why
//! [`CapabilityRegistry::apply_scope_change`](crate::CapabilityRegistry::apply_scope_change)
//! has no reachable caller yet. The write leg and the change leg are committed
//! here and become reachable together, at that one producer; wiring either one
//! earlier would mean fabricating a probe result that no probe produced.
//!
//! The readback half of this path is live today: the daemon's complete paged
//! drain runs at startup and rebuilds the registry from whatever the store
//! actually holds.

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, StateFence};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationRequest, OrderingHeadExpectation,
    RevisionHeadExpectation, ScopeId, SecurityContext, TransitionClass, WriteReceipt,
    WriteReceiptStatus, canonical_json_bytes, decode_capability_evidence_mutation,
    generated_operation_manifests, operation_manifest_set_digest,
    reject_direct_capability_evidence_write, sha256_hex,
};

use crate::capability_evidence::{
    CapabilityEvidenceRecord, OwnerEvidenceRevision, is_evidence_ref,
};
use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};

/// Builds the closed `RecordCapabilityEvidenceRecord` mutation request for one
/// verified record.
///
/// The presented `record_digest` is the digest over the exact canonical record
/// bytes, and the same digest is the owner-issued evidence reference the store
/// echoes on readback — so one value binds the committed bytes, the durable row
/// identity, and the revision the Governor registry orders by.
///
/// # Errors
///
/// Returns [`CompositionError::Owner`] when the skill identity or scope
/// fingerprint cannot produce a bounded wire shape, when the record bytes
/// exceed the declared bounded length, or when the built request fails the
/// closed named-operation guard.
pub fn capability_evidence_mutation_request_for_record(
    record: &CapabilityEvidenceRecord,
    expected_canonical_revision: u64,
    idempotency_key: String,
) -> Result<NamedMutationRequest, CompositionError> {
    if !eliot_store_api::valid_skill_id(&record.skill_id) {
        return Err(CompositionError::Owner(
            "capability evidence skill identity is not a bounded non-blank identity".to_owned(),
        ));
    }
    let record_bytes = canonical_json_bytes(record).map_err(|error| {
        CompositionError::Owner(format!("capability evidence record bytes: {error}"))
    })?;
    if record_bytes.len() > eliot_store_api::MAX_CAPABILITY_EVIDENCE_RECORD_JSON_BYTES {
        return Err(CompositionError::Owner(
            "capability evidence record document exceeds the bounded length".to_owned(),
        ));
    }
    let record_json = String::from_utf8(record_bytes).map_err(|_| {
        CompositionError::Owner("capability evidence record document is not UTF-8".to_owned())
    })?;
    // The scope key is the owner-issued reference of the exact route-scope
    // fingerprint, so the durable row is addressed by behaviour scope and the
    // store never has to parse a route.
    let scope_key = record.scope_fingerprint.reference_digest();
    let record_digest = sha256_hex(record_json.as_bytes());
    let request = eliot_store_api::capability_evidence_mutation_request(
        eliot_store_api::capability_evidence_commit_params(
            record.skill_id.clone(),
            scope_key,
            record_json,
            record_digest,
            expected_canonical_revision,
            idempotency_key,
        ),
    );
    reject_direct_capability_evidence_write(&request).map_err(|error| {
        CompositionError::Owner(format!("capability evidence commit guard: {error}"))
    })?;
    Ok(request)
}

/// Reports whether one canonical receipt really committed the named
/// capability-evidence request, with no stale projection reported healthy
/// (issue #223 P2 discipline).
///
/// Identity/fence agreement mirrors the store's own receipt-identity rule and
/// head agreement follows the owner CAS contract. This is the same
/// freshness check the sibling commit paths apply, named for this leg.
fn check_capability_evidence_commit_freshness(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    idempotency_key: &str,
    envelope_fence: &StateFence,
) -> Result<(), CompositionError> {
    receipt.validate().map_err(|error| {
        CompositionError::Owner(format!(
            "capability evidence commit receipt invalid: {error}"
        ))
    })?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(CompositionError::Owner(
            "capability evidence commit receipt is not committed; stale projection refused"
                .to_owned(),
        ));
    }
    if receipt.operation_id != *operation_id || receipt.idempotency_key != idempotency_key {
        return Err(CompositionError::Owner(
            "capability evidence commit receipt identity does not match the committed envelope"
                .to_owned(),
        ));
    }
    if receipt.state_fence != *envelope_fence {
        return Err(CompositionError::Owner(
            "capability evidence commit receipt fence does not match the committed envelope fence"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Commits one prebuilt named capability-evidence request through the canonical
/// owner and returns the store-issued owner revision of the evidence row.
///
/// Derives the real [`CanonicalWriteEnvelope`] from the caller identity, the
/// decoded closed parameters of the single named evidence command, the
/// caller-addressed scope, proof refs, live head expectations, and the live
/// store manifest digest — then invokes
/// [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical)
/// and checks the returned receipt for freshness.
///
/// Never accepts a caller-created `PreparedTransition` (there is no such
/// parameter), never mints a revision from a local clock, and never reinterprets
/// the receipt.
#[allow(
    clippy::too_many_arguments,
    reason = "the commit caller joins every handoff-required envelope input in one typed call"
)]
pub async fn commit_capability_evidence_record<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    request: NamedMutationRequest,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<(WriteReceipt, OwnerEvidenceRevision), CompositionError> {
    reject_direct_capability_evidence_write(&request)
        .map_err(|error| CompositionError::Owner(format!("capability evidence guard: {error}")))?;
    let decoded = decode_capability_evidence_mutation(request.operation, &request.parameters)
        .map_err(|error| {
            CompositionError::Owner(format!("capability evidence parameters: {error}"))
        })?;
    identity.validate().map_err(|error| {
        CompositionError::Owner(format!("capability evidence identity invalid: {error}"))
    })?;
    if identity.idempotency_key != decoded.idempotency_key {
        return Err(CompositionError::Owner(
            "capability evidence idempotency key does not match the named request key".to_owned(),
        ));
    }
    if !is_evidence_ref(&decoded.record_digest) {
        return Err(CompositionError::Owner(
            "capability evidence presented digest is not one hex SHA-256 digest".to_owned(),
        ));
    }
    let operation_id = OperationId::new(format!(
        "capability-evidence-{}-{}-{}",
        decoded.skill_id, decoded.scope_key, decoded.record_digest
    ))
    .map_err(|error| {
        CompositionError::Owner(format!("capability evidence identity invalid: {error}"))
    })?;
    let envelope_fence = identity.request.metadata.state_fence.clone();
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            CompositionError::Owner(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| CompositionError::Owner(format!("operation manifest digest: {error}")))?;
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
    check_capability_evidence_commit_freshness(
        &receipt,
        &operation_id,
        &decoded.idempotency_key,
        &envelope_fence,
    )?;
    // Re-derived, not read back. This is the same `expected + 1` the store
    // issues under its fenced compare-and-set (see this module's docs for both
    // provider endpoints); it is a store contract this function depends on, not
    // an observation of the store. The presented digest is the owner-issued
    // evidence reference the store echoes verbatim on readback.
    let issued =
        decoded
            .expected_canonical_revision
            .checked_add(1)
            .ok_or(CompositionError::Owner(
                "capability evidence revision overflow".to_owned(),
            ))?;
    let revision =
        OwnerEvidenceRevision::issued(issued, &decoded.record_digest).map_err(|error| {
            CompositionError::Owner(format!("capability evidence issued revision: {error}"))
        })?;
    Ok((receipt, revision))
}
