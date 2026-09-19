//! Pure transaction planning: revision/ordering advancement, projection and
//! outbox derivation, receipt construction and write validation.
//!
//! Everything here is deterministic and independent of the physical store, so
//! it is unit-testable without a running `SurrealDB`. It mirrors the in-memory
//! reference store so two stores produce equivalent receipts from the same
//! inputs.

use std::collections::{BTreeMap, BTreeSet};

use eliot_store_api::{
    CanonicalRequestView, CommitId, EventId, EventProjectionRelationIntents, ExactJsonBytes,
    NamedMutationOperation, OrderingHead, OrderingHeadExpectation, OrderingScopeId, OutboxId,
    OutboxIntent, OutboxState, PAYLOAD_AUTHORITY_VERSION, PayloadEncoding, PayloadSource,
    PreparedTransition, ProjectionMode, ProjectionPublicationId, ProjectionPublicationRecord,
    ProjectionStatus, RequestMeta, Resubmission, RevisionDelta, RevisionHead,
    RevisionHeadExpectation, RevisionKey, SplitView, StoreError, WriteReceipt, WriteReceiptStatus,
    canonical_json_bytes, canonical_request_hash, issue_store_receipt_envelope, sha256_hex,
    validate_store_receipt_envelope, verify_canonical_request_hash,
};
use serde_json::Value;

use crate::error::AdapterError;

/// Opaque payload-authority provenance for one named operation (issue #10).
///
/// This record carries identity only (version, encoding, digest, length):
/// the exact bytes are persisted opaquely by the transaction writer, while
/// every queryable body below stays a derivative projection. A plan with an
/// empty `payload_authority` vector is a legacy transition with no claimed
/// authority; its behavior is unchanged.
#[derive(Clone, Debug)]
pub(crate) struct PayloadAuthorityRecord {
    pub(crate) operation_index: usize,
    pub(crate) version: u16,
    pub(crate) encoding: String,
    pub(crate) digest_hex: String,
    pub(crate) byte_len: usize,
    pub(crate) bytes: Vec<u8>,
}

/// Recoverable evidence record for one `CaptureObservation` (T11.1, #19).
///
/// Carries the full recoverable content, never a lossy projection: the exact
/// subject selector, the complete admitted parameters, and the exact bytes
/// with their version/encoding/digest/length provenance. When the transition
/// supplied an [`ExactJsonBytes`] authority, `bytes` are those original raw
/// bytes; otherwise they are the canonical JSON of the admitted parameters
/// (the only exact representation available on the legacy path, sufficient
/// for the memory-parity `parameters` readback and for T13 full-content
/// recovery). `commit_sequence` plus `operation_index` give the durable
/// capture order; `named_operation_count` is the transition's total operation
/// count so readers can reconstruct global capture identity.
#[derive(Clone, Debug)]
pub(crate) struct EvidenceRecord {
    pub(crate) operation_index: usize,
    pub(crate) subject: String,
    pub(crate) parameters: BTreeMap<String, Value>,
    pub(crate) version: u16,
    pub(crate) encoding: String,
    pub(crate) digest_hex: String,
    pub(crate) byte_len: usize,
    pub(crate) bytes: Vec<u8>,
    pub(crate) commit_sequence: u64,
    pub(crate) named_operation_count: usize,
}

/// Planned durable effects of one committed transition.
#[derive(Clone, Debug)]
pub(crate) struct ApplyPlan {
    pub(crate) commit_sequence: u64,
    pub(crate) committed_at: String,
    pub(crate) commit_id: CommitId,
    pub(crate) revision_before_after: Vec<RevisionDelta>,
    pub(crate) next_revision_heads: Vec<RevisionHead>,
    pub(crate) next_ordering_heads: Vec<OrderingHead>,
    pub(crate) event_ids: Vec<EventId>,
    pub(crate) command_ids: Vec<String>,
    pub(crate) projection_records: Vec<ProjectionPublicationRecord>,
    pub(crate) outbox_records: Vec<OutboxIntent>,
    pub(crate) next_commit_sequence: u64,
    pub(crate) next_outbox_sequence: u64,
    /// Per-operation payload authorities bound into this plan. Empty for
    /// legacy transitions. Queryable `projection_records` and outbox bodies
    /// are derivatives of these authorities, never replacements for them.
    pub(crate) payload_authority: Vec<PayloadAuthorityRecord>,
    /// Recoverable `CaptureObservation` evidence persisted alongside the
    /// receipt for the `GetEvidencePack` closed read (T11.1, #19). Present
    /// for every capture regardless of authority presence; empty when the
    /// transition carries no capture.
    pub(crate) evidence_records: Vec<EvidenceRecord>,
}

/// Computes the durable effects of a transition from current heads and the
/// store's next sequence values.
///
/// Legacy entry point: every operation claims no payload authority, so the
/// plan carries no authority records and all digests keep their historical
/// values. Authority-carrying callers use
/// [`plan_apply_with_payload_authority`].
pub(crate) fn plan_apply(
    transition: &PreparedTransition,
    current_revision_heads: &[RevisionHead],
    current_ordering_heads: &[OrderingHead],
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
) -> Result<ApplyPlan, StoreError> {
    let authorities: Vec<Option<ExactJsonBytes>> = vec![None; transition.named_operations.len()];
    plan_apply_with_payload_authority(
        transition,
        &authorities,
        current_revision_heads,
        current_ordering_heads,
        next_commit_sequence,
        next_outbox_sequence,
    )
}

/// Routes one transition to the legacy or the authority-carrying plan.
///
/// Slice C2 (issue #19): when at least one operation claims a payload
/// authority, the transaction plans through
/// [`plan_apply_with_payload_authority`] with the original authority values
/// (never re-parsed from a re-serialized `Value`); otherwise it keeps the
/// exact legacy [`plan_apply`] path. Authority alignment is enforced in both
/// directions: a length mismatch against the transition's named operations
/// fails closed instead of silently dropping or inventing authorities.
pub(crate) fn select_apply_plan(
    transition: &PreparedTransition,
    authorities: &[Option<ExactJsonBytes>],
    current_revision_heads: &[RevisionHead],
    current_ordering_heads: &[OrderingHead],
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
) -> Result<ApplyPlan, StoreError> {
    if authorities.len() != transition.named_operations.len() {
        return Err(StoreError::InvalidField {
            field: "payload.authority",
            reason: "payload authority count does not match named operations",
        });
    }
    if authorities.iter().any(Option::is_some) {
        plan_apply_with_payload_authority(
            transition,
            authorities,
            current_revision_heads,
            current_ordering_heads,
            next_commit_sequence,
            next_outbox_sequence,
        )
    } else {
        plan_apply(
            transition,
            current_revision_heads,
            current_ordering_heads,
            next_commit_sequence,
            next_outbox_sequence,
        )
    }
}
///
/// Plans one committed transition with per-operation payload authorities
/// bound in (issue #10, Wave C).
///
/// `authorities` aligns 1:1 with `transition.named_operations`: `Some`
/// entries are revalidated and must decode to exactly the operation's
/// queryable parameters, `None` entries mean that operation claims no
/// authority. When at least one authority is present, the outbox payload
/// digest binds every authority digest on top of the whole-transition
/// digest; legacy all-`None` plans keep the exact historical digest.
pub(crate) fn plan_apply_with_payload_authority(
    transition: &PreparedTransition,
    authorities: &[Option<ExactJsonBytes>],
    current_revision_heads: &[RevisionHead],
    current_ordering_heads: &[OrderingHead],
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
) -> Result<ApplyPlan, StoreError> {
    transition.validate()?;
    let records = payload_authority_records(transition, authorities)?;
    let commit_sequence = next_commit_sequence;
    let committed_at = committed_at_for(next_commit_sequence);
    let next_commit_sequence =
        checked_increment(next_commit_sequence, "commit.sequence", "sequence overflow")?;

    let revision_keys = revision_keys(transition)?;
    let mut revision_before_after = Vec::with_capacity(revision_keys.len());
    let mut next_revision_heads = Vec::with_capacity(revision_keys.len());
    for key in revision_keys {
        let before = current_revision_heads
            .iter()
            .find(|head| head.key == key)
            .map_or(1, |head| head.revision);
        let after = checked_increment(before, "revision", "revision overflow")?;
        revision_before_after.push(RevisionDelta {
            key: key.clone(),
            before,
            after,
        });
        next_revision_heads.push(RevisionHead {
            key,
            revision: after,
            state_fence: transition.state_fence.clone(),
        });
    }

    let mut next_ordering_heads = Vec::with_capacity(transition.ordering_scopes.len());
    for scope in transition.ordering_scopes.iter().cloned() {
        let before = current_ordering_heads
            .iter()
            .find(|head| head.scope == scope)
            .map_or(1, |head| head.sequence);
        let sequence = checked_increment(before, "ordering.sequence", "sequence overflow")?;
        next_ordering_heads.push(OrderingHead {
            scope,
            sequence,
            state_fence: transition.state_fence.clone(),
        });
    }

    let operation_key = transition.identity.operation_id.to_string();
    let commit_id = CommitId::new(format!("commit-{operation_key}"))?;
    let event_ids = event_ids(
        &transition.event_projection_relation_intents,
        &operation_key,
    )?;
    let command_ids = command_ids(transition, &operation_key);
    let payload_digest = if records.is_empty() {
        transition_payload_digest(transition)?
    } else {
        bound_payload_digest(transition, &records)?
    };
    let projection_records =
        projection_records(transition, &operation_key, &commit_id, &next_revision_heads)?;
    let (outbox_records, next_outbox_sequence) = outbox_records(
        transition,
        &operation_key,
        &event_ids,
        &payload_digest,
        next_outbox_sequence,
    )?;
    let evidence_records = evidence_records(transition, authorities, commit_sequence)?;

    Ok(ApplyPlan {
        commit_sequence,
        committed_at,
        commit_id,
        revision_before_after,
        next_revision_heads,
        next_ordering_heads,
        event_ids,
        command_ids,
        projection_records,
        outbox_records,
        next_commit_sequence,
        next_outbox_sequence,
        payload_authority: records,
        evidence_records,
    })
}

/// Renders the commit instant bound to one allocated commit sequence.
///
/// Single owner for the allocation-derived instant format: full planning
/// and allocation-only recomputation both bind through here, so a retry
/// can never drift from the planned instant representation.
fn committed_at_for(next_commit_sequence: u64) -> String {
    format!("commit-sequence-{next_commit_sequence:016}")
}

/// Recomputes only the allocation-derived outputs of an established
/// semantic plan (S-CONC-TX, issue #989).
///
/// Sole owner of every allocative field: `commit_sequence`, the derived
/// `committed_at` instant, `next_commit_sequence`, the outbox record
/// sequences plus `next_outbox_sequence`, and the evidence capture order.
/// The caller's [`build_receipt`] then rebinds the receipt fields that
/// carry those allocation values. Every semantic field — event and
/// command identities, payloads and digests, projections, relations,
/// revision deltas, ordering-head results, semantic receipt bindings — is
/// preserved byte-for-byte from `semantic_plan`, never re-derived: the
/// bounded allocation retry loop re-enters through here and never through
/// the full planner, so retry planning cannot duplicate or drift from
/// full-plan logic by construction.
pub(crate) fn recompute_allocation(
    semantic_plan: &ApplyPlan,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
) -> Result<ApplyPlan, StoreError> {
    let mut plan = semantic_plan.clone();
    plan.commit_sequence = next_commit_sequence;
    plan.committed_at = committed_at_for(next_commit_sequence);
    plan.next_commit_sequence =
        checked_increment(next_commit_sequence, "commit.sequence", "sequence overflow")?;
    let mut outbox_cursor = next_outbox_sequence;
    for record in &mut plan.outbox_records {
        record.sequence = outbox_cursor;
        outbox_cursor = checked_increment(outbox_cursor, "outbox.sequence", "sequence overflow")?;
    }
    plan.next_outbox_sequence = outbox_cursor;
    for evidence in &mut plan.evidence_records {
        evidence.commit_sequence = next_commit_sequence;
    }
    Ok(plan)
}

/// Validates per-operation payload authorities against the transition's
/// queryable parameters and renders their plan records.
///
/// Length, digest, duplicate-key, control-field, and narrowing checks all
/// run here, before any durable effect is planned: a mismatched authority
/// fails the plan instead of reaching the transaction writer.
fn payload_authority_records(
    transition: &PreparedTransition,
    authorities: &[Option<ExactJsonBytes>],
) -> Result<Vec<PayloadAuthorityRecord>, StoreError> {
    if authorities.len() != transition.named_operations.len() {
        return Err(StoreError::InvalidField {
            field: "payload.authority",
            reason: "payload authority count does not match named operations",
        });
    }
    let mut records = Vec::new();
    for (index, (operation, authority)) in transition
        .named_operations
        .iter()
        .zip(authorities.iter())
        .enumerate()
    {
        if let Some(authority) = authority {
            authority.validate()?;
            let decoded = authority.decode_object_parameters()?;
            if decoded != operation.parameters {
                return Err(StoreError::InvalidField {
                    field: "payload.authority",
                    reason: "payload authority does not match named-operation parameters",
                });
            }
            records.push(PayloadAuthorityRecord {
                operation_index: index,
                version: authority.version,
                encoding: authority.encoding.mnemonic().to_owned(),
                digest_hex: authority.digest_hex(),
                byte_len: authority.byte_len(),
                bytes: authority.bytes.clone(),
            });
        }
    }
    Ok(records)
}

/// Builds the recoverable `CaptureObservation` evidence for one transition.
///
/// Runs after [`payload_authority_records`] so supplied authorities are
/// already validated against the queryable parameters. Every capture is
/// persisted regardless of authority presence: with an authority the original
/// raw bytes travel verbatim; without one the canonical JSON of the admitted
/// parameters is the exact recoverable representation (the legacy path has no
/// original bytes, only the admitted `Value`). A missing or blank subject
/// fails closed here instead of persisting an unselectable record.
fn evidence_records(
    transition: &PreparedTransition,
    authorities: &[Option<ExactJsonBytes>],
    commit_sequence: u64,
) -> Result<Vec<EvidenceRecord>, StoreError> {
    if authorities.len() != transition.named_operations.len() {
        return Err(StoreError::InvalidField {
            field: "payload.authority",
            reason: "payload authority count does not match named operations",
        });
    }
    let named_operation_count = transition.named_operations.len();
    let mut records = Vec::new();
    for (index, (operation, authority)) in transition
        .named_operations
        .iter()
        .zip(authorities.iter())
        .enumerate()
    {
        if operation.operation != NamedMutationOperation::CaptureObservation {
            continue;
        }
        let subject = operation
            .parameters
            .get("subject")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            })?;
        if subject.trim().is_empty() || subject.chars().any(char::is_control) {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "subject must be a non-blank string",
            });
        }
        let (version, encoding, digest_hex, byte_len, bytes) = if let Some(authority) = authority {
            (
                authority.version,
                authority.encoding.mnemonic().to_owned(),
                authority.digest_hex(),
                authority.byte_len(),
                authority.bytes.clone(),
            )
        } else {
            let canonical = canonical_json_bytes(&operation.parameters)
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            let bound = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, &canonical)?;
            (
                bound.version,
                bound.encoding.mnemonic().to_owned(),
                bound.digest_hex(),
                bound.byte_len(),
                bound.bytes.clone(),
            )
        };
        // Legacy fallback provenance uses the canonical authority version;
        // keep the single owner: the derived bytes must carry the current
        // authority version, never a hardcoded constant.
        debug_assert_eq!(version, PAYLOAD_AUTHORITY_VERSION);
        debug_assert_eq!(encoding, PayloadEncoding::Utf8Json.mnemonic());
        records.push(EvidenceRecord {
            operation_index: index,
            subject: subject.to_owned(),
            parameters: operation.parameters.clone(),
            version,
            encoding,
            digest_hex,
            byte_len,
            bytes,
            commit_sequence,
            named_operation_count,
        });
    }
    Ok(records)
}

/// Whole-transition digest used when no payload authority is claimed.
/// Computed in exactly one place so legacy and bound plans agree on the
/// base value.
fn transition_payload_digest(transition: &PreparedTransition) -> Result<String, StoreError> {
    Ok(sha256_hex(&canonical_json_bytes(transition).map_err(
        |error| StoreError::Serialization(error.to_string()),
    )?))
}

/// Binds per-operation payload-authority digests over the
/// whole-transition digest. The base digest keeps its historical value; the
/// bound digest additionally covers every authority digest in operation
/// order, so a substituted authority can never reuse a bound outbox row.
fn bound_payload_digest(
    transition: &PreparedTransition,
    records: &[PayloadAuthorityRecord],
) -> Result<String, StoreError> {
    let mut material = transition_payload_digest(transition)?;
    for record in records {
        material.push_str(&record.digest_hex);
    }
    Ok(sha256_hex(material.as_bytes()))
}

/// Builds and validates the immutable write receipt for a planned transition.
pub(crate) fn build_receipt(
    ctx: &RequestMeta,
    transition: &PreparedTransition,
    plan: &ApplyPlan,
) -> Result<WriteReceipt, StoreError> {
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(plan.commit_id.clone()),
        state_fence: transition.state_fence.clone(),
        ordering_sequences: plan.next_ordering_heads.clone(),
        revision_before_after: plan.revision_before_after.clone(),
        applied_command_ids: plan.command_ids.clone(),
        emitted_event_ids: plan.event_ids.clone(),
        projection_refs: plan
            .projection_records
            .iter()
            .map(|record| record.publication_id.clone())
            .collect(),
        outbox_refs: plan
            .outbox_records
            .iter()
            .map(|record| record.outbox_id.clone())
            .collect(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some(plan.committed_at.clone()),
        envelope: None,
    };
    receipt.envelope = Some(issue_store_receipt_envelope(
        ctx,
        transition,
        &receipt,
        plan.commit_sequence,
    )?);
    receipt.validate()?;
    Ok(receipt)
}

/// Validates that a returned receipt matches the transition that requested it.
pub(crate) fn validate_receipt_identity(
    receipt: &WriteReceipt,
    ctx: &RequestMeta,
    transition: &PreparedTransition,
) -> Result<(), AdapterError> {
    receipt.validate()?;
    if receipt.operation_id != transition.identity.operation_id
        || receipt.idempotency_key != transition.identity.idempotency_key
        || receipt.canonical_request_hash != transition.identity.canonical_request_hash
        || receipt.transition_class != transition.transition_class
        || receipt.operation_manifest_digest != transition.operation_manifest_digest
        || receipt.state_fence != ctx.state_fence
    {
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    }
    validate_store_receipt_envelope(ctx, transition, receipt)?;
    Ok(())
}

/// Recomputes the canonical request hash from the exact values to be
/// executed/committed (RECHECK-63 slice C).
///
/// Shared-helper only: builds [`CanonicalRequestView::from_apply`] from the
/// transported `ctx` + `transition` + expected heads and hashes via
/// [`canonical_request_hash`]. Never reimplements hashing.
#[allow(dead_code)]
pub(crate) fn recomputed_canonical_request_hash(
    ctx: &RequestMeta,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<String, StoreError> {
    let view = CanonicalRequestView::from_apply(
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    canonical_request_hash(&view)
}

/// Verifies the supplied claim against the recomputed digest and returns the
/// recomputed value for receipt binding.
///
/// Supplied != recomputed is [`StoreError::TransitionDigestMismatch`] with no
/// transaction and no lookup success. Callers must invoke this BEFORE any
/// idempotency-lookup success is returned and BEFORE any transaction/receipt.
#[allow(dead_code)]
pub(crate) fn verify_apply_canonical_hash(
    ctx: &RequestMeta,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<String, StoreError> {
    let view = CanonicalRequestView::from_apply(
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)?;
    canonical_request_hash(&view)
}

/// Builds the receipt bound to the recomputed digest (slice C).
///
/// Verifies first, then binds `WriteReceipt.canonical_request_hash` to the
/// recomputed value (never a blind copy of the supplied claim).
/// Residual wiring (cannot edit `apply.rs` here): `apply.rs:622`
/// `build_receipt(ctx, &transition, &plan)` must switch to this function with
/// the `expected_revision_heads` / `expected_ordering_heads` available in
/// `apply_prepared_with_authority`, otherwise the live Surreal path keeps the
/// legacy blind-copy receipt for non-empty-heads applies.
#[allow(dead_code)]
pub(crate) fn build_receipt_with_expected_heads(
    ctx: &RequestMeta,
    transition: &PreparedTransition,
    plan: &ApplyPlan,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<WriteReceipt, StoreError> {
    let recomputed = verify_apply_canonical_hash(
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    )?;
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: recomputed,
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(plan.commit_id.clone()),
        state_fence: transition.state_fence.clone(),
        ordering_sequences: plan.next_ordering_heads.clone(),
        revision_before_after: plan.revision_before_after.clone(),
        applied_command_ids: plan.command_ids.clone(),
        emitted_event_ids: plan.event_ids.clone(),
        projection_refs: plan
            .projection_records
            .iter()
            .map(|record| record.publication_id.clone())
            .collect(),
        outbox_refs: plan
            .outbox_records
            .iter()
            .map(|record| record.outbox_id.clone())
            .collect(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some(plan.committed_at.clone()),
        envelope: None,
    };
    receipt.envelope = Some(issue_store_receipt_envelope(
        ctx,
        transition,
        &receipt,
        plan.commit_sequence,
    )?);
    receipt.validate()?;
    Ok(receipt)
}

/// Validates receipt identity plus the recomputed digest (slice C).
///
/// Checks supplied == recomputed (typed mismatch otherwise), receipt ==
/// recomputed, and the legacy identity/envelope rules. Residual wiring:
/// `apply.rs:581` and `apply.rs:638` `validate_receipt_identity` calls must
/// switch here with the expected heads from `apply_prepared_with_authority`.
#[allow(dead_code)]
pub(crate) fn validate_receipt_identity_with_expected_heads(
    receipt: &WriteReceipt,
    ctx: &RequestMeta,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), AdapterError> {
    let recomputed = verify_apply_canonical_hash(
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    )
    .map_err(AdapterError::Store)?;
    if receipt.canonical_request_hash != recomputed {
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    }
    validate_receipt_identity(receipt, ctx, transition)
}

/// Validates a deduplicated revision-head result set.
pub(crate) fn validate_revision_heads(heads: &[RevisionHead]) -> Result<(), StoreError> {
    ensure_unique_revision_keys(
        &heads
            .iter()
            .map(|head| head.key.clone())
            .collect::<Vec<_>>(),
    )?;
    for head in heads {
        head.validate()?;
    }
    Ok(())
}

/// Validates a deduplicated ordering-head result set.
pub(crate) fn validate_ordering_heads(heads: &[OrderingHead]) -> Result<(), StoreError> {
    ensure_unique_ordering_scopes(
        &heads
            .iter()
            .map(|head| head.scope.clone())
            .collect::<Vec<_>>(),
    )?;
    for head in heads {
        head.validate()?;
    }
    Ok(())
}

fn revision_keys(transition: &PreparedTransition) -> Result<Vec<RevisionKey>, StoreError> {
    let mut keys = BTreeSet::new();
    keys.insert(RevisionKey::new(format!("scope:{}", transition.scope_id))?);
    Ok(keys.into_iter().collect())
}

fn event_ids(
    intents: &EventProjectionRelationIntents,
    operation_key: &str,
) -> Result<Vec<EventId>, StoreError> {
    if intents.event_ids.is_empty() {
        return Ok(vec![EventId::new(format!("event-{operation_key}"))?]);
    }
    Ok(intents.event_ids.clone())
}

fn command_ids(transition: &PreparedTransition, operation_key: &str) -> Vec<String> {
    transition
        .named_operations
        .iter()
        .enumerate()
        .map(|(index, _)| format!("command-{operation_key}-{index}"))
        .collect()
}

/// Derives queryable projection publications for a transition.
///
/// These records are explicitly derivatives: when a plan carries payload
/// authorities, the opaque authority bytes (persisted alongside the receipt)
/// are the lossless representation and these projections must never be used
/// to reconstruct payload content. Any authority/projection disagreement is
/// a typed error at the read boundary, never a silent fallback.
fn projection_records(
    transition: &PreparedTransition,
    operation_key: &str,
    commit_id: &CommitId,
    source_revision_heads: &[RevisionHead],
) -> Result<Vec<ProjectionPublicationRecord>, StoreError> {
    transition
        .event_projection_relation_intents
        .projection_kinds
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            let source_cursor = source_revision_heads
                .iter()
                .map(|head| head.revision)
                .max()
                .unwrap_or(1);
            let record = ProjectionPublicationRecord {
                publication_id: ProjectionPublicationId::new(format!(
                    "projection-{operation_key}-{index}"
                ))?,
                projection_kind: kind.clone(),
                projection_generation: 1,
                source_generation: 1,
                source_cursor,
                state_fence: transition.state_fence.clone(),
                mode: ProjectionMode::Delta,
                source_revision_heads: source_revision_heads.to_vec(),
                atomic_data_commit: commit_id.clone(),
                provenance_manifest_ref: transition.operation_manifest_digest.to_string(),
                visible_lag_checkpoint: None,
                split_view: SplitView::None,
                status: ProjectionStatus::Current,
            };
            record.validate()?;
            Ok(record)
        })
        .collect()
}

fn outbox_records(
    transition: &PreparedTransition,
    operation_key: &str,
    event_ids: &[EventId],
    payload_digest: &str,
    next_sequence: u64,
) -> Result<(Vec<OutboxIntent>, u64), StoreError> {
    let mut records = Vec::with_capacity(event_ids.len());
    let mut sequence_cursor = next_sequence;
    for (index, _) in event_ids.iter().enumerate() {
        let sequence = sequence_cursor;
        sequence_cursor =
            checked_increment(sequence_cursor, "outbox.sequence", "sequence overflow")?;
        let record = OutboxIntent {
            outbox_id: OutboxId::new(format!("outbox-{operation_key}-{index}"))?,
            operation_id: transition.identity.operation_id.clone(),
            sequence,
            payload_digest: payload_digest.to_owned(),
            state_fence: transition.state_fence.clone(),
            arrival_fence: format!("arrival-{operation_key}"),
            claim_fence: None,
            state: OutboxState::Arrived,
        };
        record.validate()?;
        records.push(record);
    }
    Ok((records, sequence_cursor))
}

fn checked_increment(
    value: u64,
    field: &'static str,
    reason: &'static str,
) -> Result<u64, StoreError> {
    value
        .checked_add(1)
        .ok_or(StoreError::InvalidField { field, reason })
}

fn ensure_unique_revision_keys(keys: &[RevisionKey]) -> Result<(), StoreError> {
    let mut seen = BTreeSet::new();
    if keys.iter().any(|key| !seen.insert(key.clone())) {
        return Err(StoreError::Duplicate {
            field: "revision_keys",
        });
    }
    Ok(())
}

fn ensure_unique_ordering_scopes(scopes: &[OrderingScopeId]) -> Result<(), StoreError> {
    let mut seen = BTreeSet::new();
    if scopes.iter().any(|scope| !seen.insert(scope.clone())) {
        return Err(StoreError::Duplicate {
            field: "ordering_scopes",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
    };
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationId, OperationIdentity, OperationManifestDigest, OrderingScopeId, ReceiptEnvelope,
        ScopeId, SecurityContext, StateFence, TransitionClass,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fixture() -> Result<(RequestMeta, PreparedTransition), StoreError> {
        let state_fence = StateFence::new(test_epoch(1), ResourceGeneration::genesis());
        let context = RequestMeta {
            request_id: RequestId::new("request-1").map_err(StoreError::Foundation)?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1").map_err(StoreError::Foundation)?,
            source_id: SourceId::new("source-1").map_err(StoreError::Foundation)?,
            state_fence: state_fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        };
        let operation = "op-envelope";
        let transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: OperationId::new(operation).map_err(StoreError::Foundation)?,
                idempotency_key: format!("idem-{operation}"),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence,
            scope_id: ScopeId::new("scope-1")?,
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-1")?],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "a".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1")?,
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(String::from("subject"), json!(operation))]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: vec![String::from("task_state")],
                relation_kinds: vec![String::from("causes")],
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        Ok((context, transition))
    }

    #[test]
    fn build_receipt_binds_authoritative_context_and_is_deterministic() -> Result<(), StoreError> {
        let (context, transition) = fixture()?;
        let plan = plan_apply(&transition, &[], &[], 1, 1)?;
        let first = build_receipt(&context, &transition, &plan)?;
        let replay = build_receipt(&context, &transition, &plan)?;

        assert_eq!(first, replay);
        assert_eq!(
            first
                .require_reconciliation_envelope()?
                .core
                .request
                .metadata,
            context
        );
        validate_store_receipt_envelope(&context, &transition, &first)?;
        Ok(())
    }

    #[test]
    fn receipt_identity_rejects_transition_and_envelope_substitution() -> Result<(), StoreError> {
        let (context, transition) = fixture()?;
        let plan = plan_apply(&transition, &[], &[], 1, 1)?;
        let receipt = build_receipt(&context, &transition, &plan)?;

        let mut substituted_transition = transition.clone();
        substituted_transition.named_operations[0]
            .parameters
            .insert("subject".to_owned(), json!("substituted"));
        assert!(validate_receipt_identity(&receipt, &context, &substituted_transition).is_err());

        let mut substituted_core = receipt.require_reconciliation_envelope()?.core.clone();
        substituted_core.operation.operation_kind = "store.apply.substituted".to_owned();
        let mut substituted_receipt = receipt.clone();
        substituted_receipt.envelope =
            Some(ReceiptEnvelope::issue(substituted_core).map_err(StoreError::Receipt)?);
        assert!(validate_receipt_identity(&substituted_receipt, &context, &transition).is_err());
        Ok(())
    }

    #[test]
    fn plan_routing_keeps_legacy_path_without_authorities() -> Result<(), StoreError> {
        use crate::plan::select_apply_plan;

        let (_, transition) = fixture()?;
        let legacy = plan_apply(&transition, &[], &[], 1, 1)?;
        assert!(legacy.payload_authority.is_empty());
        let routed = select_apply_plan(&transition, &[None], &[], &[], 1, 1)?;
        assert!(routed.payload_authority.is_empty());
        assert_eq!(
            routed.outbox_records, legacy.outbox_records,
            "all-None authorities keep the exact historical digest path"
        );
        Ok(())
    }

    #[test]
    fn plan_routing_binds_original_authority_bytes_when_present() -> Result<(), StoreError> {
        use crate::plan::select_apply_plan;
        use eliot_store_api::{ExactJsonBytes, PayloadSource};

        let (_, transition) = fixture()?;
        let raw = br#"{"subject":"op-envelope"}"#;
        let authority = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw)?;
        assert_eq!(
            authority.decode_object_parameters()?,
            transition.named_operations[0].parameters,
            "fixture authority matches the admitted parameters"
        );
        let routed = select_apply_plan(&transition, &[Some(authority)], &[], &[], 1, 1)?;
        assert_eq!(routed.payload_authority.len(), 1);
        assert_eq!(
            routed.payload_authority[0].bytes, raw,
            "original raw bytes reach the plan, never a re-serialized Value"
        );
        let legacy = plan_apply(&transition, &[], &[], 1, 1)?;
        assert_ne!(
            routed.outbox_records[0].payload_digest, legacy.outbox_records[0].payload_digest,
            "claimed authority changes the bound outbox digest"
        );
        // Misaligned or substituted authorities fail closed.
        assert!(
            select_apply_plan(&transition, &[], &[], &[], 1, 1).is_err(),
            "authority count mismatch fails closed"
        );
        let substituted = ExactJsonBytes::parse(
            PayloadSource::NamedOperationParameter,
            br#"{"subject":"substituted"}"#,
        )?;
        assert!(
            select_apply_plan(&transition, &[Some(substituted)], &[], &[], 1, 1).is_err(),
            "substituted authority fails closed"
        );
        Ok(())
    }

    #[test]
    fn canonical_recompute_rejects_tamper_and_binds_recomputed() -> Result<(), StoreError> {
        // RECHECK-63 slice C (pure, no live DB): the shared helper recomputes
        // from the exact values to be committed. The legacy fixture claim
        // `"a".repeat(64)` is a placeholder (proof below: it never equals the
        // recomputed digest), so the new validators bind the recomputed value.
        // Cross-crate stability: this uses the same `canonical_request_hash`
        // that yields the Slice A golden
        // `55e62e405f35c7f137fe9fcdf177c66a1cba54a5b75fb547deaa11f001a89ec1`
        // in `eliot-store-api`.
        let (context, mut transition) = fixture()?;
        let recomputed = recomputed_canonical_request_hash(&context, &transition, &[], &[])?;
        assert_ne!(
            recomputed,
            "a".repeat(64),
            "placeholder claim is never the real digest"
        );
        // Exact binds recomputed and validates.
        transition.identity.canonical_request_hash = recomputed.clone();
        let plan = plan_apply(&transition, &[], &[], 1, 1)?;
        let receipt = build_receipt_with_expected_heads(&context, &transition, &plan, &[], &[])?;
        assert_eq!(receipt.canonical_request_hash, recomputed);
        validate_receipt_identity_with_expected_heads(&receipt, &context, &transition, &[], &[])
            .expect("exact receipt identity validates");
        // Tampered executable bytes with the old claim fail typed.
        let mut tampered = transition.clone();
        tampered.named_operations[0]
            .parameters
            .insert("subject".to_owned(), json!("tampered"));
        assert!(matches!(
            verify_apply_canonical_hash(&context, &tampered, &[], &[]),
            Err(StoreError::TransitionDigestMismatch { .. })
        ));
        assert!(matches!(
            build_receipt_with_expected_heads(&context, &tampered, &plan, &[], &[]),
            Err(StoreError::TransitionDigestMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn fresh_allocation_recomputes_only_allocation_dependent_values() -> Result<(), StoreError> {
        // S-CONC-TX (issue #989, pure, no live DB): the bounded retry
        // re-plans the unchanged admitted transition against a moved fence.
        // Only allocation-dependent values may change; every semantic effect
        // (revision/ordering heads, event/command/projection/relation
        // contents) is identical.
        let (_, transition) = fixture()?;
        let stale = plan_apply(&transition, &[], &[], 1, 1)?;
        let fresh = plan_apply(&transition, &[], &[], 2, 4)?;
        assert_eq!(stale.commit_sequence, 1);
        assert_eq!(fresh.commit_sequence, 2);
        assert_eq!(stale.next_commit_sequence, 2);
        assert_eq!(fresh.next_commit_sequence, 3);
        assert_eq!(stale.next_outbox_sequence, 2);
        assert_eq!(fresh.next_outbox_sequence, 5);
        assert_ne!(stale.committed_at, fresh.committed_at);
        assert_eq!(
            stale.outbox_records.len(),
            fresh.outbox_records.len(),
            "same semantic input plans the same outbox count"
        );
        for (stale_outbox, fresh_outbox) in
            stale.outbox_records.iter().zip(fresh.outbox_records.iter())
        {
            assert_eq!(
                stale_outbox.outbox_id, fresh_outbox.outbox_id,
                "outbox identity is semantic, not allocative"
            );
            assert_eq!(
                stale_outbox.payload_digest, fresh_outbox.payload_digest,
                "outbox payload digest is semantic, not allocative"
            );
            assert_ne!(
                stale_outbox.sequence, fresh_outbox.sequence,
                "outbox sequences consume the moved allocation"
            );
        }
        assert_eq!(
            stale.next_revision_heads, fresh.next_revision_heads,
            "revision heads do not move with allocation"
        );
        assert_eq!(
            stale.next_ordering_heads, fresh.next_ordering_heads,
            "ordering heads do not move with allocation"
        );
        assert_eq!(
            stale.event_ids, fresh.event_ids,
            "event identity is semantic, not allocative"
        );
        assert_eq!(
            stale.command_ids, fresh.command_ids,
            "command identity is semantic, not allocative"
        );
        assert_eq!(
            stale.revision_before_after, fresh.revision_before_after,
            "revision deltas do not move with allocation"
        );
        Ok(())
    }

    #[test]
    fn allocation_recompute_preserves_semantic_material_and_advances_sequences()
    -> Result<(), StoreError> {
        // S-CONC-TX rework (issue #989, pure, no live DB): the bounded
        // retry re-enters ONLY through `recompute_allocation`. Recomputing
        // the established semantic plan against the moved fence must equal
        // a full plan built at the moved allocation, field for field, while
        // the pre-retry semantic material stays byte-identical.
        let (context, transition) = fixture()?;
        let authorities = vec![None; transition.named_operations.len()];
        let semantic = select_apply_plan(&transition, &authorities, &[], &[], 1, 1)?;
        let recomputed = recompute_allocation(&semantic, 2, 4)?;
        let fresh = select_apply_plan(&transition, &authorities, &[], &[], 2, 4)?;
        // Allocative outputs track the moved fence.
        assert_eq!(recomputed.commit_sequence, 2);
        assert_eq!(recomputed.committed_at, "commit-sequence-0000000000000002");
        assert_eq!(recomputed.next_commit_sequence, 3);
        assert_eq!(recomputed.next_outbox_sequence, 5);
        assert_eq!(recomputed.outbox_records.len(), 1);
        assert_eq!(recomputed.outbox_records[0].sequence, 4);
        assert_eq!(recomputed.evidence_records.len(), 1);
        assert_eq!(recomputed.evidence_records[0].commit_sequence, 2);
        // Identical to the full plan at the same allocation.
        assert_eq!(
            format!("{recomputed:?}"),
            format!("{fresh:?}"),
            "recompute equals a full plan at the moved allocation"
        );
        // Semantic material is unchanged from the pre-retry plan.
        assert_eq!(
            recomputed.event_ids, semantic.event_ids,
            "event identity is semantic, not allocative"
        );
        assert_eq!(
            recomputed.command_ids, semantic.command_ids,
            "command identity is semantic, not allocative"
        );
        assert_eq!(
            recomputed.revision_before_after, semantic.revision_before_after,
            "revision deltas do not move with allocation"
        );
        assert_eq!(
            recomputed.next_revision_heads, semantic.next_revision_heads,
            "revision heads do not move with allocation"
        );
        assert_eq!(
            recomputed.next_ordering_heads, semantic.next_ordering_heads,
            "ordering heads do not move with allocation"
        );
        assert_eq!(
            format!("{:?}", recomputed.projection_records),
            format!("{:?}", semantic.projection_records),
            "projections do not move with allocation"
        );
        assert_eq!(
            format!("{:?}", recomputed.payload_authority),
            format!("{:?}", semantic.payload_authority),
            "payload authority is semantic, not allocative"
        );
        for (recomputed_evidence, semantic_evidence) in recomputed
            .evidence_records
            .iter()
            .zip(semantic.evidence_records.iter())
        {
            assert_eq!(recomputed_evidence.subject, semantic_evidence.subject);
            assert_eq!(recomputed_evidence.parameters, semantic_evidence.parameters);
            assert_eq!(recomputed_evidence.bytes, semantic_evidence.bytes);
            assert_eq!(recomputed_evidence.digest_hex, semantic_evidence.digest_hex);
        }
        // The receipt rebinds the recomputed allocation values.
        let receipt = build_receipt(&context, &transition, &recomputed)?;
        assert_eq!(
            receipt.committed_at.as_deref(),
            Some("commit-sequence-0000000000000002")
        );
        validate_store_receipt_envelope(&context, &transition, &receipt)?;
        // Allocation bounds fail closed here exactly as in full planning.
        assert!(
            recompute_allocation(&semantic, u64::MAX, 1).is_err(),
            "commit allocation overflow fails closed"
        );
        assert!(
            recompute_allocation(&semantic, 1, u64::MAX).is_err(),
            "outbox allocation overflow fails closed"
        );
        Ok(())
    }

    #[test]
    fn sequence_overflow_fails_closed_never_wraps() -> Result<(), StoreError> {
        // S-CONC-TX (issue #989, pure): integer bounds on every allocated
        // sequence fail closed with an exact disposition; allocation never
        // wraps, resets, or invents a duplicate identity.
        let (_, transition) = fixture()?;
        assert!(
            plan_apply(&transition, &[], &[], u64::MAX, 1).is_err(),
            "commit allocation overflow fails closed"
        );
        assert!(
            plan_apply(&transition, &[], &[], 1, u64::MAX).is_err(),
            "outbox allocation overflow fails closed"
        );
        assert!(
            plan_apply(&transition, &[], &[], u64::MAX, u64::MAX).is_err(),
            "joint allocation overflow fails closed"
        );
        assert!(
            checked_increment(u64::MAX, "commit.sequence", "sequence overflow").is_err(),
            "increment helper never wraps"
        );
        Ok(())
    }
}
