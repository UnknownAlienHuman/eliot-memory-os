//! Pure transaction planning: revision/ordering advancement, projection and
//! outbox derivation, receipt construction and write validation.
//!
//! Everything here is deterministic and independent of the physical store, so
//! it is unit-testable without a running SurrealDB. It mirrors the in-memory
//! reference store so two stores produce equivalent receipts from the same
//! inputs.

use std::collections::BTreeSet;

use eliot_store_api::{
    canonical_json_bytes, sha256_hex, CommitId, EventId, EventProjectionRelationIntents,
    OrderingHead, OrderingScopeId, OutboxId, OutboxIntent, OutboxState, PreparedTransition,
    ProjectionMode, ProjectionPublicationId, ProjectionPublicationRecord, ProjectionStatus,
    RequestMeta, Resubmission, RevisionDelta, RevisionHead, RevisionKey, SplitView, StoreError,
    WriteReceipt, WriteReceiptStatus,
};

use crate::error::AdapterError;

/// Planned durable effects of one committed transition.
#[derive(Clone, Debug)]
pub(crate) struct ApplyPlan {
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
}

/// Computes the durable effects of a transition from current heads and the
/// store's next sequence values.
pub(crate) fn plan_apply(
    transition: &PreparedTransition,
    current_revision_heads: &[RevisionHead],
    current_ordering_heads: &[OrderingHead],
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
) -> Result<ApplyPlan, StoreError> {
    transition.validate()?;
    let committed_at = format!("commit-sequence-{next_commit_sequence:016}");
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
    let payload_digest = sha256_hex(
        &canonical_json_bytes(transition)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    let projection_records = projection_records(
        transition,
        &operation_key,
        &commit_id,
        &next_revision_heads,
    )?;
    let (outbox_records, next_outbox_sequence) = outbox_records(
        transition,
        &operation_key,
        &event_ids,
        &payload_digest,
        next_outbox_sequence,
    )?;

    Ok(ApplyPlan {
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
    })
}

/// Builds and validates the immutable write receipt for a planned transition.
pub(crate) fn build_receipt(
    transition: &PreparedTransition,
    plan: &ApplyPlan,
) -> Result<WriteReceipt, StoreError> {
    let receipt = WriteReceipt {
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
    receipt.validate()?;
    Ok(receipt)
}

/// Validates that a returned receipt matches the transition that requested it.
pub(crate) fn validate_receipt_identity(
    receipt: &WriteReceipt,
    ctx: &RequestMeta,
    transition: &PreparedTransition,
) -> Result<(), AdapterError> {
    if receipt.operation_id != transition.identity.operation_id
        || receipt.idempotency_key != transition.identity.idempotency_key
        || receipt.canonical_request_hash != transition.identity.canonical_request_hash
        || receipt.transition_class != transition.transition_class
        || receipt.operation_manifest_digest != transition.operation_manifest_digest
        || receipt.state_fence != ctx.state_fence
    {
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    }
    Ok(())
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
        sequence_cursor = checked_increment(
            sequence_cursor,
            "outbox.sequence",
            "sequence overflow",
        )?;
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
