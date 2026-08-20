//! Deterministic, sequential in-memory reference store for ELIOT S-02.
//!
//! This implementation is a model, not a provider adapter. It owns no
//! authority, performs no I/O, and has no database or process-global state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_store_api::{
    CanonicalStoreClient, CanonicalValidationSnapshot, CommitId, EventId,
    EventProjectionRelationIntents, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    OperationId, OperationManifestDigest, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    OutboxId, OutboxIntent, OutboxState, PreparedTransition, ProjectionMode,
    ProjectionPublicationId, ProjectionPublicationRecord, ProjectionStatus, RequestMeta,
    Resubmission, RevisionDelta, RevisionHead, RevisionHeadExpectation, RevisionKey, ScopeId,
    ScopeRevisionView, SplitView, StateFence, StoreError, StoreHealth, StoreHealthStatus,
    WriteReceipt, WriteReceiptStatus, canonical_json_bytes, issue_store_receipt_envelope,
    sha256_hex, validate_store_receipt_envelope,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A deterministic reference store with no external authority or I/O.
#[derive(Debug)]
pub struct MemoryStore {
    state: Mutex<MemoryState>,
}

impl Clone for MemoryStore {
    fn clone(&self) -> Self {
        let state = match self.state.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Self {
            state: Mutex::new(state),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// Creates an empty deterministic model.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemoryState::default()),
        }
    }

    /// Registers a manifest for strict admission checking.
    pub fn register_manifest(
        &self,
        manifest: eliot_store_api::NamedOperationManifest,
    ) -> Result<(), StoreError> {
        manifest.validate()?;
        let mut state = self.lock_state()?;
        state
            .manifests
            .insert(manifest.digest.as_str().to_owned(), manifest);
        Ok(())
    }

    /// Applies one transition synchronously for model/reference tests.
    pub fn apply_transaction(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: &[RevisionHeadExpectation],
        expected_ordering_heads: &[OrderingHeadExpectation],
    ) -> Result<WriteReceipt, StoreError> {
        validate_transaction(ctx, &transition)?;
        let operation_key = transition.identity.operation_id.to_string();
        let mut state = self.lock_state()?;
        let canonical_hash = transition.identity.canonical_request_hash.clone();
        let idempotency_key = transition.identity.idempotency_key.clone();
        if let Some(receipt) = existing_receipt(
            &state,
            ctx,
            &transition,
            &operation_key,
            &idempotency_key,
            &canonical_hash,
        )? {
            return Ok(receipt);
        }
        validate_transaction_state(
            &state,
            &transition,
            expected_revision_heads,
            expected_ordering_heads,
        )?;
        let plan = transaction_plan(&state, &transition, &operation_key)?;
        let receipt =
            transaction_receipt(ctx, &transition, idempotency_key, canonical_hash, &plan)?;
        Ok(commit_transaction(
            &mut state,
            transition,
            operation_key,
            plan,
            receipt,
        ))
    }
}

fn validate_transaction(
    ctx: &RequestMeta,
    transition: &PreparedTransition,
) -> Result<(), StoreError> {
    ctx.validate().map_err(StoreError::Foundation)?;
    transition.validate()?;
    if ctx.state_fence != transition.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    Ok(())
}

fn existing_receipt(
    state: &MemoryState,
    ctx: &RequestMeta,
    transition: &PreparedTransition,
    operation_key: &str,
    idempotency_key: &str,
    canonical_hash: &str,
) -> Result<Option<WriteReceipt>, StoreError> {
    if let Some(receipt) = state.receipts_by_operation.get(operation_key) {
        if receipt.idempotency_key == idempotency_key
            && receipt.canonical_request_hash == canonical_hash
        {
            validate_store_receipt_envelope(ctx, transition, receipt)?;
            return Ok(Some(receipt.clone()));
        }
        return Err(StoreError::IdentityConflict);
    }
    if let Some((existing_hash, existing_operation)) =
        state.receipts_by_idempotency.get(idempotency_key)
    {
        if existing_hash == canonical_hash
            && existing_operation == operation_key
            && let Some(receipt) = state.receipts_by_operation.get(existing_operation)
        {
            validate_store_receipt_envelope(ctx, transition, receipt)?;
            return Ok(Some(receipt.clone()));
        }
        return Err(StoreError::IdentityConflict);
    }
    Ok(None)
}

fn validate_transaction_state(
    state: &MemoryState,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), StoreError> {
    if let Some(existing_fence) = &state.fences
        && existing_fence != &transition.state_fence
    {
        return Err(StoreError::FenceMismatch);
    }
    validate_expected_revisions(state, &transition.state_fence, expected_revision_heads)?;
    validate_expected_ordering(state, &transition.state_fence, expected_ordering_heads)?;
    let manifest = state
        .manifests
        .get(transition.operation_manifest_digest.as_str())
        .ok_or(StoreError::ManifestMismatch)?;
    transition.validate_against_manifest(manifest)?;
    Ok(())
}

struct TransactionPlan {
    commit_sequence: u64,
    revision_before_after: Vec<RevisionDelta>,
    next_revision_heads: Vec<RevisionHead>,
    next_ordering_heads: Vec<OrderingHead>,
    commit_id: CommitId,
    event_ids: Vec<EventId>,
    command_ids: Vec<String>,
    projection_records: Vec<ProjectionPublicationRecord>,
    outbox_records: Vec<OutboxIntent>,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
}

fn transaction_plan(
    state: &MemoryState,
    transition: &PreparedTransition,
    operation_key: &str,
) -> Result<TransactionPlan, StoreError> {
    let commit_sequence = state.next_commit_sequence;
    let next_commit_sequence =
        checked_increment(commit_sequence, "commit.sequence", "sequence overflow")?;
    let revision_keys = revision_keys(transition)?;
    let mut revision_before_after = Vec::with_capacity(revision_keys.len());
    let mut next_revision_heads = Vec::with_capacity(revision_keys.len());
    for key in revision_keys {
        let before = state
            .revision_heads
            .get(key.as_str())
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
        let before = state
            .ordering_heads
            .get(scope.as_str())
            .map_or(1, |head| head.sequence);
        let sequence = checked_increment(before, "ordering.sequence", "sequence overflow")?;
        next_ordering_heads.push(OrderingHead {
            scope,
            sequence,
            state_fence: transition.state_fence.clone(),
        });
    }

    let commit_id = CommitId::new(format!("commit-{operation_key}"))?;
    let event_ids = event_ids(&transition.event_projection_relation_intents, operation_key)?;
    let command_ids = transition
        .named_operations
        .iter()
        .enumerate()
        .map(|(index, _)| format!("command-{operation_key}-{index}"))
        .collect::<Vec<_>>();
    let payload_digest = sha256_hex(
        &canonical_json_bytes(&transition)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    let projection_records =
        projection_records(transition, operation_key, &commit_id, &next_revision_heads)?;
    let (outbox_records, next_outbox_sequence) = outbox_records(
        transition,
        operation_key,
        &event_ids,
        &payload_digest,
        state.next_outbox_sequence,
    )?;
    Ok(TransactionPlan {
        commit_sequence,
        revision_before_after,
        next_revision_heads,
        next_ordering_heads,
        commit_id,
        event_ids,
        command_ids,
        projection_records,
        outbox_records,
        next_commit_sequence,
        next_outbox_sequence,
    })
}

fn transaction_receipt(
    ctx: &RequestMeta,
    transition: &PreparedTransition,
    idempotency_key: String,
    canonical_hash: String,
    plan: &TransactionPlan,
) -> Result<WriteReceipt, StoreError> {
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key,
        canonical_request_hash: canonical_hash,
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
        committed_at: Some(format!("commit-sequence-{:016}", plan.commit_sequence)),
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

fn commit_transaction(
    state: &mut MemoryState,
    transition: PreparedTransition,
    operation_key: String,
    plan: TransactionPlan,
    receipt: WriteReceipt,
) -> WriteReceipt {
    for head in plan.next_revision_heads {
        state
            .revision_heads
            .insert(head.key.as_str().to_owned(), head);
    }
    for head in plan.next_ordering_heads {
        state
            .ordering_heads
            .insert(head.scope.as_str().to_owned(), head);
    }
    state.next_commit_sequence = plan.next_commit_sequence;
    state.next_outbox_sequence = plan.next_outbox_sequence;
    state
        .fences
        .get_or_insert_with(|| transition.state_fence.clone());
    for record in plan.projection_records {
        state
            .projections
            .insert(record.publication_id.as_str().to_owned(), record);
    }
    for record in plan.outbox_records {
        state
            .outbox
            .insert(record.outbox_id.as_str().to_owned(), record);
    }
    state
        .relations
        .extend(transition.event_projection_relation_intents.relation_kinds);
    state
        .named_operations
        .extend(transition.named_operations.clone());
    state.receipts_by_idempotency.insert(
        receipt.idempotency_key.clone(),
        (
            receipt.canonical_request_hash.clone(),
            operation_key.clone(),
        ),
    );
    state
        .receipts_by_operation
        .insert(operation_key, receipt.clone());
    receipt
}

impl MemoryStore {
    /// Returns a deterministic model snapshot.
    pub fn snapshot(&self) -> Result<MemorySnapshot, StoreError> {
        Ok(self.lock_state()?.snapshot())
    }

    /// Returns all projection publications in stable identity order.
    pub fn projections(&self) -> Result<Vec<ProjectionPublicationRecord>, StoreError> {
        Ok(self.lock_state()?.projections.values().cloned().collect())
    }

    /// Returns all outbox intents in stable identity order.
    pub fn outbox(&self) -> Result<Vec<OutboxIntent>, StoreError> {
        Ok(self.lock_state()?.outbox.values().cloned().collect())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, MemoryState>, StoreError> {
        self.state.lock().map_err(|_| StoreError::Unavailable)
    }

    fn receipt_sync(&self, operation_id: &OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        Ok(self
            .lock_state()?
            .receipts_by_operation
            .get(operation_id.as_str())
            .cloned())
    }

    fn revision_heads_sync(&self, keys: &[RevisionKey]) -> Result<Vec<RevisionHead>, StoreError> {
        ensure_unique_revision_keys(keys)?;
        let state = self.lock_state()?;
        Ok(keys
            .iter()
            .filter_map(|key| state.revision_heads.get(key.as_str()).cloned())
            .collect())
    }

    fn validation_snapshot_sync(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        let state = self.lock_state()?;
        let state_fence = state.fences.clone().ok_or(StoreError::Unavailable)?;
        let snapshot = CanonicalValidationSnapshot {
            state_fence,
            revision_heads: state.revision_heads.values().cloned().collect(),
            validation_revision: state.next_commit_sequence,
            observed_at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| StoreError::Unavailable)?
                .as_millis()
                .try_into()
                .map_err(|_| StoreError::Unavailable)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn ordering_heads_sync(
        &self,
        scopes: &[OrderingScopeId],
    ) -> Result<Vec<OrderingHead>, StoreError> {
        ensure_unique_ordering_scopes(scopes)?;
        let state = self.lock_state()?;
        Ok(scopes
            .iter()
            .filter_map(|scope| state.ordering_heads.get(scope.as_str()).cloned())
            .collect())
    }

    fn scope_revision_view_sync(&self, scope_id: ScopeId) -> Result<ScopeRevisionView, StoreError> {
        let state = self.lock_state()?;
        let fence = state.fences.clone().ok_or(StoreError::ReceiptNotFound)?;
        let revision_heads = state
            .revision_heads
            .values()
            .filter(|head| head.key.as_str() == format!("scope:{scope_id}"))
            .cloned()
            .collect();
        let ordering_heads = state
            .ordering_heads
            .values()
            .filter(|head| head.scope.as_str() == scope_id.as_str())
            .cloned()
            .collect();
        let view = ScopeRevisionView {
            scope_id,
            revision_heads,
            ordering_heads,
            state_fence: fence,
        };
        view.validate()?;
        Ok(view)
    }

    fn execute_named_sync(
        &self,
        query: &NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        query.validate()?;
        let state = self.lock_state()?;
        let fence = match state.fences.clone() {
            Some(fence) => fence,
            None => query.state_fence.clone(),
        };
        if fence != query.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        let revision_heads = state.revision_heads.values().cloned().collect::<Vec<_>>();
        let payload = match query.operation {
            NamedReadOperation::GetRevisionHeads => serde_json::to_value(&revision_heads),
            NamedReadOperation::GetOrderingHeads => {
                serde_json::to_value(state.ordering_heads.values().collect::<Vec<_>>())
            }
            NamedReadOperation::ResolveWriteReceipt => {
                let operation_id = query
                    .parameters
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .ok_or(StoreError::InvalidField {
                        field: "operation_id",
                        reason: "named receipt read requires a string operation_id",
                    })?;
                serde_json::to_value(state.receipts_by_operation.get(operation_id))
            }
            NamedReadOperation::GetScopeRevisionView => {
                let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
                    field: "scope_id",
                    reason: "scope revision read requires scope_id",
                })?;
                let revision = state
                    .revision_heads
                    .values()
                    .find(|head| head.key.as_str() == format!("scope:{scope_id}"));
                let ordering = state
                    .ordering_heads
                    .values()
                    .find(|head| head.scope.as_str() == scope_id.as_str());
                serde_json::to_value(json!({
                    "scope_id": scope_id,
                    "revision_head": revision,
                    "ordering_head": ordering,
                    "state_fence": fence,
                }))
            }
            _ => serde_json::to_value(json!({
                "operation": format!("{:?}", query.operation),
                "records": state.named_operations,
            })),
        };
        let payload = payload.map_err(|error| StoreError::Serialization(error.to_string()))?;
        let response = NamedReadResponse {
            operation: query.operation,
            state_fence: fence,
            revision_heads,
            payload,
        };
        response.validate()?;
        Ok(response)
    }

    fn health_sync(&self) -> Result<StoreHealth, StoreError> {
        let status = match self.state.try_lock() {
            Ok(_guard) => StoreHealthStatus::Ready,
            Err(TryLockError::WouldBlock) => StoreHealthStatus::Degraded,
            Err(TryLockError::Poisoned(_)) => StoreHealthStatus::Unavailable,
        };
        Ok(StoreHealth {
            status,
            contract_version: eliot_store_api::CONTRACT_VERSION,
            manifest_digest: OperationManifestDigest::new("memory-reference-v1")?,
        })
    }
}

impl CanonicalStoreClient for MemoryStore {
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        self.apply_transaction(
            ctx,
            transition,
            &expected_revision_heads,
            &expected_ordering_heads,
        )
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        self.receipt_sync(&operation_id)
    }

    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        self.revision_heads_sync(&keys)
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        self.validation_snapshot_sync()
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        self.scope_revision_view_sync(scope_id)
    }

    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        self.ordering_heads_sync(&scopes)
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        self.execute_named_sync(&query)
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        self.health_sync()
    }
}

#[derive(Clone, Debug)]
struct MemoryState {
    fences: Option<StateFence>,
    revision_heads: BTreeMap<String, RevisionHead>,
    ordering_heads: BTreeMap<String, OrderingHead>,
    receipts_by_operation: BTreeMap<String, WriteReceipt>,
    receipts_by_idempotency: BTreeMap<String, (String, String)>,
    projections: BTreeMap<String, ProjectionPublicationRecord>,
    outbox: BTreeMap<String, OutboxIntent>,
    relations: BTreeSet<String>,
    named_operations: Vec<eliot_store_api::NamedMutationRequest>,
    manifests: BTreeMap<String, eliot_store_api::NamedOperationManifest>,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
}

impl Default for MemoryState {
    fn default() -> Self {
        Self {
            fences: None,
            revision_heads: BTreeMap::new(),
            ordering_heads: BTreeMap::new(),
            receipts_by_operation: BTreeMap::new(),
            receipts_by_idempotency: BTreeMap::new(),
            projections: BTreeMap::new(),
            outbox: BTreeMap::new(),
            relations: BTreeSet::new(),
            named_operations: Vec::new(),
            manifests: BTreeMap::new(),
            next_commit_sequence: 1,
            next_outbox_sequence: 1,
        }
    }
}

impl MemoryState {
    fn snapshot(&self) -> MemorySnapshot {
        MemorySnapshot {
            state_fence: self.fences.clone(),
            revision_heads: self.revision_heads.values().cloned().collect(),
            ordering_heads: self.ordering_heads.values().cloned().collect(),
            receipts: self.receipts_by_operation.values().cloned().collect(),
            projections: self.projections.values().cloned().collect(),
            outbox: self.outbox.values().cloned().collect(),
            relations: self.relations.iter().cloned().collect(),
            named_operations: self.named_operations.clone(),
        }
    }
}

/// Stable, comparable state projection of the reference store.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub state_fence: Option<StateFence>,
    pub revision_heads: Vec<RevisionHead>,
    pub ordering_heads: Vec<OrderingHead>,
    pub receipts: Vec<WriteReceipt>,
    pub projections: Vec<ProjectionPublicationRecord>,
    pub outbox: Vec<OutboxIntent>,
    pub relations: Vec<String>,
    pub named_operations: Vec<eliot_store_api::NamedMutationRequest>,
}

fn revision_keys(transition: &PreparedTransition) -> Result<Vec<RevisionKey>, StoreError> {
    let mut keys = BTreeSet::new();
    keys.insert(RevisionKey::new(format!("scope:{}", transition.scope_id))?);
    Ok(keys.into_iter().collect())
}

fn validate_expected_revisions(
    state: &MemoryState,
    fence: &StateFence,
    expected: &[RevisionHeadExpectation],
) -> Result<(), StoreError> {
    ensure_unique_revision_expectations(expected)?;
    for item in expected {
        item.validate()?;
        if &item.state_fence != fence {
            return Err(StoreError::FenceMismatch);
        }
        match state.revision_heads.get(item.key.as_str()) {
            Some(current) if current.state_fence != *fence => {
                return Err(StoreError::FenceMismatch);
            }
            Some(current) if current.revision != item.expected_revision => {
                return Err(StoreError::RevisionConflict);
            }
            None if item.expected_revision != 1 => return Err(StoreError::RevisionConflict),
            _ => {}
        }
    }
    Ok(())
}

fn validate_expected_ordering(
    state: &MemoryState,
    fence: &StateFence,
    expected: &[OrderingHeadExpectation],
) -> Result<(), StoreError> {
    ensure_unique_ordering_expectations(expected)?;
    for item in expected {
        item.validate()?;
        if &item.state_fence != fence {
            return Err(StoreError::FenceMismatch);
        }
        match state.ordering_heads.get(item.scope.as_str()) {
            Some(current) if current.state_fence != *fence => {
                return Err(StoreError::FenceMismatch);
            }
            Some(current) if current.sequence != item.expected_sequence => {
                return Err(StoreError::OrderingConflict);
            }
            None if item.expected_sequence != 1 => return Err(StoreError::OrderingConflict),
            _ => {}
        }
    }
    Ok(())
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

fn ensure_unique_revision_expectations(
    values: &[RevisionHeadExpectation],
) -> Result<(), StoreError> {
    ensure_unique_revision_keys(
        &values
            .iter()
            .map(|value| value.key.clone())
            .collect::<Vec<_>>(),
    )
}

fn ensure_unique_ordering_expectations(
    values: &[OrderingHeadExpectation],
) -> Result<(), StoreError> {
    ensure_unique_ordering_scopes(
        &values
            .iter()
            .map(|value| value.scope.clone())
            .collect::<Vec<_>>(),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        AuthorityEpoch, ClockReading, ProductId, RequestId, ResourceGeneration, SourceId,
    };
    use eliot_store_api::{EffectClass, NamedOperationManifest, TransitionClass};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn metadata(state_fence: &StateFence) -> Result<RequestMeta, StoreError> {
        Ok(RequestMeta {
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
        })
    }

    fn manifest() -> Result<NamedOperationManifest, StoreError> {
        NamedOperationManifest::new(
            "memory-reference-test",
            eliot_store_api::CONTRACT_VERSION,
            vec![TransitionClass::CaptureCandidate],
            EffectClass::Candidate,
            1_024,
            1_024,
            1_000,
        )
    }

    fn store() -> Result<MemoryStore, StoreError> {
        let store = MemoryStore::new();
        store.register_manifest(manifest()?)?;
        Ok(store)
    }

    fn transition(
        operation: &str,
        state_fence: &StateFence,
    ) -> Result<PreparedTransition, StoreError> {
        let operation_id = OperationId::new(operation).map_err(StoreError::Foundation)?;
        Ok(PreparedTransition {
            identity: eliot_store_api::OperationIdentity {
                operation_id,
                idempotency_key: format!("idem-{operation}"),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: state_fence.clone(),
            scope_id: ScopeId::new("scope-1")?,
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-1")?],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "a".repeat(64),
            operation_manifest_digest: manifest()?.digest,
            named_operations: vec![eliot_store_api::NamedMutationRequest {
                operation: eliot_store_api::NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(String::from("subject"), json!(operation))]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: vec![],
                projection_kinds: vec![String::from("task_state")],
                relation_kinds: vec![String::from("causes")],
            },
            security: eliot_store_api::SecurityContext::default(),
            required_proof_and_approval_refs: vec![],
        })
    }

    #[test]
    fn replay_is_exact_and_does_not_advance_model() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        let ctx = metadata(&state_fence)?;
        let prepared = transition("op-1", &state_fence)?;
        let first = store.apply_transaction(&ctx, prepared.clone(), &[], &[])?;
        let before = store.snapshot()?;
        let replay = store.apply_transaction(&ctx, prepared, &[], &[])?;
        assert_eq!(first, replay);
        assert_eq!(before, store.snapshot()?);
        Ok(())
    }

    #[test]
    fn committed_receipt_has_exact_reconciliation_envelope() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        let ctx = metadata(&state_fence)?;
        let prepared = transition("op-envelope", &state_fence)?;

        let receipt = store.apply_transaction(&ctx, prepared.clone(), &[], &[])?;
        assert!(receipt.require_reconciliation_envelope().is_ok());
        validate_store_receipt_envelope(&ctx, &prepared, &receipt)?;
        let envelope = receipt
            .envelope
            .as_ref()
            .ok_or(StoreError::MissingReceiptEnvelope)?;
        assert_eq!(envelope.core.request.metadata, ctx);
        Ok(())
    }

    #[test]
    fn replay_rejects_prepared_payload_substitution() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        let ctx = metadata(&state_fence)?;
        let prepared = transition("op-substitution", &state_fence)?;
        store.apply_transaction(&ctx, prepared.clone(), &[], &[])?;

        let mut substituted = prepared;
        substituted.named_operations[0]
            .parameters
            .insert("subject".to_owned(), json!("substituted"));
        assert_eq!(
            store.apply_transaction(&ctx, substituted, &[], &[]),
            Err(StoreError::InvalidReceipt)
        );
        Ok(())
    }

    #[test]
    fn replay_rejects_receipt_envelope_substitution() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        let ctx = metadata(&state_fence)?;
        let first = transition("op-envelope-a", &state_fence)?;
        let second = transition("op-envelope-b", &state_fence)?;
        store.apply_transaction(&ctx, first.clone(), &[], &[])?;
        let second_receipt = store.apply_transaction(&ctx, second, &[], &[])?;
        {
            let mut state = store.lock_state()?;
            let stored = state
                .receipts_by_operation
                .get_mut(first.identity.operation_id.as_str())
                .ok_or(StoreError::ReceiptNotFound)?;
            stored.envelope = second_receipt.envelope;
        }
        assert_eq!(
            store.apply_transaction(&ctx, first, &[], &[]),
            Err(StoreError::InvalidReceipt)
        );
        Ok(())
    }

    #[test]
    fn stale_revision_is_typed_and_atomic() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        let ctx = metadata(&state_fence)?;
        store.apply_transaction(&ctx, transition("op-1", &state_fence)?, &[], &[])?;
        let before = store.snapshot()?;
        let stale = vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope:scope-1")?,
            expected_revision: 1,
            state_fence: state_fence.clone(),
        }];
        let error = store.apply_transaction(
            &ctx,
            transition("op-2", &state_fence)?,
            &stale,
            &[OrderingHeadExpectation {
                scope: OrderingScopeId::new("scope-1")?,
                expected_sequence: 2,
                state_fence,
            }],
        );
        assert!(matches!(error, Err(StoreError::RevisionConflict)));
        assert_eq!(before, store.snapshot()?);
        Ok(())
    }

    #[test]
    fn validation_snapshot_is_one_coherent_store_read() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        store.apply_transaction(
            &metadata(&state_fence)?,
            transition("snapshot", &state_fence)?,
            &[],
            &[],
        )?;

        let snapshot = store.validation_snapshot_sync()?;
        assert_eq!(snapshot.state_fence, state_fence);
        assert_eq!(snapshot.revision_heads.len(), 1);
        assert_eq!(snapshot.revision_heads[0].revision, 2);
        assert_eq!(snapshot.validation_revision, 2);
        assert!(snapshot.observed_at_unix_ms > 0);
        snapshot.validate()
    }

    #[test]
    fn independent_models_have_equal_projection_outbox_and_receipt() -> Result<(), StoreError> {
        let state_fence = fence();
        let ctx = metadata(&state_fence)?;
        let prepared = transition("op-1", &state_fence)?;
        let left = store()?;
        let right = store()?;
        let left_receipt = left.apply_transaction(&ctx, prepared.clone(), &[], &[])?;
        let right_receipt = right.apply_transaction(&ctx, prepared, &[], &[])?;
        assert_eq!(left_receipt, right_receipt);
        assert_eq!(left.snapshot()?, right.snapshot()?);
        assert_eq!(left.projections()?, right.projections()?);
        assert_eq!(left.outbox()?, right.outbox()?);
        Ok(())
    }

    #[test]
    fn missing_manifest_is_typed_and_atomic() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = MemoryStore::new();
        let before = store.snapshot()?;

        let result = store.apply_transaction(
            &metadata(&state_fence)?,
            transition("op-missing-manifest", &state_fence)?,
            &[],
            &[],
        );

        assert_eq!(result, Err(StoreError::ManifestMismatch));
        assert_eq!(before, store.snapshot()?);
        Ok(())
    }

    #[test]
    fn revision_overflow_is_typed_and_atomic() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        {
            let mut state = store.lock_state()?;
            let key = RevisionKey::new("scope:scope-1")?;
            state.revision_heads.insert(
                key.as_str().to_owned(),
                RevisionHead {
                    key,
                    revision: u64::MAX,
                    state_fence: state_fence.clone(),
                },
            );
        }
        let before = store.snapshot()?;

        let result = store.apply_transaction(
            &metadata(&state_fence)?,
            transition("op-revision-overflow", &state_fence)?,
            &[],
            &[],
        );

        assert_eq!(
            result,
            Err(StoreError::InvalidField {
                field: "revision",
                reason: "revision overflow",
            })
        );
        assert_eq!(before, store.snapshot()?);
        Ok(())
    }

    #[test]
    fn ordering_overflow_is_typed_and_atomic() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        {
            let mut state = store.lock_state()?;
            let scope = OrderingScopeId::new("scope-1")?;
            state.ordering_heads.insert(
                scope.as_str().to_owned(),
                OrderingHead {
                    scope,
                    sequence: u64::MAX,
                    state_fence: state_fence.clone(),
                },
            );
        }
        let before = store.snapshot()?;

        let result = store.apply_transaction(
            &metadata(&state_fence)?,
            transition("op-ordering-overflow", &state_fence)?,
            &[],
            &[],
        );

        assert_eq!(
            result,
            Err(StoreError::InvalidField {
                field: "ordering.sequence",
                reason: "sequence overflow",
            })
        );
        assert_eq!(before, store.snapshot()?);
        Ok(())
    }

    #[test]
    fn outbox_overflow_is_typed_and_atomic() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        store.lock_state()?.next_outbox_sequence = u64::MAX;
        let before = store.snapshot()?;

        let result = store.apply_transaction(
            &metadata(&state_fence)?,
            transition("op-outbox-overflow", &state_fence)?,
            &[],
            &[],
        );

        assert_eq!(
            result,
            Err(StoreError::InvalidField {
                field: "outbox.sequence",
                reason: "sequence overflow",
            })
        );
        assert_eq!(store.lock_state()?.next_outbox_sequence, u64::MAX);
        assert_eq!(before, store.snapshot()?);
        Ok(())
    }

    #[test]
    fn commit_overflow_is_typed_and_atomic() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        store.lock_state()?.next_commit_sequence = u64::MAX;
        let before = store.snapshot()?;

        let result = store.apply_transaction(
            &metadata(&state_fence)?,
            transition("op-commit-overflow", &state_fence)?,
            &[],
            &[],
        );

        assert_eq!(
            result,
            Err(StoreError::InvalidField {
                field: "commit.sequence",
                reason: "sequence overflow",
            })
        );
        assert_eq!(store.lock_state()?.next_commit_sequence, u64::MAX);
        assert_eq!(before, store.snapshot()?);
        Ok(())
    }

    #[test]
    fn clone_recovers_exact_poisoned_snapshot_without_panicking() -> Result<(), StoreError> {
        let state_fence = fence();
        let store = store()?;
        store.apply_transaction(
            &metadata(&state_fence)?,
            transition("op-before-poison", &state_fence)?,
            &[],
            &[],
        )?;
        let expected = store.snapshot()?;

        let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(_guard) = store.state.lock() else {
                panic!("test mutex was unexpectedly poisoned");
            };
            panic!("poison memory-store mutex");
        }));
        assert!(poison_result.is_err());

        let clone_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.clone()));
        let Ok(cloned) = clone_result else {
            panic!("cloning a poisoned memory store panicked");
        };
        assert_eq!(expected, cloned.snapshot()?);
        Ok(())
    }

    #[test]
    fn health_reflects_lock_contention_and_poisoning() -> Result<(), StoreError> {
        let store = store()?;
        assert_eq!(store.health_sync()?.status, StoreHealthStatus::Ready);

        {
            let guard = store.lock_state()?;
            assert_eq!(store.health_sync()?.status, StoreHealthStatus::Degraded);
            drop(guard);
        }

        let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(_guard) = store.state.lock() else {
                panic!("test mutex was unexpectedly poisoned");
            };
            panic!("poison memory-store mutex");
        }));
        assert!(poison_result.is_err());
        assert_eq!(store.health_sync()?.status, StoreHealthStatus::Unavailable);
        Ok(())
    }
}
