//! Architecture: A2.3, A12.3, ARCH-MOD-01, ARCH-MOD-02, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I5.1, I5.4, I5.9, I2.2, I2.23.
//! Responsibility: existing physical Surreal bridge genesis bootstrap cell only; forbids second writer, semantic decode, default/retry synthesis, credential ownership, or schema ownership beyond the existing bridge.

use serde_json::{Map, Value, json};

use crate::SurrealStoreAdapter;
use crate::client;
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::schema;
use eliot_store_api::{
    CommitId, RecoveryRecord, RecoveryRecordKey, RequestMeta, Resubmission, StoreError,
    StoreGenesisRequest, TransitionClass, WriteReceipt, WriteReceiptStatus, genesis_manifest,
    is_genesis_fence, issue_genesis_receipt_envelope, validate_genesis_receipt_envelope,
};

use super::receipt_reconciliation::read_receipt_by_operation;
use super::{
    FenceRecord, SchemaMetaRecord, take_schema_meta, validate_fence_record,
    validate_schema_meta_record,
};

#[derive(Clone, Debug)]
pub(super) struct GenesisState {
    pub(super) schema: Option<SchemaMetaRecord>,
    pub(super) fence: Option<FenceRecord>,
    pub(super) owners: Vec<RecoveryRecord>,
    pub(super) jobs: Vec<RecoveryRecord>,
    pub(super) receipts: Vec<WriteReceipt>,
    pub(super) revision_heads: Vec<Value>,
    pub(super) ordering_heads: Vec<Value>,
    pub(super) events: Vec<Value>,
    pub(super) projections: Vec<Value>,
    pub(super) outbox: Vec<Value>,
    pub(super) relations: Vec<Value>,
}

async fn read_genesis_state(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<GenesisState, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "genesis.preflight",
        schema::READ_GENESIS_SCHEMA_AND_STATE,
        Map::new(),
    )
    .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(GenesisState {
        schema: take_schema_meta(&mut response, 1)?,
        fence: response.take::<Option<FenceRecord>>(2)?,
        owners: response.take::<Vec<RecoveryRecord>>(3)?,
        jobs: response.take::<Vec<RecoveryRecord>>(4)?,
        receipts: response.take::<Vec<WriteReceipt>>(5)?,
        revision_heads: response.take::<Vec<Value>>(6)?,
        ordering_heads: response.take::<Vec<Value>>(7)?,
        events: response.take::<Vec<Value>>(8)?,
        projections: response.take::<Vec<Value>>(9)?,
        outbox: response.take::<Vec<Value>>(10)?,
        relations: response.take::<Vec<Value>>(11)?,
    })
}

fn validate_genesis_schema_fence(
    state: &GenesisState,
    config: &SurrealAdapterConfig,
    request: &StoreGenesisRequest,
) -> Result<(), AdapterError> {
    let schema = state
        .schema
        .as_ref()
        .ok_or(AdapterError::MigrationRequired)?;
    validate_schema_meta_record(schema)?;
    if schema.generation != config.expected_schema_generation.as_str()
        || schema.migration_state != "APPLIED"
    {
        return Err(AdapterError::MigrationRequired);
    }
    let fence = state
        .fence
        .as_ref()
        .ok_or(AdapterError::MigrationRequired)?;
    validate_fence_record(fence)?;
    if fence.state_fence != request.state_fence || !is_genesis_fence(&fence.state_fence) {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    for record in state.owners.iter().chain(state.jobs.iter()) {
        record.validate()?;
        if record.state_fence != request.state_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
    }
    for receipt in &state.receipts {
        receipt.validate()?;
        if receipt.state_fence != request.state_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
    }
    Ok(())
}

pub(super) fn validate_fresh_genesis_state(state: &GenesisState) -> Result<(), AdapterError> {
    let fence = state
        .fence
        .as_ref()
        .ok_or(AdapterError::MigrationRequired)?;
    if fence.next_commit_sequence != 1 || fence.next_outbox_sequence != 1 {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if !genesis_state_is_absent(state) {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(())
}

pub(super) fn validate_replayed_genesis_state(
    state: &GenesisState,
    request: &StoreGenesisRequest,
) -> Result<(), AdapterError> {
    let fence = state
        .fence
        .as_ref()
        .ok_or(AdapterError::MigrationRequired)?;
    if fence.next_commit_sequence != 2 || fence.next_outbox_sequence != 1 {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if state.receipts.len() != 1
        || !state.jobs.is_empty()
        || !state.revision_heads.is_empty()
        || !state.ordering_heads.is_empty()
        || !state.events.is_empty()
        || !state.projections.is_empty()
        || !state.outbox.is_empty()
        || !state.relations.is_empty()
        || sorted_recovery_records(&state.owners) != sorted_recovery_records(&request.owner_records)
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(())
}

fn genesis_state_is_absent(state: &GenesisState) -> bool {
    state.owners.is_empty()
        && state.jobs.is_empty()
        && state.receipts.is_empty()
        && state.revision_heads.is_empty()
        && state.ordering_heads.is_empty()
        && state.events.is_empty()
        && state.projections.is_empty()
        && state.outbox.is_empty()
        && state.relations.is_empty()
}

fn sorted_recovery_records(records: &[RecoveryRecord]) -> Vec<RecoveryRecord> {
    let mut sorted = records.to_vec();
    sorted.sort_by_key(RecoveryRecord::record_key);
    sorted
}

pub(super) fn build_genesis_sql(owner_count: usize) -> String {
    let mut sql = format!(
        "{} {} {}",
        schema::TX_GENESIS_BEGIN,
        schema::TX_GENESIS_SCHEMA_GUARD,
        schema::TX_GENESIS_EMPTY_GUARD
    );
    for index in 0..owner_count {
        sql.push_str(&schema::indexed(schema::TX_GENESIS_CREATE_OWNER, index));
    }
    sql.push_str(schema::TX_GENESIS_FENCE_CAS);
    sql.push_str(schema::TX_GENESIS_CREATE_RECEIPT);
    sql.push_str(schema::TX_GENESIS_COMMIT);
    sql
}

fn recovery_owner_id(key: &RecoveryRecordKey) -> Result<String, AdapterError> {
    let bytes = eliot_store_api::canonical_json_bytes(key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(eliot_store_api::sha256_hex(&bytes))
}

pub(super) fn build_genesis_bindings(
    config: &SurrealAdapterConfig,
    request: &StoreGenesisRequest,
    receipt: &WriteReceipt,
) -> Result<Map<String, Value>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "expected_generation".to_owned(),
        json!(config.expected_schema_generation.as_str()),
    );
    bindings.insert(
        "expected_state_fence".to_owned(),
        json!(request.state_fence),
    );
    bindings.insert(
        "fence_table".to_owned(),
        json!(schema::table::CANONICAL_FENCE),
    );
    bindings.insert("fence_key".to_owned(), json!(schema::FENCE_KEY));
    bindings.insert(
        "fence".to_owned(),
        json!({
            "state_fence": request.state_fence,
            "next_commit_sequence": 2_u64,
            "next_outbox_sequence": 1_u64,
        }),
    );
    bindings.insert(
        "receipt_table".to_owned(),
        json!(schema::table::WRITE_RECEIPT),
    );
    bindings.insert(
        "receipt_operation_id".to_owned(),
        json!(request.operation_id.to_string()),
    );
    bindings.insert(
        "receipt".to_owned(),
        json!({
            "operation_id": receipt.operation_id.to_string(),
            "idempotency_key": receipt.idempotency_key,
            "body": receipt,
        }),
    );
    for (index, owner) in request.owner_records.iter().enumerate() {
        let suffix = index.to_string();
        bindings.insert(
            format!("owner_table{suffix}"),
            json!(schema::table::RECOVERY_OWNER),
        );
        bindings.insert(
            format!("owner_id{suffix}"),
            json!(recovery_owner_id(&owner.record_key())?),
        );
        bindings.insert(format!("owner{suffix}"), json!(owner));
    }
    Ok(bindings)
}

pub(super) fn genesis_receipt(
    context: &RequestMeta,
    request: &StoreGenesisRequest,
    commit_sequence: u64,
) -> Result<WriteReceipt, AdapterError> {
    let manifest = genesis_manifest()?;
    let mut receipt = WriteReceipt {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        canonical_request_hash: request.canonical_request_hash.clone(),
        transition_class: TransitionClass::RecoverySchema,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-genesis")?),
        state_fence: request.state_fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["genesis-seed".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: manifest.digest,
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some(format!("commit-sequence-{commit_sequence:016}")),
        envelope: None,
    };
    receipt.envelope = Some(issue_genesis_receipt_envelope(
        context,
        request,
        &receipt,
        commit_sequence,
    )?);
    receipt.validate()?;
    Ok(receipt)
}

async fn reconcile_genesis_receipt(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    context: &RequestMeta,
    request: &StoreGenesisRequest,
) -> Result<WriteReceipt, AdapterError> {
    let Ok(Some(receipt)) = read_receipt_by_operation(db, config, &request.operation_id).await
    else {
        return Err(AdapterError::Store(StoreError::MissingReceiptEnvelope));
    };
    if receipt.idempotency_key != request.idempotency_key
        || receipt.canonical_request_hash != request.canonical_request_hash
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    validate_genesis_receipt_envelope(context, request, &receipt)
        .map_err(|_| AdapterError::Store(StoreError::MissingReceiptEnvelope))?;
    Ok(receipt)
}

pub(crate) async fn initialize_genesis(
    adapter: &SurrealStoreAdapter,
    context: &RequestMeta,
    request: StoreGenesisRequest,
) -> Result<WriteReceipt, AdapterError> {
    request.validate_for_context(context)?;
    let db = super::client(adapter).await?;
    let _guard = adapter.write_lock.lock().await;
    let state = read_genesis_state(db, &adapter.config).await?;
    validate_genesis_schema_fence(&state, &adapter.config, &request)?;

    if let Some(receipt) = state
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == request.operation_id)
    {
        if receipt.idempotency_key != request.idempotency_key
            || receipt.canonical_request_hash != request.canonical_request_hash
        {
            return Err(AdapterError::Store(StoreError::IdentityConflict));
        }
        validate_replayed_genesis_state(&state, &request)?;
        validate_genesis_receipt_envelope(context, &request, receipt)?;
        return Ok(receipt.clone());
    }
    if state
        .receipts
        .iter()
        .any(|receipt| receipt.idempotency_key == request.idempotency_key)
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    validate_fresh_genesis_state(&state)?;

    let receipt = genesis_receipt(context, &request, 1)?;
    let sql = build_genesis_sql(request.owner_records.len());
    let bindings = build_genesis_bindings(&adapter.config, &request, &receipt)?;
    let Ok(mut response) =
        client::query(db, &adapter.config, "genesis.initialize", &sql, bindings).await
    else {
        return reconcile_genesis_receipt(db, &adapter.config, context, &request).await;
    };
    if !response.take_errors().is_empty() {
        return reconcile_genesis_receipt(db, &adapter.config, context, &request).await;
    }
    reconcile_genesis_receipt(db, &adapter.config, context, &request).await
}
