//! Surreal store recovery application cell.
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Implementation: I5.1, I5.9, I5.22, I2.23 — bounded coherent recovery snapshot via the Surreal bridge.
//! Ownership: bounded physical recovery SQL/binding and snapshot validation/ordering only; no provider lifecycle, genesis bootstrap, empty migration, schema-contract, atomic write, receipt reconciliation/read-boundary, or host-journal ownership beyond this boundary.
//! No lifecycle/canonical authority — this cell never owns daemon lifecycle or kernel canonical state; it only renders the existing committed store state into a validated `StoreRecoverySnapshot` via the store bridge (source: `crates/storage/eliot-store-surreal-adapter/src/apply.rs:646-835`).

use serde_json::{Map, Value, json};

use crate::config::SchemaGeneration;
use crate::error::AdapterError;
use crate::plan;
use crate::plan::validate_revision_heads;
use crate::schema;
use eliot_store_api::{
    CONTRACT_VERSION, OrderingHead, RecoveryRecord, RecoveryRecordKey, RevisionHead, ScopeId,
    ScopeRevisionView, StateFence, StoreError, StoreRecoveryRequest, StoreRecoverySnapshot,
    WriteReceipt,
};

use super::schema_contract::{
    FenceRecord, SchemaMetaRecord, validate_fence_record, validate_schema_meta_record,
};

pub(super) struct RecoverySnapshotInput {
    pub(super) schema: Option<SchemaMetaRecord>,
    pub(super) fence: Option<FenceRecord>,
    pub(super) owner_records: Vec<RecoveryRecord>,
    pub(super) job_records: Vec<RecoveryRecord>,
    pub(super) receipts: Vec<WriteReceipt>,
    pub(super) receipt_authorities: Vec<eliot_store_api::RecoveryReceiptAuthority>,
    pub(super) revision_heads: Vec<RevisionHead>,
    pub(super) ordering_heads: Vec<OrderingHead>,
}

pub(super) fn build_recovery_sql(request: &StoreRecoveryRequest) -> String {
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(schema::READ_SCHEMA_META);
    sql.push_str("SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current;");
    for index in 0..request.records.len() {
        sql.push_str(&schema::indexed(schema::READ_RECOVERY_OWNER_BY_KEY, index));
    }
    if request.include_jobs {
        sql.push_str(schema::READ_ALL_RECOVERY_JOBS);
    }
    if request.include_receipts {
        if request.receipt_authority_operation_ids.is_empty() {
            sql.push_str(schema::READ_ALL_RECEIPTS);
        } else {
            sql.push_str(schema::READ_REQUESTED_RECOVERY_RECEIPTS);
        }
    }
    if !request.receipt_authority_operation_ids.is_empty() {
        sql.push_str(schema::READ_REQUESTED_RECEIPT_AUTHORITIES);
    }
    sql.push_str(schema::READ_ALL_REVISION_HEADS);
    sql.push_str(schema::READ_ALL_ORDERING_HEADS);
    sql.push_str(schema::TX_COMMIT);
    sql
}

pub(super) fn build_recovery_bindings(request: &StoreRecoveryRequest) -> Map<String, Value> {
    let mut bindings = Map::new();
    for (index, key) in request.records.iter().enumerate() {
        let suffix = index.to_string();
        bindings.insert(format!("recovery_namespace{suffix}"), json!(key.namespace));
        bindings.insert(format!("recovery_key{suffix}"), json!(key.key));
    }
    if !request.receipt_authority_operation_ids.is_empty() {
        bindings.insert(
            "recovery_authority_operation_ids".to_owned(),
            json!(request
                .receipt_authority_operation_ids
                .iter()
                .map(|operation_id| operation_id.as_str())
                .collect::<Vec<_>>()),
        );
    }
    bindings
}

pub(super) fn build_recovery_snapshot(
    mut input: RecoverySnapshotInput,
    expected_generation: &SchemaGeneration,
    expected_fence: &StateFence,
    requested_keys: &[RecoveryRecordKey],
    requested_authority_operation_ids: &[eliot_store_api::OperationId],
) -> Result<StoreRecoverySnapshot, AdapterError> {
    let schema = input.schema.take().ok_or(AdapterError::MigrationRequired)?;
    validate_schema_meta_record(&schema)?;
    if schema.generation != expected_generation.as_str() || schema.migration_state != "APPLIED" {
        return Err(AdapterError::MigrationRequired);
    }
    let fence = input.fence.take().ok_or(AdapterError::MigrationRequired)?;
    validate_fence_record(&fence)?;
    if fence.state_fence != *expected_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let mut actual_keys = input
        .owner_records
        .iter()
        .map(RecoveryRecord::record_key)
        .collect::<Vec<_>>();
    actual_keys.sort();
    let mut expected_keys = requested_keys.to_vec();
    expected_keys.sort();
    if actual_keys != expected_keys {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "recovery.records",
            reason: "requested record is missing",
        }));
    }
    for record in input.owner_records.iter().chain(input.job_records.iter()) {
        record.validate()?;
        if record.state_fence != *expected_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
    }
    for receipt in &input.receipts {
        receipt.validate()?;
        if receipt.state_fence != *expected_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
    }
    if !requested_authority_operation_ids.is_empty() {
        let mut actual_receipt_ids = input
            .receipts
            .iter()
            .map(|receipt| receipt.operation_id.clone())
            .collect::<Vec<_>>();
        actual_receipt_ids.sort();
        let mut expected_receipt_ids = requested_authority_operation_ids.to_vec();
        expected_receipt_ids.sort();
        if actual_receipt_ids != expected_receipt_ids {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "recovery.receipts",
                reason: "requested receipt is missing or substituted",
            }));
        }
    }
    let mut actual_authority_ids = input
        .receipt_authorities
        .iter()
        .map(|authority| authority.operation_id.clone())
        .collect::<Vec<_>>();
    actual_authority_ids.sort();
    let mut expected_authority_ids = requested_authority_operation_ids.to_vec();
    expected_authority_ids.sort();
    if actual_authority_ids != expected_authority_ids {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "recovery.receipt_authorities",
            reason: "requested operation authority is missing or substituted",
        }));
    }
    validate_revision_heads(&input.revision_heads)?;
    plan::validate_ordering_heads(&input.ordering_heads)?;
    input.owner_records.sort_by_key(RecoveryRecord::record_key);
    input.job_records.sort_by_key(RecoveryRecord::record_key);
    input
        .receipts
        .sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    input
        .receipt_authorities
        .sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    input
        .revision_heads
        .sort_by_key(|head| head.key.to_string());
    input
        .ordering_heads
        .sort_by_key(|head| head.scope.to_string());

    let snapshot = StoreRecoverySnapshot {
        contract_version: CONTRACT_VERSION,
        state_fence: fence.state_fence.clone(),
        validation_revision: fence.next_commit_sequence,
        canonical_scope: ScopeRevisionView {
            scope_id: ScopeId::new("store")?,
            revision_heads: input.revision_heads,
            ordering_heads: input.ordering_heads,
            state_fence: fence.state_fence,
        },
        owner_records: input.owner_records,
        job_records: input.job_records,
        receipts: input.receipts,
        receipt_authorities: input.receipt_authorities,
    };
    snapshot.validate()?;
    Ok(snapshot)
}
