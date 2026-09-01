//! Physical receipt, idempotency and fence reconciliation reads for the Surreal adapter.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Implementation: I5.1, I5.9, I5.19, I5.20, I5.3, I2.23 — R2 storage execution, receipt/read-export and bridge named operations via the Surreal bridge.
//! Ownership: physical receipt/idempotency/fence reconciliation reads only; no semantic policy, transition/write, authority, retry/default or Store-SDK ownership beyond the existing adapter port.

use serde_json::{Map, json};

use crate::SurrealStoreAdapter;
use crate::client;
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::schema;
use eliot_store_api::{OperationId, WriteReceipt, validate_store_receipt_envelope};

use super::{FenceRecord, Idempotency, take_optional, take_vec};

/// Resolves a durable receipt by operation identity; the reconciliation read.
pub(crate) async fn read_receipt(
    adapter: &SurrealStoreAdapter,
    operation_id: OperationId,
) -> Result<Option<WriteReceipt>, AdapterError> {
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    read_receipt_by_operation(db, &adapter.config, &operation_id).await
}

pub(super) async fn read_receipt_by_operation(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    operation_id: &OperationId,
) -> Result<Option<WriteReceipt>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert("table".to_owned(), json!(schema::table::WRITE_RECEIPT));
    bindings.insert("key".to_owned(), json!(operation_id.to_string()));
    let mut response = client::query(
        db,
        config,
        "read.receipt_by_operation",
        schema::READ_RECEIPT_BY_OPERATION,
        bindings,
    )
    .await?;
    let receipt = take_optional::<WriteReceipt>(&mut response, 0)?;
    if let Some(receipt) = &receipt {
        receipt.validate()?;
        receipt.require_reconciliation_envelope()?;
    }
    Ok(receipt)
}

pub(super) async fn read_idempotency(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    ctx: &eliot_store_api::RequestMeta,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<Idempotency, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "operation_id".to_owned(),
        json!(transition.identity.operation_id.to_string()),
    );
    bindings.insert(
        "idempotency_key".to_owned(),
        json!(transition.identity.idempotency_key),
    );
    let mut response = client::query(
        db,
        config,
        "read.receipt_idempotency",
        schema::READ_RECEIPT_IDEMPOTENCY,
        bindings,
    )
    .await?;
    let by_operation = take_vec::<WriteReceipt>(&mut response, 0)?;
    let by_idempotency = take_vec::<WriteReceipt>(&mut response, 1)?;

    if let Some(receipt) = by_operation.into_iter().next() {
        receipt.validate()?;
        return if receipt.idempotency_key == transition.identity.idempotency_key
            && receipt.canonical_request_hash == transition.identity.canonical_request_hash
        {
            validate_store_receipt_envelope(ctx, transition, &receipt)?;
            Ok(Idempotency::Replay(receipt))
        } else {
            Ok(Idempotency::Conflict)
        };
    }
    if let Some(receipt) = by_idempotency.into_iter().next() {
        receipt.validate()?;
        return if receipt.canonical_request_hash == transition.identity.canonical_request_hash
            && receipt.operation_id == transition.identity.operation_id
        {
            validate_store_receipt_envelope(ctx, transition, &receipt)?;
            Ok(Idempotency::Replay(receipt))
        } else {
            Ok(Idempotency::Conflict)
        };
    }
    Ok(Idempotency::None)
}

pub(super) async fn read_fence(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Option<FenceRecord>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.canonical_fence",
        schema::READ_FENCE,
        Map::new(),
    )
    .await?;
    take_optional::<FenceRecord>(&mut response, 0)
}
