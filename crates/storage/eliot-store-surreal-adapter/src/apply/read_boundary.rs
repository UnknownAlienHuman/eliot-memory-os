//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Implementation: I5.1, I5.3, I5.9, I2.2, I2.23.
//! Ownership: bounded physical named-read execution and validation only; no semantic command-catalog, write/transition, authority, policy, retry, or default ownership.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::SurrealStoreAdapter;
use crate::client;
use crate::config::{SchemaGeneration, SurrealAdapterConfig};
use crate::error::AdapterError;
use crate::plan;
use crate::plan::validate_revision_heads;
use crate::schema;
use eliot_store_api::{
    CanonicalValidationSnapshot, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    OperationId, OrderingHead, OrderingScopeId, RevisionHead, RevisionKey, ScopeId,
    ScopeRevisionView, StoreError, generated_operation_manifests,
};

use super::{
    FenceRecord, SchemaMetaRecord, ensure_ready, ensure_unique_ordering_scopes,
    ensure_unique_revision_keys, read_fence, read_ordering_heads_inner, read_receipt_by_operation,
    read_revision_heads_inner, take_schema_meta, take_vec, to_value, validate_fence_record,
    validate_schema_meta_record,
};

pub(super) const READ_VALIDATION_SNAPSHOT: &str = "BEGIN TRANSACTION; SELECT * FROM ONLY schema_meta:current; SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current; SELECT VALUE body FROM revision_head; COMMIT TRANSACTION;";

/// Enforces the active generated catalogue on one named read before dispatch
/// (slice C2, issue #19).
///
/// Only the five activated reads (plus the genesis bootstrap entry, which
/// never arrives through this path) are admitted: catalogue membership, the
/// owner-approved typed parameters, the scope declaration, and the declared
/// input bound are checked here, before any provider I/O. Unknown operations
/// fail with [`StoreError::UnknownOperation`]; extra, control-substitution,
/// or misshapen parameters fail with their existing typed mismatch variants.
/// Nothing is normalized and there is no fallback: every rejection maps to a
/// typed [`StoreFailure`](eliot_store_api::StoreFailure) at the dispatch
/// boundary, never to a generic error.
fn validate_named_against_active_catalogue(query: &NamedReadRequest) -> Result<(), StoreError> {
    let entries = generated_operation_manifests()?;
    query.validate_against_catalogue(&entries)
}

pub(crate) async fn read_validation_snapshot(
    adapter: &SurrealStoreAdapter,
) -> Result<CanonicalValidationSnapshot, AdapterError> {
    let db = super::client(adapter).await?;
    let mut response = client::query(
        db,
        &adapter.config,
        "read.validation_snapshot",
        READ_VALIDATION_SNAPSHOT,
        Map::new(),
    )
    .await?;
    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AdapterError::ProviderUnavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| AdapterError::ProviderUnavailable)?;
    parse_validation_snapshot(
        &mut response,
        &adapter.config.expected_schema_generation,
        observed_at_unix_ms,
    )
}

fn parse_validation_snapshot(
    response: &mut client::RpcResults,
    expected_generation: &SchemaGeneration,
    observed_at_unix_ms: i64,
) -> Result<CanonicalValidationSnapshot, AdapterError> {
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let schema = take_schema_meta(response, 1)?.ok_or(AdapterError::MigrationRequired)?;
    validate_schema_meta_record(&schema)?;
    if schema.migration_state != "APPLIED" || schema.generation != expected_generation.as_str() {
        return Err(AdapterError::MigrationRequired);
    }
    let fence = response
        .take::<Option<FenceRecord>>(2)?
        .ok_or(StoreError::Unavailable)?;
    validate_fence_record(&fence)?;
    let revision_heads = response.take::<Vec<RevisionHead>>(3)?;
    let commit_result = response.take::<Value>(4)?;
    build_validation_snapshot(
        Some(schema),
        Some(fence),
        revision_heads,
        expected_generation,
        observed_at_unix_ms,
        commit_result,
    )
}

pub(super) fn build_validation_snapshot(
    schema: Option<SchemaMetaRecord>,
    fence: Option<FenceRecord>,
    revision_heads: Vec<RevisionHead>,
    expected_generation: &SchemaGeneration,
    observed_at_unix_ms: i64,
    _commit_result: Value,
) -> Result<CanonicalValidationSnapshot, AdapterError> {
    let schema = schema.ok_or(AdapterError::MigrationRequired)?;
    validate_schema_meta_record(&schema)?;
    if schema.migration_state != "APPLIED" || schema.generation != expected_generation.as_str() {
        return Err(AdapterError::MigrationRequired);
    }
    let fence = fence.ok_or(StoreError::Unavailable)?;
    validate_fence_record(&fence)?;
    let snapshot = CanonicalValidationSnapshot {
        state_fence: fence.state_fence,
        revision_heads,
        validation_revision: fence.next_commit_sequence,
        observed_at_unix_ms,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

pub(crate) async fn read_revision_heads(
    adapter: &SurrealStoreAdapter,
    keys: Vec<RevisionKey>,
) -> Result<Vec<RevisionHead>, AdapterError> {
    ensure_unique_revision_keys(&keys)?;
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut bindings = Map::new();
    bindings.insert(
        "keys".to_owned(),
        to_value(&keys.iter().map(ToString::to_string).collect::<Vec<_>>())?,
    );
    let mut response = client::query(
        db,
        &adapter.config,
        "read.revision_heads",
        schema::READ_REVISION_HEADS_BY_KEYS,
        bindings,
    )
    .await?;
    let heads = take_vec::<RevisionHead>(&mut response, 0)?;
    validate_revision_heads(&heads)?;
    Ok(heads)
}

pub(crate) async fn read_ordering_heads(
    adapter: &SurrealStoreAdapter,
    scopes: Vec<OrderingScopeId>,
) -> Result<Vec<OrderingHead>, AdapterError> {
    ensure_unique_ordering_scopes(&scopes)?;
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;
    if scopes.is_empty() {
        return Ok(Vec::new());
    }
    let mut bindings = Map::new();
    bindings.insert(
        "scopes".to_owned(),
        to_value(&scopes.iter().map(ToString::to_string).collect::<Vec<_>>())?,
    );
    let mut response = client::query(
        db,
        &adapter.config,
        "read.ordering_heads",
        schema::READ_ORDERING_HEADS_BY_SCOPES,
        bindings,
    )
    .await?;
    let heads = take_vec::<OrderingHead>(&mut response, 0)?;
    plan::validate_ordering_heads(&heads)?;
    Ok(heads)
}

pub(crate) async fn read_scope_view(
    adapter: &SurrealStoreAdapter,
    scope_id: ScopeId,
) -> Result<ScopeRevisionView, AdapterError> {
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;
    let fence = read_fence(db, &adapter.config).await?;
    let state_fence = fence.ok_or(StoreError::ReceiptNotFound)?.state_fence;
    let revision_heads = read_revision_heads_inner(
        db,
        &adapter.config,
        &[RevisionKey::new(format!("scope:{scope_id}"))?],
    )
    .await?;
    let ordering_heads = read_ordering_heads_inner(
        db,
        &adapter.config,
        &[OrderingScopeId::new(scope_id.as_str())?],
    )
    .await?;
    let view = ScopeRevisionView {
        scope_id,
        revision_heads,
        ordering_heads,
        state_fence,
    };
    view.validate()?;
    Ok(view)
}

pub(crate) async fn execute_named(
    adapter: &SurrealStoreAdapter,
    query: NamedReadRequest,
) -> Result<NamedReadResponse, AdapterError> {
    validate_named_against_active_catalogue(&query).map_err(AdapterError::Store)?;
    let db = super::client(adapter).await?;
    ensure_ready(adapter, db).await?;

    let fence = read_fence(db, &adapter.config).await?;
    let state_fence = match &fence {
        Some(fence) => fence.state_fence.clone(),
        None => query.state_fence.clone(),
    };
    if fence.is_some() && state_fence != query.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }

    let revision_heads = read_all_revision_heads(db, &adapter.config).await?;
    let payload = named_read_payload(adapter, db, &query).await?;
    let response = NamedReadResponse {
        operation: query.operation,
        state_fence,
        revision_heads,
        payload,
    };
    response.validate()?;
    Ok(response)
}

async fn named_read_payload(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    query: &NamedReadRequest,
) -> Result<Value, AdapterError> {
    match query.operation {
        NamedReadOperation::GetRevisionHeads => Ok(to_value(
            &read_all_revision_heads(db, &adapter.config).await?,
        )?),
        NamedReadOperation::GetOrderingHeads => Ok(to_value(
            &read_all_ordering_heads(db, &adapter.config).await?,
        )?),
        NamedReadOperation::GetScopeRevisionView => {
            let scope_id = query.scope_id.clone().ok_or(StoreError::InvalidField {
                field: "scope_id",
                reason: "scope revision read requires scope_id",
            })?;
            Ok(to_value(&read_scope_view(adapter, scope_id).await?)?)
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
            let operation_id = OperationId::new(operation_id).map_err(StoreError::Foundation)?;
            Ok(to_value(
                &read_receipt_by_operation(db, &adapter.config, &operation_id).await?,
            )?)
        }
        other => Err(AdapterError::NamedOperationUnavailable {
            operation: format!("{other:?}"),
        }),
    }
}

async fn read_all_revision_heads(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<RevisionHead>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.all_revision_heads",
        schema::READ_ALL_REVISION_HEADS,
        Map::new(),
    )
    .await?;
    let heads = take_vec::<RevisionHead>(&mut response, 0)?;
    validate_revision_heads(&heads)?;
    Ok(heads)
}

async fn read_all_ordering_heads(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Vec<OrderingHead>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.all_ordering_heads",
        schema::READ_ALL_ORDERING_HEADS,
        Map::new(),
    )
    .await?;
    let heads = take_vec::<OrderingHead>(&mut response, 0)?;
    plan::validate_ordering_heads(&heads)?;
    Ok(heads)
}

#[cfg(test)]
mod admitted_read_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_store_api::ReadConsistency;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn test_fence() -> eliot_store_api::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        eliot_store_api::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn read_request(
        operation: NamedReadOperation,
        scope_id: Option<ScopeId>,
        parameters: BTreeMap<String, Value>,
    ) -> NamedReadRequest {
        NamedReadRequest {
            operation,
            scope_id,
            consistency: ReadConsistency::Eventual,
            state_fence: test_fence(),
            parameters,
        }
    }

    #[test]
    fn activated_reads_are_accepted_before_dispatch() {
        for request in [
            read_request(NamedReadOperation::GetRevisionHeads, None, BTreeMap::new()),
            read_request(NamedReadOperation::GetOrderingHeads, None, BTreeMap::new()),
            read_request(
                NamedReadOperation::GetScopeRevisionView,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::new(),
            ),
            read_request(
                NamedReadOperation::ResolveWriteReceipt,
                None,
                BTreeMap::from([("operation_id".to_owned(), json!("op-1"))]),
            ),
            read_request(
                NamedReadOperation::GetEvidencePack,
                Some(ScopeId::new("scope-1").expect("scope")),
                BTreeMap::from([
                    ("subject".to_owned(), json!("observation-1")),
                    ("max_records".to_owned(), json!("10")),
                ]),
            ),
        ] {
            assert!(
                validate_named_against_active_catalogue(&request).is_ok(),
                "activated read must pass the pre-dispatch gate: {:?}",
                request.operation
            );
        }
    }

    #[test]
    fn extra_unknown_and_control_parameters_are_rejected_before_dispatch() {
        // Extra undeclared parameter on an activated read.
        let extra = read_request(
            NamedReadOperation::GetRevisionHeads,
            None,
            BTreeMap::from([("extra".to_owned(), json!(1))]),
        );
        assert!(matches!(
            validate_named_against_active_catalogue(&extra),
            Err(StoreError::InvalidField { .. })
        ));
        // Control-substitution parameter name.
        let control = read_request(
            NamedReadOperation::GetRevisionHeads,
            None,
            BTreeMap::from([("state_fence".to_owned(), json!("x"))]),
        );
        assert!(matches!(
            validate_named_against_active_catalogue(&control),
            Err(StoreError::InvalidField {
                field: "payload.control_field",
                ..
            })
        ));
        // Known-but-unadvertised operation stays unsupported.
        let unadvertised = read_request(NamedReadOperation::GetTaskState, None, BTreeMap::new());
        assert_eq!(
            validate_named_against_active_catalogue(&unadvertised),
            Err(StoreError::UnknownOperation)
        );
        // Missing required typed parameter.
        let missing = read_request(
            NamedReadOperation::ResolveWriteReceipt,
            None,
            BTreeMap::new(),
        );
        assert!(matches!(
            validate_named_against_active_catalogue(&missing),
            Err(StoreError::InvalidField { .. })
        ));
        // Scope declaration mismatch in both directions.
        let stray_scope = read_request(
            NamedReadOperation::GetRevisionHeads,
            Some(ScopeId::new("scope-1").expect("scope")),
            BTreeMap::new(),
        );
        assert!(validate_named_against_active_catalogue(&stray_scope).is_err());
        let missing_scope = read_request(
            NamedReadOperation::GetScopeRevisionView,
            None,
            BTreeMap::new(),
        );
        assert!(validate_named_against_active_catalogue(&missing_scope).is_err());
    }
}
