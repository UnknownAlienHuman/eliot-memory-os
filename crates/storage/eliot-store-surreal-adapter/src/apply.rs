//! Database-backed store operations: atomic apply, reconciliation reads,
//! named reads, health and migration.
//!
//! All SurrealQL and physical table access stays inside this module and
//! [`crate::schema`]. The public boundary only ever carries store-API types.

use std::collections::BTreeSet;

use crate::SurrealStoreAdapter;
use crate::config::{SchemaGeneration, SurrealAdapterConfig};
use crate::error::AdapterError;
use crate::health::{AdapterAvailability, AdapterHealth, ProviderHealth};
use crate::plan::{
    self, ApplyPlan, build_receipt, validate_receipt_identity, validate_revision_heads,
};
use crate::readiness::{CompiledMigration, MigrationReceipt, SemanticReadiness};
use crate::{client, schema};
use eliot_store_api::{
    CONTRACT_VERSION, NamedReadOperation, NamedReadRequest, NamedReadResponse, OperationId,
    OrderingHead, OrderingHeadExpectation, OrderingScopeId, RevisionHead, RevisionHeadExpectation,
    RevisionKey, ScopeId, ScopeRevisionView, StateFence, StoreError, StoreHealth,
    StoreHealthStatus, WriteReceipt,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

/// The durable canonical fence singleton.
#[derive(Debug, Serialize, serde::Deserialize)]
struct FenceRecord {
    state_fence: StateFence,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
}

#[derive(Debug, Serialize, serde::Deserialize)]
struct SchemaMetaRecord {
    generation: String,
    migration_state: String,
}

enum Idempotency {
    None,
    Replay(WriteReceipt),
    Conflict,
}

fn take_optional<T>(
    response: &mut client::RpcResults,
    index: usize,
) -> Result<Option<T>, AdapterError>
where
    T: DeserializeOwned,
{
    response.take::<Option<T>>(index)
}

fn take_vec<T>(response: &mut client::RpcResults, index: usize) -> Result<Vec<T>, AdapterError>
where
    T: DeserializeOwned,
{
    response.take::<Vec<T>>(index)
}

/// Returns a connected client, connecting lazily on first use.
pub(crate) async fn client(
    adapter: &SurrealStoreAdapter,
) -> Result<&client::RpcTransport, AdapterError> {
    if let Some(db) = adapter.client.get() {
        return Ok(db);
    }
    let transport = client::RpcTransport::connect(&adapter.config).await?;
    if adapter.client.set(transport).is_err() {
        return adapter
            .client
            .get()
            .ok_or(AdapterError::ProviderUnavailable);
    }
    adapter
        .client
        .get()
        .ok_or(AdapterError::ProviderUnavailable)
}

/// Reads the recorded schema generation, if any.
pub(crate) async fn probe_generation(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Option<String>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.schema_generation",
        schema::READ_SCHEMA_GENERATION,
        Map::new(),
    )
    .await?;
    let record = take_optional::<SchemaMetaRecord>(&mut response, 0)?;
    Ok(record
        .filter(|record| record.migration_state == "APPLIED")
        .map(|record| record.generation))
}

/// Observes the semantic readiness of the database against the configured
/// schema generation.
pub(crate) async fn probe_readiness(
    adapter: &SurrealStoreAdapter,
) -> Result<SemanticReadiness, AdapterError> {
    let db = client(adapter).await?;
    let observed = probe_generation(&db, &adapter.config).await?;
    Ok(readiness_from_observation(
        observed,
        &adapter.config.expected_schema_generation,
    ))
}

fn readiness_from_observation(
    observed: Option<String>,
    expected: &SchemaGeneration,
) -> SemanticReadiness {
    match observed {
        Some(generation) if generation == expected.as_str() => SemanticReadiness::Ready {
            generation: expected.clone(),
        },
        Some(generation) => SemanticReadiness::MigrationRequired {
            expected: expected.clone(),
            observed: Some(generation),
        },
        None => SemanticReadiness::MigrationRequired {
            expected: expected.clone(),
            observed: None,
        },
    }
}

/// Fails unless the database is migrated to the expected schema generation.
pub(crate) async fn ensure_ready(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
) -> Result<(), AdapterError> {
    let observed = probe_generation(db, &adapter.config).await?;
    match readiness_from_observation(observed, &adapter.config.expected_schema_generation) {
        SemanticReadiness::Ready { .. } => Ok(()),
        SemanticReadiness::MigrationRequired { .. } | SemanticReadiness::Unavailable => {
            Err(AdapterError::MigrationRequired)
        }
    }
}

/// Applies one explicit migration and records the new schema generation.
pub(crate) async fn apply_migration(
    adapter: &SurrealStoreAdapter,
    migration: &CompiledMigration,
    observed_clock: &eliot_platform::ClockObservation,
) -> Result<MigrationReceipt, AdapterError> {
    let db = client(adapter).await?;
    migration
        .validate()
        .map_err(|reason| AdapterError::Config(reason.to_owned()))?;
    if migration.statements.trim() != schema::SCHEMA_DDL.trim() {
        return Err(AdapterError::Config(
            "migration plan is not admitted by the S-03 schema compiler".to_owned(),
        ));
    }
    observed_clock
        .validate()
        .map_err(|error| AdapterError::Config(error.to_string()))?;
    let _guard = adapter.write_lock.lock().await;
    let updated_at = observed_clock
        .known_time_ms
        .or(observed_clock.valid_time_ms)
        .ok_or_else(|| {
            AdapterError::Config(
                "migration requires an observed P-01 wall-clock timestamp".to_owned(),
            )
        })?;
    let statements = migration.statements.trim();
    let sql = format!(
        "{} {} {} {}",
        schema::TX_BEGIN,
        statements,
        schema::TX_UPSERT_SCHEMA_META,
        schema::TX_COMMIT,
    );
    let record = json!({
        "generation": migration.generation_after.as_str(),
        "migration_state": "APPLIED",
        "migration_id": migration.migration_id,
        "migration_checksum_sha256": migration.checksum_sha256,
        "compatible_bridge_range": crate::ADAPTER_NAME,
        "updated_at": updated_at.to_string(),
    });
    let mut bindings = Map::new();
    bindings.insert(
        "schema_meta_table".to_owned(),
        json!(schema::table::SCHEMA_META),
    );
    bindings.insert("schema_meta_key".to_owned(), json!(schema::SCHEMA_META_KEY));
    bindings.insert("schema_meta_record".to_owned(), record);
    let mut response =
        client::query(&db, &adapter.config, "migration.apply", &sql, bindings).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::UnknownMigrationOutcome {
            migration_id: migration.migration_id.clone(),
        });
    }
    Ok(MigrationReceipt {
        migration_id: migration.migration_id.clone(),
        checksum_sha256: migration.checksum_sha256.clone(),
        generation_after: migration.generation_after.clone(),
    })
}

/// Bounded bridge health observation; never a semantic readiness verdict.
pub(crate) async fn adapter_health(adapter: &SurrealStoreAdapter) -> AdapterHealth {
    let db = match client(adapter).await {
        Ok(db) => db,
        Err(_) => return AdapterHealth::unprobed(),
    };
    match probe_generation(&db, &adapter.config).await {
        Ok(Some(generation))
            if generation == adapter.config.expected_schema_generation.as_str() =>
        {
            AdapterHealth {
                protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
                availability: AdapterAvailability::Available,
                provider: ProviderHealth::Reachable,
                schema_generation: Some(generation),
            }
        }
        Ok(Some(generation)) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::MigrationUnavailable,
            provider: ProviderHealth::Reachable,
            schema_generation: Some(generation),
        },
        Ok(None) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::MigrationUnavailable,
            provider: ProviderHealth::Reachable,
            schema_generation: None,
        },
        Err(_) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::ProviderUnavailable,
            provider: ProviderHealth::Unavailable,
            schema_generation: None,
        },
    }
}

/// Atomically applies one exact S-01 transition and returns its immutable receipt.
/// Projection publications and outbox intents are derived by the shared
/// transition planner, matching the in-memory reference implementation.
pub(crate) async fn apply_prepared(
    adapter: &SurrealStoreAdapter,
    ctx: &eliot_store_api::RequestMeta,
    transition: eliot_store_api::PreparedTransition,
    expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
    expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
) -> Result<WriteReceipt, AdapterError> {
    validate_transition(adapter, ctx, &transition)?;

    let db = client(adapter).await?;
    ensure_ready(adapter, &db).await?;

    let _guard = adapter.write_lock.lock().await;

    match read_idempotency(&db, &adapter.config, &transition).await? {
        Idempotency::Replay(receipt) => {
            validate_receipt_identity(&receipt, ctx, &transition)?;
            return Ok(receipt);
        }
        Idempotency::Conflict => return Err(AdapterError::Store(StoreError::IdentityConflict)),
        Idempotency::None => {}
    }

    let fence = read_fence(&db, &adapter.config).await?;
    if let Some(fence) = &fence
        && fence.state_fence != transition.state_fence
    {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let next_commit_sequence = fence.as_ref().map_or(1, |fence| fence.next_commit_sequence);
    let next_outbox_sequence = fence.as_ref().map_or(1, |fence| fence.next_outbox_sequence);

    let revision_keys = union_revision_keys(&expected_revision_heads, &transition);
    let ordering_scopes = union_ordering_scopes(&expected_ordering_heads, &transition);
    let current_revisions = read_revision_heads_inner(&db, &adapter.config, &revision_keys).await?;
    let current_orderings =
        read_ordering_heads_inner(&db, &adapter.config, &ordering_scopes).await?;

    check_expected_revisions(
        &current_revisions,
        &expected_revision_heads,
        &transition.state_fence,
    )?;
    check_expected_orderings(
        &current_orderings,
        &expected_ordering_heads,
        &transition.state_fence,
    )?;

    let plan = plan::plan_apply(
        &transition,
        &current_revisions,
        &current_orderings,
        next_commit_sequence,
        next_outbox_sequence,
    )?;
    let receipt = build_receipt(&transition, &plan)?;

    write_transaction(
        &db,
        &adapter.config,
        &transition,
        &plan,
        &receipt,
        fence.is_none(),
        fence.as_ref().map_or(1, |value| value.next_commit_sequence),
        fence.as_ref().map_or(1, |value| value.next_outbox_sequence),
    )
    .await?;

    validate_receipt_identity(&receipt, ctx, &transition)?;
    Ok(receipt)
}

fn validate_transition(
    adapter: &SurrealStoreAdapter,
    ctx: &eliot_store_api::RequestMeta,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    ctx.validate().map_err(StoreError::Foundation)?;
    transition.validate()?;
    transition.validate_against_manifest(&adapter.operation_manifest)?;
    if ctx.state_fence != transition.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    Ok(())
}

/// Resolves a durable receipt by operation identity; the reconciliation read.
pub(crate) async fn read_receipt(
    adapter: &SurrealStoreAdapter,
    operation_id: OperationId,
) -> Result<Option<WriteReceipt>, AdapterError> {
    let db = client(adapter).await?;
    ensure_ready(adapter, &db).await?;
    read_receipt_by_operation(&db, &adapter.config, &operation_id).await
}

async fn read_receipt_by_operation(
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
    }
    Ok(receipt)
}

async fn read_idempotency(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
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
            Ok(Idempotency::Replay(receipt))
        } else {
            Ok(Idempotency::Conflict)
        };
    }
    Ok(Idempotency::None)
}

async fn read_fence(
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

/// Reads revision heads for the requested keys, deduplicated and validated.
pub(crate) async fn read_revision_heads(
    adapter: &SurrealStoreAdapter,
    keys: Vec<RevisionKey>,
) -> Result<Vec<RevisionHead>, AdapterError> {
    ensure_unique_revision_keys(&keys)?;
    let db = client(adapter).await?;
    ensure_ready(adapter, &db).await?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut bindings = Map::new();
    bindings.insert(
        "keys".to_owned(),
        to_value(&keys.iter().map(ToString::to_string).collect::<Vec<_>>())?,
    );
    let mut response = client::query(
        &db,
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

/// Reads ordering heads for the requested scopes, deduplicated and validated.
pub(crate) async fn read_ordering_heads(
    adapter: &SurrealStoreAdapter,
    scopes: Vec<OrderingScopeId>,
) -> Result<Vec<OrderingHead>, AdapterError> {
    ensure_unique_ordering_scopes(&scopes)?;
    let db = client(adapter).await?;
    ensure_ready(adapter, &db).await?;
    if scopes.is_empty() {
        return Ok(Vec::new());
    }
    let mut bindings = Map::new();
    bindings.insert(
        "scopes".to_owned(),
        to_value(&scopes.iter().map(ToString::to_string).collect::<Vec<_>>())?,
    );
    let mut response = client::query(
        &db,
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

/// Reads the rebuildable scope revision view.
pub(crate) async fn read_scope_view(
    adapter: &SurrealStoreAdapter,
    scope_id: ScopeId,
) -> Result<ScopeRevisionView, AdapterError> {
    let db = client(adapter).await?;
    ensure_ready(adapter, &db).await?;
    let fence = read_fence(&db, &adapter.config).await?;
    let state_fence = fence.ok_or(StoreError::ReceiptNotFound)?.state_fence;
    let revision_heads = read_revision_heads_inner(
        &db,
        &adapter.config,
        &[RevisionKey::new(format!("scope:{scope_id}"))?],
    )
    .await?;
    let ordering_heads = read_ordering_heads_inner(
        &db,
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

/// Executes one closed named read and returns a validated response.
pub(crate) async fn execute_named(
    adapter: &SurrealStoreAdapter,
    query: NamedReadRequest,
) -> Result<NamedReadResponse, AdapterError> {
    query.validate()?;
    let db = client(adapter).await?;
    ensure_ready(adapter, &db).await?;

    let fence = read_fence(&db, &adapter.config).await?;
    let state_fence = match &fence {
        Some(fence) => fence.state_fence.clone(),
        None => query.state_fence.clone(),
    };
    if fence.is_some() && state_fence != query.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }

    let revision_heads = read_all_revision_heads(&db, &adapter.config).await?;
    let payload = named_read_payload(adapter, &db, &query).await?;
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

/// Maps the bridge availability to the bounded store health status.
pub(crate) async fn health(adapter: &SurrealStoreAdapter) -> Result<StoreHealth, StoreError> {
    let health = adapter_health(adapter).await;
    let status = match health.availability {
        AdapterAvailability::Available => StoreHealthStatus::Ready,
        AdapterAvailability::MigrationUnavailable | AdapterAvailability::ProviderUnavailable => {
            StoreHealthStatus::Unavailable
        }
        AdapterAvailability::Unavailable => StoreHealthStatus::Degraded,
    };
    let digest = adapter.operation_manifest.digest.clone();
    Ok(StoreHealth {
        status,
        contract_version: CONTRACT_VERSION,
        manifest_digest: digest,
    })
}

/// Persists one fully planned transaction atomically.
async fn write_transaction(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
    plan: &ApplyPlan,
    receipt: &WriteReceipt,
    initial_state: bool,
    expected_commit_sequence: u64,
    expected_outbox_sequence: u64,
) -> Result<(), AdapterError> {
    let operation_id = transition.identity.operation_id.to_string();
    let mut sql = String::from(schema::TX_BEGIN);
    let mut bindings = Map::new();

    sql.push_str(if initial_state {
        schema::TX_CREATE_FENCE
    } else {
        schema::TX_UPSERT_FENCE
    });
    bindings.insert(
        "fence_table".to_owned(),
        json!(schema::table::CANONICAL_FENCE),
    );
    bindings.insert("fence_key".to_owned(), json!(schema::FENCE_KEY));
    bindings.insert(
        "fence".to_owned(),
        json!({
            "state_fence": transition.state_fence,
            "next_commit_sequence": plan.next_commit_sequence,
            "next_outbox_sequence": plan.next_outbox_sequence,
        }),
    );
    bindings.insert(
        "expected_state_fence".to_owned(),
        json!(transition.state_fence),
    );
    bindings.insert(
        "expected_commit_sequence".to_owned(),
        json!(expected_commit_sequence),
    );
    bindings.insert(
        "expected_outbox_sequence".to_owned(),
        json!(expected_outbox_sequence),
    );

    sql.push_str(if initial_state {
        schema::TX_CREATE_REVISION
    } else {
        schema::TX_UPSERT_REVISION
    });
    bindings.insert(
        "revision_table".to_owned(),
        json!(schema::table::REVISION_HEAD),
    );
    let revision = plan
        .next_revision_heads
        .first()
        .expect("a prepared transition always advances one revision key");
    bindings.insert("revision_key".to_owned(), json!(revision.key.to_string()));
    bindings.insert(
        "revision_record".to_owned(),
        json!({
            "revision_key": revision.key.to_string(),
            "body": to_value(revision)?,
        }),
    );
    bindings.insert(
        "expected_revision".to_owned(),
        json!(
            plan.revision_before_after
                .first()
                .map_or(1, |delta| delta.before)
        ),
    );

    for (index, head) in plan.next_ordering_heads.iter().enumerate() {
        let template = if initial_state {
            schema::TX_CREATE_ORDERING
        } else {
            schema::TX_UPSERT_ORDERING
        };
        sql.push_str(&schema::indexed(template, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("ordering_table{suffix}"),
            json!(schema::table::ORDERING_HEAD),
        );
        bindings.insert(
            format!("ordering_scope{suffix}"),
            json!(head.scope.to_string()),
        );
        bindings.insert(
            format!("ordering_record{suffix}"),
            json!({
                "ordering_scope": head.scope.to_string(),
                "body": to_value(head)?,
            }),
        );
        bindings.insert(
            format!("expected_ordering_sequence{suffix}"),
            json!(head.sequence.saturating_sub(1)),
        );
    }

    for (index, event_id) in plan.event_ids.iter().enumerate() {
        sql.push_str(&schema::indexed(schema::TX_CREATE_EVENT, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("event_table{suffix}"),
            json!(schema::table::CANONICAL_EVENT),
        );
        bindings.insert(format!("event_id{suffix}"), json!(event_id.to_string()));
        bindings.insert(
            format!("event{suffix}"),
            json!({
                "event_id": event_id.to_string(),
                "operation_id": operation_id,
            }),
        );
    }

    for (index, projection) in plan.projection_records.iter().enumerate() {
        sql.push_str(&schema::indexed(schema::TX_CREATE_PROJECTION, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("projection_table{suffix}"),
            json!(schema::table::PROJECTION_RECORD),
        );
        bindings.insert(
            format!("publication_id{suffix}"),
            json!(projection.publication_id.to_string()),
        );
        bindings.insert(
            format!("projection{suffix}"),
            json!({
                "publication_id": projection.publication_id.to_string(),
                "body": to_value(projection)?,
            }),
        );
    }

    for (index, relation_kind) in transition
        .event_projection_relation_intents
        .relation_kinds
        .iter()
        .enumerate()
    {
        sql.push_str(&schema::indexed(schema::TX_CREATE_RELATION, index));
        let suffix = index.to_string();
        let relation_id = format!("relation-{operation_id}-{index}");
        bindings.insert(
            format!("relation_table{suffix}"),
            json!(schema::table::RELATION_RECORD),
        );
        bindings.insert(format!("relation_id{suffix}"), json!(&relation_id));
        bindings.insert(
            format!("relation{suffix}"),
            json!({
                "relation_id": relation_id,
                "relation_kind": relation_kind,
                "operation_id": operation_id,
                "state_fence": transition.state_fence,
            }),
        );
    }

    for (index, outbox) in plan.outbox_records.iter().enumerate() {
        sql.push_str(&schema::indexed(schema::TX_CREATE_OUTBOX, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("outbox_table{suffix}"),
            json!(schema::table::OUTBOX_EVENT),
        );
        bindings.insert(
            format!("outbox_id{suffix}"),
            json!(outbox.outbox_id.to_string()),
        );
        bindings.insert(
            format!("outbox{suffix}"),
            json!({
                "outbox_id": outbox.outbox_id.to_string(),
                "operation_id": operation_id,
                "sequence": outbox.sequence,
                "body": to_value(outbox)?,
            }),
        );
    }

    sql.push_str(schema::TX_CREATE_RECEIPT);
    bindings.insert(
        "receipt_table".to_owned(),
        json!(schema::table::WRITE_RECEIPT),
    );
    bindings.insert("receipt_operation_id".to_owned(), json!(operation_id));
    bindings.insert(
        "receipt".to_owned(),
        json!({
            "operation_id": receipt.operation_id.to_string(),
            "idempotency_key": receipt.idempotency_key,
            "body": to_value(receipt)?,
        }),
    );

    sql.push_str(schema::TX_COMMIT);

    let mut response = match client::query(db, config, "transaction.apply", &sql, bindings).await {
        Ok(response) => response,
        Err(AdapterError::ProviderUnavailable) => {
            return Err(AdapterError::UnknownOutcome { operation_id });
        }
        Err(error) => return Err(error),
    };
    if !response.take_errors().is_empty() {
        return Err(AdapterError::UnknownOutcome { operation_id });
    }
    // The first statement is the provider-side fence CAS/create.  A matched
    // zero-row update is a deterministic conflict, not a successful write;
    // never let a stale pre-read turn into a second commit.
    let cas_result = response
        .take::<Vec<Value>>(0)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    if cas_result.is_empty() {
        return Err(AdapterError::ProviderConflict);
    }
    Ok(())
}

async fn read_revision_heads_inner(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    keys: &[RevisionKey],
) -> Result<Vec<RevisionHead>, AdapterError> {
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
        config,
        "read.revision_heads_inner",
        schema::READ_REVISION_HEADS_BY_KEYS,
        bindings,
    )
    .await?;
    let heads = take_vec::<RevisionHead>(&mut response, 0)?;
    validate_revision_heads(&heads)?;
    Ok(heads)
}

async fn read_ordering_heads_inner(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    scopes: &[OrderingScopeId],
) -> Result<Vec<OrderingHead>, AdapterError> {
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
        config,
        "read.ordering_heads_inner",
        schema::READ_ORDERING_HEADS_BY_SCOPES,
        bindings,
    )
    .await?;
    let heads = take_vec::<OrderingHead>(&mut response, 0)?;
    plan::validate_ordering_heads(&heads)?;
    Ok(heads)
}

fn union_revision_keys(
    expected: &[RevisionHeadExpectation],
    transition: &eliot_store_api::PreparedTransition,
) -> Vec<RevisionKey> {
    let mut keys = BTreeSet::new();
    for head in expected {
        keys.insert(head.key.clone());
    }
    if let Ok(key) = RevisionKey::new(format!("scope:{}", transition.scope_id)) {
        keys.insert(key);
    }
    keys.into_iter().collect()
}

fn union_ordering_scopes(
    expected: &[OrderingHeadExpectation],
    transition: &eliot_store_api::PreparedTransition,
) -> Vec<OrderingScopeId> {
    let mut scopes = BTreeSet::new();
    for head in expected {
        scopes.insert(head.scope.clone());
    }
    scopes.extend(transition.ordering_scopes.iter().cloned());
    scopes.into_iter().collect()
}

fn check_expected_revisions(
    current: &[RevisionHead],
    expected: &[RevisionHeadExpectation],
    fence: &StateFence,
) -> Result<(), AdapterError> {
    let mut seen = BTreeSet::new();
    for item in expected {
        item.validate()?;
        if !seen.insert(item.key.clone()) {
            return Err(AdapterError::Store(StoreError::Duplicate {
                field: "revision_keys",
            }));
        }
        match current.iter().find(|head| head.key == item.key) {
            Some(head) if head.state_fence != *fence => {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
            Some(head) if head.revision != item.expected_revision => {
                return Err(AdapterError::Store(StoreError::RevisionConflict));
            }
            None if item.expected_revision != 1 => {
                return Err(AdapterError::Store(StoreError::RevisionConflict));
            }
            _ => {}
        }
    }
    Ok(())
}

fn check_expected_orderings(
    current: &[OrderingHead],
    expected: &[OrderingHeadExpectation],
    fence: &StateFence,
) -> Result<(), AdapterError> {
    let mut seen = BTreeSet::new();
    for item in expected {
        item.validate()?;
        if !seen.insert(item.scope.clone()) {
            return Err(AdapterError::Store(StoreError::Duplicate {
                field: "ordering_scopes",
            }));
        }
        match current.iter().find(|head| head.scope == item.scope) {
            Some(head) if head.state_fence != *fence => {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
            Some(head) if head.sequence != item.expected_sequence => {
                return Err(AdapterError::Store(StoreError::OrderingConflict));
            }
            None if item.expected_sequence != 1 => {
                return Err(AdapterError::Store(StoreError::OrderingConflict));
            }
            _ => {}
        }
    }
    Ok(())
}

fn ensure_unique_revision_keys(keys: &[RevisionKey]) -> Result<(), AdapterError> {
    let mut seen = BTreeSet::new();
    if keys.iter().any(|key| !seen.insert(key.clone())) {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "revision_keys",
        }));
    }
    Ok(())
}

fn ensure_unique_ordering_scopes(scopes: &[OrderingScopeId]) -> Result<(), AdapterError> {
    let mut seen = BTreeSet::new();
    if scopes.iter().any(|scope| !seen.insert(scope.clone())) {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "ordering_scopes",
        }));
    }
    Ok(())
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, AdapterError> {
    serde_json::to_value(value).map_err(|error| AdapterError::Serialization(error.to_string()))
}
