//! Database-backed store operations: atomic apply, reconciliation reads,
//! named reads, health and migration.
//!
//! All `SurrealQL` and physical table access stays inside this module and
//! [`crate::schema`]. The public boundary only ever carries store-API types.

use std::collections::BTreeSet;

use crate::SurrealStoreAdapter;
use crate::config::{SchemaGeneration, SurrealAdapterConfig};
use crate::error::AdapterError;
use crate::plan::{self, build_receipt, validate_receipt_identity, validate_revision_heads};
use crate::readiness::{CompiledMigration, MigrationReceipt, SemanticReadiness};
use crate::{client, schema};
#[cfg(test)]
use eliot_store_api::{
    CONTRACT_VERSION, OperationId, StoreGenesisRequest, validate_genesis_receipt_envelope,
};
use eliot_store_api::{
    OrderingHead, OrderingHeadExpectation, OrderingScopeId, RecoveryRecord, RevisionHead,
    RevisionHeadExpectation, RevisionKey, StateFence, StoreError, StoreRecoveryRequest,
    StoreRecoverySnapshot, WriteReceipt,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

mod atomic_write;
mod empty_migration;
mod genesis;
#[path = "health_probe.rs"]
mod health_probe;
mod read_boundary;
mod receipt_reconciliation;
mod recovery;
mod schema_contract;
#[cfg(test)]
use atomic_write::{ordering_write_template, revision_write_template};
use atomic_write::{to_value, write_transaction};
use empty_migration::handle_empty_migration;
pub(crate) use genesis::initialize_genesis;
#[cfg(test)]
use genesis::{
    GenesisState, build_genesis_bindings, build_genesis_sql, genesis_receipt,
    validate_fresh_genesis_state, validate_replayed_genesis_state,
};
pub(crate) use health_probe::{adapter_health, health};
#[cfg(test)]
use read_boundary::{READ_VALIDATION_SNAPSHOT, build_validation_snapshot};
pub(crate) use read_boundary::{
    execute_named, read_ordering_heads, read_revision_heads, read_scope_view,
    read_validation_snapshot,
};
pub(crate) use receipt_reconciliation::read_receipt;
use receipt_reconciliation::{read_fence, read_idempotency, read_receipt_by_operation};
use recovery::{
    RecoverySnapshotInput, build_recovery_bindings, build_recovery_snapshot, build_recovery_sql,
};
#[cfg(test)]
use schema_contract::SchemaMigrationIdentity;
#[cfg(test)]
use schema_contract::schema_meta_record;
use schema_contract::{
    FenceRecord, MigrationPreflight, SchemaMetaRecord, schema_meta_record_for_v1_to_v2,
    v1_identity, validate_fence_record, validate_schema_meta_record, validate_v1_pin,
};

fn is_admitted_migration(migration: &CompiledMigration) -> bool {
    if !validate_v1_pin() {
        return false;
    }
    if migration.migration_id == schema::MIGRATION_ID_V1
        && migration.checksum_sha256 == schema::SCHEMA_DDL_V1_SHA256
        && migration.generation_after.as_str() == schema::GENERATION_V1
        && migration.statements.trim() == schema::SCHEMA_DDL.trim()
    {
        return true;
    }
    let v2_full = eliot_store_api::sha256_hex(schema::SCHEMA_DDL_V2.as_bytes());
    if migration.migration_id == schema::MIGRATION_ID_V2
        && migration.checksum_sha256 == v2_full
        && migration.generation_after.as_str() == schema::GENERATION_V2
        && migration.statements.trim() == schema::SCHEMA_DDL_V2.trim()
    {
        return true;
    }
    let v2_delta = eliot_store_api::sha256_hex(schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.as_bytes());
    if migration.migration_id == schema::MIGRATION_ID_V1_TO_V2
        && migration.checksum_sha256 == v2_delta
        && migration.generation_after.as_str() == schema::GENERATION_V2
        && migration.statements.trim() == schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.trim()
    {
        return true;
    }
    false
}

fn is_guard_conflict(error: &str) -> bool {
    error.contains("schema_predecessor_mismatch") || error.contains("schema_fence_guard_mismatch")
}

fn build_forward_sql() -> String {
    schema::forward_migration_sql()
}

fn build_forward_bindings(
    existing: &SchemaMetaRecord,
    fence: &FenceRecord,
    new_record: &SchemaMetaRecord,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("expected_state_fence".to_owned(), json!(fence.state_fence));
    m.insert(
        "expected_commit_sequence".to_owned(),
        json!(fence.next_commit_sequence),
    );
    m.insert(
        "expected_outbox_sequence".to_owned(),
        json!(fence.next_outbox_sequence),
    );
    m.insert("expected_generation".to_owned(), json!(existing.generation));
    m.insert(
        "expected_migration_id".to_owned(),
        json!(existing.migration_id),
    );
    m.insert(
        "expected_migration_checksum_sha256".to_owned(),
        json!(existing.migration_checksum_sha256),
    );
    m.insert(
        "expected_bridge_range".to_owned(),
        json!(existing.compatible_bridge_range),
    );
    m.insert(
        "expected_migration_state".to_owned(),
        json!(existing.migration_state),
    );
    m.insert(
        "expected_migrations_len".to_owned(),
        json!(existing.migrations.len()),
    );
    let first = &existing.migrations[0];
    m.insert(
        "expected_migration_0_id".to_owned(),
        json!(first.migration_id),
    );
    m.insert(
        "expected_migration_0_checksum".to_owned(),
        json!(first.migration_checksum_sha256),
    );
    m.insert(
        "expected_migration_0_generation".to_owned(),
        json!(first.generation),
    );
    m.insert("expected_updated_at".to_owned(), json!(existing.updated_at));
    m.insert(
        "schema_meta_table".to_owned(),
        json!(schema::table::SCHEMA_META),
    );
    m.insert("schema_meta_key".to_owned(), json!(schema::SCHEMA_META_KEY));
    m.insert("schema_meta_record".to_owned(), json!(new_record));
    m
}

fn migration_preflight(
    record: Option<SchemaMetaRecord>,
    migration: &CompiledMigration,
) -> Result<MigrationPreflight, AdapterError> {
    if !is_admitted_migration(migration) {
        return Err(AdapterError::Config(
            "migration plan is not admitted by the S-03 schema compiler".to_owned(),
        ));
    }
    let Some(record) = record else {
        if migration.migration_id == schema::MIGRATION_ID_V2
            && migration.generation_after.as_str() == schema::GENERATION_V2
        {
            return Ok(MigrationPreflight::Empty);
        }
        return Err(AdapterError::Config(
            "empty database admits exactly the v2 initial plan".to_owned(),
        ));
    };
    validate_schema_meta_record(&record)?;
    if record.migration_state != "APPLIED" {
        return Err(AdapterError::PartialOutcome);
    }
    if record.compatible_bridge_range != crate::ADAPTER_NAME {
        return Err(AdapterError::Config(
            "schema metadata belongs to an incompatible adapter".to_owned(),
        ));
    }
    if record.migration_id == migration.migration_id
        && record.migration_checksum_sha256 == migration.checksum_sha256
        && record.generation == migration.generation_after.as_str()
    {
        return Ok(MigrationPreflight::ExactReplay);
    }
    if record.generation == schema::GENERATION_V1
        && record.migration_id == schema::MIGRATION_ID_V1
        && record.migrations.len() == 1
        && migration.migration_id == schema::MIGRATION_ID_V1_TO_V2
        && migration.generation_after.as_str() == schema::GENERATION_V2
    {
        let expected = v1_identity();
        if record.migration_checksum_sha256 != expected.migration_checksum_sha256 {
            return Err(AdapterError::PartialOutcome);
        }
        return Ok(MigrationPreflight::V1ToV2);
    }
    Err(AdapterError::Config(
        "schema migration identity does not match the admitted plan".to_owned(),
    ))
}

fn migration_receipt(migration: &CompiledMigration) -> MigrationReceipt {
    MigrationReceipt {
        migration_id: migration.migration_id.clone(),
        checksum_sha256: migration.checksum_sha256.clone(),
        generation_after: migration.generation_after.clone(),
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "replay carries the complete public receipt; boxing would add indirection to the internal recovery path"
)]
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
    let transport = match adapter
        .client
        .get_or_init(|| async {
            client::RpcTransport::connect(&adapter.config, &adapter.provider_process_lease).await
        })
        .await
    {
        Ok(transport) => transport,
        Err(error) => return Err(error.clone()),
    };
    transport
        .validate_liveness(&adapter.config, &adapter.provider_process_lease)
        .await?;
    Ok(transport)
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
        schema::READ_SCHEMA_META,
        Map::new(),
    )
    .await?;
    let record = take_schema_meta(&mut response, 0)?;
    if let Some(record) = &record {
        validate_schema_meta_record(record)?;
        if record.migration_state != "APPLIED" {
            return Ok(None);
        }
    }
    Ok(record.map(|record| record.generation))
}

async fn read_schema_meta(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Option<SchemaMetaRecord>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.schema_meta",
        schema::READ_SCHEMA_META,
        Map::new(),
    )
    .await?;
    take_schema_meta(&mut response, 0)
}

fn take_schema_meta(
    response: &mut client::RpcResults,
    index: usize,
) -> Result<Option<SchemaMetaRecord>, AdapterError> {
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    match take_optional(response, index) {
        Ok(record) => Ok(record),
        Err(AdapterError::Serialization(_)) => Err(AdapterError::PartialOutcome),
        Err(error) => Err(error),
    }
}

/// Observes the semantic readiness of the database against the configured
/// schema generation.
pub(crate) async fn probe_readiness(
    adapter: &SurrealStoreAdapter,
) -> Result<SemanticReadiness, AdapterError> {
    let db = client(adapter).await?;
    observe_readiness(db, &adapter.config).await
}

async fn observe_readiness(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<SemanticReadiness, AdapterError> {
    let observed = probe_generation(db, config).await?;
    let readiness = readiness_from_observation(observed, &config.expected_schema_generation);
    if matches!(readiness, SemanticReadiness::Ready { .. }) {
        let fence = read_fence(db, config).await?;
        return readiness_with_fence(readiness, fence, &config.expected_schema_generation);
    }
    Ok(readiness)
}

fn readiness_with_fence(
    readiness: SemanticReadiness,
    fence: Option<FenceRecord>,
    expected: &SchemaGeneration,
) -> Result<SemanticReadiness, AdapterError> {
    if matches!(readiness, SemanticReadiness::Ready { .. }) {
        let Some(fence) = fence else {
            return Ok(SemanticReadiness::MigrationRequired {
                expected: expected.clone(),
                observed: None,
            });
        };
        validate_fence_record(&fence)?;
    }
    Ok(readiness)
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
    match observe_readiness(db, &adapter.config).await? {
        SemanticReadiness::Ready { .. } => Ok(()),
        SemanticReadiness::MigrationRequired { .. } | SemanticReadiness::Unavailable => {
            Err(AdapterError::MigrationRequired)
        }
    }
}

async fn handle_forward_migration(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    migration: &CompiledMigration,
    existing: SchemaMetaRecord,
    fence: FenceRecord,
    state_fence: &StateFence,
    updated_at: &str,
) -> Result<MigrationReceipt, AdapterError> {
    if migration
        .statements
        .trim()
        .to_ascii_lowercase()
        .contains("drop ")
        || migration
            .statements
            .trim()
            .to_ascii_lowercase()
            .contains("delete ")
        || migration
            .statements
            .trim()
            .to_ascii_lowercase()
            .contains("remove ")
    {
        return Err(AdapterError::PartialOutcome);
    }
    let record = schema_meta_record_for_v1_to_v2(&existing, migration, updated_at);
    let sql = build_forward_sql();
    let bindings = build_forward_bindings(&existing, &fence, &record);
    let mut response = client::query(db, config, "migration.apply", &sql, bindings).await?;
    let errors = response.take_errors();
    if errors.iter().any(|e| is_guard_conflict(e)) {
        return Err(AdapterError::Config("forward guard conflict".to_owned()));
    }
    if !errors.is_empty() {
        return Err(AdapterError::UnknownMigrationOutcome {
            migration_id: migration.migration_id.clone(),
        });
    }
    let observed = read_schema_meta(db, config).await?;
    match migration_preflight(observed, migration) {
        Ok(MigrationPreflight::ExactReplay) => {
            let after = read_fence(db, config).await?;
            let Some(after) = after else {
                return Err(AdapterError::PartialOutcome);
            };
            validate_fence_record(&after)?;
            if after.state_fence != *state_fence
                || after.next_commit_sequence != fence.next_commit_sequence
                || after.next_outbox_sequence != fence.next_outbox_sequence
            {
                return Err(AdapterError::PartialOutcome);
            }
            Ok(migration_receipt(migration))
        }
        _ => Err(AdapterError::PartialOutcome),
    }
}

/// Applies one explicit migration and records the new schema generation.
pub(crate) async fn apply_migration(
    adapter: &SurrealStoreAdapter,
    migration: &CompiledMigration,
    observed_clock: &eliot_platform::ClockObservation,
    state_fence: &StateFence,
) -> Result<MigrationReceipt, AdapterError> {
    let db = client(adapter).await?;
    migration
        .validate()
        .map_err(|r| AdapterError::Config(r.to_owned()))?;
    if !is_admitted_migration(migration) {
        return Err(AdapterError::Config(
            "migration plan is not admitted by the S-03 schema compiler".to_owned(),
        ));
    }
    let _guard = adapter.write_lock.lock().await;
    state_fence.validate().map_err(StoreError::Foundation)?;
    let existing = read_schema_meta(db, &adapter.config).await?;
    let preflight = migration_preflight(existing.clone(), migration)?;
    if matches!(preflight, MigrationPreflight::ExactReplay) {
        let f = read_fence(db, &adapter.config).await?;
        let Some(f) = f else {
            return Err(AdapterError::PartialOutcome);
        };
        validate_fence_record(&f)?;
        if f.state_fence != *state_fence {
            return Err(AdapterError::PartialOutcome);
        }
        return Ok(migration_receipt(migration));
    }
    observed_clock
        .validate()
        .map_err(|e| AdapterError::Config(e.to_string()))?;
    let updated_at = observed_clock
        .known_time_ms
        .or(observed_clock.valid_time_ms)
        .ok_or_else(|| {
            AdapterError::Config(
                "migration requires an observed P-01 wall-clock timestamp".to_owned(),
            )
        })?
        .to_string();
    match preflight {
        MigrationPreflight::Empty => {
            handle_empty_migration(db, &adapter.config, migration, state_fence, &updated_at).await
        }
        MigrationPreflight::V1ToV2 => {
            let fence = read_fence(db, &adapter.config).await?;
            let Some(fence) = fence else {
                return Err(AdapterError::PartialOutcome);
            };
            validate_fence_record(&fence)?;
            if fence.state_fence != *state_fence {
                return Err(AdapterError::PartialOutcome);
            }
            let Some(existing) = existing else {
                return Err(AdapterError::PartialOutcome);
            };
            handle_forward_migration(
                db,
                &adapter.config,
                migration,
                existing,
                fence,
                state_fence,
                &updated_at,
            )
            .await
        }
        MigrationPreflight::ExactReplay => Ok(migration_receipt(migration)),
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
    ensure_ready(adapter, db).await?;

    let _guard = adapter.write_lock.lock().await;

    match read_idempotency(db, &adapter.config, ctx, &transition).await? {
        Idempotency::Replay(receipt) => {
            validate_receipt_identity(&receipt, ctx, &transition)?;
            return Ok(receipt);
        }
        Idempotency::Conflict => return Err(AdapterError::Store(StoreError::IdentityConflict)),
        Idempotency::None => {}
    }

    let fence = read_fence(db, &adapter.config).await?;
    if let Some(fence) = &fence
        && fence.state_fence != transition.state_fence
    {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let next_commit_sequence = fence.as_ref().map_or(1, |fence| fence.next_commit_sequence);
    let next_outbox_sequence = fence.as_ref().map_or(1, |fence| fence.next_outbox_sequence);

    let revision_keys = union_revision_keys(&expected_revision_heads, &transition);
    let ordering_scopes = union_ordering_scopes(&expected_ordering_heads, &transition);
    let current_revisions = read_revision_heads_inner(db, &adapter.config, &revision_keys).await?;
    let current_orderings =
        read_ordering_heads_inner(db, &adapter.config, &ordering_scopes).await?;

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
    let receipt = build_receipt(ctx, &transition, &plan)?;

    write_transaction(
        db,
        &adapter.config,
        &transition,
        &plan,
        &receipt,
        fence.is_none(),
        fence.as_ref().map_or(1, |value| value.next_commit_sequence),
        fence.as_ref().map_or(1, |value| value.next_outbox_sequence),
        &current_revisions,
        &current_orderings,
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

/// Reads one bounded recovery snapshot from one coherent provider transaction.
pub(crate) async fn recovery(
    adapter: &SurrealStoreAdapter,
    request: StoreRecoveryRequest,
) -> Result<StoreRecoverySnapshot, AdapterError> {
    request.validate()?;
    let db = client(adapter).await?;
    let sql = build_recovery_sql(&request);
    let mut response = client::query(
        db,
        &adapter.config,
        "recovery.snapshot",
        &sql,
        build_recovery_bindings(&request),
    )
    .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }

    let schema = take_schema_meta(&mut response, 1)?;
    let fence = response.take::<Option<FenceRecord>>(2)?;

    let mut index = 3;
    let mut owner_records = Vec::with_capacity(request.records.len());
    for key in &request.records {
        let records = response.take::<Vec<RecoveryRecord>>(index)?;
        index += 1;
        if records.len() != 1 {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "recovery.records",
                reason: "requested record must have exactly one match",
            }));
        }
        let record = records.into_iter().next().ok_or({
            AdapterError::Store(StoreError::InvalidField {
                field: "recovery.records",
                reason: "requested record is missing",
            })
        })?;
        if record.record_key() != *key {
            return Err(AdapterError::Store(StoreError::IdentityConflict));
        }
        owner_records.push(record);
    }
    let job_records = if request.include_jobs {
        let jobs = response.take::<Vec<RecoveryRecord>>(index)?;
        index += 1;
        jobs
    } else {
        Vec::new()
    };
    let receipts = if request.include_receipts {
        let receipts = response.take::<Vec<WriteReceipt>>(index)?;
        index += 1;
        receipts
    } else {
        Vec::new()
    };
    let revision_heads = response.take::<Vec<RevisionHead>>(index)?;
    index += 1;
    let ordering_heads = response.take::<Vec<OrderingHead>>(index)?;
    build_recovery_snapshot(
        RecoverySnapshotInput {
            schema,
            fence,
            owner_records,
            job_records,
            receipts,
            revision_heads,
            ordering_heads,
        },
        &adapter.config.expected_schema_generation,
        &request.state_fence,
        &request.records,
    )
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

#[cfg(test)]
mod tests;
