//! Database-backed store operations: atomic apply, reconciliation reads,
//! named reads, health and migration.
//!
//! All `SurrealQL` and physical table access stays inside this module and
//! [`crate::schema`]. The public boundary only ever carries store-API types.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

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
    CONTRACT_VERSION, CanonicalValidationSnapshot, CommitId, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OperationId, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    RecoveryRecord, RecoveryRecordKey, Resubmission, RevisionHead, RevisionHeadExpectation,
    RevisionKey, ScopeId, ScopeRevisionView, StateFence, StoreError, StoreGenesisRequest,
    StoreHealth, StoreHealthStatus, StoreRecoveryRequest, StoreRecoverySnapshot, TransitionClass,
    WriteReceipt, WriteReceiptStatus, genesis_manifest, is_genesis_fence,
    issue_genesis_receipt_envelope, validate_genesis_receipt_envelope,
    validate_store_receipt_envelope,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

const READ_VALIDATION_SNAPSHOT: &str = "BEGIN TRANSACTION; SELECT * FROM ONLY schema_meta:current; SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current; SELECT VALUE body FROM revision_head; COMMIT TRANSACTION;";

/// The durable canonical fence singleton.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceRecord {
    state_fence: StateFence,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaMetaRecord {
    generation: String,
    migrations: Vec<SchemaMigrationIdentity>,
    compatible_bridge_range: String,
    migration_state: String,
    migration_id: String,
    migration_checksum_sha256: String,
    updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaMigrationIdentity {
    migration_id: String,
    migration_checksum_sha256: String,
    generation: String,
}

#[derive(Debug, Eq, PartialEq)]
enum MigrationPreflight {
    Empty,
    ExactReplay,
    V1ToV2,
}

fn v1_identity() -> SchemaMigrationIdentity {
    SchemaMigrationIdentity {
        migration_id: schema::MIGRATION_ID_V1.to_owned(),
        migration_checksum_sha256: schema::SCHEMA_DDL_V1_SHA256.to_owned(),
        generation: schema::GENERATION_V1.to_owned(),
    }
}

fn validate_v1_pin() -> bool {
    eliot_store_api::sha256_hex(schema::SCHEMA_DDL.as_bytes()) == schema::SCHEMA_DDL_V1_SHA256
}

fn schema_meta_record(migration: &CompiledMigration, updated_at: &str) -> SchemaMetaRecord {
    let migrations = if migration.generation_after.as_str() == schema::GENERATION_V2 {
        vec![
            v1_identity(),
            SchemaMigrationIdentity {
                migration_id: migration.migration_id.clone(),
                migration_checksum_sha256: migration.checksum_sha256.clone(),
                generation: migration.generation_after.as_str().to_owned(),
            },
        ]
    } else {
        vec![SchemaMigrationIdentity {
            migration_id: migration.migration_id.clone(),
            migration_checksum_sha256: migration.checksum_sha256.clone(),
            generation: migration.generation_after.as_str().to_owned(),
        }]
    };
    SchemaMetaRecord {
        generation: migration.generation_after.as_str().to_owned(),
        migrations,
        compatible_bridge_range: crate::ADAPTER_NAME.to_owned(),
        migration_state: "APPLIED".to_owned(),
        migration_id: migration.migration_id.clone(),
        migration_checksum_sha256: migration.checksum_sha256.clone(),
        updated_at: updated_at.to_owned(),
    }
}

fn schema_meta_record_for_v1_to_v2(
    existing: &SchemaMetaRecord,
    migration: &CompiledMigration,
    updated_at: &str,
) -> SchemaMetaRecord {
    let mut migrations = existing.migrations.clone();
    migrations.push(SchemaMigrationIdentity {
        migration_id: migration.migration_id.clone(),
        migration_checksum_sha256: migration.checksum_sha256.clone(),
        generation: migration.generation_after.as_str().to_owned(),
    });
    SchemaMetaRecord {
        generation: migration.generation_after.as_str().to_owned(),
        migrations,
        compatible_bridge_range: crate::ADAPTER_NAME.to_owned(),
        migration_state: "APPLIED".to_owned(),
        migration_id: migration.migration_id.clone(),
        migration_checksum_sha256: migration.checksum_sha256.clone(),
        updated_at: updated_at.to_owned(),
    }
}

fn validate_schema_meta_record(record: &SchemaMetaRecord) -> Result<(), AdapterError> {
    let non_blank = |value: &str| !value.trim().is_empty() && !value.chars().any(char::is_control);
    if !non_blank(&record.generation)
        || record.migrations.is_empty()
        || !non_blank(&record.compatible_bridge_range)
        || !non_blank(&record.migration_state)
        || !non_blank(&record.migration_id)
        || !non_blank(&record.migration_checksum_sha256)
        || !non_blank(&record.updated_at)
    {
        return Err(AdapterError::PartialOutcome);
    }
    if record.compatible_bridge_range != crate::ADAPTER_NAME {
        return Err(AdapterError::Config(
            "schema metadata belongs to an incompatible adapter".to_owned(),
        ));
    }
    if record.migration_state != "APPLIED" {
        return Err(AdapterError::PartialOutcome);
    }
    let Some(last) = record.migrations.last() else {
        return Err(AdapterError::PartialOutcome);
    };
    if !non_blank(&last.migration_id)
        || !non_blank(&last.migration_checksum_sha256)
        || !non_blank(&last.generation)
        || last.migration_id != record.migration_id
        || last.migration_checksum_sha256 != record.migration_checksum_sha256
        || last.generation != record.generation
    {
        return Err(AdapterError::PartialOutcome);
    }
    if record.generation == schema::GENERATION_V1 {
        if record.migrations.len() != 1 {
            return Err(AdapterError::PartialOutcome);
        }
        let first = &record.migrations[0];
        let expected = v1_identity();
        if first.migration_id != expected.migration_id
            || first.migration_checksum_sha256 != expected.migration_checksum_sha256
            || first.generation != expected.generation
        {
            return Err(AdapterError::PartialOutcome);
        }
        if record.migration_id != schema::MIGRATION_ID_V1
            || record.migration_checksum_sha256 != expected.migration_checksum_sha256
        {
            return Err(AdapterError::PartialOutcome);
        }
    } else if record.generation == schema::GENERATION_V2 {
        if record.migrations.len() != 2 {
            return Err(AdapterError::PartialOutcome);
        }
        let first = &record.migrations[0];
        let expected_v1 = v1_identity();
        if first.migration_id != expected_v1.migration_id
            || first.migration_checksum_sha256 != expected_v1.migration_checksum_sha256
            || first.generation != expected_v1.generation
        {
            return Err(AdapterError::PartialOutcome);
        }
        let v2_checksum_full = eliot_store_api::sha256_hex(schema::SCHEMA_DDL_V2.as_bytes());
        let v2_checksum_delta =
            eliot_store_api::sha256_hex(schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.as_bytes());
        let last = &record.migrations[1];
        if last.generation != schema::GENERATION_V2 {
            return Err(AdapterError::PartialOutcome);
        }
        if !(last.migration_id == schema::MIGRATION_ID_V2
            && last.migration_checksum_sha256 == v2_checksum_full
            || last.migration_id == schema::MIGRATION_ID_V1_TO_V2
                && last.migration_checksum_sha256 == v2_checksum_delta)
        {
            return Err(AdapterError::PartialOutcome);
        }
        if record.migration_id != last.migration_id
            || record.migration_checksum_sha256 != last.migration_checksum_sha256
        {
            return Err(AdapterError::PartialOutcome);
        }
    } else {
        return Err(AdapterError::PartialOutcome);
    }
    for entry in &record.migrations {
        if !non_blank(&entry.migration_id)
            || !non_blank(&entry.migration_checksum_sha256)
            || !non_blank(&entry.generation)
        {
            return Err(AdapterError::PartialOutcome);
        }
    }
    Ok(())
}

fn validate_fence_record(record: &FenceRecord) -> Result<(), AdapterError> {
    record
        .state_fence
        .validate()
        .map_err(StoreError::Foundation)?;
    if record.next_commit_sequence == 0 || record.next_outbox_sequence == 0 {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

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

fn build_empty_sql(statements: &str) -> String {
    format!(
        "{} {} {} {} {}",
        schema::TX_BEGIN,
        statements.trim(),
        schema::TX_CREATE_FENCE,
        schema::TX_CREATE_SCHEMA_META,
        schema::TX_COMMIT
    )
}

fn build_empty_bindings(
    migration: &CompiledMigration,
    updated_at: &str,
    state_fence: &StateFence,
) -> Map<String, Value> {
    let record = schema_meta_record(migration, updated_at);
    let mut m = Map::new();
    m.insert(
        "schema_meta_table".to_owned(),
        json!(schema::table::SCHEMA_META),
    );
    m.insert("schema_meta_key".to_owned(), json!(schema::SCHEMA_META_KEY));
    m.insert("schema_meta_record".to_owned(), json!(record));
    m.insert(
        "fence_table".to_owned(),
        json!(schema::table::CANONICAL_FENCE),
    );
    m.insert("fence_key".to_owned(), json!(schema::FENCE_KEY));
    m.insert(
        "fence".to_owned(),
        json!({
            "state_fence": state_fence,
            "next_commit_sequence": 1_u64,
            "next_outbox_sequence": 1_u64,
        }),
    );
    m
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

async fn handle_empty_migration(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    migration: &CompiledMigration,
    state_fence: &StateFence,
    updated_at: &str,
) -> Result<MigrationReceipt, AdapterError> {
    let sql = build_empty_sql(migration.statements.trim());
    let bindings = build_empty_bindings(migration, updated_at, state_fence);
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
            let fence = read_fence(db, config).await?;
            let Some(fence) = fence else {
                return Err(AdapterError::PartialOutcome);
            };
            validate_fence_record(&fence)?;
            if fence.state_fence != *state_fence {
                return Err(AdapterError::PartialOutcome);
            }
            Ok(migration_receipt(migration))
        }
        _ => Err(AdapterError::PartialOutcome),
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

/// Bounded bridge health observation.
///
/// `Available` is deliberately withheld until the semantic readiness probe
/// confirms both the expected schema generation and the canonical fence. A
/// reachable provider with missing/mismatched schema remains unavailable to
/// Store callers.
pub(crate) async fn adapter_health(adapter: &SurrealStoreAdapter) -> AdapterHealth {
    match probe_readiness(adapter).await {
        Ok(SemanticReadiness::Ready { generation }) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::Available,
            provider: ProviderHealth::Reachable,
            schema_generation: Some(generation.to_string()),
        },
        Ok(SemanticReadiness::MigrationRequired { observed, .. }) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::MigrationUnavailable,
            provider: ProviderHealth::Reachable,
            schema_generation: observed,
        },
        Ok(SemanticReadiness::Unavailable) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::Unavailable,
            provider: ProviderHealth::Unknown,
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

/// Resolves a durable receipt by operation identity; the reconciliation read.
pub(crate) async fn read_receipt(
    adapter: &SurrealStoreAdapter,
    operation_id: OperationId,
) -> Result<Option<WriteReceipt>, AdapterError> {
    let db = client(adapter).await?;
    ensure_ready(adapter, db).await?;
    read_receipt_by_operation(db, &adapter.config, &operation_id).await
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
        receipt.require_reconciliation_envelope()?;
    }
    Ok(receipt)
}

async fn read_idempotency(
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

fn build_recovery_sql(request: &StoreRecoveryRequest) -> String {
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
        sql.push_str(schema::READ_ALL_RECEIPTS);
    }
    sql.push_str(schema::READ_ALL_REVISION_HEADS);
    sql.push_str(schema::READ_ALL_ORDERING_HEADS);
    sql.push_str(schema::TX_COMMIT);
    sql
}

fn build_recovery_bindings(request: &StoreRecoveryRequest) -> Map<String, Value> {
    let mut bindings = Map::new();
    for (index, key) in request.records.iter().enumerate() {
        let suffix = index.to_string();
        bindings.insert(format!("recovery_namespace{suffix}"), json!(key.namespace));
        bindings.insert(format!("recovery_key{suffix}"), json!(key.key));
    }
    bindings
}

struct RecoverySnapshotInput {
    schema: Option<SchemaMetaRecord>,
    fence: Option<FenceRecord>,
    owner_records: Vec<RecoveryRecord>,
    job_records: Vec<RecoveryRecord>,
    receipts: Vec<WriteReceipt>,
    revision_heads: Vec<RevisionHead>,
    ordering_heads: Vec<OrderingHead>,
}

fn build_recovery_snapshot(
    mut input: RecoverySnapshotInput,
    expected_generation: &SchemaGeneration,
    expected_fence: &StateFence,
    requested_keys: &[RecoveryRecordKey],
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
    validate_revision_heads(&input.revision_heads)?;
    plan::validate_ordering_heads(&input.ordering_heads)?;
    input.owner_records.sort_by_key(RecoveryRecord::record_key);
    input.job_records.sort_by_key(RecoveryRecord::record_key);
    input
        .receipts
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
    };
    snapshot.validate()?;
    Ok(snapshot)
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

#[derive(Clone, Debug)]
struct GenesisState {
    schema: Option<SchemaMetaRecord>,
    fence: Option<FenceRecord>,
    owners: Vec<RecoveryRecord>,
    jobs: Vec<RecoveryRecord>,
    receipts: Vec<WriteReceipt>,
    revision_heads: Vec<Value>,
    ordering_heads: Vec<Value>,
    events: Vec<Value>,
    projections: Vec<Value>,
    outbox: Vec<Value>,
    relations: Vec<Value>,
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

fn validate_fresh_genesis_state(state: &GenesisState) -> Result<(), AdapterError> {
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

fn validate_replayed_genesis_state(
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

fn build_genesis_sql(owner_count: usize) -> String {
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

fn build_genesis_bindings(
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

fn genesis_receipt(
    context: &eliot_store_api::RequestMeta,
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
    context: &eliot_store_api::RequestMeta,
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

/// Reads or atomically seeds the provider's all-absent genesis state.
pub(crate) async fn initialize_genesis(
    adapter: &SurrealStoreAdapter,
    context: &eliot_store_api::RequestMeta,
    request: StoreGenesisRequest,
) -> Result<WriteReceipt, AdapterError> {
    request.validate_for_context(context)?;
    let db = client(adapter).await?;
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

/// Reads the canonical fence and all revision heads at one provider boundary.
pub(crate) async fn read_validation_snapshot(
    adapter: &SurrealStoreAdapter,
) -> Result<CanonicalValidationSnapshot, AdapterError> {
    let db = client(adapter).await?;
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

fn build_validation_snapshot(
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

/// Reads revision heads for the requested keys, deduplicated and validated.
pub(crate) async fn read_revision_heads(
    adapter: &SurrealStoreAdapter,
    keys: Vec<RevisionKey>,
) -> Result<Vec<RevisionHead>, AdapterError> {
    ensure_unique_revision_keys(&keys)?;
    let db = client(adapter).await?;
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

/// Reads ordering heads for the requested scopes, deduplicated and validated.
pub(crate) async fn read_ordering_heads(
    adapter: &SurrealStoreAdapter,
    scopes: Vec<OrderingScopeId>,
) -> Result<Vec<OrderingHead>, AdapterError> {
    ensure_unique_ordering_scopes(&scopes)?;
    let db = client(adapter).await?;
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

/// Reads the rebuildable scope revision view.
pub(crate) async fn read_scope_view(
    adapter: &SurrealStoreAdapter,
    scope_id: ScopeId,
) -> Result<ScopeRevisionView, AdapterError> {
    let db = client(adapter).await?;
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

/// Executes one closed named read and returns a validated response.
pub(crate) async fn execute_named(
    adapter: &SurrealStoreAdapter,
    query: NamedReadRequest,
) -> Result<NamedReadResponse, AdapterError> {
    query.validate()?;
    let db = client(adapter).await?;
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
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transaction writer preserves the closed named-operation order and atomic SQL assembly"
)]
async fn write_transaction(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
    plan: &ApplyPlan,
    receipt: &WriteReceipt,
    initial_state: bool,
    expected_commit_sequence: u64,
    expected_outbox_sequence: u64,
    current_revisions: &[RevisionHead],
    current_orderings: &[OrderingHead],
) -> Result<(), AdapterError> {
    let operation_id = transition.identity.operation_id.to_string();
    let revision = plan.next_revision_heads.first().ok_or_else(|| {
        AdapterError::Serialization(
            "prepared transition plan is missing its required revision head".to_owned(),
        )
    })?;
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

    let revision_exists = current_revisions
        .iter()
        .any(|head| head.key == revision.key);
    sql.push_str(revision_write_template(initial_state, revision_exists));
    bindings.insert(
        "revision_table".to_owned(),
        json!(schema::table::REVISION_HEAD),
    );
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
        let ordering_exists = current_orderings
            .iter()
            .any(|current| current.scope == head.scope);
        let template = ordering_write_template(initial_state, ordering_exists);
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
    let errors = response.take_errors();
    if !errors.is_empty() {
        // Fence, revision and ordering cardinality guards THROW before the
        // receipt and COMMIT statements.  Only those explicit guards are a
        // deterministic conflict; every other provider error remains
        // unknown because the transport cannot prove whether COMMIT ran.
        if errors.iter().any(|error| is_transaction_conflict(error)) {
            return Err(AdapterError::ProviderConflict);
        }
        return Err(AdapterError::UnknownOutcome { operation_id });
    }
    Ok(())
}

fn is_transaction_conflict(error: &str) -> bool {
    [
        "canonical_fence_cas_conflict",
        "canonical_fence_create_conflict",
        "revision_head_cas_conflict",
        "revision_head_create_conflict",
        "ordering_head_cas_conflict",
        "ordering_head_create_conflict",
    ]
    .iter()
    .any(|marker| error.contains(marker))
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

fn revision_write_template(initial_state: bool, exists: bool) -> &'static str {
    if initial_state || !exists {
        schema::TX_CREATE_REVISION
    } else {
        schema::TX_UPSERT_REVISION
    }
}

fn ordering_write_template(initial_state: bool, exists: bool) -> &'static str {
    if initial_state || !exists {
        schema::TX_CREATE_ORDERING
    } else {
        schema::TX_UPSERT_ORDERING
    }
}

#[cfg(test)]
mod migration_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn v1_migration() -> CompiledMigration {
        CompiledMigration::new(
            schema::MIGRATION_ID_V1,
            schema::SCHEMA_DDL,
            SchemaGeneration::new(schema::GENERATION_V1).expect("valid"),
        )
    }

    fn v2_baseline_migration() -> CompiledMigration {
        CompiledMigration::new(
            schema::MIGRATION_ID_V2,
            schema::SCHEMA_DDL_V2,
            SchemaGeneration::new(schema::GENERATION_V2).expect("valid"),
        )
    }

    fn v1_to_v2_migration() -> CompiledMigration {
        CompiledMigration::new(
            schema::MIGRATION_ID_V1_TO_V2,
            schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
            SchemaGeneration::new(schema::GENERATION_V2).expect("valid"),
        )
    }

    fn genesis_fixture() -> (eliot_store_api::RequestMeta, StoreGenesisRequest) {
        let fence = StateFence::new(
            eliot_contracts::AuthorityEpoch::genesis(),
            eliot_contracts::ResourceGeneration::genesis(),
        );
        let payload = b"{\"seed\":true}".to_vec();
        let owner = RecoveryRecord {
            namespace: "owner".to_owned(),
            key: "seed".to_owned(),
            state_fence: fence.clone(),
            revision: 1,
            schema: "opaque.v1".to_owned(),
            value_digest: eliot_store_api::sha256_hex(&payload),
            payload,
        };
        let request = StoreGenesisRequest {
            contract_version: CONTRACT_VERSION,
            operation_id: OperationId::new("genesis-op").expect("operation id"),
            idempotency_key: "genesis-key".to_owned(),
            canonical_request_hash: String::new(),
            state_fence: fence.clone(),
            owner_records: vec![owner],
        }
        .with_computed_digest()
        .expect("genesis digest");
        let context = eliot_store_api::RequestMeta {
            request_id: eliot_contracts::RequestId::new("genesis-request").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: eliot_contracts::ProductId::new("product").expect("product id"),
            source_id: eliot_contracts::SourceId::new("source").expect("source id"),
            state_fence: fence,
            clock: eliot_contracts::ClockReading::default(),
        };
        (context, request)
    }

    fn genesis_state(request: &StoreGenesisRequest, receipt: Option<WriteReceipt>) -> GenesisState {
        GenesisState {
            schema: Some(schema_meta_record(&v2_baseline_migration(), "1000")),
            fence: Some(FenceRecord {
                state_fence: request.state_fence.clone(),
                next_commit_sequence: receipt.as_ref().map_or(1, |_| 2),
                next_outbox_sequence: 1,
            }),
            owners: if receipt.is_some() {
                request.owner_records.clone()
            } else {
                Vec::new()
            },
            jobs: Vec::new(),
            receipts: receipt.into_iter().collect(),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            events: Vec::new(),
            projections: Vec::new(),
            outbox: Vec::new(),
            relations: Vec::new(),
        }
    }

    #[test]
    fn genesis_sql_guards_all_absent_state_and_advances_only_commit_sequence() {
        let (context, request) = genesis_fixture();
        let receipt = genesis_receipt(&context, &request, 1).expect("genesis receipt");
        let sql = build_genesis_sql(request.owner_records.len());
        assert!(schema::TX_GENESIS_SCHEMA_GUARD.contains("type::is_object($genesis_schema)"));
        assert!(schema::TX_GENESIS_SCHEMA_GUARD.contains("type::is_object($genesis_fence)"));
        assert!(!schema::TX_GENESIS_SCHEMA_GUARD.contains("array::len($genesis_schema"));
        assert!(!schema::TX_GENESIS_SCHEMA_GUARD.contains("array::len($genesis_fence"));
        assert!(sql.starts_with(schema::TX_GENESIS_BEGIN));
        assert!(sql.contains(schema::TX_GENESIS_SCHEMA_GUARD));
        assert!(sql.contains(schema::TX_GENESIS_EMPTY_GUARD));
        assert!(sql.contains(&schema::indexed(schema::TX_GENESIS_CREATE_OWNER, 0)));
        assert!(sql.contains(schema::TX_GENESIS_FENCE_CAS));
        assert!(sql.contains(schema::TX_GENESIS_CREATE_RECEIPT));
        assert!(sql.ends_with(schema::TX_GENESIS_COMMIT));
        let bindings = build_genesis_bindings(
            &SurrealAdapterConfig {
                endpoint: "ws://127.0.0.1:18000/rpc".to_owned(),
                namespace: "ns".to_owned(),
                database: "db".to_owned(),
                username: "user".to_owned(),
                password: secrecy::SecretString::new("password".to_owned().into()),
                provider_bind_address: "127.0.0.1:18000".to_owned(),
                installation_id: "install".to_owned(),
                installation_profile: "portable_dev".to_owned(),
                runtime_state_roots_digest: "a".repeat(64),
                provider_executable_path: "C:\\surreal.exe".to_owned(),
                provider_artifact_digest: "b".repeat(64),
                provider_arguments: Vec::new(),
                store_data_root: "C:\\data".to_owned(),
                store_work_root: "C:\\work".to_owned(),
                store_temp_root: "C:\\temp".to_owned(),
                connect_timeout_ms: 1000,
                query_timeout_ms: 1000,
                expected_provider_major: 3,
                expected_schema_generation: SchemaGeneration::v2(),
            },
            &request,
            &receipt,
        )
        .expect("genesis bindings");
        assert_eq!(bindings.get("expected_generation"), Some(&json!("2.0.0")));
        assert_eq!(
            bindings
                .get("fence")
                .and_then(Value::as_object)
                .and_then(|f| f.get("next_commit_sequence")),
            Some(&json!(2))
        );
        assert_eq!(
            bindings
                .get("fence")
                .and_then(Value::as_object)
                .and_then(|f| f.get("next_outbox_sequence")),
            Some(&json!(1))
        );
    }

    #[test]
    fn genesis_replay_requires_exact_committed_state_and_is_immutable() {
        let (context, request) = genesis_fixture();
        let receipt = genesis_receipt(&context, &request, 1).expect("genesis receipt");
        validate_genesis_receipt_envelope(&context, &request, &receipt).expect("valid envelope");
        let replay_state = genesis_state(&request, Some(receipt.clone()));
        validate_replayed_genesis_state(&replay_state, &request).expect("exact replay state");
        assert_eq!(replay_state.receipts[0], receipt);

        let mut stale_sequence = replay_state.clone();
        stale_sequence
            .fence
            .as_mut()
            .expect("fence")
            .next_commit_sequence = 1;
        assert_eq!(
            validate_replayed_genesis_state(&stale_sequence, &request),
            Err(AdapterError::Store(StoreError::IdentityConflict))
        );

        let mut substituted = replay_state.clone();
        substituted.owners[0].key = "substituted".to_owned();
        assert_eq!(
            validate_replayed_genesis_state(&substituted, &request),
            Err(AdapterError::Store(StoreError::IdentityConflict))
        );
    }

    #[test]
    fn genesis_fresh_state_rejects_partial_presence_and_sql_marks_unknown_outcome() {
        let (_, request) = genesis_fixture();
        let mut partial = genesis_state(&request, None);
        partial.owners = request.owner_records.clone();
        assert_eq!(
            validate_fresh_genesis_state(&partial),
            Err(AdapterError::Store(StoreError::IdentityConflict))
        );
        let stale = genesis_state(
            &request,
            Some(genesis_receipt(&genesis_fixture().0, &request, 1).expect("receipt")),
        );
        assert!(build_genesis_sql(1).contains("genesis_state_conflict"));
        assert!(build_genesis_sql(1).contains("genesis_fence_conflict"));
        assert_eq!(
            AdapterError::Store(StoreError::MissingReceiptEnvelope).into_store_error(),
            StoreError::MissingReceiptEnvelope
        );
        assert_eq!(stale.receipts.len(), 1);
    }

    #[test]
    fn recovery_sql_is_one_transaction_with_requested_owner_bindings_and_sorted_output_helper() {
        let (_, request) = genesis_fixture();
        let recovery_request = StoreRecoveryRequest {
            contract_version: CONTRACT_VERSION,
            state_fence: request.state_fence,
            records: vec![request.owner_records[0].record_key()],
            include_receipts: true,
            include_jobs: true,
        };
        let sql = build_recovery_sql(&recovery_request);
        assert!(sql.starts_with(schema::TX_BEGIN));
        assert!(sql.contains("recovery_namespace0"));
        assert!(sql.contains(schema::READ_ALL_RECOVERY_JOBS));
        assert!(sql.contains(schema::READ_ALL_RECEIPTS));
        assert!(sql.ends_with(schema::TX_COMMIT));
        let bindings = build_recovery_bindings(&recovery_request);
        assert_eq!(bindings.get("recovery_namespace0"), Some(&json!("owner")));
        assert_eq!(bindings.get("recovery_key0"), Some(&json!("seed")));
    }

    #[test]
    fn recovery_result_requires_exact_requested_presence_and_sorts_deterministically() {
        let (_, request) = genesis_fixture();
        let mut second = request.owner_records[0].clone();
        second.key = "a-seed".to_owned();
        second.payload = b"{\"seed\":\"a\"}".to_vec();
        second.value_digest = eliot_store_api::sha256_hex(&second.payload);
        let first_key = request.owner_records[0].record_key();
        let second_key = second.record_key();
        let snapshot = build_recovery_snapshot(
            RecoverySnapshotInput {
                schema: Some(schema_meta_record(&v2_baseline_migration(), "1000")),
                fence: Some(FenceRecord {
                    state_fence: request.state_fence.clone(),
                    next_commit_sequence: 2,
                    next_outbox_sequence: 1,
                }),
                owner_records: vec![request.owner_records[0].clone(), second.clone()],
                job_records: Vec::new(),
                receipts: Vec::new(),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
            },
            &SchemaGeneration::v2(),
            &request.state_fence,
            &[first_key.clone(), second_key.clone()],
        )
        .expect("recovery snapshot");
        assert_eq!(snapshot.owner_records[0].record_key(), second_key);
        assert_eq!(snapshot.owner_records[1].record_key(), first_key);

        let missing = build_recovery_snapshot(
            RecoverySnapshotInput {
                schema: Some(schema_meta_record(&v2_baseline_migration(), "1000")),
                fence: Some(FenceRecord {
                    state_fence: request.state_fence.clone(),
                    next_commit_sequence: 2,
                    next_outbox_sequence: 1,
                }),
                owner_records: vec![request.owner_records[0].clone()],
                job_records: Vec::new(),
                receipts: Vec::new(),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
            },
            &SchemaGeneration::v2(),
            &request.state_fence,
            &[first_key, second_key],
        );
        assert!(matches!(
            missing,
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "recovery.records",
                ..
            }))
        ));
    }

    #[test]
    fn exact_applied_identity_is_a_replay_without_provider_effect() {
        let migration = v1_migration();
        let observed = schema_meta_record(&migration, "1000");
        assert!(matches!(
            migration_preflight(Some(observed), &migration),
            Ok(MigrationPreflight::ExactReplay)
        ));
        let v2 = v2_baseline_migration();
        let observed_v2 = schema_meta_record(&v2, "1000");
        assert!(matches!(
            migration_preflight(Some(observed_v2), &v2),
            Ok(MigrationPreflight::ExactReplay)
        ));
        let fwd = v1_to_v2_migration();
        let v1_record = schema_meta_record(&v1_migration(), "1000");
        let v2_from_v1 = schema_meta_record_for_v1_to_v2(&v1_record, &fwd, "2000");
        assert!(matches!(
            migration_preflight(Some(v2_from_v1), &fwd),
            Ok(MigrationPreflight::ExactReplay)
        ));
    }

    #[test]
    fn identity_mismatch_is_rejected_before_provider_effect() {
        let migration = v1_migration();
        let mut observed = schema_meta_record(&migration, "1000");
        observed.generation = "2.0.0".to_owned();
        observed.migrations[0].generation = "2.0.0".to_owned();
        assert!(matches!(
            migration_preflight(Some(observed), &migration),
            Err(AdapterError::Config(_) | AdapterError::PartialOutcome)
        ));
    }

    #[test]
    fn empty_database_admits_exactly_v2_initial_plan() {
        let v2 = v2_baseline_migration();
        assert!(matches!(
            migration_preflight(None, &v2),
            Ok(MigrationPreflight::Empty)
        ));
        let v1 = v1_migration();
        assert!(matches!(
            migration_preflight(None, &v1),
            Err(AdapterError::Config(_))
        ));
        let fwd = v1_to_v2_migration();
        assert!(matches!(
            migration_preflight(None, &fwd),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn valid_exact_v1_admits_exactly_v1_to_v2() {
        let v1 = v1_migration();
        let observed = schema_meta_record(&v1, "1000");
        let fwd = v1_to_v2_migration();
        assert!(matches!(
            migration_preflight(Some(observed.clone()), &fwd),
            Ok(MigrationPreflight::V1ToV2)
        ));
        let v2_baseline = v2_baseline_migration();
        assert!(matches!(
            migration_preflight(Some(observed), &v2_baseline),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn exact_v2_yields_replay_no_mutation() {
        let v2 = v2_baseline_migration();
        let observed = schema_meta_record(&v2, "1000");
        assert!(matches!(
            migration_preflight(Some(observed), &v2),
            Ok(MigrationPreflight::ExactReplay)
        ));
    }

    #[test]
    fn wrong_predecessor_is_rejected() {
        let v1 = v1_migration();
        let v2 = v2_baseline_migration();
        let observed_v2 = schema_meta_record(&v2, "1000");
        assert!(matches!(
            migration_preflight(Some(observed_v2), &v1),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn wrong_checksum_is_rejected() {
        let mut fwd = v1_to_v2_migration();
        fwd.checksum_sha256 = "0".repeat(64);
        let v1 = v1_migration();
        let observed = schema_meta_record(&v1, "1000");
        assert!(matches!(
            migration_preflight(Some(observed), &fwd),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn wrong_migration_id_is_rejected() {
        let mut fwd = v1_to_v2_migration();
        fwd.migration_id = "wrong.id".to_owned();
        let v1 = v1_migration();
        let observed = schema_meta_record(&v1, "1000");
        assert!(matches!(
            migration_preflight(Some(observed), &fwd),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn wrong_generation_is_rejected() {
        let wrong = CompiledMigration::new(
            schema::MIGRATION_ID_V2,
            schema::SCHEMA_DDL_V2,
            SchemaGeneration::new("9.9.9").expect("valid"),
        );
        assert!(matches!(
            migration_preflight(None, &wrong),
            Err(AdapterError::Config(_))
        ));
        let v1 = v1_migration();
        let observed = schema_meta_record(&v1, "1000");
        let mut fwd = v1_to_v2_migration();
        fwd.generation_after = SchemaGeneration::new("9.9.9").expect("valid");
        assert!(matches!(
            migration_preflight(Some(observed), &fwd),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn wrong_bridge_range_is_rejected() {
        let v2 = v2_baseline_migration();
        let mut observed = schema_meta_record(&v2, "1000");
        observed.compatible_bridge_range = "wrong.adapter".to_owned();
        assert!(matches!(
            migration_preflight(Some(observed), &v2),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn partial_metadata_is_fail_closed() {
        let v2 = v2_baseline_migration();
        let mut observed = schema_meta_record(&v2, "1000");
        observed.migrations.clear();
        assert_eq!(
            migration_preflight(Some(observed), &v2),
            Err(AdapterError::PartialOutcome)
        );
        let mut observed2 = schema_meta_record(&v2, "1000");
        observed2.migration_state = "APPLYING".to_owned();
        assert_eq!(
            migration_preflight(Some(observed2), &v2),
            Err(AdapterError::PartialOutcome)
        );
        let mut observed3 = schema_meta_record(&v2, "1000");
        observed3.migrations[0].migration_id = String::new();
        assert_eq!(
            migration_preflight(Some(observed3), &v2),
            Err(AdapterError::PartialOutcome)
        );
    }

    #[test]
    fn unknown_metadata_is_fail_closed() {
        let v2 = v2_baseline_migration();
        let mut observed = schema_meta_record(&v2, "1000");
        observed.generation = "9.9.9".to_owned();
        assert_eq!(
            migration_preflight(Some(observed), &v2),
            Err(AdapterError::PartialOutcome)
        );
        let mut observed2 = schema_meta_record(&v2, "1000");
        observed2.migrations.push(SchemaMigrationIdentity {
            migration_id: "extra".to_owned(),
            migration_checksum_sha256: "a".repeat(64),
            generation: "3.0.0".to_owned(),
        });
        assert_eq!(
            migration_preflight(Some(observed2), &v2),
            Err(AdapterError::PartialOutcome)
        );
    }

    #[test]
    fn bridge_range_fence_and_state_are_fenced() {
        let v1 = v1_migration();
        let observed = schema_meta_record(&v1, "1000");
        let fwd = v1_to_v2_migration();
        let ok = migration_preflight(Some(observed.clone()), &fwd).expect("v1 to v2");
        assert_eq!(ok, MigrationPreflight::V1ToV2);
        let mut wrong_fence = observed;
        wrong_fence.compatible_bridge_range = "other".to_owned();
        assert!(matches!(
            migration_preflight(Some(wrong_fence), &fwd),
            Err(AdapterError::Config(_))
        ));
    }

    #[test]
    fn post_read_requires_the_complete_durable_identity() {
        let migration = v1_migration();
        let mut observed = schema_meta_record(&migration, "1000");
        observed.migrations.clear();
        assert_eq!(
            migration_preflight(Some(observed), &migration),
            Err(AdapterError::PartialOutcome)
        );
    }

    #[test]
    fn transitional_metadata_is_fail_closed() {
        let migration = v1_migration();
        let mut observed = schema_meta_record(&migration, "1000");
        observed.migration_state = "APPLYING".to_owned();
        assert_eq!(
            migration_preflight(Some(observed), &migration),
            Err(AdapterError::PartialOutcome)
        );
    }

    #[test]
    fn history_append_preserves_v1_and_appends_v2() {
        let v2 = v2_baseline_migration();
        let record = schema_meta_record(&v2, "1000");
        assert_eq!(record.migrations.len(), 2);
        assert_eq!(record.migrations[0].migration_id, schema::MIGRATION_ID_V1);
        assert_eq!(record.migrations[0].generation, schema::GENERATION_V1);
        assert_eq!(record.migrations[1].migration_id, schema::MIGRATION_ID_V2);
        assert_eq!(record.generation, schema::GENERATION_V2);
        assert_eq!(record.migration_id, schema::MIGRATION_ID_V2);
        let v1 = v1_migration();
        let v1_record = schema_meta_record(&v1, "1000");
        let fwd = v1_to_v2_migration();
        let v1_to_v2_record = schema_meta_record_for_v1_to_v2(&v1_record, &fwd, "2000");
        assert_eq!(v1_to_v2_record.migrations.len(), 2);
        assert_eq!(
            v1_to_v2_record.migrations[0].migration_id,
            schema::MIGRATION_ID_V1
        );
        assert_eq!(
            v1_to_v2_record.migrations[1].migration_id,
            schema::MIGRATION_ID_V1_TO_V2
        );
        assert_eq!(v1_to_v2_record.generation, schema::GENERATION_V2);
    }

    #[test]
    fn v1_ddl_bytes_are_immutable_and_v2_is_additive() {
        assert!(!schema::SCHEMA_DDL.contains("recovery_owner"));
        assert!(schema::SCHEMA_DDL_V2.contains(schema::SCHEMA_DDL.trim()));
        assert!(schema::SCHEMA_DDL_V2.contains("recovery_owner"));
        assert!(schema::SCHEMA_DDL_V2.contains("recovery_job"));
        assert!(schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.contains("recovery_owner"));
        assert!(!schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.contains("DEFINE TABLE schema_meta"));
    }

    #[test]
    fn transaction_has_no_destructive_statements_and_no_fence_rewrite_for_forward() {
        for ddl in [
            schema::SCHEMA_DDL,
            schema::SCHEMA_DDL_V2,
            schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
        ] {
            let lower = ddl.to_ascii_lowercase();
            assert!(!lower.contains("drop "));
            assert!(!lower.contains("delete "));
            assert!(!lower.contains("remove "));
            assert!(!lower.contains("reset"));
        }
        let v1 = v1_migration();
        let v1_record = schema_meta_record(&v1, "1000");
        let fwd = v1_to_v2_migration();
        let record = schema_meta_record_for_v1_to_v2(&v1_record, &fwd, "2000");
        assert_eq!(record.migrations.len(), 2);
        let forward_sql = build_forward_sql();
        assert!(!forward_sql.to_ascii_lowercase().contains("drop "));
        assert!(!forward_sql.contains(schema::TX_CREATE_FENCE));
        assert!(!forward_sql.contains(schema::TX_UPSERT_FENCE));
        assert!(forward_sql.contains(schema::TX_GUARD_FENCE));
        assert!(forward_sql.contains(schema::TX_GUARD_SCHEMA_PREDECESSOR));
        assert!(forward_sql.contains(schema::TX_UPDATE_SCHEMA_META_CAS));
        assert!(forward_sql.contains(schema::RECOVERY_TABLES_DDL.trim()));
        let fence = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("gen"),
            ),
            next_commit_sequence: 7,
            next_outbox_sequence: 9,
        };
        let bindings = build_forward_bindings(&v1_record, &fence, &record);
        assert_eq!(
            bindings.get("expected_state_fence"),
            Some(&json!(fence.state_fence))
        );
        assert_eq!(
            bindings.get("expected_commit_sequence"),
            Some(&json!(7_u64))
        );
        assert!(is_guard_conflict("schema_predecessor_mismatch"));
        assert!(is_guard_conflict("schema_fence_guard_mismatch"));
        assert!(!is_guard_conflict("other_error"));
    }

    #[test]
    fn forward_sql_contains_predecessor_cas_and_fence_guard_no_data_mutation() {
        let sql = build_forward_sql();
        assert!(sql.starts_with(schema::TX_BEGIN));
        assert!(sql.ends_with(schema::TX_COMMIT));
        assert!(sql.contains(schema::TX_GUARD_FENCE));
        assert!(sql.contains(schema::TX_GUARD_SCHEMA_PREDECESSOR));
        assert!(sql.contains(schema::TX_UPDATE_SCHEMA_META_CAS));
        assert!(!sql.contains(schema::TX_CREATE_FENCE));
        assert!(!sql.contains(schema::TX_UPSERT_FENCE));
        assert!(!sql.contains(schema::TX_CREATE_RECEIPT));
        assert!(!sql.contains(schema::TX_CREATE_REVISION));
        assert!(!sql.contains(schema::TX_UPSERT_REVISION));
        let bindings_keys = schema::forward_migration_expected_bindings();
        assert!(bindings_keys.contains(&"expected_state_fence"));
        assert!(bindings_keys.contains(&"expected_generation"));
        for key in bindings_keys {
            assert!(sql.contains(key) || key.contains("schema_meta"));
        }
    }

    #[test]
    fn wrong_state_fence_is_rejected_by_forward_guard() {
        let v1 = v1_migration();
        let existing = schema_meta_record(&v1, "1000");
        let fence_ok = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("gen"),
            ),
            next_commit_sequence: 1,
            next_outbox_sequence: 1,
        };
        let fence_bad = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(2).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("gen"),
            ),
            next_commit_sequence: 1,
            next_outbox_sequence: 1,
        };
        let new_record = schema_meta_record_for_v1_to_v2(&existing, &v1_to_v2_migration(), "2000");
        let ok_bind = build_forward_bindings(&existing, &fence_ok, &new_record);
        let bad_bind = build_forward_bindings(&existing, &fence_bad, &new_record);
        assert_ne!(
            ok_bind.get("expected_state_fence"),
            bad_bind.get("expected_state_fence")
        );
        assert!(is_guard_conflict("schema_fence_guard_mismatch"));
        let sql = build_forward_sql();
        assert!(sql.contains("schema_fence_guard_mismatch"));
    }

    #[test]
    fn changed_sequence_is_rejected_by_forward_guard() {
        let v1 = v1_migration();
        let existing = schema_meta_record(&v1, "1000");
        let fence_ok = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("gen"),
            ),
            next_commit_sequence: 1,
            next_outbox_sequence: 1,
        };
        let fence_changed = FenceRecord {
            state_fence: fence_ok.state_fence.clone(),
            next_commit_sequence: 99,
            next_outbox_sequence: 1,
        };
        let new_record = schema_meta_record_for_v1_to_v2(&existing, &v1_to_v2_migration(), "2000");
        let ok_bind = build_forward_bindings(&existing, &fence_ok, &new_record);
        let changed_bind = build_forward_bindings(&existing, &fence_changed, &new_record);
        assert_ne!(
            ok_bind.get("expected_commit_sequence"),
            changed_bind.get("expected_commit_sequence")
        );
        let fence_changed2 = FenceRecord {
            state_fence: fence_ok.state_fence.clone(),
            next_commit_sequence: 1,
            next_outbox_sequence: 99,
        };
        let changed_bind2 = build_forward_bindings(&existing, &fence_changed2, &new_record);
        assert_ne!(
            ok_bind.get("expected_outbox_sequence"),
            changed_bind2.get("expected_outbox_sequence")
        );
        assert!(is_guard_conflict("schema_fence_guard_mismatch"));
    }

    #[test]
    fn unknown_top_level_field_fails_deserialization() {
        let v2 = v2_baseline_migration();
        let record = schema_meta_record(&v2, "1000");
        let mut value = serde_json::to_value(&record).expect("serialize");
        if let Value::Object(map) = &mut value {
            map.insert("extra_top_level".to_owned(), json!("boom"));
        }
        let res: Result<SchemaMetaRecord, _> = serde_json::from_value(value);
        assert!(
            res.is_err(),
            "deny_unknown_fields must reject extra top-level"
        );
    }

    #[test]
    fn unknown_history_entry_field_fails_deserialization() {
        let v2 = v2_baseline_migration();
        let record = schema_meta_record(&v2, "1000");
        let mut value = serde_json::to_value(&record).expect("serialize");
        if let Value::Object(map) = &mut value
            && let Some(Value::Array(arr)) = map.get_mut("migrations")
            && let Some(Value::Object(entry)) = arr.get_mut(0)
        {
            entry.insert("extra_entry_field".to_owned(), json!("boom"));
        }
        let res: Result<SchemaMetaRecord, _> = serde_json::from_value(value);
        assert!(
            res.is_err(),
            "deny_unknown_fields must reject extra history entry"
        );
    }

    #[test]
    fn schema_and_fence_records_round_trip_as_json() {
        let migration = v2_baseline_migration();
        let schema = schema_meta_record(&migration, "1000");
        let fence = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("generation"),
            ),
            next_commit_sequence: 2,
            next_outbox_sequence: 3,
        };
        let schema_json = serde_json::to_vec(&schema).expect("schema serialize");
        let fence_json = serde_json::to_vec(&fence).expect("fence serialize");
        assert_eq!(
            serde_json::from_slice::<SchemaMetaRecord>(&schema_json).expect("schema deserialize"),
            schema
        );
        assert_eq!(
            serde_json::from_slice::<FenceRecord>(&fence_json).expect("fence deserialize"),
            fence
        );
    }

    #[test]
    fn unknown_fence_record_field_fails_deserialization() {
        let fence = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("generation"),
            ),
            next_commit_sequence: 1,
            next_outbox_sequence: 1,
        };
        for extra_field in ["extra_fence_field", "id"] {
            let mut value = serde_json::to_value(&fence).expect("serialize");
            if let Value::Object(map) = &mut value {
                map.insert(extra_field.to_owned(), json!("boom"));
            }
            let result: Result<FenceRecord, _> = serde_json::from_value(value);
            assert!(
                result.is_err(),
                "deny_unknown_fields must reject extra fence field {extra_field}"
            );
        }
    }

    #[test]
    fn predecessor_cas_binds_every_predecessor_field_and_history_value() {
        let v1 = v1_migration();
        let existing = schema_meta_record(&v1, "1000");
        let fence = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("generation"),
            ),
            next_commit_sequence: 1,
            next_outbox_sequence: 1,
        };
        let next = schema_meta_record_for_v1_to_v2(&existing, &v1_to_v2_migration(), "2000");
        let bindings = build_forward_bindings(&existing, &fence, &next);
        for key in schema::forward_migration_expected_bindings() {
            assert!(bindings.contains_key(key), "missing binding {key}");
        }
        assert_eq!(bindings.get("expected_updated_at"), Some(&json!("1000")));

        let mut changed = existing.clone();
        changed.updated_at = "1001".to_owned();
        let changed_bindings = build_forward_bindings(&changed, &fence, &next);
        assert_ne!(
            bindings.get("expected_updated_at"),
            changed_bindings.get("expected_updated_at")
        );
        let mut changed_history = existing.clone();
        changed_history.migrations[0].migration_id = "tampered".to_owned();
        let changed_history_bindings = build_forward_bindings(&changed_history, &fence, &next);
        assert_ne!(
            bindings.get("expected_migration_0_id"),
            changed_history_bindings.get("expected_migration_0_id")
        );
        let sql = build_forward_sql();
        for key in [
            "expected_bridge_range",
            "expected_migration_state",
            "expected_migrations_len",
            "expected_migration_0_id",
            "expected_migration_0_checksum",
            "expected_migration_0_generation",
            "expected_updated_at",
        ] {
            assert!(sql.contains(key), "CAS SQL missing {key}");
        }
    }

    #[test]
    fn genesis_and_mixed_head_presence_choose_create_or_update_per_head() {
        assert_eq!(
            revision_write_template(true, false),
            schema::TX_CREATE_REVISION
        );
        assert_eq!(
            revision_write_template(false, false),
            schema::TX_CREATE_REVISION
        );
        assert_eq!(
            revision_write_template(false, true),
            schema::TX_UPSERT_REVISION
        );
        assert_eq!(
            ordering_write_template(true, false),
            schema::TX_CREATE_ORDERING
        );
        assert_eq!(
            ordering_write_template(false, false),
            schema::TX_CREATE_ORDERING
        );
        assert_eq!(
            ordering_write_template(false, true),
            schema::TX_UPSERT_ORDERING
        );
    }

    #[test]
    fn validation_query_keeps_schema_fence_heads_and_commit_in_one_transaction() {
        assert!(READ_VALIDATION_SNAPSHOT.starts_with("BEGIN TRANSACTION;"));
        assert!(READ_VALIDATION_SNAPSHOT.contains("schema_meta:current"));
        assert!(READ_VALIDATION_SNAPSHOT.contains("canonical_fence:current"));
        assert!(READ_VALIDATION_SNAPSHOT.contains("SELECT VALUE body FROM revision_head"));
        assert!(READ_VALIDATION_SNAPSHOT.ends_with("COMMIT TRANSACTION;"));
    }

    #[test]
    fn canonical_fence_record_reads_use_explicit_flat_projection() {
        let (_, request) = genesis_fixture();
        let recovery_request = StoreRecoveryRequest {
            contract_version: CONTRACT_VERSION,
            state_fence: request.state_fence,
            records: vec![request.owner_records[0].record_key()],
            include_receipts: true,
            include_jobs: true,
        };
        let expected_projection = "SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current";
        let recovery_sql = build_recovery_sql(&recovery_request);
        for (name, query) in [
            ("validation", READ_VALIDATION_SNAPSHOT),
            ("read_fence", schema::READ_FENCE),
            ("genesis_read", schema::READ_GENESIS_SCHEMA_AND_STATE),
            ("genesis_guard", schema::TX_GENESIS_SCHEMA_GUARD),
            ("recovery", recovery_sql.as_str()),
        ] {
            assert!(query.contains(expected_projection), "{name} projection");
            assert!(
                !query.contains("SELECT VALUE body FROM ONLY canonical_fence:current"),
                "{name} must not read the legacy body field"
            );
            assert!(
                !query.contains("SELECT * FROM ONLY canonical_fence:current"),
                "{name} must not admit the SurrealDB id field"
            );
        }
    }

    #[test]
    fn validation_result_indexes_admit_a_fresh_empty_canonical_store() {
        let migration = v2_baseline_migration();
        let fence = StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        );
        let snapshot = build_validation_snapshot(
            Some(schema_meta_record(&migration, "1000")),
            Some(FenceRecord {
                state_fence: fence,
                next_commit_sequence: 1,
                next_outbox_sequence: 1,
            }),
            Vec::new(),
            &migration.generation_after,
            1_000,
            Value::Null,
        )
        .expect("fresh snapshot");
        assert!(snapshot.revision_heads.is_empty());
        assert_eq!(snapshot.validation_revision, 1);
    }

    #[test]
    fn validation_rejects_missing_or_malformed_fence() {
        let migration = v2_baseline_migration();
        let missing = build_validation_snapshot(
            Some(schema_meta_record(&migration, "1000")),
            None,
            Vec::new(),
            &migration.generation_after,
            1_000,
            Value::Null,
        );
        assert_eq!(missing, Err(AdapterError::Store(StoreError::Unavailable)));

        let malformed = build_validation_snapshot(
            Some(schema_meta_record(&migration, "1000")),
            Some(FenceRecord {
                state_fence: StateFence::new(
                    eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                    eliot_contracts::ResourceGeneration::new(1).expect("generation"),
                ),
                next_commit_sequence: 0,
                next_outbox_sequence: 1,
            }),
            Vec::new(),
            &migration.generation_after,
            1_000,
            Value::Null,
        );
        assert_eq!(malformed, Err(AdapterError::PartialOutcome));
    }

    #[test]
    fn readiness_oracle_observed_1_0_0_is_migration_required_and_2_0_0_is_ready() {
        let expected = SchemaGeneration::v2();
        let observed_v1 = Some(schema::GENERATION_V1.to_owned());
        let observed_v2 = Some(schema::GENERATION_V2.to_owned());
        assert!(matches!(
            readiness_from_observation(observed_v1, &expected),
            SemanticReadiness::MigrationRequired { .. }
        ));
        assert!(matches!(
            readiness_from_observation(observed_v2, &expected),
            SemanticReadiness::Ready { .. }
        ));
        assert!(matches!(
            readiness_from_observation(None, &expected),
            SemanticReadiness::MigrationRequired { .. }
        ));
    }

    #[test]
    fn ready_v2_requires_a_valid_canonical_fence() {
        let expected = SchemaGeneration::v2();
        let ready = readiness_from_observation(Some(schema::GENERATION_V2.to_owned()), &expected);
        assert!(matches!(ready, SemanticReadiness::Ready { .. }));
        assert!(matches!(
            readiness_with_fence(ready.clone(), None, &expected),
            Ok(SemanticReadiness::MigrationRequired { observed: None, .. })
        ));

        let malformed = FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("generation"),
            ),
            next_commit_sequence: 0,
            next_outbox_sequence: 1,
        };
        assert_eq!(
            readiness_with_fence(ready, Some(malformed), &expected),
            Err(AdapterError::PartialOutcome)
        );
    }
}
