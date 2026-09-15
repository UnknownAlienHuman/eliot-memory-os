//! Database-backed store operations: atomic apply, reconciliation reads,
//! named reads, health and migration.
//!
//! All `SurrealQL` and physical table access stays inside this module and
//! [`crate::schema`]. The public boundary only ever carries store-API types.

use std::collections::BTreeSet;

use crate::SurrealStoreAdapter;
use crate::config::{SchemaGeneration, SurrealAdapterConfig};
use crate::error::AdapterError;
use crate::plan::select_apply_plan;
use crate::plan::{self, build_receipt, validate_receipt_identity, validate_revision_heads};
use crate::readiness::{CompiledMigration, MigrationReceipt, SemanticReadiness};
use crate::{client, schema};
#[cfg(test)]
use eliot_store_api::{
    CONTRACT_VERSION, OperationId, StoreGenesisRequest, validate_genesis_receipt_envelope,
};
use eliot_store_api::{
    ExactJsonBytes, OrderingHead, OrderingHeadExpectation, OrderingScopeId, RecoveryRecord,
    RevisionHead, RevisionHeadExpectation, RevisionKey, StateFence, StoreError,
    StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt, generated_operation_manifests,
    operation_manifest_set_digest,
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
    let errors = response.take_errors();
    if !errors.is_empty() {
        // S1 #775 real-provider compatibility: reads against never-defined
        // tables observe absent-table, which preflight translates into
        // "not yet migrated" (`None`). Every other error class keeps its
        // existing reconciling disposition.
        if errors.iter().all(|error| client::is_absent_table(error)) {
            return Ok(None);
        }
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
///
/// Legacy entry point: no operation claims a payload authority, so planning
/// keeps the exact historical digest path. Authority-carrying callers use
/// [`apply_prepared_with_authority`].
pub(crate) async fn apply_prepared(
    adapter: &SurrealStoreAdapter,
    ctx: &eliot_store_api::RequestMeta,
    transition: eliot_store_api::PreparedTransition,
    expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
    expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
) -> Result<WriteReceipt, AdapterError> {
    let authorities: Vec<Option<ExactJsonBytes>> = vec![None; transition.named_operations.len()];
    apply_prepared_with_authority(
        adapter,
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
        &authorities,
    )
    .await
}

/// Atomically applies one exact S-01 transition with per-operation payload
/// authorities bound in (slice C2, issue #19).
///
/// `authorities` aligns 1:1 with the transition's named operations and
/// carries the original authority values (never re-parsed from a
/// re-serialized `Value`): entries with at least one claimed authority plan
/// through the authority-carrying path, all-`None` entries keep the legacy
/// path. The admitted-operation gate ([`validate_transition`]) runs before
/// any provider I/O in both cases.
pub(crate) async fn apply_prepared_with_authority(
    adapter: &SurrealStoreAdapter,
    ctx: &eliot_store_api::RequestMeta,
    transition: eliot_store_api::PreparedTransition,
    expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
    expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    authorities: &[Option<ExactJsonBytes>],
) -> Result<WriteReceipt, AdapterError> {
    validate_transition(ctx, &transition)?;

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

    let plan = select_apply_plan(
        &transition,
        authorities,
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

/// Enforces the same admitted operation before staging and commit (slice C2).
///
/// The pre-stage gate binds, in order: the generic transition shape
/// ([`PreparedTransition::validate`], which also aligns security scope/proof
/// material and the effect ceiling with the transition fence), the active
/// generated catalogue set ([`generated_operation_manifests`] with its
/// [`operation_manifest_set_digest`] well-formedness proof and
/// [`PreparedTransition::validate_against_catalogue`] membership/digest/bound
/// checks, covering the original admitted plan identity through the
/// operation-manifest digest), and the caller/transition fence equality. A
/// set-digest mismatch, an unknown or extra operation, a scope/effect excess,
/// or a fence mismatch fails closed here, before any provider I/O, receipt,
/// or fence advance. There is no aggregate-manifest fallback.
fn validate_transition(
    ctx: &eliot_store_api::RequestMeta,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    ctx.validate().map_err(StoreError::Foundation)?;
    transition.validate()?;
    let entries = generated_operation_manifests().map_err(AdapterError::Store)?;
    operation_manifest_set_digest(&entries).map_err(AdapterError::Store)?;
    transition
        .validate_against_catalogue(&entries)
        .map_err(AdapterError::Store)?;
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

#[cfg(test)]
mod admitted_operation_gate_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationIdentity, OperationManifestDigest, OrderingScopeId, ScopeId, SecurityContext,
        TransitionClass, genesis_manifest,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        use eliot_contracts::{EpochId, EpochLineageId};
        use std::num::NonZeroU64;
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("canonical test lineage-A"),
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence(sequence: u64) -> StateFence {
        StateFence::new(
            test_epoch(sequence),
            eliot_contracts::ResourceGeneration::genesis(),
        )
    }

    fn test_context(fence: &StateFence) -> eliot_store_api::RequestMeta {
        eliot_store_api::RequestMeta {
            request_id: eliot_contracts::RequestId::new("request-gate").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: eliot_contracts::ProductId::new("product-gate").expect("product"),
            source_id: eliot_contracts::SourceId::new("source-gate").expect("source"),
            state_fence: fence.clone(),
            clock: eliot_contracts::ClockReading::default(),
        }
    }

    fn transition_with(
        fence: &StateFence,
        manifest_digest: OperationManifestDigest,
        class: TransitionClass,
        ceiling: eliot_store_api::EffectClass,
        named_operations: Vec<eliot_store_api::NamedMutationRequest>,
    ) -> eliot_store_api::PreparedTransition {
        eliot_store_api::PreparedTransition {
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new("op-gate").expect("operation"),
                idempotency_key: "idem-gate".to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence.clone(),
            scope_id: ScopeId::new("scope-gate").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-gate").expect("ordering")],
            transition_class: class,
            requested_effect_ceiling: ceiling,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: manifest_digest,
            named_operations,
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        }
    }

    fn mutation_operation() -> eliot_store_api::NamedMutationRequest {
        NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!("op-gate"))]),
        }
    }

    fn audit_operation() -> eliot_store_api::NamedMutationRequest {
        NamedMutationRequest {
            operation: NamedMutationOperation::AppendAuditEvent,
            parameters: BTreeMap::from([
                ("operation_id".to_owned(), json!("op-gate")),
                ("idempotency_key".to_owned(), json!("idem-gate")),
                ("session_id".to_owned(), json!("session-gate")),
                ("access_digest".to_owned(), json!("a".repeat(64))),
                ("action_digest".to_owned(), json!("b".repeat(64))),
                ("expected_revision".to_owned(), json!("7")),
            ]),
        }
    }

    fn lifecycle_operation() -> eliot_store_api::NamedMutationRequest {
        NamedMutationRequest {
            operation: NamedMutationOperation::ApplyLifecyclePolicy,
            parameters: BTreeMap::from([
                ("action".to_owned(), json!("keep")),
                ("base_view_digest".to_owned(), json!("a".repeat(64))),
                ("candidate_digest".to_owned(), json!("b".repeat(64))),
                (
                    "candidate_package_digest".to_owned(),
                    json!("c".repeat(64)),
                ),
                ("skill_id".to_owned(), json!("skill-gate")),
                ("verifier_ref".to_owned(), json!("verifier-gate")),
            ]),
        }
    }

    fn recovery_operation() -> eliot_store_api::NamedMutationRequest {
        NamedMutationRequest {
            operation: NamedMutationOperation::ReconcileRecovery,
            parameters: BTreeMap::from([
                ("problem_id".to_owned(), json!("problem-gate")),
                ("expected_problem_revision".to_owned(), json!("7")),
                ("attempt_digest".to_owned(), json!("a".repeat(64))),
                ("effect_digest".to_owned(), json!("b".repeat(64))),
                (
                    "operation_manifest_digest".to_owned(),
                    json!("c".repeat(64)),
                ),
                (
                    "artifact_binding_digest".to_owned(),
                    json!("b".repeat(64)),
                ),
                ("fence_digest".to_owned(), json!("d".repeat(64))),
                ("observation_operation_id".to_owned(), json!("op-gate")),
                ("observation_record_id".to_owned(), json!("record-gate")),
                (
                    "observation_request_digest".to_owned(),
                    json!("e".repeat(64)),
                ),
            ]),
        }
    }

    fn task_state_operation() -> eliot_store_api::NamedMutationRequest {
        NamedMutationRequest {
            operation: NamedMutationOperation::UpdateTaskState,
            parameters: BTreeMap::from([
                ("task_id".to_owned(), json!("task-gate")),
                ("event_id".to_owned(), json!("event-gate")),
                ("from".to_owned(), json!("PROPOSED")),
                ("to".to_owned(), json!("OPEN")),
                ("expected_revision".to_owned(), json!("1")),
                ("actor_ref".to_owned(), json!("actor-gate")),
            ]),
        }
    }

    #[test]
    fn genesis_shaped_transition_passes_the_pre_stage_gate() {
        let fence = test_fence(1);
        let context = test_context(&fence);
        let manifest = genesis_manifest().expect("genesis entry is active");
        let transition = transition_with(
            &fence,
            manifest.digest.clone(),
            TransitionClass::RecoverySchema,
            EffectClass::ReversibleMutation,
            Vec::new(),
        );
        assert!(
            validate_transition(&context, &transition).is_ok(),
            "genesis/bootstrap shape stays admitted"
        );
    }

    #[test]
    fn pre_stage_digest_mismatch_leaves_no_receipt_or_fence_effect() {
        // The gate runs before any provider I/O, receipt, or fence advance
        // (see `apply_prepared_with_authority` ordering): every rejection
        // below is deterministic and repeatable with no durable effect.
        let fence = test_fence(1);
        let context = test_context(&fence);
        let entries = generated_operation_manifests().expect("active catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest computes");

        // Stale manifest digest on a mutation: membership cannot even start.
        let stale = transition_with(
            &fence,
            OperationManifestDigest::new("stale-manifest-digest").expect("digest"),
            TransitionClass::CaptureCandidate,
            EffectClass::Candidate,
            vec![mutation_operation()],
        );
        assert_eq!(
            validate_transition(&context, &stale),
            Err(AdapterError::Store(StoreError::ManifestMismatch))
        );
        // Current set digest but still-unadmitted mutation entry: fail-closed
        // for the remaining mutations. `CaptureObservation`,
        // `AppendAuditEvent`, `ApplyLifecyclePolicy`, `ReconcileRecovery`,
        // and `UpdateTaskState` are admitted (their handler/schema/consumer
        // triples are proven); this proof uses `ApplyEpistemicRevision`
        // (still unadmitted).
        let unadmitted = transition_with(
            &fence,
            set_digest.clone(),
            TransitionClass::Epistemic,
            EffectClass::Candidate,
            vec![NamedMutationRequest {
                operation: NamedMutationOperation::ApplyEpistemicRevision,
                parameters: BTreeMap::new(),
            }],
        );
        assert_eq!(
            validate_transition(&context, &unadmitted),
            Err(AdapterError::Store(StoreError::UnknownOperation))
        );
        // Admitted `CaptureObservation` with current set digest and approved
        // subject params passes the pre-stage gate.
        let admitted = transition_with(
            &fence,
            set_digest.clone(),
            TransitionClass::CaptureCandidate,
            EffectClass::Candidate,
            vec![mutation_operation()],
        );
        assert!(
            validate_transition(&context, &admitted).is_ok(),
            "admitted CaptureObservation passes the pre-stage gate"
        );
        // Admitted `AppendAuditEvent` with current set digest and approved
        // receipt-bound params passes the pre-stage gate.
        let admitted_audit = transition_with(
            &fence,
            set_digest.clone(),
            TransitionClass::CaptureCandidate,
            EffectClass::Candidate,
            vec![audit_operation()],
        );
        assert!(
            validate_transition(&context, &admitted_audit).is_ok(),
            "admitted AppendAuditEvent passes the pre-stage gate"
        );
        // Admitted `ApplyLifecyclePolicy` with current set digest and approved
        // lifecycle-policy params passes the pre-stage gate.
        let admitted_lifecycle = transition_with(
            &fence,
            set_digest.clone(),
            TransitionClass::LifecyclePolicy,
            EffectClass::ReversibleMutation,
            vec![lifecycle_operation()],
        );
        assert!(
            validate_transition(&context, &admitted_lifecycle).is_ok(),
            "admitted ApplyLifecyclePolicy passes the pre-stage gate"
        );
        // Admitted `ReconcileRecovery` with current set digest and approved
        // problem-leg recovery params passes the pre-stage gate.
        let admitted_recovery = transition_with(
            &fence,
            set_digest.clone(),
            TransitionClass::RecoverySchema,
            EffectClass::ReversibleMutation,
            vec![recovery_operation()],
        );
        assert!(
            validate_transition(&context, &admitted_recovery).is_ok(),
            "admitted ReconcileRecovery passes the pre-stage gate"
        );
        // Admitted `UpdateTaskState` with current set digest and approved
        // task-control params passes the pre-stage gate.
        let admitted_task = transition_with(
            &fence,
            set_digest,
            TransitionClass::TaskControl,
            EffectClass::ReversibleMutation,
            vec![task_state_operation()],
        );
        assert!(
            validate_transition(&context, &admitted_task).is_ok(),
            "admitted UpdateTaskState passes the pre-stage gate"
        );
        // Fence divergence between caller context and transition.
        let manifest = genesis_manifest().expect("genesis entry is active");
        let drifted = transition_with(
            &test_fence(2),
            manifest.digest.clone(),
            TransitionClass::RecoverySchema,
            EffectClass::ReversibleMutation,
            Vec::new(),
        );
        assert_eq!(
            validate_transition(&context, &drifted),
            Err(AdapterError::Store(StoreError::FenceMismatch))
        );
        // Deterministic: repeating the rejections changes nothing.
        assert_eq!(
            validate_transition(&context, &stale),
            Err(AdapterError::Store(StoreError::ManifestMismatch))
        );
    }
}
