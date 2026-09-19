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
use crate::write_execution::{
    AttemptOutcome, ExclusiveOpKind, ExecutableAttempt, OpExecution, ProviderGate,
    ReconcileOutcome, ReservedAttemptTransport, current_time_ms,
};
use crate::{client, schema};
#[cfg(test)]
use eliot_store_api::{CONTRACT_VERSION, validate_genesis_receipt_envelope};
use eliot_store_api::{
    ERASURE_PARAM_OPERATION_ID, ERASURE_PARAM_SUBJECT, ERASURE_PARAM_SURFACES, ExactJsonBytes,
    NamedMutationOperation, OperationId, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    RecoveryRecord, RequestMeta, ReservedWriteRequest, RevisionHead, RevisionHeadExpectation,
    RevisionKey, StateFence, StoreError, StoreGenesisRequest, StoreRecoveryRequest,
    StoreRecoverySnapshot, TransitionClass, WriteReceipt, decode_erasure_surfaces,
    generated_operation_manifests, operation_manifest_set_digest,
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
use atomic_write::{TxLane, to_value, write_transaction};
#[cfg(test)]
use atomic_write::{ordering_write_template, revision_write_template};
use empty_migration::handle_empty_migration;
pub(crate) async fn initialize_genesis(
    adapter: &SurrealStoreAdapter,
    context: &RequestMeta,
    request: StoreGenesisRequest,
) -> Result<WriteReceipt, AdapterError> {
    // S-CONC-EXECUTE (issue #993): genesis runs through the exclusive
    // drain gate when a generation is installed, mirroring migrations.
    let Some(execution) = adapter.execution_handle() else {
        return genesis::initialize_genesis_direct(adapter, context, request).await;
    };
    let transport = ProviderReservedTransport { adapter };
    let (_, receipt) = execution
        .drain_for_migration(
            ExclusiveOpKind::Genesis,
            current_time_ms(),
            &transport,
            || genesis::initialize_genesis_direct(adapter, context, request),
        )
        .await?;
    Ok(receipt)
}

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
            client::RpcTransport::connect_with_limits(
                &adapter.config,
                &adapter.provider_process_lease,
                adapter.client_limits,
            )
            .await
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
///
/// When a write-execution generation is installed, the migration runs
/// through its exclusive drain gate: normal admission closes, queued work
/// dispositions without effects, every possible in-flight effect is
/// awaited and reconciled, and only a verified quiescence grants
/// exclusivity to the existing operation below. Without an installed
/// generation this keeps the exact legacy entrypoint.
pub(crate) async fn apply_migration(
    adapter: &SurrealStoreAdapter,
    migration: &CompiledMigration,
    observed_clock: &eliot_platform::ClockObservation,
    state_fence: &StateFence,
) -> Result<MigrationReceipt, AdapterError> {
    let Some(execution) = adapter.execution_handle() else {
        return apply_migration_direct(adapter, migration, observed_clock, state_fence).await;
    };
    let transport = ProviderReservedTransport { adapter };
    let (_, receipt) = execution
        .drain_for_migration(
            ExclusiveOpKind::Migration,
            current_time_ms(),
            &transport,
            || apply_migration_direct(adapter, migration, observed_clock, state_fence),
        )
        .await?;
    Ok(receipt)
}

/// Applies one explicit migration and records the new schema generation.
async fn apply_migration_direct(
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
/// Bounded allocation attempts for one admitted operation (S-CONC-TX, #989).
///
/// One initial canonical transaction plus this many allocation-contention
/// retries. The bound absorbs racing disjoint-scope writers without an
/// unbounded CAS spin; exhaustion reports exact allocation contention, never
/// a false semantic conflict and never an unknown outcome.
///
/// S-CONC-TX rework: this production entry holds no process-global write
/// guard across the allocation loop below. Independent transitions overlap
/// their fence/head reads, allocation attempts, and bounded retries; the
/// canonical transaction's fence CAS plus its revision and ordering head
/// predicates arbitrate shared sequence allocation, so disjoint scopes
/// commit concurrently while genuine conflicts fail closed. Each provider
/// RPC stays atomic on its own session socket. The process-global write
/// lock now guards only the migration and erasure-dispatch entrypoints,
/// never normal-write allocation network I/O.
const MAX_ALLOCATION_RETRIES: u32 = 7;

pub(crate) async fn apply_prepared_with_authority(
    adapter: &SurrealStoreAdapter,
    ctx: &eliot_store_api::RequestMeta,
    transition: eliot_store_api::PreparedTransition,
    expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
    expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    authorities: &[Option<ExactJsonBytes>],
) -> Result<WriteReceipt, AdapterError> {
    // S-CONC-EXECUTE (issue #993): a concurrent execution generation owns
    // the writable root, so the old unreserved path must not bypass its
    // scheduler. The serial profile explicitly admits this legacy lane.
    if let Some(execution) = adapter.execution_handle()
        && !execution.unreserved_apply_admission().allowed()
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "store.write_path",
            reason: "unreserved apply is not admitted under the concurrent execution generation",
        }));
    }
    validate_transition(ctx, &transition)?;

    let db = client(adapter).await?;
    ensure_ready(adapter, db).await?;

    apply_with_retry(
        adapter,
        db,
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
        authorities,
        TxLane::Facade,
    )
    .await
}

/// Explicit test/private allocation seam (S-CONC-TX, issue #989).
///
/// Runs the exact production attempt loop over the admitted #987 pooled
/// read lane for pre-transaction reads and the pooled normal-write lane
/// for the canonical transaction (one checked-out session per concurrent
/// task). Since the rework, the production entry above is equally
/// unguarded and arbitrates through the same fence CAS and head
/// predicates; this seam never disables safety globally, never compiles
/// outside `#[cfg(test)]`, and remains as additional pooled-lane
/// coverage — never as the only concurrent path.
#[cfg(test)]
pub(crate) async fn apply_prepared_without_write_guard(
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

    apply_with_retry(
        adapter,
        db,
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
        authorities,
        TxLane::PooledWrite,
    )
    .await
}

/// Applies one sealed reserved write through the installed concurrent
/// execution generation (S-CONC-EXECUTE, issue #993).
///
/// Runs the existing admitted receiving boundary first, then queues the
/// operation behind the generation's bounded scheduler and executes the
/// ready batch over the pooled normal-write lane. Without an installed
/// concurrent generation this preserves the default refusal semantics for
/// backends without scheduler support. A submitted operation that finds
/// no ready execution in this batch (blocked behind a predecessor or an
/// uncertain scope) reports retryable unavailability: nothing was
/// fabricated and the caller reconciles or retries by identity.
pub(crate) async fn apply_reserved_write(
    adapter: &SurrealStoreAdapter,
    request: ReservedWriteRequest,
) -> Result<WriteReceipt, AdapterError> {
    request.validate().map_err(AdapterError::Store)?;
    let Some(execution) = adapter.execution_handle() else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if !execution.is_concurrent() {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request.transition.identity.operation_id.clone();
    execution.submit_reserved(request, current_time_ms())?;
    let transport = ProviderReservedTransport { adapter };
    let outcomes = execution
        .run_ready_batch(current_time_ms(), &transport)
        .await?;
    for outcome in &outcomes {
        if outcome.operation_id() == &operation_id {
            return op_outcome_to_receipt(outcome);
        }
    }
    Err(AdapterError::Store(StoreError::Unavailable))
}

/// Maps one executed reserved outcome onto the client boundary.
fn op_outcome_to_receipt(outcome: &OpExecution) -> Result<WriteReceipt, AdapterError> {
    match outcome {
        OpExecution::Committed { receipt, .. } => Ok(receipt.as_ref().clone()),
        OpExecution::Rejected { error, .. } => Err(AdapterError::Store(error.clone())),
        OpExecution::DeadLetter { .. } => Err(AdapterError::Store(StoreError::InvalidField {
            field: "store.write_disposition",
            reason: "dead letter with proven non-application",
        })),
        OpExecution::CancelledBeforeEffect { .. } | OpExecution::DrainedWithoutEffect { .. } => {
            Err(AdapterError::Store(StoreError::Unavailable))
        }
        OpExecution::UnknownRetained { .. } => {
            Err(AdapterError::Store(StoreError::MissingReceiptEnvelope))
        }
        OpExecution::ExecutionError { error, .. } => Err(error.clone()),
    }
}

/// Production reserved attempt over the admitted #987 pooled normal-write
/// lane (S-CONC-EXECUTE, issue #993).
///
/// Mirrors the [`apply_prepared_with_authority`] preamble exactly —
/// admitted-operation gate, transport, readiness — and runs the same #989
/// bounded attempt loop, except on `TxLane::PooledWrite` so concurrent
/// tasks execute on real separate sessions instead of serializing on the
/// facade socket. No transaction SQL is duplicated: the canonical attempt
/// below is shared. Authorities stay all-`None` (the legacy digest path),
/// matching the unreserved entry, because the #990 sealed shape carries no
/// per-operation authority material.
pub(crate) async fn apply_reserved_attempt(
    adapter: &SurrealStoreAdapter,
    attempt: &ExecutableAttempt,
) -> Result<WriteReceipt, AdapterError> {
    let authorities: Vec<Option<ExactJsonBytes>> =
        vec![None; attempt.transition.named_operations.len()];
    validate_transition(&attempt.context, &attempt.transition)?;
    let db = client(adapter).await?;
    ensure_ready(adapter, db).await?;
    apply_with_retry(
        adapter,
        db,
        &attempt.context,
        attempt.transition.clone(),
        attempt.expected_revision_heads.clone(),
        attempt.expected_ordering_heads.clone(),
        &authorities,
        TxLane::PooledWrite,
    )
    .await
}

/// Production transport behind the execution orchestration: pooled-lane
/// attempts, gate reads against the durable fence, and exact receipt
/// reconciliation. Holds no scheduler lock and no global write mutex.
pub(crate) struct ProviderReservedTransport<'a> {
    adapter: &'a SurrealStoreAdapter,
}

impl ReservedAttemptTransport for ProviderReservedTransport<'_> {
    async fn read_submission_gate(
        &self,
        _execution: &crate::write_execution::WriteExecution,
        attempt: &ExecutableAttempt,
        now_ms: u64,
    ) -> ProviderGate {
        let Ok(db) = client(self.adapter).await else {
            return ProviderGate::closed();
        };
        let Ok(fence) = read_fence(db, &self.adapter.config).await else {
            return ProviderGate::closed();
        };
        // An absent fence admits nothing: the reserved path requires a
        // verified admission condition before provider execution. A present
        // fence must match the admitted transition fence exactly.
        let fence_matches = fence
            .as_ref()
            .is_some_and(|fence| fence.state_fence == attempt.transition.state_fence);
        let not_expired =
            u64::try_from(attempt.expires_at_ms).is_ok_and(|expires| now_ms < expires);
        ProviderGate {
            owner_current: true,
            fence_matches,
            not_expired,
        }
    }

    async fn execute_attempt(
        &self,
        _execution: &crate::write_execution::WriteExecution,
        attempt: &ExecutableAttempt,
    ) -> AttemptOutcome {
        match apply_reserved_attempt(self.adapter, attempt).await {
            Ok(receipt) => AttemptOutcome::Committed(Box::new(receipt)),
            Err(error) => map_attempt_error(error),
        }
    }

    async fn reconcile_unknown(
        &self,
        _execution: &crate::write_execution::WriteExecution,
        operation_id: &OperationId,
    ) -> ReconcileOutcome {
        match read_receipt(self.adapter, operation_id.clone()).await {
            Ok(Some(receipt)) => ReconcileOutcome::Committed(Box::new(receipt)),
            // Absence of a receipt is not proof of non-application: the
            // commit may have landed without a readable receipt yet. Stay
            // unknown and reconcile again later; restart recovery owns the
            // terminal escape hatch through its durable denominator.
            Ok(None) | Err(_) => ReconcileOutcome::StillUnknown,
        }
    }
}

/// Maps one production attempt failure onto the orchestration outcome.
///
/// Local defects that provably precede any provider send dispose as
/// `Cancelled` (safe to resubmit under the same identity); deterministic
/// conflicts and malformed inputs dispose as `Rejected` with the exact
/// cause; everything ambiguous — including any transport loss inside the
/// attempt window, which is treated as possible-submission per I14.21 —
/// stays `Unknown` for exact receipt reconciliation. `AllocationContention`
/// cannot reach here unhandled: the #989 loop retries it internally and
/// only surfaces exhaustion, which proved no commit for this identity.
fn map_attempt_error(error: AdapterError) -> AttemptOutcome {
    match error {
        AdapterError::Store(store) => match store {
            StoreError::IdentityConflict
            | StoreError::RevisionConflict
            | StoreError::OrderingConflict
            | StoreError::FenceMismatch
            | StoreError::InvalidField { .. }
            | StoreError::Empty { .. }
            | StoreError::Duplicate { .. }
            | StoreError::Foundation(_)
            | StoreError::Security(_)
            | StoreError::Receipt(_)
            | StoreError::UnknownOperation
            | StoreError::ManifestMismatch
            | StoreError::TransitionClassExceeded
            | StoreError::EffectCeilingExceeded
            | StoreError::InvalidProjection
            | StoreError::InvalidOutbox
            | StoreError::InvalidReceipt
            | StoreError::TransitionDigestMismatch { .. }
            | StoreError::ReceiptNotFound
            | StoreError::PayloadTooLarge => AttemptOutcome::Rejected(store),
            StoreError::Serialization(_) => AttemptOutcome::Cancelled,
            StoreError::MissingReceiptEnvelope | StoreError::Unavailable => {
                AttemptOutcome::Unknown { retry_after_ms: 0 }
            }
        },
        AdapterError::ProviderConflict => AttemptOutcome::Rejected(StoreError::RevisionConflict),
        // Pre-effect dispositions without provider effects: allocation
        // exhaustion proved no commit for this identity inside the #989
        // loop, and the local defects below all precede any provider send.
        AdapterError::AllocationContention { .. }
        | AdapterError::MigrationRequired
        | AdapterError::Config(_)
        | AdapterError::Serialization(_)
        | AdapterError::NamedOperationUnavailable { .. } => AttemptOutcome::Cancelled,
        AdapterError::UnknownOutcome { .. }
        | AdapterError::PartialOutcome
        | AdapterError::UnknownMigrationOutcome { .. }
        | AdapterError::ProviderUnavailable => AttemptOutcome::Unknown { retry_after_ms: 0 },
    }
}

/// Production-path transaction-attempt rendezvous (S-CONC-TX, issue #989).
///
/// When the adapter's rendezvous is armed (only the
/// `production_path_disjoint_writers_overlap_and_conflicts_fail_closed`
/// integration test arms it), the first allocation attempt of each writer
/// blocks here — after admission, the idempotency/fence/head reads, and the
/// plan build, before the canonical transaction is sent — until every party
/// has arrived. Both public production calls therefore reach the same
/// post-admission transaction-attempt rendezvous before either is allowed to
/// continue, so a single serialized production write lane (for example the
/// removed process-global write guard re-added over this loop) deadlocks
/// here instead: the first writer waits for a second writer that can never
/// arrive, and the bounded wait below fails the attempt rather than hanging
/// the suite.
///
/// Production-safe when unarmed (the only state reachable outside that
/// test: no production caller arms it): one uncontended `std` mutex lock
/// plus an `is_none` check, then return — no await, no allocation, no
/// provider I/O, no error-taxonomy change. The mutex is never held across an
/// await and never contended in production, so unarmed writers neither block
/// nor serialize on it.
///
/// First-attempt only (callers invoke this solely while `semantic_plan` is
/// still `None`): allocation-contention retries re-enter alone after the
/// partner has moved on, so a second wait would stall until the bound below.
async fn rendezvous_before_transaction(adapter: &SurrealStoreAdapter) -> Result<(), AdapterError> {
    let Some(barrier) = adapter.tx_rendezvous_barrier() else {
        return Ok(());
    };
    tokio::time::timeout(std::time::Duration::from_mins(1), barrier.wait())
        .await
        .map_err(|_| AdapterError::ProviderUnavailable)?;
    Ok(())
}

/// Bounded in-transaction allocation loop (S-CONC-TX, issue #989).
///
/// Allocation lives in the canonical transaction: every attempt re-reads the
/// fence and the union heads, re-verifies every declared expected revision
/// and ordering head plus the fence, recomputes only the allocation-derived
/// plan values through [`plan::recompute_allocation`] under the unchanged
/// semantic input/scope/fence/expected-head contract, and commits
/// event/projection/relation/head/outbox/idempotency/receipt effects
/// atomically with the fence CAS.
///
/// Retry discipline: only a provider-classified allocation contention
/// (`AllocationContention`, proved-not-committed: the fence CAS precedes the
/// receipt create) re-enters the loop, and only after the next iteration
/// re-proves absence through the idempotency read — a concurrent same-op
/// winner observed there replays its original receipt instead of
/// re-committing. Deterministic semantic conflicts, fence mismatches, and
/// every unknown outcome return immediately: a transport timeout,
/// cancellation, missing/malformed response, or possibly committed provider
/// error is never retried and never allocates another operation; it requires
/// exact same-operation receipt reconciliation before replay.
#[allow(
    clippy::too_many_arguments,
    reason = "the apply attempt carries the exact admitted contract: context, transition, both head sets, authorities, lane"
)]
async fn apply_with_retry(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    ctx: &eliot_store_api::RequestMeta,
    transition: eliot_store_api::PreparedTransition,
    expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
    expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    authorities: &[Option<ExactJsonBytes>],
    lane: TxLane,
) -> Result<WriteReceipt, AdapterError> {
    let mut retries = 0u32;
    let mut erasure_dispatched = false;
    // The full semantic plan is established once, on the first attempt.
    // Allocation-contention retries re-enter ONLY through
    // `plan::recompute_allocation` below, never through the full planner,
    // so retry planning owns allocation-derived values alone and cannot
    // duplicate or drift from semantic logic by construction.
    let mut semantic_plan: Option<plan::ApplyPlan> = None;
    loop {
        match read_idempotency(db, &adapter.config, ctx, &transition).await? {
            Idempotency::Replay(receipt) => {
                validate_receipt_identity(&receipt, ctx, &transition)?;
                return Ok(receipt);
            }
            Idempotency::Conflict => {
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
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
        let current_revisions =
            read_revision_heads_inner(db, &adapter.config, &revision_keys).await?;
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

        // Issue #1712: the admitted erasure operation dispatches its recorded
        // intent-before-delete plan here, after every fallible precondition
        // and before receipt planning. Dispatched once per operation: the
        // sealed intent/outcome rows make a same-operation re-dispatch replay
        // without duplicate destructive work, but allocation retries must not
        // re-dispatch what the first attempt already sealed. Same-operation
        // replay returns the sealed outcomes without duplicate destructive
        // work; a lost commit response reconciles by same-operation retry
        // through the receipt path above, never by blind retry.
        if transition.transition_class == TransitionClass::Erasure && !erasure_dispatched {
            let intent = surreal_intent_from_transition(&transition)?;
            apply_surreal_erasure(adapter, &intent).await?;
            erasure_dispatched = true;
        }

        let first_attempt = semantic_plan.is_none();
        let plan = if let Some(semantic) = &semantic_plan {
            plan::recompute_allocation(semantic, next_commit_sequence, next_outbox_sequence)?
        } else {
            let full = plan::select_apply_plan(
                &transition,
                authorities,
                &current_revisions,
                &current_orderings,
                next_commit_sequence,
                next_outbox_sequence,
            )?;
            semantic_plan = Some(full.clone());
            full
        };
        let receipt = build_receipt(ctx, &transition, &plan)?;

        // S-CONC-TX production-path rendezvous (issue #989): first attempt
        // only, after every pre-transaction read and the plan build, before
        // the canonical transaction is sent. See
        // `rendezvous_before_transaction`.
        if first_attempt {
            rendezvous_before_transaction(adapter).await?;
        }

        match write_transaction(
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
            lane,
        )
        .await
        {
            Ok(()) => {
                validate_receipt_identity(&receipt, ctx, &transition)?;
                return Ok(receipt);
            }
            Err(AdapterError::AllocationContention { .. }) if retries < MAX_ALLOCATION_RETRIES => {
                retries += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// 688-B: the adapter's apply-path erasure execution.
///
/// The erasure protocol needs the same intent-before-dispatch gate as the
/// reference store: a `record_erasure_intent` step persists the intent row(s)
/// in the same atomic transaction BEFORE any destructive statement (see the
/// intent-before-delete template in `atomic_write`). This gate refuses
/// fail-closed with zero destructive effects when no recorded intent exists
/// ([`StoreError::ReceiptNotFound`]), sealing the original per-surface
/// outcomes for same-operation replay (idempotent on `operation_id`,
/// `Unknown` preserved for reconciliation, no blind retry, no second
/// ledger). Destructive statements delete only the selected surfaces for the
/// exact subject/scope. All `SurrealQL` stays in `apply`/`schema` modules;
/// this boundary carries store-api types only (plus the local intent/outcome
/// model in `atomic_write`, since the neutral purge port is defined in a
/// parallel subtask and is not yet on this base; the adapter never imports
/// `eliot-erasure`).
///
/// `record_surreal_erasure_intent` validates and freezes the intent: in the
/// live path the returned intent is the durable row the atomic transaction
/// below opens with, so no destructive statement can precede it.
///
/// Issue #1712 admits the named dispatch: `apply_prepared_with_authority`
/// routes an admitted `ApplyErasure` transition through this gate, so the
/// intent-before-delete path is live.
///
/// Follow-up integration slice (NOT this contour): `GetEvidencePack`
/// suppression of sealed erasures plus the `erasure_intent`/`erasure_outcome`
/// table migration stay with the real-Surreal integration owner.
pub(crate) fn record_surreal_erasure_intent(
    intent: atomic_write::SurrealErasureIntent,
) -> Result<atomic_write::SurrealErasureIntent, AdapterError> {
    intent.validate().map_err(AdapterError::Store)?;
    Ok(intent)
}

/// 688-B: dispatches one recorded erasure intent through the atomic writer.
///
/// Same-operation replay returns the original per-surface outcomes without
/// duplicate destructive work (the writer's sealed-outcome replay check);
/// `Unknown` outcomes stay preserved for same-operation reconciliation.
/// Fail-closed with zero destructive effects when the intent step above
/// refuses: `write_erasure_transaction` is never reached, so no `DELETE`
/// can precede the durable intent row.
///
/// Issue #1712 admits the named dispatch (see
/// `apply_prepared_with_authority`); this entry executes only the recorded
/// plan and never derives deletion semantics.
///
/// Follow-up integration slice (NOT this contour): `GetEvidencePack`
/// suppression of sealed erasures plus the `erasure_intent`/`erasure_outcome`
/// table migration stay with the real-Surreal integration owner.
pub(crate) async fn apply_surreal_erasure(
    adapter: &SurrealStoreAdapter,
    intent: &atomic_write::SurrealErasureIntent,
) -> Result<Vec<atomic_write::SurrealSurfaceOutcome>, AdapterError> {
    let intent = record_surreal_erasure_intent(intent.clone())?;
    let db = client(adapter).await?;
    ensure_ready(adapter, db).await?;
    let _guard = adapter.write_lock.lock().await;
    atomic_write::write_erasure_transaction(db, &adapter.config, &intent).await
}

/// Builds the pure intent-before-delete ordering assertion used by tests:
/// the intent upsert opens the transaction before every destructive
/// statement and the outcome seal closes it. Returns the byte offsets of
/// the three sections inside the rendered template.
#[allow(dead_code)]
pub(crate) fn erasure_template_ordering(
    store_owned_surface_count: usize,
) -> Result<(usize, usize, usize), AdapterError> {
    let sql = atomic_write::erasure_transaction_template(store_owned_surface_count);
    let intent_at = sql.find("erasure_intent").ok_or_else(|| {
        AdapterError::Serialization("erasure template is missing its intent step".to_owned())
    })?;
    let delete_at = sql.find("DELETE").ok_or_else(|| {
        AdapterError::Serialization("erasure template is missing its delete step".to_owned())
    })?;
    let outcome_at = sql.find("erasure_outcome").ok_or_else(|| {
        AdapterError::Serialization("erasure template is missing its outcome seal".to_owned())
    })?;
    if intent_at < delete_at && delete_at < outcome_at {
        Ok((intent_at, delete_at, outcome_at))
    } else {
        Err(AdapterError::Serialization(
            "erasure template orders intent before delete before outcome seal".to_owned(),
        ))
    }
}

/// Builds the recorded erasure intent verbatim from the admitted named
/// operation (issue #1712).
///
/// The bridge applies only the recorded plan: subject, scope, fence, and
/// surfaces are copied verbatim from the admitted `ApplyErasure` parameters
/// into the local intent, never derived. The stable intent identity must
/// equal the transition identity, binding record, execution, and receipt
/// under one identity; divergence is an identity conflict with no
/// destructive effect.
fn surreal_intent_from_transition(
    transition: &eliot_store_api::PreparedTransition,
) -> Result<atomic_write::SurrealErasureIntent, AdapterError> {
    if transition.transition_class != TransitionClass::Erasure {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let Some(command) = transition.named_operations.first() else {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    };
    if command.operation != NamedMutationOperation::ApplyErasure {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let text_param = |name: &'static str| {
        command
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            }))
    };
    let subject = text_param(ERASURE_PARAM_SUBJECT)?;
    let surfaces_value = text_param(ERASURE_PARAM_SURFACES)?;
    let operation_id = text_param(ERASURE_PARAM_OPERATION_ID)?;
    if operation_id != transition.identity.operation_id.to_string() {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    let surfaces = decode_erasure_surfaces(surfaces_value)
        .map_err(AdapterError::Store)?
        .iter()
        .map(|name| atomic_write::SurrealErasureSurface::by_name(name))
        .collect::<Result<Vec<_>, _>>()
        .map_err(AdapterError::Store)?;
    Ok(atomic_write::SurrealErasureIntent {
        operation_id: operation_id.to_owned(),
        subject: subject.to_owned(),
        scope_id: transition.scope_id.clone(),
        surfaces,
        state_fence: transition.state_fence.clone(),
    })
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
                ("candidate_package_digest".to_owned(), json!("c".repeat(64))),
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
                ("artifact_binding_digest".to_owned(), json!("b".repeat(64))),
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
        // T11.2 activates both UpdateTaskState and ApplyEpistemicRevision, so
        // the remaining unactivated mutation (RecordAuthorityRevocation) still
        // fails closed before staging.
        let unadmitted = transition_with(
            &fence,
            set_digest.clone(),
            TransitionClass::RecoverySchema,
            EffectClass::ReversibleMutation,
            vec![revocation_operation()],
        );
        assert_eq!(
            validate_transition(&context, &unadmitted),
            Err(AdapterError::Store(StoreError::UnknownOperation))
        );
        // ApplyEpistemicRevision is admitted: an empty payload fails as a
        // typed parameter error, not UnknownOperation.
        let missing_epistemic_payload = transition_with(
            &fence,
            set_digest.clone(),
            TransitionClass::Epistemic,
            EffectClass::Candidate,
            vec![NamedMutationRequest {
                operation: NamedMutationOperation::ApplyEpistemicRevision,
                parameters: BTreeMap::new(),
            }],
        );
        assert!(matches!(
            validate_transition(&context, &missing_epistemic_payload),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                ..
            }))
        ));
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

    fn revocation_operation() -> eliot_store_api::NamedMutationRequest {
        NamedMutationRequest {
            operation: NamedMutationOperation::RecordAuthorityRevocation,
            parameters: BTreeMap::from([
                ("origin_ref".to_owned(), json!("root:alpha")),
                ("closure_id".to_owned(), json!("revocation-686-01")),
                ("closure_revision".to_owned(), json!("9")),
                ("affected_digest".to_owned(), json!("a".repeat(64))),
                ("affected_count".to_owned(), json!("3")),
                ("invalidation_reason".to_owned(), json!("SOURCE_REVOKED")),
                ("fence_digest".to_owned(), json!("b".repeat(64))),
            ]),
        }
    }

    /// Issue #686: the revocation-record mutation is known-but-unsupported
    /// until a store-owned slice activates its catalogue row with proven
    /// handlers. The closed name spelling holds and the pre-stage gate
    /// refuses it with typed `UnknownOperation` — never silent success.
    #[test]
    fn revocation_record_mutation_fails_closed_until_store_activation() {
        use eliot_store_api::{named_mutation_operation_by_name, named_mutation_operation_name};
        assert_eq!(
            named_mutation_operation_name(NamedMutationOperation::RecordAuthorityRevocation),
            "RecordAuthorityRevocation"
        );
        assert_eq!(
            named_mutation_operation_by_name("RecordAuthorityRevocation"),
            Some(NamedMutationOperation::RecordAuthorityRevocation)
        );
        assert_eq!(
            NamedMutationOperation::RecordAuthorityRevocation.transition_class(),
            TransitionClass::RecoverySchema
        );
        let fence = test_fence(1);
        let context = test_context(&fence);
        let entries = generated_operation_manifests().expect("active catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest computes");
        let pending = transition_with(
            &fence,
            set_digest,
            TransitionClass::RecoverySchema,
            EffectClass::ReversibleMutation,
            vec![revocation_operation()],
        );
        assert_eq!(
            validate_transition(&context, &pending),
            Err(AdapterError::Store(StoreError::UnknownOperation))
        );
    }

    /// Issue #686: the revocation-history read is known-but-unsupported
    /// until a store-owned slice activates its catalogue row with a proven
    /// handler. The closed name spelling holds and the read gate refuses it
    /// with typed `UnknownOperation` — never a successful empty view.
    #[test]
    fn revocation_history_read_fails_closed_until_store_activation() {
        use eliot_store_api::{
            NamedReadOperation, ReadConsistency, ScopeId, named_read_operation_by_name,
            named_read_operation_name,
        };
        assert_eq!(
            named_read_operation_name(NamedReadOperation::GetAuthorityRevocationHistory),
            "GetAuthorityRevocationHistory"
        );
        assert_eq!(
            named_read_operation_by_name("GetAuthorityRevocationHistory"),
            Some(NamedReadOperation::GetAuthorityRevocationHistory)
        );
        let fence = test_fence(1);
        let entries = generated_operation_manifests().expect("active catalogue generates");
        let query = eliot_store_api::NamedReadRequest {
            operation: NamedReadOperation::GetAuthorityRevocationHistory,
            scope_id: Some(ScopeId::new("governor").expect("scope")),
            consistency: ReadConsistency::Eventual,
            state_fence: fence,
            parameters: BTreeMap::from([
                ("origin_ref".to_owned(), json!("root:alpha")),
                ("max_records".to_owned(), json!("8")),
            ]),
        };
        assert_eq!(
            query.validate_against_catalogue(&entries),
            Err(StoreError::UnknownOperation)
        );
    }

    fn erasure_operation() -> eliot_store_api::NamedMutationRequest {
        NamedMutationRequest {
            operation: NamedMutationOperation::ApplyErasure,
            parameters: BTreeMap::from([
                ("subject".to_owned(), json!("subject-gate")),
                ("surfaces".to_owned(), json!("CanonicalPayload,Index")),
                ("reason".to_owned(), json!("user requested deletion")),
                ("requester".to_owned(), json!("user:test")),
                ("erasure_operation_id".to_owned(), json!("op-gate")),
            ]),
        }
    }

    fn erasure_transition(
        fence: &StateFence,
        manifest_digest: OperationManifestDigest,
    ) -> eliot_store_api::PreparedTransition {
        let mut transition = transition_with(
            fence,
            manifest_digest,
            TransitionClass::Erasure,
            EffectClass::ReversibleMutation,
            vec![erasure_operation()],
        );
        transition.required_proof_and_approval_refs = vec!["approval-user-1".to_owned()];
        transition
    }

    /// Issue #1712: the admitted erasure operation passes the pre-stage gate
    /// under its declared class, and the intent builder binds the recorded
    /// plan verbatim from the admitted parameters.
    #[test]
    fn admitted_erasure_passes_the_pre_stage_gate() {
        let fence = test_fence(1);
        let context = test_context(&fence);
        let entries = generated_operation_manifests().expect("active catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest computes");
        let transition = erasure_transition(&fence, set_digest);
        assert!(
            validate_transition(&context, &transition).is_ok(),
            "admitted erasure passes the pre-stage gate"
        );
        let intent = surreal_intent_from_transition(&transition).expect("intent binds");
        assert_eq!(intent.operation_id, "op-gate");
        assert_eq!(intent.subject, "subject-gate");
        assert_eq!(intent.scope_id.as_str(), "scope-gate");
        assert_eq!(
            intent.surfaces,
            vec![
                atomic_write::SurrealErasureSurface::CanonicalPayload,
                atomic_write::SurrealErasureSurface::Index,
            ]
        );
    }

    /// Issue #1712: unapproved, out-of-manifest, and divergent erasure plans
    /// are rejected pre-stage with no provider effect.
    #[test]
    fn erasure_gate_rejects_unapproved_and_out_of_manifest() {
        let fence = test_fence(1);
        let context = test_context(&fence);
        let entries = generated_operation_manifests().expect("active catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest computes");

        // No explicit approval: automatic paths furnish none and fail here.
        let mut unapproved = erasure_transition(&fence, set_digest.clone());
        unapproved.required_proof_and_approval_refs.clear();
        assert!(matches!(
            validate_transition(&context, &unapproved),
            Err(AdapterError::Store(StoreError::InvalidField { .. }))
        ));

        // Wrong transition class for the named erasure operation.
        let mut wrong_class = erasure_transition(&fence, set_digest.clone());
        wrong_class.transition_class = TransitionClass::CaptureCandidate;
        assert_eq!(
            validate_transition(&context, &wrong_class),
            Err(AdapterError::Store(StoreError::TransitionClassExceeded))
        );

        // Stale manifest digest never reaches the store.
        let mut stale = transition_with(
            &fence,
            OperationManifestDigest::new("stale-manifest-digest").expect("digest"),
            TransitionClass::Erasure,
            EffectClass::ReversibleMutation,
            vec![erasure_operation()],
        );
        stale.required_proof_and_approval_refs = vec!["approval-user-1".to_owned()];
        assert_eq!(
            validate_transition(&context, &stale),
            Err(AdapterError::Store(StoreError::ManifestMismatch))
        );

        // Unknown surface: dispatch refuses the invented denominator.
        let mut unknown = erasure_transition(&fence, set_digest);
        unknown.named_operations[0]
            .parameters
            .insert("surfaces".to_owned(), json!("Nope"));
        assert!(matches!(
            surreal_intent_from_transition(&unknown),
            Err(AdapterError::Store(StoreError::InvalidField { .. }))
        ));

        // Divergent intent identity: record, execution, and receipt stay
        // bound under one identity.
        let mut divergent = erasure_operation();
        divergent
            .parameters
            .insert("erasure_operation_id".to_owned(), json!("op-other"));
        let mut transition = erasure_transition(
            &fence,
            operation_manifest_set_digest(
                &generated_operation_manifests().expect("active catalogue generates"),
            )
            .expect("set digest computes"),
        );
        transition.named_operations = vec![divergent];
        assert_eq!(
            surreal_intent_from_transition(&transition),
            Err(AdapterError::Store(StoreError::IdentityConflict))
        );
    }
}

/// 688-B: memory + Surreal erasure execution (adapter contour).
///
/// The intent-before-delete template asserts the whole protocol ordering —
/// intent row first, destructive deletes second, outcome seal last — and
/// the bindings assertion pins the sealed per-surface derivation (store
/// surfaces purge, foreign surfaces stay incomplete, `Unknown` preserved).
/// The live round-trip stays with integration (not this unit).
#[cfg(test)]
mod erasure_execution_tests {
    use super::atomic_write::{
        SurrealErasureIntent, SurrealErasureSurface, SurrealSurfaceOutcome,
        erasure_transaction_bindings, erasure_transaction_template,
    };
    use super::{erasure_template_ordering, record_surreal_erasure_intent};

    fn test_fence() -> Result<eliot_store_api::StateFence, Box<dyn std::error::Error>> {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .map_err(|error| format!("canonical test lineage-A: {error:?}"))?;
        let sequence = NonZeroU64::new(1).ok_or("non-zero test sequence")?;
        let epoch = EpochId::new(lineage, sequence)
            .map_err(|error| format!("valid test epoch: {error:?}"))?;
        Ok(eliot_store_api::StateFence::new(
            epoch,
            ResourceGeneration::genesis(),
        ))
    }

    fn intent() -> Result<SurrealErasureIntent, Box<dyn std::error::Error>> {
        Ok(SurrealErasureIntent {
            operation_id: "erasure-op-1".to_owned(),
            subject: "evidence-alpha".to_owned(),
            scope_id: eliot_store_api::ScopeId::new("scope-1")
                .map_err(|error| format!("valid test scope: {error:?}"))?,
            surfaces: vec![
                SurrealErasureSurface::CanonicalPayload,
                SurrealErasureSurface::Blob,
            ],
            state_fence: test_fence()?,
        })
    }

    #[test]
    fn erasure_template_records_intent_before_delete_before_outcome_seal()
    -> Result<(), Box<dyn std::error::Error>> {
        // Real template + real ordering gate: the intent step opens the
        // transaction before any destructive statement and the outcome seal
        // closes it; destructive statements delete only the exact
        // subject/scope pair.
        let intent = record_surreal_erasure_intent(intent()?)
            .map_err(|error| format!("intent records: {error:?}"))?;
        let store_owned = intent
            .surfaces
            .iter()
            .filter(|surface| surface.is_store_owned())
            .count();
        assert_eq!(store_owned, 1);
        let sql = erasure_transaction_template(store_owned);
        assert!(sql.starts_with("BEGIN TRANSACTION;"));
        assert!(sql.ends_with("COMMIT TRANSACTION;"));
        let (intent_at, delete_at, outcome_at) = erasure_template_ordering(store_owned)
            .map_err(|error| format!("ordering resolves: {error:?}"))?;
        assert!(intent_at < delete_at && delete_at < outcome_at);
        assert_eq!(sql.matches("DELETE").count(), store_owned);
        assert!(sql.contains("$erasure_subject0"));
        assert!(sql.contains("$erasure_scope_expected0"));
        assert!(sql.contains("erasure_intent_conflict"));
        let (bindings, outcomes) = erasure_transaction_bindings(&intent, &[])
            .map_err(|error| format!("bindings build: {error:?}"))?;
        assert!(bindings.contains_key("erasure_table"));
        assert!(bindings.contains_key("erasure_intent_expected"));
        assert!(bindings.contains_key("erasure_intent_record"));
        assert!(bindings.contains_key("erasure_subject0"));
        assert!(!bindings.contains_key("erasure_subject1"));
        assert!(bindings.contains_key("erasure_outcome_record"));
        assert_eq!(
            outcomes,
            vec![
                SurrealSurfaceOutcome::Purged {
                    surface: SurrealErasureSurface::CanonicalPayload,
                },
                SurrealSurfaceOutcome::Incomplete {
                    surface: SurrealErasureSurface::Blob,
                },
            ]
        );
        // Same-operation replay keeps a preserved `Unknown` verbatim instead
        // of re-running destructive work or clearing it: the replay emits no
        // `erasure_subject{i}` bindings, so the rendered template carries no
        // `DELETE` for the replayed surface.
        let prior = vec![SurrealSurfaceOutcome::Unknown {
            surface: SurrealErasureSurface::CanonicalPayload,
        }];
        let (replay_bindings, replayed) = erasure_transaction_bindings(&intent, &prior)
            .map_err(|error| format!("replay binds: {error:?}"))?;
        assert_eq!(replayed[0], prior[0]);
        assert!(
            !replay_bindings
                .keys()
                .any(|key| key.starts_with("erasure_subject")),
            "replayed-Unknown emits no destructive bindings"
        );
        let replay_store_owned = replay_bindings
            .keys()
            .filter(|key| {
                key.starts_with("erasure_subject")
                    && key["erasure_subject".len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_digit())
            })
            .count();
        let replay_sql = erasure_transaction_template(replay_store_owned);
        assert_eq!(replay_sql.matches("DELETE").count(), 0);
        assert!(
            !replay_sql.contains("DELETE"),
            "replayed-Unknown renders no DELETE statement"
        );
        // No intent, no template: the gate refuses before any provider I/O.
        let mut missing = intent.clone();
        missing.operation_id.clear();
        assert!(record_surreal_erasure_intent(missing).is_err());
        Ok(())
    }
}

/// S-CONC-TX (issue #989) allocation tests.
///
/// Pure pins cover the bounded retry contract; live proofs exercise the
/// production entry (facade lane, no process-global guard) alongside the
/// explicit test/private seam against real provider sessions on an
/// isolated provider. No production database, no user credentials.
#[cfg(test)]
mod concurrent_allocation_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// Compile-time pin: the retry absorbs racing writers without an
    /// unbounded CAS spin. The behavioral counterpart (loop re-enters only
    /// on classified contention, every other outcome returns without retry)
    /// is proven live beside the seam and guarded in the
    /// `concurrent_transaction_allocation` integration target.
    const _: () = assert!(MAX_ALLOCATION_RETRIES > 0 && MAX_ALLOCATION_RETRIES <= 8);

    #[cfg(windows)]
    mod live_seam_tests {
        #![allow(clippy::expect_used, clippy::print_stdout)]
        // Live allocation proofs necessarily hold admitted transitions
        // across awaits while concurrent writers overlap; same rationale as
        // the `concurrent_transaction_allocation` target allowance.
        #![allow(clippy::large_futures)]

        use super::super::{
            apply_prepared_with_authority, apply_prepared_without_write_guard, atomic_write,
            build_receipt, client, read_fence, validate_receipt_identity,
        };
        use crate::client::session_pool::SessionRole;
        use crate::config::{ClientSetLimits, SurrealAdapterConfig};
        use crate::error::AdapterError;
        use crate::plan;
        use crate::{SchemaGeneration, SurrealStoreAdapter};
        use eliot_platform_windows::WindowsPlatform;
        use eliot_store_api::{
            CONTRACT_VERSION, CanonicalRequestView, CanonicalStoreClient, EffectClass,
            EventProjectionRelationIntents, ExactJsonBytes, GENESIS_MANIFEST_NAME,
            NamedMutationOperation, NamedMutationRequest, OperationIdentity,
            OperationManifestDigest, OrderingScopeId, ScopeId, SecurityContext, StateFence,
            StoreRecoveryRequest, TransitionClass, WriteReceipt, canonical_request_hash,
            generated_operation_manifests, operation_manifest_set_digest,
        };
        use secrecy::{ExposeSecret, SecretString};
        use serde_json::json;
        use std::collections::BTreeMap;
        use std::path::{Path, PathBuf};
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::net::TcpStream;
        use tokio::process::Command;
        use tokio::time::{Instant, sleep, timeout};

        const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

        fn fence() -> StateFence {
            use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
            use std::num::NonZeroU64;
            let lineage = EpochLineageId::new(TEST_LINEAGE).expect("lineage");
            let epoch =
                EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
            StateFence::new(epoch, ResourceGeneration::genesis())
        }

        fn fixture_ctx() -> eliot_store_api::RequestMeta {
            use eliot_contracts::{ClockReading, ProductId, RequestId, SourceId};
            eliot_store_api::RequestMeta {
                request_id: RequestId::new("request-989-seam").expect("request"),
                session_id: None,
                task_id: None,
                product_id: ProductId::new("product-989-seam").expect("product"),
                source_id: SourceId::new("source-989-seam").expect("source"),
                state_fence: fence(),
                clock: ClockReading {
                    valid_time_ms: Some(1000),
                    known_time_ms: Some(1001),
                    ..ClockReading::default()
                },
            }
        }

        /// One admitted disjoint-scope capture: valid catalogue digest and
        /// recomputed request hash, so only allocation can fail.
        fn admitted(operation: &str, scope: &str, subject: &str) -> PreparedTransitionForTest {
            let ctx = fixture_ctx();
            let mut transition = eliot_store_api::PreparedTransition {
                identity: OperationIdentity {
                    operation_id: eliot_store_api::OperationId::new(operation).expect("operation"),
                    idempotency_key: format!("idem-{operation}"),
                    canonical_request_hash: "a".repeat(64),
                },
                state_fence: fence(),
                scope_id: ScopeId::new(scope).expect("scope"),
                task_id: None,
                ordering_scopes: vec![OrderingScopeId::new(scope).expect("ordering")],
                transition_class: TransitionClass::CaptureCandidate,
                requested_effect_ceiling: EffectClass::Candidate,
                admission_contract_set_digest: "b".repeat(64),
                operation_manifest_digest: OperationManifestDigest::new("manifest-1")
                    .expect("manifest"),
                named_operations: vec![NamedMutationRequest {
                    operation: NamedMutationOperation::CaptureObservation,
                    parameters: BTreeMap::from([("subject".to_owned(), json!(subject))]),
                }],
                event_projection_relation_intents: EventProjectionRelationIntents {
                    event_ids: Vec::new(),
                    projection_kinds: Vec::new(),
                    relation_kinds: Vec::new(),
                },
                security: SecurityContext::default(),
                required_proof_and_approval_refs: Vec::new(),
            };
            transition.operation_manifest_digest =
                operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
                    .expect("manifest digest");
            transition.identity.canonical_request_hash = canonical_request_hash(
                &CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]),
            )
            .expect("request hash");
            PreparedTransitionForTest { ctx, transition }
        }

        struct PreparedTransitionForTest {
            ctx: eliot_store_api::RequestMeta,
            transition: eliot_store_api::PreparedTransition,
        }

        struct Harness {
            root: PathBuf,
            config: SurrealAdapterConfig,
            adapter: Option<SurrealStoreAdapter>,
        }

        impl Harness {
            async fn start() -> Self {
                let port = std::net::TcpListener::bind("127.0.0.1:0")
                    .expect("loopback")
                    .local_addr()
                    .expect("address")
                    .port();
                let root =
                    std::env::temp_dir().join(format!("eliot-sconc-989-{}", uuid::Uuid::new_v4()));
                let exe = root.join("bin/surreal.exe");
                let data = root.join("store/data");
                let work = root.join("store/work");
                let tmp = root.join("store/tmp");
                for path in [root.join("bin"), data.clone(), work.clone(), tmp.clone()] {
                    std::fs::create_dir_all(path).expect("isolated root");
                }
                let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
                    || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
                    PathBuf::from,
                );
                std::fs::copy(provider, &exe).expect("stage provider");
                let digest =
                    eliot_store_api::sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
                let bind = format!("127.0.0.1:{port}");
                let mut config = SurrealAdapterConfig {
                    endpoint: format!("ws://{bind}/rpc"),
                    namespace: "sconc989".into(),
                    database: "alloc989".into(),
                    username: "sconc989-user".into(),
                    password: SecretString::new(format!("test-{}", uuid::Uuid::new_v4()).into()),
                    provider_bind_address: bind,
                    installation_id: "sconc989-test".into(),
                    installation_profile: "portable_dev".into(),
                    runtime_state_roots_digest: "a".repeat(64),
                    provider_executable_path: exe.to_string_lossy().into_owned(),
                    provider_artifact_digest: digest,
                    provider_arguments: Vec::new(),
                    store_data_root: data.to_string_lossy().into_owned(),
                    store_work_root: work.to_string_lossy().into_owned(),
                    store_temp_root: tmp.to_string_lossy().into_owned(),
                    connect_timeout_ms: 30_000,
                    query_timeout_ms: 30_000,
                    expected_provider_major: crate::PINNED_SURREALDB_MAJOR,
                    expected_schema_generation: SchemaGeneration::v2(),
                };
                config.provider_arguments = config.expected_provider_arguments();
                let mut harness = Self {
                    root,
                    config,
                    adapter: None,
                };
                println!(
                    "SCONC-989 provider={} sha256={} root={}",
                    exe.display(),
                    harness.config.provider_artifact_digest,
                    harness.root.display()
                );
                let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
                let mut child = Command::new(&exe)
                    .args(&harness.config.provider_arguments)
                    .current_dir(&work)
                    .env_clear()
                    .env("SystemRoot", &system_root)
                    .env("WINDIR", &system_root)
                    .env("TEMP", &tmp)
                    .env("TMP", &tmp)
                    .env("SURREAL_USER", &harness.config.username)
                    .env("SURREAL_PASS", harness.config.password.expose_secret())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .creation_flags(0x0800_0000)
                    .kill_on_drop(true)
                    .spawn()
                    .expect("bootstrap provider");
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    assert!(
                        child.try_wait().expect("child status").is_none(),
                        "bootstrap exited"
                    );
                    if TcpStream::connect(&harness.config.provider_bind_address)
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    assert!(Instant::now() < deadline, "bootstrap bind timeout");
                    sleep(Duration::from_millis(50)).await;
                }
                child.kill().await.expect("stop bootstrap");
                child.wait().await.expect("reap bootstrap");
                harness.open().await;
                harness
            }

            async fn open(&mut self) {
                let platform = WindowsPlatform::new(self.root.clone()).expect("platform");
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut last_error = None;
                let limits = ClientSetLimits::new(2, 2, 1).expect("concurrent profile");
                loop {
                    let lease = platform
                        .retain_process_path_lease(
                            Path::new(&self.config.provider_executable_path),
                            Path::new(&self.config.store_work_root),
                            &self.config.provider_artifact_digest,
                        )
                        .expect("process lease");
                    let manifest = generated_operation_manifests()
                        .expect("catalogue")
                        .into_iter()
                        .find(|entry| entry.name == GENESIS_MANIFEST_NAME)
                        .expect("genesis manifest");
                    self.adapter = Some(
                        SurrealStoreAdapter::new_with_client_set(
                            self.config.clone(),
                            lease,
                            manifest,
                            limits,
                        )
                        .expect("adapter"),
                    );
                    match tokio::time::timeout_at(deadline, self.adapter().connect()).await {
                        Ok(Ok(())) => return,
                        Ok(Err(error)) => last_error = Some(error),
                        Err(_) => {
                            self.adapter = None;
                            panic!(
                                "authenticated provider readiness timed out; last error: {last_error:?}"
                            );
                        }
                    }
                    self.adapter = None;
                    assert!(
                        Instant::now() < deadline,
                        "authenticated provider readiness timed out; last error: {last_error:?}"
                    );
                    sleep(
                        Duration::from_millis(100)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    )
                    .await;
                }
            }

            fn adapter(&self) -> &SurrealStoreAdapter {
                self.adapter.as_ref().expect("live adapter")
            }

            async fn migrate(&self) {
                let ctx = fixture_ctx();
                self.adapter()
                    .apply_migration(
                        &SurrealStoreAdapter::v2_baseline_migration(),
                        &ctx.clock,
                        &ctx.state_fence,
                    )
                    .await
                    .expect("baseline migration");
            }

            async fn close(&mut self) {
                self.adapter = None;
                let deadline = Instant::now() + Duration::from_secs(10);
                while TcpStream::connect(&self.config.provider_bind_address)
                    .await
                    .is_ok()
                {
                    assert!(
                        Instant::now() < deadline,
                        "provider did not release endpoint"
                    );
                    sleep(Duration::from_millis(50)).await;
                }
            }

            async fn cleanup(&mut self) {
                self.close().await;
                let deadline = Instant::now() + Duration::from_secs(10);
                while let Err(error) = std::fs::remove_dir_all(&self.root) {
                    assert!(
                        Instant::now() < deadline,
                        "test root cleanup failed: {error}"
                    );
                    sleep(Duration::from_millis(50)).await;
                }
                assert!(!self.root.exists(), "test root removed");
            }
        }

        impl Drop for Harness {
            fn drop(&mut self) {
                self.adapter = None;
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }

        struct PlannedPair {
            authorities_b: Vec<Option<ExactJsonBytes>>,
            plan_a: plan::ApplyPlan,
            receipt_a: WriteReceipt,
            plan_b: plan::ApplyPlan,
            receipt_b: WriteReceipt,
        }

        /// Plans both writers against one observed allocation (pure): the
        /// deterministic shared-counter race setup without timing flakes.
        fn planned_pair(
            a: &PreparedTransitionForTest,
            b: &PreparedTransitionForTest,
            commit: u64,
            outbox: u64,
        ) -> PlannedPair {
            let authorities_a = vec![None; a.transition.named_operations.len()];
            let authorities_b = vec![None; b.transition.named_operations.len()];
            let plan_a =
                plan::select_apply_plan(&a.transition, &authorities_a, &[], &[], commit, outbox)
                    .expect("plan A applies");
            let receipt_a = build_receipt(&a.ctx, &a.transition, &plan_a).expect("receipt A");
            let plan_b =
                plan::select_apply_plan(&b.transition, &authorities_b, &[], &[], commit, outbox)
                    .expect("plan B applies against the same observed allocation");
            let receipt_b = build_receipt(&b.ctx, &b.transition, &plan_b).expect("receipt B");
            PlannedPair {
                authorities_b,
                plan_a,
                receipt_a,
                plan_b,
                receipt_b,
            }
        }

        #[tokio::test]
        async fn stale_allocation_contends_then_bounded_retry_commits() {
            let mut harness = Harness::start().await;
            harness.migrate().await;
            let adapter = harness.adapter();
            let db = client(adapter).await.expect("transport");
            let prepared_a = admitted("op-989-stale-a", "scope-989-a", "subject-989-a");
            let prepared_b = admitted("op-989-stale-b", "scope-989-b", "subject-989-b");
            // Both writers observe the same initial fence through separate
            // sessions: the disjoint semantic scopes share one global
            // allocation, which is the original race.
            let fence_opt = read_fence(db, &adapter.config).await.expect("fence read");
            let fence = fence_opt.as_ref().expect("fence row");
            assert_eq!(
                (fence.next_commit_sequence, fence.next_outbox_sequence),
                (1, 1),
                "isolated database starts at the genesis allocation"
            );
            let initial = fence_opt.is_none();
            let planned = planned_pair(&prepared_a, &prepared_b, 1, 1);
            atomic_write::write_transaction(
                db,
                &adapter.config,
                &prepared_a.transition,
                &planned.plan_a,
                &planned.receipt_a,
                initial,
                1,
                1,
                &[],
                &[],
                atomic_write::TxLane::PooledWrite,
            )
            .await
            .expect("first writer commits");
            // The second writer's pre-read allocation is now stale. Its
            // disjoint semantic scopes are fresh, so this must surface as
            // transient allocation contention — never a false semantic
            // conflict and never an unknown outcome.
            match atomic_write::write_transaction(
                db,
                &adapter.config,
                &prepared_b.transition,
                &planned.plan_b,
                &planned.receipt_b,
                false,
                1,
                1,
                &[],
                &[],
                atomic_write::TxLane::PooledWrite,
            )
            .await
            {
                Err(AdapterError::AllocationContention { operation_id }) => {
                    assert_eq!(operation_id, "op-989-stale-b");
                }
                unexpected => panic!("stale allocation must contend, got {unexpected:?}"),
            }
            // Bounded retry under the unchanged semantic contract: fresh
            // allocation, same scopes, same expected heads.
            let moved = read_fence(db, &adapter.config)
                .await
                .expect("fence re-read")
                .expect("fence row");
            assert_eq!(
                (moved.next_commit_sequence, moved.next_outbox_sequence),
                (2, 2),
                "exactly one allocation was consumed"
            );
            let plan_b2 = plan::select_apply_plan(
                &prepared_b.transition,
                &planned.authorities_b,
                &[],
                &[],
                moved.next_commit_sequence,
                moved.next_outbox_sequence,
            )
            .expect("replan applies");
            let receipt_b2 = build_receipt(&prepared_b.ctx, &prepared_b.transition, &plan_b2)
                .expect("receipt B2");
            atomic_write::write_transaction(
                db,
                &adapter.config,
                &prepared_b.transition,
                &plan_b2,
                &receipt_b2,
                false,
                moved.next_commit_sequence,
                moved.next_outbox_sequence,
                &[],
                &[],
                atomic_write::TxLane::PooledWrite,
            )
            .await
            .expect("bounded retry commits");
            validate_receipt_identity(&receipt_b2, &prepared_b.ctx, &prepared_b.transition)
                .expect("retried receipt identity validates");
            assert_eq!(
                receipt_b2.committed_at.as_deref(),
                Some("commit-sequence-0000000000000002"),
                "retry consumed exactly the next allocation"
            );
            harness.cleanup().await;
        }

        #[tokio::test]
        async fn concurrent_disjoint_commits_share_no_allocation() {
            let mut harness = Harness::start().await;
            harness.migrate().await;
            let adapter = harness.adapter();
            // Overlap precondition: the write lane admits two sessions under
            // one provider generation; the facade session is untouched.
            let db = client(adapter).await.expect("transport");
            assert_eq!(
                db.session_pool().slot_count(SessionRole::NormalWrite),
                2,
                "seam test needs two write-lane sessions"
            );
            let prepared_a = admitted("op-989-live-a", "scope-989-a", "subject-989-a");
            let prepared_b = admitted("op-989-live-b", "scope-989-b", "subject-989-b");
            let authorities_a = vec![None; prepared_a.transition.named_operations.len()];
            let authorities_b = vec![None; prepared_b.transition.named_operations.len()];
            let (receipt_a, receipt_b) = tokio::join!(
                apply_prepared_without_write_guard(
                    adapter,
                    &prepared_a.ctx,
                    prepared_a.transition.clone(),
                    Vec::new(),
                    Vec::new(),
                    &authorities_a,
                ),
                apply_prepared_without_write_guard(
                    adapter,
                    &prepared_b.ctx,
                    prepared_b.transition.clone(),
                    Vec::new(),
                    Vec::new(),
                    &authorities_b,
                )
            );
            let receipt_a = receipt_a.expect("disjoint writer A commits");
            let receipt_b = receipt_b.expect("disjoint writer B commits");
            // Interleaving-insensitive: the allocated pair is exactly {1,2}
            // whatever the commit order was.
            let mut committed: Vec<_> = [
                receipt_a.committed_at.clone(),
                receipt_b.committed_at.clone(),
            ]
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .expect("both receipts carry commit instants");
            committed.sort();
            assert_eq!(
                committed,
                vec![
                    "commit-sequence-0000000000000001".to_owned(),
                    "commit-sequence-0000000000000002".to_owned(),
                ],
                "disjoint commits hold unique valid allocations"
            );
            assert_ne!(
                receipt_a.outbox_refs, receipt_b.outbox_refs,
                "outbox allocation is unique per commit"
            );
            for receipt in [&receipt_a, &receipt_b] {
                validate_store_receipt_envelope_for_test(receipt);
            }
            let snapshot = adapter
                .recovery(StoreRecoveryRequest {
                    contract_version: CONTRACT_VERSION,
                    state_fence: fence(),
                    records: Vec::new(),
                    include_receipts: true,
                    include_jobs: false,
                })
                .await
                .expect("recovery snapshot");
            snapshot.validate().expect("snapshot validates");
            assert_eq!(
                snapshot.receipts.len(),
                2,
                "exactly the two effect sets are durable"
            );
            let heads: std::collections::BTreeMap<_, _> = snapshot
                .canonical_scope
                .ordering_heads
                .iter()
                .map(|head| (head.scope.to_string(), head.sequence))
                .collect();
            assert_eq!(
                heads.get("scope-989-a"),
                heads.get("scope-989-b"),
                "symmetric disjoint commits advance symmetric per-scope heads"
            );
            harness.cleanup().await;
        }

        #[tokio::test]
        async fn production_apply_commits_while_global_guard_is_held() {
            let mut harness = Harness::start().await;
            harness.migrate().await;
            let adapter = harness.adapter();
            // Discriminator: hold the process-global write guard for the
            // whole concurrent section. If production allocation still rode
            // under it, both writers below would block until this guard
            // drops and the bounded wait would time out; with fence-CAS
            // plus head-predicate arbitration they commit while it is held.
            let held = adapter.write_lock.lock().await;
            let prepared_a = admitted("op-989-prod-a", "scope-989-a", "subject-989-a");
            let prepared_b = admitted("op-989-prod-b", "scope-989-b", "subject-989-b");
            let authorities_a = vec![None; prepared_a.transition.named_operations.len()];
            let authorities_b = vec![None; prepared_b.transition.named_operations.len()];
            let (receipt_a, receipt_b) = timeout(Duration::from_mins(2), async {
                tokio::join!(
                    apply_prepared_with_authority(
                        adapter,
                        &prepared_a.ctx,
                        prepared_a.transition.clone(),
                        Vec::new(),
                        Vec::new(),
                        &authorities_a,
                    ),
                    apply_prepared_with_authority(
                        adapter,
                        &prepared_b.ctx,
                        prepared_b.transition.clone(),
                        Vec::new(),
                        Vec::new(),
                        &authorities_b,
                    )
                )
            })
            .await
            .expect("production writers commit while the global guard is held elsewhere");
            let receipt_a = receipt_a.expect("production writer A commits");
            let receipt_b = receipt_b.expect("production writer B commits");
            // Interleaving-insensitive: the allocated pair is exactly {1,2}
            // whatever the commit order was.
            let mut committed: Vec<_> = [
                receipt_a.committed_at.clone(),
                receipt_b.committed_at.clone(),
            ]
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .expect("both receipts carry commit instants");
            committed.sort();
            assert_eq!(
                committed,
                vec![
                    "commit-sequence-0000000000000001".to_owned(),
                    "commit-sequence-0000000000000002".to_owned(),
                ],
                "production disjoint commits hold unique valid allocations"
            );
            assert_ne!(
                receipt_a.outbox_refs, receipt_b.outbox_refs,
                "outbox allocation is unique per commit"
            );
            for receipt in [&receipt_a, &receipt_b] {
                validate_store_receipt_envelope_for_test(receipt);
            }
            drop(held);
            let snapshot = adapter
                .recovery(StoreRecoveryRequest {
                    contract_version: CONTRACT_VERSION,
                    state_fence: fence(),
                    records: Vec::new(),
                    include_receipts: true,
                    include_jobs: false,
                })
                .await
                .expect("recovery snapshot");
            snapshot.validate().expect("snapshot validates");
            assert_eq!(
                snapshot.receipts.len(),
                2,
                "exactly the two production effect sets are durable"
            );
            println!("SCONC-989 production-guard-held committed={committed:?} receipts=2");
            harness.cleanup().await;
        }

        #[tokio::test]
        async fn concurrent_same_operation_yields_one_effect_set() {
            let mut harness = Harness::start().await;
            harness.migrate().await;
            let adapter = harness.adapter();
            let prepared = admitted("op-989-same", "scope-989-same", "subject-989-same");
            let authorities = vec![None; prepared.transition.named_operations.len()];
            let (first, second) = tokio::join!(
                apply_prepared_without_write_guard(
                    adapter,
                    &prepared.ctx,
                    prepared.transition.clone(),
                    Vec::new(),
                    Vec::new(),
                    &authorities,
                ),
                apply_prepared_without_write_guard(
                    adapter,
                    &prepared.ctx,
                    prepared.transition.clone(),
                    Vec::new(),
                    Vec::new(),
                    &authorities,
                )
            );
            let first = first.expect("same-op writer commits");
            let second = second.expect("same-op writer resolves");
            assert_eq!(
                first, second,
                "exact duplicate submission returns the original receipt"
            );
            let snapshot = adapter
                .recovery(StoreRecoveryRequest {
                    contract_version: CONTRACT_VERSION,
                    state_fence: fence(),
                    records: Vec::new(),
                    include_receipts: true,
                    include_jobs: false,
                })
                .await
                .expect("recovery snapshot");
            assert_eq!(
                snapshot.receipts.len(),
                1,
                "concurrent duplicates persist one effect set"
            );
            assert_eq!(snapshot.receipts[0], first);
            harness.cleanup().await;
        }

        fn validate_store_receipt_envelope_for_test(receipt: &eliot_store_api::WriteReceipt) {
            receipt.validate().expect("receipt validates");
            receipt
                .require_reconciliation_envelope()
                .expect("reconciliation envelope travels");
        }
    }
}

#[cfg(test)]
mod execution_delegation_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::config::ClientSetLimits;
    use crate::write_execution::WriteExecution;

    #[test]
    fn deterministic_failures_reject_with_the_exact_cause() {
        assert!(matches!(
            map_attempt_error(AdapterError::Store(StoreError::IdentityConflict)),
            AttemptOutcome::Rejected(StoreError::IdentityConflict)
        ));
        assert!(matches!(
            map_attempt_error(AdapterError::Store(StoreError::RevisionConflict)),
            AttemptOutcome::Rejected(StoreError::RevisionConflict)
        ));
        assert!(matches!(
            map_attempt_error(AdapterError::ProviderConflict),
            AttemptOutcome::Rejected(StoreError::RevisionConflict)
        ));
        assert!(matches!(
            map_attempt_error(AdapterError::Store(StoreError::InvalidField {
                field: "admission.scopes",
                reason: "reservation projection failed scheduler structure",
            })),
            AttemptOutcome::Rejected(StoreError::InvalidField { .. })
        ));
    }

    #[test]
    fn serial_generation_admits_the_legacy_lane() {
        let execution = WriteExecution::install_serial(
            ClientSetLimits::compatibility(),
            std::num::NonZeroUsize::new(4).expect("queue"),
        )
        .expect("serial installs");
        assert!(execution.unreserved_apply_admission().allowed());
    }

    #[test]
    fn pre_effect_local_defects_cancel_without_provider_effects() {
        for error in [
            AdapterError::AllocationContention {
                operation_id: "op-993-cancel".to_owned(),
            },
            AdapterError::Config("bad lane".to_owned()),
            AdapterError::Serialization("bad plan".to_owned()),
            AdapterError::MigrationRequired,
            AdapterError::NamedOperationUnavailable {
                operation: "unknown.op".to_owned(),
            },
            AdapterError::Store(StoreError::Serialization("bad bytes".to_owned())),
        ] {
            assert!(
                matches!(map_attempt_error(error), AttemptOutcome::Cancelled),
                "pre-effect defect must dispose without effects"
            );
        }
    }

    #[test]
    fn ambiguous_outcomes_stay_unknown_for_reconciliation() {
        for error in [
            AdapterError::UnknownOutcome {
                operation_id: "op-993-unknown".to_owned(),
            },
            AdapterError::PartialOutcome,
            AdapterError::UnknownMigrationOutcome {
                migration_id: "migration-993".to_owned(),
            },
            AdapterError::ProviderUnavailable,
            AdapterError::Store(StoreError::Unavailable),
            AdapterError::Store(StoreError::MissingReceiptEnvelope),
        ] {
            assert!(
                matches!(
                    map_attempt_error(error),
                    AttemptOutcome::Unknown { retry_after_ms: 0 }
                ),
                "ambiguous outcome must reconcile, never blind-retry or complete"
            );
        }
    }
}
