//! Empty-migration application cell for the Surreal adapter.
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Implementation: I5.1, I5.9, I5.22, I2.2, I2.23 — Surreal bridge DDL transaction, fence and schema-meta creation for the empty-database v2 baseline.
//! Responsibility: empty-database v2 baseline migration only; transactional DDL plus canonical fence and schema-meta creation/verification; forbids forward migration, genesis, atomic write, receipt/reconciliation, read-boundary, provider process/handshake, or migration-contract ownership beyond this boundary.

use serde_json::{Map, Value, json};

use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::readiness::{CompiledMigration, MigrationReceipt};
use crate::{client, schema};
use eliot_store_api::StateFence;

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
    let record = super::schema_contract::schema_meta_record(migration, updated_at);
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

pub(super) async fn handle_empty_migration(
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
    if errors.iter().any(|e| super::is_guard_conflict(e)) {
        return Err(AdapterError::Config("forward guard conflict".to_owned()));
    }
    if !errors.is_empty() {
        return Err(AdapterError::UnknownMigrationOutcome {
            migration_id: migration.migration_id.clone(),
        });
    }
    let observed = super::read_schema_meta(db, config).await?;
    match super::migration_preflight(observed, migration) {
        Ok(super::schema_contract::MigrationPreflight::ExactReplay) => {
            let fence = super::receipt_reconciliation::read_fence(db, config).await?;
            let Some(fence) = fence else {
                return Err(AdapterError::PartialOutcome);
            };
            super::schema_contract::validate_fence_record(&fence)?;
            if fence.state_fence != *state_fence {
                return Err(AdapterError::PartialOutcome);
            }
            Ok(super::migration_receipt(migration))
        }
        _ => Err(AdapterError::PartialOutcome),
    }
}
