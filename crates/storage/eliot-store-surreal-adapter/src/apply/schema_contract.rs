//! Pure schema/fence contract validation.
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-AUTH-01, ARCH-SEC-02, ARCH-RES-03.
//! Implementation: I5.1, I5.9, I5.22, I2.17, I2.23.
//! Ownership: pure schema/fence contract validation only; no RPC, DDL, write, semantic transition, authority, retry or default ownership.

use crate::error::AdapterError;
use crate::readiness::CompiledMigration;
use crate::schema;
use eliot_store_api::{StateFence, StoreError};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FenceRecord {
    pub(super) state_fence: StateFence,
    pub(super) next_commit_sequence: u64,
    pub(super) next_outbox_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SchemaMetaRecord {
    pub(super) generation: String,
    pub(super) migrations: Vec<SchemaMigrationIdentity>,
    pub(super) compatible_bridge_range: String,
    pub(super) migration_state: String,
    pub(super) migration_id: String,
    pub(super) migration_checksum_sha256: String,
    pub(super) updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SchemaMigrationIdentity {
    pub(super) migration_id: String,
    pub(super) migration_checksum_sha256: String,
    pub(super) generation: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum MigrationPreflight {
    Empty,
    ExactReplay,
    V1ToV2,
    /// The durable `schema_meta` row already carries this plan's intent, so
    /// this operation still owns the row and the DDL transaction it left
    /// uncommitted. The intent is written in its own committed transaction
    /// before any provider DDL work, and the DDL plus the `APPLIED` write
    /// share one transaction, so an `APPLYING` row for these exact bytes is
    /// proof that the DDL did not commit: the outcome is known, not guessed.
    IntentRecorded,
}

pub(super) fn v1_identity() -> SchemaMigrationIdentity {
    SchemaMigrationIdentity {
        migration_id: schema::MIGRATION_ID_V1.to_owned(),
        migration_checksum_sha256: schema::SCHEMA_DDL_V1_SHA256.to_owned(),
        generation: schema::GENERATION_V1.to_owned(),
    }
}

pub(super) fn schema_meta_record(
    migration: &CompiledMigration,
    updated_at: &str,
) -> SchemaMetaRecord {
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
        migration_state: schema::MIGRATION_STATE_APPLIED.to_owned(),
        migration_id: migration.migration_id.clone(),
        migration_checksum_sha256: migration.checksum_sha256.clone(),
        updated_at: updated_at.to_owned(),
    }
}

pub(super) fn schema_meta_record_for_v1_to_v2(
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
        migration_state: schema::MIGRATION_STATE_APPLIED.to_owned(),
        migration_id: migration.migration_id.clone(),
        migration_checksum_sha256: migration.checksum_sha256.clone(),
        updated_at: updated_at.to_owned(),
    }
}

/// The durable intent for one forward migration (issue #1221, W7/A8).
///
/// It is the same record the migration would commit, with the applied
/// generation, the applied migration identity, the same DDL bytes digest and
/// the same `updated_at` stamp, differing only in the state. Writing it in its
/// own committed transaction before the DDL transaction is what makes an
/// unknown outcome reconcilable: the DDL transaction writes
/// [`schema::MIGRATION_STATE_APPLIED`] over exactly these fields, so an
/// `APPLYING` row read back afterwards means the DDL never committed and the
/// recorded identity is the exact plan that was in flight.
pub(super) fn migration_intent_record(
    applied: &SchemaMetaRecord,
) -> SchemaMetaRecord {
    SchemaMetaRecord {
        generation: applied.generation.clone(),
        migrations: applied.migrations.clone(),
        compatible_bridge_range: applied.compatible_bridge_range.clone(),
        migration_state: schema::MIGRATION_STATE_APPLYING.to_owned(),
        migration_id: applied.migration_id.clone(),
        migration_checksum_sha256: applied.migration_checksum_sha256.clone(),
        updated_at: applied.updated_at.clone(),
    }
}

/// The applied record an intent row commits to: identical in every field
/// except the state, so the forward transaction's compare-and-set refuses any
/// row that is not exactly the intent this operation recorded.
pub(super) fn applied_record_from_intent(intent: &SchemaMetaRecord) -> SchemaMetaRecord {
    SchemaMetaRecord {
        generation: intent.generation.clone(),
        migrations: intent.migrations.clone(),
        compatible_bridge_range: intent.compatible_bridge_range.clone(),
        migration_state: schema::MIGRATION_STATE_APPLIED.to_owned(),
        migration_id: intent.migration_id.clone(),
        migration_checksum_sha256: intent.migration_checksum_sha256.clone(),
        updated_at: intent.updated_at.clone(),
    }
}

pub(super) fn validate_schema_meta_record(record: &SchemaMetaRecord) -> Result<(), AdapterError> {
    validate_schema_meta_record_in_state(record, schema::MIGRATION_STATE_APPLIED)
}

/// Validates a recorded `schema_meta` row against the one state it is
/// required to hold, for the applied row and for the durable intent row
/// (issue #1221, W7/A8).
///
/// Every other check is shared: the migration history, the head identity, the
/// generation-specific identity and the bridge range are exactly the same
/// whether the row is applied or in flight, so an intent row is validated as
/// strictly as an applied one and cannot be a thinner record that a migration
/// writes in order to bypass history.
fn validate_schema_meta_record_in_state(
    record: &SchemaMetaRecord,
    expected_state: &str,
) -> Result<(), AdapterError> {
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
    if record.migration_state != expected_state {
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

/// Validates a durable migration intent against the exact plan that presented
/// it, and reports whether the recorded plan is this one.
///
/// The identity is compared, not restated: a row whose recorded migration id,
/// DDL bytes digest, target generation, bridge range or predecessor
/// generation is any other plan's is refused rather than adopted, so a stale
/// or foreign intent can never be completed by this migration. The successor
/// record is the row read back from the provider, not a record rebuilt from
/// the plan that asked for it.
pub(super) fn validate_migration_intent_record(
    record: &SchemaMetaRecord,
    migration: &CompiledMigration,
) -> Result<(), AdapterError> {
    validate_schema_meta_record_in_state(record, schema::MIGRATION_STATE_APPLYING)?;
    if record.migration_id != migration.migration_id
        || record.migration_checksum_sha256 != migration.checksum_sha256
        || record.generation != migration.generation_after.as_str()
        || record.compatible_bridge_range != migration.bridge_range
    {
        return Err(AdapterError::PartialOutcome);
    }
    if migration.predecessor_migration_id.is_none() || migration.predecessor_generation.is_none() {
        return Err(AdapterError::Config(
            "a durable migration intent requires a plan with a bound predecessor".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_fence_record(record: &FenceRecord) -> Result<(), AdapterError> {
    record
        .state_fence
        .validate()
        .map_err(StoreError::Foundation)?;
    if record.next_commit_sequence == 0 || record.next_outbox_sequence == 0 {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}
