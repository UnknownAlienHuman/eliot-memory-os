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
}

pub(super) fn v1_identity() -> SchemaMigrationIdentity {
    SchemaMigrationIdentity {
        migration_id: schema::MIGRATION_ID_V1.to_owned(),
        migration_checksum_sha256: schema::SCHEMA_DDL_V1_SHA256.to_owned(),
        generation: schema::GENERATION_V1.to_owned(),
    }
}

pub(super) fn validate_v1_pin() -> bool {
    eliot_store_api::sha256_hex(schema::SCHEMA_DDL.as_bytes()) == schema::SCHEMA_DDL_V1_SHA256
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
        migration_state: "APPLIED".to_owned(),
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
        migration_state: "APPLIED".to_owned(),
        migration_id: migration.migration_id.clone(),
        migration_checksum_sha256: migration.checksum_sha256.clone(),
        updated_at: updated_at.to_owned(),
    }
}

pub(super) fn validate_schema_meta_record(record: &SchemaMetaRecord) -> Result<(), AdapterError> {
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
