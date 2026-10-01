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
    /// The forward step from the second generation into the third, which is the
    /// generation the capture census is built for. It reuses the same forward
    /// transaction, intent record and predecessor compare-and-set as
    /// [`MigrationPreflight::V1ToV2`]; only the generation the step starts from
    /// differs, and it is compared against the row read back from the provider.
    V2ToV3,
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
    let head = || SchemaMigrationIdentity {
        migration_id: migration.migration_id.clone(),
        migration_checksum_sha256: migration.checksum_sha256.clone(),
        generation: migration.generation_after.as_str().to_owned(),
    };
    let migrations = if migration.generation_after.as_str() == schema::GENERATION_V2 {
        // A fresh second-generation baseline subsumes the first generation, so
        // its recorded history starts at the first-generation identity.
        vec![v1_identity(), head()]
    } else if migration.generation_after.as_str() == schema::GENERATION_V3 {
        // A fresh third-generation baseline subsumes both earlier generations,
        // so its recorded history is the complete chain rather than only its
        // own head. Each earlier entry is the identity that owner publishes for
        // that generation, never this plan's own values, and the digests are the
        // digests of the published DDL bodies. This is the same construction the
        // second-generation case already used for the first generation.
        vec![v1_identity(), v2_baseline_identity(), head()]
    } else {
        vec![head()]
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
pub(super) fn migration_intent_record(applied: &SchemaMetaRecord) -> SchemaMetaRecord {
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

/// The identity a fresh second-generation baseline records for itself.
///
/// The digest is derived from the published baseline DDL, the same bytes the
/// plan for that generation is built from, so the recorded entry is the owner's
/// own identity rather than a value supplied by a caller.
fn v2_baseline_identity() -> SchemaMigrationIdentity {
    SchemaMigrationIdentity {
        migration_id: schema::MIGRATION_ID_V2.to_owned(),
        migration_checksum_sha256: eliot_store_api::sha256_hex(schema::SCHEMA_DDL_V2.as_bytes()),
        generation: schema::GENERATION_V2.to_owned(),
    }
}

/// Reports whether one recorded history entry is the admitted head of the
/// second generation.
///
/// A store reaches generation 2 either by the fresh-database v2 baseline or by
/// the additive v1-to-v2 delta, so the entry that closed generation 2 is one of
/// exactly two admitted identities. Each is compared against the digest of the
/// DDL bytes this owner publishes for it, so the expected pair is derived from
/// [`crate::schema`] and never from the entry being checked: a third way of
/// reaching generation 2 is a refusal rather than a silently widened case.
///
/// Both the second-generation record and the third-generation record below are
/// checked against this one pair, so a v3 history carries the same v2 evidence
/// a v2 record did rather than a restatement of it.
fn is_admitted_v2_entry(entry: &SchemaMigrationIdentity) -> bool {
    let full = eliot_store_api::sha256_hex(schema::SCHEMA_DDL_V2.as_bytes());
    let delta = eliot_store_api::sha256_hex(schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.as_bytes());
    (entry.migration_id == schema::MIGRATION_ID_V2 && entry.migration_checksum_sha256 == full)
        || (entry.migration_id == schema::MIGRATION_ID_V1_TO_V2
            && entry.migration_checksum_sha256 == delta)
}

/// Reports whether one recorded history entry is the admitted head of the third
/// generation.
///
/// Generation 3 has exactly two admitted routes into it — the additive v2-to-v3
/// delta, which a store that already carries a row takes, and the third-
/// generation fresh-database baseline, which only an empty database takes — so
/// this is a pair rather than a single identity. Each entry is compared against
/// the digest of the published DDL body it names, so the expected set is derived
/// from [`crate::schema`] and never from the entry being checked.
fn is_admitted_v3_entry(entry: &SchemaMigrationIdentity) -> bool {
    let delta = eliot_store_api::sha256_hex(schema::SCHEMA_MIGRATION_V2_TO_V3_DDL.as_bytes());
    let baseline = eliot_store_api::sha256_hex(schema::SCHEMA_DDL_V3.as_bytes());
    (entry.migration_id == schema::MIGRATION_ID_V2_TO_V3
        && entry.migration_checksum_sha256 == delta)
        || (entry.migration_id == schema::MIGRATION_ID_V3
            && entry.migration_checksum_sha256 == baseline)
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
    // Everything above is shared by every generation. What distinguishes one
    // recorded row from another is the history its own generation was reached
    // by, so that is dispatched to one arm per generation: the third
    // generation is a peer of the first and second here rather than a fourth
    // block appended to this function, and a generation this owner does not
    // publish is refused rather than falling through with the shared checks
    // above as though they were enough.
    validate_generation_history(record)?;
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

/// Reports whether one recorded history entry is the admitted first-generation
/// baseline identity.
///
/// The comparison is against [`v1_identity`], the identity this owner publishes
/// for generation 1, never against the entry being checked. Every generation
/// whose history is a chain rather than a single baseline begins with this
/// entry, so the later generations are checked against the same published
/// evidence the first-generation record was, not against a restatement of it.
fn is_admitted_v1_entry(entry: &SchemaMigrationIdentity) -> bool {
    let expected = v1_identity();
    entry.migration_id == expected.migration_id
        && entry.migration_checksum_sha256 == expected.migration_checksum_sha256
        && entry.generation == expected.generation
}

/// Dispatches to the one history validator the record's own generation admits.
///
/// A generation this owner does not publish has no arm and is refused: the
/// shared shape, bridge and head checks that ran before this dispatch are not
/// sufficient on their own, so falling through to them would admit a record
/// whose history was never validated at all.
fn validate_generation_history(record: &SchemaMetaRecord) -> Result<(), AdapterError> {
    match record.generation.as_str() {
        schema::GENERATION_V1 => validate_v1_history(record),
        schema::GENERATION_V2 => validate_v2_history(record),
        schema::GENERATION_V3 => validate_v3_history(record),
        _ => Err(AdapterError::PartialOutcome),
    }
}

/// Validates the recorded history of a first-generation row.
///
/// Generation 1 is reached only by its fresh-database baseline, so its history
/// is exactly that one published identity and the recorded head is that same
/// identity rather than any other plan's values.
fn validate_v1_history(record: &SchemaMetaRecord) -> Result<(), AdapterError> {
    let expected = v1_identity();
    if record.migrations.len() != 1 {
        return Err(AdapterError::PartialOutcome);
    }
    if !is_admitted_v1_entry(&record.migrations[0]) {
        return Err(AdapterError::PartialOutcome);
    }
    if record.migration_id != schema::MIGRATION_ID_V1
        || record.migration_checksum_sha256 != expected.migration_checksum_sha256
    {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Validates the recorded history of a second-generation row.
///
/// Generation 2 is reached either by its own fresh-database baseline or by the
/// additive v1-to-v2 delta, so its history is the first-generation identity
/// followed by one of the two admitted ways of closing generation 2, and the
/// recorded head is that closing entry.
fn validate_v2_history(record: &SchemaMetaRecord) -> Result<(), AdapterError> {
    if record.migrations.len() != 2 {
        return Err(AdapterError::PartialOutcome);
    }
    if !is_admitted_v1_entry(&record.migrations[0]) {
        return Err(AdapterError::PartialOutcome);
    }
    let last = &record.migrations[1];
    if last.generation != schema::GENERATION_V2 || !is_admitted_v2_entry(last) {
        return Err(AdapterError::PartialOutcome);
    }
    if record.migration_id != last.migration_id
        || record.migration_checksum_sha256 != last.migration_checksum_sha256
    {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Validates the recorded history of a third-generation row.
///
/// The third generation is additive over the second, so its history is the
/// complete admitted v1 and v2 evidence plus exactly one v2-to-v3 entry. Every
/// position is compared against the published identity it must carry and the
/// recorded head must equal the last entry, so a v3 row can neither skip a
/// generation nor claim a head the chain did not reach. A record of any other
/// length, or whose second entry is not one of the two admitted ways of
/// reaching generation 2, is refused rather than accepted as a shorter or
/// differently-arrived history.
fn validate_v3_history(record: &SchemaMetaRecord) -> Result<(), AdapterError> {
    if record.migrations.len() != 3 {
        return Err(AdapterError::PartialOutcome);
    }
    if !is_admitted_v1_entry(&record.migrations[0]) {
        return Err(AdapterError::PartialOutcome);
    }
    let second = &record.migrations[1];
    if second.generation != schema::GENERATION_V2 || !is_admitted_v2_entry(second) {
        return Err(AdapterError::PartialOutcome);
    }
    let last = &record.migrations[2];
    if !is_admitted_v3_entry(last) {
        return Err(AdapterError::PartialOutcome);
    }
    if record.migration_id != last.migration_id
        || record.migration_checksum_sha256 != last.migration_checksum_sha256
    {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Validates a durable migration intent against the exact plan presenting it.
///
/// The identity is compared, not restated: a row whose recorded migration id,
/// DDL bytes digest, target generation, bridge range or predecessor is any
/// other plan's is refused rather than adopted, so a stale or foreign intent
/// can never be completed by this migration. The row compared is the one read
/// back from the provider, never a record rebuilt from the plan that asked.
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
    // Only a plan the published graph binds to a predecessor can leave a
    // resumable intent: a fresh-database baseline has nothing to resume, and
    // its DDL commits with the record it creates in one transaction.
    if migration.predecessor_generation.as_deref()
        != crate::schema_inventory::required_predecessor_generation(&migration.migration_id)
        || migration.predecessor_migration_id.as_deref()
            != crate::schema_inventory::required_predecessor_migration_id(&migration.migration_id)
    {
        return Err(AdapterError::PartialOutcome);
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
