//! Durable restore-journal backend inside the existing ORS store (issue #957).
//!
//! The three existing v1 table names are retained as the physical row-family
//! identity. Their record/index layout is explicitly v2 and is admitted only by
//! a complete marker set. A v1 marker, a partial table set, a foreign table or
//! an unbound history is never silently upgraded: the one exception is a legacy
//! journal that holds nothing a v2 reader would have to reinterpret, which the
//! explicit additive migration may promote. A legacy journal that holds rows or
//! non-binding metadata — including the old `pruned\0<stream>` markers — is
//! refused with a migration error instead.
//!
//! All journal mutations use one short Redb write transaction. The unique
//! phase-slot index, sequence row and (when present) result row are committed
//! together. A receipt is owner-issued only after current-owner readback.
//!
//! An append-triggered retention pass is composed into that same transaction
//! and runs only after the append has been admitted against the addressed
//! stream binding, the exact operation/envelope identity, the retired-slot and
//! budget preconditions and the current predecessor. A refused append therefore
//! cannot commit a reclamation, and an exact replay cannot reclaim the very row
//! whose persisted receipt it returns.

use std::collections::{BTreeMap, BTreeSet};

use redb::{
    ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
    WriteTransaction,
};
use serde::{Deserialize, Serialize};

use super::RedbRecoveryStore;
use super::persistence_codec::encode;
use super::storage;
use crate::OrsError;
use crate::model::sha256_hex;
use crate::restore_journal::{
    JournalPredecessor, MAX_JOURNAL_HISTORY_ENTRIES, MAX_JOURNAL_PAGE_ENTRIES,
    MAX_JOURNAL_STREAM_KEY_BYTES, MAX_JOURNAL_TOTAL_BYTES, MAX_JOURNAL_WORK_ENTRIES,
    RESTORE_JOURNAL_RECORD_SCHEMA, RESTORE_JOURNAL_SCHEMA_VERSION, RestoreJournalAppendReceipt,
    RestoreJournalCompleteness, RestoreJournalEntry, RestoreJournalMemberDenominator,
    RestoreJournalOperation, RestoreJournalReadback, RestoreJournalReadbackRequest,
    RestoreJournalReceiptKind, RestoreJournalResult, RestoreJournalRetentionDisposition,
    RestoreJournalRetentionFrontier, RestoreJournalRetentionPolicy, RestoreJournalRetentionRecord,
    RestoreJournalRetentionReport, RestoreJournalStreamBinding,
};

/// Versioned intent table: owner-neutral restore intent rows.
const RESTORE_JOURNAL_INTENTS: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("ors_restore_journal_intents_v1");
/// Versioned result table: receipts answering exact committed intents.
const RESTORE_JOURNAL_RESULTS: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("ors_restore_journal_results_v1");
/// Dedicated journal meta table: schema, bindings, fences and unique indexes.
const RESTORE_JOURNAL_META: TableDefinition<'static, &'static str, &'static str> =
    TableDefinition::new("ors_restore_journal_meta_v1");
/// Schema marker row inside the meta table.
const RESTORE_JOURNAL_SCHEMA_ROW: &str = "schema";
/// Ceiling on a persisted table name, marker, or tombstone key, checked BEFORE
/// the value is copied out of Redb. Cloning first would let a corrupt row force
/// an unbounded allocation before the aggregate byte ceiling could reject it.
const MAX_JOURNAL_NAME_BYTES: usize = 1024;
/// Markers are short fixed identities; anything larger is corrupt by definition.
const MAX_JOURNAL_MARKER_BYTES: usize = 256;

/// Copies a bounded table name out of a Redb handle.
pub(super) fn bound_table_name(name: &str) -> Result<String, OrsError> {
    if name.len() > MAX_JOURNAL_NAME_BYTES {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    Ok(name.to_owned())
}

/// Reads one schema/adoption marker, rejecting an oversized value before it is
/// cloned into a `String`.
fn read_marker<T: ReadableTable<&'static str, &'static str>>(
    table: &T,
    key: &str,
) -> Result<Option<String>, OrsError> {
    let Some(value) = table.get(key).map_err(storage)? else {
        return Ok(None);
    };
    if value.value().len() > MAX_JOURNAL_MARKER_BYTES {
        return Err(integrity(
            "restore_journal_meta",
            "persisted marker exceeds the marker byte bound",
        ));
    }
    Ok(Some(value.value().to_owned()))
}

/// Explicit additive migration marker row.
const RESTORE_JOURNAL_MIGRATION_ROW: &str = "migration/operation-index-v2";
const RESTORE_JOURNAL_SCHEMA_IDENTITY: &str = "ors-restore-journal-schema-v2";
const RESTORE_JOURNAL_MIGRATION_IDENTITY: &str = "eliot.ors.restore-journal.operation-index.v2";
/// Marker written by the superseded v1 layout. It carried no unique operation
/// index, no additive migration marker and admitted plaintext payload/receipt
/// bytes, so its rows can never be reinterpreted as v2 rows.
const RESTORE_JOURNAL_LEGACY_SCHEMA_IDENTITY: &str = "ors-restore-journal-schema-v1";

/// Key namespace separator (never valid inside validated text fields).
const KEY_SEP: char = '\0';
const INTENT_PREFIX: &str = "intent";
const RESULT_PREFIX: &str = "result";
const BINDING_PREFIX: &str = "binding";
const HISTORY_PREFIX: &str = "history";
const OPERATION_PREFIX: &str = "operation";
const USED_PREFIX: &str = "used";
const HEAD_PREFIX: &str = "head";
/// Durable retention-decision row: what the last reclamation pass reclaimed
/// and which recovery-needed members it refused to evict.
const RETENTION_PREFIX: &str = "retention";
/// Ceiling on database tables enumerated by the journal family check. Every
/// journal entry point runs that check, so the scan itself must be bounded.
const MAX_JOURNAL_TABLES_SCANNED: usize = 4096;
/// Tombstone marker for a phase slot whose operation index was pruned. The
/// value is a fixed token: only the presence of the row carries meaning, so no
/// pruned payload or identity byte is retained.
const TOMBSTONE_VALUE: &str = "1";

/// Durable prune fence for one stream.
///
/// It carries the exact predecessor of the first retained row AND the number of
/// phase slots retired so far. The count is what makes the retired-slot set
/// verifiable: a store that kept a fence but lost tombstones no longer
/// satisfies `tombstone_count == fence.retired_slots`, so a deleted tombstone
/// cannot silently make a retired phase slot reusable.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalHistoryFence {
    predecessor: JournalPredecessor,
    retired_slots: u64,
}

impl JournalHistoryFence {
    fn validate(&self) -> Result<(), OrsError> {
        self.predecessor.validate()?;
        if self.retired_slots == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: "restore_journal_meta",
                reason: "a history fence must retire at least one phase slot".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreJournalOperationIndex {
    stream: String,
    slot_identity: String,
    slot_sha256: String,
    operation_identity: String,
    operation_sha256: String,
    transaction_id: String,
    phase_operation: String,
    payload_sha256: String,
    intent_key: String,
    intent_sequence: u64,
    intent_record_sha256: String,
    result_key: Option<String>,
    result_record_sha256: Option<String>,
}

impl RestoreJournalOperationIndex {
    fn validate(&self) -> Result<(), OrsError> {
        validate_journal_text(&self.stream, "journal.index_stream")?;
        crate::model::validate_digest(&self.slot_sha256, "journal.slot_sha256")?;
        crate::model::validate_digest(&self.operation_sha256, "journal.operation_sha256")?;
        crate::model::validate_digest(&self.payload_sha256, "journal.index_payload_sha256")?;
        crate::model::validate_digest(
            &self.intent_record_sha256,
            "journal.index_intent_record_sha256",
        )?;
        if let Some(result_digest) = &self.result_record_sha256 {
            crate::model::validate_digest(result_digest, "journal.index_result_record_sha256")?;
        }
        if self.result_key.is_some() != self.result_record_sha256.is_some() {
            return Err(OrsError::IntegrityProblem {
                record_type: "restore_journal_index",
                reason: "partial result index binding".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Default)]
struct JournalStreamState {
    binding: Option<RestoreJournalStreamBinding>,
    history_fence: Option<JournalHistoryFence>,
    intents: BTreeMap<u64, RestoreJournalEntry>,
    intent_slots: BTreeMap<String, u64>,
    indexes: BTreeMap<String, RestoreJournalOperationIndex>,
    results: BTreeMap<String, RestoreJournalResult>,
    /// Phase slots already consumed by a pruned operation. The unique operation
    /// index is deleted together with a pruned row, so without these durable
    /// tombstones a retired (stream, transaction, phase) slot could be reused
    /// for an unrelated operation.
    used_slots: BTreeSet<String>,
    /// Durable head: the predecessor of the next append. Updated in the same
    /// transaction as every append and prune, so losing the newest retained row
    /// is detected instead of yielding a truncated history that still looks
    /// contiguous.
    head: Option<JournalPredecessor>,
    /// Durable retention decision committed with the last reclamation. Absent
    /// on a store that never pruned and on one written before the decision
    /// existed; its presence is checked against the prune fence rather than
    /// assumed, so an older retained history is never upgraded into a claimed
    /// one.
    retention: Option<RestoreJournalRetentionRecord>,
}

impl JournalStreamState {
    /// Computes the head the persisted rows imply, without consulting the
    /// durable head record.
    fn derived_head(&self) -> Result<Option<JournalPredecessor>, OrsError> {
        if let Some((sequence, entry)) = self.intents.iter().next_back() {
            return Ok(Some(JournalPredecessor {
                sequence: *sequence,
                digest: entry.digest()?,
            }));
        }
        Ok(self
            .history_fence
            .as_ref()
            .map(|fence| fence.predecessor.clone()))
    }
}

#[derive(Default)]
struct JournalState {
    streams: BTreeMap<String, JournalStreamState>,
    total_bytes: usize,
    work: usize,
}

impl JournalState {
    fn stream_mut(&mut self, stream: &str) -> &mut JournalStreamState {
        self.streams.entry(stream.to_owned()).or_default()
    }

    fn stream(&self, stream: &str) -> Result<&JournalStreamState, OrsError> {
        self.streams.get(stream).ok_or_else(|| {
            integrity(
                "restore_journal_binding",
                "journal stream has no persisted binding",
            )
        })
    }
}

/// Initializes the journal layout inside an existing Redb write transaction.
///
/// This is deliberately an `initialize` hook, not a second initialization
/// transaction. A fresh store is created directly at v2. A store already at v2
/// is validated unchanged. A store still carrying the superseded v1 marker is
/// migrated by this explicit additive step, but only when it holds no intent or
/// result row: a v1 row admitted plaintext payload bytes and no unique
/// operation index, so it can never be reinterpreted as a v2 row and is
/// refused instead. A foreign, partial or mixed table family, and any unknown
/// marker, is a migration error.
/// Enumerates the database table names and classifies the restore-journal family
/// on any readable database, bounded exactly as the write-side path is.
/// Enumerates and classifies the restore-journal table family on a read
/// transaction. Every journal read funnels through this, so a foreign
/// `ors_restore_journal_*` table, or a family that is not exactly the declared
/// three, is refused rather than silently ignored while a read or a receipt
/// verification reports success.
fn validate_journal_table_names(read: &redb::ReadTransaction) -> Result<(), OrsError> {
    let mut discovered = BTreeSet::new();
    for table in read.list_tables().map_err(storage)? {
        discovered.insert(bound_table_name(table.name())?);
        if discovered.len() > MAX_JOURNAL_TABLES_SCANNED {
            return Err(OrsError::ProjectionLimitExceeded);
        }
    }
    classify_journal_table_family(&discovered, false)
}

/// Classifies an enumerated table-name set against the declared journal family.
///
/// `allow_absent` is set only by the write-side initializer, which is allowed to
/// create the family on a store that has none yet. Read paths always require the
/// full family.
fn classify_journal_table_family(
    discovered: &BTreeSet<String>,
    allow_absent: bool,
) -> Result<(), OrsError> {
    let expected = [
        RESTORE_JOURNAL_INTENTS.name(),
        RESTORE_JOURNAL_RESULTS.name(),
        RESTORE_JOURNAL_META.name(),
    ];
    let present = expected
        .iter()
        .filter(|name| discovered.contains(**name))
        .count();
    let foreign = discovered
        .iter()
        .any(|name| name.starts_with("ors_restore_journal_") && !expected.contains(&name.as_str()));
    let acceptable = if allow_absent {
        present == 0 || present == expected.len()
    } else {
        present == expected.len()
    };
    if foreign || !acceptable {
        return Err(migration(
            "restore journal table family is foreign, partial, or mixed",
        ));
    }
    Ok(())
}

/// Initializes the journal layout inside an existing Redb write transaction.
///
/// Returns `true` when this call CREATED the table family, which the caller uses
/// to tell a genuinely fresh store from one whose journal family had gone
/// missing. Everything happens in the caller's transaction, so a refusal after
/// this returns rolls the creation back.
pub(super) fn initialize_restore_journal_schema(
    write: &WriteTransaction,
) -> Result<bool, OrsError> {
    let table_names = bounded_table_names(write)?;
    let family_absent = !table_names.contains(RESTORE_JOURNAL_INTENTS.name());
    // Read the adoption marker BEFORE creating anything. Every entry point that
    // can materialize the family funnels through this function, so a family that
    // vanished after this store adopted it is refused here rather than being
    // silently recreated as an empty journal. A pre-change store that never had
    // a journal family carries no marker, so it still adopts cleanly.
    let already_adopted = read_adoption_marker(write)?.is_some();
    classify_journal_table_family(&table_names, true)?;
    if family_absent && already_adopted {
        return Err(migration(
            "restore journal tables are absent from a store that already adopted them",
        ));
    }

    if family_absent {
        let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        meta.insert(RESTORE_JOURNAL_SCHEMA_ROW, RESTORE_JOURNAL_SCHEMA_IDENTITY)
            .map_err(storage)?;
        meta.insert(
            RESTORE_JOURNAL_MIGRATION_ROW,
            RESTORE_JOURNAL_MIGRATION_IDENTITY,
        )
        .map_err(storage)?;
        drop(meta);
        drop(write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?);
        drop(write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?);
    } else if migrate_legacy_journal_to_v2(write)? {
        // The additive migration markers are written inside the caller's write
        // transaction, so the upgrade commits atomically with the rest of
        // `initialize` and a repeated open observes an already-migrated store.
    }

    let meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
    let schema = read_marker(&meta, RESTORE_JOURNAL_SCHEMA_ROW)?;
    let migration_marker = read_marker(&meta, RESTORE_JOURNAL_MIGRATION_ROW)?;
    if schema.as_deref() != Some(RESTORE_JOURNAL_SCHEMA_IDENTITY)
        || migration_marker.as_deref() != Some(RESTORE_JOURNAL_MIGRATION_IDENTITY)
    {
        return Err(migration(
            "restore journal schema or additive migration marker is unsupported",
        ));
    }
    let intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
    let results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
    validate_journal_tables(&intents, &results, &meta)?;
    record_adoption_marker(write, already_adopted)?;
    // POSTCONDITION on the table ceiling. The pre-check above only sees the
    // store as it was; creating the family adds three tables, and the caller may
    // have added more just before this call. Checking only up front would let a
    // successful transaction commit a table count that every later journal read
    // rejects, turning a bounded store into an unreadable one. This runs inside
    // the caller's transaction, so a refusal discards the whole thing.
    bounded_table_names(write)?;
    Ok(family_absent)
}

/// Enumerates the database table names, bounding both the name length and the
/// count. Every journal entry point runs this, so the scan itself is bounded.
fn bounded_table_names(write: &WriteTransaction) -> Result<BTreeSet<String>, OrsError> {
    let mut discovered = BTreeSet::new();
    for table in write.list_tables().map_err(storage)? {
        discovered.insert(bound_table_name(table.name())?);
        if discovered.len() > MAX_JOURNAL_TABLES_SCANNED {
            return Err(OrsError::ProjectionLimitExceeded);
        }
    }
    Ok(discovered)
}

/// Schema identity the store records once it has adopted a v2 journal family.
pub(super) const RESTORE_JOURNAL_ADOPTION_IDENTITY: &str = "ors-restore-journal-schema-v2";

/// Reads the base-`META` adoption marker, byte-bounded before it is cloned.
fn read_adoption_marker(write: &WriteTransaction) -> Result<Option<String>, OrsError> {
    let meta = write.open_table(super::META).map_err(storage)?;
    read_marker(&meta, super::RESTORE_JOURNAL_ADOPTION_KEY)
}

/// Records adoption additively and idempotently. It lives in the base `META`
/// table, outside the journal family, so it survives deletion of those tables —
/// which is exactly what lets a vanished family be told apart from a fresh one.
fn record_adoption_marker(write: &WriteTransaction, already_adopted: bool) -> Result<(), OrsError> {
    if already_adopted {
        return Ok(());
    }
    let mut meta = write.open_table(super::META).map_err(storage)?;
    meta.insert(
        super::RESTORE_JOURNAL_ADOPTION_KEY,
        RESTORE_JOURNAL_ADOPTION_IDENTITY,
    )
    .map_err(storage)?;
    Ok(())
}

/// Applies the explicit additive v1 to v2 migration and reports whether it ran.
///
/// The promotion is deliberately narrow. A legacy journal is promotable only
/// when it carries nothing that v2 would have to reinterpret:
///
/// * no intent and no result row — those admitted plaintext payload bytes and
///   no unique operation index;
/// * no `migration/operation-index-v2` row, or exactly the v2 identity — an
///   unexpected value is never silently overwritten;
/// * no metadata row outside `schema` and `binding\0<stream>`. The legacy
///   layout wrote `pruned\0<stream>` markers, which record a pruning history
///   this layout cannot represent, so they are refused rather than dropped.
///
/// Stream bindings carry no version-specific interpretation and are preserved
/// untouched. Everything else is a `MigrationRequired` refusal, which is
/// operator-visible and actionable rather than a silent promotion.
fn migrate_legacy_journal_to_v2(write: &WriteTransaction) -> Result<bool, OrsError> {
    let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
    let schema = read_marker(&meta, RESTORE_JOURNAL_SCHEMA_ROW)?;
    let Some(schema) = schema else {
        return Ok(false);
    };
    if schema == RESTORE_JOURNAL_SCHEMA_IDENTITY {
        return Ok(false);
    }
    if schema != RESTORE_JOURNAL_LEGACY_SCHEMA_IDENTITY {
        return Err(migration(
            "restore journal schema identity is not a recognized layout",
        ));
    }
    let migration_marker = read_marker(&meta, RESTORE_JOURNAL_MIGRATION_ROW)?;
    if migration_marker
        .as_deref()
        .is_some_and(|marker| marker != RESTORE_JOURNAL_MIGRATION_IDENTITY)
    {
        return Err(migration(
            "restore journal additive migration marker is not the v2 identity",
        ));
    }
    let mut scanned = 0_usize;
    for entry in meta.iter().map_err(storage)? {
        scanned = scanned.saturating_add(1);
        if scanned > MAX_JOURNAL_WORK_ENTRIES {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let (key, _) = entry.map_err(storage)?;
        let key = key.value();
        if key == RESTORE_JOURNAL_SCHEMA_ROW || key == RESTORE_JOURNAL_MIGRATION_ROW {
            continue;
        }
        if namespace_value(key, BINDING_PREFIX).is_none() {
            return Err(migration(
                "legacy restore journal holds metadata that cannot be represented as v2",
            ));
        }
    }
    let intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
    let results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
    if !intents.is_empty().map_err(storage)? || !results.is_empty().map_err(storage)? {
        return Err(migration(
            "legacy restore journal holds rows that cannot be reinterpreted as v2",
        ));
    }
    drop(intents);
    drop(results);
    meta.insert(RESTORE_JOURNAL_SCHEMA_ROW, RESTORE_JOURNAL_SCHEMA_IDENTITY)
        .map_err(storage)?;
    meta.insert(
        RESTORE_JOURNAL_MIGRATION_ROW,
        RESTORE_JOURNAL_MIGRATION_IDENTITY,
    )
    .map_err(storage)?;
    Ok(true)
}

/// One resolved operation a prune will drop, with everything needed to remove
/// its rows, retire its phase slot and advance the fence.
struct PruneRemoval {
    sequence: u64,
    intent_row_key: String,
    result_row_key: String,
    index_key: String,
    tombstone_key: String,
    predecessor: JournalPredecessor,
}

/// How many resolved operations this prune may drop, honouring `keep_resolved`.
fn resolved_prefix_target(stream_state: &JournalStreamState, keep_resolved: usize) -> usize {
    let resolved_count = stream_state
        .indexes
        .values()
        .filter(|index| index.result_key.is_some())
        .count();
    resolved_count.saturating_sub(keep_resolved)
}

/// Exact phase slot a retained intent occupies.
///
/// A retained intent without a derivable phase identity cannot be matched to
/// its unique operation index, which is an integrity refusal rather than a
/// skipped row.
fn intent_slot(stream: &str, entry: &RestoreJournalEntry) -> Result<String, OrsError> {
    Ok(sha256_hex(
        entry
            .operation
            .phase_identity(stream)
            .map_err(|_| integrity("restore_journal_index", "invalid phase identity"))?
            .as_bytes(),
    ))
}

/// The recovery-needed members a retention pass refuses to evict.
///
/// This is recomputed from current owner state rather than carried from the
/// plan, so the reported frontier is the one that still holds. Only a durable
/// result makes a member resolved, so reclamation can never lower it.
fn unresolved_frontier(
    stream: &str,
    stream_state: &JournalStreamState,
) -> Result<RestoreJournalRetentionFrontier, OrsError> {
    let mut unresolved_members = 0_u64;
    let mut oldest_unresolved_sequence = None;
    for (sequence, entry) in &stream_state.intents {
        let slot = intent_slot(stream, entry)?;
        let index = stream_state
            .indexes
            .get(&slot)
            .ok_or_else(|| integrity("restore_journal_index", "operation index is missing"))?;
        if index.result_key.is_some() {
            continue;
        }
        if oldest_unresolved_sequence.is_none() {
            oldest_unresolved_sequence = Some(*sequence);
        }
        unresolved_members = unresolved_members.saturating_add(1);
    }
    let retained_members = u64::try_from(stream_state.intents.len()).unwrap_or(u64::MAX);
    Ok(RestoreJournalRetentionFrontier {
        unresolved_members,
        oldest_unresolved_sequence,
        policy_retained_members: retained_members.saturating_sub(unresolved_members),
    })
}

/// Plans the oldest contiguous resolved prefix. It stops at the first unresolved
/// intent, because removing a newer resolved pair while an unresolved operation
/// stays in the prefix would evict recovery-needed state out of order.
fn plan_resolved_prefix(
    stream: &str,
    stream_state: &JournalStreamState,
    target: usize,
) -> Result<Vec<PruneRemoval>, OrsError> {
    let mut removals = Vec::new();
    if target == 0 {
        return Ok(removals);
    }
    for (sequence, entry) in &stream_state.intents {
        if removals.len() >= target {
            break;
        }
        let slot = intent_slot(stream, entry)?;
        let Some(index) = stream_state.indexes.get(&slot) else {
            return Err(integrity(
                "restore_journal_index",
                "operation index is missing",
            ));
        };
        let Some(result_key) = index.result_key.as_ref() else {
            break;
        };
        removals.push(PruneRemoval {
            sequence: *sequence,
            intent_row_key: intent_key(stream, *sequence),
            result_row_key: result_key.clone(),
            index_key: operation_key(&slot),
            tombstone_key: used_key(stream, &slot),
            predecessor: JournalPredecessor {
                sequence: *sequence,
                digest: entry
                    .digest()
                    .map_err(|_| integrity("restore_journal_entry", "entry digest is invalid"))?,
            },
        });
    }
    Ok(removals)
}

/// True when the presented predecessor is exactly the current journal head.
///
/// A stream with no retained row has no head, and a request that omits the
/// predecessor matches it. Every other relationship is a conflict: a caller
/// whose request was built against a reclaimed or superseded head must learn
/// that rather than append onto a head it never observed.
fn expected_predecessor_matches(
    operation: &RestoreJournalOperation,
    head: Option<&JournalPredecessor>,
) -> bool {
    match (&operation.expected_predecessor, head) {
        (None, None) => true,
        (Some(expected), Some(current)) => {
            expected.sequence == current.sequence && expected.digest == current.digest
        }
        _ => false,
    }
}

/// Reports whether already-validated stream state has reached the accepted
/// reclaim point of the retention policy.
///
/// This is deliberately a PURE function over the in-transaction
/// [`JournalStreamState`] the writer transaction has already validated, not a
/// preflight read. A separate read transaction would answer the pressure
/// question from a snapshot that a later prune could invalidate before the pass
/// runs, which is exactly the unlocked check-then-act race this must not have.
/// A stream that does not exist yet never reaches this function: the caller has
/// already refused an unbound stream. Both the retained members and the retired
/// phase-slot tombstones count, so a stream that has already reclaimed heavily
/// reaches the point again and is reclaimed again.
fn restore_journal_under_retention_pressure(
    stream_state: &JournalStreamState,
    policy: &RestoreJournalRetentionPolicy,
) -> bool {
    stream_state.intents.len() >= policy.reclaim_from_members
        || stream_state.used_slots.len() >= policy.reclaim_from_members
}

/// Reclaims the oldest contiguous resolved prefix under the accepted window.
///
/// The whole pass runs inside the caller's single write transaction, so the
/// removals, the phase-slot tombstones, the prune fence, the head and the
/// durable retention decision are one durable unit. An interrupted pass leaves
/// the journal exactly as it was, and a committed pass can never report a
/// reclamation it did not perform.
///
/// The pass stops at the first unresolved intent and never evicts a
/// recovery-needed member to stay under a bound: a reclamation the retired-slot
/// bound would refuse removes nothing and is reported as a refusal with the
/// frontier it stopped at.
#[allow(
    clippy::too_many_arguments,
    reason = "one bounded retention pass over three tables"
)]
fn retain_restore_journal_locked(
    intents: &mut redb::Table<'_, &'static str, &'static str>,
    results: &mut redb::Table<'_, &'static str, &'static str>,
    meta: &mut redb::Table<'_, &'static str, &'static str>,
    state: &JournalState,
    stream_state: &JournalStreamState,
    stream: &str,
    keep_resolved: usize,
) -> Result<RestoreJournalRetentionRecord, OrsError> {
    let frontier = unresolved_frontier(stream, stream_state)?;
    let retired_before = stream_state
        .history_fence
        .as_ref()
        .map_or(0_u64, |fence| fence.retired_slots);
    let target = resolved_prefix_target(stream_state, keep_resolved);
    // Refuse BEFORE removing anything when this pass would push the
    // retired-slot set past the same bound validation enforces. Committing
    // first and failing on the next read would brick an otherwise valid store,
    // and evicting an unresolved member to stay under the bound is exactly
    // what this pass must never do.
    let retired_after = retired_before.saturating_add(u64::try_from(target).unwrap_or(u64::MAX));
    let bound_refuses =
        usize::try_from(retired_after).unwrap_or(usize::MAX) > MAX_JOURNAL_HISTORY_ENTRIES;
    let removals = if bound_refuses {
        Vec::new()
    } else {
        plan_resolved_prefix(stream, stream_state, target)?
    };
    let removed_members = u64::try_from(removals.len()).unwrap_or(u64::MAX);
    let disposition = if bound_refuses {
        RestoreJournalRetentionDisposition::RefusedRetiredSlotBound
    } else if removed_members > 0 {
        RestoreJournalRetentionDisposition::ReclaimedResolvedPrefix
    } else {
        RestoreJournalRetentionDisposition::NoResolvedPrefixToReclaim
    };
    let record = RestoreJournalRetentionRecord {
        record_schema: RESTORE_JOURNAL_RECORD_SCHEMA.to_owned(),
        keep_resolved: u64::try_from(keep_resolved).unwrap_or(u64::MAX),
        removed_members,
        retired_members: retired_before.saturating_add(removed_members),
        disposition,
        frontier: RestoreJournalRetentionFrontier {
            policy_retained_members: frontier
                .policy_retained_members
                .saturating_sub(removed_members),
            ..frontier
        },
    };
    record.validate()?;
    RedbRecoveryStore::apply_prune(
        intents,
        results,
        meta,
        state,
        stream_state,
        stream,
        &removals,
        retired_before,
        &record,
    )?;
    Ok(record)
}

impl RedbRecoveryStore {
    /// Binds one stream to its exact restore context, durably and idempotently.
    ///
    /// A different binding for the same stream conflicts. A binding cannot be
    /// introduced beside an already persisted partial history.
    pub fn bind_restore_journal_stream(
        &self,
        stream: &str,
        binding: &RestoreJournalStreamBinding,
    ) -> Result<(), OrsError> {
        binding.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        let write = self.database.begin_write().map_err(storage)?;
        initialize_restore_journal_schema(&write)?;
        let intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
        let results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
        let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        let state = validate_journal_tables(&intents, &results, &meta)?;
        if let Some(existing) = state.streams.get(stream) {
            if existing.binding.as_ref() != Some(binding) {
                return Err(integrity(
                    "restore_journal_binding",
                    "conflicting binding for the same journal stream",
                ));
            }
            drop(intents);
            drop(results);
            drop(meta);
            write.commit().map_err(storage)?;
            return Ok(());
        }
        let encoded_binding = encode(binding)?;
        let encoded_key = binding_key(stream);
        ensure_work(state.work, 1)?;
        ensure_aggregate_bytes(state.total_bytes, encoded_binding.len() + encoded_key.len())?;
        meta.insert(encoded_key.as_str(), encoded_binding.as_str())
            .map_err(storage)?;
        drop(intents);
        drop(results);
        drop(meta);
        write.commit().map_err(storage)
    }

    /// Reads one stream binding only after validating the complete journal
    /// schema and index closure.
    pub fn load_restore_journal_binding(
        &self,
        stream: &str,
    ) -> Result<Option<RestoreJournalStreamBinding>, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        let state = self.read_restore_journal_state()?;
        Ok(state
            .streams
            .get(stream)
            .and_then(|stream_state| stream_state.binding.clone()))
    }

    /// Ensures the explicit versioned journal layout. This method is
    /// idempotent for a valid v2 layout and refuses to recreate a missing or
    /// legacy table.
    pub fn ensure_restore_journal_schema(&self) -> Result<u32, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        initialize_restore_journal_schema(&write)?;
        write.commit().map_err(storage)?;
        Ok(RESTORE_JOURNAL_SCHEMA_VERSION)
    }

    /// Appends one intent with exact binding, predecessor and unique-index
    /// compare, or replays the exact owner row.
    ///
    /// Every admission decision is taken inside the one write transaction that
    /// commits the append, and in this order: addressed stream binding, exact
    /// operation/envelope replay classification, retired phase slot, retained
    /// plus retired budget, current predecessor. Only then, and only for a
    /// genuinely new admitted append, is the bounded retention pass composed
    /// into the same transaction. A refusal at any step drops that transaction,
    /// so no bound, identity, retired-slot or predecessor refusal can leave a
    /// committed journal mutation behind.
    #[allow(
        clippy::too_many_lines,
        reason = "the atomic append boundary keeps validation, compare, indexes and readback together"
    )]
    pub fn append_restore_journal_intent(
        &self,
        stream: &str,
        operation: &RestoreJournalOperation,
        payload_sha256: &str,
        payload: &str,
    ) -> Result<RestoreJournalAppendReceipt, OrsError> {
        operation.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        crate::restore_journal::validate_envelope_bytes(
            payload,
            payload_sha256,
            "journal.payload",
        )?;
        let phase_identity = operation.phase_identity(stream)?;
        let slot_sha256 = sha256_hex(phase_identity.as_bytes());
        let operation_sha256 = operation.identity_sha256(stream)?;
        // The accepted retention window an append-triggered reclamation runs
        // under. It is the same policy the independent maintenance operation
        // applies, so the append path can never reclaim under a laxer window
        // than maintenance.
        let retention_policy = RestoreJournalRetentionPolicy::accepted();
        retention_policy.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        initialize_restore_journal_schema(&write)?;
        let mut intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
        let mut results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
        let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        let mut state = validate_journal_tables(&intents, &results, &meta)?;
        // Admission is decided against the SAME write transaction that later
        // commits this append, and nothing is written until the addressed stream
        // binding, the exact operation/envelope identity, the retired-slot and
        // budget preconditions and the current predecessor have all been proven.
        // A refused append therefore cannot leave a committed retention effect
        // behind: a retained row, phase-slot tombstone, prune fence, head or
        // retention decision is only ever reclaimed as part of an append that is
        // itself admitted and committed together with it.
        {
            let stream_state = state.stream(stream)?;
            if stream_state
                .binding
                .as_ref()
                .is_none_or(|binding| !operation.matches_binding(binding))
            {
                return Err(integrity(
                    "restore_journal_binding",
                    "operation does not match the persisted stream binding",
                ));
            }
            // Exact replay is classified BEFORE any retention effect. A replayed
            // operation is by definition still retained, so reclaiming here would
            // delete the very row whose persisted receipt the caller asked for
            // and turn an exact replay into a pruned-slot refusal. A changed
            // identity or payload in the same phase slot is an identity conflict
            // and performs no transition at all.
            if let Some(index) = stream_state.indexes.get(&slot_sha256) {
                let entry = stream_state
                    .intents
                    .get(&index.intent_sequence)
                    .ok_or_else(|| {
                        integrity("restore_journal_index", "operation index has no intent row")
                    })?;
                if index.operation_sha256 != operation_sha256
                    || index.payload_sha256 != payload_sha256
                    || entry.operation != *operation
                    || entry.payload != payload
                {
                    return Err(identity_conflict());
                }
                drop(intents);
                drop(results);
                drop(meta);
                write.commit().map_err(storage)?;
                return self.owner_receipt(
                    stream,
                    &slot_sha256,
                    RestoreJournalReceiptKind::Intent,
                    true,
                );
            }
            if stream_state.used_slots.contains(&slot_sha256) {
                // The operation that owned this phase slot was pruned. Its row and
                // index are gone, so accepting a new operation here would make the
                // slot reusable and break phase-slot uniqueness across the journal
                // history. The caller must reconcile against the history fence
                // instead of appending into a retired slot. The refusal stays
                // honest: the lost receipt is never reconstructed from the
                // presented request, and the slot never becomes reusable.
                return Err(integrity(
                    "restore_journal_operation",
                    "phase slot was already consumed by a pruned operation",
                ));
            }

            // Refuse BEFORE writing anything when the combined retained-plus-retired
            // slot budget is already full. Validation enforces the same bound, so
            // admitting one more slot here would let a normal append commit a state
            // that the very next read rejects, bricking an otherwise valid store.
            if stream_state.intents.len() >= MAX_JOURNAL_HISTORY_ENTRIES
                || stream_state.used_slots.len() >= MAX_JOURNAL_HISTORY_ENTRIES
            {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            if !expected_predecessor_matches(operation, stream_state.head.as_ref()) {
                return Err(predecessor_conflict());
            }
        }

        // Only a genuinely new, admitted append reaches retention. The bounded
        // pass runs through the existing locked helper over the already-open
        // table handles inside this same transaction, so reclamation and the
        // append share one owner-controlled atomic boundary: no second
        // transaction, and no unlocked preflight that could race a later prune
        // between the pressure decision and the pass. A stream whose unresolved
        // frontier blocks reclamation simply proceeds to the ceiling refusal
        // above — it is never made room by evicting an unresolved intent.
        let under_retention_pressure =
            restore_journal_under_retention_pressure(state.stream(stream)?, &retention_policy);
        if under_retention_pressure {
            let stream_state = state.stream(stream)?;
            retain_restore_journal_locked(
                &mut intents,
                &mut results,
                &mut meta,
                &state,
                stream_state,
                stream,
                retention_policy.keep_resolved,
            )?;
            // The pass removed rows, added tombstones and can move the head, so
            // the whole closure is re-derived from the mutated tables. The
            // append's own sequence and byte/work accounting then describe the
            // state this transaction will actually commit. Any refusal below
            // drops the write transaction, so a committed reclamation can never
            // exist beside a rejected append or a half-updated metadata row.
            state = validate_journal_tables(&intents, &results, &meta)?;
        }
        let stream_state = state.stream(stream)?;
        // The predecessor is proven again against the head this append actually
        // uses. Reclamation only drops the oldest resolved prefix, so the head
        // normally does not move, but appending onto a moved head without this
        // check would commit a predecessor linkage the very next read rejects.
        if !expected_predecessor_matches(operation, stream_state.head.as_ref()) {
            return Err(predecessor_conflict());
        }
        let head = stream_state.head.clone();
        let sequence = match head {
            Some(current) => current
                .sequence
                .checked_add(1)
                .ok_or_else(|| integrity("restore_journal_entry", "journal sequence exhausted"))?,
            None => 0,
        };
        let entry = RestoreJournalEntry {
            operation: operation.clone(),
            sequence,
            payload_sha256: payload_sha256.to_owned(),
            payload: payload.to_owned(),
        };
        entry.validate_for_stream(stream)?;
        let intent_row_key = intent_key(stream, sequence);
        let intent_digest = entry.digest()?;
        let index = RestoreJournalOperationIndex {
            stream: stream.to_owned(),
            slot_identity: phase_identity,
            slot_sha256: slot_sha256.clone(),
            operation_identity: operation.identity(stream)?,
            operation_sha256,
            transaction_id: operation.transaction_id.clone(),
            phase_operation: operation.phase_operation.clone(),
            payload_sha256: payload_sha256.to_owned(),
            intent_key: intent_row_key.clone(),
            intent_sequence: sequence,
            intent_record_sha256: intent_digest.clone(),
            result_key: None,
            result_record_sha256: None,
        };
        index.validate()?;
        let encoded_entry = encode(&entry)?;
        let encoded_index = encode(&index)?;
        // The head advances with this row, in the same transaction, so a later
        // read can prove the retained history still ends where it claims to.
        let new_head = JournalPredecessor {
            sequence,
            digest: intent_digest.clone(),
        };
        let encoded_head = encode(&new_head)?;
        let head_key = head_key(stream);
        // An existing head row is REPLACED, so its bytes are credited back
        // before the replacement is charged. `saturating_sub` matters: a
        // noncanonical oversized persisted head must degrade to a smaller charge,
        // never to an arithmetic underflow.
        let replaced_head_bytes = optional_row_bytes(&meta, &head_key)?;
        let added_bytes = (encoded_entry.len()
            + encoded_index.len()
            + intent_row_key.len()
            + operation_key(&slot_sha256).len()
            + encoded_head.len()
            + head_key.len())
        .saturating_sub(replaced_head_bytes);
        // Three rows land: the intent, its unique operation index and the head.
        // Under-counting here would let a normal append commit a state that the
        // very next read rejects at the scan-work ceiling.
        ensure_work(state.work, 3)?;
        ensure_aggregate_bytes(state.total_bytes, added_bytes)?;
        intents
            .insert(intent_row_key.as_str(), encoded_entry.as_str())
            .map_err(storage)?;
        meta.insert(operation_key(&slot_sha256).as_str(), encoded_index.as_str())
            .map_err(storage)?;
        meta.insert(head_key.as_str(), encoded_head.as_str())
            .map_err(storage)?;
        drop(intents);
        drop(results);
        drop(meta);
        if let Err(error) = write.commit() {
            // Unknown commit. Reconcile against the operation THIS call
            // attempted, never against whatever now occupies the phase slot: a
            // concurrent writer could have committed a different operation or
            // payload into the same slot while this transaction was in doubt.
            return match self.reconcile_restore_journal_intent(
                stream,
                operation,
                payload_sha256,
                payload,
            ) {
                Ok(Some(receipt)) => Ok(receipt),
                _ => Err(storage(error)),
            };
        }
        self.owner_receipt(
            stream,
            &slot_sha256,
            RestoreJournalReceiptKind::Intent,
            false,
        )
    }

    /// Appends one result answering the exact indexed intent. Result and index
    /// updates are one write transaction and therefore one durable unit.
    #[allow(
        clippy::too_many_lines,
        reason = "the atomic result boundary keeps exact linkage, result and index closure together"
    )]
    pub fn append_restore_journal_result(
        &self,
        stream: &str,
        result: &RestoreJournalResult,
    ) -> Result<RestoreJournalAppendReceipt, OrsError> {
        result.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        let phase_identity =
            phase_identity(stream, &result.transaction_id, &result.phase_operation)?;
        let slot_sha256 = sha256_hex(phase_identity.as_bytes());
        let write = self.database.begin_write().map_err(storage)?;
        initialize_restore_journal_schema(&write)?;
        let intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
        let mut results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
        let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        let state = validate_journal_tables(&intents, &results, &meta)?;
        let stream_state = state.stream(stream)?;
        let index = stream_state.indexes.get(&slot_sha256).ok_or_else(|| {
            integrity(
                "restore_journal_index",
                "result has no unique operation index",
            )
        })?;
        let intent = stream_state
            .intents
            .get(&index.intent_sequence)
            .ok_or_else(|| {
                integrity("restore_journal_index", "operation index has no intent row")
            })?;
        result.validate_for_intent(stream, intent)?;
        let result_row_key = result_key(stream, &index.operation_sha256);
        if let Some(result_digest) = &index.result_record_sha256 {
            let stored = stream_state
                .results
                .get(&index.operation_sha256)
                .ok_or_else(|| {
                    integrity("restore_journal_result", "result index has no result row")
                })?;
            if stored != result || result.digest()? != *result_digest {
                return Err(identity_conflict());
            }
            drop(intents);
            drop(results);
            drop(meta);
            write.commit().map_err(storage)?;
            return self.owner_receipt(
                stream,
                &slot_sha256,
                RestoreJournalReceiptKind::Result,
                true,
            );
        }
        let mut updated_index = index.clone();
        let result_digest = result.digest()?;
        updated_index.result_key = Some(result_row_key.clone());
        updated_index.result_record_sha256 = Some(result_digest);
        updated_index.validate()?;
        let encoded_result = encode(result)?;
        let encoded_index = encode(&updated_index)?;
        // The operation index is REPLACED here, not added, so the WHOLE stored
        // row — key and value — is credited back before the replacement and the
        // new result row are charged.
        let replaced_index_bytes = row_size(&meta, operation_key(&slot_sha256).as_str())?;
        ensure_work(state.work, 1)?;
        ensure_aggregate_bytes(
            state.total_bytes,
            (encoded_result.len()
                + encoded_index.len()
                + result_row_key.len()
                + operation_key(&slot_sha256).len())
            .saturating_sub(replaced_index_bytes),
        )?;
        results
            .insert(result_row_key.as_str(), encoded_result.as_str())
            .map_err(storage)?;
        meta.insert(operation_key(&slot_sha256).as_str(), encoded_index.as_str())
            .map_err(storage)?;
        drop(intents);
        drop(results);
        drop(meta);
        if let Err(error) = write.commit() {
            // Unknown commit. Reconcile against the exact result THIS call
            // attempted; a concurrent writer may have committed a different
            // receipt for the same intent into the same slot.
            return match self.reconcile_restore_journal_result(stream, result) {
                Ok(Some(receipt)) => Ok(receipt),
                _ => Err(storage(error)),
            };
        }
        self.owner_receipt(
            stream,
            &slot_sha256,
            RestoreJournalReceiptKind::Result,
            false,
        )
    }

    /// Reconciles an unknown intent outcome by exact owner readback. It never
    /// appends, retries or converts an unavailable read into absence.
    pub fn reconcile_restore_journal_intent(
        &self,
        stream: &str,
        operation: &RestoreJournalOperation,
        payload_sha256: &str,
        payload: &str,
    ) -> Result<Option<RestoreJournalAppendReceipt>, OrsError> {
        operation.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        crate::restore_journal::validate_envelope_bytes(
            payload,
            payload_sha256,
            "journal.payload",
        )?;
        let phase_identity = operation.phase_identity(stream)?;
        let slot = sha256_hex(phase_identity.as_bytes());
        let state = self.read_restore_journal_state()?;
        let stream_state = state.stream(stream)?;
        let Some(index) = stream_state.indexes.get(&slot) else {
            if stream_state.history_fence.is_some() {
                return Err(integrity(
                    "restore_journal_operation",
                    "operation is outside the retained history and cannot be proven absent",
                ));
            }
            return Ok(None);
        };
        let entry = stream_state
            .intents
            .get(&index.intent_sequence)
            .ok_or_else(|| {
                integrity("restore_journal_index", "operation index has no intent row")
            })?;
        if index.operation_sha256 != operation.identity_sha256(stream)?
            || entry.operation != *operation
            || entry.payload != payload
        {
            return Err(identity_conflict());
        }
        Self::receipt_from_state(
            &state,
            stream,
            &slot,
            RestoreJournalReceiptKind::Intent,
            true,
        )
        .map(Some)
    }

    /// Reconciles an unknown result outcome by exact owner readback.
    pub fn reconcile_restore_journal_result(
        &self,
        stream: &str,
        result: &RestoreJournalResult,
    ) -> Result<Option<RestoreJournalAppendReceipt>, OrsError> {
        result.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        let phase_identity =
            phase_identity(stream, &result.transaction_id, &result.phase_operation)?;
        let slot = sha256_hex(phase_identity.as_bytes());
        let state = self.read_restore_journal_state()?;
        let stream_state = state.stream(stream)?;
        let Some(index) = stream_state.indexes.get(&slot) else {
            if stream_state.history_fence.is_some() {
                return Err(integrity(
                    "restore_journal_operation",
                    "operation is outside the retained history and cannot be proven absent",
                ));
            }
            return Ok(None);
        };
        let Some(stored) = stream_state.results.get(&index.operation_sha256) else {
            return Ok(None);
        };
        if stored != result {
            return Err(identity_conflict());
        }
        Self::receipt_from_state(
            &state,
            stream,
            &slot,
            RestoreJournalReceiptKind::Result,
            true,
        )
        .map(Some)
    }

    /// Returns a fully validated retained page and its history fence. `None`
    /// means a validated exact new stream with no entries. `Some(fence)` means
    /// the returned rows are a retained suffix and must not be treated as the
    /// complete historical denominator without the caller's member proof.
    ///
    /// This compatibility-shaped read reports no denominator of its own. A
    /// caller that needs complete restore proof uses
    /// `load_restore_journal_readback_against`, which compares the observed
    /// retained-plus-retired member set against an explicit expectation.
    pub fn load_restore_journal_readback(
        &self,
        stream: &str,
        limit: usize,
    ) -> Result<(Vec<RestoreJournalEntry>, Option<JournalPredecessor>), OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        validate_page_limit(limit)?;
        let state = self.read_restore_journal_state()?;
        let stream_state = state.stream(stream)?;
        if stream_state.intents.len() > limit {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let rows = stream_state.intents.values().cloned().collect::<Vec<_>>();
        Ok((
            rows,
            stream_state
                .history_fence
                .as_ref()
                .map(|fence| fence.predecessor.clone()),
        ))
    }

    /// Reads one stream against an explicit member denominator and returns
    /// complete restore proof only when the observed journal accounts for
    /// exactly what the requester required.
    ///
    /// The denominator counts the WHOLE journal, retired members included, so
    /// a retained suffix is proved rather than assumed to be the entire
    /// history. Missing, corrupt, unsupported, stale or partially reclaimed
    /// storage returns a typed refusal instead of a proof. Zero entries is
    /// [`RestoreJournalCompleteness::ExactNew`] only for a validated exact new
    /// journal — bound, no retained member, no retired phase slot and no prune
    /// fence — so an empty read can never stand in for unavailable storage.
    pub fn load_restore_journal_readback_against(
        &self,
        request: &RestoreJournalReadbackRequest,
    ) -> Result<RestoreJournalReadback, OrsError> {
        request.validate()?;
        validate_journal_text(request.stream.as_str(), "journal.stream")?;
        let state = self.read_restore_journal_state()?;
        // A stream with no persisted binding is refused here, so unavailable or
        // unadopted storage can never be observed as an empty journal.
        let stream_state = state.stream(request.stream.as_str())?;
        if stream_state.intents.len() > request.limit {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let retained_members = u64::try_from(stream_state.intents.len()).unwrap_or(u64::MAX);
        let retired_members = stream_state
            .history_fence
            .as_ref()
            .map_or(0_u64, |fence| fence.retired_slots);
        let total_members = retained_members.saturating_add(retired_members);
        let head = stream_state.head.clone();
        let history_fence = stream_state
            .history_fence
            .as_ref()
            .map(|fence| fence.predecessor.clone());
        let completeness = Self::check_restore_journal_denominator(
            stream_state,
            &request.denominator,
            total_members,
            head.as_ref(),
        )?;
        Ok(RestoreJournalReadback {
            stream: request.stream.clone(),
            entries: stream_state.intents.values().cloned().collect(),
            retained_members,
            retired_members,
            total_members,
            head,
            history_fence,
            completeness,
            retention: stream_state.retention.clone(),
        })
    }

    /// Refuses a readback whose observed members do not account for the
    /// requested denominator.
    ///
    /// A zero denominator additionally requires the exact-new-journal proof. Any
    /// other way of reading as empty — a reclaimed prefix, an unbound stream, a
    /// store that could not be validated — is a refusal, never a known-empty
    /// journal.
    fn check_restore_journal_denominator(
        stream_state: &JournalStreamState,
        denominator: &RestoreJournalMemberDenominator,
        total_members: u64,
        head: Option<&JournalPredecessor>,
    ) -> Result<RestoreJournalCompleteness, OrsError> {
        if total_members != denominator.members {
            return Err(integrity(
                "restore_journal_readback",
                "observed journal member denominator does not match the requested denominator",
            ));
        }
        if denominator.head.as_ref() != head {
            return Err(integrity(
                "restore_journal_readback",
                "observed journal head does not match the requested denominator",
            ));
        }
        if denominator.members > 0 {
            return Ok(RestoreJournalCompleteness::Complete);
        }
        // Known-empty is admitted only with the full exact-new proof. Without
        // it, an empty read would be indistinguishable from storage that was
        // never written, never validated, or already reclaimed.
        if stream_state.binding.is_none()
            || stream_state.history_fence.is_some()
            || !stream_state.used_slots.is_empty()
            || !stream_state.intents.is_empty()
            || !stream_state.indexes.is_empty()
            || !stream_state.results.is_empty()
            || head.is_some()
        {
            return Err(integrity(
                "restore_journal_readback",
                "an empty journal is known-empty only for a validated exact new journal",
            ));
        }
        Ok(RestoreJournalCompleteness::ExactNew)
    }

    /// Bounded full-stream readback. A retained/pruned history is deliberately
    /// rejected by this compatibility-shaped API; callers that can prove the
    /// retention/member denominator must use
    /// `load_restore_journal_readback_against`.
    pub fn load_restore_journal_stream(
        &self,
        stream: &str,
        limit: usize,
    ) -> Result<Vec<RestoreJournalEntry>, OrsError> {
        let (rows, fence) = self.load_restore_journal_readback(stream, limit)?;
        if fence.is_some() {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        Ok(rows)
    }

    /// Loads one exact result by transaction/phase slot. A missing result is
    /// only a valid observation after the complete owner state was validated.
    pub fn load_restore_journal_result(
        &self,
        stream: &str,
        phase_operation: &str,
    ) -> Result<Option<RestoreJournalResult>, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        validate_journal_text(phase_operation, "journal.phase_operation")?;
        let state = self.read_restore_journal_state()?;
        let stream_state = state.stream(stream)?;
        let transaction_id = stream_state
            .binding
            .as_ref()
            .ok_or_else(|| {
                integrity(
                    "restore_journal_binding",
                    "journal stream has no persisted binding",
                )
            })?
            .transaction_id
            .as_str();
        let phase = phase_identity(stream, transaction_id, phase_operation)?;
        let slot = sha256_hex(phase.as_bytes());
        let Some(index) = stream_state.indexes.get(&slot) else {
            if stream_state.history_fence.is_some() {
                return Err(integrity(
                    "restore_journal_operation",
                    "result is outside the retained history and cannot be proven absent",
                ));
            }
            return Ok(None);
        };
        Ok(stream_state.results.get(&index.operation_sha256).cloned())
    }

    /// Verifies a receipt against the current owner row, sequence and unique
    /// indexes. A self-hash or caller-supplied success shape is not accepted.
    pub fn verify_restore_journal_receipt(
        &self,
        stream: &str,
        receipt: &RestoreJournalAppendReceipt,
    ) -> Result<(), OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        let state = self.read_restore_journal_state()?;
        let stream_state = state.stream(stream)?;
        let proof = &receipt.owner_readback;
        if proof.schema != RESTORE_JOURNAL_RECORD_SCHEMA
            || proof.stream != stream
            || proof.record_digest != receipt.record_digest
            || proof.replayed != receipt.replayed
        {
            return Err(integrity(
                "restore_journal_receipt",
                "receipt owner proof is not exact",
            ));
        }
        // Bound the caller-supplied identity BEFORE it is hashed, so a
        // fabricated proof cannot force an unbounded digest computation.
        validate_journal_text(&proof.phase_identity, "journal.receipt_phase_identity")?;
        let slot = sha256_hex(proof.phase_identity.as_bytes());
        let index = stream_state.indexes.get(&slot).ok_or_else(|| {
            integrity(
                "restore_journal_receipt",
                "receipt operation index is absent",
            )
        })?;
        if proof.phase_identity != index.slot_identity {
            return Err(integrity(
                "restore_journal_receipt",
                "receipt phase identity does not match the operation index",
            ));
        }
        let (sequence, digest) = match proof.kind {
            RestoreJournalReceiptKind::Intent => {
                (index.intent_sequence, index.intent_record_sha256.clone())
            }
            RestoreJournalReceiptKind::Result => {
                let result = stream_state
                    .results
                    .get(&index.operation_sha256)
                    .ok_or_else(|| {
                        integrity("restore_journal_receipt", "receipt result row is absent")
                    })?;
                (result.intent_sequence, result.digest()?)
            }
        };
        if receipt.transaction_id != index.transaction_id
            || receipt.phase_operation != index.phase_operation
            || receipt.sequence != sequence
            || receipt.record_digest != digest
        {
            return Err(integrity(
                "restore_journal_receipt",
                "receipt does not match the current persisted row",
            ));
        }
        Ok(())
    }

    /// Prunes only the oldest contiguous resolved prefix. Unresolved intents
    /// and their newer same-slot operations remain retained. The prune fence
    /// is the exact predecessor of the last removed intent.
    ///
    /// The pass is idempotent: a run with nothing reclaimable removes no
    /// journal row and only refreshes the durable retention decision. It is
    /// interrupt-safe because the removals, the phase-slot tombstones, the
    /// fence, the head and that decision are one transaction, so a reclaimed
    /// member and the report of it are never separated.
    pub fn prune_restore_journal(
        &self,
        stream: &str,
        keep_resolved: usize,
    ) -> Result<u64, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        let policy = RestoreJournalRetentionPolicy {
            keep_resolved,
            ..RestoreJournalRetentionPolicy::accepted()
        };
        policy.validate()?;
        Ok(self
            .run_restore_journal_retention(stream, policy.keep_resolved)?
            .removed_members)
    }

    /// Applies the ACCEPTED retention policy to one stream and reports what it
    /// reclaimed together with the recovery-needed members it refused to
    /// evict.
    ///
    /// This is an INDEPENDENTLY AUTHORIZED maintenance operation: it runs in its
    /// own write transaction and returns its own
    /// [`RestoreJournalRetentionReport`], which is never folded into an
    /// append receipt. The append path reaches the same bounded pass under the
    /// accepted reclaim point, but only for an append it has already admitted,
    /// and only inside that append's own atomic boundary. Neither surface ever
    /// evicts an unresolved intent to make room: reclamation stops at the first
    /// unresolved intent, and a reclamation the retired-slot bound would refuse
    /// removes nothing and is reported as a refusal. The surviving frontier is
    /// recomputed from current owner state after the pass, so the report cannot
    /// claim a reclamation the journal does not show.
    pub fn apply_restore_journal_retention(
        &self,
        stream: &str,
    ) -> Result<RestoreJournalRetentionReport, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        let policy = RestoreJournalRetentionPolicy::accepted();
        policy.validate()?;
        let record = self.run_restore_journal_retention(stream, policy.keep_resolved)?;
        let state = self.read_restore_journal_state()?;
        let frontier = unresolved_frontier(stream, state.stream(stream)?)?;
        Ok(RestoreJournalRetentionReport {
            stream: stream.to_owned(),
            record,
            surviving_unresolved_members: frontier.unresolved_members,
            oldest_surviving_unresolved: frontier.oldest_unresolved_sequence,
        })
    }

    /// Runs exactly one retention pass in its own write transaction and returns
    /// the durable decision that pass committed.
    fn run_restore_journal_retention(
        &self,
        stream: &str,
        keep_resolved: usize,
    ) -> Result<RestoreJournalRetentionRecord, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        initialize_restore_journal_schema(&write)?;
        let mut intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
        let mut results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
        let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        let state = validate_journal_tables(&intents, &results, &meta)?;
        let stream_state = state.stream(stream)?;
        let pass = retain_restore_journal_locked(
            &mut intents,
            &mut results,
            &mut meta,
            &state,
            stream_state,
            stream,
            keep_resolved,
        )?;
        drop(intents);
        drop(results);
        drop(meta);
        write.commit().map_err(storage)?;
        Ok(pass)
    }

    /// Applies one retention pass: removals, tombstones, the fence, the head
    /// and the durable retention decision, all inside the caller's single
    /// write transaction.
    #[allow(
        clippy::too_many_lines,
        reason = "the prune boundary keeps row removal, tombstones, fence, head and the retention decision in one unit"
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "one bounded prune pass over three tables"
    )]
    fn apply_prune(
        intents: &mut redb::Table<'_, &'static str, &'static str>,
        results: &mut redb::Table<'_, &'static str, &'static str>,
        meta: &mut redb::Table<'_, &'static str, &'static str>,
        state: &JournalState,
        stream_state: &JournalStreamState,
        stream: &str,
        removals: &[PruneRemoval],
        retired_before: u64,
        record: &RestoreJournalRetentionRecord,
    ) -> Result<(), OrsError> {
        let mut removed = 0_u64;
        let mut last_removed = stream_state
            .history_fence
            .as_ref()
            .map(|fence| fence.predecessor.clone());
        // Tombstones, the fence and the head are written in the SAME transaction
        // as the removals, so a retired phase slot can never be observed as free
        // and a truncated retained chain can never be observed as complete.
        //
        // The byte/work budget is tracked against the POST-removal totals, not
        // the snapshot taken before this call: pruning only ever drops rows, so
        // accounting against the stale total would let a genuinely freeing
        // prune be rejected at the ceiling while also double-counting the
        // replacements against rows that are about to disappear.
        let mut live_bytes = state.total_bytes;
        let mut live_work = state.work;
        let removed_sequences = removals
            .iter()
            .map(|removal| removal.sequence)
            .collect::<BTreeSet<_>>();
        for removal in removals {
            // Credit back the three rows this removal drops before charging
            // the tombstone, so the budget tracks live rows.
            live_bytes = live_bytes
                .saturating_sub(row_size(intents, removal.intent_row_key.as_str())?)
                .saturating_sub(row_size(results, removal.result_row_key.as_str())?)
                .saturating_sub(row_size(&*meta, removal.index_key.as_str())?);
            live_work = live_work.saturating_sub(3);
            let tombstone_size = removal.tombstone_key.len() + TOMBSTONE_VALUE.len();
            ensure_work(live_work, 1)?;
            ensure_aggregate_bytes(live_bytes, tombstone_size)?;
            live_bytes += tombstone_size;
            live_work += 1;
            intents
                .remove(removal.intent_row_key.as_str())
                .map_err(storage)?;
            results
                .remove(removal.result_row_key.as_str())
                .map_err(storage)?;
            meta.remove(removal.index_key.as_str()).map_err(storage)?;
            meta.insert(removal.tombstone_key.as_str(), TOMBSTONE_VALUE)
                .map_err(storage)?;
            last_removed = Some(removal.predecessor.clone());
            removed += 1;
        }
        if removed > 0 {
            // The fence now records the running retired-slot total, which is
            // what lets readback prove the tombstone set is COMPLETE rather than
            // merely non-empty.
            let retired_slots = removed + retired_before;
            let predecessor = last_removed.clone().ok_or_else(|| {
                integrity(
                    "restore_journal_meta",
                    "prune did not produce a history fence",
                )
            })?;
            let encoded_fence = encode(&JournalHistoryFence {
                predecessor: predecessor.clone(),
                retired_slots,
            })?;
            let fence_key = history_key(stream);
            // The fence row is INSERTED on the first prune and REPLACED on every
            // later one, so credit the stored row back only when one exists.
            let replaced_fence_bytes = optional_row_bytes(&*meta, fence_key.as_str())?;
            ensure_work(live_work, 1)?;
            ensure_aggregate_bytes(
                live_bytes,
                (encoded_fence.len() + fence_key.len()).saturating_sub(replaced_fence_bytes),
            )?;
            live_bytes +=
                (encoded_fence.len() + fence_key.len()).saturating_sub(replaced_fence_bytes);
            live_work += 1;
            meta.insert(fence_key.as_str(), encoded_fence.as_str())
                .map_err(storage)?;

            // The head follows whatever survived: the last retained row, or the
            // new fence when the prune emptied the stream. Deleting the newest
            // retained row later would then break `head == derived_head`.
            let new_head = match stream_state
                .intents
                .iter()
                .rev()
                .find(|(sequence, _)| !removed_sequences.contains(sequence))
            {
                Some((sequence, entry)) => JournalPredecessor {
                    sequence: *sequence,
                    digest: entry.digest()?,
                },
                None => predecessor,
            };
            let encoded_head = encode(&new_head)?;
            let head_key = head_key(stream);
            let replaced_head_bytes = optional_row_bytes(&*meta, &head_key)?;
            ensure_work(live_work, 1)?;
            ensure_aggregate_bytes(
                live_bytes,
                (encoded_head.len() + head_key.len()).saturating_sub(replaced_head_bytes),
            )?;
            meta.insert(head_key.as_str(), encoded_head.as_str())
                .map_err(storage)?;
        }
        // The durable retention decision is committed even when nothing was
        // reclaimed. A reclamation that reclaimed nothing is a fact a restoring
        // owner has to see — that is where "an unresolved intent was retained
        // rather than evicted" becomes observable instead of inferred from a
        // silent no-op. Writing it in this same transaction is what makes the
        // reported decision and the removed rows impossible to disagree about.
        let encoded_record = encode(record)?;
        let retention_row_key = retention_key(stream);
        let replaced_record_bytes = optional_row_bytes(&*meta, retention_row_key.as_str())?;
        ensure_work(live_work, 1)?;
        ensure_aggregate_bytes(
            live_bytes,
            (encoded_record.len() + retention_row_key.len()).saturating_sub(replaced_record_bytes),
        )?;
        meta.insert(retention_row_key.as_str(), encoded_record.as_str())
            .map_err(storage)?;
        Ok(())
    }

    /// Every journal read funnels through here, so it re-runs the table-family
    /// check. A foreign `ors_restore_journal_*` table, or a family that is not
    /// exactly the declared three, is refused here rather than silently ignored
    /// while a read or a receipt verification reports success.
    fn read_restore_journal_state(&self) -> Result<JournalState, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        validate_journal_table_names(&read)?;
        let intents = read.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
        let results = read.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
        let meta = read.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        validate_journal_tables(&intents, &results, &meta)
    }

    /// Rebuilds an owner receipt from current owner state.
    ///
    /// The slot is always an internally derived SHA-256 of a phase identity, so
    /// an absent slot here means the owner's own post-commit readback did not
    /// observe what it just wrote. That is an integrity problem, never an
    /// absence the caller may treat as "not committed".
    fn owner_receipt(
        &self,
        stream: &str,
        slot: &str,
        kind: RestoreJournalReceiptKind,
        replayed: bool,
    ) -> Result<RestoreJournalAppendReceipt, OrsError> {
        let state = self.read_restore_journal_state()?;
        let Some(stream_state) = state.streams.get(stream) else {
            return Err(integrity(
                "restore_journal_binding",
                "journal stream has no persisted binding",
            ));
        };
        if !stream_state.indexes.contains_key(slot) {
            return Err(integrity(
                "restore_journal_receipt",
                "owner readback found no committed row for this operation slot",
            ));
        }
        Self::receipt_from_state(&state, stream, slot, kind, replayed)
    }

    fn receipt_from_state(
        state: &JournalState,
        stream: &str,
        slot: &str,
        kind: RestoreJournalReceiptKind,
        replayed: bool,
    ) -> Result<RestoreJournalAppendReceipt, OrsError> {
        let stream_state = state.stream(stream)?;
        let index = stream_state
            .indexes
            .get(slot)
            .ok_or_else(|| integrity("restore_journal_receipt", "operation index is absent"))?;
        let (sequence, digest) = match kind {
            RestoreJournalReceiptKind::Intent => {
                (index.intent_sequence, index.intent_record_sha256.clone())
            }
            RestoreJournalReceiptKind::Result => {
                let result = stream_state
                    .results
                    .get(&index.operation_sha256)
                    .ok_or_else(|| integrity("restore_journal_receipt", "result row is absent"))?;
                (result.intent_sequence, result.digest()?)
            }
        };
        Ok(RestoreJournalAppendReceipt::owner_issued(
            &crate::restore_journal::RestoreJournalReceiptIssue {
                transaction_id: &index.transaction_id,
                phase_operation: &index.phase_operation,
                sequence,
                record_digest: &digest,
                stream,
                phase_identity: &index.slot_identity,
                kind,
                replayed,
            },
        ))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "full table closure validation is intentionally one bounded read pass"
)]
fn validate_journal_tables<T: ReadableTable<&'static str, &'static str>>(
    intents: &T,
    results: &T,
    meta: &T,
) -> Result<JournalState, OrsError> {
    initialize_schema_marker_for_generic(meta)?;
    let mut state = JournalState::default();

    for entry in meta.iter().map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        account_row(&mut state, key.value().len(), value.value().len())?;
        let key = key.value();
        if key == RESTORE_JOURNAL_SCHEMA_ROW || key == RESTORE_JOURNAL_MIGRATION_ROW {
            continue;
        }
        if let Some(stream) = namespace_value(key, BINDING_PREFIX) {
            validate_journal_text(&stream, "journal.meta_binding_stream")?;
            let binding: RestoreJournalStreamBinding = decode_binding(value.value())?;
            let stream_state = state.stream_mut(&stream);
            if stream_state.binding.replace(binding).is_some() {
                return Err(integrity(
                    "restore_journal_binding",
                    "duplicate stream binding",
                ));
            }
            continue;
        }
        if let Some(stream) = namespace_value(key, HISTORY_PREFIX) {
            validate_journal_text(&stream, "journal.meta_history_stream")?;
            let fence: JournalHistoryFence = decode_fence(value.value())?;
            fence.validate()?;
            let stream_state = state.stream_mut(&stream);
            if stream_state.history_fence.replace(fence).is_some() {
                return Err(integrity("restore_journal_meta", "duplicate history fence"));
            }
            continue;
        }
        if let Some(stream) = namespace_value(key, HEAD_PREFIX) {
            validate_journal_text(&stream, "journal.meta_head_stream")?;
            let head: JournalPredecessor = decode_predecessor(value.value())?;
            let stream_state = state.stream_mut(&stream);
            if stream_state.head.replace(head).is_some() {
                return Err(integrity("restore_journal_meta", "duplicate journal head"));
            }
            continue;
        }
        if let Some(stream) = namespace_value(key, RETENTION_PREFIX) {
            validate_journal_text(&stream, "journal.meta_retention_stream")?;
            let record = decode_retention(value.value())?;
            let stream_state = state.stream_mut(&stream);
            if stream_state.retention.replace(record).is_some() {
                return Err(integrity(
                    "restore_journal_meta",
                    "duplicate retention decision",
                ));
            }
            continue;
        }
        if let Some((stream, slot)) = parse_used_key(key) {
            validate_journal_text(&stream, "journal.meta_used_stream")?;
            crate::model::validate_digest(&slot, "journal.slot_sha256")?;
            if value.value() != TOMBSTONE_VALUE {
                return Err(integrity(
                    "restore_journal_meta",
                    "pruned phase-slot tombstone is malformed",
                ));
            }
            let stream_state = state.stream_mut(&stream);
            if !stream_state.used_slots.insert(slot) {
                return Err(integrity(
                    "restore_journal_meta",
                    "duplicate pruned phase-slot tombstone",
                ));
            }
            continue;
        }
        if let Some(slot) = namespace_value(key, OPERATION_PREFIX) {
            crate::model::validate_digest(&slot, "journal.slot_sha256")?;
            let index: RestoreJournalOperationIndex = decode_index(value.value())?;
            index.validate()?;
            if index.slot_sha256 != slot || index.stream.is_empty() {
                return Err(integrity(
                    "restore_journal_index",
                    "operation index key does not match row",
                ));
            }
            let stream_state = state.stream_mut(&index.stream);
            if stream_state.indexes.insert(slot, index).is_some() {
                return Err(integrity(
                    "restore_journal_index",
                    "duplicate operation index",
                ));
            }
            continue;
        }
        return Err(integrity(
            "restore_journal_meta",
            "unknown journal metadata row",
        ));
    }

    for entry in intents.iter().map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        account_row(&mut state, key.value().len(), value.value().len())?;
        let (stream, key_sequence) = parse_intent_key(key.value())?;
        let entry: RestoreJournalEntry = decode_entry(value.value())?;
        if entry.sequence != key_sequence {
            return Err(integrity(
                "restore_journal_entry",
                "sequence key does not match row",
            ));
        }
        entry.validate_for_stream(&stream).map_err(|error| {
            redact_persisted(
                &error,
                "restore_journal_entry",
                "intent row failed closed validation",
            )
        })?;
        let slot = sha256_hex(
            entry
                .operation
                .phase_identity(&stream)
                .map_err(|_| integrity("restore_journal_entry", "invalid phase identity"))?
                .as_bytes(),
        );
        let stream_state = state.stream_mut(&stream);
        if stream_state.intents.insert(key_sequence, entry).is_some()
            || stream_state
                .intent_slots
                .insert(slot.clone(), key_sequence)
                .is_some()
        {
            return Err(integrity(
                "restore_journal_entry",
                "duplicate sequence or operation slot",
            ));
        }
    }

    for entry in results.iter().map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        account_row(&mut state, key.value().len(), value.value().len())?;
        let (stream, operation_sha256) = parse_result_key(key.value())?;
        let result: RestoreJournalResult = decode_result(value.value())?;
        let stream_state = state.stream_mut(&stream);
        if stream_state
            .results
            .insert(operation_sha256, result)
            .is_some()
        {
            return Err(integrity(
                "restore_journal_result",
                "duplicate result index",
            ));
        }
    }

    validate_stream_closures(&state)?;
    Ok(state)
}

#[allow(
    clippy::too_many_lines,
    reason = "stream closure checks are kept together to make every fail-closed relationship explicit"
)]
fn validate_stream_closures(state: &JournalState) -> Result<(), OrsError> {
    for (stream, stream_state) in &state.streams {
        if stream_state.intents.len() > MAX_JOURNAL_HISTORY_ENTRIES
            || stream_state.indexes.len() > MAX_JOURNAL_HISTORY_ENTRIES
            || stream_state.results.len() > MAX_JOURNAL_HISTORY_ENTRIES
            || stream_state.used_slots.len() > MAX_JOURNAL_HISTORY_ENTRIES
            || stream_state.intent_slots.len() != stream_state.intents.len()
            || stream_state.indexes.len() != stream_state.intents.len()
        {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let binding = stream_state.binding.as_ref().ok_or_else(|| {
            integrity(
                "restore_journal_binding",
                "history has no persisted stream binding",
            )
        })?;
        let mut previous = stream_state
            .history_fence
            .as_ref()
            .map(|fence| fence.predecessor.clone());
        let mut result_count = 0_usize;
        for (sequence, entry) in &stream_state.intents {
            if !entry.operation.matches_binding(binding) {
                return Err(integrity(
                    "restore_journal_entry",
                    "intent does not match persisted stream binding",
                ));
            }
            let phase_identity = entry
                .operation
                .phase_identity(stream)
                .map_err(|_| integrity("restore_journal_entry", "invalid phase identity"))?;
            let slot = sha256_hex(phase_identity.as_bytes());
            let index = stream_state.indexes.get(&slot).ok_or_else(|| {
                integrity(
                    "restore_journal_index",
                    "intent has no unique operation index",
                )
            })?;
            let operation_digest = entry
                .operation
                .identity_sha256(stream)
                .map_err(|_| integrity("restore_journal_entry", "invalid operation identity"))?;
            let operation_identity = entry
                .operation
                .identity(stream)
                .map_err(|_| integrity("restore_journal_entry", "invalid operation identity"))?;
            if index.stream != *stream
                || index.slot_identity != phase_identity
                || index.slot_sha256 != slot
                || index.operation_identity != operation_identity
                || index.operation_sha256 != operation_digest
                || index.transaction_id != entry.operation.transaction_id
                || index.phase_operation != entry.operation.phase_operation
                || index.payload_sha256 != entry.payload_sha256
                || index.intent_key != intent_key(stream, *sequence)
                || index.intent_sequence != *sequence
                || index.intent_record_sha256 != entry.digest()?
            {
                return Err(integrity(
                    "restore_journal_index",
                    "operation index does not close over intent row",
                ));
            }
            let expected_sequence = match &previous {
                Some(fence) => fence.sequence.checked_add(1).ok_or_else(|| {
                    integrity("restore_journal_entry", "journal sequence exhausted")
                })?,
                None => 0,
            };
            if *sequence != expected_sequence {
                return Err(integrity(
                    "restore_journal_entry",
                    "journal sequence is not contiguous",
                ));
            }
            match (&entry.operation.expected_predecessor, &previous) {
                (None, None) => {}
                (Some(expected), Some(current))
                    if expected.sequence == current.sequence
                        && expected.digest == current.digest => {}
                _ => {
                    return Err(integrity(
                        "restore_journal_entry",
                        "journal predecessor linkage is broken",
                    ));
                }
            }
            previous = Some(JournalPredecessor {
                sequence: *sequence,
                digest: entry.digest()?,
            });
            if let Some(stored_result_key) = &index.result_key {
                let result = stream_state
                    .results
                    .get(&index.operation_sha256)
                    .ok_or_else(|| {
                        integrity("restore_journal_index", "result index has no result row")
                    })?;
                let result_digest = result.digest()?;
                if stored_result_key != &result_key(stream, &index.operation_sha256)
                    || index.result_record_sha256.as_deref() != Some(result_digest.as_str())
                {
                    return Err(integrity(
                        "restore_journal_index",
                        "result index binding is broken",
                    ));
                }
                result.validate_for_intent(stream, entry).map_err(|error| {
                    redact_persisted(
                        &error,
                        "restore_journal_result",
                        "result does not bind its exact intent",
                    )
                })?;
                result_count += 1;
            }
        }
        if result_count != stream_state.results.len() {
            return Err(integrity(
                "restore_journal_result",
                "orphan or missing result row",
            ));
        }
        for (slot, index) in &stream_state.indexes {
            if stream_state
                .intent_slots
                .get(slot)
                .is_none_or(|sequence| *sequence != index.intent_sequence)
            {
                return Err(integrity(
                    "restore_journal_index",
                    "operation index has no matching intent slot",
                ));
            }
        }
        for operation_sha256 in stream_state.results.keys() {
            if !stream_state
                .indexes
                .values()
                .any(|index| &index.operation_sha256 == operation_sha256)
            {
                return Err(integrity(
                    "restore_journal_result",
                    "result has no operation index",
                ));
            }
        }
        // A phase slot is either live (it owns an operation index) or retired
        // (prune left a tombstone). It can never be both, because that would
        // mean prune dropped a uniqueness record it was supposed to keep.
        for slot in &stream_state.used_slots {
            if stream_state.indexes.contains_key(slot) {
                return Err(integrity(
                    "restore_journal_index",
                    "phase slot is both live and retired",
                ));
            }
        }
        // Prune is the only writer of both the history fence and the slot
        // tombstones, and it writes a fence if and only if it removed at least
        // one operation. So a fence and a tombstone must always appear
        // together. Without this pairing a hand-damaged or partially restored
        // store could keep a fence (advancing `head`) while dropping the
        // tombstones, which would make a retired phase slot look free again.
        let has_fence = stream_state.history_fence.is_some();
        let has_tombstones = !stream_state.used_slots.is_empty();
        if has_fence != has_tombstones {
            return Err(integrity(
                "restore_journal_meta",
                "history fence and pruned phase-slot tombstones are not paired",
            ));
        }
        // Prune is the only writer of the fence, the tombstones and the head,
        // and it records how many slots it retired. Comparing that recorded
        // count against the tombstones actually present is what makes the
        // retired set complete: a store that kept a fence but dropped one
        // tombstone fails here, so the missing retired slot cannot be reused.
        if let Some(fence) = &stream_state.history_fence
            && usize::try_from(fence.retired_slots).unwrap_or(usize::MAX)
                != stream_state.used_slots.len()
        {
            return Err(integrity(
                "restore_journal_meta",
                "retired phase-slot tombstones do not match the recorded count",
            ));
        }
        // The durable retention decision and the prune fence are written by one
        // pass in one transaction, so a stored decision must account for exactly
        // the retired slots the fence records. A decision that outlived its
        // fence would claim a reclamation the journal can no longer prove. The
        // reverse — a fence written before decisions existed — is tolerated and
        // is refreshed by the next pass, so an older retained history is never
        // upgraded into a claimed one.
        if let Some(record) = &stream_state.retention
            && record.retired_members
                != stream_state
                    .history_fence
                    .as_ref()
                    .map_or(0_u64, |fence| fence.retired_slots)
        {
            return Err(integrity(
                "restore_journal_meta",
                "durable retention decision does not match the recorded retired phase slots",
            ));
        }
        // The durable head must equal the head the retained rows imply. If the
        // newest retained row was lost, the remaining chain is still internally
        // contiguous, so only this comparison detects the truncation.
        if stream_state.head != stream_state.derived_head()? {
            return Err(integrity(
                "restore_journal_meta",
                "durable journal head does not match the retained history",
            ));
        }
    }
    Ok(())
}

fn initialize_schema_marker_for_generic<T: ReadableTable<&'static str, &'static str>>(
    meta: &T,
) -> Result<(), OrsError> {
    let schema = read_marker(meta, RESTORE_JOURNAL_SCHEMA_ROW)?;
    let migration_marker = read_marker(meta, RESTORE_JOURNAL_MIGRATION_ROW)?;
    if schema.as_deref() != Some(RESTORE_JOURNAL_SCHEMA_IDENTITY)
        || migration_marker.as_deref() != Some(RESTORE_JOURNAL_MIGRATION_IDENTITY)
    {
        return Err(migration(
            "restore journal schema or additive migration marker is unsupported",
        ));
    }
    Ok(())
}

/// Exact stored size of one row, key included, so prune can credit back what it
/// is about to drop instead of guessing.
fn row_size<T: ReadableTable<&'static str, &'static str>>(
    table: &T,
    key: &str,
) -> Result<usize, OrsError> {
    let row = table
        .get(key)
        .map_err(storage)?
        .ok_or_else(|| integrity("restore_journal_meta", "row to remove is already absent"))?;
    Ok(key.len() + row.value().len())
}

fn account_row(
    state: &mut JournalState,
    key_bytes: usize,
    value_bytes: usize,
) -> Result<(), OrsError> {
    state.work = state
        .work
        .checked_add(1)
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    if state.work > MAX_JOURNAL_WORK_ENTRIES {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    state.total_bytes = state
        .total_bytes
        .checked_add(key_bytes.saturating_add(value_bytes))
        .ok_or(OrsError::ProjectionLimitExceeded)?;
    if state.total_bytes > MAX_JOURNAL_TOTAL_BYTES {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    Ok(())
}

fn ensure_aggregate_bytes(current: usize, added: usize) -> Result<(), OrsError> {
    if current.saturating_add(added) > MAX_JOURNAL_TOTAL_BYTES {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    Ok(())
}

fn ensure_work(current: usize, added: usize) -> Result<(), OrsError> {
    if current
        .checked_add(added)
        .is_none_or(|work| work > MAX_JOURNAL_WORK_ENTRIES)
    {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    Ok(())
}

fn validate_page_limit(limit: usize) -> Result<(), OrsError> {
    if limit == 0 || limit > MAX_JOURNAL_PAGE_ENTRIES {
        return Err(OrsError::InvalidField {
            field: "journal.page_limit",
            reason: "page limit must be between 1 and the journal page bound",
        });
    }
    Ok(())
}

fn phase_identity(
    stream: &str,
    transaction_id: &str,
    phase_operation: &str,
) -> Result<String, OrsError> {
    crate::restore_journal::phase_identity_for(stream, transaction_id, phase_operation)
}

fn decode_entry(raw: &str) -> Result<RestoreJournalEntry, OrsError> {
    let value: RestoreJournalEntry = serde_json::from_str(raw)
        .map_err(|_| integrity("restore_journal_entry", "serialized intent row is invalid"))?;
    value.validate().map_err(|error| {
        redact_persisted(
            &error,
            "restore_journal_entry",
            "intent row failed validation",
        )
    })?;
    Ok(value)
}

fn decode_result(raw: &str) -> Result<RestoreJournalResult, OrsError> {
    let value: RestoreJournalResult = serde_json::from_str(raw)
        .map_err(|_| integrity("restore_journal_result", "serialized result row is invalid"))?;
    value.validate().map_err(|error| {
        redact_persisted(
            &error,
            "restore_journal_result",
            "result row failed validation",
        )
    })?;
    Ok(value)
}

fn decode_index(raw: &str) -> Result<RestoreJournalOperationIndex, OrsError> {
    serde_json::from_str(raw).map_err(|_| {
        integrity(
            "restore_journal_index",
            "serialized operation index is invalid",
        )
    })
}

fn decode_binding(raw: &str) -> Result<RestoreJournalStreamBinding, OrsError> {
    let value: RestoreJournalStreamBinding = serde_json::from_str(raw)
        .map_err(|_| integrity("restore_journal_binding", "serialized binding is invalid"))?;
    value.validate().map_err(|error| {
        redact_persisted(
            &error,
            "restore_journal_binding",
            "binding failed validation",
        )
    })?;
    Ok(value)
}

fn decode_fence(raw: &str) -> Result<JournalHistoryFence, OrsError> {
    let value: JournalHistoryFence = serde_json::from_str(raw).map_err(|_| {
        integrity(
            "restore_journal_meta",
            "serialized history fence is invalid",
        )
    })?;
    value.validate().map_err(|error| {
        redact_persisted(
            &error,
            "restore_journal_meta",
            "history fence failed validation",
        )
    })?;
    Ok(value)
}

fn decode_predecessor(raw: &str) -> Result<JournalPredecessor, OrsError> {
    let value: JournalPredecessor = serde_json::from_str(raw)
        .map_err(|_| integrity("restore_journal_meta", "serialized journal head is invalid"))?;
    value.validate().map_err(|error| {
        redact_persisted(
            &error,
            "restore_journal_meta",
            "journal head failed validation",
        )
    })?;
    Ok(value)
}

fn decode_retention(raw: &str) -> Result<RestoreJournalRetentionRecord, OrsError> {
    let value: RestoreJournalRetentionRecord = serde_json::from_str(raw).map_err(|_| {
        integrity(
            "restore_journal_meta",
            "serialized retention decision is invalid",
        )
    })?;
    value.validate().map_err(|error| {
        redact_persisted(
            &error,
            "restore_journal_meta",
            "retention decision failed validation",
        )
    })?;
    Ok(value)
}

fn binding_key(stream: &str) -> String {
    format!("{BINDING_PREFIX}{KEY_SEP}{stream}")
}

fn history_key(stream: &str) -> String {
    format!("{HISTORY_PREFIX}{KEY_SEP}{stream}")
}

fn head_key(stream: &str) -> String {
    format!("{HEAD_PREFIX}{KEY_SEP}{stream}")
}

fn retention_key(stream: &str) -> String {
    format!("{RETENTION_PREFIX}{KEY_SEP}{stream}")
}

/// Stored size of one row if present, zero if absent. Used for rows this call
/// INSERTS on first use and REPLACES afterwards (the history fence and the
/// journal head): the first write must not be charged for a predecessor that
/// does not exist yet, and a later one must not be charged twice.
fn optional_row_bytes<T: ReadableTable<&'static str, &'static str>>(
    table: &T,
    key: &str,
) -> Result<usize, OrsError> {
    match table.get(key).map_err(storage)? {
        Some(row) => Ok(key.len() + row.value().len()),
        None => Ok(0),
    }
}

fn operation_key(slot: &str) -> String {
    format!("{OPERATION_PREFIX}{KEY_SEP}{slot}")
}

fn used_key(stream: &str, slot: &str) -> String {
    format!("{USED_PREFIX}{KEY_SEP}{stream}{KEY_SEP}{slot}")
}

fn parse_used_key(key: &str) -> Option<(String, String)> {
    let value = key.strip_prefix(USED_PREFIX)?.strip_prefix(KEY_SEP)?;
    let (stream, slot) = value.split_once(KEY_SEP)?;
    if stream.is_empty() || slot.is_empty() || slot.contains(KEY_SEP) {
        return None;
    }
    Some((stream.to_owned(), slot.to_owned()))
}

fn intent_key(stream: &str, sequence: u64) -> String {
    format!("{INTENT_PREFIX}{KEY_SEP}{stream}{KEY_SEP}{sequence:020}")
}

fn result_key(stream: &str, operation_sha256: &str) -> String {
    format!("{RESULT_PREFIX}{KEY_SEP}{stream}{KEY_SEP}{operation_sha256}")
}

fn namespace_value(key: &str, prefix: &str) -> Option<String> {
    let value = key.strip_prefix(prefix)?.strip_prefix(KEY_SEP)?;
    if value.is_empty() || value.contains(KEY_SEP) {
        return None;
    }
    Some(value.to_owned())
}

fn parse_intent_key(key: &str) -> Result<(String, u64), OrsError> {
    let value = key
        .strip_prefix(INTENT_PREFIX)
        .and_then(|value| value.strip_prefix(KEY_SEP))
        .ok_or_else(|| integrity("restore_journal_entry", "malformed intent key"))?;
    let (stream, sequence) = value
        .split_once(KEY_SEP)
        .ok_or_else(|| integrity("restore_journal_entry", "malformed intent key"))?;
    if stream.is_empty()
        || sequence.len() != 20
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(integrity(
            "restore_journal_entry",
            "malformed intent sequence key",
        ));
    }
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| integrity("restore_journal_entry", "malformed intent sequence key"))?;
    Ok((stream.to_owned(), sequence))
}

fn parse_result_key(key: &str) -> Result<(String, String), OrsError> {
    let value = key
        .strip_prefix(RESULT_PREFIX)
        .and_then(|value| value.strip_prefix(KEY_SEP))
        .ok_or_else(|| integrity("restore_journal_result", "malformed result key"))?;
    let (stream, operation_sha256) = value
        .split_once(KEY_SEP)
        .ok_or_else(|| integrity("restore_journal_result", "malformed result key"))?;
    if stream.is_empty() || operation_sha256.len() != 64 {
        return Err(integrity("restore_journal_result", "malformed result key"));
    }
    validate_journal_text(stream, "journal.result_stream")?;
    crate::model::validate_digest(operation_sha256, "journal.result_operation_sha256")?;
    Ok((stream.to_owned(), operation_sha256.to_owned()))
}

fn validate_journal_text(value: &str, field: &'static str) -> Result<(), OrsError> {
    // Length is checked FIRST: `trim()` scans the whole string, so validating
    // emptiness first would let an oversized all-whitespace input force an
    // unbounded scan before it is rejected.
    if value.len() > MAX_JOURNAL_STREAM_KEY_BYTES
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.contains(KEY_SEP)
    {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be non-blank bounded text with no control or separator characters",
        });
    }
    Ok(())
}

fn identity_conflict() -> OrsError {
    integrity(
        "restore_journal_operation",
        "same operation slot has a different complete identity or payload",
    )
}

fn predecessor_conflict() -> OrsError {
    integrity(
        "restore_journal_entry",
        "expected predecessor does not match the current journal head",
    )
}

fn migration(reason: &'static str) -> OrsError {
    OrsError::MigrationRequired {
        reason: reason.to_owned(),
    }
}

/// Collapses a persisted-row failure into a bounded, redacted diagnostic.
///
/// Only the typed ORS failures whose variants are field-and-reason bounded and
/// carry no row bytes are preserved verbatim. Every other variant — which can
/// embed serialized row text, provider messages or storage strings — is replaced
/// by a static [`integrity`] reason, so decoding a hostile or corrupt row can
/// never echo its content back through the error channel or change a
/// persistence outcome.
fn redact_persisted(error: &OrsError, record_type: &'static str, reason: &'static str) -> OrsError {
    match error {
        OrsError::UnsupportedContractVersion(version) => {
            OrsError::UnsupportedContractVersion(*version)
        }
        OrsError::PayloadTooLarge => OrsError::PayloadTooLarge,
        OrsError::PayloadIntegrityMismatch => OrsError::PayloadIntegrityMismatch,
        OrsError::FenceMismatch => OrsError::FenceMismatch,
        OrsError::InvalidEpochLineage => OrsError::InvalidEpochLineage,
        OrsError::InvalidExpiry => OrsError::InvalidExpiry,
        OrsError::InvalidField { field, reason } => OrsError::InvalidField { field, reason },
        _ => integrity(record_type, reason),
    }
}

fn integrity(record_type: &'static str, reason: &'static str) -> OrsError {
    OrsError::IntegrityProblem {
        record_type,
        reason: reason.to_owned(),
    }
}
