//! Durable restore-journal backend inside the existing ORS store (issue #957).
//!
//! No second database, no backup import, no phase semantics: this module owns
//! three versioned tables plus the compare-and-append / readback / prune
//! operations over them, delegating through the single `RedbRecoveryStore`
//! writer. Journal rows are owner-neutral identity bindings with opaque
//! payloads; encryption ownership follows existing ORS policy (digests and
//! handles only, never credentials or authority).
//!
//! Every mutation runs in one short redb write transaction, so
//! check-then-insert is atomic: two writers cannot both advance the same
//! head, and intent/result/index writes land together or not at all.

use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::RESTORE_JOURNAL_STATE_CURRENT;
use super::RedbRecoveryStore;
use super::persistence_codec::{PersistedValue, decode_named, encode};
use super::storage;
use crate::OrsError;
use crate::model::sha256_hex;
use crate::restore_journal::{
    MAX_JOURNAL_PAGE_ENTRIES, MAX_JOURNAL_PAYLOAD_BYTES, MAX_JOURNAL_STREAM_KEY_BYTES,
    RESTORE_JOURNAL_RECORD_SCHEMA, RESTORE_JOURNAL_SCHEMA_VERSION, RestoreJournalEntry,
    RestoreJournalOperation, RestoreJournalResult, RestoreJournalStateRecord,
};

/// Versioned intent table: owner-neutral restore intent rows.
const RESTORE_JOURNAL_INTENTS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_restore_journal_intents_v1");
/// Versioned result table: receipts answering committed intents.
const RESTORE_JOURNAL_RESULTS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_restore_journal_results_v1");
/// Dedicated journal meta table: schema marker plus per-stream prune marks.
const RESTORE_JOURNAL_META: TableDefinition<&str, &str> =
    TableDefinition::new("ors_restore_journal_meta_v1");
/// Schema marker row inside the meta table.
const RESTORE_JOURNAL_SCHEMA_ROW: &str = "schema";
/// Frozen schema identity recorded by [`ensure_restore_journal_schema`].
const RESTORE_JOURNAL_SCHEMA_IDENTITY: &str = "ors-restore-journal-schema-v1";

impl PersistedValue for RestoreJournalEntry {
    const RECORD_TYPE: &'static str = "restore_journal_entry";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for RestoreJournalResult {
    const RECORD_TYPE: &'static str = "restore_journal_result";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for RestoreJournalStateRecord {
    const RECORD_TYPE: &'static str = "restore_journal_state";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// Key namespace separator (never valid inside validated text fields).
const KEY_SEP: char = '\0';

fn intent_key(stream: &str, sequence: u64) -> String {
    format!("{stream}{KEY_SEP}{sequence:020}")
}

fn result_key(stream: &str, phase_operation: &str) -> String {
    format!("{stream}{KEY_SEP}result{KEY_SEP}{phase_operation}")
}

fn pruned_marker_key(stream: &str) -> String {
    format!("pruned{KEY_SEP}{stream}")
}

fn split_key(key: &str) -> Option<(&str, &str)> {
    let (stream, rest) = key.split_once(KEY_SEP)?;
    Some((stream, rest))
}

fn binding_row_key(stream: &str) -> String {
    format!("binding{KEY_SEP}{stream}")
}

/// Outcome of scanning one stream: an identical persisted operation to replay,
/// if any, plus the current head `(sequence, digest)` for predecessor compare.
struct JournalScan {
    replay: Option<RestoreJournalEntry>,
    head: Option<(u64, String)>,
}

/// Scans one stream for an identical operation or the current head.
///
/// Pure read over the open intents table: replays (never duplicates) an
/// identical operation, rejects a changed payload under the same operation
/// identity, and enforces monotone sequences. The caller performs the
/// predecessor compare and the append inside the same write transaction.
fn scan_journal_stream(
    intents: &redb::Table<'_, &str, &str>,
    stream: &str,
    operation: &RestoreJournalOperation,
    payload_sha256: &str,
    payload: &str,
) -> Result<JournalScan, OrsError> {
    let mut head: Option<(u64, String)> = None;
    let mut replay: Option<RestoreJournalEntry> = None;
    let prefix = format!("{stream}{KEY_SEP}");
    let mut scanned = 0_usize;
    for entry in intents.iter().map_err(storage)? {
        let (key, value) = entry.map_err(storage)?;
        let (entry_stream, _) = split_key(key.value()).ok_or(integrity(
            "restore_journal_entry",
            "malformed journal row key",
        ))?;
        if entry_stream != stream {
            continue;
        }
        if !key.value().starts_with(&prefix) {
            continue;
        }
        scanned += 1;
        if scanned > MAX_JOURNAL_PAGE_ENTRIES * 16 {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        let stored: RestoreJournalEntry = decode_named(value.value(), "restore_journal_entry")?;
        stored.validate()?;
        if stored.operation.transaction_id == operation.transaction_id
            && stored.operation.phase_operation == operation.phase_operation
            && stored.operation.request_digest == operation.request_digest
            && stored.operation.body_digest == operation.body_digest
        {
            if stored.payload_sha256 != payload_sha256 || stored.payload != payload {
                return Err(integrity(
                    "restore_journal_entry",
                    "changed payload under the same journal operation identity",
                ));
            }
            replay = Some(stored);
            break;
        }
        let digest = stored.digest()?;
        match &head {
            Some((sequence, _)) if stored.sequence <= *sequence => {
                return Err(integrity(
                    "restore_journal_entry",
                    "journal sequence is not monotone",
                ));
            }
            _ => head = Some((stored.sequence, digest)),
        }
    }
    Ok(JournalScan { replay, head })
}

impl RedbRecoveryStore {
    /// Binds one stream to its exact restore context, durably and idempotently.
    ///
    /// The first bind persists the binding; replaying the identical binding
    /// succeeds without effect; a different binding for the same stream
    /// conflicts instead of silently rebinding. Every later append on the
    /// stream carries these bindings in its operation.
    pub fn bind_restore_journal_stream(
        &self,
        stream: &str,
        binding: &crate::restore_journal::RestoreJournalStreamBinding,
    ) -> Result<(), OrsError> {
        binding.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
            let key = binding_row_key(stream);
            let stored: Option<crate::restore_journal::RestoreJournalStreamBinding> = meta
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| {
                    serde_json::from_str(value.value()).map_err(|error| {
                        OrsError::IntegrityProblem {
                            record_type: "restore_journal_binding",
                            reason: error.to_string(),
                        }
                    })
                })
                .transpose()?;
            match stored {
                Some(stored) => {
                    if stored != *binding {
                        return Err(integrity(
                            "restore_journal_binding",
                            "conflicting binding for the same journal stream",
                        ));
                    }
                }
                None => {
                    meta.insert(
                        key.as_str(),
                        serde_json::to_string(binding)
                            .map_err(|error| OrsError::Encoding(error.to_string()))?
                            .as_str(),
                    )
                    .map_err(storage)?;
                }
            }
        }
        write.commit().map_err(storage)?;
        Ok(())
    }

    /// Reads one stream binding, if bound.
    pub fn load_restore_journal_binding(
        &self,
        stream: &str,
    ) -> Result<Option<crate::restore_journal::RestoreJournalStreamBinding>, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        let read = self.database.begin_read().map_err(storage)?;
        let meta = read.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        meta.get(binding_row_key(stream).as_str())
            .map_err(storage)?
            .map(|value| {
                serde_json::from_str(value.value()).map_err(|error| OrsError::IntegrityProblem {
                    record_type: "restore_journal_binding",
                    reason: error.to_string(),
                })
            })
            .transpose()
    }
    /// Ensures the versioned journal tables plus the idempotent schema marker.
    ///
    /// Creates missing tables, records schema v1 exactly once, and refuses
    /// unknown `ors_restore_journal` tables or a foreign schema identity so
    /// an old empty/incomplete journal can never read as complete.
    pub fn ensure_restore_journal_schema(&self) -> Result<u32, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
            let existing: Option<String> = meta
                .get(RESTORE_JOURNAL_SCHEMA_ROW)
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            match existing {
                Some(identity) if identity == RESTORE_JOURNAL_SCHEMA_IDENTITY => {}
                Some(_) => {
                    return Err(integrity(
                        "restore_journal_schema",
                        "unknown restore journal schema identity",
                    ));
                }
                None => {
                    meta.insert(RESTORE_JOURNAL_SCHEMA_ROW, RESTORE_JOURNAL_SCHEMA_IDENTITY)
                        .map_err(storage)?;
                }
            }
            let _ = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
            let _ = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(RESTORE_JOURNAL_SCHEMA_VERSION)
    }

    /// Loads one exact opaque restore-journal state row, if present.
    pub fn load_restore_journal_state(
        &self,
        journal_key: &str,
    ) -> Result<Option<RestoreJournalStateRecord>, OrsError> {
        validate_journal_text(journal_key, "restore_state.journal_key")?;
        let read = self.database.begin_read().map_err(storage)?;
        let table = read
            .open_table(RESTORE_JOURNAL_STATE_CURRENT)
            .map_err(storage)?;
        table
            .get(journal_key)
            .map_err(storage)?
            .map(|value| {
                let record: RestoreJournalStateRecord =
                    decode_named(value.value(), "restore_journal_state")?;
                record.validate()?;
                if record.journal_key != journal_key {
                    return Err(integrity(
                        "restore_journal_state",
                        "journal key does not match the durable row",
                    ));
                }
                Ok(record)
            })
            .transpose()
    }

    /// Compare-and-swaps one opaque restore-journal state row.
    ///
    /// Revision zero is the explicit initial state used by the backup
    /// coordinator. Every later write must advance by exactly one; an exact
    /// replay is idempotent, while a stale or skipped revision refuses.
    pub fn compare_and_swap_restore_journal_state(
        &self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalStateRecord,
    ) -> Result<(), OrsError> {
        validate_journal_text(journal_key, "restore_state.journal_key")?;
        next.validate()?;
        if next.journal_key != journal_key {
            return Err(integrity(
                "restore_journal_state",
                "next journal key does not match the requested key",
            ));
        }
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write
                .open_table(RESTORE_JOURNAL_STATE_CURRENT)
                .map_err(storage)?;
            let current = table
                .get(journal_key)
                .map_err(storage)?
                .map(|value| {
                    decode_named::<RestoreJournalStateRecord>(
                        value.value(),
                        "restore_journal_state",
                    )
                })
                .transpose()?;
            if let Some(current) = current {
                current.validate()?;
                if current.revision != expected_revision {
                    return Err(OrsError::DuplicateConflict);
                }
                if current == next {
                    return Ok(());
                }
                if next.revision != expected_revision.saturating_add(1) {
                    return Err(integrity(
                        "restore_journal_state",
                        "journal revision must advance by exactly one",
                    ));
                }
            } else if expected_revision != 0 || next.revision != 0 {
                return Err(OrsError::DuplicateConflict);
            }
            table
                .insert(journal_key, encode(&next)?.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    /// Appends one intent with exact-predecessor compare, or replays it.
    ///
    /// Validates the operation, then in one write transaction: replays the
    /// identical operation (same transaction, phase, request, and body
    /// digests) as its persisted receipt instead of duplicating; otherwise
    /// requires the expected predecessor to equal the current stream head
    /// (`None` exactly for an empty stream) and appends at head + 1.
    /// Changed payload under the same operation identity conflicts.
    pub fn append_restore_journal_intent(
        &self,
        stream: &str,
        operation: &RestoreJournalOperation,
        payload_sha256: &str,
        payload: &str,
    ) -> Result<crate::restore_journal::RestoreJournalAppendReceipt, OrsError> {
        operation.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        if payload.len() > MAX_JOURNAL_PAYLOAD_BYTES {
            return Err(OrsError::PayloadTooLarge);
        }
        crate::model::validate_digest(payload_sha256, "journal.payload_sha256")?;
        if sha256_hex(payload.as_bytes()) != payload_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        if operation.record_schema != RESTORE_JOURNAL_RECORD_SCHEMA {
            return Err(OrsError::InvalidField {
                field: "journal.record_schema",
                reason: "unsupported restore journal record schema",
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let receipt = {
            let mut intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
            let scan = scan_journal_stream(&intents, stream, operation, payload_sha256, payload)?;
            if let Some(existing) = scan.replay {
                let digest = existing.digest()?;
                (existing.sequence, digest, true)
            } else {
                match (&operation.expected_predecessor, &scan.head) {
                    (None, None) => {}
                    (Some(expected), Some((sequence, digest)))
                        if expected.sequence == *sequence && expected.digest == *digest => {}
                    _ => {
                        return Err(integrity(
                            "restore_journal_entry",
                            "expected predecessor does not match the current journal head",
                        ));
                    }
                }
                let sequence = scan.head.map_or(0, |(sequence, _)| sequence + 1);
                let stored = RestoreJournalEntry {
                    operation: operation.clone(),
                    sequence,
                    payload_sha256: payload_sha256.to_owned(),
                    payload: payload.to_owned(),
                };
                stored.validate()?;
                let key = intent_key(stream, sequence);
                let digest = stored.digest()?;
                intents
                    .insert(key.as_str(), encode(&stored)?.as_str())
                    .map_err(storage)?;
                (sequence, digest, false)
            }
        };
        write.commit().map_err(storage)?;
        Ok(crate::restore_journal::RestoreJournalAppendReceipt {
            transaction_id: operation.transaction_id.clone(),
            phase_operation: operation.phase_operation.clone(),
            sequence: receipt.0,
            record_digest: receipt.1,
            replayed: receipt.2,
        })
    }

    /// Appends one result answering a committed intent.
    ///
    /// Requires the referenced intent row to exist with a matching digest;
    /// a second differing result for the same stream phase conflicts, while
    /// an identical one replays. Results never mint intents.
    pub fn append_restore_journal_result(
        &self,
        stream: &str,
        result: &RestoreJournalResult,
    ) -> Result<crate::restore_journal::RestoreJournalAppendReceipt, OrsError> {
        result.validate()?;
        validate_journal_text(stream, "journal.stream")?;
        let write = self.database.begin_write().map_err(storage)?;
        let receipt = {
            let intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
            let mut results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
            let key = result_key(stream, &result.phase_operation);
            if let Some(existing) = results.get(key.as_str()).map_err(storage)? {
                let stored: RestoreJournalResult =
                    decode_named(existing.value(), "restore_journal_result")?;
                stored.validate()?;
                if stored != *result {
                    return Err(integrity(
                        "restore_journal_result",
                        "conflicting result for the same journal phase",
                    ));
                }
                let digest = stored.digest()?;
                (stored.intent_sequence, digest, true)
            } else {
                let prefix = format!("{stream}{KEY_SEP}");
                let mut answered = false;
                for entry in intents.iter().map_err(storage)? {
                    let (key, value) = entry.map_err(storage)?;
                    if !key.value().starts_with(&prefix) {
                        continue;
                    }
                    let stored: RestoreJournalEntry =
                        decode_named(value.value(), "restore_journal_entry")?;
                    if stored.operation.transaction_id == result.transaction_id
                        && stored.operation.phase_operation == result.phase_operation
                        && stored.sequence == result.intent_sequence
                    {
                        answered = true;
                        break;
                    }
                }
                if !answered {
                    return Err(integrity(
                        "restore_journal_result",
                        "result answers no committed journal intent",
                    ));
                }
                results
                    .insert(key.as_str(), encode(result)?.as_str())
                    .map_err(storage)?;
                let digest = result.digest()?;
                (result.intent_sequence, digest, false)
            }
        };
        write.commit().map_err(storage)?;
        Ok(crate::restore_journal::RestoreJournalAppendReceipt {
            transaction_id: result.transaction_id.clone(),
            phase_operation: result.phase_operation.clone(),
            sequence: receipt.0,
            record_digest: receipt.1,
            replayed: receipt.2,
        })
    }

    /// Bounded readback of one stream with full chain validation.
    ///
    /// Decodes and validates every row, enforces monotone sequences and exact
    /// predecessor linkage (a pruned prefix recorded by
    /// [`prune_restore_journal`](Self::prune_restore_journal) starts the
    /// chain), and refuses unbounded reads. Missing, corrupt, duplicate, or
    /// stale history fails closed; an empty stream is known-empty, never an
    /// error.
    pub fn load_restore_journal_stream(
        &self,
        stream: &str,
        limit: usize,
    ) -> Result<Vec<RestoreJournalEntry>, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        if limit == 0 || limit > MAX_JOURNAL_PAGE_ENTRIES {
            return Err(OrsError::InvalidField {
                field: "journal.page_limit",
                reason: "page limit must be between 1 and the journal page bound",
            });
        }
        let read = self.database.begin_read().map_err(storage)?;
        let intents = read.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
        let prefix = format!("{stream}{KEY_SEP}");
        let mut rows: Vec<(u64, RestoreJournalEntry)> = Vec::new();
        for entry in intents.iter().map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            if !key.value().starts_with(&prefix) {
                continue;
            }
            if rows.len() >= limit {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            let stored: RestoreJournalEntry = decode_named(value.value(), "restore_journal_entry")?;
            stored.validate()?;
            rows.push((stored.sequence, stored));
        }
        rows.sort_by_key(|(sequence, _)| *sequence);
        let mut deduped: Vec<(u64, RestoreJournalEntry)> = Vec::with_capacity(rows.len());
        for row in rows {
            if deduped.last().map(|(sequence, _)| *sequence) == Some(row.0) {
                return Err(integrity(
                    "restore_journal_entry",
                    "duplicate journal sequence",
                ));
            }
            deduped.push(row);
        }
        let pruned_before = Self::pruned_before_sequence(&read, stream)?;
        let mut previous: Option<(u64, String)> = None;
        for (sequence, stored) in &deduped {
            match (&stored.operation.expected_predecessor, &previous) {
                (None, None) => {}
                (Some(expected), Some((previous_sequence, previous_digest)))
                    if expected.sequence == *previous_sequence
                        && expected.digest == *previous_digest => {}
                (Some(_), None) if pruned_before.is_some_and(|mark| mark + 1 == *sequence) => {}
                _ => {
                    return Err(integrity(
                        "restore_journal_entry",
                        "journal predecessor linkage is broken",
                    ));
                }
            }
            previous = Some((*sequence, stored.digest()?));
        }
        Ok(deduped.into_iter().map(|(_, stored)| stored).collect())
    }

    /// Loads one result row by stream and phase, if present.
    pub fn load_restore_journal_result(
        &self,
        stream: &str,
        phase_operation: &str,
    ) -> Result<Option<RestoreJournalResult>, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        validate_journal_text(phase_operation, "journal.phase_operation")?;
        let read = self.database.begin_read().map_err(storage)?;
        let results = read.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
        let key = result_key(stream, phase_operation);
        results
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                let stored: RestoreJournalResult =
                    decode_named(value.value(), "restore_journal_result")?;
                stored.validate()?;
                Ok(stored)
            })
            .transpose()
    }

    /// Prunes oldest resolved pairs beyond the keep count.
    ///
    /// Only intent/result pairs with a committed result prune, oldest first;
    /// unresolved intents are never evicted to fit. The pruned prefix marker
    /// keeps readback linkage validation exact. Returns pruned pair count.
    pub fn prune_restore_journal(
        &self,
        stream: &str,
        keep_resolved: usize,
    ) -> Result<u64, OrsError> {
        validate_journal_text(stream, "journal.stream")?;
        let write = self.database.begin_write().map_err(storage)?;
        let pruned = {
            let mut intents = write.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
            let mut results = write.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
            let mut meta = write.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
            let prefix = format!("{stream}{KEY_SEP}");
            let mut pairs: Vec<(u64, String, String)> = Vec::new();
            for entry in intents.iter().map_err(storage)? {
                let (key, value) = entry.map_err(storage)?;
                if !key.value().starts_with(&prefix) {
                    continue;
                }
                let stored: RestoreJournalEntry =
                    decode_named(value.value(), "restore_journal_entry")?;
                let phase_key = result_key(stream, &stored.operation.phase_operation);
                if results.get(phase_key.as_str()).map_err(storage)?.is_some() {
                    pairs.push((stored.sequence, key.value().to_owned(), phase_key));
                }
            }
            pairs.sort();
            let mut removed = 0_u64;
            let existing: Option<String> = meta
                .get(pruned_marker_key(stream).as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned());
            let mut pruned_mark = parse_pruned_marker(existing)?;
            let excess = pairs.len().saturating_sub(keep_resolved);
            for (sequence, intent_key, phase_key) in pairs.into_iter().take(excess) {
                intents.remove(intent_key.as_str()).map_err(storage)?;
                results.remove(phase_key.as_str()).map_err(storage)?;
                pruned_mark = Some(pruned_mark.map_or(sequence, |mark| mark.max(sequence)));
                removed += 1;
            }
            if let Some(mark) = pruned_mark {
                meta.insert(
                    pruned_marker_key(stream).as_str(),
                    serde_json::to_string(&mark)
                        .map_err(|error| OrsError::Encoding(error.to_string()))?
                        .as_str(),
                )
                .map_err(storage)?;
            }
            removed
        };
        write.commit().map_err(storage)?;
        Ok(pruned)
    }

    fn pruned_before_sequence(
        read: &redb::ReadTransaction,
        stream: &str,
    ) -> Result<Option<u64>, OrsError> {
        let meta = read.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
        let raw: Option<String> = meta
            .get(pruned_marker_key(stream).as_str())
            .map_err(storage)?
            .map(|value| value.value().to_owned());
        parse_pruned_marker(raw)
    }
}

fn parse_pruned_marker(raw: Option<String>) -> Result<Option<u64>, OrsError> {
    match raw {
        Some(value) => serde_json::from_str(&value).map_err(|error| OrsError::IntegrityProblem {
            record_type: "restore_journal_meta",
            reason: error.to_string(),
        }),
        None => Ok(None),
    }
}

fn integrity(record_type: &'static str, reason: &'static str) -> OrsError {
    OrsError::IntegrityProblem {
        record_type,
        reason: reason.to_owned(),
    }
}

fn validate_journal_text(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.trim().is_empty()
        || value.len() > MAX_JOURNAL_STREAM_KEY_BYTES
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
