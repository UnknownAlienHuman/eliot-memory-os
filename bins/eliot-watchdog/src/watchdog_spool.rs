//! Physical protected spool cell for the independent Runtime 0.17 watchdog.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-02.
//! Implementation: I8.1, I8.3, I8.10, I8.13, I2.23.
//! Physical protected spool only — no semantic/canonical/Kernel/Governor
//! authority and no new default or retry; bytes/layout/recovery/high-water/fail-closed
//! behavior is preserved verbatim from the reviewed production cell.

use std::path::{Path, PathBuf};

use eliot_contracts::sha256_hex;
use eliot_platform_windows::ProtectedRuntimePathLease;
use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolCursor, WatchdogSpoolExportBatch,
    WatchdogSpoolExportEntry, WatchdogSpoolPayloadKind, WatchdogSpoolReconciliationError,
    acknowledgement_advances_cursor, is_duplicate_ack, validate_acknowledgement, validate_batch,
    validate_batch_freshness, validate_cursor,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::{SERVICE_NAME, SpoolError, WatchdogRuntimeBinding, current_unix_ms};

mod codec;

pub use codec::{WatchdogSpoolEntry, WatchdogSpoolPayload};
pub(crate) use codec::{WatchdogSpoolHeader, encode_entry, encode_high_water, validate_header};
use codec::{
    collect_entries, decode_header, decode_high_water, encode_header, read_high_water,
    validate_high_water,
};

pub(crate) const SPOOL_SCHEMA_VERSION: u16 = 1;
pub(crate) const SPOOL_HEADER_KEY: u64 = 0;
pub(crate) const SPOOL_MAX_RECORDS: u64 = 4096;
pub(crate) const SPOOL_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const SPOOL_MAX_RECORD_BYTES: usize = 64 * 1024;
pub(crate) const WATCHDOG_SPOOL_FILE_NAME: &str = "watchdog.redb";
pub(crate) const SPOOL_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_v1");
pub(crate) const SPOOL_HIGH_WATER_KEY: u64 = 0;
pub(crate) const SPOOL_HIGH_WATER_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_high_water_v1");
/// Default and hard ceiling for the number of spool records covered by one
/// export batch.
///
/// A single export stays small against `SPOOL_MAX_RECORDS`: 256 records are
/// one sixteenth of the 4096-record retention ceiling, so a full spool drains
/// in a bounded handful of exports while no single export can pin the sink
/// with an unbounded window.
pub(crate) const EXPORT_MAX_ITEMS: usize = 256;
/// Default and hard ceiling for the total raw entry bytes covered by one
/// export batch.
///
/// 512 KiB is one eighth of `SPOOL_MAX_BYTES` (4 MiB) and eight times
/// `SPOOL_MAX_RECORD_BYTES` (64 KiB), so any single retained record always
/// fits while a full spool still drains in a bounded handful of exports.
pub(crate) const EXPORT_MAX_BYTES: u64 = 512 * 1024;
/// Acknowledgement window for one export batch, in milliseconds.
///
/// The spool owner stamps `created_at_ms` from its own clock and enforces the
/// window with its own clock at acknowledgement time. An expired batch fails
/// closed and the sink retries with a fresh export over the same immutable
/// records; the window never enters the batch digest material.
pub(crate) const EXPORT_BATCH_TTL_MS: u64 = 60_000;
/// Storage revision of the persisted export cursor record.
///
/// This intentionally equals `SPOOL_SCHEMA_VERSION` today. A future revision
/// bump refuses to mix cursor generations instead of reinterpreting them.
pub(crate) const SPOOL_EXPORT_CURSOR_SCHEMA_VERSION: u16 = 1;
/// Single-key cursor row inside the export cursor table.
pub(crate) const SPOOL_EXPORT_CURSOR_KEY: u64 = 0;
/// Cursor table inside the same `watchdog.redb` file.
///
/// The spool keeps its single writer and never shards cursor state into a
/// second file; every cursor read and write below runs inside the same
/// transactional patterns as the header and high-water paths.
pub(crate) const SPOOL_EXPORT_CURSOR_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_export_cursor_v1");
/// Maximum accepted length for one persisted cursor identity string.
///
/// Cursor identities are short installer-bound names such as
/// `installation-7`. The cap keeps the single-key cursor row tiny and fails
/// closed on corrupt oversized values instead of growing it without bound.
pub(crate) const SPOOL_EXPORT_CURSOR_IDENTITY_MAX: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpoolAppendOutcome {
    Stored,
    Pressure { evicted_records: u64 },
}

/// Bounded window for one spool export.
///
/// Both caps apply together: export stops at whichever bound is reached
/// first, after always covering at least one record so a non-empty spool
/// always makes progress. The defaults equal `EXPORT_MAX_ITEMS` and
/// `EXPORT_MAX_BYTES`, which are also hard ceilings; a caller window outside
/// those ceilings is rejected instead of silently clamped so an exact retry
/// of the same window stays byte-equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogSpoolExportLimits {
    pub max_items: usize,
    pub max_bytes: u64,
}

impl Default for WatchdogSpoolExportLimits {
    fn default() -> Self {
        Self {
            max_items: EXPORT_MAX_ITEMS,
            max_bytes: EXPORT_MAX_BYTES,
        }
    }
}

impl WatchdogSpoolExportLimits {
    /// Rejects unbounded or unprogressable windows before any spool read.
    ///
    /// The lower byte bound is one maximum-size record, which guarantees the
    /// first covered record always fits and export always makes progress.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] carrying the exact reconciliation
    /// field failure when either bound is zero or above its hard ceiling.
    fn validate(&self) -> Result<(), SpoolError> {
        if self.max_items == 0 || self.max_items > EXPORT_MAX_ITEMS {
            return Err(WatchdogSpoolReconciliationError::InvalidField("max_items").into());
        }
        if self.max_bytes < SPOOL_MAX_RECORD_BYTES as u64 || self.max_bytes > EXPORT_MAX_BYTES {
            return Err(WatchdogSpoolReconciliationError::InvalidField("max_bytes").into());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct WatchdogSpool {
    pub(crate) database: Database,
    pub(crate) _path_lease: Option<ProtectedRuntimePathLease>,
}

impl WatchdogSpool {
    pub(crate) fn open_runtime_binding(
        binding: &WatchdogRuntimeBinding,
    ) -> Result<Self, SpoolError> {
        let path = watchdog_spool_path(binding.watchdog_state_root());
        let path_lease = ProtectedRuntimePathLease::open_or_create_absolute(&path)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let spool = Self {
            database,
            _path_lease: Some(path_lease),
        };
        spool.initialize_or_recover()?;
        Ok(spool)
    }

    pub(crate) fn open_existing_runtime_binding(
        binding: &WatchdogRuntimeBinding,
    ) -> Result<Self, SpoolError> {
        let path = watchdog_spool_path(binding.watchdog_state_root());
        let path_lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        if path_lease.path() != path {
            return Err(SpoolError::InvalidProtectedRoot);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| SpoolError::InvalidProtectedRoot)?;
        let database = Database::open(path_lease.path())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: Some(path_lease),
        })
    }

    pub(crate) fn readback(&self) -> Result<Vec<WatchdogSpoolEntry>, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let header = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let header = decode_header(header.value())?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        let high_water = read_high_water(&high_water)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))?;
        validate_high_water(&header, &entries, high_water)?;
        Ok(entries)
    }

    pub(crate) fn initialize_or_recover(&self) -> Result<(), SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = match read.open_table(SPOOL_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                drop(read);
                return self.write_header(&WatchdogSpoolHeader {
                    schema_version: SPOOL_SCHEMA_VERSION,
                    next_sequence: 1,
                    first_sequence: 1,
                    record_count: 0,
                    bytes: 0,
                });
            }
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let header = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let entries = collect_entries(&table);
        let parsed_header = header
            .as_ref()
            .and_then(|value| decode_header(value.value()).ok());
        let high_water_table = match read.open_table(SPOOL_HIGH_WATER_TABLE) {
            Ok(table) => Some(table),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        let parsed_high_water = high_water_table
            .as_ref()
            .map(read_high_water)
            .transpose()?
            .flatten();
        let header_and_entries_valid = parsed_header
            .as_ref()
            .zip(entries.as_ref().ok())
            .is_some_and(|(header, entries)| validate_header(header, entries).is_ok());
        let valid = header_and_entries_valid
            && parsed_high_water.is_some_and(|high_water| {
                parsed_header
                    .as_ref()
                    .zip(entries.as_ref().ok())
                    .is_some_and(|(header, entries)| {
                        validate_high_water(header, entries, high_water).is_ok()
                    })
            });
        if valid {
            return self.ensure_export_cursor();
        }
        if header_and_entries_valid
            && let Some(high_water) = parsed_high_water
            && let Some((header, entries)) = parsed_header.as_ref().zip(entries.as_ref().ok())
        {
            validate_high_water(header, entries, high_water)?;
        }
        let corrupt_digest = header
            .as_ref()
            .map_or_else(|| "missing".to_owned(), |value| sha256_hex(value.value()));
        drop(table);
        drop(read);
        self.recover(
            "existing spool header or record set failed validation",
            None,
            corrupt_digest,
        )
    }

    fn write_header(&self, header: &WatchdogSpoolHeader) -> Result<(), SpoolError> {
        let bytes = encode_header(header)?;
        let high_water = header.next_sequence.saturating_sub(1);
        let high_water_bytes = encode_high_water(high_water)?;
        // A fresh spool has acknowledged nothing. The cursor row starts
        // unbound (zero generation, empty identities); the first export binds
        // the caller identities in memory and the first acknowledgement
        // persists them, so no canned identity is ever invented here.
        let cursor_bytes = encode_export_cursor(&unbound_export_cursor())?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        {
            let mut table = write
                .open_table(SPOOL_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(SPOOL_HEADER_KEY, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(table);
            let mut high_water_table = write
                .open_table(SPOOL_HIGH_WATER_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            high_water_table
                .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(high_water_table);
            let mut cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            cursor_table
                .insert(SPOOL_EXPORT_CURSOR_KEY, cursor_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(cursor_table);
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    fn recover(
        &self,
        reason: &str,
        corrupt_sequence: Option<u64>,
        corrupt_digest: String,
    ) -> Result<(), SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is missing; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let previous_high_water = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let previous_high_water = decode_high_water(&previous_high_water)?;
        let recovery_sequence = previous_high_water
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?;
        // Preserve-then-clamp: a restart keeps the stored cursor. See
        // `preserved_export_cursor_bytes` for the exact guarantee.
        let preserved_cursor_bytes = preserved_export_cursor_bytes(&write, recovery_sequence)?;
        let entry = WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence: recovery_sequence,
            observed_at_ms: current_unix_ms()?.max(1),
            payload: WatchdogSpoolPayload::Recovery {
                service: SERVICE_NAME.to_owned(),
                reason: reason.to_owned(),
                corrupt_sequence,
                corrupt_digest,
            },
        };
        let bytes = encode_entry(&entry)?;
        let header = WatchdogSpoolHeader {
            schema_version: SPOOL_SCHEMA_VERSION,
            next_sequence: recovery_sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?,
            first_sequence: recovery_sequence,
            record_count: 1,
            bytes: bytes.len() as u64,
        };
        let header_bytes = encode_header(&header)?;
        {
            let mut table = write
                .open_table(SPOOL_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            let keys = table
                .iter()
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .map(|item| {
                    item.map(|(key, _)| key.value())
                        .map_err(|error| SpoolError::Database(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if keys
                .iter()
                .filter(|key| **key != SPOOL_HEADER_KEY)
                .any(|key| *key > previous_high_water)
            {
                return Err(SpoolError::Corrupt(
                    "high-water metadata is below a retained sequence; continuity cannot be proven"
                        .to_owned(),
                ));
            }
            for key in keys {
                table
                    .remove(key)
                    .map_err(|error| SpoolError::Database(error.to_string()))?;
            }
            table
                .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            table
                .insert(entry.sequence, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            let high_water_bytes = encode_high_water(recovery_sequence)?;
            high_water_table
                .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(table);
            store_export_cursor_bytes(&write, &preserved_cursor_bytes)?;
        }
        drop(high_water_table);
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "bounded spool retention, pressure marking, and high-water updates stay one atomic redb transaction"
    )]
    pub(crate) fn append(
        &self,
        observed_at_ms: u64,
        payload: WatchdogSpoolPayload,
    ) -> Result<SpoolAppendOutcome, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut table = write
            .open_table(SPOOL_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is unavailable; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let mut header = decode_header(&header_bytes)?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let high_water = decode_high_water(&high_water)?;
        validate_high_water(&header, &entries, high_water)?;
        let sequence = high_water
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence exhausted".to_owned()))?;
        if sequence != header.next_sequence {
            return Err(SpoolError::Corrupt(
                "spool header next sequence does not match high-water metadata".to_owned(),
            ));
        }
        let entry = WatchdogSpoolEntry {
            schema_version: SPOOL_SCHEMA_VERSION,
            sequence,
            observed_at_ms,
            payload: payload.clone(),
        };
        let initial_bytes = encode_entry(&entry)?;
        let pressure = header.record_count >= SPOOL_MAX_RECORDS
            || header.bytes.saturating_add(initial_bytes.len() as u64) > SPOOL_MAX_BYTES;
        let encoded_entries = if pressure {
            let marker = WatchdogSpoolEntry {
                schema_version: SPOOL_SCHEMA_VERSION,
                sequence,
                observed_at_ms,
                payload: WatchdogSpoolPayload::Gap {
                    service: SERVICE_NAME.to_owned(),
                    reason: crate::GapRecoveryReason::SpoolPressure,
                    coverage_claimed: false,
                },
            };
            let entry_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
            let entry = WatchdogSpoolEntry {
                schema_version: SPOOL_SCHEMA_VERSION,
                sequence: entry_sequence,
                observed_at_ms,
                payload,
            };
            vec![
                (sequence, encode_entry(&marker)?),
                (entry_sequence, encode_entry(&entry)?),
            ]
        } else {
            vec![(sequence, initial_bytes)]
        };
        let total_bytes = encoded_entries
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum::<u64>();
        let mut evicted_records = 0;
        while header.record_count + encoded_entries.len() as u64 > SPOOL_MAX_RECORDS
            || header.bytes.saturating_add(total_bytes) > SPOOL_MAX_BYTES
        {
            if header.record_count == 0 {
                break;
            }
            let old_sequence = header.first_sequence;
            let old = table
                .remove(old_sequence)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .ok_or_else(|| SpoolError::Corrupt("retention record is missing".to_owned()))?;
            header.bytes = header
                .bytes
                .checked_sub(old.value().len() as u64)
                .ok_or_else(|| SpoolError::Corrupt("spool byte counter underflow".to_owned()))?;
            header.first_sequence = old_sequence
                .checked_add(1)
                .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
            header.record_count -= 1;
            evicted_records += 1;
        }
        for (sequence, bytes) in &encoded_entries {
            table
                .insert(*sequence, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            if header.record_count == 0 {
                header.first_sequence = *sequence;
            }
            header.record_count += 1;
            header.bytes = header
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| SpoolError::Corrupt("spool byte counter overflow".to_owned()))?;
        }
        header.schema_version = SPOOL_SCHEMA_VERSION;
        let last_sequence = encoded_entries
            .last()
            .map(|(sequence, _)| *sequence)
            .ok_or_else(|| SpoolError::Corrupt("spool append produced no records".to_owned()))?;
        header.next_sequence = last_sequence
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
        let header_bytes = encode_header(&header)?;
        table
            .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let high_water_bytes = encode_high_water(last_sequence)?;
        high_water_table
            .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        drop(table);
        drop(high_water_table);
        write
            .commit()
            .map(|()| {
                if pressure {
                    SpoolAppendOutcome::Pressure { evicted_records }
                } else {
                    SpoolAppendOutcome::Stored
                }
            })
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    /// Reads the durable high-water sequence without mutating any spool state.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the database cannot be read or the
    /// high-water metadata is absent or invalid.
    pub(crate) fn high_water_sequence(&self) -> Result<u64, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        read_high_water(&table)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))
    }

    /// Reads the stored Watchdog-owned export cursor.
    ///
    /// A spool that predates the cursor table (or has no cursor row yet)
    /// reports the unbound acknowledged-zero cursor; the first export binds
    /// the caller identities in memory and the first acknowledgement persists
    /// them. Nothing is written by this read.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the database cannot be read or a present
    /// cursor row fails strict decoding.
    pub(crate) fn read_export_cursor(&self) -> Result<WatchdogSpoolCursor, SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        match read.open_table(SPOOL_EXPORT_CURSOR_TABLE) {
            Ok(table) => decode_export_cursor_value(&table),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(unbound_export_cursor()),
            Err(error) => Err(SpoolError::Database(error.to_string())),
        }
    }

    /// Builds one bounded immutable export batch for an exact acknowledgement.
    ///
    /// The export is read-only: it never mutates the header, the high-water,
    /// or the cursor. It covers only the consecutive window starting just
    /// past the predecessor cursor, capped by both `limits` bounds, and an
    /// empty spool (`acknowledged == high-water`) yields the explicit empty
    /// batch. Digest material carries no timestamps, so an exact retry of the
    /// same cursor, high-water, and identities is digest-equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the window is unbounded, the predecessor
    /// fails contract validation or diverges from the stored cursor, the
    /// caller high-water runs past the durable high-water, or the retained
    /// records no longer cover the cursor consecutively.
    pub(crate) fn export_batch(
        &self,
        predecessor: &WatchdogSpoolCursor,
        high_water: u64,
        limits: WatchdogSpoolExportLimits,
    ) -> Result<(WatchdogSpoolExportBatch, Vec<Vec<u8>>), SpoolError> {
        limits.validate()?;
        validate_cursor(predecessor, high_water)?;
        let (entries, live_high_water, stored) = self.read_export_snapshot()?;
        if high_water > live_high_water {
            return Err(WatchdogSpoolReconciliationError::InvalidCursor.into());
        }
        check_export_predecessor(&stored, predecessor)?;
        if predecessor.acknowledged_sequence == high_water {
            let batch = build_empty_export_batch(predecessor, high_water)?;
            validate_batch(&batch, high_water)?;
            return Ok((batch, Vec::new()));
        }
        let selected = select_export_window(
            &entries,
            predecessor.acknowledged_sequence,
            high_water,
            &limits,
        )?;
        let (batch, raws) = build_export_batch(predecessor, high_water, &selected)?;
        validate_batch(&batch, high_water)?;
        Ok((batch, raws))
    }

    /// Applies an exact authenticated sink acknowledgement to the cursor.
    ///
    /// The batch is revalidated against the live high-water, the batch
    /// freshness window is enforced with the owner clock, and the terminal
    /// disposition table decides through the owner-neutral core call, so
    /// `Received`, `Durable`, `AdmittedCandidate`, and `Unknown` outcomes
    /// surface as non-terminal failures and skipped gaps fail closed. Unknown
    /// outcomes, timeouts, and disconnects must never reach this method; only
    /// a complete acknowledgement for one immutable batch is applied. Inside
    /// one write transaction the stored cursor is re-read: an acknowledgement
    /// whose predecessor lies below the stored sequence is an idempotent
    /// duplicate and returns the stored sequence unchanged without writing,
    /// while any other predecessor break fails closed without writing.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] carrying the exact reconciliation failure when
    /// the batch or acknowledgement is stale, mutated, expired, non-terminal,
    /// or mismatched, and when the predecessor breaks the stored cursor.
    pub(crate) fn apply_acknowledgement(
        &self,
        batch: &WatchdogSpoolExportBatch,
        ack: &WatchdogSpoolAcknowledgement,
    ) -> Result<u64, SpoolError> {
        let live_high_water = self.high_water_sequence()?;
        let now_ms = current_unix_ms()?;
        validate_batch(batch, live_high_water)?;
        validate_batch_freshness(batch, now_ms)?;
        validate_acknowledgement(batch, ack)?;
        let advanced = acknowledgement_advances_cursor(batch, ack)?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = {
            let cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            match cursor_table
                .get(SPOOL_EXPORT_CURSOR_KEY)
                .map_err(|error| SpoolError::Database(error.to_string()))?
            {
                // A missing row is a spool that predates the cursor table;
                // the first acknowledgement binds it. A present but corrupt
                // row fails closed here and heals at the next open.
                None => unbound_export_cursor(),
                Some(value) => decode_export_cursor(value.value())?,
            }
        };
        if is_duplicate_ack(stored.acknowledged_sequence, ack) {
            return Ok(stored.acknowledged_sequence);
        }
        if ack.predecessor_sequence != stored.acknowledged_sequence {
            return Err(WatchdogSpoolReconciliationError::PredecessorMismatch.into());
        }
        check_acknowledged_cursor_binding(&stored, batch)?;
        let next = WatchdogSpoolCursor {
            schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
            acknowledged_sequence: advanced,
            watchdog_generation: batch.watchdog_generation,
            watchdog_epoch: batch.watchdog_epoch,
            installation_id: batch.installation_id.clone(),
            sink_id: batch.predecessor_cursor.sink_id.clone(),
        };
        let next_bytes = encode_export_cursor(&next)?;
        {
            let mut cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            cursor_table
                .insert(SPOOL_EXPORT_CURSOR_KEY, next_bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(cursor_table);
        }
        write
            .commit()
            .map(|()| advanced)
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    /// Compacts durably acknowledged records below the stored export cursor.
    ///
    /// This is the Wave C compaction entry point; no production path calls it
    /// yet. Only retained entries at or below the acknowledged sequence are
    /// candidates, and a `Gap` or `Recovery` boundary entry at or above the
    /// cursor is never removed: it is retained until a later acknowledgement
    /// advances past it. Before removing, the retained `Gap` and `Recovery`
    /// payloads are scanned and removal stops below the first unresolved
    /// marker above the cursor, so compaction can never cross an unresolved
    /// gap. The header high-water marker and `next_sequence` are never
    /// touched; only the entry rows plus the header `first_sequence`,
    /// `record_count`, and `byte` counters move, and the header is
    /// revalidated before commit.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the caller sequence differs from the
    /// stored cursor, when the stored cursor is unusable for a non-empty
    /// plan, or when the header, high-water, or counters fail validation.
    pub fn compact_below_cursor(&self, stored_cursor_acknowledged: u64) -> Result<u64, SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let mut table = write
            .open_table(SPOOL_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let high_water_table = write.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!(
                "high-water metadata is unavailable; sequence continuity cannot be proven: {error}"
            ))
        })?;
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let mut header = decode_header(&header_bytes)?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water_bytes = high_water_table
            .get(SPOOL_HIGH_WATER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| {
                SpoolError::Corrupt(
                    "high-water metadata is missing; sequence continuity cannot be proven"
                        .to_owned(),
                )
            })?;
        let live_high_water = decode_high_water(&high_water_bytes)?;
        validate_high_water(&header, &entries, live_high_water)?;
        let cursor_table = write
            .open_table(SPOOL_EXPORT_CURSOR_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let stored = match cursor_table
            .get(SPOOL_EXPORT_CURSOR_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
        {
            // A missing row means nothing was ever acknowledged; a present
            // but corrupt row fails closed and heals at the next open.
            None => unbound_export_cursor(),
            Some(value) => decode_export_cursor(value.value())?,
        };
        drop(cursor_table);
        drop(high_water_table);
        if stored_cursor_acknowledged != stored.acknowledged_sequence {
            return Err(SpoolError::Corrupt(
                "watchdog spool compaction cursor does not match the stored export cursor; refusing to compact"
                    .to_owned(),
            ));
        }
        let removable = compaction_plan(&entries, stored.acknowledged_sequence);
        if removable.is_empty() {
            return Ok(0);
        }
        if is_unbound_export_cursor(&stored) {
            return Err(SpoolError::Corrupt(
                "watchdog spool export cursor is unbound; refusing to compact".to_owned(),
            ));
        }
        validate_cursor(&stored, live_high_water)?;
        let mut removed_bytes: u64 = 0;
        let mut removed: u64 = 0;
        for sequence in &removable {
            let old = table
                .remove(*sequence)
                .map_err(|error| SpoolError::Database(error.to_string()))?
                .ok_or_else(|| SpoolError::Corrupt("retention record is missing".to_owned()))?;
            removed_bytes = removed_bytes.saturating_add(old.value().len() as u64);
            removed = removed.saturating_add(1);
        }
        header.record_count = header
            .record_count
            .checked_sub(removed)
            .ok_or_else(|| SpoolError::Corrupt("spool record counter underflow".to_owned()))?;
        header.bytes = header
            .bytes
            .checked_sub(removed_bytes)
            .ok_or_else(|| SpoolError::Corrupt("spool byte counter underflow".to_owned()))?;
        let remaining: Vec<WatchdogSpoolEntry> = entries
            .into_iter()
            .filter(|entry| !removable.contains(&entry.sequence))
            .collect();
        header.first_sequence = remaining
            .first()
            .map_or(header.next_sequence, |entry| entry.sequence);
        let header_bytes = encode_header(&header)?;
        table
            .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        validate_header(&header, &remaining)?;
        drop(table);
        write
            .commit()
            .map(|()| removed)
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    /// Reads one validated export snapshot inside a single read transaction.
    fn read_export_snapshot(
        &self,
    ) -> Result<(Vec<WatchdogSpoolEntry>, u64, WatchdogSpoolCursor), SpoolError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let table = read.open_table(SPOOL_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("spool export cannot open the spool table: {error}"))
        })?;
        let header_bytes = table
            .get(SPOOL_HEADER_KEY)
            .map_err(|error| SpoolError::Database(error.to_string()))?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| SpoolError::Corrupt("spool header is missing".to_owned()))?;
        let header = decode_header(&header_bytes)?;
        let entries = collect_entries(&table)?;
        validate_header(&header, &entries)?;
        let high_water_table = read.open_table(SPOOL_HIGH_WATER_TABLE).map_err(|error| {
            SpoolError::Corrupt(format!("high-water metadata is unavailable: {error}"))
        })?;
        let live_high_water = read_high_water(&high_water_table)?
            .ok_or_else(|| SpoolError::Corrupt("high-water metadata is missing".to_owned()))?;
        validate_high_water(&header, &entries, live_high_water)?;
        let stored = match read.open_table(SPOOL_EXPORT_CURSOR_TABLE) {
            Ok(cursor_table) => decode_export_cursor_value(&cursor_table)?,
            Err(redb::TableError::TableDoesNotExist(_)) => unbound_export_cursor(),
            Err(error) => return Err(SpoolError::Database(error.to_string())),
        };
        Ok((entries, live_high_water, stored))
    }

    /// Backfills or heals the single-key export cursor on a valid spool.
    ///
    /// A missing row (a spool that predates the cursor table) and an
    /// undecodable row both reset to the unbound acknowledged-zero cursor.
    /// The reset direction is replay-safe: exports restart from the
    /// beginning and never skip a record, while a retention hole left by
    /// earlier pressure eviction still fails closed at export time rather
    /// than at open time.
    fn ensure_export_cursor(&self) -> Result<(), SpoolError> {
        let write = self
            .database
            .begin_write()
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let needs_init = {
            let cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            match cursor_table
                .get(SPOOL_EXPORT_CURSOR_KEY)
                .map_err(|error| SpoolError::Database(error.to_string()))?
            {
                None => true,
                Some(value) => decode_export_cursor(value.value()).is_err(),
            }
        };
        if needs_init {
            let bytes = encode_export_cursor(&unbound_export_cursor())?;
            let mut cursor_table = write
                .open_table(SPOOL_EXPORT_CURSOR_TABLE)
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            cursor_table
                .insert(SPOOL_EXPORT_CURSOR_KEY, bytes.as_slice())
                .map_err(|error| SpoolError::Database(error.to_string()))?;
            drop(cursor_table);
        }
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }
}

pub(crate) fn watchdog_spool_path(watchdog_state_root: &Path) -> PathBuf {
    watchdog_state_root.join(WATCHDOG_SPOOL_FILE_NAME)
}

/// Storage encoding of the Watchdog-owned export cursor.
///
/// This private record exists only because the owner-neutral core contract
/// is zero-dependency and carries no `serde` implementation. It mirrors the
/// [`WatchdogSpoolCursor`] fields one to one and converts through the two
/// explicit functions below; it never shadows the core type in any API.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WatchdogSpoolExportCursorRecord {
    schema_version: u16,
    acknowledged_sequence: u64,
    watchdog_generation: u64,
    watchdog_epoch: u64,
    installation_id: String,
    sink_id: String,
}

/// Fresh-spool cursor: nothing acknowledged and no sink bound yet.
fn unbound_export_cursor() -> WatchdogSpoolCursor {
    WatchdogSpoolCursor {
        schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
        acknowledged_sequence: 0,
        watchdog_generation: 0,
        watchdog_epoch: 0,
        installation_id: String::new(),
        sink_id: String::new(),
    }
}

/// True while the stored cursor binds no sink identity yet.
fn is_unbound_export_cursor(cursor: &WatchdogSpoolCursor) -> bool {
    cursor.watchdog_generation == 0
        || cursor.installation_id.is_empty()
        || cursor.sink_id.is_empty()
}

/// Maps a reconciliation failure into the spool error with its exact reason.
///
/// The existing [`SpoolError`] enum gains no variant here; every contract
/// failure keeps its full core display text inside the fail-closed
/// corruption shell, which triggers no automatic recovery by itself. The
/// `?` operator applies this conversion at every validation site below.
impl From<WatchdogSpoolReconciliationError> for SpoolError {
    fn from(error: WatchdogSpoolReconciliationError) -> Self {
        Self::Corrupt(format!("watchdog spool reconciliation: {error}"))
    }
}

fn encode_export_cursor(cursor: &WatchdogSpoolCursor) -> Result<Vec<u8>, SpoolError> {
    let record = WatchdogSpoolExportCursorRecord {
        schema_version: cursor.schema_version,
        acknowledged_sequence: cursor.acknowledged_sequence,
        watchdog_generation: cursor.watchdog_generation,
        watchdog_epoch: cursor.watchdog_epoch,
        installation_id: cursor.installation_id.clone(),
        sink_id: cursor.sink_id.clone(),
    };
    serde_json::to_vec(&record).map_err(|error| SpoolError::Serialization(error.to_string()))
}

fn decode_export_cursor(bytes: &[u8]) -> Result<WatchdogSpoolCursor, SpoolError> {
    let record: WatchdogSpoolExportCursorRecord =
        serde_json::from_slice(bytes).map_err(|error| {
            SpoolError::Corrupt(format!("export cursor record is invalid: {error}"))
        })?;
    if record.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION {
        return Err(SpoolError::Corrupt(
            "export cursor record schema is unsupported".to_owned(),
        ));
    }
    if record.installation_id.len() > SPOOL_EXPORT_CURSOR_IDENTITY_MAX
        || record.sink_id.len() > SPOOL_EXPORT_CURSOR_IDENTITY_MAX
    {
        return Err(SpoolError::Corrupt(
            "export cursor record identity exceeds the bounded frame".to_owned(),
        ));
    }
    Ok(WatchdogSpoolCursor {
        schema_version: record.schema_version,
        acknowledged_sequence: record.acknowledged_sequence,
        watchdog_generation: record.watchdog_generation,
        watchdog_epoch: record.watchdog_epoch,
        installation_id: record.installation_id,
        sink_id: record.sink_id,
    })
}

/// Strictly decodes the single-key cursor row of an open read table.
///
/// A missing row reports the unbound acknowledged-zero cursor for spools
/// that predate the cursor table; a present row must decode strictly, so
/// direct readers fail closed while the open and acknowledgement paths heal
/// through their own documented reset.
fn decode_export_cursor_value<T>(table: &T) -> Result<WatchdogSpoolCursor, SpoolError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    table
        .get(SPOOL_EXPORT_CURSOR_KEY)
        .map_err(|error| SpoolError::Database(error.to_string()))?
        .map_or_else(
            || Ok(unbound_export_cursor()),
            |value| decode_export_cursor(value.value()),
        )
}

/// Reads the stored cursor and clamps it below a new recovery marker.
///
/// Recovery preserves the cursor identities verbatim and never advances past
/// them here; only the acknowledged sequence is clamped, so the cursor can
/// never jump over the recovery record. An unreadable cursor resets to the
/// unbound acknowledged-zero state, which only replays exports from the
/// start and never skips a record.
///
/// # Errors
///
/// Returns [`SpoolError`] when the cursor row cannot be read or the clamped
/// cursor cannot be encoded.
fn preserved_export_cursor_bytes(
    write: &WriteTransaction,
    recovery_sequence: u64,
) -> Result<Vec<u8>, SpoolError> {
    let cursor_table = write
        .open_table(SPOOL_EXPORT_CURSOR_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    let stored = cursor_table
        .get(SPOOL_EXPORT_CURSOR_KEY)
        .map_err(|error| SpoolError::Database(error.to_string()))?
        .map_or_else(unbound_export_cursor, |value| {
            decode_export_cursor(value.value()).unwrap_or_else(|_| unbound_export_cursor())
        });
    drop(cursor_table);
    let preserved = WatchdogSpoolCursor {
        acknowledged_sequence: stored
            .acknowledged_sequence
            .min(recovery_sequence.saturating_sub(1)),
        ..stored
    };
    encode_export_cursor(&preserved)
}

/// Persists one cursor encoding inside the caller write transaction.
///
/// # Errors
///
/// Returns [`SpoolError`] when the cursor table cannot be written.
fn store_export_cursor_bytes(write: &WriteTransaction, bytes: &[u8]) -> Result<(), SpoolError> {
    let mut cursor_table = write
        .open_table(SPOOL_EXPORT_CURSOR_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    cursor_table
        .insert(SPOOL_EXPORT_CURSOR_KEY, bytes)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    drop(cursor_table);
    Ok(())
}

/// Maps one spool codec payload to its owner-neutral export class.
fn export_payload_kind(payload: &WatchdogSpoolPayload) -> WatchdogSpoolPayloadKind {
    match payload {
        WatchdogSpoolPayload::Heartbeat { .. } => WatchdogSpoolPayloadKind::Heartbeat,
        WatchdogSpoolPayload::Gap { .. } => WatchdogSpoolPayloadKind::Gap,
        WatchdogSpoolPayload::Recovery { .. } => WatchdogSpoolPayloadKind::Recovery,
    }
}

/// Checks the export predecessor against the stored Watchdog-owned cursor.
///
/// An unbound stored cursor accepts any shape-valid predecessor and binds it
/// in memory; a bound cursor requires the exact acknowledged sequence plus
/// identical owner identities, including the cursor revision.
fn check_export_predecessor(
    stored: &WatchdogSpoolCursor,
    predecessor: &WatchdogSpoolCursor,
) -> Result<(), WatchdogSpoolReconciliationError> {
    if predecessor.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION
        || stored.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION
    {
        return Err(WatchdogSpoolReconciliationError::PredecessorMismatch);
    }
    if predecessor.acknowledged_sequence != stored.acknowledged_sequence {
        return Err(WatchdogSpoolReconciliationError::PredecessorMismatch);
    }
    if is_unbound_export_cursor(stored) {
        return Ok(());
    }
    if predecessor.installation_id != stored.installation_id {
        return Err(WatchdogSpoolReconciliationError::InstallationMismatch);
    }
    if predecessor.watchdog_generation != stored.watchdog_generation {
        return Err(WatchdogSpoolReconciliationError::GenerationMismatch);
    }
    if predecessor.watchdog_epoch != stored.watchdog_epoch {
        return Err(WatchdogSpoolReconciliationError::EpochMismatch);
    }
    if predecessor.sink_id != stored.sink_id {
        return Err(WatchdogSpoolReconciliationError::SinkMismatch);
    }
    Ok(())
}

/// Checks the acknowledged batch predecessor against the stored cursor.
///
/// An unbound stored cursor is bound by the first acknowledgement; a bound
/// cursor requires the exact predecessor identities the export carried.
fn check_acknowledged_cursor_binding(
    stored: &WatchdogSpoolCursor,
    batch: &WatchdogSpoolExportBatch,
) -> Result<(), WatchdogSpoolReconciliationError> {
    if is_unbound_export_cursor(stored) {
        return Ok(());
    }
    check_export_predecessor(stored, &batch.predecessor_cursor)
}

/// Selects the consecutive export window past the cursor under both caps.
///
/// The window starts exactly at `acknowledged + 1` and extends through the
/// smaller of the caller high-water and the item cap, stopping early at the
/// byte cap. At least one record is always selected so a non-empty spool
/// makes progress. Any retention hole inside the window fails closed instead
/// of skipping a sequence.
fn select_export_window(
    entries: &[WatchdogSpoolEntry],
    acknowledged: u64,
    high_water: u64,
    limits: &WatchdogSpoolExportLimits,
) -> Result<Vec<(WatchdogSpoolEntry, Vec<u8>)>, SpoolError> {
    let first_needed = acknowledged
        .checked_add(1)
        .ok_or(WatchdogSpoolReconciliationError::PredecessorMismatch)?;
    let item_cap_end = acknowledged
        .saturating_add(limits.max_items as u64)
        .min(high_water);
    let mut selected = Vec::new();
    let mut bytes_total: u64 = 0;
    let mut expected = first_needed;
    for entry in entries
        .iter()
        .filter(|entry| entry.sequence >= first_needed && entry.sequence <= item_cap_end)
    {
        if entry.sequence != expected {
            return Err(SpoolError::Corrupt(
                "watchdog spool retention no longer covers the export cursor; refusing to skip sequences"
                    .to_owned(),
            ));
        }
        let raw = encode_entry(entry)?;
        if !selected.is_empty()
            && (selected.len() >= limits.max_items
                || bytes_total.saturating_add(raw.len() as u64) > limits.max_bytes)
        {
            break;
        }
        bytes_total = bytes_total.saturating_add(raw.len() as u64);
        // `expected` only saturates at `u64::MAX`, which no later retained
        // sequence can follow; entries are strictly increasing by header
        // validation, so the saturated value is never revisited.
        expected = expected.saturating_add(1);
        selected.push((entry.clone(), raw));
    }
    if selected.is_empty() {
        return Err(SpoolError::Corrupt(
            "watchdog spool retention no longer covers the export cursor; refusing to skip sequences"
                .to_owned(),
        ));
    }
    Ok(selected)
}

/// Derives the opaque per-entry digests from the canonical entry encoding.
///
/// `payload_digest` covers the canonical entry bytes while `record_digest`
/// additionally binds the sequence identity, so a restated payload under the
/// same sequence is detectable as a digest mismatch.
fn export_record_digests(entry: &WatchdogSpoolEntry, raw: &[u8]) -> (String, String) {
    let payload_digest = sha256_hex(raw);
    let prefix = format!(
        "{}\0{}\0{}\0",
        entry.sequence, entry.schema_version, entry.observed_at_ms
    );
    let mut material = prefix.into_bytes();
    material.extend_from_slice(raw);
    (payload_digest, sha256_hex(&material))
}

/// Derives the deterministic batch identity or digest over timestamp-free
/// material.
///
/// The `NUL`-separated owner identities, range endpoints, embedded
/// high-water, and concatenated record digests fully determine the value;
/// `created_at_ms` and `expires_at_ms` are carried outside the digest so an
/// exact retry stays digest-equivalent. The domain prefix keeps the batch id
/// and the batch digest distinct values over the same fields.
fn export_batch_identity(
    predecessor: &WatchdogSpoolCursor,
    first_sequence: u64,
    last_sequence: u64,
    high_water: u64,
    record_digests: &[String],
    domain: &str,
) -> String {
    let mut material = format!(
        "{domain}\0{}\0{}\0{}\0{}\0{first_sequence}\0{last_sequence}\0{high_water}\0",
        predecessor.installation_id,
        predecessor.watchdog_generation,
        predecessor.watchdog_epoch,
        predecessor.acknowledged_sequence
    );
    for digest in record_digests {
        material.push_str(digest);
        material.push('\0');
    }
    sha256_hex(material.as_bytes())
}

/// Builds a non-empty batch over one selected window plus its raw bytes.
fn build_export_batch(
    predecessor: &WatchdogSpoolCursor,
    high_water: u64,
    selected: &[(WatchdogSpoolEntry, Vec<u8>)],
) -> Result<(WatchdogSpoolExportBatch, Vec<Vec<u8>>), SpoolError> {
    let mut export_entries = Vec::with_capacity(selected.len());
    let mut record_digests = Vec::with_capacity(selected.len());
    let mut raws = Vec::with_capacity(selected.len());
    let mut byte_size: u64 = 0;
    for (entry, raw) in selected {
        if entry.schema_version != SPOOL_EXPORT_CURSOR_SCHEMA_VERSION {
            return Err(SpoolError::Corrupt(
                "watchdog spool record schema drifted from the export contract; refusing to export"
                    .to_owned(),
            ));
        }
        let (payload_digest, record_digest) = export_record_digests(entry, raw);
        record_digests.push(record_digest.clone());
        export_entries.push(WatchdogSpoolExportEntry {
            sequence: entry.sequence,
            schema_version: entry.schema_version,
            observed_at_ms: entry.observed_at_ms,
            payload_kind: export_payload_kind(&entry.payload),
            payload_digest,
            record_digest,
        });
        byte_size = byte_size.saturating_add(raw.len() as u64);
        raws.push(raw.clone());
    }
    let first_sequence = export_entries
        .first()
        .map(|entry| entry.sequence)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export selected no records".to_owned())
        })?;
    let last_sequence = export_entries
        .last()
        .map(|entry| entry.sequence)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export selected no records".to_owned())
        })?;
    let created_at_ms = current_unix_ms()?;
    let expires_at_ms = created_at_ms
        .checked_add(EXPORT_BATCH_TTL_MS)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export acknowledgement window overflows".to_owned())
        })?;
    Ok((
        WatchdogSpoolExportBatch {
            schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
            batch_id: export_batch_identity(
                predecessor,
                first_sequence,
                last_sequence,
                high_water,
                &record_digests,
                "watchdog-spool-batch-id-v1",
            ),
            installation_id: predecessor.installation_id.clone(),
            watchdog_generation: predecessor.watchdog_generation,
            watchdog_epoch: predecessor.watchdog_epoch,
            predecessor_cursor: predecessor.clone(),
            first_sequence,
            last_sequence,
            high_water_sequence: high_water,
            item_count: export_entries.len(),
            byte_size,
            batch_digest: export_batch_identity(
                predecessor,
                first_sequence,
                last_sequence,
                high_water,
                &record_digests,
                "watchdog-spool-batch-digest-v1",
            ),
            is_empty_batch: false,
            created_at_ms,
            expires_at_ms,
            entries: export_entries,
        },
        raws,
    ))
}

/// Builds the explicit empty batch for `acknowledged == high-water`.
///
/// The empty shape carries no entries, zero counts, and
/// `first == last + 1 == high-water + 1`; its identity still binds the owner
/// identities and endpoints so a mismatched acknowledgement cannot reuse it.
fn build_empty_export_batch(
    predecessor: &WatchdogSpoolCursor,
    high_water: u64,
) -> Result<WatchdogSpoolExportBatch, SpoolError> {
    let first_sequence = high_water
        .checked_add(1)
        .ok_or(WatchdogSpoolReconciliationError::PredecessorMismatch)?;
    let created_at_ms = current_unix_ms()?;
    let expires_at_ms = created_at_ms
        .checked_add(EXPORT_BATCH_TTL_MS)
        .ok_or_else(|| {
            SpoolError::Corrupt("watchdog spool export acknowledgement window overflows".to_owned())
        })?;
    Ok(WatchdogSpoolExportBatch {
        schema_version: SPOOL_EXPORT_CURSOR_SCHEMA_VERSION,
        batch_id: export_batch_identity(
            predecessor,
            first_sequence,
            high_water,
            high_water,
            &[],
            "watchdog-spool-batch-id-v1",
        ),
        installation_id: predecessor.installation_id.clone(),
        watchdog_generation: predecessor.watchdog_generation,
        watchdog_epoch: predecessor.watchdog_epoch,
        predecessor_cursor: predecessor.clone(),
        first_sequence,
        last_sequence: high_water,
        high_water_sequence: high_water,
        entries: Vec::new(),
        item_count: 0,
        byte_size: 0,
        batch_digest: export_batch_identity(
            predecessor,
            first_sequence,
            high_water,
            high_water,
            &[],
            "watchdog-spool-batch-digest-v1",
        ),
        is_empty_batch: true,
        created_at_ms,
        expires_at_ms,
    })
}

/// Plans the compaction prefix below the acknowledged cursor.
///
/// Candidates are retained entries at or below the acknowledged sequence,
/// except a `Gap` or `Recovery` boundary entry at or above the cursor, which
/// is retained until a later acknowledgement advances past it. Removal also
/// stops below the first unresolved `Gap` or `Recovery` marker above the
/// cursor; that bound is implied by the candidate ceiling and enforced here
/// explicitly so compaction can never cross an unresolved gap.
fn compaction_plan(entries: &[WatchdogSpoolEntry], acknowledged: u64) -> Vec<u64> {
    let first_unresolved = entries
        .iter()
        .filter(|entry| {
            !matches!(
                export_payload_kind(&entry.payload),
                WatchdogSpoolPayloadKind::Heartbeat
            ) && entry.sequence > acknowledged
        })
        .map(|entry| entry.sequence)
        .min();
    entries
        .iter()
        .filter(|entry| entry.sequence <= acknowledged)
        .filter(|entry| {
            matches!(
                export_payload_kind(&entry.payload),
                WatchdogSpoolPayloadKind::Heartbeat
            ) || entry.sequence < acknowledged
        })
        .filter(|entry| first_unresolved.is_none_or(|marker| entry.sequence < marker))
        .map(|entry| entry.sequence)
        .collect()
}
