//! Physical protected spool cell for the independent Runtime 0.17 watchdog.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-02.
//! Implementation: I8.1, I8.3, I8.10, I8.13, I2.2, I2.23.
//! Physical protected spool only — no semantic/canonical/Kernel/Governor
//! authority and no new default or retry; bytes/layout/recovery/high-water/fail-closed
//! behavior is preserved verbatim from the reviewed production cell.

use std::path::{Path, PathBuf};

use eliot_contracts::sha256_hex;
use eliot_platform_windows::ProtectedRuntimePathLease;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{GapRecoveryReason, SERVICE_NAME, SpoolError, WatchdogRuntimeBinding, current_unix_ms};

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

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WatchdogSpoolHeader {
    pub(crate) schema_version: u16,
    pub(crate) next_sequence: u64,
    pub(crate) first_sequence: u64,
    pub(crate) record_count: u64,
    pub(crate) bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WatchdogSpoolHighWater {
    pub(crate) schema_version: u16,
    pub(crate) high_water_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "record_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WatchdogSpoolPayload {
    Heartbeat {
        service: String,
        lease_id: String,
        scope_ref: String,
        kernel_epoch: u64,
        watchdog_epoch: u64,
        payload_digest: String,
        envelope_digest: String,
        signer_id: String,
        key_id: String,
        signature_algorithm: String,
        signature: String,
        public_key_fingerprint: String,
        lease_revision: u64,
    },
    Gap {
        service: String,
        reason: GapRecoveryReason,
        coverage_claimed: bool,
    },
    Recovery {
        service: String,
        reason: String,
        corrupt_sequence: Option<u64>,
        corrupt_digest: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogSpoolEntry {
    pub schema_version: u16,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub payload: WatchdogSpoolPayload,
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
        let header: WatchdogSpoolHeader = serde_json::from_slice(header.value())
            .map_err(|error| SpoolError::Corrupt(format!("invalid spool header: {error}")))?;
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
            .and_then(|value| serde_json::from_slice::<WatchdogSpoolHeader>(value.value()).ok());
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
            return Ok(());
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
        let bytes = serde_json::to_vec(header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        let high_water = header.next_sequence.saturating_sub(1);
        let high_water_bytes = encode_high_water(high_water)?;
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
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
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
        }
        drop(high_water_table);
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }

    pub(crate) fn append(
        &self,
        observed_at_ms: u64,
        payload: WatchdogSpoolPayload,
    ) -> Result<(), SpoolError> {
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
        let mut header: WatchdogSpoolHeader = serde_json::from_slice(&header_bytes)
            .map_err(|error| SpoolError::Corrupt(format!("invalid spool header: {error}")))?;
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
            payload,
        };
        let bytes = encode_entry(&entry)?;
        while header.record_count >= SPOOL_MAX_RECORDS
            || header.bytes.saturating_add(bytes.len() as u64) > SPOOL_MAX_BYTES
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
        }
        table
            .insert(sequence, bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        header.schema_version = SPOOL_SCHEMA_VERSION;
        header.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| SpoolError::Corrupt("spool sequence overflow".to_owned()))?;
        if header.record_count == 0 {
            header.first_sequence = sequence;
        }
        header.record_count += 1;
        header.bytes = header
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| SpoolError::Corrupt("spool byte counter overflow".to_owned()))?;
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?;
        table
            .insert(SPOOL_HEADER_KEY, header_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        let high_water_bytes = encode_high_water(sequence)?;
        high_water_table
            .insert(SPOOL_HIGH_WATER_KEY, high_water_bytes.as_slice())
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        drop(table);
        drop(high_water_table);
        write
            .commit()
            .map_err(|error| SpoolError::Database(error.to_string()))
    }
}

pub(crate) fn watchdog_spool_path(watchdog_state_root: &Path) -> PathBuf {
    watchdog_state_root.join(WATCHDOG_SPOOL_FILE_NAME)
}

pub(crate) fn encode_entry(entry: &WatchdogSpoolEntry) -> Result<Vec<u8>, SpoolError> {
    let bytes =
        serde_json::to_vec(entry).map_err(|error| SpoolError::Serialization(error.to_string()))?;
    if bytes.len() > SPOOL_MAX_RECORD_BYTES {
        return Err(SpoolError::Serialization(
            "watchdog spool record exceeds the bounded frame size".to_owned(),
        ));
    }
    Ok(bytes)
}

pub(crate) fn encode_high_water(sequence: u64) -> Result<Vec<u8>, SpoolError> {
    serde_json::to_vec(&WatchdogSpoolHighWater {
        schema_version: SPOOL_SCHEMA_VERSION,
        high_water_sequence: sequence,
    })
    .map_err(|error| SpoolError::Serialization(error.to_string()))
}

pub(crate) fn decode_high_water(bytes: &[u8]) -> Result<u64, SpoolError> {
    let high_water: WatchdogSpoolHighWater = serde_json::from_slice(bytes)
        .map_err(|error| SpoolError::Corrupt(format!("invalid high-water metadata: {error}")))?;
    if high_water.schema_version != SPOOL_SCHEMA_VERSION {
        return Err(SpoolError::Corrupt(
            "high-water metadata schema is unsupported".to_owned(),
        ));
    }
    Ok(high_water.high_water_sequence)
}

pub(crate) fn read_high_water<T>(table: &T) -> Result<Option<u64>, SpoolError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    table
        .get(SPOOL_HIGH_WATER_KEY)
        .map_err(|error| SpoolError::Database(error.to_string()))?
        .map(|value| decode_high_water(value.value()))
        .transpose()
}

pub(crate) fn collect_entries<T>(table: &T) -> Result<Vec<WatchdogSpoolEntry>, SpoolError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    let mut entries = Vec::new();
    for item in table
        .iter()
        .map_err(|error| SpoolError::Database(error.to_string()))?
    {
        let (key, value) = item.map_err(|error| SpoolError::Database(error.to_string()))?;
        if key.value() == SPOOL_HEADER_KEY {
            continue;
        }
        if value.value().len() > SPOOL_MAX_RECORD_BYTES {
            return Err(SpoolError::Corrupt(format!(
                "record {} exceeds the bounded frame size",
                key.value()
            )));
        }
        let entry: WatchdogSpoolEntry = serde_json::from_slice(value.value()).map_err(|error| {
            SpoolError::Corrupt(format!("record {} is invalid: {error}", key.value()))
        })?;
        if entry.schema_version != SPOOL_SCHEMA_VERSION || entry.sequence != key.value() {
            return Err(SpoolError::Corrupt(format!(
                "record {} has an invalid schema or sequence",
                key.value()
            )));
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.sequence);
    Ok(entries)
}

pub(crate) fn validate_header(
    header: &WatchdogSpoolHeader,
    entries: &[WatchdogSpoolEntry],
) -> Result<(), SpoolError> {
    if header.schema_version != SPOOL_SCHEMA_VERSION
        || header.next_sequence == 0
        || header.first_sequence == 0
        || header.record_count != entries.len() as u64
        || header.record_count > SPOOL_MAX_RECORDS
        || header.bytes > SPOOL_MAX_BYTES
        || entries
            .iter()
            .map(|entry| serde_json::to_vec(entry).map(|bytes| bytes.len() as u64))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| SpoolError::Serialization(error.to_string()))?
            .into_iter()
            .sum::<u64>()
            != header.bytes
    {
        return Err(SpoolError::Corrupt(
            "spool header counters or schema are inconsistent".to_owned(),
        ));
    }
    let expected_first = entries
        .first()
        .map_or(header.next_sequence, |entry| entry.sequence);
    if header.first_sequence != expected_first
        || entries
            .windows(2)
            .any(|window| window[1].sequence <= window[0].sequence)
        || entries
            .last()
            .is_some_and(|entry| entry.sequence >= header.next_sequence)
    {
        return Err(SpoolError::Corrupt(
            "spool sequence ordering is inconsistent".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_high_water(
    header: &WatchdogSpoolHeader,
    entries: &[WatchdogSpoolEntry],
    high_water: u64,
) -> Result<(), SpoolError> {
    let expected = header
        .next_sequence
        .checked_sub(1)
        .ok_or_else(|| SpoolError::Corrupt("spool header next sequence is invalid".to_owned()))?;
    let last = entries.last().map_or(0, |entry| entry.sequence);
    if high_water != expected || high_water < last {
        return Err(SpoolError::Corrupt(
            "high-water metadata does not bind the spool sequence".to_owned(),
        ));
    }
    Ok(())
}
