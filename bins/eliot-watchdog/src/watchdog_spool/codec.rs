//! Canonical watchdog spool wire codecs and validation.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-02.
//! Implementation: I8.1, I8.3, I8.10, I8.13, I2.2, I2.23.
//! This child owns canonical watchdog spool wire DTOs, encode/decode, and bounded structural validation only; REDB persistence/recovery/retention and watchdog lifecycle/canonical authority remain in the parent/control plane.

use redb::ReadableTable;

use crate::{GapRecoveryReason, SpoolError};

use super::{
    SPOOL_HEADER_KEY, SPOOL_HIGH_WATER_KEY, SPOOL_MAX_BYTES, SPOOL_MAX_RECORD_BYTES,
    SPOOL_MAX_RECORDS, SPOOL_SCHEMA_VERSION,
};

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

pub(super) fn encode_header(header: &WatchdogSpoolHeader) -> Result<Vec<u8>, SpoolError> {
    serde_json::to_vec(header).map_err(|error| SpoolError::Serialization(error.to_string()))
}

pub(super) fn decode_header(bytes: &[u8]) -> Result<WatchdogSpoolHeader, SpoolError> {
    serde_json::from_slice(bytes)
        .map_err(|error| SpoolError::Corrupt(format!("invalid spool header: {error}")))
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

fn decode_entry(sequence: u64, bytes: &[u8]) -> Result<WatchdogSpoolEntry, SpoolError> {
    if bytes.len() > SPOOL_MAX_RECORD_BYTES {
        return Err(SpoolError::Corrupt(format!(
            "record {sequence} exceeds the bounded frame size"
        )));
    }
    let entry: WatchdogSpoolEntry = serde_json::from_slice(bytes)
        .map_err(|error| SpoolError::Corrupt(format!("record {sequence} is invalid: {error}")))?;
    if entry.schema_version != SPOOL_SCHEMA_VERSION || entry.sequence != sequence {
        return Err(SpoolError::Corrupt(format!(
            "record {sequence} has an invalid schema or sequence"
        )));
    }
    Ok(entry)
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
        entries.push(decode_entry(key.value(), value.value())?);
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
