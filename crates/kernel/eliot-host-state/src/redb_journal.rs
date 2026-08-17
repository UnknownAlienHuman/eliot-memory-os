//! Crash-safe redb adapter for the Host-owned journal.

use std::path::{Path, PathBuf};

use eliot_platform::{PlatformHandle, UnknownReason};
use eliot_platform_windows::{ProtectedPathLease, require_protected_program_data_path};
use redb::{Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BackendError, BackendReconcileState, CommittedAppend, DurableImage, JournalBackend,
    PreparedAppend, StoredEpoch,
};

const HOST_JOURNAL_RELATIVE_PATH: &str = "Eliot/host/host-state-journal.redb";
const SCHEMA: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_host_journal_schema_v1");
const EPOCHS: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_host_journal_epochs_v1");
const PREPARED: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_host_journal_prepared_v1");
const RECEIPTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_host_journal_receipts_v1");
const PAYLOADS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_host_journal_payloads_v1");
const SCHEMA_MARKER_KEY: &str = "schema";
const SCHEMA_MARKER: &[u8] = b"eliot-host-journal-schema-v1";

const MAX_EPOCHS: usize = 256;
const MAX_PREPARED: usize = 128;
const MAX_RECEIPTS: usize = 8_192;
const MAX_APPEND_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPrepared {
    descriptor: PreparedAppend,
    bytes: Vec<u8>,
    flushed: bool,
    synced: bool,
}

/// Production `HostStateJournal` backend backed by a separate Host-owned redb file.
///
/// The retained [`ProtectedPathLease`] is held for the lifetime of the database,
/// so redb never reopens a path whose final component could have been replaced.
pub struct RedbJournalBackend {
    database: Database,
    path: PathBuf,
    _path_lease: JournalPathLease,
}

enum JournalPathLease {
    Protected {
        _lease: ProtectedPathLease,
    },
    #[cfg(test)]
    Unprotected,
}

struct BackendSnapshot {
    epochs: Vec<(String, StoredEpoch)>,
    prepared: Vec<(String, StoredPrepared)>,
    receipts: Vec<(String, CommittedAppend)>,
}

impl RedbJournalBackend {
    /// Opens or creates the dedicated Host journal database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BackendError> {
        let path = path.as_ref();
        require_protected_program_data_path(path, HOST_JOURNAL_RELATIVE_PATH)
            .map_err(|_| BackendError::Unavailable)?;
        let path_lease = ProtectedPathLease::open_or_create(HOST_JOURNAL_RELATIVE_PATH)
            .map_err(|_| BackendError::Unavailable)?;
        if path_lease.path() != path {
            return Err(BackendError::Unavailable);
        }
        path_lease
            .verify_path_identity()
            .map_err(|_| BackendError::Unavailable)?;
        let database =
            Database::create(path_lease.path()).map_err(|_| BackendError::Unavailable)?;
        path_lease
            .verify_path_identity()
            .map_err(|_| BackendError::Unavailable)?;
        Ok(Self {
            database,
            path: path.to_path_buf(),
            _path_lease: JournalPathLease::Protected { _lease: path_lease },
        })
        .and_then(|backend| {
            backend.ensure_schema()?;
            backend.snapshot()?;
            Ok(backend)
        })
    }

    #[cfg(test)]
    pub(crate) fn open_unprotected_for_test(path: impl AsRef<Path>) -> Result<Self, BackendError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| BackendError::Unavailable)?;
        }
        let database = Database::create(path).map_err(|_| BackendError::Unavailable)?;
        let backend = Self {
            database,
            path: path.to_path_buf(),
            _path_lease: JournalPathLease::Unprotected,
        };
        backend.ensure_schema()?;
        backend.snapshot()?;
        Ok(backend)
    }

    /// Returns the exact protected path used by this backend.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_schema(&self) -> Result<(), BackendError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| BackendError::Unavailable)?;
        let present = [
            has_table(&read, SCHEMA)?,
            has_table(&read, EPOCHS)?,
            has_table(&read, PREPARED)?,
            has_table(&read, RECEIPTS)?,
            has_table(&read, PAYLOADS)?,
        ];
        if present.iter().all(|item| !item) {
            drop(read);
            let write = self
                .database
                .begin_write()
                .map_err(|_| BackendError::Unavailable)?;
            {
                let mut schema = write
                    .open_table(SCHEMA)
                    .map_err(|_| BackendError::Unavailable)?;
                let _epochs = write
                    .open_table(EPOCHS)
                    .map_err(|_| BackendError::Unavailable)?;
                let _prepared = write
                    .open_table(PREPARED)
                    .map_err(|_| BackendError::Unavailable)?;
                let _receipts = write
                    .open_table(RECEIPTS)
                    .map_err(|_| BackendError::Unavailable)?;
                let _payloads = write
                    .open_table(PAYLOADS)
                    .map_err(|_| BackendError::Unavailable)?;
                schema
                    .insert(SCHEMA_MARKER_KEY, SCHEMA_MARKER)
                    .map_err(|_| BackendError::Unavailable)?;
            }
            return commit_write(write);
        }
        if present.iter().any(|item| !item) {
            return Err(BackendError::Unavailable);
        }
        validate_schema_marker(&read)
    }

    fn snapshot(&self) -> Result<BackendSnapshot, BackendError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| BackendError::Unavailable)?;
        validate_schema_marker(&read)?;
        let epochs = read_epochs(&read)?;
        let prepared = read_prepared(&read)?;
        let receipts = read_receipts(&read)?;
        let payloads = read_payloads(&read)?;
        validate_snapshot(&epochs, &prepared, &receipts, &payloads)?;
        Ok(BackendSnapshot {
            epochs,
            prepared,
            receipts,
        })
    }
}

fn has_table(
    read: &ReadTransaction,
    definition: TableDefinition<&str, &[u8]>,
) -> Result<bool, BackendError> {
    match read.open_table(definition) {
        Ok(_table) => Ok(true),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
        Err(_) => Err(BackendError::Unavailable),
    }
}

fn validate_schema_marker(read: &ReadTransaction) -> Result<(), BackendError> {
    let table = read
        .open_table(SCHEMA)
        .map_err(|_| BackendError::Unavailable)?;
    let mut entries = 0_usize;
    for item in table.iter().map_err(|_| BackendError::Unavailable)? {
        let (key, value) = item.map_err(|_| BackendError::Unavailable)?;
        entries = entries.checked_add(1).ok_or(BackendError::Unavailable)?;
        if key.value() != SCHEMA_MARKER_KEY || value.value() != SCHEMA_MARKER {
            return Err(BackendError::Unavailable);
        }
    }
    if entries != 1 {
        return Err(BackendError::Unavailable);
    }
    Ok(())
}

fn read_epochs(read: &ReadTransaction) -> Result<Vec<(String, StoredEpoch)>, BackendError> {
    let table = read
        .open_table(EPOCHS)
        .map_err(|_| BackendError::Unavailable)?;
    let mut result: Vec<(String, StoredEpoch)> = Vec::new();
    for item in table.iter().map_err(|_| BackendError::Unavailable)? {
        let (key, value) = item.map_err(|_| BackendError::Unavailable)?;
        let key = key.value().to_owned();
        let ordinal = validate_epoch_key(&key)?;
        if ordinal != result.len() || result.len() >= MAX_EPOCHS {
            return Err(BackendError::Unavailable);
        }
        let bytes = value.value();
        if bytes.len() > MAX_METADATA_BYTES + MAX_APPEND_BYTES {
            return Err(BackendError::Unavailable);
        }
        let epoch: StoredEpoch =
            serde_json::from_slice(bytes).map_err(|_| BackendError::Unavailable)?;
        epoch
            .host
            .validate()
            .map_err(|_| BackendError::Unavailable)?;
        if epoch.bytes.is_empty() || epoch.bytes.len() > MAX_APPEND_BYTES {
            return Err(BackendError::Unavailable);
        }
        if result.iter().any(|(_, prior)| prior.host == epoch.host) {
            return Err(BackendError::Unavailable);
        }
        result.push((key, epoch));
    }
    Ok(result)
}

fn read_prepared(read: &ReadTransaction) -> Result<Vec<(String, StoredPrepared)>, BackendError> {
    let table = read
        .open_table(PREPARED)
        .map_err(|_| BackendError::Unavailable)?;
    let mut result = Vec::new();
    for item in table.iter().map_err(|_| BackendError::Unavailable)? {
        let (key, value) = item.map_err(|_| BackendError::Unavailable)?;
        let key = key.value().to_owned();
        let bytes = value.value();
        if bytes.len() > MAX_METADATA_BYTES + MAX_APPEND_BYTES {
            return Err(BackendError::Unavailable);
        }
        let prepared: StoredPrepared =
            serde_json::from_slice(bytes).map_err(|_| BackendError::Unavailable)?;
        validate_transaction_key(&key, &prepared.descriptor.transaction_id)?;
        validate_prepared(&prepared)?;
        result.push((key, prepared));
        if result.len() > MAX_PREPARED {
            return Err(BackendError::Unavailable);
        }
    }
    Ok(result)
}

fn read_receipts(read: &ReadTransaction) -> Result<Vec<(String, CommittedAppend)>, BackendError> {
    let table = read
        .open_table(RECEIPTS)
        .map_err(|_| BackendError::Unavailable)?;
    let mut result = Vec::new();
    for item in table.iter().map_err(|_| BackendError::Unavailable)? {
        let (key, value) = item.map_err(|_| BackendError::Unavailable)?;
        let key = key.value().to_owned();
        let bytes = value.value();
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(BackendError::Unavailable);
        }
        let receipt: CommittedAppend =
            serde_json::from_slice(bytes).map_err(|_| BackendError::Unavailable)?;
        validate_transaction_key(&key, &receipt.transaction_id)?;
        receipt
            .host
            .validate()
            .map_err(|_| BackendError::Unavailable)?;
        validate_operation(&receipt.operation).map_err(|_| BackendError::Unavailable)?;
        validate_digest(&receipt.record_checksum)?;
        validate_digest(&receipt.payload_digest)?;
        result.push((key, receipt));
        if result.len() > MAX_RECEIPTS {
            return Err(BackendError::Unavailable);
        }
    }
    Ok(result)
}

fn read_payloads(read: &ReadTransaction) -> Result<Vec<(String, Vec<u8>)>, BackendError> {
    let table = read
        .open_table(PAYLOADS)
        .map_err(|_| BackendError::Unavailable)?;
    let mut result = Vec::new();
    for item in table.iter().map_err(|_| BackendError::Unavailable)? {
        let (key, value) = item.map_err(|_| BackendError::Unavailable)?;
        let key = key.value().to_owned();
        if !is_valid_text(&key) {
            return Err(BackendError::Unavailable);
        }
        let bytes = value.value();
        if bytes.is_empty() || bytes.len() > MAX_APPEND_BYTES {
            return Err(BackendError::Unavailable);
        }
        result.push((key, bytes.to_vec()));
        if result.len() > MAX_RECEIPTS {
            return Err(BackendError::Unavailable);
        }
    }
    Ok(result)
}

fn validate_snapshot(
    epochs: &[(String, StoredEpoch)],
    prepared: &[(String, StoredPrepared)],
    receipts: &[(String, CommittedAppend)],
    payloads: &[(String, Vec<u8>)],
) -> Result<(), BackendError> {
    let mut total = 0_usize;
    for epoch in epochs.iter().map(|(_, item)| item) {
        total = total
            .checked_add(epoch.bytes.len())
            .ok_or(BackendError::Unavailable)?;
    }
    for prepared in prepared.iter().map(|(_, item)| item) {
        total = total
            .checked_add(prepared.bytes.len())
            .ok_or(BackendError::Unavailable)?;
    }
    for payload in payloads.iter().map(|(_, item)| item) {
        total = total
            .checked_add(payload.len())
            .ok_or(BackendError::Unavailable)?;
    }
    if total > MAX_TOTAL_BYTES {
        return Err(BackendError::Unavailable);
    }
    for (_, receipt) in receipts {
        let payload = payloads
            .iter()
            .find(|(key, _)| key.as_str() == receipt.transaction_id.as_str())
            .map(|(_, bytes)| bytes)
            .ok_or(BackendError::Unavailable)?;
        if sha256_digest(payload) != receipt.payload_digest
            || !epochs
                .iter()
                .any(|(_, epoch)| contains_bytes(&epoch.bytes, payload))
        {
            return Err(BackendError::Unavailable);
        }
        if prepared
            .iter()
            .any(|(_, item)| item.descriptor.transaction_id == receipt.transaction_id)
        {
            return Err(BackendError::Unavailable);
        }
    }
    if payloads.iter().any(|(key, _)| {
        !receipts
            .iter()
            .any(|(_, receipt)| receipt.transaction_id.as_str() == key)
    }) {
        return Err(BackendError::Unavailable);
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn commit_write(write: redb::WriteTransaction) -> Result<(), BackendError> {
    write
        .commit()
        .map_err(|_| BackendError::Unknown(UnknownReason::Indeterminate))
}

fn persist_commit(
    database: &Database,
    transaction_id: &PlatformHandle,
    epoch_key: &str,
    epoch: &StoredEpoch,
    committed: &CommittedAppend,
    bytes: &[u8],
) -> Result<(), BackendError> {
    let epoch_encoded = encode_bounded(epoch, MAX_METADATA_BYTES + MAX_APPEND_BYTES)?;
    let receipt_encoded = encode_bounded(committed, MAX_METADATA_BYTES)?;
    let write = database
        .begin_write()
        .map_err(|_| BackendError::Unavailable)?;
    {
        let mut epoch_table = write
            .open_table(EPOCHS)
            .map_err(|_| BackendError::Unavailable)?;
        let mut receipt_table = write
            .open_table(RECEIPTS)
            .map_err(|_| BackendError::Unavailable)?;
        let mut prepared_table = write
            .open_table(PREPARED)
            .map_err(|_| BackendError::Unavailable)?;
        let mut payload_table = write
            .open_table(PAYLOADS)
            .map_err(|_| BackendError::Unavailable)?;
        epoch_table
            .insert(epoch_key, epoch_encoded.as_slice())
            .map_err(|_| BackendError::Unavailable)?;
        receipt_table
            .insert(transaction_id.as_str(), receipt_encoded.as_slice())
            .map_err(|_| BackendError::Unavailable)?;
        payload_table
            .insert(transaction_id.as_str(), bytes)
            .map_err(|_| BackendError::Unavailable)?;
        prepared_table
            .remove(transaction_id.as_str())
            .map_err(|_| BackendError::Unavailable)?;
    }
    commit_write(write)
}

impl JournalBackend for RedbJournalBackend {
    fn load(&mut self) -> Result<DurableImage, BackendError> {
        let snapshot = self.snapshot()?;
        Ok(DurableImage {
            epochs: snapshot.epochs.into_iter().map(|(_, item)| item).collect(),
            receipts: snapshot
                .receipts
                .into_iter()
                .map(|(_, item)| item)
                .collect(),
        })
    }

    fn prepare(&mut self, append: &PreparedAppend) -> Result<(), BackendError> {
        validate_descriptor(append)?;
        let snapshot = self.snapshot()?;
        if let Some((_, receipt)) = snapshot
            .receipts
            .iter()
            .find(|(_, item)| item.transaction_id == append.transaction_id)
        {
            return if receipt.matches_prepared(append) {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        if let Some((_, prepared)) = snapshot
            .prepared
            .iter()
            .find(|(_, item)| item.descriptor.transaction_id == append.transaction_id)
        {
            return if prepared.descriptor == *append {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        if snapshot.prepared.len() >= MAX_PREPARED {
            return Err(BackendError::Failed(
                "prepared journal limit reached".into(),
            ));
        }
        let stored = StoredPrepared {
            descriptor: append.clone(),
            bytes: Vec::new(),
            flushed: false,
            synced: false,
        };
        let encoded = encode_bounded(&stored, MAX_METADATA_BYTES)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| BackendError::Unavailable)?;
        {
            let mut table = write
                .open_table(PREPARED)
                .map_err(|_| BackendError::Unavailable)?;
            table
                .insert(append.transaction_id.as_str(), encoded.as_slice())
                .map_err(|_| BackendError::Unavailable)?;
        }
        commit_write(write)
    }

    fn append_prepared(
        &mut self,
        transaction_id: &PlatformHandle,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        if bytes.is_empty() || bytes.len() > MAX_APPEND_BYTES {
            return Err(BackendError::Failed("append size is outside bounds".into()));
        }
        let snapshot = self.snapshot()?;
        let Some((_, existing)) = snapshot
            .prepared
            .iter()
            .find(|(_, item)| item.descriptor.transaction_id == *transaction_id)
        else {
            return if snapshot
                .receipts
                .iter()
                .any(|(_, item)| item.transaction_id == *transaction_id)
            {
                Err(BackendError::Conflict)
            } else {
                Err(BackendError::Failed("transaction was not prepared".into()))
            };
        };
        let mut prepared = existing.clone();
        if !prepared.bytes.is_empty() && prepared.bytes != bytes {
            return Err(BackendError::Conflict);
        }
        if !prepared.bytes.is_empty() {
            return Ok(());
        }
        if sha256_digest(bytes) != prepared.descriptor.payload_digest {
            return Err(BackendError::Conflict);
        }
        prepared.bytes = bytes.to_vec();
        prepared.flushed = false;
        prepared.synced = false;
        let encoded = encode_bounded(&prepared, MAX_METADATA_BYTES + MAX_APPEND_BYTES)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| BackendError::Unavailable)?;
        {
            let mut table = write
                .open_table(PREPARED)
                .map_err(|_| BackendError::Unavailable)?;
            table
                .insert(transaction_id.as_str(), encoded.as_slice())
                .map_err(|_| BackendError::Unavailable)?;
        }
        commit_write(write)
    }

    fn flush(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        self.update_prepared(transaction_id, |prepared| {
            if prepared.bytes.is_empty() {
                return Err(BackendError::Failed("cannot flush an empty append".into()));
            }
            prepared.flushed = true;
            Ok(())
        })
    }

    fn sync(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        self.update_prepared(transaction_id, |prepared| {
            if prepared.bytes.is_empty() || !prepared.flushed {
                return Err(BackendError::Failed("append was not flushed".into()));
            }
            prepared.synced = true;
            Ok(())
        })
    }

    fn commit(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        let snapshot = self.snapshot()?;
        let Some((_, prepared)) = snapshot
            .prepared
            .iter()
            .find(|(_, item)| item.descriptor.transaction_id == *transaction_id)
        else {
            return if snapshot
                .receipts
                .iter()
                .any(|(_, item)| item.transaction_id == *transaction_id)
            {
                Ok(())
            } else {
                Err(BackendError::Failed("transaction was not prepared".into()))
            };
        };
        let prepared = prepared.clone();
        if prepared.bytes.is_empty() || !prepared.flushed || !prepared.synced {
            return Err(BackendError::Failed(
                "append was not flushed and synchronized".into(),
            ));
        }
        if sha256_digest(&prepared.bytes) != prepared.descriptor.payload_digest {
            return Err(BackendError::Conflict);
        }
        let committed = CommittedAppend::from_prepared(prepared.descriptor.clone());
        if let Some((_, receipt)) = snapshot
            .receipts
            .iter()
            .find(|(_, item)| item.transaction_id == *transaction_id)
        {
            return if *receipt == committed {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        if snapshot.receipts.len() >= MAX_RECEIPTS {
            return Err(BackendError::Failed("receipt limit reached".into()));
        }
        let mut epochs = snapshot.epochs;
        let existing = epochs
            .iter_mut()
            .find(|(_, epoch)| epoch.host == prepared.descriptor.host);
        let epoch_key = if let Some((key, epoch)) = existing {
            let new_len = epoch
                .bytes
                .len()
                .checked_add(prepared.bytes.len())
                .ok_or_else(|| BackendError::Failed("epoch size overflow".into()))?;
            if new_len > MAX_APPEND_BYTES {
                return Err(BackendError::Failed("epoch size limit reached".into()));
            }
            epoch.bytes.extend_from_slice(&prepared.bytes);
            key.clone()
        } else {
            if epochs.len() >= MAX_EPOCHS {
                return Err(BackendError::Failed("epoch limit reached".into()));
            }
            let ordinal = epochs.len();
            epochs.push((
                epoch_key(ordinal),
                StoredEpoch {
                    host: prepared.descriptor.host.clone(),
                    bytes: prepared.bytes.clone(),
                },
            ));
            epochs
                .last()
                .map_or_else(|| unreachable!(), |(key, _)| key.clone())
        };
        let epoch = epochs
            .iter()
            .find(|(key, _)| *key == epoch_key)
            .map(|(_, epoch)| epoch)
            .ok_or(BackendError::Unavailable)?;
        persist_commit(
            &self.database,
            transaction_id,
            epoch_key.as_str(),
            epoch,
            &committed,
            &prepared.bytes,
        )
    }

    fn reconcile(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<BackendReconcileState, BackendError> {
        let snapshot = self.snapshot()?;
        if let Some((_, receipt)) = snapshot
            .receipts
            .into_iter()
            .find(|(_, item)| item.transaction_id == *transaction_id)
        {
            Ok(BackendReconcileState::Committed(Box::new(receipt)))
        } else if snapshot
            .prepared
            .iter()
            .any(|(_, item)| item.descriptor.transaction_id == *transaction_id)
        {
            Ok(BackendReconcileState::Prepared)
        } else {
            Ok(BackendReconcileState::Absent)
        }
    }
}

impl RedbJournalBackend {
    fn update_prepared<F>(
        &mut self,
        transaction_id: &PlatformHandle,
        update: F,
    ) -> Result<(), BackendError>
    where
        F: FnOnce(&mut StoredPrepared) -> Result<(), BackendError>,
    {
        let snapshot = self.snapshot()?;
        let Some((_, existing)) = snapshot
            .prepared
            .iter()
            .find(|(_, item)| item.descriptor.transaction_id == *transaction_id)
        else {
            return Err(BackendError::Failed("transaction was not prepared".into()));
        };
        let mut prepared = existing.clone();
        update(&mut prepared)?;
        let encoded = encode_bounded(&prepared, MAX_METADATA_BYTES + MAX_APPEND_BYTES)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| BackendError::Unavailable)?;
        {
            let mut table = write
                .open_table(PREPARED)
                .map_err(|_| BackendError::Unavailable)?;
            table
                .insert(transaction_id.as_str(), encoded.as_slice())
                .map_err(|_| BackendError::Unavailable)?;
        }
        commit_write(write)
    }
}

fn validate_descriptor(descriptor: &PreparedAppend) -> Result<(), BackendError> {
    if !is_valid_text(descriptor.transaction_id.as_str())
        || !is_valid_text(&descriptor.record_checksum)
        || !is_valid_text(&descriptor.payload_digest)
    {
        return Err(BackendError::Failed(
            "prepared descriptor is malformed".into(),
        ));
    }
    descriptor
        .host
        .validate()
        .map_err(|_| BackendError::Failed("prepared host is malformed".into()))?;
    validate_operation(&descriptor.operation)?;
    validate_digest(&descriptor.record_checksum)?;
    validate_digest(&descriptor.payload_digest)?;
    if serde_json::to_vec(descriptor)
        .map_err(|_| BackendError::Unavailable)?
        .len()
        > MAX_METADATA_BYTES
    {
        return Err(BackendError::Failed(
            "prepared descriptor is too large".into(),
        ));
    }
    Ok(())
}

fn validate_operation(operation: &crate::IdempotencyIdentity) -> Result<(), BackendError> {
    for value in [&operation.operation_id, &operation.idempotency_key] {
        if value.as_str().trim().is_empty() || value.as_str().chars().any(char::is_control) {
            return Err(BackendError::Failed(
                "prepared operation is malformed".into(),
            ));
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), BackendError> {
    if is_sha256_digest(value) {
        Ok(())
    } else {
        Err(BackendError::Unavailable)
    }
}

fn is_valid_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_prepared(prepared: &StoredPrepared) -> Result<(), BackendError> {
    validate_descriptor(&prepared.descriptor)?;
    if prepared.bytes.len() > MAX_APPEND_BYTES {
        return Err(BackendError::Unavailable);
    }
    if prepared.bytes.is_empty() {
        if prepared.flushed || prepared.synced {
            return Err(BackendError::Unavailable);
        }
    } else {
        if prepared.synced && !prepared.flushed {
            return Err(BackendError::Unavailable);
        }
        if sha256_digest(&prepared.bytes) != prepared.descriptor.payload_digest {
            return Err(BackendError::Unavailable);
        }
    }
    Ok(())
}

fn encode_bounded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, BackendError> {
    let encoded = serde_json::to_vec(value).map_err(|_| BackendError::Unavailable)?;
    if encoded.len() > limit {
        return Err(BackendError::Failed(
            "journal metadata exceeds bounds".into(),
        ));
    }
    Ok(encoded)
}

fn validate_epoch_key(key: &str) -> Result<usize, BackendError> {
    let Some(ordinal) = key.strip_prefix("epoch-") else {
        return Err(BackendError::Unavailable);
    };
    if ordinal.len() != 20 || !ordinal.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BackendError::Unavailable);
    }
    ordinal
        .parse::<usize>()
        .map_err(|_| BackendError::Unavailable)
}

fn validate_transaction_key(
    key: &str,
    transaction_id: &PlatformHandle,
) -> Result<(), BackendError> {
    if key != transaction_id.as_str() || key.is_empty() || key.chars().any(char::is_control) {
        return Err(BackendError::Unavailable);
    }
    Ok(())
}

fn epoch_key(index: usize) -> String {
    format!("epoch-{index:020}")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{EpochIdentity, EpochTransition, HostInstallationEpoch, IdempotencyIdentity};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
    }

    fn test_host() -> HostInstallationEpoch {
        HostInstallationEpoch {
            installation: handle("test-installation"),
            epoch: EpochTransition {
                current: EpochIdentity {
                    lineage: handle("test-lineage"),
                    sequence: 1,
                },
                parent: None,
            },
            nonce: handle("test-nonce"),
            recovery: None,
        }
    }

    fn make_descriptor(transaction: &str, bytes: &[u8]) -> PreparedAppend {
        PreparedAppend {
            transaction_id: handle(transaction),
            host: test_host(),
            operation: IdempotencyIdentity {
                operation_id: handle("test-operation"),
                idempotency_key: handle(transaction),
            },
            record_checksum: sha256_digest(b"record"),
            payload_digest: sha256_digest(bytes),
        }
    }

    fn new_backend() -> (RedbJournalBackend, std::path::PathBuf) {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "eliot-host-journal-test-{}-{serial}",
            std::process::id()
        ));
        let path = root.join("journal.redb");
        let backend =
            RedbJournalBackend::open_unprotected_for_test(&path).unwrap_or_else(|_| unreachable!());
        (backend, root)
    }

    fn remove(root: &std::path::Path) {
        std::fs::remove_dir_all(root).unwrap_or_else(|_| unreachable!());
    }

    fn rewrite_prepared(
        backend: &RedbJournalBackend,
        transaction: &str,
        value: &serde_json::Value,
    ) {
        let write = backend
            .database
            .begin_write()
            .unwrap_or_else(|_| unreachable!());
        {
            let mut table = write
                .open_table(PREPARED)
                .unwrap_or_else(|_| unreachable!());
            let encoded = serde_json::to_vec(&value).unwrap_or_else(|_| unreachable!());
            table
                .insert(transaction, encoded.as_slice())
                .unwrap_or_else(|_| unreachable!());
        }
        write.commit().unwrap_or_else(|_| unreachable!());
    }

    #[test]
    fn redb_prepare_reopen_reconcile_distinguishes_prepared_and_absent() {
        let (mut backend, root) = new_backend();
        let descriptor = make_descriptor("tx-prepared", b"frame-prepared");
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        drop(backend);
        let mut reopened = RedbJournalBackend::open_unprotected_for_test(root.join("journal.redb"))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            reopened.reconcile(&descriptor.transaction_id),
            Ok(BackendReconcileState::Prepared)
        );
        assert_eq!(
            reopened.reconcile(&handle("tx-absent")),
            Ok(BackendReconcileState::Absent)
        );
        drop(reopened);
        remove(&root);
    }

    #[test]
    fn redb_commit_reopen_preserves_exact_bytes_and_receipt() {
        let (mut backend, root) = new_backend();
        let bytes = b"exact-frame-bytes\0\xff";
        let descriptor = make_descriptor("tx-commit", bytes);
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        backend
            .append_prepared(&descriptor.transaction_id, bytes)
            .unwrap_or_else(|_| unreachable!());
        backend
            .flush(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .sync(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .commit(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        let image = backend.load().unwrap_or_else(|_| unreachable!());
        assert_eq!(image.epochs[0].bytes, bytes);
        assert_eq!(image.receipts.len(), 1);
        assert_eq!(image.receipts[0].payload_digest, descriptor.payload_digest);
        drop(backend);
        let mut reopened = RedbJournalBackend::open_unprotected_for_test(root.join("journal.redb"))
            .unwrap_or_else(|_| unreachable!());
        let reopened_image = reopened.load().unwrap_or_else(|_| unreachable!());
        assert_eq!(reopened_image.epochs[0].bytes, bytes);
        assert_eq!(reopened_image.receipts, image.receipts);
        drop(reopened);
        remove(&root);
    }

    #[test]
    fn redb_duplicate_operations_are_idempotent() {
        let (mut backend, root) = new_backend();
        let bytes = b"duplicate-frame";
        let descriptor = make_descriptor("tx-duplicate", bytes);
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        backend
            .append_prepared(&descriptor.transaction_id, bytes)
            .unwrap_or_else(|_| unreachable!());
        backend
            .append_prepared(&descriptor.transaction_id, bytes)
            .unwrap_or_else(|_| unreachable!());
        backend
            .flush(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .flush(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .sync(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .sync(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .commit(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .commit(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        let image = backend.load().unwrap_or_else(|_| unreachable!());
        assert_eq!(image.receipts.len(), 1);
        assert_eq!(image.epochs[0].bytes, bytes);
        drop(backend);
        remove(&root);
    }

    #[test]
    fn redb_changed_descriptor_conflicts() {
        let (mut backend, root) = new_backend();
        let first = make_descriptor("tx-conflict", b"first");
        let mut changed = first.clone();
        changed.payload_digest = sha256_digest(b"changed");
        backend.prepare(&first).unwrap_or_else(|_| unreachable!());
        assert_eq!(backend.prepare(&changed), Err(BackendError::Conflict));
        drop(backend);
        remove(&root);
    }

    #[test]
    fn redb_commit_before_sync_is_rejected() {
        let (mut backend, root) = new_backend();
        let bytes = b"not-synced";
        let descriptor = make_descriptor("tx-before-sync", bytes);
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        backend
            .append_prepared(&descriptor.transaction_id, bytes)
            .unwrap_or_else(|_| unreachable!());
        backend
            .flush(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            backend.commit(&descriptor.transaction_id),
            Err(BackendError::Failed(_))
        ));
        assert_eq!(
            backend.reconcile(&descriptor.transaction_id),
            Ok(BackendReconcileState::Prepared)
        );
        drop(backend);
        remove(&root);
    }

    #[test]
    fn redb_corrupt_prepared_flags_and_bytes_fail_closed() {
        let (mut backend, root) = new_backend();
        let bytes = b"prepared-bytes";
        let descriptor = make_descriptor("tx-corrupt-flags", bytes);
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        let mut value = serde_json::to_value(StoredPrepared {
            descriptor: descriptor.clone(),
            bytes: Vec::new(),
            flushed: true,
            synced: false,
        })
        .unwrap_or_else(|_| unreachable!());
        value["bytes"] = serde_json::json!([]);
        rewrite_prepared(&backend, descriptor.transaction_id.as_str(), &value);
        assert!(backend.load().is_err());
        drop(backend);
        remove(&root);

        let (mut backend, root) = new_backend();
        let descriptor = make_descriptor("tx-corrupt-sync", bytes);
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        let value = serde_json::to_value(StoredPrepared {
            descriptor: descriptor.clone(),
            bytes: bytes.to_vec(),
            flushed: false,
            synced: true,
        })
        .unwrap_or_else(|_| unreachable!());
        rewrite_prepared(&backend, descriptor.transaction_id.as_str(), &value);
        assert!(backend.load().is_err());
        drop(backend);
        remove(&root);
    }

    #[test]
    fn redb_sparse_epoch_key_fails_closed() {
        let (mut backend, root) = new_backend();
        let bytes = b"epoch-bytes";
        let descriptor = make_descriptor("tx-sparse", bytes);
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        backend
            .append_prepared(&descriptor.transaction_id, bytes)
            .unwrap_or_else(|_| unreachable!());
        backend
            .flush(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .sync(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .commit(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        let epoch = backend.load().unwrap_or_else(|_| unreachable!()).epochs[0].clone();
        let write = backend
            .database
            .begin_write()
            .unwrap_or_else(|_| unreachable!());
        {
            let mut table = write.open_table(EPOCHS).unwrap_or_else(|_| unreachable!());
            let encoded = serde_json::to_vec(&epoch).unwrap_or_else(|_| unreachable!());
            let key = epoch_key(2);
            table
                .insert(key.as_str(), encoded.as_slice())
                .unwrap_or_else(|_| unreachable!());
        }
        write.commit().unwrap_or_else(|_| unreachable!());
        assert!(backend.load().is_err());
        drop(backend);
        remove(&root);
    }

    #[test]
    fn redb_missing_required_table_or_schema_fails_closed() {
        let (backend, root) = new_backend();
        let write = backend
            .database
            .begin_write()
            .unwrap_or_else(|_| unreachable!());
        write
            .delete_table(PAYLOADS)
            .unwrap_or_else(|_| unreachable!());
        write.commit().unwrap_or_else(|_| unreachable!());
        drop(backend);
        assert!(RedbJournalBackend::open_unprotected_for_test(root.join("journal.redb")).is_err());
        remove(&root);

        let (backend, root) = new_backend();
        let write = backend
            .database
            .begin_write()
            .unwrap_or_else(|_| unreachable!());
        write
            .delete_table(SCHEMA)
            .unwrap_or_else(|_| unreachable!());
        write.commit().unwrap_or_else(|_| unreachable!());
        drop(backend);
        assert!(RedbJournalBackend::open_unprotected_for_test(root.join("journal.redb")).is_err());
        remove(&root);
    }

    #[test]
    fn redb_tampered_payload_digest_fails_reopen() {
        let (mut backend, root) = new_backend();
        let bytes = b"tamper-payload";
        let descriptor = make_descriptor("tx-tamper-payload", bytes);
        backend
            .prepare(&descriptor)
            .unwrap_or_else(|_| unreachable!());
        backend
            .append_prepared(&descriptor.transaction_id, bytes)
            .unwrap_or_else(|_| unreachable!());
        backend
            .flush(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .sync(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        backend
            .commit(&descriptor.transaction_id)
            .unwrap_or_else(|_| unreachable!());
        let write = backend
            .database
            .begin_write()
            .unwrap_or_else(|_| unreachable!());
        {
            let mut table = write
                .open_table(RECEIPTS)
                .unwrap_or_else(|_| unreachable!());
            let raw = table
                .get(descriptor.transaction_id.as_str())
                .unwrap_or_else(|_| unreachable!())
                .map_or_else(|| unreachable!(), |value| value.value().to_vec());
            let mut value: serde_json::Value =
                serde_json::from_slice(&raw).unwrap_or_else(|_| unreachable!());
            value["payload_digest"] = serde_json::json!(sha256_digest(b"tampered"));
            let encoded = serde_json::to_vec(&value).unwrap_or_else(|_| unreachable!());
            table
                .insert(descriptor.transaction_id.as_str(), encoded.as_slice())
                .unwrap_or_else(|_| unreachable!());
        }
        write.commit().unwrap_or_else(|_| unreachable!());
        assert!(backend.load().is_err());
        drop(backend);
        assert!(RedbJournalBackend::open_unprotected_for_test(root.join("journal.redb")).is_err());
        remove(&root);
    }
}
