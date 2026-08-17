//! Crash-safe redb adapter for the Host-owned journal.

use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_platform_windows::{ProtectedPathLease, require_protected_program_data_path};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::{
    BackendError, BackendReconcileState, CommittedAppend, DurableImage, JournalBackend,
    PreparedAppend, StoredEpoch,
};

const HOST_JOURNAL_RELATIVE_PATH: &str = "Eliot/host/host-state-journal.redb";
const EPOCHS: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_host_journal_epochs_v1");
const PREPARED: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_host_journal_prepared_v1");
const RECEIPTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_host_journal_receipts_v1");

const MAX_EPOCHS: usize = 256;
const MAX_PREPARED: usize = 128;
const MAX_RECEIPTS: usize = 8_192;
const MAX_APPEND_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPrepared {
    descriptor: PreparedAppend,
    bytes: Vec<u8>,
    flushed: bool,
    synced: bool,
}

/// Production HostStateJournal backend backed by a separate Host-owned redb file.
///
/// The retained [`ProtectedPathLease`] is held for the lifetime of the database,
/// so redb never reopens a path whose final component could have been replaced.
pub struct RedbJournalBackend {
    database: Database,
    path: PathBuf,
    _path_lease: ProtectedPathLease,
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
            _path_lease: path_lease,
        })
    }

    /// Returns the exact protected path used by this backend.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_epochs(&self) -> Result<Vec<(String, StoredEpoch)>, BackendError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| BackendError::Unavailable)?;
        let table = match read.open_table(EPOCHS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(_) => return Err(BackendError::Unavailable),
        };
        let mut result = Vec::new();
        for item in table.iter().map_err(|_| BackendError::Unavailable)? {
            let (key, value) = item.map_err(|_| BackendError::Unavailable)?;
            let key = key.value().to_owned();
            validate_epoch_key(&key)?;
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
            if result
                .iter()
                .any(|(_, prior): &(String, StoredEpoch)| prior.host == epoch.host)
            {
                return Err(BackendError::Unavailable);
            }
            result.push((key, epoch));
            if result.len() > MAX_EPOCHS {
                return Err(BackendError::Unavailable);
            }
        }
        result.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(result)
    }

    fn read_prepared(&self) -> Result<Vec<(String, StoredPrepared)>, BackendError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| BackendError::Unavailable)?;
        let table = match read.open_table(PREPARED) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(_) => return Err(BackendError::Unavailable),
        };
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

    fn read_receipts(&self) -> Result<Vec<(String, CommittedAppend)>, BackendError> {
        let read = self
            .database
            .begin_read()
            .map_err(|_| BackendError::Unavailable)?;
        let table = match read.open_table(RECEIPTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(_) => return Err(BackendError::Unavailable),
        };
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
            validate_operation(&receipt.operation)?;
            validate_digest(&receipt.record_checksum)?;
            validate_digest(&receipt.payload_digest)?;
            result.push((key, receipt));
            if result.len() > MAX_RECEIPTS {
                return Err(BackendError::Unavailable);
            }
        }
        Ok(result)
    }

    fn prepared_for(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<Option<StoredPrepared>, BackendError> {
        Ok(self
            .read_prepared()?
            .into_iter()
            .find(|(_, item)| item.descriptor.transaction_id == *transaction_id)
            .map(|(_, item)| item))
    }

    fn receipt_for(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<Option<CommittedAppend>, BackendError> {
        Ok(self
            .read_receipts()?
            .into_iter()
            .find(|(_, item)| item.transaction_id == *transaction_id)
            .map(|(_, item)| item))
    }
}

impl JournalBackend for RedbJournalBackend {
    fn load(&mut self) -> Result<DurableImage, BackendError> {
        let epochs = self.read_epochs()?;
        let _prepared = self.read_prepared()?;
        let receipts = self.read_receipts()?;
        Ok(DurableImage {
            epochs: epochs.into_iter().map(|(_, item)| item).collect(),
            receipts: receipts.into_iter().map(|(_, item)| item).collect(),
        })
    }

    fn prepare(&mut self, append: &PreparedAppend) -> Result<(), BackendError> {
        validate_descriptor(append)?;
        if let Some(receipt) = self.receipt_for(&append.transaction_id)? {
            return if receipt.matches_prepared(append) {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        if let Some(prepared) = self.prepared_for(&append.transaction_id)? {
            return if prepared.descriptor == *append {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        if self.read_prepared()?.len() >= MAX_PREPARED {
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
        write.commit().map_err(|_| BackendError::Unavailable)
    }

    fn append_prepared(
        &mut self,
        transaction_id: &PlatformHandle,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        if bytes.is_empty() || bytes.len() > MAX_APPEND_BYTES {
            return Err(BackendError::Failed("append size is outside bounds".into()));
        }
        let Some(mut prepared) = self.prepared_for(transaction_id)? else {
            return if self.receipt_for(transaction_id)?.is_some() {
                Err(BackendError::Conflict)
            } else {
                Err(BackendError::Failed("transaction was not prepared".into()))
            };
        };
        if !prepared.bytes.is_empty() && prepared.bytes != bytes {
            return Err(BackendError::Conflict);
        }
        if prepared.bytes == bytes {
            return Ok(());
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
        write.commit().map_err(|_| BackendError::Unavailable)
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
        let Some(prepared) = self.prepared_for(transaction_id)? else {
            return if self.receipt_for(transaction_id)?.is_some() {
                Ok(())
            } else {
                Err(BackendError::Failed("transaction was not prepared".into()))
            };
        };
        if !prepared.synced {
            return Err(BackendError::Failed("append was not synchronized".into()));
        }
        let committed = CommittedAppend::from_prepared(prepared.descriptor.clone());
        if let Some(receipt) = self.receipt_for(transaction_id)? {
            return if receipt == committed {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        if self.read_receipts()?.len() >= MAX_RECEIPTS {
            return Err(BackendError::Failed("receipt limit reached".into()));
        }
        let mut epochs = self.read_epochs()?;
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
        let epoch_encoded = encode_bounded(epoch, MAX_METADATA_BYTES + MAX_APPEND_BYTES)?;
        let receipt_encoded = encode_bounded(&committed, MAX_METADATA_BYTES)?;
        let write = self
            .database
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
            epoch_table
                .insert(epoch_key.as_str(), epoch_encoded.as_slice())
                .map_err(|_| BackendError::Unavailable)?;
            receipt_table
                .insert(transaction_id.as_str(), receipt_encoded.as_slice())
                .map_err(|_| BackendError::Unavailable)?;
            prepared_table
                .remove(transaction_id.as_str())
                .map_err(|_| BackendError::Unavailable)?;
        }
        write.commit().map_err(|_| BackendError::Unavailable)
    }

    fn reconcile(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<BackendReconcileState, BackendError> {
        let _ = self.load()?;
        if let Some(receipt) = self.receipt_for(transaction_id)? {
            Ok(BackendReconcileState::Committed(Box::new(receipt)))
        } else if self.prepared_for(transaction_id)?.is_some() {
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
        let Some(mut prepared) = self.prepared_for(transaction_id)? else {
            return Err(BackendError::Failed("transaction was not prepared".into()));
        };
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
        write.commit().map_err(|_| BackendError::Unavailable)
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
    if is_valid_text(value) {
        Ok(())
    } else {
        Err(BackendError::Unavailable)
    }
}

fn is_valid_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn validate_prepared(prepared: &StoredPrepared) -> Result<(), BackendError> {
    validate_descriptor(&prepared.descriptor)?;
    if prepared.bytes.len() > MAX_APPEND_BYTES {
        return Err(BackendError::Unavailable);
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

fn validate_epoch_key(key: &str) -> Result<(), BackendError> {
    let Some(ordinal) = key.strip_prefix("epoch-") else {
        return Err(BackendError::Unavailable);
    };
    if ordinal.len() != 20 || !ordinal.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BackendError::Unavailable);
    }
    Ok(())
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
