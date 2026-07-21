use crate::StoreError;
use eliot_types::{
    ControlWalConfig, MemoryRevision, MemoryWriteEnvelope, ProjectId, ProjectRevisionSummary,
    ProjectSequence, SCHEMA_VERSION, WriteId, WriteReceipt, WriteRejectReason, WriteStatus,
};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;

const META: TableDefinition<&str, &str> = TableDefinition::new("control_wal_meta");
const PENDING_WRITES: TableDefinition<&str, &str> = TableDefinition::new("pending_writes");
const COMMITTED_RECEIPTS: TableDefinition<&str, &str> = TableDefinition::new("committed_receipts");
const FAILED_WRITES: TableDefinition<&str, &str> = TableDefinition::new("failed_writes");
const DEAD_LETTERS: TableDefinition<&str, &str> = TableDefinition::new("dead_letters");
const PROJECT_HEADS: TableDefinition<&str, &str> = TableDefinition::new("project_heads");

pub struct ControlWal {
    db: Database,
}

impl ControlWal {
    pub fn open(config: &ControlWalConfig) -> Result<Self, StoreError> {
        let path = Path::new(&config.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = Database::create(path)?;
        Ok(Self { db })
    }

    pub fn record_bootstrap(&self, service_instance: &str) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(META)?;
            table.insert("schema_version", SCHEMA_VERSION)?;
            table.insert("last_bootstrap_instance", service_instance)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn append_pending(&self, envelope: &MemoryWriteEnvelope) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(PENDING_WRITES)?;
            let pending = WalPendingWrite {
                envelope: envelope.clone(),
                status: WriteStatus::Staged,
                attempts: 0,
                last_error: None,
            };
            let payload = encode(&pending)?;
            table.insert(envelope.write_id.to_string().as_str(), payload.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_by_write_id(&self, write_id: &WriteId) -> Result<Option<WalWriteState>, StoreError> {
        let key = write_id.to_string();
        let read_txn = self.db.begin_read()?;

        if let Ok(table) = read_txn.open_table(COMMITTED_RECEIPTS)
            && let Some(value) = table.get(key.as_str())?
        {
            return Ok(Some(WalWriteState::Committed(Box::new(decode(
                value.value(),
            )?))));
        }
        if let Ok(table) = read_txn.open_table(PENDING_WRITES)
            && let Some(value) = table.get(key.as_str())?
        {
            return Ok(Some(WalWriteState::Pending(Box::new(decode(
                value.value(),
            )?))));
        }
        if let Ok(table) = read_txn.open_table(FAILED_WRITES)
            && let Some(value) = table.get(key.as_str())?
        {
            return Ok(Some(WalWriteState::Failed(Box::new(decode(
                value.value(),
            )?))));
        }
        if let Ok(table) = read_txn.open_table(DEAD_LETTERS)
            && let Some(value) = table.get(key.as_str())?
        {
            return Ok(Some(WalWriteState::DeadLetter(Box::new(decode(
                value.value(),
            )?))));
        }

        Ok(None)
    }

    pub fn mark_applying(&self, write_id: &WriteId) -> Result<(), StoreError> {
        self.update_pending(write_id, |pending| {
            pending.status = WriteStatus::Applying;
            pending.attempts = pending.attempts.saturating_add(1);
        })
    }

    pub fn mark_committed(&self, receipt: &WriteReceipt) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let key = receipt.write_id.to_string();
            let mut pending = write_txn.open_table(PENDING_WRITES)?;
            pending.remove(key.as_str())?;

            let mut committed = write_txn.open_table(COMMITTED_RECEIPTS)?;
            let payload = encode(receipt)?;
            committed.insert(key.as_str(), payload.as_str())?;

            if let (Some(memory_revision), Some(project_sequence)) =
                (receipt.memory_revision, receipt.project_sequence)
            {
                let head = WalProjectHead {
                    project_id: receipt.project_id,
                    memory_revision,
                    project_sequence,
                    last_write_id: receipt.write_id,
                };
                let head_payload = encode(&head)?;
                let mut heads = write_txn.open_table(PROJECT_HEADS)?;
                heads.insert(
                    receipt.project_id.to_string().as_str(),
                    head_payload.as_str(),
                )?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn mark_failed(&self, write_id: &WriteId, error: &StoreError) -> Result<(), StoreError> {
        self.mark_terminal_failure(
            write_id,
            WriteStatus::FailedPermanent,
            error.to_string(),
            None,
        )
    }

    pub fn mark_rejected(&self, receipt: &WriteReceipt) -> Result<(), StoreError> {
        self.mark_terminal_failure(
            &receipt.write_id,
            WriteStatus::Rejected,
            receipt.rejected_reason.map_or_else(
                || "write rejected".to_owned(),
                |reason| format!("{reason:?}"),
            ),
            Some(receipt.clone()),
        )
    }

    pub fn mark_unknown_commit(
        &self,
        write_id: &WriteId,
        error: &StoreError,
    ) -> Result<(), StoreError> {
        self.update_pending(write_id, |pending| {
            pending.status = WriteStatus::UnknownCommit;
            pending.last_error = Some(error.to_string());
        })
    }

    fn mark_terminal_failure(
        &self,
        write_id: &WriteId,
        status: WriteStatus,
        error: String,
        receipt: Option<WriteReceipt>,
    ) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let key = write_id.to_string();
            let mut pending_table = write_txn.open_table(PENDING_WRITES)?;
            let pending = pending_table
                .get(key.as_str())?
                .map(|value| decode::<WalPendingWrite>(value.value()))
                .transpose()?;
            pending_table.remove(key.as_str())?;

            let failed = WalFailedWrite {
                write_id: *write_id,
                status,
                pending,
                receipt,
                error,
            };
            let payload = encode(&failed)?;
            let mut failed_table = write_txn.open_table(FAILED_WRITES)?;
            failed_table.insert(key.as_str(), payload.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn move_to_dead_letter(&self, write_id: &WriteId, reason: &str) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let key = write_id.to_string();
            let mut pending_table = write_txn.open_table(PENDING_WRITES)?;
            let pending = pending_table
                .get(key.as_str())?
                .map(|value| decode::<WalPendingWrite>(value.value()))
                .transpose()?;
            pending_table.remove(key.as_str())?;

            let dead_letter = WalDeadLetter {
                write_id: *write_id,
                pending,
                reason: reason.to_owned(),
            };
            let payload = encode(&dead_letter)?;
            let mut dead_letters = write_txn.open_table(DEAD_LETTERS)?;
            dead_letters.insert(key.as_str(), payload.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn recover_pending(&self) -> Result<Vec<MemoryWriteEnvelope>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(PENDING_WRITES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut pending = Vec::new();
        for row in table.iter()? {
            let (_key, value) = row?;
            let state: WalPendingWrite = decode(value.value())?;
            pending.push(state.envelope);
        }
        Ok(pending)
    }

    pub fn pending_count(&self) -> Result<u64, StoreError> {
        self.table_count(PENDING_WRITES)
    }

    pub fn committed_count(&self) -> Result<u64, StoreError> {
        self.table_count(COMMITTED_RECEIPTS)
    }

    pub fn failed_count(&self) -> Result<u64, StoreError> {
        self.count_failed_by(|failed| failed.status == WriteStatus::FailedPermanent)
    }

    pub fn rejected_count(&self) -> Result<u64, StoreError> {
        self.count_failed_by(|failed| failed.status == WriteStatus::Rejected)
    }

    pub fn unknown_commit_count(&self) -> Result<u64, StoreError> {
        self.count_pending_by(|pending| pending.status == WriteStatus::UnknownCommit)
    }

    pub fn idempotent_replay_count(&self) -> Result<u64, StoreError> {
        self.count_committed_by(|receipt| receipt.status == WriteStatus::IdempotentReplay)
    }

    pub fn idempotency_conflict_count(&self) -> Result<u64, StoreError> {
        self.count_failed_by(|failed| {
            failed.status == WriteStatus::Rejected
                && failed.receipt.as_ref().is_some_and(|receipt| {
                    matches!(
                        receipt.rejected_reason,
                        Some(
                            WriteRejectReason::IdempotencyConflict
                                | WriteRejectReason::WriteIdInputHashConflict
                        )
                    )
                })
        })
    }

    pub fn dead_letter_count(&self) -> Result<u64, StoreError> {
        self.table_count(DEAD_LETTERS)
    }

    pub fn project_heads(&self) -> Result<Vec<ProjectRevisionSummary>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(PROJECT_HEADS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut heads = Vec::new();
        for row in table.iter()? {
            let (_key, value) = row?;
            let head: WalProjectHead = decode(value.value())?;
            heads.push(ProjectRevisionSummary {
                project_id: head.project_id,
                memory_revision: head.memory_revision,
                project_sequence: head.project_sequence,
            });
        }
        Ok(heads)
    }

    pub fn last_receipts(&self, limit: usize) -> Result<Vec<WriteReceipt>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(COMMITTED_RECEIPTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut receipts = Vec::new();
        for row in table.iter()? {
            let (_key, value) = row?;
            receipts.push(decode(value.value())?);
        }
        receipts.truncate(limit);
        Ok(receipts)
    }

    pub fn meta_value(&self, key: &str) -> Result<Option<String>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(META)?;
        let value = table.get(key)?.map(|guard| guard.value().to_owned());
        Ok(value)
    }

    fn update_pending<F>(&self, write_id: &WriteId, update: F) -> Result<(), StoreError>
    where
        F: FnOnce(&mut WalPendingWrite),
    {
        let write_txn = self.db.begin_write()?;
        {
            let key = write_id.to_string();
            let mut table = write_txn.open_table(PENDING_WRITES)?;
            let mut pending: WalPendingWrite = {
                let Some(value) = table.get(key.as_str())? else {
                    return Err(StoreError::ConfigMessage(format!(
                        "pending write {write_id} not found"
                    )));
                };
                decode(value.value())?
            };
            update(&mut pending);
            let payload = encode(&pending)?;
            table.insert(key.as_str(), payload.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn table_count(&self, definition: TableDefinition<&str, &str>) -> Result<u64, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(definition) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        Ok(table.len()?)
    }

    fn count_pending_by<F>(&self, predicate: F) -> Result<u64, StoreError>
    where
        F: Fn(&WalPendingWrite) -> bool,
    {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(PENDING_WRITES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        let mut count = 0;
        for row in table.iter()? {
            let (_key, value) = row?;
            let pending: WalPendingWrite = decode(value.value())?;
            if predicate(&pending) {
                count += 1;
            }
        }
        Ok(count)
    }

    fn count_committed_by<F>(&self, predicate: F) -> Result<u64, StoreError>
    where
        F: Fn(&WriteReceipt) -> bool,
    {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(COMMITTED_RECEIPTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        let mut count = 0;
        for row in table.iter()? {
            let (_key, value) = row?;
            let receipt: WriteReceipt = decode(value.value())?;
            if predicate(&receipt) {
                count += 1;
            }
        }
        Ok(count)
    }

    fn count_failed_by<F>(&self, predicate: F) -> Result<u64, StoreError>
    where
        F: Fn(&WalFailedWrite) -> bool,
    {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(FAILED_WRITES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        let mut count = 0;
        for row in table.iter()? {
            let (_key, value) = row?;
            let failed: WalFailedWrite = decode(value.value())?;
            if predicate(&failed) {
                count += 1;
            }
        }
        Ok(count)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalPendingWrite {
    pub envelope: MemoryWriteEnvelope,
    pub status: WriteStatus,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalFailedWrite {
    pub write_id: WriteId,
    pub status: WriteStatus,
    pub pending: Option<WalPendingWrite>,
    pub receipt: Option<WriteReceipt>,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalDeadLetter {
    pub write_id: WriteId,
    pub pending: Option<WalPendingWrite>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalProjectHead {
    pub project_id: ProjectId,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub last_write_id: WriteId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WalWriteState {
    Pending(Box<WalPendingWrite>),
    Committed(Box<WriteReceipt>),
    Failed(Box<WalFailedWrite>),
    DeadLetter(Box<WalDeadLetter>),
}

fn encode<T>(value: &T) -> Result<String, StoreError>
where
    T: Serialize,
{
    serde_json::to_string(value).map_err(|error| StoreError::Decode(error.to_string()))
}

fn decode<T>(value: &str) -> Result<T, StoreError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(value).map_err(|error| StoreError::Decode(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::ControlWal;
    use eliot_types::ControlWalConfig;

    #[test]
    fn records_bootstrap_marker() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = std::env::temp_dir().join(format!(
            "eliot-governor-control-wal-test-{}",
            std::process::id()
        ));
        let path = temp_dir.join("control.redb");

        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        wal.record_bootstrap("test-instance")?;

        assert_eq!(
            wal.meta_value("last_bootstrap_instance")?,
            Some("test-instance".to_owned())
        );

        let _ = std::fs::remove_dir_all(temp_dir);
        Ok(())
    }
}
