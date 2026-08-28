use crate::StoreError;
use eliot_types::{
    AdapterCircuitState, ControlWalConfig, MemoryWriteEnvelope, OperationRestartWindow,
    OperationRuntimeCheckpoint, ProjectRevisionSummary, SCHEMA_VERSION, SealStagingCheckpoint,
    WriteId, WriteReceipt, WriteRejectReason, WriteStatus,
};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[path = "control_wal_records.rs"]
mod control_wal_records;

pub use control_wal_records::{
    WalDeadLetter, WalFailedWrite, WalPendingWrite, WalProjectHead, WalWriteState,
};

const META: TableDefinition<&str, &str> = TableDefinition::new("control_wal_meta");
const PENDING_WRITES: TableDefinition<&str, &str> = TableDefinition::new("pending_writes");
const COMMITTED_RECEIPTS: TableDefinition<&str, &str> = TableDefinition::new("committed_receipts");
const FAILED_WRITES: TableDefinition<&str, &str> = TableDefinition::new("failed_writes");
const DEAD_LETTERS: TableDefinition<&str, &str> = TableDefinition::new("dead_letters");
const PROJECT_HEADS: TableDefinition<&str, &str> = TableDefinition::new("project_heads");
const OPERATION_RUNTIME: TableDefinition<&str, &str> = TableDefinition::new("operation_runtime_v1");
const OPERATION_RESTART_WINDOW: TableDefinition<&str, &str> =
    TableDefinition::new("operation_restart_window_v1");
const SUPERVISION_RECOVERY_CURSOR: TableDefinition<&str, &str> =
    TableDefinition::new("supervision_recovery_cursor_v1");
const SEAL_STAGING_INDEX: TableDefinition<&str, &str> =
    TableDefinition::new("seal_staging_index_v1");
const SUPERVISION_RECOVERY_CURSOR_KEY: &str = "singleton";

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
        self.append_pending_batch(std::slice::from_ref(envelope))
    }

    pub fn append_pending_batch(
        &self,
        envelopes: &[MemoryWriteEnvelope],
    ) -> Result<(), StoreError> {
        if envelopes.is_empty() {
            return Ok(());
        }
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(PENDING_WRITES)?;
            for envelope in envelopes {
                let pending = WalPendingWrite {
                    envelope: envelope.clone(),
                    status: WriteStatus::Staged,
                    attempts: 0,
                    last_error: None,
                };
                let payload = encode(&pending)?;
                table.insert(envelope.write_id.to_string().as_str(), payload.as_str())?;
            }
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
        self.mark_failed_message(write_id, error.to_string())
    }

    pub fn mark_failed_message(&self, write_id: &WriteId, error: String) -> Result<(), StoreError> {
        self.mark_terminal_failure(write_id, WriteStatus::FailedPermanent, error, None)
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
        self.mark_unknown_commit_message(write_id, error.to_string())
    }

    pub fn mark_unknown_commit_message(
        &self,
        write_id: &WriteId,
        error: String,
    ) -> Result<(), StoreError> {
        self.update_pending(write_id, |pending| {
            pending.status = WriteStatus::UnknownCommit;
            pending.last_error = Some(error);
        })
    }

    pub fn mark_retryable_message(
        &self,
        write_id: &WriteId,
        error: String,
    ) -> Result<(), StoreError> {
        self.update_pending(write_id, |pending| {
            pending.status = WriteStatus::FailedRetryable;
            pending.last_error = Some(error);
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

    pub fn retryable_count(&self) -> Result<u64, StoreError> {
        self.count_pending_by(|pending| pending.status == WriteStatus::FailedRetryable)
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

    pub fn put_operation_checkpoint(
        &self,
        checkpoint: &OperationRuntimeCheckpoint,
    ) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(OPERATION_RUNTIME)?;
            let payload = encode(checkpoint)?;
            table.insert(checkpoint.operation_id.as_str(), payload.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_operation_checkpoint(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationRuntimeCheckpoint>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(OPERATION_RUNTIME) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        table
            .get(operation_id)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    pub fn list_nonterminal_operation_checkpoints(
        &self,
    ) -> Result<Vec<OperationRuntimeCheckpoint>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(OPERATION_RUNTIME) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut checkpoints = Vec::new();
        for row in table.iter()? {
            let (_key, value) = row?;
            let checkpoint: OperationRuntimeCheckpoint = decode(value.value())?;
            if !checkpoint.is_terminal() {
                checkpoints.push(checkpoint);
            }
        }
        checkpoints.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        Ok(checkpoints)
    }

    pub fn delete_terminal_operation_checkpoint_after_retention(
        &self,
        operation_id: &str,
    ) -> Result<bool, StoreError> {
        let write_txn = self.db.begin_write()?;
        let removed = {
            let mut table = write_txn.open_table(OPERATION_RUNTIME)?;
            let terminal = table
                .get(operation_id)?
                .map(|value| decode::<OperationRuntimeCheckpoint>(value.value()))
                .transpose()?
                .is_some_and(|checkpoint| checkpoint.is_terminal());
            if terminal {
                table.remove(operation_id)?.is_some()
            } else {
                false
            }
        };
        write_txn.commit()?;
        Ok(removed)
    }

    pub fn load_restart_window(
        &self,
        key: &str,
    ) -> Result<Option<OperationRestartWindow>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(OPERATION_RESTART_WINDOW) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        table
            .get(key)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    pub fn record_restart(&self, window: &OperationRestartWindow) -> Result<(), StoreError> {
        self.put_restart_window(window)
    }

    pub fn open_circuit(
        &self,
        mut window: OperationRestartWindow,
    ) -> Result<OperationRestartWindow, StoreError> {
        window.circuit_state = AdapterCircuitState::Open;
        self.put_restart_window(&window)?;
        Ok(window)
    }

    pub fn half_open_circuit(
        &self,
        mut window: OperationRestartWindow,
    ) -> Result<OperationRestartWindow, StoreError> {
        window.circuit_state = AdapterCircuitState::HalfOpen;
        self.put_restart_window(&window)?;
        Ok(window)
    }

    pub fn reset_circuit(
        &self,
        mut window: OperationRestartWindow,
    ) -> Result<OperationRestartWindow, StoreError> {
        window.circuit_state = AdapterCircuitState::Closed;
        window.consecutive_failures = 0;
        window.last_failure_class = None;
        self.put_restart_window(&window)?;
        Ok(window)
    }

    fn put_restart_window(&self, window: &OperationRestartWindow) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(OPERATION_RESTART_WINDOW)?;
            let payload = encode(window)?;
            table.insert(window.key.as_str(), payload.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn supervision_recovery_cursor(&self) -> Result<Option<String>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(SUPERVISION_RECOVERY_CURSOR) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(table
            .get(SUPERVISION_RECOVERY_CURSOR_KEY)?
            .map(|value| value.value().to_owned()))
    }

    pub fn put_supervision_recovery_cursor(&self, cursor: &str) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SUPERVISION_RECOVERY_CURSOR)?;
            table.insert(SUPERVISION_RECOVERY_CURSOR_KEY, cursor)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn put_seal_staging_checkpoint(
        &self,
        checkpoint: &SealStagingCheckpoint,
    ) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SEAL_STAGING_INDEX)?;
            let payload = encode(checkpoint)?;
            table.insert(checkpoint.seal_attempt_id.as_str(), payload.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn load_incomplete_seal_staging(&self) -> Result<Vec<SealStagingCheckpoint>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(SEAL_STAGING_INDEX) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut checkpoints = Vec::new();
        for row in table.iter()? {
            let (_key, value) = row?;
            let checkpoint: SealStagingCheckpoint = decode(value.value())?;
            if !matches!(
                checkpoint.state,
                eliot_types::SealStagingState::Published | eliot_types::SealStagingState::Abandoned
            ) {
                checkpoints.push(checkpoint);
            }
        }
        checkpoints.sort_by(|left, right| left.seal_attempt_id.cmp(&right.seal_attempt_id));
        Ok(checkpoints)
    }

    pub fn complete_or_remove_seal_staging_checkpoint(
        &self,
        seal_attempt_id: &str,
    ) -> Result<bool, StoreError> {
        let write_txn = self.db.begin_write()?;
        let removed = {
            let mut table = write_txn.open_table(SEAL_STAGING_INDEX)?;
            table.remove(seal_attempt_id)?.is_some()
        };
        write_txn.commit()?;
        Ok(removed)
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
    use eliot_types::{
        AdapterCircuitState, ControlWalConfig, OPERATION_RESTART_WINDOW_SCHEMA_VERSION,
        OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION, OperationCancellationState, OperationPhase,
        OperationReconciliationState, OperationRestartWindow, OperationRuntimeCheckpoint,
        ProviderDispatchState,
    };
    use time::OffsetDateTime;

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

    #[test]
    fn operation_runtime_round_trip_filters_terminal_and_persists_circuit()
    -> Result<(), Box<dyn std::error::Error>> {
        let suffix = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "eliot-operation-runtime-test-{}-{suffix}",
            std::process::id()
        ));
        let wal = ControlWal::open(&ControlWalConfig {
            path: temp_dir.join("control.redb").display().to_string(),
        })?;
        let now = OffsetDateTime::now_utc();
        let mut checkpoint = OperationRuntimeCheckpoint {
            schema_version: OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION.to_owned(),
            operation_id: "adapter:fixture:1".to_owned(),
            invocation_id: Some("invocation-1".to_owned()),
            adapter_id: Some("fixture".to_owned()),
            generation: 1,
            phase: OperationPhase::Running,
            dispatch_state: ProviderDispatchState::Starting,
            cancellation_state: OperationCancellationState::NotRequested,
            reconciliation_state: OperationReconciliationState::NotRequired,
            root_pid: Some(42),
            root_process_start_ticks: None,
            root_executable_sha256: None,
            job_object_name: Some("Eliot-adapter-fixture-1-g1".to_owned()),
            active_process_count: 1,
            stdin_bytes: 10,
            stdout_bytes: 20,
            stderr_bytes: 30,
            phase_started_at: now,
            last_progress_at: now,
            phase_deadline_at: now + time::Duration::seconds(1),
            absolute_deadline_at: now + time::Duration::seconds(2),
            restart_count: 0,
            restart_window_started_at: None,
            role_lease_id: None,
            role_lease_epoch: None,
            runtime_contract_sha256: None,
            last_error_class: None,
            last_evidence_refs: Vec::new(),
        };
        wal.put_operation_checkpoint(&checkpoint)?;
        assert_eq!(
            wal.get_operation_checkpoint(&checkpoint.operation_id)?,
            Some(checkpoint.clone())
        );
        assert_eq!(
            wal.list_nonterminal_operation_checkpoints()?,
            vec![checkpoint.clone()]
        );
        assert!(
            !wal.delete_terminal_operation_checkpoint_after_retention(&checkpoint.operation_id)?
        );

        checkpoint.phase = OperationPhase::Completed;
        wal.put_operation_checkpoint(&checkpoint)?;
        assert!(wal.list_nonterminal_operation_checkpoints()?.is_empty());
        assert!(
            wal.delete_terminal_operation_checkpoint_after_retention(&checkpoint.operation_id)?
        );

        let window = OperationRestartWindow {
            schema_version: OPERATION_RESTART_WINDOW_SCHEMA_VERSION.to_owned(),
            key: "adapter:fixture".to_owned(),
            restart_timestamps: vec![now.to_string()],
            circuit_state: AdapterCircuitState::Closed,
            consecutive_failures: 5,
            last_success_at: None,
            last_failure_at: Some(now.to_string()),
            last_failure_class: Some("transport".to_owned()),
            last_terminal_operation_ref: Some("operation:fixture".to_owned()),
            updated_at: now.to_string(),
        };
        let opened = wal.open_circuit(window)?;
        assert_eq!(opened.circuit_state, AdapterCircuitState::Open);
        assert_eq!(wal.load_restart_window("adapter:fixture")?, Some(opened));

        drop(wal);
        let _ = std::fs::remove_dir_all(temp_dir);
        Ok(())
    }
}
