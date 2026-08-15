use eliot_platform::{PlatformHandle, UnknownReason};

use crate::{BackendError, HostInstallationEpoch, IdempotencyIdentity};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEpoch {
    pub host: HostInstallationEpoch,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DurableImage {
    pub epochs: Vec<StoredEpoch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAppend {
    pub transaction_id: PlatformHandle,
    pub host: HostInstallationEpoch,
    pub operation: IdempotencyIdentity,
    pub record_checksum: String,
    pub payload_digest: String,
}

/// Backend observation for an append that crossed its durable commit boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedAppend {
    pub transaction_id: PlatformHandle,
    pub host: HostInstallationEpoch,
    pub operation: IdempotencyIdentity,
    pub record_checksum: String,
    pub payload_digest: String,
}

impl CommittedAppend {
    fn from_prepared(prepared: PreparedAppend) -> Self {
        Self {
            transaction_id: prepared.transaction_id,
            host: prepared.host,
            operation: prepared.operation,
            record_checksum: prepared.record_checksum,
            payload_digest: prepared.payload_digest,
        }
    }

    fn matches_prepared(&self, prepared: &PreparedAppend) -> bool {
        self.transaction_id == prepared.transaction_id
            && self.host == prepared.host
            && self.operation == prepared.operation
            && self.record_checksum == prepared.record_checksum
            && self.payload_digest == prepared.payload_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendReconcileState {
    Absent,
    Prepared,
    Committed(Box<CommittedAppend>),
}

/// Transaction-durable port implemented by P-01 adapters.
pub trait JournalBackend: Send {
    fn load(&mut self) -> Result<DurableImage, BackendError>;
    fn prepare(&mut self, append: &PreparedAppend) -> Result<(), BackendError>;
    fn append_prepared(
        &mut self,
        transaction_id: &PlatformHandle,
        bytes: &[u8],
    ) -> Result<(), BackendError>;
    fn flush(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError>;
    fn sync(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError>;
    fn commit(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError>;
    fn reconcile(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<BackendReconcileState, BackendError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    PlanGap,
    PrepareFailed,
    PrepareUnknown,
    AppendFailed,
    FlushUnknown,
    SyncUnknown,
    CommitBeforeUnknown,
    CommitAfterUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedAppend {
    descriptor: PreparedAppend,
    bytes: Vec<u8>,
    flushed: bool,
    synced: bool,
}

/// Deterministic transaction backend for model and crash tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryBackend {
    image: DurableImage,
    staged: Vec<StagedAppend>,
    committed: Vec<CommittedAppend>,
    fault: Option<FaultPoint>,
}

impl MemoryBackend {
    pub fn with_fault(fault: FaultPoint) -> Self {
        Self {
            fault: Some(fault),
            ..Self::default()
        }
    }

    pub fn inject_fault(&mut self, fault: FaultPoint) {
        self.fault = Some(fault);
    }

    pub fn durable_image(&self) -> &DurableImage {
        &self.image
    }

    #[cfg(test)]
    pub(crate) fn corrupt_epoch_for_test(&mut self, index: usize) {
        let bytes = &mut self.image.epochs[index].bytes;
        bytes.truncate(bytes.len().saturating_sub(1));
    }

    #[cfg(test)]
    pub(crate) fn rewrite_committed_checksum_for_test(
        &mut self,
        transaction_id: &PlatformHandle,
        checksum: &str,
    ) {
        let committed = self
            .committed
            .iter_mut()
            .find(|item| &item.transaction_id == transaction_id)
            .unwrap_or_else(|| unreachable!());
        committed.record_checksum = checksum.to_owned();
    }

    fn take_fault(&mut self, expected: FaultPoint) -> bool {
        if self.fault == Some(expected) {
            self.fault = None;
            true
        } else {
            false
        }
    }

    fn staged_mut(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<&mut StagedAppend, BackendError> {
        self.staged
            .iter_mut()
            .find(|item| &item.descriptor.transaction_id == transaction_id)
            .ok_or_else(|| BackendError::Failed("transaction was not prepared".into()))
    }
}

impl JournalBackend for MemoryBackend {
    fn load(&mut self) -> Result<DurableImage, BackendError> {
        Ok(self.image.clone())
    }

    fn prepare(&mut self, append: &PreparedAppend) -> Result<(), BackendError> {
        if self.take_fault(FaultPoint::PlanGap) {
            return Err(BackendError::PlanGap {
                dependency: "P-01 eliot-platform",
            });
        }
        if self.take_fault(FaultPoint::PrepareFailed) {
            return Err(BackendError::Failed("prepare failpoint".into()));
        }
        if self.take_fault(FaultPoint::PrepareUnknown) {
            return Err(BackendError::Unknown(UnknownReason::Indeterminate));
        }
        if let Some(committed) = self
            .committed
            .iter()
            .find(|item| item.transaction_id == append.transaction_id)
        {
            return if committed.matches_prepared(append) {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        if let Some(staged) = self
            .staged
            .iter()
            .find(|item| item.descriptor.transaction_id == append.transaction_id)
        {
            return if staged.descriptor == *append {
                Ok(())
            } else {
                Err(BackendError::Conflict)
            };
        }
        self.staged.push(StagedAppend {
            descriptor: append.clone(),
            bytes: Vec::new(),
            flushed: false,
            synced: false,
        });
        Ok(())
    }

    fn append_prepared(
        &mut self,
        transaction_id: &PlatformHandle,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        if self.take_fault(FaultPoint::AppendFailed) {
            return Err(BackendError::Failed("append failpoint".into()));
        }
        let staged = self.staged_mut(transaction_id)?;
        if staged.bytes.is_empty() {
            staged.bytes.extend_from_slice(bytes);
            return Ok(());
        }
        if staged.bytes == bytes {
            Ok(())
        } else {
            Err(BackendError::Conflict)
        }
    }

    fn flush(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        if self.take_fault(FaultPoint::FlushUnknown) {
            return Err(BackendError::Unknown(UnknownReason::Indeterminate));
        }
        let staged = self.staged_mut(transaction_id)?;
        if staged.bytes.is_empty() {
            return Err(BackendError::Failed("cannot flush an empty append".into()));
        }
        staged.flushed = true;
        Ok(())
    }

    fn sync(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        if self.take_fault(FaultPoint::SyncUnknown) {
            return Err(BackendError::Unknown(UnknownReason::Indeterminate));
        }
        let staged = self.staged_mut(transaction_id)?;
        if !staged.flushed {
            return Err(BackendError::Failed("append was not flushed".into()));
        }
        staged.synced = true;
        Ok(())
    }

    fn commit(&mut self, transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        if self.take_fault(FaultPoint::CommitBeforeUnknown) {
            return Err(BackendError::Unknown(UnknownReason::Indeterminate));
        }
        if self
            .committed
            .iter()
            .any(|item| &item.transaction_id == transaction_id)
        {
            return Ok(());
        }
        let index = self
            .staged
            .iter()
            .position(|item| &item.descriptor.transaction_id == transaction_id)
            .ok_or_else(|| BackendError::Failed("transaction was not prepared".into()))?;
        if !self.staged[index].synced {
            return Err(BackendError::Failed("append was not synchronized".into()));
        }
        let staged = self.staged.remove(index);
        let committed = CommittedAppend::from_prepared(staged.descriptor.clone());
        if let Some(epoch) = self
            .image
            .epochs
            .iter_mut()
            .find(|item| item.host == staged.descriptor.host)
        {
            epoch.bytes.extend_from_slice(&staged.bytes);
        } else {
            self.image.epochs.push(StoredEpoch {
                host: staged.descriptor.host,
                bytes: staged.bytes,
            });
        }
        self.committed.push(committed);
        if self.take_fault(FaultPoint::CommitAfterUnknown) {
            Err(BackendError::Unknown(UnknownReason::Indeterminate))
        } else {
            Ok(())
        }
    }

    fn reconcile(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<BackendReconcileState, BackendError> {
        if let Some(committed) = self
            .committed
            .iter()
            .find(|item| &item.transaction_id == transaction_id)
        {
            Ok(BackendReconcileState::Committed(Box::new(
                committed.clone(),
            )))
        } else if self
            .staged
            .iter()
            .any(|item| &item.descriptor.transaction_id == transaction_id)
        {
            Ok(BackendReconcileState::Prepared)
        } else {
            Ok(BackendReconcileState::Absent)
        }
    }
}
