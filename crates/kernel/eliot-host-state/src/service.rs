use std::path::Path;

use eliot_platform::PlatformHandle;

use crate::{
    AppendReceipt, HostInstallationEpoch, HostState, HostStateJournal, HostStateRecord,
    JournalBackend, JournalError, PreparedAppend, ReconcileOutcome, RedbJournalBackend,
};

/// Production-facing service boundary for the Host operational journal.
///
/// The reducer and durability protocol remain owned by [`HostStateJournal`];
/// this facade gives Host composition one explicit state service instead of
/// exposing a second operational store or a dual-write path.
pub struct HostStateJournalService<B> {
    journal: HostStateJournal<B>,
}

impl<B: JournalBackend> HostStateJournalService<B> {
    pub fn from_backend(backend: B, host: HostInstallationEpoch) -> Result<Self, JournalError> {
        Ok(Self {
            journal: HostStateJournal::open(backend, host)?,
        })
    }

    pub fn snapshot(&self) -> Result<HostState, JournalError> {
        self.journal.snapshot()
    }

    pub fn append(&self, record: HostStateRecord) -> Result<AppendReceipt, JournalError> {
        self.journal.append(record)
    }

    pub fn append_readiness_observation(
        &self,
        observation: crate::KernelReadinessObservationRecord,
        expected: &crate::ReadinessApprovedContour,
    ) -> Result<AppendReceipt, JournalError> {
        self.journal
            .append_readiness_observation(observation, expected)
    }

    pub fn pending_transactions(&self) -> Result<Vec<PreparedAppend>, JournalError> {
        self.journal.pending_transactions()
    }

    pub fn reconcile(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<ReconcileOutcome, JournalError> {
        self.journal.reconcile(transaction_id)
    }

    pub fn into_backend(self) -> Result<B, JournalError> {
        self.journal.into_backend()
    }
}

/// Sole production Host operational-state service.
pub type ProductionHostStateJournal = HostStateJournalService<RedbJournalBackend>;

impl HostStateJournalService<RedbJournalBackend> {
    pub fn open(path: impl AsRef<Path>, host: HostInstallationEpoch) -> Result<Self, JournalError> {
        let backend = RedbJournalBackend::open(path).map_err(JournalError::Backend)?;
        Self::from_backend(backend, host)
    }
}
