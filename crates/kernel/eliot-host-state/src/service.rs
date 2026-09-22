use std::path::Path;

use eliot_platform::PlatformHandle;

use crate::{
    AppendReceipt, HostInstallationEpoch, HostState, HostStateJournal, HostStateRecord,
    JournalBackend, JournalError, PreparedAppend, ReactiveContextEnqueueReceipt,
    ReactiveContextOperationQuery, ReactiveContextPrepareRequest, ReactiveContextPrepareResult,
    ReactiveContextPreparedEnqueue, ReactiveContextQueueError, ReactiveContextQueuePort,
    ReactiveContextQueueQuery, ReactiveContextQueueSnapshot, ReactiveContextReconcileOutcome,
    ReactiveContextReconcileRequest, ReactiveContextTransition, ReactiveContextTransitionReceipt,
    ReconcileOutcome, RedbJournalBackend,
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

    /// Loads one durable backup-preparation row by preparation operation id.
    ///
    /// Read-only projection over the journal snapshot for load-before-act
    /// idempotency (issue #958). Returns `None` when no intent was recorded.
    pub fn load_backup_preparation(
        &self,
        preparation_operation_id: &str,
    ) -> Result<Option<crate::BackupPreparationRecord>, JournalError> {
        Ok(self
            .journal
            .snapshot()?
            .backup_preparations
            .into_iter()
            .find(|record| {
                record.preparation_operation_id.as_str() == preparation_operation_id
            }))
    }

    /// Lists all durable backup-preparation rows (bounded sweep for cleanup).
    pub fn list_backup_preparations(
        &self,
    ) -> Result<Vec<crate::BackupPreparationRecord>, JournalError> {
        Ok(self.journal.snapshot()?.backup_preparations)
    }

    pub fn prepare_reactive_context(
        &self,
        request: ReactiveContextPrepareRequest,
    ) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
        self.journal.prepare_reactive_context(request)
    }

    pub fn commit_reactive_context(
        &self,
        prepared: ReactiveContextPreparedEnqueue,
    ) -> Result<ReactiveContextEnqueueReceipt, ReactiveContextQueueError> {
        self.journal.commit_reactive_context(prepared)
    }

    pub fn compare_and_transition(
        &self,
        transition: ReactiveContextTransition,
    ) -> Result<ReactiveContextTransitionReceipt, ReactiveContextQueueError> {
        self.journal.compare_and_transition(transition)
    }

    pub fn load_reactive_context_queue(
        &self,
        query: ReactiveContextQueueQuery,
    ) -> Result<ReactiveContextQueueSnapshot, ReactiveContextQueueError> {
        self.journal.load_reactive_context_queue(query)
    }

    pub fn query_reactive_context_operation(
        &self,
        query: ReactiveContextOperationQuery,
    ) -> Result<crate::ReactiveContextQueueEntry, ReactiveContextQueueError> {
        self.journal.query_reactive_context_operation(query)
    }

    pub fn reconcile_reactive_context(
        &self,
        request: ReactiveContextReconcileRequest,
    ) -> Result<ReactiveContextReconcileOutcome, ReactiveContextQueueError> {
        self.journal.reconcile_reactive_context(request)
    }

    pub fn into_backend(self) -> Result<B, JournalError> {
        self.journal.into_backend()
    }
}

impl<B: JournalBackend> ReactiveContextQueuePort for HostStateJournalService<B> {
    fn prepare_or_replay(
        &self,
        request: ReactiveContextPrepareRequest,
    ) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
        self.prepare_reactive_context(request)
    }

    fn commit_enqueued(
        &self,
        prepared: ReactiveContextPreparedEnqueue,
    ) -> Result<ReactiveContextEnqueueReceipt, ReactiveContextQueueError> {
        self.commit_reactive_context(prepared)
    }

    fn compare_and_transition(
        &self,
        transition: ReactiveContextTransition,
    ) -> Result<ReactiveContextTransitionReceipt, ReactiveContextQueueError> {
        self.compare_and_transition(transition)
    }

    fn load_attempt_queue(
        &self,
        query: ReactiveContextQueueQuery,
    ) -> Result<ReactiveContextQueueSnapshot, ReactiveContextQueueError> {
        self.load_reactive_context_queue(query)
    }

    fn query_operation(
        &self,
        query: ReactiveContextOperationQuery,
    ) -> Result<crate::ReactiveContextQueueEntry, ReactiveContextQueueError> {
        self.query_reactive_context_operation(query)
    }

    fn reconcile_operation(
        &self,
        request: ReactiveContextReconcileRequest,
    ) -> Result<ReactiveContextReconcileOutcome, ReactiveContextQueueError> {
        self.reconcile_reactive_context(request)
    }
}

/// Sole production Host operational-state service.
pub type ProductionHostStateJournal = HostStateJournalService<RedbJournalBackend>;

impl HostStateJournalService<RedbJournalBackend> {
    pub fn open(path: impl AsRef<Path>, host: HostInstallationEpoch) -> Result<Self, JournalError> {
        let backend = RedbJournalBackend::open(path).map_err(JournalError::Backend)?;
        Self::from_backend(backend, host)
    }

    /// Opens the production journal at the exact per-installation Host root
    /// selected by the trusted Runtime Live bootstrap.
    pub fn open_at(
        path: impl AsRef<Path>,
        host: HostInstallationEpoch,
    ) -> Result<Self, JournalError> {
        let backend = RedbJournalBackend::open_at(path).map_err(JournalError::Backend)?;
        Self::from_backend(backend, host)
    }
}
