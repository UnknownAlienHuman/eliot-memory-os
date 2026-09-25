//! Host-side `WakeIntent` cancellation adapter for `UserAutomation` removal.
//!
//! The adapter resolves only exact owner-issued targets against the canonical
//! Host journal.  It copies the retained [`WakeRecord`] and changes its
//! lifecycle state to `Cancelled`; all timing, capability, safety, budget,
//! evidence, Host fence, and existing operation fields remain journal-owned.

use eliot_contracts::sha256_hex;
use eliot_host_state::{
    AppendDisposition, BackendError, HostStateJournalService, HostStateRecord, IdempotencyIdentity,
    JournalBackend, JournalError, WakeCancellationBatchEntry, WakeCancellationBatchRecord,
    record_checksum,
};
use eliot_kernel_service::{
    UserAutomationRuntimeError, UserAutomationWakeCancellation, UserAutomationWakePort,
    UserAutomationWakeReadRequest, UserAutomationWakeReadback,
};
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::WakeIntentState;

/// Concrete Host adapter over the canonical Host operational journal.
pub struct HostWakeIntentAdapter<'a, B: JournalBackend> {
    journal: &'a HostStateJournalService<B>,
}

impl<'a, B: JournalBackend> HostWakeIntentAdapter<'a, B> {
    /// Borrows the sole Host journal owner without creating a second wake
    /// queue or scheduler.
    #[must_use]
    pub const fn new(journal: &'a HostStateJournalService<B>) -> Self {
        Self { journal }
    }
}

impl<B: JournalBackend> UserAutomationWakePort for HostWakeIntentAdapter<'_, B> {
    async fn read_pending_wake(
        &self,
        request: UserAutomationWakeReadRequest,
    ) -> Result<UserAutomationWakeReadback, UserAutomationRuntimeError> {
        let occurrence_id = request
            .validate()
            .map_err(|error| rejected(format!("Wake read: {error}")))?;
        let snapshot = self.journal.snapshot().map_err(map_journal_error)?;
        let mut found = None;
        for wake in snapshot
            .wakes
            .iter()
            .filter(|wake| wake.wake_id.as_str() == occurrence_id)
        {
            if found.is_some() {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }
            let checksum =
                record_checksum(&HostStateRecord::Wake(wake.clone())).map_err(map_journal_error)?;
            let readback = UserAutomationWakeReadback {
                intent: wake.intent.clone(),
                operation_id: wake.operation.operation_id.as_str().to_owned(),
                idempotency_key: wake.operation.idempotency_key.as_str().to_owned(),
                record_checksum: checksum,
            };
            readback
                .validate_for(&request)
                .map_err(|error| rejected(format!("Wake owner readback: {error}")))?;
            found = Some(readback);
        }
        found.ok_or_else(|| {
            UserAutomationRuntimeError::Unavailable(
                "exact UserAutomation wake is not retained by the Host journal".to_owned(),
            )
        })
    }

    async fn cancel_pending_wakes(
        &self,
        request: UserAutomationWakeCancellation,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| rejected(format!("Wake cancellation: {error}")))?;
        if request.targets.is_empty() {
            return Err(rejected(
                "concrete Host wake cancellation requires owner-issued targets",
            ));
        }

        let snapshot = self.journal.snapshot().map_err(map_journal_error)?;
        let mut cancelled = Vec::with_capacity(request.targets.len());
        let mut entries = Vec::with_capacity(request.targets.len());
        for target in &request.targets {
            target
                .validate_for(&request)
                .map_err(|error| rejected(format!("Wake cancellation target: {error}")))?;
            let wake = snapshot
                .wakes
                .iter()
                .find(|wake| wake.wake_id.as_str() == target.wake_id)
                .ok_or_else(|| rejected("owner-issued wake target is absent from Host journal"))?;

            if wake.operation.operation_id.as_str() != target.operation_id
                || wake.operation.idempotency_key.as_str() != target.idempotency_key
            {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }
            if wake.intent.state_fence != request.state_fence
                || wake.intent.state_fence != target.state_fence
            {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }
            let current_checksum =
                record_checksum(&HostStateRecord::Wake(wake.clone())).map_err(map_journal_error)?;
            if current_checksum != target.record_checksum
                && !matches!(wake.intent.state, WakeIntentState::Cancelled)
            {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }

            match wake.intent.state {
                WakeIntentState::Pending => {
                    let mut next = wake.clone();
                    next.intent.state = WakeIntentState::Cancelled;
                    let expected_record_checksum =
                        PlatformHandle::new(target.record_checksum.clone()).map_err(|_| {
                            rejected("wake cancellation checksum identity is invalid")
                        })?;
                    entries.push(WakeCancellationBatchEntry {
                        expected_record_checksum,
                        wake: next,
                    });
                    cancelled.push(target.wake_id.clone());
                }
                WakeIntentState::Cancelled => {
                    // Keep the original operation and expected checksum in
                    // the batch.  After a committed append whose reply was
                    // lost, the current record is already Cancelled and its
                    // checksum has changed; the journal must see the same
                    // batch identity and return Replayed before applying a
                    // second lifecycle transition.
                    let expected_record_checksum =
                        PlatformHandle::new(target.record_checksum.clone()).map_err(|_| {
                            rejected("wake cancellation checksum identity is invalid")
                        })?;
                    entries.push(WakeCancellationBatchEntry {
                        expected_record_checksum,
                        wake: wake.clone(),
                    });
                    cancelled.push(target.wake_id.clone());
                }
                WakeIntentState::Claimed
                | WakeIntentState::Started
                | WakeIntentState::Satisfied
                | WakeIntentState::Expired
                | WakeIntentState::Failed => {
                    return Err(rejected(
                        "Host wake is no longer an unadmitted pending intent",
                    ));
                }
            }
        }
        if entries.is_empty() {
            return Ok(cancelled);
        }
        let fence = entries
            .first()
            .map(|entry| entry.wake.fence.clone())
            .ok_or_else(|| rejected("wake cancellation batch is empty"))?;
        let operation = cancellation_batch_identity(&request, &entries)?;
        let record = HostStateRecord::WakeCancellationBatch(WakeCancellationBatchRecord {
            fence,
            operation,
            entries,
        });
        match self
            .journal
            .append(record)
            .map_err(map_journal_error)?
            .disposition()
        {
            AppendDisposition::Applied | AppendDisposition::Replayed => {}
        }
        Ok(cancelled)
    }
}

fn cancellation_batch_identity(
    request: &UserAutomationWakeCancellation,
    entries: &[WakeCancellationBatchEntry],
) -> Result<IdempotencyIdentity, UserAutomationRuntimeError> {
    let members: Vec<(&str, &str)> = entries
        .iter()
        .map(|entry| {
            (
                entry.wake.wake_id.as_str(),
                entry.expected_record_checksum.as_str(),
            )
        })
        .collect();
    let bytes = serde_json::to_vec(&(
        "eliot.user_automation.wake-cancellation-batch.v1",
        request.identity.operation_id.as_str(),
        request.identity.idempotency_key.as_str(),
        members,
    ))
    .map_err(|error| rejected(format!("wake cancellation batch identity: {error}")))?;
    let digest = sha256_hex(&bytes);
    let operation_id = PlatformHandle::new(format!("ua-wake-cancel-batch:{digest}"))
        .map_err(|_| rejected("wake cancellation batch operation identity is invalid"))?;
    let idempotency_key = PlatformHandle::new(format!("ua-wake-cancel-batch-key:{digest}"))
        .map_err(|_| rejected("wake cancellation batch idempotency identity is invalid"))?;
    Ok(IdempotencyIdentity {
        operation_id,
        idempotency_key,
    })
}

fn map_journal_error(error: JournalError) -> UserAutomationRuntimeError {
    match error {
        JournalError::OutcomeUnknown { transaction_id } => {
            UserAutomationRuntimeError::UnknownOutcome(transaction_id.to_string())
        }
        JournalError::Synchronization
        | JournalError::Backend(
            BackendError::Unavailable | BackendError::PlanGap { .. } | BackendError::Unknown(_),
        ) => UserAutomationRuntimeError::Unavailable(error.to_string()),
        _ => UserAutomationRuntimeError::Rejected(error.to_string()),
    }
}

fn rejected(reason: impl Into<String>) -> UserAutomationRuntimeError {
    UserAutomationRuntimeError::Rejected(reason.into())
}
