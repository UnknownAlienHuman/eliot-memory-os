//! Host-side `WakeIntent` cancellation adapter for `UserAutomation` removal.
//!
//! The adapter resolves only exact owner-issued targets against the canonical
//! Host journal.  It copies the retained [`WakeRecord`] and changes its
//! lifecycle state to `Cancelled`; all timing, capability, safety, budget,
//! evidence, Host fence, and existing operation fields remain journal-owned.

use eliot_contracts::sha256_hex;
use eliot_host_state::{
    AppendDisposition, BackendError, HostStateJournalService, HostStateRecord, IdempotencyIdentity,
    JournalBackend, JournalError, record_checksum,
};
use eliot_kernel_service::{
    UserAutomationRuntimeError, UserAutomationWakeCancellation,
    UserAutomationWakeCancellationTarget, UserAutomationWakePort,
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
            if current_checksum != target.record_checksum {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }

            match wake.intent.state {
                WakeIntentState::Pending => {
                    let mut next = wake.clone();
                    next.intent.state = WakeIntentState::Cancelled;
                    let operation = cancellation_identity(&request, target)?;
                    next.operation = operation;
                    match self
                        .journal
                        .append(HostStateRecord::Wake(next))
                        .map_err(map_journal_error)?
                        .disposition()
                    {
                        AppendDisposition::Applied | AppendDisposition::Replayed => {
                            cancelled.push(target.wake_id.clone());
                        }
                    }
                }
                WakeIntentState::Cancelled => {
                    // Exact replay is safe only when the target still binds
                    // to this record.  The target's original checksum guard
                    // above prevents a caller from substituting a later
                    // lifecycle state.
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
        Ok(cancelled)
    }
}

fn cancellation_identity(
    request: &UserAutomationWakeCancellation,
    target: &UserAutomationWakeCancellationTarget,
) -> Result<IdempotencyIdentity, UserAutomationRuntimeError> {
    let bytes = serde_json::to_vec(&(
        "eliot.user_automation.wake-cancellation.v1",
        request.identity.operation_id.as_str(),
        request.identity.idempotency_key.as_str(),
        target.wake_id.as_str(),
        target.operation_id.as_str(),
        target.idempotency_key.as_str(),
    ))
    .map_err(|error| rejected(format!("wake cancellation identity: {error}")))?;
    let digest = sha256_hex(&bytes);
    let operation_id = PlatformHandle::new(format!("ua-wake-cancel:{digest}"))
        .map_err(|_| rejected("wake cancellation operation identity is invalid"))?;
    let idempotency_key = PlatformHandle::new(format!("ua-wake-cancel-key:{digest}"))
        .map_err(|_| rejected("wake cancellation idempotency identity is invalid"))?;
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
