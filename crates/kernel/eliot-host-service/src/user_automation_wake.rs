//! Host-side `WakeIntent` cancellation adapter for `UserAutomation` removal.
//!
//! The adapter resolves only exact owner-issued targets against the canonical
//! Host journal.  It copies the retained [`WakeRecord`] and changes its
//! lifecycle state to `Cancelled`; all admission material, including the
//! retained origin operation, remains journal-owned. Cancellation is one
//! atomic batch operation, while each WakeRecord keeps its lifecycle
//! operation unchanged.

use eliot_contracts::sha256_hex;
use eliot_host_state::{
    AppendDisposition, BackendError, HostState, HostStateJournalService, HostStateRecord,
    IdempotencyIdentity, JournalBackend, JournalError, WakeCancellationBatchEntry,
    WakeCancellationBatchRecord, WakeRecord, record_checksum,
};
use eliot_kernel_service::{
    UserAutomationRuntimeError, UserAutomationWakeCancellation, UserAutomationWakePort,
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
        let mut entries = Vec::with_capacity(request.targets.len());
        let mut operation_target_checksums = Vec::with_capacity(request.targets.len());
        for target in &request.targets {
            target
                .validate_for(&request)
                .map_err(|error| rejected(format!("Wake cancellation target: {error}")))?;
            let wake = snapshot
                .wakes
                .iter()
                .find(|wake| wake.wake_id.as_str() == target.wake_id)
                .ok_or_else(|| rejected("owner-issued wake target is absent from Host journal"))?;

            if wake.origin_operation.operation_id.as_str() != target.operation_id
                || wake.origin_operation.idempotency_key.as_str() != target.idempotency_key
            {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }
            if wake.intent.state_fence != request.state_fence
                || wake.intent.state_fence != target.state_fence
            {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }
            let (expected_checksum, operation_checksum) =
                canonical_cancellation_target(&snapshot, wake, &target.record_checksum)?;
            match wake.intent.state {
                WakeIntentState::Pending => {
                    let current_checksum = record_checksum(&HostStateRecord::Wake(wake.clone()))
                        .map_err(map_journal_error)?;
                    if current_checksum != expected_checksum {
                        return Err(UserAutomationRuntimeError::IdentityConflict);
                    }
                    let mut next = wake.clone();
                    next.intent.state = WakeIntentState::Cancelled;
                    let expected_record_checksum =
                        PlatformHandle::new(expected_checksum.clone()).map_err(|_| {
                            rejected("wake cancellation checksum identity is invalid")
                        })?;
                    entries.push(WakeCancellationBatchEntry {
                        expected_record_checksum,
                        wake: next,
                    });
                    cancelled.push(target.wake_id.clone());
                }
                WakeIntentState::Cancelled => {
                    // After a committed append whose reply was lost, the
                    // current record is already Cancelled and its checksum
                    // has changed. Rebuild the same batch identity from the
                    // original target checksum; the journal's operation ledger
                    // returns Replayed before another transition.
                    let expected_record_checksum =
                        PlatformHandle::new(expected_checksum.clone()).map_err(|_| {
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
            operation_target_checksums.push(operation_checksum);
        }
        if entries.is_empty() {
            return Ok(cancelled);
        }
        let fence = entries
            .first()
            .map(|entry| entry.wake.fence.clone())
            .ok_or_else(|| rejected("wake cancellation batch is empty"))?;
        let operation = cancellation_batch_identity(&request, &operation_target_checksums)?;
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

/// Reconciles an owner-issued target checksum against the canonical pending
/// WakeRecord material retained by the Host journal. A legacy frame may have a
/// raw checksum that predates `origin_operation`; the applied-operation ledger
/// is the only owner evidence allowed to map it to the migrated canonical
/// checksum. The full pending record is recomputed from the retained wake, so
/// a caller cannot supply a compatibility token or bypass changed material.
fn canonical_cancellation_target(
    snapshot: &HostState,
    wake: &WakeRecord,
    target_checksum: &str,
) -> Result<(String, String), UserAutomationRuntimeError> {
    let mut pending = wake.clone();
    pending.intent.state = WakeIntentState::Pending;
    pending.operation = pending.origin_operation.clone();
    let canonical_checksum = record_checksum(&HostStateRecord::Wake(pending))
        .map_err(map_journal_error)?;
    let applied = snapshot
        .applied_operations
        .iter()
        .find(|item| {
            item.identity == wake.origin_operation
                && (item.checksum == target_checksum
                    || item.compatibility_checksum.as_deref() == Some(target_checksum))
        })
        .ok_or(UserAutomationRuntimeError::IdentityConflict)?;
    let canonical_matches = applied
        .compatibility_checksum
        .as_deref()
        .is_some_and(|value| value == canonical_checksum)
        || (applied.compatibility_checksum.is_none() && applied.checksum == canonical_checksum);
    if !canonical_matches {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    Ok((canonical_checksum, applied.checksum.clone()))
}

fn cancellation_batch_identity(
    request: &UserAutomationWakeCancellation,
    target_checksums: &[String],
) -> Result<IdempotencyIdentity, UserAutomationRuntimeError> {
    if target_checksums.len() != request.targets.len() {
        return Err(rejected(
            "wake cancellation identity target count does not match request",
        ));
    }
    let members: Vec<(&str, &str)> = request
        .targets
        .iter()
        .zip(target_checksums)
        .map(|(target, checksum)| (target.wake_id.as_str(), checksum.as_str()))
        .collect();
    let bytes = serde_json::to_vec(&(
        "eliot.user_automation.wake-cancellation-batch.v1",
        request.identity.operation_id.as_str(),
        request.identity.idempotency_key.as_str(),
        members,
    ))
    .map_err(|error| rejected(format!("wake cancellation identity: {error}")))?;
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
