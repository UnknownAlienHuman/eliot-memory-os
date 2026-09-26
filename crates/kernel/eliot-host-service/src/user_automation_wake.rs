//! Host-side `WakeIntent` cancellation adapter for `UserAutomation` removal.
//!
//! The adapter resolves only exact owner-issued targets against the canonical
//! Host journal.  It copies the retained [`WakeRecord`] and changes its
//! lifecycle state to `Cancelled`; all timing, capability, safety, budget,
//! evidence, Host fence, and existing operation fields remain journal-owned.
//!
//! The single-occurrence read path keeps a proven absence distinct from an
//! unreadable owner. The bounded target read emits one entry per accepted
//! normalized occurrence from one journal snapshot, preserving absent and
//! non-Pending identities alongside exact Pending cancellation targets. A
//! successful journal snapshot that holds no such wake is
//! [`UserAutomationRuntimeError::NotRetained`], a complete negative answer; a
//! journal that could not be read is
//! [`UserAutomationRuntimeError::Unavailable`], which proves nothing.  The two
//! are different facts and a caller that must decide whether a retirement has
//! anything left to cancel cannot be given the same value for both.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::sha256_hex;
use eliot_host_state::{
    AppendDisposition, BackendError, HostState, HostStateJournalService, HostStateRecord,
    IdempotencyIdentity, JournalBackend, JournalError, WakeCancellationBatchEntry,
    WakeCancellationBatchRecord, record_checksum,
};
use eliot_kernel_service::{
    UserAutomationRuntimeError, UserAutomationWakeCancellation,
    UserAutomationWakeCancellationTarget, UserAutomationWakePort, UserAutomationWakeReadRequest,
    UserAutomationWakeReadback, UserAutomationWakeTargetSnapshot,
    UserAutomationWakeTargetSnapshotDisposition, UserAutomationWakeTargetSnapshotEntry,
    UserAutomationWakeTargetSnapshotRequest,
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
        request: impl Into<Box<UserAutomationWakeReadRequest>>,
    ) -> Result<UserAutomationWakeReadback, UserAutomationRuntimeError> {
        let request: Box<UserAutomationWakeReadRequest> = request.into();
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
            // The snapshot above was read successfully, so this is a complete
            // negative answer from the sole owner of this journal: it retains no
            // such record. It is deliberately not `Unavailable`, which is what
            // the journal read failure above maps to. A caller must be able to
            // tell "there is nothing here to cancel" from "I could not read what
            // is here", because only the first is a proof.
            UserAutomationRuntimeError::NotRetained(
                "exact UserAutomation wake is not retained by the Host journal".to_owned(),
            )
        })
    }

    async fn read_pending_wake_targets(
        &self,
        request: impl Into<Box<UserAutomationWakeTargetSnapshotRequest>>,
    ) -> Result<UserAutomationWakeTargetSnapshot, UserAutomationRuntimeError> {
        let request: Box<UserAutomationWakeTargetSnapshotRequest> = request.into();
        request
            .validate()
            .map_err(|error| rejected(format!("Wake target snapshot: {error}")))?;

        // One owner snapshot supplies both the complete denominator result and
        // its revision. This operation is observational and never appends.
        let snapshot = self.journal.snapshot().map_err(map_journal_error)?;
        wake_target_snapshot(&request, &snapshot)
    }

    async fn cancel_pending_wakes(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        let request: Box<UserAutomationWakeCancellation> = request.into();
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

fn wake_target_snapshot(
    request: &UserAutomationWakeTargetSnapshotRequest,
    snapshot: &HostState,
) -> Result<UserAutomationWakeTargetSnapshot, UserAutomationRuntimeError> {
    let requested_ids: BTreeSet<&str> = request
        .accepted_occurrence_ids
        .iter()
        .map(String::as_str)
        .collect();
    if requested_ids.len() != request.accepted_occurrence_ids.len() {
        return Err(rejected(
            "wake target snapshot contains duplicate occurrence ids",
        ));
    }

    let mut retained = BTreeMap::new();
    for wake in &snapshot.wakes {
        let wake_id = wake.wake_id.as_str();
        if requested_ids.contains(wake_id) && retained.insert(wake_id, wake).is_some() {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
    }

    let mut entries = Vec::with_capacity(request.accepted_occurrence_ids.len());
    for occurrence_id in &request.accepted_occurrence_ids {
        let disposition = match retained.get(occurrence_id.as_str()) {
            None => UserAutomationWakeTargetSnapshotDisposition::Absent,
            Some(wake) => {
                if wake.wake_id.as_str() != wake.intent.wake_id.as_str()
                    || wake.intent.state_fence != request.state_fence
                {
                    return Err(UserAutomationRuntimeError::IdentityConflict);
                }
                let checksum = record_checksum(&HostStateRecord::Wake((**wake).clone()))
                    .map_err(map_journal_error)?;
                let operation_id = wake.operation.operation_id.as_str().to_owned();
                let idempotency_key = wake.operation.idempotency_key.as_str().to_owned();
                match wake.intent.state {
                    WakeIntentState::Pending => {
                        UserAutomationWakeTargetSnapshotDisposition::Pending {
                            target: UserAutomationWakeCancellationTarget {
                                automation_id: request.automation_id.clone(),
                                automation_revision: request.automation_revision.clone(),
                                wake_id: wake.wake_id.as_str().to_owned(),
                                operation_id,
                                idempotency_key,
                                record_checksum: checksum,
                                state_fence: wake.intent.state_fence.clone(),
                            },
                        }
                    }
                    state => UserAutomationWakeTargetSnapshotDisposition::NonPending {
                        wake_id: wake.wake_id.as_str().to_owned(),
                        state,
                        operation_id,
                        idempotency_key,
                        record_checksum: checksum,
                        state_fence: wake.intent.state_fence.clone(),
                    },
                }
            }
        };
        entries.push(UserAutomationWakeTargetSnapshotEntry {
            occurrence_id: occurrence_id.clone(),
            disposition,
        });
    }

    // Principal, revision and normalized occurrence membership are validated
    // by the Kernel against its canonical revision before this authenticated
    // owner request is sent. HostState's WakeRecord has no typed principal or
    // revision field; Host binds each result to the request and only reports a
    // retained record when the exact journal wake identity and fence agree.
    let result = UserAutomationWakeTargetSnapshot {
        authenticated_principal: request.authenticated_principal.clone(),
        automation_id: request.automation_id.clone(),
        automation_revision: request.automation_revision.clone(),
        identity: request.identity.clone(),
        revision_digest: request.revision_digest.clone(),
        state_fence: request.state_fence.clone(),
        snapshot_sequence: snapshot.sequence,
        entries,
    };
    result
        .validate_for(request)
        .map_err(|error| rejected(format!("Wake target snapshot response: {error}")))?;
    Ok(result)
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
