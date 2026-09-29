//! Host-side `WakeIntent` cancellation adapter for `UserAutomation` removal.
//!
//! The adapter resolves only exact owner-issued targets against the canonical
//! Host journal.  It copies the retained [`WakeRecord`] and changes its
//! lifecycle state to `Cancelled`; all timing, capability, safety, budget,
//! evidence, Host fence, and existing operation fields remain journal-owned.
//!
//! The read path keeps a proven absence distinct from an unreadable owner.  A
//! successful journal snapshot that holds no such wake is
//! [`UserAutomationRuntimeError::NotRetained`], a complete negative answer; a
//! journal that could not be read is
//! [`UserAutomationRuntimeError::Unavailable`], which proves nothing.  The two
//! are different facts and a caller that must decide whether a retirement has
//! anything left to cancel cannot be given the same value for both.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_host_state::{
    AppendDisposition, BackendError, HostState, HostStateJournalService, HostStateRecord,
    IdempotencyIdentity, JournalBackend, JournalError, WakeCancellationBatchEntry,
    WakeCancellationBatchQuery, WakeCancellationBatchQueryError, WakeCancellationBatchRecord,
    host_owner_epoch_digest, record_checksum,
};
use eliot_kernel_service::{
    USER_AUTOMATION_WAKE_ENUMERATION_RECEIPT_VERSION, UserAutomationRuntimeError,
    UserAutomationWakeCancellation, UserAutomationWakeCancellationReadback,
    UserAutomationWakeEnumerationCoverage, UserAutomationWakeEnumerationReceipt,
    UserAutomationWakeEnumerationRequest, UserAutomationWakeOccurrenceDisposition,
    UserAutomationWakeOwnerEvidence, UserAutomationWakePort, UserAutomationWakeReadRequest,
    UserAutomationWakeReadback,
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
        if request.enumeration_receipt.is_none() {
            return Err(rejected(
                "concrete Host wake cancellation requires the exact persisted enumeration receipt",
            ));
        }

        let snapshot = self.journal.snapshot().map_err(map_journal_error)?;
        let receipt = request
            .enumeration_receipt
            .as_deref()
            .ok_or_else(|| rejected("wake enumeration receipt is absent"))?;
        validate_enumeration_snapshot(&snapshot, &request, receipt)?;
        let (cancelled, entries) = build_cancellation_entries(&snapshot, &request)?;
        if entries.is_empty() {
            return Ok(cancelled);
        }
        let fence = entries
            .first()
            .map(|entry| entry.wake.fence.clone())
            .ok_or_else(|| rejected("wake cancellation batch is empty"))?;
        let (operation_id, idempotency_key) = request
            .host_batch_operation_identity()
            .map_err(|error| rejected(format!("wake cancellation batch identity: {error}")))?;
        let operation = IdempotencyIdentity {
            operation_id: PlatformHandle::new(operation_id)
                .map_err(|_| rejected("wake cancellation batch operation identity is invalid"))?,
            idempotency_key: PlatformHandle::new(idempotency_key)
                .map_err(|_| rejected("wake cancellation batch idempotency identity is invalid"))?,
        };
        let request_commitment_sha256 = request
            .request_commitment_sha256()
            .map_err(|error| rejected(format!("wake cancellation request commitment: {error}")))?;
        let record = HostStateRecord::WakeCancellationBatch(WakeCancellationBatchRecord {
            fence,
            operation,
            request_commitment_sha256: Some(request_commitment_sha256),
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

    async fn read_cancellation_batch_authenticated(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
        authenticated_channel_binding_sha256: String,
    ) -> Result<UserAutomationWakeCancellationReadback, UserAutomationRuntimeError> {
        let request: Box<UserAutomationWakeCancellation> = request.into();
        request
            .validate()
            .map_err(|error| rejected(format!("wake cancellation readback: {error}")))?;
        validate_sha256(&authenticated_channel_binding_sha256)?;
        let (operation_id, idempotency_key) = request
            .host_batch_operation_identity()
            .map_err(|error| rejected(format!("wake cancellation batch identity: {error}")))?;
        let operation = IdempotencyIdentity {
            operation_id: PlatformHandle::new(operation_id)
                .map_err(|_| rejected("wake cancellation batch operation identity is invalid"))?,
            idempotency_key: PlatformHandle::new(idempotency_key)
                .map_err(|_| rejected("wake cancellation batch idempotency identity is invalid"))?,
        };
        let request_commitment_sha256 = request
            .request_commitment_sha256()
            .map_err(|error| rejected(format!("wake cancellation request commitment: {error}")))?;
        let observation = self
            .journal
            .query_wake_cancellation_batch(&WakeCancellationBatchQuery {
                operation: operation.clone(),
                request_commitment_sha256: request_commitment_sha256.clone(),
            })
            .map_err(map_cancellation_query_error)?;
        let record = observation.record();
        if record.operation != operation
            || record.request_commitment_sha256.as_deref()
                != Some(request_commitment_sha256.as_str())
            || record.entries.len() != request.targets.len()
            || record
                .entries
                .iter()
                .zip(&request.targets)
                .any(|(entry, target)| {
                    entry.wake.wake_id.as_str() != target.wake_id
                        || entry.wake.operation.operation_id.as_str() != target.operation_id
                        || entry.wake.operation.idempotency_key.as_str() != target.idempotency_key
                        || entry.expected_record_checksum.as_str() != target.record_checksum
                        || entry.wake.intent.state_fence != target.state_fence
                        || entry.wake.intent.state != WakeIntentState::Cancelled
                })
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let readback = UserAutomationWakeCancellationReadback {
            batch_operation_id: operation.operation_id.as_str().to_owned(),
            batch_idempotency_key: operation.idempotency_key.as_str().to_owned(),
            request_commitment_sha256,
            record_checksum: observation.record_checksum().to_owned(),
            journal_sequence: observation.receipt().sequence(),
            journal_transaction_id: observation.receipt().transaction_id().as_str().to_owned(),
            cancelled_wake_ids: record
                .entries
                .iter()
                .map(|entry| entry.wake.wake_id.as_str().to_owned())
                .collect(),
        };
        readback
            .validate_for(&request)
            .map_err(|_| UserAutomationRuntimeError::IdentityConflict)?;
        Ok(readback)
    }

    async fn enumerate_pending_wakes_authenticated(
        &self,
        request: impl Into<Box<UserAutomationWakeEnumerationRequest>>,
        authenticated_channel_binding_sha256: String,
    ) -> Result<UserAutomationWakeEnumerationReceipt, UserAutomationRuntimeError> {
        let request: Box<UserAutomationWakeEnumerationRequest> = request.into();
        request
            .validate()
            .map_err(|error| rejected(format!("Wake enumeration request: {error}")))?;
        validate_sha256(&authenticated_channel_binding_sha256)?;

        let snapshot = self.journal.snapshot().map_err(map_journal_error)?;
        let snapshot_evidence = HostWakeSnapshotEvidence::new(&snapshot)?;
        let dispositions = request
            .denominator
            .iter()
            .map(|occurrence| {
                enumerate_occurrence(
                    &request,
                    &snapshot,
                    &snapshot_evidence,
                    &occurrence.occurrence_id,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut receipt = UserAutomationWakeEnumerationReceipt {
            version: USER_AUTOMATION_WAKE_ENUMERATION_RECEIPT_VERSION,
            automation_id: request.automation_id.clone(),
            automation_revision: request.automation_revision.clone(),
            revision_digest: request.revision_digest.clone(),
            parent_operation_identity: request.identity.clone(),
            denominator: request.denominator.clone(),
            denominator_digest: request.denominator_digest.clone(),
            host_owner_identity: snapshot_evidence.host_owner_identity,
            host_owner_generation: snapshot_evidence.host_owner_generation,
            journal_sequence: snapshot.sequence,
            journal_last_checksum: snapshot_evidence.journal_last_checksum,
            authenticated_channel_binding_sha256,
            snapshot_digest: snapshot_evidence.snapshot_digest,
            state_fence: request.context.state_fence.clone(),
            authenticated_owner_identity: request.authenticated_principal.clone(),
            coverage: enumeration_coverage(&dispositions),
            dispositions,
            canonical_digest: String::new(),
        };
        receipt.canonical_digest = receipt
            .compute_digest()
            .map_err(|error| rejected(format!("Wake receipt digest: {error}")))?;
        receipt
            .validate_for(&request)
            .map_err(|error| rejected(format!("Wake receipt validation: {error}")))?;
        Ok(receipt)
    }
}

struct HostWakeSnapshotEvidence {
    host_owner_identity: String,
    host_owner_generation: String,
    journal_last_checksum: Option<String>,
    snapshot_digest: String,
}

impl HostWakeSnapshotEvidence {
    fn new(snapshot: &HostState) -> Result<Self, UserAutomationRuntimeError> {
        let host_owner_identity = snapshot.host.installation.as_str().to_owned();
        let host_owner_generation = host_owner_epoch_digest(&snapshot.host)
            .map_err(map_journal_error)?
            .as_str()
            .to_owned();
        let journal_last_checksum = snapshot
            .last_checksum
            .as_ref()
            .map(|value| value.as_str().to_owned());
        if let Some(checksum) = &journal_last_checksum {
            validate_sha256(checksum)?;
        }
        let snapshot_digest = sha256_hex(
            &canonical_json_bytes(&(
                "eliot.user_automation.host-wake-snapshot.v1",
                &host_owner_identity,
                &host_owner_generation,
                snapshot.sequence,
                &journal_last_checksum,
                &snapshot.wakes,
            ))
            .map_err(|error| rejected(format!("Wake snapshot encoding: {error}")))?,
        );
        Ok(Self {
            host_owner_identity,
            host_owner_generation,
            journal_last_checksum,
            snapshot_digest,
        })
    }
}

fn enumerate_occurrence(
    request: &UserAutomationWakeEnumerationRequest,
    snapshot: &HostState,
    snapshot_evidence: &HostWakeSnapshotEvidence,
    occurrence_id: &str,
) -> Result<UserAutomationWakeOccurrenceDisposition, UserAutomationRuntimeError> {
    let evidence = UserAutomationWakeOwnerEvidence {
        occurrence_id: occurrence_id.to_owned(),
        host_owner_identity: snapshot_evidence.host_owner_identity.clone(),
        host_owner_generation: snapshot_evidence.host_owner_generation.clone(),
        journal_sequence: snapshot.sequence,
        journal_last_checksum: snapshot_evidence.journal_last_checksum.clone(),
        snapshot_digest: snapshot_evidence.snapshot_digest.clone(),
        wake_record_checksum: None,
        wake_state: None,
    };
    let mut matches = snapshot
        .wakes
        .iter()
        .filter(|wake| wake.wake_id.as_str() == occurrence_id);
    let Some(wake) = matches.next() else {
        return Ok(UserAutomationWakeOccurrenceDisposition::NotRetained { evidence });
    };
    if matches.next().is_some() {
        return Ok(UserAutomationWakeOccurrenceDisposition::Unresolved {
            evidence,
            reason: "the one Host snapshot contains duplicate records for this occurrence"
                .to_owned(),
        });
    }
    let checksum =
        record_checksum(&HostStateRecord::Wake(wake.clone())).map_err(map_journal_error)?;
    let mut evidence = evidence;
    evidence.wake_record_checksum = Some(checksum.clone());
    evidence.wake_state = Some(wake.intent.state);
    if wake.intent.wake_id != occurrence_id {
        return Ok(UserAutomationWakeOccurrenceDisposition::Unresolved {
            evidence,
            reason: "the retained Host record identity conflicts with the denominator member"
                .to_owned(),
        });
    }
    if wake.intent.state != WakeIntentState::Pending {
        return Ok(UserAutomationWakeOccurrenceDisposition::NotRetained { evidence });
    }
    if wake.intent.state_fence != request.context.state_fence {
        return Ok(UserAutomationWakeOccurrenceDisposition::Unresolved {
            evidence,
            reason: "the retained pending Host record belongs to a different State Fence"
                .to_owned(),
        });
    }
    Ok(UserAutomationWakeOccurrenceDisposition::PendingTarget {
        target: eliot_kernel_service::UserAutomationWakeCancellationTarget {
            automation_id: request.automation_id.clone(),
            automation_revision: request.automation_revision.clone(),
            wake_id: wake.wake_id.as_str().to_owned(),
            operation_id: wake.operation.operation_id.as_str().to_owned(),
            idempotency_key: wake.operation.idempotency_key.as_str().to_owned(),
            record_checksum: checksum,
            state_fence: wake.intent.state_fence.clone(),
        },
    })
}

fn validate_enumeration_snapshot(
    snapshot: &HostState,
    request: &UserAutomationWakeCancellation,
    receipt: &UserAutomationWakeEnumerationReceipt,
) -> Result<(), UserAutomationRuntimeError> {
    let current_owner_generation = host_owner_epoch_digest(&snapshot.host)
        .map_err(map_journal_error)?
        .as_str()
        .to_owned();
    if receipt.host_owner_identity != snapshot.host.installation.as_str()
        || receipt.host_owner_generation != current_owner_generation
        || receipt.state_fence != request.state_fence
        || receipt.authenticated_owner_identity != request.authenticated_principal
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    for (occurrence, disposition) in receipt.denominator.iter().zip(&receipt.dispositions) {
        let mut current = snapshot
            .wakes
            .iter()
            .filter(|wake| wake.wake_id.as_str() == occurrence.occurrence_id);
        let Some(wake) = current.next() else {
            continue;
        };
        if current.next().is_some()
            || (matches!(
                disposition,
                UserAutomationWakeOccurrenceDisposition::NotRetained { .. }
            ) && wake.intent.state == WakeIntentState::Pending)
            || matches!(
                disposition,
                UserAutomationWakeOccurrenceDisposition::Unresolved { .. }
            )
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
    }
    Ok(())
}

fn build_cancellation_entries(
    snapshot: &HostState,
    request: &UserAutomationWakeCancellation,
) -> Result<(Vec<String>, Vec<WakeCancellationBatchEntry>), UserAutomationRuntimeError> {
    let mut cancelled = Vec::with_capacity(request.targets.len());
    let mut entries = Vec::with_capacity(request.targets.len());
    for target in &request.targets {
        target
            .validate_for(request)
            .map_err(|error| rejected(format!("Wake cancellation target: {error}")))?;
        let mut matching = snapshot
            .wakes
            .iter()
            .filter(|wake| wake.wake_id.as_str() == target.wake_id);
        let wake = matching
            .next()
            .ok_or_else(|| rejected("owner-issued wake target is absent from Host journal"))?;
        if matching.next().is_some()
            || wake.operation.operation_id.as_str() != target.operation_id
            || wake.operation.idempotency_key.as_str() != target.idempotency_key
            || wake.intent.state_fence != request.state_fence
            || wake.intent.state_fence != target.state_fence
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let checksum =
            record_checksum(&HostStateRecord::Wake(wake.clone())).map_err(map_journal_error)?;
        if checksum != target.record_checksum && wake.intent.state != WakeIntentState::Cancelled {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        match wake.intent.state {
            WakeIntentState::Pending | WakeIntentState::Cancelled => {
                let next = if wake.intent.state == WakeIntentState::Pending {
                    let mut next = wake.clone();
                    next.intent.state = WakeIntentState::Cancelled;
                    next
                } else {
                    wake.clone()
                };
                let expected_record_checksum = PlatformHandle::new(target.record_checksum.clone())
                    .map_err(|_| rejected("wake cancellation checksum identity is invalid"))?;
                entries.push(WakeCancellationBatchEntry {
                    expected_record_checksum,
                    wake: next,
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
    Ok((cancelled, entries))
}

fn enumeration_coverage(
    dispositions: &[UserAutomationWakeOccurrenceDisposition],
) -> UserAutomationWakeEnumerationCoverage {
    let mut pending_target_count = 0_u64;
    let mut not_retained_count = 0_u64;
    let mut unresolved_count = 0_u64;
    for disposition in dispositions {
        match disposition {
            UserAutomationWakeOccurrenceDisposition::PendingTarget { .. } => {
                pending_target_count += 1;
            }
            UserAutomationWakeOccurrenceDisposition::NotRetained { .. } => {
                not_retained_count += 1;
            }
            UserAutomationWakeOccurrenceDisposition::Unresolved { .. } => {
                unresolved_count += 1;
            }
        }
    }
    let covered_count = dispositions.len() as u64;
    UserAutomationWakeEnumerationCoverage {
        denominator_count: covered_count,
        covered_count,
        pending_target_count,
        not_retained_count,
        unresolved_count,
        complete: true,
    }
}

fn validate_sha256(value: &str) -> Result<(), UserAutomationRuntimeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(rejected(
            "authenticated wake enumeration evidence digest is invalid",
        ));
    }
    Ok(())
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

fn map_cancellation_query_error(
    error: WakeCancellationBatchQueryError,
) -> UserAutomationRuntimeError {
    match error {
        WakeCancellationBatchQueryError::NotFound
        | WakeCancellationBatchQueryError::LegacyUnbound
        | WakeCancellationBatchQueryError::RequestCommitmentMismatch
        | WakeCancellationBatchQueryError::Contradictory
        | WakeCancellationBatchQueryError::MissingReceipt
        | WakeCancellationBatchQueryError::Invalid(_)
        | WakeCancellationBatchQueryError::Journal(_) => {
            UserAutomationRuntimeError::UnknownOutcome(
                "the exact Host cancellation batch is absent, conflicting, or unreadable; the original operation remains reconciling"
                    .to_owned(),
            )
        }
    }
}

fn rejected(reason: impl Into<String>) -> UserAutomationRuntimeError {
    UserAutomationRuntimeError::Rejected(reason.into())
}
