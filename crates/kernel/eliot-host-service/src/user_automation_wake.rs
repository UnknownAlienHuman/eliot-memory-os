//! Host-side `WakeIntent` publication and cancellation adapter for
//! `UserAutomation`.
//!
//! Publication writes one canonical [`WakeRecord`] per requested occurrence
//! through the same Host journal that owns every other wake; cancellation
//! resolves only exact owner-issued targets against that journal.  The
//! cancellation path copies the retained [`WakeRecord`] and changes its
//! lifecycle state to `Cancelled`; all timing, capability, safety, budget,
//! evidence, Host fence, and existing operation fields remain journal-owned.
//!
//! The read path keeps a proven absence distinct from an unreadable owner.  A
//! successful journal snapshot that holds no such wake — whether one exact
//! occurrence or a whole published horizon — is
//! [`UserAutomationRuntimeError::NotRetained`], a complete negative answer; a
//! journal that could not be read is
//! [`UserAutomationRuntimeError::Unavailable`], which proves nothing.  The two
//! are different facts and a caller that must decide whether a retirement has
//! anything left to cancel, or whether a published horizon is still retained,
//! cannot be given the same value for both.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_host_state::{
    AppendDisposition, BackendError, HostState, HostStateJournalService, HostStateRecord,
    IdempotencyIdentity, JournalBackend, JournalError, RecordFence, ServiceSafetyClass,
    WakeCancellationBatchEntry, WakeCancellationBatchQuery, WakeCancellationBatchQueryError,
    WakeCancellationBatchRecord, WakeRecord, host_owner_epoch_digest, record_checksum,
};
use eliot_kernel_service::{
    USER_AUTOMATION_KERNEL_CAPABILITY, USER_AUTOMATION_WAKE_ENUMERATION_RECEIPT_VERSION,
    UserAutomationRuntimeError, UserAutomationWakeCancellation,
    UserAutomationWakeCancellationReadback, UserAutomationWakeEnumerationCoverage,
    UserAutomationWakeEnumerationReceipt, UserAutomationWakeEnumerationRequest,
    UserAutomationWakeHorizonEntry, UserAutomationWakeHorizonPublication,
    UserAutomationWakeOccurrenceDisposition, UserAutomationWakeOwnerEvidence,
    UserAutomationWakePort, UserAutomationWakePublication, UserAutomationWakeReadRequest,
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
    /// Publishes one bounded recurring horizon into the canonical Host wake
    /// journal, one [`WakeRecord`] per requested occurrence.
    ///
    /// The occurrence denominator is the caller's. This adapter never compiles,
    /// widens, reorders or extends it: it copies each requested entry's own
    /// owner-contract [`WakeIntent`](eliot_runtime_contracts::WakeIntent) and
    /// binds it to the automation, the immutable revision and its digest, the
    /// stable occurrence identity, the owner-normalized trigger basis, the exact
    /// State Fence, and the activation generation whose fence owns the journal
    /// record. Every journal field is a pure function of that immutable content
    /// plus the live Host activation fence, so a replay of the same publication
    /// re-derives byte-identical records.
    ///
    /// Duplicate safety is the journal's own, not a second scheme here:
    /// [`HostStateJournalService::append`] resolves a repeated
    /// [`IdempotencyIdentity`] through the reducer's `applied_operations`
    /// index and answers [`AppendDisposition::Replayed`] without writing a
    /// second frame, so a restart — and a second whole-denominator publication
    /// of the same revision through a different parent operation, such as
    /// `Resume` over a paused automation — retains exactly the same wakes.
    ///
    /// Any journal refusal is returned as its typed error instead of a partial
    /// acknowledgement. The owner then has no answer at all, and the caller
    /// keeps the exact requested set and its replay handle rather than a
    /// horizon it may report as published.
    async fn publish_wake_horizon(
        &self,
        request: impl Into<Box<UserAutomationWakeHorizonPublication>>,
    ) -> Result<UserAutomationWakePublication, UserAutomationRuntimeError> {
        let request: Box<UserAutomationWakeHorizonPublication> = request.into();
        request
            .validate()
            .map_err(|error| rejected(format!("Wake horizon publication: {error}")))?;
        validate_horizon_denominator(&request)?;
        let fence = live_activation_fence(&self.journal.snapshot().map_err(map_journal_error)?)?;
        for entry in &request.entries {
            let record = horizon_wake_record(&request, entry, fence.clone())?;
            match self
                .journal
                .append(HostStateRecord::Wake(record))
                .map_err(map_journal_error)?
                .disposition()
            {
                // Both dispositions are the same retained wake. `Replayed` is the
                // journal's own answer for an identity it already applied, and
                // it writes no second frame, which is what makes a repeated
                // publication and a restart create no duplicate wake.
                AppendDisposition::Applied | AppendDisposition::Replayed => {}
            }
        }
        // The acknowledgement is read back from the journal rather than
        // assumed from the appends. An append disposition alone does not prove
        // the wake is still retained: an activation-generation change clears
        // the wake projection, so a repeated identity can replay onto a record
        // this journal no longer holds. Naming that occurrence as acknowledged
        // would report a published horizon that no wake exists for, so the exact
        // remaining set and its retry handle are returned instead. The readback
        // re-derives its identities from the snapshot's own live generation, so
        // such an occurrence is a genuinely re-publishable one under that
        // generation and the handle it is named with is redeemable.
        let snapshot = self.journal.snapshot().map_err(map_journal_error)?;
        let (acknowledged, remaining) = retained_horizon_occurrences(&request, &snapshot)?;
        horizon_acknowledgement(&request, acknowledged, remaining)
    }

    /// Reconciles one exact horizon publication with this owner's retained
    /// records.
    ///
    /// The answer is only what this journal actually holds. A snapshot that was
    /// read successfully and holds no wake for a requested occurrence under the
    /// activation generation that owns it is
    /// [`UserAutomationRuntimeError::NotRetained`], a complete negative answer
    /// from the sole writer; a journal that could not be read is
    /// [`UserAutomationRuntimeError::Unavailable`], which proves nothing. A
    /// retained record for a requested occurrence that was published under
    /// another operation identity or carries another intent is a contradiction
    /// this publication can neither answer for nor replace, and is reported as
    /// [`UserAutomationRuntimeError::IdentityConflict`] rather than as an
    /// acknowledgement.
    async fn read_wake_horizon_publication(
        &self,
        request: impl Into<Box<UserAutomationWakeHorizonPublication>>,
    ) -> Result<UserAutomationWakePublication, UserAutomationRuntimeError> {
        let request: Box<UserAutomationWakeHorizonPublication> = request.into();
        request
            .validate()
            .map_err(|error| rejected(format!("Wake horizon publication readback: {error}")))?;
        validate_horizon_denominator(&request)?;
        let snapshot = self.journal.snapshot().map_err(map_journal_error)?;
        let (acknowledged, remaining) = retained_horizon_occurrences(&request, &snapshot)?;
        if acknowledged.is_empty() {
            // The snapshot above was read successfully, so this is a complete
            // negative answer from the sole owner of this journal: it retains no
            // wake for any requested occurrence under the activation generation
            // that currently owns it. It is deliberately not `Unavailable`, and
            // it is not proof that a lost publication call never issued its
            // effect — only that this owner holds nothing for the occurrences
            // being reconciled. Any remainder it does name is re-publishable
            // under that generation, so the handle it returns stays redeemable.
            return Err(UserAutomationRuntimeError::NotRetained(
                "the Host journal retains no wake for this horizon publication's occurrences under the live activation generation"
                    .to_owned(),
            ));
        }
        horizon_acknowledgement(&request, acknowledged, remaining)
    }

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
            .map_err(|error| map_cancellation_query_error(&error))?;
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

/// Domain separator for the deterministic per-occurrence Host operation
/// identity of one bounded horizon publication.
const WAKE_HORIZON_OPERATION_DOMAIN: &str = "eliot.user_automation.wake-horizon-publication.v1";

/// Checks the requested slice against the denominator the request itself
/// declares.
///
/// `UserAutomationWakeHorizonPublication::validate` proves the denominator is a
/// unique, non-empty list and the entries are well formed, but it cannot see
/// the revision. This owner does not hold the revision either, so it checks the
/// relation it can prove from the request alone: the published slice must be a
/// contiguous run of the declared denominator in that denominator's own order.
/// An occurrence outside the denominator, a gap, or a reordering is refused
/// before any record is written, so this owner can neither widen nor reorder
/// nor extend the publication's occurrence denominator.
fn validate_horizon_denominator(
    request: &UserAutomationWakeHorizonPublication,
) -> Result<(), UserAutomationRuntimeError> {
    let denominator = &request.denominator_occurrence_ids;
    let start = denominator
        .iter()
        .position(|occurrence_id| *occurrence_id == request.entries[0].occurrence_id)
        .ok_or_else(|| {
            rejected("the published slice starts outside the declared occurrence denominator")
        })?;
    for (offset, entry) in request.entries.iter().enumerate() {
        if denominator.get(start + offset) != Some(&entry.occurrence_id) {
            return Err(rejected(
                "the published slice is not a contiguous run of the declared occurrence \
                 denominator in its own order",
            ));
        }
    }
    Ok(())
}

/// Splits the exact requested occurrence set into what this journal actually
/// retains for it and what it does not.
///
/// This is the single accounting used by both publication and its readback, so
/// the two can never disagree about what the owner holds. A requested
/// occurrence with no retained record is `remaining`, never silently
/// acknowledged; a retained record that carries another operation identity or
/// another intent is a contradiction this publication can neither answer for
/// nor replace, and is refused rather than reported as a partial success.
///
/// The requested identities are derived from this snapshot's own live
/// activation fence, which is the fence of every wake record the reducer can
/// leave in place: it clears the whole wake projection at an activation cutover,
/// so a retained wake and the live generation that owns it are always the same
/// journal's fact. That is also what makes every entry in `remaining` honestly
/// retryable — an occurrence this journal does not hold under the current
/// generation has no `applied_operations` entry for the identity the retry would
/// re-derive, so re-presenting it is a genuine new publication rather than a
/// replay the reducer would refuse with `IdempotencyConflict`. A `remaining` set
/// that named work the journal has already applied and can no longer accept
/// would be a retry handle the owner could never keep.
///
/// The retained record is validated by the owner's own checksum function, which
/// re-runs `WakeRecord::validate` on the ORIGINAL value read back from this
/// journal. No digest is recomputed and no value is rebuilt here.
fn retained_horizon_occurrences(
    request: &UserAutomationWakeHorizonPublication,
    snapshot: &HostState,
) -> Result<(Vec<String>, Vec<String>), UserAutomationRuntimeError> {
    let live_fence = live_activation_fence(snapshot).ok();
    let mut acknowledged = Vec::with_capacity(request.entries.len());
    let mut remaining = Vec::new();
    for entry in &request.entries {
        let mut retained = snapshot
            .wakes
            .iter()
            .filter(|wake| wake.wake_id.as_str() == entry.occurrence_id.as_str());
        let Some(wake) = retained.next() else {
            remaining.push(entry.occurrence_id.clone());
            continue;
        };
        if retained.next().is_some() {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        // A retained wake with no live activation to own it is a contradiction
        // the reducer cannot produce, and the identity it was published under
        // cannot be re-derived from this snapshot, so this owner can neither
        // account for it nor replace it.
        let fence = live_fence.as_ref().ok_or_else(|| {
            rejected("the Host journal retains a wake under no live activation generation")
        })?;
        if wake.operation != horizon_wake_operation_identity(request, entry, fence)?
            || wake.intent != entry.wake_intent
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        record_checksum(&HostStateRecord::Wake(wake.clone())).map_err(map_journal_error)?;
        acknowledged.push(entry.occurrence_id.clone());
    }
    Ok((acknowledged, remaining))
}

/// Returns the current Host activation fence that owns every journal record.
///
/// The fence is the journal's own, read from the live activation projection
/// rather than supplied by a caller: the reducer refuses a record whose
/// activation identity or generation is not the current one, so a wake cannot
/// be retained under a fence this Host does not hold. A journal with no live
/// activation has no fence to write under, which is a typed refusal here and
/// not a synthesized one.
fn live_activation_fence(snapshot: &HostState) -> Result<RecordFence, UserAutomationRuntimeError> {
    snapshot
        .activation
        .as_ref()
        .map(|activation| activation.fence.clone())
        .ok_or_else(|| {
            rejected("the Host journal retains no live activation generation to own a wake record")
        })
}

/// Derives the Host journal operation identity of one published occurrence.
///
/// The identity is a pure function of the immutable revision and its digest, the
/// occurrence's own compiled identity, trigger key and source digest, and the
/// activation generation whose fence owns the record. The parent publication
/// operation identity is deliberately NOT an input.
///
/// `Pause` and `Resume` admit the same immutable revision through different
/// operator operations, and `Resume` re-derives the same occurrence identities
/// (I11.12: "Duplicate wake/restart events resolve to the same occurrence"). If
/// the parent operation were an input, that second publication would derive a
/// different identity for a wake the journal already retains, and the reducer —
/// which locates an existing wake by `wake_id` and has no `Pending -> Pending`
/// edge — would refuse it forever, so the documented
/// `Create` -> `Pause` -> `Resume` path could never publish. Deriving the
/// identity from the occurrence and the revision instead makes every
/// whole-denominator publication of one revision the same operation, so a
/// `Resume` is a genuine `Replayed` on the identical `WakeRecord` and creates no
/// second wake, while a different occurrence or a different revision digest
/// yields a different identity and is a genuinely new publication.
///
/// The activation generation is an input because the journal's own reducer
/// clears its entire wake projection at an activation cutover
/// (`eliot_host_state::journal`), while `applied_operations` survives. Binding
/// the identity to the owning generation is what keeps that asymmetry honest:
/// after a cutover the re-presentation is a new generation's first publication
/// of a wake the owner has provably discarded, not a second attempt at an
/// identity whose recorded checksum can never match again. The journal resolves
/// a repeated identity through its own `applied_operations` index and answers
/// `Replayed` without writing a second frame; no second dedup scheme is
/// introduced here, and the identity is never taken from the request unchecked.
fn horizon_wake_operation_identity(
    request: &UserAutomationWakeHorizonPublication,
    entry: &UserAutomationWakeHorizonEntry,
    fence: &RecordFence,
) -> Result<IdempotencyIdentity, UserAutomationRuntimeError> {
    let bytes = canonical_json_bytes(&(
        WAKE_HORIZON_OPERATION_DOMAIN,
        request.automation_id.as_str(),
        request.automation_revision.as_str(),
        request.revision_digest.as_str(),
        entry.occurrence_id.as_str(),
        entry.occurrence_key.as_str(),
        entry.source_digest.as_str(),
        fence,
    ))
    .map_err(|error| rejected(format!("Wake horizon operation identity encoding: {error}")))?;
    let digest = sha256_hex(&bytes);
    Ok(IdempotencyIdentity {
        operation_id: wake_handle(format!("ua-wake-publish:{digest}"), "operation_id")?,
        idempotency_key: wake_handle(format!("ua-wake-publish-key:{digest}"), "idempotency_key")?,
    })
}

/// Builds the one journal record that retains one requested occurrence.
///
/// The record grants nothing. `intent` is the revision's own compiled
/// owner-contract wake intent, which I1.5 makes inert: it schedules work and
/// carries no task, route, tool, effect, or delivery authority, and every
/// target, capability, policy, budget, and State Fence is revalidated on wake.
///
/// The remaining fields are the C0-04 wake contract's opaque owner handles.
/// They are bound to this publication's immutable content rather than to an
/// ambient clock, which is what keeps a replay byte-identical:
///
/// - `reason_evidence_refs` names the compiled schedule source digest, the
///   immutable revision digest, and the exact owner-normalized occurrence key,
///   so the retained record cites the trigger basis it was published for;
/// - `earliest_start`, `deadline`, and `expiry` name that same owner-normalized
///   occurrence. The accepted revision's normalized contract supplies exactly
///   one instant per occurrence, so this boundary derives no other time: a
///   `catch-up` or `deadline` policy is not part of the contract being published
///   and inventing one here would put a time in the journal that the revision
///   never normalized;
/// - `required_capabilities` names the existing UserAutomation kernel
///   capability the due-wake consumer must hold, reusing the constant this
///   operation family already spells rather than introducing a new vocabulary;
/// - `maintenance_family` and `budget_ref` are bound to the immutable
///   automation and revision this occurrence belongs to;
/// - `state_fence_revalidation_ref` is the canonical digest of the exact
///   publishing State Fence, and the intent carries that same fence.
fn horizon_wake_record(
    request: &UserAutomationWakeHorizonPublication,
    entry: &UserAutomationWakeHorizonEntry,
    fence: RecordFence,
) -> Result<WakeRecord, UserAutomationRuntimeError> {
    let fence_digest = sha256_hex(
        &canonical_json_bytes(&request.state_fence)
            .map_err(|error| rejected(format!("Wake State Fence encoding: {error}")))?,
    );
    let operation = horizon_wake_operation_identity(request, entry, &fence)?;
    Ok(WakeRecord {
        fence,
        operation,
        // `UserAutomationWakeHorizonPublication::validate` has already proved
        // that the entry's intent wake id is this occurrence, which is the
        // identity `WakeRecord::validate` requires the record to carry.
        wake_id: wake_handle(entry.occurrence_id.clone(), "wake_id")?,
        intent: entry.wake_intent.clone(),
        reason_evidence_refs: vec![
            wake_handle(
                format!("ua-wake-source:{}", entry.source_digest),
                "reason_evidence_ref",
            )?,
            wake_handle(
                format!("ua-wake-revision:{}", request.revision_digest),
                "reason_evidence_ref",
            )?,
            wake_handle(
                format!("ua-wake-occurrence:{}", entry.occurrence_key),
                "reason_evidence_ref",
            )?,
        ],
        earliest_start: wake_handle(
            format!("ua-wake-earliest:{}", entry.occurrence_key),
            "earliest_start",
        )?,
        deadline: wake_handle(
            format!("ua-wake-deadline:{}", entry.occurrence_key),
            "deadline",
        )?,
        expiry: wake_handle(format!("ua-wake-expiry:{}", entry.occurrence_key), "expiry")?,
        required_capabilities: vec![wake_handle(
            USER_AUTOMATION_KERNEL_CAPABILITY.to_owned(),
            "required_capability",
        )?],
        maintenance_family: wake_handle(
            format!("ua-wake-family:{}", request.automation_id),
            "maintenance_family",
        )?,
        safety_class: ServiceSafetyClass::ServiceSafe,
        state_fence_revalidation_ref: wake_handle(
            format!("ua-wake-revalidation:{fence_digest}"),
            "state_fence_revalidation_ref",
        )?,
        budget_ref: wake_handle(
            format!(
                "ua-wake-budget:{}:{}",
                request.revision_digest, entry.occurrence_id
            ),
            "budget_ref",
        )?,
    })
}

/// Builds the owner's acknowledgement over exactly the occurrences it retains.
///
/// The answer is then checked against the exact request with
/// [`UserAutomationWakePublication::validate_for`], which re-derives the
/// requested set from the request itself and requires the acknowledged and
/// remaining sets to be disjoint, duplicate-free, and together exactly that
/// set, beside the echoed publication identity and the derived retry handle. An
/// answer this owner cannot make over the requested set is therefore a typed
/// error, never a horizon a caller may report as published.
fn horizon_acknowledgement(
    request: &UserAutomationWakeHorizonPublication,
    acknowledged: Vec<String>,
    remaining: Vec<String>,
) -> Result<UserAutomationWakePublication, UserAutomationRuntimeError> {
    let retry_handle = request
        .retry_handle(&remaining)
        .map_err(|error| rejected(format!("Wake horizon retry handle: {error}")))?;
    let acknowledgement = UserAutomationWakePublication {
        automation_id: request.automation_id.clone(),
        automation_revision: request.automation_revision.clone(),
        revision_digest: request.revision_digest.clone(),
        state_fence: request.state_fence.clone(),
        publication_operation_id: request.identity.operation_id.clone(),
        publication_idempotency_key: request.identity.idempotency_key.clone(),
        acknowledged_occurrence_ids: acknowledged,
        remaining_occurrence_ids: remaining,
        retry_handle,
    };
    acknowledgement
        .validate_for(request)
        .map_err(|_| UserAutomationRuntimeError::IdentityConflict)?;
    Ok(acknowledgement)
}

fn wake_handle(
    value: String,
    field: &'static str,
) -> Result<PlatformHandle, UserAutomationRuntimeError> {
    PlatformHandle::new(value)
        .map_err(|_| rejected(format!("wake {field} is not a valid Host handle")))
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
    error: &WakeCancellationBatchQueryError,
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
