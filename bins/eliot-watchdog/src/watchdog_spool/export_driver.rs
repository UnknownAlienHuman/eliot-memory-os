//! Watchdog spool export driver: one bounded export through a sink acknowledgement.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-WDG-01.
//! Implementation: I8.1, I8.2, I2.23.
//! Wave C of the spool export decomposition (spool export through Governor
//! admission). The Watchdog owns the spool records and the export cursor; the
//! sink owns only its per-entry dispositions and never deletes, mutates, or
//! compacts source records. Cursor semantics stay with the Governor lane
//! (`admit_watchdog_batch`) and the owner-neutral core; this driver chains the
//! exact export, acknowledgement, and compaction calls without adding
//! transport, admission, canonical-store, or semantic authority. There is no
//! process execution, executor, or child-launch path here by construction.
//!
//! Spool-local intents are ordinary covered records of this window, not a
//! parked boundary: the fenced Kernel `watchdog-spool-batch-v1` intent route
//! reconciles each one, and the Watchdog keeps the original record (compaction
//! never removes an intent) so the Kernel record and the Governor's later
//! canonical Problem/Incident decision stay forensically linked to it.

use eliot_protocol::watchdog_intent_reconciliation_idempotency_key;
use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolExportBatch, WatchdogSpoolPayloadKind,
    validate_batch, validate_batch_freshness,
};

use crate::watchdog_spool::intent::{
    IntentSubmissionDisposition, PendingWatchdogIntent, WatchdogIntentSubmission,
};
use crate::{IndependentKernelSensor, SpoolError, WatchdogSpoolExportLimits, current_unix_ms};

/// Pure admission-entry projection of one export batch, in batch order.
///
/// Positions mirror the Governor admission view field-for-field: sequence,
/// kind, record digest, payload digest, observed timestamp. The kind is the
/// owner-neutral core payload class; the Governor lane maps it 1:1 onto its
/// own admission kind without a Watchdog dependency from this crate.
pub type WatchdogEntryView = (u64, WatchdogSpoolPayloadKind, String, String, u64);

/// Transport-agnostic sink for one Watchdog spool export batch.
///
/// The real Kernel/EBP plus Governor adapter implements this trait in the
/// Governor lane; this crate ships no transport client. The fake sink lives
/// only in tests: production [`export_once`] takes a real implementation.
pub trait WatchdogExportSink {
    /// Returns the bound sink identity for this export contour.
    ///
    /// The identity becomes the export predecessor cursor sink, so every
    /// acknowledgement the sink returns must echo it back; any divergence
    /// fails closed in the spool owner without writing.
    fn sink_id(&self) -> &str;

    /// Submits one immutable batch and returns its complete acknowledgement.
    ///
    /// The acknowledgement must echo the exact batch identity (id, digest,
    /// predecessor, range, sink, generation, epoch, installation) with
    /// per-entry digest coverage for every covered entry. Store-unavailable
    /// stages are expressed honestly as `Durable` or `Unknown` dispositions
    /// inside the returned acknowledgement — never as an error — so the spool
    /// owner refuses them as non-terminal, the cursor stays put, and the batch
    /// stays replayable.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] only when the sink cannot form an
    /// acknowledgement at all (for example a sink-side encoding fault).
    /// Transport outages with a known stage must still return an
    /// acknowledgement carrying that stage, not an error.
    fn submit(
        &self,
        batch: &WatchdogSpoolExportBatch,
    ) -> Result<WatchdogSpoolAcknowledgement, SpoolError>;
}

/// Drives one bounded spool export through the sink acknowledgement.
///
/// The chain is exactly: `export_spool_batch(sink.sink_id(), limits)` over the
/// Watchdog-owned spool, then `sink.submit(batch)`, then
/// `apply_spool_acknowledgement(&batch, &ack)`, then
/// `compact_spool_below_cursor` over the new cursor. An empty spool
/// short-circuits after the read-only export: the sink is never submitted to
/// (the core refuses cursor advance over an empty batch) and the current
/// acknowledged sequence is returned unchanged.
///
/// A failing acknowledgement fails closed inside the spool owner: `Received`,
/// `Durable`, `AdmittedCandidate`, and `Unknown` dispositions never advance
/// the cursor, so the error propagates, nothing compacts, and the exact batch
/// stays replayable. A duplicate acknowledgement returns the stored sequence
/// unchanged without writing, followed by the idempotent compaction no-op. A
/// compaction failure after a successful acknowledgement propagates as an
/// error even though the cursor has advanced; the leftover prefix stays
/// compactable because every later export compacts below its own cursor.
///
/// There is no semantic interpretation here and no canonical store write.
/// Cursor-advance validation stays with the Watchdog owner on every step.
///
/// # Errors
///
/// Returns [`SpoolError`] when the bounded export window is unusable, the sink
/// cannot acknowledge, the acknowledgement is forged, expired, non-terminal,
/// or mismatched, or compaction below the advanced cursor fails validation.
pub fn export_once(
    sensor: &IndependentKernelSensor,
    sink: &impl WatchdogExportSink,
    limits: WatchdogSpoolExportLimits,
) -> Result<u64, SpoolError> {
    let batch = sensor.export_spool_batch(sink.sink_id(), limits)?;
    if batch.is_empty_batch {
        return Ok(batch.predecessor_cursor.acknowledged_sequence);
    }
    let acknowledgement = sink.submit(&batch)?;
    let advanced = sensor.apply_spool_acknowledgement(&batch, &acknowledgement)?;
    sensor.compact_spool_below_cursor(advanced)?;
    Ok(advanced)
}

/// Projects one export batch onto pure admission-entry views, in batch order.
///
/// Positions mirror the Governor admission view: sequence, payload kind,
/// record digest, payload digest, observed timestamp. The projection carries
/// no sink identity and performs no I/O; the Governor-lane adapter maps each
/// view onto its admission entry and each canonical outcome back onto the
/// terminal sink disposition for its payload kind. A spool-local intent is
/// projected like any other record: only the fenced Kernel intent route may
/// turn one into a pending intent projection.
#[must_use]
pub fn watchdog_entry_views(batch: &WatchdogSpoolExportBatch) -> Vec<WatchdogEntryView> {
    batch
        .entries
        .iter()
        .map(|entry| {
            (
                entry.sequence,
                entry.payload_kind,
                entry.record_digest.clone(),
                entry.payload_digest.clone(),
                entry.observed_at_ms,
            )
        })
        .collect()
}

/// Handoff spelling of [`watchdog_entry_views`] for the RECHECK-0914 item text.
///
/// Delegates exactly; new callers prefer [`watchdog_entry_views`].
#[must_use]
pub fn watchog_entry_views(batch: &WatchdogSpoolExportBatch) -> Vec<WatchdogEntryView> {
    watchdog_entry_views(batch)
}

/// Kernel acknowledgement of one fenced Watchdog intent submission.
///
/// The acknowledgement proves only that the fenced Kernel intent route
/// recorded a pending intent projection for the exact retained spool record
/// under the exact reconciliation key. It is not a canonical Problem or
/// Incident decision: the Governor performs that transition later, and the
/// Watchdog's own record stays retained for forensic linkage either way.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogIntentAcknowledgement {
    /// Retained spool sequence the fenced route recorded.
    pub sequence: u64,
    /// Responding sink identity echoed by the fenced route.
    pub sink_id: String,
    /// Reconciliation key the fenced route derived for the record.
    pub idempotency_key: String,
    /// Digest over the exact acknowledgement the fenced route returned.
    pub acknowledgement_digest: String,
}

/// Owner-generated spool export window plus the still-pending intent records
/// covered by that exact window.
///
/// The export envelope remains intact so a Kernel client can carry its real
/// predecessor, full-window range, high-water, identity, digest, and freshness
/// bounds. The intent list is only a projection of records inside the window;
/// non-intent records still contribute to the owner-computed export digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogIntentExportBatch {
    export_batch: WatchdogSpoolExportBatch,
    intents: Vec<PendingWatchdogIntent>,
}

impl WatchdogIntentExportBatch {
    /// Returns the complete owner-generated spool window envelope.
    #[must_use]
    pub fn export_batch(&self) -> &WatchdogSpoolExportBatch {
        &self.export_batch
    }

    /// Returns pending intent records covered by `export_batch`.
    #[must_use]
    pub fn intents(&self) -> &[PendingWatchdogIntent] {
        &self.intents
    }

    /// Revalidates the exact export envelope and its record-level joins before
    /// a transport adapter is allowed to use it.
    fn validate(&self, now_ms: u64) -> Result<(), SpoolError> {
        validate_batch(&self.export_batch, self.export_batch.high_water_sequence)?;
        validate_batch_freshness(&self.export_batch, now_ms)?;
        if self.intents.is_empty() {
            return Err(SpoolError::Corrupt(
                "watchdog intent export window contains no pending intent".to_owned(),
            ));
        }
        let mut previous_sequence = None;
        for pending in &self.intents {
            let sequence = pending.record.sequence;
            if sequence < self.export_batch.first_sequence
                || sequence > self.export_batch.last_sequence
                || previous_sequence.is_some_and(|previous| sequence <= previous)
            {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export window has an out-of-range or unordered record"
                        .to_owned(),
                ));
            }
            previous_sequence = Some(sequence);

            let raw = super::encode_entry(&pending.record)?;
            let (payload_digest, record_digest) =
                super::export_record_digests(&pending.record, &raw);
            if payload_digest != pending.payload_digest || record_digest != pending.record_digest {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export window digest does not match the retained record"
                        .to_owned(),
                ));
            }
            let expected_class =
                super::intent::WatchdogIntentClass::of_payload(&pending.record.payload)?;
            if expected_class != pending.intent_class {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export window class does not match the retained record"
                        .to_owned(),
                ));
            }
            let exported = self
                .export_batch
                .entries
                .iter()
                .find(|entry| entry.sequence == sequence)
                .ok_or_else(|| {
                    SpoolError::Corrupt(
                        "watchdog intent export window omits a pending retained record".to_owned(),
                    )
                })?;
            if exported.schema_version != pending.record.schema_version
                || exported.observed_at_ms != pending.record.observed_at_ms
                || exported.payload_kind != WatchdogSpoolPayloadKind::Recovery
                || exported.payload_digest != pending.payload_digest
                || exported.record_digest != pending.record_digest
            {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export entry diverges from the retained record".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Transport-agnostic fenced Kernel route for one Watchdog intent submission.
///
/// The real EBP client implements this trait against the admitted
/// `watchdog-spool-batch-v1` Kernel route. This crate ships no transport
/// client and no in-memory implementation: the port exists so the Watchdog can
/// present the exact original record, evidence, and lineage through a fenced
/// Kernel mutation and then persist its submit-once receipt from the returned
/// acknowledgement, with no semantic interpretation on this side.
pub trait WatchdogIntentSink {
    /// Returns the bound sink identity this reconciliation contour uses.
    ///
    /// The identity becomes the export predecessor cursor sink, so it must be
    /// the exact sink the acknowledgement echoes.
    fn sink_id(&self) -> &str;

    /// Submits pending intents from one immutable owner-generated export window
    /// through the fenced Kernel route.
    ///
    /// `supervision_lease_id` is the exact lease the Watchdog last verified; the
    /// fenced route resolves it against its own retained supervision authority,
    /// so a submission naming a lease the Kernel does not hold is fenced. The
    /// batch carries the exact spool owner's predecessor, full covered range,
    /// high-water, identity, digest, and freshness window. Its intent projection
    /// carries each original record's bytes and the Watchdog's own epoch lineage;
    /// non-intent entries remain bound by the owner-computed batch digest. The
    /// route re-derives the reconciliation key and the record digests and fences on
    /// any presented value it cannot reproduce.
    ///
    /// A transport outage with an unknown stage must be reported as an error and
    /// must never be reported as an acknowledgement: the submit-once receipt is
    /// written only for a real acknowledgement, so a lost acknowledgement
    /// replays instead of skipping.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the submission cannot be delivered or the
    /// fenced route cannot form an acknowledgement at all.
    fn submit_intent(
        &self,
        supervision_lease_id: &str,
        batch: &WatchdogIntentExportBatch,
    ) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError>;
}

/// Why the oldest unsubmitted intent is not in the current exact export window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogIntentWindowBlock {
    /// The shared export cursor already passed this retained intent record.
    CursorAlreadyPassedPendingRecord,
    /// The next pending record lies beyond this bounded export window.
    PendingRecordBeyondBoundedWindow,
}

/// Result of one bounded fenced-Kernel intent reconciliation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogIntentReconciliation {
    /// No retained intent is awaiting reconciliation.
    NothingPending,
    /// A retained intent cannot be carried by the current owner-generated
    /// export window. No sink call or receipt write occurred.
    Blocked {
        pending_sequence: u64,
        predecessor_sequence: u64,
        first_sequence: u64,
        last_sequence: u64,
        reason: WatchdogIntentWindowBlock,
    },
    /// One bounded batch was submitted and its submit-once receipts are now
    /// durable. `recorded` counts receipts this call wrote; `already_submitted`
    /// counts records whose receipt already existed, so no second submission
    /// of those records is possible.
    Reconciled {
        first_sequence: u64,
        recorded: usize,
        already_submitted: usize,
    },
}

/// Reconciles one bounded window of retained Watchdog intents through the fenced
/// Kernel route and records their submit-once receipts.
///
/// The pass is: read the oldest retained intents that have no receipt, submit
/// the exact original records through the fenced route, verify the
/// acknowledgements answer exactly those sequences for the bound sink, then
/// persist one receipt per acknowledgement inside `watchdog.redb`. A receipt is
/// written only after a real acknowledgement, so a lost acknowledgement replays
/// the same submission instead of skipping it, and the durable receipt makes a
/// second submission of the same spool record impossible. Retained records are
/// never removed: the Kernel record and the Governor's later canonical
/// decision stay forensically linked to the original Watchdog record.
///
/// # Errors
///
/// Returns [`SpoolError`] when the retained spool or its receipt ledger fails
/// validation, the fenced route cannot acknowledge, the acknowledgement
/// coverage or sink identity does not answer the submitted batch, or a receipt
/// cannot be persisted.
pub fn reconcile_watchdog_intents(
    sensor: &IndependentKernelSensor,
    sink: &impl WatchdogIntentSink,
) -> Result<WatchdogIntentReconciliation, SpoolError> {
    let pending = sensor.pending_watchdog_intents()?;
    if pending.is_empty() {
        return Ok(WatchdogIntentReconciliation::NothingPending);
    }
    // A gap-only sensor that never verified a lease has no lease the fenced
    // route could resolve, so it fails closed here instead of submitting a
    // batch the Kernel must fence anyway.
    let supervision_lease_id = sensor
        .verified_supervision_lease_id()
        .ok_or_else(|| {
            SpoolError::InvalidLease(
                "watchdog intent reconciliation requires a verified supervision lease; none was admitted"
                .to_owned(),
            )
        })?;
    let sink_id = sink.sink_id().to_owned();
    let export_batch = sensor.export_spool_batch(&sink_id, WatchdogSpoolExportLimits::default())?;
    if export_batch.predecessor_cursor.sink_id != sink_id {
        return Err(SpoolError::Corrupt(
            "watchdog intent export predecessor does not match the captured sink identity"
                .to_owned(),
        ));
    }
    let window_first = export_batch.first_sequence;
    let window_last = export_batch.last_sequence;
    let pending_sequence = pending[0].record.sequence;
    let reason = if pending_sequence < window_first {
        Some(WatchdogIntentWindowBlock::CursorAlreadyPassedPendingRecord)
    } else if pending_sequence > window_last {
        Some(WatchdogIntentWindowBlock::PendingRecordBeyondBoundedWindow)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Ok(WatchdogIntentReconciliation::Blocked {
            pending_sequence,
            predecessor_sequence: export_batch.predecessor_cursor.acknowledged_sequence,
            first_sequence: window_first,
            last_sequence: window_last,
            reason,
        });
    }
    let covered_intents = pending
        .into_iter()
        .take_while(|item| item.record.sequence <= window_last)
        .collect::<Vec<_>>();
    let batch = WatchdogIntentExportBatch {
        export_batch,
        intents: covered_intents,
    };
    batch.validate(current_unix_ms()?.max(1))?;
    let first_sequence = batch.intents.first().map_or(0, |item| item.record.sequence);
    let acknowledgements = sink.submit_intent(&supervision_lease_id, &batch)?;
    if acknowledgements.len() != batch.intents.len() {
        return Err(SpoolError::Corrupt(
            "watchdog intent acknowledgement does not cover the submitted batch".to_owned(),
        ));
    }
    let submitted_at_ms = current_unix_ms()?.max(1);
    let mut recorded = 0_usize;
    let mut already_submitted = 0_usize;
    for (pending, acknowledgement) in batch.intents.iter().zip(&acknowledgements) {
        let expected_idempotency_key = watchdog_intent_reconciliation_idempotency_key(
            &batch.export_batch.installation_id,
            pending.record.sequence,
            &pending.record_digest,
        );
        if acknowledgement.sequence != pending.record.sequence
            || acknowledgement.sink_id != batch.export_batch.predecessor_cursor.sink_id
            || acknowledgement.idempotency_key != expected_idempotency_key
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent acknowledgement does not answer the exact submitted record and derived idempotency key".to_owned(),
            ));
        }
        let submission = WatchdogIntentSubmission {
            sequence: acknowledgement.sequence,
            idempotency_key: acknowledgement.idempotency_key.clone(),
            acknowledgement_digest: acknowledgement.acknowledgement_digest.clone(),
            submitted_at_ms,
        };
        match sensor.record_intent_submission(&submission)? {
            IntentSubmissionDisposition::Recorded => recorded += 1,
            IntentSubmissionDisposition::AlreadySubmitted => already_submitted += 1,
        }
    }
    Ok(WatchdogIntentReconciliation::Reconciled {
        first_sequence,
        recorded,
        already_submitted,
    })
}
