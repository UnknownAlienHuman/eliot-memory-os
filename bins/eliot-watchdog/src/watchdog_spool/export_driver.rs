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

use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolExportBatch, WatchdogSpoolPayloadKind,
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

    /// Submits one immutable intent batch through the fenced Kernel route.
    ///
    /// `supervision_lease_id` is the exact lease the Watchdog last verified; the
    /// fenced route resolves it against its own retained supervision authority,
    /// so a submission naming a lease the Kernel does not hold is fenced. The
    /// submission must carry each original record's bytes and the Watchdog's own
    /// epoch lineage; the route re-derives the reconciliation key and the record
    /// digests and fences on any presented value it cannot reproduce.
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
        batch: &[PendingWatchdogIntent],
    ) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError>;
}

/// Result of one bounded fenced-Kernel intent reconciliation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogIntentReconciliation {
    /// No retained intent is awaiting reconciliation.
    NothingPending,
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
    let batch = sensor.pending_watchdog_intents()?;
    if batch.is_empty() {
        return Ok(WatchdogIntentReconciliation::NothingPending);
    }
    let first_sequence = batch.first().map_or(0, |pending| pending.record.sequence);
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
    let acknowledgements = sink.submit_intent(&supervision_lease_id, &batch)?;
    if acknowledgements.len() != batch.len() {
        return Err(SpoolError::Corrupt(
            "watchdog intent acknowledgement does not cover the submitted batch".to_owned(),
        ));
    }
    let submitted_at_ms = current_unix_ms()?.max(1);
    let mut recorded = 0_usize;
    let mut already_submitted = 0_usize;
    for (pending, acknowledgement) in batch.iter().zip(&acknowledgements) {
        if acknowledgement.sequence != pending.record.sequence
            || acknowledgement.sink_id != sink.sink_id()
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent acknowledgement does not answer the submitted spool record"
                    .to_owned(),
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
