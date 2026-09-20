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
//! transport, admission, canonical-store, or semantic authority. Transport
//! reaches the Governor through the admitted `watchdog-spool-batch-v1` Kernel
//! route concept; the real adapter implementing [`WatchdogExportSink`] lives in
//! the Governor lane, not here. There is no process execution, executor, or
//! child-launch path here by construction.

use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolExportBatch, WatchdogSpoolPayloadKind,
};

use crate::{IndependentKernelSensor, SpoolError, WatchdogSpoolExportLimits};

/// Pure admission-entry projection of one export batch, in batch order.
///
/// Positions mirror the Governor admission view field-for-field: sequence,
/// kind, record digest, payload digest, observed timestamp. The kind is the
/// owner-neutral core payload class; the Governor lane maps it 1:1 onto its
/// own admission kind without a Watchdog dependency from this crate.
pub type WatchdogEntryView = (
    u64,
    WatchdogSpoolPayloadKind,
    String,
    String,
    u64,
);

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
/// terminal sink disposition for its payload kind. Spool-local intents never
/// reach this projection: the spool owner stops the export window before the
/// first intent until Governor-side admission lands.
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
