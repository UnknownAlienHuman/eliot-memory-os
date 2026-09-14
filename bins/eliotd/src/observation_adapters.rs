//! Private Governor-backed observation/verified-repair port adapters.
//!
//! The forwarding adapter translates between the daemon composition root and
//! one Governor
//! [`GovernorObservationReconciliation`](eliot_governor::GovernorObservationReconciliation)
//! borrowed from the single [`DaemonComposition`](super::DaemonComposition)
//! by its `observation_reconciliation` accessor. It forwards authenticated
//! input and translates typed results only:
//!
//! - No policy, admission, or semantic rules live here. Fence agreement,
//!   verifier endorsement, problem binding, scratch legality, and the two
//!   canonical commits stay with the Governor observation owner; this adapter
//!   never invents a verification, a problem revision, or a receipt.
//! - `admit_doctor_verification` forwards the exact admitted identity,
//!   operation identity, and verification report to the Governor canonical
//!   path. Only a `Committed` observation receipt admits the recovery leg;
//!   every terminal receipt is returned exactly as issued, and a lost
//!   acknowledgement reconciles the same operation receipt.
//! - Watchdog export acknowledgement mapping is pure and lives here (never
//!   in the Governor, which must not depend on the Watchdog): a terminal
//!   canonical receipt maps to its sink disposition, an unknown outcome maps
//!   to `Unknown`, and gap-like entries resolve through `GapRequiresRecovery`.
//!   `Received`, `Durable`, and `AdmittedCandidate` are never emitted by this
//!   mapping and never advance the cursor. Acknowledgements echo the exact
//!   batch digest and predecessor cursor; cursor-advance decisions stay with
//!   the Watchdog owner via its own validation.
//!
//! The adapter performs no I/O of its own beyond awaiting the inner Governor
//! owner, so it cannot block the single-thread async reactor beyond the
//! already-admitted canonical commits. The current Kernel binding is observed
//! through the Governor composition, never through a second client.

#![forbid(unsafe_code)]

use eliot_governor::{CompositionError, GovernorObservationReconciliation, KernelTransitionPort};

/// Forwards doctor-verification admission to the single Governor owner.
///
/// The wrapper owns the inner Governor adapter (which itself borrows the
/// single Governor owner triple) and forwards each call unchanged. It adds no
/// validation, retry, or state of its own; every typed success or fail-closed
/// error comes from the Governor owner.
pub struct ForwardingObservationReconciliation<'a, P: ?Sized> {
    inner: GovernorObservationReconciliation<'a, P>,
}

impl<'a, P: ?Sized> ForwardingObservationReconciliation<'a, P> {
    /// Wraps the single Governor reconciliation owner for forwarding.
    pub fn new(inner: GovernorObservationReconciliation<'a, P>) -> Self {
        Self { inner }
    }
}

impl<P: KernelTransitionPort + ?Sized> ForwardingObservationReconciliation<'_, P> {
    /// Forwards one independently verified Doctor result to the Governor
    /// canonical path and returns only the exact issued receipt.
    pub async fn admit_doctor_verification(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: &eliot_contracts::OperationId,
        report: &eliot_doctor_core::VerificationReport,
    ) -> Result<eliot_store_api::WriteReceipt, CompositionError> {
        self.inner
            .admit_doctor_verification(identity, operation_id, report)
            .await
    }
}

/// Maps a canonical outcome to its Watchdog spool sink disposition.
///
/// `None` (no receipt: the commit outcome is unknown) maps to `Unknown`,
/// which never advances the cursor. `Committed` maps to `Applied`;
/// `Rejected`, `DeadLetter`, and `Cancelled` are terminal-as-decided and map
/// to `Rejected` with an explicit reason so the cursor advances past the
/// decided entry exactly like an applied one. This mapping never emits
/// `Received`, `Durable`, or `AdmittedCandidate`: none of them advances the
/// cursor. Gap-like entries resolve through [`gap_requires_recovery`], never
/// through a canonical receipt mapping.
///
/// Live: consumed by [`forward_watchdog_batch`] below.
pub fn sink_disposition_for_canonical_outcome(
    status: Option<eliot_store_api::WriteReceiptStatus>,
) -> eliot_watchdog_core::WatchdogSpoolSinkDisposition {
    use eliot_watchdog_core::WatchdogSpoolSinkDisposition as Disposition;
    match status {
        None => Disposition::Unknown,
        Some(eliot_store_api::WriteReceiptStatus::Committed) => Disposition::Applied,
        Some(eliot_store_api::WriteReceiptStatus::Rejected) => Disposition::Rejected {
            reason: "canonical rejected".to_owned(),
        },
        Some(eliot_store_api::WriteReceiptStatus::DeadLetter) => Disposition::Rejected {
            reason: "canonical dead-letter".to_owned(),
        },
        Some(eliot_store_api::WriteReceiptStatus::Cancelled) => Disposition::Rejected {
            reason: "canonical cancelled".to_owned(),
        },
    }
}

/// Returns the terminal gap-resolution disposition for gap-like spool
/// entries. It advances the cursor only for `Gap`/`Recovery` payload kinds;
/// applying it to a `Heartbeat` entry is the wrong phase and never advances
/// (enforced by the Watchdog owner's own classifier).
///
/// Live: consumed by [`forward_watchdog_batch`] below.
pub fn gap_requires_recovery() -> eliot_watchdog_core::WatchdogSpoolSinkDisposition {
    eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery
}

/// Builds the sink-owned acknowledgement for exactly one export batch.
///
/// Every owner-identity field echoes the batch exactly: the batch digest, the
/// predecessor acknowledged sequence, the covered range, the sink, the
/// generation/epoch, and the installation. Per-entry dispositions come from
/// [`sink_disposition_for_canonical_outcome`] (or [`gap_requires_recovery`]
/// for gap-like entries) in batch order. Cursor-advance validation stays
/// with the Watchdog owner; this constructor invents no digest or cursor.
///
/// Live: consumed by [`forward_watchdog_batch`] and the store-unavailable
/// constructors below.
pub fn acknowledgement_for_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    dispositions: Vec<eliot_watchdog_core::WatchdogSpoolEntryDisposition>,
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    eliot_watchdog_core::WatchdogSpoolAcknowledgement {
        schema_version: batch.schema_version,
        batch_id: batch.batch_id.clone(),
        batch_digest: batch.batch_digest.clone(),
        predecessor_sequence: batch.predecessor_cursor.acknowledged_sequence,
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        sink_id: batch.predecessor_cursor.sink_id.clone(),
        watchdog_generation: batch.watchdog_generation,
        watchdog_epoch: batch.watchdog_epoch,
        installation_id: batch.installation_id.clone(),
        dispositions,
    }
}

/// Forwards one Watchdog export batch through the live disposition mapping.
///
/// Takes the immutable export batch plus the per-entry canonical outcomes in
/// batch order (`None` per entry means the commit outcome is unknown) and
/// returns the exact sink-owned acknowledgement. Heartbeat entries map
/// through [`sink_disposition_for_canonical_outcome`]; gap-like
/// (`Gap`/`Recovery`) entries resolve through [`gap_requires_recovery`] when
/// the canonical outcome is `Committed` and through the terminal-as-decided
/// mapping when the canonical outcome is `Rejected`/`DeadLetter`/`Cancelled`;
/// unknown outcomes stay `Unknown` and never advance the cursor. A shorter
/// outcome slice pads with `Unknown` and a longer one truncates, so a length
/// mismatch fails closed as non-terminal instead of panicking. No policy,
/// admission, or semantic rule lives here; cursor-advance validation stays
/// with the Watchdog owner. The Governor composition accessor is deferred
/// (see PR residual); this mapping is the daemon-side consumer that feeds
/// `WatchdogSpool::apply_acknowledgement`.
pub fn forward_watchdog_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    outcomes: &[Option<eliot_store_api::WriteReceiptStatus>],
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    let mut dispositions = Vec::with_capacity(batch.entries.len());
    for (index, entry) in batch.entries.iter().enumerate() {
        let outcome = outcomes.get(index).copied().flatten();
        let is_gap_like = matches!(
            entry.payload_kind,
            eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap
                | eliot_watchdog_core::WatchdogSpoolPayloadKind::Recovery
        );
        let disposition =
            if is_gap_like && outcome == Some(eliot_store_api::WriteReceiptStatus::Committed) {
                gap_requires_recovery()
            } else {
                sink_disposition_for_canonical_outcome(outcome)
            };
        dispositions.push(eliot_watchdog_core::WatchdogSpoolEntryDisposition {
            sequence: entry.sequence,
            disposition,
            record_digest: entry.record_digest.clone(),
        });
    }
    acknowledgement_for_batch(batch, dispositions)
}

/// Builds the honest store-unavailable acknowledgement for the durable stage:
/// every entry reports `Durable` (stored without admission). It never
/// advances the cursor; the Watchdog owner refuses it as non-terminal and the
/// batch stays replayable.
pub fn durable_acknowledgement_for_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    let dispositions = batch
        .entries
        .iter()
        .map(|entry| eliot_watchdog_core::WatchdogSpoolEntryDisposition {
            sequence: entry.sequence,
            disposition: eliot_watchdog_core::WatchdogSpoolSinkDisposition::Durable,
            record_digest: entry.record_digest.clone(),
        })
        .collect();
    acknowledgement_for_batch(batch, dispositions)
}

/// Builds the honest store-unavailable acknowledgement for the unknown stage:
/// every entry reports `Unknown`. It fails acknowledgement validation
/// (`UnknownOutcome`) so the cursor stays unchanged and the batch stays
/// replayable.
pub fn unknown_acknowledgement_for_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    let dispositions = batch
        .entries
        .iter()
        .map(|entry| eliot_watchdog_core::WatchdogSpoolEntryDisposition {
            sequence: entry.sequence,
            disposition: eliot_watchdog_core::WatchdogSpoolSinkDisposition::Unknown,
            record_digest: entry.record_digest.clone(),
        })
        .collect();
    acknowledgement_for_batch(batch, dispositions)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture_digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn fixture_batch() -> eliot_watchdog_core::WatchdogSpoolExportBatch {
        let predecessor = eliot_watchdog_core::WatchdogSpoolCursor {
            schema_version: 1,
            acknowledged_sequence: 0,
            watchdog_generation: 7,
            watchdog_epoch: 3,
            installation_id: "installation-test".to_owned(),
            sink_id: "sink-test".to_owned(),
        };
        eliot_watchdog_core::WatchdogSpoolExportBatch {
            schema_version: 1,
            batch_id: "batch-test-1".to_owned(),
            installation_id: "installation-test".to_owned(),
            watchdog_generation: 7,
            watchdog_epoch: 3,
            predecessor_cursor: predecessor,
            first_sequence: 1,
            last_sequence: 2,
            high_water_sequence: 2,
            entries: vec![
                eliot_watchdog_core::WatchdogSpoolExportEntry {
                    sequence: 1,
                    schema_version: 1,
                    observed_at_ms: 1_000,
                    payload_kind: eliot_watchdog_core::WatchdogSpoolPayloadKind::Heartbeat,
                    payload_digest: fixture_digest(0x0c),
                    record_digest: fixture_digest(0x0d),
                },
                eliot_watchdog_core::WatchdogSpoolExportEntry {
                    sequence: 2,
                    schema_version: 1,
                    observed_at_ms: 1_001,
                    payload_kind: eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap,
                    payload_digest: fixture_digest(0x0e),
                    record_digest: fixture_digest(0x0f),
                },
            ],
            item_count: 2,
            byte_size: 128,
            batch_digest: fixture_digest(0x0b),
            is_empty_batch: false,
            created_at_ms: 1_000,
            expires_at_ms: 2_000,
        }
    }

    #[test]
    fn forwards_heartbeat_and_gap_with_durable_unknown_branches() {
        let batch = fixture_batch();
        let ack = forward_watchdog_batch(
            &batch,
            &[
                Some(eliot_store_api::WriteReceiptStatus::Committed),
                Some(eliot_store_api::WriteReceiptStatus::Committed),
            ],
        );
        assert_eq!(ack.batch_id, batch.batch_id);
        assert_eq!(ack.batch_digest, batch.batch_digest);
        assert_eq!(
            ack.predecessor_sequence,
            batch.predecessor_cursor.acknowledged_sequence
        );
        assert_eq!(ack.first_sequence, batch.first_sequence);
        assert_eq!(ack.last_sequence, batch.last_sequence);
        assert_eq!(ack.sink_id, batch.predecessor_cursor.sink_id);
        assert_eq!(ack.dispositions.len(), 2);
        assert_eq!(
            ack.dispositions[0].disposition,
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::Applied
        );
        assert_eq!(
            ack.dispositions[1].disposition,
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery
        );

        let unknown = forward_watchdog_batch(&batch, &[None, None]);
        assert!(unknown.dispositions.iter().all(|line| {
            line.disposition == eliot_watchdog_core::WatchdogSpoolSinkDisposition::Unknown
        }));

        let durable = durable_acknowledgement_for_batch(&batch);
        assert!(durable.dispositions.iter().all(|line| {
            line.disposition == eliot_watchdog_core::WatchdogSpoolSinkDisposition::Durable
        }));

        let unknown_stage = unknown_acknowledgement_for_batch(&batch);
        assert!(unknown_stage.dispositions.iter().all(|line| {
            line.disposition == eliot_watchdog_core::WatchdogSpoolSinkDisposition::Unknown
        }));
    }
}
