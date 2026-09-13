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
/// Consumed by the Watchdog export path in a later slice; marked accordingly
/// until that consumer lands.
#[allow(dead_code)]
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
/// Consumed by the Watchdog export path in a later slice; marked accordingly
/// until that consumer lands.
#[allow(dead_code)]
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
/// Consumed by the Watchdog export path in a later slice; marked accordingly
/// until that consumer lands.
#[allow(dead_code)]
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
