//! Crash-handoff recovery for retained maintenance triggers (issue #1694 W5).
//!
//! I14.22 keeps the trigger durable while the evaluator is unavailable —
//! "The Governor-owned `MaintenanceTriggerEvaluator` is the single producer
//! of these decisions" and "If the evaluator is unavailable, the relevant
//! trigger remains durable and is surfaced on the next startup" — and I14.24
//! refuses to continue with uncertain owned state after a daemon generation
//! fails ("do not continue with uncertain owned state", then "recover
//! through Kernel"). This module is the daemon side of that handoff: after a
//! crash it re-presents the exact retained record, claim, and observation,
//! and reconciles the commit boundary without repeating any downstream
//! effect. An unknown commit stays reconciling; it is never retried blindly.
//!
//! The commit itself stays owned by
//! [`DaemonComposition::commit_maintenance_trigger_decision`]; no policy,
//! evaluation, or intent logic is restated here. Recording the bound receipt
//! into the Kernel delivery ledger and acknowledging it travel the
//! follow-up daemon-to-Kernel decision route named there. Restart-time
//! invocation of this recovery entrypoint is declared STITCH.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_protocol::{
    MaintenanceTriggerClaim, MaintenanceTriggerDecisionReceipt, MaintenanceTriggerRecord,
    ProtocolError,
};

use super::DaemonComposition;
use super::DaemonKernelClient;
use super::maintenance_trigger_evaluator::{
    MaintenanceDecisionCommitError, MaintenanceObservation,
};

impl DaemonComposition {
    /// Recovers one retained maintenance trigger after a daemon crash.
    ///
    /// The caller re-presents the exact retained record, claim, and
    /// observation: nothing is re-minted. A crash before the decision commit
    /// (`committed` is `None`) therefore replays the same trigger through
    /// [`Self::commit_maintenance_trigger_decision`] under its existing
    /// identity and revision.
    ///
    /// A crash after the commit but before delivery acknowledgement passes
    /// that committed receipt back in. It is re-validated against the
    /// retained trigger (`matches_trigger` plus revision equality with the
    /// retained claim) and returned unchanged for acknowledgement — no
    /// re-evaluation, no second intent, and therefore no second job,
    /// recommendation, or wake. A receipt answering a different trigger or
    /// binding a different revision is a [`ProtocolError::ReplayConflict`]:
    /// materially new policy or source evidence must travel a new, explicitly
    /// linked evaluation revision, never an overwrite or a blind rerun of the
    /// old result here.
    ///
    /// A lost or ambiguous commit stays open: the commit's `Ok(None)`
    /// contract already carries the pending/reconciling shape — receipt
    /// absence during an outage is not proof of non-commit — and this method
    /// propagates it unchanged for receipt-lookup reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] for the same refusals as
    /// [`Self::commit_maintenance_trigger_decision`], plus a recovered
    /// receipt that answers a different trigger or binds a different revision
    /// than the retained claim.
    pub async fn recover_maintenance_trigger_after_crash(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        observation: MaintenanceObservation,
        record: &MaintenanceTriggerRecord,
        claim: &MaintenanceTriggerClaim,
        committed: Option<&MaintenanceTriggerDecisionReceipt>,
    ) -> Result<Option<MaintenanceTriggerDecisionReceipt>, MaintenanceDecisionCommitError> {
        let Some(receipt) = committed else {
            return self
                .commit_maintenance_trigger_decision(kernel, observation, record, claim)
                .await;
        };
        receipt.matches_trigger(record)?;
        if receipt.revision != claim.revision {
            return Err(MaintenanceDecisionCommitError::Protocol(
                ProtocolError::ReplayConflict,
            ));
        }
        Ok(Some(receipt.clone()))
    }
}
