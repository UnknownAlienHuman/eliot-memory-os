use super::{HostError, HostInstallationEpoch, HostState, StoreRebindHandoff, StoreRebindState};
#[cfg(windows)]
use super::{
    StoreRecoveryInnerBinding, StoreRecoveryPendingIdentity, StoreRecoveryTerminationEvidence,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoreRecoveryReopenTermination {
    pub(super) process_id: u32,
    pub(super) process_start_time_100ns: u64,
    pub(super) process_image_path: String,
    pub(super) job_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoreRecoveryReopenInnerBinding {
    pub(super) operation_id: String,
    pub(super) request_digest: String,
    pub(super) handoff: StoreRebindHandoff,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoreRecoveryReopenFence {
    pub(super) mutation_digest: String,
    pub(super) request_id: String,
    pub(super) request_digest: String,
    pub(super) host_epoch: u64,
    pub(super) host_lineage: String,
    pub(super) termination: Option<StoreRecoveryReopenTermination>,
    pub(super) inner: Option<StoreRecoveryReopenInnerBinding>,
}

impl StoreRecoveryReopenFence {
    #[cfg(windows)]
    pub(super) fn from_durable(
        mutation_digest: String,
        pending: StoreRecoveryPendingIdentity,
        termination: Option<StoreRecoveryTerminationEvidence>,
        inner: Option<StoreRecoveryInnerBinding>,
    ) -> Result<Self, HostError> {
        pending.recover_request()?;
        if pending.mutation_digest != mutation_digest {
            return Err(HostError::RecoveryRequired(
                "Store recovery filename and pending mutation differ".to_owned(),
            ));
        }
        if let Some(termination) = termination.as_ref() {
            termination.validate_for_pending(&pending)?;
        }
        if let Some(inner) = inner.as_ref() {
            let termination = termination.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store recovery inner binding has no termination evidence".to_owned(),
                )
            })?;
            inner.validate_for_pending(&pending, termination)?;
        }
        Ok(Self {
            mutation_digest,
            request_id: pending.request_id,
            request_digest: pending.request_digest,
            host_epoch: pending.host_epoch,
            host_lineage: pending.host_lineage,
            termination: termination.map(|evidence| StoreRecoveryReopenTermination {
                process_id: evidence.process_id,
                process_start_time_100ns: evidence.process_start_time_100ns,
                process_image_path: evidence.process_image_path,
                job_name: evidence.job_name,
            }),
            inner: inner.map(|binding| StoreRecoveryReopenInnerBinding {
                operation_id: binding.store_rebind_operation_id,
                request_digest: binding.store_rebind_request_digest,
                handoff: binding.handoff,
            }),
        })
    }

    pub(super) fn validate_for_reopen(
        &self,
        last_host: &HostInstallationEpoch,
        replayed: &HostState,
    ) -> Result<(), HostError> {
        if self.host_epoch != last_host.epoch.current.sequence
            || self.host_lineage != last_host.epoch.current.lineage.as_str()
            || replayed.host != *last_host
        {
            return Err(HostError::RecoveryRequired(
                "Store recovery fence belongs to another durable Host epoch".to_owned(),
            ));
        }
        let Some(inner) = self.inner.as_ref() else {
            return Ok(());
        };
        inner
            .handoff
            .validate_canonical_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if inner.handoff.operation_id.as_str() != inner.operation_id
            || inner.handoff.request_digest != inner.request_digest
        {
            return Err(HostError::RecoveryRequired(
                "Store recovery startup handoff identity was substituted".to_owned(),
            ));
        }
        let mut records = replayed
            .store_rebinds
            .iter()
            .filter(|record| record.operation_id.as_str() == inner.operation_id);
        let Some(record) = records.next() else {
            // The inner binding is intentionally published before the journal
            // request/delivery. Absence is therefore a recoverable Unknown,
            // never permission to start a fresh contour.
            return Ok(());
        };
        if records.next().is_some() {
            return Err(HostError::RecoveryRequired(
                "Store recovery fence matched multiple inner journal records".to_owned(),
            ));
        }
        if record.request_digest.as_str() != inner.request_digest {
            return Err(HostError::RecoveryRequired(
                "Store recovery inner request digest was substituted".to_owned(),
            ));
        }
        let activation = replayed.activation.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store recovery inner record has no durable activation fence".to_owned(),
            )
        })?;
        if record.fence != activation.fence || record.fence.host != *last_host {
            return Err(HostError::RecoveryRequired(
                "Store recovery inner record is bound to another activation".to_owned(),
            ));
        }
        if record.state == StoreRebindState::Committed {
            let termination = self.termination.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "committed Store recovery has no exact termination evidence".to_owned(),
                )
            })?;
            if record.process_id == termination.process_id
                && record.process_start_time_100ns == termination.process_start_time_100ns
                && record.process_image_path.as_str() == termination.process_image_path
                && record.job_name.as_str() == termination.job_name
            {
                return Err(HostError::RecoveryRequired(
                    "committed Store recovery points at the terminated predecessor".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Mutable Host-local startup state for one or more exact unresolved Store
/// recovery bindings.  The binding itself remains durable and immutable until
/// authenticated reconciliation publishes its receipt; this state is only the
/// in-memory admission gate for the current owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum StoreRecoveryStartupFence {
    Clear,
    Unresolved(Vec<StoreRecoveryReopenFence>),
}

impl StoreRecoveryStartupFence {
    #[must_use]
    pub(super) const fn is_fenced(&self) -> bool {
        matches!(self, Self::Unresolved(_))
    }

    #[must_use]
    pub(super) fn bindings(&self) -> &[StoreRecoveryReopenFence] {
        match self {
            Self::Clear => &[],
            Self::Unresolved(bindings) => bindings,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ActivePhaseBRebindRecoveryKind {
    /// No active rebind lifecycle was present during journal reopen.
    None,
    /// An intent exists but no destination mutation was durably prepared.
    IntentOnly,
    /// A prepared record exists without a completed receipt; remain fail-closed.
    Prepared,
    /// A completed receipt exists; require a fresh-owner recovery CAS before
    /// replacing the lifecycle with a new publication intent.
    CompletedReceipt,
}

pub(super) fn active_phase_b_rebind_recovery_kind(
    active_phase_b_rebind: Option<&eliot_installation::ActivePhaseBRebind>,
) -> ActivePhaseBRebindRecoveryKind {
    match active_phase_b_rebind {
        Some(rebind) if rebind.receipt.is_some() => {
            ActivePhaseBRebindRecoveryKind::CompletedReceipt
        }
        Some(rebind) if rebind.prepared.is_some() => ActivePhaseBRebindRecoveryKind::Prepared,
        Some(_) => ActivePhaseBRebindRecoveryKind::IntentOnly,
        None => ActivePhaseBRebindRecoveryKind::None,
    }
}
