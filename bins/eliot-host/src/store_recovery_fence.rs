use super::{HostError, HostInstallationEpoch, HostState, StoreRebindHandoff, StoreRebindState};
#[cfg(windows)]
use super::{
    StoreRecoveryInnerBinding, StoreRecoveryPendingIdentity, StoreRecoveryTerminationEvidence,
};
use crate::journal_append::{
    HostJournalDisposition, HostJournalObservation, observe_host_journal_boundary,
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

// F-LOG-HOST-6 (#981) recovery-fence observation helper.
//
// The per-file seam of the family's shared closed vocabulary: it names the Store
// recovery fence boundary set and delegates to the one shared emitter.
//
// Observation-only contract: every record travels with the exact durable
// binding identity the fence already holds — its mutation digest, request
// identity, request digest, durable Host epoch and lineage, and the inner
// rebind operation identity — never evidence bytes, process identity or error
// text, so bounding limits size, not sensitivity (I15.4). Fenced and clear stay
// distinct: the fence lifts only on exact owner clearance, and an absent inner
// journal record stays a recoverable unknown, never permission for a fresh
// contour (I14.21). `StoreRecoveryStartupFence` and
// `ActivePhaseBRebindRecoveryKind` remain pure state vocabulary (explicit
// non-boundaries) and never log. These primitives own no terminal, and the live
// Event Log disposition is observed through the facade's canonical bounded
// helper rather than a discarded probe.
fn host_recovery_fence_observe(observation: &HostJournalObservation) {
    observe_host_journal_boundary(observation);
}

impl StoreRecoveryReopenFence {
    #[cfg(windows)]
    pub(super) fn from_durable(
        mutation_digest: String,
        pending: StoreRecoveryPendingIdentity,
        termination: Option<StoreRecoveryTerminationEvidence>,
        inner: Option<StoreRecoveryInnerBinding>,
    ) -> Result<Self, HostError> {
        host_recovery_fence_observe(
            &HostJournalObservation::new(
                "host.recovery fence requested",
                HostJournalDisposition::BoundaryReached,
            )
            .with_mutation(mutation_digest.as_str()),
        );
        pending.recover_request()?;
        if pending.mutation_digest != mutation_digest {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery filename mismatch observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_mutation(mutation_digest.as_str())
                .with_operation(pending.request_id.as_str())
                .with_request_digest(pending.request_digest.as_str())
                .with_host_epoch(pending.host_epoch)
                .with_host_lineage(pending.host_lineage.as_str()),
            );
            return Err(HostError::RecoveryRequired(
                "Store recovery filename and pending mutation differ".to_owned(),
            ));
        }
        if let Some(termination) = termination.as_ref() {
            termination.validate_for_pending(&pending)?;
        }
        if let Some(inner) = inner.as_ref() {
            let termination = termination.as_ref().ok_or_else(|| {
                host_recovery_fence_observe(
                    &HostJournalObservation::new(
                        "host.recovery inner without termination observed",
                        HostJournalDisposition::EvidenceIncomplete,
                    )
                    .with_mutation(pending.mutation_digest.as_str())
                    .with_operation(pending.request_id.as_str()),
                );
                HostError::RecoveryRequired(
                    "Store recovery inner binding has no termination evidence".to_owned(),
                )
            })?;
            inner.validate_for_pending(&pending, termination)?;
        }
        let fence = Self {
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
        };
        host_recovery_fence_observe(
            &HostJournalObservation::new(
                "host.recovery fence bound observed",
                if fence.termination.is_some() {
                    HostJournalDisposition::FenceBound
                } else {
                    HostJournalDisposition::EvidenceIncomplete
                },
            )
            .with_mutation(fence.mutation_digest.as_str())
            .with_operation(fence.request_id.as_str())
            .with_request_digest(fence.request_digest.as_str())
            .with_host_epoch(fence.host_epoch)
            .with_host_lineage(fence.host_lineage.as_str()),
        );
        Ok(fence)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn validate_for_reopen(
        &self,
        last_host: &HostInstallationEpoch,
        replayed: &HostState,
    ) -> Result<(), HostError> {
        if self.host_epoch != last_host.epoch.current.sequence.get()
            || self.host_lineage != last_host.epoch.current.lineage_id.as_str()
            || replayed.host != *last_host
        {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery foreign epoch observed",
                    HostJournalDisposition::EvidenceForeign,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(self.request_id.as_str())
                // This arm fires only because this fence's own epoch or lineage
                // differs from the replayed one, so the record has to carry the
                // fence's identity: `with_host` writes `installation`,
                // `host_epoch` and `host_lineage` too, and the emitter is
                // last-write-wins, so binding `last_host` here would report the
                // matching values and hide the foreign subject entirely. The
                // compared-against side is already reported by the caller's
                // earlier `host.epoch reopen existing requested` record in
                // `host_epoch_reopen.rs`, which binds `with_host(last_host)`
                // before this fence is ever validated. The caller's later
                // `host.epoch reopen fence observed` record binds that same
                // retained value but is unreachable from this arm, because this
                // refusal propagates out of the reopen before it is emitted.
                .with_host_epoch(self.host_epoch)
                .with_host_lineage(self.host_lineage.as_str()),
            );
            return Err(HostError::RecoveryRequired(
                "Store recovery fence belongs to another durable Host epoch".to_owned(),
            ));
        }
        let Some(inner) = self.inner.as_ref() else {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery fence no inner observed",
                    HostJournalDisposition::EvidenceIncomplete,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(self.request_id.as_str())
                .with_request_digest(self.request_digest.as_str()),
            );
            return Ok(());
        };
        inner
            .handoff
            .validate_canonical_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if inner.handoff.operation_id.as_str() != inner.operation_id
            || inner.handoff.request_digest != inner.request_digest
        {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery handoff substituted observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(inner.operation_id.as_str())
                .with_request_digest(inner.request_digest.as_str()),
            );
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
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery inner absent unknown observed",
                    HostJournalDisposition::FenceInnerUnresolved,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(inner.operation_id.as_str())
                .with_request_digest(inner.request_digest.as_str())
                .with_host_epoch(self.host_epoch),
            );
            return Ok(());
        };
        if records.next().is_some() {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery fence multiple inner observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(inner.operation_id.as_str())
                .with_request_digest(inner.request_digest.as_str()),
            );
            return Err(HostError::RecoveryRequired(
                "Store recovery fence matched multiple inner journal records".to_owned(),
            ));
        }
        if record.request_digest.as_str() != inner.request_digest {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery inner digest substituted observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(inner.operation_id.as_str())
                .with_request_digest(inner.request_digest.as_str())
                .with_record_fence(&record.fence),
            );
            return Err(HostError::RecoveryRequired(
                "Store recovery inner request digest was substituted".to_owned(),
            ));
        }
        let activation = replayed.activation.as_ref().ok_or_else(|| {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery inner no activation observed",
                    HostJournalDisposition::EvidenceIncomplete,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(inner.operation_id.as_str()),
            );
            HostError::RecoveryRequired(
                "Store recovery inner record has no durable activation fence".to_owned(),
            )
        })?;
        if record.fence != activation.fence || record.fence.host != *last_host {
            host_recovery_fence_observe(
                &HostJournalObservation::new(
                    "host.recovery inner wrong activation observed",
                    HostJournalDisposition::EvidenceForeign,
                )
                .with_mutation(self.mutation_digest.as_str())
                .with_operation(inner.operation_id.as_str())
                .with_record_fence(&record.fence),
            );
            return Err(HostError::RecoveryRequired(
                "Store recovery inner record is bound to another activation".to_owned(),
            ));
        }
        if record.state == StoreRebindState::Committed {
            let termination = self.termination.as_ref().ok_or_else(|| {
                host_recovery_fence_observe(
                    &HostJournalObservation::new(
                        "host.recovery committed without termination observed",
                        HostJournalDisposition::EvidenceIncomplete,
                    )
                    .with_mutation(self.mutation_digest.as_str())
                    .with_operation(inner.operation_id.as_str()),
                );
                HostError::RecoveryRequired(
                    "committed Store recovery has no exact termination evidence".to_owned(),
                )
            })?;
            if record.process_id == termination.process_id
                && record.process_start_time_100ns == termination.process_start_time_100ns
                && record.process_image_path.as_str() == termination.process_image_path
                && record.job_name.as_str() == termination.job_name
            {
                host_recovery_fence_observe(
                    &HostJournalObservation::new(
                        "host.recovery predecessor committed observed",
                        HostJournalDisposition::FenceBound,
                    )
                    .with_mutation(self.mutation_digest.as_str())
                    .with_operation(inner.operation_id.as_str())
                    .with_record_fence(&record.fence),
                );
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
