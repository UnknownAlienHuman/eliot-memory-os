#[cfg(windows)]
mod contract;
#[cfg(windows)]
#[allow(
    unused_imports,
    reason = "the readiness cadence constant is a crate facade contract used by Windows tests"
)]
pub(super) use contract::{
    DEFAULT_READINESS_CADENCE, ReadinessCadence, ReadinessContourIdentity, ReadinessFailureKind,
    ReadinessGateAction, readiness_failure_kind,
};

use super::{HostBranchDisposition, HostError};
#[cfg(windows)]
use crate::journal_append::{
    HostJournalDisposition, HostJournalObservation, observe_host_journal_boundary,
};

// F-LOG-HOST-6 (#981) readiness-gate observation helper.
//
// The per-file seam of the family's shared closed vocabulary: it names the
// readiness gate boundary set and delegates to the one shared emitter. The gate
// stays the single readiness owner (I1.10): its records report the lease, retry
// and grant dispositions the gate itself decided, and none of them is a
// readiness lifecycle state of its own (I14.20). A readiness grant refusal is a
// business outcome and stays nonterminal, and the live Event Log disposition
// is observed through the facade's canonical bounded helper rather than a
// discarded probe. The pure contract helpers in `contract.rs`
// (`same_probe_input_contour`, `readiness_failure_kind`, and the closed name
// projection `ReadinessFailureKind::as_str`) remain explicit non-boundaries:
// they classify retained state and emit nothing, so no record, decision or
// lifecycle state can enter through them.
#[cfg(windows)]
fn host_readiness_gate_observe(observation: &HostJournalObservation) {
    observe_host_journal_boundary(observation);
}

#[cfg(windows)]
impl HostJournalObservation {
    /// Attaches the exact readiness contour identity this owner compared
    /// against, slot by slot.
    ///
    /// Every slot is filled through the family's own bounding builders, so no
    /// record is ever constructed behind the emitter's back and no slot can
    /// carry an unbounded value. The contour's own content-addressed binding
    /// digest identifies the whole contour; the active Kernel record checksum,
    /// Store proof fence, supervision lease, `ORS` receipt and
    /// independent-supervision publication each keep their own slot, and a
    /// proof the contour does not carry has its builder left uncalled, so that
    /// slot stays empty and reads as explicitly missing. An incomplete proof
    /// therefore can never read as a complete one (I5.16, I14.20).
    #[must_use]
    pub(super) fn with_readiness_contour(self, contour: Option<&ReadinessContourIdentity>) -> Self {
        let Some(contour) = contour else {
            return self;
        };
        let mut observation = self
            .with_contour(contour.candidate_binding_digest.as_str())
            .with_record_checksum(contour.active_kernel_record_checksum.as_str());
        if let Some(fence) = contour.store_proof_fence.as_ref() {
            observation = observation.with_fence(fence.as_str());
        }
        if let Some(lease) = contour.supervision_lease_id.as_ref() {
            observation = observation.with_lease(lease.as_str());
        }
        if let Some(receipt) = contour.supervision_ors_receipt_digest.as_ref() {
            observation = observation.with_ors_receipt(receipt.as_str());
        }
        if let Some(publication) = contour.watchdog_publication_digest.as_ref() {
            observation = observation.with_watchdog(publication.as_str());
        }
        observation
    }
}

/// Why the gate still holds, or no longer holds, the lease it retained.
///
/// The `Valid` arm is exactly the gate's own admission predicate. Every other
/// arm only names the fact that made a retained lease unusable for this exact
/// contour, so the classification never widens or narrows the gate's decision
/// and never becomes a readiness lifecycle of its own (I14.20).
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseDisposition {
    Valid,
    Expired,
    ContourMoved,
    ProofIncomplete,
    Absent,
}

#[cfg(windows)]
impl LeaseDisposition {
    fn of(
        lease: Option<&ReadinessLease>,
        contour: Option<&ReadinessContourIdentity>,
        now: std::time::Instant,
    ) -> Self {
        match lease {
            None => Self::Absent,
            Some(lease) => {
                if contour != Some(&lease.contour) {
                    Self::ContourMoved
                } else if lease.contour.store_proof_fence.is_none()
                    || lease.contour.supervision_lease_id.is_none()
                    || lease.contour.supervision_ors_receipt_digest.is_none()
                    || lease.contour.watchdog_publication_digest.is_none()
                {
                    Self::ProofIncomplete
                } else if now >= lease.valid_until {
                    Self::Expired
                } else {
                    Self::Valid
                }
            }
        }
    }

    /// Closed disposition name for this retained-lease fact.
    const fn disposition(self) -> HostJournalDisposition {
        match self {
            Self::Valid => HostJournalDisposition::LeaseValid,
            Self::Expired => HostJournalDisposition::LeaseExpired,
            Self::ContourMoved => HostJournalDisposition::LeaseContourMoved,
            Self::ProofIncomplete => HostJournalDisposition::LeaseProofIncomplete,
            Self::Absent => HostJournalDisposition::LeaseAbsent,
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ReadinessLease {
    contour: ReadinessContourIdentity,
    valid_until: std::time::Instant,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ReadinessRetry {
    contour: Option<ReadinessContourIdentity>,
    failure: ReadinessFailureKind,
    retry_at: std::time::Instant,
}

#[cfg(windows)]
#[derive(Debug, Default)]
pub(super) struct HostReadinessGate {
    cadence: ReadinessCadence,
    lease: Option<ReadinessLease>,
    retry: Option<ReadinessRetry>,
}

#[cfg(windows)]
impl HostReadinessGate {
    pub(super) fn with_cadence(cadence: ReadinessCadence) -> Self {
        Self {
            cadence,
            lease: None,
            retry: None,
        }
    }

    pub(super) fn action(
        &mut self,
        contour: Option<&ReadinessContourIdentity>,
        now: std::time::Instant,
    ) -> ReadinessGateAction {
        // Only a complete contour under a live lease preserves health. The
        // classification below is exactly that predicate, so the retained lease
        // is dropped on precisely the same condition as before; what changes is
        // that the fact which dropped it is now named, instead of a later
        // record reading as this contour's first appearance (I14.20).
        let lease = LeaseDisposition::of(self.lease.as_ref(), contour, now);
        if lease == LeaseDisposition::Valid {
            host_readiness_gate_observe(
                &HostJournalObservation::new(
                    "host.readiness lease hit observed",
                    HostJournalDisposition::LeaseValid,
                )
                .with_readiness_contour(contour),
            );
            return ReadinessGateAction::PreserveAuthenticatedHealth;
        }
        host_readiness_gate_observe(
            &HostJournalObservation::new(
                "host.readiness lease not retained observed",
                lease.disposition(),
            )
            .with_readiness_contour(contour),
        );
        self.lease = None;
        if let Some(retry) = self
            .retry
            .as_ref()
            .filter(|retry| retry.contour.as_ref() == contour && now < retry.retry_at)
        {
            host_readiness_gate_observe(
                &HostJournalObservation::new(
                    "host.readiness retry pending observed",
                    HostJournalDisposition::RetryPending,
                )
                .with_failure(retry.failure.as_str())
                .with_readiness_contour(retry.contour.as_ref()),
            );
            return ReadinessGateAction::RetryPending(retry.failure);
        }
        self.retry = None;
        host_readiness_gate_observe(
            &HostJournalObservation::new(
                "host.readiness probe due observed",
                HostJournalDisposition::ProbeDue,
            )
            .with_readiness_contour(contour),
        );
        ReadinessGateAction::ProbeDue
    }

    pub(super) fn grant(
        &mut self,
        contour: ReadinessContourIdentity,
        now: std::time::Instant,
    ) -> bool {
        if contour.store_proof_fence.is_none()
            || contour.supervision_lease_id.is_none()
            || contour.supervision_ors_receipt_digest.is_none()
            || contour.watchdog_publication_digest.is_none()
        {
            host_readiness_gate_observe(
                &HostJournalObservation::new(
                    "host.readiness grant rejected observed",
                    HostJournalDisposition::ReadinessRefused,
                )
                .with_readiness_contour(Some(&contour)),
            );
            self.lease = None;
            return false;
        }
        let valid_until = self.cadence.deadline(now);
        host_readiness_gate_observe(
            &HostJournalObservation::new(
                "host.readiness grant observed",
                HostJournalDisposition::ReadinessGranted,
            )
            .with_readiness_contour(Some(&contour)),
        );
        self.lease = Some(ReadinessLease {
            contour,
            valid_until,
        });
        self.retry = None;
        true
    }

    pub(super) fn fail(
        &mut self,
        contour: Option<ReadinessContourIdentity>,
        failure: ReadinessFailureKind,
        now: std::time::Instant,
    ) {
        host_readiness_gate_observe(
            &HostJournalObservation::new(
                "host.readiness degraded observed",
                HostJournalDisposition::ReadinessDegraded,
            )
            .with_failure(failure.as_str())
            .with_readiness_contour(contour.as_ref()),
        );
        self.lease = None;
        self.retry = Some(ReadinessRetry {
            contour,
            failure,
            retry_at: self.cadence.deadline(now),
        });
    }

    pub(super) fn branch_degraded(&mut self) {
        host_readiness_gate_observe(&HostJournalObservation::new(
            "host.readiness branch degraded observed",
            HostJournalDisposition::BranchDegraded,
        ));
        self.lease = None;
        self.retry = None;
    }

    #[cfg(test)]
    pub(super) fn last_failure(&self) -> Option<ReadinessFailureKind> {
        self.retry.as_ref().map(|retry| retry.failure)
    }
}

#[cfg(windows)]
pub(super) fn reconcile_authenticated_readiness(
    gate: &mut HostReadinessGate,
    contour: Result<ReadinessContourIdentity, HostError>,
    now: std::time::Instant,
    authenticate_and_journal: impl FnOnce() -> Result<ReadinessContourIdentity, HostError>,
) -> HostBranchDisposition {
    let contour = match contour {
        Ok(contour) => contour,
        Err(_error) => {
            host_readiness_gate_observe(
                &HostJournalObservation::new(
                    "host.readiness contour unavailable observed",
                    HostJournalDisposition::ReadinessDegraded,
                )
                .with_failure(ReadinessFailureKind::ContourUnavailable.as_str()),
            );
            gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
            return HostBranchDisposition::ReadinessDegraded;
        }
    };
    match gate.action(Some(&contour), now) {
        ReadinessGateAction::PreserveAuthenticatedHealth => HostBranchDisposition::Healthy,
        ReadinessGateAction::RetryPending(_failure) => HostBranchDisposition::ReadinessDegraded,
        ReadinessGateAction::ProbeDue => match authenticate_and_journal() {
            Ok(journaled_contour) => {
                if gate.grant(journaled_contour, now) {
                    HostBranchDisposition::Healthy
                } else {
                    gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
                    HostBranchDisposition::ReadinessDegraded
                }
            }
            Err(error) => {
                let failure = readiness_failure_kind(&error);
                host_readiness_gate_observe(
                    &HostJournalObservation::new(
                        "host.readiness probe failed observed",
                        HostJournalDisposition::ReadinessDegraded,
                    )
                    .with_failure(failure.as_str())
                    .with_readiness_contour(Some(&contour)),
                );
                gate.fail(Some(contour), failure, now);
                HostBranchDisposition::ReadinessDegraded
            }
        },
    }
}
