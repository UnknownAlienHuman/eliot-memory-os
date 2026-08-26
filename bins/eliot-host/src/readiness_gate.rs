use super::{HostBranchDisposition, HostError, JournalError, PlatformHandle};

#[cfg(windows)]
pub(super) const DEFAULT_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(windows)]
const MIN_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_millis(250);
#[cfg(windows)]
const MAX_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_mins(1);

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadinessCadence(pub(super) std::time::Duration);

#[cfg(windows)]
impl ReadinessCadence {
    pub(super) fn bounded(interval: std::time::Duration) -> Result<Self, HostError> {
        if !(MIN_READINESS_CADENCE..=MAX_READINESS_CADENCE).contains(&interval) {
            return Err(HostError::ProcessContour(format!(
                "readiness cadence must be between {}ms and {}ms",
                MIN_READINESS_CADENCE.as_millis(),
                MAX_READINESS_CADENCE.as_millis()
            )));
        }
        Ok(Self(interval))
    }

    fn deadline(self, now: std::time::Instant) -> std::time::Instant {
        now.checked_add(self.0).unwrap_or(now)
    }
}

#[cfg(windows)]
impl Default for ReadinessCadence {
    fn default() -> Self {
        match Self::bounded(DEFAULT_READINESS_CADENCE) {
            Ok(cadence) => cadence,
            Err(_) => Self(DEFAULT_READINESS_CADENCE),
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReadinessContourIdentity {
    pub(super) approved_generation: PlatformHandle,
    pub(super) approved_kernel_artifact: PlatformHandle,
    pub(super) approved_store_artifact: PlatformHandle,
    pub(super) approved_config: PlatformHandle,
    pub(super) active_kernel_record_checksum: PlatformHandle,
    pub(super) candidate_binding_digest: PlatformHandle,
    pub(super) store_requirement_digest: PlatformHandle,
    pub(super) store_proof_fence: Option<PlatformHandle>,
    pub(super) supervision_lease_id: Option<PlatformHandle>,
    pub(super) supervision_ors_receipt_digest: Option<PlatformHandle>,
    pub(super) watchdog_publication_digest: Option<PlatformHandle>,
}

#[cfg(windows)]
impl ReadinessContourIdentity {
    pub(super) fn same_probe_input_contour(&self, other: &Self) -> bool {
        self.approved_generation == other.approved_generation
            && self.approved_kernel_artifact == other.approved_kernel_artifact
            && self.approved_store_artifact == other.approved_store_artifact
            && self.approved_config == other.approved_config
            && self.active_kernel_record_checksum == other.active_kernel_record_checksum
            && self.candidate_binding_digest == other.candidate_binding_digest
            && self.store_requirement_digest == other.store_requirement_digest
            && self.supervision_lease_id == other.supervision_lease_id
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadinessFailureKind {
    ContourUnavailable,
    ProbeRejected,
    DeliveryUnknown,
    JournalRejected,
    JournalOutcomeUnknown,
}

#[cfg(windows)]
pub(super) fn readiness_failure_kind(error: &HostError) -> ReadinessFailureKind {
    match error {
        HostError::RecoveryRequired(_) => ReadinessFailureKind::DeliveryUnknown,
        HostError::Journal(JournalError::OutcomeUnknown { .. }) => {
            ReadinessFailureKind::JournalOutcomeUnknown
        }
        HostError::Journal(_) => ReadinessFailureKind::JournalRejected,
        HostError::ProcessContour(_)
        | HostError::State(_)
        | HostError::Installation(_)
        | HostError::Platform(_)
        | HostError::Stopped
        | HostError::MissingInstallation
        | HostError::StoreNotLive { .. }
        | HostError::StoreRecoveryRequired(_)
        | HostError::OwnerLeaseHeld
        | HostError::OwnerLeaseRecovery(_) => ReadinessFailureKind::ProbeRejected,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadinessGateAction {
    PreserveAuthenticatedHealth,
    ProbeDue,
    RetryPending(ReadinessFailureKind),
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
        if self.lease.as_ref().is_some_and(|lease| {
            contour == Some(&lease.contour)
                && lease.contour.store_proof_fence.is_some()
                && lease.contour.supervision_lease_id.is_some()
                && lease.contour.supervision_ors_receipt_digest.is_some()
                && lease.contour.watchdog_publication_digest.is_some()
                && now < lease.valid_until
        }) {
            return ReadinessGateAction::PreserveAuthenticatedHealth;
        }
        self.lease = None;
        if let Some(retry) = self
            .retry
            .as_ref()
            .filter(|retry| retry.contour.as_ref() == contour && now < retry.retry_at)
        {
            return ReadinessGateAction::RetryPending(retry.failure);
        }
        self.retry = None;
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
            self.lease = None;
            return false;
        }
        self.lease = Some(ReadinessLease {
            contour,
            valid_until: self.cadence.deadline(now),
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
        self.lease = None;
        self.retry = Some(ReadinessRetry {
            contour,
            failure,
            retry_at: self.cadence.deadline(now),
        });
    }

    pub(super) fn branch_degraded(&mut self) {
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
                gate.fail(Some(contour), failure, now);
                HostBranchDisposition::ReadinessDegraded
            }
        },
    }
}
