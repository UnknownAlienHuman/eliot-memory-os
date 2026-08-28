//! Readiness cadence, contour, and classification contract.
//!
//! Architecture anchors: `docs/architecture/ELIOT_ARCHITECTURE.md` section
//! `A2.2` (Host Supervisor), `A13.2` (Kernel and failure domains), and `A13.3`
//! (Module supervision and Doctor). Implementation anchors:
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` section `I1.2` (Host
//! ownership), `I1.4` (supervision tree), `I1.8` (exact ownership and call
//! paths), and `I1.10` (service health state model).
//!
//! This child owns only the immutable readiness values and pure classification
//! helpers. It owns no lease/retry state, lifecycle reconciliation, journal
//! append, process effect, or authority transition; those remain in the parent
//! readiness-gate facade and Host composition.

use super::super::{HostError, JournalError, PlatformHandle};

#[cfg(windows)]
pub(crate) const DEFAULT_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(windows)]
const MIN_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_millis(250);
#[cfg(windows)]
const MAX_READINESS_CADENCE: std::time::Duration = std::time::Duration::from_mins(1);

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadinessCadence(pub(crate) std::time::Duration);

#[cfg(windows)]
impl ReadinessCadence {
    pub(crate) fn bounded(interval: std::time::Duration) -> Result<Self, HostError> {
        if !(MIN_READINESS_CADENCE..=MAX_READINESS_CADENCE).contains(&interval) {
            return Err(HostError::ProcessContour(format!(
                "readiness cadence must be between {}ms and {}ms",
                MIN_READINESS_CADENCE.as_millis(),
                MAX_READINESS_CADENCE.as_millis()
            )));
        }
        Ok(Self(interval))
    }

    pub(super) fn deadline(self, now: std::time::Instant) -> std::time::Instant {
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
pub(crate) struct ReadinessContourIdentity {
    pub(crate) approved_generation: PlatformHandle,
    pub(crate) approved_kernel_artifact: PlatformHandle,
    pub(crate) approved_store_artifact: PlatformHandle,
    pub(crate) approved_config: PlatformHandle,
    pub(crate) active_kernel_record_checksum: PlatformHandle,
    pub(crate) candidate_binding_digest: PlatformHandle,
    pub(crate) store_requirement_digest: PlatformHandle,
    pub(crate) store_proof_fence: Option<PlatformHandle>,
    pub(crate) supervision_lease_id: Option<PlatformHandle>,
    pub(crate) supervision_ors_receipt_digest: Option<PlatformHandle>,
    pub(crate) watchdog_publication_digest: Option<PlatformHandle>,
}

#[cfg(windows)]
impl ReadinessContourIdentity {
    pub(crate) fn same_probe_input_contour(&self, other: &Self) -> bool {
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
pub(crate) enum ReadinessFailureKind {
    ContourUnavailable,
    ProbeRejected,
    DeliveryUnknown,
    JournalRejected,
    JournalOutcomeUnknown,
}

#[cfg(windows)]
pub(crate) fn readiness_failure_kind(error: &HostError) -> ReadinessFailureKind {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessGateAction {
    PreserveAuthenticatedHealth,
    ProbeDue,
    RetryPending(ReadinessFailureKind),
}
