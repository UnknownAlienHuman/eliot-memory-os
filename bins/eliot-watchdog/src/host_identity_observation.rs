//! Read-only Host identity observation for the independent Watchdog.
//!
//! Source-backed Architecture: `ELIOT_ARCHITECTURE.md` A8.1, `ARCH-WDG-01`.
//! Source-backed Implementation: `ELIOT_IMPLEMENTATION.md` I8.1, I8.2.
//!
//! This cell forbids start, stop, restart, and kill effects; semantic or
//! canonical authority; and spool, composition, self-admission, or SCM
//! authority. It emits observation evidence only.

#[cfg(test)]
use eliot_platform_windows::WindowsAdapterError;
use eliot_platform_windows::{
    NamedPipePeerProcessBinding, ProcessIdentity, ProtectedPathLease, WindowsPlatform,
    windows_paths_equal,
};
use eliot_runtime_contracts::VerifiedSupervisionLease;

use super::{
    ApprovedHostRegistration, GapRecoveryReason, WatchdogRuntimeBinding, WatchdogRuntimeReadback,
    WatchdogRuntimeState, project_service_runtime_inspection,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Result of one read-only Host liveness observation.  This is evidence only;
/// it never grants authority to start, stop, restart, or kill a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostObservation {
    pub state: HostObservationState,
    pub identity: Option<ProcessIdentity>,
}

impl HostObservation {
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self.state, HostObservationState::Running)
    }

    #[must_use]
    pub const fn gap_reason(&self) -> Option<GapRecoveryReason> {
        match self.state {
            HostObservationState::Running => None,
            HostObservationState::AbsentOrStopped => Some(GapRecoveryReason::HostAbsentOrStopped),
            HostObservationState::PidReused => Some(GapRecoveryReason::HostPidReused),
            HostObservationState::ImageSubstituted => Some(GapRecoveryReason::HostImageSubstituted),
            HostObservationState::IdentityChanged => Some(GapRecoveryReason::HostIdentityChanged),
            HostObservationState::Unknown => Some(GapRecoveryReason::HostUnknown),
        }
    }
}

/// Process-identity state machine used by the Watchdog's read-only Host sensor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostObservationState {
    Running,
    AbsentOrStopped,
    PidReused,
    ImageSubstituted,
    IdentityChanged,
    Unknown,
}

/// Retains the last trusted Host process identity and compares every later
/// platform observation against PID, creation time, and image path.
#[derive(Debug)]
pub struct HostIdentityMonitor {
    canonical: Option<ProcessIdentity>,
    expected_image: Option<PathBuf>,
    expected_registration: Option<ApprovedHostRegistration>,
    expected_image_lease: Option<ProtectedPathLease>,
    require_image_lease: bool,
    require_registration_readback: bool,
}

impl HostIdentityMonitor {
    #[must_use]
    pub fn new(expected_image: Option<PathBuf>) -> Self {
        Self {
            canonical: None,
            expected_image,
            expected_registration: None,
            expected_image_lease: None,
            require_image_lease: false,
            require_registration_readback: false,
        }
    }

    fn with_approved_image_lease(
        expected_image: PathBuf,
        lease: ProtectedPathLease,
        expected_registration: ApprovedHostRegistration,
    ) -> Self {
        Self {
            canonical: None,
            expected_image: Some(expected_image),
            expected_registration: Some(expected_registration),
            expected_image_lease: Some(lease),
            require_image_lease: true,
            require_registration_readback: true,
        }
    }

    fn with_unavailable_image_lease(
        expected_image: PathBuf,
        expected_registration: ApprovedHostRegistration,
    ) -> Self {
        Self {
            canonical: None,
            expected_image: Some(expected_image),
            expected_registration: Some(expected_registration),
            expected_image_lease: None,
            require_image_lease: true,
            require_registration_readback: true,
        }
    }

    #[must_use]
    pub fn canonical_identity(&self) -> Option<&ProcessIdentity> {
        self.canonical.as_ref()
    }

    /// Clears the prior process identity after a fresh lease has been
    /// independently verified. A new process is never trusted merely because
    /// it appeared; the caller must establish the lease boundary first.
    pub fn rebaseline(&mut self) {
        self.canonical = None;
    }

    /// Observes the canonical `EliotHost` service through the existing Windows
    /// runtime readback primitive and classifies all non-authoritative
    /// outcomes. Configuration and process identity are read atomically from
    /// one SCM query; a second status/PID query is deliberately not used.
    #[must_use]
    pub fn observe(&mut self) -> HostObservation {
        if self.require_image_lease
            && self.expected_image_lease.is_none()
            && let Some(expected_image) = self.expected_image.as_deref()
            && let Ok(lease) = ProtectedPathLease::open_existing_absolute(expected_image)
        {
            self.expected_image_lease = Some(lease);
        }
        if self.require_image_lease
            && (self.expected_image_lease.is_none()
                || self.expected_image_lease.as_ref().is_some_and(|lease| {
                    lease.verify_stable_identity().is_err() || lease.verify_path_identity().is_err()
                }))
        {
            return HostObservation {
                state: HostObservationState::Unknown,
                identity: None,
            };
        }
        if self.require_registration_readback {
            let runtime = self.expected_registration.as_ref().map_or(
                WatchdogRuntimeReadback::Unknown,
                read_host_registration_runtime,
            );
            return self.observe_runtime_readback(runtime);
        }
        HostObservation {
            state: HostObservationState::Unknown,
            identity: None,
        }
    }

    #[must_use]
    pub(super) fn observe_runtime_readback(
        &mut self,
        runtime: WatchdogRuntimeReadback,
    ) -> HostObservation {
        match runtime {
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Running,
                process: Some(process),
                ..
            } => self.observe_process_identity(process),
            WatchdogRuntimeReadback::Matching {
                state:
                    WatchdogRuntimeState::Stopped
                    | WatchdogRuntimeState::Starting
                    | WatchdogRuntimeState::Stopping,
                ..
            }
            | WatchdogRuntimeReadback::Absent => HostObservation {
                state: HostObservationState::AbsentOrStopped,
                identity: None,
            },
            WatchdogRuntimeReadback::Matching {
                state:
                    WatchdogRuntimeState::Absent
                    | WatchdogRuntimeState::Running
                    | WatchdogRuntimeState::Unknown,
                ..
            }
            | WatchdogRuntimeReadback::Mismatched
            | WatchdogRuntimeReadback::Unknown => HostObservation {
                state: HostObservationState::Unknown,
                identity: None,
            },
        }
    }

    /// Applies one sealed platform identity. This small seam keeps PID-reuse
    /// and image-substitution tests independent from a live SCM installation.
    #[must_use]
    pub fn observe_identity(&mut self, binding: &NamedPipePeerProcessBinding) -> HostObservation {
        self.observe_process_identity(binding.identity().clone())
    }

    #[must_use]
    pub(super) fn observe_process_identity(
        &mut self,
        observed: ProcessIdentity,
    ) -> HostObservation {
        if self
            .expected_image
            .as_deref()
            .is_some_and(|expected| !windows_paths_equal(Path::new(&observed.image_path), expected))
        {
            return HostObservation {
                state: HostObservationState::ImageSubstituted,
                identity: Some(observed),
            };
        }
        let Some(canonical) = self.canonical.as_ref() else {
            self.canonical = Some(observed.clone());
            return HostObservation {
                state: HostObservationState::Running,
                identity: Some(observed),
            };
        };
        let state = if observed.process_id == canonical.process_id
            && observed.start_time_100ns != canonical.start_time_100ns
        {
            HostObservationState::PidReused
        } else if observed.process_id == canonical.process_id
            && observed.start_time_100ns == canonical.start_time_100ns
            && !windows_paths_equal(
                Path::new(&observed.image_path),
                Path::new(&canonical.image_path),
            )
        {
            HostObservationState::ImageSubstituted
        } else if observed == *canonical {
            HostObservationState::Running
        } else {
            HostObservationState::IdentityChanged
        };
        HostObservation {
            state,
            identity: Some(observed),
        }
    }
}

#[cfg(test)]
#[must_use]
pub(super) fn classify_host_error(error: WindowsAdapterError) -> HostObservationState {
    match error {
        WindowsAdapterError::Unavailable => HostObservationState::AbsentOrStopped,
        _ => HostObservationState::Unknown,
    }
}

/// Source of read-only Host process observations.
pub trait HostObservationSource: Send + Sync + 'static {
    fn observe(&self) -> HostObservation;

    /// Permits a process-identity rebaseline only after the composition has
    /// verified a fresh supervision lease. The default is deliberately a
    /// no-op for test/read-only sources.
    fn rebaseline_after_verified_lease(&self, _lease: &VerifiedSupervisionLease) {}
}

/// Production observation source backed by the canonical `EliotHost` SCM
/// query. It retains no process handle, only a read-only image identity lease,
/// and cannot perform lifecycle effects.
pub struct LiveHostObservationSource {
    monitor: Mutex<HostIdentityMonitor>,
}

impl LiveHostObservationSource {
    #[must_use]
    pub fn new(expected_image: PathBuf) -> Self {
        Self {
            monitor: Mutex::new(HostIdentityMonitor::new(Some(expected_image))),
        }
    }

    /// Creates the production observer from a registry-bound runtime
    /// binding. The caller cannot provide or replace the SCM request.
    #[must_use]
    pub fn from_binding(binding: &WatchdogRuntimeBinding) -> Self {
        Self::try_new(
            binding.approved_host_image.clone(),
            binding.approved_host_registration.clone(),
        )
    }

    /// Opens the approved Host image through the protected no-follow adapter
    /// so a same-path replacement is an identity gap, not a fresh baseline.
    /// If the image cannot be retained, the source stays alive but emits only
    /// fail-closed `Unknown` observations until the approved image can be
    /// retained again.
    #[must_use]
    pub fn try_new(
        expected_image: PathBuf,
        expected_registration: ApprovedHostRegistration,
    ) -> Self {
        let monitor = match ProtectedPathLease::open_existing_absolute(&expected_image) {
            Ok(lease) => HostIdentityMonitor::with_approved_image_lease(
                expected_image,
                lease,
                expected_registration,
            ),
            Err(_) => HostIdentityMonitor::with_unavailable_image_lease(
                expected_image,
                expected_registration,
            ),
        };
        Self {
            monitor: Mutex::new(monitor),
        }
    }
}

impl HostObservationSource for LiveHostObservationSource {
    fn observe(&self) -> HostObservation {
        self.monitor.lock().map_or(
            HostObservation {
                state: HostObservationState::Unknown,
                identity: None,
            },
            |mut monitor| monitor.observe(),
        )
    }

    fn rebaseline_after_verified_lease(&self, _lease: &VerifiedSupervisionLease) {
        if let Ok(mut monitor) = self.monitor.lock() {
            monitor.rebaseline();
        }
    }
}

pub(super) fn read_host_registration_runtime(
    approved: &ApprovedHostRegistration,
) -> WatchdogRuntimeReadback {
    let registration = &approved.request;
    let Some(root) = registration.binary_path().parent() else {
        return WatchdogRuntimeReadback::Unknown;
    };
    let Ok(platform) = WindowsPlatform::new(root.to_path_buf()) else {
        return WatchdogRuntimeReadback::Unknown;
    };
    project_service_runtime_inspection(platform.inspect_service_registration_runtime(registration))
}
