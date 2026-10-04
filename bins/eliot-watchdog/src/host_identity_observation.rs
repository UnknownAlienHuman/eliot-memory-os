//! Read-only Host identity observation for the independent Watchdog.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose), ARCH-WDG-01.
//! Implementation: I8.1 (docs/architecture/I08-01-process-and-authority.md#i81-process-and-authority), I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes).
//!
//! This cell forbids start, stop, restart, and kill effects; semantic or
//! canonical authority; and spool, composition, self-admission, or SCM
//! authority. It emits observation evidence only.

use eliot_platform::PlatformHandle;
#[cfg(test)]
use eliot_platform_windows::WindowsAdapterError;
use eliot_platform_windows::{
    FileIdentity, NamedPipePeerProcessBinding, ProcessIdentity, ProtectedPathLease,
    WindowsPlatform, windows_paths_equal,
};
use eliot_runtime_contracts::VerifiedSupervisionLease;

use crate::independent_sensor::{
    ApprovedSensorBinding, ArtifactDigestObservation, observe_approved_artifact_digest,
};

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

/// What ONE fresh live readback of the approved Host registration proved.
///
/// This is an observation record, not an assertion: the registration handle is
/// reported only when the live SCM readback returned `Matching`, which is the
/// platform adapter's exact comparison of the live service configuration
/// against the installer approval this source retains. A configuration that
/// does not match reports nothing at all, because an unproven registration is
/// never an observed one.
///
/// The handle-bound process identity comes from the SAME readback, so the
/// approved registration and the runtime identity are never two separately
/// sampled values that could disagree about which Host they describe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedRegistrationReadback {
    registration: PlatformHandle,
    identity: Option<ProcessIdentity>,
}

impl ApprovedRegistrationReadback {
    /// Records what one readback proved.
    ///
    /// This is the only way to build the record, and it takes the observed
    /// values themselves rather than a verdict about them: a source that
    /// compared no approved registration has no record to build.
    #[must_use]
    pub fn new(registration: PlatformHandle, identity: Option<ProcessIdentity>) -> Self {
        Self {
            registration,
            identity,
        }
    }

    /// The installer-approved registration this readback compared the live SCM
    /// configuration against.
    #[must_use]
    pub fn registration(&self) -> &PlatformHandle {
        &self.registration
    }

    /// The handle-bound process identity the same readback carried, when the
    /// observed service state exposed one.
    #[must_use]
    pub fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
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

fn classify_runtime_state_without_identity(state: WatchdogRuntimeState) -> HostObservationState {
    match state {
        WatchdogRuntimeState::Stopped | WatchdogRuntimeState::Absent => {
            HostObservationState::AbsentOrStopped
        }
        WatchdogRuntimeState::Starting
        | WatchdogRuntimeState::Stopping
        | WatchdogRuntimeState::Running
        | WatchdogRuntimeState::Unknown => HostObservationState::Unknown,
    }
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
    /// Installer-approved generation governing the observed Host target, from
    /// the retained runtime binding. Diagnostic identity only: it is echoed in
    /// liveness observations and never influences the observation verdict.
    /// `None` (test-constructed monitors) is reported explicitly unavailable.
    observed_generation: Option<String>,
    /// Typed approved installation+generation binding governing sensor
    /// samples stamped from this monitor (#1755 W2). `None` for
    /// test-constructed monitors and for production contours built without
    /// the registry-selected manifest; without it no bound sample is issued.
    sensor_binding: Option<ApprovedSensorBinding>,
    /// Cached approved-artifact digest keyed by the retained lease identity
    /// it was read through. Re-issued only while the same lease still
    /// verifies; any lease replacement or verification failure drops it.
    artifact_digest: Option<(FileIdentity, ArtifactDigestObservation)>,
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
            observed_generation: None,
            sensor_binding: None,
            artifact_digest: None,
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
            observed_generation: None,
            sensor_binding: None,
            artifact_digest: None,
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
            observed_generation: None,
            sensor_binding: None,
            artifact_digest: None,
        }
    }

    #[must_use]
    pub fn canonical_identity(&self) -> Option<&ProcessIdentity> {
        self.canonical.as_ref()
    }

    /// Reads the approved Host registration back from live SCM at this instant
    /// and reports exactly what that one readback proved.
    ///
    /// The readback is taken HERE, not reused from an earlier liveness
    /// observation: a recovery boundary compares the approved registration
    /// against the value the operation recorded when the challenge was issued,
    /// and that comparison is only meaningful over a readback of its own.
    ///
    /// This performs no lifecycle effect: it is the same read-only
    /// [`read_host_registration_runtime`] the liveness sensor already uses.
    #[must_use]
    pub(super) fn observe_approved_registration(&self) -> Option<ApprovedRegistrationReadback> {
        let approved = self.expected_registration.as_ref()?;
        approved_registration_readback(approved, read_host_registration_runtime(approved))
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
        let _span = tracing::debug_span!("watchdog.host_observe").entered();
        // Exact available liveness identities: the approved Host service name
        // is the observed target, and the retained binding generation governs
        // it. Both are validated nonsecret coordination identities; observed
        // process values (PID, start time, image bytes) are still never
        // emitted. Missing identities stay explicitly unavailable.
        let target = self
            .expected_registration
            .as_ref()
            .map_or("unavailable".to_owned(), |registration| {
                registration.request.service_name().to_owned()
            });
        let generation = self
            .observed_generation
            .clone()
            .unwrap_or_else(|| "unavailable".to_owned());
        if self.require_image_lease
            && self.expected_image_lease.is_none()
            && let Some(expected_image) = self.expected_image.as_deref()
            && let Ok(lease) = ProtectedPathLease::open_existing_absolute(expected_image)
        {
            self.expected_image_lease = Some(lease);
            // A fresh lease unbinds any cached digest: the cached value was
            // read through a different retained handle and must never be
            // re-issued under this one.
            self.artifact_digest = None;
        }
        if self.require_image_lease
            && (self.expected_image_lease.is_none()
                || self.expected_image_lease.as_ref().is_some_and(|lease| {
                    lease.verify_stable_identity().is_err() || lease.verify_path_identity().is_err()
                }))
        {
            tracing::debug!(
                event = "watchdog.host_observed",
                observation = "unknown",
                target = target.as_str(),
                generation = generation.as_str(),
                "host image lease unavailable; observation stays unknown"
            );
            crate::diagnostics::observe_host_observation(HostObservationState::Unknown, false);
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
            let observation = self.observe_runtime_readback(runtime);
            tracing::debug!(
                event = "watchdog.host_observed",
                observation = crate::diagnostics::host_observation_diagnostic(observation.state),
                target = target.as_str(),
                generation = generation.as_str(),
                "host observation reconciled without lifecycle authority"
            );
            return observation;
        }
        tracing::debug!(
            event = "watchdog.host_observed",
            observation = "unknown",
            target = target.as_str(),
            generation = generation.as_str(),
            "no registration readback required; observation stays unknown"
        );
        crate::diagnostics::observe_host_observation(HostObservationState::Unknown, false);
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
        // SCM acknowledgement is never readiness evidence: only an exact
        // `Running` match with a handle-bound process identity reaches the
        // identity comparison. Every other `Matching` state stays without
        // identity (`Unknown` for Starting/Running-without-process, terminal
        // absence only for Stopped/Absent). `Mismatched`/`Unknown` stay
        // `Unknown` verbatim. Identity values (PID/start/image) are preserved
        // as distinctions via `observe_process_identity`, never logged.
        let observation = match runtime {
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Running,
                process: Some(process),
                ..
            } => self.observe_process_identity(process),
            WatchdogRuntimeReadback::Matching { state, .. } => HostObservation {
                state: classify_runtime_state_without_identity(state),
                identity: None,
            },
            WatchdogRuntimeReadback::Absent => HostObservation {
                state: HostObservationState::AbsentOrStopped,
                identity: None,
            },
            WatchdogRuntimeReadback::Mismatched | WatchdogRuntimeReadback::Unknown => {
                HostObservation {
                    state: HostObservationState::Unknown,
                    identity: None,
                }
            }
        };
        crate::diagnostics::observe_host_observation(
            observation.state,
            observation.identity.is_some(),
        );
        observation
    }

    /// Applies one sealed platform identity. This small seam keeps PID-reuse
    /// and image-substitution tests independent from a live SCM installation.
    #[must_use]
    pub fn observe_identity(&mut self, binding: &NamedPipePeerProcessBinding) -> HostObservation {
        self.observe_process_identity(binding.identity().clone())
    }

    /// Observes the bounded content digest of the approved Host image through
    /// the retained no-follow lease (#1755 W2).
    ///
    /// The digest is bound to the approved installation and target
    /// generation retained from the registry-selected manifest, and to the
    /// retained lease identity it was read through: a cached digest is
    /// re-issued only while the same lease still verifies and the binding is
    /// unchanged, and any verification failure drops it. Without an approved
    /// binding or lease there is no sample at all — never a digest of an
    /// unapproved path. Bytes are hashed, never retained.
    #[must_use]
    pub fn observe_approved_artifact(&mut self, limit: u64) -> Option<ArtifactDigestObservation> {
        let binding = self.sensor_binding.clone()?;
        if let Some((identity, cached)) = self.artifact_digest.clone()
            && cached.installation() == binding.installation()
            && cached.generation() == binding.generation()
            && let Some(lease) = self.expected_image_lease.as_ref()
            && lease.identity() == identity
            && lease.verify_stable_identity().is_ok()
            && lease.verify_path_identity().is_ok()
        {
            return Some(cached);
        }
        let lease = self.expected_image_lease.as_ref()?;
        match observe_approved_artifact_digest(&binding, lease, limit) {
            Ok(observation) => {
                self.artifact_digest = Some((lease.identity(), observation.clone()));
                Some(observation)
            }
            Err(error) => {
                self.artifact_digest = None;
                tracing::debug!(
                    event = "watchdog.artifact_digest_probe_failed",
                    observation = "unobserved",
                    reason = error.to_string(),
                    "approved artifact digest unavailable; no ArtifactDigest sample this interval"
                );
                None
            }
        }
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

    /// Observes the bounded content digest of the approved Host image
    /// through the source's retained no-follow lease (#1755 W2). The default
    /// is deliberately `None` for test/read-only sources without an
    /// approved binding: no sample is better than an unbound one.
    fn observe_approved_artifact(&self, _limit: u64) -> Option<ArtifactDigestObservation> {
        None
    }

    /// Permits a process-identity rebaseline only after the composition has
    /// verified a fresh supervision lease. The default is deliberately a
    /// no-op for test/read-only sources.
    fn rebaseline_after_verified_lease(&self, _lease: &VerifiedSupervisionLease) {}

    /// Reads the installer-approved Host registration back from live SCM and
    /// reports what that one readback proved.
    ///
    /// A recovery boundary must revalidate the approved registration against
    /// the live system by CONTENT, and this is the only read-only route to
    /// that value on this contour. The default is deliberately `None` for
    /// test/read-only sources that retain no installer approval: a source that
    /// compared no approved registration offers no registration evidence, which
    /// the boundary reads as an explicit refusal and never as agreement.
    fn observe_approved_registration(&self) -> Option<ApprovedRegistrationReadback> {
        None
    }
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
        let source = Self::try_new(
            binding.approved_host_image.clone(),
            binding.approved_host_registration.clone(),
        );
        // Bind the exact approved generation governing the observed Host
        // target for liveness-observation identity. The observation verdict
        // never reads this value; a lock failure only leaves the generation
        // explicitly unavailable in later records.
        //
        // The same retained manifest also stamps the typed sensor binding
        // (#1755 W2) that bound artifact samples carry. A manifest whose
        // retained values cannot bind refuses here and is traced: the
        // artifact sensor then issues no sample rather than an unbound one.
        let sensor_binding = match ApprovedSensorBinding::from_candidate_manifest(
            &binding.selected_manifest,
        ) {
            Ok(bound) => Some(bound),
            Err(error) => {
                tracing::debug!(
                    event = "watchdog.sensor_binding_refused",
                    observation = "unbound",
                    reason = error.to_string(),
                    "registry-selected manifest cannot bind sensor samples; artifact observations stay unobserved"
                );
                None
            }
        };
        if let Ok(mut monitor) = source.monitor.lock() {
            monitor.observed_generation =
                Some(binding.selected_manifest.generation.as_str().to_owned());
            monitor.sensor_binding = sensor_binding;
        }
        source
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

    fn observe_approved_artifact(&self, limit: u64) -> Option<ArtifactDigestObservation> {
        self.monitor
            .lock()
            .ok()
            .and_then(|mut monitor| monitor.observe_approved_artifact(limit))
    }

    fn rebaseline_after_verified_lease(&self, _lease: &VerifiedSupervisionLease) {
        if let Ok(mut monitor) = self.monitor.lock() {
            monitor.rebaseline();
        }
    }

    fn observe_approved_registration(&self) -> Option<ApprovedRegistrationReadback> {
        self.monitor
            .lock()
            .ok()
            .and_then(|monitor| monitor.observe_approved_registration())
    }
}

/// Maps one live SCM readback onto the approved-registration evidence that
/// readback actually proved.
///
/// The content handle is the approved registration's own identity, taken from
/// the request `ApprovedHostRegistration` retains. That request is what
/// `InstallerServiceRegistrationApproval::service_registration_request`
/// reconstructed FROM the approval after
/// `InstallerServiceRegistrationApproval::validate`, and it refuses any
/// approval whose request does not reproduce the approval's recorded
/// `configuration_digest`; so this handle is that recorded digest, not a fresh
/// judgement about the live system and not a caller claim. It is offered only
/// when the live readback says the approved registration is still what SCM has.
///
/// `Mismatched`, `Absent` and `Unknown` yield no evidence at all. Reporting the
/// approved handle for a readback that did not match would be indistinguishable
/// from reporting it for one that did.
#[must_use]
pub(super) fn approved_registration_readback(
    approved: &ApprovedHostRegistration,
    runtime: WatchdogRuntimeReadback,
) -> Option<ApprovedRegistrationReadback> {
    let WatchdogRuntimeReadback::Matching { process, .. } = runtime else {
        return None;
    };
    let registration =
        PlatformHandle::new(approved.request.expected_configuration_digest()).ok()?;
    Some(ApprovedRegistrationReadback::new(registration, process))
}

pub(super) fn read_host_registration_runtime(
    approved: &ApprovedHostRegistration,
) -> WatchdogRuntimeReadback {
    let _span = tracing::debug_span!("watchdog.host_registration_readback").entered();
    let registration = &approved.request;
    let Some(root) = registration.binary_path().parent() else {
        tracing::debug!(
            event = "watchdog.host_readback",
            observation = "unknown",
            "approved registration has no package root; readback stays unknown"
        );
        return WatchdogRuntimeReadback::Unknown;
    };
    let Ok(platform) = WindowsPlatform::new(root.to_path_buf()) else {
        tracing::debug!(
            event = "watchdog.host_readback",
            observation = "unknown",
            "platform root unavailable; readback stays unknown"
        );
        return WatchdogRuntimeReadback::Unknown;
    };
    tracing::debug!(
        event = "watchdog.host_readback",
        observation = "attempted",
        "attempting read-only SCM registration readback"
    );
    project_service_runtime_inspection(platform.inspect_service_registration_runtime(registration))
}

/// Upper bound, in seconds, for one Watchdog responsiveness observation
/// interval. Mirrors the bounded owner-queue guarantee on the Host endpoint
/// side; a longer wait would outlive the queue and is refused at construction.
pub const MAX_CHALLENGE_WAIT_SECS: u64 = 30;

/// Bounded, cancellable observation interval for one responsiveness challenge.
///
/// Cancellation abandons the wait only: exactly as with the synchronous Event
/// Log port, abandoning a waiter never interrupts an in-flight OS call, and a
/// cancelled wait can never produce a responsiveness verdict — classification
/// of a cancelled wait stays an explicit uncertainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedChallengeWait {
    timeout_secs: u64,
    cancelled: bool,
}

impl BoundedChallengeWait {
    /// Opens a bounded wait. Refuses zero and over-bound intervals so no
    /// unbounded observation can be constructed.
    #[must_use]
    pub const fn new(timeout_secs: u64) -> Option<Self> {
        if timeout_secs == 0 || timeout_secs > MAX_CHALLENGE_WAIT_SECS {
            return None;
        }
        Some(Self {
            timeout_secs,
            cancelled: false,
        })
    }

    /// Abandons the wait. In-flight work is not interrupted; the outcome of a
    /// cancelled wait is always classified as uncertainty, never health.
    pub const fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether this wait was abandoned before a verdict.
    #[must_use]
    pub const fn is_cancelled(self) -> bool {
        self.cancelled
    }

    /// The bounded interval, in seconds, granted to the owner contour.
    #[must_use]
    pub const fn timeout_secs(self) -> u64 {
        self.timeout_secs
    }
}

/// Why a challenge attempt cannot establish responsiveness. Missing
/// authentication, a denied connection, a changed target, inadequate sensor
/// coverage, a cancelled wait, or a non-live target stays an explicit
/// uncertainty — never authenticated health and never automatic restart
/// eligibility.
///
/// The wire form is the durable record of a named uncertainty in the Watchdog
/// journal, so a stored row can say *what* was unknown instead of collapsing
/// every insufficient signal into the timeout arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ChallengeUncertainty {
    /// The challenger could not authenticate to the owner path.
    Unauthenticated,
    /// The connection was denied before any owner answer.
    ConnectionDenied,
    /// The live target changed (or was never live) across the observation.
    TargetChanged,
    /// Sensor coverage was inadequate for a competent attempt.
    InadequateCoverage,
    /// The target was not live when the attempt completed.
    TargetNotLive,
}

/// Outcome of one competently scoped challenge attempt against a validated
/// live target. A response proves only the declared control property, not
/// whole-product readiness; only the owner-path correlation validator (Host
/// endpoint lane) can establish the positive case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeAttemptOutcome {
    /// The challenge reached the validated live owner contour and the bounded
    /// wait expired with no correlated answer.
    CompetentTimeout,
    /// The attempt never became competent; see the explicit reason.
    Uncertain(ChallengeUncertainty),
}

/// Watchdog responsiveness verdict separating liveness from control ownership.
///
/// `Running` from the read-only sensor is liveness evidence only, never
/// control responsiveness: a live Host process whose control loop is stalled
/// is reported as [`HostResponsiveness::AliveUnresponsive`], never as
/// healthy. The positive case is established exclusively by the owner-path
/// challenge/response correlation owned by the Host endpoint lane.
///
/// The wire form is the durable record of one challenge outcome in the Watchdog
/// journal, so a stored row preserves which uncertainty was observed rather than
/// only that the attempt did not resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HostResponsiveness {
    /// The control owner answered the exact challenge within its bound.
    /// Established only by the owner-path correlation validator.
    Responsive,
    /// Validated live target, competently attempted challenge, bounded wait
    /// expired with no correlated owner answer.
    AliveUnresponsive,
    /// No verdict: the reason names what is unknown.
    Uncertain(ChallengeUncertainty),
}

impl HostResponsiveness {
    /// Decides recovery eligibility from this verdict, the
    /// installation-approved policy, and the durable used-attempt count.
    ///
    /// An exhausted (or zero-budget) policy yields [`RecoveryBudgetDecision::Exhausted`]:
    /// no SCM restart may be requested. `used_attempts` must be read from the
    /// durable Watchdog journal (`watchdog.redb`) — never invented from a
    /// constant and never reset by a Watchdog restart — so exhaustion persists
    /// across restarts. Durable journaling of the decision itself is owned by
    /// the Watchdog composition/spool lane (STITCH: no caller here by owner
    /// rule, one writer per shared file).
    #[must_use]
    pub fn recovery_eligibility(
        self,
        policy: &ApprovedRecoveryPolicy,
        used_attempts: u64,
    ) -> RecoveryBudgetDecision {
        match self {
            Self::Responsive => RecoveryBudgetDecision::NoRecoveryRequired,
            Self::Uncertain(_) => RecoveryBudgetDecision::ChallengeUnresolved,
            Self::AliveUnresponsive => {
                if used_attempts >= u64::from(policy.max_attempts) {
                    RecoveryBudgetDecision::Exhausted
                } else {
                    RecoveryBudgetDecision::Admitted {
                        remaining_attempts: u64::from(policy.max_attempts) - used_attempts,
                    }
                }
            }
        }
    }
}

/// Installation-approved recovery policy binding one SCM recovery operation.
///
/// Loaded from the installation's pre-authorized policy (installer lane owns
/// service configuration and pre-authorization): exact service/installation,
/// admissible Host owner-epoch lineage, permitted stop/start recipe identity,
/// failure threshold, budget window, cooldown, concurrent-attempt exclusion,
/// and audit-failure disposition. The read-only challenge permission must
/// remain usable while the Host is hung; it cannot require a fresh grant from
/// the very Host being recovered. Policy loading itself is STITCH (installer
/// owner, out of scope for this lane).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedRecoveryPolicy {
    /// Installation under recovery.
    pub installation: PlatformHandle,
    /// Exact approved service name (a name alone never authorizes an effect;
    /// the SCM boundary revalidates registration, identity, and generation).
    pub service: PlatformHandle,
    /// Admissible Host owner-epoch lineage digest.
    pub owner_epoch_digest: PlatformHandle,
    /// Permitted stop/start recipe identity.
    pub recipe_digest: PlatformHandle,
    /// Consecutive responsiveness failures before one recovery attempt.
    pub failure_threshold: u32,
    /// Total recovery attempts admitted inside one budget window.
    /// Zero is a valid policy: it admits nothing, every decision exhausts.
    pub max_attempts: u32,
    /// Budget window, in seconds; durable accounting requires a window.
    pub budget_window_secs: u64,
    /// Cooldown, in seconds, between two recovery attempts.
    pub cooldown_secs: u64,
    /// Whether concurrent recovery attempts must be excluded.
    pub exclusive_attempt: bool,
    /// Whether an audit-sink failure refuses effects instead of proceeding.
    pub audit_failure_refuses_effects: bool,
}

impl ApprovedRecoveryPolicy {
    /// Validates policy shape. Digest/handle shape is already enforced by the
    /// original [`PlatformHandle::new`] validator at construction; this checks
    /// only the numeric envelope a durable budget needs.
    ///
    /// # Errors
    ///
    /// Returns a refusal when no failure can ever be counted
    /// (`failure_threshold` is zero) or when no durable window exists
    /// (`budget_window_secs` is zero).
    pub fn validate(&self) -> Result<(), String> {
        if self.failure_threshold == 0 {
            return Err("recovery policy admits no countable failure".to_owned());
        }
        if self.budget_window_secs == 0 {
            return Err("recovery policy has no durable budget window".to_owned());
        }
        Ok(())
    }
}

/// Pure recovery-budget decision. Only [`RecoveryBudgetDecision::Admitted`]
/// permits requesting an SCM effect, and only through the fenced
/// stop/start-separated operation record owned by the Host-state lane
/// (`ScmOperationStore`); every other variant forbids effects.
///
/// The wire form is the durable record of the decision taken before an effect
/// was requested, so a stored operation names the budget verdict it was opened
/// under.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RecoveryBudgetDecision {
    /// No failure to recover: the owner answered.
    NoRecoveryRequired,
    /// One fenced recovery attempt is admitted; the count remaining in the
    /// current durable window.
    Admitted {
        /// Attempts still admitted in this window, excluding this one.
        remaining_attempts: u64,
    },
    /// Budget exhausted (or zero-budget policy): NO restart, no SCM effect.
    /// Persists across Watchdog restarts via the durable used-attempt count.
    Exhausted,
    /// The challenge never resolved; eligibility is unknown, effects refused.
    ChallengeUnresolved,
}

impl RecoveryBudgetDecision {
    /// Whether this decision admits requesting one fenced SCM effect.
    #[must_use]
    pub const fn admits_effect(self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

impl HostObservation {
    /// Classifies liveness evidence plus one challenge attempt into a
    /// responsiveness verdict. The read-only sensor is unchanged: this is a
    /// pure function of already-observed evidence.
    ///
    /// With a validated live target (`Running`) and a competently attempted
    /// challenge that timed out inside an uncancelled bounded wait, the
    /// verdict is [`HostResponsiveness::AliveUnresponsive`]. A cancelled wait,
    /// a non-live target, or an incompetent attempt stays an explicit
    /// uncertainty. Target identity must be rechecked around the bounded
    /// interval by the caller; this function classifies one instant only.
    #[must_use]
    pub fn responsiveness(
        &self,
        wait: &BoundedChallengeWait,
        attempt: &ChallengeAttemptOutcome,
    ) -> HostResponsiveness {
        if wait.is_cancelled() {
            return HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage);
        }
        match (&self.state, attempt) {
            (HostObservationState::Running, ChallengeAttemptOutcome::CompetentTimeout) => {
                HostResponsiveness::AliveUnresponsive
            }
            (_, ChallengeAttemptOutcome::Uncertain(reason)) => {
                HostResponsiveness::Uncertain(*reason)
            }
            (_, ChallengeAttemptOutcome::CompetentTimeout) => {
                HostResponsiveness::Uncertain(ChallengeUncertainty::TargetNotLive)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::installer_approval_fixture;

    #[test]
    fn transient_service_states_are_not_terminal_absence() {
        assert_eq!(
            classify_runtime_state_without_identity(WatchdogRuntimeState::Starting),
            HostObservationState::Unknown
        );
        assert_eq!(
            classify_runtime_state_without_identity(WatchdogRuntimeState::Stopping),
            HostObservationState::Unknown
        );
        assert_eq!(
            classify_runtime_state_without_identity(WatchdogRuntimeState::Running),
            HostObservationState::Unknown
        );
        assert_eq!(
            classify_runtime_state_without_identity(WatchdogRuntimeState::Unknown),
            HostObservationState::Unknown
        );
    }

    #[test]
    fn terminal_absence_states_remain_terminal_absence() {
        assert_eq!(
            classify_runtime_state_without_identity(WatchdogRuntimeState::Stopped),
            HostObservationState::AbsentOrStopped
        );
        assert_eq!(
            classify_runtime_state_without_identity(WatchdogRuntimeState::Absent),
            HostObservationState::AbsentOrStopped
        );
    }

    /// One installer-approved Host registration, built through the same owner
    /// projection production uses, so the retained request is a real approval
    /// reconstruction rather than a hand-made value.
    fn approved_registration(registration_nonce: &str) -> ApprovedHostRegistration {
        let (approval, _request) = installer_approval_fixture(
            eliot_installation::InstallerServiceRole::Host,
            registration_nonce,
        );
        ApprovedHostRegistration::from_approval(&approval)
            .unwrap_or_else(|error| panic!("approved Host registration fixture: {error}"))
    }

    /// One live readback that reports the approved registration matching and
    /// carrying a handle-bound process identity.
    fn matching_readback() -> WatchdogRuntimeReadback {
        WatchdogRuntimeReadback::Matching {
            state: WatchdogRuntimeState::Running,
            process: Some(ProcessIdentity {
                process_id: 4_200,
                start_time_100ns: 1_000_000,
                image_path: r"C:\Program Files\Eliot\eliot-host.exe".to_owned(),
            }),
            checkpoint: 0,
            wait_hint_ms: 0,
        }
    }

    /// Positive: a readback over the approved registration carries THAT
    /// approval's own recorded configuration digest and the identity the same
    /// readback observed.
    ///
    /// FAILS WITHOUT THIS CHANGE: there was no mapping at all, so no
    /// composition could obtain an approved-registration value from a live
    /// readback and the boundary compared nothing. The second approval in the
    /// same test pins the other half: the handle identifies the SPECIFIC
    /// approval, so a readback over one installer approval can never satisfy a
    /// boundary comparing a different one.
    #[test]
    fn matching_readback_carries_the_approved_registration_and_observed_identity() {
        let approved = approved_registration(&"a".repeat(64));
        let readback = approved_registration_readback(&approved, matching_readback())
            .unwrap_or_else(|| panic!("matching readback proves the approved registration"));
        assert_eq!(
            readback.registration().as_str(),
            approved.request.expected_configuration_digest()
        );
        assert_eq!(
            readback.identity().map(|identity| identity.process_id),
            Some(4_200)
        );

        let other = approved_registration(&"c".repeat(64));
        assert_ne!(
            approved_registration_readback(&approved, matching_readback())
                .map(|readback| readback.registration().clone()),
            approved_registration_readback(&other, matching_readback())
                .map(|readback| readback.registration().clone()),
            "a readback over one installer approval must not satisfy the other"
        );
    }

    /// Refusal: a readback that did NOT match the approved registration yields
    /// no evidence at all, so the approved value can never be presented as
    /// agreement with a substituted registration.
    ///
    /// FAILS WITHOUT THIS CHANGE: the mapping did not exist, so there was no
    /// statement to get wrong; once any caller supplied the approved value
    /// regardless of the readback, a `Mismatched` live configuration would have
    /// been indistinguishable from a matching one.
    #[test]
    fn non_matching_readback_yields_no_approved_registration_evidence() {
        let approved = approved_registration(&"a".repeat(64));
        for runtime in [
            WatchdogRuntimeReadback::Mismatched,
            WatchdogRuntimeReadback::Absent,
            WatchdogRuntimeReadback::Unknown,
        ] {
            assert!(
                approved_registration_readback(&approved, runtime).is_none(),
                "an unconfirmed readback must carry no approved-registration evidence"
            );
        }
    }

    /// The bounded wait the production caller grants the owner contour. The
    /// interval is this file's own `MAX_CHALLENGE_WAIT_SECS` because that is the
    /// bound the Host endpoint's bounded owner queue enforces
    /// (`QUEUE_RESPONSE_TIMEOUT`), and a longer wait would outlive that
    /// guarantee and be refused at construction.
    fn bounded_wait() -> BoundedChallengeWait {
        BoundedChallengeWait::new(MAX_CHALLENGE_WAIT_SECS)
            .unwrap_or_else(|| panic!("MAX_CHALLENGE_WAIT_SECS is admissible by construction"))
    }

    /// One validated live Host, read through the same readback classifier the
    /// liveness sensor itself uses. `Running` and the handle-bound process
    /// identity are the platform adapter's own comparison over the existing
    /// `matching_readback` fixture, so the fixture's liveness verdict is real
    /// code output rather than a hand-written observation.
    fn observed_live_host() -> HostObservation {
        let mut monitor = HostIdentityMonitor::new(None);
        monitor.observe_runtime_readback(matching_readback())
    }

    /// One terminal-absent readback through the same classifier.
    fn observed_absent_host() -> HostObservation {
        let mut monitor = HostIdentityMonitor::new(None);
        monitor.observe_runtime_readback(WatchdogRuntimeReadback::Absent)
    }

    /// A second observation of the same monitor taken after one live baseline,
    /// so the identity comparison inside `observe_process_identity` — not a
    /// hand-written state — produces the non-`Running` verdict under test.
    fn observed_after_baseline(second: ProcessIdentity) -> HostObservation {
        let mut monitor = HostIdentityMonitor::new(None);
        let baseline = monitor.observe_process_identity(ProcessIdentity {
            process_id: 4_200,
            start_time_100ns: 1_000_000,
            image_path: r"C:\Program Files\Eliot\eliot-host.exe".to_owned(),
        });
        assert_eq!(
            baseline.state,
            HostObservationState::Running,
            "the first observation of a fresh monitor is the live baseline"
        );
        monitor.observe_process_identity(second)
    }

    /// Every observation state the classifier can produce, each reached through
    /// real code: the live readback, a terminal-absent readback, and the three
    /// identity-gap verdicts that require a baseline to compare against.
    fn observed_states() -> Vec<HostObservation> {
        let mut monitor = HostIdentityMonitor::new(None);
        let identity = |process_id: u32, start_time_100ns: u64, image_path: &str| ProcessIdentity {
            process_id,
            start_time_100ns,
            image_path: image_path.to_owned(),
        };
        let transient = monitor.observe_runtime_readback(WatchdogRuntimeReadback::Matching {
            state: WatchdogRuntimeState::Starting,
            process: None,
            checkpoint: 0,
            wait_hint_ms: 0,
        });
        vec![
            observed_live_host(),
            observed_absent_host(),
            transient,
            observed_after_baseline(identity(4_200, 2_000_000, LIVE_IMAGE)),
            observed_after_baseline(identity(4_200, 1_000_000, SUBSTITUTED_IMAGE)),
            observed_after_baseline(identity(9_001, 1_000_000, LIVE_IMAGE)),
        ]
    }

    /// The approved Host image the `matching_readback` fixture reports.
    const LIVE_IMAGE: &str = r"C:\Program Files\Eliot\eliot-host.exe";
    /// A different image at the same path identity: the same PID and start time
    /// with different bytes, which `observe_process_identity` classifies as
    /// `ImageSubstituted`.
    const SUBSTITUTED_IMAGE: &str = r"C:\Program Files\Eliot\other-host.exe";

    /// Every `ChallengeAttemptOutcome` a challenger can report: the one
    /// competent attempt plus one incompetent attempt per named uncertainty.
    fn every_attempt() -> Vec<ChallengeAttemptOutcome> {
        let mut attempts = vec![ChallengeAttemptOutcome::CompetentTimeout];
        attempts.extend(
            [
                ChallengeUncertainty::Unauthenticated,
                ChallengeUncertainty::ConnectionDenied,
                ChallengeUncertainty::TargetChanged,
                ChallengeUncertainty::InadequateCoverage,
                ChallengeUncertainty::TargetNotLive,
            ]
            .map(ChallengeAttemptOutcome::Uncertain),
        );
        attempts
    }

    /// Positive: a live disposable Host whose control loop is deliberately
    /// stalled — validated `Running` target, competently attempted challenge,
    /// uncancelled bounded wait, no correlated owner answer — is
    /// `AliveUnresponsive` and never health. The verdict is the *observation* of
    /// a live-but-unresponsive control owner, which is what makes the stalled
    /// process visible to the supervisor instead of silently healthy.
    #[test]
    fn live_stalled_control_loop_is_alive_unresponsive_never_health() {
        let host = observed_live_host();
        assert_eq!(
            host.state,
            HostObservationState::Running,
            "the fixture must be the validated live target the challenge ran against"
        );
        let verdict =
            host.responsiveness(&bounded_wait(), &ChallengeAttemptOutcome::CompetentTimeout);
        assert_eq!(verdict, HostResponsiveness::AliveUnresponsive);
        assert_ne!(
            verdict,
            HostResponsiveness::Responsive,
            "a stalled control loop is liveness evidence only and is never health"
        );
    }

    /// The positive `Responsive` case is NOT reachable through this function.
    /// `HostObservation::responsiveness` has no `Responsive` arm at all: it is a
    /// pure function of already-observed liveness plus an already-classified
    /// attempt, and it never sees an owner answer. Exhaustive sweep over every
    /// observation state the classifier can produce, every attempt outcome, and
    /// both wait dispositions, so a forged, replayed, or wrong-epoch response
    /// cannot establish health here — no response can, because no input reaches
    /// `Responsive`. The positive case is owned exclusively by the owner-path
    /// correlation validator in the Host endpoint lane
    /// (`eliot-host-control-endpoint`'s
    /// `responsiveness_challenge::validate_owner_challenge_response`), which this
    /// composition root does not depend on.
    #[test]
    fn responsiveness_is_unreachable_from_liveness_evidence_and_any_attempt() {
        let observations = observed_states();
        let attempts = every_attempt();
        for state in [
            HostObservationState::Running,
            HostObservationState::AbsentOrStopped,
            HostObservationState::PidReused,
            HostObservationState::ImageSubstituted,
            HostObservationState::IdentityChanged,
            HostObservationState::Unknown,
        ] {
            assert!(
                observations
                    .iter()
                    .any(|observation| observation.state == state),
                "the sweep must cover {state:?}, the state the classifier produces"
            );
        }
        for observation in &observations {
            for attempt in &attempts {
                for cancelled in [false, true] {
                    let mut wait = bounded_wait();
                    if cancelled {
                        wait.cancel();
                    }
                    let verdict = observation.responsiveness(&wait, attempt);
                    assert_ne!(
                        verdict,
                        HostResponsiveness::Responsive,
                        "liveness evidence plus one attempt ({observation:?}, {attempt:?}, \
                         cancelled={cancelled}) must never be health"
                    );
                }
            }
        }
    }

    /// An incompetent attempt stays an explicit named uncertainty: never
    /// `AliveUnresponsive` (which would silently grant restart eligibility) and
    /// never `Responsive`. Each reported reason survives classification
    /// unchanged, so a stored journal row can say *what* was unknown instead of
    /// collapsing every insufficient signal into the timeout arm.
    #[test]
    fn incompetent_attempt_stays_an_explicit_named_uncertainty() {
        let host = observed_live_host();
        for reason in [
            ChallengeUncertainty::Unauthenticated,
            ChallengeUncertainty::ConnectionDenied,
            ChallengeUncertainty::TargetChanged,
            ChallengeUncertainty::InadequateCoverage,
            ChallengeUncertainty::TargetNotLive,
        ] {
            let verdict =
                host.responsiveness(&bounded_wait(), &ChallengeAttemptOutcome::Uncertain(reason));
            assert_eq!(
                verdict,
                HostResponsiveness::Uncertain(reason),
                "the reported uncertainty must survive classification unchanged"
            );
            assert_ne!(
                verdict,
                HostResponsiveness::AliveUnresponsive,
                "an attempt that never became competent is not a competent timeout"
            );
            assert_ne!(
                verdict,
                HostResponsiveness::Responsive,
                "an unproven challenge is never health"
            );
        }
    }

    /// Refused/denied connection, changed target identity, and inadequate
    /// sensor coverage stay three distinguishable verdicts rather than one
    /// undifferentiated refusal: two challengers that failed for different
    /// reasons must not leave the same journal evidence. The check is
    /// pairwise distinctness of the classified verdicts, so it also proves the
    /// classifier collapses nothing.
    #[test]
    fn refused_connection_changed_target_and_inadequate_coverage_stay_distinct() {
        let host = observed_live_host();
        let verdicts = [
            ChallengeUncertainty::Unauthenticated,
            ChallengeUncertainty::ConnectionDenied,
            ChallengeUncertainty::TargetChanged,
            ChallengeUncertainty::InadequateCoverage,
            ChallengeUncertainty::TargetNotLive,
        ]
        .map(|reason| {
            host.responsiveness(&bounded_wait(), &ChallengeAttemptOutcome::Uncertain(reason))
        });
        for (left, left_reason) in verdicts.iter().zip([
            ChallengeUncertainty::Unauthenticated,
            ChallengeUncertainty::ConnectionDenied,
            ChallengeUncertainty::TargetChanged,
            ChallengeUncertainty::InadequateCoverage,
            ChallengeUncertainty::TargetNotLive,
        ]) {
            assert_eq!(*left, HostResponsiveness::Uncertain(left_reason));
            for (right, right_reason) in verdicts.iter().zip([
                ChallengeUncertainty::Unauthenticated,
                ChallengeUncertainty::ConnectionDenied,
                ChallengeUncertainty::TargetChanged,
                ChallengeUncertainty::InadequateCoverage,
                ChallengeUncertainty::TargetNotLive,
            ]) {
                if left != right {
                    assert_ne!(
                        left, right,
                        "{left_reason:?} and {right_reason:?} are different failures and must \
                         stay different verdicts"
                    );
                }
            }
        }
    }

    /// Negative: a competently attempted challenge against a target that is not
    /// live is never `AliveUnresponsive`. A timeout proves the control owner was
    /// unreachable *at a live target*; without one it proves nothing, so it
    /// stays `TargetNotLive` and can never become restart eligibility.
    #[test]
    fn competent_timeout_against_a_non_live_target_is_never_alive_unresponsive() {
        for observation in observed_states() {
            if observation.state == HostObservationState::Running {
                continue;
            }
            let verdict = observation
                .responsiveness(&bounded_wait(), &ChallengeAttemptOutcome::CompetentTimeout);
            assert_eq!(
                verdict,
                HostResponsiveness::Uncertain(ChallengeUncertainty::TargetNotLive),
                "{observation:?} is not a validated live target, so a timeout establishes nothing"
            );
        }
    }

    /// Negative: a cancelled bounded wait never produces a verdict, even for the
    /// live/competent combination that would otherwise be `AliveUnresponsive`.
    /// Abandoning the wait abandons only the wait; it never interrupts in-flight
    /// OS work, so the outcome is coverage uncertainty rather than an observed
    /// stall.
    #[test]
    fn cancelled_wait_yields_coverage_uncertainty_never_health() {
        let host = observed_live_host();
        let mut wait = bounded_wait();
        assert!(!wait.is_cancelled(), "the fixture wait starts uncancelled");
        wait.cancel();
        assert!(wait.is_cancelled());
        for attempt in every_attempt() {
            let verdict = host.responsiveness(&wait, &attempt);
            assert_eq!(
                verdict,
                HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage),
                "a cancelled wait is an abandoned observation, not a verdict ({attempt:?})"
            );
        }
    }

    /// The bound is a real bound: a zero-length or over-bound wait cannot be
    /// constructed, so no unbounded observation can enter this classifier. The
    /// accepted maximum is the crate's own constant, not a literal chosen here.
    #[test]
    fn bounded_wait_construction_refuses_unbounded_intervals() {
        assert_eq!(
            BoundedChallengeWait::new(0),
            None,
            "a zero-length wait would observe nothing"
        );
        assert_eq!(
            BoundedChallengeWait::new(MAX_CHALLENGE_WAIT_SECS + 1),
            None,
            "a wait beyond the owner-queue bound would outlive the guarantee"
        );
        let wait = bounded_wait();
        assert_eq!(wait.timeout_secs(), MAX_CHALLENGE_WAIT_SECS);
        assert!(!wait.is_cancelled());
    }

    /// An opaque coordination identity. It carries no process value and no
    /// approval; only the budget gate's own comparison semantics read it, and
    /// `PlatformHandle::new` enforces its own shape at construction.
    fn coordination_identity(character: char) -> PlatformHandle {
        PlatformHandle::new(character.to_string().repeat(32))
            .unwrap_or_else(|error| panic!("coordination identity fixture: {error}"))
    }

    /// One installation-approved recovery policy. `max_attempts` is the only
    /// field the responsiveness budget gate reads, so it is the parameter; the
    /// rest is a fixed, valid envelope (`failure_threshold` and
    /// `budget_window_secs` non-zero, which is what `validate` requires) built
    /// from opaque coordination identities.
    fn approved_recovery_policy(max_attempts: u32) -> ApprovedRecoveryPolicy {
        ApprovedRecoveryPolicy {
            installation: coordination_identity('1'),
            service: coordination_identity('2'),
            owner_epoch_digest: coordination_identity('3'),
            recipe_digest: coordination_identity('4'),
            failure_threshold: 1,
            max_attempts,
            budget_window_secs: 3_600,
            cooldown_secs: 0,
            exclusive_attempt: true,
            audit_failure_refuses_effects: false,
        }
    }

    /// Positive: `AliveUnresponsive` inside the durable budget admits one fenced
    /// recovery attempt, and the remainder is exact at every point in the
    /// window — never off by one, never rounded, never capped. The expected
    /// remainder is derived from the policy's own `max_attempts` field so the
    /// assertion cannot drift from the value the gate reads.
    #[test]
    fn alive_unresponsive_within_budget_admits_the_exact_remainder() {
        let policy = approved_recovery_policy(3);
        assert!(
            policy.validate().is_ok(),
            "the fixture must be a valid policy or it proves nothing"
        );
        for used_attempts in 0..u64::from(policy.max_attempts) {
            let decision =
                HostResponsiveness::AliveUnresponsive.recovery_eligibility(&policy, used_attempts);
            assert_eq!(
                decision,
                RecoveryBudgetDecision::Admitted {
                    remaining_attempts: u64::from(policy.max_attempts) - used_attempts
                },
                "{used_attempts} used attempts of {} must leave exactly the remaining count",
                policy.max_attempts
            );
            assert!(
                decision.admits_effect(),
                "an admitted decision is the only one that may request an SCM effect"
            );
        }
    }

    /// Negative: at or over the budget, `AliveUnresponsive` exhausts instead of
    /// admitting. Both boundaries are checked because the gate compares
    /// `used_attempts >= max_attempts`, so the last admitted attempt and the
    /// first exhausted one must be adjacent, not overlapping.
    #[test]
    fn alive_unresponsive_at_or_over_budget_is_exhausted_and_admits_no_effect() {
        let policy = approved_recovery_policy(3);
        for used_attempts in [u64::from(policy.max_attempts), 4, 17] {
            let decision =
                HostResponsiveness::AliveUnresponsive.recovery_eligibility(&policy, used_attempts);
            assert_eq!(
                decision,
                RecoveryBudgetDecision::Exhausted,
                "{used_attempts} used attempts of {} must exhaust the budget",
                policy.max_attempts
            );
            assert!(
                !decision.admits_effect(),
                "an exhausted budget permits no SCM restart and no SCM effect"
            );
        }
    }

    /// Zero is a valid policy, not a malformed one: `validate` accepts it, and it
    /// exhausts from the very first verdict, including the zero-used-attempt
    /// case a fresh Watchdog would pass.
    #[test]
    fn zero_attempt_policy_is_valid_and_exhausted_from_the_first_verdict() {
        let policy = approved_recovery_policy(0);
        assert!(
            policy.validate().is_ok(),
            "a zero-attempt policy is a valid installed policy that admits nothing"
        );
        for used_attempts in [0, 1, 9] {
            let decision =
                HostResponsiveness::AliveUnresponsive.recovery_eligibility(&policy, used_attempts);
            assert_eq!(
                decision,
                RecoveryBudgetDecision::Exhausted,
                "a zero-attempt policy admits nothing at {used_attempts} used attempts"
            );
            assert!(!decision.admits_effect());
        }
    }

    /// A missing/unproven policy leaves nothing to admit against, so the same
    /// zero-budget verdict is what a refusal amounts to. `Uncertain(_)` is
    /// `ChallengeUnresolved` for ANY used-attempt count including zero:
    /// uncertainty is never restart eligibility, at any point in any window.
    #[test]
    fn uncertainty_is_never_restart_eligibility_at_any_used_attempt_count() {
        for max_attempts in [0, 1, 3] {
            let policy = approved_recovery_policy(max_attempts);
            for used_attempts in [0, 1, 2, 5] {
                for reason in [
                    ChallengeUncertainty::Unauthenticated,
                    ChallengeUncertainty::ConnectionDenied,
                    ChallengeUncertainty::TargetChanged,
                    ChallengeUncertainty::InadequateCoverage,
                    ChallengeUncertainty::TargetNotLive,
                ] {
                    let decision = HostResponsiveness::Uncertain(reason)
                        .recovery_eligibility(&policy, used_attempts);
                    assert_eq!(
                        decision,
                        RecoveryBudgetDecision::ChallengeUnresolved,
                        "{reason:?} at {used_attempts}/{max_attempts} used attempts is unresolved, \
                         never eligible"
                    );
                    assert!(
                        !decision.admits_effect(),
                        "an unresolved challenge permits no SCM effect"
                    );
                }
            }
        }
    }

    /// `Responsive` needs no recovery at all, so it is the one verdict whose
    /// budget decision ignores the policy and the used-attempt count.
    #[test]
    fn responsive_requests_no_recovery_whatever_the_budget() {
        for max_attempts in [0, 1, 3] {
            let policy = approved_recovery_policy(max_attempts);
            for used_attempts in [0, 1, 9] {
                let decision =
                    HostResponsiveness::Responsive.recovery_eligibility(&policy, used_attempts);
                assert_eq!(
                    decision,
                    RecoveryBudgetDecision::NoRecoveryRequired,
                    "an answered challenge needs no recovery at {used_attempts}/{max_attempts}"
                );
                assert!(!decision.admits_effect());
            }
        }
    }

    /// The zero-SCM-effects consequence, stated through the only API that
    /// exposes it: `admits_effect`. Exactly one of the four decision variants
    /// may request an SCM effect; the exhausted and unresolved arms — the two a
    /// stalled or unproven Host produces — may not, whatever the budget says.
    #[test]
    fn only_an_admitted_decision_admits_an_scm_effect() {
        let policy = approved_recovery_policy(3);
        let admitted = HostResponsiveness::AliveUnresponsive.recovery_eligibility(&policy, 0);
        let exhausted = HostResponsiveness::AliveUnresponsive.recovery_eligibility(&policy, 3);
        let zero_policy = HostResponsiveness::AliveUnresponsive
            .recovery_eligibility(&approved_recovery_policy(0), 0);
        let unresolved = HostResponsiveness::Uncertain(ChallengeUncertainty::TargetChanged)
            .recovery_eligibility(&policy, 0);
        let healthy = HostResponsiveness::Responsive.recovery_eligibility(&policy, 0);
        assert!(admitted.admits_effect(), "only the admitted arm effects");
        for (decision, label) in [
            (exhausted, "Exhausted"),
            (zero_policy, "Exhausted (zero-attempt policy)"),
            (unresolved, "ChallengeUnresolved"),
            (healthy, "NoRecoveryRequired"),
        ] {
            assert!(
                !decision.admits_effect(),
                "{label} must admit no SCM operation, got {decision:?}"
            );
        }
    }

    /// Exhaustion persists across a Watchdog restart, and it does so precisely
    /// because this struct carries no attempt counter: the durable count is the
    /// `used_attempts` argument, so a freshly constructed policy with no memory
    /// of any previous verdict still refuses once that count reaches the budget.
    /// The only difference between the two policy values below is that they were
    /// built by two independent constructions, as two Watchdog lifetimes would.
    #[test]
    fn exhaustion_survives_a_watchdog_restart_that_remembered_no_verdict() {
        let before_restart = approved_recovery_policy(2);
        assert!(
            HostResponsiveness::AliveUnresponsive
                .recovery_eligibility(&before_restart, 1)
                .admits_effect(),
            "the first attempt of a two-attempt window is still inside the budget"
        );
        // A restarted Watchdog reconstructs the policy from the installation and
        // reads the durable count from its journal. Nothing about the new value
        // differs, which is exactly the property under test.
        let after_restart = approved_recovery_policy(2);
        assert_eq!(
            after_restart, before_restart,
            "restart reconstructs the same installed policy"
        );
        assert_eq!(
            HostResponsiveness::AliveUnresponsive.recovery_eligibility(&after_restart, 2),
            RecoveryBudgetDecision::Exhausted,
            "the durable count carries exhaustion across the restart"
        );
        assert!(
            !HostResponsiveness::AliveUnresponsive
                .recovery_eligibility(&after_restart, 2)
                .admits_effect(),
            "no SCM effect after restart either"
        );
    }
}
