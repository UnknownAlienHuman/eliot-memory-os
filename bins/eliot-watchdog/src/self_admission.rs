//! Watchdog SCM self-admission cell — bounded timing and identity gate only.

//!
//! Architecture (verified via `codebase_memory` against `eliot-architecture-docs-fa941135` at `ELIOT_ARCHITECTURE.md`):
//! R0 independent supervision — A0.3 Hard boundaries / A2.2 Watchdog и Doctor / A8 Watchdog /
//! A13 Resilience, recovery и observability — SCM registration is read-only projection with
//! fail-closed identity handles (PID + creation time + image path). No lifecycle authority.
//!
//! Implementation (verified via `codebase_memory` against `eliot-architecture-docs-fa941135` at `ELIOT_IMPLEMENTATION.md`
//! and stale routing graph `eliot-memory-os-44e8b4b-live` verified against base `6ecf2b2217b5bd67247184928663a3e0584dedb9`):
//! I8 Watchdog implementation contract (I8.1 Process and authority, I8.2 Independent observation routes,
//! I8.3 Deterministic supervision loop) and I14 Queueing, backpressure and degraded behavior
//! (I14.6 Durable work, admission and execution axes, I14.10 Supervision strategies and restart intensity)
//! — Watchdog self-admission / bounded `SERVICE_START_PENDING` gate with wait-hint clamping.
//!
//! This cell explicitly forbids start/stop/registration mutation and semantic readiness authority.
//! It owns only timing/bounded wait and same-process identity equality; it does not own
//! HostObservation/HostIdentityMonitor, spool, Kernel sensor, or Host lifecycle.

use std::path::Path;

use eliot_platform_windows::{
    ProcessIdentity, ServiceRegistrationRuntimeInspection, windows_paths_equal,
};
use thiserror::Error;

/// Provider-neutral lifecycle state projected from one Windows SCM runtime
/// observation. The projection keeps the Watchdog composition independent of
/// the lower-level `eliot-platform` crate while preserving every state needed
/// by bounded self-admission and Host liveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogRuntimeState {
    Absent,
    Stopped,
    Starting,
    Running,
    Stopping,
    Unknown,
}

/// One atomic read-only SCM registration/runtime readback. The `Matching`
/// variant already contains the configuration, lifecycle state, and
/// handle-bound process identity from one platform query; callers must not
/// reconstruct a second status/PID observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchdogRuntimeReadback {
    Matching {
        state: WatchdogRuntimeState,
        process: Option<ProcessIdentity>,
        checkpoint: u32,
        wait_hint_ms: u32,
    },
    Absent,
    Mismatched,
    Unknown,
}

/// Projects the Windows runtime seam into the small state surface used by
/// Watchdog. The Windows adapter has already checked the complete service
/// configuration and, when required by the service state, captured process
/// PID, creation time, and image path through a live process handle.
#[must_use]
pub fn project_service_runtime_inspection(
    inspection: ServiceRegistrationRuntimeInspection,
) -> WatchdogRuntimeReadback {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation } => {
            let state = if observation.is_starting() {
                WatchdogRuntimeState::Starting
            } else if observation.is_running() {
                WatchdogRuntimeState::Running
            } else if observation.is_stopping() {
                WatchdogRuntimeState::Stopping
            } else if observation.is_stopped() {
                WatchdogRuntimeState::Stopped
            } else {
                WatchdogRuntimeState::Unknown
            };
            WatchdogRuntimeReadback::Matching {
                state,
                process: observation.process().cloned(),
                checkpoint: observation.checkpoint(),
                wait_hint_ms: observation.wait_hint_ms(),
            }
        }
        ServiceRegistrationRuntimeInspection::Absent => WatchdogRuntimeReadback::Absent,
        ServiceRegistrationRuntimeInspection::Mismatched => WatchdogRuntimeReadback::Mismatched,
        ServiceRegistrationRuntimeInspection::Unknown => WatchdogRuntimeReadback::Unknown,
    }
}

/// Fixed maximum interval in which the Watchdog may remain in
/// `SERVICE_START_PENDING` while it reconciles its own SCM runtime identity.
pub const WATCHDOG_SELF_ADMISSION_DEADLINE_MS: u64 = 30_000;
pub(super) const SELF_ADMISSION_MIN_POLL_MS: u32 = 25;
const SELF_ADMISSION_MAX_POLL_MS: u32 = 250;
const SELF_ADMISSION_DEFAULT_WAIT_HINT_MS: u32 = 250;

/// Fail-closed outcomes for the bounded Watchdog self-admission gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum WatchdogSelfAdmissionError {
    #[error("current Watchdog process identity is unavailable")]
    CurrentProcessUnavailable,
    #[error("Watchdog SCM registration is absent during self-admission")]
    RegistrationAbsent,
    #[error("Watchdog SCM registration or process identity mismatched during self-admission")]
    RegistrationMismatched,
    #[error("Watchdog SCM service stopped before self-admission")]
    ServiceStopped,
    #[error("Watchdog SCM service is stopping during self-admission")]
    ServiceStopping,
    #[error("Watchdog SCM self-admission timed out after the bounded deadline")]
    Timeout,
}

/// Injectable read-only mechanics used by the bounded self-admission loop.
/// Production supplies the Windows SCM runtime inspection and a monotonic
/// clock; tests supply a deterministic sequence without sleeping 30 seconds.
pub trait WatchdogSelfAdmissionProbe {
    fn now_ms(&mut self) -> u64;
    fn current_process_identity(&mut self) -> Option<ProcessIdentity>;
    fn inspect(&mut self) -> WatchdogRuntimeReadback;
    fn sleep_ms(&mut self, milliseconds: u32);
}

/// Injectable SCM status publisher for the self-admission loop. It is limited
/// to progress updates while the service is already `START_PENDING`; it has
/// no start/stop or registration mutation capability.
pub trait WatchdogSelfAdmissionStatus {
    fn report_start_pending(&mut self, checkpoint: u32, wait_hint_ms: u32);
}

/// Performs the production bounded self-admission with the fixed 30-second
/// deadline required by the Runtime Live service contract.
///
/// # Errors
///
/// Returns a fail-closed error when the current process identity cannot be
/// observed, the SCM registration is absent/mismatched/stopped, or the
/// bounded deadline expires before an exact `Starting`/`Running` match.
pub fn admit_watchdog_self_start<P, S>(
    probe: &mut P,
    status: &mut S,
) -> Result<ProcessIdentity, WatchdogSelfAdmissionError>
where
    P: WatchdogSelfAdmissionProbe,
    S: WatchdogSelfAdmissionStatus,
{
    admit_watchdog_self_start_with_deadline(probe, status, WATCHDOG_SELF_ADMISSION_DEADLINE_MS)
}

/// Testable form of [`admit_watchdog_self_start`] with a bounded injected
/// deadline. The production entry point always uses the fixed 30-second
/// value above; this form exists only to make timeout and transient-unknown
/// behavior deterministic in unit tests.
///
/// # Errors
///
/// Returns a fail-closed error when the current process identity cannot be
/// observed, the SCM registration is absent/mismatched/stopped, or the
/// injected deadline expires before an exact `Starting`/`Running` match.
pub fn admit_watchdog_self_start_with_deadline<P, S>(
    probe: &mut P,
    status: &mut S,
    deadline_ms: u64,
) -> Result<ProcessIdentity, WatchdogSelfAdmissionError>
where
    P: WatchdogSelfAdmissionProbe,
    S: WatchdogSelfAdmissionStatus,
{
    let expected = probe
        .current_process_identity()
        .ok_or(WatchdogSelfAdmissionError::CurrentProcessUnavailable)?;
    let started_at = probe.now_ms();
    let deadline = started_at.saturating_add(deadline_ms);
    let mut checkpoint = 1u32;

    loop {
        let now = probe.now_ms();
        if now >= deadline {
            return Err(WatchdogSelfAdmissionError::Timeout);
        }
        let observation = probe.inspect();
        let wait_hint_ms = match observation {
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Starting | WatchdogRuntimeState::Running,
                process: Some(ref actual),
                ..
            } if same_process_identity(actual, &expected) => {
                if probe.now_ms() >= deadline {
                    return Err(WatchdogSelfAdmissionError::Timeout);
                }
                return Ok(actual.clone());
            }
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Starting | WatchdogRuntimeState::Running,
                process: Some(_),
                ..
            }
            | WatchdogRuntimeReadback::Mismatched => {
                return Err(WatchdogSelfAdmissionError::RegistrationMismatched);
            }
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Stopped,
                ..
            } => return Err(WatchdogSelfAdmissionError::ServiceStopped),
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Stopping,
                ..
            } => return Err(WatchdogSelfAdmissionError::ServiceStopping),
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Absent,
                ..
            } => return Err(WatchdogSelfAdmissionError::RegistrationAbsent),
            WatchdogRuntimeReadback::Absent => {
                return Err(WatchdogSelfAdmissionError::RegistrationAbsent);
            }
            WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Starting | WatchdogRuntimeState::Running,
                process: None,
                wait_hint_ms,
                ..
            }
            | WatchdogRuntimeReadback::Matching {
                state: WatchdogRuntimeState::Unknown,
                wait_hint_ms,
                ..
            } => wait_hint_ms,
            WatchdogRuntimeReadback::Unknown => 0,
        };

        let wait_hint_ms = bounded_wait_hint_ms(wait_hint_ms);
        let remaining_ms = deadline.saturating_sub(probe.now_ms());
        if remaining_ms == 0 {
            return Err(WatchdogSelfAdmissionError::Timeout);
        }
        let status_wait_hint_ms = wait_hint_ms.min(u32::try_from(remaining_ms).unwrap_or(u32::MAX));
        checkpoint = checkpoint.saturating_add(1);
        status.report_start_pending(checkpoint, status_wait_hint_ms);
        let poll_ms = u64::from(bounded_poll_ms(wait_hint_ms)).min(remaining_ms);
        probe.sleep_ms(u32::try_from(poll_ms).unwrap_or(u32::MAX));
    }
}

fn bounded_wait_hint_ms(wait_hint_ms: u32) -> u32 {
    if wait_hint_ms == 0 {
        SELF_ADMISSION_DEFAULT_WAIT_HINT_MS
    } else {
        wait_hint_ms.clamp(SELF_ADMISSION_MIN_POLL_MS, 1_000)
    }
}

fn bounded_poll_ms(wait_hint_ms: u32) -> u32 {
    wait_hint_ms
        .saturating_div(4)
        .clamp(SELF_ADMISSION_MIN_POLL_MS, SELF_ADMISSION_MAX_POLL_MS)
}

fn same_process_identity(observed: &ProcessIdentity, expected: &ProcessIdentity) -> bool {
    observed.process_id == expected.process_id
        && observed.start_time_100ns == expected.start_time_100ns
        && windows_paths_equal(
            Path::new(&observed.image_path),
            Path::new(&expected.image_path),
        )
}
