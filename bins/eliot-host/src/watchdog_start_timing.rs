//! Bounded timing helpers for the existing Host Watchdog start convergence.
//!
//! The canonical architecture anchors are A8.1
//! (`docs/architecture/A08-01-purpose.md`, `ARCH-WDG-01`), A13.2
//! (`docs/architecture/A13-02-kernel-and-failure-domains.md`), and A13.8
//! (`docs/architecture/A13-08-integrity.md`), with implementation anchors I8.1
//! (`docs/architecture/I08-01-process-and-authority.md`), I8.2
//! (`docs/architecture/I08-02-independent-observation-routes.md`), I2.16
//! (`docs/architecture/I02-16-crate-size-and-agent-context-envelope.md`), and
//! I2.23
//! (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`).
//! The timing behavior is mechanically extracted from the `WatchdogStartClock`,
//! `SystemWatchdogStartClock`, `watchdog_start_wait`, and
//! `watchdog_unknown_wait` cell in `watchdog_service_start.rs`.
//!
//! This module provides bounded clock and wait mechanics only. It owns no
//! SCM/service mutation, process start/stop/restart/kill, lifecycle,
//! reconciliation, self-admission, spool, semantic, canonical, credential, or
//! authority behavior.
//!
//! F-LOG-HOST-4 (#979): non-boundary wait mechanics — `watchdog_start_wait`
//! and `watchdog_unknown_wait` are pure `Duration` clamps with no owner
//! state/receipt, error propagation, or terminal decision, so they carry no
//! diagnostic callsite of their own. The sole production caller is the SCM
//! start convergence loop in `watchdog_service_start.rs`
//! (`start_installed_watchdog_with_clock`), which owns the injected-clock
//! deadline decision and emits the timing observations there (the
//! `deadline_expired*` observation phases); `watchdog_start_wait` is
//! additionally re-exported to `#[cfg(all(test, windows))]` for the existing
//! exact-clamp unit assertions. Observing a pure clamp would record no owner
//! fact.

#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
pub(crate) trait WatchdogStartClock {
    fn now_ms(&mut self) -> u64;

    fn sleep(&mut self, duration: Duration);
}

#[cfg(windows)]
pub(super) struct SystemWatchdogStartClock {
    origin: Instant,
}

#[cfg(windows)]
impl SystemWatchdogStartClock {
    pub(super) fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

#[cfg(windows)]
impl WatchdogStartClock for SystemWatchdogStartClock {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(windows)]
pub(crate) const WATCHDOG_START_TIMEOUT_MS: u64 = 30_000;

#[cfg(windows)]
const WATCHDOG_START_MIN_WAIT_MS: u64 = 25;

#[cfg(windows)]
const WATCHDOG_START_MAX_WAIT_MS: u64 = 250;

#[cfg(windows)]
const WATCHDOG_START_UNKNOWN_WAIT_MS: u64 = 50;

#[cfg(windows)]
pub(crate) fn watchdog_start_wait(wait_hint_ms: u32) -> Duration {
    let wait_ms =
        u64::from(wait_hint_ms).clamp(WATCHDOG_START_MIN_WAIT_MS, WATCHDOG_START_MAX_WAIT_MS);
    Duration::from_millis(wait_ms)
}

#[cfg(windows)]
pub(super) fn watchdog_unknown_wait() -> Duration {
    Duration::from_millis(WATCHDOG_START_UNKNOWN_WAIT_MS)
}
