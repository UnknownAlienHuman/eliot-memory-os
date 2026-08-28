//! Bounded timing helpers for the existing Host Watchdog start convergence.
//!
//! The canonical architecture anchors are `ELIOT_ARCHITECTURE.md` A8.1
//! (`ARCH-WDG-01`), A13.2, and A13.8, with implementation anchors
//! `ELIOT_IMPLEMENTATION.md` I8.1, I8.2, I2.16, and I2.23. The timing behavior
//! is mechanically extracted from the `WatchdogStartClock`,
//! `SystemWatchdogStartClock`, `watchdog_start_wait`, and
//! `watchdog_unknown_wait` cell in `watchdog_service_start.rs`.
//!
//! This module provides bounded clock and wait mechanics only. It owns no
//! SCM/service mutation, process start/stop/restart/kill, lifecycle,
//! reconciliation, self-admission, spool, semantic, canonical, credential, or
//! authority behavior.

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
