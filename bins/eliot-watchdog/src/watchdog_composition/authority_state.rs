//! Watchdog readiness and bounded authority-state cell.
//!
//! Architecture anchors (`docs/architecture/ELIOT_ARCHITECTURE.md`): A8.1
//! Watchdog purpose, A13.2 Kernel and failure domains, ARCH-WDG-01 Independent
//! supervision, ARCH-RES-01 Fail locally, recover globally, and ARCH-RES-04
//! Degradation is visible and local.
//! Implementation anchors (`docs/architecture/ELIOT_IMPLEMENTATION.md`): I8.1
//! Process and authority, I8.3 Deterministic supervision loop, I8.4 Interaction
//! heartbeat, I14.10 Supervision strategies and restart intensity, and I14.15
//! Daemon hot replacement.
//!
//! This child owns only readiness values and the bounded in-memory authority
//! state transitions; it owns no Kernel effect, Host identity, lease issuance,
//! lifecycle, shutdown, canonical state, or retry authority.
//! Those boundaries remain with the parent composition facade and its injected
//! ports.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

/// Readiness data emitted by the process entrypoint.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct WatchdogReadiness {
    pub service: &'static str,
    pub protocol: &'static str,
    pub authority_state: WatchdogAuthorityState,
    pub coverage_claimed: bool,
    pub kernel_epoch: u64,
    pub watchdog_epoch: u64,
    pub tick_interval_ms: u128,
}

/// Separates SCM/process liveness from admitted heartbeat authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum WatchdogAuthorityState {
    /// The SCM sibling is alive and records gap-only evidence, but no current
    /// Host-issued lease has been admitted for heartbeat authority.
    RunningNoAuthority = 0,
    /// Exact Host identity and a current signed lease were admitted and the
    /// Kernel accepted the corresponding heartbeat.
    AdmittedHeartbeat = 1,
}

impl WatchdogAuthorityState {
    fn from_atomic(value: u8) -> Self {
        if value == Self::AdmittedHeartbeat as u8 {
            Self::AdmittedHeartbeat
        } else {
            Self::RunningNoAuthority
        }
    }

    pub(super) const fn coverage_claimed(self) -> bool {
        matches!(self, Self::AdmittedHeartbeat)
    }
}

/// Shared bounded state cell for the watchdog's admitted-heartbeat projection.
#[derive(Clone)]
pub(super) struct WatchdogAuthorityStateCell {
    value: Arc<AtomicU8>,
}

impl WatchdogAuthorityStateCell {
    pub(super) fn new() -> Self {
        Self {
            value: Arc::new(AtomicU8::new(
                WatchdogAuthorityState::RunningNoAuthority as u8,
            )),
        }
    }

    pub(super) fn transition_to(&self, state: WatchdogAuthorityState) {
        self.value.store(state as u8, Ordering::Release);
    }

    #[must_use]
    pub(super) fn load(&self) -> WatchdogAuthorityState {
        WatchdogAuthorityState::from_atomic(self.value.load(Ordering::Acquire))
    }
}
