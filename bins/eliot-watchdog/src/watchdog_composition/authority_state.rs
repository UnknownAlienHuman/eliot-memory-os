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

use std::sync::{Arc, RwLock};

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
pub enum WatchdogAuthorityState {
    /// The SCM sibling is alive and records gap-only evidence, but no current
    /// Host-issued lease has been admitted for heartbeat authority.
    RunningNoAuthority,
    /// Exact Host identity and a current signed lease were admitted and the
    /// Kernel accepted the corresponding heartbeat.
    AdmittedHeartbeat,
}

impl WatchdogAuthorityState {
    pub(super) const fn coverage_claimed(self) -> bool {
        matches!(self, Self::AdmittedHeartbeat)
    }
}

/// One coherent readiness projection. The authority state and both epoch
/// values are updated under one lock so a reader can never combine epochs from
/// different admitted leases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WatchdogAuthoritySnapshot {
    pub(super) state: WatchdogAuthorityState,
    pub(super) kernel_epoch: u64,
    pub(super) watchdog_epoch: u64,
}

impl WatchdogAuthoritySnapshot {
    const fn no_authority() -> Self {
        Self {
            state: WatchdogAuthorityState::RunningNoAuthority,
            kernel_epoch: 0,
            watchdog_epoch: 0,
        }
    }

    const fn admitted(kernel_epoch: u64, watchdog_epoch: u64) -> Self {
        Self {
            state: WatchdogAuthorityState::AdmittedHeartbeat,
            kernel_epoch,
            watchdog_epoch,
        }
    }
}

/// Shared bounded state cell for the watchdog's admitted-heartbeat projection.
#[derive(Clone)]
pub(super) struct WatchdogAuthorityStateCell {
    value: Arc<RwLock<WatchdogAuthoritySnapshot>>,
}

impl WatchdogAuthorityStateCell {
    pub(super) fn new() -> Self {
        Self {
            value: Arc::new(RwLock::new(WatchdogAuthoritySnapshot::no_authority())),
        }
    }

    /// Publishes that no current heartbeat authority is admitted. Stale epoch
    /// values are cleared rather than presented as current coverage.
    pub(super) fn publish_no_authority(&self) {
        match self.value.write() {
            Ok(mut value) => *value = WatchdogAuthoritySnapshot::no_authority(),
            Err(poisoned) => {
                *poisoned.into_inner() = WatchdogAuthoritySnapshot::no_authority();
            }
        }
    }

    /// Publishes one exact lease pair only after the injected Kernel port has
    /// accepted the corresponding heartbeat. Invalid zero epochs fail closed
    /// into the no-authority projection.
    pub(super) fn publish_admitted(&self, kernel_epoch: u64, watchdog_epoch: u64) {
        let next = if kernel_epoch == 0 || watchdog_epoch == 0 {
            WatchdogAuthoritySnapshot::no_authority()
        } else {
            WatchdogAuthoritySnapshot::admitted(kernel_epoch, watchdog_epoch)
        };
        match self.value.write() {
            Ok(mut value) => *value = next,
            Err(poisoned) => {
                *poisoned.into_inner() = next;
            }
        }
    }

    #[must_use]
    pub(super) fn load(&self) -> WatchdogAuthoritySnapshot {
        match self.value.read() {
            Ok(value) => *value,
            Err(_) => WatchdogAuthoritySnapshot::no_authority(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_epoch_pair_rotates_as_one_snapshot() {
        let cell = WatchdogAuthorityStateCell::new();
        assert_eq!(cell.load(), WatchdogAuthoritySnapshot::no_authority());

        cell.publish_admitted(7, 11);
        assert_eq!(
            cell.load(),
            WatchdogAuthoritySnapshot {
                state: WatchdogAuthorityState::AdmittedHeartbeat,
                kernel_epoch: 7,
                watchdog_epoch: 11,
            }
        );

        cell.publish_admitted(8, 12);
        assert_eq!(
            cell.load(),
            WatchdogAuthoritySnapshot {
                state: WatchdogAuthorityState::AdmittedHeartbeat,
                kernel_epoch: 8,
                watchdog_epoch: 12,
            }
        );
    }

    #[test]
    fn loss_or_invalid_epoch_clears_current_coverage() {
        let cell = WatchdogAuthorityStateCell::new();
        cell.publish_admitted(7, 11);
        cell.publish_no_authority();
        assert_eq!(cell.load(), WatchdogAuthoritySnapshot::no_authority());

        cell.publish_admitted(0, 12);
        assert_eq!(cell.load(), WatchdogAuthoritySnapshot::no_authority());
        cell.publish_admitted(8, 0);
        assert_eq!(cell.load(), WatchdogAuthoritySnapshot::no_authority());
    }
}
