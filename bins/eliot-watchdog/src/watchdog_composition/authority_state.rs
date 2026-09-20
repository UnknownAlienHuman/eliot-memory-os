//! Watchdog readiness and bounded authority-state cell.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose),
//! A13.2 (docs/architecture/A13-02-kernel-and-failure-domains.md#a132-kernel-and-failure-domains),
//! ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04.
//! Implementation: I8.1 (docs/architecture/I08-01-process-and-authority.md#i81-process-and-authority).
//!
//! This child owns only readiness values and the bounded in-memory authority
//! state transitions; it owns no Kernel effect, Host identity, lease issuance,
//! lifecycle, shutdown, canonical state, or retry authority.
//! Those boundaries remain with the parent composition facade and its injected
//! ports.

use std::sync::{Arc, RwLock};

/// Readiness data emitted by the process entrypoint.
///
/// I1.5 (#1750) verification contract for every field. This cell is
/// Watchdog-local state: the Host has no transport that reads it, so no Host
/// path may treat SCM `Running` — or any projection it cannot observe —
/// as supervised coverage. There is deliberately no Host-side heartbeat
/// validator: an uncalled validator would be dead code, and the admitted ORS
/// snapshot cannot substitute for heartbeat recency — it carries lease
/// currency (the epoch pair plus the `issued/expires/renew-before` validity
/// window) but no heartbeat observation (no authority state, no coverage
/// flag, no tick interval, no last-beat timestamp). Liveness from the
/// snapshot alone would conflate Kernel-renewal currency with a fresh
/// Watchdog heartbeat, so no such check is claimed.
///
/// Heartbeat-transport remainder (not implemented in this slice). When a
/// Host-to-Watchdog transport lands, it must deliver this exact projection
/// shape plus an emission timestamp (the current shape has no timestamp, so
/// no freshness bound is expressible yet):
/// - type: one `WatchdogReadiness` projection per supervision contour —
///   `authority_state`, `coverage_claimed`, the admitted epoch pair, and
///   `tick_interval_ms`, plus the new emission timestamp;
/// - writer: the Watchdog process entrypoint, publishing from this
///   authority-state cell after the Kernel accepts the corresponding
///   heartbeat;
/// - reader: the Host readiness/SCM admission path, which must require
///   `AdmittedHeartbeat` with `coverage_claimed == true`, the exact
///   admitted epoch pair, and an emission timestamp within a small multiple
///   of `tick_interval_ms` — anything else fails closed into the
///   gap-only signal. Until that transport exists, every supervision claim
///   that would need it must fail closed.
///
/// Field contract the future reader must apply before treating a delivered
/// projection as coverage:
/// - `authority_state` / `coverage_claimed`: require `AdmittedHeartbeat` with
///   `coverage_claimed == true`. `RunningNoAuthority` is an explicit gap-only
///   signal (the SCM sibling is alive but no current Host-issued lease has
///   been admitted for heartbeat authority), never coverage.
/// - `kernel_epoch` / `watchdog_epoch`: the exact admitted lease pair,
///   rotated atomically under one lock so a reader can never combine epochs
///   from different leases. The Host verifies them against the current
///   activation's supervision incarnation. A zero epoch is never published as
///   coverage: the cell below fails closed into the no-authority projection.
/// - `tick_interval_ms`: the bounded supervision tick, i.e. the
///   responsiveness bound. A projection older than a small multiple of this
///   interval without a fresh admitted heartbeat must be treated as
///   unresponsive, never as current coverage.
///
/// Binding a projection to its exact lease (lease identity plus ORS receipt
/// digest) is owned by the supervision-claim path, not by this shape: the
/// Host persists a watchdog-branch evidence ref naming the exact admitted
/// lease id, receipt digest, publication digest, and epoch, all derived from
/// the single Kernel-renewed `ORS` snapshot via the provisioned admission
/// template (no caller-supplied identity),
/// the Kernel `ProbeReady` gate enforces exact epoch equality against the
/// renewed ORS head, publication exactness against the ORS head is verified
/// at publish time, and governance stays degraded until a proven-ready
/// transition. SCM liveness alone (this projection unread, or
/// `RunningNoAuthority`) never satisfies that path.
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
