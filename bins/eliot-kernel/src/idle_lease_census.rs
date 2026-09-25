//! Kernel-owned exact-fence lease census for the I1.5 idle-drain gate.
//!
//! Architecture: A13.2 (a minimally live Kernel can withhold unsupported
//! authority and fence stale owners), A2.3 (one causal responsibility, one
//! owner).
//! Implementation: I1.5 (idle drain begins only when no RuntimeLease remains
//! and no valid SupervisionLease requires live sensing/containment) and I14.23
//! (the `StoreStopLeaseZero` drain phase).
//!
//! The Kernel owns the canonical-data lease, the ORS supervision-lease head and
//! the live authenticated front-door sessions, so the census lives here rather
//! than in Host, which only holds the published mirror of one of those legs.
//! Every leg reads state its own owner already produced:
//!
//! * the supervision leg reads the exact ORS head for the current activation's
//!   supervision lease through the existing
//!   [`crate::KernelSupervisionLeaseAuthority`]; a terminal or expired head ends
//!   coverage honestly and stops blocking, while an unreadable head is
//!   `Unavailable` and never `Idle`;
//! * the bridge/host-request legs read the Kernel's own admitted front-door
//!   session state, which is the live authenticated UI/CLI/MCP/bridge Session
//!   an active RuntimeLease exists for;
//! * the canonical-data leg reuses
//!   [`ShutdownDrainCoordinator::check_lease_zero`], the existing I14.23
//!   precondition.
//!
//! The census is read-only: it issues no lease, revokes nothing, and never
//! infers an obligation from a live process, an open pipe, or a heartbeat.

use crate::KernelComposition;
use crate::shutdown_drain::ShutdownDrainCoordinator;

/// One exact-fence lease census answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelIdleLeaseCensus {
    /// No lease remains: idle drain is admitted.
    Idle,
    /// An ORS supervision lease is still active and unexpired, so Watchdog
    /// coverage is still owed.
    SupervisionLeased,
    /// An authenticated front-door bridge Session is still connected.
    BridgeSessionLeased,
    /// An admitted host-request operation is still outstanding.
    HostRequestLeased,
    /// A canonical-data lease is still outstanding.
    CanonicalDataLeased,
    /// A leg could not be established. Idle drain fails closed.
    Unavailable,
}

impl KernelIdleLeaseCensus {
    /// Whether the ordered drain sequence may proceed.
    pub(crate) const fn admits_drain(self) -> bool {
        matches!(self, Self::Idle)
    }

    /// Bounded observation code for the Kernel diagnostics facade
    /// (F-LOG-KERNEL-3, I15.4: no lease identity, digest, or owner error text).
    pub(crate) const fn observation_code(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SupervisionLeased => "supervision-leased",
            Self::BridgeSessionLeased => "bridge-session-leased",
            Self::HostRequestLeased => "host-request-leased",
            Self::CanonicalDataLeased => "canonical-data-leased",
            Self::Unavailable => "unavailable",
        }
    }
}

impl KernelComposition {
    /// Establishes the Kernel-owned lease census that gates the ordered
    /// idle-drain sequence.
    pub(crate) fn idle_lease_census(&self) -> KernelIdleLeaseCensus {
        let census = self.supervision_leg();
        if census != KernelIdleLeaseCensus::Idle {
            return census;
        }
        let census = self.front_door_session_leg();
        if census != KernelIdleLeaseCensus::Idle {
            return census;
        }
        // The existing I14.23 lease-zero precondition stays the single owner of
        // the canonical-data leg.
        match ShutdownDrainCoordinator::check_lease_zero(
            self.canonical_store_claimed
                .load(std::sync::atomic::Ordering::Acquire),
        ) {
            Ok(()) => KernelIdleLeaseCensus::Idle,
            Err(_) => KernelIdleLeaseCensus::CanonicalDataLeased,
        }
    }

    /// Reads the exact ORS supervision-lease head for the activation contour
    /// the Kernel already admitted.
    #[cfg(windows)]
    fn supervision_leg(&self) -> KernelIdleLeaseCensus {
        use eliot_runtime_contracts::LeaseState;

        let Ok(runtime) = self.daemon_runtime.lock() else {
            return KernelIdleLeaseCensus::Unavailable;
        };
        if runtime.supervision_expired {
            // The progress route already reported terminal lease expiry, so
            // coverage ended honestly and is not an obstacle to drain.
            return KernelIdleLeaseCensus::Idle;
        }
        let Some(contour) = runtime.supervision.as_ref() else {
            // No admitted supervision contour means no issued lease for this
            // activation, which is the dormant-installation case.
            return KernelIdleLeaseCensus::Idle;
        };
        let Some(authority) = self.supervision_lease_authority.as_ref() else {
            return KernelIdleLeaseCensus::Unavailable;
        };
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        match authority.current_snapshot(lease_id) {
            Ok(Some(snapshot)) => {
                if snapshot.validate().is_err() {
                    return KernelIdleLeaseCensus::Unavailable;
                }
                let payload = &snapshot.record.artifact.payload;
                if snapshot.record.state == LeaseState::Active
                    && crate::unix_ms() < payload.expires_at_ms
                {
                    KernelIdleLeaseCensus::SupervisionLeased
                } else {
                    KernelIdleLeaseCensus::Idle
                }
            }
            // An absent head for an admitted contour is an exact-mismatch, not
            // an expired lease; coverage cannot be claimed from it. A read that
            // cannot be proven is treated exactly the same way: neither is
            // evidence that the installation is idle, so both legs answer
            // Unavailable and the drain gate stays closed.
            Ok(None) | Err(_) => KernelIdleLeaseCensus::Unavailable,
        }
    }

    /// The Kernel has no ORS supervision authority, Watchdog sibling, or
    /// authenticated front-door Session on non-Windows targets (I1.7), so the
    /// only remaining leg is the canonical-data one.
    #[cfg(not(windows))]
    fn supervision_leg(&self) -> KernelIdleLeaseCensus {
        KernelIdleLeaseCensus::Idle
    }

    /// Reads the Kernel's own admitted front-door session state: a live
    /// authenticated bridge connection, or a host-request operation that has
    /// not reached a terminal disposition.
    #[cfg(windows)]
    fn front_door_session_leg(&self) -> KernelIdleLeaseCensus {
        if let Ok(connections) = self.agent_bridge_connections.lock()
            && !connections.is_empty()
        {
            return KernelIdleLeaseCensus::BridgeSessionLeased;
        }
        if let Ok(index) = self.host_request_connection_index.lock()
            && index.values().any(|operations| !operations.is_empty())
        {
            return KernelIdleLeaseCensus::HostRequestLeased;
        }
        KernelIdleLeaseCensus::Idle
    }

    #[cfg(not(windows))]
    fn front_door_session_leg(&self) -> KernelIdleLeaseCensus {
        KernelIdleLeaseCensus::Idle
    }
}
