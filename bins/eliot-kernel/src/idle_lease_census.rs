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
//! # Fail-closed owner reads
//!
//! A leg is read as a *result*, never recovered. A poisoned guard is fenced
//! state, not an empty census: recovering it with `into_inner` and certifying
//! the recovered contents would authorise a drain from unreadable state, which
//! is the opposite of fail-closed. The in-crate precedent is
//! `host_request_route::fence_all_host_requests`, which fences the operations
//! it can still name and then reports `TransportError::SessionFenced` rather
//! than reporting an empty index. No guard is held across an ORS read, an RPC,
//! or an await point, and the existing lock order
//! (`daemon_runtime` → `agent_bridge_connections` → `host_request_connection_index`)
//! is preserved by releasing each guard before the next owner is touched.
//!
//! # Store attachment is not a lease
//!
//! The canonical-data leg does not derive an obligation count from the Store
//! attachment claim. The attachment claim is *Store attachment ownership* —
//! the single attachment slot #1086 retains across an idempotent reconnect and
//! refuses a second attachment — and an attached gateway is neither a workload
//! lease nor proof that work is finished. The owner read that could answer the
//! full denominator is
//! `RedbRecoveryStore::load_runtime_lease_census_by_state_fence(&StateFence,
//! Option<&OperationIdentity>)`, and it does not exist on current source: a
//! `#1751` residual recorded as
//! [`CensusUnavailability::RuntimeLeaseCensusOwnerAbsent`]. Until that owner
//! lands, the leg cannot answer KnownZero and never installs a default-zero
//! stub in its place.
//!
//! The census is read-only: it issues no lease, revokes nothing, and never
//! infers an obligation from a live process, an open pipe, or a heartbeat.

use crate::KernelComposition;
use crate::shutdown_drain::ShutdownDrainCoordinator;

/// The exact read contract a census leg could not satisfy.
///
/// Internal reason detail only (I15.4, F-LOG-KERNEL-3): every arm is a
/// compile-time constant that names *which* owner read is missing or fenced, so
/// the residual is repairable. No arm carries a lease identity, digest, epoch,
/// generation value, or owner error text.
/// [`KernelIdleLeaseCensus::observation_code`] stays the bounded external
/// vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CensusUnavailability {
    /// The Kernel's own daemon-contour guard is poisoned, so the admitted
    /// supervision contour cannot be read at all.
    DaemonContourUnreadable,
    /// A supervision contour is admitted but no ORS supervision-lease
    /// authority is attached to this composition, so no head can be read.
    SupervisionAuthorityAbsent,
    /// The exact ORS supervision-lease head for the admitted contour was
    /// absent, unreadable, or failed its own validation. A read that cannot be
    /// proven is not evidence that the installation is idle.
    SupervisionHeadUnreadable,
    /// The Kernel's admitted bridge-connection index guard is poisoned. A
    /// poisoned guard is fenced, not an empty set of sessions.
    BridgeSessionIndexUnreadable,
    /// The Kernel's admitted host-request connection index guard is poisoned. A
    /// poisoned guard is fenced, not an empty set of operations.
    HostRequestIndexUnreadable,
    /// The data leg has no owner read on current source. The exact
    /// `RedbRecoveryStore::load_runtime_lease_census_by_state_fence(&StateFence,
    /// Option<&OperationIdentity>)` read that binds live `RuntimeLease`,
    /// data/maintenance reservation, and unresolved Store-dependent effect
    /// obligations to the current State Fence is a `#1751` residual. Without
    /// it, zero obligations cannot be proven and no default-zero stub may
    /// stand in for it.
    RuntimeLeaseCensusOwnerAbsent,
}

impl CensusUnavailability {
    /// Internal reason text naming the exact missing or fenced read contract.
    ///
    /// Bounded by construction: each arm is a compile-time constant under
    /// [`crate::kernel_diagnostics::MAX_DIAGNOSTIC_FIELD_BYTES`], never
    /// owner-supplied text and never a lease identity or digest.
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::DaemonContourUnreadable => {
                "daemon-contour-guard-poisoned:cannot-read-admitted-supervision-contour"
            }
            Self::SupervisionAuthorityAbsent => {
                "supervision-lease-authority-absent:cannot-read-ors-supervision-head"
            }
            Self::SupervisionHeadUnreadable => {
                "ors-supervision-head-unreadable:KernelSupervisionLeaseAuthority::current_snapshot"
            }
            Self::BridgeSessionIndexUnreadable => {
                "agent-bridge-connection-index-guard-poisoned:cannot-read-bridge-sessions"
            }
            Self::HostRequestIndexUnreadable => {
                "host-request-connection-index-guard-poisoned:cannot-read-host-request-operations"
            }
            Self::RuntimeLeaseCensusOwnerAbsent => {
                "RedbRecoveryStore::load_runtime_lease_census_by_state_fence(&StateFence,Option<&OperationIdentity>):absent-runtime-lease-census-owner-read:#1751-residual"
            }
        }
    }
}

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
    /// A canonical-data obligation is known outstanding. The only proven
    /// blocking fact available today is the mechanical I14.23
    /// canonical-data precondition; it is never treated as an obligation
    /// count, and its satisfaction is never treated as a zero proof.
    CanonicalDataLeased,
    /// A required leg could not be established. Idle drain fails closed, and
    /// the variant carries the internal reason naming the missing read
    /// contract. The external code stays the bounded `"unavailable"`.
    Unavailable(CensusUnavailability),
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
            Self::Unavailable(_) => "unavailable",
        }
    }

    /// Internal unavailability reason, or `None` for every answer that is a
    /// real census result rather than a missing read contract.
    pub(crate) const fn unavailability(self) -> Option<CensusUnavailability> {
        match self {
            Self::Unavailable(reason) => Some(reason),
            _ => None,
        }
    }
}

impl KernelComposition {
    /// Establishes the Kernel-owned lease census that gates the ordered
    /// idle-drain sequence.
    pub(crate) fn idle_lease_census(&self) -> KernelIdleLeaseCensus {
        let census = self.supervision_leg();
        if census != KernelIdleLeaseCensus::Idle {
            return publish_census(census);
        }
        let census = self.front_door_session_leg();
        if census != KernelIdleLeaseCensus::Idle {
            return publish_census(census);
        }
        // The existing I14.23 lease-zero precondition stays the single owner of
        // the mechanical canonical-data fact, but the Store attachment claim it
        // is fed is ownership, not a lease denominator. Its satisfaction is
        // therefore not a zero proof: the leg reports the missing owner read
        // instead of `Idle` (#2625, #1751 residual).
        let census = match ShutdownDrainCoordinator::check_lease_zero(
            self.canonical_store_claimed
                .load(std::sync::atomic::Ordering::Acquire),
        ) {
            // A claimed attachment slot definitively violates the
            // mechanical I14.23 precondition, so that known blocking fact
            // is reported as such. It is never read as proof that a
            // workload lease exists.
            Err(_) => KernelIdleLeaseCensus::CanonicalDataLeased,
            // Nothing is blocked mechanically, which is not evidence that no
            // data/maintenance or unresolved Store-dependent obligation
            // remains. Name the exact missing read contract instead of
            // installing a default-zero stub.
            Ok(()) => KernelIdleLeaseCensus::Unavailable(
                CensusUnavailability::RuntimeLeaseCensusOwnerAbsent,
            ),
        };
        publish_census(census)
    }

    /// Reads the exact ORS supervision-lease head for the activation contour
    /// the Kernel already admitted.
    #[cfg(windows)]
    fn supervision_leg(&self) -> KernelIdleLeaseCensus {
        use eliot_runtime_contracts::LeaseState;

        // Copy the two admitted-contour facts the leg needs into locals and
        // release the `daemon_runtime` guard *before* the ORS read:
        // `current_snapshot` performs a synchronous Redb read and a mutex must
        // never be held across I/O.
        let (supervision_expired, supervision) = match self.daemon_runtime.lock() {
            Ok(runtime) => (runtime.supervision_expired, runtime.supervision.clone()),
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::DaemonContourUnreadable,
                );
            }
        };
        if supervision_expired {
            // The progress route already reported terminal lease expiry, so
            // coverage ended honestly and is not an obstacle to drain.
            return KernelIdleLeaseCensus::Idle;
        }
        let Some(contour) = supervision.as_ref() else {
            // No admitted supervision contour means no issued lease for this
            // activation, which is the dormant-installation case.
            return KernelIdleLeaseCensus::Idle;
        };
        let Some(authority) = self.supervision_lease_authority.as_ref() else {
            return KernelIdleLeaseCensus::Unavailable(
                CensusUnavailability::SupervisionAuthorityAbsent,
            );
        };
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        match authority.current_snapshot(lease_id) {
            Ok(Some(snapshot)) => {
                if snapshot.validate().is_err() {
                    return KernelIdleLeaseCensus::Unavailable(
                        CensusUnavailability::SupervisionHeadUnreadable,
                    );
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
            Ok(None) | Err(_) => {
                KernelIdleLeaseCensus::Unavailable(CensusUnavailability::SupervisionHeadUnreadable)
            }
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
    ///
    /// Each index is read as a result under its own guard, and each guard is
    /// released before the next owner is touched. A poisoned guard is fenced
    /// state and answers `Unavailable`; it is never recovered with
    /// `into_inner` and never falls through to `Idle`.
    #[cfg(windows)]
    fn front_door_session_leg(&self) -> KernelIdleLeaseCensus {
        let bridge_session_leased = match self.agent_bridge_connections.lock() {
            Ok(connections) => !connections.is_empty(),
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::BridgeSessionIndexUnreadable,
                );
            }
        };
        if bridge_session_leased {
            return KernelIdleLeaseCensus::BridgeSessionLeased;
        }
        let host_request_leased = match self.host_request_connection_index.lock() {
            Ok(index) => index.values().any(|operations| !operations.is_empty()),
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::HostRequestIndexUnreadable,
                );
            }
        };
        if host_request_leased {
            return KernelIdleLeaseCensus::HostRequestLeased;
        }
        KernelIdleLeaseCensus::Idle
    }

    #[cfg(not(windows))]
    fn front_door_session_leg(&self) -> KernelIdleLeaseCensus {
        KernelIdleLeaseCensus::Idle
    }
}

/// Publishes the internal unavailability reason beside the bounded external
/// code, so an operator can repair the named owner read without the external
/// vocabulary ever widening (I15.4). Every caller of the census goes through
/// here, so the residual is recorded wherever the census is consumed.
fn publish_census(census: KernelIdleLeaseCensus) -> KernelIdleLeaseCensus {
    if let Some(reason) = census.unavailability() {
        crate::health_view::observe_shutdown_observation(
            "kernel.shutdown.lease_census_unavailable",
            reason.reason_code(),
        );
    }
    census
}
