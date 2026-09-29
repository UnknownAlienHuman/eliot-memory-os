//! Kernel-owned exact-fence lease census for the I1.5 idle-drain gate.
//!
//! Architecture: A13.2 (a minimally live Kernel can withhold unsupported
//! authority and fence stale owners), A2.3 (one causal responsibility, one
//! owner).
//! Implementation: I1.5 (idle drain begins only when no `RuntimeLease` remains
//! and no valid `SupervisionLease` requires live sensing/containment) and I14.23
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
//!   an active `RuntimeLease` exists for;
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
//! lease nor proof that work is finished.
//!
//! # Exact-fence runtime-lease rows (#1918)
//!
//! The runtime leg answers the full denominator through the landed owner read
//! [`RedbRecoveryStore::load_runtime_leases_by_state_fence`]: the exact-fence
//! `RuntimeLease` current set from the canonical `ors_runtime_lease_current_v1`
//! table, re-validated on readback and ordered by lease id. A non-terminal,
//! unexpired row for the current fence is a proven blocking obligation and
//! reports [`KernelIdleLeaseCensus::RuntimeLeased`]; a verified empty set is
//! the observed store fact, never a caller-supplied default. The durable
//! issuance writer for that table is
//! [`RedbRecoveryStore::record_runtime_lease_current`], called when the
//! Kernel grants activation. The supervision half of the same owner read,
//! [`RedbRecoveryStore::load_runtime_lease_census_by_state_fence`], serves the
//! authenticated `ReadRuntimeLeaseCensus` wire for Host generation retirement.
//!
//! [`RedbRecoveryStore::load_runtime_leases_by_state_fence`]: eliot_ors::RedbRecoveryStore::load_runtime_leases_by_state_fence
//! [`RedbRecoveryStore::load_runtime_lease_census_by_state_fence`]: eliot_ors::RedbRecoveryStore::load_runtime_lease_census_by_state_fence
//! [`RedbRecoveryStore::record_runtime_lease_current`]: eliot_ors::RedbRecoveryStore::record_runtime_lease_current
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
    /// The exact-fence runtime-lease owner read could not be established:
    /// the current fence is unreadable or the store read itself failed. An
    /// unprovable runtime set is not evidence that the installation is idle,
    /// so the drain gate stays closed.
    RuntimeCensusUnreadable,
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
            Self::RuntimeCensusUnreadable => {
                "runtime-lease-census-owner-read-unavailable:cannot-establish-exact-fence-runtime-set"
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
    /// A durable exact-fence `RuntimeLease` row is still non-terminal, so a
    /// workload obligation remains that shutdown may not abandon.
    RuntimeLeased,
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
            Self::RuntimeLeased => "runtime-leased",
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
        // therefore not a zero proof: the exact-fence runtime-lease owner read
        // below answers the remaining denominator (#1918, #2625).
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
            // durable runtime obligation remains. The runtime-lease leg reads
            // the exact-fence current set from its owner instead of
            // installing a default-zero stub.
            Ok(()) => self.runtime_lease_leg(),
        };
        publish_census(census)
    }

    /// Reads the exact-fence `RuntimeLease` current set for the fence the
    /// Kernel already admitted, through the generation gateway's canonical
    /// recovery store — the same store the supervision authority reads, so no
    /// second source is consulted and no composed authority is required.
    ///
    /// The current fence is copied out of the front-door policy and every
    /// guard is released before the ORS read: the store performs synchronous
    /// Redb I/O and a mutex must never be held across I/O, following the
    /// supervision leg's own lock discipline. A non-terminal row for this
    /// fence is a proven blocking obligation. An unreadable fence or a failed
    /// store read is unprovable and answers `Unavailable`, never `Idle`.
    #[cfg(windows)]
    fn runtime_lease_leg(&self) -> KernelIdleLeaseCensus {
        use eliot_runtime_contracts::LeaseState;

        let fence = match self.front_door_policy.lock() {
            Ok(policy) => policy.module_generation.state_fence.clone(),
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::RuntimeCensusUnreadable,
                );
            }
        };
        let Ok(rows) = self
            .generation_gateway
            .ors
            .load_runtime_leases_by_state_fence(&fence)
        else {
            return KernelIdleLeaseCensus::Unavailable(
                CensusUnavailability::RuntimeCensusUnreadable,
            );
        };
        // The terminal set mirrors the retirement gate the Host consumes
        // (`RuntimeLeaseCensus::is_fully_retired`): only a terminal row stops
        // blocking the drain. A non-terminal row whose recorded expiry has
        // passed is observed as expired, exactly like the supervision leg's
        // `expires_at_ms` comparison; the census classifies the recorded
        // value and never rewrites it.
        let now_ms = crate::unix_ms();
        let live = rows.iter().any(|lease| {
            !matches!(
                lease.state,
                LeaseState::Released
                    | LeaseState::Expired
                    | LeaseState::Revoked
                    | LeaseState::Superseded
                    | LeaseState::Closed
            ) && now_ms < lease.expires_at_ms
        });
        if live {
            return KernelIdleLeaseCensus::RuntimeLeased;
        }
        KernelIdleLeaseCensus::Idle
    }

    /// The Kernel has no ORS supervision authority or exact-fence runtime
    /// surface on non-Windows targets (I1.7), so the runtime leg cannot be
    /// established there. The drain gate stays closed through the legs that
    /// remain, exactly like the supervision and session legs.
    #[cfg(not(windows))]
    fn runtime_lease_leg(&self) -> KernelIdleLeaseCensus {
        KernelIdleLeaseCensus::Unavailable(CensusUnavailability::RuntimeCensusUnreadable)
    }

    /// Serves one exact-fence retirement census from the canonical ORS owner
    /// for the authenticated `ReadRuntimeLeaseCensus` wire (#1918 ACT-1/A4).
    ///
    /// This cannot issue or renew authority: it reads the current supervision
    /// row and the exact-fence `RuntimeLease` set both bound to the presented
    /// fence through the generation gateway's canonical recovery store, then
    /// validates the composed census before returning it. Every failure — an
    /// unreadable row, a foreign fence, or an invalid composition — is the
    /// boundary's own `SessionFenced`, so an unprovable census is never
    /// served as an empty one.
    #[cfg(windows)]
    pub(crate) fn read_runtime_lease_census(
        &self,
        fence: &eliot_contracts::StateFence,
        supervision_lease_id: &str,
    ) -> Result<eliot_kernel_service::RuntimeLeaseCensus, eliot_ipc::TransportError> {
        let lease_id = eliot_ors::OperationIdentity::new(supervision_lease_id.to_owned())
            .map_err(|_| eliot_ipc::TransportError::SessionFenced)?;
        let rows = self
            .generation_gateway
            .ors
            .load_runtime_lease_census_by_state_fence(fence, &lease_id)
            .map_err(|_| eliot_ipc::TransportError::SessionFenced)?;
        let census = eliot_kernel_service::RuntimeLeaseCensus {
            state_fence: fence.clone(),
            supervision_lease_id: supervision_lease_id.to_owned(),
            runtime_leases: rows.runtime_leases,
            supervision_lease: rows.supervision,
        };
        census
            .validate()
            .map_err(|_| eliot_ipc::TransportError::SessionFenced)?;
        Ok(census)
    }

    /// The retirement census has no ORS surface on non-Windows targets (I1.7):
    /// the authenticated wire is unsupported there and the read is refused.
    #[cfg(not(windows))]
    pub(crate) fn read_runtime_lease_census(
        &self,
        _fence: &eliot_contracts::StateFence,
        _supervision_lease_id: &str,
    ) -> Result<eliot_kernel_service::RuntimeLeaseCensus, eliot_ipc::TransportError> {
        Err(eliot_ipc::TransportError::SessionFenced)
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
