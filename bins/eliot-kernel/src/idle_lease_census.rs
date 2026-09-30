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
//!   [`crate::KernelSupervisionLeaseAuthority`]; only a persisted terminal head
//!   ends coverage, while an elapsed deadline on a non-terminal head remains
//!   blocking and an unreadable head is `Unavailable`;
//! * the bridge/host-request legs read the Kernel's own admitted front-door
//!   session state, which is the live authenticated UI/CLI/MCP/bridge Session
//!   an active `RuntimeLease` exists for;
//! * the canonical-data leg reads one complete Store-stop owner projection
//!   from the canonical ORS snapshot, including runtime and supervision
//!   leases, data/maintenance reservations, staged admissions, and unresolved
//!   effects.
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
//! # Complete Store-stop owner projection
//!
//! The data leg reads [`RedbRecoveryStore::load_store_stop_obligation_census`]
//! from one redb read transaction. It validates every row in each required
//! owner family, counts every non-terminal obligation without consulting the
//! local clock, and returns the installation, Store generation, activation,
//! State Fence, admission revision, and a content revision over the exact
//! scanned rows. The authenticated `ReadRuntimeLeaseCensus` wire carries this
//! same Store-stop projection to the Host mirror and retirement barrier.
//!
//! [`RedbRecoveryStore::load_store_stop_obligation_census`]: eliot_ors::RedbRecoveryStore::load_store_stop_obligation_census
//! [`RedbRecoveryStore::load_runtime_lease_census_by_state_fence`]: eliot_ors::RedbRecoveryStore::load_runtime_lease_census_by_state_fence
//! [`RedbRecoveryStore::record_runtime_lease_current`]: eliot_ors::RedbRecoveryStore::record_runtime_lease_current
//! The census is read-only: it issues no lease, revokes nothing, and never
//! infers an obligation from a live process, an open pipe, or a heartbeat.

use crate::KernelComposition;
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
    /// The exact-fence Store-stop owner read could not establish the complete
    /// set of runtime, data, maintenance, admission, and effect obligations.
    /// An unprovable owner set is not evidence that the installation is idle.
    RuntimeCensusUnreadable,
    /// One or more required Store-stop owner families could not be read or
    /// validated as a complete same-snapshot projection.
    StoreObligationCensusUnreadable,
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
                "store-stop-owner-read-unavailable:cannot-establish-exact-fence-owner-set"
            }
            Self::StoreObligationCensusUnreadable => {
                "store-stop-census-owner-read-unavailable:complete-obligation-denominator-unproven"
            }
        }
    }
}

/// Bounded disposition of one exact-fence lease census.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KernelIdleLeaseDisposition {
    /// No blocking owner remains and the complete Store census is known zero.
    Idle,
    /// The persisted ORS supervision lease is still non-terminal, so Watchdog
    /// coverage remains owed until its owner records a terminal transition.
    SupervisionLeased,
    /// An authenticated front-door bridge Session is still connected.
    BridgeSessionLeased,
    /// An admitted host-request operation is still outstanding.
    HostRequestLeased,
    /// A persisted `RuntimeLease` in the complete Store owner projection is
    /// still non-terminal, so shutdown may not abandon its workload.
    RuntimeLeased,
    /// A Store-dependent admission, data, maintenance, or unresolved-effect
    /// obligation remains in the complete ORS owner projection.
    StoreObligationLeased,
    /// A required leg could not be established. Idle drain fails closed, and
    /// the variant carries the internal reason naming the missing read
    /// contract. The external code stays the bounded `"unavailable"`.
    Unavailable(CensusUnavailability),
}

/// One typed census result shared by status and the shutdown gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelIdleLeaseCensus {
    disposition: KernelIdleLeaseDisposition,
    store_stop_obligations: Option<eliot_ors::StoreStopObligationCensus>,
}

impl KernelIdleLeaseCensus {
    /// Whether the ordered drain sequence may proceed.
    pub(crate) fn admits_drain(&self) -> bool {
        matches!(self.disposition, KernelIdleLeaseDisposition::Idle)
            && self
                .store_stop_obligations
                .as_ref()
                .is_some_and(eliot_ors::StoreStopObligationCensus::is_known_zero)
    }

    /// Bounded observation code for the Kernel diagnostics facade
    /// (F-LOG-KERNEL-3, I15.4: no lease identity, digest, or owner error text).
    pub(crate) const fn observation_code(&self) -> &'static str {
        match self.disposition {
            KernelIdleLeaseDisposition::Idle => "idle",
            KernelIdleLeaseDisposition::SupervisionLeased => "supervision-leased",
            KernelIdleLeaseDisposition::BridgeSessionLeased => "bridge-session-leased",
            KernelIdleLeaseDisposition::HostRequestLeased => "host-request-leased",
            KernelIdleLeaseDisposition::RuntimeLeased => "runtime-leased",
            KernelIdleLeaseDisposition::StoreObligationLeased => "store-obligation-leased",
            KernelIdleLeaseDisposition::Unavailable(_) => "unavailable",
        }
    }

    /// Internal unavailability reason, or `None` for every answer that is a
    /// real census result rather than a missing read contract.
    pub(crate) const fn unavailability(&self) -> Option<CensusUnavailability> {
        match self.disposition {
            KernelIdleLeaseDisposition::Unavailable(reason) => Some(reason),
            _ => None,
        }
    }

    /// Whether the observed supervision owner is still active.
    pub(crate) const fn supervision_is_active(&self) -> bool {
        matches!(
            self.disposition,
            KernelIdleLeaseDisposition::SupervisionLeased
        )
    }

    /// Complete ORS owner projection captured with this census, if its read succeeded.
    pub(crate) fn store_stop_obligations(
        &self,
    ) -> Option<&eliot_ors::StoreStopObligationCensus> {
        self.store_stop_obligations.as_ref()
    }
}

impl KernelComposition {
    /// Establishes the Kernel-owned lease census that gates the ordered
    /// idle-drain sequence.
    pub(crate) fn idle_lease_census(&self) -> KernelIdleLeaseCensus {
        // Read each owner before choosing the bounded disposition so a known
        // busy fact is retained even if another owner is unreadable. The Store
        // attachment latch is intentionally absent: it is ownership, not an
        // obligation row, and remains claimed through this read.
        let supervision = self.supervision_leg();
        let front_door = self.front_door_session_leg();
        let (store_disposition, store_stop_obligations) = self.runtime_lease_leg();
        let disposition = if disposition_is_busy(supervision) {
            supervision
        } else if disposition_is_busy(front_door) {
            front_door
        } else if disposition_is_busy(store_disposition) {
            store_disposition
        } else if let KernelIdleLeaseDisposition::Unavailable(reason) = supervision {
            KernelIdleLeaseDisposition::Unavailable(reason)
        } else if let KernelIdleLeaseDisposition::Unavailable(reason) = front_door {
            KernelIdleLeaseDisposition::Unavailable(reason)
        } else if let KernelIdleLeaseDisposition::Unavailable(reason) = store_disposition {
            KernelIdleLeaseDisposition::Unavailable(reason)
        } else {
            KernelIdleLeaseDisposition::Idle
        };
        publish_census(KernelIdleLeaseCensus {
            disposition,
            store_stop_obligations,
        })
    }

    /// Reads the complete Store-stop owner set from one exact-fence ORS
    /// snapshot. The projection is the same typed source consumed by the
    /// status facade, Host mirror, and final shutdown gate.
    ///
    /// The current fence and activation are copied out of their guards before
    /// the ORS read. The store performs synchronous redb I/O, so no mutex is
    /// held across the owner read. Any missing family, malformed row, or
    /// unreadable fence is `Unavailable`, never a zero result.
    #[cfg(windows)]
    fn runtime_lease_leg(
        &self,
    ) -> (
        KernelIdleLeaseDisposition,
        Option<eliot_ors::StoreStopObligationCensus>,
    ) {
        let fence = match self.front_door_policy.lock() {
            Ok(policy) => policy.module_generation.state_fence.clone(),
            Err(_) => {
                return (
                    KernelIdleLeaseDisposition::Unavailable(
                        CensusUnavailability::RuntimeCensusUnreadable,
                    ),
                    None,
                );
            }
        };
        let activation_id = match self.daemon_runtime.lock() {
            Ok(runtime) => runtime
                .supervision
                .as_ref()
                .map(|contour| contour.incarnation.activation_id.clone()),
            Err(_) => {
                return (
                    KernelIdleLeaseDisposition::Unavailable(
                        CensusUnavailability::DaemonContourUnreadable,
                    ),
                    None,
                );
            }
        };
        let census = match self
            .generation_gateway
            .ors
            .load_store_stop_obligation_census(&fence, activation_id.as_deref())
        {
            Ok(census) if census.validate().is_ok() => census,
            _ => {
                return (
                    KernelIdleLeaseDisposition::Unavailable(
                        CensusUnavailability::StoreObligationCensusUnreadable,
                    ),
                    None,
                );
            }
        };
        let disposition = if census.counts.runtime_leases != 0 {
            KernelIdleLeaseDisposition::RuntimeLeased
        } else if !census.is_known_zero() {
            KernelIdleLeaseDisposition::StoreObligationLeased
        } else {
            KernelIdleLeaseDisposition::Idle
        };
        (disposition, Some(census))
    }

    /// The Kernel has no ORS supervision authority or exact-fence runtime
    /// surface on non-Windows targets (I1.7), so the runtime leg cannot be
    /// established there. The drain gate stays closed through the legs that
    /// remain, exactly like the supervision and session legs.
    #[cfg(not(windows))]
    fn runtime_lease_leg(
        &self,
    ) -> (
        KernelIdleLeaseDisposition,
        Option<eliot_ors::StoreStopObligationCensus>,
    ) {
        (
            KernelIdleLeaseDisposition::Unavailable(
                CensusUnavailability::RuntimeCensusUnreadable,
            ),
            None,
        )
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
            store_stop_obligations: rows.store_stop,
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
    fn supervision_leg(&self) -> KernelIdleLeaseDisposition {
        use eliot_runtime_contracts::LeaseState;

        // Copy the two admitted-contour facts the leg needs into locals and
        // release the `daemon_runtime` guard *before* the ORS read:
        // `current_snapshot` performs a synchronous Redb read and a mutex must
        // never be held across I/O.
        let supervision = match self.daemon_runtime.lock() {
            Ok(runtime) => runtime.supervision.clone(),
            Err(_) => {
                return KernelIdleLeaseDisposition::Unavailable(
                    CensusUnavailability::DaemonContourUnreadable,
                );
            }
        };
        let Some(contour) = supervision.as_ref() else {
            // No admitted supervision contour means no issued lease for this
            // activation, which is the dormant-installation case.
            return KernelIdleLeaseDisposition::Idle;
        };
        let Some(authority) = self.supervision_lease_authority.as_ref() else {
            return KernelIdleLeaseDisposition::Unavailable(
                CensusUnavailability::SupervisionAuthorityAbsent,
            );
        };
        let lease_id = contour.incarnation.supervision_lease_id.as_str();
        match authority.current_snapshot(lease_id) {
            Ok(Some(snapshot)) => {
                if snapshot.validate().is_err() {
                    return KernelIdleLeaseDisposition::Unavailable(
                        CensusUnavailability::SupervisionHeadUnreadable,
                    );
                }
                if matches!(
                    snapshot.record.state,
                    LeaseState::Released
                        | LeaseState::Expired
                        | LeaseState::Revoked
                        | LeaseState::Superseded
                        | LeaseState::Closed
                ) && snapshot.record.projection
                    == eliot_ors::SupervisionLeaseProjection::Terminal
                {
                    KernelIdleLeaseDisposition::Idle
                } else {
                    // The local expiry marker and deadline cannot release the
                    // durable owner. Only its terminal ORS revision can.
                    KernelIdleLeaseDisposition::SupervisionLeased
                }
            }
            // An absent head for an admitted contour is an exact-mismatch, not
            // an expired lease; coverage cannot be claimed from it. A read that
            // cannot be proven is treated exactly the same way: neither is
            // evidence that the installation is idle, so both legs answer
            // Unavailable and the drain gate stays closed.
            Ok(None) | Err(_) => {
                KernelIdleLeaseDisposition::Unavailable(
                    CensusUnavailability::SupervisionHeadUnreadable,
                )
            }
        }
    }

    /// The Kernel has no ORS supervision authority, Watchdog sibling, or
    /// authenticated front-door Session on non-Windows targets (I1.7), so the
    /// only remaining leg is the canonical-data one.
    #[cfg(not(windows))]
    fn supervision_leg(&self) -> KernelIdleLeaseDisposition {
        KernelIdleLeaseDisposition::Idle
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
    fn front_door_session_leg(&self) -> KernelIdleLeaseDisposition {
        let bridge_session_leased = match self.agent_bridge_connections.lock() {
            Ok(connections) => !connections.is_empty(),
            Err(_) => {
                return KernelIdleLeaseDisposition::Unavailable(
                    CensusUnavailability::BridgeSessionIndexUnreadable,
                );
            }
        };
        if bridge_session_leased {
            return KernelIdleLeaseDisposition::BridgeSessionLeased;
        }
        let host_request_leased = match self.host_request_connection_index.lock() {
            Ok(index) => index.values().any(|operations| !operations.is_empty()),
            Err(_) => {
                return KernelIdleLeaseDisposition::Unavailable(
                    CensusUnavailability::HostRequestIndexUnreadable,
                );
            }
        };
        if host_request_leased {
            return KernelIdleLeaseDisposition::HostRequestLeased;
        }
        KernelIdleLeaseDisposition::Idle
    }

    #[cfg(not(windows))]
    fn front_door_session_leg(&self) -> KernelIdleLeaseDisposition {
        KernelIdleLeaseDisposition::Idle
    }
}

const fn disposition_is_busy(disposition: KernelIdleLeaseDisposition) -> bool {
    matches!(
        disposition,
        KernelIdleLeaseDisposition::SupervisionLeased
            | KernelIdleLeaseDisposition::BridgeSessionLeased
            | KernelIdleLeaseDisposition::HostRequestLeased
            | KernelIdleLeaseDisposition::RuntimeLeased
            | KernelIdleLeaseDisposition::StoreObligationLeased
    )
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
