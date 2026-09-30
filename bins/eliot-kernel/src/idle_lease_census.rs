//! Kernel-owned exact-fence lease census for the I1.5 idle-drain gate.
//!
//! Architecture: A13.2 (a minimally live Kernel can withhold unsupported
//! authority and fence stale owners), A2.3 (one causal responsibility, one
//! owner).
//! Implementation: I1.5 (idle drain begins only when no `RuntimeLease` remains
//! and no valid `SupervisionLease` requires live sensing/containment) and I14.23
//! (the `StoreStopLeaseZero` drain phase).
//!
//! The Kernel owns lifecycle admission and reads the ORS supervision lease and
//! canonical Store-stop obligation owners, so the census lives here rather than
//! in Host, which only holds a mirror of the published owner result.
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
//! * the Store-stop leg reads the complete owner-issued ORS denominator for
//!   RuntimeLease rows, data and maintenance reservations, admissions already
//!   in flight, and unresolved Store-dependent effects.
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
//! # Complete Store-stop owner census (#2625)
//!
//! The runtime leg reads [`RedbRecoveryStore::load_store_stop_census`] from one
//! canonical ORS snapshot. It proves the installation, activation, Store
//! generation, exact StateFence, admission revision and owner-observation
//! revision; every required source family is scanned in full. A persisted
//! nonterminal RuntimeLease remains blocking regardless of its local expiry.
//! The typed result is retained through status and the shutdown gate and is
//! served to Host over the authenticated `ReadRuntimeLeaseCensus` arm.
//!
//! [`RedbRecoveryStore::load_store_stop_census`]: eliot_ors::RedbRecoveryStore::load_store_stop_census
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
    /// The complete Store-stop owner read or its admission binding could not
    /// be established. An unprovable denominator is not evidence that the
    /// installation is idle, so the drain gate stays closed.
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
                "RedbRecoveryStore::load_store_stop_census:complete-owner-read-unavailable"
            }
        }
    }
}

/// One Kernel status observation, retaining the shared ORS result when the
/// durable Store-stop denominator is reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KernelIdleLeaseCensus {
    /// No in-memory lease leg blocks the observation.
    Idle,
    /// An ORS supervision lease is still active and unexpired, so Watchdog
    /// coverage is still owed.
    SupervisionLeased,
    /// An authenticated front-door bridge Session is still connected.
    BridgeSessionLeased,
    /// An admitted host-request operation is still outstanding.
    HostRequestLeased,
    /// A normal Kernel admission permit is still held by an in-flight operation.
    NormalAdmissionLeased,
    /// The complete typed ORS Store-stop result for the exact current fence.
    StoreCensus(eliot_ors::StoreStopCensusResult),
    /// A required Kernel-local owner read could not be established.
    Unavailable(CensusUnavailability),
}

impl KernelIdleLeaseCensus {
    /// Whether the ordered drain sequence may proceed.
    pub(crate) fn admits_drain(&self) -> bool {
        matches!(self, Self::Idle)
            || matches!(self, Self::StoreCensus(census) if census.is_known_zero())
    }

    /// Bounded observation code for the Kernel diagnostics facade.
    pub(crate) fn observation_code(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SupervisionLeased => "supervision-leased",
            Self::BridgeSessionLeased => "bridge-session-leased",
            Self::HostRequestLeased => "host-request-leased",
            Self::NormalAdmissionLeased => "normal-admission-leased",
            Self::StoreCensus(census) => census.observation_code(),
            Self::Unavailable(_) => "unavailable",
        }
    }

    /// The exact owner result used by shutdown or the status projection.
    pub(crate) fn store_stop_result(
        &self,
    ) -> Option<&eliot_ors::StoreStopCensusResult> {
        match self {
            Self::StoreCensus(census) => Some(census),
            _ => None,
        }
    }

    /// Internal unavailability reason, or `None` for established results.
    pub(crate) fn unavailability(&self) -> Option<CensusUnavailability> {
        match self {
            Self::Unavailable(reason) => Some(*reason),
            Self::StoreCensus(eliot_ors::StoreStopCensusResult::Unavailable { .. }) => {
                Some(CensusUnavailability::RuntimeCensusUnreadable)
            }
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
        // Store attachment remains a separate single-attachment latch. It is
        // not part of the Store-stop obligation denominator. The ORS-owned
        // census is the only persisted lease input to this final leg.
        publish_census(self.runtime_lease_leg())
    }

    /// Reads the complete ORS Store-stop denominator for the Kernel's current
    /// StateFence. Admission and owner revisions remain typed through status,
    /// shutdown, and the authenticated Host response.
    #[cfg(windows)]
    fn runtime_lease_leg(&self) -> KernelIdleLeaseCensus {
        let fence = match self.front_door_policy.lock() {
            Ok(policy) => policy.module_generation.state_fence.clone(),
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::RuntimeCensusUnreadable,
                );
            }
        };
        let supervision_lease_id = match self.daemon_runtime.lock() {
            Ok(runtime) => runtime
                .supervision
                .as_ref()
                .map(|contour| contour.incarnation.supervision_lease_id.as_str().to_owned()),
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::RuntimeCensusUnreadable,
                );
            }
        };
        let admission_revision = match self.store_stop_admission_revision(&fence, false) {
            Ok(revision) => revision,
            Err("normal-admission-in-flight") => {
                return KernelIdleLeaseCensus::NormalAdmissionLeased;
            }
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::RuntimeCensusUnreadable,
                );
            }
        };
        let (installation_id, activation_id) = match self.service.lock() {
            Ok(service) => {
                let Some(candidate) = service.candidate_binding() else {
                    return KernelIdleLeaseCensus::Unavailable(
                        CensusUnavailability::RuntimeCensusUnreadable,
                    );
                };
                (
                    candidate.installation_id.as_str().to_owned(),
                    candidate.activation_id.as_str().to_owned(),
                )
            }
            Err(_) => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::RuntimeCensusUnreadable,
                );
            }
        };
        let request = eliot_ors::StoreStopCensusRequest {
            state_fence: fence.clone(),
            supervision_lease_id,
            expected_installation_id: Some(installation_id),
            expected_activation_id: Some(activation_id),
            expected_activation_generation: Some(fence.resource_generation),
            admission_revision: admission_revision.clone(),
        };
        let census = self.generation_gateway.ors.load_store_stop_census(&request);
        let revalidated_revision = self.store_stop_admission_revision(&fence, false);
        if census.validate().is_err() {
            return KernelIdleLeaseCensus::Unavailable(
                CensusUnavailability::RuntimeCensusUnreadable,
            );
        }
        match revalidated_revision {
            Ok(current) if current == admission_revision => {}
            Err("normal-admission-in-flight")
                if matches!(&census, eliot_ors::StoreStopCensusResult::KnownZero(_)) =>
            {
                return KernelIdleLeaseCensus::NormalAdmissionLeased;
            }
            _ if matches!(&census, eliot_ors::StoreStopCensusResult::KnownOutstanding(_))
                || matches!(&census, eliot_ors::StoreStopCensusResult::Unavailable { .. }) =>
            {
                // Preserve the owner's known busy or unavailable result even
                // when another frontier field moved during the read.
                return KernelIdleLeaseCensus::StoreCensus(census);
            }
            _ => {
                return KernelIdleLeaseCensus::Unavailable(
                    CensusUnavailability::RuntimeCensusUnreadable,
                );
            }
        }
        KernelIdleLeaseCensus::StoreCensus(census)
    }

    /// The Kernel has no ORS Store-stop owner surface on non-Windows targets
    /// (I1.7), so the typed result remains unavailable and drain stays closed.
    #[cfg(not(windows))]
    fn runtime_lease_leg(&self) -> KernelIdleLeaseCensus {
        KernelIdleLeaseCensus::Unavailable(CensusUnavailability::RuntimeCensusUnreadable)
    }

    /// Serves one owner-issued Store-stop census to an authenticated Host query.
    /// A well-formed `Unavailable` result crosses the wire as such; only an
    /// invalid request or invalid encoded result fences the transport.
    #[cfg(windows)]
    pub(crate) fn read_runtime_lease_census(
        &self,
        query: &eliot_kernel_service::RuntimeLeaseCensusQuery,
        admission_revision: &str,
    ) -> Result<eliot_kernel_service::RuntimeLeaseCensus, eliot_ipc::TransportError> {
        let request = eliot_ors::StoreStopCensusRequest {
            state_fence: query.state_fence.clone(),
            supervision_lease_id: Some(query.supervision_lease_id.clone()),
            expected_installation_id: Some(query.installation_id.clone()),
            expected_activation_id: Some(query.activation_id.clone()),
            expected_activation_generation: Some(query.activation_generation),
            admission_revision: admission_revision.to_owned(),
        };
        let census = self.generation_gateway.ors.load_store_stop_census(&request);
        census
            .validate()
            .map_err(|_| eliot_ipc::TransportError::SessionFenced)?;
        let revalidated_admission = self
            .store_stop_admission_revision(&query.state_fence, true)
            .map_err(|_| eliot_ipc::TransportError::SessionFenced)?;
        if revalidated_admission != admission_revision {
            return Err(eliot_ipc::TransportError::SessionFenced);
        }
        if census
            .proof()
            .is_some_and(|proof| !self.generation_gateway.ors.revalidate_store_stop_census(proof))
        {
            return Err(eliot_ipc::TransportError::SessionFenced);
        }
        Ok(census)
    }

    /// The authenticated Host census wire is unavailable outside the Windows
    /// Kernel/ORS composition boundary.
    #[cfg(not(windows))]
    pub(crate) fn read_runtime_lease_census(
        &self,
        _query: &eliot_kernel_service::RuntimeLeaseCensusQuery,
        _admission_revision: &str,
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
