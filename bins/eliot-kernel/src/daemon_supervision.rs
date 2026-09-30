//! Daemon supervision ordinary module extracted from the Kernel composition root.
//!
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04
//! Implementation: I1.4, I1.5, I2.23, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15
//! Forbidden authority: no semantic oracle, alternate lease authority, unbounded restart, or daemon-owned canonical transition.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_kernel_service::{KernelActivationReceipt, KernelServiceError};
use eliot_ors::{SupervisionLeaseOperation, SupervisionLeaseSnapshot};
use eliot_process::{EliotdLiveReadyEvidence, EliotdLiveReceipt, ProcessStartReceipt};
#[cfg(windows)]
use eliot_runtime_contracts::{
    DaemonChannelCursor, DaemonProgressObservation, DaemonSupervisionRenewalPolicy,
};
use eliot_runtime_contracts::{
    LeaseState, SupervisionGenerationBinding, SupervisionLeaseIncarnationBinding,
    SupervisionLeasePredecessorIdentity,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DaemonRuntimeStatus {
    NotLaunched,
    Launching,
    Running,
    Ready,
    Degraded(String),
    Failed(String),
}

/// F-LOG-KERNEL-3 (#901): supervision boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.supervision.*` event
/// names plus a bounded stable outcome. Subordinate infos only; the single
/// terminal for a failed supervision operation stays with the owning
/// publication/renewal boundary. Never carries lease material, cursors,
/// digests, evidence, or owner error strings (I15.4, I07.20).
fn observe_supervision(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "daemon supervision observation"
    );
}

pub(crate) const fn daemon_status_proves_ready(status: &DaemonRuntimeStatus) -> bool {
    matches!(status, DaemonRuntimeStatus::Ready)
}

pub(crate) struct DaemonRuntimeState {
    pub(crate) status: DaemonRuntimeStatus,
    pub(crate) receipt: Option<ProcessStartReceipt>,
    pub(crate) recovery_fenced: bool,
    #[cfg(windows)]
    pub(crate) supervision: Option<DaemonSupervisionContour>,
    #[cfg(windows)]
    pub(crate) live_ready: Option<EliotdLiveReadyEvidence>,
    /// Kernel-owned progress continuity for the active lease (issue #88,
    /// wave 3). Reset whenever supervision binds from unset so a restarted or
    /// replaced daemon generation can never continue the old monotonic
    /// series or cite the old predecessor.
    #[cfg(windows)]
    pub(crate) supervision_progress: DaemonSupervisionProgressState,
    /// Latest daemon-submitted observation retained for the `ProbeReady`
    /// progress route. Evidence only; every renewal re-decides against the
    /// exact durable head.
    #[cfg(windows)]
    pub(crate) last_progress_observation: Option<DaemonProgressObservation>,
    /// Set when the progress route reports terminal lease expiry. The expired
    /// supervision claim stays degraded and visible until a new admitted
    /// generation rebinds; it never auto-revives and never asserts process
    /// death by itself.
    #[cfg(windows)]
    pub(crate) supervision_expired: bool,
}

#[cfg(windows)]
impl DaemonRuntimeState {
    pub(crate) fn bind_live_receipt_publication_operation(
        &mut self,
        ready: &EliotdLiveReadyEvidence,
    ) -> Result<(), KernelServiceError> {
        if !matches!(
            self.status,
            DaemonRuntimeStatus::Running | DaemonRuntimeStatus::Ready
        ) || self.receipt.is_none()
            || self.live_ready.as_ref().is_some_and(|bound| bound != ready)
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        self.live_ready = Some(ready.clone());
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonSupervisionContour {
    pub(crate) candidate_digest: String,
    pub(crate) incarnation: SupervisionLeaseIncarnationBinding,
    pub(crate) activation: KernelActivationReceipt,
    pub(crate) generation_binding: SupervisionGenerationBinding,
    pub(crate) state_fence: StateFence,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EliotdSupervisionSuccessorEvidence {
    pub(crate) operation: SupervisionLeaseOperation,
    pub(crate) state: LeaseState,
    pub(crate) lease_id: String,
    pub(crate) revision: u64,
    pub(crate) receipt_sha256: String,
    pub(crate) previous_receipt_sha256: Option<String>,
}

#[cfg(windows)]
impl From<&SupervisionLeaseSnapshot> for EliotdSupervisionSuccessorEvidence {
    fn from(snapshot: &SupervisionLeaseSnapshot) -> Self {
        Self {
            operation: snapshot.record.operation,
            state: snapshot.record.state,
            lease_id: snapshot.record.lease_id.as_str().to_owned(),
            revision: snapshot.record.revision,
            receipt_sha256: snapshot.receipt.receipt_sha256.clone(),
            previous_receipt_sha256: snapshot.record.previous_receipt_sha256.clone(),
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EliotdLiveReceiptDisposition {
    ExactReplay,
    ReplaceActivationPredecessor,
    ReplaceRenewalPredecessor,
}

#[cfg(windows)]
pub(crate) fn classify_eliotd_live_receipt_transition(
    old: &EliotdLiveReceipt,
    expected: &EliotdLiveReceipt,
    status_is_ready: bool,
    activation_predecessor: Option<&SupervisionLeasePredecessorIdentity>,
    supervision_successor: Option<&EliotdSupervisionSuccessorEvidence>,
) -> Result<EliotdLiveReceiptDisposition, KernelServiceError> {
    if old == expected {
        // F-LOG-KERNEL-3 (#901): exact replay is an observation of the
        // existing receipt, not another publication.
        observe_supervision("kernel.supervision.receipt_replayed", "success");
        return Ok(EliotdLiveReceiptDisposition::ExactReplay);
    }
    let exact_activation_predecessor = activation_predecessor.is_some_and(|predecessor| {
        predecessor.supervision_lease_id == old.supervision.lease_id
            && predecessor.ors_receipt_sha256 == old.supervision.receipt_sha256
            && old.installation_id == expected.installation_id
            && old.runtime_state_roots_digest == expected.runtime_state_roots_digest
            && old.supervision.public_key_fingerprint == expected.supervision.public_key_fingerprint
    });
    if !status_is_ready && exact_activation_predecessor {
        observe_supervision(
            "kernel.supervision.receipt_replaced",
            "activation_predecessor",
        );
        return Ok(EliotdLiveReceiptDisposition::ReplaceActivationPredecessor);
    }
    let exact_renewal_predecessor = supervision_successor.is_some_and(|successor| {
        successor.operation == SupervisionLeaseOperation::Renew
            && successor.state == LeaseState::Active
            && successor.lease_id == expected.supervision.lease_id
            && successor.revision == expected.supervision.revision
            && successor.receipt_sha256 == expected.supervision.receipt_sha256
            && successor.previous_receipt_sha256.as_deref()
                == Some(old.supervision.receipt_sha256.as_str())
            && old.supervision.revision.checked_add(1) == Some(expected.supervision.revision)
            && old.process == expected.process
            && old.ready == expected.ready
            && old.receipt_root_identity_sha256 == expected.receipt_root_identity_sha256
            && old.runtime_state_roots_digest == expected.runtime_state_roots_digest
            && old.installation_id == expected.installation_id
            && old.approved_generation == expected.approved_generation
            && old.generation == expected.generation
            && old.authority_epoch == expected.authority_epoch
            && old.config_descriptor_sha256 == expected.config_descriptor_sha256
            && old.descriptor_sha256 == expected.descriptor_sha256
            && old.kernel_artifact_sha256 == expected.kernel_artifact_sha256
            && old.supervision.lease_id == expected.supervision.lease_id
            && old.supervision.public_key_fingerprint == expected.supervision.public_key_fingerprint
    });
    if status_is_ready && exact_renewal_predecessor {
        observe_supervision("kernel.supervision.receipt_replaced", "renewal_predecessor");
        return Ok(EliotdLiveReceiptDisposition::ReplaceRenewalPredecessor);
    }
    // Subordinate observation only; the owning publication boundary emits the
    // single terminal for the rejected transition.
    observe_supervision("kernel.supervision.receipt_rejected", "fenced");
    Err(KernelServiceError::ReadinessNotProven)
}

// ============================================================================
// Kernel-owned daemon progress continuity (issue #88, wave 2).
//
// The Kernel retains per-channel accepted cursors, the last accepted monotonic
// evidence, the last recorded renewal identity, a consecutive-miss counter,
// and the reconciliation flag. The daemon (wave 3, `eliotd` per-tick
// observation) submits candidate observations; it never writes this state.
// `StoreHealth` carries no cursor and therefore can never advance it.
//
// Owner defaults enforced with this state (see
// `SUPERVISION_LEASE_RENEWAL_POLICY` for the timing owner):
// - stale-cursor horizon: three missed renewal intervals
//   (`3 * renew_after_ms`) with no eligible observation, or three consecutive
//   blocked renewals, expires the lease (`SupervisionLeaseExpired`). An
//   expired lease requires a new admission; it never auto-revives.
// - a `Failed` health dimension on a degraded observation blocks renewal
//   fail-closed (`DegradedNoRenewal`, reported, no successor, never skipped).
// - `NoProgress` / `ObservationGap` / rollback / skew / stale
//   generation-session-epoch-fence-boot / predecessor mismatch all fail
//   closed through the contract join; exact replay stays idempotent and a
//   mutated retry reports `IDENTITY_CONFLICT`.
//
// Wave-3 handoff (MGR02): the `eliotd` per-tick observation producer binds
// this tracker to the live runtime (retention + first-use boot/session
// pinning below stays valid); this file owns the shape, not the producer.

/// Consecutive blocked renewals (or equivalent silence) that stale-expire a
/// supervision lease. The time horizon is the same count of renewal
/// intervals: `3 * renew_after_ms`.
#[cfg(windows)]
pub(crate) const SUPERVISION_PROGRESS_STALE_MISSED_INTERVALS: u64 = 3;

/// Kernel-owned progress continuity for one supervised daemon generation.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonSupervisionProgressState {
    /// Last cursor accepted by the Kernel per progress channel.
    pub(crate) accepted_cursors: Vec<DaemonChannelCursor>,
    /// Currently admitted idle contract, when one is admitted.
    pub(crate) admitted_idle_contract: Option<String>,
    /// Boot identity pinned on first use; later mismatch fails closed.
    pub(crate) boot_id: Option<String>,
    /// Transport-session binding pinned on first use; reconnects need an
    /// explicit rebinding path (mismatch fails closed until then).
    pub(crate) transport_session_evidence: Option<String>,
    /// Last accepted monotonic evidence in milliseconds (never regresses).
    pub(crate) last_monotonic_ms: u64,
    /// Request identity of the last recorded renewal, if any.
    pub(crate) last_request_id: Option<String>,
    /// Canonical digest of the last recorded observation, if any.
    pub(crate) last_observation_sha256: Option<String>,
    /// Successor revision created by the last recorded renewal, if any.
    pub(crate) last_successor_revision: Option<u64>,
    /// Consecutive blocked renewals with no eligible observation.
    pub(crate) missed_renewals: u64,
    /// Decision time of the last eligible observation that renewed, if any.
    pub(crate) last_eligible_observation_ms: Option<u64>,
    /// True while an unknown ORS/live-receipt publication outcome is still
    /// unreconciled; blocks every new successor until exact reconciliation.
    pub(crate) reconciliation_pending: bool,
}

#[cfg(windows)]
impl DaemonSupervisionProgressState {
    /// Returns the unbound continuity for a freshly bound supervision: no
    /// accepted cursors, no admitted idle contract, no boot/session pinning,
    /// no monotonic evidence, no recorded renewal, no misses, and no pending
    /// reconciliation. The first shape-valid observation pins boot, session,
    /// and monotonic evidence anew.
    pub(crate) fn unbound() -> Self {
        Self {
            accepted_cursors: Vec::new(),
            admitted_idle_contract: None,
            boot_id: None,
            transport_session_evidence: None,
            last_monotonic_ms: 0,
            last_request_id: None,
            last_observation_sha256: None,
            last_successor_revision: None,
            missed_renewals: 0,
            last_eligible_observation_ms: None,
            reconciliation_pending: false,
        }
    }

    /// Returns the stale-expiry horizon in milliseconds for a policy.
    pub(crate) fn stale_horizon_ms(policy: &DaemonSupervisionRenewalPolicy) -> u64 {
        policy
            .renew_after_ms
            .saturating_mul(SUPERVISION_PROGRESS_STALE_MISSED_INTERVALS)
    }

    /// Returns true once the lease must expire instead of retrying: three
    /// consecutive blocked renewals, or silence past the stale horizon with
    /// no eligible observation. A lease with no recorded eligibility yet
    /// (first renewal) is never stale on time alone.
    pub(crate) fn stale_renewal_expired(
        &self,
        policy: &DaemonSupervisionRenewalPolicy,
        now_ms: u64,
    ) -> bool {
        if self.missed_renewals >= SUPERVISION_PROGRESS_STALE_MISSED_INTERVALS {
            return true;
        }
        self.last_eligible_observation_ms.is_some_and(|eligible| {
            now_ms.saturating_sub(eligible) >= Self::stale_horizon_ms(policy)
        })
    }

    /// Pins the Kernel-owned boot/session continuity from the first
    /// shape-valid observation. Later observations must match exactly; a
    /// changed boot or session fails closed in the renewal join.
    pub(crate) fn admit_boot_session_binding(&mut self, observation: &DaemonProgressObservation) {
        if self.boot_id.is_none() {
            self.boot_id = Some(observation.boot_id.clone());
        }
        if self.transport_session_evidence.is_none() {
            self.transport_session_evidence = Some(observation.transport_session_evidence.clone());
        }
    }

    /// Advances the last accepted monotonic evidence; it never regresses, so
    /// rolled-back observations stay detectable after refusals.
    pub(crate) fn advance_monotonic_ms(&mut self, observed_monotonic_ms: u64) {
        self.last_monotonic_ms = self.last_monotonic_ms.max(observed_monotonic_ms);
    }

    /// Records one blocked (non-renewing) evaluation. The request identity is
    /// deliberately not recorded: refusals re-evaluate deterministically, and
    /// only recorded renewals participate in replay/identity-conflict.
    pub(crate) fn note_missed_renewal(&mut self) {
        // F-LOG-KERNEL-3 (#901): blocked-renewal observation; the stale-expiry
        // decision stays with the renewal join.
        observe_supervision("kernel.supervision.renewal_missed", "deferred");
        self.missed_renewals = self.missed_renewals.saturating_add(1);
    }

    /// Records a verified renewal: advances the channel cursor, the
    /// monotonic evidence, and the idempotency triple, resets the miss
    /// counter, stamps eligibility, and clears reconciliation. Call only
    /// after the ORS commit and post-verify both succeed.
    pub(crate) fn record_renewed(
        &mut self,
        observation: &DaemonProgressObservation,
        observation_sha256: String,
        successor_revision: u64,
        now_ms: u64,
    ) {
        if let Some(entry) = self
            .accepted_cursors
            .iter_mut()
            .find(|entry| entry.channel == observation.progress_channel)
        {
            entry.cursor = observation.progress_cursor;
        } else {
            self.accepted_cursors.push(DaemonChannelCursor {
                channel: observation.progress_channel,
                cursor: observation.progress_cursor,
            });
        }
        self.advance_monotonic_ms(observation.observed_monotonic_ms);
        self.last_request_id = Some(observation.observation_id.clone());
        self.last_observation_sha256 = Some(observation_sha256);
        self.last_successor_revision = Some(successor_revision);
        self.missed_renewals = 0;
        self.last_eligible_observation_ms = Some(now_ms);
        self.reconciliation_pending = false;
        // F-LOG-KERNEL-3 (#901): verified-renewal observation. Only the
        // outcome is logged; cursors, digests, and revision identities stay
        // with the owner.
        observe_supervision("kernel.supervision.renewal_recorded", "success");
    }

    /// Marks the durable outcome unknown after a failed renew commit. The
    /// renewal join then reports `ReconciliationRequired` instead of minting
    /// a successor until exact reconciliation.
    pub(crate) fn note_reconciliation_pending(&mut self) {
        // F-LOG-KERNEL-3 (#901): unknown-outcome observation; the outcome
        // stays unknown until the owner reconciles it exactly.
        observe_supervision("kernel.supervision.reconciliation_required", "unknown");
        self.reconciliation_pending = true;
    }
}

// ============================================================================
// Replacement startup + protected routing for retained maintenance trigger
// claims (issue #1694, step 6 / W6).
//
// Loss moment: outstanding trigger claims issued to the lost daemon consumer
// are retained, never dropped; the old consumer's authority is revoked
// through the existing Kernel owner (`revoke_daemon_agent_bridge_profile`
// and `revoke_supervision_evidence` — this seam revokes nothing itself, it
// binds the exact lost-consumer identity the owner must revoke).
//
// Startup moment: after replacement authentication and the required ORS
// mirror recovery, the bounded pending set is surfaced before the startup
// path may claim maintenance reconciliation complete.
//
// Conformance: I1.8 (Kernel checks identity/authority/fence/idempotency/
// ordering/generation only — it never invents trigger semantics, policy, or
// classification); I14.22 lineage (unavailable evaluator, durable triggers,
// single decision owner — classification arrives owner-issued with the claim);
// I14.24 lineage (daemon/ORS failure containment — old authority fenced,
// pending work retained as an explicit bounded set with visible gaps);
// I5.2 lineage (opaque ORS payload — the Kernel indexes only operational
// delivery metadata below); A13.3 (replacement fences the old epoch);
// A13.6 (ORS carries identity/envelope/reconciliation state, grants no
// authority); A13.11 (evaluator down degrades promises — protected routes
// stay visible, ordinary debt never gates runtime liveness).
//
// Narrowness: two pure functions over caller-supplied pages. No new daemon
// supervisor, database, or evaluator; no unbounded spill (one
// `MAX_RECOVERY_PAGE` page per call, the existing recovery paging
// denominator); no polling — the loss caller invokes the classifier once per
// page, the startup path invokes the gate once its preconditions hold.

/// Registered protected route on which an owner-classified safety/recovery
/// trigger stays visible while the Governor evaluator is down (#1694 W6).
///
/// The route arrives with the claim from its owner; the Kernel never invents
/// it. Ordinary maintenance claims carry no route and are visible only to
/// the authenticated replacement generation, never on a protected route, so
/// ordinary debt is never promoted to protected authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TriggerProtectedRoute {
    Host,
    Kernel,
    Watchdog,
    Doctor,
}

/// One outstanding maintenance trigger claim, as enumerated from the durable
/// ORS page at daemon-loss time (#1694 W6).
///
/// Operational delivery metadata only: stable source event/trigger identity,
/// delivery/claim identity, the consumer generation it was issued to, and
/// the owner-issued protected-routing classification. The semantic payload
/// stays opaque; the Kernel never queries the trigger as semantic memory nor
/// evaluates its policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingTriggerClaimView {
    /// Stable source event/trigger identity (exact replay key).
    pub(crate) trigger_identity: String,
    /// Delivery/claim identity bound to the consumer generation. Redelivery
    /// reuses this identity, so duplicated delivery cannot authorize
    /// duplicated containment; a claim timeout never mints a new trigger ID.
    pub(crate) delivery_identity: String,
    /// Consumer generation the claim was issued to.
    pub(crate) issued_to_consumer: SupervisionGenerationBinding,
    /// Owner-issued protected-routing classification. `None` marks ordinary
    /// maintenance debt.
    pub(crate) owner_issued_protected_route: Option<TriggerProtectedRoute>,
}

/// One claim retained across daemon loss, stripped to its replay keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedTriggerClaim {
    pub(crate) trigger_identity: String,
    pub(crate) delivery_identity: String,
    pub(crate) owner_issued_protected_route: Option<TriggerProtectedRoute>,
}

/// Settlement of one bounded outstanding-claim page at daemon-loss time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonLossClaimSettlement {
    /// Lost consumer whose authority the existing Kernel owner must revoke.
    /// Echoed so the revocation binds the exact fenced generation.
    pub(crate) lost_consumer: SupervisionGenerationBinding,
    /// Retained pending claims, bounded to one `MAX_RECOVERY_PAGE` page.
    pub(crate) retained_pending: Vec<RetainedTriggerClaim>,
    /// The page input claimed further pages. The startup path must surface
    /// every page before claiming maintenance reconciliation complete; a
    /// reconnect never resets progress to a guessed complete-empty set.
    pub(crate) more_pages_pending: bool,
    /// Matching claims dropped by the page cap. Explicit gap, never silent.
    pub(crate) over_page_cap: u64,
    /// Claims issued to another consumer. Left untouched, counted visibly.
    pub(crate) foreign_consumer_skipped: u64,
    /// Claims with an empty replay identity. Fail-closed, counted visibly.
    pub(crate) malformed_identity_skipped: u64,
}

impl DaemonLossClaimSettlement {
    /// Safety/recovery subset that stays visible on its registered
    /// Host/Kernel/Watchdog/Doctor route while the evaluator is down.
    /// Projection only; `retained_pending` stays the single store.
    pub(crate) fn protected_visible(&self) -> Vec<(&str, TriggerProtectedRoute)> {
        self.retained_pending
            .iter()
            .filter_map(|claim| {
                claim
                    .owner_issued_protected_route
                    .map(|route| (claim.delivery_identity.as_str(), route))
            })
            .collect()
    }
}

/// Caller-attested replacement startup preconditions for surfacing retained
/// claims. Both facts are established by their existing owners (replacement
/// authentication by the supervision/front-door path, mirror recovery by ORS
/// mirror reconciliation); this gate only orders surfacing after them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplacementStartupEvidence {
    pub(crate) replacement_authenticated: bool,
    pub(crate) mirror_recovered: bool,
}

/// Bounded pending set surfaced to the replacement, with its completeness.
///
/// This gate binds only the maintenance-reconciliation claim. Ordinary
/// pending debt surfaced here never keeps the runtime alive and never blocks
/// unrelated safe work; unrelated admission stays with its own owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonLossPendingSurface {
    /// Claims to surface now. Empty while the gate is closed; the withheld
    /// count below keeps that visible instead of silent.
    pub(crate) surfaced: Vec<RetainedTriggerClaim>,
    /// Retained claims withheld because the gate is closed.
    pub(crate) withheld: u64,
    /// True only once the gate is open and no further pages remain. Only
    /// then may the startup path claim maintenance reconciliation complete.
    pub(crate) reconciliation_complete: bool,
}

/// Classifies one bounded page of outstanding trigger claims at daemon-loss
/// time: retain the lost consumer's pending claims, leave foreign-consumer
/// claims untouched, and count every gap explicitly.
///
/// The caller (STITCH: `record_daemon_failed` in `daemon_runtime.rs`, next
/// to the existing `revoke_daemon_agent_bridge_profile` call) supplies the
/// lost consumer binding and the ORS-enumerated page, retains the returned
/// settlement in Kernel-owned state, and revokes the old consumer authority
/// through the existing Kernel owner. Pure: no I/O, no polling, no logging —
/// the owning boundary observes the outcome.
pub(crate) fn classify_daemon_loss_trigger_claims(
    lost_consumer: &SupervisionGenerationBinding,
    claims_page: &[PendingTriggerClaimView],
    more_pages_pending: bool,
) -> DaemonLossClaimSettlement {
    let cap = usize::from(eliot_ors::MAX_RECOVERY_PAGE);
    let mut retained_pending = Vec::new();
    let mut over_page_cap = 0u64;
    let mut foreign_consumer_skipped = 0u64;
    let mut malformed_identity_skipped = 0u64;
    for claim in claims_page {
        if claim.trigger_identity.is_empty() || claim.delivery_identity.is_empty() {
            malformed_identity_skipped = malformed_identity_skipped.saturating_add(1);
            continue;
        }
        if claim.issued_to_consumer != *lost_consumer {
            foreign_consumer_skipped = foreign_consumer_skipped.saturating_add(1);
            continue;
        }
        if retained_pending.len() >= cap {
            over_page_cap = over_page_cap.saturating_add(1);
            continue;
        }
        retained_pending.push(RetainedTriggerClaim {
            trigger_identity: claim.trigger_identity.clone(),
            delivery_identity: claim.delivery_identity.clone(),
            owner_issued_protected_route: claim.owner_issued_protected_route,
        });
    }
    DaemonLossClaimSettlement {
        lost_consumer: lost_consumer.clone(),
        retained_pending,
        more_pages_pending,
        over_page_cap,
        foreign_consumer_skipped,
        malformed_identity_skipped,
    }
}

/// Surfaces the retained pending set to the replacement once it is
/// authenticated and mirror recovery is done. While either precondition is
/// missing the claims stay retained-but-withheld (counted, never silent) and
/// reconciliation stays incomplete.
///
/// The caller (STITCH: replacement startup path after
/// `establish_daemon_supervision` in `lib.rs` plus ORS mirror
/// reconciliation) attests the preconditions from their existing owners.
/// Pure: no I/O, no polling.
pub(crate) fn gate_daemon_loss_pending_surface(
    settlement: &DaemonLossClaimSettlement,
    startup: &ReplacementStartupEvidence,
) -> DaemonLossPendingSurface {
    let open = startup.replacement_authenticated && startup.mirror_recovered;
    if open {
        DaemonLossPendingSurface {
            surfaced: settlement.retained_pending.clone(),
            withheld: 0,
            reconciliation_complete: !settlement.more_pages_pending,
        }
    } else {
        DaemonLossPendingSurface {
            surfaced: Vec::new(),
            withheld: u64::try_from(settlement.retained_pending.len()).unwrap_or(u64::MAX),
            reconciliation_complete: false,
        }
    }
}

#[cfg(all(test, windows))]
mod daemon_supervision_diagnostics_tests {
    //! F-LOG-KERNEL-3 (#901) focused diagnostics proof: readiness versus
    //! liveness, blocked-renewal stale expiry, unknown-outcome blocking, and
    //! secret-free capture for the supervision observations added above.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    fn test_progress() -> DaemonSupervisionProgressState {
        DaemonSupervisionProgressState {
            accepted_cursors: Vec::new(),
            admitted_idle_contract: None,
            boot_id: None,
            transport_session_evidence: None,
            last_monotonic_ms: 0,
            last_request_id: None,
            last_observation_sha256: None,
            last_successor_revision: None,
            missed_renewals: 0,
            last_eligible_observation_ms: None,
            reconciliation_pending: false,
        }
    }

    fn test_policy() -> DaemonSupervisionRenewalPolicy {
        DaemonSupervisionRenewalPolicy {
            validity_ms: 60_000,
            renew_after_ms: 30_000,
            max_observation_age_ms: 10_000,
            max_wall_skew_ms: 5_000,
            require_watchdog_coverage: false,
        }
    }

    #[test]
    fn supervision_diagnostics_readiness_and_renewal_boundaries() {
        // Liveness is not readiness: only `Ready` proves ready. Status
        // payloads stay with the owner; observations below carry fixed names.
        assert!(!daemon_status_proves_ready(
            &DaemonRuntimeStatus::NotLaunched
        ));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Launching));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Running));
        assert!(daemon_status_proves_ready(&DaemonRuntimeStatus::Ready));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Degraded(
            "degraded-canary".to_owned()
        )));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Failed(
            "failed-canary".to_owned()
        )));

        // Three consecutive blocked renewals stale-expire the lease; fewer do
        // not. The counting behavior is unchanged, only observed.
        let policy = test_policy();
        let mut progress = test_progress();
        assert!(!progress.stale_renewal_expired(&policy, 1_000_000));
        progress.note_missed_renewal();
        progress.note_missed_renewal();
        assert!(!progress.stale_renewal_expired(&policy, 1_000_000));
        assert_eq!(progress.missed_renewals, 2);
        progress.note_missed_renewal();
        assert!(progress.stale_renewal_expired(&policy, 1_000_000));

        // An unknown outcome blocks successors until exact reconciliation.
        assert!(!progress.reconciliation_pending);
        progress.note_reconciliation_pending();
        assert!(progress.reconciliation_pending);

        // Monotonic evidence never regresses, so rolled-back observations
        // stay detectable after refusals.
        progress.advance_monotonic_ms(500);
        progress.advance_monotonic_ms(100);
        assert_eq!(progress.last_monotonic_ms, 500);

        // Captured diagnostics carry fixed events only; owner payloads never
        // reach the sink (helpers accept `&'static str`, so no `String`
        // payload can be passed at all).
        let text = capture(|| {
            observe_supervision("kernel.supervision.renewal_missed", "deferred");
            observe_supervision("kernel.supervision.reconciliation_required", "unknown");
            observe_supervision("kernel.supervision.renewal_recorded", "success");
            observe_supervision("kernel.supervision.receipt_replayed", "success");
        });
        for marker in [
            "kernel.supervision.renewal_missed",
            "kernel.supervision.reconciliation_required",
            "kernel.supervision.renewal_recorded",
            "kernel.supervision.receipt_replayed",
        ] {
            assert!(text.contains(marker), "missing diagnostics marker {marker}");
        }
        for canary in ["degraded-canary", "failed-canary"] {
            assert!(!text.contains(canary), "owner payload leaked: {canary}");
        }
    }
}
