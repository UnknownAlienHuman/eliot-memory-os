#[cfg(windows)]
mod contract;
#[cfg(windows)]
#[allow(
    unused_imports,
    reason = "the readiness cadence constant is a crate facade contract used by Windows tests"
)]
pub(super) use contract::{
    DEFAULT_READINESS_CADENCE, ReadinessCadence, ReadinessContourIdentity, ReadinessFailureKind,
    ReadinessGateAction, readiness_failure_kind,
};

use super::{HostBranchDisposition, HostError};

// F-LOG-HOST-6 (#981) readiness-gate observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner, on the branch that already existed. The frozen boundary
// label stays a static literal first; the identity slots that follow are the
// exact nonsecret handles this gate already holds (see
// [`ReadinessGateObservation`]) — the presented contour generation, the
// retained lease generation, the observed store proof fence, the supervision
// lease identity and the closed disposition/failure labels — never a nonce,
// capability, MAC/digest over secret bytes, record byte, raw path, argv,
// environment value, credential, key material, payload, connection value or
// arbitrary `Debug`/serde error text, so bounding limits size, not sensitivity
// (I15.4).
//
// These primitives own no terminal: a single terminal per failed supervision
// operation is enforced by the outermost owner boundary, while these phases
// carry the already-owned identity rather than correlating by stage order
// alone. The pure contract helpers in `contract.rs` (`same_probe_input_contour`,
// `readiness_failure_kind`) are explicit non-boundaries and never log. Sink
// outcome never alters gate result/timer/cleanup.
#[cfg(windows)]
fn host_readiness_gate_observe(detail: &str) {
    let _ = crate::windows_event_log::event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

/// Closed disposition of one readiness-gate lease decision (F-LOG-HOST-6,
/// #981 blocking defect 5).
///
/// Every variant is the FIRST condition that actually failed the live-lease
/// conjunction, in the same evaluation order the gate itself uses: presented
/// contour equality, then the four supervision/store proof slots, then the
/// lease deadline. A gate call that preserved health is [`Self::LeaseLive`];
/// the other four are exactly the nonmatching cases one lease decision can
/// reach, and they are distinct facts, not one "retry pending"/"probe due"
/// collapse. The gate's GRANT/REFUSE decision is unchanged by this type: it
/// observes which case occurred, it never decides one.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessLeaseDisposition {
    /// The presented contour IS the retained lease contour, all four
    /// supervision/store proof slots are present, and the lease deadline has
    /// not passed.
    LeaseLive,
    /// The presented contour IS the retained lease contour with a complete
    /// supervision/store proof, but the lease deadline has already passed.
    LeaseExpired,
    /// The presented contour is not the retained lease contour: the presented
    /// generation moved, or the caller presented no contour at all.
    ContourForeign,
    /// The presented contour IS the retained lease contour, but at least one
    /// supervision/store proof slot is absent.
    ProofIncomplete,
    /// The gate holds no lease, so there was nothing that could be preserved.
    NoPriorLease,
}

#[cfg(windows)]
impl ReadinessLeaseDisposition {
    /// 1:1 frozen diagnostic label for this disposition. Never `Debug`, never
    /// the underlying reason text: the record projects owner vocabulary
    /// without formatting type internals.
    fn label(self) -> &'static str {
        match self {
            Self::LeaseLive => "lease-live",
            Self::LeaseExpired => "lease-expired",
            Self::ContourForeign => "contour-foreign",
            Self::ProofIncomplete => "proof-incomplete",
            Self::NoPriorLease => "no-prior-lease",
        }
    }
}

/// 1:1 frozen diagnostic label for the closed [`ReadinessFailureKind`] the
/// owner already classified (F-LOG-HOST-6, #981 blocking defect 5). A typed
/// probe/journal failure stays typed in the record instead of collapsing into
/// an unqualified "degraded".
#[cfg(windows)]
fn readiness_failure_label(failure: &ReadinessFailureKind) -> &'static str {
    match failure {
        ReadinessFailureKind::ContourUnavailable => "contour-unavailable",
        ReadinessFailureKind::ProbeRejected => "probe-rejected",
        ReadinessFailureKind::DeliveryUnknown => "delivery-unknown",
        ReadinessFailureKind::JournalRejected => "journal-rejected",
        ReadinessFailureKind::JournalOutcomeUnknown => "journal-outcome-unknown",
    }
}

/// Classifies the live-lease decision this gate is about to take, without
/// taking it.
///
/// The returned [`ReadinessLeaseDisposition`] is a pure function of the state
/// already in hand (the retained lease, its deadline, the presented contour
/// and `now`) and follows the gate's own conjunct order exactly, so the
/// `LeaseLive` arm holds precisely when the previous lease-preservation
/// predicate held. Nothing here reads, retries, probes or mutates.
#[cfg(windows)]
fn readiness_lease_disposition(
    lease: Option<&ReadinessLease>,
    contour: Option<&ReadinessContourIdentity>,
    now: std::time::Instant,
) -> ReadinessLeaseDisposition {
    let Some(lease) = lease else {
        return ReadinessLeaseDisposition::NoPriorLease;
    };
    if contour != Some(&lease.contour) {
        return ReadinessLeaseDisposition::ContourForeign;
    }
    if lease.contour.store_proof_fence.is_none()
        || lease.contour.supervision_lease_id.is_none()
        || lease.contour.supervision_ors_receipt_digest.is_none()
        || lease.contour.watchdog_publication_digest.is_none()
    {
        return ReadinessLeaseDisposition::ProofIncomplete;
    }
    if now >= lease.valid_until {
        return ReadinessLeaseDisposition::LeaseExpired;
    }
    ReadinessLeaseDisposition::LeaseLive
}

/// Owner-held identities bound to one readiness-gate record (F-LOG-HOST-6,
/// #981 blocking defect 5).
///
/// Every slot projects a fact this gate already holds on the branch it is
/// observing: the presented contour generation, the generation of the lease
/// the gate actually retained, the observed Store proof fence, the
/// supervision lease identity, the bounded remaining lease window, and the two
/// closed labels (lease disposition, typed failure kind). A slot the gate does
/// not hold at this point renders the explicit `k=k_missing` disposition the
/// sibling #981 identity projections use, so an absent identity can never be
/// read as a value this gate did not hold or inferred from a neighbouring
/// record.
///
/// The lease deadline is a monotonic `Instant`, not an owner-issued identity,
/// so only its bounded remaining window in whole milliseconds is rendered:
/// there is no invented identifier standing in for it.
struct ReadinessGateObservation<'a> {
    label: &'static str,
    disposition: Option<&'static str>,
    failure: Option<&'static str>,
    generation: Option<&'a str>,
    retained_generation: Option<&'a str>,
    fence: Option<&'a str>,
    lease_id: Option<&'a str>,
    window_ms: Option<u64>,
}

impl<'a> ReadinessGateObservation<'a> {
    /// Binds one `action` branch: the closed lease disposition that branch
    /// actually produced, the presented contour, the lease the gate retained
    /// (before it is cleared or preserved), and the typed failure kind when
    /// this branch carries one.
    fn for_action(
        label: &'static str,
        disposition: ReadinessLeaseDisposition,
        contour: Option<&'a ReadinessContourIdentity>,
        lease: Option<&'a ReadinessLease>,
        now: std::time::Instant,
        failure: Option<ReadinessFailureKind>,
    ) -> Self {
        Self {
            label,
            disposition: Some(disposition.label()),
            failure: failure.map(|failure| readiness_failure_label(&failure)),
            generation: contour.map(|contour| contour.approved_generation.as_str()),
            retained_generation: lease.map(|lease| lease.contour.approved_generation.as_str()),
            fence: contour
                .and_then(|contour| contour.store_proof_fence.as_ref())
                .map(|handle| handle.as_str()),
            lease_id: contour
                .and_then(|contour| contour.supervision_lease_id.as_ref())
                .map(|handle| handle.as_str()),
            window_ms: lease.map(|lease| readiness_lease_window_ms(lease.valid_until, now)),
        }
    }

    /// Binds one `grant` branch: the exact journaled contour the lease is (or
    /// would be) granted for, and the bounded lease window it was granted.
    /// `disposition` is the gate's own refusal condition when `grant` refused:
    /// it rejects exactly when a supervision/store proof slot is absent.
    fn for_grant(
        label: &'static str,
        contour: Option<&'a ReadinessContourIdentity>,
        disposition: Option<ReadinessLeaseDisposition>,
        valid_until: Option<std::time::Instant>,
        now: std::time::Instant,
    ) -> Self {
        Self {
            label,
            disposition: disposition.map(ReadinessLeaseDisposition::label),
            failure: None,
            generation: contour.map(|contour| contour.approved_generation.as_str()),
            retained_generation: None,
            fence: contour
                .and_then(|contour| contour.store_proof_fence.as_ref())
                .map(|handle| handle.as_str()),
            lease_id: contour
                .and_then(|contour| contour.supervision_lease_id.as_ref())
                .map(|handle| handle.as_str()),
            window_ms: valid_until.map(|valid_until| readiness_lease_window_ms(valid_until, now)),
        }
    }

    /// Binds one typed-failure branch: the closed failure kind the owner
    /// classified and the contour it failed against, if the caller presented
    /// one. The gate holds no lease on these branches, so no lease window is
    /// claimed.
    fn for_failure(
        label: &'static str,
        contour: Option<&'a ReadinessContourIdentity>,
        failure: ReadinessFailureKind,
    ) -> Self {
        Self {
            label,
            disposition: None,
            failure: Some(readiness_failure_label(&failure)),
            generation: contour.map(|contour| contour.approved_generation.as_str()),
            retained_generation: None,
            fence: contour
                .and_then(|contour| contour.store_proof_fence.as_ref())
                .map(|handle| handle.as_str()),
            lease_id: contour
                .and_then(|contour| contour.supervision_lease_id.as_ref())
                .map(|handle| handle.as_str()),
            window_ms: None,
        }
    }
}

/// The remaining lease window in whole milliseconds, saturating. Pure: the
/// cadence bounds it well under one minute, so this never grows a record.
#[cfg(windows)]
fn readiness_lease_window_ms(valid_until: std::time::Instant, now: std::time::Instant) -> u64 {
    u64::try_from(valid_until.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
}

/// Appends one `key=value` pair, or the explicit `key=key_missing` disposition
/// when the gate holds no value for that slot. A present value goes through
/// the facade's own bounding helper, so a longer handle is cut with the
/// facade's truncation honesty rather than emitted whole.
#[cfg(windows)]
fn push_readiness_field(detail: &mut String, key: &str, value: Option<&str>) {
    let text = value.map_or_else(
        || {
            let mut missing = String::from(key);
            missing.push_str("_missing");
            missing
        },
        |text| crate::host_diagnostics::bound_field(text).text().to_owned(),
    );
    detail.push(' ');
    detail.push_str(key);
    detail.push('=');
    detail.push_str(&text);
}

/// The counting sibling of [`push_readiness_field`]: an owner-produced count
/// renders as its decimal text through the same bounding helper, or as the
/// explicit `key_missing` disposition when the gate holds none.
#[cfg(windows)]
fn push_readiness_count(detail: &mut String, key: &str, value: Option<u64>) {
    let text = value.map(|count| count.to_string());
    push_readiness_field(detail, key, text.as_deref());
}

/// Emits one identity-bound readiness-gate observation through the #889
/// facade.
///
/// The frozen boundary label stays first so label-prefix consumers keep
/// matching, then the closed disposition and typed failure labels, then the
/// owner-held nonsecret handles as `k=v` pairs. The composed detail stays under
/// the facade's detail bound for the pinned handle shapes used here, and any
/// longer input is cut by that bound with its truncation honesty record.
#[cfg(windows)]
fn host_readiness_gate_observe_bound(observation: &ReadinessGateObservation<'_>) {
    let mut detail = String::from(observation.label);
    push_readiness_field(&mut detail, "disposition", observation.disposition);
    push_readiness_field(&mut detail, "failure", observation.failure);
    push_readiness_field(&mut detail, "gen", observation.generation);
    push_readiness_field(&mut detail, "retained", observation.retained_generation);
    push_readiness_field(&mut detail, "fence", observation.fence);
    push_readiness_field(&mut detail, "lease_id", observation.lease_id);
    push_readiness_count(&mut detail, "window_ms", observation.window_ms);
    host_readiness_gate_observe(&detail);
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ReadinessLease {
    contour: ReadinessContourIdentity,
    valid_until: std::time::Instant,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ReadinessRetry {
    contour: Option<ReadinessContourIdentity>,
    failure: ReadinessFailureKind,
    retry_at: std::time::Instant,
}

#[cfg(windows)]
#[derive(Debug, Default)]
pub(super) struct HostReadinessGate {
    cadence: ReadinessCadence,
    lease: Option<ReadinessLease>,
    retry: Option<ReadinessRetry>,
}

#[cfg(windows)]
impl HostReadinessGate {
    pub(super) fn with_cadence(cadence: ReadinessCadence) -> Self {
        Self {
            cadence,
            lease: None,
            retry: None,
        }
    }

    pub(super) fn action(
        &mut self,
        contour: Option<&ReadinessContourIdentity>,
        now: std::time::Instant,
    ) -> ReadinessGateAction {
        let disposition = readiness_lease_disposition(self.lease.as_ref(), contour, now);
        if disposition == ReadinessLeaseDisposition::LeaseLive {
            host_readiness_gate_observe_bound(&ReadinessGateObservation::for_action(
                "host.readiness lease hit observed",
                disposition,
                contour,
                self.lease.as_ref(),
                now,
                None,
            ));
            return ReadinessGateAction::PreserveAuthenticatedHealth;
        }
        // The lease this branch is about to clear, and the typed failure kind
        // of any retry it is about to keep or discard, are read here so the
        // record states the real case BEFORE the state is dropped. Copying the
        // closed failure kind ends the borrow of `self` before the mutation;
        // no handle, digest or error text is copied or derived.
        let retained = self.lease.as_ref();
        let pending_failure = self
            .retry
            .as_ref()
            .filter(|retry| retry.contour.as_ref() == contour && now < retry.retry_at)
            .map(|retry| retry.failure);
        let discarded_failure = self.retry.as_ref().map(|retry| retry.failure);
        match pending_failure {
            Some(failure) => host_readiness_gate_observe_bound(
                &ReadinessGateObservation::for_action(
                    "host.readiness retry pending observed",
                    disposition,
                    contour,
                    retained,
                    now,
                    Some(failure),
                ),
            ),
            None => host_readiness_gate_observe_bound(&ReadinessGateObservation::for_action(
                "host.readiness probe due observed",
                disposition,
                contour,
                retained,
                now,
                discarded_failure,
            )),
        }
        // Lease handling is unchanged: the lease is always cleared here, and
        // the retry is cleared only on the probe-due branch.
        self.lease = None;
        if let Some(failure) = pending_failure {
            return ReadinessGateAction::RetryPending(failure);
        }
        self.retry = None;
        ReadinessGateAction::ProbeDue
    }

    pub(super) fn grant(
        &mut self,
        contour: ReadinessContourIdentity,
        now: std::time::Instant,
    ) -> bool {
        if contour.store_proof_fence.is_none()
            || contour.supervision_lease_id.is_none()
            || contour.supervision_ors_receipt_digest.is_none()
            || contour.watchdog_publication_digest.is_none()
        {
            host_readiness_gate_observe_bound(&ReadinessGateObservation::for_grant(
                "host.readiness grant rejected observed",
                Some(&contour),
                Some(ReadinessLeaseDisposition::ProofIncomplete),
                None,
                now,
            ));
            self.lease = None;
            return false;
        }
        let valid_until = self.cadence.deadline(now);
        self.lease = Some(ReadinessLease {
            contour,
            valid_until,
        });
        self.retry = None;
        // The grant record binds the exact journaled contour that authorized
        // this lease and the bounded window it was granted for, so a local
        // cache lease is never readable as owner readiness without it.
        host_readiness_gate_observe_bound(&ReadinessGateObservation::for_grant(
            "host.readiness grant observed",
            self.lease.as_ref().map(|lease| &lease.contour),
            None,
            Some(valid_until),
            now,
        ));
        true
    }

    pub(super) fn fail(
        &mut self,
        contour: Option<ReadinessContourIdentity>,
        failure: ReadinessFailureKind,
        now: std::time::Instant,
    ) {
        host_readiness_gate_observe_bound(&ReadinessGateObservation::for_failure(
            "host.readiness degraded observed",
            contour.as_ref(),
            failure,
        ));
        self.lease = None;
        self.retry = Some(ReadinessRetry {
            contour,
            failure,
            retry_at: self.cadence.deadline(now),
        });
    }

    pub(super) fn branch_degraded(&mut self) {
        // This branch is decided without any presented contour, retained lease
        // or classified failure, so it binds no identity rather than guessing
        // one.
        host_readiness_gate_observe("host.readiness branch degraded observed");
        self.lease = None;
        self.retry = None;
    }

    #[cfg(test)]
    pub(super) fn last_failure(&self) -> Option<ReadinessFailureKind> {
        self.retry.as_ref().map(|retry| retry.failure)
    }
}

#[cfg(windows)]
pub(super) fn reconcile_authenticated_readiness(
    gate: &mut HostReadinessGate,
    contour: Result<ReadinessContourIdentity, HostError>,
    now: std::time::Instant,
    authenticate_and_journal: impl FnOnce() -> Result<ReadinessContourIdentity, HostError>,
) -> HostBranchDisposition {
    let contour = match contour {
        Ok(contour) => contour,
        Err(_error) => {
            // The caller presented no contour at all, so there is no contour
            // identity to bind: the record states the exact unavailable owner
            // condition instead of omitting it.
            host_readiness_gate_observe_bound(&ReadinessGateObservation::for_failure(
                "host.readiness contour unavailable observed",
                None,
                ReadinessFailureKind::ContourUnavailable,
            ));
            gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
            return HostBranchDisposition::ReadinessDegraded;
        }
    };
    match gate.action(Some(&contour), now) {
        ReadinessGateAction::PreserveAuthenticatedHealth => HostBranchDisposition::Healthy,
        ReadinessGateAction::RetryPending(_failure) => HostBranchDisposition::ReadinessDegraded,
        ReadinessGateAction::ProbeDue => match authenticate_and_journal() {
            Ok(journaled_contour) => {
                if gate.grant(journaled_contour, now) {
                    HostBranchDisposition::Healthy
                } else {
                    gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
                    HostBranchDisposition::ReadinessDegraded
                }
            }
            Err(error) => {
                let failure = readiness_failure_kind(&error);
                host_readiness_gate_observe_bound(&ReadinessGateObservation::for_failure(
                    "host.readiness probe failed observed",
                    Some(&contour),
                    failure,
                ));
                gate.fail(Some(contour), failure, now);
                HostBranchDisposition::ReadinessDegraded
            }
        },
    }
}