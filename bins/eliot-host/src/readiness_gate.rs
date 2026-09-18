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
// the semantic owner. Arguments are static literals only — never contour
// identities, lease timestamps, or arbitrary error text — so bounding
// limits size, not sensitivity (I15.4). A valid lease, an expired or
// incomplete contour, and a pending retry stay distinct: only a complete
// contour under a live lease preserves health, and anything else degrades
// without promoting liveness into readiness (I1.10). These primitives own
// no terminal: a single terminal per failed supervision operation is
// enforced by the outermost owner boundary, while these phases correlate by
// stage order only. The pure contract helpers in `contract.rs`
// (`same_probe_input_contour`, `readiness_failure_kind`) are explicit
// non-boundaries and never log. Sink outcome never alters gate
// result/timer/cleanup.
#[cfg(windows)]
fn host_readiness_gate_observe(detail: &str) {
    let _ = crate::windows_event_log::event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
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
        if self.lease.as_ref().is_some_and(|lease| {
            contour == Some(&lease.contour)
                && lease.contour.store_proof_fence.is_some()
                && lease.contour.supervision_lease_id.is_some()
                && lease.contour.supervision_ors_receipt_digest.is_some()
                && lease.contour.watchdog_publication_digest.is_some()
                && now < lease.valid_until
        }) {
            host_readiness_gate_observe("host.readiness lease hit observed");
            return ReadinessGateAction::PreserveAuthenticatedHealth;
        }
        self.lease = None;
        if let Some(retry) = self
            .retry
            .as_ref()
            .filter(|retry| retry.contour.as_ref() == contour && now < retry.retry_at)
        {
            host_readiness_gate_observe("host.readiness retry pending observed");
            return ReadinessGateAction::RetryPending(retry.failure);
        }
        self.retry = None;
        host_readiness_gate_observe("host.readiness probe due observed");
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
            host_readiness_gate_observe("host.readiness grant rejected observed");
            self.lease = None;
            return false;
        }
        self.lease = Some(ReadinessLease {
            contour,
            valid_until: self.cadence.deadline(now),
        });
        self.retry = None;
        host_readiness_gate_observe("host.readiness grant observed");
        true
    }

    pub(super) fn fail(
        &mut self,
        contour: Option<ReadinessContourIdentity>,
        failure: ReadinessFailureKind,
        now: std::time::Instant,
    ) {
        host_readiness_gate_observe("host.readiness degraded observed");
        self.lease = None;
        self.retry = Some(ReadinessRetry {
            contour,
            failure,
            retry_at: self.cadence.deadline(now),
        });
    }

    pub(super) fn branch_degraded(&mut self) {
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
            host_readiness_gate_observe("host.readiness contour unavailable observed");
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
                host_readiness_gate_observe("host.readiness probe failed observed");
                gate.fail(Some(contour), failure, now);
                HostBranchDisposition::ReadinessDegraded
            }
        },
    }
}
