//! Minimal acceptance proof for issue #1935 (I7.16/I7.22/I7.23).
//!
//! Only the two behaviors named under acceptance are proved:
//! 1. visible lifecycle/tool events without reliable pre-action enforcement
//!    are recorded as observed (not enforced) and the derived
//!    `GovernanceProfile` does not authorize enforcement-dependent operations;
//! 2. a later blind interval or route mismatch emits a new `GovernanceProfile`
//!    revision and a previously dependent capability is rejected under it.

use eliot_integration_coverage::{
    ALL_EVENTS, CoverageError, DispatchOrdering, EventCompleteness, EventCoverage,
    EventDisposition, GovernorCoverageDerivation, IntegrationCoverageProfile, LogicalEvent,
    TraceFreshness, WatchdogEvidence,
};

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("expected Ok, got {error:?}"),
    }
}

fn observed_event(event: LogicalEvent) -> EventCoverage {
    EventCoverage {
        event,
        disposition: EventDisposition::Observed,
        ordering: DispatchOrdering::PostDispatch,
        completeness: EventCompleteness::Complete,
        proof_ceiling: "observed-effect".to_owned(),
        source: "host-event-envelope".to_owned(),
        gaps: Vec::new(),
    }
}

fn enforced_pre_action(event: LogicalEvent) -> EventCoverage {
    EventCoverage {
        event,
        disposition: EventDisposition::Enforced,
        ordering: DispatchOrdering::PreDispatch,
        completeness: EventCompleteness::Complete,
        proof_ceiling: "enforced-action".to_owned(),
        source: "host-event-envelope".to_owned(),
        gaps: Vec::new(),
    }
}

fn fresh_watchdog() -> WatchdogEvidence {
    WatchdogEvidence {
        supervisor_id: "watchdog:supervisor-1".to_owned(),
        fresh: true,
        summary: "trace supervision current".to_owned(),
    }
}

#[test]
fn observed_lifecycle_without_enforcement_denies_enforcement_ops() {
    let candidate = must(IntegrationCoverageProfile::candidate(
        "host:adapter:fingerprint-a",
        ALL_EVENTS.iter().copied().map(observed_event).collect(),
        EventCompleteness::Complete,
        "observed-effect",
        "discovery-scan",
        Vec::new(),
    ));
    // Discovery output alone cannot derive production claims.
    let mut governor = GovernorCoverageDerivation::new();
    assert_eq!(
        governor.derive(&candidate, &fresh_watchdog(), TraceFreshness::Fresh),
        Err(CoverageError::CandidateNotVerified)
    );
    // Exact active-fingerprint production observation verifies the profile.
    let coverage = must(candidate.verify("host:adapter:fingerprint-a", true));
    assert_eq!(
        coverage.disposition(LogicalEvent::PreToolUse),
        Some(EventDisposition::Observed)
    );
    assert_eq!(
        coverage.disposition(LogicalEvent::PermissionRequest),
        Some(EventDisposition::Observed)
    );
    let profile = must(governor.derive(&coverage, &fresh_watchdog(), TraceFreshness::Fresh));
    assert!(!profile.authorizes_enforcement);
    // Enforcement-dependent operations are not authorized; observation-only
    // operations still are.
    let blocking = must(governor.issue_capability("cap:enforcing-tool", true, false));
    assert_eq!(
        governor.authorize(&blocking.capability_id),
        Err(CoverageError::CapabilityNotAuthorized(
            "cap:enforcing-tool".to_owned()
        ))
    );
    let observing = must(governor.issue_capability("cap:observe-only", false, false));
    must(governor.authorize(&observing.capability_id));
}

#[test]
fn coverage_loss_emits_new_revision_and_rejects_prior_capability() {
    let mut events: Vec<EventCoverage> = ALL_EVENTS.iter().copied().map(observed_event).collect();
    for event in &mut events {
        if matches!(
            event.event,
            LogicalEvent::PreToolUse | LogicalEvent::PermissionRequest
        ) {
            *event = enforced_pre_action(event.event);
        }
    }
    let coverage = must(
        must(IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            events,
            EventCompleteness::Complete,
            "enforced-action",
            "host-event-envelope",
            Vec::new(),
        ))
        .verify("host:adapter:fingerprint-a", true),
    );
    let mut governor = GovernorCoverageDerivation::new();
    let before = must(governor.derive(&coverage, &fresh_watchdog(), TraceFreshness::Fresh));
    assert!(before.authorizes_enforcement);
    let capability = must(governor.issue_capability("cap:guarded-tool", true, true));
    must(governor.authorize(&capability.capability_id));

    // A blind interval on the tool-outcome stream degrades completeness.
    let mut degraded: Vec<EventCoverage> = ALL_EVENTS.iter().copied().map(observed_event).collect();
    for event in &mut degraded {
        if matches!(
            event.event,
            LogicalEvent::PreToolUse | LogicalEvent::PermissionRequest
        ) {
            *event = enforced_pre_action(event.event);
        }
        if event.event == LogicalEvent::PostToolUse {
            event.completeness = EventCompleteness::Partial;
            event.gaps.push("blind interval 12:00-12:07".to_owned());
        }
    }
    let degraded = must(
        must(IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            degraded,
            EventCompleteness::Partial,
            "observed-effect",
            "host-event-envelope",
            vec!["blind interval 12:00-12:07".to_owned()],
        ))
        .verify("host:adapter:fingerprint-a", true),
    );
    let after = must(governor.derive(&degraded, &fresh_watchdog(), TraceFreshness::Fresh));
    assert!(after.revision > before.revision);
    assert!(matches!(
        governor.authorize(&capability.capability_id),
        Err(CoverageError::CapabilityRevoked(_)
            | CoverageError::StaleCapabilityBinding(_)
            | CoverageError::CapabilityNotAuthorized(_))
    ));

    // A route mismatch emits a further revision that authorizes nothing and
    // rejects capabilities bound to the lost fingerprint.
    let observer = must(governor.issue_capability("cap:observe-degraded", false, false));
    must(governor.authorize(&observer.capability_id));
    let (mismatch, revoked) = must(
        governor.report_route_mismatch("host:adapter:fingerprint-a", "host:adapter:fingerprint-b"),
    );
    assert!(mismatch.revision > after.revision);
    assert!(revoked.contains(&"cap:observe-degraded".to_owned()));
    assert!(governor.authorize(&capability.capability_id).is_err());
    assert!(governor.authorize(&observer.capability_id).is_err());
}
