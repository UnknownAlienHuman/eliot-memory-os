//! Smallest acceptance proof for issue #1937 (I7.22 exact host fingerprint
//! conformance before admitting capabilities).
//!
//! Scope is the `eliot-ipc` admission boundary only. Both tests call the real
//! public `eliot-ipc` API with no mocks.
//!
//! ACCEPTANCE/1: an adapter discovered from metadata but lacking probe and
//! active-fingerprint observation is admitted only as candidate coverage and
//! cannot satisfy a verified tool/enforcement claim.
//!
//! ACCEPTANCE/2: a completed attempt whose observed route differs from its
//! requested route is marked candidate-only, its dependent capability
//! evidence is invalidated, and any subsequent use of that fingerprint is
//! rejected or quarantined until reconciliation.

use eliot_ipc::{
    AdmissionCoverage, AttemptGate, CapabilityEvidence, ConformanceError, EvidenceTier,
    FingerprintQuarantine, HostFingerprint, RouteMismatchDisposition, admit_coverage,
    reconcile_attempt_route, require_verified_capability,
};

const EXE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PKG_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SCOPE: &str = "tool.exec.verified";
const NOW: u64 = 1_800_000_000_000;
const LIVE: u64 = 1_900_000_000_000;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn fingerprint() -> HostFingerprint {
    ok(HostFingerprint::new(
        "install-1",
        EXE_SHA,
        Some(PKG_SHA.to_owned()),
        "1.2.3",
        "0.9.0",
        "route-main",
    ))
}

fn discovery_only() -> Vec<CapabilityEvidence> {
    vec![ok(CapabilityEvidence::new(
        &fingerprint(),
        EvidenceTier::CandidateDiscovery,
        SCOPE,
        "candidate",
        LIVE,
        vec!["install-record".to_owned()],
    ))]
}

fn full_evidence() -> Vec<CapabilityEvidence> {
    vec![
        ok(CapabilityEvidence::new(
            &fingerprint(),
            EvidenceTier::ConformanceProbe,
            SCOPE,
            "probe",
            LIVE,
            vec!["probe-run-7".to_owned()],
        )),
        ok(CapabilityEvidence::new(
            &fingerprint(),
            EvidenceTier::ProductionObservation,
            SCOPE,
            "observed",
            LIVE,
            vec!["prod-span-9".to_owned()],
        )),
    ]
}

// ACCEPTANCE/1
#[test]
fn metadata_discovery_without_probe_and_observation_is_candidate_only() {
    let quarantine = FingerprintQuarantine::new();
    let coverage = ok(admit_coverage(
        &discovery_only(),
        &fingerprint(),
        SCOPE,
        NOW,
        &quarantine,
    ));
    assert_eq!(coverage, AdmissionCoverage::CandidateOnly);
    assert_eq!(
        require_verified_capability(&discovery_only(), &fingerprint(), SCOPE, NOW, &quarantine),
        Err(ConformanceError::CandidateOnlyWhereVerifiedRequired)
    );
    // The same adapter with probe plus active-fingerprint observation verifies.
    let coverage = ok(admit_coverage(
        &full_evidence(),
        &fingerprint(),
        SCOPE,
        NOW,
        &quarantine,
    ));
    assert_eq!(coverage, AdmissionCoverage::Verified);
    ok(require_verified_capability(
        &full_evidence(),
        &fingerprint(),
        SCOPE,
        NOW,
        &quarantine,
    ));
}

// ACCEPTANCE/2
#[test]
fn route_mismatch_marks_candidate_only_invalidates_and_quarantines() {
    let active = fingerprint();
    let mut evidence = full_evidence();
    let mut quarantine = FingerprintQuarantine::new();
    let outcome = ok(reconcile_attempt_route(
        "route-main",
        Some("route-shadow"),
        &mut evidence,
        &mut quarantine,
        &active,
        RouteMismatchDisposition::Quarantine,
    ));
    assert!(!outcome.matches);
    assert!(outcome.candidate_only);
    assert_eq!(outcome.invalidated_count, 2);
    assert!(outcome.quarantined);
    assert!(evidence.iter().all(|item| item.is_invalidated()));
    // Subsequent use of that fingerprint is rejected until reconciliation.
    assert_eq!(
        admit_coverage(&evidence, &active, SCOPE, NOW, &quarantine),
        Err(ConformanceError::Quarantined)
    );
    assert_eq!(
        require_verified_capability(&evidence, &active, SCOPE, NOW, &quarantine),
        Err(ConformanceError::Quarantined)
    );
    // No silent mid-attempt failover after the boundary either.
    let mut gate = ok(AttemptGate::new("attempt-1"));
    gate.record_tool_use();
    assert_eq!(
        gate.retry_or_substitute(),
        Err(ConformanceError::SilentFailoverDenied)
    );
    let next = ok(gate.next_attempt_after_effect("attempt-2"));
    assert_eq!(next.causal_parent(), Some(&"attempt-1".to_owned()));
    // Reconciliation clears the quarantine; fresh evidence re-verifies.
    assert!(quarantine.reconcile(&active.canonical()));
    let fresh = full_evidence();
    assert_eq!(
        ok(admit_coverage(&fresh, &active, SCOPE, NOW, &quarantine)),
        AdmissionCoverage::Verified
    );
}
