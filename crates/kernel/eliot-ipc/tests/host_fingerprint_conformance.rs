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

use std::num::NonZeroU64;

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence, parse_versioned_sha256_digest,
};
use eliot_ipc::{
    AdmissionCoverage, AttemptGate, CapabilityEvidence, ConformanceError, EvidenceTier,
    FingerprintQuarantine, HostFingerprint, RouteMismatchDisposition, admit_coverage,
    reconcile_attempt_route, require_verified_capability,
};
use eliot_protocol::{HandoffCausalLink, HandoffCompleteness, RehydrationBundle, RouteFingerprint};

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
        Vec::new(),
    ))]
}

fn full_evidence() -> Vec<CapabilityEvidence> {
    evidence_for(&fingerprint(), "prod-span-9")
}

fn evidence_for(active: &HostFingerprint, observed_span: &str) -> Vec<CapabilityEvidence> {
    let probe = ok(CapabilityEvidence::new(
        active,
        EvidenceTier::ConformanceProbe,
        SCOPE,
        "probe",
        LIVE,
        vec!["probe-run-7".to_owned()],
        Vec::new(),
    ));
    let mut quarantine = FingerprintQuarantine::new();
    let mut no_prior_evidence: Vec<CapabilityEvidence> = Vec::new();
    let matched_route = ok(reconcile_attempt_route(
        "route-main",
        Some("route-main"),
        &mut no_prior_evidence,
        &mut quarantine,
        active,
        RouteMismatchDisposition::Quarantine,
    ));
    let observation = ok(matched_route.project_production_observation(
        &probe,
        active,
        observed_span,
        NOW,
    ));
    vec![probe, observation]
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
    assert!(evidence.iter().all(CapabilityEvidence::is_invalidated));
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
    let bundle = RehydrationBundle {
        task_acceptance_and_plan: "plan".to_owned(),
        epistemic_position_and_architecture_constraints: "position".to_owned(),
        base_diff_environment_receipts: vec!["base-receipt".to_owned()],
        artifacts_and_evidence_handles: vec!["evidence-handle".to_owned()],
        failed_paths_and_reopen_conditions: Vec::new(),
        open_unknowns_permissions_budgets_output_schema: "unknowns".to_owned(),
    };
    let bundle_digest = ok(bundle.canonical_digest());
    let epoch = ok(EpochId::new(
        ok(EpochLineageId::new("00000000-0000-0000-0000-000000000001")),
        NonZeroU64::MIN,
    ));
    let handoff = HandoffCausalLink {
        source_attempt_id: "attempt-1".to_owned(),
        source_session_ref: "session-1".to_owned(),
        source_revision: "revision-1".to_owned(),
        source_state_fence: StateFence::new(epoch.clone(), ResourceGeneration::genesis()),
        source_authority_epoch: epoch,
        source_event_cursor: None,
        source_outbox_cursor: None,
        in_flight_effect_dispositions: Vec::new(),
        handoff_checkpoint_ref: "checkpoint-1".to_owned(),
        omission_manifest_digest: ok(parse_versioned_sha256_digest(&format!("sha256:{EXE_SHA}"))),
        replay_from_cursor: None,
        rehydration_bundle_digest: Some(ok(parse_versioned_sha256_digest(&format!(
            "sha256:{bundle_digest}"
        )))),
        target_attempt_id: "attempt-2".to_owned(),
        target_route_fingerprint: RouteFingerprint {
            route_id: "route-main".to_owned(),
            runtime_id: "runtime-1".to_owned(),
            adapter_id: "adapter-1".to_owned(),
            fingerprint: ok(parse_versioned_sha256_digest(&format!("sha256:{EXE_SHA}"))),
        },
        post_resume_revalidation_ref: "revalidation-1".to_owned(),
        completeness: HandoffCompleteness::Unknown,
    };
    let next = ok(gate.next_attempt_after_effect("attempt-2", handoff, bundle));
    assert_eq!(next.causal_parent(), Some(&"attempt-1".to_owned()));
    // Identity-only release and empty revalidation cannot clear quarantine.
    assert_eq!(
        quarantine.reconcile_with_revalidation(&active, &[], SCOPE, NOW),
        Err(ConformanceError::CandidateOnlyWhereVerifiedRequired)
    );
    assert!(quarantine.is_quarantined(&active.canonical()));

    // A matched production attempt plus its live probe releases quarantine.
    let fresh = full_evidence();
    assert!(ok(quarantine.reconcile_with_revalidation(
        &active, &fresh, SCOPE, NOW
    )));
    assert_eq!(
        ok(admit_coverage(&fresh, &active, SCOPE, NOW, &quarantine)),
        AdmissionCoverage::Verified
    );
}

// HARDENING/1: `/` is the canonical join separator, so it is rejected inside
// fingerprint fields — two distinct tuples must never share one canonical
// string and each other's evidence.
#[test]
fn fingerprint_fields_reject_canonical_separator() {
    for field in ["in/stal", "1.2/3", "0.9/0", "route/ma"] {
        let (installation, host, adapter, route) = match field {
            "in/stal" => (field, "1.2.3", "0.9.0", "route-main"),
            "1.2/3" => ("install-1", field, "0.9.0", "route-main"),
            "0.9/0" => ("install-1", "1.2.3", field, "route-main"),
            _ => ("install-1", "1.2.3", "0.9.0", field),
        };
        assert_eq!(
            HostFingerprint::new(
                installation,
                EXE_SHA,
                Some(PKG_SHA.to_owned()),
                host,
                adapter,
                route
            ),
            Err(ConformanceError::InvalidInput)
        );
    }
}

// HARDENING/2: route-mismatch reconciliation invalidates only evidence bound
// to the mismatched fingerprint; unrelated fingerprints stay live.
#[test]
fn route_mismatch_invalidates_only_dependent_fingerprint() {
    let active = fingerprint();
    let other = ok(HostFingerprint::new(
        "install-2",
        EXE_SHA,
        Some(PKG_SHA.to_owned()),
        "1.2.3",
        "0.9.0",
        "route-main",
    ));
    let mut evidence = full_evidence();
    evidence.extend(evidence_for(&other, "prod-span-other"));
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
    assert_eq!(outcome.invalidated_count, 2);
    assert!(evidence[..2].iter().all(CapabilityEvidence::is_invalidated));
    assert!(!evidence[2].is_invalidated());
    assert!(evidence[2].is_live(NOW));
}
