//! Failure/revision coverage must remain incomplete when omissions exist.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_observation_contracts::{
    CONTRACT_VERSION, CoverageDisposition, CoverageEvidence, FailureObservation, FailureOmission,
    FailureOmissionClass, MemoryRevisionEvidence, ObservationScope, SourceRevisionHandle,
};

fn fence() -> StateFence {
    let lineage =
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("fixture sequence"))
        .expect("fixture epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn scope() -> ObservationScope {
    ObservationScope {
        work_scope: "scope:issue-196".parse().expect("fixture scope"),
        task_ref: Some("task:issue-196".to_owned()),
        attempt_ref: None,
        module_or_route_ref: None,
    }
}

fn coverage() -> CoverageEvidence {
    CoverageEvidence {
        disposition: CoverageDisposition::Complete,
        denominator_source_ref: "memory-owner:revision-7".to_owned(),
        interval: None,
        blind_intervals: Vec::new(),
        observed_count: 0,
    }
}

fn revision() -> SourceRevisionHandle {
    SourceRevisionHandle {
        source_id: "memory-owner".to_owned(),
        revision: "revision-7".to_owned(),
        content_sha256: "a".repeat(64),
        byte_length: 128,
    }
}

fn omission() -> FailureOmission {
    FailureOmission {
        handle: Some(ArtifactId::new("omitted-journal-record").expect("fixture handle")),
        class: FailureOmissionClass::JournalBlind,
        note: "one journal record was not observable".to_owned(),
    }
}

fn observation() -> FailureObservation {
    let mut value = FailureObservation {
        contract_version: CONTRACT_VERSION,
        observation_id: ArtifactId::new("failure-observation").expect("fixture observation"),
        fingerprint: "trigger:action:outcome".to_owned(),
        trigger: "trigger".to_owned(),
        failed_action: "action".to_owned(),
        outcome: "failure".to_owned(),
        violated_invariant: "invariant".to_owned(),
        scope: scope(),
        state_fence: fence(),
        journal_refs: Vec::new(),
        journal_revision: revision(),
        coverage: coverage(),
        reopen_condition: "reopen after a changed environment".to_owned(),
        extinction_condition: "extinct after safe re-exposure".to_owned(),
        omissions: Vec::new(),
        digest: String::new(),
    };
    value.digest = value.compute_digest().expect("fixture observation digest");
    value
}

fn evidence() -> MemoryRevisionEvidence {
    let mut value = MemoryRevisionEvidence {
        contract_version: CONTRACT_VERSION,
        evidence_id: ArtifactId::new("revision-evidence").expect("fixture evidence"),
        observation_ref: ArtifactId::new("failure-observation").expect("fixture observation"),
        evidence_refs: Vec::new(),
        evidence_revision: revision(),
        scope: scope(),
        state_fence: fence(),
        coverage: coverage(),
        same_hypothesis_recurrence: false,
        prior_attempts: 1,
        omissions: Vec::new(),
        digest: String::new(),
    };
    value.digest = value.compute_digest().expect("fixture evidence digest");
    value
}

#[test]
fn observation_complete_posture_rejects_named_omissions() {
    let mut value = observation();
    assert!(value.coverage_complete());
    value.omissions.push(omission());
    value.digest = value.compute_digest().expect("omitted digest");
    value
        .validate()
        .expect("explicit omission remains a valid partial read");
    assert!(!value.coverage_complete());
}

#[test]
fn revision_complete_posture_rejects_named_omissions() {
    let mut value = evidence();
    assert!(value.coverage_complete());
    value.omissions.push(omission());
    value.digest = value.compute_digest().expect("omitted digest");
    value
        .validate()
        .expect("explicit omission remains a valid partial read");
    assert!(!value.coverage_complete());
}
