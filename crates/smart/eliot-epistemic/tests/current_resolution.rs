use std::error::Error;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ResourceGeneration, SourceId, StateFence,
};
use eliot_epistemic::{
    EpistemicError, EpistemicRecord, PositionRequest, PositionState, resolve,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn record(
    handle: &str,
    subject: &str,
    status: EpistemicStatus,
    freshness: EvidenceFreshness,
    supersedes: Vec<ArtifactId>,
) -> Result<EpistemicRecord, Box<dyn Error>> {
    let assertability = match status {
        EpistemicStatus::Supported | EpistemicStatus::Verified => Assertability::Assertable,
        _ => Assertability::NonAssertableUnverified,
    };
    Ok(EpistemicRecord {
        handle: ArtifactId::new(handle)?,
        subject: subject.to_owned(),
        scope: "scope:test".to_owned(),
        evidence: EvidenceEnvelope {
            authority: EvidenceAuthority::DeterministicRuntimeTest,
            freshness,
            coverage: EvidenceCoverage::CompleteForScope,
            status,
            assertability,
            provenance: Provenance {
                source_id: SourceId::new(format!("source:{handle}"))?,
                capture_route: "test-fixture".to_owned(),
                scope: "scope:test".to_owned(),
                raw_handle: Some(format!("raw:{handle}")),
                revision: Some("revision:1".to_owned()),
            },
            verification: None,
            state_fence: fence(),
        },
        supersedes,
        note: None,
    })
}

fn request(records: Vec<EpistemicRecord>) -> PositionRequest {
    PositionRequest {
        question: "what is current?".to_owned(),
        scope: "scope:test".to_owned(),
        state_fence: fence(),
        records,
    }
}

#[test]
fn known_older_supported_record_requires_revalidation() -> TestResult {
    let handle = ArtifactId::new("artifact:known-older")?;
    let position = resolve(&request(vec![record(
        handle.as_str(),
        "older support",
        EpistemicStatus::Supported,
        EvidenceFreshness::KnownOlderSnapshot,
        Vec::new(),
    )?]))?;

    assert_eq!(position.state, PositionState::Stale);
    assert!(position.direct_observations.is_empty());
    assert!(position.supporting_records.is_empty());
    assert!(position.rival_records.is_empty());
    assert_eq!(position.stale_records, vec![handle.clone()]);
    assert!(
        position
            .required_inquiry
            .contains(&format!("establish freshness for {handle}"))
    );
    Ok(())
}

#[test]
fn every_non_current_freshness_excludes_every_current_role() -> TestResult {
    for (freshness_index, freshness) in [
        EvidenceFreshness::KnownOlderSnapshot,
        EvidenceFreshness::Stale,
        EvidenceFreshness::Unknown,
    ]
    .into_iter()
    .enumerate()
    {
        for (status_index, status) in [
            EpistemicStatus::Observed,
            EpistemicStatus::Supported,
            EpistemicStatus::Contested,
        ]
        .into_iter()
        .enumerate()
        {
            let handle = ArtifactId::new(format!(
                "artifact:non-current-{freshness_index}-{status_index}"
            ))?;
            let position = resolve(&request(vec![record(
                handle.as_str(),
                "non-current role",
                status,
                freshness,
                Vec::new(),
            )?]))?;

            assert_eq!(position.state, PositionState::Stale);
            assert!(position.direct_observations.is_empty());
            assert!(position.supporting_records.is_empty());
            assert!(position.rival_records.is_empty());
            assert_eq!(position.stale_records, vec![handle]);
        }
    }
    Ok(())
}

#[test]
fn unknown_freshness_preserves_the_subject_gap_without_current_support() -> TestResult {
    let handle = ArtifactId::new("artifact:unknown-freshness")?;
    let position = resolve(&request(vec![record(
        handle.as_str(),
        "unknown subject",
        EpistemicStatus::Unknown,
        EvidenceFreshness::Unknown,
        Vec::new(),
    )?]))?;

    assert_eq!(position.state, PositionState::Stale);
    assert!(position.direct_observations.is_empty());
    assert!(position.supporting_records.is_empty());
    assert!(position.rival_records.is_empty());
    assert_eq!(position.stale_records, vec![handle]);
    assert!(position.unknowns.contains(&"unknown subject".to_owned()));
    assert!(
        position
            .required_inquiry
            .contains(&"obtain evidence for unknown subject".to_owned())
    );
    Ok(())
}

#[test]
fn explicit_supersession_lineage_is_retained_in_the_position_and_provenance() -> TestResult {
    let current = ArtifactId::new("artifact:current")?;
    let predecessor_a = ArtifactId::new("artifact:predecessor-a")?;
    let predecessor_b = ArtifactId::new("artifact:predecessor-b")?;
    let position = resolve(&request(vec![record(
        current.as_str(),
        "current support",
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCommit,
        vec![predecessor_b.clone(), predecessor_a.clone()],
    )?]))?;

    assert_eq!(position.state, PositionState::Supported);
    assert_eq!(position.supporting_records, vec![current.clone()]);
    assert_eq!(
        position.superseded_records,
        vec![predecessor_a.clone(), predecessor_b.clone()]
    );
    assert_eq!(
        position.provenance.record_handles,
        vec![current, predecessor_a, predecessor_b]
    );
    Ok(())
}

#[test]
fn duplicate_predecessor_handles_fail_closed() -> TestResult {
    let predecessor = ArtifactId::new("artifact:duplicate-predecessor")?;
    let current = ArtifactId::new("artifact:current")?;
    let request = request(vec![record(
        current.as_str(),
        "current support",
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCommit,
        vec![predecessor.clone(), predecessor.clone()],
    )?]);

    assert_eq!(
        request.validate(),
        Err(EpistemicError::DuplicatePredecessor {
            handle: current,
            predecessor,
        })
    );
    Ok(())
}

#[test]
fn self_supersession_fails_closed() -> TestResult {
    let current = ArtifactId::new("artifact:self")?;
    let request = request(vec![record(
        current.as_str(),
        "self reference",
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCommit,
        vec![current.clone()],
    )?]);

    assert_eq!(
        request.validate(),
        Err(EpistemicError::SelfSupersession { handle: current })
    );
    Ok(())
}

#[test]
fn every_exact_current_freshness_variant_can_support_the_current_position() -> TestResult {
    for (index, freshness) in [
        EvidenceFreshness::ExactCandidate,
        EvidenceFreshness::ExactCommit,
        EvidenceFreshness::ExactQuiescedWorktree,
    ]
    .into_iter()
    .enumerate()
    {
        let handle = ArtifactId::new(format!("artifact:exact-current-{index}"))?;
        let position = resolve(&request(vec![record(
            handle.as_str(),
            "current support",
            EpistemicStatus::Supported,
            freshness,
            Vec::new(),
        )?]))?;

        assert_eq!(position.state, PositionState::Supported);
        assert_eq!(position.supporting_records, vec![handle]);
        assert!(position.stale_records.is_empty());
    }
    Ok(())
}

#[test]
fn input_permutation_does_not_change_position_or_provenance() -> TestResult {
    let current = record(
        "artifact:current",
        "current support",
        EpistemicStatus::Supported,
        EvidenceFreshness::ExactCommit,
        vec![ArtifactId::new("artifact:predecessor")?],
    )?;
    let stale_unknown = record(
        "artifact:stale-unknown",
        "unknown subject",
        EpistemicStatus::Unknown,
        EvidenceFreshness::KnownOlderSnapshot,
        Vec::new(),
    )?;

    let forward = resolve(&request(vec![current.clone(), stale_unknown.clone()]))?;
    let reverse = resolve(&request(vec![stale_unknown, current]))?;

    assert_eq!(forward, reverse);
    Ok(())
}
