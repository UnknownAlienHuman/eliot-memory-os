#![allow(clippy::expect_used)]

#[path = "support/episode.rs"]
mod support;

use eliot_dreamer_contracts::{CandidateDisposition, ContractViolation};
use eliot_dreamer_episode::{
    ChronologyRelation, EpisodeStatus, OverlapDisposition, reconstruct_episode_candidate,
};
use support::fixture;

#[test]
fn closed_episode_preserves_full_immutable_closure() {
    let mut fixture = fixture();
    fixture.existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect("closed Episode");
    assert_eq!(candidate.status, EpisodeStatus::Closed);
    assert_eq!(candidate.disposition, CandidateDisposition::Candidate);
    assert_eq!(candidate.events.len(), 2);
    assert_eq!(candidate.participants.len(), 2);
    assert_eq!(candidate.outcomes.len(), 2);
    assert_eq!(candidate.overlap.disposition, OverlapDisposition::None);
    assert_eq!(candidate.source.members.len(), 3);
    assert_eq!(candidate.handler_result.request_id, "request-1");
    let chronology = candidate
        .chronology
        .iter()
        .find(|link| link.left_event_id == "event-start")
        .expect("chronology");
    assert_eq!(chronology.relation, ChronologyRelation::Before);
    assert_eq!(chronology.support.len(), 2);

    let replay = support::fixture();
    let replay_candidate = reconstruct_episode_candidate(
        &replay.input,
        &replay.events,
        &replay.snapshot,
        &replay.existing,
        &replay.policy,
    )
    .expect("exact replay");
    assert_eq!(
        replay_candidate.disposition,
        CandidateDisposition::Duplicate
    );
}

#[test]
fn open_episode_requires_start_anchor_only() {
    let fixture = fixture();
    let mut policy = fixture.policy.clone();
    policy.end_event_id = None;
    policy.policy_digest = policy.computed_digest().expect("policy digest");
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &policy,
    )
    .expect("open Episode");
    assert_eq!(candidate.status, EpisodeStatus::Open);
    assert!(candidate.boundary.end_event_id.is_none());
}

#[test]
fn partial_event_denominator_retains_explicit_gap() {
    let fixture = support::fixture_with_modes(true, false, false);
    let mut events = fixture.events.clone();
    events.denominator.coverage = eliot_memory_curation_contracts::DenominatorCoverage::Partial;
    events.events.pop();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect("partial Episode");
    assert_eq!(candidate.status, EpisodeStatus::Partial);
    assert!(
        candidate
            .coverage
            .gaps
            .iter()
            .any(|gap| { gap.member_id.as_deref() == Some("event-end") })
    );
    assert!(candidate.events[0].temporal.event_time.is_none());
}

#[test]
fn changed_identity_is_rejected_against_exact_member_digest() {
    let fixture = support::fixture();
    let mut events = fixture.events.clone();
    events.events[0].source_content_digest = support::digest_value("changed");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("changed source identity");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "event.content_binding",
            ..
        }
    ));
}

#[test]
fn grounding_mismatch_rejects_changed_temporal_payload() {
    let cross_domain = support::fixture_with_modes(false, true, false);
    let cross_candidate = reconstruct_episode_candidate(
        &cross_domain.input,
        &cross_domain.events,
        &cross_domain.snapshot,
        &cross_domain.existing,
        &cross_domain.policy,
    )
    .expect("cross-domain chronology");
    assert!(
        cross_candidate
            .chronology
            .iter()
            .all(|link| link.relation == ChronologyRelation::Incomparable)
    );
    let near_overlap = support::fixture_with_modes(false, false, true);
    let near_candidate = reconstruct_episode_candidate(
        &near_overlap.input,
        &near_overlap.events,
        &near_overlap.snapshot,
        &near_overlap.existing,
        &near_overlap.policy,
    )
    .expect("near-overlap chronology");
    assert!(
        near_candidate
            .chronology
            .iter()
            .all(|link| link.relation == ChronologyRelation::Incomparable)
    );

    let fixture = fixture();
    let mut events = fixture.events.clone();
    let reading = &mut events.events[0]
        .temporal
        .event_time
        .as_mut()
        .expect("time")
        .reading;
    reading.valid_time_ms = Some(999);
    reading.known_time_ms = Some(999);
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("changed temporal material");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "evidence.material_preimage",
            ..
        }
    ));
}

#[test]
fn cancellation_and_capacity_fail_before_semantic_join() {
    let fixture = fixture();
    let mut policy = fixture.policy.clone();
    policy.cancellation_requested = true;
    policy.policy_digest = policy.computed_digest().expect("policy digest");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &policy,
    )
    .expect_err("cancelled Episode");
    assert!(matches!(
        error,
        ContractViolation::Budget {
            dimension: "episode.cancellation",
            ..
        }
    ));

    let fixture = support::fixture();
    let mut policy = fixture.policy.clone();
    policy.max_work = 1;
    policy.policy_digest = policy.computed_digest().expect("policy digest");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &policy,
    )
    .expect_err("bounded chronology work");
    assert!(matches!(
        error,
        ContractViolation::Budget {
            dimension: "episode.work",
            ..
        }
    ));
}
