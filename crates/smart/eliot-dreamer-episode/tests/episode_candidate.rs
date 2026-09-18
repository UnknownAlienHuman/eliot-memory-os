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

// WORK_UNIT_CASE: 657/1
#[test]
fn case_01_closed_episode_from_exact_grounded_events() {
    let mut fixture = fixture();
    fixture.existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect("closed episode");
    assert_eq!(candidate.status, EpisodeStatus::Closed);
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Candidate
    );
    assert_eq!(candidate.events.len(), 2);
    assert_eq!(candidate.boundary.start_event_id, "event-start");
    assert_eq!(
        candidate.boundary.end_event_id.as_deref(),
        Some("event-end")
    );
    assert!(candidate.coverage.gaps.is_empty());
    assert!(eliot_dreamer_contracts::is_hex64_lower(
        &candidate.whole_input_digest
    ));
    assert!(eliot_dreamer_contracts::is_hex64_lower(
        &candidate.candidate_id
    ));
    candidate.validate().expect("closed candidate validates");
    assert_eq!(candidate.rollback.retained_event_ids.len(), 2);
    assert!(
        candidate
            .rollback
            .retained_event_ids
            .contains(&"event-start".to_owned())
    );
    assert!(
        candidate
            .rollback
            .retained_event_ids
            .contains(&"event-end".to_owned())
    );
}

// WORK_UNIT_CASE: 657/2
#[test]
fn case_02_valid_open_in_progress_episode() {
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
    .expect("open episode");
    assert_eq!(candidate.status, EpisodeStatus::Open);
    assert!(candidate.boundary.end_event_id.is_none());
    assert_eq!(candidate.boundary.start_event_id, "event-start");
    assert_eq!(candidate.events.len(), 2);
    candidate.validate().expect("open candidate validates");
}

// WORK_UNIT_CASE: 657/3
#[test]
fn case_03_exact_event_role_boundary_time_disposition_vocabulary() {
    let fixture = fixture();
    assert!(matches!(
        fixture.policy.boundary_rule,
        eliot_dreamer_episode::BoundaryRule::ExplicitEventAnchors
    ));
    let mut existing_cleared = fixture.existing.clone();
    existing_cleared.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing_cleared,
        &fixture.policy,
    )
    .expect("vocabulary episode");
    let link = candidate
        .chronology
        .iter()
        .find(|l| l.left_event_id == "event-start")
        .expect("chronology link");
    assert_eq!(link.relation, ChronologyRelation::Before);
    assert_eq!(link.support.len(), 2);
    assert_eq!(candidate.status, EpisodeStatus::Closed);
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Candidate
    );
    let target = fixture
        .snapshot
        .coverage
        .members
        .iter()
        .find(|m| m.member_id.as_str() == "episode-1")
        .expect("target coverage");
    assert_eq!(
        target.disposition,
        eliot_memory_curation_contracts::MemberDisposition::Eligible
    );
    let reference = fixture
        .snapshot
        .coverage
        .members
        .iter()
        .find(|m| m.member_id.as_str() == "event-start")
        .expect("reference coverage");
    assert_eq!(
        reference.disposition,
        eliot_memory_curation_contracts::MemberDisposition::PreservedReference
    );
    assert!(candidate.coverage.gaps.is_empty());
}

// WORK_UNIT_CASE: 657/4
#[test]
fn case_04_wrong_curation_kind_payload_rejected() {
    let fixture = fixture();
    let mut item = (*fixture.input.item).clone();
    item.kind_spelling = "concept".to_owned();
    let item_ref: &'static eliot_dreamer_contracts::ValidatedCurationItem =
        Box::leak(Box::new(item));
    let input = eliot_dreamer_episode::ValidatedCurationInput {
        item: item_ref,
        ctx: fixture.input.ctx,
    };
    let error = reconstruct_episode_candidate(
        &input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("wrong kind rejected");
    assert!(matches!(error, ContractViolation::KindPayload(_)));
    let fixture2 = support::fixture();
    let mut item2 = (*fixture2.input.item).clone();
    item2.family_spelling = "relation".to_owned();
    let item_ref2: &'static eliot_dreamer_contracts::ValidatedCurationItem =
        Box::leak(Box::new(item2));
    let input2 = eliot_dreamer_episode::ValidatedCurationInput {
        item: item_ref2,
        ctx: fixture2.input.ctx,
    };
    assert!(
        reconstruct_episode_candidate(
            &input2,
            &fixture2.events,
            &fixture2.snapshot,
            &fixture2.existing,
            &fixture2.policy,
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 657/5
#[test]
fn case_05_task_scope_fence_bundle_manifest_grounding_mismatch() {
    let fixture = fixture();
    let mut item = (*fixture.input.item).clone();
    item.task_id = "other-task".to_owned();
    let item_ref: &'static eliot_dreamer_contracts::ValidatedCurationItem =
        Box::leak(Box::new(item));
    let input = eliot_dreamer_episode::ValidatedCurationInput {
        item: item_ref,
        ctx: fixture.input.ctx,
    };
    let error = reconstruct_episode_candidate(
        &input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("task mismatch");
    assert!(matches!(error, ContractViolation::BindingMismatch { .. }));
    let fixture2 = support::fixture();
    let mut policy = fixture2.policy.clone();
    policy.policy_id = "other-policy".to_owned();
    policy.policy_digest = policy.computed_digest().expect("policy digest");
    let error2 = reconstruct_episode_candidate(
        &fixture2.input,
        &fixture2.events,
        &fixture2.snapshot,
        &fixture2.existing,
        &policy,
    )
    .expect_err("policy mismatch");
    assert!(matches!(
        error2,
        ContractViolation::BindingMismatch {
            field: "episode.policy",
            ..
        }
    ));
    let fixture3 = support::fixture();
    let mut snapshot = fixture3.snapshot.clone();
    snapshot.source.identity.revision = 99;
    let error3 = reconstruct_episode_candidate(
        &fixture3.input,
        &fixture3.events,
        &snapshot,
        &fixture3.existing,
        &fixture3.policy,
    )
    .expect_err("source revision mismatch");
    assert!(matches!(error3, ContractViolation::BindingMismatch { .. }));
}

// WORK_UNIT_CASE: 657/6
#[test]
fn case_06_duplicate_replay_versus_same_id_changed_event() {
    let fixture = fixture();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect("exact replay");
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Duplicate
    );
    assert_eq!(
        candidate.overlap.disposition,
        OverlapDisposition::ExactReplay
    );
    let mut events = fixture.events.clone();
    events.events[0].source_content_digest = support::digest_value("changed");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("same-id changed rejected");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "event.content_binding",
            ..
        }
    ));
    let mut dup_events = fixture.events.clone();
    let mut second = dup_events.events[1].clone();
    second.core.event_id_and_time.event_id = "event-start".to_owned();
    dup_events.events[1] = second;
    let dup_error = reconstruct_episode_candidate(
        &fixture.input,
        &dup_events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("duplicate event id");
    assert!(matches!(
        dup_error,
        ContractViolation::BindingMismatch {
            field: "events.event_id",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/7
#[test]
fn case_07_supported_partial_unavailable_unknown_evidence_statuses() {
    for availability in [
        eliot_memory_curation_contracts::SourceAvailability::Partial,
        eliot_memory_curation_contracts::SourceAvailability::Unavailable,
        eliot_memory_curation_contracts::SourceAvailability::Unknown,
        eliot_memory_curation_contracts::SourceAvailability::Stale,
        eliot_memory_curation_contracts::SourceAvailability::Blocked,
    ] {
        let fixture = fixture();
        let mut snapshot = fixture.snapshot.clone();
        snapshot.source.denominator.coverage =
            eliot_memory_curation_contracts::DenominatorCoverage::Partial;
        snapshot.coverage.denominator.coverage =
            eliot_memory_curation_contracts::DenominatorCoverage::Partial;
        snapshot.coverage.digest = snapshot
            .coverage
            .computed_digest()
            .expect("coverage digest");
        snapshot.source.availability = availability;
        let mut existing = fixture.existing.clone();
        existing.members.clear();
        let candidate = reconstruct_episode_candidate(
            &fixture.input,
            &fixture.events,
            &snapshot,
            &existing,
            &fixture.policy,
        )
        .expect("availability episode");
        assert!(
            !candidate.coverage.gaps.is_empty(),
            "availability gap must be explicit"
        );
        assert_eq!(
            candidate.disposition,
            eliot_dreamer_contracts::CandidateDisposition::Partial
        );
    }
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("supported episode");
    assert_eq!(
        candidate.coverage.source_availability,
        eliot_memory_curation_contracts::SourceAvailability::Available
    );
}

// WORK_UNIT_CASE: 657/8
#[test]
fn case_08_transformed_summary_versus_raw_event_lineage() {
    let fixture = fixture();
    let mut events = fixture.events.clone();
    events.events[0].core.observed_delta = "transformed-summary".to_owned();
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("transformed summary rejected");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "evidence.material_preimage",
            ..
        }
    ));
    let fixture2 = support::fixture();
    let mut events2 = fixture2.events.clone();
    events2.events[1].participants[0].role = "inferred-role".to_owned();
    let error2 = reconstruct_episode_candidate(
        &fixture2.input,
        &events2,
        &fixture2.snapshot,
        &fixture2.existing,
        &fixture2.policy,
    )
    .expect_err("inferred participant rejected");
    assert!(matches!(
        error2,
        ContractViolation::BindingMismatch {
            field: "evidence.material_preimage",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/9
#[test]
fn case_09_all_five_time_commit_order_distinctions() {
    let fixture = fixture();
    let temporal = &fixture.events.events[0].temporal;
    assert!(temporal.event_time.is_some());
    assert!(temporal.effective_time.is_some());
    assert!(temporal.observation_time.is_some());
    assert!(temporal.ingestion_time.is_some());
    assert!(temporal.commit_time.is_some());
    for role in ["event", "effective", "observation", "ingestion", "commit"] {
        let mut events = fixture.events.clone();
        let point = match role {
            "event" => events.events[0].temporal.event_time.as_mut().expect("time"),
            "effective" => events.events[0]
                .temporal
                .effective_time
                .as_mut()
                .expect("time"),
            "observation" => events.events[0]
                .temporal
                .observation_time
                .as_mut()
                .expect("time"),
            "ingestion" => events.events[0]
                .temporal
                .ingestion_time
                .as_mut()
                .expect("time"),
            _ => events.events[0]
                .temporal
                .commit_time
                .as_mut()
                .expect("time"),
        };
        point.reading.valid_time_ms = Some(9999);
        point.reading.known_time_ms = Some(9999);
        let error = reconstruct_episode_candidate(
            &fixture.input,
            &events,
            &fixture.snapshot,
            &fixture.existing,
            &fixture.policy,
        )
        .expect_err("each time role is load-bearing");
        assert!(
            matches!(
                error,
                ContractViolation::BindingMismatch {
                    field: "evidence.material_preimage",
                    ..
                }
            ),
            "role {role} must be bound"
        );
    }
}

// WORK_UNIT_CASE: 657/10
#[test]
fn case_10_clock_conversion_with_uncertainty() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("zero-uncertainty order");
    let link = candidate
        .chronology
        .iter()
        .find(|l| l.left_event_id == "event-start")
        .expect("link");
    assert_eq!(link.relation, ChronologyRelation::Before);
    assert_eq!(link.support.len(), 2);
    let near = support::fixture_with_modes(false, false, true);
    let mut near_existing = near.existing.clone();
    near_existing.members.clear();
    let near_candidate = reconstruct_episode_candidate(
        &near.input,
        &near.events,
        &near.snapshot,
        &near_existing,
        &near.policy,
    )
    .expect("overlapping uncertainty");
    assert!(
        near_candidate
            .chronology
            .iter()
            .all(|l| l.relation == ChronologyRelation::Incomparable)
    );
    assert!(
        near_candidate
            .chronology
            .iter()
            .all(|l| l.support.is_empty())
    );
}

// WORK_UNIT_CASE: 657/11
#[test]
fn case_11_missing_stale_incompatible_clock_conversion() {
    let cross = support::fixture_with_modes(false, true, false);
    let mut cross_existing = cross.existing.clone();
    cross_existing.members.clear();
    let cross_candidate = reconstruct_episode_candidate(
        &cross.input,
        &cross.events,
        &cross.snapshot,
        &cross_existing,
        &cross.policy,
    )
    .expect("cross-domain");
    assert!(
        cross_candidate
            .chronology
            .iter()
            .all(|l| l.relation == ChronologyRelation::Incomparable)
    );
    let unknown = support::fixture_with_modes(true, false, false);
    let mut unknown_existing = unknown.existing.clone();
    unknown_existing.members.clear();
    let unknown_candidate = reconstruct_episode_candidate(
        &unknown.input,
        &unknown.events,
        &unknown.snapshot,
        &unknown_existing,
        &unknown.policy,
    )
    .expect("missing time");
    assert!(
        unknown_candidate
            .chronology
            .iter()
            .all(|l| l.relation == ChronologyRelation::Unknown)
    );
    assert!(
        unknown_candidate
            .chronology
            .iter()
            .all(|l| l.support.is_empty())
    );
}

// WORK_UNIT_CASE: 657/12
#[test]
fn case_12_partial_order_concurrent_incomparable_events() {
    let cross = support::fixture_with_modes(false, true, false);
    let mut existing = cross.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &cross.input,
        &cross.events,
        &cross.snapshot,
        &existing,
        &cross.policy,
    )
    .expect("partial order");
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
    assert_eq!(candidate.status, EpisodeStatus::Partial);
    assert!(
        !candidate
            .chronology
            .iter()
            .any(|l| l.relation == ChronologyRelation::Concurrent)
    );
    let unknown = support::fixture_with_modes(true, false, false);
    let mut unknown_existing = unknown.existing.clone();
    unknown_existing.members.clear();
    let unknown_candidate = reconstruct_episode_candidate(
        &unknown.input,
        &unknown.events,
        &unknown.snapshot,
        &unknown_existing,
        &unknown.policy,
    )
    .expect("unknown order");
    assert!(
        !unknown_candidate
            .chronology
            .iter()
            .any(|l| l.relation == ChronologyRelation::Concurrent)
    );
}

// WORK_UNIT_CASE: 657/13
#[test]
fn case_13_contradictory_ordering_preserves_conflict_set() {
    let near = support::fixture_with_modes(false, false, true);
    let mut existing = near.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &near.input,
        &near.events,
        &near.snapshot,
        &existing,
        &near.policy,
    )
    .expect("contradictory order");
    let link = candidate.chronology.first().expect("link");
    assert_eq!(link.relation, ChronologyRelation::Incomparable);
    assert!(link.support.is_empty());
    assert_eq!(candidate.source.members.len(), 3);
    assert_eq!(
        candidate.source.members[0].member_id.as_str(),
        "event-start"
    );
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
}

// WORK_UNIT_CASE: 657/14
#[test]
fn case_14_list_order_equal_timestamps_cannot_fabricate_order() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let forward = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("forward order");
    assert_eq!(forward.chronology[0].relation, ChronologyRelation::Before);
    let mut swapped = fixture.events.clone();
    swapped.events.reverse();
    let reversed = reconstruct_episode_candidate(
        &fixture.input,
        &swapped,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("reversed list order");
    assert_eq!(reversed.chronology[0].relation, ChronologyRelation::After);
    assert_eq!(reversed.chronology[0].left_event_id, "event-end");
    assert_eq!(reversed.chronology[0].right_event_id, "event-start");
    let near = support::fixture_with_modes(false, false, true);
    let mut near_existing = near.existing.clone();
    near_existing.members.clear();
    let near_candidate = reconstruct_episode_candidate(
        &near.input,
        &near.events,
        &near.snapshot,
        &near_existing,
        &near.policy,
    )
    .expect("overlapping times");
    assert_ne!(
        near_candidate.chronology[0].relation,
        ChronologyRelation::Before
    );
}

// WORK_UNIT_CASE: 657/15
#[test]
fn case_15_chronology_cooccurrence_cannot_create_causality() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("chronology without causality");
    for link in &candidate.chronology {
        assert!(!matches!(link.relation, ChronologyRelation::Concurrent));
    }
    let near = support::fixture_with_modes(false, false, true);
    let mut near_existing = near.existing.clone();
    near_existing.members.clear();
    let near_candidate = reconstruct_episode_candidate(
        &near.input,
        &near.events,
        &near.snapshot,
        &near_existing,
        &near.policy,
    )
    .expect("cooccurrence");
    assert!(
        near_candidate
            .chronology
            .iter()
            .all(|l| l.support.is_empty())
    );
    assert_eq!(
        near_candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
}

// WORK_UNIT_CASE: 657/16
#[test]
fn case_16_exact_start_end_anchors() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("anchored");
    assert_eq!(candidate.boundary.start_event_id, "event-start");
    assert_eq!(
        candidate.boundary.end_event_id.as_deref(),
        Some("event-end")
    );
    let mut bad_policy = fixture.policy.clone();
    bad_policy.start_event_id = Some("ghost-event".to_owned());
    bad_policy.policy_digest = bad_policy.computed_digest().expect("digest");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &bad_policy,
    )
    .expect_err("missing start anchor");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "boundary.start_event_id",
            ..
        }
    ));
    let mut end_ghost = fixture.policy.clone();
    end_ghost.end_event_id = Some("ghost-end".to_owned());
    end_ghost.policy_digest = end_ghost.computed_digest().expect("digest");
    let open = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &end_ghost,
    )
    .expect("absent end stays open");
    assert!(open.boundary.end_event_id.is_none());
    assert_eq!(open.status, EpisodeStatus::Open);
}

// WORK_UNIT_CASE: 657/17
#[test]
fn case_17_missing_ambiguous_boundaries_and_visible_material_gap() {
    let fixture = fixture();
    let mut policy = fixture.policy.clone();
    policy.start_event_id = None;
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &policy,
    )
    .expect_err("start required");
    assert!(matches!(
        error,
        ContractViolation::MissingField("policy.boundary_anchors")
    ));
    let partial = support::fixture_with_modes(true, false, false);
    let mut events = partial.events.clone();
    events.denominator.coverage = eliot_memory_curation_contracts::DenominatorCoverage::Partial;
    events.events.pop();
    let mut existing = partial.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &partial.input,
        &events,
        &partial.snapshot,
        &existing,
        &partial.policy,
    )
    .expect("gap episode");
    assert!(!candidate.coverage.gaps.is_empty());
    assert_eq!(candidate.status, EpisodeStatus::Partial);
}

// WORK_UNIT_CASE: 657/18
#[test]
fn case_18_partial_log_page_cannot_prove_closed_no_intervening() {
    let fixture = support::fixture_with_modes(true, false, false);
    let mut events = fixture.events.clone();
    events.denominator.coverage = eliot_memory_curation_contracts::DenominatorCoverage::Partial;
    events.events.pop();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("partial episode");
    assert_ne!(candidate.status, EpisodeStatus::Closed);
    assert_eq!(candidate.status, EpisodeStatus::Partial);
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Partial
    );
    assert!(
        candidate
            .coverage
            .gaps
            .iter()
            .any(|g| g.member_id.as_deref() == Some("event-end"))
    );
}

// WORK_UNIT_CASE: 657/19
#[test]
fn case_19_every_event_membership_disposition_accounted() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("accounted");
    assert_eq!(
        candidate.coverage.observed_events,
        fixture.events.events.len() as u64
    );
    assert!(candidate.coverage.gaps.is_empty());
    let mut complete_missing = fixture.events.clone();
    complete_missing.events.pop();
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &complete_missing,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect_err("complete denominator must account");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "event.denominator",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/20
#[test]
fn case_20_participant_identity_and_role_conflict() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("participants");
    assert_eq!(candidate.participants.len(), 2);
    let mut events = fixture.events.clone();
    events.events[0].participants[0].role = "changed-role".to_owned();
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect_err("role change bound");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "evidence.material_preimage",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/21
#[test]
fn case_21_name_similarity_cannot_establish_participant_identity() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("exact identity");
    assert_eq!(
        candidate.participants[0].participant_id.as_str(),
        "participant-1"
    );
    let mut events = fixture.events.clone();
    events.events[0].participants[0].participant_id =
        eliot_contracts::ArtifactId::new("participant-1-similar").expect("id");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect_err("similar name rejected");
    assert!(matches!(error, ContractViolation::BindingMismatch { .. }));
}

// WORK_UNIT_CASE: 657/22
#[test]
fn case_22_expected_versus_observed_unknown_outcome() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("observed outcomes");
    assert_eq!(candidate.outcomes.len(), 2);
    assert!(candidate.outcomes.iter().all(|o| o.status == "observed"));
    let mut events = fixture.events.clone();
    events.events[0].outcomes[0].status = "expected".to_owned();
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect_err("expected status bound");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "evidence.material_preimage",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/23
#[test]
fn case_23_exact_duplicate_existing_episode_idempotent_replay() {
    let first = fixture();
    let first_candidate = reconstruct_episode_candidate(
        &first.input,
        &first.events,
        &first.snapshot,
        &first.existing,
        &first.policy,
    )
    .expect("first replay");
    assert_eq!(
        first_candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Duplicate
    );
    assert_eq!(
        first_candidate.overlap.disposition,
        OverlapDisposition::ExactReplay
    );
    let second = support::fixture();
    let second_candidate = reconstruct_episode_candidate(
        &second.input,
        &second.events,
        &second.snapshot,
        &second.existing,
        &second.policy,
    )
    .expect("second replay");
    assert_eq!(first_candidate.candidate_id, second_candidate.candidate_id);
    assert_eq!(
        first_candidate.whole_input_digest,
        second_candidate.whole_input_digest
    );
}

// WORK_UNIT_CASE: 657/24
#[test]
fn case_24_changed_same_episode_id_conflicts() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.pop();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("changed member conflict");
    assert_eq!(candidate.overlap.disposition, OverlapDisposition::Conflict);
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Conflict
    );
    let mut blocked_policy = fixture.policy.clone();
    blocked_policy.overlap_rule = eliot_dreamer_episode::OverlapRule::Block;
    blocked_policy.policy_digest = blocked_policy.computed_digest().expect("digest");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &blocked_policy,
    )
    .expect_err("blocked overlap");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "episode.overlap",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/25
#[test]
fn case_25_overlap_containment_adjacency_without_silent_merge() {
    let fixture = fixture();
    let mut adjacent = fixture.existing.clone();
    adjacent.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &adjacent,
        &fixture.policy,
    )
    .expect("adjacent");
    assert_eq!(candidate.overlap.disposition, OverlapDisposition::None);
    assert_eq!(candidate.events.len(), 2);
    let mut contained = fixture.existing.clone();
    contained.members.pop();
    let conflict = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &contained,
        &fixture.policy,
    )
    .expect("containment");
    assert_eq!(conflict.overlap.disposition, OverlapDisposition::Conflict);
    assert_eq!(conflict.events.len(), 2);
    assert_eq!(contained.members.len(), 1);
}

// WORK_UNIT_CASE: 657/26
#[test]
fn case_26_late_event_extension_reopen_with_exact_predecessor() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.predecessor_episode_id = Some("episode-0".to_owned());
    let mut cleared = existing.clone();
    cleared.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("predecessor retained");
    assert_eq!(
        candidate.existing.predecessor_episode_id.as_deref(),
        Some("episode-0")
    );
    assert_eq!(candidate.rollback.episode_id, "episode-1");
    candidate
        .validate()
        .expect("predecessor candidate validates");
}

// WORK_UNIT_CASE: 657/27
#[test]
fn case_27_wrong_predecessor_stale_episode_snapshot() {
    let fixture = fixture();
    let mut stale = fixture.existing.clone();
    stale.revision = eliot_contracts::TaskRevision::new(2).expect("revision");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &stale,
        &fixture.policy,
    )
    .expect_err("stale revision");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "existing.target_binding",
            ..
        }
    ));
    let mut wrong_id = fixture.existing.clone();
    wrong_id.episode_id = "other-episode".to_owned();
    let error2 = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &wrong_id,
        &fixture.policy,
    )
    .expect_err("wrong episode id");
    assert!(matches!(
        error2,
        ContractViolation::BindingMismatch {
            field: "episode.id",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/28
#[test]
fn case_28_structure_repair_handoff_without_execution() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.pop();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("repair handoff");
    assert_eq!(
        candidate.disposition,
        eliot_dreamer_contracts::CandidateDisposition::Conflict
    );
    assert_eq!(candidate.events.len(), 2);
    assert_eq!(existing.members.len(), 1);
    assert_eq!(candidate.existing.members.len(), 1);
    assert!(candidate.coverage.gaps.is_empty());
}

// WORK_UNIT_CASE: 657/29
#[test]
fn case_29_rollback_and_raw_history_preservation() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("rollback");
    assert_eq!(candidate.rollback.episode_id, "episode-1");
    assert_eq!(candidate.rollback.source_fence, fixture.policy.state_fence);
    let mut retained = candidate.rollback.retained_event_ids.clone();
    retained.sort();
    assert_eq!(
        retained,
        vec!["event-end".to_owned(), "event-start".to_owned()]
    );
    assert_eq!(candidate.source.members.len(), 3);
    assert_eq!(candidate.source.members, fixture.snapshot.source.members);
    assert_eq!(
        candidate.rollback.note,
        "drop this candidate and retain the immutable source closure"
    );
}

// WORK_UNIT_CASE: 657/30
#[test]
fn case_30_seven_preservation_dimensions_upstream_receipt_without_a05() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("preservation");
    assert_eq!(candidate.preservation.verdicts.len(), 7);
    candidate
        .preservation
        .overall()
        .expect("all dimensions pass");
    candidate
        .preservation
        .validate()
        .expect("preservation validates");
    assert_eq!(candidate.handler_id, "eliot-dreamer-episode");
    assert_eq!(candidate.handler_result.handler_id, "eliot-dreamer-episode");
}

// WORK_UNIT_CASE: 657/31
#[test]
fn case_31_partial_budget_deadline_cancel() {
    let fixture = fixture();
    let mut cancelled = fixture.policy.clone();
    cancelled.cancellation_requested = true;
    cancelled.policy_digest = cancelled.computed_digest().expect("digest");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &cancelled,
    )
    .expect_err("cancelled");
    assert!(matches!(
        error,
        ContractViolation::Budget {
            dimension: "episode.cancellation",
            ..
        }
    ));
    let fixture2 = support::fixture();
    let mut deadline = fixture2.policy.clone();
    deadline.deadline_ms = Some(100);
    deadline.now_ms = Some(100);
    deadline.policy_digest = deadline.computed_digest().expect("digest");
    let error2 = reconstruct_episode_candidate(
        &fixture2.input,
        &fixture2.events,
        &fixture2.snapshot,
        &fixture2.existing,
        &deadline,
    )
    .expect_err("deadline");
    assert!(matches!(
        error2,
        ContractViolation::Budget {
            dimension: "episode.deadline",
            ..
        }
    ));
    let fixture3 = support::fixture();
    let mut tiny_output = fixture3.policy.clone();
    tiny_output.max_output_bytes = 1;
    tiny_output.policy_digest = tiny_output.computed_digest().expect("digest");
    let error3 = reconstruct_episode_candidate(
        &fixture3.input,
        &fixture3.events,
        &fixture3.snapshot,
        &fixture3.existing,
        &tiny_output,
    )
    .expect_err("output bound");
    assert!(matches!(
        error3,
        ContractViolation::Budget {
            dimension: "episode.output_bytes",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/32
#[test]
fn case_32_privacy_authority_effect_proof_escalation() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("authority ceiling");
    let authority = candidate
        .preservation
        .verdicts
        .iter()
        .find(|v| v.dimension == eliot_dreamer_contracts::PreservationDimension::AuthorityCeiling)
        .expect("authority dimension");
    assert!(authority.passed);
    assert_eq!(
        candidate.kind,
        eliot_dreamer_contracts::curation::CurationKind::Episode
    );
    let mut events = fixture.events.clone();
    events.events[0]
        .core
        .privacy_retention_and_disclosure
        .disclosure_class = "escalated-public".to_owned();
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect_err("privacy escalation bound");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "evidence.material_preimage",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/33
#[test]
fn case_33_every_event_source_participant_gap_neighborhood_output_work_bound() {
    let fixture = fixture();
    let mut small_events = fixture.policy.clone();
    small_events.max_events = 1;
    small_events.policy_digest = small_events.computed_digest().expect("digest");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &small_events,
    )
    .expect_err("event bound");
    assert!(matches!(error, ContractViolation::Budget { .. }));
    let fixture2 = support::fixture();
    let mut small_participants = fixture2.policy.clone();
    small_participants.max_participants = 1;
    small_participants.policy_digest = small_participants.computed_digest().expect("digest");
    let error2 = reconstruct_episode_candidate(
        &fixture2.input,
        &fixture2.events,
        &fixture2.snapshot,
        &fixture2.existing,
        &small_participants,
    )
    .expect_err("participant bound");
    assert!(matches!(error2, ContractViolation::Budget { .. }));
    let fixture3 = support::fixture();
    let mut small_input = fixture3.policy.clone();
    small_input.max_input_bytes = 1;
    small_input.policy_digest = small_input.computed_digest().expect("digest");
    let error3 = reconstruct_episode_candidate(
        &fixture3.input,
        &fixture3.events,
        &fixture3.snapshot,
        &fixture3.existing,
        &small_input,
    )
    .expect_err("input bound");
    assert!(matches!(error3, ContractViolation::Budget { .. }));
    let fixture4 = support::fixture();
    let mut small_work = fixture4.policy.clone();
    small_work.max_work = 1;
    small_work.policy_digest = small_work.computed_digest().expect("digest");
    let error4 = reconstruct_episode_candidate(
        &fixture4.input,
        &fixture4.events,
        &fixture4.snapshot,
        &fixture4.existing,
        &small_work,
    )
    .expect_err("work bound");
    assert!(matches!(error4, ContractViolation::Budget { .. }));
}

// WORK_UNIT_CASE: 657/34
#[test]
fn case_34_input_permutations_stable_while_semantic_time_order_preserved() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let forward = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("forward");
    let mut swapped = fixture.events.clone();
    swapped.events.reverse();
    let reversed = reconstruct_episode_candidate(
        &fixture.input,
        &swapped,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("reversed");
    assert_eq!(forward.status, reversed.status);
    assert_eq!(forward.disposition, reversed.disposition);
    let mut forward_ids: Vec<_> = forward
        .events
        .iter()
        .map(|e| e.core.event_id_and_time.event_id.clone())
        .collect();
    let mut reversed_ids: Vec<_> = reversed
        .events
        .iter()
        .map(|e| e.core.event_id_and_time.event_id.clone())
        .collect();
    forward_ids.sort();
    reversed_ids.sort();
    assert_eq!(forward_ids, reversed_ids);
}

// WORK_UNIT_CASE: 657/35
#[test]
fn case_35_replay_and_same_id_changed_request_policy() {
    let first = fixture();
    let mut cleared = first.existing.clone();
    cleared.members.clear();
    let a = reconstruct_episode_candidate(
        &first.input,
        &first.events,
        &first.snapshot,
        &cleared,
        &first.policy,
    )
    .expect("first");
    let second = support::fixture();
    let mut cleared2 = second.existing.clone();
    cleared2.members.clear();
    let b = reconstruct_episode_candidate(
        &second.input,
        &second.events,
        &second.snapshot,
        &cleared2,
        &second.policy,
    )
    .expect("replay");
    assert_eq!(a.candidate_id, b.candidate_id);
    let mut changed_policy = first.policy.clone();
    changed_policy.max_events = 16;
    changed_policy.policy_digest = changed_policy.computed_digest().expect("digest");
    let c = reconstruct_episode_candidate(
        &first.input,
        &first.events,
        &first.snapshot,
        &cleared,
        &changed_policy,
    )
    .expect("changed policy");
    assert_ne!(a.candidate_id, c.candidate_id);
    assert_ne!(a.whole_input_digest, c.whole_input_digest);
    let mut stale_policy = first.policy.clone();
    stale_policy.max_events = 16;
    let error = reconstruct_episode_candidate(
        &first.input,
        &first.events,
        &first.snapshot,
        &cleared,
        &stale_policy,
    )
    .expect_err("stale policy digest");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "episode.policy_digest",
            ..
        }
    ));
}

// WORK_UNIT_CASE: 657/36
#[test]
fn case_36_bounded_malformed_property_input_never_panics() {
    let fixture = fixture();
    let mut empty = fixture.events.clone();
    empty.events.clear();
    assert!(
        reconstruct_episode_candidate(
            &fixture.input,
            &empty,
            &fixture.snapshot,
            &fixture.existing,
            &fixture.policy,
        )
        .is_err()
    );
    let mut bad_digest = fixture.events.clone();
    bad_digest.events[0].event_binding.material_digest = "not-hex".to_owned();
    assert!(
        reconstruct_episode_candidate(
            &fixture.input,
            &bad_digest,
            &fixture.snapshot,
            &fixture.existing,
            &fixture.policy,
        )
        .is_err()
    );
    let mut no_handles = fixture.events.clone();
    no_handles.events[0].event_binding.evidence_handles.clear();
    assert!(
        reconstruct_episode_candidate(
            &fixture.input,
            &no_handles,
            &fixture.snapshot,
            &fixture.existing,
            &fixture.policy,
        )
        .is_err()
    );
    let mut bad_policy = fixture.policy.clone();
    bad_policy.max_events = 0;
    assert!(
        reconstruct_episode_candidate(
            &fixture.input,
            &fixture.events,
            &fixture.snapshot,
            &fixture.existing,
            &bad_policy,
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 657/37
#[test]
fn case_37_every_observed_included_event_at_exact_frozen_manifest_revision() {
    let fixture = fixture();
    let mut events = fixture.events.clone();
    events.events[0].source_revision = eliot_contracts::TaskRevision::new(2).expect("revision");
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("revision drift");
    assert!(matches!(
        error,
        ContractViolation::BindingMismatch {
            field: "event.content_binding",
            ..
        }
    ));
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("exact revision");
    for event in &candidate.events {
        let member = candidate
            .source
            .members
            .iter()
            .find(|m| m.member_id == event.source_member_id)
            .expect("member");
        assert_eq!(member.revision, event.source_revision);
        assert_eq!(member.content_digest, event.source_content_digest);
    }
}

// WORK_UNIT_CASE: 657/38
#[test]
fn case_38_every_denominator_event_has_exactly_one_disposition() {
    let fixture = fixture();
    let declared: std::collections::BTreeSet<_> = fixture
        .events
        .denominator
        .declared_member_ids
        .iter()
        .map(|m| m.as_str().to_owned())
        .collect();
    let receipt: std::collections::BTreeSet<_> = fixture
        .snapshot
        .enumeration
        .members
        .iter()
        .map(|m| m.member.as_str().to_owned())
        .chain(
            fixture
                .snapshot
                .enumeration
                .omissions
                .iter()
                .map(|m| m.member.as_str().to_owned()),
        )
        .collect();
    assert_eq!(declared, receipt);
    let mut broken = fixture.snapshot.clone();
    broken.enumeration.members.pop();
    let error = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &broken,
        &fixture.existing,
        &fixture.policy,
    )
    .expect_err("denominator gap");
    assert!(matches!(error, ContractViolation::BindingMismatch { .. }));
}

// WORK_UNIT_CASE: 657/39
#[test]
fn case_39_closed_complete_implies_full_coverage_and_exact_start_end() {
    let mut fixture = fixture();
    fixture.existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect("closed complete");
    assert_eq!(candidate.status, EpisodeStatus::Closed);
    assert!(candidate.coverage.gaps.is_empty());
    assert!(matches!(
        candidate.event_denominator.kind,
        eliot_epistemic_contracts::DenominatorKind::CompleteScope
    ));
    assert!(candidate.event_receipt.is_terminal());
    assert!(candidate.event_receipt.omissions.is_empty());
    assert_eq!(candidate.boundary.start_event_id, "event-start");
    assert_eq!(
        candidate.boundary.end_event_id.as_deref(),
        Some("event-end")
    );
    assert!(candidate.chronology.iter().all(|l| matches!(
        l.relation,
        ChronologyRelation::Before | ChronologyRelation::After
    )));
    candidate.validate().expect("closed validates");
}

// WORK_UNIT_CASE: 657/40
#[test]
fn case_40_no_causal_relation_solely_from_temporal_order() {
    let mut fixture = fixture();
    fixture.existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &fixture.existing,
        &fixture.policy,
    )
    .expect("temporal order");
    let link = candidate.chronology.first().expect("link");
    assert_eq!(link.relation, ChronologyRelation::Before);
    assert_eq!(link.support.len(), 2);
    for event in &candidate.events {
        assert!(
            event.source_member_id.as_str() == "event-start"
                || event.source_member_id.as_str() == "event-end"
        );
    }
    let near = support::fixture_with_modes(false, false, true);
    let mut near_existing = near.existing.clone();
    near_existing.members.clear();
    let near_candidate = reconstruct_episode_candidate(
        &near.input,
        &near.events,
        &near.snapshot,
        &near_existing,
        &near.policy,
    )
    .expect("no causal from proximity");
    assert_eq!(
        near_candidate.chronology[0].relation,
        ChronologyRelation::Incomparable
    );
}

// WORK_UNIT_CASE: 657/41
#[test]
fn case_41_changed_event_source_boundary_policy_invalidates_digest() {
    let base = fixture();
    let mut cleared = base.existing.clone();
    cleared.members.clear();
    let a = reconstruct_episode_candidate(
        &base.input,
        &base.events,
        &base.snapshot,
        &cleared,
        &base.policy,
    )
    .expect("base");
    let mut open_policy = base.policy.clone();
    open_policy.end_event_id = None;
    open_policy.policy_digest = open_policy.computed_digest().expect("digest");
    let b = reconstruct_episode_candidate(
        &base.input,
        &base.events,
        &base.snapshot,
        &cleared,
        &open_policy,
    )
    .expect("changed boundary");
    assert_ne!(a.whole_input_digest, b.whole_input_digest);
    assert_ne!(a.candidate_id, b.candidate_id);
    let mut partial_snapshot = base.snapshot.clone();
    partial_snapshot.source.denominator.coverage =
        eliot_memory_curation_contracts::DenominatorCoverage::Partial;
    partial_snapshot.coverage.denominator.coverage =
        eliot_memory_curation_contracts::DenominatorCoverage::Partial;
    partial_snapshot.coverage.digest = partial_snapshot
        .coverage
        .computed_digest()
        .expect("coverage digest");
    partial_snapshot.source.availability =
        eliot_memory_curation_contracts::SourceAvailability::Partial;
    let c = reconstruct_episode_candidate(
        &base.input,
        &base.events,
        &partial_snapshot,
        &cleared,
        &base.policy,
    )
    .expect("changed source");
    assert_ne!(a.whole_input_digest, c.whole_input_digest);
    let mut changed_events = base.events.clone();
    changed_events.events[0].source_content_digest = support::digest_value("changed");
    assert!(
        reconstruct_episode_candidate(
            &base.input,
            &changed_events,
            &base.snapshot,
            &cleared,
            &base.policy,
        )
        .is_err()
    );
}

// WORK_UNIT_CASE: 657/42
#[test]
fn case_42_no_source_query_cursor_mutation_merge_provider_effect_finish() {
    let fixture = fixture();
    let mut existing = fixture.existing.clone();
    existing.members.clear();
    let candidate = reconstruct_episode_candidate(
        &fixture.input,
        &fixture.events,
        &fixture.snapshot,
        &existing,
        &fixture.policy,
    )
    .expect("pure candidate");
    assert_eq!(candidate.source, fixture.snapshot.source);
    assert_eq!(candidate.existing, existing);
    assert_eq!(
        candidate.event_denominator,
        fixture.snapshot.event_denominator
    );
    assert_eq!(candidate.event_receipt, fixture.snapshot.enumeration);
    assert!(!candidate.source.page.has_more);
    assert!(fixture.snapshot.coverage.next_cursor.is_none());
    assert_eq!(
        candidate.handler_result.kind,
        eliot_dreamer_contracts::curation::CurationKind::Episode
    );
    assert_eq!(candidate.handler_id, "eliot-dreamer-episode");
    assert_eq!(candidate.events.len(), fixture.events.events.len());
    candidate.validate().expect("pure candidate validates");
}
