//! Pure Episode reconstruction phases.

use crate::input::{
    BoundaryRule, EpisodePolicy, EventAndSourceSnapshot, ExistingEpisodeSnapshot, GroundedEvent,
    GroundedEventSet, MAX_SERIALIZED_INPUT, ValidatedCurationInput, capped_serialized_len,
    event_time_point,
};
use crate::result::{
    ChronologyLink, ChronologyRelation, EpisodeBoundary, EpisodeCandidate, EpisodeCoverage,
    EpisodeGap, EpisodeRollback, EpisodeStatus, OverlapAssessment, OverlapDisposition,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    CandidateDisposition, ContractViolation, CurationFamily, CurationKind, PreservationDimension,
    TypedCurationHandlerResult, ValidatedCurationItem, canonical_bytes, digest_hex,
};
use eliot_epistemic_contracts::MemberDisposition as ReceiptDisposition;
use eliot_memory_curation_contracts::MemberDisposition;
use eliot_memory_curation_contracts::{SourceAvailability, SourceMemberKind};
use serde::Serialize;
use std::collections::BTreeSet;

/// Reconstructs one inert Episode candidate from five validated, immutable inputs.
pub fn reconstruct_episode_candidate(
    validated_curation_input: &ValidatedCurationInput<'_>,
    grounded_event_set: &GroundedEventSet,
    event_and_source_snapshot: &EventAndSourceSnapshot,
    existing_episode_snapshot: &ExistingEpisodeSnapshot,
    episode_policy: &EpisodePolicy,
) -> Result<EpisodeCandidate, ContractViolation> {
    whole_input_preflight(
        validated_curation_input,
        grounded_event_set,
        event_and_source_snapshot,
        existing_episode_snapshot,
        episode_policy,
    )?;
    capacity_preflight(
        grounded_event_set,
        event_and_source_snapshot,
        existing_episode_snapshot,
        episode_policy,
        validated_curation_input,
    )?;
    admission_phase(validated_curation_input)?;
    policy_phase(validated_curation_input, episode_policy)?;
    source_phase(
        validated_curation_input,
        grounded_event_set,
        event_and_source_snapshot,
    )?;
    existing_episode_snapshot.validate()?;
    if existing_episode_snapshot.state_fence != episode_policy.state_fence {
        return Err(ContractViolation::BindingMismatch {
            field: "existing.state_fence",
            reason: "existing Episode is from a different fence".to_owned(),
        });
    }
    let episode = episode_name(validated_curation_input)?;
    if existing_episode_snapshot.episode_id != episode {
        return Err(ContractViolation::BindingMismatch {
            field: "episode.id",
            reason: "existing Episode identity differs from admitted payload".to_owned(),
        });
    }
    let target_member = event_and_source_snapshot
        .source
        .members
        .iter()
        .find(|member| member.member_id.as_str() == episode)
        .ok_or(ContractViolation::BindingMismatch {
            field: "episode.target_member",
            reason: "admitted Episode target is absent from the source snapshot".to_owned(),
        })?;
    if existing_episode_snapshot.revision != target_member.revision
        || existing_episode_snapshot.content_digest != target_member.content_digest
    {
        return Err(ContractViolation::BindingMismatch {
            field: "existing.target_binding",
            reason: "prior Episode is not bound to the admitted changed target revision".to_owned(),
        });
    }
    grounded_event_set.validate()?;
    if grounded_event_set.events.len() > episode_policy.max_events {
        return Err(ContractViolation::Budget {
            dimension: "episode.events",
            reason: "event count exceeds policy".to_owned(),
        });
    }
    planned_output_preflight(
        grounded_event_set,
        event_and_source_snapshot,
        existing_episode_snapshot,
        episode_policy,
    )?;

    let semantic = semantic_phase(
        grounded_event_set,
        event_and_source_snapshot,
        existing_episode_snapshot,
        episode_policy,
        validated_curation_input,
    )?;
    finalize_candidate(
        validated_curation_input,
        grounded_event_set,
        event_and_source_snapshot,
        existing_episode_snapshot,
        episode_policy,
        episode,
        semantic,
    )
}

struct SemanticAssembly {
    events: Vec<GroundedEvent>,
    boundary: EpisodeBoundary,
    chronology: Vec<ChronologyLink>,
    overlap: OverlapAssessment,
    participants: Vec<crate::input::EpisodeParticipant>,
    outcomes: Vec<crate::input::EpisodeOutcome>,
    coverage: EpisodeCoverage,
    preservation: eliot_dreamer_contracts::PreservationReport,
    disposition: CandidateDisposition,
    status: EpisodeStatus,
    rollback: EpisodeRollback,
}

fn semantic_phase(
    grounded_event_set: &GroundedEventSet,
    source_snapshot: &EventAndSourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    policy: &EpisodePolicy,
    input: &ValidatedCurationInput<'_>,
) -> Result<SemanticAssembly, ContractViolation> {
    let events = join_events(grounded_event_set, source_snapshot, input)?;
    let boundary = boundary_phase(&events, policy)?;
    let chronology = chronology_phase(&events)?;
    let overlap = overlap_phase(&events, existing, &boundary, policy)?;
    let gaps = coverage_gaps(grounded_event_set, source_snapshot);
    if gaps.len() > policy.max_gaps {
        return Err(ContractViolation::Budget {
            dimension: "episode.gaps",
            reason: "gap count exceeds policy".to_owned(),
        });
    }
    let participants = events
        .iter()
        .flat_map(|event| event.participants.iter().cloned())
        .collect::<Vec<_>>();
    let outcomes = events
        .iter()
        .flat_map(|event| event.outcomes.iter().cloned())
        .collect::<Vec<_>>();
    let coverage = EpisodeCoverage {
        event_denominator_size: grounded_event_set.denominator.total_members,
        observed_events: grounded_event_set.events.len() as u64,
        gaps,
        source_availability: source_snapshot.source.availability,
    };
    let preservation = preservation_phase(
        &coverage,
        &chronology,
        &overlap,
        &events,
        &source_snapshot.source,
        existing,
        admission_closure(input),
    );
    let disposition = disposition_for(&coverage, &chronology, &overlap, &preservation);
    let status = status_for(&coverage, &chronology, &overlap, &boundary);
    let rollback = EpisodeRollback {
        source_fence: source_snapshot.source.identity.state_fence.clone(),
        episode_id: existing.episode_id.clone(),
        retained_event_ids: events
            .iter()
            .map(|event| event.core.event_id_and_time.event_id.clone())
            .collect(),
        retained_source_member_ids: events
            .iter()
            .map(|event| event.source_member_id.as_str().to_owned())
            .collect(),
        note: "drop this candidate and retain the immutable source closure".to_owned(),
    };
    Ok(SemanticAssembly {
        events,
        boundary,
        chronology,
        overlap,
        participants,
        outcomes,
        coverage,
        preservation,
        disposition,
        status,
        rollback,
    })
}

fn admission_phase(input: &ValidatedCurationInput<'_>) -> Result<(), ContractViolation> {
    input.accept()
}

fn finalize_candidate(
    input: &ValidatedCurationInput<'_>,
    grounded_event_set: &GroundedEventSet,
    source_snapshot: &EventAndSourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    policy: &EpisodePolicy,
    episode: String,
    semantic: SemanticAssembly,
) -> Result<EpisodeCandidate, ContractViolation> {
    let admission_item_digest = input.item.item_digest(input.ctx.grounded)?;
    let admission_receipt_digest = digest_hex(&canonical_bytes(input.ctx.receipt)?);
    let whole_input_digest =
        whole_input_digest(input, grounded_event_set, source_snapshot, existing, policy)?;
    let handler_request_digest = digest_hex(&canonical_bytes(input.ctx.request)?);
    let handler_result = TypedCurationHandlerResult {
        request_id: input.ctx.request.request_id.clone(),
        kind: CurationKind::Episode,
        family: CurationFamily::Episode,
        disposition: semantic.disposition,
        handler_id: "eliot-dreamer-episode".to_owned(),
        request_digest: handler_request_digest.clone(),
        result_digest: "0".repeat(64),
    };
    let mut candidate = EpisodeCandidate {
        candidate_id: String::new(),
        request_id: input.ctx.request.request_id.clone(),
        receipt_id: input.ctx.request.receipt_id.clone(),
        job_id: input.ctx.job.canonical_id(),
        task_id: input.ctx.job.task_id.clone(),
        scope_id: input.ctx.job.scope_id.clone(),
        state_fence: policy.state_fence.clone(),
        policy_id: policy.policy_id.clone(),
        policy_digest: policy.policy_digest.clone(),
        handler_id: "eliot-dreamer-episode".to_owned(),
        handler_request_digest,
        admission_item_digest,
        admission_receipt_digest,
        screen_coverage_digest: source_snapshot.coverage.digest.to_string(),
        whole_input_digest,
        kind: CurationKind::Episode,
        family: CurationFamily::Episode,
        episode,
        status: semantic.status,
        disposition: semantic.disposition,
        boundary: semantic.boundary,
        events: semantic.events,
        participants: semantic.participants,
        outcomes: semantic.outcomes,
        chronology: semantic.chronology,
        coverage: semantic.coverage,
        overlap: semantic.overlap,
        rollback: semantic.rollback,
        preservation: semantic.preservation,
        source: source_snapshot.source.clone(),
        event_denominator: source_snapshot.event_denominator.clone(),
        event_receipt: source_snapshot.enumeration.clone(),
        existing: existing.clone(),
        handler_result,
        result_digest: String::new(),
    };
    candidate.candidate_id = candidate.computed_identity()?;
    candidate.result_digest = candidate.computed_digest()?;
    candidate
        .handler_result
        .result_digest
        .clone_from(&candidate.result_digest);
    capped_serialized_len(&candidate, policy.max_output_bytes).map_err(|reason| {
        ContractViolation::Budget {
            dimension: "episode.output_bytes",
            reason,
        }
    })?;
    candidate.validate()?;
    Ok(candidate)
}

#[derive(Serialize)]
struct WholeInputPreimage<'a> {
    item: &'a ValidatedCurationItem,
    job: &'a eliot_dreamer_contracts::DreamJobInput,
    bundle: &'a eliot_dreamer_contracts::DreamInputBundle,
    receipt: &'a eliot_dreamer_contracts::ValidationReceipt,
    screen: &'a eliot_dreamer_contracts::ScreenBinding,
    grounded: &'a eliot_dreamer_contracts::GroundedDreamDraft,
    request: &'a eliot_dreamer_contracts::TypedCurationHandlerRequest,
    usage: &'a eliot_dreamer_contracts::BudgetUsage,
    events: &'a GroundedEventSet,
    source: &'a EventAndSourceSnapshot,
    existing: &'a ExistingEpisodeSnapshot,
    policy: &'a EpisodePolicy,
}

#[derive(Serialize)]
struct PlannedOutputPreimage<'a> {
    events: &'a GroundedEventSet,
    source: &'a EventAndSourceSnapshot,
    existing: &'a ExistingEpisodeSnapshot,
    policy: &'a EpisodePolicy,
}

fn planned_output_preflight(
    events: &GroundedEventSet,
    source: &EventAndSourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    policy: &EpisodePolicy,
) -> Result<(), ContractViolation> {
    let plan = PlannedOutputPreimage {
        events,
        source,
        existing,
        policy,
    };
    capped_serialized_len(&plan, policy.max_output_bytes).map_err(|reason| {
        ContractViolation::Budget {
            dimension: "episode.output_bytes",
            reason,
        }
    })?;
    Ok(())
}

fn whole_input_preflight(
    input: &ValidatedCurationInput<'_>,
    events: &GroundedEventSet,
    source: &EventAndSourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    policy: &EpisodePolicy,
) -> Result<(), ContractViolation> {
    let cap = usize::try_from(policy.max_input_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_SERIALIZED_INPUT);
    let preimage = WholeInputPreimage {
        item: input.item,
        job: input.ctx.job,
        bundle: input.ctx.bundle,
        receipt: input.ctx.receipt,
        screen: input.ctx.screen,
        grounded: input.ctx.grounded,
        request: input.ctx.request,
        usage: input.ctx.usage,
        events,
        source,
        existing,
        policy,
    };
    capped_serialized_len(&preimage, cap).map_err(|reason| ContractViolation::Budget {
        dimension: "episode.input_bytes",
        reason,
    })?;
    Ok(())
}

fn whole_input_digest(
    input: &ValidatedCurationInput<'_>,
    events: &GroundedEventSet,
    source: &EventAndSourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    policy: &EpisodePolicy,
) -> Result<String, ContractViolation> {
    let preimage = WholeInputPreimage {
        item: input.item,
        job: input.ctx.job,
        bundle: input.ctx.bundle,
        receipt: input.ctx.receipt,
        screen: input.ctx.screen,
        grounded: input.ctx.grounded,
        request: input.ctx.request,
        usage: input.ctx.usage,
        events,
        source,
        existing,
        policy,
    };
    capped_serialized_len(&preimage, MAX_SERIALIZED_INPUT).map_err(|reason| {
        ContractViolation::Budget {
            dimension: "episode.input_bytes",
            reason,
        }
    })?;
    Ok(digest_hex(&canonical_bytes(&preimage)?))
}

fn capacity_preflight(
    events: &GroundedEventSet,
    snapshot: &EventAndSourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    policy: &EpisodePolicy,
    input: &ValidatedCurationInput<'_>,
) -> Result<(), ContractViolation> {
    if events.events.len() > policy.max_events
        || events.events.len() > policy.max_source_members
        || snapshot.source.members.len() > policy.max_source_members
    {
        return Err(ContractViolation::Budget {
            dimension: "episode.source_members",
            reason: "source/event cardinality exceeds policy".to_owned(),
        });
    }
    if events.denominator.declared_member_ids.len() > policy.max_source_members
        || snapshot.coverage.members.len() > policy.max_source_members
        || snapshot.enumeration.members.len() + snapshot.enumeration.omissions.len()
            > policy.max_source_members
    {
        return Err(ContractViolation::Budget {
            dimension: "episode.coverage",
            reason: "coverage cardinality exceeds policy".to_owned(),
        });
    }
    let gap_count = gap_count(events, snapshot)?;
    if gap_count > policy.max_gaps {
        return Err(ContractViolation::Budget {
            dimension: "episode.gaps",
            reason: "planned gap count exceeds policy".to_owned(),
        });
    }
    let participant_count = events
        .events
        .iter()
        .map(|event| event.participants.len())
        .try_fold(0usize, usize::checked_add)
        .ok_or(ContractViolation::Budget {
            dimension: "episode.participants",
            reason: "participant count overflow".to_owned(),
        })?;
    if participant_count > policy.max_participants {
        return Err(ContractViolation::Budget {
            dimension: "episode.participants",
            reason: "participant count exceeds policy".to_owned(),
        });
    }
    let outcome_count = events
        .events
        .iter()
        .map(|event| event.outcomes.len())
        .try_fold(0usize, usize::checked_add)
        .ok_or(ContractViolation::Budget {
            dimension: "episode.outcomes",
            reason: "outcome count overflow".to_owned(),
        })?;
    if outcome_count > crate::input::MAX_OUTCOMES {
        return Err(ContractViolation::Budget {
            dimension: "episode.outcomes",
            reason: "outcome count exceeds class ceiling".to_owned(),
        });
    }
    if existing.members.len() > policy.max_events {
        return Err(ContractViolation::Budget {
            dimension: "episode.neighborhood",
            reason: "existing Episode neighborhood exceeds policy".to_owned(),
        });
    }
    phase_work_preflight(
        events,
        snapshot,
        existing,
        policy,
        input,
        CapacityCounts {
            participants: participant_count,
            outcomes: outcome_count,
            gaps: gap_count,
        },
    )?;
    let input_bytes = input
        .ctx
        .bundle
        .materials
        .iter()
        .map(|material| material.bytes)
        .try_fold(0_u64, u64::checked_add)
        .ok_or(ContractViolation::Budget {
            dimension: "episode.input_bytes",
            reason: "input byte sum overflow".to_owned(),
        })?;
    if input_bytes > policy.max_input_bytes {
        return Err(ContractViolation::Budget {
            dimension: "episode.input_bytes",
            reason: "accepted materials exceed Episode policy".to_owned(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct CapacityCounts {
    participants: usize,
    outcomes: usize,
    gaps: usize,
}

fn phase_work_preflight(
    events: &GroundedEventSet,
    snapshot: &EventAndSourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    policy: &EpisodePolicy,
    input: &ValidatedCurationInput<'_>,
    counts: CapacityCounts,
) -> Result<(), ContractViolation> {
    let pair_count = events
        .events
        .len()
        .checked_mul(
            events
                .events
                .len()
                .checked_sub(1)
                .ok_or(ContractViolation::Budget {
                    dimension: "episode.work",
                    reason: "chronology cardinality underflow".to_owned(),
                })?,
        )
        .ok_or(ContractViolation::Budget {
            dimension: "episode.work",
            reason: "chronology work bound overflow".to_owned(),
        })?
        / 2;
    if pair_count > policy.max_neighborhood
        || u64::try_from(pair_count).unwrap_or(u64::MAX) > policy.max_work
    {
        return Err(ContractViolation::Budget {
            dimension: "episode.work",
            reason: "chronology neighborhood exceeds policy".to_owned(),
        });
    }
    let scan_count = snapshot
        .enumeration
        .members
        .len()
        .checked_add(snapshot.enumeration.omissions.len())
        .and_then(|value| value.checked_add(input.ctx.bundle.materials.len()))
        .and_then(|value| value.checked_add(snapshot.coverage.members.len()))
        .and_then(|value| value.checked_add(1))
        .ok_or(ContractViolation::Budget {
            dimension: "episode.work",
            reason: "owner scan count overflow".to_owned(),
        })?;
    let work = events
        .events
        .len()
        .checked_add(counts.participants)
        .and_then(|value| value.checked_add(counts.outcomes))
        .and_then(|value| value.checked_add(snapshot.source.members.len()))
        .and_then(|value| value.checked_add(existing.members.len()))
        .and_then(|value| value.checked_add(counts.gaps))
        .and_then(|value| value.checked_add(pair_count))
        .and_then(|value| value.checked_add(scan_count))
        .ok_or(ContractViolation::Budget {
            dimension: "episode.work",
            reason: "cumulative phase work overflow".to_owned(),
        })?;
    if u64::try_from(work).unwrap_or(u64::MAX) > policy.max_work {
        return Err(ContractViolation::Budget {
            dimension: "episode.work",
            reason: "cumulative phase work exceeds policy".to_owned(),
        });
    }
    Ok(())
}

fn gap_count(
    events: &GroundedEventSet,
    snapshot: &EventAndSourceSnapshot,
) -> Result<usize, ContractViolation> {
    let present: BTreeSet<_> = events
        .events
        .iter()
        .map(|event| event.source_member_id.clone())
        .collect();
    let mut missing = events
        .denominator
        .declared_member_ids
        .iter()
        .filter(|member| !present.contains(*member))
        .count();
    if snapshot.source.availability != SourceAvailability::Available {
        missing = missing.checked_add(1).ok_or(ContractViolation::Budget {
            dimension: "episode.gaps",
            reason: "gap count overflow".to_owned(),
        })?;
    }
    Ok(missing)
}

fn policy_phase(
    input: &ValidatedCurationInput<'_>,
    policy: &EpisodePolicy,
) -> Result<(), ContractViolation> {
    policy.validate()?;
    if policy.policy_digest != policy.computed_digest()? {
        return Err(ContractViolation::BindingMismatch {
            field: "episode.policy_digest",
            reason: "policy digest does not cover the supplied policy fields".to_owned(),
        });
    }
    if input.ctx.job.policy_ref != policy.policy_id {
        return Err(ContractViolation::BindingMismatch {
            field: "episode.policy",
            reason: "policy is not the one admitted by the job".to_owned(),
        });
    }
    if input.ctx.job.state_fence != policy.state_fence {
        return Err(ContractViolation::BindingMismatch {
            field: "episode.policy_fence",
            reason: "policy fence differs from accepted job".to_owned(),
        });
    }
    if policy.cancellation_requested {
        return Err(ContractViolation::Budget {
            dimension: "episode.cancellation",
            reason: "Episode reconstruction was cancelled before semantic work".to_owned(),
        });
    }
    if let (Some(now), Some(deadline)) = (policy.now_ms, policy.deadline_ms)
        && now >= deadline
    {
        return Err(ContractViolation::Budget {
            dimension: "episode.deadline",
            reason: "Episode policy deadline elapsed".to_owned(),
        });
    }
    if input.ctx.usage.stu_used > policy.max_stu {
        return Err(ContractViolation::Budget {
            dimension: "episode.stu",
            reason: "observed STU exceeds Episode policy".to_owned(),
        });
    }
    let input_bytes = input
        .ctx
        .bundle
        .materials
        .iter()
        .map(|material| material.bytes)
        .try_fold(0_u64, u64::checked_add)
        .ok_or(ContractViolation::Budget {
            dimension: "episode.input_bytes",
            reason: "input byte sum overflow".to_owned(),
        })?;
    if input_bytes > policy.max_input_bytes {
        return Err(ContractViolation::Budget {
            dimension: "episode.input_bytes",
            reason: "accepted materials exceed Episode policy".to_owned(),
        });
    }
    Ok(())
}

fn source_phase(
    input: &ValidatedCurationInput<'_>,
    events: &GroundedEventSet,
    snapshot: &EventAndSourceSnapshot,
) -> Result<(), ContractViolation> {
    snapshot.validate(input.ctx)?;
    if events.denominator.is_complete()
        && events.events.len() != events.denominator.declared_member_ids.len()
    {
        return Err(ContractViolation::BindingMismatch {
            field: "event.denominator",
            reason: "complete event enumeration does not account for every declared member"
                .to_owned(),
        });
    }
    if events.events.len() > snapshot.source.members.len() {
        return Err(ContractViolation::BindingMismatch {
            field: "event.source_members",
            reason: "event set exceeds source snapshot members".to_owned(),
        });
    }
    validate_event_receipt(events, snapshot)?;
    for event in &events.events {
        validate_event_membership(input, event, snapshot)?;
    }
    if input.ctx.request.source_snapshot != snapshot.source.identity.snapshot_id.as_str()
        || input.ctx.request.source_revision != snapshot.source.identity.revision.to_string()
    {
        return Err(ContractViolation::BindingMismatch {
            field: "event.source_identity",
            reason: "source snapshot/revision differs from the admitted request".to_owned(),
        });
    }
    let targets = validated_targets(input)?;
    for target in targets {
        let member = snapshot
            .source
            .partition
            .changed_targets
            .iter()
            .find(|member| member.as_str() == target)
            .ok_or(ContractViolation::BindingMismatch {
                field: "episode.targets",
                reason: "A-03 target is not in the source changed-target partition".to_owned(),
            })?;
        let eligible = snapshot.coverage.members.iter().any(|coverage| {
            &coverage.member_id == member && coverage.disposition == MemberDisposition::Eligible
        });
        if !eligible {
            return Err(ContractViolation::ScreenIneligible(
                "Episode target lacks owner screening eligibility".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_event_membership(
    input: &ValidatedCurationInput<'_>,
    event: &GroundedEvent,
    snapshot: &EventAndSourceSnapshot,
) -> Result<(), ContractViolation> {
    let member =
        snapshot
            .member(&event.source_member_id)
            .ok_or(ContractViolation::BindingMismatch {
                field: "event.source_member_id",
                reason: "event member is absent from source snapshot".to_owned(),
            })?;
    if member.kind != SourceMemberKind::Observation {
        return Err(ContractViolation::BindingMismatch {
            field: "event.kind",
            reason: "ObservationEventCore requires an Observation source member".to_owned(),
        });
    }
    if event.core.affected_scope.work_scope.as_str() != snapshot.source.identity.scope.as_str()
        || event
            .core
            .affected_scope
            .task_ref
            .as_deref()
            .is_some_and(|task| task != input.ctx.job.task_id)
    {
        return Err(ContractViolation::BindingMismatch {
            field: "event.scope",
            reason: "event scope/task differs from accepted source/job".to_owned(),
        });
    }
    if event
        .core
        .evidence_and_raw_handles
        .iter()
        .any(|handle| !owner_evidence_contains(member, handle))
    {
        return Err(ContractViolation::BindingMismatch {
            field: "event.evidence_handles",
            reason: "raw event handle is outside exact member evidence union".to_owned(),
        });
    }
    if !snapshot
        .source
        .partition
        .immutable_references
        .contains(&event.source_member_id)
    {
        return Err(ContractViolation::BindingMismatch {
            field: "event.partition",
            reason: "raw event must remain an immutable source reference".to_owned(),
        });
    }
    let receipt = snapshot
        .enumeration
        .members
        .iter()
        .find(|outcome| outcome.member.as_str() == event.source_member_id.as_str());
    if receipt.is_none_or(|outcome| outcome.disposition != ReceiptDisposition::Observed) {
        return Err(ContractViolation::BindingMismatch {
            field: "event.enumeration.disposition",
            reason: "grounded event is not Observed by the event receipt".to_owned(),
        });
    }
    Ok(())
}

fn owner_evidence_contains(
    member: &eliot_memory_curation_contracts::SourceMember,
    handle: &str,
) -> bool {
    member
        .evidence
        .provenance
        .iter()
        .any(|value| value.as_str() == handle)
        || member
            .evidence
            .owner_status
            .iter()
            .any(|value| value.as_str() == handle)
        || member
            .evidence
            .protection
            .iter()
            .any(|value| value.as_str() == handle)
        || member
            .evidence
            .conflict
            .iter()
            .any(|value| value.as_str() == handle)
        || member
            .evidence
            .audit
            .iter()
            .any(|value| value.as_str() == handle)
}

fn admission_closure(input: &ValidatedCurationInput<'_>) -> bool {
    let ctx = input.ctx;
    input.item.task_id == ctx.job.task_id
        && input.item.scope_id == ctx.job.scope_id
        && input.item.state_fence == ctx.job.state_fence
        && ctx.request.task_id == ctx.job.task_id
        && ctx.request.scope_id == ctx.job.scope_id
        && ctx.request.state_fence == ctx.job.state_fence
        && ctx.receipt.task_id == ctx.job.task_id
        && ctx.receipt.scope_id == ctx.job.scope_id
        && ctx.receipt.state_fence == ctx.job.state_fence
        && ctx.screen.task_id == ctx.job.task_id
        && ctx.screen.scope_id == ctx.job.scope_id
        && ctx.screen.state_fence == ctx.job.state_fence
}

fn validate_event_receipt(
    events: &GroundedEventSet,
    snapshot: &EventAndSourceSnapshot,
) -> Result<(), ContractViolation> {
    if events.denominator.total_members != snapshot.enumeration.denominator_size {
        return Err(ContractViolation::BindingMismatch {
            field: "event.enumeration.denominator",
            reason: "event denominator differs from its coverage receipt".to_owned(),
        });
    }
    let owner_events: BTreeSet<_> = snapshot
        .event_denominator
        .members
        .iter()
        .map(eliot_contracts::ArtifactId::as_str)
        .collect();
    let declared_events: BTreeSet<_> = events
        .denominator
        .declared_member_ids
        .iter()
        .map(eliot_memory_curation_contracts::MemberId::as_str)
        .collect();
    let receipt_events: BTreeSet<_> = snapshot
        .enumeration
        .members
        .iter()
        .map(|member| member.member.as_str())
        .chain(
            snapshot
                .enumeration
                .omissions
                .iter()
                .map(|member| member.member.as_str()),
        )
        .collect();
    if declared_events != receipt_events {
        return Err(ContractViolation::BindingMismatch {
            field: "event.enumeration.members",
            reason: "event receipt does not account for exact event universe".to_owned(),
        });
    }
    if declared_events != owner_events {
        return Err(ContractViolation::BindingMismatch {
            field: "event.denominator_owner",
            reason: "event denominator differs from its owner denominator".to_owned(),
        });
    }
    if snapshot
        .enumeration
        .members
        .iter()
        .any(|outcome| outcome.role != "event")
    {
        return Err(ContractViolation::BindingMismatch {
            field: "event.enumeration.role",
            reason: "event receipt contains a non-event role".to_owned(),
        });
    }
    for event in &events.events {
        let receipt = snapshot
            .enumeration
            .members
            .iter()
            .find(|outcome| outcome.member.as_str() == event.source_member_id.as_str());
        if receipt.is_none_or(|outcome| outcome.disposition != ReceiptDisposition::Observed) {
            return Err(ContractViolation::BindingMismatch {
                field: "event.enumeration.disposition",
                reason: "grounded event is not Observed by the event receipt".to_owned(),
            });
        }
    }
    Ok(())
}

fn validated_targets(input: &ValidatedCurationInput<'_>) -> Result<Vec<String>, ContractViolation> {
    let facets = input.ctx.request.payload.facets();
    if facets.targets.len() != 1 {
        return Err(ContractViolation::BindingMismatch {
            field: "episode.targets",
            reason: "Episode requires exactly one changed target".to_owned(),
        });
    }
    Ok(facets.targets.clone())
}

fn episode_name(input: &ValidatedCurationInput<'_>) -> Result<String, ContractViolation> {
    match &input.ctx.request.payload {
        eliot_dreamer_contracts::CurationPayload::Episode(payload) => Ok(payload.episode.clone()),
        _ => Err(ContractViolation::KindPayload(
            "Episode handler received a non-Episode payload".to_owned(),
        )),
    }
}

fn join_events<'a>(
    events: &'a GroundedEventSet,
    snapshot: &'a EventAndSourceSnapshot,
    input: &ValidatedCurationInput<'_>,
) -> Result<Vec<GroundedEvent>, ContractViolation> {
    let mut ids = BTreeSet::new();
    let mut joined = Vec::with_capacity(events.events.len());
    for event in &events.events {
        let event_id = &event.core.event_id_and_time.event_id;
        if !ids.insert(event_id.clone()) {
            return Err(ContractViolation::BindingMismatch {
                field: "event.id",
                reason: "duplicate event identity".to_owned(),
            });
        }
        let member =
            snapshot
                .member(&event.source_member_id)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "event.source_member_id",
                    reason: "event member is absent from source snapshot".to_owned(),
                })?;
        if member.revision != event.source_revision
            || member.content_digest != event.source_content_digest
            || event.event_binding.member_id != event.source_member_id
            || event.event_binding.member_revision != event.source_revision
            || event.event_binding.member_content_digest != event.source_content_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "event.content_binding",
                reason: "event does not bind exact member revision/content digest".to_owned(),
            });
        }
        check_material(
            input,
            member,
            &event.event_binding,
            &crate::input::event_material_preimage(event)?,
        )?;
        for participant in &event.participants {
            check_material(
                input,
                member,
                &participant.binding,
                &crate::input::participant_material_preimage(participant)?,
            )?;
            if participant.binding.member_id != event.source_member_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "participant.member_id",
                    reason: "participant is grounded in another source member".to_owned(),
                });
            }
        }
        for outcome in &event.outcomes {
            check_material(
                input,
                member,
                &outcome.binding,
                &crate::input::outcome_material_preimage(outcome)?,
            )?;
            if outcome.binding.member_id != event.source_member_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "outcome.member_id",
                    reason: "outcome is grounded in another source member".to_owned(),
                });
            }
        }
        if let Some(binding) = &event.temporal_binding {
            check_material(
                input,
                member,
                binding,
                &crate::input::temporal_material_preimage(&event.temporal)?,
            )?;
            if binding.member_id != event.source_member_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "temporal.member_id",
                    reason: "temporal evidence is grounded in another source member".to_owned(),
                });
            }
        }
        joined.push(event.clone());
    }
    Ok(joined)
}

fn check_material(
    input: &ValidatedCurationInput<'_>,
    member: &eliot_memory_curation_contracts::SourceMember,
    binding: &crate::input::EvidenceBinding,
    preimage: &crate::input::MaterialPreimage,
) -> Result<(), ContractViolation> {
    if binding.member_id != member.member_id
        || binding.member_revision != member.revision
        || binding.member_content_digest != member.content_digest
    {
        return Err(ContractViolation::BindingMismatch {
            field: "evidence.member_binding",
            reason: "evidence is not bound to the exact source member revision".to_owned(),
        });
    }
    let material = input
        .ctx
        .bundle
        .materials
        .iter()
        .find(|material| material.handle == binding.material_handle)
        .ok_or(ContractViolation::BindingMismatch {
            field: "evidence.material_handle",
            reason: "load-bearing evidence is not an admitted bundle material".to_owned(),
        })?;
    if material.digest != binding.material_digest
        || material.bytes != binding.material_bytes
        || material.digest != preimage.digest
        || material.bytes != preimage.bytes
    {
        return Err(ContractViolation::BindingMismatch {
            field: "evidence.material_preimage",
            reason: format!(
                "material {} mismatch: declared {}:{} computed {}:{}",
                binding.material_handle,
                material.digest,
                material.bytes,
                preimage.digest,
                preimage.bytes
            ),
        });
    }
    if binding.evidence_handles.iter().any(|handle| {
        !member.evidence.provenance.contains(handle)
            && !member.evidence.owner_status.contains(handle)
            && !member.evidence.protection.contains(handle)
            && !member.evidence.conflict.contains(handle)
            && !member.evidence.audit.contains(handle)
    }) {
        return Err(ContractViolation::BindingMismatch {
            field: "evidence.handles",
            reason: "evidence handle is outside the exact source member owner union".to_owned(),
        });
    }
    Ok(())
}

fn boundary_phase(
    events: &[GroundedEvent],
    policy: &EpisodePolicy,
) -> Result<EpisodeBoundary, ContractViolation> {
    if !matches!(policy.boundary_rule, BoundaryRule::ExplicitEventAnchors) {
        return Err(ContractViolation::UnknownVariant {
            field: "boundary_rule",
            value: "unsupported".to_owned(),
        });
    }
    let start = policy
        .start_event_id
        .as_ref()
        .ok_or(ContractViolation::MissingField("policy.start_event_id"))?;
    if !events
        .iter()
        .any(|event| &event.core.event_id_and_time.event_id == start)
    {
        return Err(ContractViolation::BindingMismatch {
            field: "boundary.start_event_id",
            reason: "start anchor is absent from grounded events".to_owned(),
        });
    }
    let end = policy.end_event_id.as_ref().filter(|end| {
        events
            .iter()
            .any(|event| &event.core.event_id_and_time.event_id == *end)
    });
    Ok(EpisodeBoundary {
        start_event_id: start.clone(),
        end_event_id: end.cloned(),
    })
}

fn chronology_phase(events: &[GroundedEvent]) -> Result<Vec<ChronologyLink>, ContractViolation> {
    let mut links = Vec::new();
    for (left_index, left) in events.iter().enumerate() {
        for right in events.iter().skip(left_index + 1) {
            let (relation, support) = match (
                event_time_point(&left.temporal),
                event_time_point(&right.temporal),
            ) {
                (Some(left_point), Some(right_point))
                    if left_point.clock_ref == right_point.clock_ref
                        && left.temporal_binding.is_some()
                        && right.temporal_binding.is_some()
                        && matches!(
                            left.temporal.temporal_status,
                            eliot_evidence::EpistemicStatus::Supported
                                | eliot_evidence::EpistemicStatus::Verified
                        )
                        && matches!(
                            right.temporal.temporal_status,
                            eliot_evidence::EpistemicStatus::Supported
                                | eliot_evidence::EpistemicStatus::Verified
                        ) =>
                {
                    let left_ms = left_point
                        .reading
                        .valid_time_ms
                        .ok_or(ContractViolation::MissingField("temporal.event_time"))?;
                    let right_ms = right_point
                        .reading
                        .valid_time_ms
                        .ok_or(ContractViolation::MissingField("temporal.event_time"))?;
                    let left_value = i128::from(left_ms);
                    let right_value = i128::from(right_ms);
                    let left_uncertainty = i128::from(left_point.uncertainty_ms);
                    let right_uncertainty = i128::from(right_point.uncertainty_ms);
                    let left_end = left_value + left_uncertainty;
                    let right_end = right_value + right_uncertainty;
                    let relation = if left_end < right_value {
                        ChronologyRelation::Before
                    } else if right_end < left_value {
                        ChronologyRelation::After
                    } else {
                        ChronologyRelation::Incomparable
                    };
                    let support = if matches!(
                        relation,
                        ChronologyRelation::Before | ChronologyRelation::After
                    ) {
                        vec![
                            left.temporal_binding
                                .clone()
                                .ok_or(ContractViolation::MissingField("temporal.left_support"))?,
                            right
                                .temporal_binding
                                .clone()
                                .ok_or(ContractViolation::MissingField("temporal.right_support"))?,
                        ]
                    } else {
                        Vec::new()
                    };
                    (relation, support)
                }
                (Some(_), Some(_)) => (ChronologyRelation::Incomparable, Vec::new()),
                _ => (ChronologyRelation::Unknown, Vec::new()),
            };
            links.push(ChronologyLink {
                left_event_id: left.core.event_id_and_time.event_id.clone(),
                right_event_id: right.core.event_id_and_time.event_id.clone(),
                relation,
                support,
            });
        }
    }
    Ok(links)
}

fn overlap_phase(
    events: &[GroundedEvent],
    existing: &ExistingEpisodeSnapshot,
    boundary: &EpisodeBoundary,
    policy: &EpisodePolicy,
) -> Result<OverlapAssessment, ContractViolation> {
    let proposed: BTreeSet<_> = events
        .iter()
        .map(|event| event.core.event_id_and_time.event_id.clone())
        .collect();
    let replay = exact_replay(events, existing, boundary);
    let mut overlap = Vec::new();
    for member in &existing.members {
        if proposed.contains(&member.event_id) {
            if matches!(policy.overlap_rule, crate::input::OverlapRule::Block) && !replay {
                return Err(ContractViolation::BindingMismatch {
                    field: "episode.overlap",
                    reason: "overlap policy blocks a changed existing member".to_owned(),
                });
            }
            overlap.push(member.event_id.clone());
        }
    }
    overlap.sort();
    let disposition = if overlap.is_empty() {
        OverlapDisposition::None
    } else if replay {
        OverlapDisposition::ExactReplay
    } else {
        OverlapDisposition::Conflict
    };
    Ok(OverlapAssessment {
        disposition,
        event_ids: overlap,
    })
}

fn exact_replay(
    events: &[GroundedEvent],
    existing: &ExistingEpisodeSnapshot,
    boundary: &EpisodeBoundary,
) -> bool {
    events.len() == existing.members.len()
        && boundary.start_event_id == existing.boundary_start_event_id
        && boundary.end_event_id == existing.boundary_end_event_id
        && events.iter().all(|event| {
            existing.members.iter().any(|member| {
                member.event_id == event.core.event_id_and_time.event_id
                    && member.source_member_id == event.source_member_id
                    && member.revision == event.source_revision
                    && member.content_digest == event.source_content_digest
            })
        })
}

fn coverage_gaps(events: &GroundedEventSet, snapshot: &EventAndSourceSnapshot) -> Vec<EpisodeGap> {
    let present: BTreeSet<_> = events
        .events
        .iter()
        .map(|event| event.source_member_id.clone())
        .collect();
    let mut gaps = events
        .denominator
        .declared_member_ids
        .iter()
        .filter(|member| !present.contains(*member))
        .map(|member| EpisodeGap {
            member_id: Some(member.as_str().to_owned()),
            reason: "event is outside the grounded event set".to_owned(),
        })
        .collect::<Vec<_>>();
    if snapshot.source.availability != SourceAvailability::Available {
        gaps.push(EpisodeGap {
            member_id: None,
            reason: format!("source availability is {:?}", snapshot.source.availability),
        });
    }
    gaps
}

fn disposition_for(
    coverage: &EpisodeCoverage,
    chronology: &[ChronologyLink],
    overlap: &OverlapAssessment,
    preservation: &eliot_dreamer_contracts::PreservationReport,
) -> CandidateDisposition {
    if overlap.disposition == OverlapDisposition::Conflict {
        return CandidateDisposition::Conflict;
    }
    if preservation.overall().is_err()
        || !coverage.gaps.is_empty()
        || chronology.iter().any(|link| {
            matches!(
                link.relation,
                ChronologyRelation::Unknown | ChronologyRelation::Incomparable
            )
        })
    {
        CandidateDisposition::Partial
    } else if overlap.disposition == OverlapDisposition::ExactReplay {
        CandidateDisposition::Duplicate
    } else {
        CandidateDisposition::Candidate
    }
}

fn status_for(
    coverage: &EpisodeCoverage,
    chronology: &[ChronologyLink],
    overlap: &OverlapAssessment,
    boundary: &EpisodeBoundary,
) -> EpisodeStatus {
    if !coverage.gaps.is_empty()
        || chronology.iter().any(|link| {
            matches!(
                link.relation,
                ChronologyRelation::Unknown | ChronologyRelation::Incomparable
            )
        })
    {
        EpisodeStatus::Partial
    } else if boundary.end_event_id.is_none() {
        EpisodeStatus::Open
    } else if overlap.disposition == OverlapDisposition::Conflict {
        EpisodeStatus::Conflicted
    } else {
        EpisodeStatus::Closed
    }
}

fn preservation_phase(
    coverage: &EpisodeCoverage,
    chronology: &[ChronologyLink],
    overlap: &OverlapAssessment,
    events: &[GroundedEvent],
    source: &eliot_memory_curation_contracts::SourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
    admission_bound: bool,
) -> eliot_dreamer_contracts::PreservationReport {
    let (
        coverage_ok,
        coverage_known,
        temporal_known,
        temporal_grounded,
        lineage_ok,
        reversible,
        authority_ceiling,
        dependency_closure,
        provenance_ok,
    ) = preservation_facts(coverage, chronology, overlap, events, source, existing);
    let all = [
        (
            PreservationDimension::Coverage,
            coverage_ok,
            coverage_known,
            "all event members are accounted",
        ),
        (
            PreservationDimension::Faithfulness,
            temporal_known && temporal_grounded,
            temporal_known,
            "temporal claims retain explicit uncertainty",
        ),
        (
            PreservationDimension::Lineage,
            lineage_ok,
            lineage_ok,
            "event, participant and outcome bindings are retained",
        ),
        (
            PreservationDimension::Reversibility,
            reversible,
            reversible,
            "rollback retains the immutable closure",
        ),
        (
            PreservationDimension::AuthorityCeiling,
            authority_ceiling,
            true,
            "candidate carries no canonical authority",
        ),
        (
            PreservationDimension::DependencyClosure,
            dependency_closure && admission_bound,
            dependency_closure && admission_bound,
            "source and existing closures are retained",
        ),
        (
            PreservationDimension::ProvenanceRetention,
            provenance_ok,
            provenance_ok,
            "raw event provenance is retained",
        ),
    ];
    eliot_dreamer_contracts::PreservationReport {
        verdicts: all
            .into_iter()
            .map(|(dimension, passed, known, note)| DimensionVerdict {
                dimension,
                passed,
                known,
                note: note.to_owned(),
            })
            .collect(),
    }
}

fn preservation_facts(
    coverage: &EpisodeCoverage,
    chronology: &[ChronologyLink],
    overlap: &OverlapAssessment,
    events: &[GroundedEvent],
    source: &eliot_memory_curation_contracts::SourceSnapshot,
    existing: &ExistingEpisodeSnapshot,
) -> (bool, bool, bool, bool, bool, bool, bool, bool, bool) {
    let coverage_ok = coverage.gaps.is_empty();
    let coverage_known = source.availability != SourceAvailability::Unknown;
    let temporal_known = chronology
        .iter()
        .all(|link| link.relation != ChronologyRelation::Unknown);
    let temporal_grounded = chronology.iter().all(|link| {
        matches!(
            link.relation,
            ChronologyRelation::Incomparable | ChronologyRelation::Unknown
        ) || link.support.len() == 2
    });
    let lineage_ok = events.iter().all(|event| {
        !event.event_binding.evidence_handles.is_empty()
            && event
                .participants
                .iter()
                .all(|participant| !participant.binding.evidence_handles.is_empty())
            && event
                .outcomes
                .iter()
                .all(|outcome| !outcome.binding.evidence_handles.is_empty())
    });
    let source_ids: BTreeSet<_> = source
        .members
        .iter()
        .map(|member| member.member_id.clone())
        .collect();
    let retained_ids: BTreeSet<_> = events
        .iter()
        .map(|event| event.source_member_id.clone())
        .collect();
    let immutable_closure = !events.is_empty()
        && retained_ids
            .iter()
            .all(|member_id| source_ids.contains(member_id))
        && source
            .partition
            .immutable_references
            .is_superset(&retained_ids)
        && !existing.episode_id.is_empty();
    let reversible = immutable_closure && overlap.disposition != OverlapDisposition::Blocked;
    let authority_ceiling = overlap.disposition != OverlapDisposition::Blocked;
    let dependency_closure = immutable_closure && !source.members.is_empty();
    let provenance_ok = events.iter().all(|event| {
        source.members.iter().any(|member| {
            member.member_id == event.source_member_id
                && member.revision == event.source_revision
                && member.content_digest == event.source_content_digest
                && event
                    .core
                    .evidence_and_raw_handles
                    .iter()
                    .all(|handle| owner_evidence_contains(member, handle))
        })
    });
    (
        coverage_ok,
        coverage_known,
        temporal_known,
        temporal_grounded,
        lineage_ok,
        reversible,
        authority_ceiling,
        dependency_closure,
        provenance_ok,
    )
}
