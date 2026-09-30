//! Governor-owned canonical projection producer (CC-004).
//!
//! `produce_canonical_projections` accepts one admitted context binding,
//! owner-supplied projection members and immutable owner source snapshots. It
//! returns the strict four-member set only when every required member/source
//! is present under that exact binding and fence. Otherwise it returns a
//! typed partial or missing readback. It opens no store and performs no effect.

#![forbid(unsafe_code)]

use eliot_context_contracts::{
    AffordanceProjection, CanonicalProjectionMember, CanonicalProjectionOmission,
    CanonicalProjectionOmissionReason, CanonicalProjectionOmissionStatus,
    CanonicalProjectionOutcome, CanonicalProjectionReadback,
    CanonicalProjectionSourceReadback, CanonicalProjectionSourceRole,
    CanonicalProjectionSourceSnapshot, ContextBinding, ContinuityProjection,
    SafetyProjection, TaskProjection, CANONICAL_PROJECTION_SOURCE_DENOMINATOR,
};
use eliot_contracts::fences_match_exact;
use eliot_observation::ObservationJournalEntry;
use eliot_session::SessionLifecycleSnapshot;
use eliot_task::TaskLifecycleSnapshot;
use eliot_workscope::WorkScopeBindingSnapshot;
use thiserror::Error;

/// Fail-closed errors from the pure owner producer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GovernorProjectionError {
    /// The supplied fence is invalid.
    #[error("governor projection fence is invalid")]
    InvalidFence,
    /// A canonical fence does not match the admitted binding.
    #[error("governor projection fence mismatch")]
    FenceMismatch,
    /// A canonical snapshot failed its own validation.
    #[error("governor projection snapshot is invalid: {0}")]
    InvalidSnapshot(&'static str),
    /// A projection field or owner relationship is malformed.
    #[error("governor projection field is invalid: {0}")]
    InvalidField(&'static str),
    /// A repeated field exceeds its bound or carries duplicates.
    #[error("governor projection bound exceeded: {0}")]
    Bounds(&'static str),
}

/// Actual canonical member readbacks supplied by their Governor owners.
///
/// Each member is optional because the current task/session/WorkScope owners
/// do not expose all fields required by the strict CC-004 shapes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanonicalProjectionOwnerMembers {
    pub task: Option<TaskProjection>,
    pub continuity: Option<ContinuityProjection>,
    pub safety: Option<SafetyProjection>,
    pub affordance: Option<AffordanceProjection>,
}

/// Inputs to the Governor-owned CC-004 production readback.
pub struct CanonicalProjectionOwnerInputs<'a> {
    /// Binding admitted for this exact task, WorkScope, decision and fence.
    pub binding: &'a ContextBinding,
    /// Task owner snapshot, when available.
    pub task_snapshot: Option<&'a TaskLifecycleSnapshot>,
    /// Session owner snapshot, when available.
    pub session_snapshot: Option<&'a SessionLifecycleSnapshot>,
    /// Admitted WorkScope binding, when available.
    pub scope_snapshot: Option<&'a WorkScopeBindingSnapshot>,
    /// Existing observations are unscoped by task and are never projected as
    /// task safety, even when supplied.
    pub observation_journal: Option<&'a [ObservationJournalEntry]>,
    /// Complete member values, copied only from their semantic owners.
    pub members: CanonicalProjectionOwnerMembers,
    /// Owner-issued immutable source snapshots tied to the same binding.
    pub source_snapshots: Vec<CanonicalProjectionSourceSnapshot>,
}

fn source_has_role(
    sources: &CanonicalProjectionSourceReadback,
    member: CanonicalProjectionMember,
    role: CanonicalProjectionSourceRole,
) -> bool {
    sources
        .snapshots
        .iter()
        .any(|source| source.member == member && source.role == role)
}

fn source_complete_for_member(
    sources: &CanonicalProjectionSourceReadback,
    member: CanonicalProjectionMember,
) -> bool {
    CANONICAL_PROJECTION_SOURCE_DENOMINATOR
        .iter()
        .filter(|required| required.member == member)
        .all(|required| source_has_role(sources, required.member, required.role))
}

fn source_snapshot_for<'a>(
    sources: &'a CanonicalProjectionSourceReadback,
    member: CanonicalProjectionMember,
    role: CanonicalProjectionSourceRole,
) -> Option<&'a CanonicalProjectionSourceSnapshot> {
    sources
        .snapshots
        .iter()
        .find(|source| source.member == member && source.role == role)
}

fn omission(
    member: CanonicalProjectionMember,
    status: CanonicalProjectionOmissionStatus,
    reason: CanonicalProjectionOmissionReason,
    role: Option<CanonicalProjectionSourceRole>,
    sources: &CanonicalProjectionSourceReadback,
) -> CanonicalProjectionOmission {
    let source = role.and_then(|source_role| source_snapshot_for(sources, member, source_role));
    CanonicalProjectionOmission {
        member,
        status,
        reason,
        source_role: role,
        source_snapshot_id: source.map(|entry| entry.snapshot.snapshot_id.clone()),
        source_revision: source.map(|entry| entry.snapshot.revision.clone()),
    }
}

fn append_source_gaps(
    omissions: &mut Vec<CanonicalProjectionOmission>,
    member: CanonicalProjectionMember,
    status: CanonicalProjectionOmissionStatus,
    sources: &CanonicalProjectionSourceReadback,
) {
    for requirement in CANONICAL_PROJECTION_SOURCE_DENOMINATOR
        .iter()
        .filter(|required| required.member == member)
    {
        if !source_has_role(sources, member, requirement.role) {
            omissions.push(omission(
                member,
                status,
                CanonicalProjectionOmissionReason::SourceSnapshotUnavailable,
                Some(requirement.role),
                sources,
            ));
        }
    }
}

fn validate_member_binding(
    binding: &ContextBinding,
    projection_binding: &ContextBinding,
) -> Result<(), GovernorProjectionError> {
    if projection_binding != binding
        || !fences_match_exact(&projection_binding.state_fence, &binding.state_fence)
    {
        return Err(GovernorProjectionError::FenceMismatch);
    }
    Ok(())
}

/// Produces the actual CC-004 owner outcome under one admitted binding.
///
/// The strict `CanonicalProjectionSet` is returned only when all four
/// owner-supplied members, all eight expected member/source records and their
/// exact binding/fence validate. Incomplete owner state becomes a typed
/// readback. The unscoped observation journal is deliberately not inspected:
/// it cannot establish task-specific negative-memory triggers.
pub fn produce_canonical_projections(
    input: CanonicalProjectionOwnerInputs<'_>,
) -> Result<CanonicalProjectionOutcome, GovernorProjectionError> {
    input
        .binding
        .validate()
        .map_err(|_| GovernorProjectionError::InvalidField("context.binding"))?;

    let task_record = input
        .task_snapshot
        .and_then(|snapshot| snapshot.tasks.get(&input.binding.task_id));
    if let Some(record) = task_record {
        if !fences_match_exact(&record.state_fence, &input.binding.state_fence) {
            return Err(GovernorProjectionError::FenceMismatch);
        }
    }

    if let Some(scope) = input.scope_snapshot {
        scope
            .validate()
            .map_err(|_| GovernorProjectionError::InvalidSnapshot("workscope"))?;
        if !fences_match_exact(&scope.state_fence, &input.binding.state_fence)
            || scope.binding.scope.scope_ref != input.binding.scope_id.as_str()
        {
            return Err(GovernorProjectionError::FenceMismatch);
        }
    }

    let sources = CanonicalProjectionSourceReadback {
        expected: CANONICAL_PROJECTION_SOURCE_DENOMINATOR.to_vec(),
        snapshots: input.source_snapshots,
    };
    sources
        .validate(input.binding)
        .map_err(|_| GovernorProjectionError::InvalidSnapshot("projection-sources"))?;

    let mut omissions = Vec::new();
    let mut task = None;
    let mut continuity = None;
    let mut safety = None;
    let mut affordance = None;

    if let Some(projection) = input.members.task.as_ref() {
        projection
            .validate()
            .map_err(|_| GovernorProjectionError::InvalidField("task.projection"))?;
        validate_member_binding(&input.binding, &projection.binding)?;
        if task_record.is_some_and(|record| record.goal != projection.goal)
            || task_record.is_none()
        {
            return Err(GovernorProjectionError::InvalidField("task.owner_readback"));
        }
        if source_complete_for_member(&sources, CanonicalProjectionMember::Task) {
            task = Some(projection.clone());
        } else {
            append_source_gaps(
                &mut omissions,
                CanonicalProjectionMember::Task,
                CanonicalProjectionOmissionStatus::Partial,
                &sources,
            );
        }
    } else if task_record.is_some() {
        append_source_gaps(
            &mut omissions,
            CanonicalProjectionMember::Task,
            CanonicalProjectionOmissionStatus::Partial,
            &sources,
        );
        omissions.push(omission(
            CanonicalProjectionMember::Task,
            CanonicalProjectionOmissionStatus::Partial,
            CanonicalProjectionOmissionReason::RequiredFieldUnavailable,
            Some(CanonicalProjectionSourceRole::TaskCommitments),
            &sources,
        ));
    } else {
        omissions.push(omission(
            CanonicalProjectionMember::Task,
            CanonicalProjectionOmissionStatus::Missing,
            CanonicalProjectionOmissionReason::OwnerSnapshotUnavailable,
            Some(CanonicalProjectionSourceRole::TaskLifecycle),
            &sources,
        ));
        omissions.push(omission(
            CanonicalProjectionMember::Task,
            CanonicalProjectionOmissionStatus::Missing,
            CanonicalProjectionOmissionReason::OwnerSnapshotUnavailable,
            Some(CanonicalProjectionSourceRole::TaskCommitments),
            &sources,
        ));
    }

    if let Some(projection) = input.members.continuity.as_ref() {
        projection
            .validate()
            .map_err(|_| GovernorProjectionError::InvalidField("continuity.projection"))?;
        validate_member_binding(&input.binding, &projection.binding)?;
        if task_record.is_none()
            || input.session_snapshot.is_none()
            || !source_complete_for_member(&sources, CanonicalProjectionMember::Continuity)
        {
            append_source_gaps(
                &mut omissions,
                CanonicalProjectionMember::Continuity,
                CanonicalProjectionOmissionStatus::Partial,
                &sources,
            );
        } else {
            continuity = Some(projection.clone());
        }
    } else {
        let status = if task_record.is_some() && input.session_snapshot.is_some() {
            CanonicalProjectionOmissionStatus::Partial
        } else {
            CanonicalProjectionOmissionStatus::Missing
        };
        append_source_gaps(
            &mut omissions,
            CanonicalProjectionMember::Continuity,
            status,
            &sources,
        );
        omissions.push(omission(
            CanonicalProjectionMember::Continuity,
            status,
            if status == CanonicalProjectionOmissionStatus::Partial {
                CanonicalProjectionOmissionReason::RequiredFieldUnavailable
            } else {
                CanonicalProjectionOmissionReason::OwnerSnapshotUnavailable
            },
            Some(CanonicalProjectionSourceRole::ContinuityNote),
            &sources,
        ));
    }

    if let Some(projection) = input.members.safety.as_ref() {
        projection
            .validate()
            .map_err(|_| GovernorProjectionError::InvalidField("safety.projection"))?;
        validate_member_binding(&input.binding, &projection.binding)?;
        if source_complete_for_member(&sources, CanonicalProjectionMember::Safety) {
            safety = Some(projection.clone());
        } else {
            append_source_gaps(
                &mut omissions,
                CanonicalProjectionMember::Safety,
                CanonicalProjectionOmissionStatus::Unknown,
                &sources,
            );
        }
    } else {
        omissions.push(omission(
            CanonicalProjectionMember::Safety,
            CanonicalProjectionOmissionStatus::Unknown,
            if input.observation_journal.is_some() {
                CanonicalProjectionOmissionReason::SourceNotTaskScoped
            } else {
                CanonicalProjectionOmissionReason::OwnerSnapshotUnavailable
            },
            Some(CanonicalProjectionSourceRole::TaskScopedSafety),
            &sources,
        ));
    }

    if let Some(projection) = input.members.affordance.as_ref() {
        projection
            .validate()
            .map_err(|_| GovernorProjectionError::InvalidField("affordance.projection"))?;
        validate_member_binding(&input.binding, &projection.binding)?;
        if input.scope_snapshot.is_none() {
            return Err(GovernorProjectionError::InvalidSnapshot("workscope"));
        }
        if source_complete_for_member(&sources, CanonicalProjectionMember::Affordance) {
            affordance = Some(projection.clone());
        } else {
            append_source_gaps(
                &mut omissions,
                CanonicalProjectionMember::Affordance,
                CanonicalProjectionOmissionStatus::Unknown,
                &sources,
            );
        }
    } else {
        if input.scope_snapshot.is_none() {
            omissions.push(omission(
                CanonicalProjectionMember::Affordance,
                CanonicalProjectionOmissionStatus::Missing,
                CanonicalProjectionOmissionReason::OwnerSnapshotUnavailable,
                Some(CanonicalProjectionSourceRole::WorkScopeBinding),
                &sources,
            ));
        }
        omissions.push(omission(
            CanonicalProjectionMember::Affordance,
            CanonicalProjectionOmissionStatus::Unknown,
            CanonicalProjectionOmissionReason::AuthorizedAffordancesUnavailable,
            Some(CanonicalProjectionSourceRole::AuthorizedAffordances),
            &sources,
        ));
        append_source_gaps(
            &mut omissions,
            CanonicalProjectionMember::Affordance,
            CanonicalProjectionOmissionStatus::Unknown,
            &sources,
        );
    }

    if let (Some(task), Some(continuity), Some(safety), Some(affordance)) =
        (task.clone(), continuity.clone(), safety.clone(), affordance.clone())
    {
        if !sources.is_complete() || !omissions.is_empty() {
            return Err(GovernorProjectionError::InvalidField(
                "projections.complete_source_closure",
            ));
        }
        let set = eliot_context_contracts::CanonicalProjectionSet {
            binding: input.binding.clone(),
            task,
            continuity,
            safety,
            affordance,
            omissions: Vec::new(),
        };
        set.validate()
            .map_err(|_| GovernorProjectionError::InvalidField("projections.complete_set"))?;
        let outcome = CanonicalProjectionOutcome::Complete { set, sources };
        outcome
            .validate()
            .map_err(|_| GovernorProjectionError::InvalidField("projections.complete_outcome"))?;
        return Ok(outcome);
    }

    let readback = CanonicalProjectionReadback {
        binding: input.binding.clone(),
        sources,
        task,
        continuity,
        safety,
        affordance,
        omissions,
    };
    readback
        .validate()
        .map_err(|_| GovernorProjectionError::InvalidField("projections.owner_readback"))?;
    let has_observed_owner_state = task_record.is_some()
        || input.session_snapshot.is_some()
        || input.scope_snapshot.is_some()
        || input.observation_journal.is_some()
        || input.members.task.is_some()
        || input.members.continuity.is_some()
        || input.members.safety.is_some()
        || input.members.affordance.is_some()
        || !readback.sources.snapshots.is_empty()
        || readback.task.is_some()
        || readback.continuity.is_some()
        || readback.safety.is_some()
        || readback.affordance.is_some();
    let outcome = if has_observed_owner_state {
        CanonicalProjectionOutcome::Partial(readback)
    } else {
        CanonicalProjectionOutcome::Missing(readback)
    };
    outcome
        .validate()
        .map_err(|_| GovernorProjectionError::InvalidField("projections.owner_outcome"))?;
    Ok(outcome)
}
