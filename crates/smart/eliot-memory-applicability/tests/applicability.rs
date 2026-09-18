//! Applicability fixtures over the shared CC-008 fence.
//!
//! These fixtures bind the exact same task, scope, session, and fence the
//! provider tests use: provider and evaluator share one WorkScope/fence
//! fixture family, and every negative case below changes exactly one field.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, SessionId, SourceId, StateFence,
    TaskId,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_applicability::{ApplicabilityRequest, evaluate_applicability};
use eliot_memory_projection_contracts::{
    ApplicableMemorySet, DenominatorState, ExcludedMemory, ExclusionReason, FreshnessState,
    MemoryFreshness, MemoryKind, MemoryProjectionBatch, MemoryProjectionRecord, MemoryRole,
    MemoryScopeBinding, NegativeTrigger, Precondition, ProjectionCoverage,
};
use eliot_receipts::WorkScopeId;

fn task() -> TaskId {
    TaskId::new("task-cc008").expect("fixture task")
}

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-cc008").expect("fixture scope")
}

fn session() -> SessionId {
    SessionId::new("session-cc008").expect("fixture session")
}

fn source() -> SourceId {
    SourceId::new("source-cc008").expect("fixture source")
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(1).expect("non-zero"),
        )
        .expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

fn binding() -> MemoryScopeBinding {
    MemoryScopeBinding {
        task_id: task(),
        scope_id: scope(),
        session_id: Some(session()),
        state_fence: fence(),
    }
}

fn provenance() -> Provenance {
    Provenance {
        source_id: source(),
        capture_route: "governor.read.memory".to_owned(),
        scope: "scope-cc008".to_owned(),
        raw_handle: None,
        revision: Some("rev-1".to_owned()),
    }
}

fn record(handle: &str) -> MemoryProjectionRecord {
    MemoryProjectionRecord {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        handle: aid(handle),
        kind: MemoryKind::Episode,
        binding: binding(),
        state_fence: fence(),
        projection_revision: 1,
        epistemic: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        lifecycle: LifecycleState::Active,
        freshness: MemoryFreshness {
            state: FreshnessState::Current,
            note: "projected at the batch fence".to_owned(),
        },
        provenance: provenance(),
        predecessor: None,
        roles: vec![MemoryRole::Minority],
        influence_eligible: true,
        preconditions: vec![],
        applicability_limits: vec![],
        cue_triggers: vec![],
        negative_trigger: None,
        source_id: source(),
    }
}

fn batch(records: Vec<MemoryProjectionRecord>) -> MemoryProjectionBatch {
    let total = records.len();
    MemoryProjectionBatch {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        binding: binding(),
        records,
        coverage: ProjectionCoverage {
            denominator: DenominatorState::Known { total },
            truncated: false,
            frontier: vec![],
            omissions: vec![],
            revalidation_required: false,
        },
    }
}

fn request(records: Vec<MemoryProjectionRecord>) -> ApplicabilityRequest {
    ApplicabilityRequest {
        batch: batch(records),
        task_key: "task-cc008:step-3".to_owned(),
        cue_hits: vec![],
    }
}

fn evaluate(records: Vec<MemoryProjectionRecord>) -> ApplicableMemorySet {
    evaluate_applicability(&request(records)).expect("fixture evaluation")
}

fn excluded(set: &ApplicableMemorySet, handle: &str) -> ExcludedMemory {
    set.excluded
        .iter()
        .find(|entry| entry.handle == aid(handle))
        .expect("excluded entry")
        .clone()
}

#[test]
fn applicable_happy_path_preserves_roles_and_flags_cue_hit() {
    let mut candidate = request(vec![record("mem-1")]);
    candidate.cue_hits = vec![aid("mem-1")];
    let set = evaluate_applicability(&candidate).expect("happy path");
    assert_eq!(set.applicable.len(), 1);
    assert!(set.excluded.is_empty());
    assert_eq!(set.applicable[0].roles, vec![MemoryRole::Minority]);
    assert!(set.applicable[0].cue_hit);
    assert_eq!(set.cue_hits_considered, 1);
}

#[test]
fn stale_and_conflicted_are_excluded() {
    let mut stale = record("mem-stale");
    stale.freshness.state = FreshnessState::Stale;
    let mut conflicted = record("mem-conflicted");
    conflicted.epistemic = EpistemicStatus::Contested;
    let set = evaluate(vec![stale, conflicted]);
    assert!(set.applicable.is_empty());
    assert_eq!(excluded(&set, "mem-stale").reason, ExclusionReason::Stale);
    assert_eq!(
        excluded(&set, "mem-conflicted").reason,
        ExclusionReason::Conflicted
    );
}

#[test]
fn protected_records_are_withheld() {
    let mut protected = record("mem-protected");
    protected.roles = vec![MemoryRole::Protected, MemoryRole::Audit];
    let set = evaluate(vec![protected]);
    assert!(set.applicable.is_empty());
    assert_eq!(
        excluded(&set, "mem-protected").reason,
        ExclusionReason::Protected
    );
}

#[test]
fn exact_negative_trigger_blocks_only_on_equality() {
    let mut blocked = record("mem-blocked");
    blocked.kind = MemoryKind::NegativeMemory;
    blocked.negative_trigger = Some(NegativeTrigger {
        trigger: "task-cc008:step-3".to_owned(),
        failed_action: "retry without revalidation".to_owned(),
        outcome: "repeated timeout".to_owned(),
        violated_invariant: "revalidate before retry".to_owned(),
        reopen_condition: "route profile change".to_owned(),
        extinction_condition: "three clean replays".to_owned(),
    });
    let mut unrelated = record("mem-unrelated");
    unrelated.kind = MemoryKind::NegativeMemory;
    unrelated.negative_trigger = Some(NegativeTrigger {
        trigger: "task-other:step-9".to_owned(),
        failed_action: "retry without revalidation".to_owned(),
        outcome: "repeated timeout".to_owned(),
        violated_invariant: "revalidate before retry".to_owned(),
        reopen_condition: "route profile change".to_owned(),
        extinction_condition: "three clean replays".to_owned(),
    });
    let set = evaluate(vec![blocked, unrelated]);
    assert_eq!(
        excluded(&set, "mem-blocked").reason,
        ExclusionReason::NegativeMemory
    );
    assert_eq!(set.applicable.len(), 1);
    assert_eq!(set.applicable[0].handle, aid("mem-unrelated"));
}

#[test]
fn failed_precondition_beats_cue_hit() {
    // Adversarial core of CC-008: the cue fired on this record, the
    // precondition still fails, and activation must not promote it.
    let mut gated = record("mem-gated");
    gated.kind = MemoryKind::Procedure;
    gated.preconditions = vec![Precondition {
        id: "pre-revalidate".to_owned(),
        satisfied: Some(false),
    }];
    let mut candidate = request(vec![gated]);
    candidate.cue_hits = vec![aid("mem-gated")];
    let set = evaluate_applicability(&candidate).expect("evaluation runs");
    assert!(set.applicable.is_empty());
    let entry = excluded(&set, "mem-gated");
    assert!(entry.cue_hit);
    assert_eq!(
        entry.reason,
        ExclusionReason::PreconditionFailed {
            id: "pre-revalidate".to_owned(),
        }
    );
}

#[test]
fn unassessed_precondition_fails_closed() {
    let mut gated = record("mem-unassessed");
    gated.kind = MemoryKind::Procedure;
    gated.preconditions = vec![Precondition {
        id: "pre-unknown".to_owned(),
        satisfied: None,
    }];
    let set = evaluate(vec![gated]);
    assert!(set.applicable.is_empty());
    assert_eq!(
        excluded(&set, "mem-unassessed").reason,
        ExclusionReason::PreconditionUnassessed {
            id: "pre-unknown".to_owned(),
        }
    );
}

#[test]
fn missing_denominator_fails_closed() {
    let mut candidate = request(vec![record("mem-1")]);
    candidate.batch.coverage.denominator = DenominatorState::Unknown {
        reason: "read side could not count".to_owned(),
    };
    let error = evaluate_applicability(&candidate).expect_err("unknown denominator");
    assert!(matches!(
        error,
        eliot_memory_applicability::ApplicabilityError::MissingDenominator
    ));
}

#[test]
fn truncation_and_revalidation_echo_to_the_set() {
    let mut candidate = request(vec![record("mem-1")]);
    candidate.batch.coverage.truncated = true;
    candidate.batch.coverage.frontier = vec!["resume-after-mem-1".to_owned()];
    candidate.batch.coverage.revalidation_required = true;
    let set = evaluate_applicability(&candidate).expect("truncated evaluation");
    assert!(set.truncated);
    assert!(set.revalidation_required);
    assert_eq!(set.applicable.len(), 1);
}

#[test]
fn shared_fence_fixture_matches_the_provider_family() {
    // Same task/scope/session/fence the provider projection tests bind:
    // fence sequence 1 on the fixture lineage, genesis generation.
    let set = evaluate(vec![record("mem-1")]);
    set.validate().expect("valid set");
    assert_eq!(set.binding.task_id, task());
    assert_eq!(set.binding.scope_id, scope());
    assert_eq!(set.binding.session_id, Some(session()));
    assert!(set.binding.state_fence.is_compatible_with(&fence()));
}
