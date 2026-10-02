//! Applicability fixtures over the shared CC-008 fence.
//!
//! These fixtures bind the exact same task, scope, session, and fence the
//! provider tests use: provider and evaluator share one WorkScope/fence
//! fixture family, and every negative case below changes exactly one field.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, SessionId, SourceId, StateFence,
    TaskId, TaskRevision,
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

/// A fence compatible with [`fence`] but unequal to it.
///
/// `StateFence::is_compatible_with` treats an absent optional revision as a
/// match, so this pair is mutually compatible while comparing unequal. The
/// declared-binding rule is about the scope a record CLAIMS, so the tests that
/// exercise it need a fence pair that separates the two questions instead of
/// failing the compatibility check first.
fn fence_with_task_revision() -> StateFence {
    StateFence {
        task_revision: Some(TaskRevision::new(1).expect("fixture revision")),
        ..fence()
    }
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
    candidate.batch.coverage.denominator = DenominatorState::Known { total: 2 };
    candidate.batch.coverage.truncated = true;
    candidate.batch.coverage.frontier = vec!["resume-after-mem-1".to_owned()];
    candidate.batch.coverage.revalidation_required = true;
    let set = evaluate_applicability(&candidate).expect("truncated evaluation");
    assert!(set.truncated);
    assert!(set.revalidation_required);
    assert_eq!(set.applicable.len(), 1);
    // The recovery identities stay on the batch this operation consumed; the
    // verdict carries only the ceiling that says the result is incomplete.
    assert_eq!(
        candidate.batch.coverage.frontier,
        vec!["resume-after-mem-1"]
    );
    set.validate()
        .expect("the incomplete verdict declares its proof ceiling");
}

#[test]
fn unaccounted_known_remainder_fails_before_evaluation() {
    // The empty/total-one counterexample: a batch that declares one observed
    // record, projects none of it, and neither omits nor defers it.
    let mut candidate = request(vec![]);
    candidate.batch.coverage.denominator = DenominatorState::Known { total: 1 };
    let error = evaluate_applicability(&candidate)
        .expect_err("an unaccounted known remainder must fail closed");
    assert!(matches!(
        error,
        eliot_memory_applicability::ApplicabilityError::Projection(
            eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch { .. }
        )
    ));
}

#[test]
fn duplicate_and_overlapping_recovery_identities_are_refused() {
    let mut duplicated = request(vec![record("mem-1")]);
    duplicated.batch.coverage.denominator = DenominatorState::Known { total: 3 };
    duplicated.batch.coverage.revalidation_required = true;
    duplicated.batch.coverage.omissions = vec![
        eliot_memory_projection_contracts::CoverageOmission {
            handle: aid("mem-2"),
            reason: "fence-mismatch".to_owned(),
        },
        eliot_memory_projection_contracts::CoverageOmission {
            handle: aid("mem-2"),
            reason: "scope-mismatch".to_owned(),
        },
    ];
    assert!(matches!(
        evaluate_applicability(&duplicated),
        Err(eliot_memory_applicability::ApplicabilityError::Projection(
            eliot_memory_projection_contracts::MemoryProjectionError::Duplicate { .. }
        ))
    ));

    let mut overlapping = request(vec![record("mem-1")]);
    overlapping.batch.coverage.denominator = DenominatorState::Known { total: 2 };
    overlapping.batch.coverage.revalidation_required = true;
    overlapping.batch.coverage.omissions = vec![
        eliot_memory_projection_contracts::CoverageOmission {
            handle: aid("mem-1"),
            reason: "fence-mismatch".to_owned(),
        },
    ];
    assert!(matches!(
        evaluate_applicability(&overlapping),
        Err(eliot_memory_applicability::ApplicabilityError::Projection(
            eliot_memory_projection_contracts::MemoryProjectionError::Duplicate { .. }
        ))
    ));
}

#[test]
fn a_record_declaring_another_scope_fence_never_reaches_a_verdict() {
    // The evaluator's own scope rule runs first and would name the record
    // SCOPE_MISMATCH, so this proves the refusal happens earlier: at the batch
    // owner that proves the denominator. A wrong-scope record inside an
    // otherwise valid batch must never become an ordinary exclusion, because
    // an exclusion still counts the record toward the assessed denominator
    // while the record itself belongs to a different scope.
    let mut candidate = request(vec![record("mem-1")]);
    candidate.batch.binding.state_fence = fence_with_task_revision();
    candidate.batch.records[0].binding = binding();
    let error = evaluate_applicability(&candidate)
        .expect_err("a wrong-scope record must fail closed before evaluation");
    assert!(matches!(
        error,
        eliot_memory_applicability::ApplicabilityError::Projection(
            eliot_memory_projection_contracts::MemoryProjectionError::FenceMismatch {
                left: "record.binding.state_fence",
                right: "batch.binding.state_fence",
            }
        )
    ));
}

#[test]
fn a_compatible_projection_fence_still_evaluates() {
    // The positive half: a record read under an older compatible fence with a
    // matching declared binding is evaluated normally and stays applicable.
    let mut candidate = request(vec![record("mem-1")]);
    candidate.batch.binding.state_fence = fence_with_task_revision();
    candidate.batch.records[0].binding = candidate.batch.binding.clone();
    candidate.batch.records[0].state_fence = fence();
    let set = evaluate_applicability(&candidate).expect("compatible fence evaluates");
    assert_eq!(set.applicable.len(), 1);
}

#[test]
fn a_standalone_verdict_cannot_claim_a_short_closed_denominator() {
    // The set is independently deserializable, so this proves the ceiling is
    // checked on the verdict itself, not only while the evaluator runs.
    let set = evaluate(vec![record("mem-1")]);
    set.validate().expect("the exact verdict is closed and complete");
    let mut wire = serde_json::to_value(&set).expect("serialize set");
    wire["denominator"] = serde_json::json!({ "state": "KNOWN", "total": 2 });
    let decoded: ApplicableMemorySet =
        serde_json::from_value(wire).expect("deserialize set independently");
    assert!(matches!(
        decoded.validate(),
        Err(eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch { .. })
    ));
}

#[test]
fn a_standalone_verdict_over_an_unknown_denominator_fails_closed() {
    let set = evaluate(vec![record("mem-1")]);
    let mut wire = serde_json::to_value(&set).expect("serialize set");
    wire["denominator"] =
        serde_json::json!({ "state": "UNKNOWN", "reason": "read side could not count" });
    let decoded: ApplicableMemorySet =
        serde_json::from_value(wire).expect("deserialize set independently");
    assert!(matches!(
        decoded.validate(),
        Err(eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch { .. })
    ));
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
