//! Provider projection fixtures over the shared CC-008 fence.
//!
//! These fixtures bind the exact same task, scope, session, and fence the
//! evaluator tests use: provider and evaluator share one WorkScope/fence
//! fixture family, and every negative case below changes exactly one field.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, SessionId, SourceId, StateFence,
    TaskId,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_projection_contracts::{
    FreshnessState, MemoryFreshness, MemoryKind, MemoryRole, MemoryScopeBinding,
};
use eliot_memory_projection_provider::{
    AdmittedMemoryObservation, OMISSION_FENCE_MISMATCH, OMISSION_SCOPE_MISMATCH, ProjectionRequest,
    project_batch,
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

fn fence_other() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(7).expect("non-zero"),
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

fn observation(handle: &str) -> AdmittedMemoryObservation {
    AdmittedMemoryObservation {
        handle: aid(handle),
        kind: MemoryKind::Episode,
        task_id: task(),
        scope_id: scope(),
        session_id: Some(session()),
        state_fence: fence(),
        epistemic: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        lifecycle: LifecycleState::Active,
        freshness: MemoryFreshness {
            state: FreshnessState::Current,
            note: "admitted at the batch fence".to_owned(),
        },
        provenance: Provenance {
            source_id: source(),
            capture_route: "governor.read.memory".to_owned(),
            scope: "scope-cc008".to_owned(),
            raw_handle: None,
            revision: Some("rev-1".to_owned()),
        },
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

fn request(observations: Vec<AdmittedMemoryObservation>) -> ProjectionRequest {
    ProjectionRequest {
        binding: binding(),
        projection_revision: 3,
        denominator_total: observations.len(),
        observations,
    }
}

#[test]
fn projects_admitted_observations_with_shared_binding() {
    let batch = project_batch(&request(vec![observation("mem-1"), observation("mem-2")]))
        .expect("happy path");
    batch.validate().expect("valid batch");
    assert_eq!(batch.records.len(), 2);
    assert_eq!(batch.records[0].projection_revision, 3);
    assert_eq!(batch.records[0].binding.task_id, task());
    assert!(!batch.coverage.truncated);
    assert!(batch.coverage.omissions.is_empty());
    assert!(!batch.coverage.revalidation_required);
}

#[test]
fn fence_and_scope_skips_become_named_omissions() {
    let mut fenced_out = observation("mem-fenced");
    fenced_out.state_fence = fence_other();
    let mut scoped_out = observation("mem-scoped");
    scoped_out.task_id = TaskId::new("task-other").expect("fixture task");
    let batch = project_batch(&request(vec![observation("mem-1"), fenced_out, scoped_out]))
        .expect("skips are explicit, not errors");
    batch.validate().expect("valid batch");
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.coverage.omissions.len(), 2);
    let reasons: Vec<&str> = batch
        .coverage
        .omissions
        .iter()
        .map(|omission| omission.reason.as_str())
        .collect();
    assert!(reasons.contains(&OMISSION_FENCE_MISMATCH));
    assert!(reasons.contains(&OMISSION_SCOPE_MISMATCH));
    assert!(!batch.coverage.truncated);
    assert!(batch.coverage.revalidation_required);
}

#[test]
fn volume_beyond_bound_truncates_with_frontier() {
    let observations: Vec<AdmittedMemoryObservation> = (0..257)
        .map(|index| observation(&format!("mem-{index:03}")))
        .collect();
    let batch = project_batch(&request(observations)).expect("truncation is explicit");
    batch.validate().expect("valid batch");
    assert_eq!(
        batch.records.len(),
        eliot_memory_projection_contracts::MEMORY_PROJECTION_MAX_RECORDS
    );
    assert!(batch.coverage.truncated);
    assert_eq!(batch.coverage.frontier.len(), 1);
    assert_eq!(batch.coverage.frontier[0], "mem-256");
    assert!(batch.coverage.revalidation_required);
}

#[test]
fn denominator_contradiction_fails_closed() {
    let mut candidate = request(vec![observation("mem-1")]);
    candidate.denominator_total = 2;
    let error = project_batch(&candidate).expect_err("contradiction must fail");
    assert!(matches!(
        error,
        eliot_memory_projection_provider::ProjectionError::DenominatorContradiction { .. }
    ));
}

#[test]
fn shared_binding_matches_the_evaluator_family() {
    // Same task/scope/session/fence the evaluator tests bind: fence
    // sequence 1 on the fixture lineage, genesis generation.
    let batch = project_batch(&request(vec![observation("mem-1")])).expect("happy path");
    assert_eq!(batch.binding.task_id, task());
    assert_eq!(batch.binding.scope_id, scope());
    assert_eq!(batch.binding.session_id, Some(session()));
    assert!(batch.binding.state_fence.is_compatible_with(&fence()));
}
