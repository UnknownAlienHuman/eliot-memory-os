//! Package fixtures for the bounded memory candidate query.
//!
//! The query and the batch share one task, one scope, one session, and one
//! fence. Every negative case derives from the same binding by changing
//! exactly one field.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, SessionId, SourceId, StateFence,
    TaskId,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_projection_contracts::{
    CONTRACT_VERSION, DenominatorState, FreshnessState, MemoryFreshness, MemoryKind,
    MemoryProjectionBatch, MemoryProjectionRecord, MemoryScopeBinding, ProjectionCoverage,
};
use eliot_memory_projection::{MemoryCandidateQuery, QueryError, select};
use eliot_receipts::WorkScopeId;

fn task() -> TaskId {
    TaskId::new("task-memproj").expect("fixture task")
}

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-memproj").expect("fixture scope")
}

fn session() -> SessionId {
    SessionId::new("session-memproj").expect("fixture session")
}

fn source() -> SourceId {
    SourceId::new("source-memproj").expect("fixture source")
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

fn lineage() -> EpochLineageId {
    EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage")
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(lineage(), NonZeroU64::new(1).expect("non-zero")).expect("fixture epoch"),
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
        scope: "scope-memproj".to_owned(),
        raw_handle: None,
        revision: Some("rev-1".to_owned()),
    }
}

fn record(handle: &str, kind: MemoryKind) -> MemoryProjectionRecord {
    MemoryProjectionRecord {
        contract_version: CONTRACT_VERSION,
        handle: aid(handle),
        kind,
        binding: binding(),
        state_fence: fence(),
        projection_revision: 3,
        epistemic: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        lifecycle: LifecycleState::Active,
        freshness: MemoryFreshness {
            state: FreshnessState::Current,
            note: "projected at the batch fence".to_owned(),
        },
        provenance: provenance(),
        predecessor: None,
        roles: vec![],
        influence_eligible: true,
        preconditions: vec![],
        applicability_limits: vec![],
        cue_triggers: vec![],
        negative_trigger: None,
        source_id: source(),
    }
}

fn batch() -> MemoryProjectionBatch {
    MemoryProjectionBatch {
        contract_version: CONTRACT_VERSION,
        binding: binding(),
        records: vec![
            record("mem-1", MemoryKind::Episode),
            record("mem-2", MemoryKind::NegativeMemory),
            record("mem-3", MemoryKind::Concept),
        ],
        coverage: ProjectionCoverage {
            denominator: DenominatorState::Known { total: 3 },
            truncated: false,
            frontier: vec![],
            omissions: vec![],
            revalidation_required: false,
        },
    }
}

fn query(limit: usize, kinds: Vec<MemoryKind>) -> MemoryCandidateQuery {
    MemoryCandidateQuery::new(binding(), limit, kinds).expect("fixture query")
}

#[test]
fn select_narrows_to_the_explicit_allowlist() {
    let snapshot = select(
        &query(256, vec![MemoryKind::Episode, MemoryKind::Concept]),
        &batch(),
    )
    .expect("valid selection");
    let handles: Vec<&str> = snapshot
        .candidates
        .iter()
        .map(|candidate| candidate.handle.as_str())
        .collect();
    assert_eq!(handles, vec!["mem-1", "mem-3"]);
    assert_eq!(snapshot.binding, binding());
    assert_eq!(snapshot.denominator_total, 3);
    assert!(!snapshot.truncated);
    assert!(!snapshot.revalidation_required);
}

#[test]
fn select_preserves_deterministic_provider_order() {
    let snapshot = select(&query(256, vec![MemoryKind::Concept, MemoryKind::Episode]), &batch())
        .expect("valid selection");
    let handles: Vec<&str> = snapshot
        .candidates
        .iter()
        .map(|candidate| candidate.handle.as_str())
        .collect();
    assert_eq!(handles, vec!["mem-1", "mem-3"]);
}

#[test]
fn select_applies_the_limit_and_marks_truncation() {
    let snapshot = select(&query(1, vec![MemoryKind::Episode, MemoryKind::Concept]), &batch())
        .expect("valid selection");
    assert_eq!(snapshot.candidates.len(), 1);
    assert_eq!(snapshot.candidates[0].handle.as_str(), "mem-1");
    assert!(snapshot.truncated);
}

#[test]
fn select_rejects_binding_mismatch() {
    let mut other = batch();
    other.binding.task_id = TaskId::new("task-other").expect("fixture task");
    let error = select(&query(256, vec![MemoryKind::Episode]), &other).expect_err("mismatch");
    // The tampered batch fails upstream validation before the binding check.
    assert!(matches!(
        error,
        QueryError::Upstream(_) | QueryError::BindingMismatch
    ));
}

#[test]
fn select_rejects_query_binding_mismatch() {
    let mut request = query(256, vec![MemoryKind::Episode]);
    request.binding.scope_id = WorkScopeId::new("scope-other").expect("fixture scope");
    let error = select(&request, &batch()).expect_err("mismatch must fail");
    assert!(matches!(error, QueryError::BindingMismatch));
}

#[test]
fn select_fails_closed_on_unknown_denominator() {
    let mut unknown = batch();
    unknown.coverage.denominator = DenominatorState::Unknown {
        reason: "read side could not count".to_owned(),
    };
    let error = select(&query(256, vec![MemoryKind::Episode]), &unknown).expect_err("no denominator");
    assert!(matches!(error, QueryError::UnknownDenominator));
}

#[test]
fn limit_over_the_frozen_bound_is_rejected() {
    let error = MemoryCandidateQuery::new(binding(), 257, vec![MemoryKind::Episode])
        .expect_err("over-bound limit must fail");
    assert!(matches!(error, QueryError::LimitOverBound { .. }));
}

#[test]
fn zero_limit_is_rejected() {
    let error = MemoryCandidateQuery::new(binding(), 0, vec![MemoryKind::Episode])
        .expect_err("zero limit must fail");
    assert!(matches!(error, QueryError::LimitOverBound { .. }));
}

#[test]
fn empty_allowlist_is_rejected() {
    let error =
        MemoryCandidateQuery::new(binding(), 10, vec![]).expect_err("empty allowlist must fail");
    assert!(matches!(error, QueryError::EmptyKinds));
}

#[test]
fn duplicate_allowlist_kind_is_rejected() {
    let error = MemoryCandidateQuery::new(
        binding(),
        10,
        vec![MemoryKind::Episode, MemoryKind::Episode],
    )
    .expect_err("duplicate kind must fail");
    assert!(matches!(error, QueryError::DuplicateKind { .. }));
}

#[test]
fn invalid_batch_is_rejected_upstream() {
    // Break one record fence so upstream batch validation fails.
    let mut fenced = batch();
    fenced.records[0].state_fence = StateFence::new(
        EpochId::new(lineage(), NonZeroU64::new(7).expect("non-zero")).expect("fixture epoch"),
        ResourceGeneration::genesis(),
    );
    let error = select(&query(256, vec![MemoryKind::Episode]), &fenced).expect_err("bad fence");
    assert!(matches!(error, QueryError::Upstream(_)));
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "binding": {
            "task_id": "task-memproj",
            "scope_id": "scope-memproj",
            "session_id": "session-memproj",
            "state_fence": {
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 1
                },
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            }
        },
        "limit": 10,
        "kinds": ["EPISODE"],
        "similarity_cutoff": 0.5
    });
    let error =
        serde_json::from_value::<MemoryCandidateQuery>(json).expect_err("unknown field must fail");
    assert!(error.to_string().contains("similarity_cutoff"));
}

#[test]
fn snapshot_roundtrips_over_the_wire() {
    let snapshot = select(&query(256, vec![MemoryKind::Episode]), &batch()).expect("valid");
    let wire = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let back: eliot_memory_projection::MemoryCandidateSnapshot =
        serde_json::from_str(&wire).expect("deserialize snapshot");
    assert_eq!(snapshot, back);
}
