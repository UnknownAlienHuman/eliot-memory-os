//! Contract fixtures for the memory projection read set.
//!
//! Provider and evaluator share these exact WorkScope/fence values: the
//! fixtures below bind one task, one scope, and one fence, and every
//! negative case derives from the same binding by changing exactly one
//! field.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, SessionId, SourceId,
    StateFence, TaskId,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_projection_contracts::{
    CONTRACT_VERSION, CoverageOmission, DenominatorState, ExclusionReason, MemoryFreshness,
    MemoryKind, MemoryProjectionBatch, MemoryProjectionRecord, MemoryRole, MemoryScopeBinding,
    ProjectionCoverage,
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

fn lineage() -> EpochLineageId {
    EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage")
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(lineage(), NonZeroU64::new(1).expect("non-zero")).expect("fixture epoch"),
        ResourceGeneration::genesis(),
    )
}

fn fence_other() -> StateFence {
    StateFence::new(
        EpochId::new(lineage(), NonZeroU64::new(7).expect("non-zero")).expect("fixture epoch"),
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

/// One minimal valid record bound to [`binding`] under [`fence`].
pub fn record(handle: &str) -> MemoryProjectionRecord {
    MemoryProjectionRecord {
        contract_version: CONTRACT_VERSION,
        handle: aid(handle),
        kind: MemoryKind::Episode,
        binding: binding(),
        state_fence: fence(),
        projection_revision: 1,
        epistemic: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        lifecycle: LifecycleState::Active,
        freshness: MemoryFreshness {
            state: eliot_memory_projection_contracts::FreshnessState::Current,
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

fn coverage_known(total: usize) -> ProjectionCoverage {
    ProjectionCoverage {
        denominator: DenominatorState::Known { total },
        truncated: false,
        frontier: vec![],
        omissions: vec![],
        revalidation_required: false,
    }
}

/// One minimal valid batch: two records, exact denominator, no loss.
pub fn batch() -> MemoryProjectionBatch {
    MemoryProjectionBatch {
        contract_version: CONTRACT_VERSION,
        binding: binding(),
        records: vec![record("mem-1"), record("mem-2")],
        coverage: coverage_known(2),
    }
}

#[test]
fn valid_batch_passes_shared_fence_gating() {
    batch().validate().expect("valid batch");
}

#[test]
fn record_fence_mismatch_fails_closed() {
    let mut candidate = batch();
    candidate.records[0].state_fence = fence_other();
    let error = candidate.validate().expect_err("fence mismatch must fail");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::FenceMismatch { .. }
    ));
}

#[test]
fn record_scope_mismatch_fails_closed() {
    let mut candidate = batch();
    candidate.records[0].binding.task_id = TaskId::new("task-other").expect("fixture task");
    let error = candidate.validate().expect_err("scope mismatch must fail");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::ScopeMismatch { .. }
    ));
}

#[test]
fn duplicate_handles_are_rejected() {
    let mut candidate = batch();
    candidate.records[1] = record("mem-1");
    let error = candidate.validate().expect_err("duplicates must fail");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::Duplicate { .. }
    ));
}

#[test]
fn truncated_coverage_without_frontier_is_rejected() {
    let mut candidate = batch();
    candidate.coverage.truncated = true;
    candidate.coverage.revalidation_required = true;
    let error = candidate
        .validate()
        .expect_err("frontier-less truncation must fail");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch { .. }
    ));
}

#[test]
fn unknown_denominator_stays_representable() {
    let mut candidate = batch();
    candidate.coverage.denominator = DenominatorState::Unknown {
        reason: "read side could not count".to_owned(),
    };
    candidate
        .validate()
        .expect("unknown denominator is explicit, not invalid");
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "contract_version": {"major": 0, "minor": 1, "patch": 0},
        "handle": "mem-1",
        "kind": "EPISODE",
        "binding": {
            "task_id": "task-cc008",
            "scope_id": "scope-cc008",
            "session_id": "session-cc008",
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
        "state_fence": {
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1
            },
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        },
        "projection_revision": 1,
        "epistemic": "SUPPORTED",
        "assertability": "NON_ASSERTABLE_UNVERIFIED",
        "lifecycle": "ACTIVE",
        "freshness": {"state": "CURRENT", "note": "n"},
        "provenance": {
            "source_id": "source-cc008",
            "capture_route": "governor.read.memory",
            "scope": "scope-cc008",
            "raw_handle": null,
            "revision": "rev-1"
        },
        "predecessor": null,
        "roles": ["MINORITY"],
        "influence_eligible": true,
        "preconditions": [],
        "applicability_limits": [],
        "cue_triggers": [],
        "negative_trigger": null,
        "source_id": "source-cc008",
        "similarity_score": 0.99
    });
    let error = serde_json::from_value::<MemoryProjectionRecord>(json).expect_err("unknown field");
    assert!(error.to_string().contains("similarity_score"));
}

#[test]
fn exclusion_reasons_cover_the_acceptance_cases() {
    let reasons = [
        ExclusionReason::Stale,
        ExclusionReason::Conflicted,
        ExclusionReason::Protected,
        ExclusionReason::NegativeMemory,
        ExclusionReason::PreconditionFailed {
            id: "pre-1".to_owned(),
        },
        ExclusionReason::FenceMismatch,
        ExclusionReason::ScopeMismatch,
    ];
    for reason in &reasons {
        reason.validate().expect("acceptance reason is valid");
    }
    // Wire roundtrip keeps every reason distinct.
    let wire = serde_json::to_string(&reasons).expect("serialize reasons");
    let back: Vec<ExclusionReason> = serde_json::from_str(&wire).expect("deserialize reasons");
    assert_eq!(reasons.as_slice(), back.as_slice());
}

#[test]
fn omission_entries_require_exact_reasons() {
    let omission = CoverageOmission {
        handle: aid("mem-9"),
        reason: String::new(),
    };
    omission
        .validate()
        .expect_err("blank omission reason must fail");
}

#[test]
fn stale_contract_version_is_rejected() {
    let mut stale = record("mem-1");
    stale.contract_version = ContractVersion::new(9, 9, 9);
    let error = stale.validate().expect_err("version drift must fail");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::VersionMismatch
    ));
}
