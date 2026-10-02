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
    StateFence, TaskId, TaskRevision,
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

/// A fence on the same epoch and generation as [`fence`] that additionally
/// carries a task revision.
///
/// `StateFence::is_compatible_with` treats an absent optional revision on
/// either side as a match, so `fence()` and this fence are mutually
/// compatible while comparing unequal. That makes them the one honest way to
/// build a compatible-but-distinct fence pair in this fixture family;
/// `fence_other` differs in epoch sequence and is therefore incompatible.
fn fence_with_task_revision() -> StateFence {
    StateFence {
        task_revision: Some(TaskRevision::new(1).expect("fixture revision")),
        ..fence()
    }
}

fn binding_at(state_fence: StateFence) -> MemoryScopeBinding {
    MemoryScopeBinding {
        task_id: task(),
        scope_id: scope(),
        session_id: Some(session()),
        state_fence,
    }
}

fn binding() -> MemoryScopeBinding {
    binding_at(fence())
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
fn a_compatible_projection_fence_is_admitted_when_the_declared_binding_matches() {
    // The positive half of the scope/fence rule, and the reason the rule stops
    // where it does: a record projected at an older-but-compatible fence is a
    // legitimate read observation and stays admissible. What must equal the
    // batch is the binding the record DECLARES, not the fence it was read
    // under. Tightening this into `record.state_fence ==
    // batch.binding.state_fence` would reject every record read before the
    // batch's own fence, which is the normal case the relaxation exists for.
    let mut candidate = batch();
    candidate.binding = binding_at(fence_with_task_revision());
    for record in &mut candidate.records {
        record.binding = candidate.binding.clone();
        // Compatible with the batch fence, and unequal to it.
        record.state_fence = fence();
    }
    candidate
        .validate()
        .expect("a compatible projection fence with an equal declared binding passes");
}

#[test]
fn a_record_declaring_another_scope_fence_is_refused_even_when_compatible() {
    // The wrong-scope record the batch previously admitted: task, scope and
    // session all match, and the record's own projection fence is compatible
    // with the batch fence, so both pre-existing checks pass. Only the
    // declared binding fence differs, which means the record asserts it was
    // projected under a different scope while reading as if it were this one.
    // A digest computed over this batch would then cover a record from
    // outside the scope it claims.
    let mut candidate = batch();
    candidate.binding = binding_at(fence_with_task_revision());
    for record in &mut candidate.records {
        // Declares the other scope; its own projection fence stays compatible,
        // so only the declared binding gives the record away.
        record.binding = binding_at(fence());
    }
    let error = candidate
        .validate()
        .expect_err("a record declaring another scope fence must fail closed");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::FenceMismatch {
            left: "record.binding.state_fence",
            right: "batch.binding.state_fence",
        }
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

// WORK_UNIT_CASE: 196/W3-2
#[test]
fn a_record_declaring_another_work_scope_is_refused_by_the_scope_comparison() {
    // The wrong-scope record, on the `scope_id` axis specifically. Task,
    // session, the declared binding fence and the record's own projection fence
    // are all left exactly equal to the batch's, so every other comparison in
    // `MemoryProjectionBatch::validate` passes and only the scope identity
    // differs. A batch digest computed over this record would then cover
    // material from a scope the batch never claimed.
    //
    // The `scope_id` term is the one arm of the scope comparison with no
    // fixture anywhere in this crate: `record_scope_mismatch_fails_closed`
    // varies `task_id`, and the two fence fixtures vary `state_fence`. Nothing
    // here is weakened to make the case pass: the two control batches below
    // are the ordinary admitted shapes, and only the one field differs.
    let mut candidate = batch();
    candidate.records[0].binding.scope_id = WorkScopeId::new("scope-other-cc008").expect("other scope");
    let error = candidate
        .validate()
        .expect_err("a record from another work scope must fail closed");
    assert_eq!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::ScopeMismatch {
            reason: "record binding must equal the batch binding",
        },
        "the refusal must be the typed scope comparison, not a fence relaxation"
    );

    // Control: the identical batch with the scope restored is admitted, so the
    // refusal above is attributable to the scope identity alone.
    let mut admitted = batch();
    admitted.records[0].binding.scope_id = scope();
    admitted.validate().expect("the in-scope record is ordinary evidence");

    // Control: the mismatch is refused even when the batch is otherwise
    // perfect coverage — the scope comparison is not conditioned on coverage.
    let mut lossy = batch();
    lossy.coverage.denominator = DenominatorState::Known { total: 3 };
    lossy.coverage.omissions = vec![CoverageOmission {
        handle: aid("mem-3"),
        reason: "fence-mismatch".to_owned(),
    }];
    lossy.coverage.revalidation_required = true;
    lossy.records[0].binding.scope_id = WorkScopeId::new("scope-other-cc008").expect("other scope");
    assert!(matches!(
        lossy.validate(),
        Err(eliot_memory_projection_contracts::MemoryProjectionError::ScopeMismatch { .. })
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
    // The positive half of the unknown-denominator rule, and the reason the
    // rule is a ceiling rather than a refusal: the state remains expressible.
    // What it may not do is travel beside a closed revalidation claim, because
    // that is the one combination that reads as a complete read nobody can
    // prove is complete.
    candidate.coverage.revalidation_required = true;
    candidate
        .validate()
        .expect("unknown denominator is explicit, not invalid");
}

#[test]
fn an_unknown_denominator_may_not_close_revalidation() {
    // The same batch as `unknown_denominator_stays_representable` with the
    // revalidation flag dropped. Nothing is truncated and nothing is omitted,
    // so the previous rule had no term to fire on, and the batch passed while
    // asserting both that it could not count its observed population and that
    // the consumer therefore had nothing to revalidate. That is the frozen
    // `ProjectionCoverage` note read backwards: "Unknown stays representable
    // but no consumer may read it as completeness." Substituting the returned
    // record count for the missing denominator would be the same claim with a
    // number attached, which is why the fix requires the ceiling instead.
    let mut candidate = batch();
    candidate.coverage.denominator = DenominatorState::Unknown {
        reason: "read side could not count".to_owned(),
    };
    let error = candidate
        .validate()
        .expect_err("an unprovable denominator cannot claim no revalidation");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch {
            reason: "an unknown denominator requires revalidation",
        }
    ));
}

#[test]
fn unaccounted_known_remainder_is_refused() {
    // The control-flow counterexample: an empty batch that declares one
    // observed record, projects none of it, omits none, defers none, and
    // claims no truncation. Unclaimed completeness, refused at the owner.
    let mut candidate = batch();
    candidate.records.clear();
    candidate.coverage = coverage_known(1);
    let error = candidate
        .validate()
        .expect_err("an unaccounted known remainder must fail closed");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch { .. }
    ));
}

#[test]
fn duplicate_omission_identities_are_refused() {
    let mut candidate = batch();
    candidate.coverage.denominator = DenominatorState::Known { total: 4 };
    candidate.coverage.revalidation_required = true;
    candidate.coverage.omissions = vec![
        CoverageOmission {
            handle: aid("mem-3"),
            reason: "fence-mismatch".to_owned(),
        },
        CoverageOmission {
            handle: aid("mem-3"),
            reason: "scope-mismatch".to_owned(),
        },
    ];
    let error = candidate
        .validate()
        .expect_err("one observed record cannot be omitted twice");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::Duplicate {
            field: "coverage.omissions",
            ..
        }
    ));
}

#[test]
fn projected_and_omitted_identities_cannot_overlap() {
    let mut candidate = batch();
    candidate.coverage.denominator = DenominatorState::Known { total: 3 };
    candidate.coverage.revalidation_required = true;
    candidate.coverage.omissions = vec![CoverageOmission {
        handle: aid("mem-1"),
        reason: "fence-mismatch".to_owned(),
    }];
    let error = candidate
        .validate()
        .expect_err("one observed record cannot be both returned and lost");
    assert!(matches!(
        error,
        eliot_memory_projection_contracts::MemoryProjectionError::Duplicate {
            field: "coverage.omissions",
            ..
        }
    ));
}

#[test]
fn a_truncated_batch_retains_its_exact_remainder() {
    let mut candidate = batch();
    candidate.coverage.denominator = DenominatorState::Known { total: 3 };
    candidate.coverage.truncated = true;
    candidate.coverage.revalidation_required = true;
    candidate.coverage.frontier = vec!["mem-3".to_owned()];
    candidate
        .validate()
        .expect("one deferred identity with truncation is exact");
    // Claiming truncation while returning nothing deferred is unclaimed
    // volume rather than a truncation.
    let mut unbacked = candidate.clone();
    unbacked.coverage.frontier.clear();
    assert!(matches!(
        unbacked.validate(),
        Err(eliot_memory_projection_contracts::MemoryProjectionError::CoverageMismatch { .. })
    ));
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
