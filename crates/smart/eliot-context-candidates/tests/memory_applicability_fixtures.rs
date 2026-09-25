//! Issue #43 memory-slot fixtures: the typed eighth provider input.
//!
//! The memory slot is not a structural handle-list mirror. It carries the
//! exact owner batch and applicability verdict, plus the read identity needed
//! to recheck omission/frontier recovery. The mapped seven-slot path remains
//! unchanged; the eighth-slot vocabulary is only a migration target.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(dead_code)]
mod helpers;

use std::num::NonZeroU64;

use eliot_context_candidates::inputs::check_denominator_is_seven;
use eliot_context_candidates::{
    ContextError, MEMORY_PROVIDER, MemoryInput, ProjectionState,
    check_denominator_is_seven_or_eight, eight_slots, memory_availability,
};
use eliot_context_contracts::{AtomAvailability, ProviderId, ProviderRole, SemanticRole};
use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_projection_contracts::{
    ApplicableMemorySet, CoverageOmission, DenominatorState, ExcludedMemory, ExclusionReason,
    FreshnessState, MemoryFreshness, MemoryKind, MemoryProjectionBatch, MemoryProjectionRecord,
    MemoryRole, MemoryScopeBinding, ProjectionCoverage,
};
use helpers::{aid, binding, recipe_for, scope, source_id};

fn fence() -> StateFence {
    StateFence {
        task_revision: Some(TaskRevision::new(1).expect("fixture revision")),
        ..StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("fixture lineage"),
                NonZeroU64::new(1).expect("fixture sequence"),
            )
            .expect("fixture epoch"),
            ResourceGeneration::genesis(),
        )
    }
}

fn memory_binding() -> MemoryScopeBinding {
    let request_binding = binding();
    MemoryScopeBinding {
        task_id: request_binding.task_id,
        scope_id: request_binding.scope_id,
        session_id: None,
        state_fence: request_binding.state_fence,
    }
}

fn record() -> MemoryProjectionRecord {
    let owner_fence = fence();
    MemoryProjectionRecord {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        handle: aid("mem-gated"),
        kind: MemoryKind::Procedure,
        binding: memory_binding(),
        state_fence: owner_fence.clone(),
        projection_revision: 7,
        epistemic: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        lifecycle: LifecycleState::Active,
        freshness: MemoryFreshness {
            state: FreshnessState::Current,
            note: "projected at the fixture fence".to_owned(),
        },
        provenance: Provenance {
            source_id: source_id("memory-source"),
            capture_route: "governor.read.memory".to_owned(),
            scope: scope().as_str().to_owned(),
            raw_handle: None,
            revision: Some("revision-1".to_owned()),
        },
        predecessor: None,
        roles: vec![MemoryRole::Minority],
        influence_eligible: true,
        preconditions: Vec::new(),
        applicability_limits: Vec::new(),
        cue_triggers: Vec::new(),
        negative_trigger: None,
        source_id: source_id("memory-source"),
    }
}

fn batch(records: Vec<MemoryProjectionRecord>) -> MemoryProjectionBatch {
    let total = records.len();
    MemoryProjectionBatch {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        binding: memory_binding(),
        records,
        coverage: ProjectionCoverage {
            denominator: DenominatorState::Known { total },
            truncated: false,
            frontier: Vec::new(),
            omissions: Vec::new(),
            revalidation_required: false,
        },
    }
}

fn set_for(batch_value: &MemoryProjectionBatch) -> ApplicableMemorySet {
    ApplicableMemorySet {
        contract_version: eliot_memory_projection_contracts::CONTRACT_VERSION,
        binding: batch_value.binding.clone(),
        applicable: Vec::new(),
        excluded: vec![ExcludedMemory {
            handle: aid("mem-gated"),
            kind: MemoryKind::Procedure,
            reason: ExclusionReason::PreconditionFailed {
                id: "precondition-1".to_owned(),
            },
            cue_hit: true,
        }],
        denominator: batch_value.coverage.denominator.clone(),
        truncated: batch_value.coverage.truncated,
        revalidation_required: batch_value.coverage.revalidation_required,
        cue_hits_considered: 1,
    }
}

fn input() -> MemoryInput {
    let batch_value = batch(vec![record()]);
    let applicable = set_for(&batch_value);
    let source_batch_digest = batch_value
        .canonical_digest()
        .expect("batch source identity");
    MemoryInput {
        binding: binding(),
        state: ProjectionState::Complete,
        batch: batch_value,
        applicable,
        projection_read_receipt: aid("memory-read-receipt"),
        source_batch_digest,
        missing_owner: None,
    }
}

fn memory_slot() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(MEMORY_PROVIDER).expect("memory provider"),
        role: SemanticRole::Evidence,
    }
}

#[test]
fn memory_slot_denominator_is_explicit() {
    let request_binding = binding();
    let seven_recipe = recipe_for(&request_binding);
    check_denominator_is_seven(&seven_recipe).expect("seven slots still map");
    check_denominator_is_seven_or_eight(&seven_recipe).expect("seven slots stay admissible");

    let mut eight_recipe = seven_recipe.clone();
    eight_recipe.denominator.requested.push(memory_slot());
    eight_recipe.recipe_sha256 = eight_recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    assert!(matches!(
        check_denominator_is_seven(&eight_recipe),
        Err(ContextError::DenominatorMismatch)
    ));
    check_denominator_is_seven_or_eight(&eight_recipe).expect("exact eighth slot");

    let mut wrong_recipe = seven_recipe;
    wrong_recipe.denominator.requested.push(ProviderRole {
        provider: ProviderId::new("eliot.unknown.v9").expect("provider"),
        role: SemanticRole::Evidence,
    });
    assert!(matches!(
        check_denominator_is_seven_or_eight(&wrong_recipe),
        Err(ContextError::DenominatorMismatch)
    ));

    let mut eight = eight_slots().expect("eight slots");
    let mut seven = eliot_context_candidates::seven_slots().expect("seven slots");
    eight.sort();
    seven.sort();
    assert_eq!(eight.len(), seven.len() + 1);
    assert!(eight.contains(&memory_slot()));
    for slot in &seven {
        assert!(eight.contains(slot));
    }
}

#[test]
fn typed_memory_input_keeps_cue_hit_non_authoritative() {
    let value = input();
    value.validate().expect("typed memory input validates");
    assert_eq!(
        memory_availability(&value),
        AtomAvailability::PresentCurrent
    );
    assert!(value.applicable.applicable.is_empty());
    assert!(value.applicable.excluded[0].cue_hit);
    assert_eq!(value.applicable.excluded[0].handle, aid("mem-gated"));
}

#[test]
fn typed_memory_input_rejects_structural_drift_and_unnamed_recovery() {
    let mut value = input();
    value.source_batch_digest = "f".repeat(64);
    assert!(matches!(
        value.validate(),
        Err(ContextError::InvalidField("memory.source_batch_digest"))
    ));

    let mut value = input();
    value.state = ProjectionState::Missing;
    value.applicable.excluded.clear();
    value
        .applicable
        .applicable
        .push(eliot_memory_projection_contracts::ApplicableMemory {
            handle: aid("mem-gated"),
            kind: MemoryKind::Procedure,
            roles: vec![MemoryRole::Minority],
            cue_hit: true,
        });
    assert!(value.validate().is_err());

    let mut value = input();
    value.state = ProjectionState::Blocked {
        reason: "owner-read-blocked".to_owned(),
    };
    assert!(matches!(
        value.validate(),
        Err(ContextError::InvalidField("memory.missing_owner"))
    ));

    let mut value = input();
    value.batch.coverage.denominator = DenominatorState::Known { total: 2 };
    value.batch.coverage.omissions.push(CoverageOmission {
        handle: aid("mem-omitted"),
        reason: "owner-read-failed".to_owned(),
    });
    value.batch.coverage.revalidation_required = true;
    value.applicable.denominator = value.batch.coverage.denominator.clone();
    value.applicable.revalidation_required = true;
    value.missing_owner = Some(SourceId::new("memory-read-owner").expect("fixture owner"));
    value.state = ProjectionState::Partial {
        reason: "owner-read-recovery".to_owned(),
    };
    value.source_batch_digest = value
        .batch
        .canonical_digest()
        .expect("rebound recovery batch");
    value
        .validate()
        .expect("named owner binds explicit recovery");
}

#[test]
fn typed_memory_input_binds_set_to_exact_batch_members() {
    let mut value = input();
    value.applicable.excluded[0].kind = MemoryKind::Episode;
    assert!(value.validate().is_err());

    let mut value = input();
    value.applicable.cue_hits_considered = 513;
    assert!(matches!(
        value.validate(),
        Err(ContextError::Bounds {
            field: "memory.cue_hits_considered"
        })
    ));
}
