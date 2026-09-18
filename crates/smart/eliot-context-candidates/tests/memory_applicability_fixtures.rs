//! Issue #43 memory-slot fixtures: the eighth provider slot design.
//!
//! These fixtures pin the consumer-side contract without changing the mapped
//! denominator: the seven-slot path keeps mapping exactly seven slots, the
//! eight-slot check names the migration target, and the cue-hit
//! adversarial shows activation evidence staying advisory at the consumer
//! boundary. The mapper itself is untouched (#41 owns the mapped path).

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[allow(dead_code)]
mod helpers;

use eliot_context_candidates::inputs::check_denominator_is_seven;
use eliot_context_candidates::{
    MEMORY_PROVIDER, MemoryExclusion, MemoryInput, ProjectionState,
    check_denominator_is_seven_or_eight, eight_slots, memory_availability,
};
use eliot_context_contracts::{
    AtomAvailability, ContextError, ProviderId, ProviderRole, SemanticRole,
};
use helpers::{aid, binding, recipe_for};

fn memory_slot() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(MEMORY_PROVIDER).expect("memory provider"),
        role: SemanticRole::Evidence,
    }
}

#[test]
fn memory_slot_denominator_is_explicit() {
    let binding = binding();
    let seven_recipe = recipe_for(&binding);
    // The mapped seven-slot denominator is unchanged by the slot design.
    check_denominator_is_seven(&seven_recipe).expect("seven slots still map");
    check_denominator_is_seven_or_eight(&seven_recipe).expect("seven slots stay admissible");

    // The eighth slot joins by exact identity: seven-check rejects it,
    // eight-check accepts it, and a wrong eighth slot fails both.
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

    let mut wrong_recipe = seven_recipe.clone();
    wrong_recipe.denominator.requested.push(ProviderRole {
        provider: ProviderId::new("eliot.unknown.v9").expect("provider"),
        role: SemanticRole::Evidence,
    });
    assert!(matches!(
        check_denominator_is_seven_or_eight(&wrong_recipe),
        Err(ContextError::DenominatorMismatch)
    ));

    // The eight-slot vocabulary is exactly the seven slots plus memory.
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
fn cue_hit_without_applicability_stays_excluded() {
    let binding = binding();
    let cue_hit = aid("mem-gated");
    // Adversarial consumer view: the cue fired on `mem-gated`, the evaluator
    // refused it for a failed precondition, and the slot carries that exact
    // refusal with the cue flag noted but powerless.
    let input = MemoryInput {
        binding: binding.clone(),
        state: ProjectionState::Complete,
        applicable: vec![],
        excluded: vec![MemoryExclusion {
            handle: cue_hit.clone(),
            reason: "PRECONDITION_FAILED".to_owned(),
            cue_hit: true,
        }],
        cue_hits: vec![cue_hit.clone()],
        denominator_known: true,
        truncated: false,
    };
    input.validate().expect("adversarial slot is representable");
    // Slot availability reflects the readable projection, not per-record
    // standing: readability never promotes the excluded record.
    assert_eq!(
        memory_availability(&input),
        AtomAvailability::PresentCurrent
    );
    assert!(!input.applicable.contains(&cue_hit));
    assert!(input.excluded[0].cue_hit);

    // The slot boundary has teeth: overlapping handles, members under a
    // member-less state, applicable members without a denominator, and
    // duplicated cue hits are all rejected, never absorbed.
    let mut overlap = input.clone();
    overlap.applicable = vec![cue_hit.clone()];
    assert!(matches!(
        overlap.validate(),
        Err(ContextError::Duplicate(_))
    ));

    let mut missing = input.clone();
    missing.state = ProjectionState::Missing;
    missing.applicable = vec![aid("mem-other")];
    assert!(matches!(
        missing.validate(),
        Err(ContextError::InvalidField(_))
    ));

    let mut no_denominator = input.clone();
    no_denominator.denominator_known = false;
    no_denominator.applicable = vec![aid("mem-other")];
    assert!(matches!(
        no_denominator.validate(),
        Err(ContextError::InvalidField(_))
    ));

    let mut dup_hits = input.clone();
    dup_hits.cue_hits = vec![cue_hit.clone(), cue_hit.clone()];
    assert!(matches!(
        dup_hits.validate(),
        Err(ContextError::Duplicate(_))
    ));
}
