//! #196 provider-class MEMBERSHIP, not just closedness.
//!
//! `unavailable_owner_and_provider_class.rs` proves the decidable half: an
//! extra or unknown class is refused. This file closes the membership question
//! that file deliberately left open, by pinning WHICH classes the closed
//! provider class set contains.
//!
//! # The decision these fixtures encode
//!
//! The provider axis IS the existing semantic role axis. There is no separate
//! provider-class enum. The deciding document pair is:
//!
//! - `docs/architecture/I07-11-context-payload-profiles-and-decision-safety-floor.md:5-15`
//!   closes the atom class axis as `ContextAtomPolicy.class`, enumerating
//!   `AUTHORITY | GOAL | SCOPE | ACCEPTANCE | SOURCE | VERIFIER |
//!   MATERIAL_UNKNOWN | NEGATIVE | SECURITY | OPTIONAL`;
//! - `docs/architecture/I12-13-context-compiler.md:55,59` budgets the same axis
//!   as `ContextSectionBudget.semantic_role`.
//!
//! Neither attaches a class to the PROVIDER: the provider identity is
//! `ProviderId`, a validated free-text label, and the class of what it supplied
//! is the `role` carried on `ProviderRole`. So the closed provider class set is
//! `SemanticRole` itself, and its members are the fourteen the declaration
//! names. The four beyond I7.11's ten (`CONFLICT`, `CONSTRAINT`, `INSTRUCTION`,
//! `EVIDENCE`) are each required by normative prose in the same two documents.
//!
//! Issue #196 §2 instead names seven classes from `cognitive-rev12-coverage.toml`.
//! That file has never existed in this repository, and the seven member names
//! name no referent on `main` (four of them have no referent anywhere; the other
//! three are live symbols under other owners). The count is therefore not
//! seven, and these fixtures pin the fourteen that are real.

#![allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{
    AtomAvailability, AtomRepresentation, AuthorityClass, CONTEXT_CONTRACT_VERSION, CapacityLimits,
    ContextBinding, ContextCandidate, ContextCandidateSet, ContextError, ContextRecipe,
    DecisionRevision, LossPolicy, MeasurementRef, PrivacyClass, ProofBinding, ProviderDisposition,
    ProviderId, ProviderRole, ProviderRoleDenominator, RepresentationKind, RoleLossRule,
    SemanticRole, SourceSnapshot,
};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

/// The closed provider class set, each member paired with its exact wire
/// spelling as `identity.rs` spells it under
/// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`.
const CLOSED_PROVIDER_CLASSES: [(SemanticRole, &str); 14] = [
    (SemanticRole::Authority, "AUTHORITY"),
    (SemanticRole::Goal, "GOAL"),
    (SemanticRole::Scope, "SCOPE"),
    (SemanticRole::Acceptance, "ACCEPTANCE"),
    (SemanticRole::Source, "SOURCE"),
    (SemanticRole::Verifier, "VERIFIER"),
    (SemanticRole::MaterialUnknown, "MATERIAL_UNKNOWN"),
    (SemanticRole::Negative, "NEGATIVE"),
    (SemanticRole::Security, "SECURITY"),
    (SemanticRole::Evidence, "EVIDENCE"),
    (SemanticRole::Instruction, "INSTRUCTION"),
    (SemanticRole::Optional, "OPTIONAL"),
    (SemanticRole::Conflict, "CONFLICT"),
    (SemanticRole::Constraint, "CONSTRAINT"),
];

/// Every class name the #196 issue body claimed, none of which exists on `main`.
/// Listed here so a reader sees that the retirement is measured, not asserted:
/// each one is refused below.
const RETIRED_SEVEN: [&str; 7] = [
    "GOAL_TASK",
    "CRITICAL_ATTENTION",
    "EPISTEMIC_POSITION",
    "MEMORY_RECALL",
    "AUTHORITY_AFFORDANCE",
    "SELF_MODEL",
    "DECISION_TAIL",
];

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest() -> String {
    "a".repeat(64)
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
        std::num::NonZeroU64::new(1).expect("fixture sequence"),
    )
    .expect("fixture epoch")
}

fn binding() -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new("task").expect("fixture task"),
        attempt_id: AgentAttemptId::new("attempt").expect("fixture attempt"),
        scope_id: WorkScopeId::new("scope").expect("fixture scope"),
        state_fence: StateFence::new(
            test_epoch(),
            ResourceGeneration::new(1).expect("fixture generation"),
        ),
        decision_id: DecisionId::new("decision").expect("fixture decision"),
        operation_id: None,
    }
}

fn slot(provider: &str, role: SemanticRole) -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(provider).expect("fixture provider"),
        role,
    }
}

/// A denominator requesting exactly the classes the recipe declares, each
/// `PresentCurrent`, so the fixture itself never contributes a refusal.
fn denominator_for(roles: &[SemanticRole]) -> ProviderRoleDenominator {
    let requested: Vec<ProviderRole> = roles
        .iter()
        .enumerate()
        .map(|(index, role)| slot(&format!("provider-{index}"), *role))
        .collect();
    ProviderRoleDenominator {
        dispositions: requested
            .iter()
            .cloned()
            .map(|slot| ProviderDisposition {
                slot,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            })
            .collect(),
        requested,
    }
}

/// A recipe declaring exactly `roles`, coherent by construction: one rule per
/// declared class, every rule required, so the required set equals the
/// mandatory set and the recipe is an admitted control.
fn recipe_for(context: &ContextBinding, roles: &[SemanticRole]) -> ContextRecipe {
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: DecisionRevision {
            decision_id: context.decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("fixture revision"),
            policy_sha256: digest(),
        },
        recipe_sha256: digest(),
        denominator: denominator_for(roles),
        mandatory_roles: roles.to_vec(),
        role_policies: roles
            .iter()
            .map(|role| RoleLossRule {
                role: *role,
                loss_policy: LossPolicy::NonDroppable,
                required: true,
                allowed_representations: vec![RepresentationKind::Whole],
            })
            .collect(),
        capacity: CapacityLimits {
            route_capacity: 100,
            fixed_overhead: 1,
            output_reserve: 1,
            review_reserve: 1,
        },
        predecessor: None,
        invalidation: None,
    };
    // The recipe digest is content-bound, so a changed fixture must reseal it
    // or it would be refused by the digest guard instead of the rule under
    // test. Resealing is what makes each refusal attributable.
    recipe.recipe_sha256 = recipe
        .canonical_policy_digest()
        .expect("fixture policy digest");
    recipe
}

/// A candidate whose slot is `provider-0` in the named class, so a
/// candidate-level refusal is attributable to the class and not to an unrelated
/// defect.
fn candidate(context: &ContextBinding, role: SemanticRole) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id("atom"),
        provider_role: slot("provider-0", role),
        source_range: None,
        source: SourceSnapshot {
            source_id: SourceId::new("source").expect("fixture source"),
            owner: ProviderId::new("provider-0").expect("fixture owner"),
            snapshot_id: id("snapshot"),
            revision: "r1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        learning: None,
        representation: AtomRepresentation::Whole {
            content: "whole".to_owned(),
        },
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: false,
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: digest(),
            serializer: "serde-json".to_owned(),
        },
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id("evidence"),
            ceiling: ProofCeiling::Observation,
        },
    }
}

// WORK_UNIT_CASE: 196/provider-class-membership-positive
#[test]
fn every_member_of_the_closed_provider_class_set_is_admitted() {
    let context = binding();
    let roles: Vec<SemanticRole> = CLOSED_PROVIDER_CLASSES
        .iter()
        .map(|(role, _)| *role)
        .collect();

    // The whole declared set at once. This is the positive case: a recipe that
    // declares every member of the closed provider class set is ADMITTED, so
    // the set recorded in the doc comment is the set the owner validators
    // accept, and the claim is not vacuous.
    let all = recipe_for(&context, &roles);
    all.validate()
        .expect("every closed provider class is admissible together");

    // Each member also stands alone, so no single class is carried only by the
    // cohort. This is what makes the membership per-class rather than a
    // whole-set artifact: a member that were refused would fail here while the
    // combined recipe passed.
    for (role, wire) in CLOSED_PROVIDER_CLASSES {
        recipe_for(&context, &[role])
            .validate()
            .unwrap_or_else(|error| panic!("{wire} must be an admitted class, got {error:?}"));

        // Each member reaches its EXACT wire spelling, in both directions, and
        // the slot carrying it is a well-formed provider/role slot. This is the
        // wire half of membership: a member that decoded under a different
        // spelling would break every consumer reading the frozen name.
        let encoded = serde_json::to_string(&role).expect("class encoding");
        assert_eq!(
            encoded,
            format!("\"{wire}\""),
            "{wire} must be the exact wire spelling of its Rust variant"
        );
        assert_eq!(
            serde_json::from_str::<SemanticRole>(&encoded).expect("member decodes"),
            role,
            "{wire} must decode back to its own variant"
        );
        slot("provider-0", role)
            .validate()
            .unwrap_or_else(|error| panic!("slot carrying {wire} must be well formed: {error:?}"));
    }

    // And a member's material is admitted through the real candidate
    // validator, so membership is not confined to recipe policy.
    candidate(&context, SemanticRole::MaterialUnknown)
        .validate()
        .expect("a candidate in a closed-set class validates");

    // The generated schema is the third surface. It must enumerate the whole
    // closed set and admit nothing outside it, so a consumer reading the
    // schema sees exactly these classes.
    let schema =
        serde_json::to_string(&schemars::schema_for!(SemanticRole)).expect("schema encoding");
    for (_, wire) in CLOSED_PROVIDER_CLASSES {
        assert!(
            schema.contains(&format!("\"{wire}\"")),
            "the schema must enumerate {wire}"
        );
    }
    for retired in RETIRED_SEVEN {
        assert!(
            !schema.contains(&format!("\"{retired}\"")),
            "{retired} is retired and must not reappear in the schema"
        );
    }
}

// WORK_UNIT_CASE: 196/provider-class-membership-refusal
#[test]
fn a_class_outside_the_closed_provider_class_set_is_refused() {
    let context = binding();

    // Control first: the single-class recipe and the candidate bound to its own
    // slot are admitted before anything is changed, so every refusal below is
    // attributable to the class and not to a defective fixture.
    recipe_for(&context, &[SemanticRole::Goal])
        .validate()
        .expect("one declared class validates");
    candidate(&context, SemanticRole::Goal)
        .validate()
        .expect("control candidate validates");

    // The seven names the issue body claims are refused at the wire, each one
    // individually so a partial match cannot hide. A closed type with no
    // catch-all and a decode that fails rather than defaulting is what makes
    // these refusals possible at all.
    for retired in RETIRED_SEVEN {
        assert!(
            serde_json::from_str::<SemanticRole>(&format!("\"{retired}\"")).is_err(),
            "{retired} is not a class of the closed set and must not decode"
        );
    }

    // The other retired spellings from the same claim, in the exact CamelCase
    // the issue body used, so the refusal is not an artifact of the rename.
    for camel in [
        "GoalTask",
        "CriticalAttention",
        "EpistemicPosition",
        "MemoryRecall",
        "AuthorityAffordance",
        "SelfModel",
        "DecisionTail",
    ] {
        assert!(
            serde_json::from_str::<SemanticRole>(&format!("\"{camel}\"")).is_err(),
            "{camel} is not a class of the closed set and must not decode"
        );
    }

    // A Rust-side name outside the set cannot be constructed either, and a
    // payload cannot smuggle one in through an absent, empty or null value.
    assert!(serde_json::from_str::<SemanticRole>("null").is_err());
    assert!(serde_json::from_str::<SemanticRole>("\"\"").is_err());
    assert!(serde_json::from_str::<SemanticRole>("\"OTHER\"").is_err());

    // The same refusal at the ADMISSION point, where material actually enters:
    // a recipe that declares one class but carries a required rule for a
    // second class is refused by `ContextRecipe::validate` as
    // `DenominatorMismatch`, because the required-rule set and the
    // mandatory-class set must be equal. This is the typed refusal, not a
    // string verdict: an extra class cannot be added to the declared set from
    // either side.
    let mut extra = recipe_for(&context, &[SemanticRole::Goal]);
    extra.role_policies.push(RoleLossRule {
        role: SemanticRole::Evidence,
        loss_policy: LossPolicy::NonDroppable,
        required: true,
        allowed_representations: vec![RepresentationKind::Whole],
    });
    extra.recipe_sha256 = extra
        .canonical_policy_digest()
        .expect("resealed digest for the extra class");
    assert_eq!(
        extra.validate(),
        Err(ContextError::DenominatorMismatch),
        "an extra required provider class must be refused, not admitted"
    );

    // The symmetric extra, reached from the other side of the same equality: a
    // mandatory class with no rule at all is refused as a missing field, so
    // neither direction can be satisfied by leaving the other unchecked.
    let mut undeclared = recipe_for(&context, &[SemanticRole::Goal]);
    undeclared.mandatory_roles.push(SemanticRole::Security);
    undeclared.recipe_sha256 = undeclared
        .canonical_policy_digest()
        .expect("resealed digest for the undeclared class");
    assert_eq!(
        undeclared.validate(),
        Err(ContextError::MissingField("recipe.role_policies"))
    );

    // And the candidate side: material arriving in a class the declared
    // denominator does not request is refused with the same typed error. The
    // control candidate is admitted first, so the refusal is attributable to
    // the class alone.
    let set = ContextCandidateSet {
        binding: context.clone(),
        candidates: vec![candidate(&context, SemanticRole::Constraint)],
        denominator: denominator_for(&[SemanticRole::Goal]),
    };
    assert_eq!(
        set.validate_for_admission(),
        Err(ContextError::DenominatorMismatch),
        "a candidate carrying a class outside the declared denominator must be refused"
    );
}
