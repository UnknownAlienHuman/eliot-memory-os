//! #196 W3 negative fixtures: an unavailable/blocked outcome that does not
//! name its missing owner, and an extra/unknown provider class.
//!
//! Both cases drive existing production validators through their real entry
//! points. Neither adds a type, a variant, or a fixture truth that the source
//! does not already carry.
//!
//! ## What the closed provider-class set is, measured
//!
//! The rev12 "closed seven-class provider set" has **no referent in current
//! source**. `crates/smart/cognitive-rev12-contract-schema-freeze.toml:4129`
//! records it as `[[not_frozen]]` with
//! `r11_disposition = "MISSING_CONTRACT_DECISION"`, and `:4134` measures that
//! `SemanticRole` (`crates/smart/eliot-context-contracts/src/identity.rs`)
//! has FOURTEEN members and `ProviderRole` is a two-field slot struct, not an
//! enum. The file the issue body cites for the seven,
//! `cognitive-rev12-coverage.toml`, has never existed in this repository. So
//! these fixtures deliberately do **not** assert membership against a
//! seven-member vocabulary, and do not invent one. What they do assert is the
//! property that is decidable in source today and that the frozen item asks
//! for: an **extra or unknown class is refused by an existing typed error**,
//! never admitted by a permissive default.
//!
//! **Membership is decided separately, and these assertions do not change.**
//! The `eliot-context-contracts` owner has since closed the membership
//! question: the provider axis IS the existing `SemanticRole` axis, the closed
//! set is its fourteen declared members, and the deciding document sentences
//! are recorded on the enum itself
//! (`crates/smart/eliot-context-contracts/src/identity.rs`, "Semantic role of a
//! whole Context unit — and, by decision, the CLOSED PROVIDER CLASS SET").
//! The per-class positive and negative cases are in
//! `tests/provider_class_membership.rs`. Nothing here is relaxed by that
//! decision: an extra or unknown class still cannot slip through admission,
//! and the seven names the issue body claimed are refused there individually.

#![allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{
    AtomAvailability, AtomRepresentation, AuthorityClass, CONTEXT_CONTRACT_VERSION, CapacityLimits,
    ContextBinding, ContextCandidate, ContextCandidateSet, ContextError, ContextRecipe,
    DecisionRevision, LossPolicy, MeasurementRef, PrivacyClass, ProofBinding, ProviderDisposition,
    ProviderId, ProviderRole, ProviderRoleDenominator, QualityApplicability,
    QualityApplicabilityInput, QualityApplicabilityResolution, QualityApplicabilityResolutionSet,
    QualityOperation, RepresentationKind, RoleLossRule, SemanticRole, SourceSnapshot,
};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest() -> String {
    "a".repeat(64)
}

fn decision_revision(context: &ContextBinding) -> DecisionRevision {
    DecisionRevision {
        decision_id: context.decision_id.clone(),
        recipe_revision: TaskRevision::new(1).expect("fixture revision"),
        policy_sha256: digest(),
    }
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

/// One admitted provider slot: a requested denominator whose single disposition
/// is `PresentCurrent`, so nothing about the fixture itself is incomplete.
fn provider_denominator() -> ProviderRoleDenominator {
    let requested = slot("fixture-provider", SemanticRole::Goal);
    ProviderRoleDenominator {
        dispositions: vec![ProviderDisposition {
            slot: requested.clone(),
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        }],
        requested: vec![requested],
    }
}

/// A recipe whose single mandatory class and single required rule agree, so the
/// fixture is an admitted control before any provider class is changed.
fn base_recipe(context: &ContextBinding) -> ContextRecipe {
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: decision_revision(context),
        recipe_sha256: digest(),
        denominator: provider_denominator(),
        mandatory_roles: vec![SemanticRole::Goal],
        role_policies: vec![RoleLossRule {
            role: SemanticRole::Goal,
            loss_policy: LossPolicy::NonDroppable,
            required: true,
            allowed_representations: vec![RepresentationKind::Whole],
        }],
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
    // test. Resealing here is what makes the refusal attributable.
    recipe.recipe_sha256 = recipe
        .canonical_policy_digest()
        .expect("fixture policy digest");
    recipe
}

/// A candidate bound to the recipe's own slot, so a recipe-level provider-class
/// refusal is never masked by an unrelated candidate defect.
fn candidate(context: &ContextBinding) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id("atom"),
        provider_role: slot("fixture-provider", SemanticRole::Goal),
        source_range: None,
        source: SourceSnapshot {
            source_id: SourceId::new("source").expect("fixture source"),
            owner: ProviderId::new("fixture-provider").expect("fixture owner"),
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

// WORK_UNIT_CASE: 196/W3-4
#[test]
fn an_extra_provider_class_is_refused_rather_than_admitted() {
    let context = binding();

    // Control: the single-class recipe and the candidate bound to its own slot
    // are both admitted before anything is changed, so every refusal below is
    // attributable to the provider class and not to a defective fixture.
    let admitted = base_recipe(&context);
    admitted.validate().expect("one declared class validates");
    candidate(&context)
        .validate()
        .expect("control candidate validates");

    // The closed set is the owner's to declare, so this fixture does not claim
    // which classes belong in it. It claims the decidable half: a class added
    // to the recipe's rule set without a matching mandatory declaration is an
    // EXTRA class relative to the recipe's own denominator, and
    // `ContextRecipe::validate` refuses it as `DenominatorMismatch` because the
    // required-rule set and the mandatory-class set must be equal.
    let mut extra = base_recipe(&context);
    extra.role_policies.push(RoleLossRule {
        role: SemanticRole::Source,
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

    // The symmetric extra: a mandatory class with no rule at all. Same typed
    // refusal family, reached from the other side of the same equality, so
    // neither direction can be satisfied by leaving the other one unchecked.
    let mut undeclared = base_recipe(&context);
    undeclared.mandatory_roles.push(SemanticRole::Source);
    undeclared.recipe_sha256 = undeclared
        .canonical_policy_digest()
        .expect("resealed digest for the undeclared class");
    assert_eq!(
        undeclared.validate(),
        Err(ContextError::MissingField("recipe.role_policies"))
    );

    // An UNKNOWN class value cannot be constructed through the typed API at
    // all: `SemanticRole` is a closed enum, so there is no "Other" or default
    // member to smuggle an extra class through, and a wire value outside the
    // closed set fails at decode. Both halves matter — a closed type with no
    // catch-all, and a decode that fails rather than defaulting.
    assert!(serde_json::from_str::<SemanticRole>("\"NOT_A_PROVIDER_CLASS\"").is_err());
    assert!(serde_json::from_str::<SemanticRole>("\"SOURCE\"").is_ok());
    assert!(serde_json::from_str::<SemanticRole>("null").is_err());

    // And the closedness is visible in the generated schema, not only in the
    // decoder: the enumerator lists the owner's members and admits no other.
    let schema = serde_json::to_string(&schemars::schema_for!(SemanticRole))
        .expect("semantic role schema encoding");
    assert!(schema.contains("CONSTRAINT"));
    assert!(!schema.contains("NOT_A_PROVIDER_CLASS"));

    // Finally, the admission owner refuses an extra class at the point material
    // actually enters: a candidate whose provider slot is outside the requested
    // denominator is refused as `DenominatorMismatch`. The recipe-level checks
    // above prove the declared set is coherent; this one proves an undeclared
    // class cannot arrive attached to real material. The control candidate is
    // admitted first, so the refusal is attributable to the class alone.
    let mut extra_slot = candidate(&context);
    extra_slot.provider_role = slot("fixture-provider", SemanticRole::Source);
    let set = ContextCandidateSet {
        binding: context.clone(),
        candidates: vec![extra_slot],
        denominator: provider_denominator(),
    };
    assert_eq!(
        set.validate_for_admission(),
        Err(ContextError::DenominatorMismatch),
        "a candidate carrying an undeclared provider class must be refused"
    );
}

// WORK_UNIT_CASE: 196/W3-3
#[test]
fn an_unavailable_outcome_without_a_named_missing_owner_is_refused() {
    // `QualityApplicabilityResolution::Unknown` is this crate's blocked /
    // unavailable outcome: no owner supplied the input, and the dependent
    // action is blocked rather than graded. It carries exactly one piece of
    // evidence — `missing_owner` — and that name is what makes it admissible.
    // A blank one is an unavailable outcome that names nobody, so a consumer
    // reading it cannot tell which owner to chase.
    //
    // The refusal is `QualityApplicabilityResolutionSet::validate` refusing the
    // blank name, and it is reached through `from_resolutions` — the real
    // production entry point that partitions the six inputs — rather than by
    // inspecting the enum directly. Existence or shape alone would prove
    // nothing: the same `Unknown` variant with a named owner is admitted and
    // lands in `unknown`, which is exactly the difference under test.
    let named = QualityApplicabilityResolutionSet {
        task_acceptance: QualityApplicabilityResolution::Resolved {
            owner: "task-controller".to_owned(),
            answer: "acceptance-goal-1".to_owned(),
        },
        route: QualityApplicabilityResolution::Resolved {
            owner: "task-controller".to_owned(),
            answer: "route-plan-1".to_owned(),
        },
        impact: QualityApplicabilityResolution::Resolved {
            owner: "impact-owner".to_owned(),
            answer: "impact-routine".to_owned(),
        },
        governance_profile: QualityApplicabilityResolution::Resolved {
            owner: "governor".to_owned(),
            answer: "governance-default".to_owned(),
        },
        protected_floor: QualityApplicabilityResolution::Resolved {
            owner: "safety-owner".to_owned(),
            answer: "safety-floor-1".to_owned(),
        },
        active_directive: QualityApplicabilityResolution::Unknown {
            missing_owner: "the Governor directive publisher named at issue #196 C1".to_owned(),
        },
    };

    // Control: the named owner is admissible, and it produces a typed blocked
    // outcome rather than a resolved one. This is the positive half that makes
    // the refusal below attributable to the missing NAME, not to the presence
    // of the `Unknown` variant.
    let partition = QualityApplicability::from_resolutions(&named)
        .expect("a named missing owner is admissible");
    assert_eq!(
        partition.unknown,
        vec![QualityApplicabilityInput::ActiveDirective],
        "an unavailable input with a named owner stays blocked, never resolved"
    );
    assert!(
        !partition
            .resolved
            .contains(&QualityApplicabilityInput::ActiveDirective)
    );
    assert!(QualityOperation::DependentAction.blocks_on_unresolved_applicability());

    // Now the same outcome with the name removed. Blank and whitespace-only are
    // both refused: `validate_text` rejects an empty-after-trim value, so a
    // name of spaces is not a name.
    for blank in ["", "   ", "\t\n"] {
        let mut unnamed = named.clone();
        unnamed.active_directive = QualityApplicabilityResolution::Unknown {
            missing_owner: blank.to_owned(),
        };
        assert_eq!(
            QualityApplicability::from_resolutions(&unnamed),
            Err(ContextError::InvalidField(
                "quality.applicability.missing_owner"
            )),
            "an unavailable outcome naming no owner must be refused: {blank:?}"
        );
    }

    // The same rule on the `Resolved` arm, which is the other way an owner
    // identity goes missing: `Resolved` names an owner and an answer, and a
    // blank owner is an answer nobody gave. Refusing it here keeps the rule
    // symmetric — a caller cannot launder an unnamed owner through the
    // resolved spelling to escape the check on the unknown one.
    let mut unnamed_resolved = named.clone();
    unnamed_resolved.task_acceptance = QualityApplicabilityResolution::Resolved {
        owner: String::new(),
        answer: "acceptance-goal-1".to_owned(),
    };
    assert_eq!(
        QualityApplicability::from_resolutions(&unnamed_resolved),
        Err(ContextError::InvalidField("quality.applicability.owner"))
    );

    // And the wire shape carries no escape hatch: the `Unknown` arm is tagged
    // and closed, so a payload cannot omit `missing_owner` and still decode as
    // an unavailable outcome. This is what stops "no named owner" from being
    // reachable by deserialization rather than only by construction.
    assert!(
        serde_json::from_str::<QualityApplicabilityResolution>(r#"{"status":"UNKNOWN"}"#).is_err(),
        "an UNKNOWN payload without missing_owner must fail to decode"
    );
    assert!(
        serde_json::from_str::<QualityApplicabilityResolution>(
            r#"{"status":"UNKNOWN","missing_owner":"governor"}"#
        )
        .is_ok()
    );
    assert!(
        serde_json::from_str::<QualityApplicabilityResolution>(r#"{"status":"MAYBE"}"#).is_err(),
        "an unrecognised resolution status must fail closed, not default"
    );
}
