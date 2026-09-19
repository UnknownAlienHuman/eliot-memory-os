//! Work-unit 584 slice 1: Context contract and Decision Safety Floor vocabulary,
//! cases 1..12 (closed wire surface, identity, denominator, source lineage,
//! canonical digest, whole atoms, measurement binding).
//!
//! Remainder (cases 13..63) stays QUEUED on issue #584.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest() -> String {
    "a".repeat(64)
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
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

fn provider_role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("fixture-provider").expect("fixture provider"),
        role: SemanticRole::Goal,
    }
}

fn source_snapshot() -> SourceSnapshot {
    SourceSnapshot {
        source_id: eliot_contracts::SourceId::new("fixture-source").expect("fixture source"),
        owner: ProviderId::new("fixture-provider").expect("fixture owner"),
        snapshot_id: id("snapshot"),
        revision: "r1".to_owned(),
        content_sha256: digest(),
        predecessor: None,
    }
}

fn candidate() -> ContextCandidate {
    ContextCandidate {
        binding: binding(),
        atom_id: id("atom"),
        provider_role: provider_role(),
        source: source_snapshot(),
        representation: AtomRepresentation::Whole {
            content: "complete goal with source detail".to_owned(),
        },
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: true,
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: digest(),
            serializer: "fixture-serde-v1".to_owned(),
        },
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id("evidence"),
            ceiling: ProofCeiling::Observation,
        },
    }
}

fn denominator() -> ProviderRoleDenominator {
    ProviderRoleDenominator {
        requested: vec![provider_role()],
        dispositions: vec![ProviderDisposition {
            slot: provider_role(),
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        }],
    }
}

fn decision() -> DecisionRevision {
    DecisionRevision {
        decision_id: binding().decision_id.clone(),
        recipe_revision: TaskRevision::new(1).expect("revision"),
        policy_sha256: digest(),
    }
}

fn recipe() -> ContextRecipe {
    let context = binding();
    let denominator = denominator();
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context,
        decision: decision(),
        recipe_sha256: digest(),
        denominator,
        mandatory_roles: vec![SemanticRole::Goal],
        role_policies: vec![RoleLossRule {
            role: SemanticRole::Goal,
            loss_policy: LossPolicy::NonDroppable,
            required: true,
            allowed_representations: vec![RepresentationKind::Whole],
        }],
        capacity: CapacityLimits {
            route_capacity: 100_000,
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
        },
        predecessor: None,
        invalidation: None,
    };
    recipe.recipe_sha256 = recipe
        .canonical_policy_digest()
        .expect("recipe policy digest");
    recipe
}

fn exact_measurement(context: &ContextBinding) -> SerializedContextMeasurement {
    SerializedContextMeasurement {
        measurement_id: id("measurement"),
        context: context.clone(),
        schema_version: CONTEXT_CONTRACT_VERSION,
        envelope_digest: digest(),
        serializer_id: "serde-json".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        rendered_utf8_bytes: 13,
        stu_estimate: None,
        tokenizer: None,
        status: MeasurementStatus::ExactUtf8,
        fixed_overhead: 2,
        output_reserve: 3,
        review_reserve: 4,
        false_safe_overflow: None,
        false_rejection_or_decomposition: None,
        valid_until: None,
    }
}

#[derive(serde::Deserialize)]
struct LossPolicyHolder {
    policy: LossPolicy,
}

// WORK_UNIT_CASE: 584/2
#[test]
fn loss_policy_rejects_missing_unknown_and_null_variants() {
    assert!(serde_json::from_str::<LossPolicy>("\"NON DROPPABLE\"").is_err());
    assert!(serde_json::from_str::<LossPolicy>("\"non_droppable\"").is_err());
    assert!(serde_json::from_str::<LossPolicy>("\"\"").is_err());
    assert!(serde_json::from_str::<LossPolicy>("null").is_err());
    assert!(serde_json::from_str::<LossPolicy>("\"HANDLE_ONLY \"").is_err());
    assert!(serde_json::from_str::<LossPolicyHolder>(r"{}").is_err());
    assert!(serde_json::from_str::<LossPolicyHolder>(r#"{"policy":null}"#).is_err());
    let holder: LossPolicyHolder =
        serde_json::from_str(r#"{"policy":"EXTRACTIVE"}"#).expect("present field");
    assert_eq!(holder.policy, LossPolicy::Extractive);
}

// WORK_UNIT_CASE: 584/3
#[test]
fn recipe_identity_round_trip() {
    let recipe = recipe();
    recipe.validate().expect("valid recipe");
    assert_eq!(
        recipe.recipe_sha256,
        recipe
            .canonical_policy_digest()
            .expect("stable policy digest")
    );
    let encoded = serde_json::to_string(&recipe).expect("recipe encoding");
    let decoded: ContextRecipe = serde_json::from_str(&encoded).expect("recipe round-trip");
    assert_eq!(decoded, recipe);
    decoded.validate().expect("decoded recipe validates");
}

// WORK_UNIT_CASE: 584/4
#[test]
fn task_attempt_scope_fence_mismatch_rejected() {
    let mut recipe = recipe();
    recipe.decision.decision_id = DecisionId::new("other-decision").expect("fixture decision");
    assert_eq!(recipe.validate(), Err(ContextError::IdentityConflict));

    let context = binding();
    let mut foreign = candidate();
    foreign.binding.task_id = TaskId::new("other-task").expect("fixture task");
    let set = ContextCandidateSet {
        binding: context,
        candidates: vec![foreign],
        denominator: denominator(),
    };
    assert_eq!(
        set.validate_for_admission(),
        Err(ContextError::InvalidFence)
    );
}

// WORK_UNIT_CASE: 584/5
#[test]
fn exact_provider_role_denominator_with_one_slot_per_provider() {
    let denominator = denominator();
    assert_eq!(denominator.requested.len(), 1);
    denominator.validate().expect("exact denominator");
    let empty = ProviderRoleDenominator {
        requested: Vec::new(),
        dispositions: Vec::new(),
    };
    assert_eq!(
        empty.validate(),
        Err(ContextError::MissingField("denominator.requested"))
    );
}

// WORK_UNIT_CASE: 584/6
#[test]
fn missing_duplicate_extra_provider_members_distinguished() {
    let other_slot = ProviderRole {
        provider: ProviderId::new("other-provider").expect("fixture provider"),
        role: SemanticRole::Source,
    };
    let missing = ProviderRoleDenominator {
        requested: vec![provider_role(), other_slot.clone()],
        dispositions: vec![ProviderDisposition {
            slot: provider_role(),
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        }],
    };
    assert_eq!(missing.validate(), Err(ContextError::DenominatorMismatch));
    let duplicate = ProviderRoleDenominator {
        requested: vec![provider_role(), provider_role()],
        dispositions: vec![ProviderDisposition {
            slot: provider_role(),
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        }],
    };
    assert_eq!(
        duplicate.validate(),
        Err(ContextError::Duplicate("denominator.requested"))
    );
    let extra = ProviderRoleDenominator {
        requested: vec![provider_role()],
        dispositions: vec![
            ProviderDisposition {
                slot: provider_role(),
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            },
            ProviderDisposition {
                slot: other_slot,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            },
        ],
    };
    assert_eq!(extra.validate(), Err(ContextError::DenominatorMismatch));
}

// WORK_UNIT_CASE: 584/7
#[test]
fn source_revision_content_predecessor_round_trip() {
    let source = source_snapshot();
    source.validate().expect("valid source snapshot");
    let encoded = serde_json::to_string(&source).expect("source encoding");
    let decoded: SourceSnapshot = serde_json::from_str(&encoded).expect("source round-trip");
    assert_eq!(decoded, source);

    let mut cyclic = source.clone();
    cyclic.predecessor = Some(cyclic.snapshot_id.clone());
    assert_eq!(cyclic.validate(), Err(ContextError::IdentityConflict));
    let mut bad_digest = source.clone();
    bad_digest.content_sha256 = "not-a-digest".to_owned();
    assert!(matches!(
        bad_digest.validate(),
        Err(ContextError::InvalidDigest(_))
    ));
}

// WORK_UNIT_CASE: 584/8
#[test]
fn set_permutation_preserves_canonical_policy_digest() {
    let mut recipe = recipe();
    recipe.mandatory_roles.push(SemanticRole::Source);
    recipe.role_policies.push(RoleLossRule {
        role: SemanticRole::Source,
        loss_policy: LossPolicy::HandleOnly,
        required: true,
        allowed_representations: vec![RepresentationKind::Handle],
    });
    let source_slot = ProviderRole {
        provider: ProviderId::new("other-provider").expect("fixture provider"),
        role: SemanticRole::Source,
    };
    recipe.denominator.requested.push(source_slot.clone());
    recipe.denominator.dispositions.push(ProviderDisposition {
        slot: source_slot,
        state: AtomAvailability::PresentCurrent,
        evidence: None,
    });
    recipe.recipe_sha256 = recipe
        .canonical_policy_digest()
        .expect("recipe policy digest");
    recipe.validate().expect("two-role recipe");
    let baseline = recipe.canonical_policy_digest().expect("baseline digest");

    let mut permuted = recipe.clone();
    permuted.mandatory_roles.reverse();
    permuted.denominator.requested.reverse();
    permuted.denominator.dispositions.reverse();
    permuted.role_policies.reverse();
    assert_eq!(
        permuted.canonical_policy_digest().expect("permuted digest"),
        baseline
    );

    let mut changed = recipe.clone();
    changed.capacity.route_capacity += 1;
    assert_ne!(
        changed.canonical_policy_digest().expect("changed digest"),
        baseline
    );
}

// WORK_UNIT_CASE: 584/9
#[test]
fn valid_whole_atom_for_every_role_class() {
    let roles = [
        SemanticRole::Authority,
        SemanticRole::Goal,
        SemanticRole::Scope,
        SemanticRole::Acceptance,
        SemanticRole::Source,
        SemanticRole::Verifier,
        SemanticRole::MaterialUnknown,
        SemanticRole::Negative,
        SemanticRole::Security,
        SemanticRole::Evidence,
        SemanticRole::Instruction,
        SemanticRole::Optional,
        SemanticRole::Conflict,
        SemanticRole::Constraint,
    ];
    assert_eq!(roles.len(), 14);
    for role in roles {
        let mut atom = candidate();
        atom.provider_role.role = role;
        atom.representation = AtomRepresentation::Whole {
            content: "whole unit".to_owned(),
        };
        atom.loss_policy = LossPolicy::NonDroppable;
        atom.validate()
            .unwrap_or_else(|_| panic!("whole atom valid for role {role:?}"));
    }
}

// WORK_UNIT_CASE: 584/10
#[test]
fn duplicate_atom_identity_rejected() {
    let context = binding();
    let set = ContextCandidateSet {
        binding: context,
        candidates: vec![candidate(), candidate()],
        denominator: denominator(),
    };
    assert_eq!(
        set.validate_for_admission(),
        Err(ContextError::Duplicate("candidates.atom_id"))
    );
}

// WORK_UNIT_CASE: 584/11
#[test]
fn changed_content_under_same_atom_id_conflicts() {
    let context = binding();
    let mut changed = candidate();
    changed.source.revision = "r2".to_owned();
    changed.source.content_sha256 = "b".repeat(64);
    changed.loss_policy = LossPolicy::Summarizable;
    changed.representation = AtomRepresentation::Summary {
        content: "changed summary".to_owned(),
        source_digest: "b".repeat(64),
    };
    let set = ContextCandidateSet {
        binding: context,
        candidates: vec![candidate(), changed],
        denominator: denominator(),
    };
    assert_eq!(
        set.validate_for_admission(),
        Err(ContextError::Duplicate("candidates.atom_id"))
    );
}

// WORK_UNIT_CASE: 584/12
#[test]
fn measurement_bound_to_exact_bytes_schema_route() {
    let context = binding();
    let measurement = exact_measurement(&context);
    measurement.validate().expect("exact measurement");
    assert_eq!(SerializedContextMeasurement::utf8_bytes("hello"), 5);
    assert_eq!(SerializedContextMeasurement::utf8_bytes("h\u{e9}llo"), 6);

    let mut stu = measurement.clone();
    stu.status = MeasurementStatus::ConservativeStu;
    assert_eq!(stu.validate(), Err(ContextError::UnknownMeasurement));
    let mut tokenizer = measurement.clone();
    tokenizer.status = MeasurementStatus::ExactTokenizer;
    assert_eq!(tokenizer.validate(), Err(ContextError::UnknownMeasurement));
    let mut bad_digest = measurement.clone();
    bad_digest.envelope_digest = "short".to_owned();
    assert!(matches!(
        bad_digest.validate(),
        Err(ContextError::InvalidDigest(_))
    ));
    let mut unnamed = measurement.clone();
    unnamed.serializer_id.clear();
    assert!(matches!(
        unnamed.validate(),
        Err(ContextError::InvalidField(_))
    ));
}

// WORK_UNIT_CASE: 584/13
#[test]
fn missing_mismatched_measurement_rejected() {
    candidate()
        .measurement
        .validate()
        .expect("valid measurement");

    let mut short = candidate();
    short.measurement.digest = "abc123".to_owned();
    assert_eq!(
        short.validate(),
        Err(ContextError::InvalidDigest("measurement.digest"))
    );

    let mut uppercase = candidate();
    uppercase.measurement.digest = "A".repeat(64);
    assert_eq!(
        uppercase.validate(),
        Err(ContextError::InvalidDigest("measurement.digest"))
    );

    let mut unnamed = candidate();
    unnamed.measurement.serializer.clear();
    assert_eq!(
        unnamed.validate(),
        Err(ContextError::InvalidField("measurement.serializer"))
    );

    // A PresentCurrent floor member without measurement cannot prove currency.
    let context = binding();
    let floor = DecisionSafetyFloor {
        binding: context,
        mandatory_atoms: vec![id("atom")],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: denominator(),
        members: vec![SafetyFloorMember {
            atom_id: id("atom"),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: None,
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: CapacityLimits {
            route_capacity: 100_000,
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
        },
    };
    assert_eq!(
        floor.validate(),
        Err(ContextError::MissingField("floor.member.measurement"))
    );

    // A retargeted digest is still well-formed, so it validates here;
    // identity conservation against the floor/admitted payload is owned
    // by the admitted-set equality proof, not by digest syntax.
    let mut retargeted = candidate();
    retargeted.measurement.digest = "b".repeat(64);
    retargeted
        .validate()
        .expect("well-formed retargeted digest validates");
}

// WORK_UNIT_CASE: 584/14
#[test]
fn no_split_merge_into_new_semantic_members() {
    let context = binding();
    let closed = ContextCandidateSet {
        binding: context.clone(),
        candidates: vec![candidate()],
        denominator: denominator(),
    };
    closed.validate().expect("closed single member");

    // A fragment that depends on an absent atom is not a closed semantic
    // member: strict validation rejects it while the partial admission path
    // stays explicit instead of silently merging it.
    let mut fragment = candidate();
    fragment.dependencies = vec![id("absent-parent")];
    let partial = ContextCandidateSet {
        binding: context,
        candidates: vec![fragment],
        denominator: denominator(),
    };
    assert_eq!(
        partial.validate(),
        Err(ContextError::MissingField("candidate.dependencies"))
    );
    partial
        .validate_for_admission()
        .expect("partial set stays explicit at admission");
}

// WORK_UNIT_CASE: 584/15
#[test]
fn loss_policy_cannot_be_inferred_from_size_role_recency_or_confidence() {
    #[derive(serde::Deserialize)]
    struct PolicyHolder {
        policy: LossPolicy,
    }
    assert!(serde_json::from_str::<PolicyHolder>(r"{}").is_err());
    let holder: PolicyHolder =
        serde_json::from_str(r#"{"policy":"EXTRACTIVE"}"#).expect("explicit policy");
    assert_eq!(holder.policy, LossPolicy::Extractive);
    assert!(serde_json::from_str::<LossPolicy>("\"NON DROPPABLE\"").is_err());
    assert!(serde_json::from_str::<LossPolicy>("\"non_droppable\"").is_err());

    // Size does not select the policy: tiny and large whole units share it.
    let mut tiny = candidate();
    tiny.representation = AtomRepresentation::Whole {
        content: "x".to_owned(),
    };
    tiny.loss_policy = LossPolicy::NonDroppable;
    tiny.validate().expect("tiny whole unit");

    let mut large = candidate();
    large.representation = AtomRepresentation::Whole {
        content: "x".repeat(10_000),
    };
    large.loss_policy = LossPolicy::NonDroppable;
    large.validate().expect("large whole unit");

    // Role does not select the policy either: the same handle policy holds
    // for another role, while the wrong policy/representation pair fails.
    let mut handle = candidate();
    handle.provider_role.role = SemanticRole::Source;
    handle.loss_policy = LossPolicy::HandleOnly;
    handle.representation = AtomRepresentation::Handle { handle: id("h") };
    handle.validate().expect("explicit handle-only");

    let mut inferred = candidate();
    inferred.loss_policy = LossPolicy::NonDroppable;
    inferred.representation = AtomRepresentation::Handle { handle: id("h") };
    assert_eq!(inferred.validate(), Err(ContextError::WholeUnitRequired));
}

// WORK_UNIT_CASE: 584/16
#[test]
fn incompatible_required_protected_representation_rejected() {
    let mut summary = candidate();
    summary.representation = AtomRepresentation::Summary {
        content: "lossy".to_owned(),
        source_digest: digest(),
    };
    assert_eq!(summary.validate(), Err(ContextError::WholeUnitRequired));

    let mut extractive = candidate();
    extractive.representation = AtomRepresentation::Extractive {
        content: "kept".to_owned(),
        manifest: vec!["field".to_owned()],
    };
    assert_eq!(extractive.validate(), Err(ContextError::WholeUnitRequired));

    let mut whole_as_handle_only = candidate();
    whole_as_handle_only.loss_policy = LossPolicy::HandleOnly;
    assert_eq!(
        whole_as_handle_only.validate(),
        Err(ContextError::WholeUnitRequired)
    );

    // Whole is no more lossy than a summarizable policy, so it is allowed.
    let mut whole_as_summarizable = candidate();
    whole_as_summarizable.loss_policy = LossPolicy::Summarizable;
    whole_as_summarizable
        .validate()
        .expect("whole under summarizable");

    let mut handle_as_summarizable = candidate();
    handle_as_summarizable.loss_policy = LossPolicy::Summarizable;
    handle_as_summarizable.representation = AtomRepresentation::Handle { handle: id("h") };
    assert_eq!(
        handle_as_summarizable.validate(),
        Err(ContextError::WholeUnitRequired)
    );

    let rule = RoleLossRule {
        role: SemanticRole::Goal,
        loss_policy: LossPolicy::NonDroppable,
        required: true,
        allowed_representations: vec![RepresentationKind::Summary],
    };
    assert_eq!(rule.validate(), Err(ContextError::WholeUnitRequired));
}

// WORK_UNIT_CASE: 584/17
#[test]
fn bounded_interpretation_dependencies_cannot_disappear() {
    let mut duplicate = candidate();
    duplicate.dependencies = vec![id("dep"), id("dep")];
    assert_eq!(
        duplicate.validate(),
        Err(ContextError::Duplicate("candidate.dependencies"))
    );

    let mut oversized = candidate();
    oversized.dependencies = vec![id("dep"); 257];
    assert!(matches!(
        oversized.validate(),
        Err(ContextError::Bounds { .. })
    ));

    // Strict membership keeps the dependency closure closed: a dangling
    // reference fails instead of silently disappearing.
    let context = binding();
    let mut dangling = candidate();
    dangling.dependencies = vec![id("absent")];
    let set = ContextCandidateSet {
        binding: context.clone(),
        candidates: vec![dangling],
        denominator: denominator(),
    };
    assert_eq!(
        set.validate(),
        Err(ContextError::MissingField("candidate.dependencies"))
    );

    // Floor dependency closure is exact: self-reference and non-member
    // references both fail closed.
    let member = SafetyFloorMember {
        atom_id: id("atom"),
        role: SemanticRole::Goal,
        availability: AtomAvailability::Missing,
        measurement: None,
        required_dependencies: vec![id("atom")],
    };
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![id("atom")],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: ProviderRoleDenominator {
            requested: vec![provider_role()],
            dispositions: vec![ProviderDisposition {
                slot: provider_role(),
                state: AtomAvailability::Missing,
                evidence: None,
            }],
        },
        members: vec![member],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: CapacityLimits {
            route_capacity: 100,
            fixed_overhead: 1,
            output_reserve: 1,
            review_reserve: 1,
        },
    };
    assert_eq!(
        floor.validate(),
        Err(ContextError::Duplicate("floor.required_dependencies"))
    );

    let mut foreign = floor.clone();
    foreign.members[0].required_dependencies = vec![id("elsewhere")];
    assert_eq!(foreign.validate(), Err(ContextError::MissingFloor));

    let mut interpretation = floor.clone();
    interpretation.members[0].required_dependencies = Vec::new();
    interpretation.interpretation_dependencies = vec![id("elsewhere")];
    assert_eq!(interpretation.validate(), Err(ContextError::MissingFloor));
}

// WORK_UNIT_CASE: 584/18
#[test]
fn freshness_privacy_authority_evidence_proof_cannot_widen() {
    let mut stale = candidate();
    stale.status = EpistemicStatus::Stale;
    assert_eq!(
        stale.validate(),
        Err(ContextError::InvalidField("candidate.availability"))
    );

    let mut superseded = candidate();
    superseded.status = EpistemicStatus::Superseded;
    assert_eq!(
        superseded.validate(),
        Err(ContextError::InvalidField("candidate.availability"))
    );

    // Availability must track the denominator slot: a present candidate
    // against a missing slot is an identity conflict, not a widening.
    let context = binding();
    let missing_denominator = ProviderRoleDenominator {
        requested: vec![provider_role()],
        dispositions: vec![ProviderDisposition {
            slot: provider_role(),
            state: AtomAvailability::Missing,
            evidence: None,
        }],
    };
    let widened = ContextCandidateSet {
        binding: context,
        candidates: vec![candidate()],
        denominator: missing_denominator,
    };
    assert_eq!(
        widened.validate_for_admission(),
        Err(ContextError::IdentityConflict)
    );

    // Blocked/unavailable slots need named evidence; absence fails closed.
    let blocked = ProviderDisposition {
        slot: provider_role(),
        state: AtomAvailability::Blocked,
        evidence: None,
    };
    assert_eq!(
        blocked.validate(),
        Err(ContextError::MissingField(
            "denominator.dispositions.evidence"
        ))
    );
}

fn safety_floor_with(availability: AtomAvailability) -> DecisionSafetyFloor {
    let measurement = (availability == AtomAvailability::PresentCurrent).then(|| MeasurementRef {
        digest: digest(),
        serializer: "fixture-serde-v1".to_owned(),
    });
    DecisionSafetyFloor {
        binding: binding(),
        mandatory_atoms: vec![id("atom")],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: denominator(),
        members: vec![SafetyFloorMember {
            atom_id: id("atom"),
            role: SemanticRole::Goal,
            availability,
            measurement,
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: CapacityLimits {
            route_capacity: 100,
            fixed_overhead: 1,
            output_reserve: 1,
            review_reserve: 1,
        },
    }
}

// WORK_UNIT_CASE: 584/19
#[test]
fn exact_complete_safety_floor_succeeds() {
    let floor = safety_floor_with(AtomAvailability::PresentCurrent);
    floor.validate().expect("complete floor validates");
    assert_eq!(
        floor.incomplete().expect("complete floor rechecks"),
        None,
        "a fully present-current floor has no gaps"
    );
}

// WORK_UNIT_CASE: 584/20
#[test]
fn missing_mandatory_member_stays_missing() {
    let floor = safety_floor_with(AtomAvailability::Missing);
    floor.validate().expect("missing floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("missing floor rechecks")
        .expect("missing member cannot be complete");
    assert_eq!(incomplete.missing, vec![id("atom")]);
    assert!(incomplete.stale.is_empty());
    assert!(incomplete.blocked.is_empty());
    assert!(incomplete.unavailable.is_empty());
    assert!(incomplete.omitted.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");
}

// WORK_UNIT_CASE: 584/21
#[test]
fn stale_mandatory_member_stays_stale() {
    let floor = safety_floor_with(AtomAvailability::Stale);
    floor.validate().expect("stale floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("stale floor rechecks")
        .expect("stale member cannot be complete");
    assert_eq!(incomplete.stale, vec![id("atom")]);
    assert!(incomplete.missing.is_empty());
    assert!(incomplete.blocked.is_empty());
    assert!(incomplete.unavailable.is_empty());
    assert!(incomplete.omitted.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");
}

// WORK_UNIT_CASE: 584/22
#[test]
fn blocked_mandatory_member_stays_blocked() {
    let floor = safety_floor_with(AtomAvailability::Blocked);
    floor.validate().expect("blocked floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("blocked floor rechecks")
        .expect("blocked member cannot be complete");
    assert_eq!(incomplete.blocked, vec![id("atom")]);
    assert!(incomplete.missing.is_empty());
    assert!(incomplete.stale.is_empty());
    assert!(incomplete.unavailable.is_empty());
    assert!(incomplete.omitted.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");
}

// WORK_UNIT_CASE: 584/23
#[test]
fn unavailable_mandatory_member_stays_unavailable() {
    let floor = safety_floor_with(AtomAvailability::Unavailable);
    floor.validate().expect("unavailable floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("unavailable floor rechecks")
        .expect("unavailable member cannot be complete");
    assert_eq!(incomplete.unavailable, vec![id("atom")]);
    assert!(incomplete.missing.is_empty());
    assert!(incomplete.stale.is_empty());
    assert!(incomplete.blocked.is_empty());
    assert!(incomplete.omitted.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");
}

// WORK_UNIT_CASE: 584/24
#[test]
fn omitted_mandatory_member_cannot_be_complete() {
    let floor = safety_floor_with(AtomAvailability::Omitted);
    floor.validate().expect("omitted floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("omitted floor rechecks")
        .expect("omitted member cannot be complete");
    assert_eq!(incomplete.omitted, vec![id("atom")]);
    assert!(incomplete.missing.is_empty());
    assert!(incomplete.stale.is_empty());
    assert!(incomplete.blocked.is_empty());
    assert!(incomplete.unavailable.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");
}

// WORK_UNIT_CASE: 584/25
#[test]
fn exhausted_mandatory_member_cannot_be_complete() {
    let floor = safety_floor_with(AtomAvailability::Exhausted);
    floor.validate().expect("exhausted floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("exhausted floor rechecks")
        .expect("exhausted member cannot be complete");
    assert_eq!(incomplete.exhausted, vec![id("atom")]);
    assert!(incomplete.missing.is_empty());
    assert!(incomplete.stale.is_empty());
    assert!(incomplete.blocked.is_empty());
    assert!(incomplete.unavailable.is_empty());
    assert!(incomplete.omitted.is_empty());
    assert!(incomplete.unknown.is_empty());
    assert!(incomplete.known_empty.is_empty());
    assert!(incomplete.partial.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");
}

// WORK_UNIT_CASE: 584/26
#[test]
fn partial_provider_coverage_cannot_make_complete_floor() {
    let partial_providers = ProviderRoleDenominator {
        requested: vec![provider_role()],
        dispositions: vec![ProviderDisposition {
            slot: provider_role(),
            state: AtomAvailability::Partial,
            evidence: None,
        }],
    };
    partial_providers
        .validate()
        .expect("partial denominator shape validates");
    let mut floor = safety_floor_with(AtomAvailability::Partial);
    floor.providers = partial_providers;
    floor.validate().expect("partial floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("partial floor rechecks")
        .expect("partial coverage cannot be complete");
    assert_eq!(incomplete.partial, vec![id("atom")]);
    assert_eq!(incomplete.provider_gaps.len(), 1);
    assert_eq!(incomplete.provider_gaps[0].slot, provider_role());
    assert_eq!(incomplete.provider_gaps[0].state, AtomAvailability::Partial);
    assert!(incomplete.missing.is_empty());
    assert!(incomplete.stale.is_empty());
    assert!(incomplete.blocked.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");
}

// WORK_UNIT_CASE: 584/27
#[test]
fn known_empty_requires_complete_authoritative_denominator() {
    let floor = safety_floor_with(AtomAvailability::KnownEmpty);
    floor.validate().expect("known-empty floor shape validates");
    let incomplete = floor
        .incomplete()
        .expect("known-empty floor rechecks")
        .expect("known-empty cannot be complete");
    assert_eq!(incomplete.known_empty, vec![id("atom")]);
    assert!(incomplete.missing.is_empty());
    assert!(incomplete.partial.is_empty());
    assert!(incomplete.oversized.is_empty());
    incomplete.validate().expect("incomplete outcome validates");

    // Without a complete authoritative denominator the claim fails closed.
    let empty = ProviderRoleDenominator {
        requested: Vec::new(),
        dispositions: Vec::new(),
    };
    assert_eq!(
        empty.validate(),
        Err(ContextError::MissingField("denominator.requested"))
    );
    let truncated = ProviderRoleDenominator {
        requested: vec![provider_role()],
        dispositions: Vec::new(),
    };
    assert_eq!(truncated.validate(), Err(ContextError::DenominatorMismatch));
    let mut unauthoritative = safety_floor_with(AtomAvailability::KnownEmpty);
    unauthoritative.providers = truncated;
    assert_eq!(
        unauthoritative.validate(),
        Err(ContextError::DenominatorMismatch)
    );
}

// WORK_UNIT_CASE: 584/28
#[test]
fn decision_context_incomplete_distinct_from_contract_error() {
    let floor = safety_floor_with(AtomAvailability::Missing);
    let incomplete = floor
        .incomplete()
        .expect("missing floor rechecks")
        .expect("missing member cannot be complete");
    assert_eq!(incomplete.code, ContextErrorCode::DecisionContextIncomplete);
    let wire = serde_json::to_string(&incomplete.code).expect("code wire encoding");
    assert_eq!(wire, "\"DECISION_CONTEXT_INCOMPLETE\"");
    incomplete
        .validate()
        .expect("incomplete is a valid outcome, not an error");

    // Contract/shape failures are Err values, never an incomplete outcome.
    let mut empty_floor = safety_floor_with(AtomAvailability::Missing);
    empty_floor.mandatory_atoms.clear();
    empty_floor.members.clear();
    assert_eq!(empty_floor.validate(), Err(ContextError::MissingFloor));

    let mut wrong_code = incomplete.clone();
    wrong_code.code = ContextErrorCode::InvalidIdentity;
    assert_eq!(
        wrong_code.validate(),
        Err(ContextError::InvalidField("incomplete.code"))
    );

    let outcome: ContextOutcome<AdmittedContextSet> =
        ContextOutcome::Incomplete(incomplete.clone());
    assert!(matches!(outcome, ContextOutcome::Incomplete(_)));
    assert!(!matches!(outcome, ContextOutcome::Complete(_)));
}

// WORK_UNIT_CASE: 584/29
#[test]
fn incomplete_preserves_gap_sets_and_reopening_requirements() {
    let oversized_capacity = CapacityLimits {
        route_capacity: 2,
        fixed_overhead: 1,
        output_reserve: 1,
        review_reserve: 1,
    };
    let floor = DecisionSafetyFloor {
        binding: binding(),
        mandatory_atoms: vec![id("missing-atom"), id("stale-atom"), id("blocked-atom")],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: denominator(),
        members: vec![
            SafetyFloorMember {
                atom_id: id("missing-atom"),
                role: SemanticRole::Goal,
                availability: AtomAvailability::Missing,
                measurement: None,
                required_dependencies: Vec::new(),
            },
            SafetyFloorMember {
                atom_id: id("stale-atom"),
                role: SemanticRole::Goal,
                availability: AtomAvailability::Stale,
                measurement: None,
                required_dependencies: Vec::new(),
            },
            SafetyFloorMember {
                atom_id: id("blocked-atom"),
                role: SemanticRole::Goal,
                availability: AtomAvailability::Blocked,
                measurement: None,
                required_dependencies: Vec::new(),
            },
        ],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: oversized_capacity,
    };
    floor.validate().expect("multi-gap floor shape validates");
    let mut incomplete = floor
        .incomplete()
        .expect("multi-gap floor rechecks")
        .expect("multi-gap floor cannot be complete");
    assert_eq!(incomplete.missing, vec![id("missing-atom")]);
    assert_eq!(incomplete.stale, vec![id("stale-atom")]);
    assert_eq!(incomplete.blocked, vec![id("blocked-atom")]);
    assert_eq!(
        incomplete.oversized,
        vec![id("missing-atom"), id("stale-atom"), id("blocked-atom")]
    );
    assert!(incomplete.unavailable.is_empty());
    assert!(incomplete.omitted.is_empty());

    incomplete
        .reopening_requirements
        .push("reopen blocked-atom with fresh evidence".to_owned());
    incomplete.measurements.push(id("measurement"));
    incomplete.validate().expect("gaps plus reopening validate");
    let encoded = serde_json::to_string(&incomplete).expect("incomplete encoding");
    let decoded: DecisionContextIncomplete =
        serde_json::from_str(&encoded).expect("incomplete round-trip");
    assert_eq!(decoded, incomplete);
    assert_eq!(decoded.missing, vec![id("missing-atom")]);
    assert_eq!(decoded.stale, vec![id("stale-atom")]);
    assert_eq!(decoded.blocked, vec![id("blocked-atom")]);
}

// WORK_UNIT_CASE: 584/30
#[test]
fn incomplete_cannot_decode_to_thinner_complete_success() {
    let floor = safety_floor_with(AtomAvailability::Missing);
    let incomplete = floor
        .incomplete()
        .expect("missing floor rechecks")
        .expect("missing member cannot be complete");
    let encoded = serde_json::to_string(&incomplete).expect("incomplete encoding");
    assert!(serde_json::from_str::<ContextCandidateSet>(&encoded).is_err());
    assert!(serde_json::from_str::<AdmittedContextSet>(&encoded).is_err());
    assert!(serde_json::from_str::<ContextRecipe>(&encoded).is_err());

    let outcome: ContextOutcome<AdmittedContextSet> =
        ContextOutcome::Incomplete(incomplete.clone());
    match outcome {
        ContextOutcome::Incomplete(result) => {
            assert_eq!(result.missing, vec![id("atom")]);
            result.validate().expect("incomplete stays incomplete");
        }
        ContextOutcome::Complete(_) => panic!("incomplete must not convert to success"),
    }

    // An empty gap set is not a valid incomplete and cannot stand in for success.
    let empty = DecisionContextIncomplete::new(id("floor-rule"));
    assert_eq!(empty.validate(), Err(ContextError::MissingFloor));
}

fn admitted_single() -> AdmittedContextSet {
    let context = binding();
    let cand = candidate();
    let atom_id = cand.atom_id.clone();
    let measurement = cand.measurement.clone();
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: denominator(),
        members: vec![SafetyFloorMember {
            atom_id: atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(measurement.clone()),
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: CapacityLimits {
            route_capacity: 100_000,
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
        },
    };
    let economy = ContextEconomyReceipt {
        binding: context.clone(),
        decision_id: context.decision_id.clone(),
        measurement,
        requested: vec![atom_id.clone()],
        admitted: vec![atom_id.clone()],
        displaced: Vec::new(),
        omissions: Vec::new(),
        applied_rule: id("economy-rule"),
        allocations: EconomyAllocations {
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
            admitted_required: 10,
            admitted_optional: 0,
            remaining_headroom: 99_981,
            route_capacity: 100_000,
        },
        recipe_digest: digest(),
        receipt_digest: digest(),
    };
    let mut admitted = AdmittedContextSet {
        binding: context,
        records: vec![AdmittedAtom {
            candidate: cand,
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        admissions: vec![AdmissionRecord {
            atom_id,
            provider_role: provider_role(),
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        floor,
        economy,
    };
    let mut unsigned = admitted.economy.clone();
    unsigned.receipt_digest = "0".repeat(64);
    admitted.economy.receipt_digest =
        canonical_digest(&unsigned).expect("admitted economy receipt digest");
    admitted
}

fn omission_binding() -> ContextBinding {
    let mut context = binding();
    context.state_fence.task_revision = Some(TaskRevision::new(1).expect("omission task revision"));
    context
}

fn omission_decision() -> DecisionRevision {
    DecisionRevision {
        decision_id: omission_binding().decision_id.clone(),
        recipe_revision: TaskRevision::new(1).expect("omission task revision"),
        policy_sha256: digest(),
    }
}

fn reversible_omission() -> (ContextBinding, OmissionRecord) {
    let context = omission_binding();
    let decision = omission_decision();
    let handle = ExpansionHandle {
        handle_id: id("handle"),
        atom_id: id("atom"),
        source_id: id("source"),
        source_revision: "r1".to_owned(),
        context: context.clone(),
        decision: decision.clone(),
        policy: LossPolicy::NonDroppable,
        provider_role: provider_role(),
        handle_digest: "c".repeat(64),
        expires: None,
        invalidation: None,
    };
    let record = OmissionRecord {
        atom_id: id("atom"),
        source_id: id("source"),
        provider_role: provider_role(),
        decision,
        task_revision: TaskRevision::new(1).expect("omission task revision"),
        reason: OmissionReason::Capacity,
        competing_constraint: "route capacity".to_owned(),
        measured_cost: Some(4),
        allowed_representation: LossPolicy::NonDroppable,
        expansion: Some(handle),
        non_recoverable_reason: None,
        authorization_requirement: "decision owner".to_owned(),
        privacy_requirement: "restricted".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
        digest: digest(),
    };
    (context, record)
}

// WORK_UNIT_CASE: 584/31
#[test]
fn candidate_admitted_membership_identity_binding() {
    let admitted = admitted_single();
    admitted.validate().expect("bound admitted set validates");
    let encoded = serde_json::to_string(&admitted).expect("admitted encoding");
    let decoded: AdmittedContextSet = serde_json::from_str(&encoded).expect("admitted round-trip");
    assert_eq!(decoded, admitted);
    decoded.validate().expect("decoded admitted set validates");

    let mut retargeted_atom = admitted.clone();
    retargeted_atom.admissions[0].atom_id = id("other-atom");
    assert_eq!(
        retargeted_atom.validate(),
        Err(ContextError::DenominatorMismatch)
    );

    let mut retargeted_role = admitted.clone();
    retargeted_role.admissions[0].provider_role = ProviderRole {
        provider: ProviderId::new("other-provider").expect("fixture provider"),
        role: SemanticRole::Source,
    };
    assert_eq!(
        retargeted_role.validate(),
        Err(ContextError::IdentityConflict)
    );

    let mut rebound = admitted.clone();
    rebound.records[0].candidate.binding.task_id = TaskId::new("other-task").expect("fixture task");
    assert!(rebound.validate().is_err());

    let mut refloor = admitted.clone();
    refloor.floor.binding.task_id = TaskId::new("other-task").expect("fixture task");
    assert_eq!(refloor.validate(), Err(ContextError::InvalidFence));

    let mut reeconomy = admitted.clone();
    reeconomy.economy.binding.task_id = TaskId::new("other-task").expect("fixture task");
    assert_eq!(reeconomy.validate(), Err(ContextError::InvalidFence));
}

// WORK_UNIT_CASE: 584/32
#[test]
fn admission_dispositions_remain_distinct() {
    let expected = [
        (AdmissionDisposition::Include, "INCLUDE"),
        (AdmissionDisposition::HandleOnly, "HANDLE_ONLY"),
        (AdmissionDisposition::Revalidate, "REVALIDATE"),
        (AdmissionDisposition::Suppress, "SUPPRESS"),
        (AdmissionDisposition::Quarantine, "QUARANTINE"),
        (AdmissionDisposition::Unavailable, "UNAVAILABLE"),
        (AdmissionDisposition::Blocked, "BLOCKED"),
        (AdmissionDisposition::OverBudget, "OVER_BUDGET"),
    ];
    assert_eq!(expected.len(), 8);
    let mut wires = std::collections::BTreeSet::new();
    for (disposition, wire) in expected {
        let encoded = serde_json::to_string(&disposition).expect("disposition encoding");
        assert_eq!(encoded, format!("\"{wire}\""));
        assert_eq!(
            serde_json::from_str::<AdmissionDisposition>(&encoded).expect("disposition round-trip"),
            disposition
        );
        assert!(wires.insert(wire));
    }
    assert!(serde_json::from_str::<AdmissionDisposition>("\"OTHER\"").is_err());
    assert!(serde_json::from_str::<AdmissionDisposition>("\"include\"").is_err());

    // Only admitted outcomes carry Include/HandleOnly; every other explicit
    // disposition is rejected at the admitted-set boundary, never coerced.
    for disposition in [
        AdmissionDisposition::Revalidate,
        AdmissionDisposition::Suppress,
        AdmissionDisposition::Quarantine,
        AdmissionDisposition::Unavailable,
        AdmissionDisposition::Blocked,
        AdmissionDisposition::OverBudget,
    ] {
        let mut admitted = admitted_single();
        admitted.records[0].disposition = disposition;
        admitted.admissions[0].disposition = disposition;
        assert_eq!(
            admitted.validate(),
            Err(ContextError::DenominatorMismatch),
            "non-admitted disposition {disposition:?} cannot validate as admitted"
        );
    }
    let mut handle_only = admitted_single();
    handle_only.records[0].disposition = AdmissionDisposition::HandleOnly;
    handle_only.admissions[0].disposition = AdmissionDisposition::HandleOnly;
    handle_only
        .validate()
        .expect("handle-only stays a distinct admitted outcome");
}

// WORK_UNIT_CASE: 584/33
#[test]
fn exactly_one_disposition_per_candidate_provider() {
    admitted_single()
        .validate()
        .expect("one admission per record validates");

    let mut duplicated = admitted_single();
    duplicated.admissions.push(duplicated.admissions[0].clone());
    assert_eq!(
        duplicated.validate(),
        Err(ContextError::DenominatorMismatch)
    );

    let mut missing = admitted_single();
    missing.admissions.clear();
    assert_eq!(missing.validate(), Err(ContextError::DenominatorMismatch));

    let mut extra = admitted_single();
    extra.admissions.push(AdmissionRecord {
        atom_id: id("unknown-atom"),
        provider_role: provider_role(),
        disposition: AdmissionDisposition::Suppress,
        rule_evidence: id("extra-rule"),
    });
    assert_eq!(extra.validate(), Err(ContextError::DenominatorMismatch));

    let mut mismatched_role = admitted_single();
    mismatched_role.admissions[0].provider_role = ProviderRole {
        provider: ProviderId::new("other-provider").expect("fixture provider"),
        role: SemanticRole::Source,
    };
    assert_eq!(
        mismatched_role.validate(),
        Err(ContextError::IdentityConflict)
    );

    let mut mismatched_disposition = admitted_single();
    mismatched_disposition.admissions[0].disposition = AdmissionDisposition::HandleOnly;
    assert_eq!(
        mismatched_disposition.validate(),
        Err(ContextError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 584/34
#[test]
fn valid_reversible_omission_handle() {
    let (context, record) = reversible_omission();
    let handle = record.expansion.clone().expect("reversible handle");
    handle.validate().expect("expansion handle validates");
    record
        .validate(&context)
        .expect("reversible omission validates");
    assert_eq!(record.non_recoverable_reason, None);

    let encoded = serde_json::to_string(&record).expect("omission encoding");
    let decoded: OmissionRecord = serde_json::from_str(&encoded).expect("omission round-trip");
    assert_eq!(decoded, record);
    decoded
        .validate(&context)
        .expect("decoded reversible omission validates");

    let handle_encoded = serde_json::to_string(&handle).expect("handle encoding");
    let decoded_handle: ExpansionHandle =
        serde_json::from_str(&handle_encoded).expect("handle round-trip");
    assert_eq!(decoded_handle, handle);
}

// WORK_UNIT_CASE: 584/35
#[test]
fn wrong_omission_handle_binding_rejected() {
    let (context, record) = reversible_omission();
    record
        .validate(&context)
        .expect("baseline omission validates");

    let mut wrong_atom = record.clone();
    wrong_atom.atom_id = id("other-atom");
    assert_eq!(
        wrong_atom.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut wrong_source = record.clone();
    wrong_source.source_id = id("other-source");
    assert_eq!(
        wrong_source.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut wrong_decision = record.clone();
    wrong_decision
        .expansion
        .as_mut()
        .expect("expansion handle")
        .context
        .decision_id = DecisionId::new("other-decision").expect("fixture decision");
    assert_eq!(
        wrong_decision.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut wrong_task = record.clone();
    wrong_task
        .expansion
        .as_mut()
        .expect("expansion handle")
        .context
        .task_id = TaskId::new("other-task").expect("fixture task");
    assert_eq!(
        wrong_task.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut wrong_scope = record.clone();
    wrong_scope
        .expansion
        .as_mut()
        .expect("expansion handle")
        .context
        .scope_id = WorkScopeId::new("other-scope").expect("fixture scope");
    assert_eq!(
        wrong_scope.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut wrong_fence = record.clone();
    wrong_fence
        .expansion
        .as_mut()
        .expect("expansion handle")
        .context
        .state_fence = StateFence::new(
        test_epoch(),
        ResourceGeneration::new(2).expect("fixture generation"),
    );
    wrong_fence
        .expansion
        .as_mut()
        .expect("expansion handle")
        .context
        .state_fence
        .task_revision = Some(TaskRevision::new(1).expect("omission task revision"));
    assert_eq!(
        wrong_fence.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut wrong_revision = record.clone();
    wrong_revision.task_revision = TaskRevision::new(2).expect("other revision");
    assert_eq!(
        wrong_revision.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut wrong_policy_revision = record.clone();
    wrong_policy_revision.decision.recipe_revision = TaskRevision::new(2).expect("other revision");
    assert_eq!(
        wrong_policy_revision.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );
}

// WORK_UNIT_CASE: 584/36
#[test]
fn non_recoverable_omission_needs_typed_reason_and_no_reversibility() {
    let (context, mut record) = reversible_omission();
    record.expansion = None;
    record.non_recoverable_reason = Some(NonRecoverableReason::PolicyDisallows);
    record
        .validate(&context)
        .expect("typed non-recoverable omission validates");
    let encoded = serde_json::to_string(&record).expect("omission encoding");
    let decoded: OmissionRecord = serde_json::from_str(&encoded).expect("omission round-trip");
    assert_eq!(
        decoded.non_recoverable_reason,
        Some(NonRecoverableReason::PolicyDisallows)
    );
    assert_eq!(decoded.expansion, None);

    // Both halves present claims reversibility and non-recoverability at once.
    let (context, mut both) = reversible_omission();
    both.non_recoverable_reason = Some(NonRecoverableReason::Privacy);
    assert_eq!(
        both.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    // Neither half present claims neither recovery path.
    let (context, mut neither) = reversible_omission();
    neither.expansion = None;
    neither.non_recoverable_reason = None;
    assert_eq!(
        neither.validate(&context),
        Err(ContextError::OmissionHandleInvalid)
    );

    // A reversible handle must not smuggle a non-recoverable reason.
    let (_context, reversible) = reversible_omission();
    assert_eq!(reversible.non_recoverable_reason, None);
    assert!(reversible.expansion.is_some());
}
