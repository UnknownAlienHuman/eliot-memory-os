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
