#![allow(
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_admission::admit_context;
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, DecisionId, ResourceGeneration, SourceId, StateFence, TaskId,
    TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest(byte: u8) -> String {
    char::from(byte).to_string().repeat(64)
}

fn binding() -> ContextBinding {
    let mut fence = StateFence::new(
        AuthorityEpoch::new(1).expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    fence.task_revision = Some(TaskRevision::new(1).expect("task revision"));
    ContextBinding {
        task_id: TaskId::new("task").expect("task"),
        attempt_id: AgentAttemptId::new("attempt").expect("attempt"),
        scope_id: WorkScopeId::new("scope").expect("scope"),
        state_fence: fence,
        decision_id: DecisionId::new("decision").expect("decision"),
        operation_id: None,
    }
}

fn role(provider: &str, semantic: SemanticRole) -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(provider).expect("provider"),
        role: semantic,
    }
}

fn decision(context: &ContextBinding) -> DecisionRevision {
    DecisionRevision {
        decision_id: context.decision_id.clone(),
        recipe_revision: TaskRevision::new(1).expect("revision"),
        policy_sha256: digest(b'a'),
    }
}

fn candidate(
    context: &ContextBinding,
    atom_id: &str,
    provider_role: ProviderRole,
    content: &str,
    loss_policy: LossPolicy,
    protected: bool,
) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id(atom_id),
        provider_role,
        source: SourceSnapshot {
            source_id: SourceId::new(format!("source-{atom_id}")).expect("source"),
            owner: ProviderId::new(format!("owner-{atom_id}")).expect("owner"),
            snapshot_id: id(&format!("snapshot-{atom_id}")),
            revision: "r1".to_owned(),
            content_sha256: digest(b'b'),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: content.to_owned(),
        },
        loss_policy,
        availability: AtomAvailability::PresentCurrent,
        protected,
        privacy: PrivacyClass::Scoped,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: digest(b'c'),
            serializer: "json-v1".to_owned(),
        },
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id(&format!("evidence-{atom_id}")),
            ceiling: ProofCeiling::Observation,
        },
    }
}

fn input_with_optional(optional_cost: AdmissionMeasuredCost) -> AdmissionInput {
    let context = binding();
    let required_role = role("required-provider", SemanticRole::Goal);
    let optional_role = role("optional-provider", SemanticRole::Optional);
    let required = candidate(
        &context,
        "required",
        required_role.clone(),
        "required",
        LossPolicy::NonDroppable,
        true,
    );
    let optional = candidate(
        &context,
        "optional",
        optional_role.clone(),
        "optional",
        LossPolicy::Summarizable,
        false,
    );
    let requested = vec![required_role.clone(), optional_role.clone()];
    let dispositions = requested
        .iter()
        .cloned()
        .map(|slot| ProviderDisposition {
            slot,
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        })
        .collect::<Vec<_>>();
    let denominator = ProviderRoleDenominator {
        requested,
        dispositions,
    };
    let capacity = CapacityLimits {
        route_capacity: 100,
        fixed_overhead: 10,
        output_reserve: 10,
        review_reserve: 10,
    };
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: decision(&context),
        recipe_sha256: digest(b'd'),
        denominator: denominator.clone(),
        mandatory_roles: vec![SemanticRole::Goal],
        role_policies: vec![
            RoleLossRule {
                role: SemanticRole::Goal,
                loss_policy: LossPolicy::NonDroppable,
                required: true,
                allowed_representations: vec![RepresentationKind::Whole],
            },
            RoleLossRule {
                role: SemanticRole::Optional,
                loss_policy: LossPolicy::Summarizable,
                required: false,
                allowed_representations: vec![
                    RepresentationKind::Whole,
                    RepresentationKind::Summary,
                ],
            },
        ],
        capacity,
        predecessor: None,
        invalidation: None,
    };
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![required.atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: ProviderRoleDenominator {
            requested: vec![required_role.clone()],
            dispositions: vec![ProviderDisposition {
                slot: required_role,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
        members: vec![SafetyFloorMember {
            atom_id: required.atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(required.measurement.clone()),
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity,
    };
    let subject = canonical_digest(&required).expect("required subject");
    let optional_subject = canonical_digest(&optional).expect("optional subject");
    let measurement =
        |candidate: &ContextCandidate, measurement_id: &str, cost| AdmissionMeasurement {
            measurement_id: id(measurement_id),
            atom_id: candidate.atom_id.clone(),
            representation: candidate.representation.kind(),
            unit: MeasurementUnit::Utf8Bytes,
            binding: AdmissionMeasurementBinding {
                context: context.clone(),
                schema_version: CONTEXT_CONTRACT_VERSION,
                subject_digest: if candidate.atom_id == required.atom_id {
                    subject.clone()
                } else {
                    optional_subject.clone()
                },
                input_digest: candidate.measurement.digest.clone(),
                output_digest: digest(b'e'),
                serializer_id: "json-v1".to_owned(),
                serializer_version: "1".to_owned(),
                serializer_options_digest: digest(b'f'),
                route_id: "route".to_owned(),
                model_id: "model".to_owned(),
            },
            cost,
            observation: None,
        };
    AdmissionInput {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        recipe: recipe.clone(),
        candidates: ContextCandidateSet {
            binding: context.clone(),
            candidates: vec![required.clone(), optional.clone()],
            denominator: denominator.clone(),
        },
        floor: SafetyFloorIdentity {
            floor_id: id("floor"),
            decision: recipe.decision.clone(),
            floor,
        },
        priority: PriorityPolicyIdentity {
            policy_id: id("priority"),
            decision: recipe.decision.clone(),
            priorities: vec![
                CandidatePriority {
                    atom_id: required.atom_id.clone(),
                    class: AdmissionPriorityClass::Required,
                    ordinal: 0,
                },
                CandidatePriority {
                    atom_id: optional.atom_id.clone(),
                    class: AdmissionPriorityClass::Normal,
                    ordinal: 1,
                },
            ],
        },
        rule: AdmissionRuleIdentity {
            rule_id: id("rule"),
            decision: recipe.decision,
            rule_sha256: digest(b'a'),
        },
        measurement_profile: MeasurementCompositionProfile {
            profile_id: id("profile"),
            schema_version: CONTEXT_CONTRACT_VERSION,
            serializer_id: "json-v1".to_owned(),
            serializer_version: "1".to_owned(),
            serializer_options_digest: digest(b'f'),
            route_id: "route".to_owned(),
            model_id: "model".to_owned(),
            unit: MeasurementUnit::Utf8Bytes,
            aggregation: MeasurementAggregationMode::QualifiedUtf8Contribution,
            qualification: id("qualification"),
            capacity,
        },
        supplied_omissions: vec![SuppliedOmissionBinding {
            atom_id: optional.atom_id.clone(),
            policy: LossPolicy::Summarizable,
            expansion: None,
            non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
            authorization_requirement: "owner".to_owned(),
            privacy_requirement: "scoped".to_owned(),
            proof_requirement: "observation".to_owned(),
            expires: None,
            invalidation: None,
        }],
        measurements: vec![
            measurement(
                &required,
                "required-measurement",
                AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 },
            ),
            measurement(&optional, "optional-measurement", optional_cost),
        ],
    }
}

#[test]
fn required_floor_is_admitted_before_fitting_optional_material() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let result = admit_context(&input).expect("valid admission");
    let ContextOutcome::Complete(ref admitted) = result.outcome else {
        panic!("floor should fit");
    };
    assert_eq!(admitted.records.len(), 2);
    assert_eq!(admitted.economy.allocations.admitted_required, 20);
    assert_eq!(admitted.economy.allocations.admitted_optional, 20);
    result.validate_for(&input).expect("result conservation");
}

#[test]
fn invalid_reserves_fail_before_optional_selection() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input.recipe.capacity.route_capacity = 15;
    input.recipe.recipe_sha256 = input
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    input.floor.floor.capacity = input.recipe.capacity;
    input.measurement_profile.capacity = input.recipe.capacity;
    assert_eq!(admit_context(&input), Err(ContextError::CapacityExceeded));
}

#[test]
fn required_missing_stale_unknown_and_oversized_are_exact_gaps() {
    let mut missing = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    missing.candidates.candidates[0].availability = AtomAvailability::Missing;
    missing.candidates.denominator.dispositions[0].state = AtomAvailability::Missing;
    missing.recipe.denominator.dispositions[0].state = AtomAvailability::Missing;
    missing.recipe.recipe_sha256 = missing
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    missing.measurements[0].binding.subject_digest =
        canonical_digest(&missing.candidates.candidates[0]).expect("missing subject");
    missing.floor.floor.members[0].availability = AtomAvailability::Missing;
    missing.floor.floor.members[0].measurement = None;
    missing.floor.floor.providers.dispositions[0].state = AtomAvailability::Missing;
    let result = admit_context(&missing).expect("missing is valid incomplete input");
    let ContextOutcome::Incomplete(gap) = result.outcome else {
        panic!("expected gap");
    };
    assert_eq!(gap.missing, vec![id("required")]);
    assert_eq!(gap.provider_gaps.len(), 1);

    let mut unknown = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    unknown.measurements[0].cost = AdmissionMeasuredCost::Unknown;
    let result = admit_context(&unknown).expect("unknown is explicit");
    assert!(
        matches!(result.outcome, ContextOutcome::Incomplete(gap) if gap.unknown == vec![id("required")])
    );

    let mut oversized = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    oversized.recipe.capacity.route_capacity = 39;
    oversized.recipe.recipe_sha256 = oversized
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    oversized.floor.floor.capacity = oversized.recipe.capacity;
    oversized.measurement_profile.capacity = oversized.recipe.capacity;
    let result = admit_context(&oversized).expect("oversized floor is explicit");
    assert!(
        matches!(result.outcome, ContextOutcome::Incomplete(gap) if gap.oversized == vec![id("required")])
    );
}

#[test]
fn exact_optional_overbudget_is_reversible_omission() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    let result = admit_context(&input).expect("optional omission is valid");
    let ContextOutcome::Complete(admitted) = result.outcome else {
        panic!("floor fits");
    };
    assert_eq!(admitted.records.len(), 1);
    let omission = result
        .evidence
        .omissions
        .first()
        .expect("omission evidence");
    assert_eq!(omission.measured_cost, Some(80));
    assert_eq!(omission.reason, OmissionReason::Capacity);
    assert!(omission.non_recoverable_reason.is_some());
}

#[test]
fn unknown_optional_is_visible_without_inventing_zero_cost() {
    let input = input_with_optional(AdmissionMeasuredCost::Unknown);
    let result = admit_context(&input).expect("unknown optional is valid");
    assert!(matches!(result.outcome, ContextOutcome::Complete(_)));
    let omission = result.evidence.omissions.first().expect("unknown omission");
    assert_eq!(omission.measured_cost, None);
    assert_eq!(omission.reason, OmissionReason::UnknownMeasurement);
}

#[test]
fn candidate_permutation_keeps_membership_and_priority_stable() {
    let first = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let mut second = first.clone();
    second.candidates.candidates.reverse();
    second.measurements.reverse();
    second.priority.priorities.reverse();
    second.supplied_omissions.reverse();
    let one = admit_context(&first).expect("first order");
    let two = admit_context(&second).expect("permuted order");
    assert_eq!(one, two);
    assert_eq!(one.evidence.decisions.len(), 2);
    assert!(
        one.evidence
            .decisions
            .iter()
            .all(|decision| { matches!(decision.disposition, AdmissionDisposition::Include) })
    );
}
