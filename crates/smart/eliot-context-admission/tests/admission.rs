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

fn measurement(
    context: &ContextBinding,
    candidate: &ContextCandidate,
    measurement_id: &str,
    cost: AdmissionMeasuredCost,
) -> AdmissionMeasurement {
    AdmissionMeasurement {
        measurement_id: id(measurement_id),
        atom_id: candidate.atom_id.clone(),
        representation: candidate.representation.kind(),
        unit: MeasurementUnit::Utf8Bytes,
        binding: AdmissionMeasurementBinding {
            context: context.clone(),
            schema_version: CONTEXT_CONTRACT_VERSION,
            subject_digest: canonical_digest(candidate).expect("candidate subject"),
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
    }
}

fn expansion(
    context: &ContextBinding,
    candidate: &ContextCandidate,
    policy: LossPolicy,
) -> ExpansionHandle {
    ExpansionHandle {
        handle_id: id(&format!("handle-{}", candidate.atom_id)),
        atom_id: candidate.atom_id.clone(),
        source_id: id(candidate.source.source_id.as_str()),
        source_revision: candidate.source.revision.clone(),
        context: context.clone(),
        decision: decision(context),
        policy,
        provider_role: candidate.provider_role.clone(),
        handle_digest: digest(b'a'),
        expires: None,
        invalidation: None,
    }
}

fn make_handle_optional(input: &mut AdmissionInput) {
    let context = input.binding.clone();
    let candidate = &mut input.candidates.candidates[1];
    let handle = id(&format!("handle-{}", candidate.atom_id));
    candidate.representation = AtomRepresentation::Handle { handle };
    candidate.loss_policy = LossPolicy::HandleOnly;
    let policy = input
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == SemanticRole::Optional)
        .expect("optional policy");
    policy.loss_policy = LossPolicy::HandleOnly;
    policy.allowed_representations = vec![RepresentationKind::Handle];
    input.supplied_omissions[0].policy = LossPolicy::HandleOnly;
    input.supplied_omissions[0].expansion =
        Some(expansion(&context, candidate, LossPolicy::HandleOnly));
    input.supplied_omissions[0].non_recoverable_reason = None;
    input.measurements[1] = measurement(
        &context,
        candidate,
        "optional-measurement",
        input.measurements[1].cost.clone(),
    );
    input.recipe.recipe_sha256 = input
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
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
                &context,
                &required,
                "required-measurement",
                AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 },
            ),
            measurement(&context, &optional, "optional-measurement", optional_cost),
        ],
    }
}

#[test]
fn required_floor_is_admitted_before_fitting_optional_material() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let dependency = input.candidates.candidates[1].atom_id.clone();
    let dependency_role = input.candidates.candidates[1].provider_role.clone();
    input.candidates.candidates[0]
        .dependencies
        .push(dependency.clone());
    input.measurements[0].binding.subject_digest =
        canonical_digest(&input.candidates.candidates[0]).expect("required subject");
    input.floor.floor.members[0]
        .required_dependencies
        .push(dependency.clone());
    input.floor.floor.mandatory_atoms.push(dependency.clone());
    input
        .floor
        .floor
        .mandatory_roles
        .push(SemanticRole::Optional);
    input.floor.floor.members.push(SafetyFloorMember {
        atom_id: dependency,
        role: SemanticRole::Optional,
        availability: AtomAvailability::PresentCurrent,
        measurement: Some(input.candidates.candidates[1].measurement.clone()),
        required_dependencies: Vec::new(),
    });
    input
        .floor
        .floor
        .providers
        .requested
        .push(dependency_role.clone());
    input
        .floor
        .floor
        .providers
        .dispositions
        .push(ProviderDisposition {
            slot: dependency_role,
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        });
    input.recipe.mandatory_roles.push(SemanticRole::Optional);
    input
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == SemanticRole::Optional)
        .expect("optional policy")
        .required = true;
    make_handle_optional(&mut input);
    let result = admit_context(&input).expect("valid admission");
    let ContextOutcome::Complete(ref admitted) = result.outcome else {
        panic!("floor should fit");
    };
    assert_eq!(admitted.records.len(), 2);
    assert!(
        admitted
            .records
            .iter()
            .any(|record| record.disposition == AdmissionDisposition::HandleOnly)
    );
    assert_eq!(admitted.economy.allocations.admitted_required, 40);
    assert_eq!(admitted.economy.allocations.admitted_optional, 0);
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

    let mut stale_unavailable =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    stale_unavailable.candidates.candidates[0].availability = AtomAvailability::Stale;
    stale_unavailable.candidates.denominator.dispositions[0].state = AtomAvailability::Stale;
    stale_unavailable.recipe.denominator.dispositions[0].state = AtomAvailability::Stale;
    stale_unavailable.floor.floor.members[0].availability = AtomAvailability::Stale;
    stale_unavailable.floor.floor.providers.dispositions[0].state = AtomAvailability::Stale;
    let unavailable_id = stale_unavailable.candidates.candidates[1].atom_id.clone();
    stale_unavailable.candidates.candidates[1].availability = AtomAvailability::Unavailable;
    stale_unavailable.candidates.denominator.dispositions[1].state = AtomAvailability::Unavailable;
    stale_unavailable.recipe.denominator.dispositions[1].state = AtomAvailability::Unavailable;
    stale_unavailable
        .floor
        .floor
        .members
        .push(SafetyFloorMember {
            atom_id: unavailable_id.clone(),
            role: SemanticRole::Optional,
            availability: AtomAvailability::Unavailable,
            measurement: Some(
                stale_unavailable.candidates.candidates[1]
                    .measurement
                    .clone(),
            ),
            required_dependencies: Vec::new(),
        });
    stale_unavailable
        .floor
        .floor
        .mandatory_atoms
        .push(unavailable_id.clone());
    stale_unavailable
        .floor
        .floor
        .mandatory_roles
        .push(SemanticRole::Optional);
    stale_unavailable
        .recipe
        .mandatory_roles
        .push(SemanticRole::Optional);
    stale_unavailable
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == SemanticRole::Optional)
        .expect("optional policy")
        .required = true;
    stale_unavailable.floor.floor.providers.requested.push(
        stale_unavailable.candidates.candidates[1]
            .provider_role
            .clone(),
    );
    stale_unavailable
        .floor
        .floor
        .providers
        .dispositions
        .push(ProviderDisposition {
            slot: stale_unavailable.candidates.candidates[1]
                .provider_role
                .clone(),
            state: AtomAvailability::Unavailable,
            evidence: None,
        });
    stale_unavailable.candidates.candidates[0]
        .dependencies
        .push(unavailable_id.clone());
    stale_unavailable.floor.floor.members[0]
        .required_dependencies
        .push(unavailable_id);
    stale_unavailable.recipe.recipe_sha256 = stale_unavailable
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    stale_unavailable.measurements[0].binding.subject_digest =
        canonical_digest(&stale_unavailable.candidates.candidates[0]).expect("stale subject");
    stale_unavailable.measurements[1].binding.subject_digest =
        canonical_digest(&stale_unavailable.candidates.candidates[1]).expect("unavailable subject");
    let result = admit_context(&stale_unavailable).expect("combined floor gaps");
    let ContextOutcome::Incomplete(gap) = result.outcome else {
        panic!("expected combined gap");
    };
    assert_eq!(gap.stale, vec![id("required")]);
    assert_eq!(gap.unavailable, vec![id("optional")]);
    assert!(gap.measurements.contains(&id("optional-measurement")));

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
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    make_handle_optional(&mut input);
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
    assert!(omission.expansion.is_some());
}

#[test]
fn unknown_optional_is_visible_without_inventing_zero_cost() {
    let input = input_with_optional(AdmissionMeasuredCost::Unknown);
    let result = admit_context(&input).expect("unknown optional is valid");
    assert!(matches!(result.outcome, ContextOutcome::Complete(_)));
    let omission = result.evidence.omissions.first().expect("unknown omission");
    assert_eq!(omission.measured_cost, None);
    assert_eq!(omission.reason, OmissionReason::UnknownMeasurement);

    let mut unknown_state = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    unknown_state.candidates.candidates[1].availability = AtomAvailability::Unknown;
    unknown_state.candidates.denominator.dispositions[1].state = AtomAvailability::Unknown;
    unknown_state.recipe.denominator.dispositions[1].state = AtomAvailability::Unknown;
    unknown_state.recipe.recipe_sha256 = unknown_state
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    unknown_state.measurements[1].binding.subject_digest =
        canonical_digest(&unknown_state.candidates.candidates[1]).expect("unknown subject");
    let result = admit_context(&unknown_state).expect("unknown availability is explicit");
    let omission = result
        .evidence
        .omissions
        .first()
        .expect("unknown availability omission");
    assert_eq!(omission.measured_cost, Some(1));
    assert_eq!(omission.reason, OmissionReason::Policy);
    assert!(matches!(
        result
            .evidence
            .decisions
            .iter()
            .find(|decision| decision.atom_id == id("optional"))
            .map(|decision| decision.disposition),
        Some(AdmissionDisposition::Revalidate)
    ));

    let mut unavailable = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    unavailable.candidates.candidates[1].availability = AtomAvailability::Unavailable;
    unavailable.candidates.denominator.dispositions[1].state = AtomAvailability::Unavailable;
    unavailable.recipe.denominator.dispositions[1].state = AtomAvailability::Unavailable;
    unavailable.recipe.recipe_sha256 = unavailable
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    unavailable.measurements[1].binding.subject_digest =
        canonical_digest(&unavailable.candidates.candidates[1]).expect("unavailable subject");
    let result = admit_context(&unavailable).expect("unavailable optional is explicit");
    let omission = result
        .evidence
        .omissions
        .first()
        .expect("unavailable omission");
    assert_eq!(omission.measured_cost, Some(1));
    assert_eq!(omission.reason, OmissionReason::Unavailable);
}

#[test]
fn candidate_permutation_keeps_membership_and_priority_stable() {
    let mut first = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    first.recipe.capacity.route_capacity = 55;
    first.floor.floor.capacity = first.recipe.capacity;
    first.measurement_profile.capacity = first.recipe.capacity;
    first.recipe.recipe_sha256 = first
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    let context = first.binding.clone();
    let role = first.candidates.candidates[1].provider_role.clone();
    let mut a = candidate(
        &context,
        "a",
        role.clone(),
        "aaaaaaaaaa",
        LossPolicy::Summarizable,
        false,
    );
    let mut b = candidate(
        &context,
        "b",
        role.clone(),
        "b",
        LossPolicy::Summarizable,
        false,
    );
    let d = first.candidates.candidates[1].clone();
    a.dependencies.push(d.atom_id.clone());
    b.dependencies.push(d.atom_id.clone());
    first.candidates.candidates.push(a.clone());
    first.candidates.candidates.push(b.clone());
    first.measurements.push(measurement(
        &context,
        &a,
        "a-measurement",
        AdmissionMeasuredCost::ExactUtf8Bytes { value: 10 },
    ));
    first.measurements.push(measurement(
        &context,
        &b,
        "b-measurement",
        AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 },
    ));
    first.priority.priorities[1] = CandidatePriority {
        atom_id: d.atom_id.clone(),
        class: AdmissionPriorityClass::Low,
        ordinal: 2,
    };
    first.priority.priorities.push(CandidatePriority {
        atom_id: a.atom_id.clone(),
        class: AdmissionPriorityClass::High,
        ordinal: 0,
    });
    first.priority.priorities.push(CandidatePriority {
        atom_id: b.atom_id.clone(),
        class: AdmissionPriorityClass::Normal,
        ordinal: 1,
    });
    first.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: a.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    first.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: b.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    first.recipe.recipe_sha256 = first
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    let mut second = first.clone();
    second.candidates.candidates.reverse();
    second.measurements.reverse();
    second.priority.priorities.reverse();
    second.supplied_omissions.reverse();
    let one = admit_context(&first).expect("first order");
    let two = admit_context(&second).expect("permuted order");
    assert_eq!(one, two);
    assert_eq!(one.evidence.decisions.len(), 4);
    assert_eq!(one.evidence.omissions.len(), 1);
    assert_eq!(one.evidence.omissions[0].atom_id, id("a"));
    assert_eq!(one.evidence.omissions[0].measured_cost, Some(10));
    let ContextOutcome::Complete(admitted) = one.outcome else {
        panic!("shared dependency route should fit");
    };
    let admitted_ids = admitted
        .records
        .iter()
        .map(|record| record.candidate.atom_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(admitted_ids, vec![id("b"), id("optional"), id("required")]);
}
