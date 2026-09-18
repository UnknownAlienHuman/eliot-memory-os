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
    ArtifactId, ContractVersion, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId,
    StateFence, TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest(byte: u8) -> String {
    char::from(byte).to_string().repeat(64)
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn binding() -> ContextBinding {
    let mut fence = StateFence::new(
        test_epoch(),
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
        // Admission currently accepts only the public route projection; the
        // privacy refusal path below covers narrower classes explicitly.
        privacy: PrivacyClass::Public,
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
fn non_public_privacy_is_refused_before_selection() {
    for privacy in [
        PrivacyClass::Scoped,
        PrivacyClass::Restricted,
        PrivacyClass::Secret,
    ] {
        let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
        input.candidates.candidates[0].privacy = privacy;
        assert_eq!(
            admit_context(&input),
            Err(ContextError::InvalidField("candidate.privacy"))
        );
    }
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
    stale_unavailable.candidates.denominator.dispositions[1].evidence = Some(ProofBinding {
        evidence_id: id("optional-unavailable-reason"),
        ceiling: ProofCeiling::Observation,
    });
    stale_unavailable.recipe.denominator.dispositions[1].state = AtomAvailability::Unavailable;
    stale_unavailable.recipe.denominator.dispositions[1].evidence = Some(ProofBinding {
        evidence_id: id("optional-unavailable-reason"),
        ceiling: ProofCeiling::Observation,
    });
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
            evidence: Some(ProofBinding {
                evidence_id: id("optional-unavailable-reason"),
                ceiling: ProofCeiling::Observation,
            }),
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
    unavailable.candidates.denominator.dispositions[1].evidence = Some(ProofBinding {
        evidence_id: id("optional-unavailable-reason"),
        ceiling: ProofCeiling::Observation,
    });
    unavailable.recipe.denominator.dispositions[1].state = AtomAvailability::Unavailable;
    unavailable.recipe.denominator.dispositions[1].evidence = Some(ProofBinding {
        evidence_id: id("optional-unavailable-reason"),
        ceiling: ProofCeiling::Observation,
    });
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

#[test]
fn mutated_economy_recipe_digest_fails_receipt_validation() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let result = admit_context(&input).expect("valid admission");
    let ContextOutcome::Complete(admitted) = result.outcome else {
        panic!("floor should fit");
    };
    assert_eq!(admitted.economy.recipe_digest, input.recipe.recipe_sha256);
    admitted.validate().expect("bound receipt validates");
    let mut mutated = admitted.clone();
    let original = mutated.economy.recipe_digest.clone();
    let replacement = if original == "b".repeat(64) {
        "c".repeat(64)
    } else {
        "b".repeat(64)
    };
    mutated.economy.recipe_digest = replacement;
    assert_eq!(
        mutated.economy.validate(),
        Err(ContextError::IdentityConflict)
    );
    assert_eq!(mutated.validate(), Err(ContextError::IdentityConflict));
}

// ---- 608 additive fixtures (legacy fixtures above are untouched) ----

fn refresh_recipe(input: &mut AdmissionInput) {
    input.recipe.recipe_sha256 = input
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
}

fn set_capacity(input: &mut AdmissionInput, route: u64, fixed: u64, output: u64, review: u64) {
    let capacity = CapacityLimits {
        route_capacity: route,
        fixed_overhead: fixed,
        output_reserve: output,
        review_reserve: review,
    };
    input.recipe.capacity = capacity;
    input.floor.floor.capacity = capacity;
    input.measurement_profile.capacity = capacity;
    refresh_recipe(input);
}

fn remeasure(input: &mut AdmissionInput, atom: &str) {
    let target = id(atom);
    let subject = input
        .candidates
        .candidates
        .iter()
        .find(|candidate| candidate.atom_id == target)
        .expect("candidate present")
        .clone();
    let digest = canonical_digest(&subject).expect("candidate subject");
    let record = input
        .measurements
        .iter_mut()
        .find(|item| item.atom_id == target && item.representation == subject.representation.kind())
        .expect("measurement present");
    record.binding.subject_digest = digest;
}

fn state_evidence() -> ProofBinding {
    ProofBinding {
        evidence_id: id("state-evidence"),
        ceiling: ProofCeiling::Observation,
    }
}

fn set_availability(input: &mut AdmissionInput, atom: &str, state: AtomAvailability) {
    let target = id(atom);
    let slot = input
        .candidates
        .candidates
        .iter()
        .find(|candidate| candidate.atom_id == target)
        .expect("candidate present")
        .provider_role
        .clone();
    for candidate in &mut input.candidates.candidates {
        if candidate.atom_id == target {
            candidate.availability = state;
        }
    }
    for disposition in &mut input.candidates.denominator.dispositions {
        if disposition.slot == slot {
            disposition.state = state;
            disposition.evidence = None;
            if matches!(
                state,
                AtomAvailability::Blocked | AtomAvailability::Unavailable
            ) {
                disposition.evidence = Some(state_evidence());
            }
        }
    }
    for disposition in &mut input.recipe.denominator.dispositions {
        if disposition.slot == slot {
            disposition.state = state;
            disposition.evidence = None;
            if matches!(
                state,
                AtomAvailability::Blocked | AtomAvailability::Unavailable
            ) {
                disposition.evidence = Some(state_evidence());
            }
        }
    }
    if let Some(member) = input
        .floor
        .floor
        .members
        .iter_mut()
        .find(|member| member.atom_id == target)
    {
        member.availability = state;
    }
    if let Some(disposition) = input
        .floor
        .floor
        .providers
        .dispositions
        .iter_mut()
        .find(|disposition| disposition.slot == slot)
    {
        disposition.state = state;
        disposition.evidence = None;
        if matches!(
            state,
            AtomAvailability::Blocked | AtomAvailability::Unavailable
        ) {
            disposition.evidence = Some(state_evidence());
        }
    }
    // Disposition states are part of the canonical recipe digest.
    refresh_recipe(input);
    remeasure(input, atom);
}

fn push_optional(
    input: &mut AdmissionInput,
    atom: &str,
    content: &str,
    cost_value: u64,
    class: AdmissionPriorityClass,
    ordinal: u32,
) {
    let context = input.binding.clone();
    let slot = input.candidates.candidates[1].provider_role.clone();
    let atom_candidate = candidate(
        &context,
        atom,
        slot,
        content,
        LossPolicy::Summarizable,
        false,
    );
    let cost = AdmissionMeasuredCost::ExactUtf8Bytes { value: cost_value };
    input.measurements.push(measurement(
        &context,
        &atom_candidate,
        &format!("{atom}-measurement"),
        cost,
    ));
    input.priority.priorities.push(CandidatePriority {
        atom_id: atom_candidate.atom_id.clone(),
        class,
        ordinal,
    });
    input.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: atom_candidate.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    input.candidates.candidates.push(atom_candidate);
}

fn push_extractive(
    input: &mut AdmissionInput,
    atom: &str,
    content: &str,
    manifest: Vec<String>,
    cost_value: u64,
    class: AdmissionPriorityClass,
    ordinal: u32,
) {
    let context = input.binding.clone();
    let slot = input.candidates.candidates[1].provider_role.clone();
    let mut atom_candidate = candidate(
        &context,
        atom,
        slot,
        content,
        LossPolicy::Extractive,
        false,
    );
    atom_candidate.representation = AtomRepresentation::Extractive {
        content: content.to_owned(),
        manifest,
    };
    if let Some(policy) = input
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == SemanticRole::Optional)
    {
        policy.loss_policy = LossPolicy::Extractive;
        policy.allowed_representations = vec![
            RepresentationKind::Whole,
            RepresentationKind::Extractive,
        ];
    }
    let cost = AdmissionMeasuredCost::ExactUtf8Bytes { value: cost_value };
    input.measurements.push(measurement(
        &context,
        &atom_candidate,
        &format!("{atom}-measurement"),
        cost,
    ));
    input.priority.priorities.push(CandidatePriority {
        atom_id: atom_candidate.atom_id.clone(),
        class,
        ordinal,
    });
    input.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: atom_candidate.atom_id.clone(),
        policy: LossPolicy::Extractive,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    input.candidates.candidates.push(atom_candidate);
    refresh_recipe(input);
}

fn push_summary(
    input: &mut AdmissionInput,
    atom: &str,
    content: &str,
    cost_value: u64,
    class: AdmissionPriorityClass,
    ordinal: u32,
) {
    let context = input.binding.clone();
    let slot = input.candidates.candidates[1].provider_role.clone();
    let mut atom_candidate = candidate(
        &context,
        atom,
        slot,
        content,
        LossPolicy::Summarizable,
        false,
    );
    atom_candidate.representation = AtomRepresentation::Summary {
        content: content.to_owned(),
        source_digest: digest(b'b'),
    };
    let cost = AdmissionMeasuredCost::ExactUtf8Bytes { value: cost_value };
    input.measurements.push(measurement(
        &context,
        &atom_candidate,
        &format!("{atom}-measurement"),
        cost,
    ));
    input.priority.priorities.push(CandidatePriority {
        atom_id: atom_candidate.atom_id.clone(),
        class,
        ordinal,
    });
    input.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: atom_candidate.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    input.candidates.candidates.push(atom_candidate);
}

fn add_provider_slot(
    input: &mut AdmissionInput,
    provider: &str,
    role: SemanticRole,
) -> ProviderRole {
    let slot = ProviderRole {
        provider: ProviderId::new(provider).expect("provider"),
        role,
    };
    if !input.candidates.denominator.requested.contains(&slot) {
        input.candidates.denominator.requested.push(slot.clone());
        input.candidates.denominator.dispositions.push(ProviderDisposition {
            slot: slot.clone(),
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        });
    }
    if !input.recipe.denominator.requested.contains(&slot) {
        input.recipe.denominator.requested.push(slot.clone());
        input.recipe.denominator.dispositions.push(ProviderDisposition {
            slot: slot.clone(),
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        });
    }
    refresh_recipe(input);
    slot
}

fn ensure_role_policy(
    input: &mut AdmissionInput,
    role: SemanticRole,
    loss: LossPolicy,
    required: bool,
    allowed: Vec<RepresentationKind>,
) {
    if let Some(policy) = input
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == role)
    {
        policy.loss_policy = loss;
        policy.required = required;
        policy.allowed_representations = allowed;
    } else {
        input.recipe.role_policies.push(RoleLossRule {
            role,
            loss_policy: loss,
            required,
            allowed_representations: allowed,
        });
    }
    refresh_recipe(input);
}

fn promote_to_floor(input: &mut AdmissionInput, atom: &str) {
    let target = id(atom);
    let found = input
        .candidates
        .candidates
        .iter()
        .find(|candidate| candidate.atom_id == target)
        .expect("candidate present")
        .clone();
    if !input.floor.floor.mandatory_atoms.contains(&target) {
        input.floor.floor.mandatory_atoms.push(target.clone());
    }
    if !input
        .floor
        .floor
        .mandatory_roles
        .contains(&found.provider_role.role)
    {
        input
            .floor
            .floor
            .mandatory_roles
            .push(found.provider_role.role);
        input.recipe.mandatory_roles.push(found.provider_role.role);
    }
    if !input
        .floor
        .floor
        .members
        .iter()
        .any(|member| member.atom_id == target)
    {
        input.floor.floor.members.push(SafetyFloorMember {
            atom_id: target.clone(),
            role: found.provider_role.role,
            availability: found.availability,
            measurement: Some(found.measurement.clone()),
            required_dependencies: found.dependencies.clone(),
        });
    }
    if !input
        .floor
        .floor
        .providers
        .requested
        .contains(&found.provider_role)
    {
        input
            .floor
            .floor
            .providers
            .requested
            .push(found.provider_role.clone());
        input.floor.floor.providers.dispositions.push(ProviderDisposition {
            slot: found.provider_role.clone(),
            state: found.availability,
            evidence: None,
        });
    }
    if let Some(policy) = input
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == found.provider_role.role)
    {
        policy.required = true;
    }
    refresh_recipe(input);
}

fn add_dependency(input: &mut AdmissionInput, from: &str, to: &str) {
    let target = id(to);
    let source = id(from);
    for candidate in &mut input.candidates.candidates {
        if candidate.atom_id == source && !candidate.dependencies.contains(&target) {
            candidate.dependencies.push(target.clone());
        }
    }
    if let Some(member) = input
        .floor
        .floor
        .members
        .iter_mut()
        .find(|member| member.atom_id == source)
        && !member.required_dependencies.contains(&target)
    {
        member.required_dependencies.push(target.clone());
    }
    remeasure(input, from);
}

fn complete_set(result: &AdmissionResult) -> &AdmittedContextSet {
    match &result.outcome {
        ContextOutcome::Complete(set) => set,
        ContextOutcome::Incomplete(_) => panic!("expected complete admission"),
    }
}

fn incomplete_gap(result: &AdmissionResult) -> &DecisionContextIncomplete {
    match &result.outcome {
        ContextOutcome::Incomplete(gap) => gap,
        ContextOutcome::Complete(_) => panic!("expected incomplete outcome"),
    }
}

fn admitted_ids(set: &AdmittedContextSet) -> Vec<ArtifactId> {
    let mut ids = set
        .records
        .iter()
        .map(|record| record.candidate.atom_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

// WORK_UNIT_CASE: 608/1
#[test]
fn minimal_valid_set_recipe_budget_measurement_admits() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let result = admit_context(&input).expect("minimal valid admission");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("optional"), id("required")]);
    assert_eq!(admitted.economy.allocations.admitted_required, 20);
    assert_eq!(admitted.economy.allocations.admitted_optional, 20);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 30);
    assert_eq!(
        admitted.economy.allocations.fixed_overhead
            + admitted.economy.allocations.output_reserve
            + admitted.economy.allocations.review_reserve
            + admitted.economy.allocations.admitted_required
            + admitted.economy.allocations.admitted_optional
            + admitted.economy.allocations.remaining_headroom,
        admitted.economy.allocations.route_capacity
    );
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/2
#[test]
fn unsupported_input_recipe_policy_measurement_schemas_are_distinct() {
    let mut input_schema = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input_schema.schema_version = ContractVersion::new(9, 9, 9);
    assert_eq!(
        admit_context(&input_schema),
        Err(ContextError::InvalidField("admission.schema_version"))
    );

    let mut recipe_schema = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    recipe_schema.recipe.schema_version = ContractVersion::new(9, 9, 9);
    assert_eq!(
        admit_context(&recipe_schema),
        Err(ContextError::InvalidField("recipe.schema_version"))
    );

    let mut policy_shape = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    policy_shape.recipe.role_policies[1].allowed_representations = Vec::new();
    refresh_recipe(&mut policy_shape);
    assert_eq!(
        admit_context(&policy_shape),
        Err(ContextError::MissingField(
            "role_policy.allowed_representations"
        ))
    );

    let mut profile_unit = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    profile_unit.measurement_profile.unit = MeasurementUnit::Stu;
    assert_eq!(
        admit_context(&profile_unit),
        Err(ContextError::UnknownMeasurement)
    );

    let mut binding_schema = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    binding_schema.measurements[0].binding.schema_version = ContractVersion::new(9, 9, 9);
    assert_eq!(
        admit_context(&binding_schema),
        Err(ContextError::InvalidField(
            "admission_measurement.schema_version"
        ))
    );
}

// WORK_UNIT_CASE: 608/3
#[test]
fn task_mismatch_is_rejected_before_selection() {
    let mut recipe_task = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    recipe_task.recipe.binding.task_id = TaskId::new("other-task").expect("task");
    refresh_recipe(&mut recipe_task);
    assert_eq!(
        admit_context(&recipe_task),
        Err(ContextError::IdentityConflict)
    );

    let mut candidate_task = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    candidate_task.candidates.candidates[0].binding.task_id =
        TaskId::new("other-task").expect("task");
    assert_eq!(
        admit_context(&candidate_task),
        Err(ContextError::InvalidFence)
    );
}

// WORK_UNIT_CASE: 608/4
#[test]
fn attempt_mismatch_is_rejected_before_selection() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input.recipe.binding.attempt_id = AgentAttemptId::new("other-attempt").expect("attempt");
    refresh_recipe(&mut input);
    assert_eq!(admit_context(&input), Err(ContextError::IdentityConflict));
}

// WORK_UNIT_CASE: 608/5
#[test]
fn workscope_mismatch_is_rejected_before_selection() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input.recipe.binding.scope_id = WorkScopeId::new("other-scope").expect("scope");
    refresh_recipe(&mut input);
    assert_eq!(admit_context(&input), Err(ContextError::IdentityConflict));
}

// WORK_UNIT_CASE: 608/6
#[test]
fn state_fence_mismatch_is_rejected_before_selection() {
    let mut recipe_fence = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    recipe_fence.recipe.binding.state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("660e8400-e29b-41d4-a716-446655440001").expect("lineage"),
            std::num::NonZeroU64::new(2).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    refresh_recipe(&mut recipe_fence);
    assert_eq!(
        admit_context(&recipe_fence),
        Err(ContextError::IdentityConflict)
    );

    let mut candidate_fence =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    candidate_fence.candidates.candidates[0]
        .binding
        .state_fence
        .task_revision = Some(TaskRevision::new(2).expect("task revision"));
    assert_eq!(
        admit_context(&candidate_fence),
        Err(ContextError::InvalidFence)
    );
}

// WORK_UNIT_CASE: 608/7
#[test]
fn recipe_provider_role_mismatch_is_denominator_error() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let ghost = role("ghost-provider", SemanticRole::Optional);
    input.recipe.denominator.requested.push(ghost.clone());
    input.recipe.denominator.dispositions.push(ProviderDisposition {
        slot: ghost,
        state: AtomAvailability::PresentCurrent,
        evidence: None,
    });
    refresh_recipe(&mut input);
    assert_eq!(
        admit_context(&input),
        Err(ContextError::DenominatorMismatch)
    );
}

// WORK_UNIT_CASE: 608/8
#[test]
fn missing_provider_disposition_is_denominator_error() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input.candidates.denominator.dispositions.remove(1);
    assert_eq!(
        admit_context(&input),
        Err(ContextError::DenominatorMismatch)
    );
}

// WORK_UNIT_CASE: 608/9
#[test]
fn duplicate_and_extra_provider_dispositions_are_denominator_errors() {
    let mut duplicate = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let repeated = duplicate.candidates.denominator.dispositions[0].clone();
    duplicate
        .candidates
        .denominator
        .dispositions
        .push(repeated);
    assert_eq!(
        admit_context(&duplicate),
        Err(ContextError::DenominatorMismatch)
    );

    let mut extra = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    extra.candidates.denominator.dispositions.push(ProviderDisposition {
        slot: role("ghost-provider", SemanticRole::Optional),
        state: AtomAvailability::PresentCurrent,
        evidence: None,
    });
    assert_eq!(admit_context(&extra), Err(ContextError::DenominatorMismatch));
}

// WORK_UNIT_CASE: 608/10
#[test]
fn duplicate_atom_and_duplicate_measurement_are_rejected() {
    let mut duplicate_atom = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let repeated = duplicate_atom.candidates.candidates[0].clone();
    duplicate_atom.candidates.candidates.push(repeated);
    assert_eq!(
        admit_context(&duplicate_atom),
        Err(ContextError::Duplicate("candidates.atom_id"))
    );

    let mut duplicate_measurement =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let repeated_measurement = duplicate_measurement.measurements[0].clone();
    duplicate_measurement
        .measurements
        .push(repeated_measurement);
    assert_eq!(
        admit_context(&duplicate_measurement),
        Err(ContextError::Duplicate(
            "admission.measurements.atom_representation"
        ))
    );
}

// WORK_UNIT_CASE: 608/11
#[test]
fn same_id_changed_content_source_measurement_conflicts() {
    let mut changed_content = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    if let AtomRepresentation::Whole { content } =
        &mut changed_content.candidates.candidates[0].representation
    {
        content.push('!');
    }
    assert_eq!(
        admit_context(&changed_content),
        Err(ContextError::IdentityConflict)
    );

    let mut changed_source = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    changed_source.candidates.candidates[0].source.revision = "r2".to_owned();
    assert_eq!(
        admit_context(&changed_source),
        Err(ContextError::IdentityConflict)
    );

    let mut changed_measurement =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    changed_measurement.candidates.candidates[0].measurement.digest = digest(b'd');
    assert_eq!(
        admit_context(&changed_measurement),
        Err(ContextError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 608/12
#[test]
fn stale_source_recipe_policy_measurement_are_distinct_signals() {
    let mut stale_source = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut stale_source, "required", AtomAvailability::Stale);
    let result = admit_context(&stale_source).expect("stale is explicit incomplete");
    assert_eq!(incomplete_gap(&result).stale, vec![id("required")]);

    let mut stale_recipe = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    stale_recipe.recipe.decision.recipe_revision = TaskRevision::new(2).expect("revision");
    refresh_recipe(&mut stale_recipe);
    assert_eq!(
        admit_context(&stale_recipe),
        Err(ContextError::IdentityConflict)
    );

    let mut stale_policy = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    stale_policy.recipe.capacity.output_reserve = 11;
    assert_eq!(
        admit_context(&stale_policy),
        Err(ContextError::IdentityConflict)
    );

    let mut stale_profile = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    stale_profile.measurement_profile.capacity.route_capacity = 101;
    assert_eq!(
        admit_context(&stale_profile),
        Err(ContextError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 608/13
#[test]
fn exact_utf8_non_ascii_measurement_is_admitted() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let content = "héllo 🌍";
    let expected = u64::try_from(content.len()).expect("utf8 length");
    assert_eq!(expected, 11);
    if let AtomRepresentation::Whole { content: slot } =
        &mut input.candidates.candidates[0].representation
    {
        *slot = content.to_owned();
    }
    input.measurements[0].cost = AdmissionMeasuredCost::ExactUtf8Bytes { value: expected };
    remeasure(&mut input, "required");
    let result = admit_context(&input).expect("non-ascii exact admission");
    let admitted = complete_set(&result);
    assert_eq!(admitted.economy.allocations.admitted_required, expected);
    let record = admitted
        .records
        .iter()
        .find(|record| record.candidate.atom_id == id("required"))
        .expect("required admitted");
    assert_eq!(
        record.candidate.representation,
        AtomRepresentation::Whole {
            content: content.to_owned()
        }
    );
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/14
#[test]
fn foreign_serializer_schema_route_model_tokenizer_are_rejected() {
    let mut foreign_serializer =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    foreign_serializer.measurements[0].binding.serializer_id = "foreign-serializer".to_owned();
    assert_eq!(
        admit_context(&foreign_serializer),
        Err(ContextError::IdentityConflict)
    );

    let mut foreign_schema = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    foreign_schema.measurements[0].binding.schema_version = ContractVersion::new(9, 9, 9);
    assert_eq!(
        admit_context(&foreign_schema),
        Err(ContextError::InvalidField(
            "admission_measurement.schema_version"
        ))
    );

    let mut foreign_route = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    foreign_route.measurements[0].binding.route_id = "foreign-route".to_owned();
    assert_eq!(
        admit_context(&foreign_route),
        Err(ContextError::IdentityConflict)
    );

    let mut foreign_model = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    foreign_model.measurements[0].binding.model_id = "foreign-model".to_owned();
    assert_eq!(
        admit_context(&foreign_model),
        Err(ContextError::IdentityConflict)
    );

    let mut tokenizer_cost = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    tokenizer_cost.measurements[0].cost = AdmissionMeasuredCost::ExactTokenizer {
        observation: TokenizerObservation {
            tokenizer_id: "tok".to_owned(),
            tokenizer_version: "1".to_owned(),
            tokenizer_hash: digest(b'a'),
            tokens: 5,
        },
    };
    // A tokenizer-unit cost is foreign to the exact UTF-8 profile denominator.
    assert_eq!(
        admit_context(&tokenizer_cost),
        Err(ContextError::IdentityConflict)
    );

    let mut stu_observation =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    stu_observation.measurements[0].observation =
        Some(AdmissionMeasuredCost::ConservativeStu {
            estimate: StuEstimate {
                value: 99,
                empirical: false,
            },
        });
    // An unqualified STU observation can never authorize additive fit.
    assert_eq!(
        admit_context(&stu_observation),
        Err(ContextError::UnknownMeasurement)
    );
}

// WORK_UNIT_CASE: 608/15
#[test]
fn missing_required_measurement_is_rejected() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input.measurements.remove(0);
    assert_eq!(
        admit_context(&input),
        Err(ContextError::DenominatorMismatch)
    );
}

// WORK_UNIT_CASE: 608/16
#[test]
fn unknown_measurement_cannot_prove_fit() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input.measurements[0].cost = AdmissionMeasuredCost::Unknown;
    let result = admit_context(&input).expect("unknown floor is explicit incomplete");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(gap.unknown, vec![id("required")]);
    assert!(gap.measurements.contains(&id("required-measurement")));
    assert!(!gap.reopening_requirements.is_empty());
    result.validate_for(&input).expect("incomplete conservation");
}

// WORK_UNIT_CASE: 608/17
#[test]
fn exact_route_capacity_boundary_succeeds() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    set_capacity(&mut input, 70, 10, 10, 10);
    let result = admit_context(&input).expect("exact boundary fits");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("optional"), id("required")]);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 0);
    admitted.economy.validate().expect("economy reconciles");
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/18
#[test]
fn one_byte_over_boundary_does_not_pass_optional() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    set_capacity(&mut input, 69, 10, 10, 10);
    let result = admit_context(&input).expect("floor still fits");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    let omission = result
        .evidence
        .omissions
        .iter()
        .find(|omission| omission.atom_id == id("optional"))
        .expect("optional omission");
    assert_eq!(omission.reason, OmissionReason::Capacity);
    assert_eq!(omission.measured_cost, Some(20));
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/19
#[test]
fn fixed_overhead_overflow_precedes_selection() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_capacity(&mut input, 100, 90, 10, 10);
    assert_eq!(
        admit_context(&input),
        Err(ContextError::CapacityExceeded)
    );
}

// WORK_UNIT_CASE: 608/20
#[test]
fn output_reserve_is_established_first() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_capacity(&mut input, 100, 10, 50, 10);
    let result = admit_context(&input).expect("output reserve fits");
    let admitted = complete_set(&result);
    assert_eq!(admitted.economy.allocations.output_reserve, 50);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 9);
    assert_eq!(admitted_ids(admitted), vec![id("optional"), id("required")]);
    admitted.economy.validate().expect("economy reconciles");
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/21
#[test]
fn review_reserve_is_established_first() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_capacity(&mut input, 100, 10, 10, 50);
    let result = admit_context(&input).expect("review reserve fits");
    let admitted = complete_set(&result);
    assert_eq!(admitted.economy.allocations.review_reserve, 50);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 9);
    assert_eq!(admitted_ids(admitted), vec![id("optional"), id("required")]);
    admitted.economy.validate().expect("economy reconciles");
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/22
#[test]
fn context_cannot_consume_declared_reserves() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 2 });
    set_capacity(&mut input, 51, 10, 10, 10);
    let result = admit_context(&input).expect("floor fits without reserves");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    assert_eq!(admitted.economy.allocations.admitted_optional, 0);
    assert_eq!(admitted.economy.allocations.fixed_overhead, 10);
    assert_eq!(admitted.economy.allocations.output_reserve, 10);
    assert_eq!(admitted.economy.allocations.review_reserve, 10);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 1);
    let omission = result
        .evidence
        .omissions
        .iter()
        .find(|omission| omission.atom_id == id("optional"))
        .expect("optional omission");
    assert_eq!(omission.reason, OmissionReason::Capacity);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/23
#[test]
fn valid_non_droppable_whole_representation_is_admitted() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let result = admit_context(&input).expect("floor fits");
    let admitted = complete_set(&result);
    let record = admitted
        .records
        .iter()
        .find(|record| record.candidate.atom_id == id("required"))
        .expect("required admitted");
    assert_eq!(record.disposition, AdmissionDisposition::Include);
    assert_eq!(record.candidate.loss_policy, LossPolicy::NonDroppable);
    assert!(record.candidate.representation.is_whole());
    assert_eq!(record.rule_evidence, input.rule.rule_id);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/24
#[test]
fn non_droppable_cannot_use_weaker_form_to_fit() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    input.candidates.candidates[0].representation = AtomRepresentation::Handle {
        handle: id("handle-required"),
    };
    assert_eq!(
        admit_context(&input),
        Err(ContextError::WholeUnitRequired)
    );
}

// WORK_UNIT_CASE: 608/25
#[test]
fn valid_handle_only_plus_expansion_is_admitted() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    make_handle_optional(&mut input);
    let result = admit_context(&input).expect("handle floor fits");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("optional"), id("required")]);
    let record = admitted
        .records
        .iter()
        .find(|record| record.candidate.atom_id == id("optional"))
        .expect("optional admitted");
    assert_eq!(record.disposition, AdmissionDisposition::HandleOnly);
    assert_eq!(admitted.economy.allocations.admitted_required, 20);
    assert_eq!(admitted.economy.allocations.admitted_optional, 20);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/26
#[test]
fn stale_foreign_expired_expansion_is_unavailable() {
    let mut changed_handle =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    make_handle_optional(&mut changed_handle);
    changed_handle.supplied_omissions[0]
        .expansion
        .as_mut()
        .expect("expansion present")
        .handle_id = id("other-handle");
    assert_eq!(
        admit_context(&changed_handle),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut foreign_source = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    make_handle_optional(&mut foreign_source);
    foreign_source.supplied_omissions[0]
        .expansion
        .as_mut()
        .expect("expansion present")
        .source_revision = "r9".to_owned();
    assert_eq!(
        admit_context(&foreign_source),
        Err(ContextError::OmissionHandleInvalid)
    );

    let mut expired_decision =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    make_handle_optional(&mut expired_decision);
    expired_decision.supplied_omissions[0]
        .expansion
        .as_mut()
        .expect("expansion present")
        .decision
        .recipe_revision = TaskRevision::new(2).expect("revision");
    assert_eq!(
        admit_context(&expired_decision),
        Err(ContextError::OmissionHandleInvalid)
    );
}

// WORK_UNIT_CASE: 608/27
#[test]
fn valid_producer_extractive_with_receipt_is_admitted() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_extractive(
        &mut input,
        "excerpt",
        "extract content",
        vec!["field-a".to_owned(), "field-b".to_owned()],
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    let result = admit_context(&input).expect("extractive fits");
    let admitted = complete_set(&result);
    assert_eq!(
        admitted_ids(admitted),
        vec![id("excerpt"), id("optional"), id("required")]
    );
    let record = admitted
        .records
        .iter()
        .find(|record| record.candidate.atom_id == id("excerpt"))
        .expect("extract admitted");
    assert_eq!(record.disposition, AdmissionDisposition::Include);
    assert_eq!(
        record.candidate.representation,
        AtomRepresentation::Extractive {
            content: "extract content".to_owned(),
            manifest: vec!["field-a".to_owned(), "field-b".to_owned()],
        }
    );
    assert_eq!(admitted.economy.allocations.admitted_optional, 6);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/28
#[test]
fn absent_or_changed_extract_receipt_blocks_selection() {
    let mut absent = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_extractive(
        &mut absent,
        "excerpt",
        "extract content",
        Vec::new(),
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    assert_eq!(
        admit_context(&absent),
        Err(ContextError::Bounds {
            field: "atom.representation.manifest"
        })
    );

    let mut changed = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_extractive(
        &mut changed,
        "excerpt",
        "extract content",
        vec!["field-a".to_owned()],
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    let position = changed
        .candidates
        .candidates
        .iter()
        .position(|candidate| candidate.atom_id == id("excerpt"))
        .expect("excerpt present");
    if let AtomRepresentation::Extractive { content, .. } =
        &mut changed.candidates.candidates[position].representation
    {
        content.push_str(" plus more");
    }
    assert_eq!(
        admit_context(&changed),
        Err(ContextError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 608/29
#[test]
fn valid_producer_summarizable_with_receipt_is_admitted() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_summary(
        &mut input,
        "digest-a",
        "summary content",
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    let result = admit_context(&input).expect("summary fits");
    let admitted = complete_set(&result);
    assert_eq!(
        admitted_ids(admitted),
        vec![id("digest-a"), id("optional"), id("required")]
    );
    let record = admitted
        .records
        .iter()
        .find(|record| record.candidate.atom_id == id("digest-a"))
        .expect("summary admitted");
    assert_eq!(record.disposition, AdmissionDisposition::Include);
    assert_eq!(
        record.candidate.representation,
        AtomRepresentation::Summary {
            content: "summary content".to_owned(),
            source_digest: digest(b'b'),
        }
    );
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/30
#[test]
fn absent_or_changed_summary_receipt_blocks_selection() {
    let mut absent = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_summary(
        &mut absent,
        "digest-a",
        "summary content",
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    let position = absent
        .candidates
        .candidates
        .iter()
        .position(|candidate| candidate.atom_id == id("digest-a"))
        .expect("summary present");
    if let AtomRepresentation::Summary { source_digest, .. } =
        &mut absent.candidates.candidates[position].representation
    {
        *source_digest = "not-a-digest".to_owned();
    }
    remeasure(&mut absent, "digest-a");
    assert_eq!(
        admit_context(&absent),
        Err(ContextError::InvalidDigest(
            "atom.representation.source_digest"
        ))
    );

    let mut changed = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_summary(
        &mut changed,
        "digest-a",
        "summary content",
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    let position = changed
        .candidates
        .candidates
        .iter()
        .position(|candidate| candidate.atom_id == id("digest-a"))
        .expect("summary present");
    if let AtomRepresentation::Summary { content, .. } =
        &mut changed.candidates.candidates[position].representation
    {
        content.push_str(" plus more");
    }
    assert_eq!(
        admit_context(&changed),
        Err(ContextError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 608/31
#[test]
fn admission_implements_no_extract_summary_or_truncation() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 5 });
    let result = admit_context(&input).expect("whole admission");
    let admitted = complete_set(&result);
    for record in &admitted.records {
        let supplied = input
            .candidate(&record.candidate.atom_id)
            .expect("admitted atom is supplied");
        assert_eq!(&record.candidate, supplied);
        assert!(matches!(
            record.candidate.representation,
            AtomRepresentation::Whole { .. }
        ));
    }
    assert!(
        admitted.records.iter().all(|record| !matches!(
            record.candidate.representation,
            AtomRepresentation::Extractive { .. } | AtomRepresentation::Summary { .. }
        ))
    );
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/32
#[test]
fn admission_never_splits_one_atom_into_members() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 5 });
    push_optional(
        &mut input,
        "extra-a",
        "extra a",
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    push_optional(
        &mut input,
        "extra-b",
        "extra b",
        5,
        AdmissionPriorityClass::Normal,
        3,
    );
    let result = admit_context(&input).expect("optionals fit");
    let admitted = complete_set(&result);
    let supplied_ids = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| candidate.atom_id.clone())
        .collect::<Vec<_>>();
    assert!(admitted.records.len() <= supplied_ids.len());
    for record in &admitted.records {
        assert!(supplied_ids.contains(&record.candidate.atom_id));
        let supplied = input
            .candidate(&record.candidate.atom_id)
            .expect("admitted atom is supplied");
        assert_eq!(&record.candidate, supplied);
    }
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/33
#[test]
fn required_dependency_closure_is_atomic() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    promote_to_floor(&mut input, "optional");
    add_dependency(&mut input, "required", "optional");
    let result = admit_context(&input).expect("closed floor fits");
    let admitted = complete_set(&result);
    assert_eq!(
        admitted_ids(admitted),
        vec![id("optional"), id("required")]
    );
    assert_eq!(admitted.economy.allocations.admitted_required, 40);
    assert_eq!(admitted.economy.allocations.admitted_optional, 0);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/34
#[test]
fn missing_stale_blocked_dependency_is_exact_incomplete() {
    let mut missing = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    promote_to_floor(&mut missing, "optional");
    add_dependency(&mut missing, "required", "optional");
    set_availability(&mut missing, "optional", AtomAvailability::Missing);
    let result = admit_context(&missing).expect("missing dependency is explicit");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(gap.missing, vec![id("optional")]);

    let mut stale = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    promote_to_floor(&mut stale, "optional");
    add_dependency(&mut stale, "required", "optional");
    set_availability(&mut stale, "optional", AtomAvailability::Stale);
    let result = admit_context(&stale).expect("stale dependency is explicit");
    assert_eq!(incomplete_gap(&result).stale, vec![id("optional")]);

    let mut blocked = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    promote_to_floor(&mut blocked, "optional");
    add_dependency(&mut blocked, "required", "optional");
    set_availability(&mut blocked, "optional", AtomAvailability::Blocked);
    let result = admit_context(&blocked).expect("blocked dependency is explicit");
    assert_eq!(incomplete_gap(&result).blocked, vec![id("optional")]);
}

// WORK_UNIT_CASE: 608/35
#[test]
fn required_negative_evidence_cannot_be_displaced() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 5 });
    let slot = add_provider_slot(&mut input, "neg-provider", SemanticRole::Negative);
    ensure_role_policy(
        &mut input,
        SemanticRole::Negative,
        LossPolicy::NonDroppable,
        true,
        vec![RepresentationKind::Whole],
    );
    let context = input.binding.clone();
    let negative = candidate(
        &context,
        "neg",
        slot,
        "negative evidence",
        LossPolicy::NonDroppable,
        true,
    );
    input.measurements.push(measurement(
        &context,
        &negative,
        "neg-measurement",
        AdmissionMeasuredCost::ExactUtf8Bytes { value: 10 },
    ));
    input.priority.priorities.push(CandidatePriority {
        atom_id: negative.atom_id.clone(),
        class: AdmissionPriorityClass::Required,
        ordinal: 0,
    });
    input.candidates.candidates.push(negative);
    promote_to_floor(&mut input, "neg");
    push_optional(
        &mut input,
        "flood-a",
        "flood a",
        40,
        AdmissionPriorityClass::Normal,
        3,
    );
    push_optional(
        &mut input,
        "flood-b",
        "flood b",
        40,
        AdmissionPriorityClass::Normal,
        4,
    );
    push_optional(
        &mut input,
        "flood-c",
        "flood c",
        40,
        AdmissionPriorityClass::Normal,
        5,
    );
    let result = admit_context(&input).expect("floor survives flood");
    let admitted = complete_set(&result);
    assert_eq!(
        admitted_ids(admitted),
        vec![id("neg"), id("optional"), id("required")]
    );
    assert_eq!(admitted.economy.allocations.admitted_required, 30);
    for flood in ["flood-a", "flood-b", "flood-c"] {
        let omission = result
            .evidence
            .omissions
            .iter()
            .find(|omission| omission.atom_id == id(flood))
            .expect("flood omission");
        assert_eq!(omission.reason, OmissionReason::Capacity);
    }
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/36
#[test]
fn optional_cannot_substitute_exact_floor_member() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "required", AtomAvailability::Missing);
    let result = admit_context(&input).expect("missing floor is explicit");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.missing, vec![id("required")]);
    assert!(
        matches!(result.outcome, ContextOutcome::Incomplete(_)),
        "present optional must not substitute the exact missing member"
    );
    assert!(result.evidence.economy.is_none());
}

// WORK_UNIT_CASE: 608/37
#[test]
fn exact_fitting_floor_succeeds() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    set_capacity(&mut input, 50, 10, 10, 10);
    let result = admit_context(&input).expect("exact floor fits");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 0);
    assert_eq!(result.evidence.decisions.len(), 2);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/38
#[test]
fn one_over_floor_yields_canonical_incomplete() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_capacity(&mut input, 49, 10, 10, 10);
    let result = admit_context(&input).expect("one-over floor is explicit");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(gap.oversized, vec![id("required")]);
    assert!(gap.measurements.contains(&id("required-measurement")));
    assert!(!gap.reopening_requirements.is_empty());
    gap.validate().expect("canonical gap validates");
    result.validate_for(&input).expect("incomplete conservation");
}

// WORK_UNIT_CASE: 608/39
#[test]
fn missing_mandatory_stays_missing() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "required", AtomAvailability::Missing);
    let result = admit_context(&input).expect("missing is explicit");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.missing, vec![id("required")]);
    assert_eq!(gap.provider_gaps.len(), 1);
    assert_eq!(
        gap.provider_gaps[0].slot,
        input.candidates.candidates[0].provider_role
    );
    result.validate_for(&input).expect("incomplete conservation");
}

// WORK_UNIT_CASE: 608/40
#[test]
fn stale_mandatory_stays_stale() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "required", AtomAvailability::Stale);
    let first = admit_context(&input).expect("stale is explicit");
    let second = admit_context(&input).expect("stale is deterministic");
    assert_eq!(first, second);
    let gap = incomplete_gap(&first);
    assert_eq!(gap.stale, vec![id("required")]);
    assert!(
        gap.reopening_requirements
            .iter()
            .any(|requirement| requirement.contains("required")),
        "reopen evidence must name the stale member"
    );
}

// WORK_UNIT_CASE: 608/41
#[test]
fn blocked_unavailable_unmeasured_mandatory_are_exact() {
    let mut blocked = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut blocked, "required", AtomAvailability::Blocked);
    let result = admit_context(&blocked).expect("blocked is explicit");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(gap.blocked, vec![id("required")]);

    let mut unavailable = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut unavailable, "required", AtomAvailability::Unavailable);
    let result = admit_context(&unavailable).expect("unavailable is explicit");
    assert_eq!(incomplete_gap(&result).unavailable, vec![id("required")]);

    let mut unmeasured = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    unmeasured.measurements[0].cost = AdmissionMeasuredCost::Unavailable;
    let result = admit_context(&unmeasured).expect("unmeasured is explicit");
    assert_eq!(
        incomplete_gap(&result).unavailable,
        vec![id("required")]
    );
}

// WORK_UNIT_CASE: 608/42
#[test]
fn required_provider_coverage_gap_is_incomplete() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let slot = add_provider_slot(&mut input, "quiet-provider", SemanticRole::Verifier);
    input.floor.floor.providers.requested.push(slot.clone());
    input.floor.floor.providers.dispositions.push(ProviderDisposition {
        slot: slot.clone(),
        state: AtomAvailability::Stale,
        evidence: None,
    });
    for dispositions in [
        &mut input.candidates.denominator.dispositions,
        &mut input.recipe.denominator.dispositions,
    ] {
        let entry = dispositions
            .iter_mut()
            .find(|disposition| disposition.slot == slot)
            .expect("quiet disposition");
        entry.state = AtomAvailability::Stale;
    }
    refresh_recipe(&mut input);
    let result = admit_context(&input).expect("provider gap is explicit");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(gap.provider_gaps.len(), 1);
    assert_eq!(gap.provider_gaps[0].slot, slot);
    assert!(gap.missing.is_empty());
    assert!(gap.stale.is_empty());
    result.validate_for(&input).expect("incomplete conservation");
}

// WORK_UNIT_CASE: 608/43
#[test]
fn partial_coverage_is_neither_complete_nor_known_empty() {
    let mut optional_partial =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut optional_partial, "optional", AtomAvailability::Partial);
    let result = admit_context(&optional_partial).expect("partial optional stays visible");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    let omission = result
        .evidence
        .omissions
        .iter()
        .find(|omission| omission.atom_id == id("optional"))
        .expect("partial omission");
    assert_eq!(omission.reason, OmissionReason::Unavailable);
    let decision = result
        .evidence
        .decisions
        .iter()
        .find(|decision| decision.atom_id == id("optional"))
        .expect("partial decision");
    assert_eq!(decision.disposition, AdmissionDisposition::Unavailable);

    let mut required_partial =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut required_partial, "required", AtomAvailability::Partial);
    let result = admit_context(&required_partial).expect("partial floor is explicit");
    assert_eq!(incomplete_gap(&result).partial, vec![id("required")]);
}

// WORK_UNIT_CASE: 608/44
#[test]
fn optional_known_empty_requires_authoritative_coverage() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "optional", AtomAvailability::KnownEmpty);
    let result = admit_context(&input).expect("known-empty stays visible");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    assert!(result.evidence.incomplete.is_none());
    let omission = result
        .evidence
        .omissions
        .iter()
        .find(|omission| omission.atom_id == id("optional"))
        .expect("known-empty omission");
    assert_eq!(omission.reason, OmissionReason::Unavailable);
    assert_eq!(omission.measured_cost, Some(1));
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/45
#[test]
fn incomplete_retains_capacity_member_dependency_reopen_evidence() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "required", AtomAvailability::Missing);
    let result = admit_context(&input).expect("missing is explicit");
    let gap = incomplete_gap(&result);
    assert_eq!(gap.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(gap.failed_floor_rule, id("floor-rule"));
    assert_eq!(gap.missing, vec![id("required")]);
    assert!(gap.measurements.contains(&id("required-measurement")));
    assert!(!gap.reopening_requirements.is_empty());
    assert_eq!(result.floor_id, id("floor"));
    assert_eq!(result.recipe_digest, input.recipe.recipe_sha256);
    result.validate_for(&input).expect("incomplete conservation");
}

// WORK_UNIT_CASE: 608/46
#[test]
fn incomplete_cannot_convert_to_thinner_admitted_complete() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "required", AtomAvailability::Missing);
    let result = admit_context(&input).expect("missing is explicit");
    assert!(matches!(
        result.outcome,
        ContextOutcome::Incomplete(_)
    ));
    assert!(result.evidence.economy.is_none());
    assert_eq!(result.evidence.decisions.len(), 2);
    assert!(
        result.evidence.decisions.iter().all(|decision| !matches!(
            decision.disposition,
            AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
        )),
        "no admitted disposition may survive an incomplete floor"
    );
    let gap = incomplete_gap(&result);
    assert_eq!(
        result.selection_digest,
        canonical_digest(gap).expect("gap digest")
    );
}

// WORK_UNIT_CASE: 608/47
#[test]
fn optional_flood_cannot_crowd_or_alter_floor() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    for (index, atom) in ["flood-a", "flood-b", "flood-c", "flood-d", "flood-e"]
        .iter()
        .enumerate()
    {
        push_optional(
            &mut input,
            atom,
            &format!("flood content {index}"),
            60,
            AdmissionPriorityClass::Normal,
            u32::try_from(index + 2).expect("ordinal"),
        );
    }
    let result = admit_context(&input).expect("floor survives flood");
    let admitted = complete_set(&result);
    assert_eq!(
        admitted_ids(admitted),
        vec![id("optional"), id("required")]
    );
    let required_record = admitted
        .records
        .iter()
        .find(|record| record.candidate.atom_id == id("required"))
        .expect("floor record");
    assert_eq!(
        &required_record.candidate,
        &input.candidates.candidates[0],
        "floor representation must be unaltered"
    );
    assert_eq!(admitted.economy.allocations.admitted_required, 20);
    assert_eq!(admitted.economy.allocations.admitted_optional, 20);
    assert_eq!(result.evidence.omissions.len(), 5);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/48
#[test]
fn optional_cannot_consume_protected_headroom() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_capacity(&mut input, 50, 10, 10, 10);
    let result = admit_context(&input).expect("exact floor fits");
    let admitted = complete_set(&result);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 0);
    assert_eq!(admitted.economy.allocations.admitted_optional, 0);
    assert_eq!(admitted.economy.allocations.fixed_overhead, 10);
    assert_eq!(admitted.economy.allocations.output_reserve, 10);
    assert_eq!(admitted.economy.allocations.review_reserve, 10);
    admitted.economy.validate().expect("economy reconciles");

    let mut protected = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let context = protected.binding.clone();
    let slot = protected.candidates.candidates[1].provider_role.clone();
    let guarded = candidate(
        &context,
        "guarded",
        slot,
        "guarded",
        LossPolicy::Summarizable,
        true,
    );
    protected.measurements.push(measurement(
        &context,
        &guarded,
        "guarded-measurement",
        AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 },
    ));
    protected.priority.priorities.push(CandidatePriority {
        atom_id: guarded.atom_id.clone(),
        class: AdmissionPriorityClass::Normal,
        ordinal: 2,
    });
    protected.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: guarded.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    protected.candidates.candidates.push(guarded);
    assert_eq!(
        admit_context(&protected),
        Err(ContextError::MissingFloor)
    );
}

// WORK_UNIT_CASE: 608/49
#[test]
fn explicit_priority_beats_stable_tie_breaks() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    set_capacity(&mut input, 70, 10, 10, 10);
    push_optional(
        &mut input,
        "late-high",
        "late high",
        10,
        AdmissionPriorityClass::High,
        5,
    );
    push_optional(
        &mut input,
        "early-normal",
        "early normal",
        10,
        AdmissionPriorityClass::Normal,
        0,
    );
    let result = admit_context(&input).expect("priority decides");
    let admitted = complete_set(&result);
    assert_eq!(
        admitted_ids(admitted),
        vec![id("early-normal"), id("late-high"), id("required")]
    );
    assert!(
        !admitted_ids(admitted).contains(&id("optional")),
        "lower priority optional yields despite earlier ordinal"
    );
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/50
#[test]
fn tie_break_is_independent_of_insertion_order() {
    let mut first = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 60 });
    set_capacity(&mut first, 60, 10, 10, 10);
    push_optional(
        &mut first,
        "tie-a",
        "tie a",
        10,
        AdmissionPriorityClass::Normal,
        0,
    );
    push_optional(
        &mut first,
        "tie-b",
        "tie b",
        10,
        AdmissionPriorityClass::Normal,
        1,
    );
    let mut second = first.clone();
    second.candidates.candidates.reverse();
    second.measurements.reverse();
    second.priority.priorities.reverse();
    second.supplied_omissions.reverse();
    let one = admit_context(&first).expect("first order");
    let two = admit_context(&second).expect("permuted order");
    assert_eq!(one, two);
    assert_eq!(
        admitted_ids(complete_set(&one)),
        vec![id("required"), id("tie-a")]
    );
}

// WORK_UNIT_CASE: 608/51
#[test]
fn provider_role_coverage_holds_under_unequal_volume() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 10 });
    set_capacity(&mut input, 70, 10, 10, 10);
    let big_slot = add_provider_slot(&mut input, "big-provider", SemanticRole::Optional);
    let context = input.binding.clone();
    let big = candidate(
        &context,
        "big-one",
        big_slot,
        "big one",
        LossPolicy::Summarizable,
        false,
    );
    input.measurements.push(measurement(
        &context,
        &big,
        "big-one-measurement",
        AdmissionMeasuredCost::ExactUtf8Bytes { value: 10 },
    ));
    input.priority.priorities.push(CandidatePriority {
        atom_id: big.atom_id.clone(),
        class: AdmissionPriorityClass::Normal,
        ordinal: 0,
    });
    input.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: big.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    input.candidates.candidates.push(big);
    push_optional(
        &mut input,
        "small-extra",
        "small extra",
        10,
        AdmissionPriorityClass::Normal,
        2,
    );
    let result = admit_context(&input).expect("coverage holds");
    let admitted = complete_set(&result);
    assert_eq!(
        admitted_ids(admitted),
        vec![id("big-one"), id("optional"), id("required")]
    );
    let mut providers = admitted
        .records
        .iter()
        .map(|record| record.candidate.provider_role.provider.as_str().to_owned())
        .collect::<Vec<_>>();
    providers.sort();
    providers.dedup();
    assert_eq!(
        providers,
        vec!["big-provider", "optional-provider", "required-provider"]
    );
    assert_eq!(result.evidence.decisions.len(), 4);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/52
#[test]
fn scalar_priority_cannot_override_failed_constraint() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "optional", AtomAvailability::Stale);
    let position = input
        .priority
        .priorities
        .iter()
        .position(|priority| priority.atom_id == id("optional"))
        .expect("optional priority");
    input.priority.priorities[position].class = AdmissionPriorityClass::Protected;
    let result = admit_context(&input).expect("stale stays omitted");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    let omission = result
        .evidence
        .omissions
        .iter()
        .find(|omission| omission.atom_id == id("optional"))
        .expect("stale omission");
    assert_eq!(omission.reason, OmissionReason::Stale);
    let decision = result
        .evidence
        .decisions
        .iter()
        .find(|decision| decision.atom_id == id("optional"))
        .expect("stale decision");
    assert_eq!(decision.disposition, AdmissionDisposition::Revalidate);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/53
#[test]
fn one_disposition_per_candidate_provider_representation() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 5 });
    push_optional(
        &mut input,
        "extra-a",
        "extra a",
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    let result = admit_context(&input).expect("dispositions complete");
    complete_set(&result);
    assert_eq!(
        result.evidence.decisions.len(),
        input.candidates.candidates.len()
    );
    let mut seen = std::collections::BTreeSet::new();
    for decision in &result.evidence.decisions {
        assert!(seen.insert(decision.atom_id.clone()));
        let supplied = input
            .candidate(&decision.atom_id)
            .expect("decision names a candidate");
        assert_eq!(&supplied.provider_role, &decision.provider_role);
        let measured = input
            .measurement(&decision.atom_id, supplied.representation.kind())
            .expect("measured representation");
        assert_eq!(measured.representation, supplied.representation.kind());
    }
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/54
#[test]
fn reversible_omission_carries_exact_identity_reason_decision_expansion() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    make_handle_optional(&mut input);
    let result = admit_context(&input).expect("over-budget handle omits");
    complete_set(&result);
    assert_eq!(result.evidence.omissions.len(), 1);
    let omission = &result.evidence.omissions[0];
    assert_eq!(omission.atom_id, id("optional"));
    assert_eq!(omission.reason, OmissionReason::Capacity);
    assert_eq!(omission.decision, input.recipe.decision);
    assert_eq!(omission.measured_cost, Some(80));
    assert_eq!(omission.allowed_representation, LossPolicy::HandleOnly);
    let expansion = omission.expansion.as_ref().expect("reversible handle");
    assert_eq!(expansion.handle_id, id("handle-optional"));
    assert_eq!(expansion.atom_id, id("optional"));
    assert_eq!(expansion.decision, input.recipe.decision);
    assert_eq!(omission.task_revision, TaskRevision::new(1).expect("revision"));
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/55
#[test]
fn nonrecoverable_omission_requires_typed_reason() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    let result = admit_context(&input).expect("over-budget omits");
    complete_set(&result);
    let omission = result
        .evidence
        .omissions
        .iter()
        .find(|omission| omission.atom_id == id("optional"))
        .expect("optional omission");
    assert_eq!(
        omission.non_recoverable_reason,
        Some(NonRecoverableReason::SourceUnavailable)
    );
    assert!(omission.expansion.is_none());
    assert_eq!(omission.authorization_requirement, "owner");
    assert_eq!(omission.privacy_requirement, "scoped");
    assert_eq!(omission.proof_requirement, "observation");

    let mut untyped = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    untyped.supplied_omissions[0].non_recoverable_reason = None;
    assert_eq!(
        admit_context(&untyped),
        Err(ContextError::OmissionHandleInvalid)
    );
}

// WORK_UNIT_CASE: 608/56
#[test]
fn optional_unavailable_is_visible_without_required_gap() {
    let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    set_availability(&mut input, "optional", AtomAvailability::Unavailable);
    let result = admit_context(&input).expect("unavailable optional stays visible");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    assert!(result.evidence.incomplete.is_none());
    let omission = result
        .evidence
        .omissions
        .iter()
        .find(|omission| omission.atom_id == id("optional"))
        .expect("unavailable omission");
    assert_eq!(omission.reason, OmissionReason::Unavailable);
    assert_eq!(omission.measured_cost, Some(1));
    let decision = result
        .evidence
        .decisions
        .iter()
        .find(|decision| decision.atom_id == id("optional"))
        .expect("unavailable decision");
    assert_eq!(decision.disposition, AdmissionDisposition::Unavailable);
    result.validate_for(&input).expect("result conservation");
}

// WORK_UNIT_CASE: 608/57
#[test]
fn economy_displacement_rule_arithmetic_is_exact() {
    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    let result = admit_context(&input).expect("omission keeps economy");
    let admitted = complete_set(&result);
    let economy = &admitted.economy;
    let mut requested = economy.requested.clone();
    requested.sort();
    assert_eq!(requested, vec![id("optional"), id("required")]);
    assert_eq!(economy.admitted, vec![id("required")]);
    assert_eq!(economy.displaced, vec![id("optional")]);
    assert_eq!(economy.applied_rule, input.rule.rule_id);
    assert_eq!(economy.recipe_digest, input.recipe.recipe_sha256);
    let omitted = economy
        .omissions
        .iter()
        .map(|omission| omission.atom_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(omitted, economy.displaced);
    economy.validate().expect("economy reconciles");

    let mut tampered = admitted.clone();
    tampered.economy.applied_rule = id("other-rule");
    assert_eq!(
        tampered.economy.validate(),
        Err(ContextError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 608/58
#[test]
fn allocation_plus_every_reserve_never_exceeds_capacity() {
    for route in [70_u64, 100_u64, 150_u64] {
        let mut input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
        set_capacity(&mut input, route, 10, 10, 10);
        let result = admit_context(&input).expect("floor fits at every route");
        let admitted = complete_set(&result);
        let allocations = &admitted.economy.allocations;
        let used = allocations.fixed_overhead
            + allocations.output_reserve
            + allocations.review_reserve
            + allocations.admitted_required
            + allocations.admitted_optional;
        assert!(used <= route);
        assert_eq!(used + allocations.remaining_headroom, route);
        assert_eq!(allocations.admitted_required, 20);
        assert_eq!(allocations.admitted_optional, 20);
        result.validate_for(&input).expect("result conservation");
    }
}

// WORK_UNIT_CASE: 608/59
#[test]
fn removing_optional_material_keeps_floor_valid() {
    let full = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let full_result = admit_context(&full).expect("full admission");
    let full_floor = admitted_ids(complete_set(&full_result))
        .into_iter()
        .filter(|atom| {
            full.floor.floor.mandatory_atoms.contains(atom)
        })
        .collect::<Vec<_>>();

    let mut reduced = full.clone();
    reduced.candidates.candidates.retain(|candidate| {
        candidate.atom_id != id("optional")
    });
    reduced
        .measurements
        .retain(|item| item.atom_id != id("optional"));
    reduced
        .priority
        .priorities
        .retain(|priority| priority.atom_id != id("optional"));
    reduced
        .supplied_omissions
        .retain(|binding| binding.atom_id != id("optional"));
    let result = admit_context(&reduced).expect("reduced admission");
    let admitted = complete_set(&result);
    assert_eq!(admitted_ids(admitted), vec![id("required")]);
    let reduced_floor = admitted
        .records
        .iter()
        .map(|record| record.candidate.atom_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(reduced_floor, full_floor);
    result.validate_for(&reduced).expect("result conservation");
}

// WORK_UNIT_CASE: 608/60
#[test]
fn malformed_inputs_are_panic_free_and_permutations_deterministic() {
    let mut emptied = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    emptied.candidates.candidates.clear();
    assert!(admit_context(&emptied).is_err());

    let mut tampered_digest =
        input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    tampered_digest.recipe.recipe_sha256 = "c".repeat(64);
    assert!(admit_context(&tampered_digest).is_err());

    let mut duplicated = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    let repeated = duplicated.candidates.candidates[0].clone();
    duplicated.candidates.candidates.push(repeated);
    assert!(admit_context(&duplicated).is_err());

    let mut foreign_digest = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    foreign_digest.measurements[0].binding.input_digest = "ab".repeat(32);
    assert!(admit_context(&foreign_digest).is_err());

    let input = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 5 });
    let first = admit_context(&input).expect("first call");
    let second = admit_context(&input).expect("second call");
    assert_eq!(first, second);
    let mut permuted = input.clone();
    permuted.candidates.candidates.reverse();
    permuted.measurements.reverse();
    permuted.priority.priorities.reverse();
    permuted.supplied_omissions.reverse();
    let reordered = admit_context(&permuted).expect("permuted call");
    assert_eq!(first, reordered);
}
