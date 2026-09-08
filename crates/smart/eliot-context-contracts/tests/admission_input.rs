#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, DecisionId, ResourceGeneration, StateFence, TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest() -> String {
    "a".repeat(64)
}

fn binding() -> ContextBinding {
    let mut state_fence = StateFence::new(
        AuthorityEpoch::new(1).expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    state_fence.task_revision = Some(TaskRevision::new(1).expect("revision"));
    ContextBinding {
        task_id: TaskId::new("task").expect("task"),
        attempt_id: AgentAttemptId::new("attempt").expect("attempt"),
        scope_id: WorkScopeId::new("scope").expect("scope"),
        state_fence,
        decision_id: DecisionId::new("decision").expect("decision"),
        operation_id: None,
    }
}

fn decision() -> DecisionRevision {
    DecisionRevision {
        decision_id: binding().decision_id.clone(),
        recipe_revision: eliot_contracts::TaskRevision::new(1).expect("revision"),
        policy_sha256: digest(),
    }
}

fn candidate(context: &ContextBinding) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id("atom"),
        provider_role: ProviderRole {
            provider: ProviderId::new("provider").expect("provider"),
            role: SemanticRole::Goal,
        },
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new("source").expect("source"),
            owner: ProviderId::new("provider").expect("owner"),
            snapshot_id: id("snapshot"),
            revision: "r1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: "goal".to_owned(),
        },
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: true,
        // Executable admission inputs use the current public-only route;
        // restricted labels remain covered by inert contract tests.
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: digest(),
            serializer: "json-v1".to_owned(),
        },
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id("evidence"),
            ceiling: ProofCeiling::Observation,
        },
    }
}

#[allow(clippy::too_many_lines)]
fn input() -> AdmissionInput {
    let context = binding();
    let candidate = candidate(&context);
    let subject_digest = canonical_digest(&candidate).expect("candidate subject digest");
    let slot = candidate.provider_role.clone();
    let denominator = ProviderRoleDenominator {
        requested: vec![slot.clone()],
        dispositions: vec![ProviderDisposition {
            slot,
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        }],
    };
    let capacity = CapacityLimits {
        route_capacity: 100,
        fixed_overhead: 10,
        output_reserve: 20,
        review_reserve: 20,
    };
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: decision(),
        recipe_sha256: digest(),
        denominator: denominator.clone(),
        mandatory_roles: vec![SemanticRole::Goal],
        role_policies: vec![RoleLossRule {
            role: SemanticRole::Goal,
            loss_policy: LossPolicy::NonDroppable,
            required: true,
            allowed_representations: vec![RepresentationKind::Whole],
        }],
        capacity,
        predecessor: None,
        invalidation: None,
    };
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![candidate.atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: denominator,
        members: vec![SafetyFloorMember {
            atom_id: candidate.atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(candidate.measurement.clone()),
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
            candidates: vec![candidate],
            denominator: recipe.denominator.clone(),
        },
        floor: SafetyFloorIdentity {
            floor_id: id("floor"),
            decision: recipe.decision.clone(),
            floor,
        },
        priority: PriorityPolicyIdentity {
            policy_id: id("priority"),
            decision: recipe.decision.clone(),
            priorities: vec![CandidatePriority {
                atom_id: id("atom"),
                class: AdmissionPriorityClass::Required,
                ordinal: 0,
            }],
        },
        rule: AdmissionRuleIdentity {
            rule_id: id("rule"),
            decision: recipe.decision,
            rule_sha256: "b".repeat(64),
        },
        measurement_profile: MeasurementCompositionProfile {
            profile_id: id("profile"),
            schema_version: CONTEXT_CONTRACT_VERSION,
            serializer_id: "json-v1".to_owned(),
            serializer_version: "1".to_owned(),
            serializer_options_digest: digest(),
            route_id: "route".to_owned(),
            model_id: "model".to_owned(),
            unit: MeasurementUnit::Utf8Bytes,
            aggregation: MeasurementAggregationMode::QualifiedUtf8Contribution,
            qualification: id("qualification"),
            capacity,
        },
        supplied_omissions: vec![SuppliedOmissionBinding {
            atom_id: id("atom"),
            policy: LossPolicy::NonDroppable,
            expansion: None,
            non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
            authorization_requirement: "decision owner".to_owned(),
            privacy_requirement: "restricted".to_owned(),
            proof_requirement: "observation".to_owned(),
            expires: None,
            invalidation: None,
        }],
        measurements: vec![AdmissionMeasurement {
            measurement_id: id("measurement"),
            atom_id: id("atom"),
            representation: RepresentationKind::Whole,
            unit: MeasurementUnit::Utf8Bytes,
            binding: AdmissionMeasurementBinding {
                context,
                schema_version: CONTEXT_CONTRACT_VERSION,
                input_digest: digest(),
                subject_digest,
                output_digest: "b".repeat(64),
                serializer_id: "json-v1".to_owned(),
                serializer_version: "1".to_owned(),
                serializer_options_digest: digest(),
                route_id: "route".to_owned(),
                model_id: "model".to_owned(),
            },
            cost: AdmissionMeasuredCost::ExactUtf8Bytes { value: 4 },
            observation: None,
        }],
    }
}

fn complete_result(input: &AdmissionInput) -> AdmissionResult {
    let candidate = input.candidates.candidates[0].clone();
    let atom_id = candidate.atom_id.clone();
    let profile_digest = input
        .measurement_profile
        .canonical_digest()
        .expect("profile digest");
    let economy = ContextEconomyReceipt {
        binding: input.binding.clone(),
        decision_id: input.binding.decision_id.clone(),
        measurement: MeasurementRef {
            digest: profile_digest.clone(),
            serializer: input.measurement_profile.serializer_id.clone(),
        },
        requested: vec![atom_id.clone()],
        admitted: vec![atom_id.clone()],
        displaced: Vec::new(),
        omissions: Vec::new(),
        applied_rule: id("economy-rule"),
        allocations: EconomyAllocations {
            fixed_overhead: 10,
            output_reserve: 20,
            review_reserve: 20,
            admitted_required: 4,
            admitted_optional: 0,
            remaining_headroom: 46,
            route_capacity: 100,
        },
        receipt_digest: digest(),
    };
    let mut admitted = AdmittedContextSet {
        binding: input.binding.clone(),
        records: vec![AdmittedAtom {
            candidate: candidate.clone(),
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        admissions: vec![AdmissionRecord {
            atom_id: atom_id.clone(),
            provider_role: candidate.provider_role.clone(),
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        floor: input.floor.floor.clone(),
        economy: economy.clone(),
    };
    let admitted_digest = admitted
        .canonical_payload_digest()
        .expect("admitted payload digest");
    admitted
        .economy
        .measurement
        .digest
        .clone_from(&admitted_digest);
    let evidence = AdmissionDecisionEvidence {
        binding: input.binding.clone(),
        decisions: admitted.admissions.clone(),
        omissions: Vec::new(),
        supplied_omissions: Vec::new(),
        incomplete: None,
        economy: Some(admitted.economy.clone()),
        proof_ceiling: ProofCeiling::Observation,
    };
    let mut result = AdmissionResult {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: input.binding.clone(),
        input_digest: input.canonical_digest().expect("input digest"),
        recipe_digest: input.recipe.recipe_sha256.clone(),
        profile_digest,
        floor_id: input.floor.floor_id.clone(),
        selection_digest: admitted_digest,
        outcome: ContextOutcome::Complete(admitted),
        evidence,
        result_digest: digest(),
    };
    let mut unsigned = result.clone();
    unsigned.result_digest = "0".repeat(64);
    result.result_digest = canonical_digest(&unsigned).expect("result digest");
    result
}

#[test]
fn valid_input_binds_measurement_floor_priority_and_rule() {
    let input = input();
    input.validate().expect("complete admission input");
    assert_eq!(
        input
            .measurement(&id("atom"), RepresentationKind::Whole)
            .unwrap()
            .cost
            .unit(),
        Some(MeasurementUnit::Utf8Bytes)
    );
    assert_eq!(input.canonical_digest().unwrap().len(), 64);
    complete_result(&input)
        .validate_for(&input)
        .expect("complete result conserves admitted membership");
    let mut unknown_cost_input = input.clone();
    unknown_cost_input.measurements[0].cost = AdmissionMeasuredCost::Unknown;
    let unknown_result = complete_result(&unknown_cost_input);
    assert_eq!(
        unknown_result.validate_for(&unknown_cost_input),
        Err(ContextError::UnknownMeasurement)
    );
}

#[test]
fn canonical_digest_is_stable_for_set_permutations() {
    let mut first = input();
    let mut optional = first.candidates.candidates[0].clone();
    optional.atom_id = id("atom-2");
    optional.measurement.digest = "c".repeat(64);
    let optional_subject = canonical_digest(&optional).expect("optional subject digest");
    first.candidates.candidates.push(optional.clone());
    let mut optional_measurement = first.measurements[0].clone();
    optional_measurement.measurement_id = id("measurement-2");
    optional_measurement.atom_id = optional.atom_id.clone();
    optional_measurement.binding.input_digest = optional.measurement.digest.clone();
    optional_measurement.binding.subject_digest = optional_subject;
    optional_measurement.binding.output_digest = "d".repeat(64);
    first.measurements.push(optional_measurement);
    first.priority.priorities.push(CandidatePriority {
        atom_id: optional.atom_id.clone(),
        class: AdmissionPriorityClass::Low,
        ordinal: 1,
    });
    let mut optional_binding = first.supplied_omissions[0].clone();
    optional_binding.atom_id = optional.atom_id;
    first.supplied_omissions.push(optional_binding);

    let mut second = first.clone();
    second.measurements.reverse();
    second.priority.priorities.reverse();
    second.candidates.candidates.reverse();
    second.supplied_omissions.reverse();
    assert_eq!(first.canonical_digest(), second.canonical_digest());
    first.measurements[0].cost = AdmissionMeasuredCost::ExactUtf8Bytes { value: 5 };
    assert_ne!(first.canonical_digest(), second.canonical_digest());
}

#[test]
fn each_candidate_requires_exactly_one_matching_measurement() {
    let mut missing = input();
    missing.measurements.clear();
    assert_eq!(
        missing.validate(),
        Err(ContextError::Bounds {
            field: "admission.input",
        })
    );
    let mut duplicate = input();
    duplicate
        .measurements
        .push(duplicate.measurements[0].clone());
    assert_eq!(
        duplicate.validate(),
        Err(ContextError::Duplicate(
            "admission.measurements.atom_representation"
        ))
    );
}

#[test]
fn unknown_cost_remains_valid_but_is_not_an_exact_unit() {
    let mut input = input();
    input.measurements[0].cost = AdmissionMeasuredCost::Unknown;
    input
        .validate()
        .expect("unknown is explicit input evidence");
    input
        .validate_additive_measurements()
        .expect("unknown remains explicit for the admission algorithm");
    assert_eq!(input.measurements[0].cost.unit(), None);

    let mut omission_context = binding();
    omission_context.state_fence.task_revision = Some(TaskRevision::new(1).expect("revision"));
    let omission = OmissionRecord {
        atom_id: id("atom"),
        source_id: id("source"),
        provider_role: input.candidates.candidates[0].provider_role.clone(),
        decision: decision(),
        task_revision: TaskRevision::new(1).expect("revision"),
        reason: OmissionReason::Unavailable,
        competing_constraint: "provider unavailable".to_owned(),
        measured_cost: None,
        allowed_representation: LossPolicy::NonDroppable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "decision owner".to_owned(),
        privacy_requirement: "restricted".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
        digest: digest(),
    };
    assert_eq!(
        serde_json::to_value(OmissionReason::UnknownMeasurement).unwrap(),
        serde_json::json!("UNKNOWN_MEASUREMENT")
    );
    assert_eq!(
        serde_json::to_value(OmissionReason::MeasurementUnavailable).unwrap(),
        serde_json::json!("MEASUREMENT_UNAVAILABLE")
    );
    omission
        .validate(&omission_context)
        .expect("unknown omission cost is explicit");
    let mut known_zero = omission.clone();
    known_zero.measured_cost = Some(0);
    known_zero
        .validate(&omission_context)
        .expect("known zero omission cost remains distinct from unknown");
    assert_eq!(
        serde_json::from_value::<OmissionRecord>(serde_json::to_value(&known_zero).unwrap())
            .unwrap()
            .measured_cost,
        Some(0)
    );
    let mut encoded = serde_json::to_value(&omission).expect("omission encoding");
    assert!(serde_json::from_value::<OmissionRecord>(encoded.clone()).is_ok());
    encoded
        .as_object_mut()
        .expect("omission object")
        .remove("measured_cost");
    assert!(serde_json::from_value::<OmissionRecord>(encoded).is_err());
}

#[test]
fn tokenizer_observation_cannot_be_claimed_as_an_additive_byte_cost() {
    let mut input = input();
    input.measurements[0].observation = Some(AdmissionMeasuredCost::ExactTokenizer {
        observation: TokenizerObservation {
            tokenizer_id: "tokenizer".to_owned(),
            tokenizer_version: "1".to_owned(),
            tokenizer_hash: digest(),
            tokens: 2,
        },
    });
    input.validate().expect("observation is valid evidence");
    assert_eq!(
        input.validate_additive_measurements(),
        Err(ContextError::UnknownMeasurement)
    );
}

#[test]
fn decision_evidence_requires_one_disposition_per_candidate() {
    let candidate_input = input();
    let evidence = AdmissionDecisionEvidence {
        binding: candidate_input.binding.clone(),
        decisions: Vec::new(),
        omissions: Vec::new(),
        supplied_omissions: Vec::new(),
        incomplete: None,
        economy: None,
        proof_ceiling: ProofCeiling::Observation,
    };
    assert_eq!(
        evidence.validate_for(&candidate_input.candidates),
        Err(ContextError::DenominatorMismatch)
    );

    let mut partial_candidates = candidate_input.candidates.clone();
    partial_candidates.candidates.clear();
    partial_candidates
        .validate_for_admission()
        .expect("admission accepts a requested denominator with no candidates yet");
    let mut absent_dependency = candidate_input.candidates.clone();
    absent_dependency.candidates[0]
        .dependencies
        .push(id("missing"));
    absent_dependency
        .validate_for_admission()
        .expect("admission preserves an absent dependency for incomplete reporting");
    assert_eq!(
        absent_dependency.validate(),
        Err(ContextError::MissingField("candidate.dependencies"))
    );

    let mut empty_input = candidate_input.clone();
    empty_input.candidates.candidates.clear();
    empty_input.measurements.clear();
    empty_input.priority.priorities.clear();
    empty_input.supplied_omissions.clear();
    empty_input.floor.floor.members[0].availability = AtomAvailability::Missing;
    empty_input.floor.floor.members[0].measurement = None;
    empty_input
        .validate()
        .expect("empty admission input preserves an incomplete floor");

    let mut incomplete_input = input();
    incomplete_input.candidates.candidates[0].availability = AtomAvailability::Missing;
    incomplete_input.candidates.denominator.dispositions[0].state = AtomAvailability::Missing;
    incomplete_input.floor.floor.members[0].availability = AtomAvailability::Missing;
    incomplete_input.floor.floor.members[0].measurement = None;
    incomplete_input.floor.floor.providers.dispositions[0].state = AtomAvailability::Missing;
    incomplete_input.measurements[0].binding.subject_digest =
        canonical_digest(&incomplete_input.candidates.candidates[0])
            .expect("incomplete candidate subject digest");
    let incomplete = incomplete_input
        .floor
        .floor
        .incomplete()
        .expect("incomplete floor validates")
        .expect("missing floor is explicit");
    let decision = AdmissionRecord {
        atom_id: id("atom"),
        provider_role: incomplete_input.candidates.candidates[0]
            .provider_role
            .clone(),
        disposition: AdmissionDisposition::Blocked,
        rule_evidence: id("incomplete-rule"),
    };
    let evidence = AdmissionDecisionEvidence {
        binding: incomplete_input.binding.clone(),
        decisions: vec![decision],
        omissions: Vec::new(),
        supplied_omissions: Vec::new(),
        incomplete: Some(incomplete.clone()),
        economy: None,
        proof_ceiling: ProofCeiling::Observation,
    };
    let mut result = AdmissionResult {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: incomplete_input.binding.clone(),
        input_digest: incomplete_input.canonical_digest().expect("input digest"),
        recipe_digest: incomplete_input.recipe.recipe_sha256.clone(),
        profile_digest: incomplete_input
            .measurement_profile
            .canonical_digest()
            .expect("profile digest"),
        floor_id: incomplete_input.floor.floor_id.clone(),
        outcome: ContextOutcome::Incomplete(incomplete.clone()),
        evidence,
        selection_digest: canonical_digest(&incomplete).expect("incomplete digest"),
        result_digest: digest(),
    };
    let mut unsigned = result.clone();
    unsigned.result_digest = "0".repeat(64);
    result.result_digest = canonical_digest(&unsigned).expect("result digest");
    result
        .validate_for(&incomplete_input)
        .expect("incomplete result preserves floor gaps");
    result.evidence.decisions[0].disposition = AdmissionDisposition::Include;
    assert_eq!(
        result.validate_for(&incomplete_input),
        Err(ContextError::DenominatorMismatch)
    );
}
