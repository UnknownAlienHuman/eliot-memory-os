#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
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

fn optional_provider_role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("fixture-provider").expect("fixture provider"),
        role: SemanticRole::Optional,
    }
}

fn measurement_ref() -> MeasurementRef {
    MeasurementRef {
        digest: digest(),
        serializer: "fixture-serde-v1".to_owned(),
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
            content: "complete goal\n\twith source detail".to_owned(),
        },
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: true,
        // Executable admitted fixtures use the public-only route; the test
        // below changes this inert candidate to Secret and keeps it valid.
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: measurement_ref(),
        dependencies: Vec::new(),
        proof: ProofBinding {
            evidence_id: id("evidence"),
            ceiling: ProofCeiling::Observation,
        },
    }
}

fn denominator(state: AtomAvailability) -> ProviderRoleDenominator {
    ProviderRoleDenominator {
        requested: vec![provider_role()],
        dispositions: vec![ProviderDisposition {
            slot: provider_role(),
            state,
            evidence: None,
        }],
    }
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

fn quality(context: &ContextBinding) -> QualityScorecard {
    let dimensions = [
        QualityDimension::AcceptanceDecisionCoverage,
        QualityDimension::CausalOperationalSufficiency,
        QualityDimension::ExactAnchorProvenanceCoverage,
        QualityDimension::FreshnessStateFenceCoherence,
        QualityDimension::RivalsConflictsUnknownsVisibility,
        QualityDimension::NegativeMemoryInvariantCoverage,
        QualityDimension::VerifierActionReadiness,
        QualityDimension::RouteAccessibilityLayoutRisk,
        QualityDimension::InstructionSufficiency,
        QualityDimension::PayloadHandleReconstructionCost,
        QualityDimension::KnownOmissionsExpansionPaths,
        QualityDimension::TelemetryMeasurementCostCoverage,
    ];
    QualityScorecard {
        binding: context.clone(),
        results: dimensions
            .into_iter()
            .map(|dimension| QualityDimensionResult {
                dimension,
                passed: true,
                evidence: vec![id("quality-evidence")],
                measurements: Vec::new(),
                failed_invariant: None,
                unknown_evidence: Vec::new(),
                proof_ceiling: ProofCeiling::Observation,
                invalidation: None,
                binding: context.clone(),
            })
            .collect(),
    }
}

fn admitted_set(candidate: ContextCandidate) -> AdmittedContextSet {
    let context = candidate.binding.clone();
    let atom_id = candidate.atom_id.clone();
    let role = candidate.provider_role.role;
    let measurement = candidate.measurement.clone();
    let mut optional = candidate.clone();
    optional.atom_id = id("optional-atom");
    optional.provider_role = optional_provider_role();
    optional.source.snapshot_id = id("optional-snapshot");
    let provider_denominator = denominator(AtomAvailability::PresentCurrent);
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![atom_id.clone()],
        mandatory_roles: vec![role],
        providers: provider_denominator,
        members: vec![SafetyFloorMember {
            atom_id: atom_id.clone(),
            role,
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
        measurement: MeasurementRef {
            serializer: "serde-json".to_owned(),
            ..measurement
        },
        requested: vec![atom_id.clone(), optional.atom_id.clone()],
        admitted: vec![atom_id.clone(), optional.atom_id.clone()],
        displaced: Vec::new(),
        omissions: Vec::new(),
        applied_rule: id("economy-rule"),
        allocations: EconomyAllocations {
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
            admitted_required: 1,
            admitted_optional: 1,
            remaining_headroom: 99_989,
            route_capacity: 100_000,
        },
        recipe_digest: digest(),
        receipt_digest: digest(),
    };
    let mut admitted = AdmittedContextSet {
        binding: context,
        records: vec![
            AdmittedAtom {
                candidate,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmittedAtom {
                candidate: optional,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("optional-admission-rule"),
            },
        ],
        admissions: vec![
            AdmissionRecord {
                atom_id,
                provider_role: provider_role(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmissionRecord {
                atom_id: id("optional-atom"),
                provider_role: optional_provider_role(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("optional-admission-rule"),
            },
        ],
        floor,
        economy,
    };
    {
        let mut unsigned = admitted.economy.clone();
        unsigned.receipt_digest = "0".repeat(64);
        admitted.economy.receipt_digest =
            canonical_digest(&unsigned).expect("intermediate economy receipt");
    }
    let payload_bytes = admitted
        .canonical_payload_utf8_bytes()
        .expect("valid admitted payload");
    admitted.economy.allocations.admitted_required = payload_bytes;
    admitted.economy.allocations.admitted_optional = 0;
    admitted.economy.allocations.remaining_headroom = 100_000 - 2 - 3 - 4 - payload_bytes;
    {
        let mut unsigned = admitted.economy.clone();
        unsigned.receipt_digest = "0".repeat(64);
        admitted.economy.receipt_digest =
            canonical_digest(&unsigned).expect("pre-measurement economy receipt");
    }
    admitted.economy.measurement.digest = admitted
        .canonical_payload_digest()
        .expect("valid admitted payload digest");
    {
        let mut unsigned = admitted.economy.clone();
        unsigned.receipt_digest = "0".repeat(64);
        admitted.economy.receipt_digest =
            canonical_digest(&unsigned).expect("final economy receipt");
    }
    admitted
}

#[test]
fn loss_policy_wire_names_are_closed_over_all_four_variants() {
    #[derive(serde::Deserialize)]
    struct LossPolicyHolder {
        policy: LossPolicy,
    }
    let expected = [
        (LossPolicy::NonDroppable, "NON_DROPPABLE"),
        (LossPolicy::HandleOnly, "HANDLE_ONLY"),
        (LossPolicy::Extractive, "EXTRACTIVE"),
        (LossPolicy::Summarizable, "SUMMARIZABLE"),
    ];
    for (policy, wire) in expected {
        let encoded = serde_json::to_string(&policy).expect("wire encoding");
        assert_eq!(encoded, format!("\"{wire}\""));
        assert_eq!(
            serde_json::from_str::<LossPolicy>(&encoded).expect("wire round-trip"),
            policy
        );
    }
    assert!(serde_json::from_str::<LossPolicy>("\"OTHER\"").is_err());

    let holder: LossPolicyHolder =
        serde_json::from_str(r#"{"policy":"HANDLE_ONLY"}"#).expect("present field");
    assert_eq!(holder.policy, LossPolicy::HandleOnly);
    assert!(serde_json::from_str::<LossPolicyHolder>(r"{}").is_err());
}

#[test]
fn decision_context_incomplete_wire_code_is_exact() {
    let encoded =
        serde_json::to_string(&ContextErrorCode::DecisionContextIncomplete).expect("wire encoding");
    assert_eq!(encoded, "\"DECISION_CONTEXT_INCOMPLETE\"");
    assert_eq!(
        serde_json::from_str::<ContextErrorCode>(&encoded).expect("wire round-trip"),
        ContextErrorCode::DecisionContextIncomplete
    );
    assert!(serde_json::from_str::<ContextErrorCode>("\"OTHER\"").is_err());

    let mut incomplete = DecisionContextIncomplete::new(id("floor-rule"));
    incomplete.missing.push(id("atom"));
    incomplete
        .validate()
        .expect("explicit gap is incomplete, not failure");
    let mut wrong_code = incomplete.clone();
    wrong_code.code = ContextErrorCode::InvalidIdentity;
    assert_eq!(
        wrong_code.validate(),
        Err(ContextError::InvalidField("incomplete.code"))
    );
}

#[test]
fn quality_dimension_wire_spellings_are_closed_over_all_twelve() {
    let expected = [
        (
            QualityDimension::AcceptanceDecisionCoverage,
            "ACCEPTANCE_DECISION_COVERAGE",
        ),
        (
            QualityDimension::CausalOperationalSufficiency,
            "CAUSAL_OPERATIONAL_SUFFICIENCY",
        ),
        (
            QualityDimension::ExactAnchorProvenanceCoverage,
            "EXACT_ANCHOR_PROVENANCE_COVERAGE",
        ),
        (
            QualityDimension::FreshnessStateFenceCoherence,
            "FRESHNESS_STATE_FENCE_COHERENCE",
        ),
        (
            QualityDimension::RivalsConflictsUnknownsVisibility,
            "RIVALS_CONFLICTS_UNKNOWNS_VISIBILITY",
        ),
        (
            QualityDimension::NegativeMemoryInvariantCoverage,
            "NEGATIVE_MEMORY_INVARIANT_COVERAGE",
        ),
        (
            QualityDimension::VerifierActionReadiness,
            "VERIFIER_ACTION_READINESS",
        ),
        (
            QualityDimension::RouteAccessibilityLayoutRisk,
            "ROUTE_ACCESSIBILITY_LAYOUT_RISK",
        ),
        (
            QualityDimension::InstructionSufficiency,
            "INSTRUCTION_SUFFICIENCY",
        ),
        (
            QualityDimension::PayloadHandleReconstructionCost,
            "PAYLOAD_HANDLE_RECONSTRUCTION_COST",
        ),
        (
            QualityDimension::KnownOmissionsExpansionPaths,
            "KNOWN_OMISSIONS_EXPANSION_PATHS",
        ),
        (
            QualityDimension::TelemetryMeasurementCostCoverage,
            "TELEMETRY_MEASUREMENT_COST_COVERAGE",
        ),
    ];
    for (dimension, wire) in expected {
        let encoded = serde_json::to_string(&dimension).expect("wire encoding");
        assert_eq!(encoded, format!("\"{wire}\""));
        assert_eq!(
            serde_json::from_str::<QualityDimension>(&encoded).expect("wire round-trip"),
            dimension
        );
    }
    assert!(serde_json::from_str::<QualityDimension>("\"SCALAR_SCORE\"").is_err());
    assert!(serde_json::from_str::<QualityDimension>("\"OTHER\"").is_err());
}

#[test]
fn selection_integrity_proof_rejects_duplicates_and_membership_mismatch() {
    let proof = SelectionIntegrityProof {
        binding: binding(),
        admitted_ids: vec![id("atom-a")],
        rendered_ids: vec![id("atom-a")],
        omission_evidence: Vec::new(),
        output_digest: digest(),
    };
    proof.validate().expect("exact membership proves integrity");

    let mut duplicated_admitted = proof.clone();
    duplicated_admitted.admitted_ids.push(id("atom-a"));
    assert_eq!(
        duplicated_admitted.validate(),
        Err(ContextError::SelectionIntegrityMismatch)
    );

    let mut duplicated_rendered = proof.clone();
    duplicated_rendered.rendered_ids.push(id("atom-a"));
    assert_eq!(
        duplicated_rendered.validate(),
        Err(ContextError::SelectionIntegrityMismatch)
    );

    let mut mismatched = proof.clone();
    mismatched.rendered_ids = vec![id("atom-b")];
    assert_eq!(
        mismatched.validate(),
        Err(ContextError::SelectionIntegrityMismatch)
    );
}

#[test]
fn digests_reject_uppercase_and_short_forms() {
    measurement_ref()
        .validate()
        .expect("lowercase hex digest is valid");

    let mut uppercase = measurement_ref();
    uppercase.digest = "A".repeat(64);
    assert_eq!(
        uppercase.validate(),
        Err(ContextError::InvalidDigest("measurement.digest"))
    );

    let mut short = measurement_ref();
    short.digest = "abc123".to_owned();
    assert_eq!(
        short.validate(),
        Err(ContextError::InvalidDigest("measurement.digest"))
    );
}

#[test]
fn whole_unit_and_loss_policy_are_closed_and_coherent() {
    let mut candidate = candidate();
    candidate.validate().expect("whole non-droppable candidate");
    candidate.privacy = PrivacyClass::Secret;
    candidate
        .validate()
        .expect("inert candidate retains its privacy label");
    candidate.representation = AtomRepresentation::Summary {
        content: "lossy".to_owned(),
        source_digest: digest(),
    };
    assert_eq!(candidate.validate(), Err(ContextError::WholeUnitRequired));

    let encoded = serde_json::to_string(&LossPolicy::NonDroppable).expect("wire encoding");
    assert_eq!(encoded, "\"NON_DROPPABLE\"");
    assert!(serde_json::from_str::<LossPolicy>("\"OTHER\"").is_err());

    let retained_role =
        serde_json::to_string(&SemanticRole::Constraint).expect("role wire encoding");
    assert_eq!(retained_role, "\"CONSTRAINT\"");
    assert!(serde_json::from_str::<SemanticRole>("\"DECISION_TAIL\"").is_err());
    let role_schema =
        serde_json::to_string(&schemars::schema_for!(SemanticRole)).expect("role schema encoding");
    assert!(role_schema.contains("CONSTRAINT"));
    assert!(!role_schema.contains("DECISION_TAIL"));

    let incompatible_rule = RoleLossRule {
        role: SemanticRole::Goal,
        loss_policy: LossPolicy::NonDroppable,
        required: true,
        allowed_representations: vec![RepresentationKind::Whole, RepresentationKind::Summary],
    };
    assert_eq!(
        incompatible_rule.validate(),
        Err(ContextError::WholeUnitRequired)
    );
    let duplicate_rule = RoleLossRule {
        allowed_representations: vec![RepresentationKind::Whole, RepresentationKind::Whole],
        ..incompatible_rule
    };
    assert_eq!(
        duplicate_rule.validate(),
        Err(ContextError::WholeUnitRequired)
    );
}

#[test]
fn denominator_and_floor_preserve_incomplete_observability() {
    let context = binding();
    let mut missing = denominator(AtomAvailability::Missing);
    missing.dispositions.clear();
    assert_eq!(missing.validate(), Err(ContextError::DenominatorMismatch));

    let floor = DecisionSafetyFloor {
        binding: context,
        mandatory_atoms: vec![id("atom")],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: denominator(AtomAvailability::Missing),
        members: vec![SafetyFloorMember {
            atom_id: id("atom"),
            role: SemanticRole::Goal,
            availability: AtomAvailability::Missing,
            measurement: None,
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("rule"),
        capacity: CapacityLimits {
            route_capacity: 100,
            fixed_overhead: 1,
            output_reserve: 1,
            review_reserve: 1,
        },
    };
    let incomplete = floor
        .incomplete()
        .expect("valid incomplete floor")
        .expect("missing floor");
    assert_eq!(incomplete.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(incomplete.missing, vec![id("atom")]);
    assert_eq!(
        incomplete.provider_gaps,
        vec![ProviderRoleGap {
            slot: provider_role(),
            state: AtomAvailability::Missing,
        }]
    );
    incomplete
        .validate()
        .expect("incomplete result remains explicit");

    let mut oversized_missing = floor.clone();
    oversized_missing.capacity.route_capacity = 2;
    let oversized = oversized_missing
        .incomplete()
        .expect("oversized missing floor remains explicit")
        .expect("oversized missing floor cannot complete");
    assert_eq!(oversized.missing, vec![id("atom")]);
    assert_eq!(oversized.oversized, vec![id("atom")]);

    let mut unknown_floor = floor.clone();
    unknown_floor.providers.dispositions[0].state = AtomAvailability::Unknown;
    unknown_floor.members[0].availability = AtomAvailability::Unknown;
    let unknown = unknown_floor
        .incomplete()
        .expect("unknown floor remains representable")
        .expect("unknown instrumentation cannot become complete");
    assert_eq!(unknown.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(unknown.unknown, vec![id("atom")]);
    assert_eq!(
        unknown.provider_gaps,
        vec![ProviderRoleGap {
            slot: provider_role(),
            state: AtomAvailability::Unknown,
        }]
    );

    let mut known_empty_floor = unknown_floor;
    known_empty_floor.providers.dispositions[0].state = AtomAvailability::KnownEmpty;
    known_empty_floor.members[0].availability = AtomAvailability::KnownEmpty;
    let known_empty = known_empty_floor
        .incomplete()
        .expect("known-empty floor remains explicit")
        .expect("known-empty cannot become complete");
    assert_eq!(known_empty.known_empty, vec![id("atom")]);

    let mut invalid_dependency = floor;
    invalid_dependency.members[0].required_dependencies = vec![id("atom")];
    assert_eq!(
        invalid_dependency.validate(),
        Err(ContextError::Duplicate("floor.required_dependencies"))
    );
    invalid_dependency.members[0].required_dependencies = vec![id("other"), id("other")];
    assert_eq!(
        invalid_dependency.validate(),
        Err(ContextError::Duplicate("floor.required_dependencies"))
    );
}

#[test]
fn economy_requires_exact_requested_admitted_displaced_conservation() {
    let context = binding();
    let mut receipt = ContextEconomyReceipt {
        binding: context.clone(),
        decision_id: context.decision_id.clone(),
        measurement: measurement_ref(),
        requested: vec![id("atom"), id("displaced")],
        admitted: vec![id("atom")],
        displaced: vec![id("displaced")],
        omissions: Vec::new(),
        applied_rule: id("rule"),
        allocations: EconomyAllocations {
            fixed_overhead: 0,
            output_reserve: 0,
            review_reserve: 0,
            admitted_required: 1,
            admitted_optional: 0,
            remaining_headroom: 9,
            route_capacity: 10,
        },
        recipe_digest: digest(),
        receipt_digest: digest(),
    };
    receipt
        .validate()
        .expect_err("displaced material needs an omission record");
    receipt.displaced.clear();
    assert_eq!(receipt.validate(), Err(ContextError::EconomyMismatch));
}

#[test]
fn uncertain_measurement_cannot_prove_capacity_fit() {
    let context = binding();
    let mut measurement = exact_measurement(&context);
    assert!(measurement.proves_fit(30).expect("exact measurement"));
    assert_eq!(SerializedContextMeasurement::utf8_bytes("é"), 2);

    measurement.status = MeasurementStatus::Unknown;
    assert_eq!(
        measurement.proves_fit(30),
        Err(ContextError::UnknownMeasurement)
    );

    measurement.status = MeasurementStatus::ConservativeStu;
    measurement.stu_estimate = None;
    assert_eq!(
        measurement.validate(),
        Err(ContextError::UnknownMeasurement)
    );
}

#[test]
fn quality_scorecard_requires_each_independent_axis() {
    let context = binding();
    let mut scorecard = quality(&context);
    scorecard.validate().expect("all twelve dimensions");
    assert!(scorecard.all_pass().expect("all dimensions pass"));

    scorecard.results[0].unknown_evidence.push(id("unknown"));
    assert_eq!(scorecard.validate(), Err(ContextError::QualityIncomplete));
    scorecard.results[0].unknown_evidence.clear();
    scorecard.results.pop();
    assert_eq!(scorecard.validate(), Err(ContextError::QualityIncomplete));
}

fn assert_private_view_rejected(admitted: &AdmittedContextSet, view: &ActiveUnderstandingView) {
    let context = admitted.binding.clone();
    let mut private_admitted = admitted.clone();
    private_admitted.records[0].candidate.privacy = PrivacyClass::Secret;
    let mut private_view = view.clone();
    private_view.rendered[0].privacy = PrivacyClass::Secret;
    private_view.output_digest = ActiveUnderstandingView::canonical_output_digest(
        &context,
        &private_view.recipe_digest,
        &private_view.fence_digest,
        &private_view.rendered,
    )
    .expect("private rendered digest");
    private_view.selection.output_digest = private_view.output_digest.clone();
    private_view.measurement.envelope_digest = private_view.output_digest.clone();
    private_view.measurement.rendered_utf8_bytes =
        ActiveUnderstandingView::canonical_output_utf8_bytes(
            &context,
            &private_view.recipe_digest,
            &private_view.fence_digest,
            &private_view.rendered,
        )
        .expect("private rendered bytes");
    private_view
        .validate()
        .expect("coherent inert private view");
    assert_eq!(
        private_view.validate_against(&private_admitted),
        Err(ContextError::InvalidField("candidate.privacy"))
    );
}

#[test]
fn admitted_view_preserves_protected_fields_and_rejects_injected_content() {
    let admitted = admitted_set(candidate());
    admitted.validate().expect("admitted set");
    let context = admitted.binding.clone();
    let recipe_digest = digest();
    let fence_digest = "b".repeat(64);
    let rendered: Vec<_> = admitted
        .records
        .iter()
        .map(RenderedAtom::from_admitted)
        .collect();
    let output_digest = ActiveUnderstandingView::canonical_output_digest(
        &context,
        &recipe_digest,
        &fence_digest,
        &rendered,
    )
    .expect("canonical rendered payload digest");
    let rendered_bytes = ActiveUnderstandingView::canonical_output_utf8_bytes(
        &context,
        &recipe_digest,
        &fence_digest,
        &rendered,
    )
    .expect("canonical rendered payload bytes");
    let mut measurement = exact_measurement(&context);
    measurement.envelope_digest = output_digest.clone();
    measurement.rendered_utf8_bytes = rendered_bytes;
    let mut view = ActiveUnderstandingView::assemble(
        &admitted,
        quality(&context),
        measurement,
        output_digest.clone(),
        recipe_digest,
        fence_digest,
    )
    .expect("view projection");
    assert!(view.rendered[0].protected);
    assert_eq!(view.selection.output_digest, output_digest);
    view.validate_against(&admitted)
        .expect("exact admitted projection");
    assert_private_view_rejected(&admitted, &view);

    let mut qualified = exact_measurement(&context);
    qualified.status = MeasurementStatus::ExactTokenizer;
    qualified.tokenizer = Some(TokenizerObservation {
        tokenizer_id: "fixture-tokenizer".to_owned(),
        tokenizer_version: "1".to_owned(),
        tokenizer_hash: digest(),
        tokens: admitted
            .canonical_payload_utf8_bytes()
            .expect("admitted payload token fixture"),
    });
    qualified.envelope_digest = admitted
        .canonical_payload_digest()
        .expect("admitted payload digest");
    qualified.rendered_utf8_bytes = admitted
        .canonical_payload_utf8_bytes()
        .expect("admitted payload bytes");
    assert!(matches!(
        admitted
            .outcome(&qualified)
            .expect("qualified complete outcome"),
        ContextOutcome::Complete(_)
    ));

    let mut stale = admitted_set(candidate());
    stale.floor.members[0].availability = AtomAvailability::Stale;
    stale.floor.providers.dispositions[0].state = AtomAvailability::Stale;
    stale.records[0].candidate.availability = AtomAvailability::Stale;
    assert!(matches!(
        stale
            .outcome(&exact_measurement(&stale.binding))
            .expect("stale admitted set validates"),
        ContextOutcome::Incomplete(_)
    ));
    let mut mismatched = admitted_set(candidate());
    mismatched.floor.members[0].availability = AtomAvailability::Stale;
    mismatched.floor.providers.dispositions[0].state = AtomAvailability::Stale;
    assert_eq!(mismatched.validate(), Err(ContextError::IdentityConflict));

    let mut stale_status = candidate();
    stale_status.status = EpistemicStatus::Stale;
    assert_eq!(
        stale_status.validate(),
        Err(ContextError::InvalidField("candidate.availability"))
    );

    let mut injected = view.clone();
    let mut extra = injected.rendered[0].clone();
    extra.atom_id = id("injected");
    injected.rendered.push(extra);
    assert_eq!(
        injected.validate_against(&admitted),
        Err(ContextError::SelectionIntegrityMismatch)
    );

    view.rendered[0].source_revision = "r2".to_owned();
    assert_eq!(
        view.validate_against(&admitted),
        Err(ContextError::SelectionIntegrityMismatch)
    );
}

#[test]
fn blocked_and_unavailable_denominators_require_named_evidence() {
    denominator(AtomAvailability::PresentCurrent)
        .validate()
        .expect("present denominator needs no evidence");
    denominator(AtomAvailability::Missing)
        .validate()
        .expect("missing denominator needs no evidence");

    assert_eq!(
        denominator(AtomAvailability::Blocked).validate(),
        Err(ContextError::MissingField(
            "denominator.dispositions.evidence"
        ))
    );
    assert_eq!(
        denominator(AtomAvailability::Unavailable).validate(),
        Err(ContextError::MissingField(
            "denominator.dispositions.evidence"
        ))
    );

    for state in [AtomAvailability::Blocked, AtomAvailability::Unavailable] {
        let mut evidenced = denominator(state);
        evidenced.dispositions[0].evidence = Some(ProofBinding {
            evidence_id: id("named-reason"),
            ceiling: eliot_receipts::ProofCeiling::Observation,
        });
        evidenced
            .validate()
            .expect("named blocked/unavailable evidence validates");
    }
}
