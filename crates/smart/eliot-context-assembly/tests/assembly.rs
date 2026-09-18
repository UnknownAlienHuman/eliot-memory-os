#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_assembly::{
    ActiveUnderstandingView, AdmittedContextSet, AssemblyError, AssemblyPolicy, QualityScorecard,
    SerializedContextMeasurement, assemble_active_view,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    TaskRevision, sha256_hex,
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

fn role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("fixture-provider").expect("fixture provider"),
        role: SemanticRole::Goal,
    }
}

fn candidate(context: &ContextBinding) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id("atom"),
        provider_role: role(),
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new("source").expect("fixture source"),
            owner: ProviderId::new("fixture-provider").expect("fixture owner"),
            snapshot_id: id("snapshot"),
            revision: "revision-1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: "whole goal matériél".to_owned(),
        },
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: true,
        // The pure assembly fixture represents the current public-only route.
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

fn admitted() -> AdmittedContextSet {
    let context = binding();
    let candidate = candidate(&context);
    let atom_id = candidate.atom_id.clone();
    let provider = role();
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: ProviderRoleDenominator {
            requested: vec![provider.clone()],
            dispositions: vec![ProviderDisposition {
                slot: provider.clone(),
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
        members: vec![SafetyFloorMember {
            atom_id: atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(candidate.measurement.clone()),
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
    let mut value = AdmittedContextSet {
        binding: context.clone(),
        records: vec![AdmittedAtom {
            candidate,
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        admissions: vec![AdmissionRecord {
            atom_id: atom_id.clone(),
            provider_role: provider,
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        floor,
        economy: ContextEconomyReceipt {
            binding: context.clone(),
            decision_id: context.decision_id.clone(),
            measurement: MeasurementRef {
                digest: digest(),
                serializer: "fixture-serde-v1".to_owned(),
            },
            requested: vec![atom_id.clone()],
            admitted: vec![atom_id],
            displaced: Vec::new(),
            omissions: Vec::new(),
            applied_rule: id("economy-rule"),
            allocations: EconomyAllocations {
                fixed_overhead: 2,
                output_reserve: 3,
                review_reserve: 4,
                admitted_required: 1,
                admitted_optional: 0,
                remaining_headroom: 99_990,
                route_capacity: 100_000,
            },
            recipe_digest: recipe(&context).recipe_sha256.clone(),
            receipt_digest: digest(),
        },
    };
    refresh_economy_receipt(&mut value);
    let payload_bytes = value
        .canonical_payload_utf8_bytes()
        .expect("admitted payload");
    value.economy.allocations.admitted_required = payload_bytes;
    value.economy.allocations.remaining_headroom = 100_000 - 9 - payload_bytes;
    refresh_economy_receipt(&mut value);
    value.economy.measurement.digest = value.canonical_payload_digest().expect("admitted digest");
    refresh_economy_receipt(&mut value);
    value
}

fn refresh_economy_receipt(value: &mut AdmittedContextSet) {
    let mut unsigned = value.economy.clone();
    unsigned.receipt_digest = "0".repeat(64);
    value.economy.receipt_digest =
        eliot_context_contracts::canonical_digest(&unsigned).expect("economy receipt");
}

fn admitted_two() -> AdmittedContextSet {
    let mut value = admitted();
    let context = value.binding.clone();
    let mut second = candidate(&context);
    second.atom_id = id("atom-two");
    second.source.snapshot_id = id("snapshot-two");
    second.representation = AtomRepresentation::Whole {
        content: "second admitted atom".to_owned(),
    };
    value.records.push(AdmittedAtom {
        candidate: second,
        disposition: AdmissionDisposition::Include,
        rule_evidence: id("admission-rule-two"),
    });
    value.admissions.push(AdmissionRecord {
        atom_id: id("atom-two"),
        provider_role: role(),
        disposition: AdmissionDisposition::Include,
        rule_evidence: id("admission-rule-two"),
    });
    value.economy.requested.push(id("atom-two"));
    value.economy.admitted.push(id("atom-two"));
    refresh_economy_receipt(&mut value);
    let payload_bytes = value
        .canonical_payload_utf8_bytes()
        .expect("two-atom admitted payload");
    value.economy.allocations.admitted_required = payload_bytes;
    value.economy.allocations.remaining_headroom = 100_000 - 9 - payload_bytes;
    refresh_economy_receipt(&mut value);
    value.economy.measurement.digest = value
        .canonical_payload_digest()
        .expect("two-atom admitted digest");
    refresh_economy_receipt(&mut value);
    value
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

fn measurement(context: &ContextBinding, bytes: &[u8]) -> SerializedContextMeasurement {
    SerializedContextMeasurement {
        measurement_id: id("measurement"),
        context: context.clone(),
        schema_version: CONTEXT_CONTRACT_VERSION,
        envelope_digest: sha256_hex(bytes),
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        rendered_utf8_bytes: u64::try_from(bytes.len()).expect("fixture byte count"),
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

fn policy(max_serialized_bytes: u64) -> AssemblyPolicy {
    policy_for(&binding(), max_serialized_bytes)
}

fn policy_for(context: &ContextBinding, max_serialized_bytes: u64) -> AssemblyPolicy {
    AssemblyPolicy {
        fence_digest: eliot_context_contracts::canonical_fence_digest(&context.state_fence)
            .expect("fence digest"),
        max_serialized_bytes,
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        measurement_status: MeasurementStatus::ExactUtf8,
    }
}

fn recipe(context: &ContextBinding) -> ContextRecipe {
    let provider = role();
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: DecisionRevision {
            decision_id: context.decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("recipe revision"),
            policy_sha256: digest(),
        },
        recipe_sha256: digest(),
        denominator: ProviderRoleDenominator {
            requested: vec![provider.clone()],
            dispositions: vec![ProviderDisposition {
                slot: provider,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
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
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
    recipe
}

// WORK_UNIT_CASE: 626/1
#[test]
fn assembles_exact_admitted_projection_and_measures_once() {
    let value = admitted();
    let context = value.binding.clone();
    let mut calls = 0;
    let view = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| {
            calls += 1;
            Ok(measurement(&context, bytes))
        },
    )
    .expect("exact projection");
    assert_eq!(calls, 1);
    assert_eq!(view.view.rendered.len(), 1);
    assert_eq!(view.view.admitted_ids, vec![id("atom")]);
    assert_eq!(
        view.view.measurement.rendered_utf8_bytes,
        u64::try_from(view.serialized_bytes.len()).expect("serialized byte count")
    );
}

// WORK_UNIT_CASE: 626/8
#[test]
fn non_public_admitted_privacy_is_refused_before_measurement() {
    for privacy in [
        PrivacyClass::Scoped,
        PrivacyClass::Restricted,
        PrivacyClass::Secret,
    ] {
        let mut value = admitted();
        value.records[0].candidate.privacy = privacy;
        let context = value.binding.clone();
        let mut calls = 0;
        let result = assemble_active_view(
            &value,
            &recipe(&context),
            quality(&context),
            &policy(100_000),
            |_bytes| {
                calls += 1;
                panic!("privacy refusal must precede measurement");
            },
        );
        assert_eq!(calls, 0);
        assert_eq!(
            result,
            Err(AssemblyError::Contract(ContextError::InvalidField(
                "candidate.privacy"
            )))
        );
    }
}

// WORK_UNIT_CASE: 626/9
#[test]
fn canonical_payload_matches_a15_digest_and_order() {
    let first = admitted_two();
    let original_records = first.records.clone();
    let original_admissions = first.admissions.clone();
    let context = first.binding.clone();
    let left = assemble_active_view(
        &first,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("first projection");
    assert_eq!(first.records, original_records);
    assert_eq!(first.admissions, original_admissions);
    let mut second = admitted_two();
    second.records.reverse();
    second.admissions.reverse();
    // Reversing records does not change the canonical admitted payload digest
    // (ordering is normalized), but the economy receipt must be refreshed for
    // the reordered measurement binding to stay verifiable.
    second.economy.measurement.digest = second
        .canonical_payload_digest()
        .expect("reversed admitted digest");
    refresh_economy_receipt(&mut second);
    let right = assemble_active_view(
        &second,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("second projection");
    assert_eq!(left.view.rendered, right.view.rendered);
    assert_eq!(left.serialized_bytes, right.serialized_bytes);
    assert_eq!(left.view.output_digest, right.view.output_digest);
    assert_eq!(
        left.view.output_digest,
        ActiveUnderstandingView::canonical_output_digest(
            &context,
            &recipe(&context).recipe_sha256,
            &eliot_context_contracts::canonical_fence_digest(&context.state_fence)
                .expect("fence digest"),
            &left.view.rendered,
        )
        .expect("A15 digest")
    );
}

// WORK_UNIT_CASE: 626/24
#[test]
fn measurement_mismatch_is_typed_and_rejected() {
    let value = admitted();
    let context = value.binding.clone();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| {
            let mut measured = measurement(&context, bytes);
            measured.rendered_utf8_bytes += 1;
            Ok(measured)
        },
    );
    assert_eq!(
        result,
        Err(AssemblyError::MeasurementMismatch("rendered_utf8_bytes"))
    );
    let unsupported = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| {
            let mut measured = measurement(&context, bytes);
            measured.status = MeasurementStatus::ExactTokenizer;
            measured.tokenizer = Some(TokenizerObservation {
                tokenizer_id: "fixture-tokenizer".to_owned(),
                tokenizer_version: "1".to_owned(),
                tokenizer_hash: digest(),
                tokens: 1,
            });
            Ok(measured)
        },
    );
    assert_eq!(
        unsupported,
        Err(AssemblyError::Contract(ContextError::UnknownMeasurement))
    );
}

// WORK_UNIT_CASE: 626/21
#[test]
fn output_byte_limit_is_checked_before_measurement() {
    let value = admitted();
    let context = value.binding.clone();
    let rendered: Vec<_> = value
        .records
        .iter()
        .map(RenderedAtom::from_admitted)
        .collect();
    let bytes = ActiveUnderstandingView::canonical_output_utf8_bytes(
        &context,
        &digest(),
        &eliot_context_contracts::canonical_fence_digest(&context.state_fence)
            .expect("fence digest"),
        &rendered,
    )
    .expect("rendered payload");
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(bytes - 1),
        |_bytes| panic!("measurement must not run after byte-limit rejection"),
    );
    assert_eq!(result, Err(AssemblyError::Bounds("assembly.final_bytes")));
}

// WORK_UNIT_CASE: 626/39
#[test]
fn oversized_nested_material_is_rejected_before_rendering() {
    let mut value = admitted();
    if let AtomRepresentation::Whole { content } = &mut value.records[0].candidate.representation {
        content.push_str(&"x".repeat(1_048_576));
    }
    let context = value.binding.clone();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("measurement must not run after preflight rejection"),
    );
    assert_eq!(result, Err(AssemblyError::Bounds("representation.content")));
}

// WORK_UNIT_CASE: 626/28
#[test]
fn rendered_fields_and_quality_binding_are_retained() {
    let value = admitted();
    let context = value.binding.clone();
    let view = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("projection");
    let rendered = &view.view.rendered[0];
    let source = &value.records[0].candidate;
    assert_eq!(rendered.representation, source.representation);
    assert_eq!(rendered.source_identity, source.source.source_id);
    assert_eq!(rendered.proof, source.proof);
    assert!(view.view.quality.all_pass().expect("quality closure"));
    view.view
        .validate_against(&value)
        .expect("A15 conservation");

    let mut stale_admission = admitted();
    stale_admission.economy.measurement.digest = "c".repeat(64);
    let result = assemble_active_view(
        &stale_admission,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("stale admission digest must preflight before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::IdentityConflict))
    );

    let mut mismatched_recipe = recipe(&context);
    mismatched_recipe.mandatory_roles.push(SemanticRole::Source);
    mismatched_recipe.role_policies.push(RoleLossRule {
        role: SemanticRole::Source,
        loss_policy: LossPolicy::NonDroppable,
        required: true,
        allowed_representations: vec![RepresentationKind::Whole],
    });
    mismatched_recipe.recipe_sha256 = mismatched_recipe
        .canonical_policy_digest()
        .expect("mismatched recipe digest");
    let result = assemble_active_view(
        &value,
        &mismatched_recipe,
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("mandatory-role mismatch must preflight before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::DenominatorMismatch))
    );
}

// WORK_UNIT_CASE: 626/3
#[test]
fn fence_digest_binds_to_admitted_state_fence() {
    let value = admitted();
    let context = value.binding.clone();
    let expected =
        eliot_context_contracts::canonical_fence_digest(&context.state_fence).expect("fence");
    let view = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("real fence binds");
    assert_eq!(view.view.fence_digest, expected);
    view.view
        .validate_against(&value)
        .expect("fence-bound view");
}

// WORK_UNIT_CASE: 626/31
#[test]
fn forged_fence_digest_is_rejected_as_invalid_fence() {
    let value = admitted();
    let context = value.binding.clone();
    let expected =
        eliot_context_contracts::canonical_fence_digest(&context.state_fence).expect("fence");
    let mut forged = "b".repeat(64);
    if forged == expected {
        forged = "c".repeat(64);
    }
    let forged_policy = AssemblyPolicy {
        fence_digest: forged,
        max_serialized_bytes: 100_000,
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        measurement_status: MeasurementStatus::ExactUtf8,
    };
    let mut calls = 0;
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &forged_policy,
        |bytes| {
            calls += 1;
            Ok(measurement(&context, bytes))
        },
    );
    assert_eq!(calls, 0);
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidFence))
    );
}

// ---- 626 proof helpers (package-local, real contracts only) ----

fn provider_role_named(provider: &str, role: SemanticRole) -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(provider).expect("fixture provider"),
        role,
    }
}

fn candidate_named(
    context: &ContextBinding,
    atom: &str,
    snapshot: &str,
    provider: &str,
    role: SemanticRole,
    body: &str,
) -> ContextCandidate {
    let mut base = candidate(context);
    base.atom_id = id(atom);
    base.provider_role = provider_role_named(provider, role);
    base.source.source_id =
        eliot_contracts::SourceId::new(format!("source-{atom}")).expect("fixture source id");
    base.source.owner = ProviderId::new(provider).expect("fixture owner");
    base.source.snapshot_id = id(snapshot);
    base.source.revision = format!("revision-{atom}");
    base.representation = AtomRepresentation::Whole {
        content: body.to_owned(),
    };
    base
}

/// Reconcile economy allocations/receipts after record/admission changes.
/// Caller must have set `economy.requested/admitted/displaced/omissions`
/// and `economy.recipe_digest` consistently beforehand.
fn refinalize(value: &mut AdmittedContextSet, recipe_digest: &str) {
    recipe_digest.clone_into(&mut value.economy.recipe_digest);
    let capacity = value.floor.capacity;
    value.economy.allocations.admitted_required = 0;
    value.economy.allocations.admitted_optional = 0;
    value.economy.allocations.remaining_headroom =
        capacity.route_capacity - capacity.fixed_overhead - capacity.output_reserve - capacity.review_reserve;
    refresh_economy_receipt(value);
    let payload_bytes = value
        .canonical_payload_utf8_bytes()
        .expect("admitted payload");
    value.economy.allocations.admitted_required = payload_bytes;
    value.economy.allocations.remaining_headroom = capacity.route_capacity
        - capacity.fixed_overhead
        - capacity.output_reserve
        - capacity.review_reserve
        - payload_bytes;
    refresh_economy_receipt(value);
    value.economy.measurement.digest = value
        .canonical_payload_digest()
        .expect("admitted digest");
    refresh_economy_receipt(value);
}

#[allow(clippy::too_many_lines)]
fn admitted_multi_role() -> (AdmittedContextSet, ContextRecipe) {
    let context = binding();
    let first = candidate(&context);
    let first_id = first.atom_id.clone();
    let first_role = role();
    let second_role = provider_role_named("second-provider", SemanticRole::Source);
    let mut second = candidate(&context);
    second.atom_id = id("atom-source");
    second.provider_role = second_role.clone();
    second.source.source_id =
        eliot_contracts::SourceId::new("source-atom-source").expect("fixture source");
    second.source.owner = ProviderId::new("second-provider").expect("fixture owner");
    second.source.snapshot_id = id("snapshot-source");
    "revision-atom-source".clone_into(&mut second.source.revision);
    second.representation = AtomRepresentation::Whole {
        content: "second source material".to_owned(),
    };
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![first_id.clone(), id("atom-source")],
        mandatory_roles: vec![SemanticRole::Goal, SemanticRole::Source],
        providers: ProviderRoleDenominator {
            requested: vec![first_role.clone(), second_role.clone()],
            dispositions: vec![
                ProviderDisposition {
                    slot: first_role.clone(),
                    state: AtomAvailability::PresentCurrent,
                    evidence: None,
                },
                ProviderDisposition {
                    slot: second_role.clone(),
                    state: AtomAvailability::PresentCurrent,
                    evidence: None,
                },
            ],
        },
        members: vec![
            SafetyFloorMember {
                atom_id: first_id.clone(),
                role: SemanticRole::Goal,
                availability: AtomAvailability::PresentCurrent,
                measurement: Some(first.measurement.clone()),
                required_dependencies: Vec::new(),
            },
            SafetyFloorMember {
                atom_id: id("atom-source"),
                role: SemanticRole::Source,
                availability: AtomAvailability::PresentCurrent,
                measurement: Some(second.measurement.clone()),
                required_dependencies: Vec::new(),
            },
        ],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity: CapacityLimits {
            route_capacity: 100_000,
            fixed_overhead: 2,
            output_reserve: 3,
            review_reserve: 4,
        },
    };
    let mut value = AdmittedContextSet {
        binding: context.clone(),
        records: vec![
            AdmittedAtom {
                candidate: first,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmittedAtom {
                candidate: second,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule-source"),
            },
        ],
        admissions: vec![
            AdmissionRecord {
                atom_id: first_id.clone(),
                provider_role: first_role.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmissionRecord {
                atom_id: id("atom-source"),
                provider_role: second_role.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule-source"),
            },
        ],
        floor,
        economy: ContextEconomyReceipt {
            binding: context.clone(),
            decision_id: context.decision_id.clone(),
            measurement: MeasurementRef {
                digest: digest(),
                serializer: "fixture-serde-v1".to_owned(),
            },
            requested: vec![first_id, id("atom-source")],
            admitted: vec![id("atom"), id("atom-source")],
            displaced: Vec::new(),
            omissions: Vec::new(),
            applied_rule: id("economy-rule"),
            allocations: EconomyAllocations {
                fixed_overhead: 2,
                output_reserve: 3,
                review_reserve: 4,
                admitted_required: 0,
                admitted_optional: 0,
                remaining_headroom: 100_000 - 9,
                route_capacity: 100_000,
            },
            recipe_digest: digest(),
            receipt_digest: digest(),
        },
    };
    let mut recipe = recipe(&context);
    recipe.denominator = ProviderRoleDenominator {
        requested: vec![first_role, second_role],
        dispositions: vec![
            ProviderDisposition {
                slot: role(),
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            },
            ProviderDisposition {
                slot: provider_role_named("second-provider", SemanticRole::Source),
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            },
        ],
    };
    recipe.mandatory_roles = vec![SemanticRole::Goal, SemanticRole::Source];
    recipe.role_policies = vec![
        RoleLossRule {
            role: SemanticRole::Goal,
            loss_policy: LossPolicy::NonDroppable,
            required: true,
            allowed_representations: vec![RepresentationKind::Whole],
        },
        RoleLossRule {
            role: SemanticRole::Source,
            loss_policy: LossPolicy::NonDroppable,
            required: true,
            allowed_representations: vec![RepresentationKind::Whole],
        },
    ];
    recipe.recipe_sha256 = recipe
        .canonical_policy_digest()
        .expect("multi-role recipe digest");
    refinalize(&mut value, &recipe.recipe_sha256.clone());
    (value, recipe)
}

// WORK_UNIT_CASE: 626/2
#[test]
fn multi_role_provider_set_is_deterministic() {
    let (value, recipe) = admitted_multi_role();
    let context = value.binding.clone();
    let left = assemble_active_view(
        &value,
        &recipe,
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("multi-role projection");
    let right = assemble_active_view(
        &value,
        &recipe,
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("repeat projection");
    assert_eq!(left.view.rendered.len(), 2);
    assert_eq!(left.serialized_bytes, right.serialized_bytes);
    assert_eq!(left.view.output_digest, right.view.output_digest);
    assert_eq!(left.view.rendered, right.view.rendered);
    let roles: Vec<_> = left.view.rendered.iter().map(|atom| atom.role).collect();
    assert!(roles.contains(&SemanticRole::Goal));
    assert!(roles.contains(&SemanticRole::Source));
    assert!(left.view.rendered[0].role <= left.view.rendered[1].role);
    left.view
        .validate_against(&value)
        .expect("multi-role conservation");
}

// WORK_UNIT_CASE: 626/4
#[test]
fn denominator_mismatch_is_rejected() {
    let value = admitted();
    let context = value.binding.clone();
    let mut foreign = recipe(&context);
    let slot = provider_role_named("foreign-provider", SemanticRole::Goal);
    foreign.denominator = ProviderRoleDenominator {
        requested: vec![slot.clone()],
        dispositions: vec![ProviderDisposition {
            slot,
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        }],
    };
    foreign.recipe_sha256 = foreign
        .canonical_policy_digest()
        .expect("foreign recipe digest");
    let result = assemble_active_view(
        &value,
        &foreign,
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::DenominatorMismatch))
    );

    let mut broken = admitted();
    broken.economy.admitted.clear();
    refresh_economy_receipt(&mut broken);
    let broken_context = broken.binding.clone();
    let result = assemble_active_view(
        &broken,
        &recipe(&broken_context),
        quality(&broken_context),
        &policy(100_000),
        |bytes| Ok(measurement(&broken_context, bytes)),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::EconomyMismatch))
    );
}

// WORK_UNIT_CASE: 626/5
#[test]
fn duplicate_atom_identity_is_rejected() {
    let mut value = admitted();
    let duplicate = value.records[0].clone();
    value.records.push(duplicate);
    let context = value.binding.clone();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("duplicate must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::Duplicate(
            "admitted.atom_id"
        )))
    );
}

// WORK_UNIT_CASE: 626/6
#[test]
fn missing_admitted_material_yields_exact_incomplete() {
    let mut value = admitted();
    value.records[0].candidate.availability = AtomAvailability::Missing;
    value.floor.members[0].availability = AtomAvailability::Missing;
    value.floor.members[0].measurement = None;
    value.floor.providers.dispositions[0].state = AtomAvailability::Missing;
    let mut missing_recipe = recipe(&value.binding.clone());
    missing_recipe.denominator.dispositions[0].state = AtomAvailability::Missing;
    missing_recipe.recipe_sha256 = missing_recipe
        .canonical_policy_digest()
        .expect("missing recipe digest");
    refinalize(&mut value, &missing_recipe.recipe_sha256.clone());
    let context = value.binding.clone();
    let result = assemble_active_view(
        &value,
        &missing_recipe,
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("incomplete floor must precede measurement"),
    );
    match result {
        Err(AssemblyError::Incomplete(incomplete)) => {
            assert_eq!(
                incomplete.code,
                ContextErrorCode::DecisionContextIncomplete
            );
            assert_eq!(incomplete.missing, vec![id("atom")]);
        }
        other => panic!("expected exact incomplete, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 626/7
#[test]
fn nonadmitted_rendering_material_is_rejected() {
    let mut value = admitted();
    let context = value.binding.clone();
    let mut outsider = candidate(&context);
    outsider.atom_id = id("outsider");
    outsider.source.snapshot_id = id("snapshot-outsider");
    value.records.push(AdmittedAtom {
        candidate: outsider,
        disposition: AdmissionDisposition::Include,
        rule_evidence: id("admission-rule-outsider"),
    });
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("nonadmitted material must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::DenominatorMismatch))
    );
}

// WORK_UNIT_CASE: 626/10
#[test]
fn dropping_admitted_atom_to_fit_fails_selection_integrity() {
    let value = admitted_two();
    let context = value.binding.clone();
    let full = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("two-atom projection");
    assert_eq!(full.view.rendered.len(), 2);
    let tight = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(full.serialized_bytes.len() as u64 - 1),
        |_bytes| panic!("tight bound must fail before measurement"),
    );
    assert_eq!(tight, Err(AssemblyError::Bounds("assembly.final_bytes")));

    let proof = SelectionIntegrityProof {
        binding: context,
        admitted_ids: vec![id("atom"), id("atom-two")],
        rendered_ids: vec![id("atom")],
        omission_evidence: Vec::new(),
        output_digest: digest(),
    };
    assert_eq!(
        proof.validate(),
        Err(ContextError::SelectionIntegrityMismatch)
    );
}

// WORK_UNIT_CASE: 626/11
#[test]
fn adding_omitted_atom_fails() {
    let mut value = admitted();
    let context = value.binding.clone();
    let injected = candidate_named(
        &context,
        "injected",
        "snapshot-injected",
        "injected-provider",
        SemanticRole::Source,
        "injected similar material",
    );
    value.records.push(AdmittedAtom {
        candidate: injected,
        disposition: AdmissionDisposition::Include,
        rule_evidence: id("admission-rule-injected"),
    });
    value.admissions.push(AdmissionRecord {
        atom_id: id("injected"),
        provider_role: provider_role_named("injected-provider", SemanticRole::Source),
        disposition: AdmissionDisposition::Include,
        rule_evidence: id("admission-rule-injected"),
    });
    value.economy.requested.push(id("injected"));
    value.economy.admitted.push(id("injected"));
    let digest = recipe(&context).recipe_sha256.clone();
    refinalize(&mut value, &digest);
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("injected atom must fail membership"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::DenominatorMismatch))
    );
}

// WORK_UNIT_CASE: 626/12
#[test]
fn changed_role_required_protected_state_fails() {
    let mut value = admitted();
    value.records[0].candidate.provider_role.role = SemanticRole::Source;
    let context = value.binding.clone();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("changed role must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::IdentityConflict))
    );

    let value = admitted();
    let context = value.binding.clone();
    let mut widened = recipe(&context);
    widened.mandatory_roles.push(SemanticRole::Source);
    widened.role_policies.push(RoleLossRule {
        role: SemanticRole::Source,
        loss_policy: LossPolicy::NonDroppable,
        required: true,
        allowed_representations: vec![RepresentationKind::Whole],
    });
    widened.recipe_sha256 = widened
        .canonical_policy_digest()
        .expect("widened recipe digest");
    let result = assemble_active_view(
        &value,
        &widened,
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("widened mandatory roles must fail denominator"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::DenominatorMismatch))
    );
}

// WORK_UNIT_CASE: 626/13
#[test]
fn splitting_merging_whole_atoms_fails() {
    let mut value = admitted();
    value.records[0].candidate.representation = AtomRepresentation::Extractive {
        content: "whole goal matériél".to_owned(),
        manifest: vec!["field".to_owned()],
    };
    let context = value.binding.clone();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("split representation must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::WholeUnitRequired))
    );

    let mut merged = admitted();
    merged.records[0].candidate.representation = AtomRepresentation::Summary {
        content: "merged summary".to_owned(),
        source_digest: digest(),
    };
    let merged_context = merged.binding.clone();
    let result = assemble_active_view(
        &merged,
        &recipe(&merged_context),
        quality(&merged_context),
        &policy(100_000),
        |_bytes| panic!("merged summary must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::WholeUnitRequired))
    );
}

// WORK_UNIT_CASE: 626/14
#[test]
fn provider_store_never_invoked_projection_is_pure() {
    let value = admitted();
    let context = value.binding.clone();
    let before = value.clone();
    let mut calls = 0;
    let first = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| {
            calls += 1;
            Ok(measurement(&context, bytes))
        },
    )
    .expect("pure projection");
    assert_eq!(calls, 1);
    assert_eq!(value, before, "admitted inputs stay immutable");
    let mut replay_calls = 0;
    let second = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| {
            replay_calls += 1;
            Ok(measurement(&context, bytes))
        },
    )
    .expect("replay projection");
    assert_eq!(replay_calls, 1);
    assert_eq!(first.serialized_bytes, second.serialized_bytes);
    assert_eq!(first.view.output_digest, second.view.output_digest);
}

// WORK_UNIT_CASE: 626/15
#[test]
fn no_ranking_compression_summary_implementation() {
    let value = admitted_two();
    let context = value.binding.clone();
    let view = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("exact projection");
    for record in &value.records {
        let rendered = view
            .view
            .rendered
            .iter()
            .find(|atom| atom.atom_id == record.candidate.atom_id)
            .expect("every admitted atom rendered once");
        assert_eq!(
            rendered.representation, record.candidate.representation,
            "no compression or summary rewrite"
        );
        assert!(
            matches!(
                rendered.representation,
                AtomRepresentation::Whole { .. }
            ),
            "only whole units pass a NonDroppable route"
        );
    }

    let mut summarized = admitted();
    summarized.records[0].candidate.representation = AtomRepresentation::Summary {
        content: "lossy".to_owned(),
        source_digest: digest(),
    };
    let summarized_context = summarized.binding.clone();
    let result = assemble_active_view(
        &summarized,
        &recipe(&summarized_context),
        quality(&summarized_context),
        &policy(100_000),
        |_bytes| panic!("summary must not rank as a substitute"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::WholeUnitRequired))
    );
}

// WORK_UNIT_CASE: 626/16
#[test]
fn normative_layout_and_stable_tiebreak_enforced() {
    let first = admitted_two();
    let context = first.binding.clone();
    let left = assemble_active_view(
        &first,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("ordered projection");
    assert_eq!(left.view.rendered.len(), 2);
    assert!(
        left.view.rendered[0].atom_id < left.view.rendered[1].atom_id,
        "same role/provider tie-breaks on atom identity"
    );

    let mut reversed = admitted_two();
    reversed.records.reverse();
    reversed.admissions.reverse();
    reversed.economy.measurement.digest = reversed
        .canonical_payload_digest()
        .expect("reversed digest");
    refresh_economy_receipt(&mut reversed);
    let right = assemble_active_view(
        &reversed,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("reversed projection");
    assert_eq!(left.view.rendered, right.view.rendered);
    assert_eq!(left.serialized_bytes, right.serialized_bytes);

    let (multi, multi_recipe) = admitted_multi_role();
    let multi_context = multi.binding.clone();
    let ordered = assemble_active_view(
        &multi,
        &multi_recipe,
        quality(&multi_context),
        &policy(100_000),
        |bytes| Ok(measurement(&multi_context, bytes)),
    )
    .expect("multi-role layout");
    assert_eq!(ordered.view.rendered[0].role, SemanticRole::Goal);
    assert_eq!(ordered.view.rendered[1].role, SemanticRole::Source);
}

fn binding_with_revision() -> ContextBinding {
    let mut revised = binding();
    revised.state_fence.task_revision =
        Some(eliot_contracts::TaskRevision::new(1).expect("revision"));
    revised
}

fn decision_for(context: &ContextBinding) -> DecisionRevision {
    DecisionRevision {
        decision_id: context.decision_id.clone(),
        recipe_revision: eliot_contracts::TaskRevision::new(1).expect("revision"),
        policy_sha256: digest(),
    }
}

fn admitted_with_omission() -> (AdmittedContextSet, ContextRecipe) {
    let context = binding_with_revision();
    let candidate = candidate(&binding());
    let mut owned = candidate;
    owned.binding = context.clone();
    let atom_id = owned.atom_id.clone();
    let provider = role();
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: ProviderRoleDenominator {
            requested: vec![provider.clone()],
            dispositions: vec![ProviderDisposition {
                slot: provider.clone(),
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
        members: vec![SafetyFloorMember {
            atom_id: atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(owned.measurement.clone()),
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
    let omission = OmissionRecord {
        atom_id: id("displaced-atom"),
        source_id: id("displaced-source"),
        provider_role: provider,
        decision: decision_for(&context),
        task_revision: eliot_contracts::TaskRevision::new(1).expect("revision"),
        reason: OmissionReason::Capacity,
        competing_constraint: "route capacity".to_owned(),
        measured_cost: Some(4),
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
    let mut value = AdmittedContextSet {
        binding: context.clone(),
        records: vec![AdmittedAtom {
            candidate: owned,
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        admissions: vec![AdmissionRecord {
            atom_id: atom_id.clone(),
            provider_role: role(),
            disposition: AdmissionDisposition::Include,
            rule_evidence: id("admission-rule"),
        }],
        floor,
        economy: ContextEconomyReceipt {
            binding: context.clone(),
            decision_id: context.decision_id.clone(),
            measurement: MeasurementRef {
                digest: digest(),
                serializer: "fixture-serde-v1".to_owned(),
            },
            requested: vec![atom_id.clone(), id("displaced-atom")],
            admitted: vec![atom_id],
            displaced: vec![id("displaced-atom")],
            omissions: vec![omission],
            applied_rule: id("economy-rule"),
            allocations: EconomyAllocations {
                fixed_overhead: 2,
                output_reserve: 3,
                review_reserve: 4,
                admitted_required: 0,
                admitted_optional: 0,
                remaining_headroom: 100_000 - 9,
                route_capacity: 100_000,
            },
            recipe_digest: digest(),
            receipt_digest: digest(),
        },
    };
    let recipe = recipe(&context);
    refinalize(&mut value, &recipe.recipe_sha256.clone());
    (value, recipe)
}

// WORK_UNIT_CASE: 626/17
#[test]
fn omission_expansion_records_are_retained() {
    let (value, recipe) = admitted_with_omission();
    let context = value.binding.clone();
    let view = assemble_active_view(
        &value,
        &recipe,
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("omission-preserving projection");
    assert_eq!(view.view.rendered.len(), 1);
    assert_eq!(
        view.view.selection.omission_evidence,
        vec![id("displaced-atom")]
    );
    assert_eq!(value.economy.omissions.len(), 1);
    assert_eq!(
        value.economy.omissions[0].reason,
        OmissionReason::Capacity
    );
    view.view
        .validate_against(&value)
        .expect("omission evidence conserved");
}

// WORK_UNIT_CASE: 626/18
#[test]
fn missing_changed_crosstask_expansion_handle_fails() {
    let (mut value, omission_recipe) = admitted_with_omission();
    let context = value.binding.clone();
    let handle = ExpansionHandle {
        handle_id: id("handle-displaced"),
        atom_id: id("displaced-atom"),
        source_id: id("displaced-source"),
        source_revision: "revision-displaced".to_owned(),
        context: context.clone(),
        decision: decision_for(&context),
        policy: LossPolicy::NonDroppable,
        provider_role: role(),
        handle_digest: digest(),
        expires: None,
        invalidation: None,
    };
    value.economy.omissions[0].expansion = Some(handle);
    value.economy.omissions[0].non_recoverable_reason = None;
    refinalize(&mut value, &omission_recipe.recipe_sha256.clone());
    value
        .validate()
        .expect("bound expansion handle validates");

    let mut wrong_atom = value.clone();
    wrong_atom.economy.omissions[0]
        .expansion
        .as_mut()
        .expect("expansion")
        .atom_id = id("other-atom");
    refresh_economy_receipt(&mut wrong_atom);
    let wrong_context = wrong_atom.binding.clone();
    let result = assemble_active_view(
        &wrong_atom,
        &recipe(&wrong_context),
        quality(&wrong_context),
        &policy_for(&wrong_context, 100_000),
        |_bytes| panic!("changed handle must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::OmissionHandleInvalid))
    );

    let mut cross_task = value.clone();
    cross_task.economy.omissions[0]
        .expansion
        .as_mut()
        .expect("expansion")
        .context
        .decision_id = eliot_contracts::DecisionId::new("other-decision").expect("decision");
    refresh_economy_receipt(&mut cross_task);
    let cross_context = cross_task.binding.clone();
    let result = assemble_active_view(
        &cross_task,
        &recipe(&cross_context),
        quality(&cross_context),
        &policy_for(&cross_context, 100_000),
        |_bytes| panic!("cross-task handle must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::OmissionHandleInvalid))
    );
}

// WORK_UNIT_CASE: 626/19
#[test]
fn final_utf8_measurement_includes_non_ascii_bytes() {
    let value = admitted();
    let context = value.binding.clone();
    let material = match &value.records[0].candidate.representation {
        AtomRepresentation::Whole { content } => content.clone(),
        other => panic!("fixture must stay whole, got {other:?}"),
    };
    assert!(
        material.contains('é'),
        "fixture keeps non-ASCII proof content"
    );
    let view = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("utf-8 projection");
    assert_eq!(
        view.view.measurement.rendered_utf8_bytes,
        view.serialized_bytes.len() as u64
    );
    assert!(
        view.serialized_bytes.len() > material.chars().count(),
        "byte length exceeds scalar count for non-ASCII"
    );
    assert!(
        view.serialized_bytes
            .windows(2)
            .any(|pair| pair == [0xC3, 0xA9]),
        "serialized bytes carry UTF-8 for é"
    );
    assert_eq!(
        SerializedContextMeasurement::utf8_bytes("é"),
        2,
        "exact UTF-8 byte identity"
    );
}

// WORK_UNIT_CASE: 626/20
#[test]
fn estimate_and_exact_observation_identities_are_distinct() {
    let value = admitted();
    let context = value.binding.clone();
    let exact = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("exact projection");
    let exact_bytes = exact.view.measurement.rendered_utf8_bytes;
    assert!(exact.view.measurement.stu_estimate.is_none());
    assert!(exact.view.measurement.tokenizer.is_none());
    assert_eq!(exact.view.measurement.status, MeasurementStatus::ExactUtf8);

    let mut estimated = measurement(&context, &exact.serialized_bytes);
    estimated.status = MeasurementStatus::ConservativeStu;
    estimated.stu_estimate = Some(StuEstimate {
        value: exact_bytes + 500,
        empirical: false,
    });
    assert_ne!(
        estimated.stu_estimate.map(|estimate| estimate.value),
        Some(exact_bytes)
    );
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_| Ok(estimated.clone()),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::UnknownMeasurement))
    );
}

// WORK_UNIT_CASE: 626/22
#[test]
fn protected_output_review_headroom_not_consumed() {
    let value = admitted();
    let context = value.binding.clone();
    let exact = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("headroom projection");
    assert_eq!(exact.view.measurement.fixed_overhead, 2);
    assert_eq!(exact.view.measurement.output_reserve, 3);
    assert_eq!(exact.view.measurement.review_reserve, 4);
    assert!(
        exact
            .view
            .measurement
            .proves_fit(100_000)
            .expect("fit proves")
    );
    let fit_bytes = exact.serialized_bytes.len() as u64;
    let snug = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(fit_bytes),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("exact fit keeps reserves");
    assert_eq!(snug.view.measurement.fixed_overhead, 2);

    let mut consumed = measurement(&context, &exact.serialized_bytes);
    consumed.output_reserve = 30;
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_| Ok(consumed.clone()),
    );
    assert_eq!(
        result,
        Err(AssemblyError::MeasurementMismatch("capacity_reserves"))
    );
}

// WORK_UNIT_CASE: 626/23
#[test]
fn unknown_measurement_cannot_prove_fit() {
    let value = admitted();
    let context = value.binding.clone();
    for status in [MeasurementStatus::Unknown, MeasurementStatus::Unavailable] {
        let mut unknown = measurement(&context, b"probe");
        unknown.status = status;
        unknown.envelope_digest = digest();
        unknown.rendered_utf8_bytes = 5;
        let result = assemble_active_view(
            &value,
            &recipe(&context),
            quality(&context),
            &policy(100_000),
            |_| Ok(unknown.clone()),
        );
        assert_eq!(
            result,
            Err(AssemblyError::Contract(ContextError::UnknownMeasurement)),
            "status {status:?} never proves fit"
        );
    }

    let mut stu_without_estimate = measurement(&context, b"probe");
    stu_without_estimate.status = MeasurementStatus::ConservativeStu;
    stu_without_estimate.stu_estimate = None;
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_| Ok(stu_without_estimate.clone()),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::UnknownMeasurement))
    );
}

// WORK_UNIT_CASE: 626/25
#[test]
fn overflow_preserves_admitted_evidence() {
    let value = admitted();
    let context = value.binding.clone();
    let before = value.clone();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(10),
        |_bytes| panic!("overflow must precede measurement"),
    );
    assert_eq!(result, Err(AssemblyError::Bounds("assembly.final_bytes")));
    assert_eq!(value, before, "overflow keeps every admitted atom");
    assert_eq!(value.records.len(), 1);
    assert_eq!(value.economy.admitted, vec![id("atom")]);
}

// WORK_UNIT_CASE: 626/26
#[test]
fn measurement_port_called_exactly_once_on_final_bytes() {
    let (value, recipe) = admitted_multi_role();
    let context = value.binding.clone();
    let mut calls = 0;
    let mut seen: Vec<u8> = Vec::new();
    let view = assemble_active_view(
        &value,
        &recipe,
        quality(&context),
        &policy(100_000),
        |bytes| {
            calls += 1;
            seen = bytes.to_vec();
            Ok(measurement(&context, bytes))
        },
    )
    .expect("measured projection");
    assert_eq!(calls, 1);
    assert_eq!(seen, view.serialized_bytes);
    let expected = ActiveUnderstandingView::canonical_output_utf8_bytes(
        &context,
        &recipe.recipe_sha256,
        &eliot_context_contracts::canonical_fence_digest(&context.state_fence)
            .expect("fence digest"),
        &view.view.rendered,
    )
    .expect("canonical bytes");
    assert_eq!(expected, view.serialized_bytes.len() as u64);

    let mut refused_calls = 0;
    let forged = AssemblyPolicy {
        fence_digest: "b".repeat(64),
        ..policy(100_000)
    };
    let result: Result<_, AssemblyError> = assemble_active_view(
        &value,
        &recipe,
        quality(&context),
        &forged,
        |bytes| {
            refused_calls += 1;
            Ok(measurement(&context, bytes))
        },
    );
    assert!(result.is_err());
    assert_eq!(refused_calls, 0, "no local fallback call on refusal");
}

// WORK_UNIT_CASE: 626/27
#[test]
fn source_guard_rejects_local_fallback_estimators() {
    let value = admitted();
    let context = value.binding.clone();
    let material = match &value.records[0].candidate.representation {
        AtomRepresentation::Whole { content } => content.clone(),
        other => panic!("fixture must stay whole, got {other:?}"),
    };
    let char_count = material.chars().count() as u64;
    let byte_count = material.len() as u64;
    assert!(byte_count > char_count, "non-ASCII separates bytes from chars");
    let view = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("exact bytes");
    assert_ne!(char_count, view.view.measurement.rendered_utf8_bytes);

    let mut char_measured = measurement(&context, &view.serialized_bytes);
    char_measured.rendered_utf8_bytes = char_measured
        .rendered_utf8_bytes
        .saturating_sub(byte_count - char_count);
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_| Ok(char_measured.clone()),
    );
    assert_eq!(
        result,
        Err(AssemblyError::MeasurementMismatch("rendered_utf8_bytes"))
    );

    let mut tokenizer_fallback = measurement(&context, &view.serialized_bytes);
    tokenizer_fallback.status = MeasurementStatus::ExactTokenizer;
    tokenizer_fallback.tokenizer = None;
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |_| Ok(tokenizer_fallback.clone()),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::UnknownMeasurement))
    );
}

// WORK_UNIT_CASE: 626/29
#[test]
fn one_semantic_occurrence_per_admitted_atom() {
    let (value, recipe) = admitted_multi_role();
    let context = value.binding.clone();
    let view = assemble_active_view(
        &value,
        &recipe,
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("single-occurrence projection");
    assert_eq!(view.view.rendered.len(), 2);
    for atom in [id("atom"), id("atom-source")] {
        let occurrences = view
            .view
            .rendered
            .iter()
            .filter(|rendered| rendered.atom_id == atom)
            .count();
        assert_eq!(occurrences, 1, "exactly one semantic occurrence");
    }
    let mut rendered_sorted = view.view.rendered.clone();
    rendered_sorted.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    rendered_sorted.dedup_by(|left, right| left.atom_id == right.atom_id);
    assert_eq!(rendered_sorted.len(), 2);
}

// WORK_UNIT_CASE: 626/30
#[test]
fn duplicate_rendered_occurrence_is_rejected() {
    let context = binding();
    let proof = SelectionIntegrityProof {
        binding: context,
        admitted_ids: vec![id("atom")],
        rendered_ids: vec![id("atom"), id("atom")],
        omission_evidence: Vec::new(),
        output_digest: digest(),
    };
    assert_eq!(
        proof.validate(),
        Err(ContextError::SelectionIntegrityMismatch)
    );

    let mut duplicated = admitted();
    duplicated.records.push(duplicated.records[0].clone());
    let duplicated_context = duplicated.binding.clone();
    let result = assemble_active_view(
        &duplicated,
        &recipe(&duplicated_context),
        quality(&duplicated_context),
        &policy(100_000),
        |_bytes| panic!("duplicate rendered must fail before measurement"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::Duplicate(
            "admitted.atom_id"
        )))
    );
}

// WORK_UNIT_CASE: 626/32
#[test]
fn missing_omission_coverage_evidence_is_rejected() {
    let (mut value, omission_recipe) = admitted_with_omission();
    value.economy.omissions.clear();
    refresh_economy_receipt(&mut value);
    let context = value.binding.clone();
    let result = assemble_active_view(
        &value,
        &omission_recipe,
        quality(&context),
        &policy_for(&context, 100_000),
        |_bytes| panic!("missing omission record must fail"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::EconomyMismatch))
    );

    let value = admitted();
    let context = value.binding.clone();
    let mut thin_quality = quality(&context);
    thin_quality.results.pop();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        thin_quality,
        &policy(100_000),
        |_bytes| panic!("missing quality axis must fail"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_))
    ));
}

// WORK_UNIT_CASE: 626/33
#[test]
fn exact_twelve_quality_dimensions_and_wire_names() {
    let context = binding();
    let scorecard = quality(&context);
    assert_eq!(scorecard.results.len(), 12);
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
    let mut seen = std::collections::BTreeSet::new();
    for (dimension, wire) in expected {
        assert!(seen.insert(dimension), "each dimension appears once");
        let bytes = eliot_contracts::canonical_json_bytes(&dimension).expect("wire bytes");
        let text = String::from_utf8(bytes).expect("wire utf-8");
        assert_eq!(text, format!("\"{wire}\""));
    }
    scorecard.validate().expect("twelve-axis closure");
    let value = admitted();
    let context = value.binding.clone();
    assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("twelve-axis projection");
}

// WORK_UNIT_CASE: 626/34
#[test]
fn each_quality_dimension_fails_independently() {
    let value = admitted();
    let context = value.binding.clone();
    let base = quality(&context);
    assert_eq!(base.results.len(), 12);
    for index in 0..12 {
        let mut failed = base.clone();
        failed.results[index].passed = false;
        failed.results[index].failed_invariant = Some(id("failed-invariant"));
        failed.results[index].unknown_evidence.clear();
        for (other, result) in failed.results.iter().enumerate() {
            if other != index {
                assert!(result.passed, "other eleven stay unchanged");
            }
        }
        let result = assemble_active_view(
            &value,
            &recipe(&context),
            failed,
            &policy(100_000),
            |_bytes| panic!("failed dimension must block before measurement"),
        );
        match result {
            Err(AssemblyError::QualityIncomplete(scorecard)) => {
                assert_eq!(scorecard.results.len(), 12);
                assert!(!scorecard.results[index].passed);
            }
            other => panic!("dimension {index} must block complete, got {other:?}"),
        }
    }
}

// WORK_UNIT_CASE: 626/35
#[test]
fn unknown_mandatory_quality_blocks_complete() {
    let value = admitted();
    let context = value.binding.clone();
    let mut unknown = quality(&context);
    unknown.results[0].passed = false;
    unknown.results[0].failed_invariant = None;
    unknown.results[0].unknown_evidence = vec![id("unknown-evidence")];
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        unknown,
        &policy(100_000),
        |_bytes| panic!("unknown evidence must block before measurement"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_))
    ));

    let mut qualified_unknown = quality(&context);
    qualified_unknown.results[1].unknown_evidence = vec![id("unknown-evidence")];
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        qualified_unknown,
        &policy(100_000),
        |_bytes| panic!("passed with unknown evidence must block"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_))
    ));
}

// WORK_UNIT_CASE: 626/36
#[test]
fn no_scalar_weighted_average_compensation() {
    let value = admitted();
    let context = value.binding.clone();
    let mut compensated = quality(&context);
    for result in compensated.results.iter_mut().skip(1) {
        result.evidence.push(id("extra-evidence"));
    }
    compensated.results[0].passed = false;
    compensated.results[0].failed_invariant = Some(id("failed-invariant"));
    compensated.results[0].unknown_evidence.clear();
    assert!(
        !compensated.all_pass().unwrap_or(false),
        "one failure blocks closure despite extra evidence elsewhere"
    );
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        compensated,
        &policy(100_000),
        |_bytes| panic!("compensation must not complete"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_))
    ));
}

// WORK_UNIT_CASE: 626/37
#[test]
fn complete_partial_upstream_material_measurement_stay_distinct() {
    let complete_value = admitted();
    let complete_context = complete_value.binding.clone();
    let complete = assemble_active_view(
        &complete_value,
        &recipe(&complete_context),
        quality(&complete_context),
        &policy(100_000),
        |bytes| Ok(measurement(&complete_context, bytes)),
    );
    assert!(complete.is_ok(), "complete stays complete");

    let mut missing_value = admitted();
    missing_value.records[0].candidate.availability = AtomAvailability::Missing;
    missing_value.floor.members[0].availability = AtomAvailability::Missing;
    missing_value.floor.members[0].measurement = None;
    missing_value.floor.providers.dispositions[0].state = AtomAvailability::Missing;
    let mut missing_recipe = recipe(&missing_value.binding.clone());
    missing_recipe.denominator.dispositions[0].state = AtomAvailability::Missing;
    missing_recipe.recipe_sha256 = missing_recipe
        .canonical_policy_digest()
        .expect("missing recipe digest");
    refinalize(&mut missing_value, &missing_recipe.recipe_sha256.clone());
    let missing_context = missing_value.binding.clone();
    let upstream = assemble_active_view(
        &missing_value,
        &missing_recipe,
        quality(&missing_context),
        &policy(100_000),
        |_| panic!("upstream gap precedes measurement"),
    );
    assert!(matches!(upstream, Err(AssemblyError::Incomplete(_))));

    let mut failed_quality = quality(&complete_context);
    failed_quality.results[0].passed = false;
    failed_quality.results[0].failed_invariant = Some(id("failed-invariant"));
    failed_quality.results[0].unknown_evidence.clear();
    let material = assemble_active_view(
        &complete_value,
        &recipe(&complete_context),
        failed_quality,
        &policy(100_000),
        |_| panic!("quality gap precedes measurement"),
    );
    assert!(matches!(
        material,
        Err(AssemblyError::QualityIncomplete(_))
    ));

    let tight = assemble_active_view(
        &complete_value,
        &recipe(&complete_context),
        quality(&complete_context),
        &policy(10),
        |_| panic!("byte ceiling precedes measurement"),
    );
    assert!(matches!(tight, Err(AssemblyError::Bounds(_))));

    let mut bad_bytes = measurement(&complete_context, b"probe");
    bad_bytes.envelope_digest = digest();
    bad_bytes.rendered_utf8_bytes = 7;
    let measured = assemble_active_view(
        &complete_value,
        &recipe(&complete_context),
        quality(&complete_context),
        &policy(100_000),
        |_| Ok(bad_bytes.clone()),
    );
    assert!(measured.is_err());
    assert_ne!(upstream, material);
    assert_ne!(material, tight);
    assert_ne!(tight, measured);
}

// WORK_UNIT_CASE: 626/38
#[test]
fn unknown_fields_variants_protected_defaults_are_rejected() {
    let value = admitted();
    let context = value.binding.clone();
    let mut bad_schema = recipe(&context);
    bad_schema.schema_version = eliot_contracts::ContractVersion::new(9, 9, 9);
    let result = assemble_active_view(
        &value,
        &bad_schema,
        quality(&context),
        &policy(100_000),
        |_bytes| panic!("unknown schema must fail"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidField(
            "recipe.schema_version"
        )))
    );

    let mut bad_digest = policy(100_000);
    bad_digest.serializer_options_digest = "NOT-HEX".to_owned();
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &bad_digest,
        |_bytes| panic!("unknown digest shape must fail"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidDigest(
            "assembly.serializer_options_digest"
        )))
    );

    let mut unknown_policy = policy(100_000);
    unknown_policy.measurement_status = MeasurementStatus::Unknown;
    let result = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &unknown_policy,
        |_bytes| panic!("unknown measurement status must fail"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::UnknownMeasurement))
    );
}

// WORK_UNIT_CASE: 626/40
#[test]
fn successful_views_are_one_to_one_and_within_measured_bounds() {
    let fixtures: Vec<(AdmittedContextSet, ContextRecipe)> = vec![
        {
            let value = admitted();
            let context = value.binding.clone();
            let recipe = recipe(&context);
            (value, recipe)
        },
        {
            let value = admitted_two();
            let context = value.binding.clone();
            let recipe = recipe(&context);
            (value, recipe)
        },
        admitted_multi_role(),
    ];
    for (value, recipe) in &fixtures {
        let context = value.binding.clone();
        let max = 100_000;
        let view = assemble_active_view(
            value,
            recipe,
            quality(&context),
            &policy(max),
            |bytes| Ok(measurement(&context, bytes)),
        )
        .expect("bounded one-to-one view");
        let mut admitted_sorted = view.view.admitted_ids.clone();
        admitted_sorted.sort();
        let mut rendered_sorted = view
            .view
            .rendered
            .iter()
            .map(|atom| atom.atom_id.clone())
            .collect::<Vec<_>>();
        rendered_sorted.sort();
        assert_eq!(admitted_sorted, rendered_sorted);
        assert_eq!(view.view.rendered.len(), view.view.admitted_ids.len());
        assert_eq!(
            view.view.measurement.rendered_utf8_bytes,
            view.serialized_bytes.len() as u64
        );
        assert!(view.serialized_bytes.len() as u64 <= max);
        assert!(view.view.measurement.proves_fit(100_000).expect("fit"));
        view.view
            .validate_against(value)
            .expect("one-to-one conservation");
    }
}

// WORK_UNIT_CASE: 626/41
#[test]
fn no_admission_delivery_authority_effect_finish_path() {
    let value = admitted();
    let context = value.binding.clone();
    let view = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("projection-only view");
    assert_eq!(view.view.binding, value.binding);
    assert_eq!(view.view.selection.binding, value.binding);
    assert_eq!(view.view.quality.binding, value.binding);
    assert_eq!(view.view.measurement.context, value.binding);
    assert_eq!(view.view.recipe_digest, recipe(&context).recipe_sha256);
    let replay = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("idempotent replay");
    assert_eq!(view.view, replay.view, "no effect or Finish transition");
    assert_eq!(
        view.view.quality.results.len(),
        12,
        "projection carries quality, not delivery or use"
    );
}
