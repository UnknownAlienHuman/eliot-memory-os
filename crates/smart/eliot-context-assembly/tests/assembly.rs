#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_assembly::{
    ActiveUnderstandingView, AdmittedContextSet, AssemblyError, AssemblyPolicy, QualityScorecard,
    SerializedContextMeasurement, assemble_active_view,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, DecisionId, ResourceGeneration, StateFence, TaskId, TaskRevision,
    sha256_hex,
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
    ContextBinding {
        task_id: TaskId::new("task").expect("fixture task"),
        attempt_id: AgentAttemptId::new("attempt").expect("fixture attempt"),
        scope_id: WorkScopeId::new("scope").expect("fixture scope"),
        state_fence: StateFence::new(
            AuthorityEpoch::new(1).expect("fixture epoch"),
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
        privacy: PrivacyClass::Restricted,
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
            receipt_digest: digest(),
        },
    };
    let payload_bytes = value
        .canonical_payload_utf8_bytes()
        .expect("admitted payload");
    value.economy.allocations.admitted_required = payload_bytes;
    value.economy.allocations.remaining_headroom = 100_000 - 9 - payload_bytes;
    value.economy.measurement.digest = value.canonical_payload_digest().expect("admitted digest");
    value
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
    let payload_bytes = value
        .canonical_payload_utf8_bytes()
        .expect("two-atom admitted payload");
    value.economy.allocations.admitted_required = payload_bytes;
    value.economy.allocations.remaining_headroom = 100_000 - 9 - payload_bytes;
    value.economy.measurement.digest = value
        .canonical_payload_digest()
        .expect("two-atom admitted digest");
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
    AssemblyPolicy {
        fence_digest: "b".repeat(64),
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
    second.economy.measurement.digest = second
        .canonical_payload_digest()
        .expect("reversed admitted digest");
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
            &"b".repeat(64),
            &left.view.rendered,
        )
        .expect("A15 digest")
    );
}

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
        &"b".repeat(64),
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
