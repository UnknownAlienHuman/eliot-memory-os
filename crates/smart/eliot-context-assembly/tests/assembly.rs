#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/approved_recipe.rs"]
mod approved_recipe;

use approved_recipe::{approved_for, seal};

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
        // This fixture asserts about assembly membership and boundary
        // preservation, not about a measured position inside the snapshot, so
        // the range stays a typed unknown.
        source_range: None,
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new("source").expect("fixture source"),
            owner: ProviderId::new("fixture-provider").expect("fixture owner"),
            snapshot_id: id("snapshot"),
            revision: "revision-1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        learning: None,
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
    let instance = recipe(&context);
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
            // Both digests come from the ONE sealed instance, so the
            // receipt and the instance a caller assembles with are the
            // same record rather than two that merely look similar.
            recipe_digest: instance.recipe_sha256.clone(),
            policy_sha256: instance.decision.policy_sha256.clone(),
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

fn resolved_applicability() -> QualityApplicability {
    QualityApplicability {
        resolved: QUALITY_APPLICABILITY_INPUTS.to_vec(),
        unknown: Vec::new(),
    }
}

/// Intrinsically well-formed output binding for a card that is only checked for
/// structural integrity, or for a packet assembly refuses before the grade is
/// read. [`quality_for`] is the card a real packet accepts.
///
/// The serializer and route identities here are the ones
/// [`policy_for`] applies, because a card that names a different serializer or
/// route than the bytes were produced under is not the grade of those bytes and
/// `require_graded_output` refuses it. The digests stay placeholder values:
/// those are the fields [`quality_for`] replaces with this packet's own.
fn fixture_output_binding() -> QualityOutputBinding {
    QualityOutputBinding {
        recipe_digest: digest(),
        fence_digest: digest(),
        admitted_digest: digest(),
        rendered_digest: digest(),
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        evidence_revisions: Vec::new(),
        omission_handles: Vec::new(),
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
        schema_version: QUALITY_SCORECARD_SCHEMA_VERSION,
        binding: context.clone(),
        output: fixture_output_binding(),
        applicability: resolved_applicability(),
        results: dimensions
            .into_iter()
            .map(|dimension| QualityDimensionResult {
                schema_version: QUALITY_RESULT_SCHEMA_VERSION,
                dimension,
                state: QualityDimensionState::Passed,
                rule_revision: id("rule-revision"),
                required_evidence: vec![id("quality-evidence")],
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

/// The card a real packet accepts: it records the exact output it graded, so
/// the recipe revision, the fence, the admitted set's own canonical payload
/// digest, the ordered rendered payload digest, the serializer/route identity
/// the bytes are produced under and the source revisions they are read from are
/// this packet's values. A card that omits or forges any of them is refused by
/// `require_graded_output` rather than accepted on the strength of its twelve
/// passing dimensions.
fn quality_for(admitted: &AdmittedContextSet, recipe: &ContextRecipe) -> QualityScorecard {
    let mut card = quality(&admitted.binding);
    let fence_digest =
        eliot_context_contracts::canonical_fence_digest(&admitted.binding.state_fence)
            .expect("fixture fence digest");
    let rendered = rendered_for(admitted);
    card.output.recipe_digest = recipe.recipe_sha256.clone();
    card.output.fence_digest = fence_digest.clone();
    // A test that deliberately corrupts the admitted set reaches this
    // before the owner refuses it, so the digest is taken from the set's
    // OWN recorded measurement rather than re-derived: re-deriving would
    // validate the very record under test and turn the expected refusal
    // into a fixture panic. The owner still compares this field against
    // its own derivation, so a corrupted set is refused by the owner,
    // which is exactly what those tests assert.
    card.output.admitted_digest = if let Ok(digest) = admitted.canonical_payload_digest() {
        digest
    } else {
        admitted.economy.measurement.digest.clone()
    };
    card.output.rendered_digest = ActiveUnderstandingView::canonical_output_digest(
        &admitted.binding,
        &recipe.recipe_sha256,
        &fence_digest,
        &rendered,
    )
    .expect("fixture rendered digest");
    card.output.omission_handles = admitted.economy.displaced.clone();
    // The source revisions this packet was actually read from, deduplicated in
    // canonical order exactly as the owner derives them from the admitted
    // records. These are real observations, so the binding is satisfied by the
    // packet and not by a self-referential list.
    card.output.evidence_revisions = admitted
        .records
        .iter()
        .map(|record| record.candidate.source.snapshot_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    card
}

/// The A-18 role/provider/atom ordering the assembly owner renders in.
fn rendered_for(admitted: &AdmittedContextSet) -> Vec<RenderedAtom> {
    let mut rendered: Vec<RenderedAtom> = admitted
        .records
        .iter()
        .map(RenderedAtom::from_admitted)
        .collect();
    rendered.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then_with(|| left.provider.cmp(&right.provider))
            .then_with(|| left.atom_id.cmp(&right.atom_id))
    });
    rendered
}

/// The bare `quality()` card, completed against the sealed instance.
///
/// A card graded for a real packet names the exact output it graded, so a test
/// that edits one dimension of an otherwise valid card still has to name the
/// instance assembly will use. It is graded from the PRISTINE admitted set:
/// `quality_for` on the set under test would grade the corruption these cases
/// are about.
fn quality_for_binding(context: &ContextBinding, recipe: &ContextRecipe) -> QualityScorecard {
    let mut card = quality_for(&admitted(), recipe);
    // Every result carries the scorecard's own binding and the owner refuses a
    // card whose results name a different one, so moving the card's binding has
    // to move each result's with it.
    card.binding = context.clone();
    for result in &mut card.results {
        result.binding = context.clone();
    }
    card
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
    // The approved revision this instance names is part of the instance,
    // not something a call site adds: the economy receipt already records
    // `recipe(&context).decision.policy_sha256`, so sealing here is what
    // keeps the admitted set and the approved revision one record.
    seal(recipe)
}

// WORK_UNIT_CASE: 626/1
#[test]
fn assembles_exact_admitted_projection_and_measures_once() {
    let value = admitted();
    let context = value.binding.clone();
    let mut calls = 0;
    let recipe1 = recipe(&context);
    let recipe1_approved = approved_for(&recipe1);
    let view = assemble_active_view(
        &value,
        &recipe1,
        &recipe1_approved,
        quality_for(&value, &recipe1),
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
        let recipe2 = recipe(&context);
        let recipe2_approved = approved_for(&recipe2);
        let result = assemble_active_view(
            &value,
            &recipe2,
            &recipe2_approved,
            quality_for(&value, &recipe2),
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
    let recipe3 = recipe(&context);
    let recipe3_approved = approved_for(&recipe3);
    let left = assemble_active_view(
        &first,
        &recipe3,
        &recipe3_approved,
        quality_for(&first, &recipe3),
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
    let recipe4 = recipe(&context);
    let recipe4_approved = approved_for(&recipe4);
    let right = assemble_active_view(
        &second,
        &recipe4,
        &recipe4_approved,
        quality_for(&second, &recipe4),
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
    let recipe5 = recipe(&context);
    let recipe5_approved = approved_for(&recipe5);
    let result = assemble_active_view(
        &value,
        &recipe5,
        &recipe5_approved,
        quality_for(&value, &recipe5),
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
    let recipe6 = recipe(&context);
    let recipe6_approved = approved_for(&recipe6);
    let unsupported = assemble_active_view(
        &value,
        &recipe6,
        &recipe6_approved,
        quality_for(&value, &recipe6),
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
    let recipe7 = recipe(&context);
    let recipe7_approved = approved_for(&recipe7);
    let result = assemble_active_view(
        &value,
        &recipe7,
        &recipe7_approved,
        quality_for(&value, &recipe7),
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
    let recipe8 = recipe(&context);
    let recipe8_approved = approved_for(&recipe8);
    let result = assemble_active_view(
        &value,
        &recipe8,
        &recipe8_approved,
        quality_for(&value, &recipe8),
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
    let recipe9 = recipe(&context);
    let recipe9_approved = approved_for(&recipe9);
    let view = assemble_active_view(
        &value,
        &recipe9,
        &recipe9_approved,
        quality_for(&value, &recipe9),
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
    let recipe10 = recipe(&context);
    let recipe10_approved = approved_for(&recipe10);
    let result = assemble_active_view(
        &stale_admission,
        &recipe10,
        &recipe10_approved,
        quality_for(&stale_admission, &recipe10),
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
    // Customized after `recipe()` sealed it, so it names a
    // different approved revision: re-seal it, and let the
    // admitted set's receipt name THIS instance so the owner
    // reaches this test's own case instead of refusing the pair.
    let mismatched_recipe = seal(mismatched_recipe);
    // This re-sealed instance is the RECIPE SUBJECT, so the admitted
    // set's receipt has to name it; otherwise the owner refuses the
    // pair before reaching the case under test.
    let mut value = value;
    refinalize(&mut value, &mismatched_recipe);
    let recipe11 = mismatched_recipe.clone();
    let recipe11_approved = approved_for(&recipe11);
    let result = assemble_active_view(
        &value,
        &recipe11,
        &recipe11_approved,
        quality_for(&value, &mismatched_recipe),
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
    let recipe12 = recipe(&context);
    let recipe12_approved = approved_for(&recipe12);
    let view = assemble_active_view(
        &value,
        &recipe12,
        &recipe12_approved,
        quality_for(&value, &recipe12),
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
    let recipe13 = recipe(&context);
    let recipe13_approved = approved_for(&recipe13);
    let result = assemble_active_view(
        &value,
        &recipe13,
        &recipe13_approved,
        quality_for(&value, &recipe13),
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
fn refinalize(value: &mut AdmittedContextSet, recipe: &ContextRecipe) {
    // Both digests come from the ONE instance the caller assembles
    // with, so the receipt never describes a different recipe than
    // the approved revision that sealed this one.
    recipe
        .recipe_sha256
        .clone_into(&mut value.economy.recipe_digest);
    recipe
        .decision
        .policy_sha256
        .clone_into(&mut value.economy.policy_sha256);
    let capacity = value.floor.capacity;
    value.economy.allocations.admitted_required = 0;
    value.economy.allocations.admitted_optional = 0;
    value.economy.allocations.remaining_headroom = capacity.route_capacity
        - capacity.fixed_overhead
        - capacity.output_reserve
        - capacity.review_reserve;
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
    value.economy.measurement.digest = value.canonical_payload_digest().expect("admitted digest");
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
            policy_sha256: digest(),
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
    // Customized after `recipe()` sealed it, so it names a
    // different approved revision: re-seal it, and let the
    // admitted set's receipt name THIS instance so the owner
    // reaches this test's own case instead of refusing the pair.
    let recipe = seal(recipe);
    // This instance was customized above, so it names a different
    // approved revision than the one `recipe()` sealed: re-seal it
    // before the receipt names it.
    let recipe = seal(recipe);
    refinalize(&mut value, &recipe);
    (value, recipe)
}

// WORK_UNIT_CASE: 626/2
#[test]
fn multi_role_provider_set_is_deterministic() {
    let (value, recipe) = admitted_multi_role();
    let context = value.binding.clone();
    let recipe14 = recipe.clone();
    let recipe14_approved = approved_for(&recipe14);
    let left = assemble_active_view(
        &value,
        &recipe14,
        &recipe14_approved,
        quality_for(&value, &recipe),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("multi-role projection");
    let recipe15 = recipe.clone();
    let recipe15_approved = approved_for(&recipe15);
    let right = assemble_active_view(
        &value,
        &recipe15,
        &recipe15_approved,
        quality_for(&value, &recipe),
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
    // Customized after `recipe()` sealed it, so it names a
    // different approved revision: re-seal it, and let the
    // admitted set's receipt name THIS instance so the owner
    // reaches this test's own case instead of refusing the pair.
    let foreign = seal(foreign);
    // This re-sealed instance is the RECIPE SUBJECT, so the admitted
    // set's receipt has to name it; otherwise the owner refuses the
    // pair before reaching the case under test.
    let mut value = value;
    refinalize(&mut value, &foreign);
    let recipe16 = foreign.clone();
    let recipe16_approved = approved_for(&recipe16);
    let result = assemble_active_view(
        &value,
        &recipe16,
        &recipe16_approved,
        quality_for(&value, &foreign),
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
    let recipe17 = recipe(&broken_context);
    let recipe17_approved = approved_for(&recipe17);
    let result = assemble_active_view(
        &broken,
        &recipe17,
        &recipe17_approved,
        quality_for(&broken, &recipe17),
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
    let recipe18 = recipe(&context);
    let recipe18_approved = approved_for(&recipe18);
    let result = assemble_active_view(
        &value,
        &recipe18,
        &recipe18_approved,
        quality_for(&value, &recipe18),
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
    // Customized after `recipe()` sealed it, so it names a
    // different approved revision: re-seal it, and let the
    // admitted set's receipt name THIS instance so the owner
    // reaches this test's own case instead of refusing the pair.
    let missing_recipe = seal(missing_recipe);
    // The re-sealed instance is the recipe subject here too.
    refinalize(&mut value, &missing_recipe);
    refinalize(&mut value, &missing_recipe);
    let context = value.binding.clone();
    let recipe19 = missing_recipe.clone();
    let recipe19_approved = approved_for(&recipe19);
    let result = assemble_active_view(
        &value,
        &recipe19,
        &recipe19_approved,
        quality_for(&value, &missing_recipe),
        &policy(100_000),
        |_bytes| panic!("incomplete floor must precede measurement"),
    );
    match result {
        Err(AssemblyError::Incomplete(incomplete)) => {
            assert_eq!(incomplete.code, ContextErrorCode::DecisionContextIncomplete);
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
    let recipe20 = recipe(&context);
    let recipe20_approved = approved_for(&recipe20);
    let result = assemble_active_view(
        &value,
        &recipe20,
        &recipe20_approved,
        quality_for(&value, &recipe20),
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
    let recipe21 = recipe(&context);
    let recipe21_approved = approved_for(&recipe21);
    let full = assemble_active_view(
        &value,
        &recipe21,
        &recipe21_approved,
        quality_for(&value, &recipe21),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("two-atom projection");
    assert_eq!(full.view.rendered.len(), 2);
    let recipe22 = recipe(&context);
    let recipe22_approved = approved_for(&recipe22);
    let tight = assemble_active_view(
        &value,
        &recipe22,
        &recipe22_approved,
        quality_for(&value, &recipe22),
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
    // The receipt names the SAME sealed instance the assembly below
    // uses, so a second, independently built recipe cannot describe a
    // different one.
    let recipe23 = recipe(&context);
    refinalize(&mut value, &recipe23);
    let recipe23_approved = approved_for(&recipe23);
    let result = assemble_active_view(
        &value,
        &recipe23,
        &recipe23_approved,
        quality_for(&value, &recipe23),
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
    let recipe24 = recipe(&context);
    let recipe24_approved = approved_for(&recipe24);
    let result = assemble_active_view(
        &value,
        &recipe24,
        &recipe24_approved,
        quality_for(&value, &recipe24),
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
    // Customized after `recipe()` sealed it, so it names a
    // different approved revision: re-seal it, and let the
    // admitted set's receipt name THIS instance so the owner
    // reaches this test's own case instead of refusing the pair.
    let widened = seal(widened);
    // This re-sealed instance is the RECIPE SUBJECT, so the admitted
    // set's receipt has to name it; otherwise the owner refuses the
    // pair before reaching the widened-denominator case under test.
    let mut value = value;
    refinalize(&mut value, &widened);
    let recipe25 = widened.clone();
    let recipe25_approved = approved_for(&recipe25);
    let result = assemble_active_view(
        &value,
        &recipe25,
        &recipe25_approved,
        quality_for(&value, &widened),
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
    let recipe26 = recipe(&context);
    let recipe26_approved = approved_for(&recipe26);
    let result = assemble_active_view(
        &value,
        &recipe26,
        &recipe26_approved,
        quality_for(&value, &recipe26),
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
    let recipe27 = recipe(&merged_context);
    let recipe27_approved = approved_for(&recipe27);
    let result = assemble_active_view(
        &merged,
        &recipe27,
        &recipe27_approved,
        quality_for(&merged, &recipe27),
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
    let recipe28 = recipe(&context);
    let recipe28_approved = approved_for(&recipe28);
    let first = assemble_active_view(
        &value,
        &recipe28,
        &recipe28_approved,
        quality_for(&value, &recipe28),
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
    let recipe29 = recipe(&context);
    let recipe29_approved = approved_for(&recipe29);
    let second = assemble_active_view(
        &value,
        &recipe29,
        &recipe29_approved,
        quality_for(&value, &recipe29),
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
    let recipe30 = recipe(&context);
    let recipe30_approved = approved_for(&recipe30);
    let view = assemble_active_view(
        &value,
        &recipe30,
        &recipe30_approved,
        quality_for(&value, &recipe30),
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
            matches!(rendered.representation, AtomRepresentation::Whole { .. }),
            "only whole units pass a NonDroppable route"
        );
    }

    let mut summarized = admitted();
    summarized.records[0].candidate.representation = AtomRepresentation::Summary {
        content: "lossy".to_owned(),
        source_digest: digest(),
    };
    let summarized_context = summarized.binding.clone();
    let recipe31 = recipe(&summarized_context);
    let recipe31_approved = approved_for(&recipe31);
    let result = assemble_active_view(
        &summarized,
        &recipe31,
        &recipe31_approved,
        quality_for(&summarized, &recipe31),
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
    let recipe32 = recipe(&context);
    let recipe32_approved = approved_for(&recipe32);
    let left = assemble_active_view(
        &first,
        &recipe32,
        &recipe32_approved,
        quality_for(&first, &recipe32),
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
    let recipe33 = recipe(&context);
    let recipe33_approved = approved_for(&recipe33);
    let right = assemble_active_view(
        &reversed,
        &recipe33,
        &recipe33_approved,
        quality_for(&reversed, &recipe33),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("reversed projection");
    assert_eq!(left.view.rendered, right.view.rendered);
    assert_eq!(left.serialized_bytes, right.serialized_bytes);

    let (multi, multi_recipe) = admitted_multi_role();
    let multi_context = multi.binding.clone();
    let recipe34 = multi_recipe.clone();
    let recipe34_approved = approved_for(&recipe34);
    let ordered = assemble_active_view(
        &multi,
        &recipe34,
        &recipe34_approved,
        quality_for(&multi, &multi_recipe),
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
            policy_sha256: digest(),
            receipt_digest: digest(),
        },
    };
    let recipe = recipe(&context);
    refinalize(&mut value, &recipe);
    (value, recipe)
}

// WORK_UNIT_CASE: 626/17
#[test]
fn omission_expansion_records_are_retained() {
    let (value, recipe) = admitted_with_omission();
    let context = value.binding.clone();
    let recipe35 = recipe.clone();
    let recipe35_approved = approved_for(&recipe35);
    let view = assemble_active_view(
        &value,
        &recipe35,
        &recipe35_approved,
        quality_for(&value, &recipe),
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
    assert_eq!(value.economy.omissions[0].reason, OmissionReason::Capacity);
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
    refinalize(&mut value, &omission_recipe);
    value.validate().expect("bound expansion handle validates");

    let mut wrong_atom = value.clone();
    wrong_atom.economy.omissions[0]
        .expansion
        .as_mut()
        .expect("expansion")
        .atom_id = id("other-atom");
    refresh_economy_receipt(&mut wrong_atom);
    let wrong_context = wrong_atom.binding.clone();
    let recipe36 = recipe(&wrong_context);
    let recipe36_approved = approved_for(&recipe36);
    let result = assemble_active_view(
        &wrong_atom,
        &recipe36,
        &recipe36_approved,
        quality_for(&wrong_atom, &recipe36),
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
    let recipe37 = recipe(&cross_context);
    let recipe37_approved = approved_for(&recipe37);
    let result = assemble_active_view(
        &cross_task,
        &recipe37,
        &recipe37_approved,
        quality_for(&cross_task, &recipe37),
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
    let recipe38 = recipe(&context);
    let recipe38_approved = approved_for(&recipe38);
    let view = assemble_active_view(
        &value,
        &recipe38,
        &recipe38_approved,
        quality_for(&value, &recipe38),
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
    let recipe39 = recipe(&context);
    let recipe39_approved = approved_for(&recipe39);
    let exact = assemble_active_view(
        &value,
        &recipe39,
        &recipe39_approved,
        quality_for(&value, &recipe39),
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
    let recipe40 = recipe(&context);
    let recipe40_approved = approved_for(&recipe40);
    let result = assemble_active_view(
        &value,
        &recipe40,
        &recipe40_approved,
        quality_for(&value, &recipe40),
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
    let recipe41 = recipe(&context);
    let recipe41_approved = approved_for(&recipe41);
    let exact = assemble_active_view(
        &value,
        &recipe41,
        &recipe41_approved,
        quality_for(&value, &recipe41),
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
    let recipe42 = recipe(&context);
    let recipe42_approved = approved_for(&recipe42);
    let snug = assemble_active_view(
        &value,
        &recipe42,
        &recipe42_approved,
        quality_for(&value, &recipe42),
        &policy(fit_bytes),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("exact fit keeps reserves");
    assert_eq!(snug.view.measurement.fixed_overhead, 2);

    let mut consumed = measurement(&context, &exact.serialized_bytes);
    consumed.output_reserve = 30;
    let recipe43 = recipe(&context);
    let recipe43_approved = approved_for(&recipe43);
    let result = assemble_active_view(
        &value,
        &recipe43,
        &recipe43_approved,
        quality_for(&value, &recipe43),
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
        let recipe44 = recipe(&context);
        let recipe44_approved = approved_for(&recipe44);
        let result = assemble_active_view(
            &value,
            &recipe44,
            &recipe44_approved,
            quality_for(&value, &recipe44),
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
    let recipe45 = recipe(&context);
    let recipe45_approved = approved_for(&recipe45);
    let result = assemble_active_view(
        &value,
        &recipe45,
        &recipe45_approved,
        quality_for(&value, &recipe45),
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
    let recipe46 = recipe(&context);
    let recipe46_approved = approved_for(&recipe46);
    let result = assemble_active_view(
        &value,
        &recipe46,
        &recipe46_approved,
        quality_for(&value, &recipe46),
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
    let recipe47 = recipe.clone();
    let recipe47_approved = approved_for(&recipe47);
    let view = assemble_active_view(
        &value,
        &recipe47,
        &recipe47_approved,
        quality_for(&value, &recipe),
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
    let recipe48 = recipe.clone();
    let recipe48_approved = approved_for(&recipe48);
    let result: Result<_, AssemblyError> = assemble_active_view(
        &value,
        &recipe48,
        &recipe48_approved,
        quality_for(&value, &recipe),
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
    assert!(
        byte_count > char_count,
        "non-ASCII separates bytes from chars"
    );
    let recipe49 = recipe(&context);
    let recipe49_approved = approved_for(&recipe49);
    let view = assemble_active_view(
        &value,
        &recipe49,
        &recipe49_approved,
        quality_for(&value, &recipe49),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("exact bytes");
    assert_ne!(char_count, view.view.measurement.rendered_utf8_bytes);

    let mut char_measured = measurement(&context, &view.serialized_bytes);
    char_measured.rendered_utf8_bytes = char_measured
        .rendered_utf8_bytes
        .saturating_sub(byte_count - char_count);
    let recipe50 = recipe(&context);
    let recipe50_approved = approved_for(&recipe50);
    let result = assemble_active_view(
        &value,
        &recipe50,
        &recipe50_approved,
        quality_for(&value, &recipe50),
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
    let recipe51 = recipe(&context);
    let recipe51_approved = approved_for(&recipe51);
    let result = assemble_active_view(
        &value,
        &recipe51,
        &recipe51_approved,
        quality_for(&value, &recipe51),
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
    let recipe52 = recipe.clone();
    let recipe52_approved = approved_for(&recipe52);
    let view = assemble_active_view(
        &value,
        &recipe52,
        &recipe52_approved,
        quality_for(&value, &recipe),
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
    let recipe53 = recipe(&duplicated_context);
    let recipe53_approved = approved_for(&recipe53);
    let result = assemble_active_view(
        &duplicated,
        &recipe53,
        &recipe53_approved,
        quality_for(&duplicated, &recipe53),
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
    let recipe54 = omission_recipe.clone();
    let recipe54_approved = approved_for(&recipe54);
    let result = assemble_active_view(
        &value,
        &recipe54,
        &recipe54_approved,
        quality_for_binding(&context, &recipe54),
        &policy_for(&context, 100_000),
        |_bytes| panic!("missing omission record must fail"),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::EconomyMismatch))
    );

    let value = admitted();
    let context = value.binding.clone();
    let recipe55 = recipe(&context);
    let mut thin_quality = quality_for_binding(&context, &recipe55);
    // One declared axis graded `Unknown` rather than an observed pass, with
    // the exact missing element it could not establish. The card stays
    // structurally valid — every declared axis is present — so the refusal is
    // the owner's blocking one rather than a malformed-card rejection.
    thin_quality.results[0].state = QualityDimensionState::Unknown;
    thin_quality.results[0].unknown_evidence = vec![id("missing-axis-evidence")];
    let recipe55_approved = approved_for(&recipe55);
    let result = assemble_active_view(
        &value,
        &recipe55,
        &recipe55_approved,
        thin_quality,
        &policy(100_000),
        |_bytes| panic!("missing quality axis must fail"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_, _))
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
    let recipe56 = recipe(&context);
    let recipe56_approved = approved_for(&recipe56);
    assemble_active_view(
        &value,
        &recipe56,
        &recipe56_approved,
        quality_for(&value, &recipe56),
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
        failed.results[index].state = QualityDimensionState::Failed;
        failed.results[index].failed_invariant = Some(id("failed-invariant"));
        failed.results[index].unknown_evidence.clear();
        for (other, result) in failed.results.iter().enumerate() {
            if other != index {
                assert!(result.state.is_pass(), "other eleven stay unchanged");
            }
        }
        let recipe57 = recipe(&context);
        let recipe57_approved = approved_for(&recipe57);
        let result = assemble_active_view(
            &value,
            &recipe57,
            &recipe57_approved,
            failed,
            &policy(100_000),
            |_bytes| panic!("failed dimension must block before measurement"),
        );
        match result {
            Err(AssemblyError::QualityIncomplete(scorecard, _)) => {
                assert_eq!(scorecard.results.len(), 12);
                assert!(!scorecard.results[index].state.is_pass());
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
    let recipe58 = recipe(&context);
    let mut unknown = quality_for_binding(&context, &recipe58);
    unknown.results[0].state = QualityDimensionState::Failed;
    unknown.results[0].failed_invariant = None;
    unknown.results[0].unknown_evidence = vec![id("unknown-evidence")];
    let recipe58_approved = approved_for(&recipe58);
    let result = assemble_active_view(
        &value,
        &recipe58,
        &recipe58_approved,
        unknown,
        &policy(100_000),
        |_bytes| panic!("unknown evidence must block before measurement"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_, _))
    ));

    let recipe59 = recipe(&context);
    let mut qualified_unknown = quality_for_binding(&context, &recipe59);
    // A dimension that carries unknown evidence is graded `Unknown`, not
    // `Passed`: the owner refuses a pass that still names what it could
    // not establish, so leaving the state at `Passed` would assert the
    // opposite of what the evidence says.
    qualified_unknown.results[1].state = QualityDimensionState::Unknown;
    qualified_unknown.results[1].unknown_evidence = vec![id("unknown-evidence")];
    let recipe59_approved = approved_for(&recipe59);
    let result = assemble_active_view(
        &value,
        &recipe59,
        &recipe59_approved,
        qualified_unknown,
        &policy(100_000),
        |_bytes| panic!("passed with unknown evidence must block"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_, _))
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
    compensated.results[0].state = QualityDimensionState::Failed;
    compensated.results[0].failed_invariant = Some(id("failed-invariant"));
    compensated.results[0].unknown_evidence.clear();
    assert!(
        !compensated.all_pass().unwrap_or(false),
        "one failure blocks closure despite extra evidence elsewhere"
    );
    let recipe60 = recipe(&context);
    let recipe60_approved = approved_for(&recipe60);
    let result = assemble_active_view(
        &value,
        &recipe60,
        &recipe60_approved,
        compensated,
        &policy(100_000),
        |_bytes| panic!("compensation must not complete"),
    );
    assert!(matches!(
        result,
        Err(AssemblyError::QualityIncomplete(_, _))
    ));
}

// WORK_UNIT_CASE: 626/37
#[test]
fn complete_partial_upstream_material_measurement_stay_distinct() {
    let complete_value = admitted();
    let complete_context = complete_value.binding.clone();
    let recipe61 = recipe(&complete_context);
    let recipe61_approved = approved_for(&recipe61);
    let complete = assemble_active_view(
        &complete_value,
        &recipe61,
        &recipe61_approved,
        quality_for(&complete_value, &recipe61),
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
    // Customized after `recipe()` sealed it, so it names a
    // different approved revision: re-seal it, and let the
    // admitted set's receipt name THIS instance so the owner
    // reaches this test's own case instead of refusing the pair.
    let missing_recipe = seal(missing_recipe);
    refinalize(&mut missing_value, &missing_recipe);
    let missing_context = missing_value.binding.clone();
    let recipe62 = missing_recipe.clone();
    let recipe62_approved = approved_for(&recipe62);
    let upstream = assemble_active_view(
        &missing_value,
        &recipe62,
        &recipe62_approved,
        quality_for(&missing_value, &missing_recipe),
        &policy(100_000),
        |_| panic!("upstream gap precedes measurement"),
    );
    assert!(matches!(upstream, Err(AssemblyError::Incomplete(_))));

    let mut failed_quality = quality(&complete_context);
    failed_quality.results[0].state = QualityDimensionState::Failed;
    failed_quality.results[0].failed_invariant = Some(id("failed-invariant"));
    failed_quality.results[0].unknown_evidence.clear();
    let recipe63 = recipe(&complete_context);
    let recipe63_approved = approved_for(&recipe63);
    let material = assemble_active_view(
        &complete_value,
        &recipe63,
        &recipe63_approved,
        failed_quality,
        &policy(100_000),
        |_| panic!("quality gap precedes measurement"),
    );
    assert!(matches!(
        material,
        Err(AssemblyError::QualityIncomplete(_, _))
    ));

    let recipe64 = recipe(&complete_context);
    let recipe64_approved = approved_for(&recipe64);
    let tight = assemble_active_view(
        &complete_value,
        &recipe64,
        &recipe64_approved,
        quality_for(&complete_value, &recipe64),
        &policy(10),
        |_| panic!("byte ceiling precedes measurement"),
    );
    assert!(matches!(tight, Err(AssemblyError::Bounds(_))));

    let mut bad_bytes = measurement(&complete_context, b"probe");
    bad_bytes.envelope_digest = digest();
    bad_bytes.rendered_utf8_bytes = 7;
    let recipe65 = recipe(&complete_context);
    let recipe65_approved = approved_for(&recipe65);
    let measured = assemble_active_view(
        &complete_value,
        &recipe65,
        &recipe65_approved,
        quality_for(&complete_value, &recipe65),
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
    let recipe66 = bad_schema.clone();
    let recipe66_approved = approved_for(&recipe66);
    let result = assemble_active_view(
        &value,
        &recipe66,
        &recipe66_approved,
        quality_for(&value, &bad_schema),
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
    let recipe67 = recipe(&context);
    let recipe67_approved = approved_for(&recipe67);
    let result = assemble_active_view(
        &value,
        &recipe67,
        &recipe67_approved,
        quality_for(&value, &recipe67),
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
    let recipe68 = recipe(&context);
    let recipe68_approved = approved_for(&recipe68);
    let result = assemble_active_view(
        &value,
        &recipe68,
        &recipe68_approved,
        quality_for(&value, &recipe68),
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
        // The card records the exact output it graded, including the source
        // revisions these atoms were read from, so this asserts a real packet
        // bound to its real grade.
        let recipe69 = recipe.clone();
        let recipe69_approved = approved_for(&recipe69);
        let view = assemble_active_view(
            value,
            &recipe69,
            &recipe69_approved,
            quality_for(value, recipe),
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
    let recipe70 = recipe(&context);
    let recipe70_approved = approved_for(&recipe70);
    let view = assemble_active_view(
        &value,
        &recipe70,
        &recipe70_approved,
        quality_for(&value, &recipe70),
        &policy(100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("projection-only view");
    assert_eq!(view.view.binding, value.binding);
    assert_eq!(view.view.selection.binding, value.binding);
    assert_eq!(view.view.quality.binding, value.binding);
    assert_eq!(view.view.measurement.context, value.binding);
    assert_eq!(view.view.recipe_digest, recipe(&context).recipe_sha256);
    let recipe71 = recipe(&context);
    let recipe71_approved = approved_for(&recipe71);
    let replay = assemble_active_view(
        &value,
        &recipe71,
        &recipe71_approved,
        quality_for(&value, &recipe71),
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
