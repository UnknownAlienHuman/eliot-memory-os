//! Learning delivery screen proof for issue #1869 (round 4).
//!
//! Genuine issuer-to-consumer path at compile/delivery: the governed
//! assembly entrypoint [`assemble_active_view_with_learning`] re-verifies
//! declared learning atoms against an owner-issued Governor permit minted by
//! the real [`Governor`] owner, and requires the admitted compilation fence
//! to exactly match the admitted fence. Drifted fences, unadmitted-but-
//! claimed atoms, and expired overlays refuse before anything renders;
//! plain [`assemble_active_view`] behavior is preserved.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_admission::learning_gate::LearningAtomClaim;
use eliot_context_assembly::{
    AdmittedContextSet, AssemblyError, AssemblyPolicy, QualityScorecard,
    SerializedContextMeasurement, assemble_active_view, assemble_active_view_with_learning,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    TaskRevision, sha256_hex,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, issue_learning_admission, verify_learning_admission,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";
const CAMPAIGN_1869: &str = "campaign-1869-a";
const TASK_1869: &str = "task-1869-a";
const OVERLAY_1869: &str = "overlay-1869-live";
const NOW_1869: u64 = 1_800_000_000;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest() -> String {
    "a".repeat(64)
}

fn epoch_1869() -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_1869).expect("lineage"),
        NonZeroU64::new(3).expect("sequence"),
    )
    .expect("epoch")
}

fn fence_1869() -> StateFence {
    StateFence::new(
        epoch_1869(),
        ResourceGeneration::new(7).expect("generation"),
    )
}

fn governor_1869() -> Governor {
    let config = GovernorConfig {
        authority_epoch: epoch_1869(),
        resource_generation: ResourceGeneration::new(7).expect("generation"),
        queues: QueueLimits::default(),
        background_pause_interactive_depth: 1,
    };
    let mut governor = Governor::new(config).expect("governor config");
    governor.begin_startup().expect("startup begins");
    governor
}

fn binding() -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new(TASK_1869).expect("fixture task"),
        attempt_id: AgentAttemptId::new("attempt-1869").expect("fixture attempt"),
        scope_id: WorkScopeId::new("scope-1869").expect("fixture scope"),
        state_fence: fence_1869(),
        decision_id: DecisionId::new("decision-1869").expect("fixture decision"),
        operation_id: None,
    }
}

fn role(provider: &str, semantic: SemanticRole) -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(provider).expect("fixture provider"),
        role: semantic,
    }
}

fn candidate(
    context: &ContextBinding,
    atom: &str,
    provider_role: ProviderRole,
) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id(atom),
        provider_role,
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new(format!("source-{atom}"))
                .expect("fixture source"),
            owner: ProviderId::new(format!("owner-{atom}")).expect("fixture owner"),
            snapshot_id: id(&format!("snapshot-{atom}")),
            revision: "revision-1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: format!("whole {atom}"),
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
            evidence_id: id(&format!("evidence-{atom}")),
            ceiling: ProofCeiling::Observation,
        },
    }
}

fn refresh_economy_receipt(value: &mut AdmittedContextSet) {
    let mut unsigned = value.economy.clone();
    unsigned.receipt_digest = "0".repeat(64);
    value.economy.receipt_digest =
        eliot_context_contracts::canonical_digest(&unsigned).expect("economy receipt");
}

/// Admitted set with one ordinary atom plus one learning-declared atom.
///
/// Both atoms share the admitted denominator role (the established two-atom
/// pattern); learning provenance travels only in the explicit sidecar claims
/// map, never in reinterpreted role fields.
fn admitted_with_learning() -> AdmittedContextSet {
    let context = binding();
    let first = candidate(
        &context,
        "atom-1869",
        role("fixture-provider", SemanticRole::Goal),
    );
    let second = candidate(&context, "learning-1869", first.provider_role.clone());
    let atom_id = first.atom_id.clone();
    let provider = first.provider_role.clone();
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
            measurement: Some(first.measurement.clone()),
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
        records: vec![
            AdmittedAtom {
                candidate: first,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmittedAtom {
                candidate: second.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
        ],
        admissions: vec![
            AdmissionRecord {
                atom_id: atom_id.clone(),
                provider_role: provider,
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
            },
            AdmissionRecord {
                atom_id: second.atom_id.clone(),
                provider_role: second.provider_role.clone(),
                disposition: AdmissionDisposition::Include,
                rule_evidence: id("admission-rule"),
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
            requested: vec![atom_id.clone(), second.atom_id.clone()],
            admitted: vec![atom_id, second.atom_id.clone()],
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
    let provider = role("fixture-provider", SemanticRole::Goal);
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

fn owner_permit(
    governor: &Governor,
    fence: &StateFence,
) -> eliot_governor::LearningAdmissionPermit {
    issue_learning_admission(
        governor,
        &LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: CAMPAIGN_1869.to_string(),
            target_task_id: TASK_1869.to_string(),
            fence: fence.clone(),
            overlay_id: Some(OVERLAY_1869.to_string()),
            candidate_id: None,
            scope_ref: "scope-1869".to_string(),
            authority_ref: "governor-1869".to_string(),
            retention_ref: "retention-1869".to_string(),
            evaluator_ref: "evaluator-1869-a".to_string(),
            rollback_ref: "rollback-1869".to_string(),
        },
    )
    .expect("live owner issues")
}

fn learning_claims(expires: Option<u64>) -> BTreeMap<ArtifactId, LearningAtomClaim> {
    use eliot_context_admission::learning_gate::LearningAtomClaim;
    let mut claims = BTreeMap::new();
    claims.insert(
        id("learning-1869"),
        LearningAtomClaim {
            campaign_id: CAMPAIGN_1869.to_string(),
            overlay_id: Some(OVERLAY_1869.to_string()),
            candidate_id: None,
            closure_ref: None,
            owner: None,
            draft: false,
            expires_at_unix_secs: expires,
        },
    );
    claims
}

#[test]
fn learning_atom_projects_with_owner_issued_permit() {
    let governor = governor_1869();
    let fence = fence_1869();
    let value = admitted_with_learning();
    let context = value.binding.clone();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let view = assemble_active_view_with_learning(
        &value,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
        &learning_claims(Some(NOW_1869 + 3600)),
        &verified,
        NOW_1869,
    )
    .expect("covered learning atom projects");
    assert_eq!(view.view.rendered.len(), 2);
    assert!(view.view.admitted_ids.contains(&id("learning-1869")));
}

#[test]
fn drifted_fence_refuses_before_render() {
    let governor = governor_1869();
    let fence = fence_1869();
    let mut value = admitted_with_learning();
    // Drift the compilation fence past the admitted one. The wrapper
    // refuses before rendering (and before measurement runs).
    value.binding.state_fence.task_revision = Some(TaskRevision::new(2).expect("task revision"));
    let context = value.binding.clone();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut calls = 0;
    let result = assemble_active_view_with_learning(
        &value,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| {
            calls += 1;
            Ok(measurement(&context, bytes))
        },
        &learning_claims(Some(NOW_1869 + 3600)),
        &verified,
        NOW_1869,
    );
    assert_eq!(calls, 0);
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidFence))
    );
}

#[test]
fn claimed_but_unadmitted_atom_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    let value = admitted_with_learning();
    let context = value.binding.clone();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut claims = learning_claims(Some(NOW_1869 + 3600));
    claims.insert(
        id("ghost-1869"),
        eliot_context_admission::learning_gate::LearningAtomClaim {
            campaign_id: CAMPAIGN_1869.to_string(),
            overlay_id: Some(OVERLAY_1869.to_string()),
            candidate_id: None,
            closure_ref: None,
            owner: None,
            draft: false,
            expires_at_unix_secs: Some(NOW_1869 + 3600),
        },
    );
    let result = assemble_active_view_with_learning(
        &value,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
        &claims,
        &verified,
        NOW_1869,
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::DenominatorMismatch))
    );
}

#[test]
fn expired_overlay_refuses_delivery_and_plain_projection_survives() {
    let governor = governor_1869();
    let fence = fence_1869();
    let value = admitted_with_learning();
    let context = value.binding.clone();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let result = assemble_active_view_with_learning(
        &value,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
        &learning_claims(Some(NOW_1869 - 1)),
        &verified,
        NOW_1869,
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidField(
            "learning.expires_at"
        )))
    );
    // Historical behavior is untouched: the same set without learning
    // claims projects exactly as before.
    let plain = assemble_active_view(
        &value,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
    );
    match plain {
        Ok(view) => assert_eq!(view.view.rendered.len(), 2),
        Err(error) => panic!("plain fixture error: {error:?}"),
    }
}
