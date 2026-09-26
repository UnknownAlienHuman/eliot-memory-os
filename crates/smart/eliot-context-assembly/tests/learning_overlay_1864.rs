//! Governed local overlay admission proof for issue #1864, item A3.
//!
//! After expiry, the same overlay revision is not retrievable or deliverable
//! to a later attempt absent a new governed admission. These tests pin the
//! delivery side through the governed assembly entrypoint
//! [`assemble_active_view_with_learning`], which runs the shared owner-bound
//! carriage gate exactly as at retrieval:
//!
//! - the expired revision (same `overlay_id`, live mark, past `expires_at`)
//!   refuses before anything renders, and the plain base-view projection
//!   survives untouched;
//! - the same revision under a new governed admission (fresh expiry and
//!   admission handle) delivers again to its own campaign, and no longer
//!   reaches another campaign under a revalidation that only re-spelled the
//!   local admission (#1869: a carryover needs a distinct, owner-issued
//!   admission, and a request from the admitted task under a foreign campaign
//!   label is refused as cross-campaign leakage);
//! - the invalidated revision refuses even with live expiry.
//!
//! Note: `eliot-learning-contracts::overlay_eligibility` and
//! `eliot-learning-overlay::check_retrievable` express the same causal
//! property, but neither crate is a dependency of `eliot-context-assembly`
//! (see `Cargo.toml`), so these tests exercise the identical refusal reasons
//! through the available governed screen: `ExpiredOverlay` maps to
//! `InvalidField("learning.expires_at")` (the `overlay_expired` analog) and
//! `OverlayNotAdmitted` maps to `InvalidField("learning.overlay")` (the
//! `overlay_invalidated` analog).

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AdmittedContextSet, AssemblyError, AssemblyPolicy,
    QualityScorecard, SerializedContextMeasurement, assemble_active_view,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    TaskRevision, sha256_hex,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, VerifiedLearningAdmission, issue_learning_admission, verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{
    BoundedBacklog, CrossTaskCarryover, GovernedOverlay, OverlayState,
};
use eliot_improvement::{PresentedLearning, datetime_from_unix};
use eliot_receipts::{ProofCeiling, WorkScopeId};

const LINEAGE_1864: &str = "550e8400-e29b-41d4-a716-446655440001";
const CAMPAIGN_1864: &str = "campaign-1864-a";
const OTHER_CAMPAIGN_1864: &str = "campaign-1864-b";
const TASK_1864: &str = "task-1864-a";
const OVERLAY_1864: &str = "overlay-1864-rev7";
const NOW_1864: u64 = 1_800_000_000;
const LATER_1864: u64 = NOW_1864 + 7200;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest() -> String {
    "b".repeat(64)
}

fn epoch_1864() -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_1864).expect("lineage"),
        NonZeroU64::new(3).expect("sequence"),
    )
    .expect("epoch")
}

fn fence_1864() -> StateFence {
    StateFence::new(
        epoch_1864(),
        ResourceGeneration::new(7).expect("generation"),
    )
}

fn governor_1864() -> Governor {
    let config = GovernorConfig {
        authority_epoch: epoch_1864(),
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
        task_id: TaskId::new(TASK_1864).expect("fixture task"),
        attempt_id: AgentAttemptId::new("attempt-1864").expect("fixture attempt"),
        scope_id: WorkScopeId::new("scope-1864").expect("fixture scope"),
        state_fence: fence_1864(),
        decision_id: DecisionId::new("decision-1864").expect("fixture decision"),
        operation_id: None,
    }
}

fn role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("fixture-provider").expect("fixture provider"),
        role: SemanticRole::Goal,
    }
}

fn candidate(context: &ContextBinding, atom: &str) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id(atom),
        provider_role: role(),
        source: SourceSnapshot {
            source_id: eliot_contracts::SourceId::new(format!("source-{atom}"))
                .expect("fixture source"),
            owner: ProviderId::new("fixture-provider").expect("fixture owner"),
            snapshot_id: id(&format!("snapshot-{atom}")),
            revision: "revision-1".to_owned(),
            content_sha256: digest(),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: format!("whole {atom}"),
        },
        learning: None,
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

/// Admitted set with one ordinary atom plus one intrinsically marked
/// learning atom citing `permit_digest`. The mark expiry is caller-chosen so
/// refusal can be attributed to the overlay revision alone.
fn admitted_with_learning(permit_digest: &str, mark_expires: Option<u64>) -> AdmittedContextSet {
    let context = binding();
    let first = candidate(&context, "atom-1864");
    let mut second = candidate(&context, "learning-1864");
    second.learning = Some(LearningProvenance {
        campaign_id: CAMPAIGN_1864.to_string(),
        overlay_id: Some(OVERLAY_1864.to_string()),
        candidate_id: None,
        closure_ref: None,
        owner: None,
        draft: false,
        expires_at_unix_secs: mark_expires,
        permit_digest: permit_digest.to_string(),
    });
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

fn refresh_economy_receipt(value: &mut AdmittedContextSet) {
    let mut unsigned = value.economy.clone();
    unsigned.receipt_digest = "0".repeat(64);
    value.economy.receipt_digest =
        eliot_context_contracts::canonical_digest(&unsigned).expect("economy receipt");
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

fn owner_permit(
    governor: &Governor,
    fence: &StateFence,
) -> eliot_governor::LearningAdmissionPermit {
    issue_learning_admission(
        governor,
        &LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: CAMPAIGN_1864.to_string(),
            target_task_id: TASK_1864.to_string(),
            fence: fence.clone(),
            overlay_id: Some(OVERLAY_1864.to_string()),
            candidate_id: None,
            scope_ref: "scope-1864".to_string(),
            authority_ref: "governor-1864".to_string(),
            retention_ref: "retention-1864".to_string(),
            evaluator_ref: "evaluator-1864-a".to_string(),
            rollback_ref: "rollback-1864".to_string(),
        },
    )
    .expect("live owner issues")
}

/// The same overlay revision under test: identical identity bytes
/// (`overlay_id`, campaign, fence); only the governed admission liveness
/// (`state`, `admission_ref`, `expires_at`) varies per case.
fn overlay_revision_1864(
    fence: &StateFence,
    state: OverlayState,
    admission_ref: &str,
    expires_at_unix_secs: u64,
) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: OVERLAY_1864.to_string(),
        campaign_id: CAMPAIGN_1864.to_string(),
        task_id: TASK_1864.to_string(),
        fence: fence.clone(),
        compatible_recipe_ref: "recipe-1864".to_string(),
        state,
        admission_ref: Some(admission_ref.to_string()),
        expires_at: Some(datetime_from_unix(expires_at_unix_secs).expect("overlay expiry")),
    }
}

#[allow(clippy::too_many_arguments)]
fn presented_1864<'a>(
    governor: &'a Governor,
    verified: &'a VerifiedLearningAdmission<'a>,
    overlay: &'a GovernedOverlay,
    backlog: &'a BoundedBacklog,
    cross_task: Option<&'a CrossTaskCarryover<'a>>,
    requesting_campaign_id: &'a str,
    now: u64,
) -> PresentedLearning<'a> {
    PresentedLearning {
        governor,
        verified,
        ticket: verified.permit().ticket(),
        overlay: Some(overlay),
        backlog,
        cross_task,
        requesting_campaign_id,
        requesting_task_id: TASK_1864,
        now_unix_secs: now,
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_marked_1864(
    value: &AdmittedContextSet,
    governor: &Governor,
    verified: &VerifiedLearningAdmission<'_>,
    overlay: &GovernedOverlay,
    backlog: &BoundedBacklog,
    cross_task: Option<&CrossTaskCarryover<'_>>,
    requesting_campaign_id: &str,
    now: u64,
) -> Result<ActiveUnderstandingViewResult, AssemblyError> {
    let context = value.binding.clone();
    assemble_active_view_with_learning(
        value,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
        presented_1864(
            governor,
            verified,
            overlay,
            backlog,
            cross_task,
            requesting_campaign_id,
            now,
        ),
    )
}

/// A3, expired revision: the same overlay revision presented to a later
/// attempt refuses delivery. The mark itself is live, so the refusal is
/// attributable to the expired revision, not to mark expiry.
#[test]
fn expired_overlay_revision_refuses_later_delivery_and_plain_projection_survives() {
    let governor = governor_1864();
    let fence = fence_1864();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(LATER_1864 + 3600));
    let overlay = overlay_revision_1864(
        &fence,
        OverlayState::LocalAdmitted,
        "admission-1864-rev7",
        NOW_1864 + 3600,
    );
    let backlog = BoundedBacklog::default();
    let result = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        CAMPAIGN_1864,
        LATER_1864,
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidField(
            "learning.expires_at"
        )))
    );
    // Historical behavior is untouched: unmarked atoms project as before.
    let mut plain = value;
    for record in &mut plain.records {
        record.candidate.learning = None;
    }
    refresh_economy_receipt(&mut plain);
    let payload_bytes = plain
        .canonical_payload_utf8_bytes()
        .expect("admitted payload");
    plain.economy.allocations.admitted_required = payload_bytes;
    plain.economy.allocations.remaining_headroom = 100_000 - 9 - payload_bytes;
    refresh_economy_receipt(&mut plain);
    plain.economy.measurement.digest = plain.canonical_payload_digest().expect("admitted digest");
    refresh_economy_receipt(&mut plain);
    let context = plain.binding.clone();
    let view = assemble_active_view(
        &plain,
        &recipe(&context),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("plain projection survives");
    assert_eq!(view.view.rendered.len(), 2);
}

/// A3, re-admission: the same revision (identical identity bytes) under a new
/// governed admission delivers again. No new admission, no delivery
/// (see the expired test above).
///
/// The old fixture asked for that delivery to ANOTHER campaign on the strength
/// of a "cross-task admission" that re-spelled this very permit's own bound
/// values and named this very task, so no other task was involved at all —
/// the defect #1869 removes. A carryover is now a distinct, owner-issued
/// admission, and a request from the admitted task under a foreign campaign
/// label is refused as cross-campaign leakage, so that leg is pinned as the
/// refusal it now is and the re-admitted revision is proved on the campaign
/// its learning belongs to.
#[test]
fn readmitted_overlay_revision_delivers_to_other_campaign_with_new_admission() {
    let governor = governor_1864();
    let fence = fence_1864();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(LATER_1864 + 3600));
    let overlay = overlay_revision_1864(
        &fence,
        OverlayState::LocalAdmitted,
        "admission-1864-rev7-readmit",
        LATER_1864 + 3600,
    );
    let backlog = BoundedBacklog::default();
    let refusal = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        OTHER_CAMPAIGN_1864,
        LATER_1864,
    );
    assert_eq!(
        refusal,
        Err(AssemblyError::Contract(ContextError::IdentityConflict)),
        "another campaign is not a carryover a re-spelled local admission buys"
    );

    let view = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        CAMPAIGN_1864,
        LATER_1864,
    )
    .expect("readmitted revision delivers with new governed admission");
    assert_eq!(view.view.rendered.len(), 2);
    assert!(view.view.admitted_ids.contains(&id("learning-1864")));
}

/// A3, invalidation: the same revision with live expiry but an invalidated
/// state refuses delivery; expiry is not the only way a revision dies.
#[test]
fn invalidated_overlay_revision_refuses_delivery() {
    let governor = governor_1864();
    let fence = fence_1864();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(NOW_1864 + 3600));
    let overlay = overlay_revision_1864(
        &fence,
        OverlayState::Invalidated,
        "admission-1864-rev7",
        NOW_1864 + 3600,
    );
    let backlog = BoundedBacklog::default();
    let result = assemble_marked_1864(
        &value,
        &governor,
        &verified,
        &overlay,
        &backlog,
        None,
        CAMPAIGN_1864,
        NOW_1864,
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidField(
            "learning.overlay"
        )))
    );
}
