//! Learning delivery screen proof for issue #1869 (round 5).
//!
//! Genuine issuer-to-consumer path at compile/delivery with intrinsic
//! provenance: the governed assembly entrypoint
//! [`assemble_active_view_with_learning`] re-verifies learning-marked
//! admitted atoms (`ContextCandidate.learning`, digest-covered — no sidecar
//! to omit) against an owner-issued Governor permit minted by the real
//! [`Governor`] owner, and requires the admitted compilation fence to
//! exactly match the admitted fence. Drifted fences, transplanted digests,
//! and expired marks refuse before anything renders; plain
//! [`assemble_active_view`] behavior is preserved.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_assembly::{
    ActiveUnderstandingView, ActiveUnderstandingViewResult, AdmittedContextSet, AssemblyError,
    AssemblyPolicy, QualityScorecard, SerializedContextMeasurement, assemble_active_view,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, PolicyRevision, ResourceGeneration,
    StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, VerifiedLearningAdmission, issue_learning_admission, verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{BoundedBacklog, GovernedOverlay, OverlayState};
use eliot_improvement::{PresentedLearning, datetime_from_unix};
use eliot_receipts::{ProofCeiling, ProtectedReserves, WorkScopeId};

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
        // This fixture asserts about learning provenance carriage, not about a
        // measured position inside the snapshot, so the range stays a typed
        // unknown.
        source_range: None,
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
/// learning atom citing `permit_digest`. Both atoms share the admitted
/// denominator role (the established two-atom pattern); learning provenance
/// travels only in the intrinsic mark, never in reinterpreted role fields.
/// The learning provenance this file's campaign revision admits: an owner-issued
/// campaign/overlay pair with no draft, closure or owner claim, and the caller's
/// chosen expiry and permit digest. Extracted so the admitted-set fixture stays
/// readable; every field is the same literal the fixture always carried.
fn learning_provenance_1869(expires: Option<u64>, permit_digest: &str) -> LearningProvenance {
    LearningProvenance {
        campaign_id: CAMPAIGN_1869.to_string(),
        overlay_id: Some(OVERLAY_1869.to_string()),
        candidate_id: None,
        closure_ref: None,
        owner: None,
        draft: false,
        expires_at_unix_secs: expires,
        permit_digest: permit_digest.to_string(),
    }
}

fn admitted_with_learning(permit_digest: &str, expires: Option<u64>) -> AdmittedContextSet {
    let context = binding();
    let first = candidate(&context, "atom-1869");
    let mut second = candidate(&context, "learning-1869");
    second.learning = Some(learning_provenance_1869(expires, permit_digest));
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
            policy_sha256: recipe(&context).decision.policy_sha256.clone(),
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

fn resolved_applicability() -> QualityApplicability {
    QualityApplicability {
        resolved: QUALITY_APPLICABILITY_INPUTS.to_vec(),
        unknown: Vec::new(),
    }
}

/// Intrinsically well-formed output binding for a card that is only checked for
/// structural integrity, or for a packet assembly refuses before the grade is
/// read. The serializer and route identities are the ones
/// [`policy_for`] applies, because a card naming a different serializer or
/// route is not the grade of the bytes produced under this policy and
/// `require_graded_output` refuses it. The digests are placeholders: a card
/// naming one packet's exact digests is built by that packet's owner.
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

/// The card a delivered packet accepts: it records the exact output it graded
/// (the instance digest, the fence, the admitted set's own canonical payload
/// digest, the ordered rendered payload digest and the source revisions the
/// bytes were read from), so `require_graded_output` compares a real grade
/// against a real packet. The intrinsic [`quality`] card above is for the
/// packets this gate refuses BEFORE the grade is read; a packet that is
/// delivered is graded, and a placeholder card is not the grade of anything.
fn quality_for(admitted: &AdmittedContextSet, recipe: &ContextRecipe) -> QualityScorecard {
    let mut card = quality(&admitted.binding);
    let fence_digest =
        eliot_context_contracts::canonical_fence_digest(&admitted.binding.state_fence)
            .expect("fixture fence digest");
    card.output.recipe_digest.clone_from(&recipe.recipe_sha256);
    card.output.fence_digest.clone_from(&fence_digest);
    card.output.admitted_digest = admitted
        .canonical_payload_digest()
        .expect("fixture admitted digest");
    card.output.rendered_digest = ActiveUnderstandingView::canonical_output_digest(
        &admitted.binding,
        &recipe.recipe_sha256,
        &fence_digest,
        &rendered_for(admitted),
    )
    .expect("fixture rendered digest");
    card.output
        .omission_handles
        .clone_from(&admitted.economy.displaced);
    card.output.evidence_revisions = admitted
        .records
        .iter()
        .map(|record| record.candidate.source.snapshot_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    card
}

/// The rendered order this fixture's approved revision declares: declared role
/// position, then provider, then atom identity. The positions
/// [`approved_policy`] assigns are `SemanticRole` ordinals, so this projection
/// and the approved revision's `layout.role_positions` state one order.
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

fn recipe(context: &ContextBinding) -> ContextRecipe {
    let provider = role();
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: DecisionRevision {
            decision_id: context.decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("recipe revision"),
            // Sealed by `seal_recipe`: the approved revision this instance is
            // issued under, not a placeholder. See that function.
            policy_sha256: String::new(),
        },
        recipe_sha256: String::new(),
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
    seal_recipe(&mut recipe);
    recipe
}

/// Re-seal one instance against the approved revision it is now issued under.
///
/// #1724 made the approved revision part of the instance's own identity: the
/// assembly joins the instance's recorded `decision.policy_sha256`, the approved
/// revision's own digest and the admitted receipt's on one value
/// (`ContextRecipePolicy::binds_recipe`, `require_recipe_policy_binding`, and
/// `ActiveUnderstandingView::validate_against` on the way out). A placeholder
/// digest cannot satisfy that join, so the instance records the digest of the
/// revision [`approved_recipe`] actually builds for it.
fn seal_recipe(recipe: &mut ContextRecipe) {
    recipe.decision.policy_sha256 =
        approved_policy(&recipe.mandatory_roles, &recipe.role_policies).policy_sha256;
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
}

/// The approved recipe revision this fixture's compilation is issued under.
///
/// #1724 W4/W5. The delivery entrypoint renders under an APPROVED revision and
/// joins it to the instance and to the admitted receipt by digest, so a
/// placeholder cannot stand in for one: this builds a real
/// `ContextRecipePolicy` and seals its own `canonical_policy_digest`, and
/// [`seal_recipe`] records that digest on the instance.
///
/// It is derived FROM the instance's own role declarations instead of being one
/// shared fixture, because the approved content must declare what this instance
/// declares: `ContextRecipePolicy::binds_recipe` refuses a budgeted role the
/// instance governs no `RoleLossRule` for, and `render::render` refuses a
/// rendered role the revision does not position. Layout positions are assigned
/// in `SemanticRole` ordinal order, which is the order [`rendered_for`] above
/// projects.
fn approved_policy(
    mandatory_roles: &[SemanticRole],
    role_policies: &[RoleLossRule],
) -> ContextRecipePolicy {
    let features: Vec<SemanticRole> = mandatory_roles
        .iter()
        .chain(role_policies.iter().map(|rule| &rule.role))
        .copied()
        .collect::<std::collections::BTreeSet<SemanticRole>>()
        .into_iter()
        .collect();
    let mut policy = ContextRecipePolicy {
        policy_schema_version: CONTEXT_RECIPE_POLICY_SCHEMA_VERSION,
        policy_id: id("fixture-recipe-policy"),
        policy_revision: PolicyRevision::new(1).expect("fixture policy revision"),
        policy_sha256: String::new(),
        applicability: RecipeApplicability {
            task_profiles: vec!["fixture-task-profile".to_owned()],
            route_profiles: vec!["fixture-route-profile".to_owned()],
            impact_profiles: vec!["fixture-impact-profile".to_owned()],
            governance_profiles: vec!["fixture-governance-profile".to_owned()],
        },
        stages: vec![RecipeStage {
            stage_id: id(EXECUTED_CONTEXT_STAGE),
            semantic_role: *features
                .first()
                .expect("fixture instance configures at least one role"),
            predecessors: Vec::new(),
        }],
        candidate_features: features.clone(),
        admission: RecipeAdmissionPolicy {
            admission_rule: id("admission-rule"),
            safety_floor: id("safety-floor"),
            // A mandatory role may never also be suppressible, and this
            // revision suppresses nothing.
            suppressible_roles: Vec::new(),
        },
        section_budgets: role_policies
            .iter()
            .map(|rule| ContextSectionBudget {
                semantic_role: rule.role,
                unit_boundary_kind: BoundaryUnitKind::Unit,
                minimum_required_whole_units: 1,
                required_exact_references: vec![id("fixture-section-unit")],
                protected_floor_refs: Vec::new(),
                planning_maximum_whole_units: 64,
                planning_route_profile: "fixture-route-profile".to_owned(),
                // The instance's OWN per-role loss rule, which is what
                // `binds_recipe` compares against this member.
                omission_or_handle_policy: rule.loss_policy,
                degradation_behavior: EXECUTED_SECTION_DEGRADATION,
                disable_feature_when_floor_cannot_be_preserved: false,
            })
            .collect(),
        protected_reserve: ProtectedReservePolicy {
            reserves: ProtectedReserves {
                reasoning_reserve: 1,
                review_reserve: 1,
                evidence_reserve: 1,
                owner_ref: "fixture-protected-reserve".to_owned(),
            },
            margin_reserve: 1,
        },
        layout: RecipeLayoutPolicy {
            role_positions: features
                .iter()
                .enumerate()
                .map(|(position, semantic_role)| RecipeRolePosition {
                    semantic_role: *semantic_role,
                    position: u32::try_from(position).expect("fixture layout position"),
                })
                .collect(),
            repetition: EXECUTED_REPETITION_POLICY,
        },
        omission: RecipeOmissionPolicy {
            permitted_reasons: vec![OmissionReason::Capacity],
            non_recoverable_reasons: Vec::new(),
        },
        blocking_dimensions: vec![QualityDimension::FreshnessStateFenceCoherence],
        execution: RecipeExecutionContour {
            contour: id("fixture-compiler-contour"),
            generation: 1,
            transform: BoundaryTransformerRevision {
                transformer_id: "fixture-transform".to_owned(),
                revision: eliot_contracts::ContractVersion::new(1, 0, 0),
                configuration_sha256: digest(),
            },
        },
        qualification: RecipeQualification {
            qualification: id("fixture-qualification"),
            state: RecipeQualificationState::Qualified,
            counter_metrics: Vec::new(),
        },
        supersession: RecipeSupersession {
            activation: id("fixture-recipe-activation"),
        },
    };
    policy.policy_sha256 = policy
        .canonical_policy_digest()
        .expect("approved recipe policy digest");
    policy
}

/// The approved revision pinned for one exact instance, taken BY VALUE.
///
/// Every call site owns the exact instance value it passes as the delivery
/// entrypoint's `recipe` argument, so the approved revision is derived from that
/// owned value rather than from a re-borrow of a name that could mean something
/// else by the time it is read. What IS validated here is the approved revision
/// this helper built, so a fixture that cannot construct one fails loudly
/// instead of passing a revision the assembly would refuse.
fn approved_recipe(recipe: ContextRecipe) -> ResolvedContextRecipe {
    let ContextRecipe {
        mandatory_roles,
        role_policies,
        ..
    } = recipe;
    let policy = approved_policy(&mandatory_roles, &role_policies);
    let mut resolution = ResolvedContextRecipe {
        identity: RecipePolicyIdentity {
            policy_id: policy.policy_id.clone(),
            policy_revision: policy.policy_revision,
            policy_sha256: policy.policy_sha256.clone(),
        },
        approval: policy.supersession.activation.clone(),
        applicability: policy.applicability.clone(),
        execution: policy.execution.clone(),
        policy,
        resolution_sha256: "0".repeat(64),
    };
    resolution.resolution_sha256 = resolution
        .canonical_resolution_digest()
        .expect("fixture approved recipe revision digest");
    resolution
        .validate()
        .expect("fixture approved recipe revision resolves");
    resolution
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

fn live_overlay_1869(fence: &StateFence) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: OVERLAY_1869.to_string(),
        campaign_id: CAMPAIGN_1869.to_string(),
        task_id: TASK_1869.to_string(),
        fence: fence.clone(),
        compatible_recipe_ref: "recipe-1869".to_string(),
        state: OverlayState::LocalAdmitted,
        admission_ref: Some("admission-1869-live".to_string()),
        expires_at: Some(datetime_from_unix(NOW_1869 + 3600).expect("overlay expiry")),
    }
}

/// Build the governed presentation the delivery screen requires: the
/// owner-verified permit plus its wire ticket, the live `LOCAL_ADMITTED`
/// overlay, an (empty — no reusable subjects here) backlog, and local
/// requesting identity with owner-sourced time.
fn presented_1869<'a>(
    governor: &'a Governor,
    verified: &'a VerifiedLearningAdmission<'a>,
    overlay: &'a GovernedOverlay,
    backlog: &'a BoundedBacklog,
    now: u64,
) -> PresentedLearning<'a> {
    PresentedLearning {
        governor,
        verified,
        ticket: verified.permit().ticket(),
        overlay: Some(overlay),
        backlog,
        cross_task: None,
        requesting_campaign_id: CAMPAIGN_1869,
        requesting_task_id: TASK_1869,
        now_unix_secs: now,
    }
}

fn assemble_marked(
    governor: &Governor,
    value: &AdmittedContextSet,
    verified: &VerifiedLearningAdmission<'_>,
    overlay: &GovernedOverlay,
    backlog: &BoundedBacklog,
    now: u64,
) -> Result<ActiveUnderstandingViewResult, AssemblyError> {
    let context = value.binding.clone();
    assemble_active_view_with_learning(
        value,
        &recipe(&context),
        &approved_recipe(recipe(&context)),
        quality_for(value, &recipe(&context)),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
        presented_1869(governor, verified, overlay, backlog, now),
    )
}

#[test]
fn marked_atom_projects_with_owner_issued_permit() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let view = assemble_marked(&governor, &value, &verified, &overlay, &backlog, NOW_1869)
        .expect("covered marked atom projects");
    assert_eq!(view.view.rendered.len(), 2);
    assert!(view.view.admitted_ids.contains(&id("learning-1869")));
}

#[test]
fn drifted_fence_refuses_before_render() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut value = admitted_with_learning(permit.digest(), Some(NOW_1869 + 3600));
    // Drift the compilation fence past the admitted one. The wrapper
    // refuses before rendering (and before measurement runs).
    value.binding.state_fence.task_revision = Some(TaskRevision::new(2).expect("task revision"));
    let context = value.binding.clone();
    let mut calls = 0;
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let result = assemble_active_view_with_learning(
        &value,
        &recipe(&context),
        &approved_recipe(recipe(&context)),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| {
            calls += 1;
            Ok(measurement(&context, bytes))
        },
        presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
    );
    assert_eq!(calls, 0);
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidFence))
    );
}

#[test]
fn transplanted_permit_digest_refused_at_delivery() {
    let governor = governor_1869();
    let fence = fence_1869();
    let other = owner_permit(&governor, &fence);
    // Same owner, second issuance for another overlay: a different digest.
    let permit = issue_learning_admission(
        &governor,
        &LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: CAMPAIGN_1869.to_string(),
            target_task_id: TASK_1869.to_string(),
            fence: fence.clone(),
            overlay_id: Some("overlay-other".to_string()),
            candidate_id: None,
            scope_ref: "scope-1869".to_string(),
            authority_ref: "governor-1869".to_string(),
            retention_ref: "retention-1869".to_string(),
            evaluator_ref: "evaluator-1869-a".to_string(),
            rollback_ref: "rollback-1869".to_string(),
        },
    )
    .expect("live owner issues");
    assert_ne!(other.digest(), permit.digest());
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    // Atom cites the other issuance: refused even though both are genuine.
    let value = admitted_with_learning(other.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let result = assemble_marked(&governor, &value, &verified, &overlay, &backlog, NOW_1869);
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::IdentityConflict))
    );
}

#[test]
fn expired_mark_refuses_delivery_and_plain_projection_survives() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = owner_permit(&governor, &fence);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let value = admitted_with_learning(permit.digest(), Some(NOW_1869 - 1));
    let context = value.binding.clone();
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let result = assemble_active_view_with_learning(
        &value,
        &recipe(&context),
        &approved_recipe(recipe(&context)),
        quality(&context),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
        presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
    );
    assert_eq!(
        result,
        Err(AssemblyError::Contract(ContextError::InvalidField(
            "learning.expires_at"
        )))
    );
    // Historical behavior is untouched: unmarked atoms project as before.
    // (Stripping the mark changes atom identity, so the economy digests are
    // recomputed exactly as the legitimate producer would emit them.)
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
        &approved_recipe(recipe(&context)),
        quality_for(&plain, &recipe(&context)),
        &policy_for(&context, 100_000),
        |bytes| Ok(measurement(&context, bytes)),
    )
    .expect("plain projection survives");
    assert_eq!(view.view.rendered.len(), 2);
}
