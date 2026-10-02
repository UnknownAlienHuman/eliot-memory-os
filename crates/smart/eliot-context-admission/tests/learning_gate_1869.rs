//! Learning retrieval screen proof for issue #1869.
//!
//! Genuine issuer-to-consumer path with intrinsic provenance: learning marks
//! ride on the candidate itself (`ContextCandidate.learning`, digest-covered)
//! — there is no sidecar to omit. The governed retrieval entrypoint
//! [`admit_context_with_learning`] admits covered marked atoms through the
//! composed admission decision and refuses expired, foreign-task,
//! stale-fence, transplanted-digest, and unclosed-reusable inputs before any
//! value surfaces. The plain path still completes for unmarked atoms.
//!
//! The composition half below drives the COMPOSED entrypoint
//! [`admit_context_governed`], the headroom-only projection
//! [`admit_context_traced_with_headroom`], and the result-only projection
//! [`admit_context_with_learning`], because those are the entrypoints the #1869
//! audit named: the headroom entry must not reach selection without the ordinary
//! learning refusal and the per-mark screen, and no entry may be a second,
//! independent composition.
//!
//! The reserved-path fixtures below are REAL owner evidence, not pre-agreed
//! verdicts: they name `eliot_runtime_contracts`' own `CapacityRequest` and
//! `CapacityPermitBinding`, so a demanded dimension is genuinely constructible and
//! nothing inside `DownstreamHeadroomResult::validate_against` is skipped by an
//! empty demand list.
//!
//! Which of its checks are actually PINNED, and where, is stated per test rather
//! than claimed here. Two of them are satisfied by construction in the
//! self-consistent fixtures — the request digest and the authority epoch are
//! derived from the very request and fence they are compared against — and no
//! test below pretends otherwise. The binding comparison and `matches_request`
//! are pinned by hand-edited fixtures in
//! `owner_evidence_is_matched_against_the_request_not_against_itself`; the
//! requester generation and the permit expiry are pinned by the supersession and
//! clock tests. The request digest and the authority epoch are NOT pinned.
//!
//! This crate has NO selection counter and its selector is pure and stateless,
//! so "exactly one selection" is not a measurable claim and is NOT asserted as
//! one anywhere below. What is asserted is the observable that differs between
//! arms, and the refusal each arm produces.
//!
//! [`admit_context_with_learning`] forwards the reservation arm its CALLER
//! declares into the same composed decision, so the reserved arm of that
//! entrypoint is exercised here too. It remains a RESULT-ONLY projection: it does
//! not surface the `HeadroomCheck` its arm produced, so nothing below asserts on a
//! `HeadroomCheck` value this function does not return. Which arm ran is observed
//! through the decision that arm produces — an admitted set, or a typed refusal —
//! never read back out of a return value that does not carry it.
//!
//! Host-only proof: the gated entrypoints below require Governor evidence,
//! which never enters the wasm32 guest contour.
#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_admission::learning_gate::admit_context_with_learning;
use eliot_context_admission::{
    DownstreamReservation, HeadroomAdmissionOutcome, HeadroomCheck, HeadroomContext,
    HeadroomRefusalRecord, LearningGovernance, MaterialRankTrace, admit_context,
    admit_context_governed, admit_context_traced_with_headroom, screen_admission_input_learning,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, VerifiedLearningAdmission, issue_learning_admission, verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{BoundedBacklog, GovernedOverlay, OverlayState};
use eliot_improvement::{
    CarriageMark, PresentedLearning, check_governed_carriage, datetime_from_unix,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};
use eliot_runtime_contracts::{
    CapacityBottleneck, CapacityLimit, CapacityPermitBinding, CapacityRequest, CapacityUnit,
    NormalWorkClass, RequestedOperationClass, frozen_bottleneck_owner_map,
};

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";
const CAMPAIGN_1869: &str = "campaign-1869-a";
const TASK_1869: &str = "task-1869-a";
const OVERLAY_1869: &str = "overlay-1869-live";
const NOW_1869: u64 = 1_800_000_000;

/// The caller clock reading the reserved-path fixtures hand to the composition
/// as `now_ms`.
///
/// It is a value the test supplies, not a reading this crate takes: nothing in
/// `eliot-context-admission` reads a clock, so staleness is decided against
/// whatever the caller passes. Asserting `headroom.now_ms` against this constant
/// would compare a field the test just assigned, so no assertion here does that.
const NOW_1869_MS: u64 = 1_800_000_000_000;

/// How long the owner-issued result envelope stays open, in milliseconds.
const RESULT_TTL_1869_MS: u64 = 60_000;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest(byte: u8) -> String {
    char::from(byte).to_string().repeat(64)
}

fn epoch_1869() -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_1869).expect("lineage"),
        NonZeroU64::new(3).expect("sequence"),
    )
    .expect("epoch")
}

fn fence_1869() -> StateFence {
    let mut fence = StateFence::new(
        epoch_1869(),
        ResourceGeneration::new(7).expect("generation"),
    );
    fence.task_revision = Some(TaskRevision::new(1).expect("task revision"));
    fence
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

fn binding(task: &str) -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new(task).expect("task"),
        attempt_id: AgentAttemptId::new("attempt-1869").expect("attempt"),
        scope_id: WorkScopeId::new("scope-1869").expect("scope"),
        state_fence: fence_1869(),
        decision_id: DecisionId::new("decision-1869").expect("decision"),
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
    loss_policy: LossPolicy,
    protected: bool,
    learning: Option<LearningProvenance>,
) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id(atom_id),
        provider_role,
        // This fixture asserts about learning provenance carriage, not about a
        // measured position inside the snapshot, so the range stays a typed
        // unknown.
        source_range: None,
        source: SourceSnapshot {
            source_id: SourceId::new(format!("source-{atom_id}")).expect("source"),
            owner: ProviderId::new(format!("owner-{atom_id}")).expect("owner"),
            snapshot_id: id(&format!("snapshot-{atom_id}")),
            revision: "r1".to_owned(),
            content_sha256: digest(b'b'),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: format!("content-{atom_id}"),
        },
        learning,
        loss_policy,
        availability: AtomAvailability::PresentCurrent,
        protected,
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

fn learning_mark(permit_digest: &str, expires: Option<u64>) -> LearningProvenance {
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

fn measurement(
    context: &ContextBinding,
    candidate: &ContextCandidate,
    measurement_id: &str,
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
        cost: AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 },
        observation: None,
    }
}

/// The route envelope every part of this input is compiled against. One value,
/// referenced by the recipe, the floor, the measurement profile and the headroom
/// ledger, so the declared reserves are never restated per part.
fn capacity_1869() -> CapacityLimits {
    CapacityLimits {
        route_capacity: 100,
        fixed_overhead: 10,
        output_reserve: 10,
        review_reserve: 10,
    }
}

/// The provider denominator for exactly `slots`, every one present and current.
fn present_denominator(slots: &[ProviderRole]) -> ProviderRoleDenominator {
    ProviderRoleDenominator {
        requested: slots.to_vec(),
        dispositions: slots
            .iter()
            .cloned()
            .map(|slot| ProviderDisposition {
                slot,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            })
            .collect(),
    }
}

/// The recipe this input is decided under, carrying its own policy digest.
fn recipe_1869(
    context: &ContextBinding,
    denominator: &ProviderRoleDenominator,
    capacity: CapacityLimits,
) -> ContextRecipe {
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: decision(context),
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
    recipe
}

/// The floor identity over the required atom only: the learning atom is
/// optional and is deliberately outside the floor.
fn floor_1869(
    context: &ContextBinding,
    required: &ContextCandidate,
    required_role: &ProviderRole,
    capacity: CapacityLimits,
) -> DecisionSafetyFloor {
    DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![required.atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: present_denominator(std::slice::from_ref(required_role)),
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
    }
}

/// The candidate set: the required floor atom plus the marked learning atom.
fn candidate_set_1869(
    context: &ContextBinding,
    required: &ContextCandidate,
    learning: &ContextCandidate,
    denominator: ProviderRoleDenominator,
) -> ContextCandidateSet {
    ContextCandidateSet {
        binding: context.clone(),
        candidates: vec![required.clone(), learning.clone()],
        denominator,
    }
}

/// The priority identity: the required atom first, the learning atom normal.
fn priority_1869(
    recipe_decision: &DecisionRevision,
    required: &ContextCandidate,
    learning: &ContextCandidate,
) -> PriorityPolicyIdentity {
    PriorityPolicyIdentity {
        policy_id: id("priority"),
        decision: recipe_decision.clone(),
        priorities: vec![
            CandidatePriority {
                atom_id: required.atom_id.clone(),
                class: AdmissionPriorityClass::Required,
                ordinal: 0,
            },
            CandidatePriority {
                atom_id: learning.atom_id.clone(),
                class: AdmissionPriorityClass::Normal,
                ordinal: 1,
            },
        ],
    }
}

/// The admission rule identity this input is decided under.
fn rule_1869(recipe_decision: DecisionRevision) -> AdmissionRuleIdentity {
    AdmissionRuleIdentity {
        rule_id: id("rule"),
        decision: recipe_decision,
        rule_sha256: digest(b'a'),
    }
}

/// The measurement profile both atoms' measurements are bound to.
fn measurement_profile_1869(capacity: CapacityLimits) -> MeasurementCompositionProfile {
    MeasurementCompositionProfile {
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
    }
}

/// The supplied reversible/non-recoverable omission the learning atom is
/// dropped under, so the summarizable optional atom has a stated owner policy.
fn supplied_omission_1869(learning: &ContextCandidate) -> SuppliedOmissionBinding {
    SuppliedOmissionBinding {
        atom_id: learning.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    }
}

/// Minimal valid input with one required floor atom plus one intrinsically
/// marked learning atom. The mark cites `permit_digest`.
///
/// Every part below is built by its own named helper, and each helper is called
/// from here exactly once, so no part of this closure can drift out of the input.
fn input_with_learning(task: &str, permit_digest: &str, expires: Option<u64>) -> AdmissionInput {
    let context = binding(task);
    let required_role = role("required-provider", SemanticRole::Goal);
    let learning_role = role("learning-provider", SemanticRole::Optional);
    let required = candidate(
        &context,
        "required-1869",
        required_role.clone(),
        LossPolicy::NonDroppable,
        true,
        None,
    );
    let learning = candidate(
        &context,
        "learning-1869",
        learning_role.clone(),
        LossPolicy::Summarizable,
        false,
        Some(learning_mark(permit_digest, expires)),
    );
    let denominator = present_denominator(&[required_role.clone(), learning_role.clone()]);
    let capacity = capacity_1869();
    let recipe = recipe_1869(&context, &denominator, capacity);
    AdmissionInput {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        recipe: recipe.clone(),
        candidates: candidate_set_1869(&context, &required, &learning, denominator),
        floor: SafetyFloorIdentity {
            floor_id: id("floor"),
            decision: recipe.decision.clone(),
            floor: floor_1869(&context, &required, &required_role, capacity),
        },
        priority: priority_1869(&recipe.decision, &required, &learning),
        rule: rule_1869(recipe.decision),
        measurement_profile: measurement_profile_1869(capacity),
        supplied_omissions: vec![supplied_omission_1869(&learning)],
        measurements: vec![
            measurement(&context, &required, "required-measurement"),
            measurement(&context, &learning, "learning-measurement"),
        ],
        learning_tickets: Vec::new(),
    }
}

fn owner_claim(
    fence: &StateFence,
    overlay: Option<&str>,
    candidate: Option<&str>,
) -> LearningAdmissionClaim {
    LearningAdmissionClaim {
        schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: CAMPAIGN_1869.to_string(),
        target_task_id: TASK_1869.to_string(),
        fence: fence.clone(),
        overlay_id: overlay.map(str::to_string),
        candidate_id: candidate.map(str::to_string),
        scope_ref: "scope-1869".to_string(),
        authority_ref: "governor-1869".to_string(),
        retention_ref: "retention-1869".to_string(),
        evaluator_ref: "evaluator-1869-a".to_string(),
        rollback_ref: "rollback-1869".to_string(),
    }
}

/// Issue a live owner permit first so fixtures cite the real digest.
fn live_permit(
    governor: &Governor,
    fence: &StateFence,
    overlay: Option<&str>,
    candidate: Option<&str>,
) -> eliot_governor::LearningAdmissionPermit {
    issue_learning_admission(governor, &owner_claim(fence, overlay, candidate))
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

/// Build the governed presentation the retrieval screen requires: the
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

/// The requester generation the live fence carries, and the generation a
/// reservation has to be issued under to count as current.
fn live_generation_1869() -> ResourceGeneration {
    ResourceGeneration::new(7).expect("generation")
}

/// How long the owner-minted PERMIT stays live after issuance, in milliseconds.
///
/// Deliberately shorter than [`RESULT_TTL_1869_MS`], so one caller clock reading
/// can sit inside the result envelope and past the permit at the same time. That
/// is the reading that makes the permit's OWN expiry — not the result's — the
/// thing that withholds the decision.
const PERMIT_TTL_1869_MS: u64 = 30_000;

/// The frozen owner reference for the demanded dimension's bottleneck, read out
/// of the owner's own frozen map rather than written here.
fn memory_owner_1869() -> &'static str {
    frozen_bottleneck_owner_map()
        .into_iter()
        .find(|row| row.bottleneck == CapacityBottleneck::ProtectedMemoryBytes)
        .expect("the frozen map has a protected-memory row")
        .owner
}

/// One demanded `MEMORY` dimension plus the exact owner request submitted for it.
///
/// `HeadroomDemand::request` is the owner's own `CapacityRequest`, not a summary
/// of it: a result can only be matched back through
/// `CapacityPermitBinding::matches_request`, so the demand, the permit and the
/// request digest must agree on operation identity, bottleneck, unit, amount,
/// requester generation, Authority Epoch and profile revision.
///
/// `generation` is the requester generation the demand was submitted under. A
/// demand submitted under a generation other than the live fence's is how the
/// superseded-permit case is built.
fn memory_demand_1869(generation: ResourceGeneration) -> HeadroomDemand {
    let amount = NonZeroU64::new(4096).expect("strictly positive demand");
    HeadroomDemand {
        dimension: HeadroomDimension::Memory,
        quantity: HeadroomQuantity::Known {
            unit: CapacityUnit::MemoryBytes,
            value: amount,
        },
        request: CapacityRequest {
            operation: RequestedOperationClass::Normal(NormalWorkClass::Interactive),
            operation_id: "operation-1869".to_owned(),
            requested_bottleneck: CapacityBottleneck::ProtectedMemoryBytes,
            requested_limit: CapacityLimit {
                unit: CapacityUnit::MemoryBytes,
                quantity: amount,
            },
            requesting_owner_ref: "context-compiler-1869".to_owned(),
            requesting_generation_ref: generation,
            authority_epoch_ref: epoch_1869(),
            profile_id: "profile-1869".to_owned(),
            profile_revision: "r1".to_owned(),
            deadline_ms: NOW_1869_MS + 60_000,
        },
    }
}

/// The owner-minted permit for `demand`: the same exact request the owner
/// validated, with an owner reference read from the frozen owner map and a
/// capacity class DERIVED from the demand's own operation tag rather than
/// asserted beside it.
fn granted_permit_1869(demand: &HeadroomDemand, expires_at_ms: u64) -> Box<CapacityPermitBinding> {
    let request = &demand.request;
    Box::new(CapacityPermitBinding {
        permit_id: "permit-1869".to_owned(),
        operation_id: request.operation_id.clone(),
        capacity_class: request.operation.capacity_class(),
        operation: request.operation,
        bottleneck: request.requested_bottleneck,
        granted_limit: request.requested_limit,
        capacity_owner_ref: memory_owner_1869().to_owned(),
        capacity_owner_generation_ref: ResourceGeneration::new(1).expect("generation"),
        requesting_owner_ref: request.requesting_owner_ref.clone(),
        requesting_generation_ref: request.requesting_generation_ref,
        authority_epoch_ref: epoch_1869(),
        profile_id: request.profile_id.clone(),
        profile_revision: request.profile_revision.clone(),
        issued_at_ms: NOW_1869_MS,
        expires_at_ms,
        owner_evidence_refs: Vec::new(),
    })
}

/// Owner-issued downstream reservation evidence for one compilation.
///
/// The bounded request, the owner's answer and the allocation ledger are built
/// from the input's OWN binding and recipe capacity, so `check_headroom` reads
/// this as real owner evidence rather than a pre-agreed verdict: the result
/// cites this request's own canonical digest, the ledger binds each purpose once
/// referencing the declared output and review reserves rather than adding them a
/// second time, and the owner's answer carries a permit for the demand that was
/// actually submitted.
///
/// The demand list is NON-EMPTY on purpose.
/// `DownstreamHeadroomRequest::validate` refuses an empty list
/// (`ContextError::Bounds`) and `validate_against` runs that validator FIRST, so
/// an empty list would leave every substantive owner-evidence check unreachable:
/// no digest comparison, no binding/fence comparison, no permit epoch/generation
/// check, no permit expiry check. With one demanded dimension each of those
/// checks executes.
///
/// `outcome` is the owner's answer FOR THE DEMANDED DIMENSION. Every other value
/// of the closed denominator is recorded as `NotApplicable`, because an undemanded
/// dimension must carry no reservation at all — a permit nobody asked for is not
/// headroom for this pipeline.
fn reservation_1869(
    input: &AdmissionInput,
    demand: &HeadroomDemand,
    outcome: &HeadroomOutcome,
) -> (
    DownstreamHeadroomRequest,
    DownstreamHeadroomResult,
    HeadroomAllocationLedger,
) {
    let request = DownstreamHeadroomRequest {
        schema_version: DOWNSTREAM_HEADROOM_SCHEMA_VERSION,
        pipeline_id: id("pipeline-1869"),
        attempt_id: id("attempt-1869"),
        stage_id: id("stage-1869"),
        consumer: HeadroomConsumer::Synthesis,
        binding: input.binding.clone(),
        route_id: "route".to_owned(),
        serializer_id: "json-v1".to_owned(),
        recipe_digest: input.recipe.recipe_sha256.clone(),
        demands: vec![demand.clone()],
        release: HeadroomReleaseCondition {
            completion_receipt: id("completion-1869"),
            release_on_cancel: true,
            expires_at_ms: NOW_1869_MS + RESULT_TTL_1869_MS,
        },
    };
    let demanded = demand.dimension;
    let demanded_outcome = outcome.clone();
    let result = DownstreamHeadroomResult {
        schema_version: DOWNSTREAM_HEADROOM_SCHEMA_VERSION,
        request_digest: request.canonical_digest().expect("request digest"),
        binding: input.binding.clone(),
        // One decision per value of the closed denominator.
        decisions: HeadroomDimension::DENOMINATOR
            .iter()
            .map(|dimension| HeadroomDecision {
                dimension: *dimension,
                outcome: if *dimension == demanded {
                    demanded_outcome.clone()
                } else {
                    HeadroomOutcome::NotApplicable {
                        basis: id("basis-1869"),
                    }
                },
            })
            .collect(),
        issued_at_ms: NOW_1869_MS,
        expires_at_ms: NOW_1869_MS + RESULT_TTL_1869_MS,
        measurement_refs: Vec::new(),
        reconciliation_refs: vec![id("reconciliation-1869")],
    };
    let capacity = input.recipe.capacity;
    let mut ledger = HeadroomAllocationLedger::new(capacity);
    // The declared output and review reserves are REFERENCED by their own
    // purposes, never added a second time; the remainder is context occupancy
    // plus the decision-local tail, and the total stays inside the envelope.
    for (purpose, share) in [
        (HeadroomPurpose::ContextOccupancy, 70),
        (HeadroomPurpose::Output, capacity.output_reserve),
        (HeadroomPurpose::ReviewReasoning, capacity.review_reserve),
        (HeadroomPurpose::DecisionTail, 0),
        (HeadroomPurpose::ToolResult, 0),
    ] {
        ledger
            .bind(purpose, share)
            .expect("one allocation per purpose");
    }
    (request, result, ledger)
}

/// A reservation whose demanded dimension the owner GRANTED under the live
/// requester generation: every substantive owner-evidence check in
/// `validate_against` passes, so the composed reserved path reaches selection.
///
/// The permit expires BEFORE the result envelope does
/// ([`PERMIT_TTL_1869_MS`] < [`RESULT_TTL_1869_MS`]). That ordering is what lets a
/// caller clock reading inside the envelope but past the permit reach the
/// permit's own expiry check.
fn granted_reservation_1869(
    input: &AdmissionInput,
) -> (
    DownstreamHeadroomRequest,
    DownstreamHeadroomResult,
    HeadroomAllocationLedger,
) {
    let demand = memory_demand_1869(live_generation_1869());
    let outcome = HeadroomOutcome::Granted {
        reservation: granted_permit_1869(&demand, NOW_1869_MS + PERMIT_TTL_1869_MS),
        admitted_demand: demand.quantity.clone(),
    };
    reservation_1869(input, &demand, &outcome)
}

/// A reservation the owner REFUSED for the demanded dimension. The evidence is
/// otherwise exactly as valid as the granted one, so the only thing that can
/// withhold the decision is the demanded dimension having no reservation.
fn refused_reservation_1869(
    input: &AdmissionInput,
) -> (
    DownstreamHeadroomRequest,
    DownstreamHeadroomResult,
    HeadroomAllocationLedger,
) {
    let demand = memory_demand_1869(live_generation_1869());
    let outcome = HeadroomOutcome::Refused {
        reason: id("memory-refusal-1869"),
        evidence_refs: vec![id("memory-refusal-evidence-1869")],
    };
    reservation_1869(input, &demand, &outcome)
}

/// A reservation whose permit was minted for a SUPERSEDED requester generation.
///
/// The request, the permit and the result digest all agree with each other, so
/// this evidence is valid in form; it is refused only because the live fence's
/// generation has moved on. That is the `requesting_generation_ref` comparison
/// in `validate_against`, which an empty demand list could never reach.
fn superseded_reservation_1869(
    input: &AdmissionInput,
) -> (
    DownstreamHeadroomRequest,
    DownstreamHeadroomResult,
    HeadroomAllocationLedger,
) {
    let demand = memory_demand_1869(ResourceGeneration::new(6).expect("generation"));
    let outcome = HeadroomOutcome::Granted {
        reservation: granted_permit_1869(&demand, NOW_1869_MS + PERMIT_TTL_1869_MS),
        admitted_demand: demand.quantity.clone(),
    };
    reservation_1869(input, &demand, &outcome)
}

/// The granted reservation with the RESULT's own binding fence advanced one task
/// revision past the request's.
///
/// `reservation_1869` clones `input.binding` into both the request and the
/// result, so in every other fixture that comparison is satisfied by
/// construction. This fixture edits ONE hand-written field of the RESULT after
/// the fact — `result.binding.state_fence.task_revision` — and changes nothing
/// else. The request digest still matches, because the digest is taken over the
/// REQUEST, which is untouched; only the `binding != request.binding` arm of
/// `validate_against` can fail.
fn result_fence_mismatch_reservation_1869(
    input: &AdmissionInput,
) -> (
    DownstreamHeadroomRequest,
    DownstreamHeadroomResult,
    HeadroomAllocationLedger,
) {
    let (request, mut result, ledger) = granted_reservation_1869(input);
    result.binding.state_fence.task_revision = Some(TaskRevision::new(9).expect("task revision"));
    (request, result, ledger)
}

/// The granted reservation whose PERMIT was minted for a different profile
/// revision than the request it is matched against.
///
/// `granted_permit_1869` copies `profile_revision` out of the demand's own
/// request, so `CapacityPermitBinding::matches_request` is satisfied by
/// construction everywhere else. This fixture rewrites that ONE field by hand
/// on the issued permit. The permit stays individually legal — `profile_revision`
/// is still a non-blank string, so `CapacityPermitBinding::validate` passes and
/// the decision validator before the match still passes — and it is refused
/// exactly where the permit stops describing the request it claims to answer.
fn permit_profile_mismatch_reservation_1869(
    input: &AdmissionInput,
) -> (
    DownstreamHeadroomRequest,
    DownstreamHeadroomResult,
    HeadroomAllocationLedger,
) {
    let (request, mut result, ledger) = granted_reservation_1869(input);
    for decision in &mut result.decisions {
        if let HeadroomOutcome::Granted { reservation, .. } = &mut decision.outcome {
            "r-other".clone_into(&mut reservation.profile_revision);
        }
    }
    (request, result, ledger)
}

/// The caller's reservation context at the fixture's own clock reading.
///
/// `now_ms` is the value the CALLER supplies; nothing in this crate reads a
/// clock. Asserting it back against `NOW_1869_MS` would compare a field the
/// test just assigned, so nothing here does.
fn headroom_at_ms<'a>(
    request: &'a DownstreamHeadroomRequest,
    result: &'a DownstreamHeadroomResult,
    ledger: &'a HeadroomAllocationLedger,
    now_ms: u64,
) -> HeadroomContext<'a> {
    HeadroomContext {
        request,
        result,
        ledger,
        now_ms,
    }
}

/// The reservation context at the fixture's own clock reading.
fn headroom_1869<'a>(
    request: &'a DownstreamHeadroomRequest,
    result: &'a DownstreamHeadroomResult,
    ledger: &'a HeadroomAllocationLedger,
) -> HeadroomContext<'a> {
    headroom_at_ms(request, result, ledger, NOW_1869_MS)
}

/// Run the composed entrypoint and take its ADMITTED arm as
/// (result, traces, check), panicking on either a transport error or a typed
/// reservation refusal.
///
/// A withheld reservation is `Ok(Refused(..))`, never `Err(..)`, so a caller
/// that reached this helper has already cleared both gates; a `Refused` arm here
/// is the thing under test going wrong, and the message names it.
fn admitted_composition(
    input: &AdmissionInput,
    learning: &LearningGovernance<'_>,
    reservation: &DownstreamReservation<'_>,
    expectation: &str,
) -> (Box<AdmissionResult>, Vec<MaterialRankTrace>, HeadroomCheck) {
    match admit_context_governed(input, learning, reservation).expect(expectation) {
        HeadroomAdmissionOutcome::Admitted {
            result,
            traces,
            check,
        } => (result, traces, check),
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("{expectation}, got refusal {refusal:?}")
        }
    }
}

/// The atom identities of the per-material rank traces of one decision, sorted.
fn traced_atom_ids(traces: &[MaterialRankTrace]) -> Vec<ArtifactId> {
    let mut ids: Vec<_> = traces.iter().map(|trace| trace.atom_id.clone()).collect();
    ids.sort();
    ids
}

/// The typed refusal a stated, unverifiable reservation withheld the composed
/// decision with.
///
/// A withheld reservation is `Ok(Refused(..))`, never `Err(..)`, so this is where
/// the exact contract error a `validate_against` comparison produced becomes
/// observable, carried verbatim in `HeadroomRefusalRecord::error` beside the
/// `reason` the compiler named.
fn withheld_refusal(
    input: &AdmissionInput,
    learning: &LearningGovernance<'_>,
    reservation: &DownstreamReservation<'_>,
    expectation: &str,
) -> HeadroomRefusalRecord {
    match admit_context_governed(input, learning, reservation).expect(expectation) {
        HeadroomAdmissionOutcome::Refused(refusal) => *refusal,
        HeadroomAdmissionOutcome::Admitted { check, .. } => {
            panic!("{expectation}, got an admitted decision {check:?}")
        }
    }
}

/// The admitted atom identities of one decision, for comparing two decisions.
fn admitted_atom_ids(result: &AdmissionResult) -> Vec<ArtifactId> {
    match &result.outcome {
        ContextOutcome::Complete(admitted) => {
            let mut ids: Vec<_> = admitted
                .records
                .iter()
                .map(|record| record.candidate.atom_id.clone())
                .collect();
            ids.sort();
            ids
        }
        ContextOutcome::Incomplete(incomplete) => {
            panic!("covered retrieval must complete, got {incomplete:?}")
        }
    }
}

#[test]
fn marked_atom_admitted_with_owner_issued_permit() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    // Host preflight alone passes on covered input.
    screen_admission_input_learning(&input, &verified, None, NOW_1869)
        .expect("covered input passes preflight");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    match admit_context_with_learning(
        &input,
        presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
        &DownstreamReservation::NotReserved,
    )
    .expect("covered marked atom admits")
    .outcome
    {
        ContextOutcome::Complete(admitted) => {
            assert!(
                admitted
                    .records
                    .iter()
                    .any(|record| record.candidate.atom_id == id("learning-1869")),
                "covered marked atom surfaces in the admitted set"
            );
        }
        ContextOutcome::Incomplete(incomplete) => {
            panic!("covered retrieval must complete, got {incomplete:?}")
        }
    }
}

#[test]
fn expired_mark_refuses_whole_retrieval_and_plain_path_survives() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 - 1));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    assert_eq!(
        admit_context_with_learning(
            &input,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
            &DownstreamReservation::NotReserved,
        ),
        Err(ContextError::InvalidField("learning.expires_at"))
    );
    // Historical behavior is untouched: unmarked atoms decide as before.
    // (Stripping the mark changes atom identity, so bound measurements are
    // rebound exactly as the legitimate producer would emit them.)
    let mut plain = input;
    for candidate in &mut plain.candidates.candidates {
        candidate.learning = None;
    }
    for measurement in &mut plain.measurements {
        let candidate = plain
            .candidates
            .candidates
            .iter()
            .find(|candidate| candidate.atom_id == measurement.atom_id)
            .expect("measured candidate");
        measurement.binding.subject_digest = canonical_digest(candidate).expect("rebound subject");
    }
    assert!(matches!(
        admit_context(&plain).expect("plain path survives").outcome,
        ContextOutcome::Complete(_)
    ));
}

#[test]
fn foreign_task_permit_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("permit targets task-1869-a");
    // Compilation serves another task than the permit target.
    let input = input_with_learning("task-1869-foreign", permit.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    assert_eq!(
        admit_context_with_learning(
            &input,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
            &DownstreamReservation::NotReserved,
        ),
        Err(ContextError::IdentityConflict)
    );
}

#[test]
fn stale_fence_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    // Advance the compilation fence past the admitted one.
    input.binding.state_fence.task_revision = Some(TaskRevision::new(2).expect("task revision"));
    for candidate in &mut input.candidates.candidates {
        candidate.binding.state_fence.task_revision =
            Some(TaskRevision::new(2).expect("task revision"));
    }
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    assert_eq!(
        admit_context_with_learning(
            &input,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
            &DownstreamReservation::NotReserved,
        ),
        Err(ContextError::InvalidFence)
    );
}

#[test]
fn transplanted_permit_digest_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    // Mark cites a DIFFERENT issuance than the verified permit.
    let other = live_permit(&governor, &fence, Some("overlay-other"), None);
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let input = input_with_learning(TASK_1869, other.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    assert_eq!(
        admit_context_with_learning(
            &input,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
            &DownstreamReservation::NotReserved,
        ),
        Err(ContextError::IdentityConflict)
    );
}

#[test]
fn unclosed_reusable_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(
        &governor,
        &fence,
        Some(OVERLAY_1869),
        Some("candidate-1869-a"),
    );
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let learning = input
        .candidates
        .candidates
        .iter_mut()
        .find(|candidate| candidate.atom_id == id("learning-1869"))
        .expect("learning atom");
    learning.learning = Some(LearningProvenance {
        campaign_id: CAMPAIGN_1869.to_string(),
        overlay_id: Some(OVERLAY_1869.to_string()),
        candidate_id: Some("candidate-1869-a".to_string()),
        closure_ref: None,
        owner: Some("governor-1869".to_string()),
        draft: false,
        expires_at_unix_secs: Some(NOW_1869 + 3600),
        permit_digest: permit.digest().to_string(),
    });
    // Rebind the measurement to the remarked candidate.
    for measurement in &mut input.measurements {
        if measurement.atom_id == id("learning-1869") {
            measurement.binding.subject_digest =
                canonical_digest(learning).expect("remarked subject");
        }
    }
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    assert_eq!(
        admit_context_with_learning(
            &input,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
            &DownstreamReservation::NotReserved,
        ),
        Err(ContextError::InvalidField("learning.closure_ref"))
    );
}

/// #1869 DECLARED RESERVATION on the result-only projection:
/// [`admit_context_with_learning`] forwards the reservation arm its CALLER states,
/// so a caller holding an owner-issued reservation can say so on this entrypoint
/// too, and a reservation the owner will not stand behind withholds the decision
/// here as well as on [`admit_context_governed`].
///
/// This is the proof for the signature defect: the arm used to be hardcoded to
/// `NotReserved`, so a caller's reservation was unreachable through this entry.
/// The evidence is SUPERSEDED — request, permit and result digest agree with each
/// other, so it is refused only by the live fence's requester generation inside
/// `DownstreamHeadroomResult::validate_against`. It is valid in form, so if it
/// were ignored the calls below would return admitted results.
///
/// HONEST CEILING: this entrypoint is a RESULT-ONLY projection. It returns
/// `Result<AdmissionResult, ContextError>` and does not surface the `HeadroomCheck`
/// its arm reached, so nothing here asserts on a `HeadroomCheck` value it does not
/// return — and it cannot, because there is none to read. What it can observe is
/// the decision that arm produces: an admitted set, or the typed refusal
/// `into_admission_result` projects out of `ComposedAdmission::Refused`. That
/// refusal is the observable, and it is a real one: it is the reservation's
/// decision, not the learning arm's, which the unreserved arm below proves by
/// admitting the identical input under the identical live carriage.
#[test]
fn learning_entrypoint_forwards_the_declared_reservation_arm() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let (request, result, ledger) = superseded_reservation_1869(&input);
    let headroom = headroom_1869(&request, &result, &ledger);

    // The RESERVED arm: the caller's reservation reaches the composed decision
    // and withholds it. `into_admission_result` projects the typed refusal out of
    // `ComposedAdmission::Refused`, so the caller sees `StaleFloor`.
    assert_eq!(
        admit_context_with_learning(
            &input,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
            &DownstreamReservation::Reserved(&headroom),
        )
        .err(),
        Some(ContextError::StaleFloor),
        "a declared reservation the owner will not stand behind must withhold here too"
    );

    // The UNRESERVED arm, same input, same live carriage: no owner evidence to
    // verify, so the learning arm's accept verdict is what remains observable.
    // This is what makes the refusal above the RESERVATION's decision and not the
    // learning arm's.
    let unreserved = admit_context_with_learning(
        &input,
        presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
        &DownstreamReservation::NotReserved,
    )
    .expect("a live carriage with no declared reservation must admit");
    assert!(
        admitted_atom_ids(&unreserved).contains(&id("learning-1869")),
        "the unreserved arm must admit the covered marked atom"
    );

    // A GRANTED, fully valid reservation on this same entrypoint reaches selection
    // and admits, so the reserved arm above refused because of that reservation's
    // own facts and not because this entrypoint can never carry one.
    let (granted_request, granted_result, granted_ledger) = granted_reservation_1869(&input);
    let granted_headroom = headroom_1869(&granted_request, &granted_result, &granted_ledger);
    let reserved = admit_context_with_learning(
        &input,
        presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
        &DownstreamReservation::Reserved(&granted_headroom),
    )
    .expect("a granted reservation reaches selection on this entrypoint too");
    assert_eq!(
        admitted_atom_ids(&reserved),
        admitted_atom_ids(&unreserved),
        "a granted reservation changes what the decision reports, not what it selects"
    );
}

/// #1869 ORDER: the composed entrypoint runs the ordinary learning refusal
/// BEFORE the bounded headroom gate, so a reservation cannot be a way around it.
///
/// Both calls state a SUPERSEDED reservation: request, permit and result digest
/// all agree with each other, so the evidence is valid in form and would be
/// refused only by the live fence's requester generation, which is inside
/// `validate_against`. That matters for the ORDER claim: if the headroom gate ran
/// first, both calls would return `Ok(HeadroomAdmissionOutcome::Refused(..))` as
/// `Stale`, not the learning error. The reservation being usable is therefore NOT
/// what these two assertions rest on; the ORDER is.
///
/// `admit_context_traced_with_headroom` is the entrypoint the audit named
/// specifically: it presents `LearningGovernance::Unpresented` and a stated
/// reservation, and must still refuse a learning-marked input.
///
/// That this reservation is not inert is proven by
/// `superseded_permit_generation_is_refused_as_stale`: the same fixture under a
/// live carriage withholds the decision as `Stale`.
#[test]
fn reservation_does_not_bypass_the_learning_refusal() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let (request, result, ledger) = superseded_reservation_1869(&input);
    let headroom = headroom_1869(&request, &result, &ledger);

    assert_eq!(
        admit_context_governed(
            &input,
            &LearningGovernance::Unpresented,
            &DownstreamReservation::Reserved(&headroom),
        ),
        Err(ContextError::InvalidField(
            "learning.governed_path_required"
        ))
    );
    assert_eq!(
        admit_context_traced_with_headroom(&input, &headroom),
        Err(ContextError::InvalidField(
            "learning.governed_path_required"
        ))
    );
}

/// #1869 BOTH GATES, reserved path: a learning-marked input with NO live carriage
/// is refused by the learning gate, and the SAME input with a live carriage AND a
/// granted, fully valid reservation reaches selection and admits the marked atom.
///
/// The distinguishing observable is the bounded headroom decision itself. The
/// reserved arm reports `HeadroomCheck::Admitted { occupancy_available }` — the
/// only check this crate can report after it verified real owner evidence — where
/// the unreserved arm can only report `HeadroomCheck::NotReserved`. A caller who
/// reached selection with a reservation nobody verified would get `NotReserved`
/// there instead, and the destructuring below would not fire.
///
/// The learning gate is proved load-bearing on the SAME reserved path by
/// `reservation_does_not_bypass_the_learning_refusal`, so neither arm of the
/// composition is assumed here.
#[test]
fn both_gates_run_on_the_reserved_path() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let (request, result, ledger) = granted_reservation_1869(&input);
    let headroom = headroom_1869(&request, &result, &ledger);

    let (reserved_result, reserved_traces, reserved_check) = admitted_composition(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&headroom),
        "both gates satisfied on the reserved path",
    );

    let HeadroomCheck::Admitted {
        occupancy_available,
    } = reserved_check
    else {
        panic!("a verified reservation must report a proven occupancy, got {reserved_check:?}")
    };
    // The figure is the recipe's own declared envelope minus its declared
    // reserves, derived here from `input.recipe.capacity` rather than read back
    // out of the ledger the same code built.
    assert_eq!(
        occupancy_available,
        input.recipe.capacity.route_capacity
            - input.recipe.capacity.fixed_overhead
            - input.recipe.capacity.output_reserve
            - input.recipe.capacity.review_reserve
    );

    // The covered marked atom was NOT screened away: it is in the admitted set of
    // THAT decision. This observes the accept side only. It cannot detect whether
    // the per-mark screen ran; `per_mark_screen_fires_when_the_carriage_gate_cannot_preempt_it`
    // is what pins the screen itself.
    assert!(
        admitted_atom_ids(&reserved_result).contains(&id("learning-1869")),
        "the covered marked atom must surface in the reserved decision"
    );
    // Conservation across the trace/result join is enforced by production —
    // `build_traces` calls `result.validate_for(input)` before deriving any trace,
    // so a trace can never describe an atom the decision did not carry. That is a
    // fail-closed guard, not an observable this file can contradict, so no
    // trace-set equality is asserted here.
    let trace_ids = traced_atom_ids(&reserved_traces);
    assert!(trace_ids.contains(&id("learning-1869")));

    // Same input, same carriage, no reservation stated: the headroom arm has no
    // owner evidence to verify, so it reports its stated absent state and never a
    // proven occupancy.
    let (unreserved_result, unreserved_traces, unreserved_check) = admitted_composition(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::NotReserved,
        "learning half verifies without a reservation",
    );
    assert_eq!(unreserved_check, HeadroomCheck::NotReserved);
    // For THIS fixture the reservation changes what the decision REPORTS, not what
    // it selects: the two arms reach the same selection and the same per-material
    // traces. Scoped to this fixture on purpose — `check_reserved_occupancy` fits
    // against the reservation-aware occupancy (70 here) rather than the nominal one
    // (90), so a packet whose `required_cost` fell in 71..=90 would admit
    // unreserved and refuse reserved. That is the reservation changing the
    // SELECTION, and no invariant is claimed about it.
    assert_eq!(
        admitted_atom_ids(&reserved_result),
        admitted_atom_ids(&unreserved_result)
    );
    assert_eq!(trace_ids, traced_atom_ids(&unreserved_traces));
}

/// #1869 EXPIRY on the reserved path: under a live owner-issued carriage, the
/// composed entry refuses an EXPIRED mark the same way it does with no
/// reservation stated.
///
/// Named for what it observes. The expiry it refuses on is enforced by
/// `check_governed_carriage`, which runs BEFORE the per-mark screen and reaches
/// the same `ContextError` for the same input — so this test does NOT observe the
/// per-mark screen, and says so rather than borrowing its name. The per-mark
/// screen is pinned separately, by
/// `per_mark_screen_fires_when_the_carriage_gate_cannot_preempt_it`.
///
/// The reservation presented here is GRANTED and fully valid, so this arm cannot
/// be withheld by the headroom gate at all. The refused input differs from the
/// admitted one in the mark's expiry and in nothing else.
#[test]
fn expired_mark_refuses_with_and_without_a_reservation() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let expired = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 - 1));
    let (request, result, ledger) = granted_reservation_1869(&expired);
    let headroom = headroom_1869(&request, &result, &ledger);

    assert_eq!(
        admit_context_governed(
            &expired,
            &LearningGovernance::Presented(presented_1869(
                &governor, &verified, &overlay, &backlog, NOW_1869,
            )),
            &DownstreamReservation::Reserved(&headroom),
        )
        .err(),
        Some(ContextError::InvalidField("learning.expires_at")),
        "the reserved arm must refuse an expired mark before the headroom gate"
    );
    assert_eq!(
        admit_context_governed(
            &expired,
            &LearningGovernance::Presented(presented_1869(
                &governor, &verified, &overlay, &backlog, NOW_1869,
            )),
            &DownstreamReservation::NotReserved,
        )
        .err(),
        Some(ContextError::InvalidField("learning.expires_at")),
        "the unreserved arm must refuse the same mark the same way"
    );
}

/// #1869 PER-MARK SCREEN, the one thing only it can decide.
///
/// `check_governed_admission_carriage` runs `check_governed_carriage` FIRST and
/// the per-mark screen SECOND, and for campaign, task, digest, expiry and closure
/// the carriage check already refuses first with the same `ContextError`. The
/// screen is therefore unpinned by any input whose candidate carries the same
/// fence as the input — which is every input `input_with_learning` builds.
///
/// This fixture is the exception. It advances ONE candidate's OWN
/// `binding.state_fence` past the input's, and nothing else:
///
/// - `check_governed_carriage` cannot see it. Its mark carries only
///   `binding_task_id`, and `verify_learning_ticket` is handed
///   `input.binding.state_fence`, which this fixture leaves untouched — so the
///   ticket still verifies against the live compilation fence.
/// - The per-mark screen sees nothing else: it compares that candidate's fence
///   against the permit's fence and refuses.
///
/// Delete `screen_admission_input_learning` from
/// `src/learning_gate.rs::check_governed_admission_carriage` and this input is
/// admitted — the marked atom reaches the selector with a stale fence. That is
/// the mutation this test exists to catch.
#[test]
fn per_mark_screen_fires_when_the_carriage_gate_cannot_preempt_it() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let mut input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));

    // Only the LEARNING candidate's own fence moves. `input.binding.state_fence`
    // stays at revision 1, so the ticket verifies and the carriage gate passes.
    let learning = input
        .candidates
        .candidates
        .iter_mut()
        .find(|candidate| candidate.atom_id == id("learning-1869"))
        .expect("learning atom");
    learning.binding.state_fence.task_revision = Some(TaskRevision::new(2).expect("task revision"));
    // The atom's own fence is inside its canonical digest, so its identity moved
    // with it: rebind the measurement the legitimate producer would have bound.
    for measurement in &mut input.measurements {
        if measurement.atom_id == id("learning-1869") {
            measurement.binding.subject_digest =
                canonical_digest(learning).expect("rebound subject");
        }
    }

    // The carriage gate alone cannot refuse this input, and says so.
    check_governed_carriage(
        &presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
        &input.binding.state_fence,
        &[CarriageMark {
            campaign_id: CAMPAIGN_1869,
            overlay_id: Some(OVERLAY_1869),
            candidate_id: None,
            closure_ref: None,
            owner: None,
            draft: false,
            expires_at_unix_secs: Some(NOW_1869 + 3600),
            permit_digest: permit.digest(),
            binding_task_id: TASK_1869,
        }],
    )
    .expect("the carriage gate cannot see a candidate-local fence");

    // The composed entry refuses, and the fence comparison in the per-mark screen
    // is the only thing that can produce this exact error for this input.
    assert_eq!(
        admit_context_governed(
            &input,
            &LearningGovernance::Presented(presented_1869(
                &governor, &verified, &overlay, &backlog, NOW_1869,
            )),
            &DownstreamReservation::NotReserved,
        )
        .err(),
        Some(ContextError::InvalidFence),
        "a candidate compiled under another fence must not reach selection"
    );
}

/// #1869 HEADROOM GATE, refusal arm: a reservation IS presented and the owner
/// REFUSED the demanded dimension. The composed decision withholds publication
/// with a TYPED refusal that names the limiting dimension, and no admitted set
/// exists.
///
/// Load-bearing on `check_headroom`: `validate_against` accepts a refused
/// demanded dimension, so the only thing that can withhold here is
/// `headroom_limiting_dimensions` reading the demand and finding no reservation
/// for it. Remove the headroom gate and the reserved arm admits this input.
///
/// The contrast comes from the SAME input and carriage with no reservation
/// stated, which is admitted — so the withholding below is the reservation's
/// decision and not the learning arm's.
#[test]
fn reserved_owner_refusal_names_the_limiting_dimension() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let (request, result, ledger) = refused_reservation_1869(&input);
    let headroom = headroom_1869(&request, &result, &ledger);

    match admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&headroom),
    )
    .expect("a withheld reservation is a typed refusal, not a transport error")
    {
        HeadroomAdmissionOutcome::Refused(refusal) => {
            assert_eq!(
                refusal.reason,
                HeadroomRefusal::Unavailable {
                    dimensions: vec![HeadroomDimension::Memory],
                },
                "the demanded dimension is the one that was withheld"
            );
            // The refusal names the limiting dimension, which is the payload a
            // caller needs in order to narrow or decompose. Nothing is asserted
            // about `attempted_recipe_digest` or `attempted_binding`: production
            // clones both out of this very input, so comparing either against the
            // input would restate the clone rather than observe anything.
        }
        HeadroomAdmissionOutcome::Admitted { check, .. } => {
            panic!("a refused demanded dimension must not admit, got {check:?}")
        }
    }
    // The same input with NO reservation stated is admitted, so the refusal above
    // is the reservation's decision and not the learning arm's: the learning gate
    // passed on this arm (the marked atom is admitted below).
    match admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::NotReserved,
    )
    .expect("no reservation stated must not withhold")
    {
        HeadroomAdmissionOutcome::Admitted { result, check, .. } => {
            assert_eq!(check, HeadroomCheck::NotReserved);
            assert!(admitted_atom_ids(&result).contains(&id("learning-1869")));
        }
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("no reservation stated must not withhold, got {refusal:?}")
        }
    }
}

/// #1869 OWNER EVIDENCE, the two comparisons a self-consistent fixture cannot
/// reach: the result's own binding against the request's, and the owner's permit
/// against the demand it answers.
///
/// Every other reservation fixture in this file is built by cloning one value
/// into the place it is later compared against, so the request-digest, binding,
/// `matches_request` and authority-epoch comparisons are satisfied by
/// construction and deleting any of them changes nothing. These two fixtures
/// break that by hand, one field each, so each comparison below is the only thing
/// that can produce its refusal.
///
/// Both refusals surface as `HeadroomAdmissionOutcome::Refused` carrying a typed
/// `reason` plus the contract error verbatim in `refusal.error`.
#[test]
fn owner_evidence_is_matched_against_the_request_not_against_itself() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));

    // The RESULT reserved under a different task revision than the request it
    // answers: `validate_against`'s binding comparison refuses it as an invalid
    // fence, and `headroom_refusal_reason` names that a stale reservation.
    let (request, result, ledger) = result_fence_mismatch_reservation_1869(&input);
    let mismatched = headroom_1869(&request, &result, &ledger);
    let fence_refusal = withheld_refusal(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&mismatched),
        "a result reserved under another fence must not admit",
    );
    assert_eq!(
        fence_refusal.error,
        ContextError::InvalidFence,
        "the result's binding must equal the request's binding"
    );
    assert!(
        matches!(fence_refusal.reason, HeadroomRefusal::Stale { .. }),
        "an invalid fence reads as a stale reservation, got {:?}",
        fence_refusal.reason
    );

    // The PERMIT was minted for a profile revision the request never named: the
    // permit is individually legal and the request digest still matches, so the
    // only check left is `matches_request`, which refuses it as an identity
    // conflict.
    let (request, result, ledger) = permit_profile_mismatch_reservation_1869(&input);
    let mismatched = headroom_1869(&request, &result, &ledger);
    let profile_refusal = withheld_refusal(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&mismatched),
        "a permit minted for another profile must not admit",
    );
    assert_eq!(
        profile_refusal.error,
        ContextError::IdentityConflict,
        "a permit must match the request it was issued for"
    );
    assert!(
        matches!(
            profile_refusal.reason,
            HeadroomRefusal::IdentityChanged { .. }
        ),
        "a permit for another profile reads as an identity change, got {:?}",
        profile_refusal.reason
    );

    // The unreserved arm admits the identical input under the identical carriage,
    // so both refusals above are the reservation's decision and not the learning
    // arm's.
    let admitted = admitted_composition(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::NotReserved,
        "no reservation stated must not withhold",
    )
    .0;
    assert!(
        admitted_atom_ids(&admitted).contains(&id("learning-1869")),
        "the learning arm accepted this input; the refusals above were the reservation's"
    );
}

/// #1869 HEADROOM GATE, staleness arm: the same GRANTED reservation is admitted
/// at one caller clock reading and refused at another. This is the load-bearing
/// replacement for asserting `headroom.now_ms` against the constant the fixture
/// assigned it from: nothing here reads the clock back out of the evidence, and
/// the decision moves with the caller's reading alone.
///
/// The refusal is TYPED as `HeadroomRefusal::Stale`, because the permit's own
/// expiry is what expired — not the result envelope, which is still open at this
/// reading. That ordering is what makes the reading prove something: only the
/// permit's own `expires_at_ms` can withhold it.
#[test]
fn granted_reservation_is_refused_once_the_callers_clock_passes_the_permit() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let (request, result, ledger) = granted_reservation_1869(&input);

    // Before the permit's own expiry, while the result envelope is still open.
    let live_headroom = headroom_at_ms(&request, &result, &ledger, NOW_1869_MS + 1_000);
    match admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&live_headroom),
    )
    .expect("a live grant at a live reading must admit")
    {
        HeadroomAdmissionOutcome::Admitted { check, .. } => {
            assert!(matches!(check, HeadroomCheck::Admitted { .. }));
        }
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("a live grant at a live reading must admit, got {refusal:?}")
        }
    }

    // One millisecond past the permit's expiry, still inside the result envelope.
    let stale_headroom =
        headroom_at_ms(&request, &result, &ledger, NOW_1869_MS + PERMIT_TTL_1869_MS);
    match admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&stale_headroom),
    )
    .expect("a stale reservation is a typed refusal, not a transport error")
    {
        HeadroomAdmissionOutcome::Refused(refusal) => {
            let reason = refusal.reason;
            assert!(
                matches!(reason, HeadroomRefusal::Stale { .. }),
                "an expired permit is a stale reservation, got {reason:?}"
            );
        }
        HeadroomAdmissionOutcome::Admitted { check, .. } => {
            panic!("an expired permit must not admit, got {check:?}")
        }
    }
}

/// #1869 HEADROOM GATE, supersession arm: the reservation is valid in form — the
/// request, the result digest, the demand and the permit all agree — but the
/// permit was minted for a SUPERSEDED requester generation. The composed decision
/// withholds it as `Stale`.
///
/// This reaches the `requesting_generation_ref` comparison inside
/// `validate_against`. It is also what proves the superseded evidence used by
/// `reservation_does_not_bypass_the_learning_refusal` is not inert: there, the
/// same fixture is withheld by the headroom gate once the learning gate passes.
#[test]
fn superseded_permit_generation_is_refused_as_stale() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let (request, result, ledger) = superseded_reservation_1869(&input);
    let headroom = headroom_1869(&request, &result, &ledger);

    match admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&headroom),
    )
    .expect("a superseded reservation is a typed refusal, not a transport error")
    {
        HeadroomAdmissionOutcome::Refused(refusal) => {
            let reason = refusal.reason;
            assert!(
                matches!(reason, HeadroomRefusal::Stale { .. }),
                "a superseded requester generation is a stale reservation, got {reason:?}"
            );
            assert_eq!(refusal.error, ContextError::StaleFloor);
        }
        HeadroomAdmissionOutcome::Admitted { check, .. } => {
            panic!("a superseded permit must not admit, got {check:?}")
        }
    }
}

/// #1869 NON-DIVERGENCE: the result-only learning projection and the composed
/// entrypoint reach the SAME selection and the SAME learning verdicts from the
/// same closure and the same live carriage.
///
/// The ACCEPT and REFUSE cases are two builds of the same fixture differing only
/// in the mark's expiry, so the contrast cannot come from the fixtures differing
/// in some other field.
#[test]
fn learning_projection_and_composed_entry_reach_the_same_selection() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();

    // ACCEPT verdict, through both entrypoints.
    let covered = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let projection = admit_context_with_learning(
        &covered,
        presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
        &DownstreamReservation::NotReserved,
    )
    .expect("live carriage admits the covered mark");
    let composed = admit_context_governed(
        &covered,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::NotReserved,
    )
    .expect("live carriage admits through the composed entry too");
    let composed_result = match composed {
        HeadroomAdmissionOutcome::Admitted { result, check, .. } => {
            assert_eq!(check, HeadroomCheck::NotReserved);
            *result
        }
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("a live carriage must admit, got {refusal:?}")
        }
    };
    assert_eq!(
        admitted_atom_ids(&projection),
        admitted_atom_ids(&composed_result)
    );
    assert!(
        admitted_atom_ids(&composed_result).contains(&id("learning-1869")),
        "both entrypoints must admit the covered marked atom"
    );

    // REFUSAL verdict, through both entrypoints.
    let expired = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 - 1));
    assert_eq!(
        admit_context_with_learning(
            &expired,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
            &DownstreamReservation::NotReserved,
        )
        .err(),
        Some(ContextError::InvalidField("learning.expires_at")),
        "the result-only projection must refuse the expired mark"
    );
    assert_eq!(
        admit_context_governed(
            &expired,
            &LearningGovernance::Presented(presented_1869(
                &governor, &verified, &overlay, &backlog, NOW_1869,
            )),
            &DownstreamReservation::NotReserved,
        )
        .err(),
        Some(ContextError::InvalidField("learning.expires_at")),
        "the composed entry must refuse the same mark the same way"
    );
}
