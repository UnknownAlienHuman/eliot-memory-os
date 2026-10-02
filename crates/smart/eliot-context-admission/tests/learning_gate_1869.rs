//! Learning retrieval screen proof for issue #1869 (round 5).
//!
//! Genuine issuer-to-consumer path with intrinsic provenance: learning marks
//! ride on the candidate itself (`ContextCandidate.learning`, digest-covered)
//! — there is no sidecar to omit. The governed retrieval entrypoint
//! [`admit_context_with_learning`] admits covered marked atoms through the
//! unchanged [`admit_context`] decision and refuses expired, foreign-task,
//! stale-fence, transplanted-digest, and unclosed-reusable inputs before any
//! value surfaces. Plain [`admit_context`] behavior is preserved bit-for-bit
//! for unmarked atoms.

//! The #1869 composition proof below drives the composed entrypoint through a
//! `DownstreamReservation::Reserved` arm, so the owner-evidence fixtures build
//! the owner's own `CapacityRequest` and `CapacityPermitBinding` vocabulary
//! (`eliot-runtime-contracts`, a dev-dependency of this package). That is what a
//! granted dimension needs: `DownstreamHeadroomRequest::validate` refuses an empty
//! demand list, so a fixture without one would leave every substantive
//! owner-evidence check unreachable.
//!
//! Not claimed here: [`admit_context_with_learning`] presents
//! `DownstreamReservation::NotReserved` by design (its own module documents that
//! residual), so nothing below claims to cover a reserved variant of that
//! entrypoint. The reserved arms are driven through [`admit_context_governed`],
//! which is the composed entry its production caller uses.
//!
//! Host-only proof: the gated entrypoints below require Governor evidence,
//! which never enters the wasm32 guest contour.
#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_admission::learning_gate::admit_context_with_learning;
use eliot_context_admission::{
    DownstreamReservation, HeadroomAdmissionOutcome, HeadroomCheck, HeadroomContext,
    LearningGovernance, admit_context, admit_context_governed, admit_context_traced_with_headroom,
    screen_admission_input_learning,
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
use eliot_improvement::{PresentedLearning, datetime_from_unix};
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

/// The clock reading this fixture hands to the composition as `now_ms`.
///
/// It is a value the test supplies, not a reading this crate takes: nothing in
/// `eliot-context-admission` reads a clock, so staleness is decided against
/// whatever the caller passes. Cases that need a different reading pass one
/// explicitly (see `headroom_at_ms`).
const NOW_1869_MS: u64 = 1_800_000_000_000;

/// The requester generation the live fence carries, and the generation a
/// reservation has to be issued under to count as current.
fn live_generation_1869() -> ResourceGeneration {
    ResourceGeneration::new(7).expect("generation")
}

/// How long the owner-minted PERMIT stays live after issuance, in milliseconds.
///
/// Deliberately shorter than [`RESULT_TTL_1869_MS`], so a caller clock reading
/// can sit inside the result envelope and past the permit at the same time. That
/// is the reading that makes the permit's own expiry - rather than the result's -
/// the thing that withholds the decision.
const PERMIT_TTL_1869_MS: u64 = 30_000;

/// How long the owner-issued RESULT stays valid, in milliseconds.
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

/// Minimal valid input with one required floor atom plus one intrinsically
/// marked learning atom. The mark cites `permit_digest`.
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
    let requested = vec![required_role.clone(), learning_role.clone()];
    let denominator = ProviderRoleDenominator {
        requested: requested.clone(),
        dispositions: requested
            .iter()
            .cloned()
            .map(|slot| ProviderDisposition {
                slot,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            })
            .collect(),
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
            candidates: vec![required.clone(), learning.clone()],
            denominator,
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
                    atom_id: learning.atom_id.clone(),
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
            atom_id: learning.atom_id.clone(),
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
    issue_learning_admission(&governor, &owner_claim(fence, overlay, candidate))
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

/// The frozen owner reference for the demanded dimension's bottleneck, read out
/// of the owner's own frozen map rather than written here.
fn memory_owner_1869() -> &'static str {
    frozen_bottleneck_owner_map()
        .into_iter()
        .find(|row| row.bottleneck == CapacityBottleneck::ProtectedMemoryBytes)
        .expect("the frozen map has a protected-memory row")
        .owner
}

/// One demanded `MEMORY` dimension plus the exact owner request submitted for
/// it.
///
/// `HeadroomDemand::request` is the owner's own `CapacityRequest`, not a summary
/// of it: a result can only be matched back through
/// `CapacityPermitBinding::matches_request`, so the demand, the permit and the
/// request digest have to agree on operation identity, bottleneck, unit, amount,
/// requester generation, Authority Epoch and profile revision. That is why this
/// fixture names `eliot-runtime-contracts` types directly (a dev-dependency of
/// this package) instead of approximating the demand.
///
/// `generation` is the requester generation the demand was submitted under. A
/// demand submitted under a generation other than the live fence's is how the
/// superseded-permit case below is built.
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
/// capacity class derived from the demand's own operation tag rather than
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
/// cites this request's own canonical digest, the ledger binds each purpose
/// once, referencing the declared output and review reserves rather than adding
/// them a second time, and the owner's answer carries a permit for the demand
/// that was actually submitted.
///
/// The demand list is NON-EMPTY on purpose.
/// `DownstreamHeadroomRequest::validate` refuses an empty list
/// (`ContextError::Bounds`) and `validate_against` runs that validator FIRST, so
/// an empty list leaves every substantive owner-evidence check unreachable: no
/// digest comparison, no binding/fence comparison, no expiry check, no decisions
/// denominator, no permit epoch/generation check. With one demanded dimension
/// each of those checks executes.
///
/// `outcome` is the owner's answer FOR THE DEMANDED DIMENSION. Every other value
/// of the closed denominator is recorded as `NotApplicable`, because an
/// undemanded dimension must carry no reservation at all - a permit nobody asked
/// for is not headroom for this pipeline.
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
    // plus the decision-local tail.
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
/// caller clock reading inside the envelope but past the permit reach the permit's
/// own expiry check, which is the staleness case the composition has to decide.
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
/// generation has moved on. That is the `requesting_generation_ref` comparison in
/// `validate_against`, which an empty demand list could never reach.
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

/// The caller's reservation context at the fixture's own clock reading.
///
/// `now_ms` is the value the CALLER supplies; nothing in this crate reads a
/// clock. Passing a different reading here is how the staleness cases below are
/// built, which is also why asserting `headroom.now_ms` against this constant
/// would only compare a field the test just assigned.
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
        ),
        Err(ContextError::InvalidField("learning.closure_ref"))
    );
}

/// #1869: BOTH gates really run on the RESERVED path, and the reserved arm
/// yields an outcome the unreserved arm cannot produce.
///
/// The audit-defect pair as executable proof. This test is driven through a
/// `DownstreamReservation::Reserved` carrying owner evidence that passes every
/// substantive check in `DownstreamHeadroomResult::validate_against`, so
/// `check_headroom` is genuinely reached rather than skipped:
/// `HeadroomCheck::NotReserved` cannot be produced from this arm, and
/// `HeadroomAdmissionOutcome::Refused` cannot either, so removing the headroom
/// gate from the composed path (leaving `HeadroomCheck::NotReserved` for a
/// reservation nobody verified) fails this test rather than passing it.
///
/// The learning gate is proved load-bearing on the SAME reserved path: a
/// learning-marked input with NO live carriage refuses with
/// `learning.governed_path_required` even though the reservation is perfectly
/// valid. That is the mutation the headroom entry must not be able to bypass, and
/// deleting `check_learning_carriage` from the composed path makes this arm
/// admit, which fails here.
///
/// This crate has NO selection counter and its selector is pure and stateless,
/// so "exactly one selection" is not a measurable claim and is NOT asserted as
/// one. What IS asserted is the observable that differs: the reserved arm
/// reports a proven occupancy figure (`HeadroomCheck::Admitted`) where the
/// unreserved arm can only report `HeadroomCheck::NotReserved`, and the reserved
/// arm's admitted set is the SAME selection the unreserved arm reaches - the
/// reservation changes what the decision REPORTS, not which material it selects.
#[test]
fn both_gates_run_on_the_reserved_path_and_selection_is_unchanged() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
    let (request, result, ledger) = granted_reservation_1869(&input);
    let headroom = headroom_1869(&request, &result, &ledger);

    // Gate 1, the LEARNING gate, on the reserved path: a valid reservation does
    // not substitute for the carriage. `check_learning_carriage` runs before the
    // headroom gate, so this is the error this call returns.
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

    // Gate 2, the HEADROOM gate, on the same reserved path with the live
    // carriage: the owner-evidence checks pass and the reserved arm admits.
    let reserved = admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&headroom),
    )
    .expect("both gates satisfied on the reserved path");
    // Same input, same carriage, no reservation stated: the headroom arm then has
    // no owner evidence to verify and reports its stated absent state.
    let unreserved = admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::NotReserved,
    )
    .expect("learning half verifies without a reservation");

    let (reserved_result, reserved_traces, reserved_check) = match reserved {
        HeadroomAdmissionOutcome::Admitted {
            result,
            traces,
            check,
        } => (result, traces, check),
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("both gates satisfied, got refusal {refusal:?}")
        }
    };
    let (unreserved_result, unreserved_traces, unreserved_check) = match unreserved {
        HeadroomAdmissionOutcome::Admitted {
            result,
            traces,
            check,
        } => (result, traces, check),
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("no reservation stated must not withhold, got {refusal:?}")
        }
    };

    assert_eq!(unreserved_check, HeadroomCheck::NotReserved);
    // `NotReserved` reports no occupancy precisely because none was proven, so
    // the reserved arm is not reading as the unreserved one, and neither check
    // withholds.
    assert!(unreserved_check.refusal().is_none());
    assert!(reserved_check.refusal().is_none());
    // The distinguishing observable. `Admitted { occupancy_available }` is the
    // only check this crate can report after it verified owner evidence; a
    // caller who reached selection with a reservation nobody checked would get
    // `NotReserved` here instead, and this panic would fire.
    let HeadroomCheck::Admitted {
        occupancy_available,
    } = reserved_check
    else {
        panic!("a verified reservation must report a proven occupancy")
    };
    // The figure is the recipe's own declared envelope minus the declared
    // reserves, which is what the ledger hands the gate; it is not a grant the
    // test chose.
    assert_eq!(
        occupancy_available,
        input.recipe.capacity.route_capacity
            - input.recipe.capacity.fixed_overhead
            - input.recipe.capacity.output_reserve
            - input.recipe.capacity.review_reserve
    );

    // The learning gate's per-mark screen really ran on the reserved path: the
    // marked atom is in the admitted set of THAT decision. (The refusal above
    // proves the gate ran; this proves it did not screen the mark away.)
    let reserved_ids = admitted_atom_ids(&reserved_result);
    assert!(
        reserved_ids.contains(&id("learning-1869")),
        "the covered marked atom must surface in the reserved decision"
    );
    // The traces belong to THAT decision: the trace atom set is exactly the
    // decision atom set of the reserved result, and the marked atom is among
    // them. This is the trace-to-result join, not a candidate count.
    let mut trace_ids: Vec<_> = reserved_traces.iter().map(|t| t.atom_id.clone()).collect();
    trace_ids.sort();
    let mut decision_ids: Vec<_> = reserved_result
        .evidence
        .decisions
        .iter()
        .map(|decision| decision.atom_id.clone())
        .collect();
    decision_ids.sort();
    assert_eq!(trace_ids, decision_ids);
    assert!(trace_ids.contains(&id("learning-1869")));
    // A reservation changes what the decision REPORTS, not what it selects: the
    // two arms reach the SAME selection and the same per-material traces.
    assert_eq!(reserved_ids, admitted_atom_ids(&unreserved_result));
    let mut unreserved_trace_ids: Vec<_> = unreserved_traces
        .iter()
        .map(|t| t.atom_id.clone())
        .collect();
    unreserved_trace_ids.sort();
    assert_eq!(trace_ids, unreserved_trace_ids);
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

/// #1869 REFUSAL: a reservation IS presented, no live learning carriage is, and
/// the input carries a learning mark. The ordinary learning refusal applies and
/// names the missing EVIDENCE (`learning.governed_path_required`) - it is not a
/// missing function, not a headroom refusal, and not a selection.
///
/// This is the audit defect directly: the headroom entry must not reach the
/// selector without the learning refusal.
///
/// The reservation used here is a real, fully VALID owner answer - request,
/// result digest, demand and permit all agree, and the only thing wrong with it
/// is that its permit was minted for a superseded requester generation. That
/// matters for the ORDER claim: this evidence WOULD withhold the decision if the
/// headroom gate ran first, so the observed `Err(learning.governed_path_required)`
/// can only be produced by the learning gate running first. Delete
/// `check_learning_carriage` and this call returns
/// `Ok(Refused(Stale))` instead; swap the two gates and it does the same.
#[test]
fn reserved_headroom_without_carriage_refuses_on_missing_evidence() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let (request, result, ledger) = superseded_reservation_1869(&input);
    let headroom = headroom_1869(&request, &result, &ledger);

    // The learning gate refuses FIRST, so the reservation evidence is never the
    // thing that decided this. That this evidence is not inert is proven by
    // `superseded_permit_generation_is_refused_as_stale`: the same fixture under
    // a live carriage withholds the decision as `Stale`.
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
    // The same guarantee on the headroom-only projection of the composed entry:
    // a learning-marked input cannot slip through by arriving with a reservation
    // and without the carriage.
    assert_eq!(
        admit_context_traced_with_headroom(&input, &headroom),
        Err(ContextError::InvalidField(
            "learning.governed_path_required"
        ))
    );
}

/// #1869 NON-DIVERGENCE: the two entrypoints run the SAME composition, so the
/// learning arm's verdict is the same whether or not a reservation is presented.
///
/// The reservation here is VALID and GRANTED, so the reserved arm reaches
/// selection instead of refusing. That is what makes this test non-vacuous for
/// the learning gate: the learning arm's ACCEPT verdict is observable on the
/// reserved path (the covered marked atom is in that decision's admitted set), and
/// the learning arm's REFUSAL verdict is observable there too (an expired mark
/// refuses identically with and without a reservation). A reservation changes
/// only what the headroom arm reports.
#[test]
fn learning_path_and_headroom_path_do_not_diverge() {
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

    // ACCEPT verdict of the learning arm, on both reservation arms.
    let with_reservation = admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::Reserved(&headroom),
    )
    .expect("live carriage and granted reservation");
    let without_reservation = admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::NotReserved,
    )
    .expect("live carriage");

    let (reserved_result, reserved_check) = match with_reservation {
        HeadroomAdmissionOutcome::Admitted { result, check, .. } => (*result, check),
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("a granted reservation must admit, got refusal {refusal:?}")
        }
    };
    let (unreserved_result, unreserved_check) = match without_reservation {
        HeadroomAdmissionOutcome::Admitted { result, check, .. } => (*result, check),
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("no reservation stated must not withhold, got {refusal:?}")
        }
    };
    // The learning arm ACCEPTED on both arms, and the covered marked atom is in
    // BOTH admitted sets: the same selection, reached through both entries.
    assert!(matches!(reserved_check, HeadroomCheck::Admitted { .. }));
    assert_eq!(unreserved_check, HeadroomCheck::NotReserved);
    assert_eq!(
        admitted_atom_ids(&reserved_result),
        admitted_atom_ids(&unreserved_result)
    );
    assert!(
        admitted_atom_ids(&reserved_result).contains(&id("learning-1869")),
        "the learning arm's accept verdict must be visible on the reserved path"
    );

    // REFUSAL verdict of the learning arm, on both reservation arms. An expired
    // mark under the same live carriage is refused identically whether or not a
    // reservation is presented, and identically whether the entry is the composed
    // one or the result-only learning projection.
    let expired = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 - 1));
    let (expired_request, expired_result, expired_ledger) = granted_reservation_1869(&expired);
    let expired_headroom = headroom_1869(&expired_request, &expired_result, &expired_ledger);
    assert_eq!(
        admit_context_governed(
            &expired,
            &LearningGovernance::Presented(presented_1869(
                &governor, &verified, &overlay, &backlog, NOW_1869,
            )),
            &DownstreamReservation::Reserved(&expired_headroom),
        )
        .err(),
        Some(ContextError::InvalidField("learning.expires_at")),
        "the reserved arm must refuse an expired mark the same way"
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
        "the unreserved arm must refuse an expired mark the same way"
    );
    assert_eq!(
        admit_context_with_learning(
            &expired,
            presented_1869(&governor, &verified, &overlay, &backlog, NOW_1869),
        )
        .err(),
        Some(ContextError::InvalidField("learning.expires_at")),
        "the result-only learning projection must refuse it the same way"
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
/// for it. Remove the headroom gate and the reserved arm admits this input
/// instead, which fails here.
#[test]
fn reserved_owner_refusal_names_the_limiting_dimension() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
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
            // The refusal carries what the caller needs to narrow or decompose.
            assert_eq!(refusal.attempted_recipe_digest, input.recipe.recipe_sha256);
            assert_eq!(refusal.attempted_binding, input.binding);
        }
        HeadroomAdmissionOutcome::Admitted { check, .. } => {
            panic!("a refused demanded dimension must not admit, got {check:?}")
        }
    }
    // The same input with NO reservation stated is admitted, so the refusal above
    // is the reservation's decision and not the learning arm's: the learning gate
    // passed on this arm (the marked atom is admitted below).
    let unreserved = admit_context_governed(
        &input,
        &LearningGovernance::Presented(presented_1869(
            &governor, &verified, &overlay, &backlog, NOW_1869,
        )),
        &DownstreamReservation::NotReserved,
    )
    .expect("no reservation stated must not withhold");
    match unreserved {
        HeadroomAdmissionOutcome::Admitted { result, check, .. } => {
            assert_eq!(check, HeadroomCheck::NotReserved);
            assert!(admitted_atom_ids(&result).contains(&id("learning-1869")));
        }
        HeadroomAdmissionOutcome::Refused(refusal) => {
            panic!("no reservation stated must not withhold, got {refusal:?}")
        }
    }
}

/// #1869 HEADROOM GATE, staleness arm: the same GRANTED reservation is admitted
/// at one caller clock reading and refused at another. This is the load-bearing
/// replacement for asserting `headroom.now_ms` against the constant the fixture
/// assigned it from: nothing here reads the clock back out of the evidence, and
/// the decision moves with the caller's reading alone.
///
/// The refusal is TYPED as `HeadroomRefusal::Stale`, because the permit's own
/// expiry is what expired - not the result envelope, which is still open at this
/// reading.
#[test]
fn granted_reservation_is_refused_once_the_callers_clock_passes_the_permit() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
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

/// #1869 HEADROOM GATE, supersession arm: the reservation is valid in form - the
/// request, the result digest, the demand and the permit all agree - but the
/// permit was minted for a SUPERSEDED requester generation. The composed decision
/// withholds it as `Stale`.
///
/// This reaches the `requesting_generation_ref` comparison inside
/// `validate_against`, which an empty demand list made unreachable.
#[test]
fn superseded_permit_generation_is_refused_as_stale() {
    let governor = governor_1869();
    let fence = fence_1869();
    let permit = live_permit(&governor, &fence, Some(OVERLAY_1869), None);
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let input = input_with_learning(TASK_1869, permit.digest(), Some(NOW_1869 + 3600));
    let overlay = live_overlay_1869(&fence);
    let backlog = BoundedBacklog::default();
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
