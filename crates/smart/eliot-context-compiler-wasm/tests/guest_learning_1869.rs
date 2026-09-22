//! In-guest learning ticket enforcement proof for issue #1869 (round 7).
//!
//! Genuine guest contour: the real `run` entrypoint (native execution of
//! guest logic) refuses learning-marked atoms without covering owner-minted
//! tickets, with tampered or transplanted tickets, and for foreign tasks —
//! all with `native_calls == 0`, proving `admit_context` never ran. A
//! covered input admitted through tickets issued by the real [`Governor`]
//! owner completes. Host-only test (Governor evidence never enters the
//! guest build); the guest code under test imports contracts only.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_compiler_wasm::{
    GUEST_ABI_VERSION, HANDLER_SUBTYPE, WORLD_NAME, GuestRequest, handle_request_typed,
};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, issue_learning_ticket,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";
const CAMPAIGN_1869: &str = "campaign-1869-a";
const TASK_1869: &str = "task-1869-a";
const OVERLAY_1869: &str = "overlay-1869-live";

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
    learning: Option<LearningProvenance>,
) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id(atom_id),
        provider_role,
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
        loss_policy: LossPolicy::Summarizable,
        availability: AtomAvailability::PresentCurrent,
        protected: false,
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

fn mark(digest_value: &str) -> LearningProvenance {
    LearningProvenance {
        campaign_id: CAMPAIGN_1869.to_string(),
        overlay_id: Some(OVERLAY_1869.to_string()),
        candidate_id: None,
        closure_ref: None,
        owner: None,
        draft: false,
        expires_at_unix_secs: Some(1_800_003_600),
        permit_digest: digest_value.to_string(),
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

/// Compact valid input: required floor atom plus marked learning atom plus
/// the presented tickets. The `task` parameter re-binds coherently.
fn input_with_mark(
    task: &str,
    permit_digest: &str,
    tickets: Vec<LearningAdmissionTicket>,
) -> AdmissionInput {
    let context = binding(task);
    let required_role = role("required-provider", SemanticRole::Goal);
    let learning_role = role("learning-provider", SemanticRole::Optional);
    let required = candidate(&context, "required-1869", required_role.clone(), None);
    // Required atom stays loss-protected on the floor.
    let mut required = required;
    required.loss_policy = LossPolicy::NonDroppable;
    required.protected = true;
    let learning = candidate(
        &context,
        "learning-1869",
        learning_role.clone(),
        Some(mark(permit_digest)),
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
        learning_tickets: tickets,
    }
}

fn owner_ticket(fence: &StateFence, overlay: Option<&str>) -> LearningAdmissionTicket {
    issue_learning_ticket(
        &governor_1869(),
        &LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: CAMPAIGN_1869.to_string(),
            target_task_id: TASK_1869.to_string(),
            fence: fence.clone(),
            overlay_id: overlay.map(str::to_string),
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

fn request_for(task: &str, permit_digest: &str, tickets: Vec<LearningAdmissionTicket>) -> GuestRequest {
    GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_string(),
        handler_subtype: HANDLER_SUBTYPE.to_string(),
        input: input_with_mark(task, permit_digest, tickets),
    }
}

#[test]
fn covered_mark_admits_through_guest() {
    let fence = fence_1869();
    let ticket = owner_ticket(&fence, Some(OVERLAY_1869));
    let request = request_for(TASK_1869, &ticket.digest.clone(), vec![ticket]);
    let response = handle_request_typed(&request);
    assert_eq!(response.error, None);
    assert_eq!(response.native_calls, 1);
    let result = response.result.expect("admission result present");
    match result.outcome {
        ContextOutcome::Complete(admitted) => {
            assert!(
                admitted
                    .records
                    .iter()
                    .any(|record| record.candidate.atom_id == id("learning-1869")),
                "covered marked atom surfaces admitted"
            );
        }
        ContextOutcome::Incomplete(incomplete) => {
            panic!("covered guest retrieval must complete, got {incomplete:?}")
        }
    }
}

#[test]
fn missing_ticket_refuses_before_native_call() {
    let fence = fence_1869();
    let ticket = owner_ticket(&fence, Some(OVERLAY_1869));
    let request = request_for(TASK_1869, &ticket.digest.clone(), Vec::new());
    let response = handle_request_typed(&request);
    assert_eq!(response.native_calls, 0);
    assert!(response.result.is_none());
    assert!(response.error.is_some(), "missing ticket is typed");
}

#[test]
fn tampered_and_transplanted_tickets_refused() {
    let fence = fence_1869();
    let ticket = owner_ticket(&fence, Some(OVERLAY_1869));
    // Tampered subject: digest no longer recomputes.
    let mut forged = ticket.clone();
    forged.overlay_id = Some("overlay-forged".to_string());
    let response =
        handle_request_typed(&request_for(TASK_1869, &ticket.digest.clone(), vec![forged]));
    assert_eq!(response.native_calls, 0);
    assert!(response.result.is_none());

    // Transplanted issuance: genuine ticket for another overlay.
    let other = owner_ticket(&fence, Some("overlay-other"));
    let response = handle_request_typed(&request_for(
        TASK_1869,
        &other.digest.clone(),
        vec![other],
    ));
    assert_eq!(response.native_calls, 0);
    assert!(response.result.is_none());
}

#[test]
fn foreign_task_refused_in_guest() {
    let fence = fence_1869();
    let ticket = owner_ticket(&fence, Some(OVERLAY_1869));
    let request = request_for("task-1869-foreign", &ticket.digest.clone(), vec![ticket]);
    let response = handle_request_typed(&request);
    assert_eq!(response.native_calls, 0);
    assert!(response.result.is_none());
}
