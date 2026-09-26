//! Host preflight composition proof for issue #1869 (round 6).
//!
//! Genuine production call path on the native host (never the guest):
//! improvement producer emits a permit-bound marked atom from a closed,
//! backlog-active reusable candidate -> the composed
//! [`compile_learning_context`] entrypoint rebinds the owner-issued permit,
//! preflights the compilation, then invokes the real guest/native
//! retrieval. Fabricated digests, stale fences, and foreign tasks refuse
//! with `native_calls == 0`, proving `admit_context` never ran.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_compiler_wasm::host::compile_learning_context;
use eliot_context_compiler_wasm::{GUEST_ABI_VERSION, GuestRequest, HANDLER_SUBTYPE, WORLD_NAME};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, issue_learning_admission,
};
use eliot_improvement::candidate_bounds::{AdmitOutcome, BoundedBacklog, CandidateBoundPolicy};
use eliot_improvement::{
    ImprovementCandidate, ImprovementSurface, ReplayPlan,
    producer::{LearningProduction, produce_learning_candidate},
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";
const CAMPAIGN_1869: &str = "campaign-1869-a";
const TASK_1869: &str = "task-1869-a";
const OVERLAY_1869: &str = "overlay-1869-live";
const NOW_1869: u64 = 1_800_000_000;

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

fn binding(task: &str, fence: &StateFence) -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new(task).expect("task"),
        attempt_id: AgentAttemptId::new("attempt-1869").expect("attempt"),
        scope_id: WorkScopeId::new("scope-1869").expect("scope"),
        state_fence: fence.clone(),
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

fn plain_candidate(
    context: &ContextBinding,
    atom_id: &str,
    provider_role: ProviderRole,
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
        learning: None,
        loss_policy: LossPolicy::NonDroppable,
        availability: AtomAvailability::PresentCurrent,
        protected: true,
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

fn replay_plan() -> ReplayPlan {
    ReplayPlan {
        fixed_replay_refs: vec!["replay-1869-a".to_string()],
        holdout_refs: vec!["holdout-1869-a".to_string()],
        transfer_refs: vec!["transfer-1869-a".to_string()],
        counter_metric_names: vec!["cost-1869".to_string()],
        verifier_refs: vec!["verifier-1869-a".to_string()],
    }
}

/// Full valid admission input embedding one producer-emitted marked atom
/// plus one required floor atom, all bound to `task`/`fence`.
#[allow(clippy::too_many_lines)]
fn input_with_produced(
    task: &str,
    fence: &StateFence,
    produced: ContextCandidate,
) -> AdmissionInput {
    let context = binding(task, fence);
    let mut required = plain_candidate(
        &context,
        "required-1869",
        role("required-provider", SemanticRole::Goal),
    );
    required.binding = context.clone();
    let mut learning = produced;
    learning.binding = context.clone();
    let requested = vec![
        required.provider_role.clone(),
        learning.provider_role.clone(),
    ];
    // The produced atom arrives Summarizable-capable: admit it through the
    // optional policy exactly like any summarizable atom.
    learning.loss_policy = LossPolicy::Summarizable;
    learning.protected = false;
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
                role: learning.provider_role.role,
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
            requested: vec![required.provider_role.clone()],
            dispositions: vec![ProviderDisposition {
                slot: required.provider_role.clone(),
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

struct Chain {
    governor: Governor,
    fence: StateFence,
    backlog: BoundedBacklog,
    candidate_id: String,
}

fn live_chain() -> Chain {
    let governor = governor_1869();
    let fence = fence_1869();
    let mut backlog = BoundedBacklog::new(vec![CandidateBoundPolicy {
        target_surface: ImprovementSurface::Memory,
        max_active: 8,
        min_value: 1.0,
        governor_authority_ref: "governor-1869".to_string(),
        policy_revision: 1,
    }])
    .expect("policy validates");
    let candidate = ImprovementCandidate::new(
        "project-1869",
        ImprovementSurface::Memory,
        "tighten context budget",
        vec!["retrieval-regret".to_string()],
        vec!["authority-change".to_string()],
        vec!["trace-1869-a".to_string()],
        vec!["ev-1869-chain-a".to_string()],
        replay_plan(),
        BTreeMap::new(),
    )
    .expect("fixture candidate validates");
    let candidate_id = candidate.candidate_id.clone();
    assert!(matches!(
        backlog.admit(candidate, 3.0, Some("governor-1869".to_string())),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    Chain {
        governor,
        fence,
        backlog,
        candidate_id,
    }
}

fn issue_chain(
    chain: &Chain,
    overlay: Option<&str>,
    candidate: Option<&str>,
) -> eliot_governor::LearningAdmissionPermit {
    issue_learning_admission(
        &chain.governor,
        &LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: CAMPAIGN_1869.to_string(),
            target_task_id: TASK_1869.to_string(),
            fence: chain.fence.clone(),
            overlay_id: overlay.map(str::to_string),
            candidate_id: candidate.map(str::to_string),
            scope_ref: "scope-1869".to_string(),
            authority_ref: "governor-1869".to_string(),
            retention_ref: "retention-1869".to_string(),
            evaluator_ref: "evaluator-1869-a".to_string(),
            rollback_ref: "rollback-1869".to_string(),
        },
    )
    .expect("live owner issues")
}

/// Producer -> request -> composed host entrypoint.
fn composed_request(
    chain: &Chain,
    task: &str,
    fence: &StateFence,
) -> (GuestRequest, eliot_governor::LearningAdmissionPermit) {
    use eliot_governor::verify_learning_admission;
    let permit = issue_chain(chain, Some(OVERLAY_1869), Some(&chain.candidate_id.clone()));
    let verified = verify_learning_admission(&chain.governor, &permit, &chain.fence)
        .expect("live owner verifies");
    let atom = produce_learning_candidate(LearningProduction {
        backlog: &chain.backlog,
        candidate_id: &chain.candidate_id,
        closure_ref: "closure-1869-a",
        owner: "governor-1869",
        binding: &binding(TASK_1869, &chain.fence),
        atom_id: "atom-learning-1869",
        provider_role: &role("learning-provider", SemanticRole::Optional),
        source_id: "source-learning-1869",
        source_owner: "learning-pipeline",
        snapshot_id: "snapshot-learning-1869",
        source_revision: "closure-1869-a",
        content: "local update: tighten context budget",
        overlay_id: Some(OVERLAY_1869),
        expires_at_unix_secs: Some(NOW_1869 + 3600),
        measurement_digest: &"d".repeat(64),
        measurement_serializer: "json-v1",
        verified: &verified,
        // The produced atom is always for the local permit's own target task
        // here, so no distinct cross-task carryover is presented.
        cross_task: None,
    })
    .expect("covered production emits");
    let input = input_with_produced(task, fence, atom);
    (
        GuestRequest {
            abi_version: GUEST_ABI_VERSION,
            world: WORLD_NAME.to_string(),
            handler_subtype: HANDLER_SUBTYPE.to_string(),
            input,
        },
        permit,
    )
}

#[test]
fn producer_to_consumer_chain_admits() {
    let chain = live_chain();
    let (request, permit) = composed_request(&chain, TASK_1869, &chain.fence.clone());
    let response = compile_learning_context(&chain.governor, &permit, None, &request, NOW_1869);
    assert_eq!(response.error, None);
    assert_eq!(response.native_calls, 1);
    let result = response.result.expect("admission result present");
    match result.outcome {
        ContextOutcome::Complete(admitted) => {
            assert!(
                admitted
                    .records
                    .iter()
                    .any(|record| record.candidate.atom_id == id("atom-learning-1869")),
                "producer-emitted atom surfaces admitted"
            );
        }
        ContextOutcome::Incomplete(incomplete) => {
            panic!("covered chain must complete, got {incomplete:?}")
        }
    }
}

#[test]
fn fabricated_digest_refuses_before_native_call() {
    let chain = live_chain();
    // Mark cites another issuance; compose against this permit.
    let other = issue_chain(
        &chain,
        Some("overlay-other"),
        Some(&chain.candidate_id.clone()),
    );
    let (mut request, permit) = composed_request(&chain, TASK_1869, &chain.fence.clone());
    for candidate in &mut request.input.candidates.candidates {
        if let Some(mark) = &mut candidate.learning {
            mark.permit_digest = other.digest().to_string();
        }
    }
    // Rebind measurements to the remarked atoms, so only the digest
    // binding is under test (not measurement closure).
    for measurement in &mut request.input.measurements {
        let candidate = request
            .input
            .candidates
            .candidates
            .iter()
            .find(|candidate| candidate.atom_id == measurement.atom_id)
            .expect("measured candidate");
        measurement.binding.subject_digest = canonical_digest(candidate).expect("remarked subject");
    }
    let response = compile_learning_context(&chain.governor, &permit, None, &request, NOW_1869);
    assert_eq!(response.native_calls, 0);
    assert!(
        response.result.is_none(),
        "refused retrieval admits nothing"
    );
    assert!(response.error.is_some(), "refusal is typed");
}

#[test]
fn stale_fence_and_foreign_task_refuse_before_native_call() {
    let chain = live_chain();
    // Stale fence: advance the compilation fence past the admitted one.
    let (mut request, permit) = composed_request(&chain, TASK_1869, &chain.fence.clone());
    let mut drifted = chain.fence.clone();
    drifted.task_revision = Some(TaskRevision::new(2).expect("task revision"));
    request.input.binding.state_fence = drifted.clone();
    for candidate in &mut request.input.candidates.candidates {
        candidate.binding.state_fence = drifted.clone();
    }
    let response = compile_learning_context(&chain.governor, &permit, None, &request, NOW_1869);
    assert_eq!(response.native_calls, 0);
    assert!(response.result.is_none());
    assert!(response.error.is_some());

    // Foreign task: same permit, compilation for another task.
    let (request, permit) = composed_request(&chain, "task-1869-foreign", &chain.fence.clone());
    let response = compile_learning_context(&chain.governor, &permit, None, &request, NOW_1869);
    assert_eq!(response.native_calls, 0);
    assert!(response.result.is_none());
    assert!(response.error.is_some());
}
