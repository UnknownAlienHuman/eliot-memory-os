//! Learning retrieval screen proof for issue #1869 (round 4).
//!
//! Genuine issuer-to-consumer path: permits are minted by the real
//! [`Governor`] owner and verified against live owner state; the governed
//! retrieval entrypoint [`admit_context_with_learning`] admits covered
//! learning atoms through the unchanged [`admit_context`] decision and
//! refuses expired, foreign-task, stale-fence, and unclosed-reusable inputs
//! before any value surfaces. Plain [`admit_context`] behavior is preserved
//! bit-for-bit when no learning claims are present.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_admission::admit_context;
use eliot_context_admission::learning_gate::{LearningAtomClaim, admit_context_with_learning};
use eliot_context_contracts::*;
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision,
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
    fence.task_revision = Some(eliot_contracts::TaskRevision::new(1).expect("task revision"));
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

/// Minimal valid input: one required floor atom plus one learning-declared
/// optional atom. The `task` parameter re-binds every identity coherently.
fn input_with_learning(task: &str) -> AdmissionInput {
    let context = binding(task);
    let required_role = role("required-provider", SemanticRole::Goal);
    let learning_role = role("learning-provider", SemanticRole::Optional);
    let required = candidate(
        &context,
        "required-1869",
        required_role.clone(),
        LossPolicy::NonDroppable,
        true,
    );
    let learning = candidate(
        &context,
        "learning-1869",
        learning_role.clone(),
        LossPolicy::Summarizable,
        false,
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

fn atom_claim(expires_at_unix_secs: Option<u64>) -> LearningAtomClaim {
    LearningAtomClaim {
        campaign_id: CAMPAIGN_1869.to_string(),
        overlay_id: Some(OVERLAY_1869.to_string()),
        candidate_id: None,
        closure_ref: None,
        owner: None,
        draft: false,
        expires_at_unix_secs,
    }
}

#[test]
fn learning_atom_admitted_with_owner_issued_permit() {
    let governor = governor_1869();
    let fence = fence_1869();
    let input = input_with_learning(TASK_1869);
    let permit =
        issue_learning_admission(&governor, &owner_claim(&fence, Some(OVERLAY_1869), None))
            .expect("live owner issues");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut claims = BTreeMap::new();
    claims.insert(id("learning-1869"), atom_claim(Some(NOW_1869 + 3600)));
    match admit_context_with_learning(&input, &claims, &verified, NOW_1869)
        .expect("covered learning atom admits")
        .outcome
    {
        ContextOutcome::Complete(admitted) => {
            assert!(
                admitted
                    .records
                    .iter()
                    .any(|record| record.candidate.atom_id == id("learning-1869")),
                "covered learning atom surfaces in the admitted set"
            );
        }
        ContextOutcome::Incomplete(incomplete) => {
            panic!("covered retrieval must complete, got {incomplete:?}")
        }
    }
}

#[test]
fn expired_overlay_refuses_whole_retrieval_and_plain_path_survives() {
    let governor = governor_1869();
    let fence = fence_1869();
    let input = input_with_learning(TASK_1869);
    let permit =
        issue_learning_admission(&governor, &owner_claim(&fence, Some(OVERLAY_1869), None))
            .expect("live owner issues");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut claims = BTreeMap::new();
    claims.insert(id("learning-1869"), atom_claim(Some(NOW_1869 - 1)));
    assert_eq!(
        admit_context_with_learning(&input, &claims, &verified, NOW_1869),
        Err(ContextError::InvalidField("learning.expires_at"))
    );
    // Historical behavior is untouched: the same input without learning
    // claims decides exactly as before.
    assert!(matches!(
        admit_context(&input).expect("plain path survives").outcome,
        ContextOutcome::Complete(_)
    ));
}

#[test]
fn foreign_task_permit_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    // Compilation serves another task than the permit target.
    let input = input_with_learning("task-1869-foreign");
    let permit =
        issue_learning_admission(&governor, &owner_claim(&fence, Some(OVERLAY_1869), None))
            .expect("permit targets task-1869-a");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut claims = BTreeMap::new();
    claims.insert(id("learning-1869"), atom_claim(Some(NOW_1869 + 3600)));
    assert_eq!(
        admit_context_with_learning(&input, &claims, &verified, NOW_1869),
        Err(ContextError::IdentityConflict)
    );
}

#[test]
fn stale_fence_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    let mut input = input_with_learning(TASK_1869);
    // Advance the compilation fence past the admitted one.
    input.binding.state_fence.task_revision =
        Some(eliot_contracts::TaskRevision::new(2).expect("task revision"));
    for candidate in &mut input.candidates.candidates {
        candidate.binding.state_fence.task_revision =
            Some(eliot_contracts::TaskRevision::new(2).expect("task revision"));
    }
    let permit =
        issue_learning_admission(&governor, &owner_claim(&fence, Some(OVERLAY_1869), None))
            .expect("live owner issues");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut claims = BTreeMap::new();
    claims.insert(id("learning-1869"), atom_claim(Some(NOW_1869 + 3600)));
    assert_eq!(
        admit_context_with_learning(&input, &claims, &verified, NOW_1869),
        Err(ContextError::InvalidFence)
    );
}

#[test]
fn unclosed_reusable_refused() {
    let governor = governor_1869();
    let fence = fence_1869();
    let input = input_with_learning(TASK_1869);
    let permit = issue_learning_admission(
        &governor,
        &owner_claim(&fence, Some(OVERLAY_1869), Some("candidate-1869-a")),
    )
    .expect("live owner issues candidate-bound permit");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut claims = BTreeMap::new();
    claims.insert(
        id("learning-1869"),
        LearningAtomClaim {
            campaign_id: CAMPAIGN_1869.to_string(),
            overlay_id: Some(OVERLAY_1869.to_string()),
            candidate_id: Some("candidate-1869-a".to_string()),
            closure_ref: None,
            owner: Some("governor-1869".to_string()),
            draft: false,
            expires_at_unix_secs: Some(NOW_1869 + 3600),
        },
    );
    assert_eq!(
        admit_context_with_learning(&input, &claims, &verified, NOW_1869),
        Err(ContextError::InvalidField("learning.closure_ref"))
    );
}
