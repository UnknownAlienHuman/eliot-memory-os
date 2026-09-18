#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{
    AffordanceProjection, CANONICAL_PROJECTIONS_SCHEMA_VERSION, CanonicalProjectionSet,
    ContinuityProjection, SafetyProjection, TaskProjection,
};
use eliot_context_contracts::{
    ContextBinding, DecisionRevision, LossPolicy, NonRecoverableReason, OmissionReason,
    OmissionRecord, ProviderId, ProviderRole, SemanticRole,
};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    TaskRevision,
};
use eliot_receipts::WorkScopeId;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest() -> String {
    "a".repeat(64)
}

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    let mut fence = StateFence::new(test_epoch(1), ResourceGeneration::genesis());
    fence.task_revision = Some(TaskRevision::new(1).expect("revision"));
    fence
}

fn fence_other() -> StateFence {
    let mut fence = StateFence::new(test_epoch(2), ResourceGeneration::genesis());
    fence.task_revision = Some(TaskRevision::new(1).expect("revision"));
    fence
}

fn binding() -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new("task-41").expect("task"),
        attempt_id: AgentAttemptId::new("attempt-41").expect("attempt"),
        scope_id: WorkScopeId::new("scope-41").expect("scope"),
        state_fence: fence(),
        decision_id: DecisionId::new("decision-41").expect("decision"),
        operation_id: None,
    }
}

fn role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("governor-owner").expect("provider"),
        role: SemanticRole::Goal,
    }
}

fn task_projection(binding: &ContextBinding) -> TaskProjection {
    TaskProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: binding.clone(),
        goal: "orient the operator".to_string(),
        commitments: vec!["commit-a".to_string()],
    }
}

fn continuity_projection(binding: &ContextBinding) -> ContinuityProjection {
    ContinuityProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: binding.clone(),
        plan_state: "plan-open".to_string(),
        continuity_note: "resume at step two".to_string(),
    }
}

fn safety_projection(binding: &ContextBinding) -> SafetyProjection {
    SafetyProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: binding.clone(),
        safety_note: "one negative trigger observed".to_string(),
        negative_memory_triggers: vec!["trigger-blocked-retry".to_string()],
    }
}

fn affordance_projection(binding: &ContextBinding) -> AffordanceProjection {
    AffordanceProjection {
        schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
        binding: binding.clone(),
        affordances: vec!["scope-41:read".to_string()],
    }
}

fn set() -> CanonicalProjectionSet {
    let binding = binding();
    CanonicalProjectionSet {
        binding: binding.clone(),
        task: task_projection(&binding),
        continuity: continuity_projection(&binding),
        safety: safety_projection(&binding),
        affordance: affordance_projection(&binding),
        omissions: Vec::new(),
    }
}

fn omission(binding: &ContextBinding) -> OmissionRecord {
    OmissionRecord {
        atom_id: id("atom-1"),
        source_id: id("source-1"),
        provider_role: role(),
        decision: DecisionRevision {
            decision_id: binding.decision_id.clone(),
            recipe_revision: TaskRevision::new(1).expect("revision"),
            policy_sha256: digest(),
        },
        task_revision: TaskRevision::new(1).expect("revision"),
        reason: OmissionReason::Unavailable,
        competing_constraint: "source unavailable".to_string(),
        measured_cost: None,
        allowed_representation: LossPolicy::NonDroppable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "decision owner".to_string(),
        privacy_requirement: "restricted".to_string(),
        proof_requirement: "observation".to_string(),
        expires: None,
        invalidation: None,
        digest: digest(),
    }
}

#[test]
fn shared_fence_accepts_and_drifted_projection_is_rejected() {
    let set = set();
    set.validate().expect("shared fence validates");
    assert!(set.is_compatible_with(&fence()));
    assert!(!set.is_compatible_with(&fence_other()));

    let mut drifted = set.clone();
    drifted.task.binding.state_fence = fence_other();
    assert!(
        drifted.validate().is_err(),
        "drifted projection fence must not validate"
    );
}

#[test]
fn explicit_omission_validates_and_wrong_decision_does_not() {
    let binding = binding();
    let mut with_omission = set();
    with_omission.omissions = vec![omission(&binding)];
    with_omission
        .validate()
        .expect("explicit omission validates");

    let mut wrong_decision = with_omission.clone();
    wrong_decision.omissions[0].decision.decision_id =
        DecisionId::new("other-decision").expect("decision");
    assert!(
        wrong_decision.validate().is_err(),
        "omission bound to another decision must fail"
    );
}

#[test]
fn replacement_projections_bind_without_rebuilding_the_consumer() {
    let first = set();
    first.validate().expect("first provider validates");

    let mut second = first.clone();
    second.safety.negative_memory_triggers = vec!["trigger-stale-snapshot".to_string()];
    second.affordance.affordances = vec!["scope-41:read".to_string(), "scope-41:diff".to_string()];
    second.validate().expect("replacement provider validates");
    assert_ne!(first, second, "replacement carries different content");
    assert_eq!(
        first.binding, second.binding,
        "replacement keeps the shared binding"
    );
}

#[test]
fn negative_triggers_are_exact_and_duplicates_fail() {
    let binding = binding();
    let mut empty = safety_projection(&binding);
    empty.negative_memory_triggers = Vec::new();
    empty.validate().expect("empty triggers stay explicit");

    let mut duplicated = safety_projection(&binding);
    duplicated.negative_memory_triggers = vec!["trigger-a".to_string(), "trigger-a".to_string()];
    assert!(
        duplicated.validate().is_err(),
        "duplicate triggers must fail"
    );
}
