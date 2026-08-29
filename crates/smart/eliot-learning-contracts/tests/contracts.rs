use eliot_contracts::{
    ArtifactId, AuthorityEpoch, RequestId, ResourceGeneration, StateFence, TaskId, TaskRevision,
};
use eliot_learning_contracts::{
    AttemptExperience, AttemptId, CampaignId, CanonicalExperienceReadSnapshot, ExperienceCoverage,
    ExperienceCoverageState, ExperienceIdentity, ExperienceOwnerKind, LearningContractError,
    ObservedOutcome, OutcomeAttribution, OutcomeStatus, SystemExperienceProjection,
    SystemExperienceProjectionRequest, canonical_experience_snapshot_digest,
    system_experience_projection_digest, validate_canonical_experience_read_snapshot,
    validate_experience_projection_request, validate_system_experience_projection,
};

fn fence(generation: u64) -> StateFence {
    let mut value = StateFence::new(
        AuthorityEpoch::genesis(),
        ResourceGeneration::new(generation).expect("generation"),
    );
    value.task_revision = Some(TaskRevision::genesis());
    value
}

fn identity() -> ExperienceIdentity {
    ExperienceIdentity {
        campaign_id: CampaignId::new("campaign-1").expect("id"),
        current_attempt_id: AttemptId::new("attempt-1").expect("id"),
        task_id: TaskId::new("task-1").expect("id"),
        task_revision: TaskRevision::genesis(),
        state_fence: fence(1),
    }
}

fn coverage(owner: ExperienceOwnerKind, count: u32) -> ExperienceCoverage {
    ExperienceCoverage {
        owner,
        state: ExperienceCoverageState::Complete,
        revision: Some("revision-1".to_owned()),
        projection_handle: Some(ArtifactId::new(format!("projection-{owner:?}")).expect("id")),
        observed_items: count,
        expected_items: Some(count),
        missing_refs: vec![],
    }
}

fn all_coverage() -> Vec<ExperienceCoverage> {
    vec![
        coverage(ExperienceOwnerKind::Task, 1),
        coverage(ExperienceOwnerKind::Attempt, 1),
        coverage(ExperienceOwnerKind::Trace, 1),
        coverage(ExperienceOwnerKind::Artifact, 1),
        coverage(ExperienceOwnerKind::Evaluator, 1),
        coverage(ExperienceOwnerKind::Effect, 1),
    ]
}

fn outcome(attribution: OutcomeAttribution) -> ObservedOutcome {
    ObservedOutcome {
        outcome_id: "outcome-1".to_owned(),
        status: OutcomeStatus::Succeeded,
        attribution,
        evidence_handles: vec![ArtifactId::new("outcome-evidence").expect("id")],
        observed_delta: "acceptance verifier passed".to_owned(),
    }
}

fn attempt() -> AttemptExperience {
    AttemptExperience {
        attempt_id: AttemptId::new("attempt-1").expect("id"),
        sequence_index: 1,
        strategy: "bounded route candidate".to_owned(),
        hypothesis_handle: Some(ArtifactId::new("hypothesis-1").expect("id")),
        trace_handles: vec![ArtifactId::new("trace-1").expect("id")],
        artifact_handles: vec![ArtifactId::new("artifact-1").expect("id")],
        evaluator_handles: vec![ArtifactId::new("evaluator-1").expect("id")],
        effect_handles: vec![ArtifactId::new("effect-1").expect("id")],
        outcome: outcome(OutcomeAttribution::ObservedUnderIntervention),
    }
}

#[test]
fn request_requires_closed_owner_denominator() {
    let request = SystemExperienceProjectionRequest {
        request_id: RequestId::new("request-1").expect("id"),
        identity: identity(),
        expected_owners: vec![ExperienceOwnerKind::Task, ExperienceOwnerKind::Attempt],
        state_fence: fence(1),
        maximum_attempts: 10,
        maximum_evidence_handles_per_attempt: 64,
    };
    assert_eq!(
        validate_experience_projection_request(&request),
        Err(LearningContractError::CoverageInvalid(
            "request must preserve task/attempt/trace/artifact/evaluator/effect denominator"
        ))
    );
}

#[test]
fn mechanism_attribution_requires_hypothesis_trace_and_effect() {
    let mut invalid_attempt = attempt();
    invalid_attempt.hypothesis_handle = None;
    let mut snapshot = CanonicalExperienceReadSnapshot {
        request_id: RequestId::new("request-1").expect("id"),
        identity: identity(),
        state_fence: fence(1),
        coverage: all_coverage(),
        attempts: vec![invalid_attempt],
        snapshot_sha256: String::new(),
    };
    snapshot.snapshot_sha256 = canonical_experience_snapshot_digest(&snapshot).expect("digest");
    assert_eq!(
        validate_canonical_experience_read_snapshot(&snapshot),
        Err(LearningContractError::AttributionInvalid(
            "mechanism-level attribution needs hypothesis, trace, and effect evidence"
        ))
    );
}

#[test]
fn projection_digest_is_attempt_order_independent() {
    let mut second = attempt();
    second.attempt_id = AttemptId::new("attempt-2").expect("id");
    second.sequence_index = 2;
    let build = |attempts| {
        let mut projection = SystemExperienceProjection {
            source_snapshot_sha256: "a".repeat(64),
            identity: identity(),
            state_fence: fence(1),
            coverage: all_coverage(),
            attempts,
            projection_sha256: String::new(),
        };
        projection.projection_sha256 =
            system_experience_projection_digest(&projection).expect("digest");
        projection
    };
    let left = build(vec![second.clone(), attempt()]);
    let right = build(vec![attempt(), second]);
    assert_eq!(left.projection_sha256, right.projection_sha256);
    validate_system_experience_projection(&left).expect("left");
    validate_system_experience_projection(&right).expect("right");
}

#[test]
fn complete_attempt_owner_requires_current_attempt() {
    let mut other = attempt();
    other.attempt_id = AttemptId::new("attempt-2").expect("id");
    let mut snapshot = CanonicalExperienceReadSnapshot {
        request_id: RequestId::new("request-1").expect("id"),
        identity: identity(),
        state_fence: fence(1),
        coverage: all_coverage(),
        attempts: vec![other],
        snapshot_sha256: String::new(),
    };
    snapshot.snapshot_sha256 = canonical_experience_snapshot_digest(&snapshot).expect("digest");
    assert_eq!(
        validate_canonical_experience_read_snapshot(&snapshot),
        Err(LearningContractError::TaskBindingMismatch)
    );
}
