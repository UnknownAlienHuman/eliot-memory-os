//! Owner-bound learning candidate producer proof for issue #1869 (round 6).
//!
//! Genuine producer path: a closed, backlog-active reusable candidate plus
//! an owner-verified permit minted by the real [`Governor`] owner yields a
//! learning-marked atom bound to the exact issuance. Archived/unknown
//! candidates, permit-subject mismatches, unclosed/ownerless reusables, and
//! task/fence drift are refused before anything is emitted.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{ContextBinding, ProviderId, ProviderRole, SemanticRole};
use eliot_contracts::{
    DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId, TaskRevision,
};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    QueueLimits, issue_learning_admission, verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{
    AdmitOutcome, ArchiveCause, BoundedBacklog, BoundsError,
};
use eliot_improvement::{
    ImprovementCandidate, ImprovementSurface, ReplayPlan,
    producer::{LearningProduction, produce_learning_candidate},
};
use eliot_receipts::WorkScopeId;

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";
const CAMPAIGN_1869: &str = "campaign-1869-a";
const TASK_1869: &str = "task-1869-a";
const OVERLAY_1869: &str = "overlay-1869-live";
const NOW_1869: u64 = 1_800_000_000;

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

fn replay_plan() -> ReplayPlan {
    ReplayPlan {
        fixed_replay_refs: vec!["replay-1869-a".to_string()],
        holdout_refs: vec!["holdout-1869-a".to_string()],
        transfer_refs: vec!["transfer-1869-a".to_string()],
        counter_metric_names: vec!["cost-1869".to_string()],
        verifier_refs: vec!["verifier-1869-a".to_string()],
    }
}

fn candidate_fixture(evidence: &[&str]) -> ImprovementCandidate {
    ImprovementCandidate::new(
        "project-1869",
        ImprovementSurface::Memory,
        "tighten context budget",
        vec!["retrieval-regret".to_string()],
        vec!["authority-change".to_string()],
        vec!["trace-1869-a".to_string()],
        evidence.iter().map(|e| e.to_string()).collect(),
        replay_plan(),
        BTreeMap::new(),
    )
    .expect("fixture candidate validates")
}

fn bound_policy() -> eliot_improvement::candidate_bounds::CandidateBoundPolicy {
    eliot_improvement::candidate_bounds::CandidateBoundPolicy {
        target_surface: ImprovementSurface::Memory,
        max_active: 8,
        min_value: 1.0,
        governor_authority_ref: "governor-1869".to_string(),
        policy_revision: 1,
    }
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

fn provider_role() -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new("learning-provider").expect("provider"),
        role: SemanticRole::Optional,
    }
}

struct LiveSetup {
    governor: Governor,
    fence: StateFence,
    backlog: BoundedBacklog,
    candidate_id: String,
}

fn live_setup() -> LiveSetup {
    let governor = governor_1869();
    let fence = fence_1869();
    let mut backlog = BoundedBacklog::new(vec![bound_policy()]).expect("policy validates");
    let candidate = candidate_fixture(&["ev-1869-producer-a"]);
    let candidate_id = candidate.candidate_id.clone();
    assert!(matches!(
        backlog.admit(candidate, 3.0, Some("governor-1869".to_string())),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    LiveSetup {
        governor,
        fence,
        backlog,
        candidate_id,
    }
}

fn issue_for(
    setup: &LiveSetup,
    overlay: Option<&str>,
    candidate: Option<&str>,
) -> eliot_governor::LearningAdmissionPermit {
    issue_learning_admission(
        &setup.governor,
        &LearningAdmissionClaim {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            source_campaign_id: CAMPAIGN_1869.to_string(),
            target_task_id: TASK_1869.to_string(),
            fence: setup.fence.clone(),
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

#[allow(clippy::too_many_arguments)]
fn produce(
    setup: &LiveSetup,
    candidate_id: &str,
    closure: &str,
    owner: &str,
    task: &str,
    fence: &StateFence,
    overlay: Option<&str>,
    verified: &eliot_governor::VerifiedLearningAdmission<'_>,
) -> Result<eliot_context_contracts::ContextCandidate, BoundsError> {
    produce_learning_candidate(LearningProduction {
        backlog: &setup.backlog,
        candidate_id,
        closure_ref: closure,
        owner,
        binding: &binding(task, fence),
        atom_id: "atom-learning-1869",
        provider_role: &provider_role(),
        source_id: "source-learning-1869",
        source_owner: "learning-pipeline",
        snapshot_id: "snapshot-learning-1869",
        source_revision: "closure-1869-a",
        content: "local update: tighten context budget",
        overlay_id: overlay,
        expires_at_unix_secs: Some(NOW_1869 + 3600),
        measurement_digest: &"d".repeat(64),
        measurement_serializer: "json-v1",
        verified,
    })
}

#[test]
fn covered_production_emits_permit_bound_atom() {
    let setup = live_setup();
    let permit = issue_for(
        &setup,
        Some(OVERLAY_1869),
        Some(&setup.candidate_id.clone()),
    );
    let verified = verify_learning_admission(&setup.governor, &permit, &setup.fence)
        .expect("live owner verifies");
    let atom = produce(
        &setup,
        &setup.candidate_id.clone(),
        "closure-1869-a",
        "governor-1869",
        TASK_1869,
        &setup.fence,
        Some(OVERLAY_1869),
        &verified,
    )
    .expect("covered production emits");
    let mark = atom.learning.as_ref().expect("atom carries the mark");
    assert_eq!(mark.campaign_id, CAMPAIGN_1869);
    assert_eq!(mark.overlay_id.as_deref(), Some(OVERLAY_1869));
    assert_eq!(
        mark.candidate_id.as_deref(),
        Some(setup.candidate_id.as_str())
    );
    assert_eq!(mark.permit_digest, permit.digest());
    assert!(!mark.draft);
    assert_eq!(atom.binding.task_id.as_str(), TASK_1869);
    assert!(eliot_contracts::fences_match_exact(
        &atom.binding.state_fence,
        permit.fence()
    ));
}

#[test]
fn archived_candidate_cannot_be_produced() {
    let mut setup = live_setup();
    let permit = issue_for(
        &setup,
        Some(OVERLAY_1869),
        Some(&setup.candidate_id.clone()),
    );
    let verified = verify_learning_admission(&setup.governor, &permit, &setup.fence)
        .expect("live owner verifies");
    setup
        .backlog
        .archive(
            &setup.candidate_id.clone(),
            ArchiveCause::Stale,
            "stale after window".to_string(),
        )
        .expect("explicit archive");
    let err = produce(
        &setup,
        &setup.candidate_id.clone(),
        "closure-1869-a",
        "governor-1869",
        TASK_1869,
        &setup.fence,
        Some(OVERLAY_1869),
        &verified,
    )
    .expect_err("archived entries lose production eligibility");
    assert_eq!(err, BoundsError::NotBacklogAdmitted);
}

#[test]
fn permit_subject_mismatch_refused() {
    let setup = live_setup();
    // Permit binds a different reusable candidate.
    let permit = issue_for(&setup, Some(OVERLAY_1869), Some("candidate-other"));
    let verified = verify_learning_admission(&setup.governor, &permit, &setup.fence)
        .expect("live owner verifies");
    let err = produce(
        &setup,
        &setup.candidate_id.clone(),
        "closure-1869-a",
        "governor-1869",
        TASK_1869,
        &setup.fence,
        Some(OVERLAY_1869),
        &verified,
    )
    .expect_err("foreign subject refused");
    assert_eq!(err, BoundsError::ReusableBackingMismatch);
}

#[test]
fn unclosed_and_ownerless_reusables_refused() {
    let setup = live_setup();
    let permit = issue_for(
        &setup,
        Some(OVERLAY_1869),
        Some(&setup.candidate_id.clone()),
    );
    let verified = verify_learning_admission(&setup.governor, &permit, &setup.fence)
        .expect("live owner verifies");
    assert_eq!(
        produce(
            &setup,
            &setup.candidate_id.clone(),
            "",
            "governor-1869",
            TASK_1869,
            &setup.fence,
            Some(OVERLAY_1869),
            &verified,
        ),
        Err(BoundsError::UnclosedReusable)
    );
    assert_eq!(
        produce(
            &setup,
            &setup.candidate_id.clone(),
            "closure-1869-a",
            "",
            TASK_1869,
            &setup.fence,
            Some(OVERLAY_1869),
            &verified,
        ),
        Err(BoundsError::OwnerlessRecord)
    );
}

#[test]
fn task_and_fence_drift_refused() {
    let setup = live_setup();
    let permit = issue_for(
        &setup,
        Some(OVERLAY_1869),
        Some(&setup.candidate_id.clone()),
    );
    let verified = verify_learning_admission(&setup.governor, &permit, &setup.fence)
        .expect("live owner verifies");
    assert_eq!(
        produce(
            &setup,
            &setup.candidate_id.clone(),
            "closure-1869-a",
            "governor-1869",
            "task-1869-foreign",
            &setup.fence,
            Some(OVERLAY_1869),
            &verified,
        ),
        Err(BoundsError::CrossTaskAdmissionMismatch)
    );
    let mut drifted = setup.fence.clone();
    drifted.task_revision = Some(TaskRevision::new(2).expect("task revision"));
    assert_eq!(
        produce(
            &setup,
            &setup.candidate_id.clone(),
            "closure-1869-a",
            "governor-1869",
            TASK_1869,
            &drifted,
            Some(OVERLAY_1869),
            &verified,
        ),
        Err(BoundsError::StaleStateFence)
    );
}
