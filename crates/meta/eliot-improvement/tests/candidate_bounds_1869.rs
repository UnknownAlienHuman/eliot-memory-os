//! Bounded candidate backlog + cross-task refusal proof for issue #1869.
//!
//! Round-1/2 structural proofs (lineage dedup merge, bound/archive, bare
//! retrieval refusals) plus round-3 genuine issuer-to-consumer proofs: every
//! governed retrieval runs on an owner-issued [`LearningAdmissionPermit`]
//! minted by the real [`Governor`] owner and verified against live owner
//! state. Fabricated epoch, rotated epoch, drifted fence, foreign task, and
//! archived-reusable inputs are refused through the wired consumer.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskRevision};
use eliot_governor::{
    Governor, GovernorConfig, LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim,
    LearningAdmissionError, QueueLimits, VerifiedLearningAdmission, issue_learning_admission,
    verify_learning_admission,
};
use eliot_improvement::candidate_bounds::{
    AdmitOutcome, ArchiveCause, BoundedBacklog, BoundsError, CandidateBoundPolicy,
    CrossTaskAdmission, GovernedClosureError, GovernedOverlay, GovernedRetrieval, OverlayState,
    ReusableCandidateRef, governed_assemble_campaign_learning_closure, retrieve_for_attempt,
    retrieve_governed,
};
use eliot_improvement::learning_closure::{
    AdmissionState, AttemptDelta, AttemptOutcomesAndDeltas, AttemptRecord, AttemptStatus,
    CampaignAndTarget, CausalAttribution, ClosureAssembly, ClosurePolicy, ClosureStatus, DeltaKind,
    EconomicsRecord, EvidenceSource, HarmRecord, LifecycleStage, OutcomeHarmAndEconomicsEvidence,
    OutcomeKind, OutcomeRecord, OverlayAndActivationAssessments, OverlayRecord,
    PriorClosureHistory, StageAssessment,
};
use eliot_improvement::{
    ImprovementCandidate, ImprovementLifecycle, ImprovementSurface, ReplayPlan,
};
use time::{Duration, OffsetDateTime};

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

const LINEAGE_1869: &str = "550e8400-e29b-41d4-a716-446655440000";

fn epoch_1869(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_1869).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn generation_1869() -> ResourceGeneration {
    ResourceGeneration::new(7).expect("valid test generation")
}

fn fence_1869(sequence: u64) -> StateFence {
    StateFence::new(epoch_1869(sequence), generation_1869())
}

fn governor_1869(sequence: u64) -> Governor {
    let config = GovernorConfig {
        authority_epoch: epoch_1869(sequence),
        resource_generation: generation_1869(),
        queues: QueueLimits::default(),
        background_pause_interactive_depth: 1,
    };
    let mut governor = Governor::new(config).expect("valid test governor config");
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

fn candidate(evidence: &[&str]) -> ImprovementCandidate {
    let mut candidate = ImprovementCandidate::new(
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
    .expect("fixture candidate validates");
    candidate.set_details(
        "retrieval regret above threshold",
        vec!["oversized context window".to_string()],
        BTreeMap::from([("cost-1869".to_string(), 1.0)]),
        "memory retrieval",
        "governor-1869",
        "work-item-1869",
        "canary-1869",
        "rollback-1869",
        "stop on cost regression",
    );
    candidate
}

fn policy(max_active: usize) -> CandidateBoundPolicy {
    CandidateBoundPolicy {
        target_surface: ImprovementSurface::Memory,
        max_active,
        min_value: 1.0,
        governor_authority_ref: "governor-1869".to_string(),
        policy_revision: 1,
    }
}

fn live_overlay(campaign: &str, fence: &StateFence, now: OffsetDateTime) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: format!("overlay-{campaign}"),
        campaign_id: campaign.to_string(),
        task_id: format!("task-{campaign}"),
        fence: fence.clone(),
        compatible_recipe_ref: "recipe-1869".to_string(),
        state: OverlayState::LocalAdmitted,
        admission_ref: Some(format!("admission-{campaign}")),
        expires_at: Some(now + Duration::hours(1)),
    }
}

fn closed_reusable(origin_campaign: &str) -> ReusableCandidateRef {
    ReusableCandidateRef {
        candidate_id: "candidate-reusable-1869".to_string(),
        closure_ref: Some("closure-1869-a".to_string()),
        owner: Some("governor-1869".to_string()),
        origin_campaign_id: origin_campaign.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Round-1 structural proofs (unchanged behavior).
// ---------------------------------------------------------------------------

#[test]
fn duplicate_lineage_merges_with_provenance() {
    let governor = governor_1869(3);
    let fence = fence_1869(3);
    let mut backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let first = candidate(&["ev-1869-a", "ev-1869-b"]);
    let first_id = first.candidate_id.clone();
    let first_permit = issue_learning_admission(
        &governor,
        &claim_1869(&fence, OVERLAY_1869, Some(&first_id)),
    )
    .expect("owner issues first admission");
    let first_verified =
        verify_learning_admission(&governor, &first_permit, &fence).expect("owner verifies first");
    assert!(matches!(
        backlog.admit_governed(
            first,
            3.0,
            Some(AUTHORITY_1869.to_string()),
            &first_verified,
        ),
        Ok(AdmitOutcome::Admitted { .. })
    ));

    let second = candidate(&["ev-1869-b", "ev-1869-c"]);
    let second_id = second.candidate_id.clone();
    let second_permit = issue_learning_admission(
        &governor,
        &claim_1869(&fence, OVERLAY_1869, Some(&second_id)),
    )
    .expect("owner issues second admission");
    let second_verified = verify_learning_admission(&governor, &second_permit, &fence)
        .expect("owner verifies second");
    let outcome = backlog
        .admit_governed(
            second,
            4.0,
            Some(AUTHORITY_1869.to_string()),
            &second_verified,
        )
        .expect("duplicate admits merge");
    assert_eq!(
        outcome,
        AdmitOutcome::Merged {
            surviving_candidate_id: first_id.clone(),
            absorbed_candidate_id: second_id.clone(),
        }
    );

    let active = backlog.active_for(ImprovementSurface::Memory);
    assert_eq!(active.len(), 1);
    let surviving = active[0];
    assert_eq!(surviving.candidate.candidate_id, first_id);
    assert!(surviving.merged_from.contains(&second_id));
    for evidence in ["ev-1869-a", "ev-1869-b", "ev-1869-c"] {
        assert!(
            surviving
                .candidate
                .evidence_refs
                .iter()
                .any(|r| r == evidence),
            "merged candidate preserves {evidence}"
        );
    }
}

#[test]
fn expired_overlay_and_unclosed_reusable_are_refused() {
    let now = OffsetDateTime::now_utc();
    let fence = fence_1869(3);
    let mut expired = live_overlay("campaign-a", &fence, now);
    expired.expires_at = Some(now - Duration::minutes(1));
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &expired,
        None,
        false,
        None,
        now,
    );
    assert_eq!(refusal, Err(BoundsError::ExpiredOverlay));

    let overlay_b = live_overlay("campaign-b", &fence, now);
    let mut unclosed = closed_reusable("campaign-a");
    unclosed.closure_ref = None;
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_b,
        Some(&unclosed),
        false,
        None,
        now,
    );
    assert_eq!(refusal, Err(BoundsError::UnclosedReusable));
}

#[test]
fn cross_task_use_requires_governed_admission() {
    let now = OffsetDateTime::now_utc();
    let fence = fence_1869(3);
    let overlay_a = live_overlay("campaign-a", &fence, now);
    let reusable = closed_reusable("campaign-a");

    // No admission: refused.
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_a,
        Some(&reusable),
        false,
        None,
        now,
    );
    assert_eq!(refusal, Err(BoundsError::CrossTaskAdmissionMissing));

    // Admission missing rollback revalidation: still refused.
    let incomplete = CrossTaskAdmission {
        admission_id: "xadmit-1869-1".to_string(),
        source_campaign_id: "campaign-a".to_string(),
        target_task_id: "task-campaign-b".to_string(),
        scope_ref: "scope-1869".to_string(),
        authority_ref: "governor-1869".to_string(),
        retention_ref: "retention-1869".to_string(),
        evaluator_ref: "evaluator-1869".to_string(),
        rollback_ref: String::new(),
    };
    let refusal = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_a,
        Some(&reusable),
        false,
        Some(&incomplete),
        now,
    );
    assert_eq!(refusal, Err(BoundsError::MissingField("rollback_ref")));

    // Complete revalidation: eligible, explicitly marked cross-task.
    let admission = CrossTaskAdmission {
        rollback_ref: "rollback-1869".to_string(),
        ..incomplete
    };
    let decision = retrieve_for_attempt(
        "campaign-b",
        "task-campaign-b",
        &overlay_a,
        Some(&reusable),
        false,
        Some(&admission),
        now,
    )
    .expect("governed cross-task admission authorizes carryover");
    assert!(decision.cross_task);
    assert_eq!(
        decision.cross_task_admission_id,
        Some("xadmit-1869-1".to_string())
    );
}

#[test]
fn bound_refuses_until_explicit_archive() {
    let mut backlog = BoundedBacklog::new(vec![policy(1)]).expect("policy validates");
    let mut first = candidate(&["ev-1869-bound-a"]);
    first
        .transition_lifecycle(ImprovementLifecycle::Stale)
        .expect("test candidate is explicitly stale");
    let first_id = first.candidate_id.clone();
    assert!(matches!(
        backlog.admit(first, 2.0, Some("governor-1869".to_string())),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    let err = backlog
        .admit(
            candidate(&["ev-1869-bound-b"]),
            3.0,
            Some("governor-1869".to_string()),
        )
        .expect_err("full bound refuses");
    assert!(matches!(err, BoundsError::BoundExceeded { .. }));

    let archived = backlog
        .archive(
            &first_id,
            ArchiveCause::Stale,
            "superseded by replay".to_string(),
        )
        .expect("explicit archive transitions");
    assert_eq!(archived.candidate_id, first_id);
    assert!(backlog.active_for(ImprovementSurface::Memory).is_empty());
    assert_eq!(backlog.archives().len(), 1);
    let retained = backlog
        .retained_entry_for(&archived.candidate_id)
        .expect("archived row remains retained");
    assert_eq!(
        retained.candidate.lifecycle,
        eliot_improvement::ImprovementLifecycle::Archived
    );
    assert_eq!(archived.archived_revision, 2);
    assert!(matches!(
        backlog.admit(
            candidate(&["ev-1869-bound-b"]),
            3.0,
            Some("governor-1869".to_string())
        ),
        Ok(AdmitOutcome::Admitted { .. })
    ));
}

// ---------------------------------------------------------------------------
// Round 3: genuine issuer-to-consumer proofs through the wired consumer.
// Every governed gate below runs on a permit minted by the real Governor
// owner; fabricated epoch/fence/task inputs are refused.
// ---------------------------------------------------------------------------

const CAMPAIGN_1869: &str = "campaign-1869-a";
const TASK_1869: &str = "task-1869-a";
const OVERLAY_1869: &str = "overlay-1869-live";
const ATTEMPT_1869: &str = "attempt-1869-1";
const SCOPE_1869: &str = "scope-1869";
const AUTHORITY_1869: &str = "governor-1869";
const RETENTION_1869: &str = "retention-1869";
const EVALUATOR_1869: &str = "evaluator-1869-a";
const ROLLBACK_1869: &str = "rollback-1869";

fn claim_1869(
    fence: &StateFence,
    overlay: &str,
    candidate: Option<&str>,
) -> LearningAdmissionClaim {
    LearningAdmissionClaim {
        schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: CAMPAIGN_1869.to_string(),
        target_task_id: TASK_1869.to_string(),
        fence: fence.clone(),
        overlay_id: Some(overlay.to_string()),
        candidate_id: candidate.map(str::to_string),
        scope_ref: SCOPE_1869.to_string(),
        authority_ref: AUTHORITY_1869.to_string(),
        retention_ref: RETENTION_1869.to_string(),
        evaluator_ref: EVALUATOR_1869.to_string(),
        rollback_ref: ROLLBACK_1869.to_string(),
    }
}

fn backing_overlay_1869(fence: &StateFence, now: OffsetDateTime) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: OVERLAY_1869.to_string(),
        campaign_id: CAMPAIGN_1869.to_string(),
        task_id: TASK_1869.to_string(),
        fence: fence.clone(),
        compatible_recipe_ref: "recipe-1869".to_string(),
        state: OverlayState::LocalAdmitted,
        admission_ref: Some("admission-1869-live".to_string()),
        expires_at: Some(now + Duration::hours(1)),
    }
}

fn closure_campaign_1869() -> CampaignAndTarget {
    CampaignAndTarget {
        campaign_id: CAMPAIGN_1869.to_string(),
        target_id: "target-1869-a".to_string(),
        task_id: TASK_1869.to_string(),
        scope_ref: "scope-1869-a".to_string(),
        fence_ref: "fence-1869-a".to_string(),
        objective_ref: "objective-1869-a".to_string(),
        acceptance_ref: "acceptance-1869-a".to_string(),
        evaluator_id: EVALUATOR_1869.to_string(),
        holdout_ref: "holdout-1869-a".to_string(),
    }
}

fn closure_policy_1869() -> ClosurePolicy {
    ClosurePolicy {
        schema_version: 1,
        allow_checkpoint: true,
        max_attempts: 16,
        max_bytes: 1_000_000,
        require_independent_verifier: true,
        external_owner_id: AUTHORITY_1869.to_string(),
        rollback_owner_id: ROLLBACK_1869.to_string(),
        idempotency_key: "idem-1869-a".to_string(),
        operation_ref: "op-1869-a".to_string(),
    }
}

fn closure_attempt_1869() -> AttemptRecord {
    AttemptRecord {
        attempt_id: ATTEMPT_1869.to_string(),
        consequential: true,
        non_consequential_reason: None,
        status: AttemptStatus::Available,
        has_outcome: true,
        delta: Some(AttemptDelta {
            delta_id: "delta-1869-1".to_string(),
            attempt_id: ATTEMPT_1869.to_string(),
            target_id: "target-1869-a".to_string(),
            base_state_ref: "state-1869-before".to_string(),
            stale_base: false,
            kind: DeltaKind::Changed {
                before_ref: "state-1869-before".to_string(),
                after_ref: "state-1869-after".to_string(),
            },
        }),
    }
}

fn closure_stage_1869(stage: LifecycleStage, use_linked: bool) -> StageAssessment {
    StageAssessment {
        attempt_id: ATTEMPT_1869.to_string(),
        overlay_id: OVERLAY_1869.to_string(),
        stage,
        observed: true,
        evidence_ref: Some(format!("ev-1869-{stage:?}")),
        use_linked,
        causally_attributed: false,
        source: EvidenceSource::IndependentVerifier {
            verifier_id: "verifier-1869-a".to_string(),
        },
    }
}

fn closure_overlays_1869() -> OverlayAndActivationAssessments {
    OverlayAndActivationAssessments {
        overlays: vec![OverlayRecord {
            overlay_id: OVERLAY_1869.to_string(),
            attempt_id: ATTEMPT_1869.to_string(),
            base_ref: "base-1869-live".to_string(),
            parent_ref: "parent-1869-live".to_string(),
            admission: AdmissionState::Admitted,
            admission_ref: "admission-1869-live".to_string(),
        }],
        assessments: vec![
            closure_stage_1869(LifecycleStage::Delivery, false),
            closure_stage_1869(LifecycleStage::Use, true),
            closure_stage_1869(LifecycleStage::Outcome, true),
        ],
    }
}

fn closure_evidence_1869() -> OutcomeHarmAndEconomicsEvidence {
    OutcomeHarmAndEconomicsEvidence {
        outcomes: vec![OutcomeRecord {
            attempt_id: ATTEMPT_1869.to_string(),
            metric: "task-success-rate".to_string(),
            unit: "ratio".to_string(),
            population: "holdout-1869-a".to_string(),
            window: "window-1869-a".to_string(),
            source_id: "source-1869-a".to_string(),
            evaluator_id: EVALUATOR_1869.to_string(),
            baseline_ref: "baseline-1869-a".to_string(),
            control_ref: Some("control-1869-a".to_string()),
            kind: OutcomeKind::Positive,
            harm: HarmRecord {
                harm_observed: false,
                harm_ref: None,
            },
            use_linked: true,
            causal: CausalAttribution::Attributed {
                control_ref: "control-1869-a".to_string(),
            },
        }],
        economics: vec![EconomicsRecord {
            attempt_id: ATTEMPT_1869.to_string(),
            cost_known: true,
            cost: 12.5,
            currency: "USD".to_string(),
            unit: "attempt".to_string(),
        }],
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_through_consumer(
    backlog: &BoundedBacklog,
    verified: &VerifiedLearningAdmission<'_>,
    overlay: &GovernedOverlay,
    reusable: Option<&ReusableCandidateRef>,
    cross_task_admission: Option<&CrossTaskAdmission>,
    now: OffsetDateTime,
) -> Result<ClosureAssembly, GovernedClosureError> {
    governed_assemble_campaign_learning_closure(
        closure_campaign_1869(),
        AttemptOutcomesAndDeltas {
            expected_attempt_ids: vec![ATTEMPT_1869.to_string()],
            attempts: vec![closure_attempt_1869()],
        },
        closure_overlays_1869(),
        closure_evidence_1869(),
        PriorClosureHistory { prior: Vec::new() },
        closure_policy_1869(),
        GovernedRetrieval {
            requesting_campaign_id: CAMPAIGN_1869,
            requesting_task_id: TASK_1869,
            overlay,
            reusable,
            draft_delta_present: false,
            cross_task_admission,
            backlog,
            verified,
            now,
        },
    )
}

#[test]
fn governed_consumer_closes_with_owner_issued_permit() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_1869(3);
    let fence = fence_1869(3);
    let mut backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let admitted = candidate(&["ev-1869-consumer-a"]);
    let admitted_id = admitted.candidate_id.clone();
    // Owner-issued permit binds overlay + reusable candidate + fence.
    let permit = issue_learning_admission(
        &governor,
        &claim_1869(&fence, OVERLAY_1869, Some(&admitted_id)),
    )
    .expect("live owner issues");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    // Bound-policy authority equals the permit-bound authority: governed
    // admission succeeds on owner-authenticated equality, not strings.
    assert!(matches!(
        backlog.admit_governed(admitted, 3.0, Some(AUTHORITY_1869.to_string()), &verified),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    let reusable = ReusableCandidateRef {
        candidate_id: admitted_id,
        closure_ref: Some("closure-1869-a".to_string()),
        owner: Some(AUTHORITY_1869.to_string()),
        origin_campaign_id: CAMPAIGN_1869.to_string(),
    };
    match assemble_through_consumer(
        &backlog,
        &verified,
        &backing_overlay_1869(&fence, now),
        Some(&reusable),
        None,
        now,
    ) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
            assert_eq!(candidate.handoff.external_owner_id, AUTHORITY_1869);
        }
        other => panic!("governed consumer must close task-local, got {other:?}"),
    }
}

#[test]
fn governed_consumer_refuses_expired_backing() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_1869(3);
    let fence = fence_1869(3);
    let backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let permit = issue_learning_admission(&governor, &claim_1869(&fence, OVERLAY_1869, None))
        .expect("live owner issues overlay-only permit");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    let mut expired = backing_overlay_1869(&fence, now);
    expired.expires_at = Some(now - Duration::minutes(1));
    let err = assemble_through_consumer(&backlog, &verified, &expired, None, None, now)
        .expect_err("expired backing never reaches assembly");
    assert_eq!(
        err,
        GovernedClosureError::Bounds(BoundsError::ExpiredOverlay)
    );
}

#[test]
fn fabricated_epoch_and_fence_are_refused() {
    let governor = governor_1869(3);
    let fence = fence_1869(3);
    // Foreign lineage at issuance: the owner refuses to mint.
    let mut foreign = claim_1869(&fence, OVERLAY_1869, None);
    foreign.fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
                .expect("valid foreign lineage"),
            NonZeroU64::new(3).expect("nonzero sequence"),
        )
        .expect("valid foreign epoch"),
        generation_1869(),
    );
    assert_eq!(
        issue_learning_admission(&governor, &foreign),
        Err(LearningAdmissionError::StaleAuthorityEpoch)
    );

    // Rotated epoch at verification: the old permit no longer binds.
    let permit = issue_learning_admission(&governor, &claim_1869(&fence, OVERLAY_1869, None))
        .expect("issued under epoch 3");
    let rotated = governor_1869(4);
    assert!(matches!(
        verify_learning_admission(&rotated, &permit, &fence_1869(4)),
        Err(LearningAdmissionError::DigestMismatch)
    ));

    // Drifted fence at the gate: exact-match fails before values surface.
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("identical fence verifies");
    let now = OffsetDateTime::now_utc();
    let mut drifted_fence = fence.clone();
    drifted_fence.task_revision = Some(TaskRevision::new(2).expect("valid task revision"));
    let drifted_overlay = backing_overlay_1869(&drifted_fence, now);
    let backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let err = assemble_through_consumer(&backlog, &verified, &drifted_overlay, None, None, now)
        .expect_err("fence drift never reaches assembly");
    assert_eq!(
        err,
        GovernedClosureError::Bounds(BoundsError::StaleStateFence)
    );
}

#[test]
fn foreign_task_without_matching_permit_is_refused() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_1869(3);
    let fence = fence_1869(3);
    let backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let permit = issue_learning_admission(&governor, &claim_1869(&fence, OVERLAY_1869, None))
        .expect("permit targets task-1869-a");
    let verified =
        verify_learning_admission(&governor, &permit, &fence).expect("live owner verifies");
    // Requesting a different task than the permit target: cross-task path
    // demands a revalidation record matching the permit, not bare strings.
    let err = governed_assemble_campaign_learning_closure(
        closure_campaign_1869(),
        AttemptOutcomesAndDeltas {
            expected_attempt_ids: vec![ATTEMPT_1869.to_string()],
            attempts: vec![closure_attempt_1869()],
        },
        closure_overlays_1869(),
        closure_evidence_1869(),
        PriorClosureHistory { prior: Vec::new() },
        closure_policy_1869(),
        GovernedRetrieval {
            requesting_campaign_id: CAMPAIGN_1869,
            requesting_task_id: "task-1869-foreign",
            overlay: &backing_overlay_1869(&fence, now),
            reusable: None,
            draft_delta_present: false,
            cross_task_admission: None,
            backlog: &backlog,
            verified: &verified,
            now,
        },
    )
    .expect_err("foreign task without permit-matching admission is refused");
    assert_eq!(
        err,
        GovernedClosureError::Bounds(BoundsError::CrossTaskAdmissionMissing)
    );
}

#[test]
fn cross_task_carryover_with_owner_issued_permit() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_1869(3);
    let fence = fence_1869(3);
    // Cross-task permit: source campaign A, target task B, all revalidation
    // refs digest-bound by the owner.
    let claim = LearningAdmissionClaim {
        schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: CAMPAIGN_1869.to_string(),
        target_task_id: "task-1869-b".to_string(),
        fence: fence.clone(),
        overlay_id: Some(OVERLAY_1869.to_string()),
        candidate_id: None,
        scope_ref: SCOPE_1869.to_string(),
        authority_ref: AUTHORITY_1869.to_string(),
        retention_ref: RETENTION_1869.to_string(),
        evaluator_ref: EVALUATOR_1869.to_string(),
        rollback_ref: ROLLBACK_1869.to_string(),
    };
    let permit = issue_learning_admission(&governor, &claim).expect("owner issues");
    let verified = verify_learning_admission(&governor, &permit, &fence).expect("owner verifies");
    let backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let admission = CrossTaskAdmission {
        admission_id: "xadmit-1869-1".to_string(),
        source_campaign_id: CAMPAIGN_1869.to_string(),
        target_task_id: "task-1869-b".to_string(),
        scope_ref: SCOPE_1869.to_string(),
        authority_ref: AUTHORITY_1869.to_string(),
        retention_ref: RETENTION_1869.to_string(),
        evaluator_ref: EVALUATOR_1869.to_string(),
        rollback_ref: ROLLBACK_1869.to_string(),
    };
    let decision = retrieve_governed(GovernedRetrieval {
        requesting_campaign_id: "campaign-1869-b",
        requesting_task_id: "task-1869-b",
        overlay: &backing_overlay_1869(&fence, now),
        reusable: None,
        draft_delta_present: false,
        cross_task_admission: Some(&admission),
        backlog: &backlog,
        verified: &verified,
        now,
    })
    .expect("owner-issued cross-task permit authorizes carryover");
    assert!(decision.cross_task);
    assert_eq!(
        decision.cross_task_admission_id,
        Some("xadmit-1869-1".to_string())
    );

    // Same strings without the permit-bound match: refused. A record that
    // rewrites even one revalidated ref does not match the permit.
    let mut forged = admission.clone();
    forged.rollback_ref = "rollback-forged".to_string();
    let err = retrieve_governed(GovernedRetrieval {
        requesting_campaign_id: "campaign-1869-b",
        requesting_task_id: "task-1869-b",
        overlay: &backing_overlay_1869(&fence, now),
        reusable: None,
        draft_delta_present: false,
        cross_task_admission: Some(&forged),
        backlog: &backlog,
        verified: &verified,
        now,
    })
    .expect_err("rewritten revalidation record is refused");
    assert_eq!(err, BoundsError::CrossTaskAdmissionMismatch);
}

#[test]
fn archived_reusable_loses_retrieval() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_1869(3);
    let fence = fence_1869(3);
    let mut backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let mut admitted = candidate(&["ev-1869-archive-a"]);
    admitted
        .transition_lifecycle(ImprovementLifecycle::Stale)
        .expect("test candidate is explicitly stale");
    let admitted_id = admitted.candidate_id.clone();
    let permit = issue_learning_admission(
        &governor,
        &claim_1869(&fence, OVERLAY_1869, Some(&admitted_id)),
    )
    .expect("owner issues");
    let verified = verify_learning_admission(&governor, &permit, &fence).expect("owner verifies");
    assert!(matches!(
        backlog.admit_governed(admitted, 2.0, Some(AUTHORITY_1869.to_string()), &verified),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    let reusable = ReusableCandidateRef {
        candidate_id: admitted_id.clone(),
        closure_ref: Some("closure-1869-a".to_string()),
        owner: Some(AUTHORITY_1869.to_string()),
        origin_campaign_id: CAMPAIGN_1869.to_string(),
    };
    let gate = |backlog: &BoundedBacklog| {
        retrieve_governed(GovernedRetrieval {
            requesting_campaign_id: CAMPAIGN_1869,
            requesting_task_id: TASK_1869,
            overlay: &backing_overlay_1869(&fence, now),
            reusable: Some(&reusable),
            draft_delta_present: false,
            cross_task_admission: None,
            backlog,
            verified: &verified,
            now,
        })
    };
    assert!(gate(&backlog).is_ok());
    backlog
        .archive(
            &admitted_id,
            ArchiveCause::Stale,
            "stale after window".to_string(),
        )
        .expect("explicit archive");
    assert_eq!(gate(&backlog), Err(BoundsError::NotBacklogAdmitted));
}
