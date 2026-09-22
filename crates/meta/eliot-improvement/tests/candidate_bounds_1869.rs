//! Bounded candidate backlog + cross-task refusal proof for issue #1869.
//!
//! Smallest proof named under the acceptance criteria: lineage dedup merge,
//! expired/unclosed retrieval refusal, and governed cross-task admission.

use eliot_improvement::candidate_bounds::{
    AdmitOutcome, ArchiveCause, BoundedBacklog, BoundsError, CandidateBoundPolicy,
    CrossTaskAdmission, GovernedClosureError, GovernedOverlay, GovernedRetrieval,
    GovernorOwnerEvidence, OverlayState, ReusableCandidateRef,
    governed_assemble_campaign_learning_closure, retrieve_for_attempt, retrieve_governed,
};
use eliot_improvement::learning_closure::{
    AdmissionState, AttemptDelta, AttemptOutcomesAndDeltas, AttemptRecord, AttemptStatus,
    CampaignAndTarget, CausalAttribution, ClosureAssembly, ClosurePolicy, ClosureStatus, DeltaKind,
    EconomicsRecord, EvidenceSource, HarmRecord, LifecycleStage, OutcomeHarmAndEconomicsEvidence,
    OutcomeKind, OutcomeRecord, OverlayAndActivationAssessments, OverlayRecord,
    PriorClosureHistory, StageAssessment,
};
use eliot_improvement::{ImprovementCandidate, ImprovementSurface, ReplayPlan};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

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

fn policy(max_active: usize) -> CandidateBoundPolicy {
    CandidateBoundPolicy {
        target_surface: ImprovementSurface::Memory,
        max_active,
        min_value: 1.0,
        governor_authority_ref: "governor-1869-policy-1".to_string(),
        policy_revision: 1,
    }
}

fn live_overlay(campaign: &str, now: OffsetDateTime) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: format!("overlay-{campaign}"),
        campaign_id: campaign.to_string(),
        task_id: format!("task-{campaign}"),
        fence_ref: format!("fence-{campaign}"),
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

#[test]
fn duplicate_lineage_merges_with_provenance() {
    let mut backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let first = candidate(&["ev-1869-a", "ev-1869-b"]);
    let first_id = first.candidate_id.clone();
    assert!(matches!(
        backlog.admit(first, 3.0, Some("governor-1869".to_string())),
        Ok(AdmitOutcome::Admitted { .. })
    ));

    let second = candidate(&["ev-1869-b", "ev-1869-c"]);
    let second_id = second.candidate_id.clone();
    let outcome = backlog
        .admit(second, 4.0, Some("governor-1869".to_string()))
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
    let mut expired = live_overlay("campaign-a", now);
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

    let overlay_b = live_overlay("campaign-b", now);
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
    let overlay_a = live_overlay("campaign-a", now);
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
        governor_admission_ref: "governor-admission-1869".to_string(),
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
    let first = candidate(&["ev-1869-bound-a"]);
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
// Round 2: governed consumer path (I12.24 closure assembly as the actual
// retrieval consumer; Governor refs confirmed against owner evidence).
// ---------------------------------------------------------------------------

const CAMPAIGN_1869: &str = "campaign-1869-a";
const TASK_1869: &str = "task-1869-a";
const OVERLAY_1869: &str = "overlay-1869-live";
const ATTEMPT_1869: &str = "attempt-1869-1";
const POLICY_OWNER_1869: &str = "governor-1869-policy-1";
const OVERLAY_ADMISSION_1869: &str = "admission-1869-live";
const EXTERNAL_OWNER_1869: &str = "governor-1869";
const ROLLBACK_OWNER_1869: &str = "rollback-1869";

/// Live Governor-minted evidence for the fixtures: the bound-policy owner,
/// the closure owners, and the overlay admission are all minted here.
/// Anything else is forged by construction.
fn governor_evidence_1869() -> GovernorOwnerEvidence {
    GovernorOwnerEvidence {
        authority_binding: "epoch-1869:gen-7".to_string(),
        minted_authorities: [POLICY_OWNER_1869, EXTERNAL_OWNER_1869, ROLLBACK_OWNER_1869]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        minted_admissions: [OVERLAY_ADMISSION_1869]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

fn backing_overlay_1869(now: OffsetDateTime) -> GovernedOverlay {
    GovernedOverlay {
        overlay_id: OVERLAY_1869.to_string(),
        campaign_id: CAMPAIGN_1869.to_string(),
        task_id: TASK_1869.to_string(),
        fence_ref: "fence-1869-a".to_string(),
        compatible_recipe_ref: "recipe-1869".to_string(),
        state: OverlayState::LocalAdmitted,
        admission_ref: Some(OVERLAY_ADMISSION_1869.to_string()),
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
        evaluator_id: "evaluator-1869-a".to_string(),
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
        external_owner_id: EXTERNAL_OWNER_1869.to_string(),
        rollback_owner_id: ROLLBACK_OWNER_1869.to_string(),
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

fn closure_overlays_1869() -> OverlayAndActivationAssessments {
    OverlayAndActivationAssessments {
        overlays: vec![OverlayRecord {
            overlay_id: OVERLAY_1869.to_string(),
            attempt_id: ATTEMPT_1869.to_string(),
            base_ref: "base-1869-live".to_string(),
            parent_ref: "parent-1869-live".to_string(),
            admission: AdmissionState::Admitted,
            admission_ref: OVERLAY_ADMISSION_1869.to_string(),
        }],
        assessments: vec![
            closure_stage_1869(LifecycleStage::Delivery, false),
            closure_stage_1869(LifecycleStage::Use, true),
            closure_stage_1869(LifecycleStage::Outcome, true),
        ],
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

fn closure_evidence_1869() -> OutcomeHarmAndEconomicsEvidence {
    OutcomeHarmAndEconomicsEvidence {
        outcomes: vec![OutcomeRecord {
            attempt_id: ATTEMPT_1869.to_string(),
            metric: "task-success-rate".to_string(),
            unit: "ratio".to_string(),
            population: "holdout-1869-a".to_string(),
            window: "window-1869-a".to_string(),
            source_id: "source-1869-a".to_string(),
            evaluator_id: "evaluator-1869-a".to_string(),
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

fn assemble_through_consumer(
    backlog: &BoundedBacklog,
    governor: &GovernorOwnerEvidence,
    overlay: &GovernedOverlay,
    reusable: Option<&ReusableCandidateRef>,
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
            cross_task_admission: None,
            backlog: Some(backlog),
            governor,
            now,
        },
    )
}

#[test]
fn governed_consumer_closes_with_live_backed_overlay() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_evidence_1869();
    let mut backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    // Bound-policy owner is Governor-minted: governed admission succeeds.
    let admitted = candidate(&["ev-1869-consumer-a"]);
    let admitted_id = admitted.candidate_id.clone();
    assert!(matches!(
        backlog.admit_governed(
            admitted,
            3.0,
            Some(EXTERNAL_OWNER_1869.to_string()),
            &governor
        ),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    let reusable = ReusableCandidateRef {
        candidate_id: admitted_id,
        closure_ref: Some("closure-1869-a".to_string()),
        owner: Some(EXTERNAL_OWNER_1869.to_string()),
        origin_campaign_id: CAMPAIGN_1869.to_string(),
    };
    match assemble_through_consumer(
        &backlog,
        &governor,
        &backing_overlay_1869(now),
        Some(&reusable),
        now,
    ) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
            assert_eq!(candidate.handoff.external_owner_id, EXTERNAL_OWNER_1869);
        }
        other => panic!("governed consumer must close task-local, got {other:?}"),
    }
}

#[test]
fn governed_consumer_refuses_expired_backing() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_evidence_1869();
    let backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let mut expired = backing_overlay_1869(now);
    expired.expires_at = Some(now - Duration::minutes(1));
    let err = assemble_through_consumer(&backlog, &governor, &expired, None, now)
        .expect_err("expired backing never reaches assembly");
    assert_eq!(
        err,
        GovernedClosureError::Bounds(BoundsError::ExpiredOverlay)
    );
}

#[test]
fn forged_governor_strings_are_refused() {
    let governor = governor_evidence_1869();
    let backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    // Well-formed but unminted authority: governed admission refuses.
    let mut forged_policy = policy(8);
    forged_policy.governor_authority_ref = "governor-forged".to_string();
    let mut forged_backlog = BoundedBacklog::new(vec![forged_policy]).expect("shape validates");
    let err = forged_backlog
        .admit_governed(
            candidate(&["ev-1869-forged-a"]),
            3.0,
            Some(EXTERNAL_OWNER_1869.to_string()),
            &governor,
        )
        .expect_err("forged authority never admits");
    assert_eq!(err, BoundsError::GovernorAuthorityUnconfirmed);

    // Well-formed but unminted overlay admission: governed retrieval refuses.
    let now = OffsetDateTime::now_utc();
    let mut forged_overlay = backing_overlay_1869(now);
    forged_overlay.admission_ref = Some("admission-forged".to_string());
    let err = retrieve_governed(GovernedRetrieval {
        requesting_campaign_id: CAMPAIGN_1869,
        requesting_task_id: TASK_1869,
        overlay: &forged_overlay,
        reusable: None,
        draft_delta_present: false,
        cross_task_admission: None,
        backlog: Some(&backlog),
        governor: &governor,
        now,
    })
    .expect_err("forged admission never retrieves");
    assert_eq!(err, BoundsError::GovernorAdmissionUnconfirmed);
}

#[test]
fn archived_reusable_loses_retrieval() {
    let now = OffsetDateTime::now_utc();
    let governor = governor_evidence_1869();
    let mut backlog = BoundedBacklog::new(vec![policy(8)]).expect("policy validates");
    let admitted = candidate(&["ev-1869-archive-a"]);
    let admitted_id = admitted.candidate_id.clone();
    assert!(matches!(
        backlog.admit(admitted, 2.0, Some(EXTERNAL_OWNER_1869.to_string())),
        Ok(AdmitOutcome::Admitted { .. })
    ));
    let reusable = ReusableCandidateRef {
        candidate_id: admitted_id.clone(),
        closure_ref: Some("closure-1869-a".to_string()),
        owner: Some(EXTERNAL_OWNER_1869.to_string()),
        origin_campaign_id: CAMPAIGN_1869.to_string(),
    };
    let gate = |backlog: &BoundedBacklog| {
        retrieve_governed(GovernedRetrieval {
            requesting_campaign_id: CAMPAIGN_1869,
            requesting_task_id: TASK_1869,
            overlay: &backing_overlay_1869(now),
            reusable: Some(&reusable),
            draft_delta_present: false,
            cross_task_admission: None,
            backlog: Some(backlog),
            governor: &governor,
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
