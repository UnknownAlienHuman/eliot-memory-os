#[path = "../src/learning_closure.rs"]
mod learning_closure;

use learning_closure::{
    AdmissionState, AttemptDelta, AttemptOutcomesAndDeltas, AttemptRecord, AttemptStatus,
    CAUSAL_PROPERTY, CampaignAndTarget, CampaignLearningClosureCandidate, CausalAttribution,
    ClosureAssembly, ClosurePolicy, ClosureStatus, DeltaKind, EconomicsRecord, EvidenceSource,
    HarmRecord, LearningClosureError, LifecycleStage, MODULE_ID, OutcomeHarmAndEconomicsEvidence,
    OutcomeKind, OutcomeRecord, OverlayAndActivationAssessments, OverlayRecord, PRODUCT_PULSE,
    PriorClosure, PriorClosureHistory, RUNTIME_LAYER, SOURCE_LAYER, StageAssessment,
};
use std::collections::BTreeSet;

fn campaign() -> CampaignAndTarget {
    CampaignAndTarget {
        campaign_id: "campaign-819-a".to_string(),
        target_id: "target-819-a".to_string(),
        task_id: "task-819-a".to_string(),
        scope_ref: "scope-819-a".to_string(),
        fence_ref: "fence-819-a".to_string(),
        objective_ref: "objective-819-a".to_string(),
        acceptance_ref: "acceptance-819-a".to_string(),
        evaluator_id: "evaluator-819-a".to_string(),
        holdout_ref: "holdout-819-a".to_string(),
    }
}

fn policy() -> ClosurePolicy {
    ClosurePolicy {
        schema_version: 1,
        allow_checkpoint: true,
        max_attempts: 16,
        max_bytes: 1_000_000,
        require_independent_verifier: true,
        external_owner_id: "governor-819".to_string(),
        rollback_owner_id: "rollback-owner-819".to_string(),
        idempotency_key: "idem-819-a".to_string(),
        operation_ref: "op-819-a".to_string(),
    }
}

fn history() -> PriorClosureHistory {
    PriorClosureHistory { prior: Vec::new() }
}

fn changed_delta(attempt_id: &str, target_id: &str) -> AttemptDelta {
    AttemptDelta {
        delta_id: format!("delta-{attempt_id}"),
        attempt_id: attempt_id.to_string(),
        target_id: target_id.to_string(),
        base_state_ref: format!("state-{attempt_id}-before"),
        stale_base: false,
        kind: DeltaKind::Changed {
            before_ref: format!("state-{attempt_id}-before"),
            after_ref: format!("state-{attempt_id}-after"),
        },
    }
}

fn attempt(id: &str, target_id: &str) -> AttemptRecord {
    AttemptRecord {
        attempt_id: id.to_string(),
        consequential: true,
        non_consequential_reason: None,
        status: AttemptStatus::Available,
        has_outcome: true,
        delta: Some(changed_delta(id, target_id)),
    }
}

fn overlay(id: &str, attempt_id: &str) -> OverlayRecord {
    OverlayRecord {
        overlay_id: id.to_string(),
        attempt_id: attempt_id.to_string(),
        base_ref: format!("base-{id}"),
        parent_ref: format!("parent-{id}"),
        admission: AdmissionState::Admitted,
        admission_ref: format!("admission-{id}"),
    }
}

fn stage(
    attempt_id: &str,
    overlay_id: &str,
    stage: LifecycleStage,
    observed: bool,
    use_linked: bool,
    causally_attributed: bool,
) -> StageAssessment {
    StageAssessment {
        attempt_id: attempt_id.to_string(),
        overlay_id: overlay_id.to_string(),
        stage,
        observed,
        evidence_ref: if observed {
            Some(format!("ev-{attempt_id}-{stage:?}-819"))
        } else {
            None
        },
        use_linked,
        causally_attributed,
        source: EvidenceSource::IndependentVerifier {
            verifier_id: "verifier-819-a".to_string(),
        },
    }
}

fn outcome(attempt_id: &str, use_linked: bool) -> OutcomeRecord {
    OutcomeRecord {
        attempt_id: attempt_id.to_string(),
        metric: "task-success-rate".to_string(),
        unit: "ratio".to_string(),
        population: "holdout-819-a".to_string(),
        window: "window-819-a".to_string(),
        source_id: "source-819-a".to_string(),
        evaluator_id: "evaluator-819-a".to_string(),
        baseline_ref: "baseline-819-a".to_string(),
        control_ref: Some("control-819-a".to_string()),
        kind: OutcomeKind::Positive,
        harm: HarmRecord {
            harm_observed: false,
            harm_ref: None,
        },
        use_linked,
        causal: CausalAttribution::Attributed {
            control_ref: "control-819-a".to_string(),
        },
    }
}

fn economics(attempt_id: &str) -> EconomicsRecord {
    EconomicsRecord {
        attempt_id: attempt_id.to_string(),
        cost_known: true,
        cost: 12.5,
        currency: "USD".to_string(),
        unit: "attempt".to_string(),
    }
}

#[allow(clippy::type_complexity)]
fn complete_inputs() -> (
    CampaignAndTarget,
    AttemptOutcomesAndDeltas,
    OverlayAndActivationAssessments,
    OutcomeHarmAndEconomicsEvidence,
    PriorClosureHistory,
    ClosurePolicy,
) {
    let target = "target-819-a";
    let attempts = AttemptOutcomesAndDeltas {
        expected_attempt_ids: vec!["attempt-1".to_string(), "attempt-2".to_string()],
        attempts: vec![attempt("attempt-1", target), attempt("attempt-2", target)],
    };
    let overlays = OverlayAndActivationAssessments {
        overlays: vec![
            overlay("overlay-1", "attempt-1"),
            overlay("overlay-2", "attempt-2"),
        ],
        assessments: vec![
            stage(
                "attempt-1",
                "overlay-1",
                LifecycleStage::Delivery,
                true,
                false,
                false,
            ),
            stage(
                "attempt-1",
                "overlay-1",
                LifecycleStage::Use,
                true,
                true,
                false,
            ),
            stage(
                "attempt-1",
                "overlay-1",
                LifecycleStage::Outcome,
                true,
                true,
                false,
            ),
            stage(
                "attempt-2",
                "overlay-2",
                LifecycleStage::Delivery,
                true,
                false,
                false,
            ),
            stage(
                "attempt-2",
                "overlay-2",
                LifecycleStage::Use,
                true,
                true,
                false,
            ),
            stage(
                "attempt-2",
                "overlay-2",
                LifecycleStage::Outcome,
                true,
                true,
                false,
            ),
        ],
    };
    let evidence = OutcomeHarmAndEconomicsEvidence {
        outcomes: vec![outcome("attempt-1", true), outcome("attempt-2", true)],
        economics: vec![economics("attempt-1"), economics("attempt-2")],
    };
    (
        campaign(),
        attempts,
        overlays,
        evidence,
        history(),
        policy(),
    )
}

fn assemble_complete() -> CampaignLearningClosureCandidate {
    let (c, a, o, e, h, p) = complete_inputs();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => *candidate,
        other => panic!("expected complete candidate, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/1
#[test]
fn case_01_router_meta_identity_and_two_file_nonoverlap() {
    assert_eq!(MODULE_ID, "meta.learning.closure");
    assert_eq!(SOURCE_LAYER, "C1");
    assert_eq!(RUNTIME_LAYER, "R7");
    assert_eq!(CAUSAL_PROPERTY, "campaign learning closure candidate");
    assert_eq!(PRODUCT_PULSE, "ONLINE_LEARNING_INNER_LOOP_PULSE_01");
    let closure_router = include_str!("../learning-closure.module.toml");
    let promotion_router = include_str!("../promotion.module.toml");
    assert!(closure_router.contains("meta.learning.closure"));
    assert!(closure_router.contains("crates/meta/eliot-improvement/src/learning_closure.rs"));
    assert!(closure_router.contains("crates/meta/eliot-improvement/tests/learning_closure.rs"));
    assert!(promotion_router.contains("crates/meta/eliot-improvement/src/promotion_input.rs"));
    assert!(promotion_router.contains("crates/meta/eliot-improvement/tests/promotion_input.rs"));
    assert!(!promotion_router.contains("learning_closure.rs"));
    assert!(!closure_router.contains("promotion_input.rs"));
}

// WORK_UNIT_CASE: 819/2
#[test]
fn case_02_closure_disposition_handoff_vocabulary() {
    let candidate = assemble_complete();
    assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
    // Debt vocabulary is representable without promotion output.
    let debt = ClosureStatus::NoReusableDelta;
    let open = ClosureStatus::OpenDebt;
    let delayed = ClosureStatus::DelayedDebt;
    let checkpoint = ClosureStatus::Checkpoint;
    assert_ne!(debt, open);
    assert_ne!(delayed, checkpoint);
    assert!(candidate.handoff.active_permit.is_none());
    assert!(candidate.handoff.promotion_receipt.is_none());
    assert_eq!(candidate.handoff.external_owner_id, "governor-819");
    assert_eq!(candidate.proof_ceiling, "module-proof-only");
}

// WORK_UNIT_CASE: 819/3
#[test]
fn case_03_complete_task_local_closure_candidate() {
    let candidate = assemble_complete();
    assert_eq!(candidate.campaign_id, "campaign-819-a");
    assert_eq!(candidate.denominators.expected_attempts, 2);
    assert_eq!(candidate.denominators.supplied_attempts, 2);
    assert_eq!(candidate.denominators.consequential_attempts, 2);
    assert!(candidate.missing_evidence.is_empty());
    assert!(!candidate.digest.is_empty());
    assert!(candidate.candidate_id.contains("campaign-819-a"));
}

// WORK_UNIT_CASE: 819/4
#[test]
fn case_04_campaign_target_task_scope_fence_objective_evaluator_identity() {
    let (mut c, a, o, e, h, p) = complete_inputs();
    c.campaign_id = String::new();
    let err = learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p)
        .expect_err("empty campaign id must fail");
    assert_eq!(err, LearningClosureError::MissingField("campaign_id"));
}

// WORK_UNIT_CASE: 819/5
#[test]
fn case_05_duplicate_conflicting_same_id_records_rejected() {
    let (c, mut a, o, e, h, p) = complete_inputs();
    let mut conflicting = attempt("attempt-1", "target-819-a");
    conflicting.has_outcome = false;
    a.attempts.push(conflicting);
    let err = learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p)
        .expect_err("same-ID changed record must fail");
    assert_eq!(
        err,
        LearningClosureError::ConflictingRecord {
            id: "attempt-1".to_string()
        }
    );
}

// WORK_UNIT_CASE: 819/6
#[test]
fn case_06_complete_attempt_denominator_closes() {
    let (c, a, o, e, h, p) = complete_inputs();
    let expected = a.expected_attempt_ids.len();
    let result = learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p);
    match result {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.expected_attempts, expected);
            assert_eq!(
                candidate.denominators.supplied_attempts,
                candidate.denominators.expected_attempts
            );
        }
        other => panic!("complete denominator must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/7
#[test]
fn case_07_missing_partial_stale_unavailable_cancelled_attempt_disposes() {
    let (c, mut a, o, e, h, p) = complete_inputs();
    a.attempts[1].status = AttemptStatus::Unavailable {
        reason: "evidence-store-unavailable-819".to_string(),
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "continue-collect");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("attempt-2"))
            );
            assert!(!disposition.open_debt.is_empty());
        }
        other => panic!("unavailable attempt must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/8
#[test]
fn case_08_non_consequential_attempt_retained_with_reason() {
    let (c, mut a, o, e, h, p) = complete_inputs();
    a.attempts[1].consequential = false;
    a.attempts[1].non_consequential_reason = Some("calibration-probe-819".to_string());
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.non_consequential_attempts, 1);
            assert_eq!(candidate.denominators.consequential_attempts, 1);
        }
        other => panic!("reasoned non-consequential attempt must stay visible, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/9
#[test]
fn case_09_valid_delta_and_evidence_backed_no_change_close() {
    let (c, mut a, mut o, e, h, p) = complete_inputs();
    a.attempts[1].delta = Some(AttemptDelta {
        delta_id: "delta-attempt-2".to_string(),
        attempt_id: "attempt-2".to_string(),
        target_id: "target-819-a".to_string(),
        base_state_ref: "state-attempt-2-before".to_string(),
        stale_base: false,
        kind: DeltaKind::NoChange {
            evidence_ref: Some("owner-no-change-evidence-819".to_string()),
        },
    });
    o.assessments
        .retain(|s| s.attempt_id != "attempt-2" || s.stage != LifecycleStage::Delivery);
    o.assessments.push(stage(
        "attempt-2",
        "overlay-2",
        LifecycleStage::Delivery,
        true,
        false,
        false,
    ));
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.delta_count, 2);
        }
        other => panic!("evidence-backed NoChange must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/10
#[test]
fn case_10_evidence_free_no_change_rejected() {
    let (c, mut a, o, e, h, p) = complete_inputs();
    a.attempts[0].delta = Some(AttemptDelta {
        delta_id: "delta-attempt-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        target_id: "target-819-a".to_string(),
        base_state_ref: "state-attempt-1-before".to_string(),
        stale_base: false,
        kind: DeltaKind::NoChange { evidence_ref: None },
    });
    let err = learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p)
        .expect_err("evidence-free NoChange must fail");
    assert_eq!(
        err,
        LearningClosureError::EvidenceFreeNoChange {
            delta_id: "delta-attempt-1".to_string()
        }
    );
}

// WORK_UNIT_CASE: 819/11
#[test]
fn case_11_stale_base_wrong_target_delta_rejected() {
    let (c, mut a, o, e, h, p) = complete_inputs();
    a.attempts[0].delta = Some(AttemptDelta {
        delta_id: "delta-attempt-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        target_id: "target-819-a".to_string(),
        base_state_ref: "stale-state-819".to_string(),
        stale_base: true,
        kind: DeltaKind::Changed {
            before_ref: "stale-state-819".to_string(),
            after_ref: "state-attempt-1-after".to_string(),
        },
    });
    let err = learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p)
        .expect_err("stale base must fail");
    assert_eq!(
        err,
        LearningClosureError::StaleDelta {
            delta_id: "delta-attempt-1".to_string()
        }
    );

    let (c2, mut a2, o2, e2, h2, p2) = complete_inputs();
    a2.attempts[0].delta = Some(AttemptDelta {
        delta_id: "delta-attempt-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        target_id: "wrong-target-819".to_string(),
        base_state_ref: "state-attempt-1-before".to_string(),
        stale_base: false,
        kind: DeltaKind::Changed {
            before_ref: "state-attempt-1-before".to_string(),
            after_ref: "state-attempt-1-after".to_string(),
        },
    });
    let err2 = learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2)
        .expect_err("wrong-target delta must fail");
    assert_eq!(
        err2,
        LearningClosureError::WrongTargetDelta {
            delta_id: "delta-attempt-1".to_string()
        }
    );
}

// WORK_UNIT_CASE: 819/12
#[test]
fn case_12_overlay_admission_activation_lineage_bound() {
    let (c, a, mut o, e, h, p) = complete_inputs();
    o.overlays[0].base_ref = String::new();
    let err = learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p)
        .expect_err("empty overlay base must fail lineage");
    assert_eq!(err, LearningClosureError::MissingField("base_ref"));
}

// WORK_UNIT_CASE: 819/13
#[test]
fn case_13_unadmitted_expired_conflicted_rolled_back_overlay_retained() {
    for admission in [
        AdmissionState::Unadmitted,
        AdmissionState::Expired,
        AdmissionState::Conflicted,
        AdmissionState::RolledBack,
    ] {
        let (c, a, mut o, e, h, p) = complete_inputs();
        o.overlays[0].admission = admission.clone();
        match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
            Ok(ClosureAssembly::Disposition(disposition)) => {
                assert_eq!(disposition.disposition, "task-local-retain");
                assert!(
                    disposition
                        .missing_evidence
                        .iter()
                        .any(|m| m.contains("overlay-1"))
                );
            }
            other => panic!("{admission:?} overlay must retain, got {other:?}"),
        }
    }
}

// WORK_UNIT_CASE: 819/14
#[test]
fn case_14_every_lifecycle_stage_distinct() {
    assert_eq!(LifecycleStage::all().len(), 10);
    let distinct: BTreeSet<LifecycleStage> = LifecycleStage::all().iter().copied().collect();
    assert_eq!(distinct.len(), 10);
    // A full ten-stage chain keeps every denominator member visible.
    let (c, a, mut o, mut e, h, p) = complete_inputs();
    o.assessments = vec![
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Delivery,
            true,
            false,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Ack,
            true,
            false,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Visibility,
            true,
            false,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Selection,
            true,
            false,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Adherence,
            true,
            false,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Use,
            true,
            true,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Action,
            true,
            true,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Outcome,
            true,
            true,
            false,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Benefit,
            true,
            true,
            true,
        ),
        stage(
            "attempt-1",
            "overlay-1",
            LifecycleStage::Causality,
            true,
            true,
            true,
        ),
    ];
    // Attempt-2 keeps the minimal valid chain so only attempt-1 exercises all ten.
    o.assessments.extend([
        stage(
            "attempt-2",
            "overlay-2",
            LifecycleStage::Delivery,
            true,
            false,
            false,
        ),
        stage(
            "attempt-2",
            "overlay-2",
            LifecycleStage::Use,
            true,
            true,
            false,
        ),
        stage(
            "attempt-2",
            "overlay-2",
            LifecycleStage::Outcome,
            true,
            true,
            false,
        ),
    ]);
    e.outcomes[0].causal = CausalAttribution::Attributed {
        control_ref: "control-819-a".to_string(),
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert!(candidate.denominators.stage_count >= 10);
        }
        other => panic!("full distinct stage chain must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/15
#[test]
fn case_15_delivery_ack_not_visibility_use() {
    let (c, a, mut o, e, h, p) = complete_inputs();
    // Delivery observed, use missing: no inference from delivery to use.
    o.assessments.retain(|s| {
        !(s.attempt_id == "attempt-1"
            && matches!(s.stage, LifecycleStage::Use | LifecycleStage::Outcome))
    });
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("delivery-without-use"))
            );
        }
        other => panic!("delivery without use must not close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/16
#[test]
fn case_16_visibility_selection_not_adherence_use() {
    let (c, a, mut o, e, h, p) = complete_inputs();
    o.assessments.retain(|s| {
        !(s.attempt_id == "attempt-1"
            && matches!(
                s.stage,
                LifecycleStage::Delivery
                    | LifecycleStage::Adherence
                    | LifecycleStage::Use
                    | LifecycleStage::Outcome
            ))
    });
    o.assessments.push(stage(
        "attempt-1",
        "overlay-1",
        LifecycleStage::Visibility,
        true,
        false,
        false,
    ));
    o.assessments.push(stage(
        "attempt-1",
        "overlay-1",
        LifecycleStage::Selection,
        true,
        false,
        false,
    ));
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("visibility-selection-without-adherence-use"))
            );
        }
        other => panic!("visibility/selection without adherence/use must not close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/17
#[test]
fn case_17_use_without_outcome_linkage_disposes() {
    let (c, a, mut o, mut e, h, p) = complete_inputs();
    for assessment in &mut o.assessments {
        if assessment.attempt_id == "attempt-1"
            && matches!(
                assessment.stage,
                LifecycleStage::Outcome | LifecycleStage::Benefit
            )
        {
            assessment.observed = false;
            assessment.evidence_ref = None;
            assessment.use_linked = false;
        }
    }
    e.outcomes[0].use_linked = false;
    e.outcomes[0].kind = OutcomeKind::Unmeasured;
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("use-without-outcome-linkage"))
            );
        }
        other => panic!("use without outcome linkage must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/18
#[test]
fn case_18_outcome_without_proven_overlay_use_disposes() {
    let (c, a, mut o, e, h, p) = complete_inputs();
    o.assessments.retain(|s| {
        !(s.attempt_id == "attempt-1"
            && matches!(s.stage, LifecycleStage::Delivery | LifecycleStage::Use))
    });
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("outcome-without-proven-use"))
            );
        }
        other => panic!("outcome without proven use must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/19
#[test]
fn case_19_benefit_without_causal_attribution_disposes() {
    let (c, a, mut o, mut e, h, p) = complete_inputs();
    o.assessments.push(stage(
        "attempt-1",
        "overlay-1",
        LifecycleStage::Benefit,
        true,
        true,
        false,
    ));
    e.outcomes[0].causal = CausalAttribution::CorrelationalOnly;
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("benefit-without-causal-attribution"))
            );
        }
        other => panic!("benefit without causal attribution must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/20
#[test]
fn case_20_process_model_worker_self_report_insufficient() {
    let (c, a, mut o, e, h, p) = complete_inputs();
    for assessment in &mut o.assessments {
        if assessment.attempt_id == "attempt-1" && assessment.stage == LifecycleStage::Outcome {
            assessment.source = EvidenceSource::SelfReport {
                reporter: "worker-819".to_string(),
            };
        }
    }
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("self-report insufficient"))
            );
        }
        other => panic!("self-report outcome must not close, got {other:?}"),
    }
}

fn multi_inputs(
    kinds: &[OutcomeKind],
) -> (
    CampaignAndTarget,
    AttemptOutcomesAndDeltas,
    OverlayAndActivationAssessments,
    OutcomeHarmAndEconomicsEvidence,
    PriorClosureHistory,
    ClosurePolicy,
) {
    let target = "target-819-a";
    let mut expected = Vec::new();
    let mut attempts = Vec::new();
    let mut overlays = Vec::new();
    let mut assessments = Vec::new();
    let mut outcomes = Vec::new();
    let mut records = Vec::new();
    for (index, kind) in kinds.iter().enumerate() {
        let attempt_id = format!("mattempt-{}", index + 1);
        let overlay_id = format!("moverlay-{}", index + 1);
        expected.push(attempt_id.clone());
        attempts.push(attempt(&attempt_id, target));
        overlays.push(overlay(&overlay_id, &attempt_id));
        assessments.push(stage(
            &attempt_id,
            &overlay_id,
            LifecycleStage::Delivery,
            true,
            false,
            false,
        ));
        assessments.push(stage(
            &attempt_id,
            &overlay_id,
            LifecycleStage::Use,
            true,
            true,
            false,
        ));
        assessments.push(stage(
            &attempt_id,
            &overlay_id,
            LifecycleStage::Outcome,
            true,
            true,
            false,
        ));
        let mut record = outcome(&attempt_id, true);
        record.kind = kind.clone();
        outcomes.push(record);
        records.push(economics(&attempt_id));
    }
    (
        campaign(),
        AttemptOutcomesAndDeltas {
            expected_attempt_ids: expected,
            attempts,
        },
        OverlayAndActivationAssessments {
            overlays,
            assessments,
        },
        OutcomeHarmAndEconomicsEvidence {
            outcomes,
            economics: records,
        },
        history(),
        policy(),
    )
}

// WORK_UNIT_CASE: 819/21
#[test]
fn case_21_complete_vs_incomplete_member_stage_denominator() {
    let candidate = assemble_complete();
    assert_eq!(candidate.denominators.supplied_attempts, 2);
    // Incomplete member denominator: attempt-2 missing from supply.
    let (c, mut a, o, e, h, p) = complete_inputs();
    a.attempts.pop();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "continue-collect");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("attempt-2"))
            );
        }
        other => panic!("missing member must dispose, got {other:?}"),
    }
    // Incomplete stage denominator: attempt-2 loses proven use.
    let (c2, a2, mut o2, e2, h2, p2) = complete_inputs();
    o2.assessments
        .retain(|s| !(s.attempt_id == "attempt-2" && s.stage == LifecycleStage::Use));
    match learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("delivery-without-use"))
            );
        }
        other => panic!("missing stage must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/22
#[test]
fn case_22_positive_negative_mixed_unchanged_harmful_outcome() {
    use OutcomeKind::{Harmful, Mixed, Negative, Positive, Unchanged};
    let (c, a, o, e, h, p) =
        multi_inputs(&[Positive, Negative, Mixed, Unchanged]);
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.outcome_count, 4);
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
        }
        other => panic!("four distinct non-harmful kinds must close, got {other:?}"),
    }
    // Kinds are load-bearing in the digest, never collapsed to positive.
    let (c2, a2, o2, e2, h2, p2) =
        multi_inputs(&[Positive, Positive, Positive, Positive]);
    let (c3, a3, o3, e3, h3, p3) =
        multi_inputs(&[Positive, Negative, Mixed, Unchanged]);
    let uniform = match learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2)
    {
        Ok(ClosureAssembly::Candidate(candidate)) => candidate,
        other => panic!("uniform kinds must close, got {other:?}"),
    };
    let varied = match learning_closure::assemble_campaign_learning_closure(c3, a3, o3, e3, h3, p3)
    {
        Ok(ClosureAssembly::Candidate(candidate)) => candidate,
        other => panic!("varied kinds must close, got {other:?}"),
    };
    assert_ne!(uniform.digest, varied.digest);
    // Harmful kind never closes: it retires to review with visible debt.
    let (c4, a4, o4, mut e4, h4, p4) =
        multi_inputs(&[Positive, Negative, Mixed, Harmful]);
    e4.outcomes[3].harm = HarmRecord {
        harm_observed: true,
        harm_ref: Some("harm-819-m4".to_string()),
    };
    match learning_closure::assemble_campaign_learning_closure(c4, a4, o4, e4, h4, p4) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "retire-review");
            assert!(
                disposition
                    .open_debt
                    .iter()
                    .any(|m| m.contains("mattempt-4"))
            );
        }
        other => panic!("harmful outcome must retire, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/23
#[test]
fn case_23_missing_measurement_vs_no_event() {
    // Missing instrumentation is unknown, never zero harm/no effect: a mutant
    // that closes over Unmeasured outcomes must fail here.
    let (c, a, mut o, mut e, h, p) = complete_inputs();
    e.outcomes[0].kind = OutcomeKind::Unmeasured;
    e.outcomes[0].use_linked = false;
    for assessment in &mut o.assessments {
        if assessment.attempt_id == "attempt-1"
            && matches!(
                assessment.stage,
                LifecycleStage::Outcome | LifecycleStage::Benefit
            )
        {
            assessment.observed = false;
            assessment.evidence_ref = None;
            assessment.use_linked = false;
        }
    }
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("use-without-outcome-linkage"))
            );
        }
        other => panic!("unmeasured outcome must dispose, got {other:?}"),
    }
    // An observed no-event is legitimate evidence and closes.
    let (c2, a2, o2, mut e2, h2, p2) = complete_inputs();
    e2.outcomes[0].kind = OutcomeKind::NoEvent;
    match learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.outcome_count, 2);
        }
        other => panic!("observed no-event must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/24
#[test]
fn case_24_metric_unit_population_window_mismatch() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[1].metric = "other-metric-819".to_string();
    e.outcomes[1].unit = "other-unit-819".to_string();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("metric-identity-mismatch"))
            );
        }
        other => panic!("metric/unit mismatch must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/25
#[test]
fn case_25_compatible_baseline_control_comparison() {
    let (c, a, o, e, h, p) = complete_inputs();
    assert_eq!(e.outcomes[0].baseline_ref, e.outcomes[1].baseline_ref);
    assert_eq!(e.outcomes[0].control_ref, e.outcomes[1].control_ref);
    assert!(e.outcomes[0].control_ref.is_some());
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.outcome_count, 2);
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
        }
        other => panic!("compatible comparison must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/26
#[test]
fn case_26_post_hoc_favorable_baseline_rejected() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[1].baseline_ref = "favorable-baseline-819".to_string();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("post-hoc-baseline"))
            );
        }
        other => panic!("post-hoc baseline must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/27
#[test]
fn case_27_attrition_selection_bias() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[1].population = "subgroup-favorable-819".to_string();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("attrition-selection-bias"))
            );
            assert_eq!(
                disposition.missing_owner,
                Some("evaluator-819-a".to_string())
            );
        }
        other => panic!("attrited population must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/28
#[test]
fn case_28_changed_environment_target_scope() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[1].window = "shifted-window-819".to_string();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("environment-window-change"))
            );
        }
        other => panic!("changed environment must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/29
#[test]
fn case_29_complete_partial_confounder_denominator() {
    let (c, a, o, e, h, p) = complete_inputs();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.outcome_count, 2);
        }
        other => panic!("complete confounder denominator must close, got {other:?}"),
    }
    let (c2, a2, o2, mut e2, h2, p2) = complete_inputs();
    e2.outcomes[1].control_ref = None;
    match learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("confounder-denominator-incomplete"))
            );
        }
        other => panic!("partial confounder denominator must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/30
#[test]
fn case_30_concurrent_intervention() {
    let (c, a, mut o, e, h, p) = complete_inputs();
    o.assessments.push(stage(
        "attempt-1",
        "overlay-1",
        LifecycleStage::Action,
        true,
        false,
        false,
    ));
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("concurrent-intervention-undisclosed"))
            );
        }
        other => panic!("undisclosed intervention must dispose, got {other:?}"),
    }
    // A use-linked, attributed action is accounted intervention evidence.
    let (c2, a2, mut o2, e2, h2, p2) = complete_inputs();
    o2.assessments.push(stage(
        "attempt-1",
        "overlay-1",
        LifecycleStage::Action,
        true,
        true,
        true,
    ));
    match learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
        }
        other => panic!("linked intervention must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/31
#[test]
fn case_31_same_model_generator_evaluator_dependence() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[0].source_id = e.outcomes[0].evaluator_id.clone();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("generator-evaluator-dependence"))
            );
        }
        other => panic!("dependent evaluation must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/32
#[test]
fn case_32_correlation_before_after_temporal_order_not_causality() {
    let (c, a, mut o, mut e, h, p) = complete_inputs();
    o.assessments.push(stage(
        "attempt-1",
        "overlay-1",
        LifecycleStage::Benefit,
        true,
        true,
        false,
    ));
    e.outcomes[0].causal = CausalAttribution::None;
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("benefit-without-causal-attribution"))
            );
        }
        other => panic!("uncorrelated benefit must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/33
#[test]
fn case_33_one_positive_attempt_not_broad_transfer() {
    use OutcomeKind::{Negative, Positive};
    let (c, a, o, e, h, p) = multi_inputs(&[Positive, Negative]);
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
            assert_eq!(candidate.handoff.requested_class, "task-local-retention");
            assert_eq!(candidate.proof_ceiling, "module-proof-only");
            assert!(candidate.handoff.active_permit.is_none());
            assert!(candidate.handoff.promotion_receipt.is_none());
        }
        other => panic!("mixed campaign must stay task-local, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/34
#[test]
fn case_34_valid_bounded_economics_evidence() {
    let (c, a, o, e, h, p) = complete_inputs();
    for record in &e.economics {
        assert!(record.cost_known);
        assert_eq!(record.currency, "USD");
        assert_eq!(record.unit, "attempt");
    }
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.economics_count, 2);
            assert_eq!(candidate.denominators.outcome_count, 2);
        }
        other => panic!("bounded economics must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/35
#[test]
fn case_35_unknown_cost_not_zero() {
    // A mutant that prices unknown cost at zero and closes must fail here.
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.economics[0].cost_known = false;
    e.economics[0].cost = 0.0;
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "continue-collect");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("unknown cost is not zero"))
            );
            assert!(!disposition.open_debt.is_empty());
        }
        other => panic!("unknown cost must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/36
#[test]
fn case_36_currency_unit_mismatch() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.economics[1].currency = "EUR".to_string();
    e.economics[1].unit = "run".to_string();
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("currency-unit-mismatch"))
            );
        }
        other => panic!("currency/unit mismatch must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/37
#[test]
fn case_37_low_cost_cannot_compensate_harm() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[0].kind = OutcomeKind::Harmful;
    e.outcomes[0].harm = HarmRecord {
        harm_observed: true,
        harm_ref: Some("harm-819-cheap".to_string()),
    };
    e.economics[0].cost = 0.01;
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "retire-review");
            assert!(
                disposition
                    .open_debt
                    .iter()
                    .any(|m| m.contains("attempt-1"))
            );
        }
        other => panic!("cheap harm must still retire, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/38
#[test]
fn case_38_retained_rejected_superseded_conflicted_expired_updates() {
    // History (superseded + active, same + other campaigns) binds the digest.
    let (c, a, o, e, _, p) = complete_inputs();
    let plain = match learning_closure::assemble_campaign_learning_closure(
        c.clone(),
        a.clone(),
        o.clone(),
        e.clone(),
        history(),
        p.clone(),
    ) {
        Ok(ClosureAssembly::Candidate(candidate)) => candidate,
        other => panic!("plain campaign must close, got {other:?}"),
    };
    let with_history = PriorClosureHistory {
        prior: vec![
            PriorClosure {
                closure_id: "closure-819-old".to_string(),
                campaign_id: "campaign-819-a".to_string(),
                digest: "old-digest-819".to_string(),
                superseded: true,
            },
            PriorClosure {
                closure_id: "closure-819-live".to_string(),
                campaign_id: "campaign-819-a".to_string(),
                digest: "live-digest-819".to_string(),
                superseded: false,
            },
            PriorClosure {
                closure_id: "closure-819-other".to_string(),
                campaign_id: "campaign-819-other".to_string(),
                digest: "other-digest-819".to_string(),
                superseded: false,
            },
        ],
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, with_history, p) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.denominators.supplied_attempts, 2);
            assert_ne!(candidate.digest, plain.digest);
        }
        other => panic!("historic updates must stay bound, got {other:?}"),
    }
    // A conflicted update is retained with debt, never silently dropped.
    let (c2, a2, mut o2, e2, h2, p2) = complete_inputs();
    o2.overlays[0].admission = AdmissionState::Conflicted;
    match learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "task-local-retain");
            assert!(
                disposition
                    .open_debt
                    .iter()
                    .any(|m| m.contains("overlay-1"))
            );
        }
        other => panic!("conflicted update must retain, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/39
#[test]
fn case_39_hidden_harmful_rejected_update_invalidates_complete() {
    // A mutant that ignores harm flags and closes must fail here.
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[0].harm = HarmRecord {
        harm_observed: true,
        harm_ref: Some("hidden-harm-819".to_string()),
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "retire-review");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("attempt-1"))
            );
            assert!(!disposition.open_debt.is_empty());
        }
        other => panic!("hidden harm must invalidate closure, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/40
#[test]
fn case_40_no_winner_by_latest_confidence_source_count() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    let mut rival = outcome("attempt-1", true);
    rival.kind = OutcomeKind::Negative;
    e.outcomes.push(rival);
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("conflicting-outcomes-no-winner"))
            );
        }
        other => panic!("contradictory outcomes must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/41
#[test]
fn case_41_materially_equivalent_repeat_campaign() {
    let (c, a, o, e, _, p) = complete_inputs();
    let evidence_hex =
        learning_closure::closure_evidence_digest(&c, &a, &o, &e);
    let repeat_history = PriorClosureHistory {
        prior: vec![PriorClosure {
            closure_id: "closure-819-first".to_string(),
            campaign_id: "campaign-819-a".to_string(),
            digest: evidence_hex.clone(),
            superseded: false,
        }],
    };
    match learning_closure::assemble_campaign_learning_closure(
        c.clone(),
        a.clone(),
        o.clone(),
        e.clone(),
        repeat_history,
        p.clone(),
    ) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "repeat-review");
            assert!(
                disposition
                    .open_debt
                    .iter()
                    .any(|m| m.contains("closure-819-first"))
            );
        }
        other => panic!("blind repeat must dispose, got {other:?}"),
    }
    // A superseded prior never blocks a fresh closure.
    let superseded_history = PriorClosureHistory {
        prior: vec![PriorClosure {
            closure_id: "closure-819-first".to_string(),
            campaign_id: "campaign-819-a".to_string(),
            digest: evidence_hex,
            superseded: true,
        }],
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, superseded_history, p)
    {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
        }
        other => panic!("superseded repeat must close, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/42
#[test]
fn case_42_external_promotion_review_only_at_proof_ceiling() {
    let candidate = assemble_complete();
    assert_eq!(candidate.proof_ceiling, "module-proof-only");
    assert_eq!(candidate.handoff.requested_class, "task-local-retention");
    assert_eq!(candidate.handoff.external_owner_id, "governor-819");
    assert_eq!(candidate.handoff.rollback_owner_id, "rollback-owner-819");
    assert!(candidate.handoff.active_permit.is_none());
    assert!(candidate.handoff.promotion_receipt.is_none());
}

// WORK_UNIT_CASE: 819/43
#[test]
fn case_43_candidate_for_review_cannot_become_promoted() {
    let candidate = assemble_complete();
    match &candidate.status {
        ClosureStatus::ClosedTaskLocal
        | ClosureStatus::Checkpoint
        | ClosureStatus::OpenDebt
        | ClosureStatus::NoReusableDelta
        | ClosureStatus::DelayedDebt => {}
    }
    assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
    assert_eq!(format!("{:?}", candidate.status), "ClosedTaskLocal");
    assert!(candidate.handoff.promotion_receipt.is_none());
    assert!(candidate.handoff.active_permit.is_none());
}

// WORK_UNIT_CASE: 819/44
#[test]
fn case_44_insufficient_evidence_disposes_never_fabricates() {
    // Unavailable attempt: delayed debt stays visible, never dropped. A mutant
    // that deletes delayed Learning debt must fail the open-debt assert.
    let (c, mut a, o, e, h, p) = complete_inputs();
    a.attempts[0].status = AttemptStatus::Stale {
        reason: "delayed-outcome-819".to_string(),
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "continue-collect");
            assert!(!disposition.open_debt.is_empty());
            assert!(disposition.missing_owner.is_some());
        }
        other => panic!("stale attempt must dispose, got {other:?}"),
    }
    // Self-reported outcome never fabricates closure.
    let (c2, a2, mut o2, e2, h2, p2) = complete_inputs();
    for assessment in &mut o2.assessments {
        if assessment.attempt_id == "attempt-2" && assessment.stage == LifecycleStage::Outcome {
            assessment.source = EvidenceSource::SelfReport {
                reporter: "worker-819".to_string(),
            };
        }
    }
    match learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "inconclusive");
            assert!(!disposition.open_debt.is_empty());
        }
        other => panic!("self-report must dispose, got {other:?}"),
    }
    // Unknown cost never fabricates closure.
    let (c3, a3, o3, mut e3, h3, p3) = complete_inputs();
    e3.economics[1].cost_known = false;
    match learning_closure::assemble_campaign_learning_closure(c3, a3, o3, e3, h3, p3) {
        Ok(ClosureAssembly::Disposition(_)) => {}
        other => panic!("unknown cost must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/45
#[test]
fn case_45_reject_retire_disable_review_without_applied_decision() {
    let (c, a, o, mut e, h, p) = complete_inputs();
    e.outcomes[0].kind = OutcomeKind::Harmful;
    e.outcomes[0].harm = HarmRecord {
        harm_observed: true,
        harm_ref: Some("harm-819-retire".to_string()),
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "retire-review");
            assert_eq!(disposition.retain_ref, "scope-819-a");
            assert_eq!(
                disposition.missing_owner,
                Some("evaluator-819-a".to_string())
            );
            assert!(!disposition.open_debt.is_empty());
        }
        other => panic!("harm must retire without decision, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/46
#[test]
fn case_46_exact_external_owner_rollback_disable_reopen_expiry() {
    let candidate = assemble_complete();
    assert_eq!(candidate.handoff.external_owner_id, "governor-819");
    assert_eq!(candidate.handoff.rollback_owner_id, "rollback-owner-819");
    assert_eq!(candidate.handoff.disable_owner_id, "rollback-owner-819");
    assert_eq!(candidate.handoff.reopen_owner_id, "governor-819");
    assert_eq!(candidate.handoff.evidence_ref, "scope-819-a");
    assert_eq!(candidate.handoff.approval_fence_ref, "fence-819-a");
    assert_eq!(candidate.handoff.expiry_ref, "op-819-a");
}

// WORK_UNIT_CASE: 819/47
#[test]
fn case_47_missing_owner_or_irreversible_control_gap() {
    let (c, a, o, e, h, mut p) = complete_inputs();
    p.external_owner_id = String::new();
    let err = learning_closure::assemble_campaign_learning_closure(
        c,
        a,
        o,
        e,
        h,
        p,
    )
    .expect_err("missing external owner must fail");
    assert_eq!(err, LearningClosureError::MissingField("external_owner_id"));

    let (c2, a2, o2, e2, h2, mut p2) = complete_inputs();
    p2.rollback_owner_id = String::new();
    let err2 = learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2)
        .expect_err("missing rollback owner must fail");
    assert_eq!(
        err2,
        LearningClosureError::MissingField("rollback_owner_id")
    );

    let (c3, a3, o3, e3, h3, mut p3) = complete_inputs();
    p3.idempotency_key = String::new();
    let err3 = learning_closure::assemble_campaign_learning_closure(c3, a3, o3, e3, h3, p3)
        .expect_err("missing idempotency key must fail");
    assert_eq!(err3, LearningClosureError::MissingField("idempotency_key"));
}

// WORK_UNIT_CASE: 819/48
#[test]
fn case_48_no_active_permit_lease_write_or_promotion_receipt() {
    let candidate = assemble_complete();
    assert!(candidate.handoff.active_permit.is_none());
    assert!(candidate.handoff.promotion_receipt.is_none());
    assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
    // Dispositions carry retention only, never receipts.
    let (c, mut a, o, e, h, p) = complete_inputs();
    a.attempts[0].status = AttemptStatus::Unavailable {
        reason: "evidence-store-down-819".to_string(),
    };
    match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.retain_ref, "scope-819-a");
            assert!(disposition.missing_owner.is_some());
        }
        other => panic!("unavailable attempt must dispose, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 819/49
#[test]
fn case_49_independent_item_output_work_deadline_bounds() {
    let (c, a, o, e, h, mut p) = complete_inputs();
    p.max_attempts = 1;
    let err = learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p)
        .expect_err("attempt overflow must fail");
    assert!(matches!(err, LearningClosureError::BoundExceeded { .. }));

    let (c2, a2, o2, e2, h2, mut p2) = complete_inputs();
    p2.max_bytes = 1;
    let err2 = learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2)
        .expect_err("byte overflow must fail");
    assert!(matches!(err2, LearningClosureError::BoundExceeded { .. }));

    let (c3, mut a3, o3, e3, h3, p3) = complete_inputs();
    a3.expected_attempt_ids[0] = String::new();
    let err3 = learning_closure::assemble_campaign_learning_closure(c3, a3, o3, e3, h3, p3)
        .expect_err("malformed attempt id must fail");
    assert!(matches!(err3, LearningClosureError::Malformed { .. }));

    let (c4, a4, o4, e4, h4, mut p4) = complete_inputs();
    p4.schema_version = 99;
    let err4 = learning_closure::assemble_campaign_learning_closure(c4, a4, o4, e4, h4, p4)
        .expect_err("unknown schema must fail");
    assert_eq!(err4, LearningClosureError::UnsupportedSchema { version: 99 });
}

// WORK_UNIT_CASE: 819/50
#[test]
fn case_50_replay_and_changed_same_id_policy_conflict() {
    // Replay under identical inputs is byte-identical: no spurious conflict.
    let (c, a, o, e, h, p) = complete_inputs();
    let first = match learning_closure::assemble_campaign_learning_closure(
        c.clone(),
        a.clone(),
        o.clone(),
        e.clone(),
        h.clone(),
        p.clone(),
    ) {
        Ok(ClosureAssembly::Candidate(candidate)) => candidate,
        other => panic!("first replay must close, got {other:?}"),
    };
    let second = match learning_closure::assemble_campaign_learning_closure(c, a, o, e, h, p.clone())
    {
        Ok(ClosureAssembly::Candidate(candidate)) => candidate,
        other => panic!("second replay must close, got {other:?}"),
    };
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.candidate_id, second.candidate_id);
    // Changed same-ID record conflicts instead of silently winning.
    let (c2, mut a2, o2, e2, h2, p2) = complete_inputs();
    let mut rival = attempt("attempt-1", "target-819-a");
    rival.has_outcome = false;
    a2.attempts.push(rival);
    let err = learning_closure::assemble_campaign_learning_closure(c2, a2, o2, e2, h2, p2)
        .expect_err("changed same-ID record must fail");
    assert_eq!(
        err,
        LearningClosureError::ConflictingRecord {
            id: "attempt-1".to_string()
        }
    );
    // Changed policy binds a different digest.
    let (c3, a3, o3, e3, h3, mut p3) = complete_inputs();
    p3.idempotency_key = "idem-819-rotated".to_string();
    let rotated =
        match learning_closure::assemble_campaign_learning_closure(c3, a3, o3, e3, h3, p3) {
            Ok(ClosureAssembly::Candidate(candidate)) => candidate,
            other => panic!("rotated policy must close, got {other:?}"),
        };
    assert_ne!(first.digest, rotated.digest);
}
