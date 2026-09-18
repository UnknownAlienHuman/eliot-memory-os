//! Candidate-admission edge proof for issue #1145 (WIRE).
//!
//! Proves the two proved cells (`meta.learning.closure` from #819 and
//! `meta.improvement.promotion_input` from #972) are jointly consumable
//! through the crate public edge that Governor maintenance admission binds,
//! and that every result stays candidate/advisory-only with no promotion
//! performance. Uses the public edge only; no `#[path]` copies.

use eliot_improvement::learning_closure::{
    AdmissionState, AttemptDelta, AttemptOutcomesAndDeltas, AttemptRecord, AttemptStatus,
    CampaignAndTarget, CausalAttribution, ClosureAssembly, ClosurePolicy, ClosureStatus, DeltaKind,
    EconomicsRecord, EvidenceSource, HarmRecord, LifecycleStage, OutcomeHarmAndEconomicsEvidence,
    OutcomeKind, OutcomeRecord, OverlayAndActivationAssessments, OverlayRecord,
    PriorClosureHistory, StageAssessment,
};
use eliot_improvement::promotion_input::{
    ActivationGates, BenefitEvidence, ComparisonEvidence, EconomicsEvidence, EvaluatorEvidence,
    HarmMember, MemberOutcome, ProductPulseEvidence, PulseResult, RetentionEvidence,
    RollbackEvidence, StageGate, TransferEvidence,
};
use eliot_improvement::{
    ClosureBinding, PromotionCandidate, PromotionGateEvidence, PromotionInputPolicy,
    PromotionPreparation, PromotionRequest,
};

// ---------------------------------------------------------------------------
// Closure fixtures (#819 shape, 1145 identity).
// ---------------------------------------------------------------------------

fn closure_campaign() -> CampaignAndTarget {
    CampaignAndTarget {
        campaign_id: "campaign-1145-a".to_string(),
        target_id: "target-1145-a".to_string(),
        task_id: "task-1145-a".to_string(),
        scope_ref: "scope-1145-a".to_string(),
        fence_ref: "fence-1145-a".to_string(),
        objective_ref: "objective-1145-a".to_string(),
        acceptance_ref: "acceptance-1145-a".to_string(),
        evaluator_id: "evaluator-1145-a".to_string(),
        holdout_ref: "holdout-1145-a".to_string(),
    }
}

fn closure_policy() -> ClosurePolicy {
    ClosurePolicy {
        schema_version: 1,
        allow_checkpoint: true,
        max_attempts: 16,
        max_bytes: 1_000_000,
        require_independent_verifier: true,
        external_owner_id: "governor-1145".to_string(),
        rollback_owner_id: "rollback-1145".to_string(),
        idempotency_key: "idem-1145-a".to_string(),
        operation_ref: "op-1145-a".to_string(),
    }
}

fn closure_attempt(id: &str) -> AttemptRecord {
    AttemptRecord {
        attempt_id: id.to_string(),
        consequential: true,
        non_consequential_reason: None,
        status: AttemptStatus::Available,
        has_outcome: true,
        delta: Some(AttemptDelta {
            delta_id: format!("delta-{id}"),
            attempt_id: id.to_string(),
            target_id: "target-1145-a".to_string(),
            base_state_ref: format!("state-{id}-before"),
            stale_base: false,
            kind: DeltaKind::Changed {
                before_ref: format!("state-{id}-before"),
                after_ref: format!("state-{id}-after"),
            },
        }),
    }
}

fn closure_overlay(id: &str, attempt_id: &str) -> OverlayRecord {
    OverlayRecord {
        overlay_id: id.to_string(),
        attempt_id: attempt_id.to_string(),
        base_ref: format!("base-{id}"),
        parent_ref: format!("parent-{id}"),
        admission: AdmissionState::Admitted,
        admission_ref: format!("admission-{id}"),
    }
}

fn closure_stage(attempt_id: &str, overlay_id: &str, stage: LifecycleStage) -> StageAssessment {
    StageAssessment {
        attempt_id: attempt_id.to_string(),
        overlay_id: overlay_id.to_string(),
        stage,
        observed: true,
        evidence_ref: Some(format!("ev-1145-{attempt_id}-{stage:?}")),
        use_linked: matches!(stage, LifecycleStage::Use | LifecycleStage::Outcome),
        causally_attributed: false,
        source: EvidenceSource::IndependentVerifier {
            verifier_id: "verifier-1145-a".to_string(),
        },
    }
}

fn closure_outcome(attempt_id: &str) -> OutcomeRecord {
    OutcomeRecord {
        attempt_id: attempt_id.to_string(),
        metric: "task-success-rate".to_string(),
        unit: "ratio".to_string(),
        population: "holdout-1145-a".to_string(),
        window: "window-1145-a".to_string(),
        source_id: "source-1145-a".to_string(),
        evaluator_id: "evaluator-1145-a".to_string(),
        baseline_ref: "baseline-1145-a".to_string(),
        control_ref: Some("control-1145-a".to_string()),
        kind: OutcomeKind::Positive,
        harm: HarmRecord {
            harm_observed: false,
            harm_ref: None,
        },
        use_linked: true,
        causal: CausalAttribution::Attributed {
            control_ref: "control-1145-a".to_string(),
        },
    }
}

fn closure_economics(attempt_id: &str) -> EconomicsRecord {
    EconomicsRecord {
        attempt_id: attempt_id.to_string(),
        cost_known: true,
        cost: 12.5,
        currency: "USD".to_string(),
        unit: "attempt".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Promotion fixtures (#972 shape, 1145 identity).
// ---------------------------------------------------------------------------

fn promotion_stage(evidence: &str, use_linked: bool) -> StageGate {
    StageGate {
        observed: true,
        evidence_ref: Some(evidence.to_string()),
        compatible: true,
        use_linked,
    }
}

fn promotion_request() -> PromotionRequest {
    PromotionRequest {
        request_id: "req-1145-a".to_string(),
        operation_ref: "op-1145-a".to_string(),
        idempotency_key: "idem-1145-a".to_string(),
        candidate_id: "cand-1145-a".to_string(),
        campaign_id: "campaign-1145-a".to_string(),
        task_id: "task-1145-a".to_string(),
        scope_ref: "scope-1145-a".to_string(),
        fence_ref: "fence-1145-a".to_string(),
        base_state_ref: "base-1145-a".to_string(),
        product_id: "product-1145-a".to_string(),
        source_id: "source-1145-a".to_string(),
        artifact_ref: "artifact-1145-a".to_string(),
        config_ref: "config-1145-a".to_string(),
        stack_ref: "stack-1145-a".to_string(),
        platform_ref: "platform-1145-a".to_string(),
        environment_ref: "env-1145-a".to_string(),
        objective_ref: "objective-1145-a".to_string(),
        acceptance_ref: "acceptance-1145-a".to_string(),
        evaluator_id: "evaluator-1145-a".to_string(),
        holdout_ref: "holdout-1145-a".to_string(),
        cancelled: false,
    }
}

fn promotion_closure() -> ClosureBinding {
    ClosureBinding {
        closure_id: "closure-1145-a".to_string(),
        campaign_id: "campaign-1145-a".to_string(),
        digest: "digest-closure-1145-a".to_string(),
        valid: true,
        stale: false,
        lineage_ref: "lineage-1145-a".to_string(),
        schema_version: 1,
        revision: 3,
    }
}

fn promotion_candidate() -> PromotionCandidate {
    PromotionCandidate {
        candidate_id: "cand-1145-a".to_string(),
        campaign_id: "campaign-1145-a".to_string(),
        task_id: "task-1145-a".to_string(),
        scope_ref: "scope-1145-a".to_string(),
        fence_ref: "fence-1145-a".to_string(),
        base_state_ref: "base-1145-a".to_string(),
        product_id: "product-1145-a".to_string(),
        source_id: "source-1145-a".to_string(),
        artifact_ref: "artifact-1145-a".to_string(),
        config_ref: "config-1145-a".to_string(),
        stack_ref: "stack-1145-a".to_string(),
        platform_ref: "platform-1145-a".to_string(),
        environment_ref: "env-1145-a".to_string(),
        objective_ref: "objective-1145-a".to_string(),
        acceptance_ref: "acceptance-1145-a".to_string(),
        evaluator_id: "evaluator-1145-a".to_string(),
        holdout_ref: "holdout-1145-a".to_string(),
        revision: 3,
        digest: "cand-digest-1145-a".to_string(),
    }
}

fn promotion_gates() -> PromotionGateEvidence {
    PromotionGateEvidence {
        activation: ActivationGates {
            activation: promotion_stage("ev-1145-activation", true),
            visibility: promotion_stage("ev-1145-visibility", false),
            selection: promotion_stage("ev-1145-selection", false),
            adherence: promotion_stage("ev-1145-adherence", false),
            use_gate: promotion_stage("ev-1145-use", true),
            action: promotion_stage("ev-1145-action", true),
            outcome: promotion_stage("ev-1145-outcome", true),
        },
        benefit: BenefitEvidence {
            benefit_observed: true,
            benefit_ref: Some("benefit-1145-a".to_string()),
            causally_attributed: true,
            control_ref: Some("control-1145-a".to_string()),
            comparison_valid: true,
            independent: true,
            use_linked: true,
        },
        harm_members: vec![
            HarmMember {
                member_id: "member-1145-1".to_string(),
                outcome: MemberOutcome::Positive,
                harm_observed: false,
                harm_ref: None,
                source_id: "source-1145-a".to_string(),
            },
            HarmMember {
                member_id: "member-1145-2".to_string(),
                outcome: MemberOutcome::Positive,
                harm_observed: false,
                harm_ref: None,
                source_id: "source-1145-b".to_string(),
            },
        ],
        comparison: ComparisonEvidence {
            comparison_ref: "comparison-1145-a".to_string(),
            control_ref: Some("control-1145-a".to_string()),
            replay_refs: vec!["replay-1145-a".to_string()],
            holdout_refs: vec!["holdout-1145-a".to_string()],
            fixed: true,
            valid: true,
        },
        retention: RetentionEvidence {
            retention_ref: "retention-1145-a".to_string(),
            period_ref: "period-1145-a".to_string(),
            period_complete: true,
            observed: true,
        },
        transfer: TransferEvidence {
            transfer_refs: vec!["transfer-1145-a".to_string()],
            tested_domain_ref: "domain-1145-a".to_string(),
            proposed_domain_ref: "domain-1145-a".to_string(),
            retention_bound: true,
        },
        pulse: ProductPulseEvidence {
            pulse_id: eliot_improvement::promotion_input::PRODUCT_PULSE.to_string(),
            pulse_ref: Some("pulse-evidence-1145-a".to_string()),
            result: PulseResult::Pass,
            package_green: true,
        },
        evaluator: EvaluatorEvidence {
            evaluator_id: "evaluator-1145-a".to_string(),
            stack_ref: "stack-1145-a".to_string(),
            fresh: true,
            stale: false,
            independent: true,
            source_id: "source-1145-a".to_string(),
            schema_version: 1,
        },
        economics: EconomicsEvidence {
            cost_known: true,
            cost: 12.5,
            resources_known: true,
            resources_ref: Some("resources-1145-a".to_string()),
            human_burden_known: true,
            human_burden_ref: Some("burden-1145-a".to_string()),
            currency: "USD".to_string(),
        },
        rollback: RollbackEvidence {
            rollback_ref: Some("rollback-1145-a".to_string()),
            disable_ref: Some("disable-1145-a".to_string()),
            reopen_ref: Some("reopen-1145-a".to_string()),
            owner_id: "rollback-1145".to_string(),
            expiry_ref: Some("op-1145-a".to_string()),
        },
        expected_member_ids: vec!["member-1145-1".to_string(), "member-1145-2".to_string()],
        expected_source_ids: vec!["source-1145-a".to_string(), "source-1145-b".to_string()],
        expected_period_refs: vec!["period-1145-a".to_string()],
        expected_gate_ids: vec![
            "activation".to_string(),
            "visibility".to_string(),
            "selection".to_string(),
            "adherence".to_string(),
            "use".to_string(),
            "action".to_string(),
            "outcome".to_string(),
            "benefit".to_string(),
            "comparison".to_string(),
            "retention".to_string(),
            "transfer".to_string(),
            "pulse".to_string(),
            "evaluator".to_string(),
            "economics".to_string(),
        ],
    }
}

fn promotion_policy() -> PromotionInputPolicy {
    PromotionInputPolicy {
        schema_version: 1,
        max_members: 16,
        max_bytes: 1_000_000,
        max_gates: 64,
        external_owner_id: "governor-1145".to_string(),
        rollback_owner_id: "rollback-1145".to_string(),
        operation_ref: "op-1145-a".to_string(),
        idempotency_key: "idem-1145-a".to_string(),
        allow_narrowing: false,
        proof_ceiling: eliot_improvement::promotion_input::PROOF_CEILING.to_string(),
        privacy_ceiling: eliot_improvement::promotion_input::PRIVACY_CEILING.to_string(),
        requested_effect: eliot_improvement::promotion_input::REQUESTED_EFFECT.to_string(),
        forbid_direct_promotion: true,
        request_direct_promotion: false,
        claimed_promotion_receipt: None,
    }
}

// ---------------------------------------------------------------------------
// Edge cases.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 1145/1 — both proved cells share one public edge with
// distinct module identities bound by Governor admission.
#[test]
fn case_01_public_edge_binds_both_proved_cells() {
    assert_eq!(
        eliot_improvement::learning_closure::MODULE_ID,
        "meta.learning.closure"
    );
    assert_eq!(
        eliot_improvement::MODULE_ID,
        "meta.improvement.promotion_input"
    );
    assert_ne!(
        eliot_improvement::learning_closure::MODULE_ID,
        eliot_improvement::MODULE_ID
    );
    // Same pulse observed as evidence only by both cells.
    assert_eq!(
        eliot_improvement::learning_closure::PRODUCT_PULSE,
        eliot_improvement::promotion_input::PRODUCT_PULSE
    );
    assert_eq!(
        eliot_improvement::promotion_input::PRODUCT_PULSE,
        "ONLINE_LEARNING_INNER_LOOP_PULSE_01"
    );
    // Governor admission binds these exact identities (opaque, no new dep).
    assert_eq!(eliot_improvement::learning_closure::SOURCE_LAYER, "C1");
    assert_eq!(eliot_improvement::promotion_input::SOURCE_LAYER, "C1");
    assert_eq!(eliot_improvement::learning_closure::RUNTIME_LAYER, "R7");
    assert_eq!(eliot_improvement::RUNTIME_LAYER, "R7");
}

// WORK_UNIT_CASE: 1145/2 — complete closure assembles task-local with no
// promotion output through the public edge.
#[test]
fn case_02_closure_candidate_is_task_local_without_promotion_output() {
    let campaign = closure_campaign();
    let attempts = AttemptOutcomesAndDeltas {
        expected_attempt_ids: vec!["attempt-1".to_string()],
        attempts: vec![closure_attempt("attempt-1")],
    };
    let overlays = OverlayAndActivationAssessments {
        overlays: vec![closure_overlay("overlay-1", "attempt-1")],
        assessments: vec![
            closure_stage("attempt-1", "overlay-1", LifecycleStage::Delivery),
            closure_stage("attempt-1", "overlay-1", LifecycleStage::Use),
            closure_stage("attempt-1", "overlay-1", LifecycleStage::Outcome),
        ],
    };
    let evidence = OutcomeHarmAndEconomicsEvidence {
        outcomes: vec![closure_outcome("attempt-1")],
        economics: vec![closure_economics("attempt-1")],
    };
    let history = PriorClosureHistory { prior: Vec::new() };
    let policy = closure_policy();
    match eliot_improvement::learning_closure::assemble_campaign_learning_closure(
        campaign, attempts, overlays, evidence, history, policy,
    ) {
        Ok(ClosureAssembly::Candidate(candidate)) => {
            assert_eq!(candidate.status, ClosureStatus::ClosedTaskLocal);
            assert_eq!(candidate.handoff.external_owner_id, "governor-1145");
            assert!(candidate.handoff.active_permit.is_none());
            assert!(candidate.handoff.promotion_receipt.is_none());
            assert!(!candidate.digest.is_empty());
        }
        other => panic!("complete closure must close task-local, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 1145/3 — complete promotion input prepares advisory-only
// with no active state or receipt through the public edge.
#[test]
fn case_03_promotion_advisory_carries_no_promotion_output() {
    match eliot_improvement::prepare_promotion_input(
        promotion_request(),
        promotion_closure(),
        promotion_candidate(),
        promotion_gates(),
        eliot_improvement::PriorPromotionHistory { prior: Vec::new() },
        promotion_policy(),
    ) {
        Ok(PromotionPreparation::Advisory(advisory)) => {
            assert_eq!(advisory.candidate_id, "cand-1145-a");
            assert!(!advisory.direct_promotion);
            assert!(advisory.handoff.active_permit.is_none());
            assert!(advisory.handoff.promotion_receipt.is_none());
            assert_eq!(advisory.handoff.external_owner_id, "governor-1145");
            assert_eq!(advisory.handoff.rollback_owner_id, "rollback-1145");
            assert!(!advisory.digest.is_empty());
        }
        other => panic!("complete gates must advise, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 1145/4 — rejection paths stay visible: harm retires the
// closure and rejects the promotion advisory (no silent promotion).
#[test]
fn case_04_harm_rejects_on_both_cells() {
    let campaign = closure_campaign();
    let attempts = AttemptOutcomesAndDeltas {
        expected_attempt_ids: vec!["attempt-1".to_string()],
        attempts: vec![closure_attempt("attempt-1")],
    };
    let overlays = OverlayAndActivationAssessments {
        overlays: vec![closure_overlay("overlay-1", "attempt-1")],
        assessments: vec![
            closure_stage("attempt-1", "overlay-1", LifecycleStage::Delivery),
            closure_stage("attempt-1", "overlay-1", LifecycleStage::Use),
            closure_stage("attempt-1", "overlay-1", LifecycleStage::Outcome),
        ],
    };
    let mut harmed = OutcomeHarmAndEconomicsEvidence {
        outcomes: vec![closure_outcome("attempt-1")],
        economics: vec![closure_economics("attempt-1")],
    };
    harmed.outcomes[0].kind = OutcomeKind::Harmful;
    harmed.outcomes[0].harm = HarmRecord {
        harm_observed: true,
        harm_ref: Some("harm-1145-a".to_string()),
    };
    match eliot_improvement::learning_closure::assemble_campaign_learning_closure(
        campaign,
        attempts,
        overlays,
        harmed,
        PriorClosureHistory { prior: Vec::new() },
        closure_policy(),
    ) {
        Ok(ClosureAssembly::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "retire-review");
        }
        other => panic!("harmed closure must retire, got {other:?}"),
    }

    let mut gates = promotion_gates();
    gates.harm_members[0].outcome = MemberOutcome::Harmful;
    gates.harm_members[0].harm_observed = true;
    gates.harm_members[0].harm_ref = Some("harm-1145-a".to_string());
    match eliot_improvement::prepare_promotion_input(
        promotion_request(),
        promotion_closure(),
        promotion_candidate(),
        gates,
        eliot_improvement::PriorPromotionHistory { prior: Vec::new() },
        promotion_policy(),
    ) {
        Ok(PromotionPreparation::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "rejected");
        }
        other => panic!("harmed promotion must reject, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 1145/5 — pulse regression rejects; exact replay is stable
// on both cells.
#[test]
fn case_05_regression_rejects_and_replay_is_stable() {
    let mut gates = promotion_gates();
    gates.pulse.result = PulseResult::Regression {
        detail: "regression-1145-a".to_string(),
    };
    match eliot_improvement::prepare_promotion_input(
        promotion_request(),
        promotion_closure(),
        promotion_candidate(),
        gates,
        eliot_improvement::PriorPromotionHistory { prior: Vec::new() },
        promotion_policy(),
    ) {
        Ok(PromotionPreparation::Disposition(disposition)) => {
            assert_eq!(disposition.disposition, "rejected");
            assert!(
                disposition
                    .missing_evidence
                    .iter()
                    .any(|m| m.contains("pulse-regression"))
            );
        }
        other => panic!("pulse regression must reject, got {other:?}"),
    }

    let first = eliot_improvement::promotion_evidence_digest(
        &promotion_request(),
        &promotion_closure(),
        &promotion_candidate(),
        &promotion_gates(),
    );
    let second = eliot_improvement::promotion_evidence_digest(
        &promotion_request(),
        &promotion_closure(),
        &promotion_candidate(),
        &promotion_gates(),
    );
    assert_eq!(first, second);
}
