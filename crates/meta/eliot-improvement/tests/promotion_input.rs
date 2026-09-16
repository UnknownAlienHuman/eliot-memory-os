#[path = "../src/promotion_input.rs"]
mod promotion_input;

use promotion_input::{
    AGENT_ORDER, ActivationGates, BenefitEvidence, CAUSAL_PROPERTY, ClosureBinding,
    ComparisonEvidence, EconomicsEvidence, EvaluatorEvidence, HarmMember, MODULE_ID, MemberOutcome,
    PRIVACY_CEILING, PRODUCT_PULSE, PROOF_CEILING, PriorPromotion, PriorPromotionHistory,
    ProductPulseEvidence, PromotionCandidate, PromotionDisposition, PromotionGateEvidence,
    PromotionInputPolicy, PromotionPreparation, PromotionRequest, PulseResult, REQUESTED_EFFECT,
    RUNTIME_LAYER, RetentionEvidence, RollbackEvidence, SOURCE_LAYER, StageGate, TransferEvidence,
};
use std::collections::BTreeSet;

fn stage(evidence: &str, use_linked: bool) -> StageGate {
    StageGate {
        observed: true,
        evidence_ref: Some(evidence.to_string()),
        compatible: true,
        use_linked,
    }
}

fn request() -> PromotionRequest {
    PromotionRequest {
        request_id: "req-972-a".to_string(),
        operation_ref: "op-972-a".to_string(),
        idempotency_key: "idem-972-a".to_string(),
        candidate_id: "cand-972-a".to_string(),
        campaign_id: "campaign-972-a".to_string(),
        task_id: "task-972-a".to_string(),
        scope_ref: "scope-972-a".to_string(),
        fence_ref: "fence-972-a".to_string(),
        base_state_ref: "base-972-a".to_string(),
        product_id: "product-972-a".to_string(),
        source_id: "source-972-a".to_string(),
        artifact_ref: "artifact-972-a".to_string(),
        config_ref: "config-972-a".to_string(),
        stack_ref: "stack-972-a".to_string(),
        platform_ref: "platform-972-a".to_string(),
        environment_ref: "env-972-a".to_string(),
        objective_ref: "objective-972-a".to_string(),
        acceptance_ref: "acceptance-972-a".to_string(),
        evaluator_id: "evaluator-972-a".to_string(),
        holdout_ref: "holdout-972-a".to_string(),
        cancelled: false,
    }
}

fn closure_binding() -> ClosureBinding {
    ClosureBinding {
        closure_id: "closure-972-a".to_string(),
        campaign_id: "campaign-972-a".to_string(),
        digest: "digest-closure-972-a".to_string(),
        valid: true,
        stale: false,
        lineage_ref: "lineage-972-a".to_string(),
        schema_version: 1,
        revision: 3,
    }
}

fn candidate() -> PromotionCandidate {
    PromotionCandidate {
        candidate_id: "cand-972-a".to_string(),
        campaign_id: "campaign-972-a".to_string(),
        task_id: "task-972-a".to_string(),
        scope_ref: "scope-972-a".to_string(),
        fence_ref: "fence-972-a".to_string(),
        base_state_ref: "base-972-a".to_string(),
        product_id: "product-972-a".to_string(),
        source_id: "source-972-a".to_string(),
        artifact_ref: "artifact-972-a".to_string(),
        config_ref: "config-972-a".to_string(),
        stack_ref: "stack-972-a".to_string(),
        platform_ref: "platform-972-a".to_string(),
        environment_ref: "env-972-a".to_string(),
        objective_ref: "objective-972-a".to_string(),
        acceptance_ref: "acceptance-972-a".to_string(),
        evaluator_id: "evaluator-972-a".to_string(),
        holdout_ref: "holdout-972-a".to_string(),
        revision: 3,
        digest: "cand-digest-972-a".to_string(),
    }
}

fn activation() -> ActivationGates {
    ActivationGates {
        activation: stage("ev-972-activation", true),
        visibility: stage("ev-972-visibility", false),
        selection: stage("ev-972-selection", false),
        adherence: stage("ev-972-adherence", false),
        use_gate: stage("ev-972-use", true),
        action: stage("ev-972-action", true),
        outcome: stage("ev-972-outcome", true),
    }
}

fn benefit() -> BenefitEvidence {
    BenefitEvidence {
        benefit_observed: true,
        benefit_ref: Some("benefit-972-a".to_string()),
        causally_attributed: true,
        control_ref: Some("control-972-a".to_string()),
        comparison_valid: true,
        independent: true,
        use_linked: true,
    }
}

fn harm_members() -> Vec<HarmMember> {
    vec![
        HarmMember {
            member_id: "member-972-1".to_string(),
            outcome: MemberOutcome::Positive,
            harm_observed: false,
            harm_ref: None,
            source_id: "source-972-a".to_string(),
        },
        HarmMember {
            member_id: "member-972-2".to_string(),
            outcome: MemberOutcome::Positive,
            harm_observed: false,
            harm_ref: None,
            source_id: "source-972-b".to_string(),
        },
    ]
}

fn comparison() -> ComparisonEvidence {
    ComparisonEvidence {
        comparison_ref: "comparison-972-a".to_string(),
        control_ref: Some("control-972-a".to_string()),
        replay_refs: vec!["replay-972-a".to_string()],
        holdout_refs: vec!["holdout-972-a".to_string()],
        fixed: true,
        valid: true,
    }
}

fn retention() -> RetentionEvidence {
    RetentionEvidence {
        retention_ref: "retention-972-a".to_string(),
        period_ref: "period-972-a".to_string(),
        period_complete: true,
        observed: true,
    }
}

fn transfer() -> TransferEvidence {
    TransferEvidence {
        transfer_refs: vec!["transfer-972-a".to_string()],
        tested_domain_ref: "domain-972-a".to_string(),
        proposed_domain_ref: "domain-972-a".to_string(),
        retention_bound: true,
    }
}

fn pulse() -> ProductPulseEvidence {
    ProductPulseEvidence {
        pulse_id: PRODUCT_PULSE.to_string(),
        pulse_ref: Some("pulse-evidence-972-a".to_string()),
        result: PulseResult::Pass,
        package_green: true,
    }
}

fn evaluator() -> EvaluatorEvidence {
    EvaluatorEvidence {
        evaluator_id: "evaluator-972-a".to_string(),
        stack_ref: "stack-972-a".to_string(),
        fresh: true,
        stale: false,
        independent: true,
        source_id: "source-972-a".to_string(),
        schema_version: 1,
    }
}

fn economics() -> EconomicsEvidence {
    EconomicsEvidence {
        cost_known: true,
        cost: 12.5,
        resources_known: true,
        resources_ref: Some("resources-972-a".to_string()),
        human_burden_known: true,
        human_burden_ref: Some("burden-972-a".to_string()),
        currency: "USD".to_string(),
    }
}

fn rollback() -> RollbackEvidence {
    RollbackEvidence {
        rollback_ref: Some("rollback-972-a".to_string()),
        disable_ref: Some("disable-972-a".to_string()),
        reopen_ref: Some("reopen-972-a".to_string()),
        owner_id: "rollback-972".to_string(),
        expiry_ref: Some("op-972-a".to_string()),
    }
}

fn gates() -> PromotionGateEvidence {
    PromotionGateEvidence {
        activation: activation(),
        benefit: benefit(),
        harm_members: harm_members(),
        comparison: comparison(),
        retention: retention(),
        transfer: transfer(),
        pulse: pulse(),
        evaluator: evaluator(),
        economics: economics(),
        rollback: rollback(),
        expected_member_ids: vec!["member-972-1".to_string(), "member-972-2".to_string()],
        expected_source_ids: vec!["source-972-a".to_string(), "source-972-b".to_string()],
        expected_period_refs: vec!["period-972-a".to_string()],
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

fn policy() -> PromotionInputPolicy {
    PromotionInputPolicy {
        schema_version: 1,
        max_members: 16,
        max_bytes: 1_000_000,
        max_gates: 64,
        external_owner_id: "governor-972".to_string(),
        rollback_owner_id: "rollback-972".to_string(),
        operation_ref: "op-972-a".to_string(),
        idempotency_key: "idem-972-a".to_string(),
        allow_narrowing: false,
        proof_ceiling: PROOF_CEILING.to_string(),
        privacy_ceiling: PRIVACY_CEILING.to_string(),
        requested_effect: REQUESTED_EFFECT.to_string(),
        forbid_direct_promotion: true,
        request_direct_promotion: false,
        claimed_promotion_receipt: None,
    }
}

fn history() -> PriorPromotionHistory {
    PriorPromotionHistory { prior: Vec::new() }
}

#[allow(clippy::type_complexity)]
fn complete_inputs() -> (
    PromotionRequest,
    ClosureBinding,
    PromotionCandidate,
    PromotionGateEvidence,
    PriorPromotionHistory,
    PromotionInputPolicy,
) {
    (
        request(),
        closure_binding(),
        candidate(),
        gates(),
        history(),
        policy(),
    )
}

fn prepare_complete() -> promotion_input::PromotionInputCandidate {
    let (r, c, k, g, h, p) = complete_inputs();
    match promotion_input::prepare_promotion_input(r, c, k, g, h, p) {
        Ok(PromotionPreparation::Advisory(candidate)) => *candidate,
        other => panic!("expected advisory, got {other:?}"),
    }
}

fn disposition_of(
    r: PromotionRequest,
    c: ClosureBinding,
    k: PromotionCandidate,
    g: PromotionGateEvidence,
    h: PriorPromotionHistory,
    p: PromotionInputPolicy,
) -> PromotionDisposition {
    match promotion_input::prepare_promotion_input(r, c, k, g, h, p) {
        Ok(PromotionPreparation::Disposition(d)) => d,
        other => panic!("expected disposition, got {other:?}"),
    }
}

// WORK_UNIT_CASE: 972/1
#[test]
fn case_01_cell_identity_separate_from_closure_and_self_quality() {
    assert_eq!(MODULE_ID, "meta.improvement.promotion_input");
    assert_eq!(SOURCE_LAYER, "C1");
    assert_eq!(RUNTIME_LAYER, "R7");
    assert_eq!(CAUSAL_PROPERTY, "outer-loop promotion-input preparation");
    assert_eq!(PRODUCT_PULSE, "ONLINE_LEARNING_INNER_LOOP_PULSE_01");
    assert_eq!(AGENT_ORDER, 38);
    let promotion_router = include_str!("../promotion.module.toml");
    let closure_router = include_str!("../learning-closure.module.toml");
    assert!(promotion_router.contains("meta.improvement.promotion_input"));
    assert!(promotion_router.contains("agent_order = 38"));
    assert!(promotion_router.contains("direct_promotion is always false"));
    assert!(promotion_router.contains("crates/meta/eliot-improvement/src/promotion_input.rs"));
    assert!(promotion_router.contains("crates/meta/eliot-improvement/tests/promotion_input.rs"));
    assert!(!promotion_router.contains("learning_closure.rs"));
    assert!(closure_router.contains("meta.learning.closure"));
    assert!(closure_router.contains("agent_order = 37"));
    assert!(!closure_router.contains("promotion_input.rs"));
    assert_ne!(MODULE_ID, "meta.learning.closure");
    assert_ne!(AGENT_ORDER, 37);
}

// WORK_UNIT_CASE: 972/2
#[test]
fn case_02_complete_evidence_yields_advisory_only() {
    let advisory = prepare_complete();
    assert_eq!(advisory.candidate_id, "cand-972-a");
    assert_eq!(advisory.campaign_id, "campaign-972-a");
    assert_eq!(advisory.evaluator_id, "evaluator-972-a");
    assert_eq!(advisory.product_id, "product-972-a");
    assert!(!advisory.direct_promotion);
    assert!(advisory.handoff.active_permit.is_none());
    assert!(advisory.handoff.promotion_receipt.is_none());
    assert_eq!(advisory.proof_ceiling, "module-proof-only");
    assert_eq!(advisory.handoff.external_owner_id, "governor-972");
    assert_eq!(advisory.handoff.rollback_owner_id, "rollback-972");
    assert_eq!(advisory.handoff.approval_fence_ref, "fence-972-a");
    assert!(!advisory.digest.is_empty());
    assert!(advisory.input_id.contains("cand-972-a"));
    assert!(advisory.missing_evidence.is_empty());
    assert!(!advisory.limitations.is_empty());
    assert_eq!(advisory.gate_report.len(), 14);
    assert!(advisory.gate_report.iter().all(|g| g.passed));
}

// WORK_UNIT_CASE: 972/3
#[test]
fn case_03_missing_foreign_stale_closure_rejected() {
    let (r, mut c, k, g, h, p) = complete_inputs();
    c.digest = String::new();
    let err = promotion_input::prepare_promotion_input(r, c, k, g, h, p)
        .expect_err("missing closure digest must fail");
    assert_eq!(
        err,
        promotion_input::PromotionInputError::MissingField("closure_digest")
    );

    let (r2, mut c2, mut k2, g2, h2, p2) = complete_inputs();
    c2.campaign_id = "foreign-campaign-972".to_string();
    k2.campaign_id = "campaign-972-a".to_string();
    let err2 = promotion_input::prepare_promotion_input(r2, c2, k2, g2, h2, p2)
        .expect_err("foreign closure campaign must fail");
    assert!(matches!(
        err2,
        promotion_input::PromotionInputError::IdentityMismatch { .. }
    ));
    assert!(format!("{err2:?}").contains("campaign"));

    let (r3, mut c3, k3, g3, h3, p3) = complete_inputs();
    c3.stale = true;
    let err3 = promotion_input::prepare_promotion_input(r3, c3, k3, g3, h3, p3)
        .expect_err("stale closure must fail");
    assert!(matches!(
        err3,
        promotion_input::PromotionInputError::StaleEvidence { .. }
    ));

    let (r4, mut c4, k4, g4, h4, p4) = complete_inputs();
    c4.valid = false;
    let d = disposition_of(r4, c4, k4, g4, h4, p4);
    assert_eq!(d.disposition, "rejected");
    assert!(d.missing_evidence.iter().any(|m| m.contains("closure")));
}

// WORK_UNIT_CASE: 972/4
#[test]
fn case_04_candidate_campaign_task_fence_base_mismatch() {
    for (field, mutate) in [
        ("campaign", "foreign-campaign-972"),
        ("task", "foreign-task-972"),
        ("scope", "foreign-scope-972"),
        ("fence", "foreign-fence-972"),
        ("base", "foreign-base-972"),
    ] {
        let (r, c, mut k, g, h, p) = complete_inputs();
        match field {
            "campaign" => k.campaign_id = mutate.to_string(),
            "task" => k.task_id = mutate.to_string(),
            "scope" => k.scope_ref = mutate.to_string(),
            "fence" => k.fence_ref = mutate.to_string(),
            _ => k.base_state_ref = mutate.to_string(),
        }
        let err = promotion_input::prepare_promotion_input(r, c, k, g, h, p)
            .expect_err("identity divergence must fail");
        assert!(
            matches!(
                err,
                promotion_input::PromotionInputError::IdentityMismatch { .. }
            ),
            "field {field} must mismatch, got {err:?}"
        );
        assert!(
            format!("{err:?}").contains(field),
            "field {field} must name itself, got {err:?}"
        );
    }
}

// WORK_UNIT_CASE: 972/5
#[test]
fn case_05_product_source_artifact_config_stack_environment_mismatch() {
    for field in [
        "product",
        "source",
        "artifact",
        "config",
        "stack",
        "environment",
    ] {
        let (r, c, mut k, mut g, h, p) = complete_inputs();
        match field {
            "product" => k.product_id = "foreign-product-972".to_string(),
            "source" => {
                k.source_id = "foreign-source-972".to_string();
            }
            "artifact" => k.artifact_ref = "foreign-artifact-972".to_string(),
            "config" => k.config_ref = "foreign-config-972".to_string(),
            "stack" => k.stack_ref = "foreign-stack-972".to_string(),
            _ => k.environment_ref = "foreign-env-972".to_string(),
        }
        // Keep evidence consistent for source/stack so the request-vs-candidate
        // binding is the load-bearing check (not the evidence binding).
        if field == "source" {
            g.evaluator.source_id = "foreign-source-972".to_string();
        }
        if field == "stack" {
            g.evaluator.stack_ref = "foreign-stack-972".to_string();
        }
        let err = promotion_input::prepare_promotion_input(r, c, k, g, h, p)
            .expect_err("product identity divergence must fail");
        assert!(
            matches!(
                err,
                promotion_input::PromotionInputError::IdentityMismatch { .. }
            ),
            "field {field} must mismatch, got {err:?}"
        );
        assert!(
            format!("{err:?}").contains(field),
            "field {field} must name itself, got {err:?}"
        );
    }
}

// WORK_UNIT_CASE: 972/6
#[test]
fn case_06_evaluator_holdout_objective_acceptance_mismatch() {
    for field in ["evaluator", "holdout", "objective", "acceptance"] {
        let (r, c, mut k, mut g, h, p) = complete_inputs();
        match field {
            "evaluator" => {
                k.evaluator_id = "foreign-evaluator-972".to_string();
            }
            "holdout" => k.holdout_ref = "foreign-holdout-972".to_string(),
            "objective" => k.objective_ref = "foreign-objective-972".to_string(),
            _ => k.acceptance_ref = "foreign-acceptance-972".to_string(),
        }
        if field == "evaluator" {
            // Keep evidence binding aligned so request-vs-candidate fires first.
            g.evaluator.evaluator_id = "foreign-evaluator-972".to_string();
        }
        if field == "holdout" {
            g.comparison.holdout_refs = vec!["foreign-holdout-972".to_string()];
        }
        let err = promotion_input::prepare_promotion_input(r, c, k, g, h, p)
            .expect_err("evaluator identity divergence must fail");
        assert!(
            matches!(
                err,
                promotion_input::PromotionInputError::IdentityMismatch { .. }
            ),
            "field {field} must mismatch, got {err:?}"
        );
        assert!(
            format!("{err:?}").contains(field),
            "field {field} must name itself, got {err:?}"
        );
    }
}

// WORK_UNIT_CASE: 972/7
#[test]
fn case_07_missing_activation_evidence() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.activation.activation.observed = false;
    g.activation.activation.evidence_ref = None;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("missing-activation"))
    );
    assert!(d.missing_owner.is_some());
}

// WORK_UNIT_CASE: 972/8
#[test]
fn case_08_missing_adherence_or_use_not_filled_by_delivery() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.activation.adherence.observed = false;
    g.activation.adherence.evidence_ref = None;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence.iter().any(|m| m.contains("adherence")),
        "got {:?}",
        d.missing_evidence
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.activation.use_gate.observed = false;
    g2.activation.use_gate.evidence_ref = None;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "incomplete");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("delivery-without-use") || m.contains("missing-use")),
        "got {:?}",
        d2.missing_evidence
    );
}

// WORK_UNIT_CASE: 972/9
#[test]
fn case_09_outcome_without_usage_linkage_cannot_establish_benefit() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.activation.outcome.use_linked = false;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("outcome-without-use-linkage")),
        "got {:?}",
        d.missing_evidence
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.benefit.use_linked = false;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "incomplete");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("use-linkage")),
        "got {:?}",
        d2.missing_evidence
    );
}

// WORK_UNIT_CASE: 972/10
#[test]
fn case_10_benefit_bounded_by_comparison_and_independence() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.benefit.causally_attributed = false;
    g.benefit.control_ref = Some("control-972-a".to_string());
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("benefit-without-causal-attribution"))
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.benefit.comparison_valid = false;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "incomplete");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("benefit-without-valid-comparison"))
    );

    let (r3, c3, k3, mut g3, h3, p3) = complete_inputs();
    g3.benefit.independent = false;
    let d3 = disposition_of(r3, c3, k3, g3, h3, p3);
    assert_eq!(d3.disposition, "incomplete");
    assert!(
        d3.missing_evidence
            .iter()
            .any(|m| m.contains("benefit-without-independence"))
    );

    let (r4, c4, k4, mut g4, h4, p4) = complete_inputs();
    g4.comparison.control_ref = None;
    let d4 = disposition_of(r4, c4, k4, g4, h4, p4);
    assert_eq!(d4.disposition, "incomplete");
    assert!(
        d4.missing_evidence
            .iter()
            .any(|m| m.contains("confounder-denominator-incomplete"))
    );
}

// WORK_UNIT_CASE: 972/11
#[test]
fn case_11_missing_retention_blocks_retention_claim() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.retention.observed = false;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("missing-retention"))
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.retention.period_complete = false;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "incomplete");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("missing-retention"))
    );
}

// WORK_UNIT_CASE: 972/12
#[test]
fn case_12_transfer_without_retention_is_not_complete() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.transfer.retention_bound = false;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("transfer-without-retention"))
    );
}

// WORK_UNIT_CASE: 972/13
#[test]
fn case_13_transfer_scope_cannot_exceed_tested_applicability() {
    let (r, c, k, mut g, h, mut p) = complete_inputs();
    g.transfer.proposed_domain_ref = "domain-972-wider".to_string();
    p.allow_narrowing = false;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "rejected");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("transfer-scope-exceeds-tested"))
    );
}

// WORK_UNIT_CASE: 972/14
#[test]
fn case_14_stale_evaluator_stack_invalidates_reuse() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.evaluator.stale = true;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "blocked");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("stale-evaluator"))
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.evaluator.fresh = false;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "blocked");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("stale-evaluator"))
    );

    let (r3, c3, k3, mut g3, h3, p3) = complete_inputs();
    g3.evaluator.stack_ref = "stale-stack-972".to_string();
    let err = promotion_input::prepare_promotion_input(r3, c3, k3, g3, h3, p3)
        .expect_err("stack change must invalidate reuse");
    assert!(matches!(
        err,
        promotion_input::PromotionInputError::IdentityMismatch { .. }
    ));
    assert!(format!("{err:?}").contains("stack"));
}

// WORK_UNIT_CASE: 972/15
#[test]
fn case_15_missing_wrong_pulse_not_replaced_by_package_green() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.pulse.pulse_ref = None;
    g.pulse.package_green = true;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("missing-product-pulse"))
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.pulse.pulse_id = "WRONG_PULSE_972".to_string();
    g2.pulse.package_green = true;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "incomplete");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("wrong-pulse-identity"))
    );
}

// WORK_UNIT_CASE: 972/16
#[test]
fn case_16_pulse_regression_blocks_positive_candidate() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.pulse.result = PulseResult::Regression {
        detail: "regression-972-a".to_string(),
    };
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "rejected");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("pulse-regression"))
    );
}

// WORK_UNIT_CASE: 972/17
#[test]
fn case_17_harm_conflict_minority_cannot_be_averaged() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.harm_members[0].outcome = MemberOutcome::Harmful;
    g.harm_members[0].harm_observed = true;
    g.harm_members[0].harm_ref = Some("harm-972-a".to_string());
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "rejected");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("member-972-1"))
    );
    assert!(!d.open_obligations.is_empty());

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.harm_members[1].outcome = MemberOutcome::Negative;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "rejected");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("member-972-2"))
    );

    let (r3, c3, k3, mut g3, h3, p3) = complete_inputs();
    g3.harm_members[0].outcome = MemberOutcome::Conflicted;
    let d3 = disposition_of(r3, c3, k3, g3, h3, p3);
    assert_eq!(d3.disposition, "conflicted");
    assert!(
        d3.missing_evidence
            .iter()
            .any(|m| m.contains("conflicting-outcomes-no-winner"))
    );
}

// WORK_UNIT_CASE: 972/18
#[test]
fn case_18_unknown_costs_resources_burden_remain_explicit() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.economics.cost_known = false;
    g.economics.cost = 0.0;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("unknown-cost"))
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.economics.resources_known = false;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "incomplete");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("unknown-resources"))
    );

    let (r3, c3, k3, mut g3, h3, p3) = complete_inputs();
    g3.economics.human_burden_known = false;
    let d3 = disposition_of(r3, c3, k3, g3, h3, p3);
    assert_eq!(d3.disposition, "incomplete");
    assert!(
        d3.missing_evidence
            .iter()
            .any(|m| m.contains("unknown-human-burden"))
    );
}

// WORK_UNIT_CASE: 972/19
#[test]
fn case_19_rollback_disable_reopen_owner_gaps_block_readiness() {
    let (r, c, k, mut g, h, p) = complete_inputs();
    g.rollback.rollback_ref = None;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "blocked");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("missing-rollback"))
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.rollback.disable_ref = None;
    g2.rollback.reopen_ref = None;
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "blocked");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("missing-disable") || m.contains("missing-reopen"))
    );

    let (r3, c3, k3, mut g3, h3, p3) = complete_inputs();
    g3.rollback.owner_id = "wrong-owner-972".to_string();
    let d3 = disposition_of(r3, c3, k3, g3, h3, p3);
    assert_eq!(d3.disposition, "blocked");
    assert!(
        d3.missing_evidence
            .iter()
            .any(|m| m.contains("rollback-owner-gap"))
    );
}

// WORK_UNIT_CASE: 972/20
#[test]
fn case_20_protected_widening_rejected() {
    let (r, c, k, g, h, mut p) = complete_inputs();
    p.proof_ceiling = "product-promotion".to_string();
    let err = promotion_input::prepare_promotion_input(r, c, k, g, h, p)
        .expect_err("proof widening must fail");
    assert!(matches!(
        err,
        promotion_input::PromotionInputError::WideningRejected { .. }
    ));

    let (r2, c2, k2, g2, h2, mut p2) = complete_inputs();
    p2.privacy_ceiling = "unbounded".to_string();
    let err2 = promotion_input::prepare_promotion_input(r2, c2, k2, g2, h2, p2)
        .expect_err("privacy widening must fail");
    assert!(matches!(
        err2,
        promotion_input::PromotionInputError::WideningRejected { .. }
    ));

    let (r3, c3, k3, g3, h3, mut p3) = complete_inputs();
    p3.requested_effect = "active-generation".to_string();
    let err3 = promotion_input::prepare_promotion_input(r3, c3, k3, g3, h3, p3)
        .expect_err("effect widening must fail");
    assert!(matches!(
        err3,
        promotion_input::PromotionInputError::WideningRejected { .. }
    ));

    let (r4, c4, k4, g4, h4, mut p4) = complete_inputs();
    p4.request_direct_promotion = true;
    let err4 = promotion_input::prepare_promotion_input(r4, c4, k4, g4, h4, p4)
        .expect_err("direct promotion request must fail");
    assert_eq!(
        err4,
        promotion_input::PromotionInputError::PromotionOutputForbidden
    );
}

// WORK_UNIT_CASE: 972/21
#[test]
fn case_21_complete_vs_partial_denominator() {
    let advisory = prepare_complete();
    assert_eq!(advisory.denominators.expected_members, 2);
    assert_eq!(advisory.denominators.supplied_members, 2);
    assert_eq!(advisory.denominators.expected_sources, 2);
    assert_eq!(advisory.denominators.supplied_sources, 2);
    assert_eq!(advisory.denominators.expected_periods, 1);
    assert_eq!(advisory.denominators.supplied_periods, 1);
    assert_eq!(
        advisory.denominators.expected_gates,
        advisory.denominators.supplied_gates
    );

    let (r, c, k, mut g, h, p) = complete_inputs();
    g.expected_member_ids.push("member-972-3".to_string());
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "incomplete");
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("missing-member"))
    );
    assert!(
        d.open_obligations
            .iter()
            .any(|m| m.contains("denominator-incomplete"))
    );

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    g2.expected_source_ids.push("source-972-extra".to_string());
    let d2 = disposition_of(r2, c2, k2, g2, h2, p2);
    assert_eq!(d2.disposition, "incomplete");
    assert!(
        d2.missing_evidence
            .iter()
            .any(|m| m.contains("missing-source"))
    );

    let (r3, c3, k3, mut g3, h3, p3) = complete_inputs();
    g3.expected_gate_ids.push("extra-gate-972".to_string());
    let d3 = disposition_of(r3, c3, k3, g3, h3, p3);
    assert_eq!(d3.disposition, "incomplete");
    assert!(
        d3.missing_evidence
            .iter()
            .any(|m| m.contains("gate-denominator-incomplete"))
    );
}

// WORK_UNIT_CASE: 972/22
#[test]
fn case_22_narrowing_retains_original_scope_and_limitations() {
    let (r, c, k, mut g, h, mut p) = complete_inputs();
    g.transfer.proposed_domain_ref = "domain-972-wider".to_string();
    p.allow_narrowing = true;
    let d = disposition_of(r, c, k, g, h, p);
    assert_eq!(d.disposition, "narrowed-for-review");
    assert_eq!(d.original_scope_ref, "domain-972-wider");
    assert_eq!(d.narrowed_scope_ref, Some("domain-972-a".to_string()));
    assert!(
        d.missing_evidence
            .iter()
            .any(|m| m.contains("transfer-scope-exceeds-tested"))
    );
    assert!(
        d.limitations
            .iter()
            .any(|m| m.contains("original-rejected-scope-retained"))
    );
}

// WORK_UNIT_CASE: 972/23
#[test]
fn case_23_no_direct_promotion_active_state_or_receipt() {
    let advisory = prepare_complete();
    assert!(!advisory.direct_promotion);
    assert!(advisory.handoff.active_permit.is_none());
    assert!(advisory.handoff.promotion_receipt.is_none());
    let debug = format!("{advisory:?}");
    assert!(!debug.contains("direct_promotion: true"));
    assert!(debug.contains("promotion_receipt: None"));

    let (r, c, k, g, h, mut p) = complete_inputs();
    p.forbid_direct_promotion = false;
    let err = promotion_input::prepare_promotion_input(r, c, k, g, h, p)
        .expect_err("direct promotion must fail");
    assert_eq!(
        err,
        promotion_input::PromotionInputError::PromotionOutputForbidden
    );

    let (r2, c2, k2, g2, h2, mut p2) = complete_inputs();
    p2.claimed_promotion_receipt = Some("receipt-972".to_string());
    let err2 = promotion_input::prepare_promotion_input(r2, c2, k2, g2, h2, p2)
        .expect_err("claimed receipt must fail");
    assert_eq!(
        err2,
        promotion_input::PromotionInputError::PromotionOutputForbidden
    );
}

// WORK_UNIT_CASE: 972/24
#[test]
fn case_24_same_operation_replay_and_changed_payload_conflict() {
    let (r, c, k, g, h, p) = complete_inputs();
    let first = match promotion_input::prepare_promotion_input(
        r.clone(),
        c.clone(),
        k.clone(),
        g.clone(),
        h.clone(),
        p.clone(),
    ) {
        Ok(PromotionPreparation::Advisory(a)) => a,
        other => panic!("first replay must advise, got {other:?}"),
    };
    let second = match promotion_input::prepare_promotion_input(r, c, k, g, h, p.clone()) {
        Ok(PromotionPreparation::Advisory(a)) => a,
        other => panic!("second replay must advise, got {other:?}"),
    };
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.input_id, second.input_id);

    let (r2, c2, k2, mut g2, h2, p2) = complete_inputs();
    let mut rival = g2.harm_members[0].clone();
    rival.harm_observed = true;
    rival.harm_ref = Some("rival-harm-972".to_string());
    g2.harm_members.push(rival);
    let err = promotion_input::prepare_promotion_input(r2, c2, k2, g2, h2, p2)
        .expect_err("changed same-ID payload must conflict");
    assert_eq!(
        err,
        promotion_input::PromotionInputError::ConflictingRecord {
            id: "member-972-1".to_string()
        }
    );

    let (r3, c3, k3, g3, _, p3) = complete_inputs();
    let evidence_hex = promotion_input::promotion_evidence_digest(&r3, &c3, &k3, &g3);
    let advisory = match promotion_input::prepare_promotion_input(
        r3.clone(),
        c3.clone(),
        k3.clone(),
        g3.clone(),
        history(),
        p3.clone(),
    ) {
        Ok(PromotionPreparation::Advisory(a)) => a,
        other => panic!("baseline must advise, got {other:?}"),
    };
    let repeat_history = PriorPromotionHistory {
        prior: vec![PriorPromotion {
            input_id: advisory.input_id.clone(),
            candidate_id: "cand-972-a".to_string(),
            digest: evidence_hex,
            superseded: false,
        }],
    };
    let d = disposition_of(r3, c3, k3, g3, repeat_history, p3);
    assert_eq!(d.disposition, "repeat-review");
    assert!(
        d.open_obligations
            .iter()
            .any(|m| m.contains(&advisory.input_id))
    );
}

// WORK_UNIT_CASE: 972/25
#[test]
fn case_25_independent_bounds_cancellation_redacted_diagnostics() {
    let (r, c, k, g, h, mut p) = complete_inputs();
    p.max_members = 1;
    let err = promotion_input::prepare_promotion_input(r, c, k, g, h, p)
        .expect_err("member overflow must fail");
    assert!(matches!(
        err,
        promotion_input::PromotionInputError::BoundExceeded { .. }
    ));
    assert!(format!("{err:?}").contains("max_members"));

    let (r2, c2, k2, g2, h2, mut p2) = complete_inputs();
    p2.max_bytes = 1;
    let err2 = promotion_input::prepare_promotion_input(r2, c2, k2, g2, h2, p2)
        .expect_err("byte overflow must fail");
    assert!(matches!(
        err2,
        promotion_input::PromotionInputError::BoundExceeded { .. }
    ));
    assert!(format!("{err:?}") != format!("{err2:?}"));

    let (mut r3, c3, k3, g3, h3, p3) = complete_inputs();
    r3.cancelled = true;
    let d = disposition_of(r3, c3, k3, g3, h3, p3);
    assert_eq!(d.disposition, "blocked");
    assert!(d.missing_evidence.iter().any(|m| m.contains("cancelled")));

    let (r4, c4, k4, mut g4, h4, p4) = complete_inputs();
    let long_id = "m".repeat(400);
    g4.harm_members[0].member_id = long_id.clone();
    g4.expected_member_ids[0] = long_id.clone();
    g4.harm_members[0].outcome = MemberOutcome::Harmful;
    g4.harm_members[0].harm_observed = true;
    g4.harm_members[0].harm_ref = Some("harm-972-long".to_string());
    let d4 = disposition_of(r4, c4, k4, g4, h4, p4);
    assert_eq!(d4.disposition, "rejected");
    for entry in &d4.missing_evidence {
        assert!(
            entry.len() <= 256,
            "diagnostic must stay bounded: {entry:?}"
        );
    }
    assert!(
        d4.missing_evidence.iter().any(|m| m.contains("[redacted]")),
        "long diagnostic must redact, got {:?}",
        d4.missing_evidence
    );

    let (r5, c5, k5, mut g5, h5, p5) = complete_inputs();
    g5.economics.cost = f64::NAN;
    let err5 = promotion_input::prepare_promotion_input(r5, c5, k5, g5, h5, p5)
        .expect_err("non-finite cost must fail");
    assert_eq!(err5, promotion_input::PromotionInputError::NonFiniteMetric);
}

// WORK_UNIT_CASE: 972/26
#[test]
fn case_26_canonical_order_digest_and_malformed_regressions() {
    let (r, c, k, g, _h, _p) = complete_inputs();
    let first = promotion_input::promotion_evidence_digest(&r, &c, &k, &g);
    let mut permuted = g.clone();
    permuted.harm_members.reverse();
    permuted.expected_member_ids.reverse();
    permuted.expected_source_ids.reverse();
    permuted.comparison.replay_refs.reverse();
    permuted.comparison.holdout_refs.reverse();
    permuted.transfer.transfer_refs.reverse();
    let second = promotion_input::promotion_evidence_digest(&r, &c, &k, &permuted);
    assert_eq!(first, second);

    let (_, _, _, mut g_changed, _, _) = complete_inputs();
    g_changed.comparison.control_ref = Some("other-control-972".to_string());
    let changed = promotion_input::promotion_evidence_digest(&r, &c, &k, &g_changed);
    assert_ne!(first, changed);

    let (mut r_bad, c2, k2, g2, h2, p2) = complete_inputs();
    r_bad.request_id = String::new();
    let err = promotion_input::prepare_promotion_input(r_bad, c2, k2, g2, h2, p2)
        .expect_err("empty request must fail");
    assert_eq!(
        err,
        promotion_input::PromotionInputError::MissingField("request_id")
    );

    let (mut r_long, c3, k3, g3, h3, p3) = complete_inputs();
    r_long.request_id = "x".repeat(600);
    let err2 = promotion_input::prepare_promotion_input(r_long, c3, k3, g3, h3, p3)
        .expect_err("overlong id must fail");
    assert!(matches!(
        err2,
        promotion_input::PromotionInputError::Malformed { .. }
    ));

    let (r4, c4, k4, g4, h4, mut p4) = complete_inputs();
    p4.schema_version = 99;
    let err3 = promotion_input::prepare_promotion_input(r4, c4, k4, g4, h4, p4)
        .expect_err("unknown schema must fail");
    assert_eq!(
        err3,
        promotion_input::PromotionInputError::UnsupportedSchema { version: 99 }
    );
}

// WORK_UNIT_CASE: 972/27
#[test]
fn case_27_source_bound_module_without_lib_edits_or_duplication() {
    const LIB: &str = include_str!("../src/lib.rs");
    assert!(!LIB.contains("mod promotion_input"));
    assert!(!LIB.contains("promotion_input.rs"));
    assert!(LIB.contains("PromotionInput"));
    const SRC: &str = include_str!("../src/promotion_input.rs");
    assert!(SRC.contains("prepare_promotion_input"));
    assert!(SRC.contains("meta.improvement.promotion_input"));
    let advisory = prepare_complete();
    assert_eq!(advisory.candidate_id, "cand-972-a");
    assert_eq!(
        promotion_input::MODULE_ID,
        "meta.improvement.promotion_input"
    );
}

// WORK_UNIT_CASE: 972/28
#[test]
fn case_28_no_runtime_assessment_promotion_effect_calls() {
    const SRC: &str = include_str!("../src/promotion_input.rs");
    for forbidden in [
        "std::fs",
        "std::net",
        "std::process",
        "tokio",
        "reqwest",
        "Store",
        "provider",
        "Finish",
        "OffsetDateTime",
        "Uuid::",
        "Command",
        ".spawn(",
        "unsafe",
        "async",
        "await",
        "learning_closure",
        "assemble_campaign",
        "use crate",
        "crate::",
        "super::",
        "extern crate",
    ] {
        assert!(
            !SRC.contains(forbidden),
            "runtime/effect path forbidden: {forbidden}"
        );
    }
    assert!(!SRC.contains("\nmod "));
    let advisory = prepare_complete();
    assert!(!advisory.direct_promotion);
    assert!(advisory.handoff.promotion_receipt.is_none());
    let distinct: BTreeSet<&str> = advisory
        .gate_report
        .iter()
        .map(|g| g.gate.as_str())
        .collect();
    assert_eq!(distinct.len(), advisory.gate_report.len());
}
