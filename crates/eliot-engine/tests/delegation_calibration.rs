use eliot_engine::{
    DelegationCalibrationIngestService, DelegationCalibrationRollupService,
    DelegationCounterfactualService, DelegationOutcomeEvidence, DelegationOutcomeLabelService,
    DelegationPolicyCandidateService, DelegationPromotionGateService,
    DelegationShadowEvaluationService, MetricRegistryService,
};
use eliot_types::{
    CalibrationCompleteness, CalibrationEvidenceClass, DelegationCalibrationConfig,
    DelegationCalibrationCosts, DelegationCalibrationLabels, DelegationCalibrationSample,
    DelegationCalibrationState, DelegationCalibrationTaskFamily, DelegationCounterfactualKind,
    DelegationDecisionKind, DelegationOrigin, DelegationPolicyPromotionDecisionKind,
    DelegationPolicyPromotionReason, DelegationReviewKind, DelegationShadowDecisionKind, ProjectId,
    TaskId,
};
use time::OffsetDateTime;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sample(class: CalibrationEvidenceClass, called: bool) -> DelegationCalibrationSample {
    DelegationCalibrationSample {
        sample_id: format!("sample-{class:?}-{called}"),
        project_id: ProjectId::new_v7(),
        task_id: TaskId::new_v7(),
        task_family: DelegationCalibrationTaskFamily::SecurityBoundary,
        evidence_class: class,
        delegation_origin: DelegationOrigin::UserDirected,
        review_kind: DelegationReviewKind::RiskReview,
        route_decision_ref: "route:1".to_owned(),
        delegation_outcome_ref: Some("outcome:1".to_owned()),
        provider_result_ref: called.then(|| "result:1".to_owned()),
        controller_outcome_refs: vec!["controller:1".to_owned()],
        verifier_refs: Vec::new(),
        shadow_decision_ref: None,
        labels: DelegationCalibrationLabels {
            provider_called: called,
            unique_findings: u32::from(called),
            ..DelegationCalibrationLabels::default()
        },
        costs: DelegationCalibrationCosts {
            provider_runtime_ms: called.then_some(100),
            provider_call_count: u32::from(called),
            monetary_cost_known: false,
            monetary_cost: None,
            ..DelegationCalibrationCosts::default()
        },
        completeness: CalibrationCompleteness {
            route_decision_present: true,
            final_task_outcome_present: true,
            provider_result_present: called,
            verifier_or_human_evidence_present: false,
            worktree_cleanup_present: true,
            live_tree_integrity_present: true,
            complete_for_provider_quality: false,
            complete_for_routing_quality: true,
            missing_refs: vec!["verifier_or_human_evidence".to_owned()],
        },
        created_at: OffsetDateTime::now_utc(),
    }
}

#[test]
fn calibration_ingests_real_executed_task() -> TestResult {
    let mut s = DelegationCalibrationState::default();
    assert!(DelegationCalibrationIngestService.ingest(
        &mut s,
        sample(CalibrationEvidenceClass::RealExecutedTask, true)
    )?);
    assert_eq!(s.samples.len(), 1);
    Ok(())
}
#[test]
fn calibration_ingests_real_no_provider_task() -> TestResult {
    let mut s = DelegationCalibrationState::default();
    DelegationCalibrationIngestService.ingest(
        &mut s,
        sample(CalibrationEvidenceClass::RealNoProviderTask, false),
    )?;
    assert!(!s.samples[0].labels.provider_called);
    Ok(())
}
#[test]
fn calibration_fixture_excluded_from_real_readiness() {
    let mut s = DelegationCalibrationState::default();
    s.samples
        .push(sample(CalibrationEvidenceClass::DeterministicFixture, true));
    let r = DelegationCalibrationRollupService.rollup(&s, &DelegationCalibrationConfig::default());
    assert_eq!(r[0].real_task_count, 0);
}
#[test]
fn calibration_historical_record_requires_complete_refs() {
    let mut s = DelegationCalibrationState::default();
    let mut x = sample(CalibrationEvidenceClass::HistoricalImportedRecord, false);
    x.completeness.final_task_outcome_present = false;
    assert!(
        DelegationCalibrationIngestService
            .ingest(&mut s, x)
            .is_err()
    );
}
#[test]
fn calibration_provider_cannot_self_label() {
    let e = DelegationOutcomeEvidence {
        provider_claimed_useful: true,
        accepted_findings: 1,
        ..DelegationOutcomeEvidence::default()
    };
    assert_eq!(DelegationOutcomeLabelService.provider_useful(&e), None);
}
#[test]
fn calibration_codex_acceptance_without_evidence_not_verified() {
    let e = DelegationOutcomeEvidence {
        accepted_findings: 1,
        ..DelegationOutcomeEvidence::default()
    };
    assert_eq!(DelegationOutcomeLabelService.provider_useful(&e), None);
}
#[test]
fn calibration_verifier_evidence_can_accept_finding() {
    let e = DelegationOutcomeEvidence {
        verifier_refs: vec!["verify:1".to_owned()],
        accepted_findings: 1,
        ..DelegationOutcomeEvidence::default()
    };
    assert_eq!(
        DelegationOutcomeLabelService.provider_useful(&e),
        Some(true)
    );
}
#[test]
fn calibration_duplicate_finding_classified() {
    let e = DelegationOutcomeEvidence {
        verifier_refs: vec!["verify:1".to_owned()],
        duplicate_findings: 2,
        ..DelegationOutcomeEvidence::default()
    };
    assert_eq!(e.duplicate_findings, 2);
}
#[test]
fn calibration_false_positive_requires_evidence() {
    let e = DelegationOutcomeEvidence {
        false_positive_findings: 3,
        ..DelegationOutcomeEvidence::default()
    };
    assert_eq!(DelegationOutcomeLabelService.false_positive_count(&e), 0);
}
#[test]
fn calibration_missing_refs_mark_incomplete() {
    assert!(
        !sample(CalibrationEvidenceClass::RealExecutedTask, true)
            .completeness
            .complete_for_provider_quality
    );
}
#[test]
fn shadow_run_never_launches_provider() {
    assert!(!DelegationShadowEvaluationService.launches_provider());
}
#[test]
fn shadow_record_created_for_real_task() {
    let x = sample(CalibrationEvidenceClass::RealNoProviderTask, false);
    let r = DelegationShadowEvaluationService.evaluate(
        &x,
        DelegationDecisionKind::NoExternalReview,
        "candidate",
    );
    assert_eq!(
        r.shadow_decision,
        DelegationShadowDecisionKind::WouldExecute
    );
}
#[test]
fn shadow_fixture_does_not_count_as_real_task() {
    let mut s = DelegationCalibrationState::default();
    s.samples.push(sample(
        CalibrationEvidenceClass::DeterministicFixture,
        false,
    ));
    s.shadows.push(DelegationShadowEvaluationService.evaluate(
        &s.samples[0],
        DelegationDecisionKind::NoExternalReview,
        "candidate",
    ));
    let r = DelegationCalibrationRollupService.rollup(&s, &DelegationCalibrationConfig::default());
    assert_eq!(r[0].real_task_count, 0);
}
#[test]
fn counterfactual_default_is_inconclusive() {
    let x = sample(CalibrationEvidenceClass::RealExecutedTask, true);
    let shadow = DelegationShadowEvaluationService.evaluate(
        &x,
        DelegationDecisionKind::Execute,
        "candidate",
    );
    assert_eq!(
        DelegationCounterfactualService
            .label(&shadow, Vec::new())
            .label,
        DelegationCounterfactualKind::Inconclusive
    );
}
#[test]
fn family_rollup_separates_real_fixture_shadow() {
    let mut s = DelegationCalibrationState::default();
    s.samples
        .push(sample(CalibrationEvidenceClass::RealExecutedTask, true));
    s.samples
        .push(sample(CalibrationEvidenceClass::DeterministicFixture, true));
    let r = DelegationCalibrationRollupService.rollup(&s, &DelegationCalibrationConfig::default());
    assert_eq!(r[0].real_task_count, 1);
}
#[test]
fn family_rollup_computes_runtime_statistics() {
    let mut s = DelegationCalibrationState::default();
    let mut a = sample(CalibrationEvidenceClass::RealExecutedTask, true);
    a.costs.provider_runtime_ms = Some(100);
    let mut b = a.clone();
    b.sample_id = "b".to_owned();
    b.task_id = TaskId::new_v7();
    b.costs.provider_runtime_ms = Some(300);
    s.samples.extend([a, b]);
    let r = DelegationCalibrationRollupService.rollup(&s, &DelegationCalibrationConfig::default());
    assert_eq!(r[0].median_provider_runtime_ms, Some(200));
    assert_eq!(r[0].p95_provider_runtime_ms, Some(300));
}
#[test]
fn policy_candidate_does_not_mutate_active_policy() {
    let active = "l0-policy".to_owned();
    let c = DelegationPolicyCandidateService.generate(&[], Vec::new());
    assert_eq!(active, "l0-policy");
    assert!(c.enabled_families.is_empty());
}
#[test]
fn promotion_gate_enforces_minimum_real_tasks() {
    let s = state_with_candidate();
    let d = gate(&s, &DelegationCalibrationConfig::default(), 0);
    assert_eq!(
        d.decision,
        DelegationPolicyPromotionDecisionKind::InsufficientData
    );
    assert!(
        d.reasons
            .contains(&DelegationPolicyPromotionReason::RealTaskCountTooLow)
    );
}
#[test]
fn promotion_gate_enforces_minimum_executed_reviews() {
    let c = DelegationCalibrationConfig {
        minimum_real_tasks_total: 1,
        ..DelegationCalibrationConfig::default()
    };
    let s = state_with_candidate_no_call();
    assert_eq!(
        gate(&s, &c, 0).decision,
        DelegationPolicyPromotionDecisionKind::RequireMoreExecutedReviews
    );
}
#[test]
fn promotion_gate_enforces_complete_outcome_fraction() {
    let c = DelegationCalibrationConfig {
        minimum_real_tasks_total: 1,
        minimum_executed_reviews_total: 1,
        ..DelegationCalibrationConfig::default()
    };
    let s = state_with_candidate();
    assert_eq!(
        gate(&s, &c, 0).decision,
        DelegationPolicyPromotionDecisionKind::RequireMoreRealTasks
    );
}
#[test]
fn promotion_gate_blocks_authority_violation() {
    let mut s = state_with_candidate();
    s.samples[0].labels.authority_violations = 1;
    assert_eq!(
        gate(&s, &DelegationCalibrationConfig::default(), 0).decision,
        DelegationPolicyPromotionDecisionKind::DenySafetyViolation
    );
}
#[test]
fn promotion_gate_blocks_live_tree_violation() {
    let mut s = state_with_candidate();
    s.samples[0].labels.live_tree_violations = 1;
    assert_eq!(
        gate(&s, &DelegationCalibrationConfig::default(), 0).decision,
        DelegationPolicyPromotionDecisionKind::DenySafetyViolation
    );
}
#[test]
fn promotion_gate_blocks_recursive_execution() {
    let s = state_with_candidate();
    assert_eq!(
        gate(&s, &DelegationCalibrationConfig::default(), 1).decision,
        DelegationPolicyPromotionDecisionKind::DenySafetyViolation
    );
}
#[test]
fn promotion_gate_honestly_returns_insufficient_data() {
    let s = state_with_candidate();
    assert_eq!(
        gate(&s, &DelegationCalibrationConfig::default(), 0).decision,
        DelegationPolicyPromotionDecisionKind::InsufficientData
    );
}
#[test]
fn mcp_calibration_surface_read_only() {
    let source = include_str!("../../eliot-app/src/mcp_stdio.rs");
    for name in [
        "eliot_delegation_calibration_status",
        "eliot_delegation_calibration_report",
        "eliot_delegation_policy_candidate",
        "eliot_delegation_promotion_status",
    ] {
        assert!(source.contains(name));
    }
}
#[test]
fn mcp_exposes_no_policy_activation_or_threshold_override() {
    let source = include_str!("../../eliot-app/src/mcp_stdio.rs");
    assert!(!source.contains("eliot_delegation_policy_activate"));
    assert!(!source.contains("eliot_delegation_threshold_override"));
}
#[test]
fn metrics_are_low_cardinality() {
    let defs = MetricRegistryService.definitions();
    let names = defs.iter().map(|d| d.name.as_str()).collect::<Vec<_>>();
    assert!(names.contains(&"delegation_calibration_samples_total"));
    for d in defs
        .iter()
        .filter(|d| d.name.starts_with("delegation_calibration"))
    {
        let labels = format!("{:?}", d.labels);
        assert!(
            !labels.contains("task_id")
                && !labels.contains("delegation_id")
                && !labels.contains("question")
        );
    }
}
fn state_with_candidate() -> DelegationCalibrationState {
    let mut s = DelegationCalibrationState::default();
    s.samples
        .push(sample(CalibrationEvidenceClass::RealExecutedTask, true));
    s.families =
        DelegationCalibrationRollupService.rollup(&s, &DelegationCalibrationConfig::default());
    s.policy_candidate = Some(DelegationPolicyCandidateService.generate(&s.families, Vec::new()));
    s
}
fn state_with_candidate_no_call() -> DelegationCalibrationState {
    let mut s = DelegationCalibrationState::default();
    s.samples
        .push(sample(CalibrationEvidenceClass::RealNoProviderTask, false));
    s.families =
        DelegationCalibrationRollupService.rollup(&s, &DelegationCalibrationConfig::default());
    s.policy_candidate = Some(DelegationPolicyCandidateService.generate(&s.families, Vec::new()));
    s
}
fn gate(
    s: &DelegationCalibrationState,
    c: &DelegationCalibrationConfig,
    r: u32,
) -> eliot_types::DelegationPolicyPromotionDecision {
    let Some(candidate) = s.policy_candidate.as_ref() else {
        std::process::abort()
    };
    DelegationPromotionGateService.decide(s, candidate, c, r)
}
