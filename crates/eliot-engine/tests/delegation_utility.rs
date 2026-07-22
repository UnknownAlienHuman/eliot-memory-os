use eliot_engine::{
    CalibrationEvidenceGapService, DelegationCalibrationCampaignService,
    DelegationCalibrationRollupService, DelegationOutcomeService, DelegationPolicyCandidateService,
    DelegationPromotionGateService, DelegationReportService, IndependentOutcomeEvidenceService,
    ProviderUtilityAssessmentService, default_work_scope,
};
use eliot_types::{
    CalibrationCompleteness, CalibrationEvidenceClass, DelegationCalibrationCampaign,
    DelegationCalibrationCampaignBudget, DelegationCalibrationCampaignCloseoutStatus,
    DelegationCalibrationCampaignState, DelegationCalibrationConfig, DelegationCalibrationCosts,
    DelegationCalibrationLabels, DelegationCalibrationSample, DelegationCalibrationState,
    DelegationCalibrationTaskFamily, DelegationEvidenceFloorSnapshot, DelegationFindingMateriality,
    DelegationOrigin, DelegationPolicyPromotionDecisionKind, DelegationPolicyPromotionReason,
    DelegationPromotionReadinessVerdict, DelegationReviewKind, DelegationState,
    ExecutedProviderReview, ExecutedProviderReviewStatus, IndependentEvidenceContaminationChecks,
    IndependentEvidenceKind, IndependentEvidenceResult, IndependentOutcomeEvidence, ProjectId,
    ProviderUtilityReason, TaskId,
};
use std::sync::OnceLock;
use time::OffsetDateTime;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn campaign_state_machine_accepts_canonical_path() -> TestResult {
    let mut campaign = campaign();
    let service = DelegationCalibrationCampaignService;
    for state in [
        DelegationCalibrationCampaignState::Ready,
        DelegationCalibrationCampaignState::ProviderExecuting,
        DelegationCalibrationCampaignState::ProviderExecuted,
        DelegationCalibrationCampaignState::AwaitingIndependentEvidence,
        DelegationCalibrationCampaignState::Attributed,
        DelegationCalibrationCampaignState::RolledUp,
        DelegationCalibrationCampaignState::Closed,
    ] {
        assert!(service.transition(&mut campaign, state)?);
    }
    assert_eq!(campaign.state, DelegationCalibrationCampaignState::Closed);
    assert_eq!(
        campaign.closeout_status,
        DelegationCalibrationCampaignCloseoutStatus::DoneVerified
    );
    assert!(campaign.closed_at.is_some());
    Ok(())
}

#[test]
fn campaign_terminal_state_is_immutable() -> TestResult {
    let mut campaign = campaign();
    let service = DelegationCalibrationCampaignService;
    service.transition(&mut campaign, DelegationCalibrationCampaignState::Cancelled)?;
    assert!(
        service
            .transition(&mut campaign, DelegationCalibrationCampaignState::Ready)
            .is_err()
    );
    Ok(())
}

#[test]
fn campaign_replay_of_same_transition_is_idempotent() -> TestResult {
    let mut campaign = campaign();
    let service = DelegationCalibrationCampaignService;
    assert!(service.transition(&mut campaign, DelegationCalibrationCampaignState::Ready)?);
    assert!(!service.transition(&mut campaign, DelegationCalibrationCampaignState::Ready)?);
    Ok(())
}

#[test]
fn review_requires_frozen_baseline_before_execution() {
    let mut state = state_with_ready_campaign();
    state.campaigns[0].baseline_state_hash.clear();
    assert!(
        DelegationCalibrationCampaignService
            .ingest_review(&mut state, review())
            .is_err()
    );
}

#[test]
fn review_must_remain_candidate_only() {
    let mut state = state_with_ready_campaign();
    let mut item = review();
    item.candidate_only = false;
    assert!(
        DelegationCalibrationCampaignService
            .ingest_review(&mut state, item)
            .is_err()
    );
}

#[test]
fn review_ingestion_is_idempotent() -> TestResult {
    let mut state = state_with_ready_campaign();
    let item = review();
    assert!(DelegationCalibrationCampaignService.ingest_review(&mut state, item.clone())?);
    assert!(!DelegationCalibrationCampaignService.ingest_review(&mut state, item)?);
    assert_eq!(state.executed_reviews.len(), 1);
    assert_eq!(state.campaigns[0].executed_review_ids.len(), 1);
    Ok(())
}

#[test]
fn provider_derived_evidence_is_rejected() -> TestResult {
    let mut state = state_with_review()?;
    let mut item = evidence(IndependentEvidenceResult::Confirmed);
    item.independent_from_provider = false;
    item.contamination_checks.producer_is_provider = true;
    assert!(
        IndependentOutcomeEvidenceService
            .attach(&mut state, item)
            .is_err()
    );
    Ok(())
}

#[test]
fn unregistered_evidence_producer_is_rejected() -> TestResult {
    let mut state = state_with_review()?;
    let mut item = evidence(IndependentEvidenceResult::Confirmed);
    item.producer_identity = "arbitrary-external-string".to_owned();
    assert!(
        IndependentOutcomeEvidenceService
            .attach(&mut state, item)
            .is_err()
    );
    Ok(())
}

#[test]
fn evidence_scope_must_match_exact_review_and_task() -> TestResult {
    let mut state = state_with_review()?;
    let mut item = evidence(IndependentEvidenceResult::Confirmed);
    item.task_id = TaskId::new_v7();
    assert!(
        IndependentOutcomeEvidenceService
            .attach(&mut state, item)
            .is_err()
    );
    Ok(())
}

#[test]
fn evidence_attachment_is_idempotent() -> TestResult {
    let mut state = state_with_review()?;
    let item = evidence(IndependentEvidenceResult::Confirmed);
    assert!(IndependentOutcomeEvidenceService.attach(&mut state, item.clone())?);
    assert!(!IndependentOutcomeEvidenceService.attach(&mut state, item)?);
    assert_eq!(state.independent_evidence.len(), 1);
    assert_eq!(state.campaigns[0].independent_evidence_ids.len(), 1);
    Ok(())
}

#[test]
fn utility_true_for_confirmed_material_novel_finding() {
    let item = evidence(IndependentEvidenceResult::Confirmed);
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[item],
    );
    assert_eq!(assessment.provider_useful, Some(true));
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::ConfirmedMaterialNovelFinding
    );
}

#[test]
fn utility_true_for_confirmed_action_change() {
    let mut item = evidence(IndependentEvidenceResult::Confirmed);
    item.changed_controller_action = true;
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[item],
    );
    assert_eq!(assessment.provider_useful, Some(true));
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::ConfirmedMaterialActionChange
    );
}

#[test]
fn utility_true_for_prevented_verified_failure() {
    let mut item = evidence(IndependentEvidenceResult::Confirmed);
    item.prevented_verified_failure = true;
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[item],
    );
    assert_eq!(assessment.provider_useful, Some(true));
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::ConfirmedFailurePrevention
    );
}

#[test]
fn utility_false_for_refuted_material_output() {
    let mut item = evidence(IndependentEvidenceResult::Refuted);
    item.supports_provider_finding_ids.clear();
    item.refutes_provider_finding_ids = vec!["finding-1".to_owned()];
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[item],
    );
    assert_eq!(assessment.provider_useful, Some(false));
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::RefutedOrFalsePositiveOutput
    );
}

#[test]
fn utility_null_without_independent_evidence() {
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[],
    );
    assert_eq!(assessment.provider_useful, None);
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::MissingIndependentEvidence
    );
}

#[test]
fn utility_null_for_inconclusive_evidence() {
    let mut item = evidence(IndependentEvidenceResult::Inconclusive);
    item.supports_provider_finding_ids.clear();
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[item],
    );
    assert_eq!(assessment.provider_useful, None);
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::InconclusiveEvidence
    );
}

#[test]
fn utility_null_for_contradictory_evidence() {
    let supports = evidence(IndependentEvidenceResult::Confirmed);
    let mut refutes = evidence(IndependentEvidenceResult::Refuted);
    refutes.evidence_id = "evidence-2".to_owned();
    refutes.supports_provider_finding_ids.clear();
    refutes.refutes_provider_finding_ids = vec!["finding-1".to_owned()];
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[supports, refutes],
    );
    assert_eq!(assessment.provider_useful, None);
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::ContradictoryEvidence
    );
}

#[test]
fn contaminated_assessment_cannot_mark_sample_complete() {
    let mut item = evidence(IndependentEvidenceResult::Confirmed);
    item.contamination_checks.producer_is_provider = true;
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[item],
    );
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::ContaminatedEvidence
    );
    assert!(assessment.evidence_refs.is_empty());
    let mut state = state_with_ready_campaign();
    state.samples.push(sample());
    ProviderUtilityAssessmentService.apply(&mut state, &review(), &assessment);
    assert!(!state.samples[0].completeness.complete_for_provider_quality);
    assert!(
        !state.samples[0]
            .completeness
            .verifier_or_human_evidence_present
    );
}

#[test]
fn task_family_materiality_threshold_is_explicit() {
    let mut item = evidence(IndependentEvidenceResult::Confirmed);
    item.materiality = DelegationFindingMateriality::Low;
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::TrivialDeterministicTask,
        &[item],
    );
    assert_eq!(assessment.provider_useful, None);
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::BelowMaterialityThreshold
    );
}

#[test]
fn utility_application_does_not_double_count() {
    let mut state = state_with_ready_campaign();
    state.samples.push(sample());
    let item = evidence(IndependentEvidenceResult::Confirmed);
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[item],
    );
    assert!(ProviderUtilityAssessmentService.apply(&mut state, &review(), &assessment));
    ProviderUtilityAssessmentService.apply(&mut state, &review(), &assessment);
    assert_eq!(state.utility_assessments.len(), 1);
    assert_eq!(state.samples[0].labels.accepted_findings, 1);
}

#[test]
fn idempotent_assessment_replay_repairs_stale_sample_projection() {
    let mut state = state_with_ready_campaign();
    state.samples.push(sample());
    let assessment = ProviderUtilityAssessmentService.assess(
        &review(),
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[evidence(IndependentEvidenceResult::Confirmed)],
    );
    ProviderUtilityAssessmentService.apply(&mut state, &review(), &assessment);
    state.samples[0].labels.provider_useful = None;
    state.samples[0].completeness.complete_for_provider_quality = false;
    assert!(ProviderUtilityAssessmentService.apply(&mut state, &review(), &assessment));
    assert_eq!(state.samples[0].labels.provider_useful, Some(true));
    assert!(state.samples[0].completeness.complete_for_provider_quality);
    assert_eq!(state.utility_assessments.len(), 1);
}

#[test]
fn rollup_replay_does_not_mutate_samples() {
    let mut state = state_with_ready_campaign();
    state.samples.push(sample());
    let before = state.samples.clone();
    let first =
        DelegationCalibrationRollupService.rollup(&state, &DelegationCalibrationConfig::default());
    let second =
        DelegationCalibrationRollupService.rollup(&state, &DelegationCalibrationConfig::default());
    assert_eq!(before, state.samples);
    assert_eq!(first[0].real_task_count, second[0].real_task_count);
}

#[test]
fn evidence_gap_preserves_existing_floors() {
    let mut state = state_with_ready_campaign();
    state.samples.push(sample());
    let config = DelegationCalibrationConfig::default();
    let gap = CalibrationEvidenceGapService.report(&state, &config, 0);
    assert_eq!(gap.required_floors.minimum_real_tasks_total, 12);
    assert_eq!(gap.required_floors.minimum_executed_reviews_total, 4);
    assert_eq!(gap.required_floors.minimum_shadow_tasks_total, 12);
    assert_eq!(
        gap.promotion_readiness,
        DelegationPromotionReadinessVerdict::InsufficientData
    );
}

#[test]
fn integrity_violation_blocks_promotion_readiness() {
    let mut state = state_with_ready_campaign();
    let mut item = sample();
    item.labels.authority_violations = 1;
    state.samples.push(item);
    let gap =
        CalibrationEvidenceGapService.report(&state, &DelegationCalibrationConfig::default(), 0);
    assert_eq!(
        gap.promotion_readiness,
        DelegationPromotionReadinessVerdict::BlockedByIntegrity
    );
}

#[test]
fn provider_call_budget_violation_blocks_campaign_readiness() {
    let mut state = state_with_ready_campaign();
    state.campaigns[0].observed_provider_calls = 2;
    state.campaigns[0]
        .integrity_violations
        .push("provider_call_budget_exceeded:2>1".to_owned());
    let gap =
        CalibrationEvidenceGapService.report(&state, &DelegationCalibrationConfig::default(), 0);
    assert_eq!(
        gap.promotion_readiness,
        DelegationPromotionReadinessVerdict::BlockedByIntegrity
    );
}

#[test]
fn failed_terminal_campaign_has_closeout_metadata() -> TestResult {
    let mut item = campaign();
    DelegationCalibrationCampaignService
        .transition(&mut item, DelegationCalibrationCampaignState::Ready)?;
    DelegationCalibrationCampaignService.transition(
        &mut item,
        DelegationCalibrationCampaignState::ProviderExecuting,
    )?;
    DelegationCalibrationCampaignService.transition(
        &mut item,
        DelegationCalibrationCampaignState::FailedProvider,
    )?;
    assert!(item.closed_at.is_some());
    assert_eq!(
        item.closeout_status,
        DelegationCalibrationCampaignCloseoutStatus::BlockedExternalDependency
    );
    Ok(())
}

#[test]
fn shadow_floor_reports_shadow_shortage() {
    let mut state = state_with_ready_campaign();
    for index in 0..12 {
        let mut item = sample();
        item.sample_id = format!("sample-{index}");
        item.task_id = TaskId::new_v7();
        item.completeness.complete_for_routing_quality = true;
        item.completeness.complete_for_provider_quality = true;
        state.samples.push(item);
    }
    state.families =
        DelegationCalibrationRollupService.rollup(&state, &DelegationCalibrationConfig::default());
    let candidate = DelegationPolicyCandidateService.generate(&state.families, Vec::new());
    let decision = DelegationPromotionGateService.decide(
        &state,
        &candidate,
        &DelegationCalibrationConfig::default(),
        0,
    );
    assert_eq!(
        decision.decision,
        DelegationPolicyPromotionDecisionKind::RequireMoreRealTasks
    );
    assert!(
        decision
            .reasons
            .contains(&DelegationPolicyPromotionReason::ShadowTaskCountTooLow)
    );
}

#[test]
fn delegation_report_aggregates_recorded_integrity_violations() {
    let mut state = DelegationState::default();
    let mut outcome = DelegationOutcomeService.record(
        "delegation-1",
        Some("result-1".to_owned()),
        1,
        0,
        0,
        0,
        Vec::new(),
        false,
        10,
        1,
        false,
    );
    outcome.integrity_evidence_present = true;
    outcome.authority_violations = 2;
    outcome.live_tree_violations = 1;
    state.outcomes.push(outcome);
    let report = DelegationReportService.summary(&state);
    assert_eq!(report["authority_violation_total"], 2);
    assert_eq!(report["live_tree_violation_total"], 1);
    assert_eq!(report["integrity_evidence_complete"], true);
}

#[test]
fn policy_candidate_stays_inactive_and_budgetless() {
    let candidate = DelegationPolicyCandidateService.generate(&[], Vec::new());
    assert!(candidate.enabled_families.is_empty());
    assert!(candidate.proposed_budget_changes.is_empty());
}

#[test]
fn auditor_profile_has_zero_calibration_tools() {
    let source = include_str!("../../eliot-app/src/mcp_stdio.rs");
    assert!(source.contains("McpAccessProfile::ExternalAuditor"));
    let auditor_tools = source
        .split_once("const READ_ONLY_TOOLS")
        .map(|(_, tail)| tail)
        .and_then(|tail| tail.split_once("];\n").map(|(list, _)| list))
        .unwrap_or_default();
    for name in [
        "eliot_delegation_calibration_status",
        "eliot_delegation_calibration_report",
        "eliot_delegation_policy_candidate",
        "eliot_delegation_promotion_status",
    ] {
        assert!(source.contains(name));
        assert!(!auditor_tools.contains(name));
    }
    assert!(!source.contains("eliot_delegation_policy_activate"));
}

#[test]
fn read_only_work_scope_never_invents_write_authority() {
    let scope = default_work_scope("repo", vec!["repo/**".to_owned()], Vec::new(), Vec::new());
    assert!(scope.write_set.is_empty());
    assert!(!scope.authority.allows_write());
    let source = include_str!("../../eliot-app/src/commands/execution.rs");
    let create = source
        .split_once("pub async fn run_work_create")
        .map(|(_, tail)| tail)
        .and_then(|tail| {
            tail.split_once("pub async fn run_work_claim")
                .map(|(body, _)| body)
        })
        .unwrap_or_default();
    assert!(create.contains("let write_set = write.to_vec();"));
    assert!(!create.contains("crates/eliot-engine/src/work.rs"));
}

fn campaign() -> DelegationCalibrationCampaign {
    DelegationCalibrationCampaign {
        campaign_id: "campaign-1".to_owned(),
        project_id: project_id(),
        schema_version: "1".to_owned(),
        created_at: OffsetDateTime::now_utc(),
        closed_at: None,
        baseline_commit: "abc123".to_owned(),
        policy_snapshot_id: "policy:l0".to_owned(),
        provider_route: "antigravity".to_owned(),
        task_family: DelegationCalibrationTaskFamily::SecurityBoundary,
        selection_rule: "explicit bounded provider sample".to_owned(),
        budget: DelegationCalibrationCampaignBudget {
            max_provider_calls: 1,
            max_cost_if_known: None,
            max_wall_time_seconds: 900,
        },
        evidence_floor_snapshot: DelegationEvidenceFloorSnapshot {
            minimum_real_tasks_total: 12,
            minimum_real_tasks_per_family: 5,
            minimum_executed_reviews_total: 4,
            minimum_executed_reviews_per_candidate_family: 3,
            minimum_complete_outcome_fraction: 0.8,
            minimum_shadow_tasks_total: 12,
        },
        selected_task_ids: vec![task_id()],
        frozen_input_refs: vec!["git:abc123".to_owned()],
        baseline_state_hash: "baseline-hash".to_owned(),
        observed_provider_calls: 0,
        integrity_violations: Vec::new(),
        executed_review_ids: Vec::new(),
        independent_evidence_ids: Vec::new(),
        shadow_evaluation_ids: Vec::new(),
        state: DelegationCalibrationCampaignState::Draft,
        closeout_status: DelegationCalibrationCampaignCloseoutStatus::Open,
        transition_history: Vec::new(),
    }
}

fn state_with_ready_campaign() -> DelegationCalibrationState {
    let mut item = campaign();
    item.state = DelegationCalibrationCampaignState::Ready;
    DelegationCalibrationState {
        campaigns: vec![item],
        ..DelegationCalibrationState::default()
    }
}

fn state_with_review() -> Result<DelegationCalibrationState, Box<dyn std::error::Error>> {
    let mut state = state_with_ready_campaign();
    DelegationCalibrationCampaignService.ingest_review(&mut state, review())?;
    Ok(state)
}

fn review() -> ExecutedProviderReview {
    ExecutedProviderReview {
        review_id: "review-1".to_owned(),
        campaign_id: "campaign-1".to_owned(),
        real_task_id: task_id(),
        provider: "antigravity".to_owned(),
        model_route_if_known: None,
        request_ref: "delegation-1".to_owned(),
        frozen_input_refs: vec!["git:abc123".to_owned()],
        baseline_state_hash: "baseline-hash".to_owned(),
        provider_gate_decision_ref: "gate:allow".to_owned(),
        quota_or_cost_receipt: "quota:one-call".to_owned(),
        started_at: OffsetDateTime::now_utc(),
        completed_at: Some(OffsetDateTime::now_utc()),
        status: ExecutedProviderReviewStatus::Succeeded,
        raw_output_ref: "blob:raw".to_owned(),
        normalized_findings: vec!["finding-1".to_owned()],
        proposed_changes: Vec::new(),
        candidate_only: true,
        trace_ref: "trace:1".to_owned(),
    }
}

fn evidence(result: IndependentEvidenceResult) -> IndependentOutcomeEvidence {
    IndependentOutcomeEvidence {
        evidence_id: "evidence-1".to_owned(),
        campaign_id: "campaign-1".to_owned(),
        review_id: "review-1".to_owned(),
        task_id: task_id(),
        evidence_kind: IndependentEvidenceKind::Verifier,
        producer_identity: "cargo-nextest".to_owned(),
        independent_from_provider: true,
        scope: "delegation_utility".to_owned(),
        observed_at: OffsetDateTime::now_utc(),
        exact_anchor_refs: vec!["verification:provider-experiment".to_owned()],
        result,
        materiality: DelegationFindingMateriality::Medium,
        supports_provider_finding_ids: vec!["finding-1".to_owned()],
        refutes_provider_finding_ids: Vec::new(),
        unresolved_provider_finding_ids: Vec::new(),
        contamination_checks: IndependentEvidenceContaminationChecks {
            producer_is_provider: false,
            criteria_added_after_provider_output: false,
            provider_output_used_as_verifier_input: false,
            scope_matches_review: true,
        },
        authority: "registered_deterministic_verifier".to_owned(),
        changed_controller_action: false,
        prevented_verified_failure: false,
        unnecessary_work: false,
        verified_quality_delta: 0,
        verified_cost_or_latency_delta: 0,
        trace_ref: "trace:verify-1".to_owned(),
    }
}

fn sample() -> DelegationCalibrationSample {
    DelegationCalibrationSample {
        sample_id: "sample-1".to_owned(),
        project_id: project_id(),
        task_id: task_id(),
        task_family: DelegationCalibrationTaskFamily::SecurityBoundary,
        evidence_class: CalibrationEvidenceClass::RealExecutedTask,
        delegation_origin: DelegationOrigin::UserDirected,
        review_kind: DelegationReviewKind::RiskReview,
        route_decision_ref: "route:1".to_owned(),
        delegation_outcome_ref: Some("outcome:1".to_owned()),
        provider_result_ref: Some("result:1".to_owned()),
        controller_outcome_refs: vec!["controller:1".to_owned()],
        verifier_refs: Vec::new(),
        shadow_decision_ref: None,
        labels: DelegationCalibrationLabels {
            provider_called: true,
            unique_findings: 1,
            ..DelegationCalibrationLabels::default()
        },
        costs: DelegationCalibrationCosts {
            provider_call_count: 1,
            ..DelegationCalibrationCosts::default()
        },
        completeness: CalibrationCompleteness {
            route_decision_present: true,
            final_task_outcome_present: true,
            provider_result_present: true,
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

fn project_id() -> ProjectId {
    static ID: OnceLock<ProjectId> = OnceLock::new();
    *ID.get_or_init(ProjectId::new_v7)
}

fn task_id() -> TaskId {
    static ID: OnceLock<TaskId> = OnceLock::new();
    *ID.get_or_init(TaskId::new_v7)
}
