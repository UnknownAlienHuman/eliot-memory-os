use eliot_engine::{
    DelegationCalibrationCampaignService, L1cCorpusEligibilityService,
    ProviderReviewPreRegistrationService, ProviderUtilityAssessmentService,
};
use eliot_types::{
    CalibrationCorpusEligibility, CalibrationCorpusSampleKind, CalibrationIntegrityStatus,
    DelegationCalibrationCampaign, DelegationCalibrationCampaignBudget,
    DelegationCalibrationCampaignCloseoutStatus, DelegationCalibrationCampaignState,
    DelegationCalibrationState, DelegationCalibrationTaskFamily, DelegationEvidenceFloorSnapshot,
    DelegationFindingMateriality, ExecutedProviderReview, ExecutedProviderReviewStatus,
    FrozenInputDigest, IndependentEvidenceContaminationChecks, IndependentEvidenceKind,
    IndependentEvidenceResult, IndependentOutcomeEvidence, ProjectId, ProviderCallReservation,
    ProviderCallReservationState, ProviderFindingDisposition, ProviderFindingMateriality,
    ProviderFindingNovelty, ProviderFindingVerdict, ProviderReviewPreRegistration,
    ProviderUtilityReason, TaskId,
};
use std::sync::OnceLock;
use time::{Duration, OffsetDateTime};

#[test]
fn canonical_l1c_campaign_state_sequence_is_explicit() -> Result<(), String> {
    let mut campaign = campaign();
    for next in [
        DelegationCalibrationCampaignState::Preregistered,
        DelegationCalibrationCampaignState::Ready,
        DelegationCalibrationCampaignState::Reserved,
        DelegationCalibrationCampaignState::Dispatching,
        DelegationCalibrationCampaignState::ProviderExecuted,
        DelegationCalibrationCampaignState::AwaitingIndependentEvidence,
        DelegationCalibrationCampaignState::Attributed,
        DelegationCalibrationCampaignState::EligibilityDecided,
        DelegationCalibrationCampaignState::RolledUp,
        DelegationCalibrationCampaignState::Closed,
    ] {
        DelegationCalibrationCampaignService.transition(&mut campaign, next)?;
    }
    assert_eq!(campaign.state, DelegationCalibrationCampaignState::Closed);
    assert_eq!(campaign.transition_history.len(), 10);
    assert!(
        DelegationCalibrationCampaignService
            .transition(&mut campaign, DelegationCalibrationCampaignState::Ready)
            .is_err()
    );
    Ok(())
}

#[test]
fn preregistration_token_and_idempotency_are_stable() -> Result<(), String> {
    let preregistration = preregistration();
    let token = ProviderReviewPreRegistrationService::execution_token(&preregistration);
    let mut sealed = preregistration.clone();
    sealed.execution_token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();
    ProviderReviewPreRegistrationService::validate_token(&sealed, &token)?;
    assert_eq!(
        ProviderReviewPreRegistrationService::idempotency_key(
            &sealed.campaign_id,
            sealed.real_task_id,
            &sealed.provider,
            &sealed.baseline_commit,
            &sealed.frozen_input_hash
        ),
        sealed.idempotency_key
    );
    assert!(ProviderReviewPreRegistrationService::validate_token(&sealed, "wrong").is_err());
    Ok(())
}

#[test]
fn sealed_semantic_mutation_requires_new_attempt() {
    let sealed = preregistration();
    let mut changed = sealed.clone();
    changed
        .review_questions
        .push("post-hoc question".to_owned());
    assert!(
        ProviderReviewPreRegistrationService::validate_sealed_replay(&sealed, &changed).is_err()
    );
    let mut widened = sealed.clone();
    widened.max_provider_calls = 2;
    assert!(
        ProviderReviewPreRegistrationService::validate_sealed_replay(&sealed, &widened).is_err()
    );
}

#[test]
fn preregistration_must_precede_reservation() {
    let mut preregistration = preregistration();
    let reservation = reservation();
    preregistration.sealed_at = reservation.reserved_at + Duration::seconds(1);
    assert!(
        ProviderReviewPreRegistrationService::validate_before_reservation(
            &preregistration,
            &reservation
        )
        .is_err()
    );
}

#[test]
fn complete_negative_canary_is_promotion_eligible() -> Result<(), String> {
    let review = review(Vec::new());
    let evidence = evidence(Vec::new(), Vec::new(), IndependentEvidenceResult::Confirmed);
    let assessment = ProviderUtilityAssessmentService.assess_preregistered(
        &review,
        DelegationCalibrationTaskFamily::SecurityBoundary,
        std::slice::from_ref(&evidence),
        &[],
        "l1c-preregistered-1",
    );
    assert_eq!(assessment.provider_useful, Some(false));
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::NoMaterialOutcomeDelta
    );
    let mut preregistration = preregistration();
    preregistration.review_ref = Some(review.review_id.clone());
    let mut campaign = campaign();
    campaign.state = DelegationCalibrationCampaignState::Attributed;
    campaign.observed_provider_calls = 1;
    campaign.executed_review_ids = vec![review.review_id.clone()];
    let mut state = DelegationCalibrationState {
        campaigns: vec![campaign],
        preregistrations: vec![preregistration],
        executed_reviews: vec![review],
        independent_evidence: vec![evidence],
        utility_assessments: vec![assessment],
        ..DelegationCalibrationState::default()
    };
    let records = L1cCorpusEligibilityService.decide(&mut state, "campaign-l1c", &reservation())?;
    assert_eq!(
        records
            .iter()
            .filter(|item| item.sample_kind == CalibrationCorpusSampleKind::ExecutedReview)
            .filter(|item| item.promotion_eligible)
            .count(),
        1
    );
    assert!(
        records
            .iter()
            .all(|item| item.integrity_status == CalibrationIntegrityStatus::Valid)
    );
    Ok(())
}

#[test]
fn null_utility_stays_observed_but_ineligible() {
    let review = review(vec!["finding-1".to_owned()]);
    let dispositions = vec![ProviderFindingDisposition {
        campaign_id: "campaign-l1c".to_owned(),
        review_id: review.review_id.clone(),
        finding_id: "finding-1".to_owned(),
        materiality: ProviderFindingMateriality::Material,
        novelty: ProviderFindingNovelty::Novel,
        independent_evidence_refs: Vec::new(),
        verdict: ProviderFindingVerdict::Unresolved,
        action_delta: "unknown".to_owned(),
        verifier_delta: "unknown".to_owned(),
        outcome_delta: "unknown".to_owned(),
        decided_at: OffsetDateTime::now_utc(),
    }];
    let evidence = evidence(
        Vec::new(),
        Vec::new(),
        IndependentEvidenceResult::Inconclusive,
    );
    let assessment = ProviderUtilityAssessmentService.assess_preregistered(
        &review,
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[evidence],
        &dispositions,
        "l1c-preregistered-1",
    );
    assert_eq!(assessment.provider_useful, None);
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::InconclusiveEvidence
    );
}

#[test]
fn novel_confirmed_material_finding_requires_independent_evidence() {
    let review = review(vec!["finding-1".to_owned()]);
    let evidence = evidence(
        vec!["finding-1".to_owned()],
        Vec::new(),
        IndependentEvidenceResult::Confirmed,
    );
    let disposition = ProviderFindingDisposition {
        campaign_id: "campaign-l1c".to_owned(),
        review_id: review.review_id.clone(),
        finding_id: "finding-1".to_owned(),
        materiality: ProviderFindingMateriality::Material,
        novelty: ProviderFindingNovelty::Novel,
        independent_evidence_refs: vec![evidence.evidence_id.clone()],
        verdict: ProviderFindingVerdict::Confirmed,
        action_delta: "controller decision changed".to_owned(),
        verifier_delta: "focused regression added".to_owned(),
        outcome_delta: "failure prevented".to_owned(),
        decided_at: OffsetDateTime::now_utc(),
    };
    let assessment = ProviderUtilityAssessmentService.assess_preregistered(
        &review,
        DelegationCalibrationTaskFamily::SecurityBoundary,
        &[evidence],
        &[disposition],
        "l1c-preregistered-1",
    );
    assert_eq!(assessment.provider_useful, Some(true));
    assert_eq!(
        assessment.reason,
        ProviderUtilityReason::ConfirmedMaterialNovelFinding
    );
}

#[test]
fn provider_free_phase_target_contains_no_execution_surface() -> std::io::Result<()> {
    let justfile = std::fs::read_to_string("../../Justfile")?;
    if let Some(target) = justfile.split("phase-l1c:\n").nth(1) {
        let body = target.split("\n\n").next().unwrap_or_default();
        assert!(!body.contains("provider-once"));
        assert!(!body.contains("execute-provider"));
        assert!(!body.contains("run_real"));
    }
    let mcp = std::fs::read_to_string("../eliot-app/src/mcp_stdio.rs")?;
    assert!(!mcp.contains("phase_l1c_provider_once"));
    Ok(())
}

#[test]
fn historical_exclusions_are_not_rewritten_by_l1c_eligibility() -> Result<(), String> {
    let historical = CalibrationCorpusEligibility {
        sample_ref: "historical-over-budget".to_owned(),
        sample_kind: CalibrationCorpusSampleKind::ExecutedReview,
        observed: true,
        integrity_status: CalibrationIntegrityStatus::OverBudget,
        promotion_eligible: false,
        exclusion_reasons: vec!["campaign_call_budget_exceeded".to_owned()],
        decided_by_rule_version: "l1b-r-integrity-1".to_owned(),
        evidence_refs: vec!["historical".to_owned()],
        decided_at: OffsetDateTime::now_utc(),
    };
    let review = review(Vec::new());
    let evidence = evidence(Vec::new(), Vec::new(), IndependentEvidenceResult::Confirmed);
    let assessment = ProviderUtilityAssessmentService.assess_preregistered(
        &review,
        DelegationCalibrationTaskFamily::SecurityBoundary,
        std::slice::from_ref(&evidence),
        &[],
        "l1c-preregistered-1",
    );
    let mut campaign = campaign();
    campaign.observed_provider_calls = 1;
    let mut state = DelegationCalibrationState {
        campaigns: vec![campaign],
        preregistrations: vec![preregistration()],
        executed_reviews: vec![review],
        independent_evidence: vec![evidence],
        utility_assessments: vec![assessment],
        corpus_eligibility: vec![historical.clone()],
        ..DelegationCalibrationState::default()
    };
    L1cCorpusEligibilityService.decide(&mut state, "campaign-l1c", &reservation())?;
    assert!(state.corpus_eligibility.contains(&historical));
    Ok(())
}

fn campaign() -> DelegationCalibrationCampaign {
    DelegationCalibrationCampaign {
        campaign_id: "campaign-l1c".to_owned(),
        project_id: project_id(),
        schema_version: "2".to_owned(),
        created_at: OffsetDateTime::now_utc(),
        closed_at: None,
        baseline_commit: "base".to_owned(),
        policy_snapshot_id: "policy:l0".to_owned(),
        provider_route: "antigravity".to_owned(),
        task_family: DelegationCalibrationTaskFamily::SecurityBoundary,
        selection_rule: "l1c canary".to_owned(),
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
        frozen_input_refs: vec!["git:base".to_owned()],
        baseline_state_hash: "frozen-hash".to_owned(),
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

fn preregistration() -> ProviderReviewPreRegistration {
    let idempotency_key = ProviderReviewPreRegistrationService::idempotency_key(
        "campaign-l1c",
        task_id(),
        "antigravity",
        "base",
        "frozen-hash",
    );
    ProviderReviewPreRegistration {
        preregistration_id: "prereg-l1c".to_owned(),
        campaign_id: "campaign-l1c".to_owned(),
        project_id: project_id(),
        real_task_id: task_id(),
        provider: "antigravity".to_owned(),
        task_family: DelegationCalibrationTaskFamily::SecurityBoundary,
        baseline_commit: "base".to_owned(),
        comparison_base_commit: "comparison".to_owned(),
        frozen_input_refs: vec!["git:base".to_owned()],
        frozen_input_digests: vec![FrozenInputDigest {
            source_ref: "git:base".to_owned(),
            content_hash: "frozen-hash".to_owned(),
        }],
        frozen_input_hash: "frozen-hash".to_owned(),
        review_questions: vec!["bounded question".to_owned()],
        materiality_rule: "material behavior only".to_owned(),
        independent_evidence_plan: vec!["cargo-nextest".to_owned()],
        utility_attribution_rule_version: "l1c-preregistered-1".to_owned(),
        max_provider_calls: 1,
        idempotency_key,
        execution_token_hash: String::new(),
        historical_exclusions_hash: "historical-hash".to_owned(),
        forbidden_effects: vec!["live_tree_write".to_owned()],
        expected_terminal_states: vec!["closed".to_owned()],
        created_at: OffsetDateTime::now_utc(),
        sealed_at: OffsetDateTime::now_utc(),
        consumed_at: None,
        reservation_ref: None,
        invocation_ref: None,
        review_ref: None,
        supersedes_ref: None,
    }
}

fn reservation() -> ProviderCallReservation {
    ProviderCallReservation {
        reservation_id: "reservation-l1c".to_owned(),
        campaign_id: "campaign-l1c".to_owned(),
        task_id: task_id(),
        provider: "antigravity".to_owned(),
        idempotency_key: preregistration().idempotency_key,
        slot_index: 0,
        budget_revision: 3,
        gate_decision_ref: "gate-l1c".to_owned(),
        state: ProviderCallReservationState::Completed,
        reserved_at: OffsetDateTime::now_utc(),
        dispatch_started_at: Some(OffsetDateTime::now_utc()),
        external_invocation_ref: Some("invocation-l1c".to_owned()),
        review_ref: Some("review-l1c".to_owned()),
        terminal_at: Some(OffsetDateTime::now_utc()),
        consumes_budget: true,
        release_or_failure_reason: None,
    }
}

fn review(findings: Vec<String>) -> ExecutedProviderReview {
    ExecutedProviderReview {
        review_id: "review-l1c".to_owned(),
        campaign_id: "campaign-l1c".to_owned(),
        real_task_id: task_id(),
        provider: "antigravity".to_owned(),
        model_route_if_known: None,
        request_ref: "delegation-l1c".to_owned(),
        frozen_input_refs: vec!["git:base".to_owned()],
        baseline_state_hash: "frozen-hash".to_owned(),
        provider_gate_decision_ref: "gate-l1c".to_owned(),
        quota_or_cost_receipt: "provider_calls=1".to_owned(),
        started_at: OffsetDateTime::now_utc(),
        completed_at: Some(OffsetDateTime::now_utc()),
        status: ExecutedProviderReviewStatus::Succeeded,
        raw_output_ref: "raw-l1c".to_owned(),
        normalized_findings: findings,
        proposed_changes: Vec::new(),
        candidate_only: true,
        trace_ref: "trace-l1c".to_owned(),
    }
}

fn evidence(
    supports: Vec<String>,
    refutes: Vec<String>,
    result: IndependentEvidenceResult,
) -> IndependentOutcomeEvidence {
    IndependentOutcomeEvidence {
        evidence_id: "evidence-l1c".to_owned(),
        campaign_id: "campaign-l1c".to_owned(),
        review_id: "review-l1c".to_owned(),
        task_id: task_id(),
        evidence_kind: IndependentEvidenceKind::Verifier,
        producer_identity: "cargo-nextest".to_owned(),
        independent_from_provider: true,
        scope: "integrity_canary".to_owned(),
        observed_at: OffsetDateTime::now_utc(),
        exact_anchor_refs: vec!["test:integrity_canary".to_owned()],
        result,
        materiality: DelegationFindingMateriality::High,
        supports_provider_finding_ids: supports,
        refutes_provider_finding_ids: refutes,
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
        trace_ref: "trace-verifier-l1c".to_owned(),
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
