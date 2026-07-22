use eliot_engine::{
    AntigravityTextOutputNormalizer, DelegationBudgetReservation, DelegationBudgetService,
    DelegationOutcomeService, DelegationPolicyContext, DelegationPolicyService,
    DelegationReportService, MetricRegistryService, antigravity_review_request,
};
use eliot_types::{
    AntigravityReviewMode, DelegationDecisionKind, DelegationOrigin, DelegationOriginChain,
    DelegationProviderPreference, DelegationReason, DelegationRequest, DelegationReviewKind,
    DelegationRootOrigin, DelegationState, ProjectId, TaintClass, TaskId, WorkLeaseId,
};
use time::{Duration, OffsetDateTime};

fn request(origin: DelegationOrigin, question: &str) -> DelegationRequest {
    DelegationRequest {
        delegation_id: format!("delegation:{}", WorkLeaseId::new_v7()),
        project_id: ProjectId::new_v7(),
        task_id: TaskId::new_v7(),
        origin,
        origin_chain: DelegationOriginChain {
            root_origin: match origin {
                DelegationOrigin::UserDirected => DelegationRootOrigin::User,
                DelegationOrigin::CodexRequested => DelegationRootOrigin::Codex,
                DelegationOrigin::PolicyShadow => DelegationRootOrigin::GovernorShadow,
            },
            provider_chain: Vec::new(),
            delegation_depth: 0,
            parent_delegation_id: None,
        },
        review_kind: DelegationReviewKind::RiskReview,
        question: question.to_owned(),
        work_lease_id: WorkLeaseId::new_v7(),
        evidence_refs: Vec::new(),
        preferred_provider: DelegationProviderPreference::Auto,
        created_at: OffsetDateTime::now_utc(),
    }
}

#[test]
fn delegation_user_directed_executes_unless_hard_denied() {
    let decision = DelegationPolicyService.decide(
        &request(DelegationOrigin::UserDirected, "second opinion"),
        &DelegationPolicyContext::default(),
    );
    assert_eq!(decision.kind, DelegationDecisionKind::Execute);
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::ExplicitUserRequest]
    );
}

#[test]
fn delegation_user_directed_returns_concrete_denial() {
    let decision = DelegationPolicyService.decide(
        &request(DelegationOrigin::UserDirected, "second opinion"),
        &DelegationPolicyContext {
            provider_available: false,
            ..DelegationPolicyContext::default()
        },
    );
    assert_eq!(decision.kind, DelegationDecisionKind::Deny);
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::ProviderUnavailable]
    );
}

#[test]
fn delegation_codex_requested_requires_strong_trigger() {
    let decision = DelegationPolicyService.decide(
        &request(
            DelegationOrigin::CodexRequested,
            "rename one local variable",
        ),
        &DelegationPolicyContext::default(),
    );
    assert_eq!(decision.kind, DelegationDecisionKind::NoExternalReview);
}

#[test]
fn delegation_codex_requested_security_boundary_executes() {
    let decision = DelegationPolicyService.decide(
        &request(
            DelegationOrigin::CodexRequested,
            "review the security authority boundary",
        ),
        &DelegationPolicyContext::default(),
    );
    assert_eq!(decision.kind, DelegationDecisionKind::Execute);
    assert!(
        decision
            .reasons
            .contains(&DelegationReason::SecurityBoundary)
    );
}

#[test]
fn delegation_codex_requested_external_integration_executes() {
    let decision = DelegationPolicyService.decide(
        &request(
            DelegationOrigin::CodexRequested,
            "audit this MCP plugin integration",
        ),
        &DelegationPolicyContext::default(),
    );
    assert_eq!(decision.kind, DelegationDecisionKind::Execute);
    assert!(
        decision
            .reasons
            .contains(&DelegationReason::ExternalIntegration)
    );
}

#[test]
fn delegation_codex_requested_repeated_failure_executes() {
    let decision = DelegationPolicyService.decide(
        &request(
            DelegationOrigin::CodexRequested,
            "the same approach failed twice",
        ),
        &DelegationPolicyContext::default(),
    );
    assert_eq!(decision.kind, DelegationDecisionKind::Execute);
    assert!(
        decision
            .reasons
            .contains(&DelegationReason::RepeatedFailure)
    );
}

#[test]
fn delegation_trivial_task_does_not_execute() {
    let decision = DelegationPolicyService.decide(
        &request(DelegationOrigin::CodexRequested, "format this file"),
        &DelegationPolicyContext::default(),
    );
    assert_eq!(decision.kind, DelegationDecisionKind::NoExternalReview);
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::TrivialDeterministicTask]
    );
}

#[test]
fn delegation_duplicate_fresh_review_does_not_execute() {
    let decision = DelegationPolicyService.decide(
        &request(
            DelegationOrigin::CodexRequested,
            "audit this security boundary",
        ),
        &DelegationPolicyContext {
            duplicate_fresh_review: true,
            ..DelegationPolicyContext::default()
        },
    );
    assert_eq!(decision.kind, DelegationDecisionKind::Deny);
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::FreshEquivalentReview]
    );
}

#[test]
fn delegation_policy_shadow_never_executes() {
    let decision = DelegationPolicyService.decide(
        &request(
            DelegationOrigin::PolicyShadow,
            "audit this security integration",
        ),
        &DelegationPolicyContext::default(),
    );
    assert_eq!(decision.kind, DelegationDecisionKind::ShadowRecommend);
    assert!(decision.provider_id.is_none());
}

#[test]
fn delegation_recursive_antigravity_call_denied() {
    let mut input = request(DelegationOrigin::UserDirected, "review boundary");
    input
        .origin_chain
        .provider_chain
        .push("antigravity".to_owned());
    let decision = DelegationPolicyService.decide(&input, &DelegationPolicyContext::default());
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::RecursiveProviderCall]
    );
}

#[test]
fn delegation_depth_above_one_denied() {
    let mut input = request(DelegationOrigin::UserDirected, "review boundary");
    input.origin_chain.delegation_depth = 2;
    let decision = DelegationPolicyService.decide(&input, &DelegationPolicyContext::default());
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::RecursiveProviderCall]
    );
}

#[test]
fn delegation_budget_user_limit_enforced() {
    let task_id = TaskId::new_v7();
    let mut budget = DelegationBudgetService.for_task(task_id);
    budget.cooldown_seconds = 0;
    let now = OffsetDateTime::now_utc();
    assert_eq!(
        DelegationBudgetService.reserve(&mut budget, DelegationOrigin::UserDirected, now),
        DelegationBudgetReservation::Reserved
    );
    assert_eq!(
        DelegationBudgetService.reserve(&mut budget, DelegationOrigin::UserDirected, now),
        DelegationBudgetReservation::Reserved
    );
    assert_eq!(
        DelegationBudgetService.reserve(&mut budget, DelegationOrigin::UserDirected, now),
        DelegationBudgetReservation::BudgetExceeded
    );
}

#[test]
fn delegation_budget_codex_limit_enforced() {
    let mut budget = DelegationBudgetService.for_task(TaskId::new_v7());
    budget.cooldown_seconds = 0;
    let now = OffsetDateTime::now_utc();
    assert_eq!(
        DelegationBudgetService.reserve(&mut budget, DelegationOrigin::CodexRequested, now),
        DelegationBudgetReservation::Reserved
    );
    assert_eq!(
        DelegationBudgetService.reserve(&mut budget, DelegationOrigin::CodexRequested, now),
        DelegationBudgetReservation::BudgetExceeded
    );
}

#[test]
fn delegation_cooldown_enforced() {
    let mut budget = DelegationBudgetService.for_task(TaskId::new_v7());
    let now = OffsetDateTime::now_utc();
    assert_eq!(
        DelegationBudgetService.reserve(&mut budget, DelegationOrigin::UserDirected, now),
        DelegationBudgetReservation::Reserved
    );
    assert_eq!(
        DelegationBudgetService.reserve(
            &mut budget,
            DelegationOrigin::UserDirected,
            now + Duration::seconds(1)
        ),
        DelegationBudgetReservation::CooldownActive
    );
}

#[test]
fn delegation_transient_retry_once() {
    let mut budget = DelegationBudgetService.for_task(TaskId::new_v7());
    assert!(DelegationBudgetService.reserve_transient_retry(&mut budget));
    assert!(!DelegationBudgetService.reserve_transient_retry(&mut budget));
}

#[test]
fn delegation_low_quality_response_not_retried() {
    let budget = DelegationBudgetService.for_task(TaskId::new_v7());
    assert_eq!(budget.transient_retries_used, 0);
}

#[test]
fn delegation_requires_cli_1_1_1() {
    let decision = DelegationPolicyService.decide(
        &request(DelegationOrigin::UserDirected, "review"),
        &DelegationPolicyContext {
            provider_version_supported: false,
            ..DelegationPolicyContext::default()
        },
    );
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::ProviderVersionBelow1_1_1]
    );
}

#[test]
fn delegation_requires_active_worklease() {
    let decision = DelegationPolicyService.decide(
        &request(DelegationOrigin::UserDirected, "review"),
        &DelegationPolicyContext {
            active_work_lease: false,
            ..DelegationPolicyContext::default()
        },
    );
    assert_eq!(decision.reasons, vec![DelegationReason::MissingWorkLease]);
}

#[test]
fn delegation_creates_child_disposable_worktree() {
    let source = include_str!("../src/antigravity.rs");
    assert!(source.contains("create_disposable_worktree"));
    assert!(source.contains("disposable worktree root must be outside the controller tree"));
}

#[test]
fn delegation_real_agy_cwd_equals_worktree_path() {
    let source = include_str!("../../eliot-app/src/delegation_runtime.rs");
    assert!(
        source.contains("cwd_equals_worktree_path: run.effective_cwd == worktree.worktree_path")
    );
}

#[test]
fn delegation_cleans_worktree_after_completion() {
    let source = include_str!("../../eliot-app/src/delegation_runtime.rs");
    assert!(source.contains("capture_cleanup_and_compare"));
    assert!(source.contains("cleanup_failed_worktree"));
}

#[test]
fn delegation_runner_timeout_exceeds_cli_print_timeout() {
    let source = include_str!("../src/antigravity.rs");
    assert!(source.contains("DEFAULT_TIMEOUT_MS: u64 = 310_000"));
    assert!(source.contains("--print-timeout=300s"));
}

#[test]
fn delegation_windows_result_path_is_encoded() {
    let source = include_str!("../../eliot-app/src/delegation_runtime.rs");
    assert!(source.contains("fn delegation_result_dir"));
    assert!(source.contains("character.is_ascii_alphanumeric()"));
    assert!(!source.contains(".join(&request.delegation_id)"));
}

#[test]
fn delegation_completed_transcript_recovery_is_bounded() {
    let source = include_str!("../../eliot-app/src/delegation_runtime.rs");
    assert!(source.contains("official CLI conversation mapping"));
    assert!(source.contains("raw_provider_output_exposed\": false"));
    assert!(source.contains("provider session closed after official CLI transcript recovery"));
}

#[test]
fn delegation_result_candidate_only_tainted() {
    let request = antigravity_review_request(
        "project",
        "task",
        AntigravityReviewMode::AuditPlan,
        "review",
    );
    let result = AntigravityTextOutputNormalizer
        .normalize_text(&request, "Finding: recursion must be denied");
    assert!(result.candidate_only);
    assert_eq!(result.taint, TaintClass::ExternalAgent);
}

#[test]
fn delegation_result_excluded_from_normal_l3() {
    let request = antigravity_review_request(
        "project",
        "task",
        AntigravityReviewMode::AuditPlan,
        "review",
    );
    let result =
        AntigravityTextOutputNormalizer.normalize_text(&request, "Finding: keep candidate only");
    assert!(!AntigravityTextOutputNormalizer.included_in_normal_l3(&result));
}

#[test]
fn delegation_outcome_requires_controller_or_verifier_acceptance() {
    let outcome = DelegationOutcomeService.record(
        "delegation",
        Some("result".to_owned()),
        1,
        1,
        0,
        0,
        Vec::new(),
        false,
        1,
        1,
        false,
    );
    assert_eq!(outcome.accepted_findings, 0);
    let verified = DelegationOutcomeService.record(
        "delegation",
        Some("result".to_owned()),
        1,
        1,
        0,
        0,
        vec!["cargo-test".to_owned()],
        false,
        1,
        1,
        false,
    );
    assert_eq!(verified.accepted_findings, 1);
}

#[test]
fn delegation_unknown_monetary_cost_not_fabricated() {
    let outcome = DelegationOutcomeService.record(
        "delegation",
        None,
        0,
        0,
        0,
        0,
        Vec::new(),
        false,
        0,
        1,
        false,
    );
    assert!(!outcome.monetary_cost_known);
}

#[test]
fn delegation_metrics_have_low_cardinality() {
    let metrics = MetricRegistryService.definitions();
    let delegation = metrics
        .iter()
        .filter(|metric| metric.component == "delegation")
        .collect::<Vec<_>>();
    assert_eq!(delegation.len(), 16);
    assert!(
        delegation
            .iter()
            .flat_map(|metric| &metric.labels)
            .all(|label| !label.high_cardinality && !label.secret_risk)
    );
}

#[test]
fn delegation_codex_profile_exposes_four_tools() {
    let source = include_str!("../../eliot-app/src/mcp_stdio.rs");
    for tool in [
        "eliot_delegate_review",
        "eliot_delegate_status",
        "eliot_delegate_result",
        "eliot_delegate_report",
    ] {
        assert!(source.contains(tool));
    }
}

#[test]
fn delegation_antigravity_profile_hides_execution_tools() {
    let source = include_str!("../../eliot-app/src/mcp_stdio.rs");
    let auditor = source
        .split("const ANTIGRAVITY_AUDITOR_TOOLS")
        .nth(1)
        .unwrap_or_default()
        .split("];")
        .next()
        .unwrap_or_default();
    assert!(!auditor.contains("eliot_delegate_review"));
    assert!(!auditor.contains("eliot_delegate_status"));
    assert!(!auditor.contains("eliot_delegate_result"));
    assert!(!auditor.contains("eliot_delegate_report"));
}

#[test]
fn delegation_no_raw_provider_surface() {
    let source = include_str!("../../eliot-app/src/delegation_runtime.rs");
    assert!(!source.contains("raw_argv"));
    assert!(!source.contains("run_gemini"));
    assert_eq!(source.matches("AntigravityRunner.run_real").count(), 1);
}

#[test]
fn delegation_live_tree_violation_zero() {
    let report = DelegationReportService.summary(&DelegationState::default());
    assert_eq!(report["live_tree_violation_total"], 0);
}

#[test]
fn delegation_authority_violation_zero() {
    let report = DelegationReportService.summary(&DelegationState::default());
    assert_eq!(report["authority_violation_total"], 0);
    assert_eq!(report["recursive_execution_total"], 0);
}

#[test]
fn delegation_hard_denial_order_is_deterministic() {
    let mut input = request(DelegationOrigin::UserDirected, "review secret credential");
    input
        .origin_chain
        .provider_chain
        .push("antigravity".to_owned());
    let decision = DelegationPolicyService.decide(
        &input,
        &DelegationPolicyContext {
            incident_lockdown: true,
            forbidden_data_exposure: true,
            provider_available: false,
            provider_healthy: false,
            provider_version_supported: false,
            plugin_and_mcp_verified: false,
            active_work_lease: false,
            budget_available: false,
            cooldown_active: true,
            duplicate_fresh_review: true,
        },
    );
    assert_eq!(
        decision.reasons,
        vec![DelegationReason::RecursiveProviderCall]
    );
}
