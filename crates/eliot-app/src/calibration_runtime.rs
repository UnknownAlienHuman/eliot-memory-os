use anyhow::{Context, Result, bail};
use eliot_engine::{
    CalibrationEvidenceGapService, CampaignIntegrityReconciliationService,
    DelegationCalibrationCampaignService, DelegationCalibrationDoctorIntegration,
    DelegationCalibrationIngestService, DelegationCalibrationRollupService,
    DelegationCounterfactualService, DelegationPolicyCandidateService,
    DelegationPromotionGateService, DelegationShadowEvaluationService,
    IndependentOutcomeEvidenceService, ProviderUtilityAssessmentService,
};
use eliot_types::{
    AntigravityNormalizedResult, CalibrationCompleteness, CalibrationCorpusSampleKind,
    CalibrationEvidenceClass, CalibrationIntegrityStatus, CampaignIntegrityIncidentStatus,
    CampaignIntegrityRootCauseStatus, DelegationCalibrationCampaign,
    DelegationCalibrationCampaignBudget, DelegationCalibrationCampaignCloseoutStatus,
    DelegationCalibrationCampaignState, DelegationCalibrationConfig, DelegationCalibrationCosts,
    DelegationCalibrationLabels, DelegationCalibrationSample, DelegationCalibrationState,
    DelegationCalibrationTaskFamily, DelegationDecisionKind, DelegationEvidenceFloorSnapshot,
    DelegationOutcomeStatus, DelegationPolicyPromotionDecisionKind,
    DelegationPromotionReadinessVerdict, DelegationReviewKind, ExecutedProviderReview,
    ExecutedProviderReviewStatus, IndependentOutcomeEvidence, ProjectId, TaskId, WorkLeaseId,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use time::OffsetDateTime;

pub const CALIBRATION_TOOL_NAMES: [&str; 4] = [
    "eliot_delegation_calibration_status",
    "eliot_delegation_calibration_report",
    "eliot_delegation_policy_candidate",
    "eliot_delegation_promotion_status",
];

#[derive(Clone, Debug)]
pub struct CampaignPreviewInput {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub task_family: DelegationCalibrationTaskFamily,
    pub selection_rule: String,
    pub provider_route: String,
    pub policy_snapshot_id: String,
    pub max_provider_calls: u32,
    pub max_cost_if_known: Option<f64>,
    pub max_wall_time_seconds: u64,
    pub frozen_input_refs: Vec<String>,
}

pub fn load_state(root: &Path) -> Result<DelegationCalibrationState> {
    read_or_default(&state_path(root))
}

pub fn campaign_preview(
    root: &Path,
    config: &DelegationCalibrationConfig,
    input: CampaignPreviewInput,
) -> Result<Value> {
    if input.max_provider_calls == 0 {
        bail!("campaign budget must allow at least one explicit provider call");
    }
    if input.frozen_input_refs.is_empty() {
        bail!("campaign requires at least one frozen input reference");
    }
    if input.selection_rule.trim().is_empty() || input.policy_snapshot_id.trim().is_empty() {
        bail!("campaign selection rule and policy snapshot are required");
    }
    let project_root = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dirty = git_output(project_root, &["status", "--porcelain=v1"])?;
    if !dirty.trim().is_empty() {
        bail!("campaign baseline freeze requires a clean Git tree");
    }
    let baseline_commit = git_output(project_root, &["rev-parse", "HEAD"])?;
    let baseline_state_hash = baseline_hash(
        baseline_commit.trim(),
        &input.policy_snapshot_id,
        &input.frozen_input_refs,
    );
    let mut state = load_state(root)?;
    if let Some(existing) = state.campaigns.iter().find(|campaign| {
        campaign.baseline_state_hash == baseline_state_hash
            && campaign.selected_task_ids == [input.task_id]
            && campaign.task_family == input.task_family
            && !DelegationCalibrationCampaignService::is_terminal(campaign.state)
    }) {
        return Ok(json!({
            "component":"delegation_calibration_campaign_preview",
            "created":false,
            "campaign":existing,
            "provider_process_started":false
        }));
    }
    let mut campaign = DelegationCalibrationCampaign {
        campaign_id: format!("delegation-campaign:{}", WorkLeaseId::new_v7()),
        project_id: input.project_id,
        schema_version: "1".to_owned(),
        created_at: OffsetDateTime::now_utc(),
        closed_at: None,
        baseline_commit: baseline_commit.trim().to_owned(),
        policy_snapshot_id: input.policy_snapshot_id,
        provider_route: input.provider_route,
        task_family: input.task_family,
        selection_rule: input.selection_rule,
        budget: DelegationCalibrationCampaignBudget {
            max_provider_calls: input.max_provider_calls,
            max_cost_if_known: input.max_cost_if_known,
            max_wall_time_seconds: input.max_wall_time_seconds,
        },
        evidence_floor_snapshot: evidence_floor_snapshot(config),
        selected_task_ids: vec![input.task_id],
        frozen_input_refs: input.frozen_input_refs,
        baseline_state_hash,
        observed_provider_calls: 0,
        integrity_violations: Vec::new(),
        executed_review_ids: Vec::new(),
        independent_evidence_ids: Vec::new(),
        shadow_evaluation_ids: Vec::new(),
        state: DelegationCalibrationCampaignState::Draft,
        closeout_status: DelegationCalibrationCampaignCloseoutStatus::Open,
        transition_history: Vec::new(),
    };
    DelegationCalibrationCampaignService
        .transition(&mut campaign, DelegationCalibrationCampaignState::Ready)
        .map_err(anyhow::Error::msg)?;
    state.campaigns.push(campaign.clone());
    save(root, &state)?;
    write_pair(root, "delegation-calibration-campaign", &campaign)?;
    Ok(json!({
        "component":"delegation_calibration_campaign_preview",
        "created":true,
        "campaign":campaign,
        "provider_process_started":false
    }))
}

#[allow(clippy::too_many_lines)]
pub fn campaign_bind_review(root: &Path, campaign_id: &str, delegation_id: &str) -> Result<Value> {
    let delegation = crate::delegation_runtime::load_state(root)?;
    let request = delegation
        .requests
        .iter()
        .find(|request| request.delegation_id == delegation_id)
        .context("delegation request is unavailable")?
        .clone();
    let decision = delegation
        .decisions
        .iter()
        .find(|decision| decision.delegation_id == delegation_id)
        .context("delegation gate decision is unavailable")?
        .clone();
    let outcome = delegation
        .outcomes
        .iter()
        .find(|outcome| outcome.delegation_id == delegation_id)
        .context("delegation outcome is unavailable")?
        .clone();
    let mut state = load_state(root)?;
    let review_id = format!("executed-review:{}", safe_segment(delegation_id));
    if let Some(existing) = state
        .executed_reviews
        .iter()
        .find(|review| review.review_id == review_id)
    {
        return Ok(json!({
            "component":"delegation_calibration_campaign_bind",
            "bound":false,
            "campaign_id":campaign_id,
            "review":existing,
            "idempotent_replay":true
        }));
    }
    let campaign = state
        .campaigns
        .iter_mut()
        .find(|campaign| campaign.campaign_id == campaign_id)
        .context("calibration campaign is unavailable")?;
    if !campaign.selected_task_ids.contains(&request.task_id) {
        bail!("delegation task is outside the selected campaign scope");
    }
    if campaign.state == DelegationCalibrationCampaignState::Ready {
        DelegationCalibrationCampaignService
            .transition(
                campaign,
                DelegationCalibrationCampaignState::ProviderExecuting,
            )
            .map_err(anyhow::Error::msg)?;
    } else if campaign.state == DelegationCalibrationCampaignState::ProviderExecuted {
        DelegationCalibrationCampaignService
            .transition(
                campaign,
                DelegationCalibrationCampaignState::AwaitingIndependentEvidence,
            )
            .map_err(anyhow::Error::msg)?;
    } else if campaign.state != DelegationCalibrationCampaignState::AwaitingIndependentEvidence {
        bail!(
            "campaign cannot bind recovered review from state {:?}",
            campaign.state
        );
    }
    if decision.kind != DelegationDecisionKind::Execute || outcome.provider_call_count == 0 {
        let blocked = if decision
            .reasons
            .contains(&eliot_types::DelegationReason::BudgetExceeded)
        {
            DelegationCalibrationCampaignState::BlockedQuota
        } else if decision
            .reasons
            .contains(&eliot_types::DelegationReason::ProviderUnavailable)
        {
            DelegationCalibrationCampaignState::BlockedProviderUnavailable
        } else {
            DelegationCalibrationCampaignState::GateDenied
        };
        DelegationCalibrationCampaignService
            .transition(campaign, blocked)
            .map_err(anyhow::Error::msg)?;
        campaign.closeout_status =
            DelegationCalibrationCampaignCloseoutStatus::BlockedExternalDependency;
        let campaign_report = campaign.clone();
        save(root, &state)?;
        write_pair(root, "delegation-calibration-campaign", &campaign_report)?;
        return Ok(json!({
            "component":"delegation_calibration_campaign_bind",
            "bound":false,
            "campaign_state":blocked,
            "gate_decision":decision,
            "provider_process_started":false
        }));
    }
    save(root, &state)?;
    ingest(root)?;
    let mut state = load_state(root)?;
    let campaign = state
        .campaigns
        .iter()
        .find(|campaign| campaign.campaign_id == campaign_id)
        .context("calibration campaign disappeared after ingest")?
        .clone();
    let execution = read_value(&root.join("reports/delegation-execution/latest.json"))?
        .context("delegation execution receipt is unavailable")?;
    if execution.get("delegation_id").and_then(Value::as_str) != Some(delegation_id) {
        bail!("latest delegation execution receipt does not match requested review");
    }
    let normalized_path = root
        .join("reports/delegation-results")
        .join(safe_segment(delegation_id))
        .join("latest.json");
    let normalized: AntigravityNormalizedResult =
        serde_json::from_reader(std::fs::File::open(&normalized_path)?)?;
    let external = normalized
        .external_review_result
        .as_ref()
        .context("provider output has no normalized external review result")?;
    let candidate_only = normalized.candidate_only
        && external.candidate_only
        && execution
            .get("candidate_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let review = ExecutedProviderReview {
        review_id: review_id.clone(),
        campaign_id: campaign_id.to_owned(),
        real_task_id: request.task_id,
        provider: decision
            .provider_id
            .clone()
            .unwrap_or_else(|| "antigravity".to_owned()),
        model_route_if_known: None,
        request_ref: request.delegation_id.clone(),
        frozen_input_refs: campaign.frozen_input_refs.clone(),
        baseline_state_hash: campaign.baseline_state_hash.clone(),
        provider_gate_decision_ref: decision.decision_id.clone(),
        quota_or_cost_receipt: format!(
            "reports/delegation-budgets/latest.json#{};provider_calls={}",
            decision.budget_id.as_deref().unwrap_or("unknown"),
            outcome.provider_call_count
        ),
        started_at: request.created_at,
        completed_at: Some(outcome.created_at),
        status: if outcome.status == DelegationOutcomeStatus::ProviderFailed {
            ExecutedProviderReviewStatus::Failed
        } else {
            ExecutedProviderReviewStatus::Succeeded
        },
        raw_output_ref: "reports/delegation-provider-run/latest.json".to_owned(),
        normalized_findings: external
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect(),
        proposed_changes: external
            .proposed_changes
            .iter()
            .map(|change| change.change_id.clone())
            .collect(),
        candidate_only,
        trace_ref: execution
            .get("g2_external_review_job_ref")
            .and_then(Value::as_str)
            .unwrap_or("missing-trace")
            .to_owned(),
    };
    let inserted = DelegationCalibrationCampaignService
        .ingest_review(&mut state, review.clone())
        .map_err(anyhow::Error::msg)?;
    let task_delegation_ids = delegation
        .requests
        .iter()
        .filter(|item| item.task_id == request.task_id)
        .map(|item| item.delegation_id.as_str())
        .collect::<Vec<_>>();
    let observed_provider_calls = delegation
        .outcomes
        .iter()
        .filter(|item| task_delegation_ids.contains(&item.delegation_id.as_str()))
        .map(|item| item.provider_call_count)
        .sum::<u32>();
    let campaign = state
        .campaigns
        .iter_mut()
        .find(|campaign| campaign.campaign_id == campaign_id)
        .context("campaign disappeared while binding review")?;
    campaign.observed_provider_calls = observed_provider_calls;
    if observed_provider_calls > campaign.budget.max_provider_calls {
        let violation = format!(
            "provider_call_budget_exceeded:{observed_provider_calls}>{}",
            campaign.budget.max_provider_calls
        );
        if !campaign.integrity_violations.contains(&violation) {
            campaign.integrity_violations.push(violation);
        }
    }
    if campaign.state == DelegationCalibrationCampaignState::ProviderExecuting {
        DelegationCalibrationCampaignService
            .transition(
                campaign,
                DelegationCalibrationCampaignState::ProviderExecuted,
            )
            .map_err(anyhow::Error::msg)?;
        DelegationCalibrationCampaignService
            .transition(
                campaign,
                DelegationCalibrationCampaignState::AwaitingIndependentEvidence,
            )
            .map_err(anyhow::Error::msg)?;
    } else if campaign.state == DelegationCalibrationCampaignState::ProviderExecuted {
        DelegationCalibrationCampaignService
            .transition(
                campaign,
                DelegationCalibrationCampaignState::AwaitingIndependentEvidence,
            )
            .map_err(anyhow::Error::msg)?;
    }
    let campaign_report = campaign.clone();
    save(root, &state)?;
    write_pair(root, "delegation-calibration-campaign", &campaign_report)?;
    write_pair(root, "delegation-executed-review", &review)?;
    Ok(json!({
        "component":"delegation_calibration_campaign_bind",
        "bound":inserted,
        "campaign_id":campaign_id,
        "review":review,
        "provider_process_count":outcome.provider_call_count,
        "candidate_only":candidate_only
    }))
}

pub fn attach_independent_evidence(root: &Path, path: &Path) -> Result<Value> {
    let evidence: IndependentOutcomeEvidence = serde_json::from_reader(std::fs::File::open(path)?)?;
    let mut state = load_state(root)?;
    let inserted = IndependentOutcomeEvidenceService
        .attach(&mut state, evidence.clone())
        .map_err(anyhow::Error::msg)?;
    if !inserted {
        let assessment = state
            .utility_assessments
            .iter()
            .find(|assessment| assessment.review_id == evidence.review_id);
        let campaign_state = state
            .campaigns
            .iter()
            .find(|campaign| campaign.campaign_id == evidence.campaign_id)
            .map(|campaign| campaign.state);
        return Ok(json!({
            "component":"delegation_independent_evidence_attach",
            "inserted":false,
            "evidence":evidence,
            "utility_assessment":assessment,
            "campaign_state":campaign_state,
            "idempotent_replay":true
        }));
    }
    let review = state
        .executed_reviews
        .iter()
        .find(|review| review.review_id == evidence.review_id)
        .context("executed review disappeared while attaching evidence")?
        .clone();
    let family = state
        .campaigns
        .iter()
        .find(|campaign| campaign.campaign_id == evidence.campaign_id)
        .context("campaign disappeared while attaching evidence")?
        .task_family;
    let assessment =
        ProviderUtilityAssessmentService.assess(&review, family, &state.independent_evidence);
    ProviderUtilityAssessmentService.apply(&mut state, &review, &assessment);
    let campaign = state
        .campaigns
        .iter_mut()
        .find(|campaign| campaign.campaign_id == evidence.campaign_id)
        .context("campaign disappeared before attribution transition")?;
    let next = if assessment.provider_useful.is_some() {
        DelegationCalibrationCampaignState::Attributed
    } else {
        DelegationCalibrationCampaignState::Inconclusive
    };
    DelegationCalibrationCampaignService
        .transition(campaign, next)
        .map_err(anyhow::Error::msg)?;
    if next == DelegationCalibrationCampaignState::Inconclusive {
        campaign.closeout_status = DelegationCalibrationCampaignCloseoutStatus::Inconclusive;
    }
    let campaign_report = campaign.clone();
    save(root, &state)?;
    write_pair(root, "delegation-independent-evidence", &evidence)?;
    write_pair(root, "delegation-utility", &assessment)?;
    write_pair(root, "delegation-calibration-campaign", &campaign_report)?;
    Ok(json!({
        "component":"delegation_independent_evidence_attach",
        "inserted":inserted,
        "evidence":evidence,
        "utility_assessment":assessment,
        "campaign_state":next
    }))
}

pub fn campaign_closeout(
    root: &Path,
    config: &DelegationCalibrationConfig,
    campaign_id: &str,
) -> Result<Value> {
    let selected = select_campaign(&load_state(root)?, campaign_id)?.clone();
    if selected.state != DelegationCalibrationCampaignState::Attributed {
        bail!(
            "campaign closeout requires attributed state, found {:?}",
            selected.state
        );
    }
    shadow_run(root)?;
    family_report(root, config)?;
    policy_candidate(root)?;
    promotion_gate(root, config)?;
    let mut state = load_state(root)?;
    let gap = CalibrationEvidenceGapService.report(&state, config, 0);
    state.evidence_gap_report = Some(gap.clone());
    let selected_tasks = state
        .campaigns
        .iter()
        .find(|campaign| campaign.campaign_id == selected.campaign_id)
        .context("campaign disappeared during closeout")?
        .selected_task_ids
        .clone();
    let shadow_ids = state
        .shadows
        .iter()
        .filter(|shadow| selected_tasks.contains(&shadow.task_id))
        .map(|shadow| shadow.shadow_id.clone())
        .collect::<Vec<_>>();
    let campaign = state
        .campaigns
        .iter_mut()
        .find(|campaign| campaign.campaign_id == selected.campaign_id)
        .context("campaign disappeared before closeout transition")?;
    campaign.shadow_evaluation_ids = shadow_ids;
    DelegationCalibrationCampaignService
        .transition(campaign, DelegationCalibrationCampaignState::RolledUp)
        .map_err(anyhow::Error::msg)?;
    DelegationCalibrationCampaignService
        .transition(campaign, DelegationCalibrationCampaignState::Closed)
        .map_err(anyhow::Error::msg)?;
    let campaign = campaign.clone();
    save(root, &state)?;
    let assessment = state
        .utility_assessments
        .iter()
        .find(|assessment| assessment.campaign_id == campaign.campaign_id)
        .context("campaign closeout has no utility assessment")?
        .clone();
    write_pair(root, "delegation-calibration-campaign", &campaign)?;
    write_pair(root, "delegation-utility", &assessment)?;
    write_pair(root, "delegation-evidence-gap", &gap)?;
    Ok(json!({
        "component":"delegation_calibration_campaign_closeout",
        "campaign":campaign,
        "utility":assessment,
        "evidence_gap":gap,
        "promotion_decision":state.promotion_decision,
        "candidate_active":false,
        "active_policy_changed":false,
        "budgets_changed":false
    }))
}

pub fn campaign_status(root: &Path, campaign_id: &str) -> Result<Value> {
    let state = load_state(root)?;
    let campaign = select_campaign(&state, campaign_id)?;
    Ok(json!({
        "component":"delegation_calibration_campaign_status",
        "campaign":campaign,
        "executed_reviews":state.executed_reviews.iter().filter(|review| review.campaign_id == campaign.campaign_id).collect::<Vec<_>>(),
        "independent_evidence":state.independent_evidence.iter().filter(|evidence| evidence.campaign_id == campaign.campaign_id).collect::<Vec<_>>(),
        "utility_assessments":state.utility_assessments.iter().filter(|assessment| assessment.campaign_id == campaign.campaign_id).collect::<Vec<_>>(),
        "evidence_gap":state.evidence_gap_report,
        "read_only":true
    }))
}

#[allow(clippy::too_many_lines)]
pub fn ingest(root: &Path) -> Result<Value> {
    let delegation = crate::delegation_runtime::load_state(root)?;
    let execution = read_value(&root.join("reports/delegation-execution/latest.json"))?;
    let mut state = load_state(root)?;
    let outcome = delegation
        .outcomes
        .iter()
        .rev()
        .find(|outcome| outcome.provider_call_count > 0)
        .context("no real executed L0 delegation outcome is available")?;
    let request = delegation
        .requests
        .iter()
        .find(|request| request.delegation_id == outcome.delegation_id)
        .context("real L0 outcome has no request")?;
    let decision = delegation
        .decisions
        .iter()
        .rev()
        .find(|decision| decision.delegation_id == outcome.delegation_id)
        .context("real L0 outcome has no route decision")?;
    let cleanup = execution
        .as_ref()
        .and_then(|value| value.get("cleanup_state"))
        .and_then(Value::as_str)
        == Some("cleaned");
    let live_tree = execution
        .as_ref()
        .and_then(|value| value.get("live_tree_unchanged"))
        .and_then(Value::as_bool)
        == Some(true);
    let authority = u32::try_from(
        execution
            .as_ref()
            .and_then(|value| value.get("authority_violation_count"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
    .unwrap_or(u32::MAX);
    let result_present = outcome.result_ref.is_some();
    let independent = !outcome.verifier_refs.is_empty();
    let missing_refs = [
        (!result_present).then_some("provider_result"),
        (!independent).then_some("verifier_or_human_evidence"),
        (!cleanup).then_some("worktree_cleanup"),
        (!live_tree).then_some("live_tree_integrity"),
    ]
    .into_iter()
    .flatten()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let sample = DelegationCalibrationSample {
        sample_id: format!("calibration:{}", safe_segment(&outcome.delegation_id)),
        project_id: request.project_id,
        task_id: request.task_id,
        task_family: classify_family(decision.kind, request.review_kind, &decision.reasons),
        evidence_class: CalibrationEvidenceClass::RealExecutedTask,
        delegation_origin: request.origin,
        review_kind: request.review_kind,
        route_decision_ref: decision.decision_id.clone(),
        delegation_outcome_ref: Some(outcome.outcome_id.clone()),
        provider_result_ref: outcome.result_ref.clone(),
        controller_outcome_refs: vec!["reports/delegation-execution/latest.json".to_owned()],
        verifier_refs: outcome.verifier_refs.clone(),
        shadow_decision_ref: None,
        labels: DelegationCalibrationLabels {
            provider_called: true,
            provider_useful: independent
                .then_some(outcome.accepted_findings > 0 || outcome.changed_controller_decision),
            changed_controller_decision: independent.then_some(outcome.changed_controller_decision),
            unique_findings: outcome.unique_findings,
            accepted_findings: if independent {
                outcome.accepted_findings
            } else {
                0
            },
            rejected_findings: outcome.rejected_findings,
            duplicate_findings: outcome.duplicate_findings,
            authority_violations: authority,
            live_tree_violations: u32::from(!live_tree),
            ..DelegationCalibrationLabels::default()
        },
        costs: DelegationCalibrationCosts {
            provider_runtime_ms: (outcome.actual_runtime_ms > 0)
                .then_some(outcome.actual_runtime_ms),
            end_to_end_runtime_ms: None,
            reconciliation_runtime_ms: None,
            provider_call_count: outcome.provider_call_count,
            input_bytes: None,
            output_bytes: None,
            quota_signal: Some("one_existing_l0_call".to_owned()),
            monetary_cost_known: false,
            monetary_cost: None,
        },
        completeness: CalibrationCompleteness {
            route_decision_present: true,
            final_task_outcome_present: true,
            provider_result_present: result_present,
            verifier_or_human_evidence_present: independent,
            worktree_cleanup_present: cleanup,
            live_tree_integrity_present: live_tree,
            complete_for_provider_quality: result_present && independent && cleanup && live_tree,
            complete_for_routing_quality: cleanup && live_tree,
            missing_refs,
        },
        created_at: OffsetDateTime::now_utc(),
    };
    let inserted = DelegationCalibrationIngestService
        .ingest(&mut state, sample)
        .map_err(anyhow::Error::msg)?;
    save(root, &state)?;
    write_baseline(root)?;
    Ok(
        json!({"component":"delegation_calibration_ingest","inserted":inserted,"sample_count":state.samples.len(),"provider_process_started":false,"source":"existing_l0_receipts"}),
    )
}

pub fn shadow_run(root: &Path) -> Result<Value> {
    let mut state = load_state(root)?;
    let mut created = 0_u32;
    for sample in
        state.samples.clone().into_iter().filter(|sample| {
            sample.evidence_class != CalibrationEvidenceClass::DeterministicFixture
        })
    {
        if let Some(shadow_id) = state
            .shadows
            .iter()
            .find(|shadow| shadow.task_id == sample.task_id)
            .map(|shadow| shadow.shadow_id.clone())
        {
            if let Some(stored) = state
                .samples
                .iter_mut()
                .find(|stored| stored.sample_id == sample.sample_id)
            {
                stored.shadow_decision_ref = Some(shadow_id);
            }
            continue;
        }
        let observed = if sample.labels.provider_called {
            DelegationDecisionKind::Execute
        } else {
            DelegationDecisionKind::NoExternalReview
        };
        let shadow =
            DelegationShadowEvaluationService.evaluate(&sample, observed, "l1a-shadow-candidate");
        let label = DelegationCounterfactualService.label(&shadow, Vec::new());
        if let Some(stored) = state
            .samples
            .iter_mut()
            .find(|stored| stored.sample_id == sample.sample_id)
        {
            stored.shadow_decision_ref = Some(shadow.shadow_id.clone());
        }
        state.shadows.push(shadow);
        state.counterfactual_labels.push(label);
        created += 1;
    }
    save(root, &state)?;
    write_pair(
        root,
        "delegation-calibration-shadow",
        &json!({"records":state.shadows,"counterfactual_labels":state.counterfactual_labels,"provider_process_started":false}),
    )?;
    Ok(
        json!({"component":"delegation_calibration_shadow","created":created,"shadow_count":state.shadows.len(),"provider_process_started":false}),
    )
}

pub fn family_report(root: &Path, config: &DelegationCalibrationConfig) -> Result<Value> {
    let mut state = load_state(root)?;
    state.families = DelegationCalibrationRollupService.rollup(&state, config);
    save(root, &state)?;
    write_pair(root, "delegation-calibration-families", &state.families)?;
    Ok(json!({"component":"delegation_calibration_families","families":state.families}))
}

pub fn policy_candidate(root: &Path) -> Result<Value> {
    let mut state = load_state(root)?;
    let candidate = DelegationPolicyCandidateService.generate(
        &state.families,
        vec!["reports/delegation-calibration-families/latest.json".to_owned()],
    );
    state.policy_candidate = Some(candidate.clone());
    save(root, &state)?;
    write_pair(root, "delegation-policy-candidate", &candidate)?;
    Ok(
        json!({"component":"delegation_policy_candidate","candidate":candidate,"active_policy_mutated":false}),
    )
}

pub fn promotion_gate(root: &Path, config: &DelegationCalibrationConfig) -> Result<Value> {
    let mut state = load_state(root)?;
    let candidate = state
        .policy_candidate
        .clone()
        .context("policy candidate has not been generated")?;
    let decision = DelegationPromotionGateService.decide(&state, &candidate, config, 0);
    state.promotion_decision = Some(decision.clone());
    save(root, &state)?;
    write_pair(root, "delegation-promotion-gate", &decision)?;
    Ok(
        json!({"component":"delegation_promotion_gate","decision":decision,"policy_activated":false}),
    )
}

pub fn status(root: &Path) -> Result<Value> {
    let state = load_state(root)?;
    Ok(
        json!({"component":"delegation_calibration_status","sample_count":state.samples.len(),"shadow_count":state.shadows.len(),"family_count":state.families.len(),"candidate_status":state.policy_candidate.as_ref().map(|candidate| candidate.status),"promotion_decision":state.promotion_decision.as_ref().map(|decision| decision.decision),"doctor":DelegationCalibrationDoctorIntegration.report(&state)}),
    )
}

pub fn samples(root: &Path) -> Result<Value> {
    Ok(
        json!({"component":"delegation_calibration_samples","samples":load_state(root)?.samples,"raw_prompts_or_provider_output_included":false}),
    )
}
pub fn candidate_status(root: &Path) -> Result<Value> {
    Ok(
        json!({"component":"delegation_policy_candidate","candidate":load_state(root)?.policy_candidate,"read_only":true}),
    )
}
pub fn promotion_status(root: &Path) -> Result<Value> {
    Ok(
        json!({"component":"delegation_promotion_status","decision":load_state(root)?.promotion_decision,"read_only":true}),
    )
}

pub fn report(root: &Path) -> Result<Value> {
    let state = load_state(root)?;
    let metrics = metrics(&state);
    write_pair(root, "delegation-calibration-samples", &state.samples)?;
    write_pair(root, "delegation-calibration-metrics", &metrics)?;
    let report = json!({"component":"delegation_calibration_report","baseline_commit":"761f969ec46743951efbb7e2fe064baddf0452fd","state":state,"doctor":DelegationCalibrationDoctorIntegration.report(&state),"metrics":metrics,"active_l0_policy_mutated":false,"provider_process_started":false});
    write_pair(root, "delegation-calibration", &report)?;
    Ok(report)
}

/// Reconstructs the frozen L1B campaign incident without invoking a provider.
/// Historical observations remain immutable; only eligibility projections and
/// the typed containment record are derived.
pub fn integrity_reconcile(
    root: &Path,
    config: &DelegationCalibrationConfig,
    campaign_id: &str,
) -> Result<Value> {
    let mut state = load_state(root)?;
    let campaign = select_campaign(&state, campaign_id)?.clone();
    let incident = CampaignIntegrityReconciliationService
        .reconcile(&mut state, &campaign.campaign_id)
        .map_err(anyhow::Error::msg)?;
    state.evidence_gap_report = Some(CalibrationEvidenceGapService.report(&state, config, 0));
    save(root, &state)?;

    // All of these passes operate only on the persisted calibration corpus.
    family_report(root, config)?;
    policy_candidate(root)?;
    promotion_gate(root, config)?;

    let mut state = load_state(root)?;
    let gap = CalibrationEvidenceGapService.report(&state, config, 0);
    state.evidence_gap_report = Some(gap.clone());
    save(root, &state)?;
    let assessment = state
        .utility_assessments
        .iter()
        .find(|assessment| {
            assessment.campaign_id == campaign.campaign_id
                && assessment.provider_useful == Some(true)
        })
        .cloned();
    let eligibility = state
        .corpus_eligibility
        .iter()
        .filter(|item| {
            item.evidence_refs.iter().any(|reference| {
                reference == &campaign.campaign_id
                    || campaign
                        .executed_review_ids
                        .iter()
                        .any(|review_id| reference.contains(review_id))
            }) || campaign
                .executed_review_ids
                .iter()
                .any(|review_id| item.sample_ref.contains(review_id))
                || campaign.shadow_evaluation_ids.contains(&item.sample_ref)
                || state.utility_assessments.iter().any(|assessment| {
                    assessment.campaign_id == campaign.campaign_id
                        && item.sample_ref == assessment.assessment_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    write_pair(root, "delegation-integrity-incident", &incident)?;
    write_pair(root, "delegation-calibration-campaign", &campaign)?;
    if let Some(assessment) = &assessment {
        write_pair(root, "delegation-utility", assessment)?;
    }
    write_pair(root, "delegation-evidence-gap", &gap)?;
    write_pair(
        root,
        "delegation-calibration-eligibility",
        &json!({"campaign_id":campaign.campaign_id,"records":eligibility}),
    )?;
    Ok(json!({
        "component":"delegation_integrity_reconciliation",
        "campaign":campaign,
        "incident":incident,
        "utility":assessment,
        "evidence_gap":gap,
        "promotion_decision":state.promotion_decision,
        "candidate_active":false,
        "active_policy_changed":false,
        "active_budgets_changed":false,
        "provider_process_started":false
    }))
}

fn metrics(state: &DelegationCalibrationState) -> Value {
    json!({"component":"delegation_calibration_metrics","metrics":[
        {"name":"delegation_calibration_samples_total","labels":["evidence_class","task_family"],"value":state.samples.len()},
        {"name":"delegation_calibration_complete_samples_total","labels":["quality_scope"],"value":state.samples.iter().filter(|s| s.completeness.complete_for_routing_quality).count()},
        {"name":"delegation_calibration_shadow_total","labels":["decision"],"value":state.shadows.len()},
        {"name":"delegation_calibration_counterfactual_total","labels":["label"],"value":state.counterfactual_labels.len()},
        {"name":"delegation_calibration_findings_total","labels":["classification"],"value":state.samples.iter().map(|s| u64::from(s.labels.unique_findings)).sum::<u64>()},
        {"name":"delegation_calibration_outcomes_total","labels":["status"],"value":state.samples.len()},
        {"name":"delegation_calibration_readiness","labels":["task_family","readiness"],"value":state.families.len()},
        {"name":"delegation_calibration_candidate_status","labels":["status"],"value":usize::from(state.policy_candidate.is_some())},
        {"name":"delegation_calibration_promotion_status","labels":["decision"],"value":usize::from(state.promotion_decision.is_some())}
    ],"forbidden_high_cardinality_labels_present":false})
}

pub(crate) fn save(root: &Path, state: &DelegationCalibrationState) -> Result<()> {
    write_pair(root, "delegation-calibration-state", state)
}
fn state_path(root: &Path) -> PathBuf {
    root.join("reports/delegation-calibration-state/latest.json")
}
fn write_baseline(root: &Path) -> Result<()> {
    write_pair(
        root,
        "delegation-calibration-baseline",
        &json!({"phase":"L0","commit":"761f969ec46743951efbb7e2fe064baddf0452fd","working_tree_was_clean":true}),
    )
}
pub(crate) fn write_pair<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<()> {
    let dir = root.join("reports").join(name);
    std::fs::create_dir_all(&dir)?;
    let text = serde_json::to_string_pretty(value)?;
    std::fs::write(dir.join("latest.json"), &text)?;
    std::fs::write(
        dir.join("latest.md"),
        format!("# Eliot Delegation Calibration\n\n```json\n{text}\n```\n"),
    )?;
    Ok(())
}
fn read_or_default<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if path.is_file() {
        Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
    } else {
        Ok(T::default())
    }
}
fn read_value(path: &Path) -> Result<Option<Value>> {
    if path.is_file() {
        Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
    } else {
        Ok(None)
    }
}
fn classify_family(
    _decision: DelegationDecisionKind,
    kind: DelegationReviewKind,
    reasons: &[eliot_types::DelegationReason],
) -> DelegationCalibrationTaskFamily {
    if reasons.contains(&eliot_types::DelegationReason::ExternalIntegration) {
        DelegationCalibrationTaskFamily::ExternalIntegration
    } else {
        match kind {
            DelegationReviewKind::ArchitectureAudit => {
                DelegationCalibrationTaskFamily::ArchitectureDesign
            }
            DelegationReviewKind::DiffAudit => DelegationCalibrationTaskFamily::BroadDiffReview,
            DelegationReviewKind::VerifierAdvice => DelegationCalibrationTaskFamily::VerifierDesign,
            DelegationReviewKind::RiskReview => DelegationCalibrationTaskFamily::SecurityBoundary,
        }
    }
}
fn safe_segment(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}
fn select_campaign<'a>(
    state: &'a DelegationCalibrationState,
    campaign_id: &str,
) -> Result<&'a DelegationCalibrationCampaign> {
    if campaign_id == "latest" {
        state
            .campaigns
            .last()
            .context("no delegation calibration campaign exists")
    } else {
        state
            .campaigns
            .iter()
            .find(|campaign| campaign.campaign_id == campaign_id)
            .context("delegation calibration campaign does not exist")
    }
}

pub(crate) fn evidence_floor_snapshot(
    config: &DelegationCalibrationConfig,
) -> DelegationEvidenceFloorSnapshot {
    DelegationEvidenceFloorSnapshot {
        minimum_real_tasks_total: config.minimum_real_tasks_total,
        minimum_real_tasks_per_family: config.minimum_real_tasks_per_family,
        minimum_executed_reviews_total: config.minimum_executed_reviews_total,
        minimum_executed_reviews_per_candidate_family: config
            .minimum_executed_reviews_per_candidate_family,
        minimum_complete_outcome_fraction: config.minimum_complete_outcome_fraction,
        minimum_shadow_tasks_total: config.minimum_shadow_tasks_total,
    }
}

fn git_output(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn baseline_hash(commit: &str, policy_snapshot: &str, frozen_refs: &[String]) -> String {
    let canonical = format!("{commit}\n{policy_snapshot}\n{}", frozen_refs.join("\n"));
    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

#[allow(dead_code)]
fn parse_ids(project: &str, task: &str) -> Result<(ProjectId, TaskId)> {
    Ok((ProjectId::from_str(project)?, TaskId::from_str(task)?))
}
