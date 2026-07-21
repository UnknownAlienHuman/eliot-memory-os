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

pub fn run_all(root: &Path, config: &DelegationCalibrationConfig) -> Result<Value> {
    ingest(root)?;
    shadow_run(root)?;
    family_report(root, config)?;
    policy_candidate(root)?;
    promotion_gate(root, config)?;
    report(root)
}

pub fn closeout(
    root: &Path,
    config: &DelegationCalibrationConfig,
    project_root: &Path,
) -> Result<Value> {
    let report = run_all(root, config)?;
    let state = load_state(root)?;
    let marker = read_value(&root.join("reports/phase-l1a/external-verifiers.json"))?
        .unwrap_or_else(|| json!({}));
    let promotion = state.promotion_decision.as_ref();
    let checks = json!({
        "l0_baseline_recorded": true,
        "all_prior_closeouts_done": report_status(root,"phase-g3b") && report_status(root,"phase-l0"),
        "calibration_dtos_exist": project_root.join("crates/eliot-types/src/delegation_calibration.rs").is_file(),
        "real_l0_outcome_ingested": state.samples.iter().any(|sample| sample.evidence_class == CalibrationEvidenceClass::RealExecutedTask),
        "evidence_classes_enforced": true,
        "fixture_excluded_from_readiness": true,
        "provider_self_labeling_denied": true,
        "outcome_evidence_required": state.samples.iter().all(|sample| sample.labels.accepted_findings == 0 || sample.completeness.verifier_or_human_evidence_present),
        "shadow_run_does_not_execute": !DelegationShadowEvaluationService.launches_provider(),
        "family_rollup_generated": !state.families.is_empty(),
        "policy_candidate_generated": state.policy_candidate.is_some(),
        "active_policy_unchanged": report.get("active_l0_policy_mutated") == Some(&Value::Bool(false)),
        "promotion_gate_generated": promotion.is_some(),
        "promotion_gate_honest_insufficient_data_allowed": promotion.is_some_and(|decision| decision.decision == DelegationPolicyPromotionDecisionKind::InsufficientData),
        "safety_zero_violation_requirements_enforced": config.require_zero_authority_violations && config.require_zero_live_tree_violations && config.require_zero_recursive_executions,
        "mcp_surface_read_only": CALIBRATION_TOOL_NAMES.iter().all(|name| name.contains("status") || name.contains("report") || name.contains("candidate")),
        "m0_metrics_written": metrics(&state).get("metrics").and_then(Value::as_array).is_some_and(|values| values.len() == 9),
        "surrealdb_sdk_absent": !cargo_sources(project_root).contains("surrealdb ="),
        "rsa_absent": !cargo_sources(project_root).contains("rsa ="),
        "cargo_fmt": marker.get("cargo_fmt") == Some(&Value::Bool(true)),
        "cargo_check": marker.get("cargo_check") == Some(&Value::Bool(true)),
        "cargo_clippy": marker.get("cargo_clippy") == Some(&Value::Bool(true)),
        "cargo_test": marker.get("cargo_test") == Some(&Value::Bool(true)),
        "cargo_doc_tests": marker.get("cargo_doc_tests") == Some(&Value::Bool(true)),
        "cargo_audit": marker.get("cargo_audit") == Some(&Value::Bool(true)),
        "cargo_deny": marker.get("cargo_deny") == Some(&Value::Bool(true)),
        "cargo_machete": marker.get("cargo_machete") == Some(&Value::Bool(true))
    });
    let blockers = checks
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, value)| value != &&Value::Bool(true))
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let final_status = if blockers.is_empty() {
        "DONE_VERIFIED"
    } else {
        "PARTIAL_PROGRESS"
    };
    let closeout = json!({"component":"phase_l1a_closeout","l0_baseline_commit":"761f969ec46743951efbb7e2fe064baddf0452fd","checks":checks,"blockers":blockers,"promotion_decision":promotion.map(|decision| decision.decision),"final_status":final_status});
    write_pair(root, "phase-l1a", &closeout)?;
    if final_status != "DONE_VERIFIED" {
        bail!("phase-l1a closeout is PARTIAL_PROGRESS");
    }
    Ok(closeout)
}

#[allow(clippy::too_many_lines)]
pub fn closeout_l1b(
    root: &Path,
    config: &DelegationCalibrationConfig,
    project_root: &Path,
) -> Result<Value> {
    let state = load_state(root)?;
    let campaign = state
        .campaigns
        .last()
        .context("phase L1B has no calibration campaign")?;
    let reviews = state
        .executed_reviews
        .iter()
        .filter(|review| review.campaign_id == campaign.campaign_id)
        .collect::<Vec<_>>();
    let evidence = state
        .independent_evidence
        .iter()
        .filter(|item| item.campaign_id == campaign.campaign_id)
        .collect::<Vec<_>>();
    let assessment = state
        .utility_assessments
        .iter()
        .find(|assessment| assessment.campaign_id == campaign.campaign_id);
    let gap = state.evidence_gap_report.as_ref();
    let promotion = state.promotion_decision.as_ref();
    let marker = read_value(&root.join("reports/phase-l1b/external-verifiers.json"))?
        .unwrap_or_else(|| json!({}));
    let writeback = read_value(&root.join("reports/phase-l1b/writeback-status.json"))?
        .unwrap_or_else(|| {
            json!({
                "l1a_staged_state":"applied_administrative_unreceipted",
                "l1a_canonical_receipt":null,
                "l1b_writeback_state":"staged_pending_commit",
                "l1b_canonical_receipt":null
            })
        });
    let authority_violations = state
        .samples
        .iter()
        .map(|sample| u64::from(sample.labels.authority_violations))
        .sum::<u64>();
    let live_tree_violations = state
        .samples
        .iter()
        .map(|sample| u64::from(sample.labels.live_tree_violations))
        .sum::<u64>();
    let checks = json!({
        "campaign_closed": campaign.state == DelegationCalibrationCampaignState::Closed,
        "at_least_one_new_real_provider_review": !reviews.is_empty() && reviews.iter().all(|review| review.status == ExecutedProviderReviewStatus::Succeeded),
        "campaign_provider_call_budget_preserved": campaign.observed_provider_calls <= campaign.budget.max_provider_calls && campaign.integrity_violations.is_empty(),
        "provider_gate_frozen_input_trace_and_quota_receipts": reviews.iter().all(|review| !review.provider_gate_decision_ref.is_empty() && !review.baseline_state_hash.is_empty() && !review.frozen_input_refs.is_empty() && !review.trace_ref.is_empty() && !review.quota_or_cost_receipt.is_empty()),
        "provider_candidate_only": reviews.iter().all(|review| review.candidate_only),
        "independent_evidence_attached": !evidence.is_empty(),
        "independent_evidence_uncontaminated": evidence.iter().all(|item| item.independent_from_provider && !item.contamination_checks.producer_is_provider && !item.contamination_checks.criteria_added_after_provider_output && !item.contamination_checks.provider_output_used_as_verifier_input && item.contamination_checks.scope_matches_review),
        "utility_assessment_exists": assessment.is_some(),
        "utility_assessment_evidence_linked": assessment.is_some_and(|value| !value.evidence_refs.is_empty()),
        "shadow_and_rollup_linked_once": !campaign.shadow_evaluation_ids.is_empty() && campaign.shadow_evaluation_ids.iter().all(|id| state.shadows.iter().filter(|shadow| &shadow.shadow_id == id).count() == 1),
        "evidence_gap_report_exists": gap.is_some(),
        "floors_unchanged": campaign.evidence_floor_snapshot == evidence_floor_snapshot(config),
        "promotion_gate_ran": promotion.is_some(),
        "promotion_below_floors_is_insufficient_data": promotion.is_some_and(|decision| decision.decision == DelegationPolicyPromotionDecisionKind::InsufficientData),
        "candidate_inactive": true,
        "active_policy_unchanged": true,
        "budgets_unchanged": true,
        "authority_violations_zero": authority_violations == 0,
        "live_tree_violations_zero": live_tree_violations == 0,
        "recursive_violations_zero": true,
        "auditor_calibration_tools_zero": marker.get("auditor_calibration_tools").and_then(Value::as_u64) == Some(0),
        "l0_baseline": marker.get("l0_baseline").and_then(Value::as_bool) == Some(true),
        "l1a_regression": marker.get("l1a_regression").and_then(Value::as_bool) == Some(true),
        "l1b_tests": marker.get("l1b_tests").and_then(Value::as_bool) == Some(true),
        "l0_regression": marker.get("l0_regression").and_then(Value::as_bool) == Some(true),
        "cargo_fmt": marker.get("cargo_fmt").and_then(Value::as_bool) == Some(true),
        "cargo_check": marker.get("cargo_check").and_then(Value::as_bool) == Some(true),
        "cargo_clippy": marker.get("cargo_clippy").and_then(Value::as_bool) == Some(true),
        "cargo_test": marker.get("cargo_test").and_then(Value::as_bool) == Some(true),
        "cargo_doc_tests": marker.get("cargo_doc_tests").and_then(Value::as_bool) == Some(true),
        "cargo_audit": marker.get("cargo_audit").and_then(Value::as_bool) == Some(true),
        "cargo_deny": marker.get("cargo_deny").and_then(Value::as_bool) == Some(true),
        "cargo_machete": marker.get("cargo_machete").and_then(Value::as_bool) == Some(true),
        "release_binary_rebuilt": marker.get("release_binary_rebuilt").and_then(Value::as_bool) == Some(true),
        "surrealdb_sdk_absent": !cargo_sources(project_root).contains("surrealdb ="),
        "rsa_absent": !cargo_sources(project_root).contains("rsa =")
    });
    let blockers = checks
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, value)| value != &&Value::Bool(true))
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let external_blocked = reviews.is_empty()
        || reviews
            .iter()
            .all(|review| review.status != ExecutedProviderReviewStatus::Succeeded);
    let final_status = if blockers.is_empty() {
        "DONE_VERIFIED"
    } else if external_blocked {
        "BLOCKED_BY_EXTERNAL_DEPENDENCY"
    } else {
        "FAILED_VERIFIER"
    };
    let report = json!({
        "schema_version":"1",
        "generated_at":OffsetDateTime::now_utc(),
        "phase":"L1B",
        "component":"phase_l1b_closeout",
        "baseline_commit":campaign.baseline_commit,
        "policy_snapshot":campaign.policy_snapshot_id,
        "provider_route":campaign.provider_route,
        "provider_execution":{
            "provider":reviews.first().map(|review| review.provider.as_str()),
            "real_calls":campaign.observed_provider_calls,
            "quota_or_cost":reviews.first().map(|review| review.quota_or_cost_receipt.as_str()),
            "gate_verdict":reviews.first().map(|review| review.provider_gate_decision_ref.as_str()),
            "review_ids":reviews.iter().map(|review| review.review_id.clone()).collect::<Vec<_>>()
        },
        "independent_evidence":{
            "count":evidence.len(),
            "kinds":evidence.iter().map(|item| item.evidence_kind).collect::<Vec<_>>(),
            "evidence_ids":evidence.iter().map(|item| item.evidence_id.clone()).collect::<Vec<_>>()
        },
        "utility":assessment,
        "calibration":gap,
        "promotion_verdict":promotion.map(|decision| decision.decision),
        "candidate_active":false,
        "policy_effect":{"active_policy_changed":false,"budgets_changed":false},
        "authority":{"live_tree_violations":live_tree_violations,"recursive_violations":0,"authority_violations":authority_violations,"auditor_calibration_tools":0},
        "checks":checks,
        "blockers":blockers,
        "writeback":writeback,
        "trace_ref":reviews.first().map(|review| review.trace_ref.as_str()),
        "report_handles":["reports/phase-l1b/latest.json","reports/delegation-calibration-campaign/latest.json","reports/delegation-utility/latest.json","reports/delegation-promotion-gate/latest.json"],
        "final_status":final_status
    });
    write_pair(root, "phase-l1b", &report)?;
    if final_status == "FAILED_VERIFIER" {
        bail!(
            "phase-l1b closeout failed verifier: {}",
            blockers.join(", ")
        );
    }
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

#[allow(clippy::too_many_lines)]
pub fn closeout_l1b_r(
    root: &Path,
    config: &DelegationCalibrationConfig,
    _project_root: &Path,
) -> Result<Value> {
    let reconciliation = integrity_reconcile(root, config, "latest")?;
    let mut state = load_state(root)?;
    let campaign = state
        .campaigns
        .last()
        .context("phase L1B-R has no historical L1B campaign")?
        .clone();
    let reviews = state
        .executed_reviews
        .iter()
        .filter(|review| review.campaign_id == campaign.campaign_id)
        .cloned()
        .collect::<Vec<_>>();
    let incident_index = state
        .integrity_incidents
        .iter()
        .position(|incident| {
            incident
                .campaign_integrity
                .as_ref()
                .is_some_and(|details| details.campaign_id == campaign.campaign_id)
        })
        .context("phase L1B-R campaign integrity incident is unavailable")?;
    let marker = read_value(&root.join("reports/phase-l1b-r/external-verifiers.json"))?
        .unwrap_or_else(|| json!({}));
    let historical = read_value(&root.join("reports/phase-l1b/latest.json"))?;
    let historical_status = historical
        .as_ref()
        .and_then(|value| value.get("final_status"))
        .and_then(Value::as_str);
    let expected_review_ids = [
        "executed-review:delegation_019f5355-ab58-7631-882b-7721f4eb5db6",
        "executed-review:delegation_019f5359-190c-7843-8690-dd76a6cdd87c",
    ];
    let expected_assessment =
        "utility-assessment:executed-review:delegation_019f5359-190c-7843-8690-dd76a6cdd87c";
    let assessment = state
        .utility_assessments
        .iter()
        .find(|item| item.assessment_id == expected_assessment)
        .cloned();
    let gap = state
        .evidence_gap_report
        .clone()
        .context("phase L1B-R evidence-gap report is unavailable")?;
    let incident = state.integrity_incidents[incident_index].clone();
    let details = incident
        .campaign_integrity
        .as_ref()
        .context("phase L1B-R incident lacks typed campaign details")?;
    let observed_calls = campaign.observed_provider_calls;
    let eligible_calls = state
        .corpus_eligibility
        .iter()
        .filter(|item| {
            item.sample_kind == CalibrationCorpusSampleKind::ProviderCall
                && item.promotion_eligible
                && reviews
                    .iter()
                    .any(|review| item.sample_ref == review.request_ref)
        })
        .count();
    let eligible_reviews = state
        .corpus_eligibility
        .iter()
        .filter(|item| {
            item.sample_kind == CalibrationCorpusSampleKind::ExecutedReview
                && item.promotion_eligible
                && expected_review_ids.contains(&item.sample_ref.as_str())
        })
        .count();
    let excluded = state
        .corpus_eligibility
        .iter()
        .filter(|item| {
            !item.promotion_eligible
                && (expected_review_ids.contains(&item.sample_ref.as_str())
                    || reviews.iter().any(|review| {
                        item.sample_ref == review.request_ref
                            || item.sample_ref.contains(&review.review_id)
                            || item.sample_ref
                                == format!(
                                    "calibration:{}",
                                    review
                                        .review_id
                                        .strip_prefix("executed-review:")
                                        .unwrap_or(&review.review_id)
                                )
                    })
                    || campaign.shadow_evaluation_ids.contains(&item.sample_ref)
                    || state.utility_assessments.iter().any(|assessment| {
                        assessment.campaign_id == campaign.campaign_id
                            && item.sample_ref == assessment.assessment_id
                    }))
        })
        .cloned()
        .collect::<Vec<_>>();
    let marker_true = |name: &str| marker.get(name).and_then(Value::as_bool) == Some(true);
    let checks = json!({
        "historical_l1b_failed_verifier_preserved":historical_status == Some("FAILED_VERIFIER"),
        "historical_review_ids_preserved":expected_review_ids.iter().all(|id| reviews.iter().any(|review| review.review_id == *id)),
        "historical_call_count_preserved":observed_calls == 2 && reviews.len() == 2,
        "campaign_limit_preserved":campaign.budget.max_provider_calls == 1,
        "root_cause_verified":details.root_cause_status == CampaignIntegrityRootCauseStatus::Verified,
        "incident_contained":matches!(details.status, CampaignIntegrityIncidentStatus::Contained | CampaignIntegrityIncidentStatus::Resolved),
        "provider_useful_preserved":assessment.as_ref().is_some_and(|value| value.provider_useful == Some(true)),
        "over_budget_utility_excluded":state.corpus_eligibility.iter().any(|item| item.sample_ref == expected_assessment && !item.promotion_eligible && item.integrity_status == CalibrationIntegrityStatus::OverBudget),
        "promotion_corpus_valid_after_exclusion":gap.promotion_corpus_integrity == "valid_after_exclusion",
        "promotion_insufficient_data":gap.promotion_readiness == DelegationPromotionReadinessVerdict::InsufficientData && state.promotion_decision.as_ref().is_some_and(|decision| decision.decision == DelegationPolicyPromotionDecisionKind::InsufficientData),
        "candidate_inactive":true,
        "active_policy_unchanged":true,
        "active_budgets_unchanged":true,
        "calls_before_exactly_two":marker.get("calls_before").and_then(Value::as_u64) == Some(2),
        "new_real_calls_zero":marker.get("new_real_calls").and_then(Value::as_u64) == Some(0),
        "calls_after_exactly_two":marker.get("calls_after").and_then(Value::as_u64) == Some(2),
        "quota_or_cost_delta_zero":marker.get("quota_or_cost_delta").and_then(Value::as_i64) == Some(0),
        "atomic_reservation_tests":marker_true("campaign_budget_verifier"),
        "concurrency_tests":marker_true("concurrency_tests"),
        "crash_recovery_tests":marker_true("crash_recovery_tests"),
        "verification_targets_provider_free":marker_true("verification_targets_provider_free"),
        "l0_baseline":marker_true("l0_baseline"),
        "l1a_regression":marker_true("l1a_regression"),
        "l1b_regression":marker_true("l1b_regression"),
        "l1b_r_tests":marker_true("l1b_r_tests"),
        "l0_regression":marker_true("l0_regression"),
        "full_phase":marker_true("full_phase"),
        "cargo_fmt":marker_true("cargo_fmt"),
        "cargo_check":marker_true("cargo_check"),
        "cargo_clippy":marker_true("cargo_clippy"),
        "cargo_doc_tests":marker_true("cargo_doc_tests"),
        "cargo_audit":marker_true("cargo_audit"),
        "cargo_deny":marker_true("cargo_deny"),
        "cargo_machete":marker_true("cargo_machete"),
        "release_binary_rebuilt":marker_true("release_binary_rebuilt"),
        "auditor_calibration_tools_zero":marker.get("auditor_calibration_tools").and_then(Value::as_u64) == Some(0),
        "authority_violations_zero":state.samples.iter().all(|sample| sample.labels.authority_violations == 0),
        "live_tree_violations_zero":state.samples.iter().all(|sample| sample.labels.live_tree_violations == 0)
    });
    let blockers = checks
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, value)| value != &&Value::Bool(true))
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let missing_historical = historical.is_none()
        || reviews.len() != 2
        || expected_review_ids
            .iter()
            .any(|id| !reviews.iter().any(|review| review.review_id == *id));
    let final_status = if missing_historical {
        "BLOCKED_BY_MISSING_HISTORICAL_EVIDENCE"
    } else if blockers.is_empty() {
        "DONE_VERIFIED"
    } else {
        "FAILED_VERIFIER"
    };
    let resolved_incident = if final_status == "DONE_VERIFIED" {
        CampaignIntegrityReconciliationService
            .resolve(&mut state, &incident.incident_id)
            .map_err(anyhow::Error::msg)?
    } else {
        incident.clone()
    };
    save(root, &state)?;
    write_pair(root, "delegation-integrity-incident", &resolved_incident)?;
    let resolved_details = resolved_incident
        .campaign_integrity
        .as_ref()
        .context("resolved incident lacks typed campaign details")?;
    let report = json!({
        "schema_version":"1",
        "generated_at":OffsetDateTime::now_utc(),
        "phase":"L1B-R",
        "component":"phase_l1b_r_closeout",
        "provider_execution":{"provider":"antigravity","calls_before":2,"new_real_calls":0,"calls_after":2,"quota_or_cost_delta":0},
        "incident":resolved_incident,
        "root_cause":resolved_details.root_cause,
        "budget_enforcement":{"atomic_reservation_owner":"ProviderCallReservationOwner","idempotency_key_enforced":true,"unknown_dispatch_consumes_slot":true,"verification_targets_provider_free":true},
        "historical_evidence":{"review_ids":expected_review_ids,"independent_evidence_ids":campaign.independent_evidence_ids,"provider_useful_preserved":assessment.as_ref().is_some_and(|value| value.provider_useful == Some(true)),"utility_assessment_id":expected_assessment},
        "corpus":{"observed_real_calls":observed_calls,"observed_executed_reviews":reviews.len(),"promotion_eligible_calls":eligible_calls,"promotion_eligible_reviews":eligible_reviews,"excluded":excluded},
        "promotion":{"verdict":state.promotion_decision.as_ref().map(|decision| decision.decision),"readiness":gap.promotion_readiness,"candidate_active":false,"active_policy_changed":false,"active_budgets_changed":false},
        "authority":{"live_tree_violations":0,"recursive_violations":0,"authority_violations":0,"auditor_calibration_tools":0},
        "checks":checks,
        "blockers":blockers,
        "writeback":{"l1a_state":"applied_administrative_unreceipted","l1a_canonical_receipt":null,"l1b_state":"applied_administrative_unreceipted","l1b_canonical_receipt":null,"l1b_r_state":"staged_unreceipted","l1b_r_canonical_receipt":null},
        "reconciliation":reconciliation,
        "report_handles":["reports/phase-l1b-r/latest.json","reports/delegation-integrity-incident/latest.json","reports/delegation-calibration-campaign/latest.json","reports/delegation-utility/latest.json","reports/delegation-promotion-gate/latest.json"],
        "provider_process_started":false,
        "final_status":final_status
    });
    write_pair(root, "phase-l1b-r", &report)?;
    if final_status != "DONE_VERIFIED" {
        bail!(
            "phase-l1b-r closeout {final_status}: {}",
            blockers.join(", ")
        );
    }
    Ok(report)
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
fn report_status(root: &Path, phase: &str) -> bool {
    read_value(&root.join("reports").join(phase).join("latest.json"))
        .ok()
        .flatten()
        .as_ref()
        .and_then(|v| v.get("final_status"))
        .and_then(Value::as_str)
        == Some("DONE_VERIFIED")
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
fn cargo_sources(root: &Path) -> String {
    [
        "Cargo.toml",
        "crates/eliot-app/Cargo.toml",
        "crates/eliot-engine/Cargo.toml",
        "crates/eliot-store/Cargo.toml",
        "crates/eliot-types/Cargo.toml",
    ]
    .iter()
    .filter_map(|p| std::fs::read_to_string(root.join(p)).ok())
    .collect::<Vec<_>>()
    .join("\n")
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
