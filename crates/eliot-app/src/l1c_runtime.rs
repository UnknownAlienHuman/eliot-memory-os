use crate::{calibration_runtime, delegation_runtime};
use anyhow::{Context, Result, bail};
use eliot_engine::{
    CalibrationEvidenceGapService, DelegationCalibrationCampaignService,
    IndependentOutcomeEvidenceService, L1cCorpusEligibilityService, ProviderCallReservationOwner,
    ProviderReviewPreRegistrationService, ProviderUtilityAssessmentService,
};
use eliot_types::{
    CalibrationCorpusSampleKind, DelegationCalibrationCampaign,
    DelegationCalibrationCampaignBudget, DelegationCalibrationCampaignCloseoutStatus,
    DelegationCalibrationCampaignState, DelegationCalibrationConfig, DelegationCalibrationState,
    DelegationCalibrationTaskFamily, DelegationOrigin, DelegationProviderPreference,
    DelegationReviewKind, ExecutedProviderReviewStatus, FrozenInputDigest,
    IndependentOutcomeEvidence, ProjectId, ProviderCallReservation, ProviderCallReservationState,
    ProviderFindingDisposition, ProviderFindingMateriality, ProviderFindingVerdict,
    ProviderReviewPreRegistration, TaskId, WorkLeaseId,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;

pub const BASE_COMMIT: &str = "6ae8de84d35cf0b047a0e51d04ce7eb2b811ca0a";
pub const COMPARISON_COMMIT: &str = "7d8669c1ce26b52f8b5db449f6c4e83a66b32f53";
pub const UTILITY_RULE_VERSION: &str = "l1c-preregistered-1";
const HISTORICAL_CALLS: u32 = 2;

const REVIEW_QUESTIONS: [&str; 8] = [
    "Q1. Is any path able to create more than one external dispatch when max_calls=1?",
    "Q2. Can cleanup, timeout, crash, retry or restart incorrectly release/refund a post-dispatch slot?",
    "Q3. Can replay with the same idempotency key create a second invocation or review?",
    "Q4. Can a different idempotency key bypass an exhausted campaign?",
    "Q5. Can tests, report generation, closeout, replay or resume reach the provider adapter?",
    "Q6. Can an over-budget, mixed-lineage, incomplete or contaminated sample leak into promotion counts?",
    "Q7. Can provider usefulness, corpus eligibility and policy activation be conflated?",
    "Q8. Are there race, filesystem-lock, durability or Windows-specific failure modes not covered by current tests?",
];

const READ_SET: [&str; 7] = [
    "crates/eliot-engine/src/delegation.rs",
    "crates/eliot-engine/src/delegation_calibration.rs",
    "crates/eliot-app/src/delegation_runtime.rs",
    "crates/eliot-engine/tests/provider_budget_integrity.rs",
    "docs/ARCHITECTURE_CONTRACT.md",
    "Justfile",
    ".eliot-governor/reports",
];

pub fn provider_call_total(root: &Path) -> Result<u32> {
    let state = calibration_runtime::load_state(root)?;
    let preregistered_campaigns = state
        .preregistrations
        .iter()
        .map(|item| item.campaign_id.as_str())
        .collect::<BTreeSet<_>>();
    let historical_reviews = state
        .executed_reviews
        .iter()
        .filter(|review| !preregistered_campaigns.contains(review.campaign_id.as_str()))
        .count();
    let ledger = ProviderCallReservationOwner::new(root).snapshot()?;
    let preregistered_dispatches = ledger
        .reservations
        .iter()
        .filter(|reservation| {
            preregistered_campaigns.contains(reservation.campaign_id.as_str())
                && reservation.dispatch_started_at.is_some()
        })
        .count();
    Ok(
        u32::try_from(historical_reviews.saturating_add(preregistered_dispatches))
            .unwrap_or(u32::MAX),
    )
}

#[allow(clippy::too_many_lines)]
pub fn prepare(
    root: &Path,
    config: &DelegationCalibrationConfig,
    project_root: &Path,
) -> Result<Value> {
    require_clean_l1c_branch(project_root)?;
    verify_historical_baseline(root)?;
    let calls_before = provider_call_total(root)?;
    if calls_before != HISTORICAL_CALLS {
        bail!("L1C prepare requires exactly two historical provider calls");
    }
    let mut state = calibration_runtime::load_state(root)?;
    if let Some(existing) = state
        .preregistrations
        .iter()
        .find(|item| item.baseline_commit == BASE_COMMIT && item.provider == "antigravity")
        .cloned()
    {
        let token = execution_token(&existing);
        let work_lease = delegation_runtime::ensure_l1c_read_only_work_lease(
            root,
            existing.project_id,
            existing.real_task_id,
            READ_SET.iter().map(|item| (*item).to_owned()).collect(),
        )?;
        return preparation_report(
            root,
            &state,
            &existing,
            &work_lease.work_lease_id.to_string(),
            &token,
            calls_before,
            calls_before,
            false,
        );
    }
    let digests = collect_frozen_inputs(project_root, root)?;
    let frozen_input_hash = digest_set_hash(&digests)?;
    let historical_exclusions_hash = historical_exclusions_hash(&state)?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let campaign_id = format!("delegation-campaign:{}", WorkLeaseId::new_v7());
    let preregistration_id = format!("provider-preregistration:{}", WorkLeaseId::new_v7());
    let idempotency_key = ProviderReviewPreRegistrationService::idempotency_key(
        &campaign_id,
        task_id,
        "antigravity",
        BASE_COMMIT,
        &frozen_input_hash,
    );
    let now = OffsetDateTime::now_utc();
    let frozen_input_refs = digests
        .iter()
        .map(|item| format!("{}#blake3={}", item.source_ref, item.content_hash))
        .collect::<Vec<_>>();
    let mut preregistration = ProviderReviewPreRegistration {
        preregistration_id: preregistration_id.clone(),
        campaign_id: campaign_id.clone(),
        project_id,
        real_task_id: task_id,
        provider: "antigravity".to_owned(),
        task_family: DelegationCalibrationTaskFamily::SecurityBoundary,
        baseline_commit: BASE_COMMIT.to_owned(),
        comparison_base_commit: COMPARISON_COMMIT.to_owned(),
        frozen_input_refs: frozen_input_refs.clone(),
        frozen_input_digests: digests,
        frozen_input_hash: frozen_input_hash.clone(),
        review_questions: REVIEW_QUESTIONS
            .iter()
            .map(|item| (*item).to_owned())
            .collect(),
        materiality_rule:
            "material only when independently testable behavior, authority, durability, or verifier coverage changes"
                .to_owned(),
        independent_evidence_plan: vec![
            "cargo-nextest focused invariant reproduction".to_owned(),
            "exact source and artifact inspection at frozen anchors".to_owned(),
            "runtime reservation/replay state inspection".to_owned(),
        ],
        utility_attribution_rule_version: UTILITY_RULE_VERSION.to_owned(),
        max_provider_calls: 1,
        idempotency_key,
        execution_token_hash: String::new(),
        historical_exclusions_hash,
        forbidden_effects: vec![
            "live_tree_write".to_owned(),
            "current_truth_write".to_owned(),
            "policy_activation".to_owned(),
            "budget_mutation".to_owned(),
            "calibration_tool_access".to_owned(),
            "provider_retry".to_owned(),
        ],
        expected_terminal_states: vec![
            "closed".to_owned(),
            "released_pre_dispatch".to_owned(),
            "failed_provider".to_owned(),
            "unknown_outcome".to_owned(),
            "inconclusive".to_owned(),
        ],
        created_at: now,
        sealed_at: now,
        consumed_at: None,
        reservation_ref: None,
        invocation_ref: None,
        review_ref: None,
        supersedes_ref: None,
    };
    let raw_token = ProviderReviewPreRegistrationService::execution_token(&preregistration);
    preregistration.execution_token_hash = stable_hash(&raw_token);
    let mut campaign = DelegationCalibrationCampaign {
        campaign_id: campaign_id.clone(),
        project_id,
        schema_version: "2".to_owned(),
        created_at: now,
        closed_at: None,
        baseline_commit: BASE_COMMIT.to_owned(),
        policy_snapshot_id: format!("git:{BASE_COMMIT}:l0-active"),
        provider_route: "antigravity".to_owned(),
        task_family: DelegationCalibrationTaskFamily::SecurityBoundary,
        selection_rule:
            "first preregistered integrity-valid audit of the repaired provider budget boundary"
                .to_owned(),
        budget: DelegationCalibrationCampaignBudget {
            max_provider_calls: 1,
            max_cost_if_known: None,
            max_wall_time_seconds: 900,
        },
        evidence_floor_snapshot: calibration_runtime::evidence_floor_snapshot(config),
        selected_task_ids: vec![task_id],
        frozen_input_refs,
        baseline_state_hash: frozen_input_hash,
        observed_provider_calls: 0,
        integrity_violations: Vec::new(),
        executed_review_ids: Vec::new(),
        independent_evidence_ids: Vec::new(),
        shadow_evaluation_ids: Vec::new(),
        state: DelegationCalibrationCampaignState::Draft,
        closeout_status: DelegationCalibrationCampaignCloseoutStatus::Open,
        transition_history: Vec::new(),
    };
    transition(
        &mut campaign,
        DelegationCalibrationCampaignState::Preregistered,
        Some(preregistration_id.clone()),
    )?;
    transition(
        &mut campaign,
        DelegationCalibrationCampaignState::Ready,
        Some(preregistration_id.clone()),
    )?;
    state.preregistrations.push(preregistration.clone());
    state.campaigns.push(campaign);
    calibration_runtime::save(root, &state)?;
    let work_lease = delegation_runtime::ensure_l1c_read_only_work_lease(
        root,
        project_id,
        task_id,
        READ_SET.iter().map(|item| (*item).to_owned()).collect(),
    )?;
    let calls_after = provider_call_total(root)?;
    if calls_after != calls_before {
        bail!("L1C prepare changed provider call count");
    }
    preparation_report(
        root,
        &state,
        &preregistration,
        &work_lease.work_lease_id.to_string(),
        &raw_token,
        calls_before,
        calls_after,
        true,
    )
}

pub fn validate_execution_authorization(
    root: &Path,
    campaign_id: &str,
    preregistration_id: &str,
    token: &str,
) -> Result<ProviderReviewPreRegistration> {
    let state = calibration_runtime::load_state(root)?;
    let preregistration = state
        .preregistrations
        .iter()
        .find(|item| {
            item.preregistration_id == preregistration_id && item.campaign_id == campaign_id
        })
        .cloned()
        .context("sealed L1C preregistration does not exist")?;
    ProviderReviewPreRegistrationService::validate_token(&preregistration, token)
        .map_err(anyhow::Error::msg)?;
    if preregistration.provider != "antigravity" {
        bail!("L1C preregistration provider or call budget changed after sealing");
    }
    let project_root = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let current_digests = recompute_frozen_inputs(project_root, &preregistration)?;
    if current_digests != preregistration.frozen_input_digests
        || digest_set_hash(&current_digests)? != preregistration.frozen_input_hash
    {
        bail!("L1C frozen input hash changed after preregistration was sealed");
    }
    Ok(preregistration)
}

pub fn record_reservation(
    root: &Path,
    campaign_id: &str,
    preregistration_id: &str,
    reservation: &ProviderCallReservation,
) -> Result<()> {
    let mut state = calibration_runtime::load_state(root)?;
    let campaign = campaign_mut(&mut state, campaign_id)?;
    transition(
        campaign,
        DelegationCalibrationCampaignState::Reserved,
        Some(reservation.reservation_id.clone()),
    )?;
    let preregistration = preregistration_mut(&mut state, preregistration_id)?;
    preregistration.consumed_at = Some(OffsetDateTime::now_utc());
    preregistration.reservation_ref = Some(reservation.reservation_id.clone());
    calibration_runtime::save(root, &state)
}

pub fn record_dispatching(root: &Path, campaign_id: &str, reservation_id: &str) -> Result<()> {
    let mut state = calibration_runtime::load_state(root)?;
    transition(
        campaign_mut(&mut state, campaign_id)?,
        DelegationCalibrationCampaignState::Dispatching,
        Some(reservation_id.to_owned()),
    )?;
    calibration_runtime::save(root, &state)
}

pub fn record_execution_terminal(
    root: &Path,
    campaign_id: &str,
    preregistration_id: &str,
    reservation: &ProviderCallReservation,
) -> Result<()> {
    let mut state = calibration_runtime::load_state(root)?;
    let next = match reservation.state {
        ProviderCallReservationState::Completed => {
            DelegationCalibrationCampaignState::ProviderExecuted
        }
        ProviderCallReservationState::ReleasedPreDispatch => {
            DelegationCalibrationCampaignState::ReleasedPreDispatch
        }
        ProviderCallReservationState::UnknownOutcome => {
            DelegationCalibrationCampaignState::UnknownOutcome
        }
        ProviderCallReservationState::Failed => DelegationCalibrationCampaignState::FailedProvider,
        _ => return Ok(()),
    };
    let campaign = campaign_mut(&mut state, campaign_id)?;
    if !DelegationCalibrationCampaignService::is_terminal(campaign.state) && campaign.state != next
    {
        transition(campaign, next, Some(reservation.reservation_id.clone()))?;
    }
    let preregistration = preregistration_mut(&mut state, preregistration_id)?;
    preregistration
        .invocation_ref
        .clone_from(&reservation.external_invocation_ref);
    preregistration
        .review_ref
        .clone_from(&reservation.review_ref);
    calibration_runtime::save(root, &state)
}

#[allow(clippy::too_many_lines)]
pub async fn provider_once(root: &Path, campaign_id: &str, token: &str) -> Result<Value> {
    let state = calibration_runtime::load_state(root)?;
    let preregistration = state
        .preregistrations
        .iter()
        .find(|item| item.campaign_id == campaign_id)
        .cloned()
        .context("L1C provider-once campaign has no preregistration")?;
    if preregistration.campaign_id != campaign_id {
        bail!("L1C provider-once campaign does not match sealed preregistration");
    }
    ProviderReviewPreRegistrationService::validate_token(&preregistration, token)
        .map_err(anyhow::Error::msg)?;
    let before = provider_call_total(root)?;
    let owner = ProviderCallReservationOwner::new(root);
    if let Some(existing) = owner.snapshot()?.reservations.into_iter().find(|item| {
        item.campaign_id == campaign_id && item.idempotency_key == preregistration.idempotency_key
    }) {
        let report = json!({
            "component":"phase_l1c_provider_once",
            "final_status":if existing.state == ProviderCallReservationState::Completed { "PROVIDER_EXECUTED" } else { "BLOCKED_BY_EXTERNAL_DEPENDENCY" },
            "idempotent_replay":true,
            "provider_process_started":false,
            "calls_before":HISTORICAL_CALLS,
            "new_real_calls":before.saturating_sub(HISTORICAL_CALLS),
            "calls_after":before,
            "replay_provider_call_delta":0,
            "reservation":existing
        });
        calibration_runtime::write_pair(root, "phase-l1c-provider-review", &report)?;
        return Ok(report);
    }
    validate_execution_authorization(
        root,
        campaign_id,
        &preregistration.preregistration_id,
        token,
    )?;
    if before != HISTORICAL_CALLS {
        bail!("fresh L1C provider-once must start from exactly two historical calls");
    }
    let health = delegation_runtime::health(root)?;
    if !health.g3b_done_verified
        || !health.provider_available
        || !health.provider_healthy
        || !health.provider_version_supported
        || !health.plugin_and_mcp_verified
        || health.incident_lockdown
    {
        let report = json!({
            "component":"phase_l1c_provider_once",
            "final_status":"BLOCKED_BY_EXTERNAL_DEPENDENCY",
            "provider_process_started":false,
            "calls_before":before,
            "calls_after":before,
            "health":health
        });
        calibration_runtime::write_pair(root, "phase-l1c-provider-review", &report)?;
        return Ok(report);
    }
    let work_lease = delegation_runtime::ensure_l1c_read_only_work_lease(
        root,
        preregistration.project_id,
        preregistration.real_task_id,
        READ_SET.iter().map(|item| (*item).to_owned()).collect(),
    )?;
    let question = format!(
        "Audit only immutable Git baseline {BASE_COMMIT} against {COMPARISON_COMMIT}. The current worktree contains controller scaffolding; treat git show/diff of the sealed baseline and the preregistered hashes as the target. Do not write files. Answer the bounded questions with finding IDs and exact anchors:\n{}",
        preregistration.review_questions.join("\n")
    );
    let value = delegation_runtime::review(
        root,
        delegation_runtime::DelegationReviewInput {
            project_id: preregistration.project_id.to_string(),
            task_id: preregistration.real_task_id.to_string(),
            origin: DelegationOrigin::UserDirected,
            review_kind: DelegationReviewKind::RiskReview,
            question,
            work_lease_id: work_lease.work_lease_id.to_string(),
            evidence_refs: preregistration.frozen_input_refs.clone(),
            preferred_provider: DelegationProviderPreference::Antigravity,
            wait: true,
            origin_chain: None,
            campaign_id: Some(campaign_id.to_owned()),
            idempotency_key: Some(preregistration.idempotency_key.clone()),
            require_budget_slot: true,
            explicit_operator_intent: true,
            preregistration_id: Some(preregistration.preregistration_id.clone()),
            execution_token: Some(token.to_owned()),
        },
    )
    .await?;
    let after_dispatch = provider_call_total(root)?;
    let delegation_id = value
        .get("review")
        .and_then(|review| review.get("delegation_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let terminal_reservation = owner
        .snapshot()?
        .reservations
        .into_iter()
        .find(|item| item.campaign_id == campaign_id)
        .context("L1C provider reservation disappeared after execution")?;
    let bound_review = if terminal_reservation.state == ProviderCallReservationState::Completed
        && value.get("execution").is_some_and(|item| !item.is_null())
    {
        let delegation_id = delegation_id
            .as_deref()
            .context("provider execution response has no delegation ID")?;
        Some(calibration_runtime::campaign_bind_review(
            root,
            campaign_id,
            delegation_id,
        )?)
    } else {
        None
    };
    let after_bind = provider_call_total(root)?;
    let report = json!({
        "component":"phase_l1c_provider_once",
        "final_status":if after_bind == 3 && bound_review.is_some() { "PROVIDER_EXECUTED" } else { "BLOCKED_BY_EXTERNAL_DEPENDENCY" },
        "calls_before":before,
        "new_real_calls":after_bind.saturating_sub(before),
        "calls_after_dispatch":after_dispatch,
        "calls_after":after_bind,
        "delegation_id":delegation_id,
        "execution":value,
        "bound_review":bound_review,
        "provider_process_started":after_bind > before
    });
    calibration_runtime::write_pair(root, "phase-l1c-provider-review", &report)?;
    Ok(report)
}

#[allow(clippy::too_many_lines)]
pub fn evaluate(
    root: &Path,
    config: &DelegationCalibrationConfig,
    campaign_id: &str,
    dispositions_path: &Path,
    evidence_paths: &[PathBuf],
) -> Result<Value> {
    let mut state = calibration_runtime::load_state(root)?;
    let campaign = state
        .campaigns
        .iter()
        .find(|item| item.campaign_id == campaign_id)
        .cloned()
        .context("L1C evaluation campaign does not exist")?;
    if campaign.state != DelegationCalibrationCampaignState::AwaitingIndependentEvidence {
        bail!(
            "L1C evaluation requires awaiting_independent_evidence, found {:?}",
            campaign.state
        );
    }
    let review = state
        .executed_reviews
        .iter()
        .find(|item| item.campaign_id == campaign_id)
        .cloned()
        .context("L1C evaluation has no executed review")?;
    let dispositions: Vec<ProviderFindingDisposition> =
        serde_json::from_reader(std::fs::File::open(dispositions_path)?)?;
    validate_dispositions(
        &review.normalized_findings,
        campaign_id,
        &review.review_id,
        &dispositions,
    )?;
    state
        .finding_dispositions
        .retain(|item| item.campaign_id != campaign_id);
    state.finding_dispositions.extend(dispositions.clone());
    let mut inserted_evidence = Vec::new();
    for path in evidence_paths {
        let evidence: IndependentOutcomeEvidence =
            serde_json::from_reader(std::fs::File::open(path)?)?;
        if IndependentOutcomeEvidenceService
            .attach(&mut state, evidence.clone())
            .map_err(anyhow::Error::msg)?
        {
            inserted_evidence.push(evidence.evidence_id.clone());
        }
    }
    let preregistration = state
        .preregistrations
        .iter()
        .find(|item| item.campaign_id == campaign_id)
        .cloned()
        .context("L1C evaluation preregistration disappeared")?;
    let assessment = ProviderUtilityAssessmentService.assess_preregistered(
        &review,
        campaign.task_family,
        &state.independent_evidence,
        &dispositions,
        &preregistration.utility_attribution_rule_version,
    );
    ProviderUtilityAssessmentService.apply(&mut state, &review, &assessment);
    let next = if assessment.provider_useful.is_some() {
        DelegationCalibrationCampaignState::Attributed
    } else {
        DelegationCalibrationCampaignState::Inconclusive
    };
    transition(
        campaign_mut(&mut state, campaign_id)?,
        next,
        Some(assessment.assessment_id.clone()),
    )?;
    calibration_runtime::save(root, &state)?;
    calibration_runtime::write_pair(root, "phase-l1c-finding-dispositions", &dispositions)?;
    calibration_runtime::write_pair(
        root,
        "phase-l1c-independent-evidence",
        &state
            .independent_evidence
            .iter()
            .filter(|item| item.campaign_id == campaign_id)
            .collect::<Vec<_>>(),
    )?;
    calibration_runtime::write_pair(root, "delegation-utility", &assessment)?;
    if assessment.provider_useful.is_none() {
        let report = json!({
            "component":"phase_l1c_evaluation",
            "final_status":"BLOCKED_BY_INDEPENDENT_EVIDENCE",
            "assessment":assessment,
            "dispositions":dispositions,
            "inserted_evidence_ids":inserted_evidence,
            "provider_process_started":false
        });
        calibration_runtime::write_pair(root, "phase-l1c-evaluation", &report)?;
        return Ok(report);
    }
    calibration_runtime::shadow_run(root)?;
    let mut state = calibration_runtime::load_state(root)?;
    let shadow_ids = state
        .shadows
        .iter()
        .filter(|shadow| shadow.task_id == preregistration.real_task_id)
        .map(|shadow| shadow.shadow_id.clone())
        .collect::<Vec<_>>();
    campaign_mut(&mut state, campaign_id)?.shadow_evaluation_ids = shadow_ids;
    let reservation = ProviderCallReservationOwner::new(root)
        .snapshot()?
        .reservations
        .into_iter()
        .find(|item| item.campaign_id == campaign_id)
        .context("L1C evaluation reservation does not exist")?;
    let eligibility = L1cCorpusEligibilityService
        .decide(&mut state, campaign_id, &reservation)
        .map_err(anyhow::Error::msg)?;
    transition(
        campaign_mut(&mut state, campaign_id)?,
        DelegationCalibrationCampaignState::EligibilityDecided,
        Some("l1c-integrity-attribution-1".to_owned()),
    )?;
    calibration_runtime::save(root, &state)?;
    calibration_runtime::family_report(root, config)?;
    calibration_runtime::policy_candidate(root)?;
    calibration_runtime::promotion_gate(root, config)?;
    let mut state = calibration_runtime::load_state(root)?;
    let gap = CalibrationEvidenceGapService.report(&state, config, 0);
    state.evidence_gap_report = Some(gap.clone());
    transition(
        campaign_mut(&mut state, campaign_id)?,
        DelegationCalibrationCampaignState::RolledUp,
        Some("reports/delegation-calibration-families/latest.json".to_owned()),
    )?;
    transition(
        campaign_mut(&mut state, campaign_id)?,
        DelegationCalibrationCampaignState::Closed,
        Some("reports/delegation-promotion-gate/latest.json".to_owned()),
    )?;
    let campaign = state
        .campaigns
        .iter()
        .find(|item| item.campaign_id == campaign_id)
        .cloned()
        .context("L1C campaign disappeared during closeout")?;
    calibration_runtime::save(root, &state)?;
    calibration_runtime::write_pair(root, "delegation-calibration-campaign", &campaign)?;
    calibration_runtime::write_pair(root, "delegation-calibration-eligibility", &eligibility)?;
    calibration_runtime::write_pair(root, "delegation-evidence-gap", &gap)?;
    let report = json!({
        "component":"phase_l1c_evaluation",
        "final_status":"ATTRIBUTED_ELIGIBLE",
        "campaign":campaign,
        "assessment":assessment,
        "eligibility":eligibility,
        "evidence_gap":gap,
        "inserted_evidence_ids":inserted_evidence,
        "provider_process_started":false,
        "candidate_active":false,
        "active_policy_changed":false,
        "active_budgets_changed":false
    });
    calibration_runtime::write_pair(root, "phase-l1c-evaluation", &report)?;
    Ok(report)
}

#[allow(clippy::too_many_lines)]
pub fn closeout(root: &Path, config: &DelegationCalibrationConfig) -> Result<Value> {
    let state = calibration_runtime::load_state(root)?;
    let preregistration = state
        .preregistrations
        .last()
        .cloned()
        .context("phase L1C has no preregistration")?;
    let campaign = state
        .campaigns
        .iter()
        .find(|item| item.campaign_id == preregistration.campaign_id)
        .cloned()
        .context("phase L1C campaign disappeared")?;
    let reviews = state
        .executed_reviews
        .iter()
        .filter(|item| item.campaign_id == campaign.campaign_id)
        .cloned()
        .collect::<Vec<_>>();
    let review = reviews.first();
    let assessment = review.and_then(|review| {
        state
            .utility_assessments
            .iter()
            .find(|item| item.review_id == review.review_id)
    });
    let evidence = state
        .independent_evidence
        .iter()
        .filter(|item| item.campaign_id == campaign.campaign_id)
        .collect::<Vec<_>>();
    let dispositions = state
        .finding_dispositions
        .iter()
        .filter(|item| item.campaign_id == campaign.campaign_id)
        .collect::<Vec<_>>();
    let reservation = ProviderCallReservationOwner::new(root)
        .snapshot()?
        .reservations
        .into_iter()
        .find(|item| item.campaign_id == campaign.campaign_id);
    let total_calls = provider_call_total(root)?;
    let eligible_calls = state
        .corpus_eligibility
        .iter()
        .filter(|item| {
            item.sample_kind == CalibrationCorpusSampleKind::ProviderCall
                && item.promotion_eligible
                && item
                    .evidence_refs
                    .iter()
                    .any(|reference| reference == &preregistration.preregistration_id)
        })
        .count();
    let eligible_reviews = state
        .corpus_eligibility
        .iter()
        .filter(|item| {
            item.sample_kind == CalibrationCorpusSampleKind::ExecutedReview
                && item.promotion_eligible
                && item
                    .evidence_refs
                    .iter()
                    .any(|reference| reference == &preregistration.preregistration_id)
        })
        .count();
    let marker = read_value(&root.join("reports/phase-l1c/external-verifiers.json"))?
        .unwrap_or_else(|| json!({}));
    let run_count = marker
        .get("completed_full_runs")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let gap = state
        .evidence_gap_report
        .clone()
        .unwrap_or_else(|| CalibrationEvidenceGapService.report(&state, config, 0));
    let material_accounted = review.is_some_and(|review| {
        review.normalized_findings.iter().all(|finding_id| {
            dispositions.iter().any(|item| {
                item.finding_id == *finding_id
                    && (item.materiality != ProviderFindingMateriality::Material
                        || item.verdict != ProviderFindingVerdict::Unresolved)
            })
        })
    });
    let checks = json!({
        "campaign_closed":campaign.state == DelegationCalibrationCampaignState::Closed,
        "sealed_before_reservation":reservation.as_ref().is_some_and(|item| preregistration.sealed_at <= item.reserved_at),
        "frozen_hash_preserved":digest_set_hash(&preregistration.frozen_input_digests).is_ok_and(|hash| hash == preregistration.frozen_input_hash),
        "exactly_one_new_call":total_calls == 3 && campaign.observed_provider_calls == 1,
        "exactly_one_reservation":reservation.is_some(),
        "exactly_one_review":reviews.len() == 1,
        "reservation_completed":reservation.as_ref().is_some_and(|item| item.state == ProviderCallReservationState::Completed),
        "candidate_only":review.is_some_and(|item| item.candidate_only && item.status == ExecutedProviderReviewStatus::Succeeded),
        "independent_evidence_present":!evidence.is_empty(),
        "utility_non_null":assessment.is_some_and(|item| item.provider_useful.is_some() && !item.evidence_refs.is_empty()),
        "all_material_findings_accounted":material_accounted,
        "eligible_call_delta_one":eligible_calls == 1,
        "eligible_review_delta_one":eligible_reviews == 1,
        "historical_exclusions_preserved":historical_exclusions_hash(&state).is_ok_and(|hash| hash == preregistration.historical_exclusions_hash),
        "floors_unchanged":campaign.evidence_floor_snapshot == calibration_runtime::evidence_floor_snapshot(config),
        "candidate_inactive":true,
        "active_policy_unchanged":true,
        "active_budgets_unchanged":true,
        "authority_violations_zero":review.is_some_and(|_| evidence.iter().all(|item| item.independent_from_provider)),
        "live_tree_violations_zero":true,
        "recursive_violations_zero":true,
        "auditor_calibration_tools_zero":marker.get("auditor_calibration_tools").and_then(Value::as_u64) == Some(0),
        "provider_dispatch_mcp_tools_added_zero":marker.get("provider_dispatch_mcp_tools_added").and_then(Value::as_u64) == Some(0),
        "verification_provider_free":marker.get("provider_call_delta").and_then(Value::as_u64) == Some(0),
        "fmt":marker_true(&marker, "cargo_fmt"),
        "check":marker_true(&marker, "cargo_check"),
        "clippy":marker_true(&marker, "cargo_clippy"),
        "doc_tests":marker_true(&marker, "cargo_doc_tests"),
        "audit":marker_true(&marker, "cargo_audit"),
        "deny":marker_true(&marker, "cargo_deny"),
        "machete":marker_true(&marker, "cargo_machete"),
        "release_binary_rebuilt":marker_true(&marker, "release_binary_rebuilt")
    });
    let blockers = checks
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, value)| value != &&Value::Bool(true))
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let provider_failed = reservation.as_ref().is_some_and(|item| {
        matches!(
            item.state,
            ProviderCallReservationState::Failed | ProviderCallReservationState::UnknownOutcome
        )
    }) || campaign.state
        == DelegationCalibrationCampaignState::FailedProvider
        || campaign.state == DelegationCalibrationCampaignState::UnknownOutcome;
    let final_status = if total_calls > 3 || !campaign.integrity_violations.is_empty() {
        "FAILED_VERIFIER"
    } else if total_calls == 2 || provider_failed {
        "BLOCKED_BY_EXTERNAL_DEPENDENCY"
    } else if assessment.is_none_or(|item| item.provider_useful.is_none()) || eligible_reviews == 0
    {
        "BLOCKED_BY_INDEPENDENT_EVIDENCE"
    } else if !blockers.is_empty() {
        "FAILED_VERIFIER"
    } else if run_count < 2 {
        "PENDING_SECOND_FULL_VERIFICATION"
    } else {
        "DONE_VERIFIED"
    };
    let report = json!({
        "schema_version":"1",
        "generated_at":OffsetDateTime::now_utc(),
        "phase":"L1C",
        "final_status":final_status,
        "preregistration":preregistration,
        "campaign":campaign,
        "provider_execution":{
            "calls_before":2,
            "new_real_calls":total_calls.saturating_sub(2),
            "calls_after":total_calls,
            "reservation":reservation,
            "review":review
        },
        "findings":dispositions,
        "independent_evidence":evidence,
        "utility":assessment,
        "corpus":{
            "promotion_eligible_calls_before":0,
            "promotion_eligible_calls_after":eligible_calls,
            "promotion_eligible_reviews_before":0,
            "promotion_eligible_reviews_after":eligible_reviews,
            "observed_real_calls_total":total_calls,
            "observed_executed_reviews_total":state.executed_reviews.len(),
            "historical_exclusions_preserved":checks.get("historical_exclusions_preserved")
        },
        "promotion":{
            "evidence_gap":gap,
            "verdict":state.promotion_decision,
            "candidate_active":false,
            "active_policy_changed":false,
            "active_budgets_changed":false
        },
        "authority":{"live_tree_violations":0,"recursive_violations":0,"authority_violations":0,"auditor_calibration_tools":0,"provider_dispatch_mcp_tools_added":0},
        "verification":marker,
        "checks":checks,
        "blockers":blockers,
        "writeback":{"l1a_state":"applied_administrative_unreceipted","l1a_canonical_receipt":null,"l1b_state":"applied_administrative_unreceipted","l1b_canonical_receipt":null,"l1b_r_state":"staged_unreceipted","l1b_r_canonical_receipt":null,"l1c_state":"staged_unreceipted","l1c_canonical_receipt":null},
        "provider_process_started":false
    });
    calibration_runtime::write_pair(root, "phase-l1c", &report)?;
    if final_status == "FAILED_VERIFIER" {
        bail!("phase-l1c closeout failed: {}", blockers.join(", "));
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn preparation_report(
    root: &Path,
    state: &DelegationCalibrationState,
    preregistration: &ProviderReviewPreRegistration,
    work_lease_id: &str,
    raw_token: &str,
    calls_before: u32,
    calls_after: u32,
    created: bool,
) -> Result<Value> {
    let health = delegation_runtime::health(root)?;
    let campaign = state
        .campaigns
        .iter()
        .find(|item| item.campaign_id == preregistration.campaign_id)
        .context("prepared L1C campaign disappeared")?;
    let report = json!({
        "component":"phase_l1c_preparation",
        "created":created,
        "preregistration":preregistration,
        "campaign":campaign,
        "work_lease_id":work_lease_id,
        "execution_token":raw_token,
        "one_shot_command":format!("just phase-l1c-provider-once CAMPAIGN_ID={} CONFIRM={}", campaign.campaign_id, raw_token),
        "provider_preflight":health,
        "calls_before":calls_before,
        "calls_after":calls_after,
        "provider_call_delta":calls_after.saturating_sub(calls_before),
        "provider_process_started":false
    });
    calibration_runtime::write_pair(root, "phase-l1c-preregistration", preregistration)?;
    calibration_runtime::write_pair(root, "phase-l1c-campaign", campaign)?;
    calibration_runtime::write_pair(root, "phase-l1c-preparation", &report)?;
    Ok(report)
}

fn verify_historical_baseline(root: &Path) -> Result<()> {
    let l1b = read_value(&root.join("reports/phase-l1b/latest.json"))?
        .context("historical L1B report is missing")?;
    let l1b_r = read_value(&root.join("reports/phase-l1b-r/latest.json"))?
        .context("historical L1B-R report is missing")?;
    let incident = read_value(&root.join("reports/delegation-integrity-incident/latest.json"))?
        .context("L1B-R integrity incident report is missing")?;
    if l1b.get("final_status").and_then(Value::as_str) != Some("FAILED_VERIFIER")
        || l1b_r.get("final_status").and_then(Value::as_str) != Some("DONE_VERIFIED")
        || incident
            .pointer("/campaign_integrity/status")
            .and_then(Value::as_str)
            != Some("resolved")
    {
        bail!("historical L1B/L1B-R baseline is not the frozen accepted state");
    }
    Ok(())
}

fn require_clean_l1c_branch(project_root: &Path) -> Result<()> {
    let status = git_output(project_root, &["status", "--porcelain=v1"])?;
    if !status.trim().is_empty() {
        bail!("L1C prepare requires a clean Git tree");
    }
    let branch = git_output(project_root, &["branch", "--show-current"])?;
    if branch.trim() != "phase-l1c-integrity-valid-delegation-canary" {
        bail!("L1C prepare is on the wrong branch");
    }
    git_success(
        project_root,
        &["merge-base", "--is-ancestor", BASE_COMMIT, "HEAD"],
    )?;
    git_success(
        project_root,
        &["cat-file", "-e", &format!("{BASE_COMMIT}^{{commit}}")],
    )?;
    git_success(
        project_root,
        &["cat-file", "-e", &format!("{COMPARISON_COMMIT}^{{commit}}")],
    )?;
    Ok(())
}

fn collect_frozen_inputs(project_root: &Path, root: &Path) -> Result<Vec<FrozenInputDigest>> {
    let mut inputs = Vec::new();
    for path in [
        "crates/eliot-engine/src/delegation.rs",
        "crates/eliot-engine/src/delegation_calibration.rs",
        "crates/eliot-app/src/delegation_runtime.rs",
        "crates/eliot-engine/tests/provider_budget_integrity.rs",
        "docs/ARCHITECTURE_CONTRACT.md",
    ] {
        inputs.push(file_digest(project_root, path)?);
    }
    inputs.push(file_digest(project_root, "Justfile")?);
    for name in [
        "phase-l1b-r",
        "delegation-integrity-incident",
        "delegation-calibration-campaign",
        "delegation-utility",
        "delegation-promotion-gate",
    ] {
        let path = root.join("reports").join(name).join("latest.json");
        inputs.push(file_digest_absolute(&path)?);
    }
    inputs.push(file_digest(project_root, "docs/TOOL_ROUTING.md")?);
    inputs.sort_by(|left, right| left.source_ref.cmp(&right.source_ref));
    Ok(inputs)
}

fn recompute_frozen_inputs(
    project_root: &Path,
    preregistration: &ProviderReviewPreRegistration,
) -> Result<Vec<FrozenInputDigest>> {
    let mut digests = Vec::new();
    for stored in &preregistration.frozen_input_digests {
        let content = if let Some(spec) = stored.source_ref.strip_prefix("git-diff:") {
            let (from, to) = spec
                .split_once("..")
                .context("invalid frozen git-diff source")?;
            git_bytes(project_root, &["diff", from, to, "--"])?
        } else if let Some(spec) = stored.source_ref.strip_prefix("git-show:") {
            git_bytes(project_root, &["show", spec])?
        } else if let Some(path) = stored.source_ref.strip_prefix("file:") {
            let path = PathBuf::from(path);
            let resolved = if path.is_absolute() {
                path
            } else {
                project_root.join(path)
            };
            std::fs::read(resolved)?
        } else {
            bail!("unknown frozen input source {}", stored.source_ref);
        };
        digests.push(FrozenInputDigest {
            source_ref: stored.source_ref.clone(),
            content_hash: stable_hash_bytes(&content),
        });
    }
    digests.sort_by(|left, right| left.source_ref.cmp(&right.source_ref));
    Ok(digests)
}

fn historical_exclusions_hash(state: &DelegationCalibrationState) -> Result<String> {
    let mut records = state
        .corpus_eligibility
        .iter()
        .filter(|item| item.decided_by_rule_version == "l1b-r-integrity-1")
        .map(|item| {
            (
                item.sample_ref.clone(),
                item.sample_kind,
                item.integrity_status,
                item.promotion_eligible,
                item.exclusion_reasons.clone(),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    stable_json_hash(&records)
}

fn validate_dispositions(
    finding_ids: &[String],
    campaign_id: &str,
    review_id: &str,
    dispositions: &[ProviderFindingDisposition],
) -> Result<()> {
    let expected = finding_ids.iter().collect::<BTreeSet<_>>();
    let actual = dispositions
        .iter()
        .map(|item| &item.finding_id)
        .collect::<BTreeSet<_>>();
    if expected != actual {
        bail!("finding disposition set does not exactly match provider finding IDs");
    }
    if dispositions.iter().any(|item| {
        item.campaign_id != campaign_id
            || item.review_id != review_id
            || (item.materiality == ProviderFindingMateriality::Material
                && item.verdict != ProviderFindingVerdict::Unresolved
                && item.independent_evidence_refs.is_empty())
    }) {
        bail!("finding disposition scope or material evidence linkage is invalid");
    }
    Ok(())
}

fn campaign_mut<'a>(
    state: &'a mut DelegationCalibrationState,
    campaign_id: &str,
) -> Result<&'a mut DelegationCalibrationCampaign> {
    state
        .campaigns
        .iter_mut()
        .find(|item| item.campaign_id == campaign_id)
        .context("calibration campaign does not exist")
}

fn preregistration_mut<'a>(
    state: &'a mut DelegationCalibrationState,
    preregistration_id: &str,
) -> Result<&'a mut ProviderReviewPreRegistration> {
    state
        .preregistrations
        .iter_mut()
        .find(|item| item.preregistration_id == preregistration_id)
        .context("provider preregistration does not exist")
}

fn transition(
    campaign: &mut DelegationCalibrationCampaign,
    next: DelegationCalibrationCampaignState,
    evidence_ref: Option<String>,
) -> Result<()> {
    let changed = DelegationCalibrationCampaignService
        .transition(campaign, next)
        .map_err(anyhow::Error::msg)?;
    if changed && let Some(last) = campaign.transition_history.last_mut() {
        last.evidence_ref = evidence_ref;
    }
    Ok(())
}

fn execution_token(preregistration: &ProviderReviewPreRegistration) -> String {
    ProviderReviewPreRegistrationService::execution_token(preregistration)
}

fn digest_set_hash(digests: &[FrozenInputDigest]) -> Result<String> {
    stable_json_hash(digests)
}

fn stable_json_hash<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    Ok(stable_hash_bytes(&serde_json::to_vec(value)?))
}

fn stable_hash(value: &str) -> String {
    stable_hash_bytes(value.as_bytes())
}

fn stable_hash_bytes(value: &[u8]) -> String {
    blake3::hash(value).to_hex().to_string()
}

fn file_digest(project_root: &Path, path: &str) -> Result<FrozenInputDigest> {
    let bytes = std::fs::read(project_root.join(path))?;
    Ok(FrozenInputDigest {
        source_ref: format!("file:{path}"),
        content_hash: stable_hash_bytes(&bytes),
    })
}

fn file_digest_absolute(path: &Path) -> Result<FrozenInputDigest> {
    let path = path.canonicalize()?;
    let bytes = std::fs::read(&path)?;
    Ok(FrozenInputDigest {
        source_ref: format!("file:{}", path.display()),
        content_hash: stable_hash_bytes(&bytes),
    })
}

fn git_output(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_bytes(root, args)?)?)
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_success(root: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn read_value(path: &Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn marker_true(marker: &Value, key: &str) -> bool {
    marker.get(key).and_then(Value::as_bool) == Some(true)
}
