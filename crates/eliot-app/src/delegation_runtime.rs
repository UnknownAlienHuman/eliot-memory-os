use crate::runtime_instance::atomic_write_bytes;
use anyhow::{Context, Result, bail};
use eliot_engine::{
    AgentSessionService, AntigravityBinaryResolver, AntigravityCapabilityProbeService,
    AntigravityCommandContractService, AntigravityDisposableWorktreeSmokeService,
    AntigravityEnablementService, AntigravityExecutionGate, AntigravityRunner,
    AntigravityVersionGateService, CandidateDiffService, DelegationBudgetReservation,
    DelegationBudgetService, DelegationCalibrationCampaignService, DelegationExecutionService,
    DelegationHealth, DelegationOutcomeService, DelegationPolicyContext, DelegationPolicyService,
    DelegationReportService, ExternalResultCompletenessService, ExternalReviewJobService,
    IncidentService, ProviderCallReservationDecision, ProviderCallReservationOwner,
    ProviderCallReservationRequest, ProviderCompletenessInput, ProviderInvocationJournal,
    WorkClaimRequest, WorkCreateRequest, WorkLeaseService, WorkQueueService, WorkState,
    antigravity_review_request, default_work_scope, external_review_request, l1c_timeout_profile,
    work_lease_is_active,
};
use eliot_types::{
    AgentRole, AntigravityBinaryResolutionStatus, AntigravityEnablementScope,
    AntigravityEnablementState, AntigravityExecutionGateDecisionKind, AntigravityProviderState,
    AntigravityReviewMode, AntigravityRunState, DelegationDecisionKind, DelegationJobState,
    DelegationOrigin, DelegationOriginChain, DelegationOutcomeStatus, DelegationProviderPreference,
    DelegationReason, DelegationRequest, DelegationReviewKind, DelegationRootOrigin,
    DelegationState, ExternalReviewJobStatus, ExternalReviewRole, ProjectId,
    ProviderCallReservationState, ProviderInvocationAttempt, ProviderInvocationState,
    ProviderReviewPreRegistration, TaintClass, TaskId, WorkLease, WorkLeaseDecisionKind,
    WorkLeaseId, WorktreeLeaseState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;
use time::OffsetDateTime;

pub const DELEGATION_TOOL_NAMES: [&str; 4] = [
    "eliot_delegate_review",
    "eliot_delegate_status",
    "eliot_delegate_result",
    "eliot_delegate_report",
];

pub fn root_from_config(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

#[derive(Clone, Debug, Deserialize)]
pub struct DelegationReviewInput {
    pub project_id: String,
    pub task_id: String,
    pub origin: DelegationOrigin,
    pub review_kind: DelegationReviewKind,
    pub question: String,
    pub work_lease_id: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default = "default_provider")]
    pub preferred_provider: DelegationProviderPreference,
    #[serde(default)]
    pub wait: bool,
    #[serde(default)]
    pub origin_chain: Option<DelegationOriginChain>,
    #[serde(default)]
    pub campaign_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub require_budget_slot: bool,
    #[serde(default)]
    pub explicit_operator_intent: bool,
    #[serde(default)]
    pub preregistration_id: Option<String>,
    #[serde(default)]
    pub execution_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct DelegationExecutionEvidence {
    delegation_id: String,
    real_provider_process_count: u32,
    worktree_lease_id: String,
    worktree_path: String,
    cwd_equals_worktree_path: bool,
    g2_external_review_request_ref: String,
    g2_external_review_job_ref: String,
    normalized_result_ref: Option<String>,
    candidate_diff_ref: String,
    candidate_only: bool,
    tainted: bool,
    cleanup_state: WorktreeLeaseState,
    #[serde(default)]
    cleanup_error: Option<String>,
    provider_disabled: bool,
    live_tree_unchanged: bool,
    controller_read_observation_count: u32,
    authority_violation_count: u32,
    created_at: OffsetDateTime,
}

pub fn load_state(root: &Path) -> Result<DelegationState> {
    read_json_or_default(&delegation_state_path(root))
}

pub(crate) fn save_host_broker_state(root: &Path, state: &DelegationState) -> Result<()> {
    write_pair_at(&root.join("reports/delegation-state"), state)?;
    write_report_pair(
        root,
        "host-broker",
        &json!({
            "schema_version": "eliot-host-broker-v1",
            "host_sessions": state.agent_host_sessions,
            "task_role_leases": state.task_role_leases,
            "controller_leases": state.controller_leases,
            "agent_invocations": state.agent_invocations,
            "operation_jobs": state.operation_jobs,
            "agent_results": state.agent_results,
            "agent_result_dispositions": state.agent_result_dispositions
        }),
    )
}

pub fn health(root: &Path) -> Result<DelegationHealth> {
    let phase_g3b = read_json_value(&root.join("reports/phase-g3b/latest.json"))?;
    let g3b_done_verified = phase_g3b
        .as_ref()
        .and_then(|value| value.get("final_status"))
        .and_then(Value::as_str)
        == Some("DONE_VERIFIED");
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    let probe = AntigravityCapabilityProbeService.probe_from_resolution(&resolution);
    let contract = AntigravityCommandContractService.build(&resolution, &probe);
    let version = resolution
        .selected_path
        .as_ref()
        .map(|path| AntigravityVersionGateService.probe(Path::new(path)));
    let plugin_proof = root
        .join("reports/antigravity-plugin-install/latest.json")
        .is_file();
    let mcp_proof = root
        .join("reports/antigravity-mcp-registration/latest.json")
        .is_file()
        && root
            .join("reports/antigravity-mcp-invocation-proof/latest.json")
            .is_file();
    Ok(DelegationHealth {
        g3b_done_verified,
        provider_available: resolution.status == AntigravityBinaryResolutionStatus::Resolved
            && contract.noninteractive_supported,
        provider_healthy: !matches!(probe.provider_state, AntigravityProviderState::NotInstalled),
        provider_version_supported: version.as_ref().is_some_and(|gate| gate.allowed),
        plugin_and_mcp_verified: plugin_proof && mcp_proof,
        incident_lockdown: IncidentService::new(root).lockdown_active()?,
        evidence_refs: vec![
            "reports/phase-g3b/latest.json".to_owned(),
            "reports/antigravity-plugin-install/latest.json".to_owned(),
            "reports/antigravity-mcp-registration/latest.json".to_owned(),
            "reports/antigravity-mcp-invocation-proof/latest.json".to_owned(),
        ],
        checked_at: OffsetDateTime::now_utc(),
    })
}

pub fn ensure_l1c_read_only_work_lease(
    root: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    read_set: Vec<String>,
) -> Result<WorkLease> {
    let mut state = load_work_state(root)?;
    if let Some(existing) = state
        .leases
        .iter()
        .find(|lease| {
            lease.project_id == project_id
                && lease.task_id == task_id
                && work_lease_is_active(lease)
        })
        .cloned()
    {
        return Ok(existing);
    }
    let project_root = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let session = AgentSessionService.create_controller(&mut state, project_id);
    let work_item_id = if let Some(existing) = state
        .work_items
        .iter()
        .find(|item| item.project_id == project_id && item.task_id == task_id)
    {
        existing.work_item_id
    } else {
        WorkQueueService
            .create_work_item(
                &mut state,
                WorkCreateRequest {
                    project_id,
                    task_id,
                    project: "eliot-governor".to_owned(),
                    task: "phase-l1c-integrity-canary".to_owned(),
                    goal: "Read-only audit of the sealed L1B-R provider-budget integrity baseline"
                        .to_owned(),
                    scope: default_work_scope(
                        project_root.display().to_string(),
                        read_set,
                        Vec::new(),
                        Vec::new(),
                    ),
                    required: true,
                    created_by: session.agent_session_id,
                    required_verifiers: Vec::new(),
                },
            )
            .work_item_id
    };
    let decision = WorkLeaseService.claim(
        &mut state,
        WorkClaimRequest {
            work_item_id,
            agent_session_id: session.agent_session_id,
            role: AgentRole::Auditor,
            ttl_minutes: 180,
        },
    );
    if decision.kind != WorkLeaseDecisionKind::Granted {
        bail!(
            "L1C read-only WorkLease was not granted: {:?}",
            decision.reason
        );
    }
    let lease_id = decision
        .work_lease_id
        .context("granted L1C WorkLease has no ID")?;
    let lease = state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .cloned()
        .context("granted L1C WorkLease disappeared")?;
    save_work_state(root, &state)?;
    Ok(lease)
}

pub fn policy_report() -> Value {
    json!({
        "component": "delegation_policy",
        "origins": ["user_directed", "codex_requested", "policy_shadow"],
        "review_kinds": ["architecture_audit", "risk_review", "diff_audit", "verifier_advice"],
        "provider": "antigravity",
        "hard_denial_order": [
            "recursive_provider_call", "incident_lockdown", "forbidden_data_exposure",
            "g3_b_not_done_verified", "provider_unavailable", "provider_unhealthy",
            "provider_version_below1_1_1", "plugin_or_mcp_integration_not_verified",
            "missing_work_lease", "budget_exceeded", "cooldown_active",
            "fresh_equivalent_review", "unsupported_review_kind"
        ],
        "constraints": ["candidate_only", "tainted", "disposable_worktree"],
        "max_delegation_depth": 1,
        "raw_provider_surface": false
    })
}

pub fn explain(origin: DelegationOrigin, kind: DelegationReviewKind, question: &str) -> Value {
    let request = DelegationRequest {
        delegation_id: new_id("delegation-explain"),
        project_id: eliot_types::ProjectId::new_v7(),
        task_id: eliot_types::TaskId::new_v7(),
        origin,
        origin_chain: default_origin_chain(origin),
        review_kind: kind,
        question: question.to_owned(),
        work_lease_id: WorkLeaseId::new_v7(),
        evidence_refs: Vec::new(),
        preferred_provider: DelegationProviderPreference::Auto,
        created_at: OffsetDateTime::now_utc(),
    };
    let decision = DelegationPolicyService.decide(&request, &DelegationPolicyContext::default());
    json!({ "request": request, "decision": decision, "provider_process_started": false })
}

pub fn fixture_report() -> Value {
    let codex = fixture_request(
        DelegationOrigin::CodexRequested,
        "Review the security authority boundary.",
    );
    let trivial = fixture_request(DelegationOrigin::CodexRequested, "format this file");
    let shadow = fixture_request(
        DelegationOrigin::PolicyShadow,
        "Review this high-risk security integration.",
    );
    let mut recursive = fixture_request(DelegationOrigin::UserDirected, "Review this boundary.");
    recursive
        .origin_chain
        .provider_chain
        .push("antigravity".to_owned());
    let context = DelegationPolicyContext::default();
    let codex_decision = DelegationPolicyService.decide(&codex, &context);
    let trivial_decision = DelegationPolicyService.decide(&trivial, &context);
    let shadow_decision = DelegationPolicyService.decide(&shadow, &context);
    let recursive_decision = DelegationPolicyService.decide(&recursive, &context);
    let mut budget = DelegationBudgetService.for_task(eliot_types::TaskId::new_v7());
    budget.cooldown_seconds = 0;
    let now = OffsetDateTime::now_utc();
    let _ = DelegationBudgetService.reserve(&mut budget, DelegationOrigin::UserDirected, now);
    let _ = DelegationBudgetService.reserve(&mut budget, DelegationOrigin::UserDirected, now);
    let budget_enforced =
        DelegationBudgetService.reserve(&mut budget, DelegationOrigin::UserDirected, now)
            == DelegationBudgetReservation::BudgetExceeded;
    let mut cooldown = DelegationBudgetService.for_task(eliot_types::TaskId::new_v7());
    let _ = DelegationBudgetService.reserve(&mut cooldown, DelegationOrigin::UserDirected, now);
    let cooldown_enforced = DelegationBudgetService.reserve(
        &mut cooldown,
        DelegationOrigin::UserDirected,
        now + time::Duration::seconds(1),
    ) == DelegationBudgetReservation::CooldownActive;
    json!({
        "component": "delegation_fixture_proofs",
        "codex_requested_positive": codex_decision.kind == DelegationDecisionKind::Execute
            && codex_decision.reasons.contains(&DelegationReason::SecurityBoundary),
        "trivial_task_no_call": trivial_decision.kind == DelegationDecisionKind::NoExternalReview,
        "policy_shadow_no_execution": shadow_decision.kind == DelegationDecisionKind::ShadowRecommend,
        "recursive_call_denied": recursive_decision.kind == DelegationDecisionKind::Deny
            && recursive_decision.reasons.contains(&DelegationReason::RecursiveProviderCall),
        "budget_enforced": budget_enforced,
        "cooldown_enforced": cooldown_enforced,
        "provider_process_count": 0,
    })
}

#[allow(clippy::if_not_else, clippy::too_many_lines)]
pub async fn review(root: &Path, input: DelegationReviewInput) -> Result<Value> {
    let mut delegation_state = load_state(root)?;
    let mut work_state = load_work_state(root)?;
    let reservation_owner = ProviderCallReservationOwner::new(root);
    if let (Some(campaign_id), Some(idempotency_key)) =
        (input.campaign_id.as_ref(), input.idempotency_key.as_ref())
        && let Some(existing) =
            reservation_owner
                .snapshot()?
                .reservations
                .into_iter()
                .find(|reservation| {
                    reservation.campaign_id == *campaign_id
                        && reservation.idempotency_key == *idempotency_key
                })
    {
        let review_ref = existing.review_ref.clone();
        return Ok(json!({
            "component":"delegation_provider_execution",
            "idempotent_replay":true,
            "provider_process_started":false,
            "reservation":existing,
            "review_ref":review_ref
        }));
    }
    let work_lease_id = WorkLeaseId::from_str(&input.work_lease_id)
        .context("work_lease_id must be a valid WorkLeaseId")?;
    let matching_lease = work_state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .cloned();
    let (project_id, task_id) = matching_lease.as_ref().map_or_else(
        || {
            (
                eliot_types::ProjectId::new_v7(),
                eliot_types::TaskId::new_v7(),
            )
        },
        |lease| (lease.project_id, lease.task_id),
    );
    let request = DelegationRequest {
        delegation_id: new_id("delegation"),
        project_id,
        task_id,
        origin: input.origin,
        origin_chain: input
            .origin_chain
            .unwrap_or_else(|| default_origin_chain(input.origin)),
        review_kind: input.review_kind,
        question: input.question,
        work_lease_id,
        evidence_refs: input.evidence_refs,
        preferred_provider: input.preferred_provider,
        created_at: OffsetDateTime::now_utc(),
    };
    let health = health(root)?;
    let active_work_lease = matching_lease.as_ref().is_some_and(|lease| {
        lease.project_id == request.project_id
            && lease.task_id == request.task_id
            && work_lease_is_active(lease)
    });
    let budget_index = ensure_budget(&mut delegation_state, request.task_id);
    let budget = &delegation_state.budgets[budget_index];
    let budget_available = match request.origin {
        DelegationOrigin::UserDirected => budget.user_directed_used < budget.user_directed_limit,
        DelegationOrigin::CodexRequested => {
            budget.codex_requested_used < budget.codex_requested_limit
        }
        DelegationOrigin::PolicyShadow => true,
    };
    let cooldown_active = request.origin != DelegationOrigin::PolicyShadow
        && budget.last_execution_at.is_some_and(|last| {
            OffsetDateTime::now_utc()
                < last
                    + time::Duration::seconds(
                        i64::try_from(budget.cooldown_seconds).unwrap_or(i64::MAX),
                    )
        });
    let duplicate_fresh_review = delegation_state.requests.iter().any(|existing| {
        existing.task_id == request.task_id
            && existing.review_kind == request.review_kind
            && existing.question == request.question
            && OffsetDateTime::now_utc() - existing.created_at < time::Duration::minutes(5)
    });
    let forbidden_data_exposure = forbidden_data(&request);
    let context = DelegationPolicyContext {
        incident_lockdown: health.incident_lockdown,
        forbidden_data_exposure,
        g3b_done_verified: health.g3b_done_verified,
        provider_available: health.provider_available,
        provider_healthy: health.provider_healthy,
        provider_version_supported: health.provider_version_supported,
        plugin_and_mcp_verified: health.plugin_and_mcp_verified,
        active_work_lease,
        budget_available,
        cooldown_active,
        duplicate_fresh_review,
    };
    let mut decision = DelegationPolicyService.decide(&request, &context);
    decision.provider_health_ref = Some("reports/delegation-health/latest.json".to_owned());
    decision.budget_id = Some(delegation_state.budgets[budget_index].budget_id.clone());
    let mut execution_evidence = None;
    if decision.kind == DelegationDecisionKind::Execute {
        let preregistration_authorized = match (
            input.campaign_id.as_deref(),
            input.preregistration_id.as_deref(),
            input.execution_token.as_deref(),
        ) {
            (Some(campaign_id), Some(preregistration_id), Some(token)) => {
                crate::l1c_runtime::validate_execution_authorization(
                    root,
                    campaign_id,
                    preregistration_id,
                    token,
                )?;
                true
            }
            _ => false,
        };
        let execution_authorized = input.require_budget_slot
            && input.explicit_operator_intent
            && preregistration_authorized
            && std::env::var_os("ELIOT_DISABLE_REAL_PROVIDER").is_none()
            && input
                .campaign_id
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            && input
                .idempotency_key
                .as_ref()
                .is_some_and(|value| !value.is_empty());
        if !execution_authorized {
            decision.kind = DelegationDecisionKind::Deny;
            decision.provider_id = None;
            decision.reasons = vec![DelegationReason::MissingCampaignReservation];
            decision.constraints.push(
                "real_provider_execution_requires_sealed_preregistration_campaign_id_idempotency_key_budget_slot_explicit_operator_intent_and_provider_enabled"
                    .to_owned(),
            );
        } else {
            let legacy_reservation = DelegationBudgetService.reserve(
                &mut delegation_state.budgets[budget_index],
                request.origin,
                OffsetDateTime::now_utc(),
            );
            if legacy_reservation != DelegationBudgetReservation::Reserved {
                decision.kind = DelegationDecisionKind::Deny;
                decision.provider_id = None;
                decision.reasons = vec![match legacy_reservation {
                    DelegationBudgetReservation::BudgetExceeded => DelegationReason::BudgetExceeded,
                    DelegationBudgetReservation::CooldownActive => DelegationReason::CooldownActive,
                    DelegationBudgetReservation::Reserved => unreachable!(),
                }];
            } else {
                let campaign_id = input.campaign_id.as_deref().unwrap_or_default();
                let idempotency_key = input.idempotency_key.as_deref().unwrap_or_default();
                let calibration = crate::calibration_runtime::load_state(root)?;
                let campaign = calibration
                    .campaigns
                    .iter()
                    .find(|campaign| campaign.campaign_id == campaign_id)
                    .context("provider execution campaign does not exist")?;
                let preregistration = calibration
                    .preregistrations
                    .iter()
                    .find(|item| {
                        item.campaign_id == campaign_id
                            && input.preregistration_id.as_deref()
                                == Some(item.preregistration_id.as_str())
                    })
                    .cloned()
                    .context("provider execution preregistration does not exist")?;
                if !campaign.selected_task_ids.contains(&request.task_id)
                    || campaign.provider_route != "antigravity"
                {
                    DelegationBudgetService
                        .release(&mut delegation_state.budgets[budget_index], request.origin);
                    decision.kind = DelegationDecisionKind::Deny;
                    decision.provider_id = None;
                    decision.reasons = vec![DelegationReason::MissingCampaignReservation];
                    decision
                        .constraints
                        .push("campaign_scope_or_provider_route_mismatch".to_owned());
                } else {
                    let reservation_decision =
                        reservation_owner.reserve(ProviderCallReservationRequest {
                            campaign_id: campaign.campaign_id.clone(),
                            task_id: request.task_id,
                            provider: "antigravity".to_owned(),
                            idempotency_key: idempotency_key.to_owned(),
                            gate_decision_ref: decision.decision_id.clone(),
                            max_calls: campaign.budget.max_provider_calls,
                            campaign_closed: DelegationCalibrationCampaignService::is_terminal(
                                campaign.state,
                            ),
                        })?;
                    match reservation_decision {
                        ProviderCallReservationDecision::Reserved(reservation) => {
                            let preregistration_id = input
                                .preregistration_id
                                .as_deref()
                                .context("authorized provider execution lost preregistration ID")?;
                            crate::l1c_runtime::record_reservation(
                                root,
                                campaign_id,
                                preregistration_id,
                                &reservation,
                            )?;
                            let reservation =
                                reservation_owner.mark_dispatching(&reservation.reservation_id)?;
                            crate::l1c_runtime::record_dispatching(
                                root,
                                campaign_id,
                                &reservation.reservation_id,
                            )?;
                            decision.constraints.push(format!(
                                "provider_call_reservation:{}",
                                reservation.reservation_id
                            ));
                            let lease = matching_lease
                                .as_ref()
                                .context("active matching WorkLease disappeared")?;
                            match execute_real(
                                root,
                                &input.project_id,
                                &input.task_id,
                                &request,
                                &mut decision,
                                &mut delegation_state,
                                &mut work_state,
                                lease,
                                &reservation_owner,
                                &reservation.reservation_id,
                                &preregistration,
                            )
                            .await
                            {
                                Ok(evidence) => {
                                    let current = reservation_owner
                                        .snapshot()?
                                        .reservations
                                        .into_iter()
                                        .find(|item| {
                                            item.reservation_id == reservation.reservation_id
                                        })
                                        .context("completed provider reservation disappeared")?;
                                    crate::l1c_runtime::record_execution_terminal(
                                        root,
                                        campaign_id,
                                        preregistration_id,
                                        &current,
                                    )?;
                                    execution_evidence = Some(evidence);
                                }
                                Err(error) => {
                                    let snapshot = reservation_owner.snapshot()?;
                                    let current = snapshot
                                        .reservations
                                        .iter()
                                        .find(|item| {
                                            item.reservation_id == reservation.reservation_id
                                        })
                                        .context("provider call reservation disappeared")?;
                                    let provider_contacted = matches!(
                                        current.state,
                                        ProviderCallReservationState::Dispatched
                                            | ProviderCallReservationState::Completed
                                            | ProviderCallReservationState::Failed
                                            | ProviderCallReservationState::UnknownOutcome
                                    );
                                    if provider_contacted {
                                        if current.state == ProviderCallReservationState::Dispatched
                                        {
                                            reservation_owner.mark_unknown_outcome(
                                                &reservation.reservation_id,
                                                &error.to_string(),
                                            )?;
                                        }
                                    } else {
                                        reservation_owner.release_pre_dispatch(
                                            &reservation.reservation_id,
                                            "provider dispatch never started",
                                        )?;
                                        DelegationBudgetService.release(
                                            &mut delegation_state.budgets[budget_index],
                                            request.origin,
                                        );
                                    }
                                    let current = reservation_owner
                                        .snapshot()?
                                        .reservations
                                        .into_iter()
                                        .find(|item| {
                                            item.reservation_id == reservation.reservation_id
                                        })
                                        .context("terminal provider reservation disappeared")?;
                                    crate::l1c_runtime::record_execution_terminal(
                                        root,
                                        campaign_id,
                                        preregistration_id,
                                        &current,
                                    )?;
                                    let mut outcome = DelegationOutcomeService.record(
                                        &request.delegation_id,
                                        None,
                                        0,
                                        0,
                                        0,
                                        0,
                                        Vec::new(),
                                        false,
                                        0,
                                        u32::from(provider_contacted),
                                        true,
                                    );
                                    outcome.integrity_evidence_present = !provider_contacted;
                                    outcome.notes.push(if provider_contacted {
                                        "provider dispatch outcome unknown; slot consumed and blind retry forbidden"
                                            .to_owned()
                                    } else {
                                        "pre-dispatch failure proved; reservation released".to_owned()
                                    });
                                    delegation_state.outcomes.push(outcome);
                                    decision.kind = DelegationDecisionKind::Deny;
                                    decision.provider_id = None;
                                    decision.reasons = vec![DelegationReason::ProviderUnavailable];
                                    decision.constraints.push(format!("launch_error:{error}"));
                                }
                            }
                        }
                        ProviderCallReservationDecision::IdempotentReplay(_) => {
                            DelegationBudgetService.release(
                                &mut delegation_state.budgets[budget_index],
                                request.origin,
                            );
                            decision.kind = DelegationDecisionKind::Deny;
                            decision.provider_id = None;
                            decision.reasons = vec![DelegationReason::FreshEquivalentReview];
                        }
                        ProviderCallReservationDecision::BudgetExceeded => {
                            DelegationBudgetService.release(
                                &mut delegation_state.budgets[budget_index],
                                request.origin,
                            );
                            decision.kind = DelegationDecisionKind::Deny;
                            decision.provider_id = None;
                            decision.reasons = vec![DelegationReason::BudgetExceeded];
                        }
                        ProviderCallReservationDecision::CampaignClosed => {
                            DelegationBudgetService.release(
                                &mut delegation_state.budgets[budget_index],
                                request.origin,
                            );
                            decision.kind = DelegationDecisionKind::Deny;
                            decision.provider_id = None;
                            decision.reasons = vec![DelegationReason::CampaignClosed];
                        }
                    }
                }
            }
        }
    }
    if decision.kind == DelegationDecisionKind::Deny
        && !delegation_state
            .outcomes
            .iter()
            .any(|outcome| outcome.delegation_id == request.delegation_id)
    {
        delegation_state
            .outcomes
            .push(policy_denied_outcome(&request.delegation_id));
    }
    delegation_state.requests.push(request.clone());
    delegation_state.decisions.push(decision.clone());
    let provider_ledger = reservation_owner.snapshot()?;
    delegation_state.provider_call_budgets = provider_ledger.budgets;
    delegation_state.provider_call_reservations = provider_ledger.reservations;
    save_work_state(root, &work_state)?;
    save_state_and_reports(
        root,
        &delegation_state,
        &health,
        execution_evidence.as_ref(),
    )?;
    let job = delegation_state
        .jobs
        .iter()
        .rev()
        .find(|job| job.delegation_id == request.delegation_id);
    let response = DelegationReportService.response(&request, &decision, job);
    Ok(json!({
        "review": response,
        "execution": execution_evidence,
        "wait_requested": input.wait
    }))
}

pub fn status(root: &Path, delegation_id: &str) -> Result<Value> {
    let state = load_state(root)?;
    let work_state = load_work_state(root)?;
    let request = state
        .requests
        .iter()
        .find(|item| item.delegation_id == delegation_id);
    let decision = state
        .decisions
        .iter()
        .find(|item| item.delegation_id == delegation_id);
    let job = state
        .jobs
        .iter()
        .find(|item| item.delegation_id == delegation_id);
    let budget = request.and_then(|request| {
        state
            .budgets
            .iter()
            .find(|item| item.task_id == request.task_id)
    });
    let worktree_state = job.and_then(|job| {
        work_state
            .worktree_leases
            .iter()
            .find(|lease| lease.worktree_lease_id == job.worktree_lease_id)
            .map(|lease| lease.state)
    });
    Ok(json!({
        "component": "delegation_status",
        "delegation_id": delegation_id,
        "decision": decision,
        "job": job,
        "worktree_state": worktree_state,
        "budget_reservation": budget,
        "latest_safe_status": decision.map(|decision| decision.kind),
    }))
}

pub fn result(root: &Path, delegation_id: &str) -> Result<Value> {
    let state = load_state(root)?;
    let outcome = state
        .outcomes
        .iter()
        .find(|item| item.delegation_id == delegation_id);
    let result_path = delegation_result_dir(root, delegation_id).join("latest.json");
    let normalized = read_json_value(&result_path)?;
    let execution = read_json_value(&root.join("reports/delegation-execution/latest.json"))?
        .filter(|value| value.get("delegation_id").and_then(Value::as_str) == Some(delegation_id));
    Ok(json!({
        "component": "delegation_result",
        "delegation_id": delegation_id,
        "normalized_external_review_result": normalized,
        "candidate_diff_handle": execution.as_ref().and_then(|value| value.get("candidate_diff_ref")),
        "external_review_request_handle": execution.as_ref().and_then(|value| value.get("g2_external_review_request_ref")),
        "external_review_job_handle": execution.as_ref().and_then(|value| value.get("g2_external_review_job_ref")),
        "outcome": outcome,
        "candidate_only": true,
        "tainted": true,
        "normal_l3_excluded": true,
    }))
}

pub fn outcome(root: &Path, delegation_id: &str) -> Result<Value> {
    let mut state = load_state(root)?;
    let mut work_state = load_work_state(root)?;
    if state.outcomes.iter().any(|outcome| {
        outcome.delegation_id == delegation_id
            && outcome.status == DelegationOutcomeStatus::ProviderFailed
    }) {
        recover_completed_transcript(root, delegation_id, &mut state, &mut work_state)?;
        let health = health(root)?;
        save_work_state(root, &work_state)?;
        save_state_and_reports(root, &state, &health, None)?;
    }
    Ok(serde_json::to_value(
        state
            .outcomes
            .iter()
            .find(|item| item.delegation_id == delegation_id),
    )?)
}

pub fn report(root: &Path) -> Result<Value> {
    let state = load_state(root)?;
    let execution = read_json_or_default::<Option<DelegationExecutionEvidence>>(
        &root.join("reports/delegation-execution/latest.json"),
    )?;
    let report = DelegationReportService.summary(&state);
    write_report_pair(root, "delegation", &report)?;
    write_report_pair(
        root,
        "delegation-metrics",
        &delegation_metrics(&state, execution.as_ref()),
    )?;
    Ok(report)
}

pub fn budgets(root: &Path) -> Result<Value> {
    Ok(json!({ "component": "delegation_budgets", "budgets": load_state(root)?.budgets }))
}

pub fn shadow_report(root: &Path) -> Result<Value> {
    let state = load_state(root)?;
    Ok(json!({
        "component": "delegation_shadow",
        "decisions": state.decisions.into_iter().filter(|decision| {
            matches!(decision.kind, DelegationDecisionKind::ShadowRecommend | DelegationDecisionKind::NoExternalReview)
        }).collect::<Vec<_>>()
    }))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn execute_real(
    root: &Path,
    project: &str,
    task: &str,
    request: &DelegationRequest,
    decision: &mut eliot_types::DelegationDecision,
    delegation_state: &mut DelegationState,
    work_state: &mut WorkState,
    work_lease: &eliot_types::WorkLease,
    reservation_owner: &ProviderCallReservationOwner,
    reservation_id: &str,
    preregistration: &ProviderReviewPreRegistration,
) -> Result<DelegationExecutionEvidence> {
    let started = Instant::now();
    let service = AntigravityDisposableWorktreeSmokeService;
    let repo_root = PathBuf::from(&work_lease.scope.repo_root).canonicalize()?;
    let live_before = service.snapshot_live_tree(&repo_root)?;
    let worktree = service
        .create_disposable_worktree(
            work_state,
            work_lease,
            &std::env::temp_dir().join("eliot-governor-delegation-worktrees"),
            45,
        )
        .await?;
    let worktree_path = PathBuf::from(&worktree.worktree_path);
    let mut g2_request = external_review_request(
        project,
        task,
        "antigravity-cli",
        ExternalReviewRole::Auditor,
        &request.question,
    );
    g2_request.project_id = request.project_id;
    g2_request.task_id = request.task_id;
    g2_request.work_lease_id = Some(request.work_lease_id);
    g2_request.worktree_lease_id = Some(worktree.worktree_lease_id);
    g2_request.evidence_refs.clone_from(&request.evidence_refs);
    let mut g2_job = ExternalReviewJobService.create_job(&g2_request);
    decision.external_review_request_ref = Some(g2_request.request_id.clone());

    let (resolution, probe, contract) = antigravity_contract();
    let previous_state = AntigravityEnablementService.state_from_probe(&probe, None);
    let enablement = AntigravityEnablementService.enable(
        previous_state,
        AntigravityEnablementScope::DisposableWorktreeAuditOnly,
        true,
        vec!["governed L0 routed delegation".to_owned()],
    )?;
    let mut provider_request = antigravity_review_request(
        project,
        task,
        AntigravityReviewMode::AuditPlan,
        &request.question,
    );
    provider_request.project_id = request.project_id;
    provider_request.task_id = request.task_id;
    provider_request.work_lease_id = Some(request.work_lease_id);
    provider_request.worktree_lease_id = Some(worktree.worktree_lease_id);
    provider_request.allowed_paths = worktree.allowed_read_set.clone();
    provider_request
        .evidence_refs
        .clone_from(&request.evidence_refs);
    provider_request.question = governed_provider_question(&request.question);
    provider_request.provider_enabled =
        AntigravityEnablementService.receipt_allows_disposable_worktree_audit(&enablement);
    let gate = AntigravityExecutionGate.decide(
        &provider_request,
        &resolution,
        &probe,
        &contract,
        Some(work_lease),
        Some(&worktree),
        true,
        false,
        false,
    );
    if gate.decision != AntigravityExecutionGateDecisionKind::AllowRealRun {
        cleanup_failed_worktree(work_state, worktree.worktree_lease_id).await;
        bail!(
            "G3B execution gate denied routed delegation: {:?}",
            gate.reasons
        );
    }
    let timeout_profile = l1c_timeout_profile();
    crate::calibration_runtime::write_pair(root, "provider-timeout-profile", &timeout_profile)?;
    let journal = ProviderInvocationJournal::new(root);
    let mut attempt = journal.create(ProviderInvocationAttempt {
        invocation_attempt_id: format!(
            "provider-invocation-attempt:{}",
            provider_request.request_id
        ),
        provider: "antigravity".to_owned(),
        campaign_id: preregistration.campaign_id.clone(),
        preregistration_id: preregistration.preregistration_id.clone(),
        reservation_id: reservation_id.to_owned(),
        idempotency_key: preregistration.idempotency_key.clone(),
        external_invocation_ref: None,
        frozen_input_hash: preregistration.frozen_input_hash.clone(),
        request_payload_hash: blake3::hash(provider_request.question.as_bytes())
            .to_hex()
            .to_string(),
        route_or_model: Some("agy --mode=plan --print; model pinned by provider config".to_owned()),
        adapter_version: None,
        executable_or_transport: contract.binary_path.clone(),
        cwd: Some(worktree.worktree_path.clone()),
        environment_fingerprint: Some(
            blake3::hash(serde_json::to_string(&contract.env_policy.fixed_vars)?.as_bytes())
                .to_hex()
                .to_string(),
        ),
        timeout_profile_id: timeout_profile.profile_id.clone(),
        state_transitions: Vec::new(),
        dispatch_started_at: None,
        process_started_at: None,
        provider_ack_at: None,
        first_output_at: None,
        last_output_at: None,
        process_exit_at: None,
        cleanup_completed_at: None,
        stdout_blob_or_hash: None,
        stderr_blob_or_hash: None,
        structured_output_blob_or_hash: None,
        exit_code_or_signal: None,
        process_or_job_identity: None,
        quota_or_cost_if_known: None,
        original_closeout_ref: None,
    })?;
    journal.transition(
        &mut attempt,
        ProviderInvocationState::Reserved,
        vec![format!("reservation:{reservation_id}")],
    )?;
    let run_result = AntigravityRunner.run_real_recorded(
        &provider_request,
        &contract,
        &worktree,
        &worktree_path,
        root,
        reservation_owner,
        reservation_id,
        &journal,
        &mut attempt,
    );
    let run = match run_result {
        Ok(run) => run,
        Err(error) => {
            cleanup_failed_worktree(work_state, worktree.worktree_lease_id).await;
            return Err(error.into());
        }
    };
    let normalized = run
        .normalized_result
        .clone()
        .context("Antigravity run did not produce a normalized result")?;
    let completeness = ExternalResultCompletenessService.evaluate(ProviderCompletenessInput {
        receipt_id: format!(
            "external-result-completeness:{}",
            provider_request.request_id
        ),
        invocation_attempt_ref: attempt.invocation_attempt_id.clone(),
        raw_output_ref: run.stdout_blob_ref.as_ref().map(|blob| {
            format!(
                "{}#{}={}",
                blob.relative_path, blob.algorithm, blob.digest_hex
            )
        }),
        expected_schema: "AntigravityNormalizedResult/v1".to_owned(),
        terminal_marker_or_protocol_status: (run.state == AntigravityRunState::Succeeded)
            .then_some("process_exit_success".to_owned()),
        required_fields_present: normalized.external_review_result.is_some(),
        truncation_detected: attempt
            .state_transitions
            .last()
            .is_some_and(|transition| transition.to == ProviderInvocationState::LocalCaptureFailed),
        stream_closed_cleanly: run.completed_at.is_some(),
        process_exit_success: run.state == AntigravityRunState::Succeeded,
    });
    write_report_pair(root, "delegation-provider-run", &run)?;
    write_report_pair(root, "external-result-completeness", &completeness)?;
    g2_job.status = if run.state == AntigravityRunState::Succeeded {
        ExternalReviewJobStatus::Succeeded
    } else {
        ExternalReviewJobStatus::Failed
    };
    g2_job.result_id = normalized
        .external_review_result
        .as_ref()
        .map(|result| result.result_id.clone());
    g2_job.completed_at = Some(OffsetDateTime::now_utc());
    let mut job =
        DelegationExecutionService.create_job(request, decision, &worktree, g2_job.job_id.clone());
    DelegationExecutionService.transition(&mut job, DelegationJobState::Running);
    let evidence_result = service
        .capture_cleanup_and_compare(
            work_state,
            &live_before,
            worktree.worktree_lease_id,
            &root.join("candidate-diffs/delegation"),
            CandidateDiffService::default_max_diff_bytes(),
            true,
        )
        .await;
    let (
        candidate_diff_ref,
        candidate_only,
        tainted,
        cleanup_state,
        live_tree_unchanged,
        cleanup_error,
    ) = match evidence_result {
        Ok(evidence) => (
            evidence.candidate_diff_id.to_string(),
            evidence.candidate_only,
            evidence.taint == TaintClass::ExternalAgent,
            evidence.cleanup_state,
            evidence.live_tree_unchanged,
            None,
        ),
        Err(error) => {
            let lease = work_state
                .worktree_leases
                .iter()
                .find(|lease| lease.worktree_lease_id == worktree.worktree_lease_id)
                .context("provider completed but its WorktreeLease disappeared")?;
            let candidate_diff_ref = work_state
                .candidate_diffs
                .iter()
                .rev()
                .find(|diff| diff.worktree_lease_id == worktree.worktree_lease_id)
                .map_or_else(
                    || "missing".to_owned(),
                    |diff| diff.candidate_diff_id.to_string(),
                );
            let live_after = service.snapshot_live_tree(&repo_root)?;
            (
                candidate_diff_ref,
                true,
                true,
                lease.state,
                service.live_tree_unchanged(&live_before, &live_after),
                Some(error.to_string()),
            )
        }
    };
    attempt.cleanup_completed_at = Some(OffsetDateTime::now_utc());
    journal.persist(&attempt)?;
    if run.state == AntigravityRunState::Succeeded {
        journal.transition(
            &mut attempt,
            if cleanup_error.is_some() {
                ProviderInvocationState::CleanupFailedAfterComplete
            } else {
                ProviderInvocationState::ReviewNormalized
            },
            cleanup_error.as_ref().map_or_else(
                || vec!["candidate review normalized after durable capture".to_owned()],
                |error| vec![format!("cleanup_error:{error}")],
            ),
        )?;
    }
    DelegationExecutionService.transition(
        &mut job,
        if run.state == AntigravityRunState::Succeeded && cleanup_error.is_none() {
            DelegationJobState::Completed
        } else {
            DelegationJobState::Failed
        },
    );
    let disable = AntigravityEnablementService.disable(
        enablement.requested_state,
        "provider disabled after governed L0 delegation",
    );
    let result_ref = normalized
        .external_review_result
        .as_ref()
        .map(|result| result.result_id.clone());
    let finding_count = normalized
        .external_review_result
        .as_ref()
        .map_or(0, |result| {
            u32::try_from(result.findings.len()).unwrap_or(u32::MAX)
        });
    let mut outcome = DelegationOutcomeService.record(
        &request.delegation_id,
        result_ref.clone(),
        finding_count,
        0,
        0,
        0,
        Vec::new(),
        false,
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        1,
        run.state != AntigravityRunState::Succeeded,
    );
    outcome.integrity_evidence_present = cleanup_error.is_none();
    outcome.authority_violations = u32::from(normalized.rejected);
    outcome.live_tree_violations = u32::from(!live_tree_unchanged);
    if let Some(error) = cleanup_error.as_ref() {
        outcome.notes.push(format!(
            "provider completed but worktree cleanup failed: {error}"
        ));
    }
    write_report_pair(root, "delegation-g2-request", &g2_request)?;
    write_report_pair(root, "delegation-g2-job", &g2_job)?;
    write_report_pair(root, "delegation-disable", &disable)?;
    let result_dir = delegation_result_dir(root, &request.delegation_id);
    write_pair_at(&result_dir, &normalized)?;
    delegation_state.jobs.push(job);
    delegation_state.outcomes.push(outcome);
    if run.state == AntigravityRunState::Succeeded {
        reservation_owner.complete(
            reservation_id,
            &format!(
                "executed-review:{}",
                request
                    .delegation_id
                    .chars()
                    .map(|character| {
                        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                            character
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>()
            ),
        )?;
    } else {
        reservation_owner
            .fail_after_dispatch(reservation_id, "provider returned a terminal failed run")?;
    }
    Ok(DelegationExecutionEvidence {
        delegation_id: request.delegation_id.clone(),
        real_provider_process_count: 1,
        worktree_lease_id: worktree.worktree_lease_id.to_string(),
        worktree_path: worktree.worktree_path.clone(),
        cwd_equals_worktree_path: run.effective_cwd == worktree.worktree_path,
        g2_external_review_request_ref: g2_request.request_id,
        g2_external_review_job_ref: g2_job.job_id,
        normalized_result_ref: result_ref,
        candidate_diff_ref,
        candidate_only,
        tainted,
        cleanup_state,
        cleanup_error,
        provider_disabled: disable.new_state == AntigravityEnablementState::DisabledAfterSmoke,
        live_tree_unchanged,
        controller_read_observation_count: 0,
        authority_violation_count: u32::from(normalized.rejected),
        created_at: OffsetDateTime::now_utc(),
    })
}

#[allow(clippy::too_many_lines)]
fn recover_completed_transcript(
    root: &Path,
    delegation_id: &str,
    state: &mut DelegationState,
    work_state: &mut WorkState,
) -> Result<()> {
    let request = state
        .requests
        .iter()
        .find(|request| request.delegation_id == delegation_id)
        .cloned()
        .context("delegation request is missing for transcript recovery")?;
    let worktree = work_state
        .worktree_leases
        .iter()
        .filter(|lease| {
            lease.work_lease_id == request.work_lease_id
                && lease.state == WorktreeLeaseState::Cleaned
                && lease.issued_at >= request.created_at
        })
        .min_by_key(|lease| lease.issued_at)
        .cloned()
        .context("cleaned delegation worktree is missing for transcript recovery")?;
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .context("USERPROFILE/HOME is unavailable for transcript recovery")?;
    let cache_path = home.join(".gemini/antigravity-cli/cache/last_conversations.json");
    let cache: std::collections::BTreeMap<String, String> =
        serde_json::from_reader(std::fs::File::open(&cache_path)?)?;
    let conversation_id = cache
        .iter()
        .find(|(path, _)| paths_equal(path, &worktree.worktree_path))
        .map(|(_, id)| id.clone())
        .context("official CLI conversation mapping is missing for delegation worktree")?;
    let transcript_path = home
        .join(".gemini/antigravity-cli/brain")
        .join(&conversation_id)
        .join(".system_generated/logs/transcript.jsonl");
    let transcript = std::fs::read_to_string(&transcript_path)?;
    let final_text = transcript
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.get("type").and_then(Value::as_str) == Some("PLANNER_RESPONSE"))
        .filter_map(|value| {
            value
                .get("content")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .rfind(|content| !content.trim().is_empty())
        .context("completed official CLI transcript has no final planner response")?;
    let mut provider_request = antigravity_review_request(
        "eliot-governor",
        "phase-l0-real-delegation",
        AntigravityReviewMode::AuditPlan,
        &request.question,
    );
    provider_request.project_id = request.project_id;
    provider_request.task_id = request.task_id;
    provider_request.work_lease_id = Some(request.work_lease_id);
    provider_request.worktree_lease_id = Some(worktree.worktree_lease_id);
    let normalized = eliot_engine::AntigravityTextOutputNormalizer
        .normalize_text(&provider_request, &final_text);
    if normalized.rejected {
        bail!("completed provider transcript violated candidate-only authority boundary");
    }
    let decision = state
        .decisions
        .iter_mut()
        .find(|decision| decision.delegation_id == delegation_id)
        .context("delegation decision is missing for transcript recovery")?;
    decision.kind = DelegationDecisionKind::Execute;
    decision.provider_id = Some("antigravity".to_owned());
    decision.reasons = vec![DelegationReason::ExplicitUserRequest];
    decision
        .constraints
        .retain(|constraint| !constraint.starts_with("launch_error:"));
    let mut job = DelegationExecutionService.create_job(
        &request,
        decision,
        &worktree,
        format!("official-cli-transcript:{conversation_id}"),
    );
    DelegationExecutionService.transition(&mut job, DelegationJobState::Completed);
    let result_ref = normalized
        .external_review_result
        .as_ref()
        .map(|result| result.result_id.clone());
    let finding_count = normalized
        .external_review_result
        .as_ref()
        .map_or(0, |result| {
            u32::try_from(result.findings.len()).unwrap_or(u32::MAX)
        });
    state
        .outcomes
        .retain(|outcome| outcome.delegation_id != delegation_id);
    state.outcomes.push(DelegationOutcomeService.record(
        delegation_id,
        result_ref.clone(),
        finding_count,
        0,
        0,
        0,
        Vec::new(),
        false,
        0,
        1,
        false,
    ));
    state.jobs.push(job);
    if let Some(budget) = state
        .budgets
        .iter_mut()
        .find(|budget| budget.task_id == request.task_id)
    {
        budget.user_directed_used = budget.user_directed_used.saturating_add(1);
        budget.last_execution_at = Some(OffsetDateTime::now_utc());
    }
    let controller_root = worktree.repo_root.replace('\\', "/");
    let normalized_transcript_paths = transcript.replace("\\\\", "/");
    let controller_read_observation_count = u32::try_from(
        normalized_transcript_paths
            .matches(&controller_root)
            .count(),
    )
    .unwrap_or(u32::MAX);
    let write_step_count = transcript
        .lines()
        .filter(|line| line.contains("WRITE_FILE") || line.contains("EDIT_FILE"))
        .count();
    if let Some(recovered) = state
        .outcomes
        .iter_mut()
        .find(|outcome| outcome.delegation_id == delegation_id)
    {
        recovered.integrity_evidence_present = true;
        recovered.authority_violations = 0;
        recovered.live_tree_violations = u32::from(write_step_count > 0);
        recovered.notes.push(
            "provider call recovered from official CLI transcript after cleanup failure".to_owned(),
        );
    }
    let disable = AntigravityEnablementService.disable(
        AntigravityEnablementState::EnabledForDisposableWorktreeAudit,
        "provider session closed after official CLI transcript recovery",
    );
    let candidate_diff_ref = work_state
        .candidate_diffs
        .iter()
        .rev()
        .find(|diff| diff.worktree_lease_id == worktree.worktree_lease_id)
        .map_or_else(
            || "none".to_owned(),
            |diff| diff.candidate_diff_id.to_string(),
        );
    let g2_external_review_request_ref = state
        .decisions
        .iter()
        .find(|decision| decision.delegation_id == delegation_id)
        .and_then(|decision| decision.external_review_request_ref.clone())
        .unwrap_or_else(|| "recovered-g2-request".to_owned());
    let evidence = DelegationExecutionEvidence {
        delegation_id: delegation_id.to_owned(),
        real_provider_process_count: 1,
        worktree_lease_id: worktree.worktree_lease_id.to_string(),
        worktree_path: worktree.worktree_path.clone(),
        cwd_equals_worktree_path: true,
        g2_external_review_request_ref,
        g2_external_review_job_ref: format!("official-cli-transcript:{conversation_id}"),
        normalized_result_ref: result_ref,
        candidate_diff_ref,
        candidate_only: true,
        tainted: true,
        cleanup_state: worktree.state,
        cleanup_error: Some("recovered after an original worktree cleanup failure".to_owned()),
        provider_disabled: true,
        live_tree_unchanged: write_step_count == 0,
        controller_read_observation_count,
        authority_violation_count: 0,
        created_at: OffsetDateTime::now_utc(),
    };
    write_pair_at(&delegation_result_dir(root, delegation_id), &normalized)?;
    write_report_pair(root, "delegation-disable", &disable)?;
    write_report_pair(
        root,
        "delegation-transcript-recovery",
        &json!({
            "component": "delegation_transcript_recovery",
            "conversation_id": conversation_id,
            "transcript_ref": transcript_path,
            "recovered": true,
            "raw_provider_output_exposed": false,
        }),
    )?;
    write_report_pair(root, "delegation-execution", &evidence)
}

fn governed_provider_question(question: &str) -> String {
    format!(
        "Operate only inside the current disposable working directory. Do not access the controller repository, call MCP tools, run commands, edit files, or claim verification/completion authority. Return candidate findings only.\n\n{question}"
    )
}

fn paths_equal(left: &str, right: &str) -> bool {
    left.replace('\\', "/")
        .trim_end_matches('/')
        .eq_ignore_ascii_case(right.replace('\\', "/").trim_end_matches('/'))
}

fn delegation_result_dir(root: &Path, delegation_id: &str) -> PathBuf {
    let safe_id = delegation_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    root.join("reports/delegation-results").join(safe_id)
}

async fn cleanup_failed_worktree(work_state: &mut WorkState, id: eliot_types::WorktreeLeaseId) {
    let _ = eliot_engine::WorktreeCleanupService.revoke(work_state, id);
    let _ = eliot_engine::WorktreeCleanupService
        .cleanup(work_state, id)
        .await;
}

fn antigravity_contract() -> (
    eliot_types::AntigravityBinaryResolution,
    eliot_types::AntigravityCapabilityProbe,
    eliot_types::AntigravityCommandContract,
) {
    let resolution =
        AntigravityBinaryResolver.resolve(&AntigravityBinaryResolver::default_config());
    let probe = AntigravityCapabilityProbeService.probe_from_resolution(&resolution);
    let contract = AntigravityCommandContractService.build(&resolution, &probe);
    (resolution, probe, contract)
}

fn default_origin_chain(origin: DelegationOrigin) -> DelegationOriginChain {
    DelegationOriginChain {
        root_origin: match origin {
            DelegationOrigin::UserDirected => DelegationRootOrigin::User,
            DelegationOrigin::CodexRequested => DelegationRootOrigin::Codex,
            DelegationOrigin::PolicyShadow => DelegationRootOrigin::GovernorShadow,
        },
        provider_chain: Vec::new(),
        delegation_depth: 0,
        parent_delegation_id: None,
    }
}

fn fixture_request(origin: DelegationOrigin, question: &str) -> DelegationRequest {
    DelegationRequest {
        delegation_id: new_id("delegation-fixture"),
        project_id: eliot_types::ProjectId::new_v7(),
        task_id: eliot_types::TaskId::new_v7(),
        origin,
        origin_chain: default_origin_chain(origin),
        review_kind: DelegationReviewKind::RiskReview,
        question: question.to_owned(),
        work_lease_id: WorkLeaseId::new_v7(),
        evidence_refs: Vec::new(),
        preferred_provider: DelegationProviderPreference::Auto,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn forbidden_data(request: &DelegationRequest) -> bool {
    let joined =
        format!("{} {}", request.question, request.evidence_refs.join(" ")).to_ascii_lowercase();
    [
        "password",
        "private key",
        ".ssh",
        "credential",
        "secret value",
    ]
    .iter()
    .any(|needle| joined.contains(needle))
}

fn ensure_budget(state: &mut DelegationState, task_id: eliot_types::TaskId) -> usize {
    if let Some(index) = state
        .budgets
        .iter()
        .position(|budget| budget.task_id == task_id && budget.provider_id == "antigravity")
    {
        return index;
    }
    state
        .budgets
        .push(DelegationBudgetService.for_task(task_id));
    state.budgets.len() - 1
}

fn policy_denied_outcome(delegation_id: &str) -> eliot_types::DelegationOutcome {
    let mut outcome = DelegationOutcomeService.record(
        delegation_id,
        None,
        0,
        0,
        0,
        0,
        Vec::new(),
        false,
        0,
        0,
        false,
    );
    outcome.status = DelegationOutcomeStatus::PolicyDenied;
    outcome
}

pub(crate) fn load_work_state(root: &Path) -> Result<WorkState> {
    read_json_or_default(&root.join("reports/work/state.json"))
}

pub(crate) fn save_work_state(root: &Path, state: &WorkState) -> Result<()> {
    let dir = root.join("reports/work");
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(state)?;
    atomic_write_bytes(&dir.join("state.json"), json.as_bytes())?;
    atomic_write_bytes(
        &dir.join("state.md"),
        format!("# Work State\n\n```json\n{json}\n```\n").as_bytes(),
    )?;
    Ok(())
}

fn save_state_and_reports(
    root: &Path,
    state: &DelegationState,
    health: &DelegationHealth,
    execution: Option<&DelegationExecutionEvidence>,
) -> Result<()> {
    write_pair_at(&root.join("reports/delegation-state"), state)?;
    write_report_pair(root, "delegation-policy", &policy_report())?;
    write_report_pair(root, "delegation-health", health)?;
    write_report_pair(root, "delegation-decisions", &state.decisions)?;
    write_report_pair(root, "delegation-budgets", &state.budgets)?;
    write_report_pair(root, "delegation-jobs", &state.jobs)?;
    write_report_pair(root, "delegation-outcomes", &state.outcomes)?;
    write_report_pair(root, "delegation-shadow", &shadow_report(root)?)?;
    write_report_pair(root, "delegation", &DelegationReportService.summary(state))?;
    write_report_pair(
        root,
        "delegation-metrics",
        &delegation_metrics(state, execution),
    )?;
    if let Some(execution) = execution {
        write_report_pair(root, "delegation-execution", execution)?;
    }
    Ok(())
}

fn delegation_metrics(
    state: &DelegationState,
    execution: Option<&DelegationExecutionEvidence>,
) -> Value {
    let count_decisions = |kind: DelegationDecisionKind| {
        state
            .decisions
            .iter()
            .filter(|decision| decision.kind == kind)
            .count()
    };
    json!({
        "component": "delegation_metrics",
        "metrics": [
            { "name": "delegation_requests_total", "value": state.requests.len(), "labels": [] },
            { "name": "delegation_decisions_total", "value": state.decisions.len(), "labels": [] },
            { "name": "delegation_denials_total", "value": count_decisions(DelegationDecisionKind::Deny), "labels": [{"reason": "bounded"}] },
            { "name": "delegation_executions_total", "value": count_decisions(DelegationDecisionKind::Execute), "labels": [] },
            { "name": "delegation_shadow_recommendations_total", "value": count_decisions(DelegationDecisionKind::ShadowRecommend), "labels": [] },
            { "name": "delegation_recursion_denied_total", "value": state.decisions.iter().filter(|decision| decision.reasons.contains(&DelegationReason::RecursiveProviderCall)).count(), "labels": [] },
            { "name": "delegation_budget_denied_total", "value": state.decisions.iter().filter(|decision| decision.reasons.contains(&DelegationReason::BudgetExceeded)).count(), "labels": [] },
            { "name": "delegation_provider_failures_total", "value": state.outcomes.iter().filter(|outcome| outcome.status == DelegationOutcomeStatus::ProviderFailed).count(), "labels": [] },
            { "name": "delegation_outcomes_total", "value": state.outcomes.len(), "labels": [] },
            { "name": "delegation_unique_findings_total", "value": state.outcomes.iter().map(|outcome| u64::from(outcome.unique_findings)).sum::<u64>(), "labels": [] },
            { "name": "delegation_accepted_findings_total", "value": state.outcomes.iter().map(|outcome| u64::from(outcome.accepted_findings)).sum::<u64>(), "labels": [] },
            { "name": "delegation_duplicate_findings_total", "value": state.outcomes.iter().map(|outcome| u64::from(outcome.duplicate_findings)).sum::<u64>(), "labels": [] },
            { "name": "delegation_runtime_ms", "value": state.outcomes.iter().map(|outcome| outcome.actual_runtime_ms).sum::<u64>(), "labels": [] },
            { "name": "delegation_live_tree_violation_total", "value": u8::from(execution.is_some_and(|evidence| !evidence.live_tree_unchanged)), "labels": [] },
            { "name": "delegation_authority_violation_total", "value": execution.map_or(0, |evidence| evidence.authority_violation_count), "labels": [] },
            { "name": "delegation_recursive_execution_total", "value": 0, "labels": [] }
        ],
        "label_policy": "low_cardinality_only",
        "task_prompt_path_or_evidence_labels_present": false,
    })
}

fn delegation_state_path(root: &Path) -> PathBuf {
    root.join("reports/delegation-state/latest.json")
}

fn write_report_pair<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<()> {
    write_pair_at(&root.join("reports").join(name), value)
}

fn write_pair_at<T: Serialize>(dir: &Path, value: &T) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_string_pretty(value)?;
    atomic_write_bytes(&dir.join("latest.json"), json.as_bytes())?;
    atomic_write_bytes(
        &dir.join("latest.md"),
        format!("# Eliot Delegation Report\n\n```json\n{json}\n```\n").as_bytes(),
    )?;
    Ok(())
}

fn read_json_or_default<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Default,
{
    if !path.is_file() {
        return Ok(T::default());
    }
    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
}

fn read_json_value(path: &Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}:{}", WorkLeaseId::new_v7())
}

const fn default_provider() -> DelegationProviderPreference {
    DelegationProviderPreference::Auto
}
