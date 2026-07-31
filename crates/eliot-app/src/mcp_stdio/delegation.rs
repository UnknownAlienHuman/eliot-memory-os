//! Handing work to another agent, and taking its result back.
//!
//! A delegation is only safe if the same session that claims a job is the one
//! that may submit for it, and only a current controller lease may dispose of
//! what comes back. The session record, the capability checks and the job and
//! result tools are that one rule seen from four sides, so they share a module
//! -- splitting them by tool name would scatter the authority chain.

use super::*;

pub(super) fn record_agent_session(
    state: &McpState,
    context: AuthenticatedRequestContext,
    request: &Value,
) -> Result<Value> {
    let params = request.get("params").unwrap_or(&Value::Null);
    if let Some(requested_profile) = params.get("eliotProfile").and_then(Value::as_str)
        && requested_profile != state.profile.as_str()
    {
        anyhow::bail!(
            "initialize cannot widen handshake profile {} to {requested_profile}",
            state.profile.as_str()
        );
    }
    let client_info = params.get("clientInfo").unwrap_or(&Value::Null);
    let client_name = client_info
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown-mcp-client");
    let client_version = client_info
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let lower_client_name = client_name.to_ascii_lowercase();
    let client_kind = if lower_client_name.contains("antigravity") {
        "antigravity"
    } else if lower_client_name.contains("opencode") {
        "opencode"
    } else if lower_client_name.contains("claude") {
        "claude"
    } else if lower_client_name.contains("codex") {
        "codex"
    } else {
        "reference_or_other"
    };
    let host_binding = host_id_from_client_kind(client_kind)
        .map(|host_id| {
            let mut broker_state = delegation_runtime::load_state(&state.root)?;
            let binding = HostBrokerService.register_session(
                &mut broker_state,
                AgentSessionId::from_uuid(context.session_id.as_uuid()),
                host_id,
                client_name.to_owned(),
                context.session_id.to_string(),
                AgentCapabilityEnvelope {
                    capabilities: vec![
                        "mcp_stdio".to_owned(),
                        "proactive_memory".to_owned(),
                        "candidate_writeback".to_owned(),
                    ],
                    structured_output: true,
                    resumable: false,
                    interactive: true,
                    supervised: false,
                },
            )?;
            delegation_runtime::save_host_broker_state(&state.root, &broker_state)?;
            Ok::<_, anyhow::Error>(binding)
        })
        .transpose()?;
    let host_identity = host_binding.as_ref().map_or_else(
        || {
            json!({
                "host_id": client_kind,
                "implementation_name": client_name,
                "client_instance_id": context.session_id
            })
        },
        |binding| json!(&binding.host_identity),
    );
    let task_role_lease_refs = host_binding
        .as_ref()
        .map(|binding| binding.task_role_lease_refs.clone())
        .unwrap_or_default();
    let session = json!({
        "schema_version": "eliot-agent-session-v1",
        "agent_session_id": context.session_id,
        "client_name": client_name,
        "client_version": client_version,
        "client_kind": client_kind,
        "access_profile": state.profile.as_str(),
        "host_identity": host_identity,
        "task_role_lease_refs": task_role_lease_refs,
        "bound_project_id": context.bound_project_id.or_else(|| host_binding.as_ref().and_then(|binding| binding.bound_project_id)),
        "bound_task_id": context.bound_task_id.or_else(|| host_binding.as_ref().and_then(|binding| binding.bound_task_id)),
        "scope_defaulting": context.bound_project_id.is_some() && context.bound_task_id.is_some(),
        "authority_note": "host identity does not grant a task role or completion authority",
        "transport": "mcp_stdio_windows_named_pipe",
        "instance_name": &state.instance_name,
        "runtime_id": &state.runtime_id,
        "auth_generation": &state.auth_generation,
        "started_at": time::OffsetDateTime::now_utc().to_string()
    });
    atomic_write_json(
        &state
            .root
            .join("reports")
            .join("agent-sessions")
            .join(format!("{}.json", context.session_id)),
        &session,
    )?;
    Ok(session)
}

pub(super) fn host_id_from_client_kind(client_kind: &str) -> Option<AgentHostId> {
    match client_kind {
        "codex" => Some(AgentHostId::Codex),
        "antigravity" => Some(AgentHostId::Antigravity),
        "opencode" => Some(AgentHostId::OpenCode),
        "claude" | "claude-desktop" => Some(AgentHostId::Claude),
        _ => None,
    }
}

pub(super) fn dispatch_host_session_status(
    state: &McpState,
    context: AuthenticatedRequestContext,
) -> Result<Value> {
    let agent_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let broker_state = delegation_runtime::load_state(&state.root)?;
    let binding = broker_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == agent_session_id);
    let now = time::OffsetDateTime::now_utc();
    let active_role_leases = broker_state
        .task_role_leases
        .iter()
        .filter(|lease| lease.agent_session_id == agent_session_id && lease.expires_at > now)
        .cloned()
        .collect::<Vec<_>>();
    let active_controller_leases = broker_state
        .controller_leases
        .iter()
        .filter(|lease| lease.agent_session_id == agent_session_id && lease.expires_at > now)
        .cloned()
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": "eliot-host-session-status-v2",
        "agent_session_id": agent_session_id,
        "access_profile": state.profile.as_str(),
        "binding": binding,
        "bound_project_id": context.bound_project_id.or_else(|| binding.and_then(|binding| binding.bound_project_id)),
        "bound_task_id": context.bound_task_id.or_else(|| binding.and_then(|binding| binding.bound_task_id)),
        "scope_status": if context.bound_project_id.is_some() && context.bound_task_id.is_some() {
            "governor_bound_scope_active"
        } else {
            "unbound_session"
        },
        "active_task_role_leases": active_role_leases,
        "active_controller_leases": active_controller_leases,
        "role_status": if active_role_leases.is_empty() { "no_task_role_granted" } else { "task_role_lease_active" },
        "authority_note": "Host identity and legacy Antigravity connector history do not grant a task role. Only active_task_role_leases above are authoritative for this session."
    }))
}

pub(super) fn authorize_dynamic_delegation(
    state: &McpState,
    context: AuthenticatedRequestContext,
    input: &delegation_runtime::DelegationReviewInput,
) -> Result<()> {
    if state.profile != McpAccessProfile::DynamicAgent {
        return Ok(());
    }
    let task_id = TaskId::from_str(&input.task_id).context("parse delegation task_id")?;
    let work_lease_id =
        WorkLeaseId::from_str(&input.work_lease_id).context("parse delegation work_lease_id")?;
    let work_state = delegation_runtime::load_work_state(&state.root)?;
    let work_lease_matches = work_state.leases.iter().any(|lease| {
        lease.work_lease_id == work_lease_id
            && lease.task_id == task_id
            && eliot_engine::work_lease_is_active(lease)
    });
    if !work_lease_matches {
        anyhow::bail!("dynamic delegation requires an active WorkLease for the requested task");
    }
    let agent_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let broker_state = delegation_runtime::load_state(&state.root)?;
    let now = time::OffsetDateTime::now_utc();
    let controller_active = broker_state.controller_leases.iter().any(|lease| {
        lease.task_id == task_id
            && lease.agent_session_id == agent_session_id
            && lease.expires_at > now
    });
    let delegation_capability_active = broker_state.task_role_leases.iter().any(|lease| {
        lease.task_id == task_id
            && lease.agent_session_id == agent_session_id
            && lease.role == AgentRole::Controller
            && lease.capability_scope.iter().any(|item| item == "delegate")
            && lease.expires_at > now
    });
    if !controller_active || !delegation_capability_active {
        anyhow::bail!(
            "dynamic delegation requires an active ControllerLease and delegate capability for the authenticated session"
        );
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one delegation admission state machine validates and persists the complete authority transition"
)]
pub(super) async fn dispatch_agent_delegate(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentDelegateToolInput = serde_json::from_value(arguments)?;
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    validate_broker_text("expected_result_kind", &input.expected_result_kind, 160)?;
    validate_broker_text("verifier_ref", &input.verifier_ref, 512)?;
    validate_broker_refs("packet_refs", &input.packet_refs)?;
    validate_broker_refs("requested_capabilities", &input.requested_capabilities)?;
    if input.requested_capabilities.is_empty() {
        anyhow::bail!("requested_capabilities must contain at least one capability");
    }
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task_id")?;
    let work_item_id = WorkItemId::from_str(&input.work_item_id).context("parse work_item_id")?;
    let work_lease_id =
        WorkLeaseId::from_str(&input.work_lease_id).context("parse target work_lease_id")?;
    let caller_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let now = time::OffsetDateTime::now_utc();
    let mut broker_state = delegation_runtime::load_state(&state.root)?;
    require_controller_capability(&broker_state, caller_session_id, task_id, "delegate", now)?;
    let target_role = broker_state
        .task_role_leases
        .iter()
        .find(|lease| {
            lease.role_lease_id == input.target_role_lease_id
                && lease.task_id == task_id
                && lease.state == eliot_types::AuthorityLeaseState::Active
                && lease.expires_at > now
        })
        .cloned()
        .context("target TaskRoleLease is missing, expired, or for another task")?;
    if target_role.role == AgentRole::Controller {
        anyhow::bail!("delegation target must not reuse the task ControllerLease");
    }
    let target_binding = broker_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == target_role.agent_session_id)
        .cloned()
        .context("target TaskRoleLease has no host binding")?;
    if target_binding.state != eliot_types::AgentSessionState::Active
        || target_binding.generation != target_role.generation
    {
        anyhow::bail!("target TaskRoleLease owner session is inactive or stale");
    }
    if target_binding.host_identity.host_id != input.target_host {
        anyhow::bail!("target_host does not match the target TaskRoleLease binding");
    }
    let work_state = delegation_runtime::load_work_state(&state.root)?;
    let work_lease_active = work_state.leases.iter().any(|lease| {
        lease.work_lease_id == work_lease_id
            && lease.work_item_id == work_item_id
            && lease.task_id == task_id
            && lease.project_id == project_id
            && lease.agent_session_id == target_role.agent_session_id
            && eliot_engine::work_lease_is_active(lease)
    });
    if !work_lease_active {
        anyhow::bail!(
            "delegation requires an active target-owned WorkLease matching project/task/work item"
        );
    }
    let invocation_id = format!(
        "agent-invocation:{}",
        blake3::hash(input.idempotency_key.as_bytes()).to_hex()
    );
    let request = AgentInvocationRequest {
        invocation_id,
        project_id,
        task_id,
        work_item_id,
        requested_capabilities: input.requested_capabilities,
        role_lease_id: input.target_role_lease_id,
        role_lease_epoch: target_role.epoch,
        operation_generation: target_role.generation,
        runtime_contract_sha256: None,
        work_lease_id: Some(work_lease_id),
        packet_refs: input.packet_refs,
        expected_result_kind: input.expected_result_kind,
        verifier_ref: input.verifier_ref,
        idempotency_key: input.idempotency_key,
    };
    let profile = HostProfileService
        .probe(input.target_host)
        .unwrap_or_else(|_| HostProfileService.connected(&target_binding));
    let job = HostBrokerService.enqueue(&mut broker_state, &request, &profile, true)?;
    let (canonical_receipt, write_status) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AgentInvocationRequest,
        &format!("agent-invocation-request:{}", request.invocation_id),
        &request,
    )
    .await?;
    delegation_runtime::save_host_broker_state(&state.root, &broker_state)?;
    Ok(json!({
        "schema_version": "eliot-agent-delegation-v1",
        "request": request,
        "job": job,
        "canonical_receipt": canonical_receipt,
        "write_status": write_status,
        "controller_session_id": caller_session_id,
        "target_session_id": target_role.agent_session_id,
        "candidate_only": true,
        "admin_authority_granted": false
    }))
}

pub(super) fn dispatch_agent_job_claim(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentInvocationRefToolInput = serde_json::from_value(arguments)?;
    let mut broker_state = delegation_runtime::load_state(&state.root)?;
    let request = broker_state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == input.invocation_id)
        .cloned()
        .context("AgentInvocationRequest not found")?;
    let binding = require_invocation_target(&broker_state, context, &request)?;
    let job_index = broker_state
        .operation_jobs
        .iter()
        .position(|job| job.invocation_id == request.invocation_id)
        .context("OperationJob not found")?;
    if broker_state.operation_jobs[job_index].state == OperationJobState::Queued {
        HostBrokerService.transition(
            &mut broker_state.operation_jobs[job_index],
            OperationJobState::Running,
            Some(binding.host_identity.client_instance_id.clone()),
        )?;
    } else if broker_state.operation_jobs[job_index].state != OperationJobState::Running {
        anyhow::bail!("only a queued or already-running OperationJob can be claimed");
    }
    let job = broker_state.operation_jobs[job_index].clone();
    delegation_runtime::save_host_broker_state(&state.root, &broker_state)?;
    Ok(json!({
        "schema_version": "eliot-agent-job-claim-v1",
        "request": request,
        "job": job,
        "claimed_by": binding.agent_session_id,
        "admin_authority_granted": false
    }))
}

pub(super) async fn dispatch_agent_result_submit(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentResultSubmitToolInput = serde_json::from_value(arguments)?;
    validate_broker_text("result_id", &input.result_id, 256)?;
    validate_broker_text("summary", &input.summary, 4_000)?;
    validate_broker_refs("artifact_refs", &input.artifact_refs)?;
    validate_broker_refs("evidence_refs", &input.evidence_refs)?;
    validate_broker_refs("verifier_refs", &input.verifier_refs)?;
    validate_broker_refs(
        "unknown_outcome_evidence_refs",
        &input.unknown_outcome_evidence_refs,
    )?;
    if input.status == AgentResultStatus::UnknownOutcome
        && input.unknown_outcome_evidence_refs.is_empty()
    {
        anyhow::bail!("unknown_outcome requires explicit reconciliation evidence refs");
    }
    if input.status != AgentResultStatus::UnknownOutcome
        && !input.unknown_outcome_evidence_refs.is_empty()
    {
        anyhow::bail!("unknown outcome evidence is valid only for unknown_outcome status");
    }
    let mut broker_state = delegation_runtime::load_state(&state.root)?;
    let request = broker_state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == input.invocation_id)
        .cloned()
        .context("AgentInvocationRequest not found")?;
    let binding = require_invocation_target(&broker_state, context, &request)?;
    let mut artifact_refs = input.artifact_refs;
    append_candidate_diff_authority_ref(&state.root, &mut artifact_refs)?;
    let result = AgentResultEnvelope {
        result_id: input.result_id,
        invocation_id: request.invocation_id,
        host_id: binding.host_identity.host_id,
        host_session_id: Some(binding.host_identity.client_instance_id),
        status: input.status,
        role_lease_epoch: request.role_lease_epoch,
        operation_generation: request.operation_generation,
        summary: input.summary,
        artifact_refs,
        evidence_refs: input.evidence_refs,
        verifier_refs: input.verifier_refs,
        candidate_only: true,
        exit_status: input.exit_status,
        token_or_cost_telemetry: input.token_or_cost_telemetry,
        unknown_outcome_evidence_refs: input.unknown_outcome_evidence_refs,
        supersedes_result_id: None,
        provider_output_hash: None,
        canonical_receipt: None,
    };
    let admission = HostBrokerService.record_result(&mut broker_state, result)?;
    let mut result = match admission {
        eliot_engine::AgentResultAdmission::Accepted(result) => result,
        eliot_engine::AgentResultAdmission::StaleEvidencePreserved(_) => {
            delegation_runtime::save_host_broker_state(&state.root, &broker_state)?;
            anyhow::bail!(
                "stale role epoch or operation generation result preserved as evidence but rejected as current"
            );
        }
    };
    if result.canonical_receipt.is_none() {
        let (receipt, _) = write_canonical_observation(
            state,
            context,
            request.project_id,
            Some(request.task_id),
            CanonicalReceiptKind::AgentResult,
            &format!("agent-result-submit:{}", result.result_id),
            &result,
        )
        .await?;
        let latest = state
            .store
            .latest_authority_observations_by_entity(
                request.project_id,
                Some(request.task_id),
                "agent_result",
                &result.result_id,
            )
            .await?;
        if latest.is_empty() {
            anyhow::bail!("canonical AgentResult was not queryable after commit");
        }
        result.canonical_receipt = Some(receipt);
        replace_finalized_agent_result(&mut broker_state, result.clone())?;
    }
    delegation_runtime::save_host_broker_state(&state.root, &broker_state)?;
    Ok(json!({
        "schema_version": "eliot-agent-result-submit-v1",
        "result": result,
        "candidate_only": true,
        "completion_authority_granted": false
    }))
}

pub(super) fn dispatch_agent_job_status(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentInvocationRefToolInput = serde_json::from_value(arguments)?;
    let broker_state = delegation_runtime::load_state(&state.root)?;
    let request = broker_state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == input.invocation_id)
        .context("AgentInvocationRequest not found")?;
    require_task_participant(&broker_state, context, request.task_id)?;
    let job = broker_state
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == request.invocation_id)
        .context("OperationJob not found")?;
    let result = broker_state
        .agent_results
        .iter()
        .find(|result| result.invocation_id == request.invocation_id);
    let dispositions = broker_state
        .agent_result_dispositions
        .iter()
        .filter(|item| item.invocation_id == request.invocation_id)
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": "eliot-agent-job-status-v1",
        "request": request,
        "job": job,
        "result": result,
        "dispositions": dispositions
    }))
}

pub(super) fn dispatch_agent_result(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentResultRefToolInput = serde_json::from_value(arguments)?;
    let broker_state = delegation_runtime::load_state(&state.root)?;
    let result = broker_state
        .agent_results
        .iter()
        .find(|result| result.result_id == input.result_id)
        .context("AgentResultEnvelope not found")?;
    let request = broker_state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == result.invocation_id)
        .context("AgentInvocationRequest not found")?;
    require_task_participant(&broker_state, context, request.task_id)?;
    let dispositions = broker_state
        .agent_result_dispositions
        .iter()
        .filter(|item| item.result_id == result.result_id)
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": "eliot-agent-result-v1",
        "request": request,
        "result": result,
        "dispositions": dispositions,
        "candidate_only": true
    }))
}

pub(super) async fn dispatch_agent_result_disposition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AgentResultDispositionToolInput = serde_json::from_value(arguments)?;
    validate_broker_text("reason", &input.reason, 2_000)?;
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    validate_broker_refs("evidence_refs", &input.evidence_refs)?;
    let controller_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let mut broker_state = delegation_runtime::load_state(&state.root)?;
    let mut disposition = HostBrokerService.disposition_result(
        &mut broker_state,
        controller_session_id,
        &input.result_id,
        input.kind,
        input.reason,
        input.evidence_refs,
        input.idempotency_key,
    )?;
    if disposition.canonical_receipt.is_none() {
        let request = broker_state
            .agent_invocations
            .iter()
            .find(|request| request.invocation_id == disposition.invocation_id)
            .context("AgentResultDisposition lost its invocation authority")?;
        let (receipt, _) = write_canonical_observation(
            state,
            context,
            request.project_id,
            Some(request.task_id),
            CanonicalReceiptKind::AgentResultDisposition,
            &format!("agent-result-disposition:{}", disposition.idempotency_key),
            &disposition,
        )
        .await?;
        disposition.canonical_receipt = Some(receipt);
        let stored = broker_state
            .agent_result_dispositions
            .iter_mut()
            .find(|item| item.disposition_id == disposition.disposition_id)
            .context("AgentResultDisposition disappeared before receipt binding")?;
        *stored = disposition.clone();
    }
    delegation_runtime::save_host_broker_state(&state.root, &broker_state)?;
    Ok(json!({
        "schema_version": "eliot-agent-result-disposition-v1",
        "disposition": disposition,
        "model_output_promoted": false,
        "completion_authority_granted": false
    }))
}

pub(super) fn require_controller_capability(
    broker_state: &eliot_types::DelegationState,
    agent_session_id: AgentSessionId,
    task_id: TaskId,
    capability: &str,
    now: time::OffsetDateTime,
) -> Result<()> {
    let controller_active = broker_state.controller_leases.iter().any(|lease| {
        lease.task_id == task_id
            && lease.agent_session_id == agent_session_id
            && lease.expires_at > now
    });
    let role_active = broker_state.task_role_leases.iter().any(|lease| {
        lease.task_id == task_id
            && lease.agent_session_id == agent_session_id
            && lease.role == AgentRole::Controller
            && lease.capability_scope.iter().any(|item| item == capability)
            && lease.expires_at > now
    });
    if !controller_active || !role_active {
        anyhow::bail!(
            "operation requires the authenticated task ControllerLease and {capability} capability"
        );
    }
    Ok(())
}

pub(super) fn require_invocation_target(
    broker_state: &eliot_types::DelegationState,
    context: AuthenticatedRequestContext,
    request: &AgentInvocationRequest,
) -> Result<eliot_types::AgentSessionHostBinding> {
    let agent_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let now = time::OffsetDateTime::now_utc();
    let target_role = broker_state
        .task_role_leases
        .iter()
        .find(|lease| {
            lease.role_lease_id == request.role_lease_id
                && lease.task_id == request.task_id
                && lease.agent_session_id == agent_session_id
                && lease.expires_at > now
        })
        .context("authenticated session does not hold the invocation TaskRoleLease")?;
    for capability in &request.requested_capabilities {
        if !target_role.capability_scope.contains(capability) {
            anyhow::bail!("invocation capability is outside the active target TaskRoleLease");
        }
    }
    broker_state
        .agent_host_sessions
        .iter()
        .find(|binding| binding.agent_session_id == agent_session_id)
        .cloned()
        .context("invocation target has no host binding")
}

pub(super) fn require_task_participant(
    broker_state: &eliot_types::DelegationState,
    context: AuthenticatedRequestContext,
    task_id: TaskId,
) -> Result<()> {
    let agent_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let now = time::OffsetDateTime::now_utc();
    if broker_state.task_role_leases.iter().any(|lease| {
        lease.task_id == task_id
            && lease.agent_session_id == agent_session_id
            && lease.expires_at > now
    }) {
        Ok(())
    } else {
        anyhow::bail!("authenticated session has no active task role for this broker record")
    }
}

pub(super) fn validate_broker_text(field: &str, value: &str, max_len: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_len {
        anyhow::bail!("{field} must be nonempty and at most {max_len} bytes");
    }
    Ok(())
}

pub(super) fn validate_broker_refs(field: &str, values: &[String]) -> Result<()> {
    if values.len() > 64
        || values
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > 512)
    {
        anyhow::bail!("{field} must contain at most 64 nonempty refs of at most 512 bytes");
    }
    Ok(())
}
