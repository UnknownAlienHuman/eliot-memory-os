//! The Operator projection surface.
//!
//! The Operator is a separate application with its own contract, reading the
//! canonical store through projections rather than through the governed agent
//! tools. It shares the store and nothing else, which is why it lives apart
//! from the tool dispatch it was tangled with.

use super::*;

pub(super) fn read_operator_cursor_signing_key(
    path: &Path,
) -> Result<[u8; OPERATOR_CURSOR_SIGNING_KEY_BYTES]> {
    let bytes = fs::read(path).context("read operator cursor signing key")?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "operator cursor signing key must contain exactly {OPERATOR_CURSOR_SIGNING_KEY_BYTES} bytes, found {}",
            bytes.len()
        )
    })
}

pub(super) fn load_or_create_operator_cursor_signing_key_file(
    instance: &RuntimeInstance,
) -> Result<[u8; OPERATOR_CURSOR_SIGNING_KEY_BYTES]> {
    let secret_dir = instance.runtime_dir().join("secrets");
    fs::create_dir_all(&secret_dir).context("create operator runtime secret directory")?;
    named_pipe_ipc::restrict_owned_directory_to_current_user(&secret_dir)?;
    let key_path = secret_dir.join(OPERATOR_CURSOR_SIGNING_KEY_FILE);
    match read_operator_cursor_signing_key(&key_path) {
        Ok(key) => Ok(key),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            let mut key = [0_u8; OPERATOR_CURSOR_SIGNING_KEY_BYTES];
            key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)
            {
                Ok(mut file) => {
                    file.write_all(&key)
                        .context("write operator cursor signing key")?;
                    file.flush().context("flush operator cursor signing key")?;
                    file.sync_all()
                        .context("sync operator cursor signing key")?;
                    Ok(key)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    read_operator_cursor_signing_key(&key_path)
                }
                Err(error) => Err(error).context("create operator cursor signing key"),
            }
        }
        Err(error) => Err(error),
    }
}

pub(super) fn load_or_create_operator_cursor_signing_key(
    instance: &RuntimeInstance,
) -> Result<[u8; OPERATOR_CURSOR_SIGNING_KEY_BYTES]> {
    if cfg!(test) || std::env::var(LEGACY_OPERATOR_CURSOR_TEST_OVERRIDE).as_deref() == Ok("1") {
        return load_or_create_operator_cursor_signing_key_file(instance);
    }

    let credential_id = format!("operator-cursor/{}", instance.name());
    if let Some(bytes) = eliot_windows_ipc::credential_read_current_user(&credential_id)? {
        return bytes.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!(
                "operator cursor credential must contain exactly {OPERATOR_CURSOR_SIGNING_KEY_BYTES} bytes, found {}",
                bytes.len()
            )
        });
    }

    let mut generated = [0_u8; OPERATOR_CURSOR_SIGNING_KEY_BYTES];
    generated[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    generated[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    eliot_windows_ipc::credential_write_current_user(&credential_id, &generated)?;
    let persisted = eliot_windows_ipc::credential_read_current_user(&credential_id)?
        .context("operator cursor credential write did not persist")?;
    if persisted.as_slice() != generated {
        anyhow::bail!("operator cursor credential readback differs from generated value");
    }
    persisted.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "operator cursor credential must contain exactly {OPERATOR_CURSOR_SIGNING_KEY_BYTES} bytes, found {}",
            bytes.len()
        )
    })
}

pub(super) fn dispatch_operator_contract() -> Result<Value> {
    Ok(json!({
        "schema_version": OPERATOR_SCHEMA_VERSION,
        "ipc_protocol_version": OPERATOR_IPC_PROTOCOL_VERSION,
        "protocol_hash": operator_contract_hash(),
        "manifest": serde_json::from_str::<Value>(OPERATOR_CONTRACT_MANIFEST)?,
    }))
}

pub(super) async fn operator_run_views(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<(Vec<eliot_types::AutonomyRunView>, Vec<String>)> {
    let contracts = cognitive_records::<AutonomyRunContract>(
        state,
        project_id,
        task_id,
        "autonomy_run_contract",
    )
    .await?;
    let mut runs = Vec::new();
    let mut events = Vec::new();
    for contract in contracts {
        let loaded =
            load_bounded_autonomy_runtime(state, project_id, task_id, &contract.autonomy_run_id)
                .await?;
        events.extend(
            loaded
                .runtime
                .transition_receipts
                .iter()
                .map(|transition| transition.transition_id.clone()),
        );
        events.extend(
            loaded
                .runtime
                .recovery_receipts
                .iter()
                .map(|recovery| recovery.recovery_id.clone()),
        );
        runs.push(autonomy_run_projection(&loaded));
    }
    Ok((runs, events))
}

pub(super) async fn operator_approval_views(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<Vec<ApprovalView>> {
    let request_records = state
        .store
        .canonical_record_page(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalRequest.as_str()],
            0,
            100,
        )
        .await?;
    let mut approvals = Vec::new();
    for record in request_records {
        let request: AutonomyApprovalRequestRecord = serde_json::from_value(record.receipt_body)?;
        if request.project_id != project_id || request.task_id != task_id {
            continue;
        }
        let decision = state
            .store
            .canonical_record_by_write_id::<AutonomyApprovalDecisionRecord>(
                project_id,
                Some(task_id),
                &[CanonicalReceiptKind::AutonomyApprovalDecision.as_str()],
                approval_decision_write_id(project_id, task_id, &request.approval_id),
            )
            .await?;
        let reason_summary = decision.as_ref().map_or_else(
            || "R3 completion request awaiting exact HumanOperator decision".to_owned(),
            |decision| {
                format!(
                    "{:?}: {}",
                    decision.receipt_body.decision, decision.receipt_body.reason
                )
            },
        );
        approvals.push(ApprovalView {
            approval_id: request.approval_id,
            exact_action_hash: request.exact_action_hash,
            risk_tier: "R3".to_owned(),
            write_or_resource_set: vec![
                format!("autonomy-run:{}", request.autonomy_run_id),
                format!("task:{}", request.task_id),
            ],
            reason_summary,
            verifier: "canonical HumanOperator decision with exact-hash and revision CAS"
                .to_owned(),
            rollback_or_compensation:
                "decision is immutable; grant remains single-use until canonical consumption"
                    .to_owned(),
            expires_at: request.expires_at,
            decision_receipt: decision
                .map(|decision| decision.canonical_receipt.receipt_id.to_string()),
        });
    }
    approvals.extend(
        semantic_records::<OperatorControlRequest>(state, project_id, "operator_control_request")
            .await?
            .into_iter()
            .filter(|request| {
                request.task_id == task_id
                    && matches!(
                        request.operation.as_str(),
                        "grant_approval" | "deny_approval"
                    )
                    && !request.target_ref.starts_with("autonomy-approval:")
            })
            .map(|request| ApprovalView {
                approval_id: request.target_ref,
                exact_action_hash: request.exact_action_hash.unwrap_or_default(),
                risk_tier: "request_only".to_owned(),
                write_or_resource_set: Vec::new(),
                reason_summary: request.disposition,
                verifier: "unsupported approval class; no authority mutation".to_owned(),
                rollback_or_compensation: "request record is informational and non-consuming"
                    .to_owned(),
                expires_at: request.created_at + time::Duration::hours(24),
                decision_receipt: Some(request.request_id),
            }),
    );
    Ok(approvals)
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_operator_snapshot(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: OperatorSnapshotToolInput = serde_json::from_value(arguments)?;
    let focus = match (input.project_id, input.task_id) {
        (None, None) => None,
        (Some(project_id), Some(task_id)) => Some((
            parse_project_id(&project_id)?,
            TaskId::from_str(&task_id).context("parse operator task_id")?,
        )),
        _ => anyhow::bail!("project_id and task_id must be provided together"),
    };

    let mut task_cognition = Vec::new();
    let mut memory_inspector = None;
    let mut runs = Vec::new();
    let mut timeline_event_refs = Vec::new();
    if let Some((project_id, task_id)) = focus {
        let task = state
            .store
            .task_contract_by_id(task_id)
            .await?
            .context("operator task does not exist")?;
        if task.project_id != project_id {
            anyhow::bail!("operator task belongs to a different project");
        }
        let current_state = ReadService::new(state.store.clone())
            .current_state(&CurrentStateRequest {
                project_id,
                consistency: ReadConsistencyMode::Latest,
                at_least_revision: None,
            })
            .await?;
        let packet = latest_task_packet(state, task_id)?;
        let outcomes = cognitive_records::<UnderstandingOutcomeRecord>(
            state,
            project_id,
            task_id,
            "understanding_outcome_record",
        )
        .await?;
        let influence = cognitive_records::<MemoryInfluenceTrace>(
            state,
            project_id,
            task_id,
            "memory_influence_trace",
        )
        .await?;
        let cargo = cognitive_records::<eliot_types::ContextCargoReceipt>(
            state,
            project_id,
            task_id,
            "context_cargo_receipt",
        )
        .await?;
        let experience_cases = deduplicate_experience_cases(
            semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?,
        );
        let experience_patterns = deduplicate_experience_patterns(
            semantic_records::<ExperiencePattern>(state, project_id, "experience_pattern").await?,
        );
        let applicability_decisions = semantic_records::<eliot_types::MemoryApplicabilityDecision>(
            state,
            project_id,
            "memory_applicability_decision",
        )
        .await?;
        let negative_transfer = semantic_records::<eliot_types::NegativeTransferRecord>(
            state,
            project_id,
            "negative_transfer_record",
        )
        .await?;
        let cognitive_lab_results = semantic_records::<eliot_types::CognitiveTransferLabReport>(
            state,
            project_id,
            "cognitive_transfer_lab_report",
        )
        .await?;
        let failure_localization = semantic_records::<CognitiveFailureLocalizationReport>(
            state,
            project_id,
            "cognitive_failure_localization_report",
        )
        .await?;
        let corpus_profile = serde_json::from_value::<eliot_types::MemoryCorpusProfile>(
            dispatch_memory_corpus_profile(state, json!({"project_id": project_id.to_string()}))
                .await?,
        )?;
        let decisions = packet
            .as_ref()
            .map_or_else(Vec::new, |packet| packet.memory_decisions.clone());
        let selected_memory = decisions
            .iter()
            .filter(|decision| {
                !matches!(
                    decision.admission,
                    eliot_types::MemoryAdmissionDecision::SuppressStale
                        | eliot_types::MemoryAdmissionDecision::SuppressWrongScope
                        | eliot_types::MemoryAdmissionDecision::RejectTainted
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let suppressed_memory = decisions
            .iter()
            .filter(|decision| !selected_memory.contains(decision))
            .cloned()
            .collect::<Vec<_>>();
        let task_meaning = packet.as_ref().map(|packet| TaskMeaningFrame {
            task_id: task_id.to_string(),
            user_goal: packet.goal.clone(),
            normalized_goal: packet.goal.clone(),
            desired_state_transition: packet.decision_locality_suffix.next_allowed_action.clone(),
            current_evidence: packet.exact_handles.clone(),
            material_unknowns: packet.decision_locality_suffix.open_unknowns.clone(),
            predicted_observable: packet.decision_locality_suffix.expected_observable.clone(),
            verifier_need: packet.decision_locality_suffix.verifier.clone(),
            ..TaskMeaningFrame::default()
        });
        task_cognition.push(TaskCognitionView {
            task_contract: task,
            task_meaning,
            active_decision_state: packet
                .as_ref()
                .map(|packet| eliot_types::ActiveDecisionState {
                    task_id,
                    packet_id: packet.packet_id.clone(),
                    revision_fence: packet.at_revision,
                    selected_owner_or_module: outcomes
                        .last()
                        .map(|outcome| outcome.selected_owner_or_module.clone()),
                    next_allowed_action: packet
                        .decision_locality_suffix
                        .next_allowed_action
                        .clone(),
                    expected_observable: packet
                        .decision_locality_suffix
                        .expected_observable
                        .clone(),
                    verifier: packet.decision_locality_suffix.verifier.clone(),
                    stop_condition: packet.decision_locality_suffix.stop_condition.clone(),
                    killed_paths: packet.killed_paths.clone(),
                    open_unknowns: packet.decision_locality_suffix.open_unknowns.clone(),
                }),
            current_truth: current_state.verified_now.clone(),
            epistemic_state: packet
                .as_ref()
                .map_or_else(eliot_types::EpistemicPacketState::default, |packet| {
                    packet.epistemic_state.clone()
                }),
            causal_bridge: packet
                .as_ref()
                .map_or_else(Vec::new, |packet| packet.causal_bridge.clone()),
            experience_priors: packet
                .as_ref()
                .map_or_else(Vec::new, |packet| packet.experience_priors.clone()),
            negative_memory: packet
                .as_ref()
                .map_or_else(Vec::new, |packet| packet.negative_memory.clone()),
            selected_memory: selected_memory.clone(),
            suppressed_memory: suppressed_memory.clone(),
            procedural_skills: packet
                .as_ref()
                .map_or_else(eliot_types::ProceduralSkillPacketView::default, |packet| {
                    packet.procedural_skills.clone()
                }),
            packet_quality: packet
                .as_ref()
                .and_then(|packet| packet.packet_quality.clone()),
            understanding_outcomes: outcomes,
            completion_proof: None,
        });
        memory_inspector = Some(MemoryInspectorView {
            project_id,
            active_current_claim_refs: current_state
                .verified_now
                .iter()
                .map(|claim| format!("claim:{}", claim.claim_id))
                .collect(),
            recalled_candidate_refs: packet.as_ref().map_or_else(Vec::new, |packet| {
                packet
                    .relevant_supported_claims
                    .iter()
                    .chain(&packet.weak_claims_warning)
                    .map(|claim| format!("claim:{}", claim.claim_id))
                    .collect()
            }),
            stale_or_superseded_refs: suppressed_memory
                .iter()
                .map(|decision| decision.memory_handle.clone())
                .collect(),
            support_and_counterevidence_refs: packet
                .as_ref()
                .map_or_else(Vec::new, |packet| packet.exact_handles.clone()),
            decisions,
            influence,
            cargo,
            lifecycle: packet
                .as_ref()
                .map_or_else(eliot_types::MemoryLifecyclePacketView::default, |packet| {
                    packet.memory_lifecycle.clone()
                }),
            experience_cases,
            experience_patterns,
            applicability_decisions,
            negative_transfer,
            cognitive_lab_results,
            failure_localization,
            corpus_profile: Some(corpus_profile),
        });
        let (run_views, run_events) = operator_run_views(state, project_id, task_id).await?;
        runs = run_views;
        timeline_event_refs.extend(run_events);
    }

    let broker_state = delegation_runtime::load_state(&state.root)?;
    let work_state = delegation_runtime::load_work_state(&state.root)?;
    let focused_task = focus.map(|(_, task_id)| task_id);
    let task_role_leases = broker_state
        .task_role_leases
        .iter()
        .filter(|lease| focused_task.is_none_or(|task_id| lease.task_id == task_id))
        .cloned()
        .collect::<Vec<_>>();
    let controller_leases = broker_state
        .controller_leases
        .iter()
        .filter(|lease| focused_task.is_none_or(|task_id| lease.task_id == task_id))
        .cloned()
        .collect::<Vec<_>>();
    let work_items = work_state
        .work_items
        .iter()
        .filter(|item| focused_task.is_none_or(|task_id| item.task_id == task_id))
        .cloned()
        .collect::<Vec<_>>();
    let focused_work_ids = work_items
        .iter()
        .map(|item| item.work_item_id)
        .collect::<std::collections::BTreeSet<_>>();
    let work_leases = work_state
        .leases
        .iter()
        .filter(|lease| focused_task.is_none() || focused_work_ids.contains(&lease.work_item_id))
        .cloned()
        .collect::<Vec<_>>();
    let worktree_leases = work_state
        .worktree_leases
        .iter()
        .filter(|lease| focused_task.is_none_or(|task_id| lease.task_id == task_id))
        .cloned()
        .collect::<Vec<_>>();
    let work_conflicts = work_state
        .conflicts
        .iter()
        .filter(|conflict| {
            focused_task.is_none() || focused_work_ids.contains(&conflict.work_item_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    let focused_invocations = broker_state
        .agent_invocations
        .iter()
        .filter(|invocation| focused_task.is_none_or(|task_id| invocation.task_id == task_id))
        .map(|invocation| invocation.invocation_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let operation_jobs = broker_state
        .operation_jobs
        .iter()
        .filter(|job| {
            focused_task.is_none() || focused_invocations.contains(job.invocation_id.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    let agent_results = broker_state
        .agent_results
        .iter()
        .filter(|result| focused_invocations.contains(result.invocation_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let focused_result_ids = agent_results
        .iter()
        .map(|result| result.result_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let agent_result_dispositions = broker_state
        .agent_result_dispositions
        .iter()
        .filter(|disposition| focused_result_ids.contains(disposition.result_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let route_policies = runs
        .iter()
        .map(|run| eliot_types::ContourRoutePolicy {
            policy_id: run.contract.contour_route_policy_ref.clone(),
            scope: eliot_types::ContourPolicyScope::Task,
            project_id: Some(run.contract.project_id),
            task_id: Some(run.contract.root_task_id),
            contour: eliot_types::ResponsibilityContour::Implementation,
            preferred_routes: run.contract.fallback_routes.clone(),
            allowed_fallbacks: run.contract.fallback_routes.clone(),
            deterministic_adapter_preference: false,
            max_parallelism: run.contract.max_active_agents,
            cost_or_token_budget: run.contract.cost_or_token_budget.clone(),
            wall_time_budget_seconds: run.contract.max_wall_time_seconds,
            required_evidence: run.contract.acceptance_items.clone(),
            required_verifier: run.contract.required_verifiers.clone(),
            escalation_route: run.contract.fallback_routes.last().cloned(),
            effective_from: run.contract.created_at,
            expires_at: None,
            policy_snapshot_id: run.contract.policy_snapshot_id.clone(),
            owner: run.contract.created_by.clone(),
        })
        .collect::<Vec<_>>();
    let route_decisions = broker_state
        .agent_invocations
        .iter()
        .filter(|invocation| focused_task.is_none_or(|task_id| invocation.task_id == task_id))
        .filter_map(|invocation| {
            let job = operation_jobs
                .iter()
                .find(|job| job.invocation_id == invocation.invocation_id)?;
            let host_id = format!("{:?}", job.host_id).to_ascii_lowercase();
            let run = runs
                .iter()
                .find(|run| run.contract.root_task_id == invocation.task_id);
            let candidate_routes = run
                .map(|run| run.contract.fallback_routes.clone())
                .unwrap_or_default();
            let selected_route = candidate_routes
                .iter()
                .find(|route| route.host_id.eq_ignore_ascii_case(&host_id))
                .cloned()
                .unwrap_or_else(|| eliot_types::ContourPreferredRoute {
                    host_id,
                    model_route_optional: None,
                    requested_role: "implementer".to_owned(),
                    capability_requirements: invocation.requested_capabilities.clone(),
                });
            Some(eliot_types::ContourRouteDecision {
                task_id: invocation.task_id,
                work_item_id: invocation.work_item_id,
                contour: eliot_types::ResponsibilityContour::Implementation,
                candidate_routes,
                selected_route,
                capability_evidence: invocation.packet_refs.clone(),
                availability_evidence: vec![format!(
                    "operation-job:{}:{:?}",
                    job.job_id, job.state
                )],
                policy_refs: run
                    .map(|run| vec![run.contract.contour_route_policy_ref.clone()])
                    .unwrap_or_default(),
                cost_latency_estimate: "not_reported_by_host".to_owned(),
                fallback: None,
                decision_receipt: job
                    .result_ref
                    .clone()
                    .unwrap_or_else(|| format!("operation-job:{}", job.job_id)),
            })
        })
        .collect::<Vec<_>>();
    let host_sessions = broker_state.agent_host_sessions.clone();
    let host_session_refs = host_sessions
        .iter()
        .map(|binding| format!("agent-session:{}", binding.agent_session_id))
        .collect::<Vec<_>>();
    let task_role_lease_refs = task_role_leases
        .iter()
        .map(|lease| format!("task-role-lease:{}", lease.role_lease_id))
        .collect::<Vec<_>>();
    let work_or_action_lease_refs = work_leases
        .iter()
        .map(|lease| format!("work-lease:{}", lease.work_lease_id))
        .chain(
            worktree_leases
                .iter()
                .map(|lease| format!("worktree-lease:{}", lease.worktree_lease_id)),
        )
        .collect::<Vec<_>>();
    let mut project_refs = work_state
        .work_items
        .iter()
        .map(|item| format!("project:{}", item.project_id))
        .collect::<std::collections::BTreeSet<_>>();
    if let Some((project_id, _)) = focus {
        project_refs.insert(format!("project:{project_id}"));
    }
    let backup_inventory = BackupService::new(&state.root).list()?;
    let incidents = IncidentService::new(&state.root).list()?;
    let incident_refs = incidents
        .iter()
        .map(|incident| format!("incident:{}", incident.incident_id))
        .collect::<Vec<_>>();
    let log_handles = LogService::new(state.root.join("logs"))
        .tail(50)?
        .into_iter()
        .map(|event| {
            event.fields_ref.unwrap_or_else(|| {
                format!(
                    "log:{}:{}:{}",
                    event.timestamp.unix_timestamp_nanos(),
                    event.target,
                    event.trace_id.unwrap_or_else(|| "no-trace".to_owned())
                )
            })
        })
        .collect::<Vec<_>>();
    let approvals = if let Some((project_id, task_id)) = focus {
        operator_approval_views(state, project_id, task_id).await?
    } else {
        Vec::new()
    };

    serde_json::to_value(OperatorSnapshot {
        schema_version: OPERATOR_SCHEMA_VERSION.to_owned(),
        protocol_version: OPERATOR_IPC_PROTOCOL_VERSION.to_owned(),
        protocol_hash: operator_contract_hash(),
        runtime_id: state.runtime_id.clone(),
        auth_generation: state.auth_generation.clone(),
        health_refs: vec![
            format!("runtime:{}", state.runtime_id),
            format!("ipc:{}", state.pipe_name),
            "store:canonical-surrealdb".to_owned(),
            "writer:single-writer-actor".to_owned(),
        ],
        task_cognition,
        memory_inspector,
        routing: AgentRoutingView {
            host_session_refs,
            task_role_lease_refs,
            work_or_action_lease_refs,
            route_policies,
            route_decisions,
            host_sessions,
            task_role_leases,
            controller_leases,
            operation_jobs,
            agent_results,
            agent_result_dispositions,
            work_items,
            work_leases,
            worktree_leases,
            work_conflicts,
        },
        runs,
        approvals,
        timeline: TraceTimelineView {
            cursor: None,
            next_cursor: None,
            event_refs: timeline_event_refs,
            incident_refs,
        },
        project_refs: project_refs.into_iter().collect(),
        backup_inventory,
        incidents,
        log_handles,
        generated_at: time::OffsetDateTime::now_utc(),
    })
    .map_err(Into::into)
}

pub(super) async fn dispatch_operator_query(state: &McpState, arguments: Value) -> Result<Value> {
    let request: OperatorQueryRequest = serde_json::from_value(arguments)?;
    if request.page_size == 0 || request.page_size > 100 {
        anyhow::bail!("operator page_size must be between 1 and 100");
    }
    if request.project_id.is_some() != request.task_id.is_some() {
        anyhow::bail!("operator query project_id and task_id must be provided together");
    }
    if !(1..=3).contains(&request.expand_depth) {
        anyhow::bail!("operator graph expand_depth must be between 1 and 3");
    }
    if request.query_operation.is_some() && request.projection != OperatorProjectionKind::QueryLab {
        anyhow::bail!("typed query_operation is only valid for the Query Lab projection");
    }
    let cursor_scope = canonical_struct_hash(&json!({
        "projection": request.projection,
        "project_id": request.project_id,
        "task_id": request.task_id,
        "filter": request.filter,
        "query_operation": request.query_operation,
        "query_parameters": request.query_parameters,
        "result_mode": request.result_mode,
        "selected_ref": request.selected_ref,
        "expand_depth": request.expand_depth,
    }))?;
    let cursor_state = operator_cursor_state(
        request.cursor.as_deref(),
        &cursor_scope,
        &state.cursor_signing_key,
    )?;
    let snapshot_arguments = match (request.project_id, request.task_id) {
        (Some(project_id), Some(task_id)) => json!({
            "project_id": project_id.to_string(),
            "task_id": task_id.to_string()
        }),
        (None, None) => json!({}),
        _ => unreachable!("project/task pairing checked above"),
    };
    let snapshot: OperatorSnapshot =
        serde_json::from_value(dispatch_operator_snapshot(state, snapshot_arguments).await?)?;
    let mut prepared = prepare_operator_query_records(&request, &snapshot)?;
    if let Some(records) = operator_typed_memory_query_records(state, &request).await? {
        prepared.records = records;
    }
    if prepared.projection == OperatorProjectionKind::MemoryExplorer
        && request.query_operation != Some(OperatorQueryOperation::ExactEvidence)
        && let (Some(project_id), Some(task_id)) = (request.project_id, request.task_id)
    {
        prepared
            .records
            .extend(operator_canonical_disposition_records(state, project_id, task_id).await?);
    }
    prepared
        .records
        .sort_by(|left, right| left.record_ref.cmp(&right.record_ref));
    prepared
        .records
        .dedup_by(|left, right| left.record_ref == right.record_ref);
    prepared
        .records
        .retain(|record| operator_record_matches(record, &request.filter));
    let page =
        paginate_operator_query_records(state, &request, &cursor_scope, cursor_state, prepared)
            .await?;
    let task_revision = snapshot
        .task_cognition
        .first()
        .map(|view| view.task_contract.memory_revision);
    let result_payload = (request.projection == OperatorProjectionKind::QueryLab
        && request.query_operation.is_some())
    .then(|| {
        json!({
            "operation": request.query_operation,
            "parameters": request.query_parameters,
            "mode": request.result_mode,
            "records": page.records,
        })
    });
    serde_json::to_value(OperatorProjectionPage {
        schema_version: OPERATOR_SCHEMA_VERSION.to_owned(),
        runtime_id: snapshot.runtime_id,
        auth_generation: snapshot.auth_generation,
        projection: request.projection,
        project_id: request.project_id,
        task_id: request.task_id,
        task_revision,
        cursor: request.cursor,
        next_cursor: page.next_cursor,
        page_size: request.page_size,
        returned: page.records.len(),
        total_matching: page.total_matching,
        total_is_exact: page.total_is_exact,
        truncated: !page.total_is_exact,
        records: page.records,
        result_mode: request.result_mode,
        result_payload,
        generated_at: time::OffsetDateTime::now_utc(),
    })
    .map_err(Into::into)
}

pub(super) async fn operator_typed_memory_query_records(
    state: &McpState,
    request: &OperatorQueryRequest,
) -> Result<Option<Vec<OperatorRecordView>>> {
    let Some(operation) = request.query_operation else {
        return Ok(None);
    };
    let Some(project_id) = request.project_id else {
        if matches!(
            operation,
            OperatorQueryOperation::RecallPreview | OperatorQueryOperation::ExactEvidence
        ) {
            anyhow::bail!("typed memory query requires project_id and task_id");
        }
        return Ok(None);
    };
    match operation {
        OperatorQueryOperation::RecallPreview => {
            let parameters = request
                .query_parameters
                .as_ref()
                .context("recall_preview requires query_parameters")?;
            let query = parameters
                .get("query")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|query| !query.is_empty())
                .context("recall_preview requires query_parameters.query")?;
            if query.len() > 512 {
                anyhow::bail!("recall_preview query must be at most 512 bytes");
            }
            let response = ReadService::new(state.store.clone())
                .recall_l0(&RecallL0Request {
                    project_id,
                    query: query.to_owned(),
                    consistency: ReadConsistencyMode::Latest,
                    at_least_revision: None,
                    lifecycle_audit: parameters
                        .get("lifecycle_audit")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    task_id: request.task_id,
                    task_class_cues: operator_string_array(parameters, "task_class_cues"),
                    scope_refs: operator_string_array(parameters, "scope_refs"),
                    concept_refs: operator_string_array(parameters, "concept_refs"),
                })
                .await?;
            Ok(Some(operator_l0_rank_records(&response)))
        }
        OperatorQueryOperation::ExactEvidence => {
            let parameters = request
                .query_parameters
                .as_ref()
                .context("exact_evidence requires query_parameters")?;
            let handles = if let Some(handles) = parameters.get("handles").and_then(Value::as_array)
            {
                handles
                    .iter()
                    .map(|handle| {
                        handle
                            .as_str()
                            .map(str::to_owned)
                            .context("exact_evidence handles must be strings")
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                vec![
                    parameters
                        .get("record_ref")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .context("exact_evidence requires record_ref or handles")?,
                ]
            };
            let response = ReadService::new(state.store.clone())
                .fetch_atoms_l2(&FetchAtomsL2Request {
                    project_id,
                    handles,
                    continuation: parameters
                        .get("continuation")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    consistency: ReadConsistencyMode::Latest,
                    at_least_revision: None,
                })
                .await?;
            Ok(Some(operator_l2_exact_records(&response)))
        }
        OperatorQueryOperation::CurrentState
        | OperatorQueryOperation::RelationshipSlice
        | OperatorQueryOperation::TraceReplay
        | OperatorQueryOperation::HealthReport => Ok(None),
    }
}

fn operator_string_array(parameters: &Value, key: &str) -> Vec<String> {
    parameters
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

pub(super) async fn operator_canonical_disposition_records(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Result<Vec<OperatorRecordView>> {
    let contracts = state
        .store
        .canonical_records_by_kind::<CognitiveRunContract>(
            project_id,
            Some(task_id),
            &["cognitive_run_contract"],
            16,
        )
        .await?;
    let mut records = Vec::new();
    for contract in contracts {
        match resolve_canonical_case_dispositions(
            &state.store,
            &contract,
            time::OffsetDateTime::now_utc(),
        )
        .await
        {
            Ok(dispositions) => {
                records.extend(dispositions.iter().map(|disposition| {
                    operator_canonical_disposition_record(&contract, disposition)
                }));
            }
            Err(error) => records.push(operator_record(
                &format!("canonical-m6:{}:unresolved", contract.receipt_body.run_id),
                "canonical_m6_disposition_chain",
                &contract.receipt_body.run_id,
                &format!("Canonical M6 disposition chain is incomplete or invalid: {error}"),
                "incomplete_or_invalid",
                "writer_actor_canonical_store",
                vec![
                    operator_field("run_id", &contract.receipt_body.run_id, true),
                    operator_field(
                        "contract_receipt_id",
                        contract.canonical_receipt.receipt_id,
                        true,
                    ),
                    operator_field(
                        "contract_write_id",
                        contract.canonical_receipt.write_id,
                        true,
                    ),
                    operator_field(
                        "contract_memory_revision",
                        contract.memory_revision.map_or_else(
                            || "none".to_owned(),
                            |revision| revision.value().to_string(),
                        ),
                        true,
                    ),
                    operator_field("resolution_error", error, false),
                ],
            )),
        }
    }
    Ok(records)
}

pub(super) fn operator_canonical_disposition_record(
    contract: &CanonicalRecord<CognitiveRunContract>,
    disposition: &CanonicalCaseDisposition,
) -> OperatorRecordView {
    let mut record = operator_record(
        &format!(
            "canonical-m6:{}:{}",
            contract.receipt_body.run_id, disposition.case_id
        ),
        "canonical_m6_disposition_chain",
        &disposition.case_id,
        "Store-resolved candidate, disposition, authority, verifier and receipt chain.",
        &format!("{:?}", disposition.disposition_kind).to_ascii_lowercase(),
        "writer_actor_canonical_store",
        vec![
            operator_field("run_id", &contract.receipt_body.run_id, true),
            operator_field("case_id", &disposition.case_id, true),
            operator_field("task_id", disposition.task_id, true),
            operator_field(
                "candidate_result_id",
                &disposition.candidate_result_id,
                true,
            ),
            operator_field("disposition_id", &disposition.disposition_id, true),
            operator_field("actor_session_id", disposition.actor_session_id, true),
            operator_field(
                "actor_role_lease_id",
                &disposition.actor_role_lease_id,
                true,
            ),
            operator_field("evidence_refs", disposition.evidence_refs.join(", "), true),
            operator_field("verifier_refs", disposition.verifier_refs.join(", "), true),
            operator_field("write_receipt_id", disposition.write_receipt_id, true),
            operator_field(
                "task_revision_before",
                disposition.task_revision_before.value(),
                true,
            ),
            operator_field(
                "task_revision_after",
                disposition.task_revision_after.value(),
                true,
            ),
            operator_field("source_commit", &disposition.source_commit, true),
            operator_field("policy_snapshot_id", &disposition.policy_snapshot_id, true),
            operator_field(
                "resolved_from_store",
                disposition.resolved_from_store,
                false,
            ),
            operator_field(
                "contract_receipt_id",
                contract.canonical_receipt.receipt_id,
                true,
            ),
            operator_field(
                "contract_write_id",
                contract.canonical_receipt.write_id,
                true,
            ),
            operator_field(
                "contract_memory_revision",
                contract.memory_revision.map_or_else(
                    || "none".to_owned(),
                    |revision| revision.value().to_string(),
                ),
                true,
            ),
        ],
    );
    record.relationships = disposition
        .evidence_refs
        .iter()
        .map(|evidence_ref| OperatorRelationshipView {
            relation: "canonical_evidence".to_owned(),
            target_ref: evidence_ref.clone(),
            evidence_ref: Some(format!("receipt:{}", disposition.write_receipt_id)),
            observed_at: None,
        })
        .chain(
            disposition
                .verifier_refs
                .iter()
                .map(|verifier_ref| OperatorRelationshipView {
                    relation: "canonical_verifier".to_owned(),
                    target_ref: verifier_ref.clone(),
                    evidence_ref: Some(format!("receipt:{}", disposition.write_receipt_id)),
                    observed_at: None,
                }),
        )
        .collect();
    record
}

fn operator_l0_feature_fields(
    score: &eliot_types::L0FeatureScore,
    at_revision: MemoryRevision,
) -> Vec<OperatorFieldView> {
    vec![
        operator_field("handle", &score.handle, true),
        operator_field("reasons", score.reasons.join(", "), false),
        operator_field("exact_identifier", score.exact_identifier, false),
        operator_field("subject_identity", score.subject_identity, false),
        operator_field("lexical_overlap", score.lexical_overlap, false),
        operator_field("task_relation", score.task_relation, false),
        operator_field("scope_fit", score.scope_fit, false),
        operator_field("lifecycle_fit", score.lifecycle_fit, false),
        operator_field("evidence_authority", score.evidence_authority, false),
        operator_field("prior_decision_delta", score.prior_decision_delta, false),
        operator_field("exact_cue", score.exact_cue, false),
        operator_field("concept_relation", score.concept_relation, false),
        operator_field("freshness_fit", score.freshness_fit, false),
        operator_field("negative_memory_value", score.negative_memory_value, false),
        operator_field("known_decision_delta", score.known_decision_delta, false),
        operator_field("prior_beneficial_use", score.prior_beneficial_use, false),
        operator_field("verification_value", score.verification_value, false),
        operator_field("context_cost", score.context_cost, false),
        operator_field("stale_penalty", score.stale_penalty, false),
        operator_field("contradiction_penalty", score.contradiction_penalty, false),
        operator_field("harm_penalty", score.harm_penalty, false),
        operator_field("repetition_penalty", score.repetition_penalty, false),
        operator_field("distraction_penalty", score.distraction_penalty, false),
        operator_field("total", score.total, false),
        operator_field("at_revision", at_revision.value(), true),
    ]
}

pub(super) fn operator_l0_rank_records(response: &RecallL0Response) -> Vec<OperatorRecordView> {
    let trace = &response.rank_trace;
    let query_hash = blake3::hash(trace.normalized_query.as_bytes())
        .to_hex()
        .to_string();
    let mut records = vec![operator_record(
        &format!("l0-rank-trace:{}", &query_hash[..16]),
        "l0_rank_trace",
        &trace.query,
        if trace.no_useful_memory {
            "No useful memory matched the query."
        } else {
            "Deterministic query-aware memory ranking."
        },
        if trace.no_useful_memory {
            "no_useful_memory"
        } else {
            "candidates_found"
        },
        "canonical_store_query_ranker",
        vec![
            operator_field("query", &trace.query, true),
            operator_field("normalized_query", &trace.normalized_query, true),
            operator_field("query_mode", &trace.query_mode, false),
            operator_field("candidates_considered", trace.candidates_considered, false),
            operator_field("candidates_returned", trace.candidates_returned, false),
            operator_field("no_useful_memory", trace.no_useful_memory, false),
            operator_field("at_revision", response.at_revision.value(), true),
        ],
    )];
    for score in &trace.feature_scores {
        let lifecycle_suppression = trace
            .lifecycle_suppressions
            .iter()
            .find(|suppression| suppression.handle == score.handle);
        let scope_suppression = trace
            .scope_suppressions
            .iter()
            .find(|suppression| suppression.handle == score.handle);
        let suppression = lifecycle_suppression.or(scope_suppression);
        let preview = response
            .handles
            .iter()
            .find(|handle| handle.handle == score.handle);
        let mut record = operator_record(
            &format!("l0-candidate:{}", score.handle),
            "l0_rank_candidate",
            preview.map_or(score.handle.as_str(), |handle| handle.preview.as_str()),
            suppression
                .map_or_else(
                    || score.reasons.join("; "),
                    |suppression| suppression.reason.clone(),
                )
                .as_str(),
            if suppression.is_some() {
                "suppressed"
            } else {
                "ranked"
            },
            "canonical_store_query_ranker",
            operator_l0_feature_fields(score, response.at_revision),
        );
        record.lifecycle = preview
            .and_then(|handle| handle.lifecycle_state)
            .map(|state| format!("{state:?}").to_ascii_lowercase())
            .or_else(|| lifecycle_suppression.map(|_| "suppressed".to_owned()));
        records.push(record);
    }
    for duplicate in &trace.collapsed_duplicates {
        records.push(operator_record(
            &format!("l0-collapsed-duplicate:{}", duplicate.authoritative_handle),
            "l0_collapsed_duplicate",
            &duplicate.authoritative_handle,
            &duplicate.reason,
            "collapsed",
            "canonical_store_query_ranker",
            vec![
                operator_field(
                    "authoritative_handle",
                    &duplicate.authoritative_handle,
                    true,
                ),
                operator_field(
                    "collapsed_record_refs",
                    duplicate.collapsed_record_refs.join(", "),
                    false,
                ),
                operator_field("reason", &duplicate.reason, false),
            ],
        ));
    }
    append_operator_l0_suppression_records(&mut records, response);
    records
}

pub(super) fn append_operator_l0_suppression_records(
    records: &mut Vec<OperatorRecordView>,
    response: &RecallL0Response,
) {
    let trace = &response.rank_trace;
    let lifecycle_only = trace.lifecycle_suppressions.iter().filter(|suppression| {
        !trace
            .feature_scores
            .iter()
            .any(|score| score.handle == suppression.handle)
    });
    for suppression in trace.scope_suppressions.iter().chain(lifecycle_only) {
        let mut record = operator_record(
            &format!("l0-suppression:{}", suppression.handle),
            "l0_rank_suppression",
            &suppression.handle,
            &suppression.reason,
            "suppressed",
            "canonical_store_query_ranker",
            vec![
                operator_field("handle", &suppression.handle, true),
                operator_field("reason", &suppression.reason, false),
                operator_field("at_revision", response.at_revision.value(), true),
            ],
        );
        record.lifecycle = Some("suppressed".to_owned());
        records.push(record);
    }
}

pub(super) fn operator_l2_exact_records(
    response: &FetchAtomsL2Response,
) -> Vec<OperatorRecordView> {
    let mut records = vec![operator_record(
        &format!("l2-resolution:{}", response.at_revision.value()),
        "l2_exact_resolution",
        "Exact memory resolution",
        "Store-scoped exact-handle resolution metadata.",
        if response.forbidden_handles.is_empty() && response.missing_handles.is_empty() {
            "resolved"
        } else {
            "partial"
        },
        "canonical_store_exact_lookup",
        vec![
            operator_field(
                "requested_handles",
                response.requested_handles.join(", "),
                true,
            ),
            operator_field(
                "returned_handles",
                response.returned_handles.join(", "),
                true,
            ),
            operator_field("missing_handles", response.missing_handles.join(", "), true),
            operator_field(
                "forbidden_handles",
                response.forbidden_handles.join(", "),
                true,
            ),
            operator_field(
                "continuation",
                response.continuation.as_deref().unwrap_or("none"),
                true,
            ),
            operator_field("at_revision", response.at_revision.value(), true),
        ],
    )];
    records.extend(
        response
            .returned_handles
            .iter()
            .filter_map(|handle| operator_l2_handle_record(response, handle)),
    );
    records.extend(
        response
            .relations
            .iter()
            .enumerate()
            .map(|(index, relation)| {
                let mut record = operator_record(
                    &format!("l2-relation:{index}:{}:{}", relation.from, relation.to),
                    "l2_relation",
                    &format!("{} → {}", relation.from, relation.to),
                    &format!("{:?}", relation.relation_type).to_ascii_lowercase(),
                    "resolved",
                    "canonical_store_exact_lookup",
                    vec![
                        operator_field("from", &relation.from, true),
                        operator_field("to", &relation.to, true),
                        operator_field(
                            "relation_type",
                            format!("{:?}", relation.relation_type).to_ascii_lowercase(),
                            false,
                        ),
                        operator_field("at_revision", response.at_revision.value(), true),
                    ],
                );
                record.relationships.push(OperatorRelationshipView {
                    relation: format!("{:?}", relation.relation_type).to_ascii_lowercase(),
                    target_ref: relation.to.clone(),
                    evidence_ref: None,
                    observed_at: None,
                });
                record
            }),
    );
    records
}

pub(super) fn operator_l2_handle_record(
    response: &FetchAtomsL2Response,
    handle: &str,
) -> Option<OperatorRecordView> {
    let identity = handle
        .split_once(':')
        .map_or(handle, |(_, identity)| identity);
    if let Some(claim) = response
        .claims
        .iter()
        .find(|claim| claim.claim_id.to_string() == identity)
    {
        return Some(operator_record(
            handle,
            "claim_card",
            &claim.statement,
            "Exact canonical claim.",
            &format!("{:?}", claim.status).to_ascii_lowercase(),
            "canonical_store_exact_lookup",
            vec![
                operator_field("claim_id", claim.claim_id, true),
                operator_field("payload_json", claim.payload.to_string(), true),
                operator_field("at_revision", response.at_revision.value(), true),
            ],
        ));
    }
    if let Some(evidence) = response
        .evidence_atoms
        .iter()
        .find(|evidence| evidence.evidence_id.to_string() == identity)
    {
        return Some(operator_record(
            handle,
            "evidence_atom",
            &evidence.summary,
            "Exact canonical evidence.",
            "resolved",
            "canonical_store_exact_lookup",
            vec![
                operator_field("evidence_id", evidence.evidence_id, true),
                operator_field("payload_json", evidence.payload.to_string(), true),
                operator_field("at_revision", response.at_revision.value(), true),
            ],
        ));
    }
    if let Some(verification) = response
        .verification_runs
        .iter()
        .find(|verification| verification.verification_id.to_string() == identity)
    {
        return Some(operator_record(
            handle,
            "verification_run",
            &verification.summary,
            "Exact canonical verification.",
            &format!("{:?}", verification.result).to_ascii_lowercase(),
            "canonical_store_exact_lookup",
            vec![
                operator_field("verification_id", verification.verification_id, true),
                operator_field("payload_json", verification.payload.to_string(), true),
                operator_field("at_revision", response.at_revision.value(), true),
            ],
        ));
    }
    if let Some(observation) = response
        .tool_observations
        .iter()
        .find(|observation| observation.observation_id == identity)
    {
        return Some(operator_record(
            handle,
            "tool_observation",
            &observation.observation,
            &observation.tool_name,
            "resolved",
            "canonical_store_exact_lookup",
            vec![
                operator_field("observation_id", &observation.observation_id, true),
                operator_field("payload_json", observation.payload.to_string(), true),
                operator_field("at_revision", response.at_revision.value(), true),
            ],
        ));
    }
    response
        .failure_fingerprints
        .iter()
        .find(|failure| failure.fingerprint == identity)
        .map(|failure| {
            operator_record(
                handle,
                "failure_fingerprint",
                &failure.summary,
                "Exact canonical failure fingerprint.",
                "resolved",
                "canonical_store_exact_lookup",
                vec![
                    operator_field("fingerprint", &failure.fingerprint, true),
                    operator_field("payload_json", failure.payload.to_string(), true),
                    operator_field("at_revision", response.at_revision.value(), true),
                ],
            )
        })
}

pub(super) fn prepare_operator_query_records(
    request: &OperatorQueryRequest,
    snapshot: &OperatorSnapshot,
) -> Result<PreparedOperatorQuery> {
    let projection = match request.query_operation {
        Some(OperatorQueryOperation::CurrentState) => OperatorProjectionKind::TaskCognition,
        Some(OperatorQueryOperation::RecallPreview | OperatorQueryOperation::ExactEvidence) => {
            OperatorProjectionKind::MemoryExplorer
        }
        Some(OperatorQueryOperation::RelationshipSlice) => OperatorProjectionKind::CausalProvenance,
        Some(OperatorQueryOperation::TraceReplay) => OperatorProjectionKind::SleepMeta,
        Some(OperatorQueryOperation::HealthReport) => OperatorProjectionKind::Overview,
        None => request.projection,
    };
    let exact_evidence_target = request
        .query_operation
        .eq(&Some(OperatorQueryOperation::ExactEvidence))
        .then(|| {
            request
                .query_parameters
                .as_ref()
                .and_then(|parameters| parameters.get("record_ref"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .context("exact_evidence requires query_parameters.record_ref")
        })
        .transpose()?;
    let mut records = operator_projection_records(snapshot, projection);
    records.retain(|record| {
        operator_query_specific_match(record, projection, exact_evidence_target.as_deref())
    });
    if projection == OperatorProjectionKind::CausalProvenance {
        records = operator_selected_neighborhood(
            records,
            request.selected_ref.as_deref(),
            request.expand_depth,
        );
    }
    records.sort_by(|left, right| left.record_ref.cmp(&right.record_ref));
    records.dedup_by(|left, right| left.record_ref == right.record_ref);
    records.retain(|record| operator_record_matches(record, &request.filter));
    Ok(PreparedOperatorQuery {
        projection,
        exact_evidence_target,
        records,
    })
}

pub(super) async fn paginate_operator_query_records(
    state: &McpState,
    request: &OperatorQueryRequest,
    cursor_scope: &str,
    cursor_state: OperatorCursorState,
    prepared: PreparedOperatorQuery,
) -> Result<OperatorQueryPageData> {
    let page_size = usize::try_from(request.page_size).unwrap_or(usize::MAX);
    let base_total = prepared.records.len();
    let base_offset = usize::try_from(cursor_state.base_offset).unwrap_or(usize::MAX);
    let mut records = prepared
        .records
        .into_iter()
        .skip(base_offset)
        .take(page_size)
        .collect::<Vec<_>>();
    let next_base_offset = base_offset.saturating_add(records.len()).min(base_total);
    let receipt_kinds = operator_query_receipt_kinds(request, prepared.projection);
    let mut canonical_start = cursor_state.canonical_start;
    let mut canonical_exhausted = receipt_kinds.is_empty() || request.project_id.is_none();
    let mut scan_budget_exhausted = false;
    if next_base_offset == base_total && records.len() < page_size && !canonical_exhausted {
        'scan: for scan_index in 0..10 {
            let canonical_page = state
                .store
                .canonical_record_page(
                    request
                        .project_id
                        .context("canonical page requires project_id")?,
                    request.task_id,
                    receipt_kinds,
                    canonical_start,
                    100,
                )
                .await?;
            let fetched = canonical_page.len();
            if fetched == 0 {
                canonical_exhausted = true;
                break;
            }
            for (record_index, canonical) in canonical_page.into_iter().enumerate() {
                canonical_start = canonical_start.saturating_add(1);
                let record = canonical_operator_record(
                    &canonical,
                    operator_canonical_record_kind(&canonical.receipt_kind),
                )?;
                if prepared.projection == OperatorProjectionKind::CausalProvenance
                    && request
                        .selected_ref
                        .as_deref()
                        .is_some_and(|selected| !operator_record_touches_node(&record, selected))
                {
                    continue;
                }
                if operator_query_specific_match(
                    &record,
                    prepared.projection,
                    prepared.exact_evidence_target.as_deref(),
                ) && operator_record_matches(&record, &request.filter)
                {
                    records.push(record);
                    if records.len() == page_size {
                        canonical_exhausted = record_index + 1 == fetched && fetched < 100;
                        break 'scan;
                    }
                }
            }
            if fetched < 100 {
                canonical_exhausted = true;
                break;
            }
            scan_budget_exhausted = scan_index == 9;
        }
    }
    let has_more = next_base_offset < base_total
        || (!canonical_exhausted
            && !receipt_kinds.is_empty()
            && (records.len() == page_size || scan_budget_exhausted));
    let matched_through_page = cursor_state
        .matched_seen
        .saturating_add(u64::try_from(records.len()).unwrap_or(u64::MAX));
    let total_matching = usize::try_from(matched_through_page)
        .unwrap_or(usize::MAX)
        .max(base_total);
    let next_cursor = has_more.then(|| {
        operator_cursor(
            OperatorCursorState {
                base_offset: u64::try_from(next_base_offset).unwrap_or(u64::MAX),
                canonical_start,
                matched_seen: matched_through_page,
            },
            cursor_scope,
            &state.cursor_signing_key,
        )
    });
    Ok(OperatorQueryPageData {
        records,
        next_cursor,
        total_matching,
        total_is_exact: !has_more,
    })
}

pub(super) fn operator_query_receipt_kinds(
    request: &OperatorQueryRequest,
    projection: OperatorProjectionKind,
) -> &'static [&'static str] {
    if matches!(
        request.query_operation,
        Some(OperatorQueryOperation::RecallPreview | OperatorQueryOperation::ExactEvidence)
    ) {
        &[]
    } else {
        operator_projection_receipt_kinds(projection)
    }
}

pub(super) fn operator_cursor(
    state: OperatorCursorState,
    scope: &str,
    signing_key: &[u8; 32],
) -> String {
    let unsigned = format!(
        "op2:{:x}:{:x}:{:x}:{}",
        state.base_offset,
        state.canonical_start,
        state.matched_seen,
        &scope[..16]
    );
    let signature = blake3::keyed_hash(signing_key, unsigned.as_bytes())
        .to_hex()
        .to_string();
    format!("{unsigned}:{}", &signature[..32])
}

pub(super) fn operator_cursor_state(
    cursor: Option<&str>,
    scope: &str,
    signing_key: &[u8; 32],
) -> Result<OperatorCursorState> {
    let Some(cursor) = cursor else {
        return Ok(OperatorCursorState::default());
    };
    let parts = cursor.split(':').collect::<Vec<_>>();
    if parts.len() != 6 || parts[0] != "op2" || parts[4] != &scope[..16] {
        anyhow::bail!("operator cursor is not a Governor-issued continuation for this query");
    }
    let unsigned = parts[..5].join(":");
    let expected_signature = blake3::keyed_hash(signing_key, unsigned.as_bytes())
        .to_hex()
        .to_string();
    if parts[5] != &expected_signature[..32] {
        anyhow::bail!("operator cursor signature is invalid");
    }
    Ok(OperatorCursorState {
        base_offset: u64::from_str_radix(parts[1], 16)
            .context("operator cursor base offset is invalid")?,
        canonical_start: u64::from_str_radix(parts[2], 16)
            .context("operator cursor canonical offset is invalid")?,
        matched_seen: u64::from_str_radix(parts[3], 16)
            .context("operator cursor matched count is invalid")?,
    })
}

pub(super) fn operator_selected_neighborhood(
    records: Vec<OperatorRecordView>,
    selected_ref: Option<&str>,
    expand_depth: u8,
) -> Vec<OperatorRecordView> {
    let Some(seed) = selected_ref
        .map(str::to_owned)
        .or_else(|| records.first().map(|record| record.record_ref.clone()))
    else {
        return records;
    };
    let mut reached = std::collections::BTreeSet::from([seed]);
    let mut included = std::collections::BTreeSet::new();
    for _ in 0..expand_depth {
        let frontier = reached.clone();
        for (index, record) in records.iter().enumerate() {
            let field_nodes = record
                .fields
                .iter()
                .filter(|field| matches!(field.label.as_str(), "from" | "to"))
                .map(|field| field.value.as_str());
            let relationship_nodes = record
                .relationships
                .iter()
                .map(|relationship| relationship.target_ref.as_str());
            let connected = frontier.contains(&record.record_ref)
                || field_nodes
                    .clone()
                    .chain(relationship_nodes.clone())
                    .any(|node| frontier.contains(node));
            if connected {
                included.insert(index);
                reached.insert(record.record_ref.clone());
                reached.extend(field_nodes.map(str::to_owned));
                reached.extend(relationship_nodes.map(str::to_owned));
            }
        }
    }
    records
        .into_iter()
        .enumerate()
        .filter(|(index, _)| included.contains(index))
        .map(|(_, record)| record)
        .take(30)
        .collect()
}

pub(super) fn operator_record_touches_node(record: &OperatorRecordView, node_ref: &str) -> bool {
    record.record_ref == node_ref
        || record
            .fields
            .iter()
            .any(|field| matches!(field.label.as_str(), "from" | "to") && field.value == node_ref)
        || record
            .relationships
            .iter()
            .any(|relationship| relationship.target_ref == node_ref)
}

pub(super) fn operator_query_specific_match(
    record: &OperatorRecordView,
    projection: OperatorProjectionKind,
    exact_evidence_target: Option<&str>,
) -> bool {
    if let Some(target) = exact_evidence_target {
        return operator_record_touches_node(record, target)
            || record.fields.iter().any(|field| field.value == target);
    }
    if projection == OperatorProjectionKind::Approvals
        && record.record_kind == "operator_control_request"
    {
        return record.fields.iter().any(|field| {
            field.label == "operation"
                && matches!(field.value.as_str(), "grant_approval" | "deny_approval")
        });
    }
    true
}

pub(super) fn operator_projection_receipt_kinds(
    projection: OperatorProjectionKind,
) -> &'static [&'static str] {
    match projection {
        OperatorProjectionKind::MemoryExplorer | OperatorProjectionKind::CausalProvenance => &[
            "state_transition",
            "memory_trajectory_correctness",
            "minority_pressure_record",
        ],
        OperatorProjectionKind::ExperienceSkills => &[
            "procedure_skill_candidate",
            "procedure_promotion_disposition",
        ],
        OperatorProjectionKind::SleepMeta => &[
            "trace_completeness_contract",
            "replay_set",
            "replay_case",
            "replay_input_snapshot",
            "sealed_replay_run",
            "replay_run",
            "replay_audit",
            "harness_experiment",
            "harness_disposition",
            "meta_metric_evidence",
            "meta_isolation_rejection",
            "experimental_policy_candidate",
            "meta_policy_promotion",
            "meta_policy_rollback",
            "sleep_consolidation_bundle",
            "sleep_consolidation_run",
            "procedure_candidate",
            "procedure_skill_candidate",
            "procedure_promotion_disposition",
            "forgetting_candidate",
            "test_candidate",
            "replay_case_candidate",
            "dream_candidate",
        ],
        OperatorProjectionKind::Autonomy => &[
            "autonomy_run_contract",
            "autonomy_run_transition",
            "autonomy_budget_ledger",
            "autonomy_work_graph",
            "autonomy_tripwire",
            "autonomy_recovery",
        ],
        OperatorProjectionKind::Approvals | OperatorProjectionKind::TimelineOperations => &[
            "autonomy_approval_request",
            "autonomy_approval_decision",
            "autonomy_approval_consumption",
            "operator_control_request",
        ],
        _ => &[],
    }
}

pub(super) fn operator_canonical_record_kind(receipt_kind: &str) -> &str {
    match receipt_kind {
        "state_transition" => "memory_state_transition",
        other => other,
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn operator_projection_records(
    snapshot: &OperatorSnapshot,
    projection: OperatorProjectionKind,
) -> Vec<OperatorRecordView> {
    let mut records = Vec::new();
    match projection {
        OperatorProjectionKind::Overview => {
            records.extend(snapshot.health_refs.iter().map(|health_ref| {
                operator_record(
                    health_ref,
                    "health",
                    health_ref,
                    "Governor-produced runtime health handle",
                    "observed",
                    "governor",
                    vec![operator_field("handle", health_ref, true)],
                )
            }));
            records.extend(snapshot.project_refs.iter().map(|project_ref| {
                operator_record(
                    project_ref,
                    "project",
                    project_ref,
                    "Project observed from the current Governor work queue.",
                    "observed",
                    "governor_control_plane",
                    vec![operator_field("project_ref", project_ref, true)],
                )
            }));
            records.extend(
                snapshot
                    .routing
                    .host_sessions
                    .iter()
                    .map(operator_host_record),
            );
            records.extend(
                snapshot
                    .routing
                    .operation_jobs
                    .iter()
                    .map(operator_job_record),
            );
            records.extend(snapshot.routing.agent_results.iter().map(|result| {
                operator_agent_result_record(result, &snapshot.routing.agent_result_dispositions)
            }));
            records.extend(
                snapshot
                    .routing
                    .work_items
                    .iter()
                    .map(operator_work_item_record),
            );
            records.extend(snapshot.backup_inventory.iter().map(operator_backup_record));
            records.extend(snapshot.incidents.iter().map(operator_incident_record));
            records.extend(snapshot.log_handles.iter().map(|handle| {
                operator_record(
                    handle,
                    "log_handle",
                    handle,
                    "Redacted native runtime log handle.",
                    "observed",
                    "governor_log_service",
                    vec![operator_field("handle", handle, true)],
                )
            }));
            records.extend(snapshot.runs.iter().map(operator_run_record));
            records.extend(snapshot.approvals.iter().map(operator_approval_record));
            if let Some(task_id) = snapshot
                .task_cognition
                .first()
                .map(|view| view.task_contract.task_id)
            {
                let mut operations = operator_record(
                    &format!("operations:{task_id}"),
                    "operations_control",
                    "Governed operations",
                    "Backup validation and import preview requests remain Governor-owned.",
                    "available",
                    "governor_operations",
                    vec![operator_field("task_id", task_id, true)],
                );
                operations.actions.extend([
                    operator_action(
                        "trigger_backup_validation",
                        "Validate backup",
                        "R1",
                        false,
                        false,
                    ),
                    operator_action(
                        "request_import_preview",
                        "Preview import",
                        "R1",
                        true,
                        false,
                    ),
                ]);
                records.push(operations);
            }
        }
        OperatorProjectionKind::TasksWork => {
            records.extend(snapshot.task_cognition.iter().map(|view| {
                let satisfied = view
                    .task_contract
                    .acceptance_items
                    .iter()
                    .filter(|item| item.satisfied)
                    .count();
                let mut record = operator_record(
                    &format!("task:{}", view.task_contract.task_id),
                    "task_contract",
                    &view.task_contract.title,
                    &format!(
                        "{satisfied}/{} acceptance items satisfied",
                        view.task_contract.acceptance_items.len()
                    ),
                    &format!("{:?}", view.task_contract.status).to_ascii_lowercase(),
                    "canonical_store",
                    vec![
                        operator_field("task_id", view.task_contract.task_id, true),
                        operator_field("project_id", view.task_contract.project_id, true),
                        operator_field(
                            "memory_revision",
                            view.task_contract.memory_revision.value(),
                            true,
                        ),
                        operator_field(
                            "verification_count",
                            view.task_contract.verification_ids.len(),
                            false,
                        ),
                    ],
                );
                record.actions.push(operator_action(
                    "finish_gap_preview",
                    "Preview finish gaps",
                    "R0",
                    false,
                    false,
                ));
                record.actions.push(operator_action(
                    "refresh_packet",
                    "Refresh task packet",
                    "R1",
                    false,
                    false,
                ));
                record
            }));
            for view in &snapshot.task_cognition {
                if let Some(decision) = &view.active_decision_state {
                    records.push(operator_record(
                        &format!("active-decision:{}", decision.packet_id),
                        "active_decision_state",
                        &decision.next_allowed_action,
                        &decision.expected_observable,
                        "active",
                        "governor_task_packet",
                        vec![
                            operator_field("packet_id", &decision.packet_id, true),
                            operator_field("verifier", &decision.verifier, true),
                            operator_field("stop_condition", &decision.stop_condition, false),
                            operator_field(
                                "open_unknowns",
                                decision.open_unknowns.join("; "),
                                false,
                            ),
                        ],
                    ));
                }
            }
            records.extend(
                snapshot
                    .routing
                    .work_items
                    .iter()
                    .map(operator_work_item_record),
            );
            records.extend(
                snapshot
                    .routing
                    .task_role_leases
                    .iter()
                    .map(operator_task_role_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .controller_leases
                    .iter()
                    .map(operator_controller_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .work_leases
                    .iter()
                    .map(operator_work_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .worktree_leases
                    .iter()
                    .map(operator_worktree_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .operation_jobs
                    .iter()
                    .map(operator_job_record),
            );
            records.extend(
                snapshot
                    .routing
                    .work_conflicts
                    .iter()
                    .map(operator_work_conflict_record),
            );
            records.extend(snapshot.runs.iter().map(operator_run_record));
        }
        OperatorProjectionKind::TaskCognition => {
            for view in &snapshot.task_cognition {
                if let Some(meaning) = &view.task_meaning {
                    records.push(operator_record(
                        &format!("task-meaning:{}", meaning.task_id),
                        "task_meaning_frame",
                        &meaning.user_goal,
                        &meaning.desired_state_transition,
                        "current_task_model",
                        "governor",
                        vec![
                            operator_field("task_type", &meaning.task_or_action_type, false),
                            operator_field(
                                "predicted_observable",
                                &meaning.predicted_observable,
                                false,
                            ),
                            operator_field("verifier_need", &meaning.verifier_need, true),
                            operator_field(
                                "material_unknowns",
                                meaning.material_unknowns.len(),
                                false,
                            ),
                        ],
                    ));
                }
                if let Some(decision) = &view.active_decision_state {
                    records.push(operator_record(
                        &format!("decision:{}", decision.packet_id),
                        "active_decision_state",
                        "Active decision state",
                        &decision.next_allowed_action,
                        "active",
                        "governor",
                        vec![
                            operator_field("packet_id", &decision.packet_id, true),
                            operator_field(
                                "expected_observable",
                                &decision.expected_observable,
                                false,
                            ),
                            operator_field("verifier", &decision.verifier, true),
                            operator_field("stop_condition", &decision.stop_condition, false),
                            operator_field("open_unknowns", decision.open_unknowns.len(), false),
                        ],
                    ));
                }
                records.extend(view.current_truth.iter().map(|claim| {
                    operator_record(
                        &format!("claim:{}", claim.claim_id),
                        "current_truth",
                        &claim.statement,
                        "Verified current-state claim",
                        &format!("{:?}", claim.status).to_ascii_lowercase(),
                        "canonical_store",
                        vec![
                            operator_field("claim_id", claim.claim_id, true),
                            operator_field("revision", claim.memory_revision.value(), true),
                        ],
                    )
                }));
                for (kind, values) in [
                    ("supported", &view.epistemic_state.supported),
                    ("assumed", &view.epistemic_state.assumed),
                    ("conflicted", &view.epistemic_state.conflicted),
                    ("unknown", &view.epistemic_state.unknown),
                ] {
                    records.extend(values.iter().map(|value| {
                        operator_record(
                            &format!("epistemic:{kind}:{}", blake3::hash(value.as_bytes())),
                            "epistemic_state",
                            value,
                            &format!("Task packet {kind} item"),
                            kind,
                            "task_packet",
                            vec![operator_field("classification", kind, false)],
                        )
                    }));
                }
                records.extend(
                    view.experience_priors
                        .iter()
                        .enumerate()
                        .map(|(index, prior)| {
                            operator_record(
                                &format!("experience-prior:{index}:{}", prior.essence),
                                "experience_brief",
                                &prior.essence,
                                &prior.why_it_may_apply.join("; "),
                                "prior_not_current_truth",
                                &prior.maturity_and_authority,
                                vec![
                                    operator_field("mechanism", &prior.underlying_mechanism, false),
                                    operator_field(
                                        "local_check",
                                        &prior.required_local_check,
                                        true,
                                    ),
                                    operator_field(
                                        "first_probe",
                                        &prior.recommended_first_probe,
                                        true,
                                    ),
                                ],
                            )
                        }),
                );
                records.extend(view.negative_memory.iter().map(|claim| {
                    operator_record(
                        &format!("negative-memory:{}", claim.claim_id),
                        "negative_memory",
                        &claim.statement,
                        "Failure or unsafe-path memory retained as a governed constraint.",
                        &format!("{:?}", claim.status).to_ascii_lowercase(),
                        "canonical_store",
                        vec![operator_field("claim_id", claim.claim_id, true)],
                    )
                }));
            }
        }
        OperatorProjectionKind::MemoryExplorer => {
            if let Some(inspector) = &snapshot.memory_inspector {
                records.extend(inspector.decisions.iter().map(|decision| {
                    let mut record = operator_record(
                        &decision.memory_handle,
                        "memory_decision",
                        &decision.memory_handle,
                        &decision.action_effect,
                        &decision.status,
                        &decision.authority,
                        vec![
                            operator_field("source_anchor", &decision.source_and_anchor, true),
                            operator_field("freshness", &decision.freshness, false),
                            operator_field(
                                "admission",
                                format!("{:?}", decision.admission).to_ascii_lowercase(),
                                false,
                            ),
                            operator_field("verifier_effect", &decision.verifier_effect, false),
                        ],
                    );
                    record.lifecycle = Some(decision.status.clone());
                    record.actions.extend(operator_memory_actions());
                    record
                }));
                records.extend(inspector.cargo.iter().map(|cargo| {
                    let mut record = operator_record(
                        &format!("cargo:{}", cargo.receipt_id),
                        "context_cargo_receipt",
                        &cargo.memory_handle,
                        &cargo.reason,
                        &format!("{:?}", cargo.disposition).to_ascii_lowercase(),
                        "writer_actor_receipt",
                        vec![
                            operator_field("receipt_id", &cargo.receipt_id, true),
                            operator_field("packet_loads", cargo.packet_load_count, false),
                            operator_field("decision_deltas", cargo.decision_delta_count, false),
                        ],
                    );
                    record.observed_at = Some(cargo.generated_at.to_string());
                    record
                }));
                for (lifecycle, refs) in [
                    ("suppressed", &inspector.lifecycle.suppressed_refs),
                    ("demoted", &inspector.lifecycle.demoted_refs),
                    ("superseded", &inspector.lifecycle.superseded_refs),
                    ("archived", &inspector.lifecycle.archived_refs),
                    (
                        "minority_preserved",
                        &inspector.lifecycle.minority_preserved_refs,
                    ),
                ] {
                    records.extend(refs.iter().map(|target_ref| {
                        let mut record = operator_record(
                            target_ref,
                            "memory_lifecycle",
                            target_ref,
                            &format!("Governed lifecycle state: {lifecycle}"),
                            lifecycle,
                            "memory_lifecycle_policy",
                            vec![operator_field("lifecycle", lifecycle, false)],
                        );
                        record.lifecycle = Some(lifecycle.to_owned());
                        record.actions.extend(operator_memory_actions());
                        record
                    }));
                }
            }
        }
        OperatorProjectionKind::CausalProvenance => {
            for view in &snapshot.task_cognition {
                records.extend(view.causal_bridge.iter().enumerate().map(|(index, hop)| {
                    let mut record = operator_record(
                        &format!("causal-hop:{index}:{}", hop.from),
                        "causal_edge",
                        &format!("{} → {}", hop.from, hop.to),
                        &hop.relation,
                        "observed",
                        "task_packet",
                        vec![
                            operator_field("from", &hop.from, true),
                            operator_field("to", &hop.to, true),
                            operator_field("relation", &hop.relation, false),
                        ],
                    );
                    record.relationships.push(OperatorRelationshipView {
                        relation: hop.relation.clone(),
                        target_ref: hop.to.clone(),
                        evidence_ref: hop.evidence_ref.clone(),
                        observed_at: None,
                    });
                    record
                }));
            }
        }
        OperatorProjectionKind::SchemaContracts => {
            records.extend(operator_schema_records());
        }
        OperatorProjectionKind::QueryLab => {
            records.extend(operator_query_lab_records());
        }
        OperatorProjectionKind::ExperienceSkills => {
            if let Some(inspector) = &snapshot.memory_inspector {
                records.extend(inspector.experience_cases.iter().map(|case| {
                    let mut record = operator_record(
                        &format!("experience-case:{}", case.case_id),
                        "experience_case",
                        &case.problem_frame.goal_pattern,
                        &case.causal_model.mechanism,
                        &format!("{:?}", case.maturity.state).to_ascii_lowercase(),
                        "candidate_prior",
                        vec![
                            operator_field("case_id", &case.case_id, true),
                            operator_field("support_count", case.maturity.support_count, false),
                            operator_field(
                                "cross_host_transfers",
                                case.maturity.cross_host_transfer_count,
                                false,
                            ),
                        ],
                    );
                    record.observed_at = Some(case.formed_at.to_string());
                    record.actions.push(operator_action(
                        "review_candidate",
                        "Review candidate",
                        "R1",
                        true,
                        false,
                    ));
                    record
                }));
                records.extend(inspector.experience_patterns.iter().map(|pattern| {
                    let mut record = operator_record(
                        &format!("experience-pattern:{}", pattern.pattern_id),
                        "experience_pattern",
                        pattern
                            .invariant_core
                            .first()
                            .map_or("Experience pattern", String::as_str),
                        &pattern.required_local_probe,
                        &format!("{:?}", pattern.maturity.state).to_ascii_lowercase(),
                        "candidate_prior",
                        vec![
                            operator_field("pattern_id", &pattern.pattern_id, true),
                            operator_field("member_cases", pattern.member_case_refs.len(), false),
                            operator_field(
                                "negative_transfers",
                                pattern.maturity.negative_transfer_count,
                                false,
                            ),
                        ],
                    );
                    record.observed_at = Some(pattern.formed_at.to_string());
                    record
                }));
            }
            for view in &snapshot.task_cognition {
                records.extend(
                    view.procedural_skills
                        .included_skills
                        .iter()
                        .map(|skill_id| {
                            operator_record(
                                &format!("skill:{skill_id}"),
                                "procedural_skill",
                                &format!("Skill {skill_id}"),
                                "Included by the current governed packet.",
                                "included",
                                "skill_lifecycle",
                                vec![operator_field("skill_id", skill_id, true)],
                            )
                        }),
                );
                records.extend(
                    view.procedural_skills
                        .excluded_skills
                        .iter()
                        .map(|skill_id| {
                            operator_record(
                                &format!("skill:{skill_id}"),
                                "procedural_skill",
                                &format!("Skill {skill_id}"),
                                "Excluded by lifecycle, scope or distractor filtering.",
                                "excluded",
                                "skill_lifecycle",
                                vec![operator_field("skill_id", skill_id, true)],
                            )
                        }),
                );
            }
        }
        OperatorProjectionKind::SleepMeta => {
            if let Some(inspector) = &snapshot.memory_inspector {
                records.extend(inspector.cognitive_lab_results.iter().map(|report| {
                    operator_record(
                        &format!("cognitive-lab:{}", report.run_id),
                        "replay_holdout_report",
                        &format!("Cognitive lab {}", report.run_id),
                        "Controlled replay/holdout evidence",
                        "completed",
                        "governor_evaluation",
                        vec![
                            operator_field("run_id", &report.run_id, true),
                            operator_field("cases", report.results.len(), false),
                            operator_field("extra_model_calls", report.extra_model_calls, false),
                            operator_field(
                                "false_suppression_count",
                                report.false_suppression_count,
                                false,
                            ),
                        ],
                    )
                }));
            }
        }
        OperatorProjectionKind::AgentsRouting => {
            records.extend(
                snapshot
                    .routing
                    .host_sessions
                    .iter()
                    .map(operator_host_record),
            );
            records.extend(
                snapshot
                    .routing
                    .task_role_leases
                    .iter()
                    .map(operator_task_role_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .controller_leases
                    .iter()
                    .map(operator_controller_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .work_leases
                    .iter()
                    .map(operator_work_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .worktree_leases
                    .iter()
                    .map(operator_worktree_lease_record),
            );
            records.extend(
                snapshot
                    .routing
                    .operation_jobs
                    .iter()
                    .map(operator_job_record),
            );
            records.extend(
                snapshot
                    .routing
                    .work_conflicts
                    .iter()
                    .map(operator_work_conflict_record),
            );
            records.extend(snapshot.routing.route_decisions.iter().map(|decision| {
                operator_record(
                    &decision.decision_receipt,
                    "route_decision",
                    &format!("{:?}", decision.contour),
                    &format!("selected {}", decision.selected_route.host_id),
                    "effective",
                    "governor_policy",
                    vec![
                        operator_field("receipt", &decision.decision_receipt, true),
                        operator_field("host", &decision.selected_route.host_id, true),
                        operator_field("cost_latency", &decision.cost_latency_estimate, false),
                    ],
                )
            }));
        }
        OperatorProjectionKind::Autonomy => {
            records.extend(snapshot.runs.iter().map(operator_run_record));
            if let Some(task_id) = snapshot
                .task_cognition
                .first()
                .map(|view| view.task_contract.task_id)
            {
                let mut control = operator_record(
                    &format!("autonomy-control:{task_id}"),
                    "autonomy_control",
                    "Create bounded autonomy run",
                    "Submit one complete typed Draft AutonomyRunContract JSON object.",
                    "available",
                    "governor_control_plane",
                    vec![operator_field("task_id", task_id, true)],
                );
                control.actions.push(operator_action(
                    "create_autonomy_run",
                    "Create Draft run",
                    "R1",
                    true,
                    false,
                ));
                records.push(control);
            }
        }
        OperatorProjectionKind::Approvals => {
            records.extend(snapshot.approvals.iter().map(operator_approval_record));
        }
        OperatorProjectionKind::TimelineOperations => {
            records.extend(snapshot.timeline.event_refs.iter().map(|event_ref| {
                operator_record(
                    event_ref,
                    "timeline_event",
                    event_ref,
                    "Canonical transition or receipt reference",
                    "observed",
                    "governor",
                    vec![operator_field("event_ref", event_ref, true)],
                )
            }));
            records.extend(snapshot.timeline.incident_refs.iter().map(|incident_ref| {
                operator_record(
                    incident_ref,
                    "incident",
                    incident_ref,
                    "Operational incident reference",
                    "open_or_recorded",
                    "governor",
                    vec![operator_field("incident_ref", incident_ref, true)],
                )
            }));
            records.extend(snapshot.incidents.iter().map(operator_incident_record));
            records.extend(snapshot.backup_inventory.iter().map(operator_backup_record));
            records.extend(
                snapshot
                    .routing
                    .operation_jobs
                    .iter()
                    .map(operator_job_record),
            );
            records.extend(snapshot.log_handles.iter().map(|handle| {
                operator_record(
                    handle,
                    "log_handle",
                    handle,
                    "Redacted native runtime log handle.",
                    "observed",
                    "governor_log_service",
                    vec![operator_field("handle", handle, true)],
                )
            }));
        }
    }
    records
}

pub(super) fn operator_run_record(run: &eliot_types::AutonomyRunView) -> OperatorRecordView {
    let mut record = operator_record(
        &format!("autonomy-run:{}", run.contract.autonomy_run_id),
        "autonomy_run",
        &run.contract.user_goal,
        &format!(
            "{} @ revision {}",
            run.finish_status, run.contract.state_revision
        ),
        &run.finish_status,
        "governor_control_plane",
        vec![
            operator_field("run_id", &run.contract.autonomy_run_id, true),
            operator_field("task_id", run.contract.root_task_id, true),
            operator_field("max_agents", run.contract.max_active_agents, false),
            operator_field(
                "max_model_invocations",
                run.contract.max_model_invocations,
                false,
            ),
            operator_field("max_tool_calls", run.contract.max_tool_calls, false),
            operator_field(
                "wall_time_seconds",
                run.contract.max_wall_time_seconds,
                false,
            ),
            operator_field(
                "cost_or_token_budget",
                run.contract
                    .cost_or_token_budget
                    .as_deref()
                    .unwrap_or("none"),
                false,
            ),
            operator_field("model_invocations_used", run.model_invocations_used, false),
            operator_field("tool_calls_used", run.tool_calls_used, false),
            operator_field("wall_time_used_seconds", run.wall_time_used_seconds, false),
            operator_field(
                "required_verifiers",
                run.contract.required_verifiers.join(", "),
                false,
            ),
            operator_field(
                "approval_boundaries",
                run.contract.approval_boundaries.join(", "),
                false,
            ),
            operator_field(
                "pause_conditions",
                run.contract.pause_conditions.join("; "),
                false,
            ),
            operator_field(
                "stop_conditions",
                run.contract.stop_conditions.join("; "),
                false,
            ),
        ],
    );
    record.actions.extend([
        operator_action("start_run", "Start", "R1", false, false),
        operator_action("pause_run", "Pause", "R1", true, false),
        operator_action("resume_run", "Resume", "R1", false, false),
        operator_action("cancel_run", "Cancel", "R1", true, false),
        operator_action(
            "preview_autonomy_edit",
            "Preview Draft edit",
            "R0",
            true,
            false,
        ),
    ]);
    record
}

pub(super) fn operator_host_record(
    binding: &eliot_types::AgentSessionHostBinding,
) -> OperatorRecordView {
    operator_record(
        &format!("agent-session:{}", binding.agent_session_id),
        "host_session",
        &binding.host_identity.implementation_name,
        &format!(
            "{} capabilities; structured={}, resumable={}",
            binding.capability_envelope.capabilities.len(),
            binding.capability_envelope.structured_output,
            binding.capability_envelope.resumable
        ),
        "observed",
        "governor_host_broker",
        vec![
            operator_field("session_id", binding.agent_session_id, true),
            operator_field(
                "host_id",
                format!("{:?}", binding.host_identity.host_id).to_ascii_lowercase(),
                true,
            ),
            operator_field(
                "client_instance_id",
                &binding.host_identity.client_instance_id,
                true,
            ),
            operator_field(
                "capabilities",
                binding.capability_envelope.capabilities.join(", "),
                false,
            ),
            operator_field(
                "role_lease_refs",
                binding.task_role_lease_refs.join(", "),
                false,
            ),
        ],
    )
}

pub(super) fn operator_job_record(job: &eliot_types::OperationJob) -> OperatorRecordView {
    let mut record = operator_record(
        &format!("operation-job:{}", job.job_id),
        "operation_job",
        &job.job_id,
        &format!("Invocation {} on {:?}", job.invocation_id, job.host_id),
        &format!("{:?}", job.state).to_ascii_lowercase(),
        "governor_host_broker",
        vec![
            operator_field("invocation_id", &job.invocation_id, true),
            operator_field(
                "host_id",
                format!("{:?}", job.host_id).to_ascii_lowercase(),
                true,
            ),
            operator_field("attempt", job.attempt, false),
            operator_field("idempotency_key", &job.idempotency_key, true),
            operator_field(
                "result_ref",
                job.result_ref.as_deref().unwrap_or("none"),
                true,
            ),
        ],
    );
    record.observed_at = Some(job.updated_at.to_string());
    record
}

pub(super) fn operator_agent_result_record(
    result: &AgentResultEnvelope,
    dispositions: &[AgentResultDisposition],
) -> OperatorRecordView {
    let disposition = dispositions
        .iter()
        .filter(|item| item.result_id == result.result_id)
        .max_by_key(|item| item.created_at);
    let mut record = operator_record(
        &result.result_id,
        "agent_result",
        &result.summary,
        &format!(
            "Invocation {} on {:?}",
            result.invocation_id, result.host_id
        ),
        &disposition.map_or_else(
            || format!("{:?}", result.status).to_ascii_lowercase(),
            |item| format!("{:?}", item.kind).to_ascii_lowercase(),
        ),
        "governor_host_broker",
        vec![
            operator_field("result_id", &result.result_id, true),
            operator_field("invocation_id", &result.invocation_id, true),
            operator_field(
                "host_id",
                format!("{:?}", result.host_id).to_ascii_lowercase(),
                true,
            ),
            operator_field("candidate_only", result.candidate_only, false),
            operator_field("artifact_refs", result.artifact_refs.join(", "), true),
            operator_field("evidence_refs", result.evidence_refs.join(", "), true),
            operator_field(
                "allowed_dispositions",
                "rejected, probe_requested (acceptance requires controller finalization)",
                false,
            ),
        ],
    );
    record.relationships.push(OperatorRelationshipView {
        relation: "invocation".to_owned(),
        target_ref: result.invocation_id.clone(),
        evidence_ref: result
            .canonical_receipt
            .as_ref()
            .map(|receipt| receipt.receipt_id.to_string()),
        observed_at: None,
    });
    if disposition.is_none() {
        record.actions.push(operator_action(
            "disposition_agent_result",
            "Reject or request probe",
            "R1",
            true,
            false,
        ));
    } else if let Some(disposition) = disposition {
        record.observed_at = Some(disposition.created_at.to_string());
    }
    record
}

pub(super) fn operator_work_item_record(item: &eliot_types::WorkItem) -> OperatorRecordView {
    let mut record = operator_record(
        &format!("work-item:{}", item.work_item_id),
        "work_item",
        &item.goal,
        &format!("{} / {}", item.project, item.task),
        &format!("{:?}", item.status).to_ascii_lowercase(),
        "governor_work_queue",
        vec![
            operator_field("work_item_id", item.work_item_id, true),
            operator_field("required", item.required, false),
            operator_field(
                "required_verifiers",
                item.required_verifiers
                    .iter()
                    .map(|verifier| verifier.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                false,
            ),
            operator_field("write_set", item.scope.write_set.join(", "), false),
            operator_field("blocker_refs", item.conflict_refs.join(", "), true),
        ],
    );
    if let Some(lease_id) = item.active_lease_id {
        record.relationships.push(OperatorRelationshipView {
            relation: "active_lease".to_owned(),
            target_ref: format!("work-lease:{lease_id}"),
            evidence_ref: item
                .write_receipt
                .as_ref()
                .map(|receipt| receipt.receipt_id.to_string()),
            observed_at: Some(item.updated_at.to_string()),
        });
    }
    record.observed_at = Some(item.updated_at.to_string());
    record
}

pub(super) fn operator_work_conflict_record(
    conflict: &eliot_types::WorkConflict,
) -> OperatorRecordView {
    let status = conflict.resolution.map_or("open".to_owned(), |resolution| {
        format!("{resolution:?}").to_ascii_lowercase()
    });
    let mut record = operator_record(
        &format!("work-conflict:{}", conflict.conflict_id),
        "work_conflict",
        &format!("{:?}", conflict.kind),
        &conflict.detail,
        &status,
        "governor_work_queue",
        vec![
            operator_field("work_item_id", conflict.work_item_id, true),
            operator_field("work_lease_id", conflict.work_lease_id, true),
            operator_field("paths", conflict.paths.join(", "), true),
        ],
    );
    record.observed_at = Some(conflict.detected_at.to_string());
    record
}

pub(super) fn operator_task_role_lease_record(
    lease: &eliot_types::TaskRoleLease,
) -> OperatorRecordView {
    operator_record(
        &format!("task-role-lease:{}", lease.role_lease_id),
        "task_role_lease",
        &format!("{:?}", lease.role),
        &format!("Task {} epoch {}", lease.task_id, lease.epoch),
        "active_or_expiring",
        "governor_host_broker",
        vec![
            operator_field("session_id", lease.agent_session_id, true),
            operator_field("expires_at", lease.expires_at, false),
            operator_field("capability_scope", lease.capability_scope.join(", "), false),
        ],
    )
}

pub(super) fn operator_controller_lease_record(
    lease: &eliot_types::ControllerLease,
) -> OperatorRecordView {
    operator_record(
        &format!("controller-lease:{}", lease.controller_lease_id),
        "controller_lease",
        "Controller lease",
        &format!("Task {} epoch {}", lease.task_id, lease.epoch),
        "active_or_expiring",
        "governor_host_broker",
        vec![
            operator_field("session_id", lease.agent_session_id, true),
            operator_field("expires_at", lease.expires_at, false),
        ],
    )
}

pub(super) fn operator_work_lease_record(lease: &eliot_types::WorkLease) -> OperatorRecordView {
    operator_record(
        &format!("work-lease:{}", lease.work_lease_id),
        "work_lease",
        &format!("{:?}", lease.role),
        &lease.decision.message,
        &format!("{:?}", lease.state).to_ascii_lowercase(),
        "governor_work_queue",
        vec![
            operator_field("work_item_id", lease.work_item_id, true),
            operator_field("session_id", lease.agent_session_id, true),
            operator_field("epoch", lease.epoch, false),
            operator_field("expires_at", lease.expires_at, false),
            operator_field("write_set", lease.scope.write_set.join(", "), false),
            operator_field("conflict_refs", lease.conflict_refs.join(", "), true),
        ],
    )
}

pub(super) fn operator_worktree_lease_record(
    lease: &eliot_types::WorktreeLease,
) -> OperatorRecordView {
    operator_record(
        &format!("worktree-lease:{}", lease.worktree_lease_id),
        "worktree_lease",
        &lease.branch_name,
        &lease.worktree_path,
        &format!("{:?}", lease.state).to_ascii_lowercase(),
        "governor_worktree_lease_service",
        vec![
            operator_field("work_item_id", lease.work_item_id, true),
            operator_field("work_lease_id", lease.work_lease_id, true),
            operator_field("base_commit", &lease.base_commit, true),
            operator_field(
                "allowed_write_set",
                lease.allowed_write_set.join(", "),
                false,
            ),
            operator_field("expires_at", lease.expires_at, false),
        ],
    )
}

pub(super) fn operator_backup_record(
    backup: &eliot_types::BackupInventoryEntry,
) -> OperatorRecordView {
    let mut record = operator_record(
        &format!("backup:{}", backup.backup_id),
        "backup_inventory",
        &backup.backup_id,
        &format!(
            "Age {} seconds; verified={}",
            backup.age_seconds, backup.verified
        ),
        &format!("{:?}", backup.status).to_ascii_lowercase(),
        "governor_backup_service",
        vec![
            operator_field("manifest_ref", &backup.manifest_ref, true),
            operator_field("age_seconds", backup.age_seconds, false),
            operator_field("verified", backup.verified, false),
        ],
    );
    record.observed_at = Some(backup.created_at.to_string());
    record
}

pub(super) fn operator_incident_record(
    incident: &eliot_types::IncidentRecord,
) -> OperatorRecordView {
    let mut record = operator_record(
        &format!("incident:{}", incident.incident_id),
        "incident",
        &incident.summary,
        &format!("{:?} / {:?}", incident.severity, incident.kind),
        &format!("{:?}", incident.status).to_ascii_lowercase(),
        "governor_incident_service",
        vec![
            operator_field("incident_id", &incident.incident_id, true),
            operator_field(
                "affected_surfaces",
                incident.affected_surfaces.join(", "),
                false,
            ),
            operator_field("evidence_refs", incident.evidence_refs.join(", "), true),
            operator_field(
                "recovery_commands",
                incident.recovery_commands.join("; "),
                true,
            ),
        ],
    );
    record.observed_at = Some(incident.opened_at.to_string());
    record
}

pub(super) fn operator_approval_record(approval: &ApprovalView) -> OperatorRecordView {
    let mut record = operator_record(
        &format!("approval:{}", approval.approval_id),
        "approval",
        &approval.reason_summary,
        &format!("{} exact action", approval.risk_tier),
        if approval.decision_receipt.is_some() {
            "decided"
        } else {
            "pending"
        },
        "governor_safety_gate",
        vec![
            operator_field("approval_id", &approval.approval_id, true),
            operator_field("exact_action_hash", &approval.exact_action_hash, true),
            operator_field("verifier", &approval.verifier, true),
            operator_field(
                "write_or_resource_set",
                approval.write_or_resource_set.join(", "),
                true,
            ),
            operator_field(
                "rollback_or_compensation",
                &approval.rollback_or_compensation,
                false,
            ),
            operator_field("expires_at", approval.expires_at, false),
        ],
    );
    if approval.decision_receipt.is_none() {
        record.actions.extend([
            operator_action("grant_approval", "Grant exact action", "R3", false, true),
            operator_action("deny_approval", "Deny exact action", "R0", true, true),
        ]);
    }
    record
}

pub(super) fn operator_memory_actions() -> Vec<OperatorActionView> {
    vec![
        operator_action(
            "request_revalidation",
            "Request revalidation",
            "R0",
            false,
            false,
        ),
        operator_action("contest_memory", "Contest", "R1", true, false),
        operator_action("suppress_memory", "Suppress", "R1", true, false),
        operator_action("archive_memory", "Archive", "R1", true, false),
        operator_action("restore_memory", "Restore", "R1", true, false),
    ]
}

pub(super) fn operator_schema_records() -> Vec<OperatorRecordView> {
    let Ok(manifest) = serde_json::from_str::<Value>(OPERATOR_CONTRACT_MANIFEST) else {
        return Vec::new();
    };
    manifest["schema_families"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|family| {
            Some((
                family.get("id")?.as_str()?,
                family.get("family")?.as_str()?,
                family.get("owner")?.as_str()?,
                family.get("write_authority")?.as_str()?,
                family,
            ))
        })
        .map(|(id, family, owner, authority, definition)| {
            operator_record(
                &format!("schema:{id}"),
                "schema_family",
                family,
                owner,
                "read_only",
                authority,
                vec![
                    operator_field("schema_version", OPERATOR_SCHEMA_VERSION, true),
                    operator_field(
                        "read_authority",
                        definition["read_authority"]
                            .as_str()
                            .unwrap_or("HumanOperator"),
                        false,
                    ),
                    operator_field("write_authority", authority, false),
                    operator_field(
                        "required_fields",
                        definition["required_fields"].to_string(),
                        false,
                    ),
                    operator_field(
                        "relation_directions",
                        definition["relations"].to_string(),
                        false,
                    ),
                    operator_field("migration", definition["migration"].to_string(), false),
                    operator_field(
                        "index_health",
                        definition["index_health"].to_string(),
                        false,
                    ),
                    operator_field("docs_ref", definition["docs_ref"].to_string(), true),
                ],
            )
        })
        .collect()
}

pub(super) fn operator_query_lab_records() -> Vec<OperatorRecordView> {
    let Ok(manifest) = serde_json::from_str::<Value>(OPERATOR_CONTRACT_MANIFEST) else {
        return Vec::new();
    };
    manifest["query_operations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|operation| {
            Some((
                operation.get("id")?.as_str()?,
                operation.get("title")?.as_str()?,
                operation,
            ))
        })
        .map(|(id, title, definition)| {
            operator_record(
                &format!("semantic-query:{id}"),
                "semantic_query",
                title,
                "Execute a closed, bounded Governor read operation.",
                "available",
                "governor_read_api",
                vec![
                    operator_field("operation", id, true),
                    operator_field("parameters", definition["parameters"].to_string(), false),
                    operator_field(
                        "result_modes",
                        definition["result_modes"].to_string(),
                        false,
                    ),
                    operator_field("raw_sql", "forbidden", false),
                    operator_field("payload_budget", "server bounded", false),
                ],
            )
        })
        .collect()
}

pub(super) fn operator_record(
    record_ref: &str,
    record_kind: &str,
    title: &str,
    summary: &str,
    status: &str,
    authority: &str,
    fields: Vec<OperatorFieldView>,
) -> OperatorRecordView {
    OperatorRecordView {
        record_ref: record_ref.to_owned(),
        record_kind: record_kind.to_owned(),
        title: title.to_owned(),
        summary: summary.to_owned(),
        status: status.to_owned(),
        lifecycle: None,
        authority: authority.to_owned(),
        observed_at: None,
        fields,
        relationships: Vec::new(),
        actions: Vec::new(),
    }
}

pub(super) fn operator_field(
    label: &str,
    value: impl std::fmt::Display,
    copyable: bool,
) -> OperatorFieldView {
    OperatorFieldView {
        label: label.to_owned(),
        value: value.to_string(),
        copyable,
    }
}

pub(super) fn operator_action(
    command: &str,
    label: &str,
    risk_tier: &str,
    requires_reason: bool,
    requires_exact_action_hash: bool,
) -> OperatorActionView {
    OperatorActionView {
        command: command.to_owned(),
        label: label.to_owned(),
        risk_tier: risk_tier.to_owned(),
        requires_reason,
        requires_exact_action_hash,
    }
}

pub(super) fn operator_record_matches(
    record: &OperatorRecordView,
    filter: &OperatorProjectionFilter,
) -> bool {
    let equals = |actual: &str, expected: &Option<String>| {
        expected
            .as_deref()
            .is_none_or(|expected| actual.eq_ignore_ascii_case(expected.trim()))
    };
    if !equals(&record.record_kind, &filter.record_kind)
        || !equals(&record.status, &filter.status)
        || !equals(&record.authority, &filter.authority)
        || !filter.lifecycle.as_deref().is_none_or(|expected| {
            record
                .lifecycle
                .as_deref()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(expected.trim()))
        })
        || !filter.observed_after.as_deref().is_none_or(|after| {
            record
                .observed_at
                .as_deref()
                .is_some_and(|observed| observed >= after)
        })
        || !filter.observed_before.as_deref().is_none_or(|before| {
            record
                .observed_at
                .as_deref()
                .is_some_and(|observed| observed <= before)
        })
    {
        return false;
    }
    filter.search.as_deref().is_none_or(|search| {
        let search = search.trim().to_ascii_lowercase();
        search.is_empty()
            || record.record_ref.to_ascii_lowercase().contains(&search)
            || record.title.to_ascii_lowercase().contains(&search)
            || record.summary.to_ascii_lowercase().contains(&search)
            || record
                .fields
                .iter()
                .any(|field| field.value.to_ascii_lowercase().contains(&search))
    })
}

#[cfg(test)]
pub(super) fn operator_observation_record(
    observation: eliot_types::ToolObservation,
    receipt_kind: &str,
) -> OperatorRecordView {
    let body = observation
        .payload
        .get("receipt_body")
        .cloned()
        .unwrap_or(Value::Null);
    let display = |name: &str| {
        body.get(name).map(|value| {
            value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned)
        })
    };
    let subject = [
        "target_ref",
        "subject_ref",
        "autonomy_run_id",
        "run_id",
        "trace_ref",
        "task_id",
    ]
    .iter()
    .find_map(|name| display(name))
    .unwrap_or_else(|| observation.observation_id.clone());
    let status = ["status", "to_state", "to", "disposition", "correct"]
        .iter()
        .find_map(|name| display(name))
        .unwrap_or_else(|| "canonical".to_owned());
    let observed_at = [
        "created_at",
        "started_at",
        "finished_at",
        "transitioned_at",
        "generated_at",
    ]
    .iter()
    .find_map(|name| display(name));
    let mut fields = vec![
        operator_field("observation_id", &observation.observation_id, true),
        operator_field("receipt_kind", receipt_kind, true),
        operator_field("receipt_body_json", body.to_string(), true),
    ];
    if let Value::Object(object) = &body {
        fields.extend(object.iter().take(64).map(|(name, value)| {
            operator_field(
                name,
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned),
                name.ends_with("_ref") || name.ends_with("_refs") || name.ends_with("_id"),
            )
        }));
    }
    let evidence_ref = display("evidence_ref");
    let mut relationships = Vec::new();
    if let Value::Object(object) = &body {
        for (name, value) in object.iter().take(64) {
            if name.ends_with("_ref")
                || name.ends_with("_id")
                || matches!(name.as_str(), "from" | "to")
            {
                if let Some(target_ref) = value.as_str() {
                    relationships.push(OperatorRelationshipView {
                        relation: name.clone(),
                        target_ref: target_ref.to_owned(),
                        evidence_ref: evidence_ref.clone(),
                        observed_at: observed_at.clone(),
                    });
                }
            } else if name.ends_with("_refs") {
                relationships.extend(value.as_array().into_iter().flatten().filter_map(|target| {
                    target.as_str().map(|target_ref| OperatorRelationshipView {
                        relation: name.clone(),
                        target_ref: target_ref.to_owned(),
                        evidence_ref: evidence_ref.clone(),
                        observed_at: observed_at.clone(),
                    })
                }));
            }
        }
    }
    OperatorRecordView {
        record_ref: format!("canonical-observation:{}", observation.observation_id),
        record_kind: receipt_kind.to_owned(),
        title: subject,
        summary: observation.observation,
        status,
        lifecycle: display("to_state"),
        authority: "writer_actor_canonical_store".to_owned(),
        observed_at,
        fields,
        relationships,
        actions: Vec::new(),
    }
}

pub(super) fn canonical_operator_record<T: serde::Serialize>(
    record: &eliot_store::CanonicalRecord<T>,
    record_kind: &str,
) -> Result<OperatorRecordView> {
    let body = serde_json::to_value(&record.receipt_body)?;
    let display_value = |name: &str| {
        body.get(name).map_or_else(
            || None,
            |value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| Some(value.to_string()))
            },
        )
    };
    let status = ["status", "to_state", "to", "disposition", "correct"]
        .iter()
        .find_map(|name| display_value(name))
        .unwrap_or_else(|| "canonical".to_owned());
    let observed_at = ["created_at", "started_at", "finished_at"]
        .iter()
        .find_map(|name| display_value(name));
    let mut view = operator_record(
        &format!("canonical:{}", record.record_id),
        record_kind,
        &record.subject_ref,
        &format!("Canonical {} record from WriterActor", record.receipt_kind),
        &status,
        "writer_actor_canonical_store",
        vec![
            operator_field("subject_ref", &record.subject_ref, true),
            operator_field("receipt_kind", &record.receipt_kind, true),
            operator_field("receipt_id", record.canonical_receipt.receipt_id, true),
            operator_field("write_id", record.canonical_receipt.write_id, true),
            operator_field(
                "memory_revision",
                record.memory_revision.map_or_else(
                    || "none".to_owned(),
                    |revision| revision.value().to_string(),
                ),
                true,
            ),
            operator_field(
                "project_sequence",
                record.project_sequence.map_or_else(
                    || "none".to_owned(),
                    |sequence| sequence.value().to_string(),
                ),
                true,
            ),
        ],
    );
    view.fields
        .push(operator_field("receipt_body_json", body.to_string(), true));
    if let Value::Object(object) = &body {
        view.fields
            .extend(object.iter().take(64).map(|(name, value)| {
                operator_field(
                    name,
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned),
                    name.ends_with("_ref") || name.ends_with("_refs") || name.ends_with("_id"),
                )
            }));
        for (name, value) in object.iter().take(64) {
            if (name.ends_with("_ref")
                || name.ends_with("_id")
                || matches!(name.as_str(), "from" | "to"))
                && let Some(target_ref) = value.as_str()
            {
                view.relationships.push(OperatorRelationshipView {
                    relation: name.clone(),
                    target_ref: target_ref.to_owned(),
                    evidence_ref: display_value("evidence_ref"),
                    observed_at: observed_at.clone(),
                });
            }
        }
    }
    view.observed_at = observed_at;
    view.lifecycle = body
        .get("to_state")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(view)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn persist_operator_lifecycle_transition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    memory_handle: &str,
    operator: ForgettingOperator,
    reason: ForgettingReason,
    binding: OperatorLifecycleBinding,
    idempotency_key: &str,
) -> Result<WriteReceiptRef> {
    let primary_key = format!("{idempotency_key}:primary");
    let policy_id = format!(
        "operator-policy-{}",
        blake3::hash(
            serde_json::to_string(&(
                project_id,
                task_id,
                memory_handle,
                operator,
                reason,
                &binding,
            ))?
            .as_bytes()
        )
    );
    let expected_write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::StateTransition,
        &primary_key,
    );
    if let Some(record) = state
        .store
        .canonical_record_by_write_id::<eliot_types::MemoryStateTransition>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::StateTransition.as_str()],
            expected_write_id,
        )
        .await?
    {
        if record.receipt_body.policy_ref == policy_id {
            return Ok(record.canonical_receipt);
        }
        anyhow::bail!("operator idempotency_key was already used for a different command");
    }
    let latest_transition = state
        .store
        .canonical_records_by_subject_ref::<eliot_types::MemoryStateTransition>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::StateTransition.as_str()],
            memory_handle,
            1,
        )
        .await?
        .into_iter()
        .next();
    let lifecycle = latest_transition.map_or_else(MemoryLifecycleService::new, |record| {
        MemoryLifecycleService::new().with_state(memory_handle, record.receipt_body.to_state)
    });
    let minority_pressure = state
        .store
        .canonical_records_by_subject_ref::<MinorityPressureRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::MinorityPressureRecord.as_str()],
            memory_handle,
            128,
        )
        .await?;
    let now = time::OffsetDateTime::now_utc();
    let reactivation = (operator == ForgettingOperator::Restore).then(|| ReactivationCondition {
        condition_id: format!(
            "operator-restore:{}",
            blake3::hash(memory_handle.as_bytes())
        ),
        description: "HumanOperator supplied evidence for governed restoration".to_owned(),
        required_evidence_refs: binding.evidence_refs.clone(),
        required_current_truth_change: None,
        expires_at: None,
    });
    let mut policy = ForgettingPolicyService::propose(
        project_id,
        memory_handle,
        operator,
        reason,
        binding.evidence_refs.clone(),
        None,
        reactivation,
    );
    policy.policy_id = policy_id;
    policy.precondition_refs = binding.precondition_refs;
    policy.approval_ref = binding.approval_ref;
    policy.expected_current_state = lifecycle.state_for(memory_handle);
    policy.effective_at = Some(now);
    policy.created_at = now;
    let transition = lifecycle
        .transition_for_policy_at(
            &policy,
            "authenticated HumanOperator",
            &minority_pressure
                .iter()
                .map(|record| record.receipt_body.clone())
                .collect::<Vec<_>>(),
            now,
        )
        .map_err(|decision| anyhow::anyhow!("lifecycle transition denied: {decision:?}"))?;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::StateTransition,
        &primary_key,
        &transition,
    )
    .await?;
    let trajectory = MemoryLifecycleService::trajectory_correctness(
        std::slice::from_ref(&transition),
        transition.expected_admission_effect,
        binding.evidence_refs,
    );
    let _ = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::MemoryTrajectoryCorrectness,
        &format!("{idempotency_key}:trajectory"),
        &trajectory,
    )
    .await?;
    Ok(receipt)
}

pub(super) async fn persist_operator_minority_pressure(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    memory_handle: &str,
    evidence_refs: Vec<String>,
    idempotency_key: &str,
) -> Result<WriteReceiptRef> {
    let primary_key = format!("{idempotency_key}:primary");
    let minority_record_id = format!(
        "operator-minority-{}",
        blake3::hash(
            serde_json::to_string(&(project_id, task_id, memory_handle, &evidence_refs))?
                .as_bytes()
        )
    );
    let expected_write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::MinorityPressureRecord,
        &primary_key,
    );
    if let Some(record) = state
        .store
        .canonical_record_by_write_id::<MinorityPressureRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::MinorityPressureRecord.as_str()],
            expected_write_id,
        )
        .await?
    {
        if record.receipt_body.minority_record_id == minority_record_id {
            return Ok(record.canonical_receipt);
        }
        anyhow::bail!("operator idempotency_key was already used for a different command");
    }
    let record = MinorityPressureRecord {
        minority_record_id,
        project_id,
        minority_claim_ref: memory_handle.to_owned(),
        majority_claim_ref: None,
        why_minority_matters: "HumanOperator contested this memory with explicit evidence"
            .to_owned(),
        discriminative_probe: None,
        status: MinorityPressureStatus::Open,
        pinned: true,
        release_condition: Some("resolved by a canonical governed review".to_owned()),
        resolved_by_ref: None,
        suppression_forbidden_until: None,
        evidence_refs,
        created_at: time::OffsetDateTime::now_utc(),
        write_receipt: None,
    };
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::MinorityPressureRecord,
        &primary_key,
        &record,
    )
    .await?;
    Ok(receipt)
}

pub(super) async fn persist_operator_control_request(
    state: &McpState,
    context: AuthenticatedRequestContext,
    draft: OperatorControlRequestDraft<'_>,
) -> Result<WriteReceiptRef> {
    validate_broker_text("operator control operation", draft.operation, 128)?;
    validate_broker_text("operator control target_ref", draft.target_ref, 1024)?;
    validate_broker_text("operator control disposition", draft.disposition, 128)?;
    if let Some(hash) = draft.exact_action_hash.as_deref() {
        validate_broker_text("operator exact action hash", hash, 512)?;
    }
    let expected_write_id = deterministic_canonical_write_id(
        draft.project_id,
        Some(draft.task_id),
        CanonicalReceiptKind::OperatorControlRequest,
        draft.idempotency_key,
    );
    if let Some(record) = state
        .store
        .canonical_record_by_write_id::<OperatorControlRequest>(
            draft.project_id,
            Some(draft.task_id),
            &[CanonicalReceiptKind::OperatorControlRequest.as_str()],
            expected_write_id,
        )
        .await?
    {
        let existing = &record.receipt_body;
        if existing.operation == draft.operation
            && existing.target_ref == draft.target_ref
            && existing.disposition == draft.disposition
            && existing.exact_action_hash == draft.exact_action_hash
            && existing.reason_or_evidence_refs == draft.reason_or_evidence_refs
        {
            return Ok(record.canonical_receipt);
        }
        anyhow::bail!("operator idempotency_key was already used for a different command");
    }
    let request = OperatorControlRequest {
        request_id: format!(
            "operator-control-request:{}",
            blake3::hash(draft.idempotency_key.as_bytes())
        ),
        project_id: draft.project_id,
        task_id: draft.task_id,
        operation: draft.operation.to_owned(),
        target_ref: draft.target_ref.to_owned(),
        disposition: draft.disposition.to_owned(),
        exact_action_hash: draft.exact_action_hash,
        reason_or_evidence_refs: draft.reason_or_evidence_refs,
        requested_by: format!("session:{}", context.session_id),
        created_at: time::OffsetDateTime::now_utc(),
        canonical_receipt: None,
    };
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        draft.project_id,
        Some(draft.task_id),
        CanonicalReceiptKind::OperatorControlRequest,
        draft.idempotency_key,
        &request,
    )
    .await?;
    Ok(receipt)
}

pub(super) async fn execute_operator_autonomy_approval_decision(
    state: &McpState,
    context: AuthenticatedRequestContext,
    input: OperatorAutonomyApprovalDecision<'_>,
) -> Result<Value> {
    let request_write_id = approval_request_write_id(input.approval_id)?;
    let request = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalRequestRecord>(
            input.project_id,
            Some(input.task_id),
            &[CanonicalReceiptKind::AutonomyApprovalRequest.as_str()],
            request_write_id,
        )
        .await?
        .context("operator autonomy approval request does not resolve canonically")?;
    if request.receipt_body.approval_id != input.approval_id
        || request.receipt_body.project_id != input.project_id
        || request.receipt_body.task_id != input.task_id
        || request.receipt_body.request_write_id != request_write_id
        || request.canonical_receipt.write_id != request_write_id
    {
        anyhow::bail!("operator autonomy approval request scope or identity is invalid");
    }
    if request.receipt_body.exact_action_hash != input.exact_action_hash {
        anyhow::bail!("operator exact action hash differs from the canonical approval request");
    }
    dispatch_autonomy_approval_decide(
        state,
        context,
        json!({
            "project_id": input.project_id,
            "task_id": input.task_id,
            "autonomy_run_id": request.receipt_body.autonomy_run_id,
            "approval_id": input.approval_id,
            "expected_approval_revision": request.receipt_body.approval_revision,
            "decision": input.decision,
            "reason": input.reason,
            "idempotency_key": input.idempotency_key,
        }),
    )
    .await
}

pub(super) fn operator_candidate_claim_id(candidate_ref: &str) -> Result<ClaimId> {
    let candidate_ref = candidate_ref.trim();
    let candidate_ref = candidate_ref
        .strip_prefix("claim:")
        .or_else(|| candidate_ref.strip_prefix("candidate:"))
        .or_else(|| candidate_ref.strip_prefix("eliot/claim/"))
        .unwrap_or(candidate_ref);
    ClaimId::from_str(candidate_ref).context("parse exact operator candidate reference")
}

pub(super) async fn resolve_operator_candidate(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    candidate_ref: &str,
) -> Result<CanonicalClaimCard> {
    let claim_id = operator_candidate_claim_id(candidate_ref)?;
    let candidate = state
        .store
        .claim_card_by_id(project_id, claim_id)
        .await?
        .context("operator candidate does not resolve in the selected canonical project")?;
    if !operator_candidate_scope_matches(&candidate, project_id, task_id) {
        anyhow::bail!("operator candidate scope differs from the selected task/project");
    }
    let dispositioned = candidate
        .payload
        .get("operator_candidate_disposition")
        .is_some_and(Value::is_object);
    if candidate
        .payload
        .get("candidate_only")
        .and_then(Value::as_bool)
        != Some(true)
        && !dispositioned
    {
        anyhow::bail!("operator target is not a governed candidate-only claim");
    }
    if candidate
        .payload
        .get("provenance_refs")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        anyhow::bail!("operator candidate has no canonical source provenance");
    }
    Ok(candidate)
}

pub(super) fn operator_candidate_scope_matches(
    candidate: &CanonicalClaimCard,
    project_id: ProjectId,
    task_id: TaskId,
) -> bool {
    candidate.project_id == project_id && candidate.task_id == Some(task_id)
}

pub(super) fn require_operator_candidate_evidence(
    candidate: &CanonicalClaimCard,
    evidence_refs: &[String],
) -> Result<Vec<String>> {
    if evidence_refs.is_empty() {
        anyhow::bail!("operator candidate disposition requires source verifier evidence");
    }
    let mut supplied = std::collections::BTreeSet::new();
    for evidence_ref in evidence_refs {
        if !supplied.insert(evidence_ref.as_str()) {
            anyhow::bail!("duplicate operator candidate evidence reference");
        }
    }
    let source_refs = candidate
        .payload
        .get("provenance_refs")
        .and_then(Value::as_array)
        .context("operator candidate has no source provenance refs")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .context("operator candidate source provenance ref is invalid")
        })
        .collect::<Result<Vec<_>>>()?;
    if source_refs.is_empty()
        || source_refs
            .iter()
            .any(|source_ref| !supplied.contains(source_ref.as_str()))
    {
        anyhow::bail!("operator evidence does not cover the candidate's exact source provenance");
    }
    Ok(source_refs)
}

pub(super) fn operator_candidate_lifecycle_binding(
    candidate: &CanonicalClaimCard,
    project_id: ProjectId,
    task_id: TaskId,
    evidence_refs: &[String],
    source_provenance_refs: &[String],
    operator_session_id: SessionId,
) -> Result<OperatorLifecycleBinding> {
    Ok(OperatorLifecycleBinding {
        evidence_refs: evidence_refs.to_vec(),
        precondition_refs: vec![
            format!("candidate-claim:{}", candidate.claim_id),
            format!("candidate-write:{}", candidate.write_id),
            format!("candidate-revision:{}", candidate.memory_revision.value()),
            format!("candidate-project:{project_id}"),
            format!("candidate-task:{task_id}"),
            format!(
                "candidate-provenance-blake3:{}",
                canonical_struct_hash(&source_provenance_refs.to_vec())?
            ),
        ],
        approval_ref: Some(format!("operator-session:{operator_session_id}")),
    })
}

pub(super) fn deterministic_operator_candidate_write_id(
    project_id: ProjectId,
    task_id: TaskId,
    idempotency_key: &str,
) -> WriteId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"eliot-operator-candidate-disposition-v1");
    hasher.update(project_id.to_string().as_bytes());
    hasher.update(task_id.to_string().as_bytes());
    hasher.update(idempotency_key.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

pub(super) async fn ensure_operator_candidate_is_active(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    claim_id: ClaimId,
) -> Result<()> {
    let subject_ref = format!("claim:{claim_id}");
    let lifecycle_state = state
        .store
        .canonical_records_by_subject_ref::<eliot_types::MemoryStateTransition>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::StateTransition.as_str()],
            &subject_ref,
            1,
        )
        .await?
        .into_iter()
        .next()
        .map_or(MemoryLifecycleState::Active, |record| {
            record.receipt_body.to_state
        });
    if !matches!(
        lifecycle_state,
        MemoryLifecycleState::Active | MemoryLifecycleState::Restored
    ) {
        anyhow::bail!("operator candidate already has a non-active lifecycle disposition");
    }
    Ok(())
}

pub(super) async fn promote_operator_candidate(
    state: &McpState,
    context: AuthenticatedRequestContext,
    promotion: CandidatePromotion<'_>,
) -> Result<WriteReceiptRef> {
    let project_id = promotion.task.project_id;
    let write_id = deterministic_operator_candidate_write_id(
        project_id,
        promotion.task.task_id,
        promotion.idempotency_key,
    );
    if let Some(receipt) = existing_candidate_promotion(state, &promotion, write_id).await? {
        return Ok(receipt);
    }
    let CandidatePromotion {
        task,
        candidate,
        evidence_refs,
        source_provenance_refs,
        idempotency_key,
        actor,
    } = promotion;
    if candidate.status != EpistemicStatus::Candidate {
        anyhow::bail!("only an undispositioned candidate claim can be promoted");
    }
    ensure_operator_candidate_is_active(state, project_id, task.task_id, candidate.claim_id)
        .await?;
    let mut payload = candidate
        .payload
        .as_object()
        .cloned()
        .context("operator candidate payload must be an object")?;
    payload.insert("candidate_only".to_owned(), Value::Bool(false));
    payload.insert(
        "controller_reconciliation_required".to_owned(),
        Value::Bool(false),
    );
    payload.insert("admitted_by_operator".to_owned(), Value::Bool(true));
    payload.insert(
        "operator_candidate_disposition".to_owned(),
        json!({
            "disposition": "promote",
            "task_id": task.task_id,
            "candidate_ref": format!("claim:{}", candidate.claim_id),
            "source_write_id": candidate.write_id,
            "source_memory_revision": candidate.memory_revision,
            "idempotency_key": idempotency_key,
            "evidence_refs": evidence_refs,
            "source_provenance_refs": source_provenance_refs,
            "operator_session_id": context.session_id,
            "actor_role_lease_id": actor.role_lease_id,
            "actor_controller_lease_id": actor.controller_lease_id,
        }),
    );
    let command = SemanticCommand::ClaimVerify(eliot_types::ClaimVerifyCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(context.session_id.as_uuid()),
            session_id: Some(context.session_id),
            project_id,
            task_id: Some(task.task_id),
            scope: format!("task:{}:candidate-disposition", task.task_id),
            authority: "human-operator-governed-candidate-review".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        claim_id: candidate.claim_id,
        verification: VerificationRunInput {
            verification_id: VerificationId::from_uuid(write_id.as_uuid()),
            claim_id: Some(candidate.claim_id),
            verifier: format!("human-operator-session:{}", context.session_id),
            result: VerificationResult::Passed,
            summary:
                "HumanOperator admitted the candidate after reviewing its exact source evidence"
                    .to_owned(),
            payload: json!({
                "authority": "human_operator",
                "operator_session_id": context.session_id,
                "actor_role_lease_id": actor.role_lease_id,
                "actor_controller_lease_id": actor.controller_lease_id,
                "project_id": project_id,
                "task_id": task.task_id,
                "candidate_ref": format!("claim:{}", candidate.claim_id),
                "candidate_original_write_id": candidate.write_id,
                "candidate_original_revision": candidate.memory_revision,
                "idempotency_key": idempotency_key,
                "evidence_refs": evidence_refs,
                "source_provenance_refs": source_provenance_refs,
                "disposition": "promote",
            }),
        },
        statement: Some(candidate.statement.clone()),
        payload: Value::Object(payload),
    });
    let receipt = state
        .writer
        .submit(WriteAdmissionService.admit(&command)?)
        .await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

pub(super) async fn execute_operator_candidate_review(
    state: &McpState,
    context: AuthenticatedRequestContext,
    task: &TaskContract,
    candidate_ref: &str,
    disposition: &str,
    evidence_refs: &[String],
    idempotency_key: &str,
) -> Result<(WriteReceiptRef, &'static str)> {
    let actor = require_candidate_disposition_actor(state, context, task).await?;
    let project_id = task.project_id;
    let candidate =
        resolve_operator_candidate(state, project_id, task.task_id, candidate_ref).await?;
    let source_provenance_refs = require_operator_candidate_evidence(&candidate, evidence_refs)?;
    if disposition == "promote" {
        let receipt = promote_operator_candidate(
            state,
            context,
            CandidatePromotion {
                task,
                candidate: &candidate,
                evidence_refs,
                source_provenance_refs,
                idempotency_key,
                actor: &actor,
            },
        )
        .await?;
        return Ok((receipt, "candidate_promoted_verified"));
    }
    if candidate.status != EpistemicStatus::Candidate {
        anyhow::bail!("only an undispositioned candidate claim can receive lifecycle disposition");
    }
    let subject_ref = format!("claim:{}", candidate.claim_id);
    let primary_key = format!("{idempotency_key}:primary");
    let expected_write_id = deterministic_canonical_write_id(
        project_id,
        Some(task.task_id),
        CanonicalReceiptKind::StateTransition,
        &primary_key,
    );
    let existing_transition = state
        .store
        .canonical_record_by_write_id::<eliot_types::MemoryStateTransition>(
            project_id,
            Some(task.task_id),
            &[CanonicalReceiptKind::StateTransition.as_str()],
            expected_write_id,
        )
        .await?;
    if existing_transition.is_none() {
        ensure_operator_candidate_is_active(state, project_id, task.task_id, candidate.claim_id)
            .await?;
    }
    let (operator, reason, outcome) = match disposition {
        "reject" => (
            ForgettingOperator::Suppress,
            ForgettingReason::VerifierContradicted,
            "candidate_rejected",
        ),
        "demote" => (
            ForgettingOperator::Demote,
            ForgettingReason::LowUtility,
            "candidate_demoted",
        ),
        "archive" => (
            ForgettingOperator::Archive,
            ForgettingReason::LowUtility,
            "candidate_archived",
        ),
        _ => anyhow::bail!("unsupported operator candidate disposition"),
    };
    let receipt = persist_operator_lifecycle_transition(
        state,
        context,
        project_id,
        task.task_id,
        &subject_ref,
        operator,
        reason,
        operator_candidate_lifecycle_binding(
            &candidate,
            project_id,
            task.task_id,
            evidence_refs,
            &source_provenance_refs,
            context.session_id,
        )?,
        idempotency_key,
    )
    .await?;
    Ok((receipt, outcome))
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_operator_command(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: OperatorCommandToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse operator task_id")?;
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    let task = state
        .store
        .task_contract_by_id(task_id)
        .await?
        .context("operator task does not exist")?;
    if task.project_id != project_id || task.memory_revision.value() != input.expected_revision {
        anyhow::bail!("operator command has stale or wrong-project task revision");
    }

    let action = serde_json::to_value(&input.command)?
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    validate_operator_command_payload(&input.command)?;
    let mut reasons = Vec::new();
    let mut canonical_receipt = None;
    let mut preview = None;
    let mut outcome = "rejected".to_owned();
    let accepted = match &input.command {
        OperatorCommand::SelectTask { task_id: selected } => *selected == task_id,
        OperatorCommand::CreateAutonomyRun { contract } => {
            if contract.project_id != project_id || contract.root_task_id != task_id {
                anyhow::bail!("operator autonomy contract scope differs from the selected task");
            }
            let result =
                dispatch_autonomy_contract_write(state, context, json!({"contract": contract}))
                    .await?;
            canonical_receipt = serde_json::from_value(result["canonical_receipt"].clone())?;
            "autonomy_contract_created".clone_into(&mut outcome);
            true
        }
        OperatorCommand::PreviewAutonomyEdit {
            autonomy_run_id,
            proposed_contract,
        } => {
            let current =
                load_autonomy_contract(state, project_id, task_id, autonomy_run_id).await?;
            if current.state != AutonomyRunState::Draft {
                anyhow::bail!("only a Draft autonomy contract can be edited");
            }
            if proposed_contract.autonomy_run_id != *autonomy_run_id
                || proposed_contract.project_id != project_id
                || proposed_contract.root_task_id != task_id
                || proposed_contract.state != AutonomyRunState::Draft
                || proposed_contract.state_revision != current.state_revision
            {
                anyhow::bail!(
                    "proposed autonomy edit changes immutable identity or revision fields"
                );
            }
            AutonomyRunService::validate_contract(proposed_contract)?;
            let current_value = serde_json::to_value(&current)?;
            let proposed_value = serde_json::to_value(proposed_contract)?;
            let changed_fields = current_value
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(name, value)| proposed_value.get(*name) != Some(*value))
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            preview = Some(json!({
                "kind": "autonomy_contract_edit_preview",
                "current": current_value,
                "proposed": proposed_value,
                "changed_fields": changed_fields,
                "mutation_executed": false,
                "next_step": "create a replacement Draft contract through its dedicated authority or keep the immutable current contract"
            }));
            "validated_preview".clone_into(&mut outcome);
            true
        }
        OperatorCommand::StartRun { autonomy_run_id } => {
            let contract =
                load_autonomy_contract(state, project_id, task_id, autonomy_run_id).await?;
            if contract.state == AutonomyRunState::Draft {
                let ready_key = format!("{}:ready", input.idempotency_key);
                let _ = apply_autonomy_transition(
                    state,
                    context,
                    project_id,
                    task_id,
                    autonomy_run_id,
                    Some(contract.state_revision),
                    AutonomyTransitionRequest {
                        target: AutonomyRunState::Ready,
                        reason: "operator validated bounded run".to_owned(),
                        risk_tier: "R1".to_owned(),
                        approval: None,
                        verifier_refs: Vec::new(),
                    },
                    Some(&ready_key),
                )
                .await?;
            }
            let primary_key = format!("{}:primary", input.idempotency_key);
            let result = apply_autonomy_transition(
                state,
                context,
                project_id,
                task_id,
                autonomy_run_id,
                None,
                AutonomyTransitionRequest {
                    target: AutonomyRunState::Running,
                    reason: "operator start".to_owned(),
                    risk_tier: "R1".to_owned(),
                    approval: None,
                    verifier_refs: Vec::new(),
                },
                Some(&primary_key),
            )
            .await?;
            canonical_receipt =
                serde_json::from_value(result["transition"]["canonical_receipt"].clone())?;
            true
        }
        OperatorCommand::PauseRun {
            autonomy_run_id,
            reason,
        }
        | OperatorCommand::CancelRun {
            autonomy_run_id,
            reason,
        } => {
            let target = if matches!(&input.command, OperatorCommand::PauseRun { .. }) {
                AutonomyRunState::PausedByOperator
            } else {
                AutonomyRunState::Cancelled
            };
            let primary_key = format!("{}:primary", input.idempotency_key);
            let result = apply_autonomy_transition(
                state,
                context,
                project_id,
                task_id,
                autonomy_run_id,
                None,
                AutonomyTransitionRequest {
                    target,
                    reason: reason.clone(),
                    risk_tier: "R1".to_owned(),
                    approval: None,
                    verifier_refs: Vec::new(),
                },
                Some(&primary_key),
            )
            .await?;
            canonical_receipt =
                serde_json::from_value(result["transition"]["canonical_receipt"].clone())?;
            true
        }
        OperatorCommand::ResumeRun { autonomy_run_id } => {
            let primary_key = format!("{}:primary", input.idempotency_key);
            let result = apply_autonomy_transition(
                state,
                context,
                project_id,
                task_id,
                autonomy_run_id,
                None,
                AutonomyTransitionRequest {
                    target: AutonomyRunState::Running,
                    reason: "operator resume".to_owned(),
                    risk_tier: "R1".to_owned(),
                    approval: None,
                    verifier_refs: Vec::new(),
                },
                Some(&primary_key),
            )
            .await?;
            canonical_receipt =
                serde_json::from_value(result["transition"]["canonical_receipt"].clone())?;
            true
        }
        OperatorCommand::ContestMemory {
            task_id: selected,
            memory_handle,
            evidence_refs,
        } => {
            if *selected == task_id {
                canonical_receipt = Some(
                    persist_operator_minority_pressure(
                        state,
                        context,
                        project_id,
                        task_id,
                        memory_handle,
                        evidence_refs.clone(),
                        &input.idempotency_key,
                    )
                    .await?,
                );
                true
            } else {
                false
            }
        }
        OperatorCommand::SuppressMemory {
            task_id: selected,
            memory_handle,
            reason,
        }
        | OperatorCommand::ArchiveMemory {
            task_id: selected,
            memory_handle,
            reason,
        } => {
            if *selected == task_id {
                let (operator, forgetting_reason) =
                    if matches!(&input.command, OperatorCommand::SuppressMemory { .. }) {
                        (ForgettingOperator::Suppress, ForgettingReason::WrongScope)
                    } else {
                        (ForgettingOperator::Archive, ForgettingReason::LowUtility)
                    };
                canonical_receipt = Some(
                    persist_operator_lifecycle_transition(
                        state,
                        context,
                        project_id,
                        task_id,
                        memory_handle,
                        operator,
                        forgetting_reason,
                        OperatorLifecycleBinding::unbound(vec![reason.clone()]),
                        &input.idempotency_key,
                    )
                    .await?,
                );
                true
            } else {
                false
            }
        }
        OperatorCommand::RestoreMemory {
            task_id: selected,
            memory_handle,
            evidence_refs,
        } => {
            if *selected == task_id {
                canonical_receipt = Some(
                    persist_operator_lifecycle_transition(
                        state,
                        context,
                        project_id,
                        task_id,
                        memory_handle,
                        ForgettingOperator::Restore,
                        ForgettingReason::WrongScope,
                        OperatorLifecycleBinding::unbound(evidence_refs.clone()),
                        &input.idempotency_key,
                    )
                    .await?,
                );
                true
            } else {
                false
            }
        }
        OperatorCommand::ReviewCandidate {
            task_id: selected,
            candidate_ref,
            disposition,
            evidence_refs,
        } => {
            if *selected != task_id {
                anyhow::bail!("operator candidate task differs from the selected canonical task");
            }
            let (receipt, candidate_outcome) = execute_operator_candidate_review(
                state,
                context,
                &task,
                candidate_ref,
                disposition,
                evidence_refs,
                &input.idempotency_key,
            )
            .await?;
            canonical_receipt = Some(receipt);
            candidate_outcome.clone_into(&mut outcome);
            true
        }
        OperatorCommand::DispositionAgentResult {
            result_id,
            disposition,
        } => {
            let kind = match disposition.trim().to_ascii_lowercase().as_str() {
                "reject" | "rejected" => AgentResultDispositionKind::Rejected,
                "probe" | "probe_requested" => AgentResultDispositionKind::ProbeRequested,
                "accept" | "accepted" => anyhow::bail!(
                    "HumanOperator acceptance must use the governed controller finalization path"
                ),
                other => anyhow::bail!(
                    "unsupported HumanOperator agent-result disposition: {other}; expected rejected or probe_requested"
                ),
            };
            let mut broker_state = delegation_runtime::load_state(&state.root)?;
            let invocation = broker_state
                .agent_results
                .iter()
                .find(|result| result.result_id == *result_id)
                .and_then(|result| {
                    broker_state
                        .agent_invocations
                        .iter()
                        .find(|request| request.invocation_id == result.invocation_id)
                })
                .context("operator agent-result disposition lacks its invocation authority")?;
            if invocation.project_id != project_id || invocation.task_id != task_id {
                anyhow::bail!("operator agent-result disposition has wrong project/task scope");
            }
            let authority_session_id = AgentSessionId::from_uuid(context.session_id.as_uuid());
            let normalized_disposition = disposition.trim().to_ascii_lowercase();
            let disposition_reason = format!(
                "HumanOperator selected {normalized_disposition} through the typed Eliot Operator command"
            );
            let disposition_evidence = vec![format!(
                "eliot/task/{task_id}@{}",
                task.memory_revision.value()
            )];
            let mut record = HostBrokerService.disposition_result_as_human_operator(
                &mut broker_state,
                authority_session_id,
                result_id,
                kind,
                disposition_reason,
                disposition_evidence,
                input.idempotency_key.clone(),
            )?;
            if record.canonical_receipt.is_none() {
                let (receipt, _) = write_canonical_observation(
                    state,
                    context,
                    project_id,
                    Some(task_id),
                    CanonicalReceiptKind::AgentResultDisposition,
                    &format!(
                        "operator-agent-result-disposition:{}",
                        input.idempotency_key
                    ),
                    &record,
                )
                .await?;
                record.canonical_receipt = Some(receipt);
                let stored = broker_state
                    .agent_result_dispositions
                    .iter_mut()
                    .find(|item| item.disposition_id == record.disposition_id)
                    .context(
                        "operator AgentResultDisposition disappeared before receipt binding",
                    )?;
                *stored = record.clone();
            }
            delegation_runtime::save_host_broker_state(&state.root, &broker_state)?;
            canonical_receipt = record.canonical_receipt.clone();
            "agent_result_disposition_committed".clone_into(&mut outcome);
            true
        }
        OperatorCommand::RequestRevalidation {
            task_id: selected,
            memory_handle,
        } if *selected == task_id => {
            canonical_receipt = Some(
                persist_operator_control_request(
                    state,
                    context,
                    OperatorControlRequestDraft {
                        project_id,
                        task_id,
                        operation: "request_revalidation",
                        target_ref: memory_handle,
                        disposition: "requested",
                        exact_action_hash: None,
                        reason_or_evidence_refs: Vec::new(),
                        idempotency_key: &input.idempotency_key,
                    },
                )
                .await?,
            );
            "revalidation_request_recorded".clone_into(&mut outcome);
            true
        }
        OperatorCommand::RefreshPacket { task_id: selected } if *selected == task_id => {
            let candidate_handles = latest_task_packet(state, task_id)?
                .map(|packet| packet.exact_handles)
                .unwrap_or_default();
            let packet = Box::pin(dispatch_compile_packet_l3(
                state,
                context,
                json!({
                    "project_id": project_id,
                    "task_id": task_id.to_string(),
                    "goal": task.title.clone(),
                    "candidate_handles": candidate_handles,
                    "max_tokens": 4096
                }),
            ))
            .await?;
            let packet_id = packet
                .get("packet_id")
                .and_then(Value::as_str)
                .context("refreshed packet has no packet_id")?
                .to_owned();
            let packet_hash = format!(
                "blake3:{}",
                blake3::hash(&serde_json::to_vec(&packet)?).to_hex()
            );
            canonical_receipt = Some(
                persist_operator_control_request(
                    state,
                    context,
                    OperatorControlRequestDraft {
                        project_id,
                        task_id,
                        operation: "refresh_packet",
                        target_ref: &packet_id,
                        disposition: "executed",
                        exact_action_hash: Some(packet_hash.clone()),
                        reason_or_evidence_refs: vec![packet_hash],
                        idempotency_key: &input.idempotency_key,
                    },
                )
                .await?,
            );
            preview = Some(packet);
            "packet_refreshed".clone_into(&mut outcome);
            true
        }
        OperatorCommand::TriggerBackupValidation { task_id: selected } if *selected == task_id => {
            let report = BackupService::new(&state.root)
                .run(eliot_types::BackupKind::LogicalExport, true)?;
            preview = Some(serde_json::to_value(&report)?);
            "validated_preview".clone_into(&mut outcome);
            true
        }
        OperatorCommand::RequestImportPreview {
            task_id: selected,
            source_ref,
        } if *selected == task_id => {
            let import_preview = ImportService::new(&state.root).preview(
                std::path::Path::new(source_ref),
                &format!("operator-runtime:{}", state.runtime_id),
            )?;
            preview = Some(serde_json::to_value(&import_preview)?);
            "validated_preview".clone_into(&mut outcome);
            true
        }
        OperatorCommand::FinishGapPreview { task_id: selected } if *selected == task_id => {
            let unsatisfied_acceptance = task
                .acceptance_items
                .iter()
                .filter(|item| !item.satisfied)
                .map(|item| item.item_id.clone())
                .collect::<Vec<_>>();
            let can_request_completion =
                unsatisfied_acceptance.is_empty() && !task.verification_ids.is_empty();
            preview = Some(json!({
                "kind": "finish_gap_preview",
                "task_id": task_id,
                "memory_revision": task.memory_revision,
                "unsatisfied_acceptance": unsatisfied_acceptance,
                "verification_ids": task.verification_ids.clone(),
                "can_request_completion": can_request_completion,
                "mutation_executed": false
            }));
            "validated_preview".clone_into(&mut outcome);
            true
        }
        OperatorCommand::GrantApproval {
            approval_id,
            exact_action_hash,
        } => {
            if approval_id.starts_with("autonomy-approval:") {
                let result = execute_operator_autonomy_approval_decision(
                    state,
                    context,
                    OperatorAutonomyApprovalDecision {
                        project_id,
                        task_id,
                        approval_id,
                        exact_action_hash,
                        decision: AutonomyApprovalDecisionKind::Granted,
                        reason: "HumanOperator granted the exact action through Eliot Operator",
                        idempotency_key: &input.idempotency_key,
                    },
                )
                .await?;
                let decision_accepted = result["accepted"].as_bool().unwrap_or(false);
                if decision_accepted {
                    canonical_receipt =
                        Some(serde_json::from_value(result["canonical_receipt"].clone())?);
                    "autonomy_approval_granted".clone_into(&mut outcome);
                } else {
                    reasons.push(
                        result["reason"]
                            .as_str()
                            .unwrap_or("canonical autonomy approval grant was denied")
                            .to_owned(),
                    );
                }
                preview = Some(result);
                decision_accepted
            } else {
                canonical_receipt = Some(
                    persist_operator_control_request(
                        state,
                        context,
                        OperatorControlRequestDraft {
                            project_id,
                            task_id,
                            operation: "grant_approval",
                            target_ref: approval_id,
                            disposition: "unsupported_approval_request_only",
                            exact_action_hash: Some(exact_action_hash.clone()),
                            reason_or_evidence_refs: Vec::new(),
                            idempotency_key: &input.idempotency_key,
                        },
                    )
                    .await?,
                );
                reasons.push(
                    "unsupported approval class recorded as request-only; no approval authority changed"
                        .to_owned(),
                );
                "unsupported_approval_request_recorded".clone_into(&mut outcome);
                true
            }
        }
        OperatorCommand::DenyApproval {
            approval_id,
            exact_action_hash,
            reason,
        } => {
            if approval_id.starts_with("autonomy-approval:") {
                let result = execute_operator_autonomy_approval_decision(
                    state,
                    context,
                    OperatorAutonomyApprovalDecision {
                        project_id,
                        task_id,
                        approval_id,
                        exact_action_hash,
                        decision: AutonomyApprovalDecisionKind::Denied,
                        reason,
                        idempotency_key: &input.idempotency_key,
                    },
                )
                .await?;
                let decision_accepted = result["accepted"].as_bool().unwrap_or(false);
                if decision_accepted {
                    canonical_receipt =
                        Some(serde_json::from_value(result["canonical_receipt"].clone())?);
                    "autonomy_approval_denied".clone_into(&mut outcome);
                } else {
                    reasons.push(
                        result["reason"]
                            .as_str()
                            .unwrap_or("canonical autonomy approval denial was rejected")
                            .to_owned(),
                    );
                }
                preview = Some(result);
                decision_accepted
            } else {
                canonical_receipt = Some(
                    persist_operator_control_request(
                        state,
                        context,
                        OperatorControlRequestDraft {
                            project_id,
                            task_id,
                            operation: "deny_approval",
                            target_ref: approval_id,
                            disposition: "unsupported_approval_request_only",
                            exact_action_hash: Some(exact_action_hash.clone()),
                            reason_or_evidence_refs: vec![reason.clone()],
                            idempotency_key: &input.idempotency_key,
                        },
                    )
                    .await?,
                );
                reasons.push(
                    "unsupported approval class recorded as request-only; no approval authority changed"
                        .to_owned(),
                );
                "unsupported_approval_request_recorded".clone_into(&mut outcome);
                true
            }
        }
        OperatorCommand::RequestRevalidation { .. }
        | OperatorCommand::RefreshPacket { .. }
        | OperatorCommand::TriggerBackupValidation { .. }
        | OperatorCommand::RequestImportPreview { .. }
        | OperatorCommand::FinishGapPreview { .. } => {
            reasons.push("command target does not match the canonical task".to_owned());
            false
        }
    };
    if !accepted && reasons.is_empty() {
        reasons.push("command target does not match the canonical task".to_owned());
    }
    let executed = canonical_receipt.is_some();
    if outcome == "rejected" && accepted {
        outcome = if executed {
            "canonical_mutation_committed".to_owned()
        } else if preview.is_some() {
            "validated_preview".to_owned()
        } else {
            "selection_applied".to_owned()
        };
    }
    serde_json::to_value(OperatorCommandReceipt {
        command_id: format!(
            "operator-command:{}",
            blake3::hash(input.idempotency_key.as_bytes())
        ),
        accepted,
        executed,
        outcome,
        task_id: Some(task_id),
        action,
        revision: Some(task.memory_revision),
        reasons,
        canonical_receipt,
        preview,
        generated_at: time::OffsetDateTime::now_utc(),
    })
    .map_err(Into::into)
}

pub(super) fn validate_operator_command_payload(command: &OperatorCommand) -> Result<()> {
    match command {
        OperatorCommand::PauseRun { reason, .. }
        | OperatorCommand::CancelRun { reason, .. }
        | OperatorCommand::SuppressMemory { reason, .. }
        | OperatorCommand::ArchiveMemory { reason, .. }
        | OperatorCommand::DenyApproval { reason, .. }
            if reason.trim().is_empty() =>
        {
            anyhow::bail!("operator command reason must not be empty");
        }
        OperatorCommand::ContestMemory { evidence_refs, .. }
        | OperatorCommand::RestoreMemory { evidence_refs, .. }
            if evidence_refs.is_empty() =>
        {
            anyhow::bail!("operator memory command requires evidence_refs");
        }
        OperatorCommand::ReviewCandidate {
            disposition,
            evidence_refs,
            ..
        } => {
            if evidence_refs.is_empty() || evidence_refs.iter().any(|value| value.trim().is_empty())
            {
                anyhow::bail!("operator candidate disposition requires non-empty evidence_refs");
            }
            if !matches!(
                disposition.as_str(),
                "promote" | "reject" | "demote" | "archive"
            ) {
                anyhow::bail!("unsupported operator candidate disposition");
            }
        }
        OperatorCommand::GrantApproval {
            approval_id,
            exact_action_hash,
        }
        | OperatorCommand::DenyApproval {
            approval_id,
            exact_action_hash,
            ..
        } if approval_id.trim().is_empty() || exact_action_hash.trim().is_empty() => {
            anyhow::bail!("operator approval requires canonical id and exact action hash");
        }
        OperatorCommand::RequestImportPreview { source_ref, .. }
            if source_ref.trim().is_empty() =>
        {
            anyhow::bail!("operator import preview requires a source reference");
        }
        OperatorCommand::DispositionAgentResult { disposition, .. }
            if disposition.trim().is_empty() =>
        {
            anyhow::bail!("operator agent-result disposition must not be empty");
        }
        _ => {}
    }
    Ok(())
}
