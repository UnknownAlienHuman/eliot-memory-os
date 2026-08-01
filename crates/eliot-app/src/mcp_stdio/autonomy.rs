//! Autonomy run lifecycle: approvals, verifier requirements, reconciliation.
//!
//! An autonomy run is the Governor acting without a human in the loop for a
//! bounded stretch, so its approval gates and verifier requirements are the
//! part of this module that must be readable on its own rather than found by
//! scrolling through tool dispatch.

use super::*;

pub(super) fn autonomy_commit_serializer() -> &'static tokio::sync::Mutex<()> {
    AUTONOMY_COMMIT_SERIALIZER.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(super) fn decode_authoritative_autonomy_aggregate(
    record: &eliot_store::CanonicalRecord<Value>,
) -> Result<Option<(AutonomyWorkGraphRecord, BoundedAutonomyRuntime)>> {
    let Ok(graph) = serde_json::from_value::<AutonomyWorkGraphRecord>(record.receipt_body.clone())
    else {
        return Ok(None);
    };
    if graph.aggregate_schema_version.as_deref() != Some(AUTONOMY_ACTION_AGGREGATE_SCHEMA) {
        return Ok(None);
    }
    let Some(commit) = graph.authoritative_commit.as_ref() else {
        return Ok(None);
    };
    if commit.aggregate_write_id != record.canonical_receipt.write_id.to_string()
        || commit.action_fingerprint != graph.action_fingerprint
        || commit.action != graph.action
        || commit.committed_runtime_revision != graph.runtime_revision
    {
        return Ok(None);
    }
    let Some(snapshot) = graph.runtime_snapshot.as_ref() else {
        return Ok(None);
    };
    let runtime = BoundedAutonomyRuntime::from_json(&serde_json::to_vec(snapshot)?)?;
    let proof_hash = graph
        .completion_proof
        .as_ref()
        .map(canonical_struct_hash)
        .transpose()?;
    let terminal_proof_valid = if runtime.contract.state == AutonomyRunState::DoneVerified {
        proof_hash.is_some()
            && proof_hash == commit.completion_proof_hash
            && graph.transition_snapshots.iter().any(|transition| {
                transition.to == AutonomyRunState::DoneVerified
                    && transition.state_revision == runtime.contract.state_revision
            })
    } else {
        proof_hash.is_none() && commit.completion_proof_hash.is_none()
    };
    let snapshot_matches = runtime.contract.autonomy_run_id == graph.autonomy_run_id
        && runtime.contract.state == commit.committed_state
        && runtime.contract.state_revision == commit.committed_state_revision
        && runtime.runtime_revision == commit.committed_runtime_revision
        && canonical_struct_hash(&runtime.work_items)? == canonical_struct_hash(&graph.work_items)?
        && canonical_struct_hash(&runtime.transition_receipts)?
            == canonical_struct_hash(&graph.transition_snapshots)?
        && canonical_struct_hash(&runtime.recovery_receipts)?
            == canonical_struct_hash(&graph.recovery_snapshots)?
        && graph.budget_snapshot.as_ref().is_some_and(|budget| {
            budget.autonomy_run_id == graph.autonomy_run_id
                && budget.runtime_revision == runtime.runtime_revision
                && canonical_struct_hash(&budget.ledger).ok()
                    == canonical_struct_hash(&runtime.ledger).ok()
        });
    Ok((terminal_proof_valid && snapshot_matches).then_some((graph, runtime)))
}

pub(super) fn apply_legacy_autonomy_transitions_fail_closed(
    contract: &mut AutonomyRunContract,
    transitions: &[eliot_types::AutonomyRunTransitionReceipt],
) -> bool {
    let mut terminal_without_commit = false;
    for transition in transitions {
        if transition.to == AutonomyRunState::DoneVerified {
            terminal_without_commit = true;
            continue;
        }
        if transition.state_revision > contract.state_revision {
            contract.state = transition.to;
            contract.state_revision = transition.state_revision;
        }
    }
    terminal_without_commit
}

#[allow(clippy::too_many_lines)]
pub(super) async fn load_bounded_autonomy_runtime(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    autonomy_run_id: &str,
) -> Result<LoadedAutonomyRuntime> {
    let canonical = state
        .store
        .autonomy_run_view(project_id, task_id, autonomy_run_id, 128)
        .await?;
    let mut contract = canonical
        .contract
        .as_ref()
        .map(|record| record.receipt_body.clone())
        .context("canonical autonomy run does not exist")?;
    let mut authoritative = None;
    for record in canonical.work_graphs.iter().rev() {
        if let Some(decoded) = decode_authoritative_autonomy_aggregate(record)? {
            authoritative = Some((decoded.0, decoded.1, record.memory_revision));
            break;
        }
    }
    if let Some((graph, runtime, _aggregate_revision)) = authoritative {
        return Ok(LoadedAutonomyRuntime {
            runtime,
            graph,
            canonical,
            integrity_status: "authoritative_atomic_aggregate".to_owned(),
        });
    }

    let legacy_transitions = canonical
        .transitions
        .iter()
        .map(|record| record.receipt_body.clone())
        .collect::<Vec<_>>();
    let legacy_terminal_without_commit =
        apply_legacy_autonomy_transitions_fail_closed(&mut contract, &legacy_transitions);
    let graph = canonical
        .work_graphs
        .iter()
        .rev()
        .find_map(|record| {
            serde_json::from_value::<AutonomyWorkGraphRecord>(record.receipt_body.clone()).ok()
        })
        .unwrap_or_else(|| AutonomyWorkGraphRecord {
            aggregate_schema_version: None,
            authoritative_commit: None,
            runtime_snapshot: None,
            transition_snapshots: Vec::new(),
            recovery_snapshots: Vec::new(),
            secondary_transition_snapshots: Vec::new(),
            secondary_recovery_snapshots: Vec::new(),
            tripwire_snapshots: Vec::new(),
            budget_snapshot: None,
            action_result: Value::Null,
            host_result_chains: Vec::new(),
            approval_consumption: None,
            autonomy_run_id: autonomy_run_id.to_owned(),
            runtime_revision: 0,
            action: "contract_loaded".to_owned(),
            action_fingerprint: String::new(),
            tripwire_policy: AutonomyTripwirePolicy::default(),
            work_items: Vec::new(),
            host_bindings: Vec::new(),
            transition_refs: Vec::new(),
            recovery_refs: Vec::new(),
            completion_proof: None,
        });
    let mut graph = graph;
    if legacy_terminal_without_commit {
        graph.completion_proof = None;
    }
    let budget = canonical.budget_ledgers.iter().rev().find_map(|record| {
        serde_json::from_value::<AutonomyBudgetRecord>(record.receipt_body.clone()).ok()
    });
    let recoveries = canonical
        .recoveries
        .iter()
        .filter_map(|record| {
            serde_json::from_value::<AutonomyRecoveryReceipt>(record.receipt_body.clone()).ok()
        })
        .collect::<Vec<_>>();
    let mut runtime = BoundedAutonomyRuntime::new(contract, graph.tripwire_policy.clone())?;
    runtime.work_items.clone_from(&graph.work_items);
    runtime.ledger = budget
        .as_ref()
        .map_or_else(AutonomyBudgetLedger::default, |record| {
            record.ledger.clone()
        });
    runtime.transition_receipts = canonical
        .transitions
        .iter()
        .filter(|record| record.receipt_body.to != AutonomyRunState::DoneVerified)
        .map(|record| record.receipt_body.clone())
        .collect();
    runtime.recovery_receipts = recoveries;
    runtime.runtime_revision = graph
        .runtime_revision
        .max(budget.as_ref().map_or(0, |record| record.runtime_revision))
        .max(
            runtime
                .recovery_receipts
                .iter()
                .map(|receipt| receipt.runtime_revision)
                .max()
                .unwrap_or(0),
        );
    runtime = BoundedAutonomyRuntime::from_json(&runtime.to_json()?)?;
    Ok(LoadedAutonomyRuntime {
        runtime,
        graph,
        canonical,
        integrity_status: if legacy_terminal_without_commit {
            "degraded_legacy_terminal_without_atomic_proof".to_owned()
        } else {
            "legacy_nonterminal_fail_closed".to_owned()
        },
    })
}

pub(super) fn autonomy_run_projection(
    loaded: &LoadedAutonomyRuntime,
) -> eliot_types::AutonomyRunView {
    let runtime = &loaded.runtime;
    let mut verifier_result_refs = runtime
        .work_items
        .iter()
        .flat_map(|item| item.verifier_refs.clone())
        .chain(
            runtime
                .transition_receipts
                .iter()
                .flat_map(|transition| transition.verifier_refs.clone()),
        )
        .collect::<Vec<_>>();
    verifier_result_refs.sort();
    verifier_result_refs.dedup();
    let recovery_event_refs = runtime
        .recovery_receipts
        .iter()
        .map(|receipt| receipt.recovery_id.clone())
        .collect::<Vec<_>>();
    let mut pause_resume_reassignment_refs = runtime
        .transition_receipts
        .iter()
        .map(|receipt| receipt.transition_id.clone())
        .chain(recovery_event_refs.iter().cloned())
        .collect::<Vec<_>>();
    pause_resume_reassignment_refs.extend(
        runtime
            .ledger
            .tripwires
            .iter()
            .map(|tripwire| tripwire.tripwire_id.clone()),
    );
    eliot_types::AutonomyRunView {
        contract: runtime.contract.clone(),
        work_item_refs: runtime
            .work_items
            .iter()
            .map(|item| item.work_item_id.to_string())
            .collect(),
        assignment_refs: runtime
            .work_items
            .iter()
            .filter_map(|item| item.lease.as_ref().map(|lease| lease.lease_ref.clone()))
            .collect(),
        verifier_result_refs,
        route_decision_refs: loaded
            .graph
            .host_bindings
            .iter()
            .map(|binding| {
                format!(
                    "{}:{}:{}",
                    binding.host_id, binding.work_item_id, binding.lease_ref
                )
            })
            .collect(),
        recovery_event_refs,
        model_invocations_used: runtime.ledger.model_invocations,
        tool_calls_used: runtime.ledger.tool_calls,
        wall_time_used_seconds: runtime.ledger.wall_time_seconds,
        cost_or_tokens_used: Some(runtime.ledger.cost_or_token_units.to_string()),
        pause_resume_reassignment_refs,
        completion_proof: loaded.graph.completion_proof.clone(),
        finish_status: if loaded.integrity_status.starts_with("degraded_") {
            loaded.integrity_status.clone()
        } else {
            format!("{:?}", runtime.contract.state).to_ascii_lowercase()
        },
    }
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_autonomy_run_status(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: AutonomyRunStatusToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse autonomy task_id")?;
    let task = state
        .store
        .task_contract_by_id(task_id)
        .await?
        .context("autonomy task does not exist")?;
    if task.project_id != project_id {
        anyhow::bail!("autonomy task belongs to a different project");
    }

    let (mut runs, _) = operator_run_views(state, project_id, task_id).await?;
    if let Some(autonomy_run_id) = input.autonomy_run_id.as_deref() {
        runs.retain(|run| run.contract.autonomy_run_id == autonomy_run_id);
        if runs.is_empty() {
            anyhow::bail!("canonical autonomy run does not exist");
        }
    }
    let mut runtime_controls = Vec::new();
    for run in &runs {
        let loaded = load_bounded_autonomy_runtime(
            state,
            project_id,
            task_id,
            &run.contract.autonomy_run_id,
        )
        .await?;
        let canonical_record_refs = loaded
            .canonical
            .contract
            .iter()
            .map(|record| record.record_id.clone())
            .chain(
                loaded
                    .canonical
                    .work_graphs
                    .iter()
                    .map(|record| record.record_id.clone()),
            )
            .chain(
                loaded
                    .canonical
                    .budget_ledgers
                    .iter()
                    .map(|record| record.record_id.clone()),
            )
            .chain(
                loaded
                    .canonical
                    .tripwires
                    .iter()
                    .map(|record| record.record_id.clone()),
            )
            .chain(
                loaded
                    .canonical
                    .recoveries
                    .iter()
                    .map(|record| record.record_id.clone()),
            )
            .collect::<Vec<_>>();
        let ready_work_item_ids = loaded.runtime.ready_work_items();
        let tripwire_refs = loaded
            .runtime
            .ledger
            .tripwires
            .iter()
            .map(|tripwire| tripwire.tripwire_id.clone())
            .collect::<Vec<_>>();
        let recovery_refs = loaded
            .runtime
            .recovery_receipts
            .iter()
            .map(|recovery| recovery.recovery_id.clone())
            .collect::<Vec<_>>();
        runtime_controls.push(json!({
            "autonomy_run_id": loaded.runtime.contract.autonomy_run_id,
            "state": loaded.runtime.contract.state,
            "state_revision": loaded.runtime.contract.state_revision,
            "runtime_revision": loaded.runtime.runtime_revision,
            "ready_work_item_ids": ready_work_item_ids,
            "work_items": loaded.runtime.work_items,
            "host_bindings": loaded.graph.host_bindings,
            "ledger": loaded.runtime.ledger,
            "tripwire_refs": tripwire_refs,
            "recovery_refs": recovery_refs,
            "completion_proof": loaded.graph.completion_proof,
            "integrity_status": loaded.integrity_status,
            "canonical_record_refs": canonical_record_refs
        }));
    }
    Ok(json!({
        "schema_version": OPERATOR_SCHEMA_VERSION,
        "project_id": project_id,
        "task_id": task_id,
        "run_count": runs.len(),
        "runs": runs,
        "runtime_controls": runtime_controls,
        "identity_semantics": {
            "run": "canonical bounded AutonomyRunContract; never a verification run or AgentSession"
        }
    }))
}

pub(super) async fn dispatch_autonomy_contract_write(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AutonomyContractWriteToolInput = serde_json::from_value(arguments)?;
    let _commit_guard = autonomy_commit_serializer().lock().await;
    let task = state
        .store
        .task_contract_by_id(input.contract.root_task_id)
        .await?
        .context("autonomy root task does not exist")?;
    if task.project_id != input.contract.project_id {
        anyhow::bail!("autonomy contract project differs from root task project");
    }
    if input.contract.state != AutonomyRunState::Draft || input.contract.state_revision != 0 {
        anyhow::bail!("a new autonomy contract must start at DRAFT revision 0");
    }
    AutonomyRunService::validate_contract(&input.contract)?;
    let (receipt, write_status) = write_canonical_observation(
        state,
        context,
        input.contract.project_id,
        Some(input.contract.root_task_id),
        CanonicalReceiptKind::AutonomyRunContract,
        &input.contract.autonomy_run_id,
        &input.contract,
    )
    .await?;
    Ok(json!({
        "contract": input.contract,
        "canonical_receipt": receipt,
        "write_status": write_status
    }))
}

pub(super) async fn load_autonomy_contract(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    run_id: &str,
) -> Result<AutonomyRunContract> {
    Ok(
        load_bounded_autonomy_runtime(state, project_id, task_id, run_id)
            .await?
            .runtime
            .contract,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_autonomy_transition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    run_id: &str,
    expected_state_revision: Option<u64>,
    request: AutonomyTransitionRequest,
    idempotency_key: Option<&str>,
) -> Result<Value> {
    let _commit_guard = autonomy_commit_serializer().lock().await;
    apply_autonomy_transition_locked(
        state,
        context,
        project_id,
        task_id,
        run_id,
        expected_state_revision,
        request,
        idempotency_key,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_autonomy_transition_locked(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    run_id: &str,
    expected_state_revision: Option<u64>,
    request: AutonomyTransitionRequest,
    idempotency_key: Option<&str>,
) -> Result<Value> {
    let loaded = load_bounded_autonomy_runtime(state, project_id, task_id, run_id).await?;
    if loaded.integrity_status == "authoritative_atomic_aggregate" {
        anyhow::bail!(
            "autonomy transition records are audit-only after aggregate activation; use eliot_autonomy_runtime_action"
        );
    }
    let mut contract = loaded.runtime.contract;
    if let Some(idempotency_key) = idempotency_key {
        let replay_write_id = deterministic_canonical_write_id(
            project_id,
            Some(task_id),
            CanonicalReceiptKind::AutonomyRunTransition,
            idempotency_key,
        );
        if let Some(record) = state
            .store
            .autonomy_run_view(project_id, task_id, run_id, 128)
            .await?
            .transitions
            .into_iter()
            .find(|record| record.canonical_receipt.write_id == replay_write_id)
        {
            return Ok(json!({
                "contract": contract,
                "transition": record.receipt_body,
                "write_status": WriteStatus::IdempotentReplay
            }));
        }
    }
    if expected_state_revision.is_some_and(|expected| expected != contract.state_revision) {
        anyhow::bail!(
            "stale autonomy state revision: expected {}, current {}",
            expected_state_revision.unwrap_or_default(),
            contract.state_revision
        );
    }
    let mut transition = AutonomyRunService::transition(&mut contract, &request)?;
    let canonical_key = idempotency_key.map_or_else(
        || {
            format!(
                "{}:{}:{}",
                transition.autonomy_run_id, transition.state_revision, transition.to as u8
            )
        },
        str::to_owned,
    );
    let (receipt, write_status) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyRunTransition,
        &canonical_key,
        &transition,
    )
    .await?;
    transition.canonical_receipt = Some(receipt);
    Ok(json!({
        "contract": contract,
        "transition": transition,
        "write_status": write_status
    }))
}

pub(super) async fn dispatch_autonomy_transition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: AutonomyTransitionToolInput = serde_json::from_value(arguments)?;
    if input.risk_tier.eq_ignore_ascii_case("R3") {
        anyhow::bail!(
            "R3 requires the typed approval request/decision and bounded runtime action path"
        );
    }
    apply_autonomy_transition(
        state,
        context,
        parse_project_id(&input.project_id)?,
        TaskId::from_str(&input.task_id).context("parse autonomy task_id")?,
        &input.autonomy_run_id,
        Some(input.expected_state_revision),
        AutonomyTransitionRequest {
            target: input.target,
            reason: input.reason,
            risk_tier: input.risk_tier,
            approval: None,
            verifier_refs: input.verifier_refs,
        },
        None,
    )
    .await
}

pub(super) fn ensure_autonomy_host_allowed(
    contract: &AutonomyRunContract,
    host_id: &str,
) -> Result<()> {
    if host_id.trim().is_empty()
        || !contract
            .fallback_routes
            .iter()
            .any(|route| route.host_id.eq_ignore_ascii_case(host_id.trim()))
    {
        anyhow::bail!("autonomy host is outside the frozen fallback routes");
    }
    Ok(())
}

pub(super) fn autonomy_path_within(path: &str, root: &str) -> bool {
    let normalize = |value: &str| {
        value
            .trim()
            .replace('\\', "/")
            .trim_matches('/')
            .to_ascii_lowercase()
    };
    let path = normalize(path);
    let root = normalize(root);
    !path.is_empty()
        && !root.is_empty()
        && !path.split('/').any(|segment| segment == "..")
        && (path == root || path.starts_with(&format!("{root}/")))
}

pub(super) async fn require_canonical_autonomy_verifiers(
    state: &McpState,
    task: &TaskContract,
    contract: &AutonomyRunContract,
    required_verifiers: &[String],
    verifier_refs: &[String],
) -> Result<Vec<CanonicalAutonomyVerifierEvidence>> {
    if verifier_refs.is_empty() {
        anyhow::bail!("autonomy progression requires canonical verifier references");
    }
    let mut resolved = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for verifier_ref in verifier_refs {
        let verification_id = verification_id_from_ref(verifier_ref)?;
        if !seen.insert(verification_id) {
            anyhow::bail!("duplicate canonical verifier reference");
        }
        if !task.verification_ids.contains(&verification_id) {
            anyhow::bail!("verifier reference is not bound to the canonical root task");
        }
        let run = state
            .store
            .verification_run_by_id(verification_id)
            .await?
            .context("canonical verifier reference does not resolve")?;
        if run.result != VerificationResult::Passed {
            anyhow::bail!("canonical verifier did not pass");
        }
        let scope = task
            .verification_scopes
            .iter()
            .find(|scope| scope.verification_id == verification_id)
            .context("canonical verifier has no task-bound artifact scope")?;
        let stored_scope = run
            .payload
            .get("artifact_scope")
            .cloned()
            .and_then(|value| serde_json::from_value::<VerifierArtifactScope>(value).ok());
        if stored_scope.as_ref() != Some(scope) {
            anyhow::bail!("canonical verifier run and task artifact scope differ");
        }
        let registry = registered_verifier_for_scope(scope)
            .context("canonical verifier registry profile is stale or unknown")?;
        revalidate_verifier_scope(state, task, scope).await?;
        let acceptance_bound = scope.acceptance_item_ids.iter().all(|item_id| {
            task.acceptance_items.iter().any(|item| {
                item.item_id == *item_id
                    && item.satisfied
                    && item.verification_id == Some(verification_id)
                    && item.verification_scope_hash.as_deref()
                        == Some(scope.canonical_scope_hash.as_str())
            })
        });
        if scope.acceptance_item_ids.is_empty() || !acceptance_bound {
            anyhow::bail!("canonical verifier is unrelated to satisfied task acceptance");
        }
        let contract_uses_task_acceptance_ids =
            contract.acceptance_items.iter().any(|contract_id| {
                task.acceptance_items
                    .iter()
                    .any(|item| item.item_id == *contract_id)
            });
        if contract_uses_task_acceptance_ids
            && !scope
                .acceptance_item_ids
                .iter()
                .any(|item_id| contract.acceptance_items.contains(item_id))
        {
            anyhow::bail!("passed task verifier is unrelated to autonomy acceptance");
        }
        let canonical_ref = format!("verification:{verification_id}");
        resolved.push(CanonicalAutonomyVerifierEvidence {
            verification_id,
            canonical_ref,
            registered_name: registry.id().to_owned(),
            profile_ref: registry.profile_ref(),
            command: registry.command_display().to_owned(),
            version: scope.verifier_version.clone(),
            artifact_scope_hash: scope.canonical_scope_hash.clone(),
            artifact_refs: scope
                .artifact_refs
                .iter()
                .map(|artifact| artifact.resource_ref.clone())
                .collect(),
            acceptance_item_ids: scope.acceptance_item_ids.clone(),
            commit_ref: scope.commit.clone(),
            verifier_ref: registry.reference(),
        });
    }
    require_exact_canonical_verifier_set(required_verifiers, &resolved)?;
    Ok(resolved)
}

pub(super) fn parse_real_autonomy_host(host_id: &str) -> Result<AgentHostId> {
    match host_id.trim().to_ascii_lowercase().as_str() {
        "opencode" => Ok(AgentHostId::OpenCode),
        "antigravity" => Ok(AgentHostId::Antigravity),
        _ => anyhow::bail!(
            "autonomy dogfood assignment requires an exact OpenCode or Antigravity host"
        ),
    }
}

pub(super) fn work_lease_id_from_autonomy_ref(reference: &str) -> Result<WorkLeaseId> {
    WorkLeaseId::from_str(
        reference
            .trim()
            .strip_prefix("work-lease:")
            .unwrap_or(reference.trim()),
    )
    .context("autonomy lease_ref must identify a canonical WorkLease")
}

pub(super) fn require_real_autonomy_reassign_lease(
    broker: &eliot_types::DelegationState,
    work: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    work_item_id: WorkItemId,
    host_label: &str,
    work_lease_ref: &str,
) -> Result<AutonomyLeaseBinding> {
    let host_id = parse_real_autonomy_host(host_label)?;
    let work_lease_id = work_lease_id_from_autonomy_ref(work_lease_ref)?;
    let lease = work
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .context("reassignment has no canonical WorkLease")?;
    if lease.project_id != project_id
        || lease.task_id != task_id
        || lease.work_item_id != work_item_id
        || !eliot_engine::work_lease_is_active(lease)
        || lease.scope.write_set.is_empty()
    {
        anyhow::bail!("reassignment WorkLease is not active and exact for the run work item");
    }
    let binding = broker
        .agent_host_sessions
        .iter()
        .find(|binding| {
            binding.agent_session_id == lease.agent_session_id
                && binding.host_identity.host_id == host_id
        })
        .context("reassignment target has no exact authenticated host session")?;
    let now = time::OffsetDateTime::now_utc();
    let role = broker
        .task_role_leases
        .iter()
        .find(|role| {
            role.task_id == task_id
                && role.agent_session_id == binding.agent_session_id
                && role.role != AgentRole::Controller
                && role.expires_at > now
                && binding.task_role_lease_refs.contains(&role.role_lease_id)
        })
        .context("reassignment target has no live task-scoped role lease")?;
    if !role.capability_scope.iter().any(|capability| {
        capability.eq_ignore_ascii_case("rust") || capability.eq_ignore_ascii_case("implementation")
    }) {
        anyhow::bail!("reassignment target role lacks implementation capability");
    }
    Ok(AutonomyLeaseBinding {
        lease_ref: format!("work-lease:{work_lease_id}"),
        holder: lease.agent_id,
        project_id,
        scope: lease.scope.clone(),
        expires_at: lease.expires_at,
    })
}

#[allow(clippy::too_many_lines)]
pub(super) fn require_real_autonomy_host_result_chain(
    broker: &eliot_types::DelegationState,
    work: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
    work_item_id: WorkItemId,
    host_label: &str,
    lease: &AutonomyLeaseBinding,
) -> Result<AutonomyHostResultChain> {
    let host_id = parse_real_autonomy_host(host_label)?;
    let work_lease_id = work_lease_id_from_autonomy_ref(&lease.lease_ref)?;
    let canonical_lease = work
        .leases
        .iter()
        .find(|candidate| candidate.work_lease_id == work_lease_id)
        .context("autonomy assignment has no canonical WorkLease")?;
    if canonical_lease.project_id != project_id
        || canonical_lease.task_id != task_id
        || canonical_lease.work_item_id != work_item_id
        || canonical_lease.agent_id != lease.holder
        || !eliot_engine::work_lease_is_active(canonical_lease)
        || canonical_struct_hash(&canonical_lease.scope)? != canonical_struct_hash(&lease.scope)?
        || canonical_lease.scope.write_set.is_empty()
    {
        anyhow::bail!("autonomy assignment does not match an active exact task WorkLease");
    }
    let binding = broker
        .agent_host_sessions
        .iter()
        .find(|binding| {
            binding.agent_session_id == canonical_lease.agent_session_id
                && binding.host_identity.host_id == host_id
        })
        .context("autonomy host has no exact authenticated AgentSessionHostBinding")?;
    let now = time::OffsetDateTime::now_utc();
    let role = broker
        .task_role_leases
        .iter()
        .find(|role| {
            role.task_id == task_id
                && role.agent_session_id == binding.agent_session_id
                && role.role != AgentRole::Controller
                && role.expires_at > now
                && binding.task_role_lease_refs.contains(&role.role_lease_id)
        })
        .context("autonomy host has no live task-scoped role lease")?;
    let request = broker
        .agent_invocations
        .iter()
        .rev()
        .find(|request| {
            request.project_id == project_id
                && request.task_id == task_id
                && request.work_item_id == work_item_id
                && request.role_lease_id == role.role_lease_id
                && request.work_lease_id == Some(work_lease_id)
        })
        .context("autonomy host has no governed invocation for the exact leases")?;
    let job = broker
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == request.invocation_id && job.host_id == host_id)
        .context("autonomy invocation has no exact host OperationJob")?;
    if job.state != OperationJobState::Completed {
        anyhow::bail!("autonomy host OperationJob is not completed");
    }
    let result = broker
        .agent_results
        .iter()
        .find(|result| {
            result.invocation_id == request.invocation_id
                && result.host_id == host_id
                && result.host_session_id.as_deref()
                    == Some(binding.host_identity.client_instance_id.as_str())
        })
        .context("autonomy invocation has no exact authenticated host result")?;
    if job.result_ref.as_deref() != Some(result.result_id.as_str())
        || result.status != AgentResultStatus::Succeeded
        || !result.candidate_only
    {
        anyhow::bail!(
            "autonomy OperationJob result_ref does not bind the succeeded candidate result"
        );
    }
    let disposition = broker
        .agent_result_dispositions
        .iter()
        .find(|disposition| {
            disposition.result_id == result.result_id
                && disposition.invocation_id == request.invocation_id
                && disposition.task_id == task_id
                && disposition.kind == AgentResultDispositionKind::Accepted
        })
        .context("autonomy host result has no governed accepted disposition")?;
    let worktree = work
        .worktree_leases
        .iter()
        .find(|worktree| {
            worktree.project_id == project_id
                && worktree.task_id == task_id
                && worktree.work_item_id == work_item_id
                && worktree.work_lease_id == work_lease_id
                && worktree.holder_session_id == binding.agent_session_id
                && matches!(
                    worktree.state,
                    eliot_types::WorktreeLeaseState::Captured
                        | eliot_types::WorktreeLeaseState::Accepted
                )
        })
        .context("autonomy host chain lacks a captured task worktree lease")?;
    let diff = work
        .candidate_diffs
        .iter()
        .find(|diff| {
            diff.worktree_lease_id == worktree.worktree_lease_id
                && diff.project_id == project_id
                && diff.task_id == task_id
                && diff.work_item_id == work_item_id
                && diff.capture_status == CandidateDiffStatus::AcceptedForPatchRunner
        })
        .context("autonomy host chain lacks an accepted in-scope candidate diff")?;
    let review = work
        .candidate_reviews
        .iter()
        .find(|review| {
            review.candidate_diff_id == diff.candidate_diff_id
                && review.decision == CandidateReviewDecision::AcceptForPatchRunner
        })
        .context("autonomy host chain lacks an accepted candidate review")?;
    let head = diff
        .worktree_head
        .as_deref()
        .filter(|head| !head.trim().is_empty())
        .context("autonomy candidate diff has no commit head")?;
    let paths_scoped = !diff.changed_files.is_empty()
        && diff.changed_files.iter().all(|path| {
            canonical_lease
                .scope
                .write_set
                .iter()
                .any(|root| autonomy_path_within(path, root))
                && worktree
                    .allowed_write_set
                    .iter()
                    .any(|root| autonomy_path_within(path, root))
        });
    let commit_ref = format!("commit:{head}");
    if !paths_scoped
        || !result.artifact_refs.contains(&diff.diff_ref)
        || !(result.artifact_refs.contains(&commit_ref)
            || result
                .artifact_refs
                .iter()
                .any(|reference| reference == head))
    {
        anyhow::bail!("autonomy host result lacks a verified in-scope diff/commit artifact");
    }
    Ok(AutonomyHostResultChain {
        work_item_id,
        host_id,
        agent_session_id: binding.agent_session_id,
        role_lease_id: role.role_lease_id.clone(),
        work_lease_id,
        invocation_id: request.invocation_id.clone(),
        result_id: result.result_id.clone(),
        disposition_id: disposition.disposition_id.clone(),
        candidate_diff_ref: diff.diff_ref.clone(),
        candidate_review_ref: review.review_id.clone(),
        commit_ref,
        changed_files: diff.changed_files.clone(),
        verifier_refs: result.verifier_refs.clone(),
    })
}

pub(super) fn autonomy_contract_requires_two_hosts(contract: &AutonomyRunContract) -> bool {
    contract.max_active_agents >= 2
        || contract.acceptance_items.iter().any(|item| {
            let item = item.to_ascii_lowercase();
            (item.contains("two-host") || item.contains("two host") || item.contains("2 host"))
                || (item.contains("opencode") && item.contains("antigravity"))
        })
}

pub(super) fn autonomy_action_response(
    loaded: &LoadedAutonomyRuntime,
    action: &str,
    idempotent_replay: bool,
    action_result: &Value,
    canonical_receipts: &[WriteReceiptRef],
) -> Value {
    json!({
        "accepted": true,
        "action": action,
        "idempotent_replay": idempotent_replay,
        "state_revision": loaded.runtime.contract.state_revision,
        "runtime_revision": loaded.runtime.runtime_revision,
        "action_result": action_result,
        "canonical_receipts": canonical_receipts,
        "run": autonomy_run_projection(loaded)
    })
}

pub(super) fn autonomy_action_denied_response(
    loaded: &LoadedAutonomyRuntime,
    action: &str,
    reason: impl std::fmt::Display,
) -> Value {
    json!({
        "accepted": false,
        "action": action,
        "idempotent_replay": false,
        "reason": reason.to_string(),
        "state_revision": loaded.runtime.contract.state_revision,
        "runtime_revision": loaded.runtime.runtime_revision,
        "canonical_receipts": [],
        "authoritative_aggregate_receipt": Value::Null,
        "run": autonomy_run_projection(loaded)
    })
}

pub(super) fn autonomy_stop_coordination_denial_reason(
    work_state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Option<String> {
    let decision =
        eliot_engine::StopCoordinationGate.evaluate(work_state, Some(project_id), Some(task_id));
    (!decision.allow).then(|| {
        format!(
            "StopCoordinationGate denied terminal autonomy completion: {}",
            decision.reasons.join(", ")
        )
    })
}

pub(super) fn autonomy_approval_denied_response(reason: impl std::fmt::Display) -> Value {
    json!({
        "accepted": false,
        "reason": reason.to_string(),
        "canonical_receipts": [],
        "canonical_receipt": Value::Null
    })
}

pub(super) fn autonomy_completion_approval_hash(
    input: &AutonomyCompletionApprovalInput<'_>,
) -> Result<String> {
    canonical_struct_hash(&AutonomyCompletionApprovalScope {
        action: "complete_run",
        project_id: input.project_id,
        task_id: input.task_id,
        autonomy_run_id: input.autonomy_run_id,
        expected_state_revision: input.expected_state_revision,
        expected_runtime_revision: input.expected_runtime_revision,
        completion_proof_hash: canonical_struct_hash(input.completion_proof)?,
        reason: input.reason,
        risk_tier: "R3",
        verifier_refs: input.verifier_refs,
    })
}

pub(super) async fn exact_autonomy_approval_request(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    autonomy_run_id: &str,
    approval_id: &str,
) -> Result<Option<CanonicalRecord<AutonomyApprovalRequestRecord>>> {
    let Ok(request_write_id) = approval_request_write_id(approval_id) else {
        return Ok(None);
    };
    let Some(request) = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalRequestRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalRequest.as_str()],
            request_write_id,
        )
        .await?
    else {
        return Ok(None);
    };
    if request.receipt_body.approval_id != approval_id
        || request.receipt_body.request_write_id != request_write_id
        || request.canonical_receipt.write_id != request_write_id
        || request.receipt_body.project_id != project_id
        || request.receipt_body.task_id != task_id
        || request.receipt_body.autonomy_run_id != autonomy_run_id
    {
        return Ok(None);
    }
    Ok(Some(request))
}

pub(super) fn validate_autonomy_approval_decision_input(
    input: &AutonomyApprovalDecisionToolInput,
) -> Result<()> {
    validate_broker_text("approval idempotency_key", &input.idempotency_key, 256)?;
    validate_broker_text("approval reason", &input.reason, 512)
}

pub(super) async fn dispatch_autonomy_approval_request(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    if state.profile != McpAccessProfile::CodexController {
        return Ok(autonomy_approval_denied_response(
            "only the authenticated controller can request R3 approval",
        ));
    }
    let input: AutonomyApprovalRequestToolInput = serde_json::from_value(arguments)?;
    validate_broker_text("approval idempotency_key", &input.idempotency_key, 256)?;
    let _commit_guard = autonomy_commit_serializer().lock().await;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse approval task_id")?;
    let loaded =
        load_bounded_autonomy_runtime(state, project_id, task_id, &input.autonomy_run_id).await?;
    if loaded.runtime.contract.state_revision != input.expected_state_revision
        || loaded.runtime.runtime_revision != input.expected_runtime_revision
        || loaded.runtime.contract.state != AutonomyRunState::Verifying
    {
        return Ok(autonomy_approval_denied_response(
            "approval request is stale or the run is not VERIFYING",
        ));
    }
    let exact_action_hash = autonomy_completion_approval_hash(&AutonomyCompletionApprovalInput {
        project_id,
        task_id,
        autonomy_run_id: &input.autonomy_run_id,
        expected_state_revision: input.expected_state_revision,
        expected_runtime_revision: input.expected_runtime_revision,
        completion_proof: &input.completion_proof,
        reason: &input.reason,
        verifier_refs: &input.verifier_refs,
    })?;
    let key = format!("approval-request:{}", input.idempotency_key);
    let write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyApprovalRequest,
        &key,
    );
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalRequestRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalRequest.as_str()],
            write_id,
        )
        .await?
    {
        if existing.receipt_body.exact_action_hash != exact_action_hash
            || existing.receipt_body.requested_by_session_id != context.session_id
            || existing.receipt_body.expected_state_revision != input.expected_state_revision
            || existing.receipt_body.expected_runtime_revision != input.expected_runtime_revision
            || existing.receipt_body.request_write_id != write_id
            || existing.canonical_receipt.write_id != write_id
        {
            return Ok(autonomy_approval_denied_response(
                "approval idempotency key was reused for a different action",
            ));
        }
        return Ok(json!({
            "accepted": true,
            "idempotent_replay": true,
            "approval": existing.receipt_body,
            "canonical_receipt": existing.canonical_receipt,
            "canonical_receipts": [existing.canonical_receipt]
        }));
    }
    let now = time::OffsetDateTime::now_utc();
    let approval = AutonomyApprovalRequestRecord {
        approval_id: format!("autonomy-approval:{write_id}"),
        request_write_id: write_id,
        autonomy_run_id: input.autonomy_run_id,
        project_id,
        task_id,
        expected_state_revision: input.expected_state_revision,
        expected_runtime_revision: input.expected_runtime_revision,
        requested_by_session_id: context.session_id,
        exact_action_hash,
        approval_revision: 0,
        expires_at: now + time::Duration::minutes(input.ttl_minutes.clamp(1, 60)),
        requested_at: now,
    };
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyApprovalRequest,
        &key,
        &approval,
    )
    .await?;
    Ok(json!({
        "accepted": true,
        "idempotent_replay": false,
        "approval": approval,
        "canonical_receipt": receipt,
        "canonical_receipts": [receipt]
    }))
}

pub(super) async fn dispatch_autonomy_approval_decide(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    if state.profile != McpAccessProfile::HumanOperator {
        return Ok(autonomy_approval_denied_response(
            "approval decision requires HumanOperator authority",
        ));
    }
    let input: AutonomyApprovalDecisionToolInput = serde_json::from_value(arguments)?;
    validate_autonomy_approval_decision_input(&input)?;
    let _commit_guard = autonomy_commit_serializer().lock().await;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse approval task_id")?;
    let Some(request) = exact_autonomy_approval_request(
        state,
        project_id,
        task_id,
        &input.autonomy_run_id,
        &input.approval_id,
    )
    .await?
    else {
        return Ok(autonomy_approval_denied_response(
            "approval request does not resolve canonically",
        ));
    };
    let request_write_id = request.receipt_body.request_write_id;
    if input.expected_approval_revision != request.receipt_body.approval_revision {
        return Ok(autonomy_approval_denied_response(
            "approval decision has a stale revision",
        ));
    }
    let key = format!("approval-decision:{}", input.approval_id);
    let write_id = approval_decision_write_id(project_id, task_id, &input.approval_id);
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalDecisionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalDecision.as_str()],
            write_id,
        )
        .await?
    {
        if existing.receipt_body.approval_id != input.approval_id
            || existing.receipt_body.decision != input.decision
            || existing.receipt_body.reason != input.reason
            || existing.receipt_body.request_write_id != request_write_id
            || existing.receipt_body.decision_write_id != write_id
            || existing.canonical_receipt.write_id != write_id
        {
            return Ok(autonomy_approval_denied_response(
                "approval decision idempotency key was reused",
            ));
        }
        return Ok(json!({
            "accepted": true,
            "idempotent_replay": true,
            "decision": existing.receipt_body,
            "canonical_receipt": existing.canonical_receipt,
            "canonical_receipts": [existing.canonical_receipt]
        }));
    }
    if request.receipt_body.expires_at <= time::OffsetDateTime::now_utc() {
        return Ok(autonomy_approval_denied_response(
            "approval request expired before the decision",
        ));
    }
    let decision = AutonomyApprovalDecisionRecord {
        approval_id: input.approval_id,
        request_write_id,
        decision_write_id: write_id,
        autonomy_run_id: input.autonomy_run_id,
        project_id,
        task_id,
        exact_action_hash: request.receipt_body.exact_action_hash,
        decision: input.decision,
        reason: input.reason,
        approval_revision: request.receipt_body.approval_revision.saturating_add(1),
        decided_by_session_id: context.session_id,
        expires_at: request.receipt_body.expires_at,
        decided_at: time::OffsetDateTime::now_utc(),
    };
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyApprovalDecision,
        &key,
        &decision,
    )
    .await?;
    Ok(json!({
        "accepted": true,
        "idempotent_replay": false,
        "decision": decision,
        "canonical_receipt": receipt,
        "canonical_receipts": [receipt]
    }))
}

pub(super) fn inject_autonomy_failure(stage: &str) -> Result<()> {
    if cfg!(test)
        && std::env::var("ELIOT_TEST_AUTONOMY_FAILURE_STAGE")
            .ok()
            .as_deref()
            == Some(stage)
    {
        anyhow::bail!("injected autonomy persistence failure at {stage}");
    }
    Ok(())
}

pub(super) async fn reconcile_autonomy_secondary_audit_records(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    idempotency_key: &str,
    aggregate: &AutonomyWorkGraphRecord,
) -> Result<Vec<WriteReceiptRef>> {
    let mut receipts = Vec::new();
    for (index, transition) in aggregate.secondary_transition_snapshots.iter().enumerate() {
        let (receipt, _) = write_canonical_observation(
            state,
            context,
            project_id,
            Some(task_id),
            CanonicalReceiptKind::AutonomyRunTransition,
            &format!("{idempotency_key}:transition:{index}"),
            transition,
        )
        .await?;
        receipts.push(receipt);
    }
    for (index, recovery) in aggregate.secondary_recovery_snapshots.iter().enumerate() {
        let (receipt, _) = write_canonical_observation(
            state,
            context,
            project_id,
            Some(task_id),
            CanonicalReceiptKind::AutonomyRecovery,
            &format!("{idempotency_key}:recovery:{index}"),
            recovery,
        )
        .await?;
        receipts.push(receipt);
    }
    for (index, tripwire) in aggregate.tripwire_snapshots.iter().enumerate() {
        let (receipt, _) = write_canonical_observation(
            state,
            context,
            project_id,
            Some(task_id),
            CanonicalReceiptKind::AutonomyTripwire,
            &format!("{idempotency_key}:tripwire:{index}"),
            tripwire,
        )
        .await?;
        receipts.push(receipt);
    }
    if let Some(budget) = aggregate.budget_snapshot.as_ref() {
        let (receipt, _) = write_canonical_observation(
            state,
            context,
            project_id,
            Some(task_id),
            CanonicalReceiptKind::AutonomyBudgetLedger,
            &format!("{idempotency_key}:budget"),
            budget,
        )
        .await?;
        receipts.push(receipt);
    }
    if let Some(consumption) = aggregate.approval_consumption.as_ref() {
        if consumption.consumption_write_id
            != approval_consumption_write_id(project_id, task_id, &consumption.approval_id)
        {
            anyhow::bail!("approval consumption canonical write identity is invalid");
        }
        let (receipt, _) = write_canonical_observation(
            state,
            context,
            project_id,
            Some(task_id),
            CanonicalReceiptKind::AutonomyApprovalConsumption,
            &format!("approval-consumption:{}", consumption.approval_id),
            consumption,
        )
        .await?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_autonomy_runtime_action(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let _commit_guard = autonomy_commit_serializer().lock().await;
    dispatch_autonomy_runtime_action_locked(state, context, arguments).await
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_autonomy_runtime_action_locked(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    if !matches!(
        state.profile,
        McpAccessProfile::CodexController | McpAccessProfile::HumanOperator
    ) {
        anyhow::bail!("only the controller or HumanOperator can control an autonomy run");
    }
    let input: AutonomyRuntimeActionToolInput = serde_json::from_value(arguments)?;
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse autonomy task_id")?;
    let task = state
        .store
        .task_contract_by_id(task_id)
        .await?
        .context("autonomy root task does not exist")?;
    if task.project_id != project_id {
        anyhow::bail!("autonomy root task belongs to a different project");
    }
    let mut loaded =
        load_bounded_autonomy_runtime(state, project_id, task_id, &input.autonomy_run_id).await?;
    if loaded.runtime.contract.project_id != project_id
        || loaded.runtime.contract.root_task_id != task_id
        || loaded.runtime.contract.autonomy_run_id != input.autonomy_run_id
    {
        anyhow::bail!("autonomy action scope does not match the canonical contract");
    }

    let action_name = input.action.name();
    let action_fingerprint = canonical_struct_hash(&input.action)?;
    let graph_key = format!("{}:work-graph", input.idempotency_key);
    let graph_write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyWorkGraph,
        &graph_key,
    );
    if let Some(record) = loaded
        .canonical
        .work_graphs
        .iter()
        .find(|record| record.canonical_receipt.write_id == graph_write_id)
    {
        let replayed: AutonomyWorkGraphRecord =
            serde_json::from_value(record.receipt_body.clone())?;
        if replayed.action_fingerprint != action_fingerprint
            || decode_authoritative_autonomy_aggregate(record)?.is_none()
        {
            anyhow::bail!("autonomy idempotency_key was reused for a different action");
        }
        let mut receipts = vec![record.canonical_receipt.clone()];
        receipts.extend(
            reconcile_autonomy_secondary_audit_records(
                state,
                context,
                project_id,
                task_id,
                &input.idempotency_key,
                &replayed,
            )
            .await?,
        );
        return Ok(autonomy_action_response(
            &loaded,
            action_name,
            true,
            &replayed.action_result,
            &receipts,
        ));
    }
    if loaded.runtime.contract.state_revision != input.expected_state_revision {
        return Ok(autonomy_action_denied_response(
            &loaded,
            action_name,
            format!(
                "stale autonomy state revision: expected {}, current {}",
                input.expected_state_revision, loaded.runtime.contract.state_revision
            ),
        ));
    }
    if loaded.runtime.runtime_revision != input.expected_runtime_revision {
        return Ok(autonomy_action_denied_response(
            &loaded,
            action_name,
            format!(
                "stale autonomy runtime revision: expected {}, current {}",
                input.expected_runtime_revision, loaded.runtime.runtime_revision
            ),
        ));
    }

    let previous_transition_count = loaded.runtime.transition_receipts.len();
    let previous_recovery_count = loaded.runtime.recovery_receipts.len();
    let previous_tripwire_count = loaded.runtime.ledger.tripwires.len();
    let mut tripwire_context: Option<(WorkItemId, String)> = None;
    let mut usage_evidence_refs = Vec::new();
    let action_result = match &input.action {
        AutonomyRuntimeAction::CreateWorkPlan {
            tripwire_policy,
            work_items,
        } => {
            if !loaded.runtime.work_items.is_empty()
                || work_items.len() < 2
                || work_items.len() > loaded.runtime.contract.max_work_items as usize
            {
                anyhow::bail!("work plan must initialize 2..=max_work_items nodes exactly once");
            }
            let _ = BoundedAutonomyRuntime::new(
                loaded.runtime.contract.clone(),
                tripwire_policy.clone(),
            )?;
            loaded.runtime.tripwire_policy = tripwire_policy.clone();
            for item in work_items {
                loaded.runtime.register_work_item(item.clone())?;
            }
            json!({"registered_work_items": work_items.len()})
        }
        AutonomyRuntimeAction::Advance {
            target,
            reason,
            risk_tier,
            verifier_refs,
        } => {
            if matches!(
                target,
                AutonomyRunState::DoneVerified | AutonomyRunState::PausedByOperator
            ) {
                anyhow::bail!("DONE and recovery pause require their dedicated typed actions");
            }
            if *target == AutonomyRunState::Verifying {
                let mut refs = loaded
                    .runtime
                    .work_items
                    .iter()
                    .flat_map(|item| item.verifier_refs.clone())
                    .chain(verifier_refs.iter().cloned())
                    .collect::<Vec<_>>();
                refs.sort();
                refs.dedup();
                let mut required = loaded
                    .runtime
                    .work_items
                    .iter()
                    .flat_map(|item| item.required_verifiers.clone())
                    .chain(loaded.runtime.contract.required_verifiers.clone())
                    .collect::<Vec<_>>();
                required.sort();
                required.dedup();
                require_canonical_autonomy_verifiers(
                    state,
                    &task,
                    &loaded.runtime.contract,
                    &required,
                    &refs,
                )
                .await?;
            }
            let transition = loaded.runtime.transition(&AutonomyTransitionRequest {
                target: *target,
                reason: reason.clone(),
                risk_tier: risk_tier.clone(),
                approval: None,
                verifier_refs: verifier_refs.clone(),
            })?;
            json!({"transition": transition})
        }
        AutonomyRuntimeAction::AssignWork {
            work_item_id,
            host_id,
            lease,
        } => {
            if let Err(error) = ensure_autonomy_host_allowed(&loaded.runtime.contract, host_id) {
                return Ok(autonomy_action_denied_response(&loaded, action_name, error));
            }
            let broker = delegation_runtime::load_state(&state.root)?;
            let work = delegation_runtime::load_work_state(&state.root)?;
            let chain = match require_real_autonomy_host_result_chain(
                &broker,
                &work,
                project_id,
                task_id,
                *work_item_id,
                host_id,
                lease,
            ) {
                Ok(chain) => chain,
                Err(error) => {
                    return Ok(autonomy_action_denied_response(&loaded, action_name, error));
                }
            };
            loaded.runtime.activate_work_item(
                *work_item_id,
                lease.clone(),
                time::OffsetDateTime::now_utc(),
            )?;
            loaded
                .graph
                .host_bindings
                .retain(|binding| binding.work_item_id != *work_item_id);
            loaded.graph.host_bindings.push(AutonomyHostBinding {
                work_item_id: *work_item_id,
                host_id: host_id.trim().to_ascii_lowercase(),
                lease_ref: lease.lease_ref.clone(),
            });
            loaded
                .graph
                .host_result_chains
                .retain(|existing| existing.work_item_id != *work_item_id);
            loaded.graph.host_result_chains.push(chain.clone());
            json!({
                "work_item_id": work_item_id,
                "host_id": host_id,
                "lease_ref": lease.lease_ref,
                "host_result_chain": chain
            })
        }
        AutonomyRuntimeAction::ChargeUsage {
            work_item_id,
            lease_ref,
            usage_evidence_ref,
            intent,
        } => {
            validate_broker_text("usage_evidence_ref", usage_evidence_ref, 512)?;
            let item = loaded
                .runtime
                .work_items
                .iter()
                .find(|item| item.work_item_id == *work_item_id)
                .context("usage work_item_id is not in the canonical graph")?;
            if item.status != WorkItemStatus::Active
                || item
                    .lease
                    .as_ref()
                    .is_none_or(|lease| lease.lease_ref != *lease_ref)
                || intent.project_id != item.project_id
                || intent.work_items_started != 0
                || intent.active_agents != loaded.runtime.ledger.active_agents
                || (intent.model_invocations == 0
                    && intent.tool_calls == 0
                    && intent.wall_time_seconds == 0
                    && intent.cost_or_token_units == 0)
            {
                anyhow::bail!("usage must be non-zero and bound to the active exact work lease");
            }
            let decision = loaded.runtime.record_step(intent)?;
            tripwire_context = Some((*work_item_id, usage_evidence_ref.clone()));
            usage_evidence_refs.push(usage_evidence_ref.clone());
            json!({"budget_decision": decision})
        }
        AutonomyRuntimeAction::CompleteWorkItem {
            work_item_id,
            lease_ref,
            _verifier_names: _,
            verifier_refs,
        } => {
            let item = loaded
                .runtime
                .work_items
                .iter()
                .find(|item| item.work_item_id == *work_item_id)
                .context("completion work_item_id is not in the canonical graph")?;
            if item
                .lease
                .as_ref()
                .is_none_or(|lease| lease.lease_ref != *lease_ref)
            {
                anyhow::bail!("work completion lease_ref does not match the active lease");
            }
            let required_verifiers = item.required_verifiers.clone();
            let resolved = require_canonical_autonomy_verifiers(
                state,
                &task,
                &loaded.runtime.contract,
                &required_verifiers,
                verifier_refs,
            )
            .await?;
            let derived_names = resolved
                .iter()
                .flat_map(|verifier| {
                    [
                        verifier.registered_name.clone(),
                        verifier.profile_ref.clone(),
                        verifier.command.clone(),
                        verifier.verifier_ref.clone(),
                    ]
                })
                .collect::<Vec<_>>();
            let canonical_refs = resolved
                .iter()
                .map(|verifier| verifier.canonical_ref.clone())
                .collect::<Vec<_>>();
            let Some(binding) = loaded
                .graph
                .host_bindings
                .iter()
                .find(|binding| binding.work_item_id == *work_item_id)
                .cloned()
            else {
                return Ok(autonomy_action_denied_response(
                    &loaded,
                    action_name,
                    "work completion has no canonical host binding",
                ));
            };
            let Some(active_lease) = item.lease.clone() else {
                return Ok(autonomy_action_denied_response(
                    &loaded,
                    action_name,
                    "work completion has no active autonomy lease",
                ));
            };
            let broker = delegation_runtime::load_state(&state.root)?;
            let work = delegation_runtime::load_work_state(&state.root)?;
            let mut chain = match require_real_autonomy_host_result_chain(
                &broker,
                &work,
                project_id,
                task_id,
                *work_item_id,
                &binding.host_id,
                &active_lease,
            ) {
                Ok(chain) => chain,
                Err(error) => {
                    return Ok(autonomy_action_denied_response(&loaded, action_name, error));
                }
            };
            let result_verification_ids = chain
                .verifier_refs
                .iter()
                .map(|reference| verification_id_from_ref(reference))
                .collect::<Result<std::collections::BTreeSet<_>>>()?;
            let required_verification_ids = resolved
                .iter()
                .map(|verifier| verifier.verification_id)
                .collect::<std::collections::BTreeSet<_>>();
            if result_verification_ids != required_verification_ids {
                return Ok(autonomy_action_denied_response(
                    &loaded,
                    action_name,
                    "host result verifier refs do not match canonical required runs",
                ));
            }
            chain.verifier_refs.clone_from(&canonical_refs);
            loaded.runtime.complete_work_item(
                *work_item_id,
                &derived_names,
                canonical_refs,
                time::OffsetDateTime::now_utc(),
            )?;
            loaded
                .graph
                .host_result_chains
                .retain(|existing| existing.work_item_id != *work_item_id);
            loaded.graph.host_result_chains.push(chain.clone());
            json!({
                "work_item_id": work_item_id,
                "status": "completed",
                "canonical_verifiers": resolved,
                "host_result_chain": chain
            })
        }
        AutonomyRuntimeAction::ReassignWork {
            work_item_id,
            host_id,
            work_lease_ref,
            reason,
        } => {
            if let Err(error) = ensure_autonomy_host_allowed(&loaded.runtime.contract, host_id) {
                return Ok(autonomy_action_denied_response(&loaded, action_name, error));
            }
            let broker = delegation_runtime::load_state(&state.root)?;
            let work = delegation_runtime::load_work_state(&state.root)?;
            let next_lease = match require_real_autonomy_reassign_lease(
                &broker,
                &work,
                project_id,
                task_id,
                *work_item_id,
                host_id,
                work_lease_ref,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    return Ok(autonomy_action_denied_response(&loaded, action_name, error));
                }
            };
            let recovery = match loaded.runtime.reassign_work_item(
                *work_item_id,
                next_lease.clone(),
                reason,
                time::OffsetDateTime::now_utc(),
            ) {
                Ok(recovery) => recovery,
                Err(error) => {
                    return Ok(autonomy_action_denied_response(&loaded, action_name, error));
                }
            };
            loaded
                .graph
                .host_bindings
                .retain(|binding| binding.work_item_id != *work_item_id);
            loaded.graph.host_bindings.push(AutonomyHostBinding {
                work_item_id: *work_item_id,
                host_id: host_id.trim().to_ascii_lowercase(),
                lease_ref: next_lease.lease_ref.clone(),
            });
            json!({"recovery": recovery, "canonical_lease": next_lease})
        }
        AutonomyRuntimeAction::RecordTripwire {
            work_item_id,
            kind,
            signature,
            reason,
            evidence_ref,
        } => {
            validate_broker_text("tripwire evidence_ref", evidence_ref, 512)?;
            if !loaded
                .runtime
                .work_items
                .iter()
                .any(|item| item.work_item_id == *work_item_id)
            {
                anyhow::bail!("tripwire work_item_id is not in the canonical graph");
            }
            let tripwire =
                loaded
                    .runtime
                    .record_external_tripwire(*kind, signature.clone(), reason.clone());
            tripwire_context = Some((*work_item_id, evidence_ref.clone()));
            json!({"tripwire": tripwire})
        }
        AutonomyRuntimeAction::PauseForRecovery {
            work_item_id,
            tripwire_id,
            reason,
        } => {
            let tripwire_matches = loaded.canonical.tripwires.iter().any(|record| {
                serde_json::from_value::<AutonomyTripwireEnvelope>(record.receipt_body.clone())
                    .is_ok_and(|envelope| {
                        envelope.work_item_id == *work_item_id
                            && envelope.tripwire.tripwire_id == *tripwire_id
                    })
            });
            if !tripwire_matches {
                anyhow::bail!("pause requires an exact canonical tripwire for the work item");
            }
            let (transition, recovery) = loaded.runtime.pause_for_recovery(
                *work_item_id,
                tripwire_id.clone(),
                reason.clone(),
            )?;
            json!({"transition": transition, "recovery": recovery})
        }
        AutonomyRuntimeAction::ResumeAfterRecovery {
            work_item_id,
            reason,
        } => {
            let (transition, recovery) = loaded
                .runtime
                .resume_after_recovery(*work_item_id, reason.clone())?;
            json!({"transition": transition, "recovery": recovery})
        }
        AutonomyRuntimeAction::CompleteRun {
            completion_proof,
            reason,
            approval_id,
            verifier_refs,
        } => {
            if completion_proof.changed_files.is_empty()
                || completion_proof.changed_files.iter().any(|path| {
                    !loaded.runtime.work_items.iter().any(|item| {
                        item.status == WorkItemStatus::Completed
                            && item.lease.as_ref().is_some_and(|lease| {
                                lease
                                    .scope
                                    .write_set
                                    .iter()
                                    .any(|root| autonomy_path_within(path, root))
                            })
                    })
                })
            {
                anyhow::bail!(
                    "CompletionProof changed files are outside completed canonical work leases"
                );
            }
            let resolved = require_canonical_autonomy_verifiers(
                state,
                &task,
                &loaded.runtime.contract,
                &loaded.runtime.contract.required_verifiers,
                verifier_refs,
            )
            .await?;
            require_completion_proof_verifier_binding(completion_proof, &resolved)?;
            let canonical_refs = resolved
                .iter()
                .map(|verifier| verifier.canonical_ref.clone())
                .collect::<Vec<_>>();
            let broker = delegation_runtime::load_state(&state.root)?;
            let work = delegation_runtime::load_work_state(&state.root)?;
            let mut terminal_chains = Vec::new();
            for item in loaded
                .runtime
                .work_items
                .iter()
                .filter(|item| item.required && item.status == WorkItemStatus::Completed)
            {
                let Some(lease) = item.lease.as_ref() else {
                    return Ok(autonomy_action_denied_response(
                        &loaded,
                        action_name,
                        "completed required work item lost its autonomy lease",
                    ));
                };
                let Some(binding) = loaded
                    .graph
                    .host_bindings
                    .iter()
                    .find(|binding| binding.work_item_id == item.work_item_id)
                else {
                    return Ok(autonomy_action_denied_response(
                        &loaded,
                        action_name,
                        "completed required work item lost its host binding",
                    ));
                };
                let chain = match require_current_canonical_autonomy_host_result_chain(
                    TerminalChainContext {
                        state,
                        broker: &broker,
                        work: &work,
                        project_id,
                        task_id,
                    },
                    item.work_item_id,
                    &binding.host_id,
                    lease,
                )
                .await
                {
                    Ok(chain) => chain,
                    Err(error) => {
                        return Ok(autonomy_action_denied_response(&loaded, action_name, error));
                    }
                };
                let host_verifiers = chain
                    .verifier_refs
                    .iter()
                    .map(|reference| verification_id_from_ref(reference))
                    .collect::<Result<std::collections::BTreeSet<_>>>()?;
                let item_verifiers = item
                    .verifier_refs
                    .iter()
                    .map(|reference| verification_id_from_ref(reference))
                    .collect::<Result<std::collections::BTreeSet<_>>>()?;
                if host_verifiers != item_verifiers {
                    return Ok(autonomy_action_denied_response(
                        &loaded,
                        action_name,
                        "terminal host result verifier refs differ from completed work evidence",
                    ));
                }
                terminal_chains.push(chain);
            }
            if let Err(error) =
                require_two_real_host_chains(&loaded.runtime.contract, &terminal_chains)
            {
                return Ok(autonomy_action_denied_response(&loaded, action_name, error));
            }
            if completion_proof.changed_files.iter().any(|path| {
                !terminal_chains
                    .iter()
                    .any(|chain| chain.changed_files.contains(path))
            }) {
                return Ok(autonomy_action_denied_response(
                    &loaded,
                    action_name,
                    "CompletionProof changed files are not backed by host diff chains",
                ));
            }
            loaded.graph.host_result_chains = terminal_chains;
            let canonical_work = delegation_runtime::load_work_state(&state.root)?;
            if let Some(reason) =
                autonomy_stop_coordination_denial_reason(&canonical_work, project_id, task_id)
            {
                return Ok(autonomy_action_denied_response(
                    &loaded,
                    action_name,
                    reason,
                ));
            }
            let exact_action_hash =
                autonomy_completion_approval_hash(&AutonomyCompletionApprovalInput {
                    project_id,
                    task_id,
                    autonomy_run_id: &input.autonomy_run_id,
                    expected_state_revision: input.expected_state_revision,
                    expected_runtime_revision: input.expected_runtime_revision,
                    completion_proof,
                    reason,
                    verifier_refs,
                })?;
            let (approval, consumption) = match resolve_canonical_r3_approval(
                state,
                context,
                CanonicalR3ApprovalResolution {
                    loaded: &loaded,
                    project_id,
                    task_id,
                    approval_id,
                    exact_action_hash: &exact_action_hash,
                    aggregate_write_id: graph_write_id,
                },
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(error) => {
                    return Ok(autonomy_action_denied_response(&loaded, action_name, error));
                }
            };
            let transition = loaded.runtime.complete_verified(
                &AutonomyTransitionRequest {
                    target: AutonomyRunState::DoneVerified,
                    reason: reason.clone(),
                    risk_tier: "R3".to_owned(),
                    approval: Some(approval),
                    verifier_refs: canonical_refs,
                },
                completion_proof,
            )?;
            loaded.graph.completion_proof = Some(completion_proof.clone());
            loaded.graph.approval_consumption = Some(consumption.clone());
            json!({
                "transition": transition,
                "completion_proof": completion_proof,
                "canonical_verifiers": resolved,
                "approval_consumption": consumption
            })
        }
    };

    let new_transitions = loaded.runtime.transition_receipts[previous_transition_count..].to_vec();
    let new_recoveries = loaded.runtime.recovery_receipts[previous_recovery_count..].to_vec();
    let new_tripwires = loaded.runtime.ledger.tripwires[previous_tripwire_count..].to_vec();
    let tripwire_snapshots =
        tripwire_context.map_or_else(Vec::new, |(work_item_id, evidence_ref)| {
            new_tripwires
                .iter()
                .map(|tripwire| AutonomyTripwireEnvelope {
                    autonomy_run_id: input.autonomy_run_id.clone(),
                    runtime_revision: loaded.runtime.runtime_revision,
                    work_item_id,
                    evidence_ref: evidence_ref.clone(),
                    tripwire: tripwire.clone(),
                })
                .collect()
        });
    let budget = AutonomyBudgetRecord {
        autonomy_run_id: input.autonomy_run_id.clone(),
        runtime_revision: loaded.runtime.runtime_revision,
        ledger: loaded.runtime.ledger.clone(),
        usage_evidence_refs,
    };

    loaded.graph.autonomy_run_id = input.autonomy_run_id;
    loaded.graph.runtime_revision = loaded.runtime.runtime_revision;
    loaded.graph.action = action_name.to_owned();
    loaded.graph.action_fingerprint = action_fingerprint;
    loaded.graph.tripwire_policy = loaded.runtime.tripwire_policy.clone();
    loaded.graph.work_items = loaded.runtime.work_items.clone();
    loaded.graph.transition_refs = loaded
        .runtime
        .transition_receipts
        .iter()
        .map(|transition| transition.transition_id.clone())
        .collect();
    loaded.graph.recovery_refs = loaded
        .runtime
        .recovery_receipts
        .iter()
        .map(|recovery| recovery.recovery_id.clone())
        .collect();
    loaded.graph.aggregate_schema_version = Some(AUTONOMY_ACTION_AGGREGATE_SCHEMA.to_owned());
    loaded.graph.runtime_snapshot = Some(serde_json::to_value(&loaded.runtime)?);
    loaded.graph.transition_snapshots = loaded.runtime.transition_receipts.clone();
    loaded.graph.recovery_snapshots = loaded.runtime.recovery_receipts.clone();
    loaded.graph.secondary_transition_snapshots = new_transitions;
    loaded.graph.secondary_recovery_snapshots = new_recoveries;
    loaded.graph.tripwire_snapshots = tripwire_snapshots;
    loaded.graph.budget_snapshot = Some(budget);
    loaded.graph.action_result = action_result.clone();
    let completion_proof_hash = loaded
        .graph
        .completion_proof
        .as_ref()
        .map(canonical_struct_hash)
        .transpose()?;
    loaded.graph.authoritative_commit = Some(AutonomyActionCommit {
        aggregate_write_id: graph_write_id.to_string(),
        idempotency_key: input.idempotency_key.clone(),
        action: action_name.to_owned(),
        action_fingerprint: loaded.graph.action_fingerprint.clone(),
        committed_state: loaded.runtime.contract.state,
        committed_state_revision: loaded.runtime.contract.state_revision,
        committed_runtime_revision: loaded.runtime.runtime_revision,
        completion_proof_hash,
    });
    inject_autonomy_failure("before_aggregate")?;
    let (graph_receipt, _) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyWorkGraph,
        &graph_key,
        &loaded.graph,
    )
    .await?;
    let mut canonical_receipts = vec![graph_receipt];
    inject_autonomy_failure("after_aggregate")?;
    canonical_receipts.extend(
        reconcile_autonomy_secondary_audit_records(
            state,
            context,
            project_id,
            task_id,
            &input.idempotency_key,
            &loaded.graph,
        )
        .await?,
    );
    Ok(autonomy_action_response(
        &loaded,
        action_name,
        false,
        &action_result,
        &canonical_receipts,
    ))
}

pub(super) async fn require_current_canonical_autonomy_host_result_chain(
    context: TerminalChainContext<'_>,
    work_item_id: WorkItemId,
    host_label: &str,
    lease: &AutonomyLeaseBinding,
) -> Result<AutonomyHostResultChain> {
    let (broker, work) =
        rehydrate_terminal_chain(&context, work_item_id, host_label, lease).await?;
    let canonical_context = TerminalChainContext {
        state: context.state,
        broker: &broker,
        work: &work,
        project_id: context.project_id,
        task_id: context.task_id,
    };
    let chain = require_real_autonomy_host_result_chain(
        canonical_context.broker,
        canonical_context.work,
        canonical_context.project_id,
        canonical_context.task_id,
        work_item_id,
        host_label,
        lease,
    )?;
    validate_current_chain_projections(&canonical_context, &chain).await?;
    persist_rehydrated_terminal_chain(context.state, &canonical_context, &chain)?;
    Ok(chain)
}
