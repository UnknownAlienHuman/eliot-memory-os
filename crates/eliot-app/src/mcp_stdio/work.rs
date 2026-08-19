//! Doing work under a lease.
//!
//! An action plan takes an action lease, a patch runs inside a worktree, and
//! both are scoped by a work lease that has to be claimed, renewed and
//! released. The authority chain is the point of this surface, so the whole
//! chain lives in one module.

use super::*;

pub(super) async fn dispatch_action_plan(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ActionPlanToolInput = serde_json::from_value(arguments)?;
    let project = input
        .project
        .or(input.project_id)
        .context("project or project_id is required")?;
    let task = input
        .task
        .or(input.task_id)
        .context("task or task_id is required")?;
    let kind = input
        .requested_action_kind
        .unwrap_or(ActionKind::ChangePlanOnly);
    let artifacts = action_plan::create_action_lease_artifacts(
        &state.root,
        state.store.clone(),
        &state.control_wal,
        action_plan::ActionPlanInput {
            project_label: project.clone(),
            task_label: task.clone(),
            goal: input.goal.clone(),
            requested_action_kind: kind,
            change_plan: input.change_plan,
            verifier_plan: input.verifier_plan,
        },
    )
    .await?;
    action_plan::write_action_lease_report(
        &state.root,
        &project,
        &task,
        &input.goal,
        &artifacts.record,
    )?;
    Ok(action_plan::action_lease_report_value(
        &project,
        &task,
        &input.goal,
        &artifacts.record,
    ))
}

pub(super) fn dispatch_action_lease_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ActionLeaseStatusToolInput = serde_json::from_value(arguments)?;
    let latest = action_plan::latest_action_lease_report(&state.root)?
        .context("no latest ActionLease report found; call eliot_action_plan first")?;
    Ok(json!({
        "component": "action_lease_status",
        "requested_project": input.project.or(input.project_id),
        "requested_task": input.task.or(input.task_id),
        "latest": latest
    }))
}

pub(super) async fn dispatch_patch_preflight(state: &McpState, arguments: Value) -> Result<Value> {
    let input: PatchToolInput = serde_json::from_value(arguments)?;
    let blob_store = BlobStore::open(&state.blob_store)?;
    let (request, lease, report, verifier_plan) =
        patch_request_from_input(&state.root, &input.lease_id, input.diff_text)?;
    let work_lease = patch_work_lease(&lease, &report, &verifier_plan);
    let repo_root = patch_repo_root(&lease)?;
    let runner = PatchRunner::new(&repo_root, Some(&blob_store));
    let incident_lockdown_active = IncidentService::new(&state.root).lockdown_active()?;
    let mut patch_run = runner
        .preflight(&PatchRunnerInput {
            request: &request,
            lease: Some(&lease),
            work_lease: Some(&work_lease),
            codecortex_reports: std::slice::from_ref(&report),
            verifier_plan: Some(&verifier_plan),
            incident_lockdown_active,
        })
        .await?;
    let mut verifier_runs = Vec::new();
    write_patch_memory(state, &mut patch_run, &mut verifier_runs).await?;
    let report_value = json!({
        "component": "patch",
        "patch_run": patch_run,
        "verifier_runs": verifier_runs
    });
    write_json_report(&patch_latest_path(&state.root), &report_value)?;
    Ok(report_value)
}

pub(super) async fn dispatch_patch_apply(state: &McpState, arguments: Value) -> Result<Value> {
    let input: PatchToolInput = serde_json::from_value(arguments)?;
    let blob_store = BlobStore::open(&state.blob_store)?;
    let (request, lease, report, verifier_plan) =
        patch_request_from_input(&state.root, &input.lease_id, input.diff_text)?;
    let work_lease = patch_work_lease(&lease, &report, &verifier_plan);
    let repo_root = patch_repo_root(&lease)?;
    let runner = PatchRunner::new(&repo_root, Some(&blob_store));
    let verifier = VerifierHarness::new(&repo_root, Some(&blob_store));
    let incident_lockdown_active = IncidentService::new(&state.root).lockdown_active()?;
    let (mut patch_run, mut verifier_runs) = runner
        .apply(
            &PatchRunnerInput {
                request: &request,
                lease: Some(&lease),
                work_lease: Some(&work_lease),
                codecortex_reports: std::slice::from_ref(&report),
                verifier_plan: Some(&verifier_plan),
                incident_lockdown_active,
            },
            &verifier,
        )
        .await?;
    write_patch_memory(state, &mut patch_run, &mut verifier_runs).await?;
    let report_value = json!({
        "component": "patch",
        "patch_run": patch_run,
        "verifier_runs": verifier_runs
    });
    write_json_report(&patch_latest_path(&state.root), &report_value)?;
    write_json_report(
        &verifier_latest_path(&state.root),
        &json!({ "component": "verifier", "verifier_runs": report_value["verifier_runs"].clone() }),
    )?;
    Ok(report_value)
}

pub(super) fn dispatch_patch_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: PatchStatusToolInput = serde_json::from_value(arguments)?;
    let report = latest_json_report(&patch_latest_path(&state.root))?
        .context("no latest PatchRun report found")?;
    Ok(json!({
        "component": "patch_status",
        "requested_patch_run": input.patch_run_id,
        "latest": report
    }))
}

pub(super) async fn dispatch_work_create(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkCreateToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let task_id = task_id_from_label(&input.task);
    let (project_id, scope, required_verifiers) =
        work_create_scope(&input.project, input.read, input.write)?;
    let session = AgentSessionService.create_controller(&mut work_state, project_id);
    let item = WorkQueueService.create_work_item(
        &mut work_state,
        WorkCreateRequest {
            project_id,
            task_id,
            project: input.project.clone(),
            task: input.task.clone(),
            goal: input.goal,
            scope,
            required: true,
            created_by: session.agent_session_id,
            required_verifiers,
        },
    );
    write_work_entities(
        state,
        &mut work_state,
        Some(session.agent_session_id),
        Some(item.work_item_id),
        None,
        &[],
    )
    .await?;
    let report = WorkQueueService.status_report(&work_state, &input.project, &input.task);
    save_work_state_and_report(&state.root, &work_state, &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

pub(super) async fn dispatch_work_claim(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkClaimToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let item = find_work_item(&work_state, &input.project, &input.task)
        .context("no matching work item found; call eliot_work_create first")?;
    let item_id = item.work_item_id;
    let project_id = item.project_id;
    let role = parse_agent_role(input.role.as_deref().unwrap_or("implementer"))?;
    let session = AgentSessionService.create_for_role(&mut work_state, project_id, role);
    let session_id = session.agent_session_id;
    let decision = WorkLeaseService.claim(
        &mut work_state,
        WorkClaimRequest {
            work_item_id: item_id,
            agent_session_id: session_id,
            role,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let conflict_ids = latest_conflict_ids_for_item(&work_state, item_id);
    write_work_entities(
        state,
        &mut work_state,
        Some(session_id),
        Some(item_id),
        decision.work_lease_id,
        &conflict_ids,
    )
    .await?;
    let report = WorkQueueService.status_report(&work_state, &input.project, &input.task);
    save_work_state_and_report(&state.root, &work_state, &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

pub(super) fn dispatch_work_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let work_state = load_work_state(&state.root)?;
    let report = WorkQueueService.status_report(&work_state, &input.project, &input.task);
    save_work_state_and_report(&state.root, &work_state, &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

pub(super) async fn dispatch_work_renew(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkLeaseToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let lease_id = WorkLeaseId::from_str(&input.lease_id).context("parse work lease id")?;
    let decision = WorkLeaseService.renew(&mut work_state, lease_id, default_lease_ttl_minutes());
    write_work_entities(
        state,
        &mut work_state,
        None,
        None,
        decision.work_lease_id,
        &[],
    )
    .await?;
    let (project, task) = labels_for_lease(&work_state, lease_id);
    let report = WorkQueueService.status_report(&work_state, &project, &task);
    save_work_state_and_report(&state.root, &work_state, &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

pub(super) async fn dispatch_work_release(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkLeaseToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let lease_id = WorkLeaseId::from_str(&input.lease_id).context("parse work lease id")?;
    let decision = WorkLeaseService.release(&mut work_state, lease_id);
    write_work_entities(
        state,
        &mut work_state,
        None,
        None,
        decision.work_lease_id,
        &[],
    )
    .await?;
    let (project, task) = labels_for_lease(&work_state, lease_id);
    let report = WorkQueueService.status_report(&work_state, &project, &task);
    save_work_state_and_report(&state.root, &work_state, &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

pub(super) fn dispatch_work_conflicts(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let work_state = load_work_state(&state.root)?;
    let report = WorkQueueService.status_report(&work_state, &input.project, &input.task);
    Ok(json!({
        "component": "work_conflicts",
        "project": input.project,
        "task": input.task,
        "conflicts": report.conflicts,
        "operation_status": if report.conflicts.is_empty() {
            OperationStatus::OperationCompleted
        } else {
            OperationStatus::Blocked
        }
    }))
}

pub(super) async fn dispatch_worktree_create(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorktreeCreateToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let work_lease_id = WorkLeaseId::from_str(&input.lease_id).context("parse work lease id")?;
    let work_lease = work_state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == work_lease_id)
        .cloned()
        .context("work lease not found")?;
    let repo_root = PathBuf::from(&work_lease.scope.repo_root);
    let request = WorktreeLeaseRequest {
        request_id: WorktreeLeaseRequestId::new_v7(),
        project_id: work_lease.project_id,
        task_id: work_lease.task_id,
        work_item_id: work_lease.work_item_id,
        work_lease_id: work_lease.work_lease_id,
        agent_session_id: work_lease.agent_session_id,
        repo_root: work_lease.scope.repo_root.clone(),
        requested_branch_name: None,
        requested_scope: work_lease.scope,
        base_commit: Some(git_head_blocking(&repo_root)?),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let mut lease = WorktreeLeaseService
        .create(
            &mut work_state,
            WorktreeCreateInput {
                request,
                worktree_root: production_worktree_root(
                    &repo_root,
                    work_lease.project_id,
                    work_lease.task_id,
                    work_lease.work_lease_id,
                )?,
                ttl_minutes: WorktreeLeaseService::default_ttl_minutes(),
            },
        )
        .await?;
    write_worktree_memory(state, Some(&mut lease), None, None, None).await?;
    replace_worktree_lease(&mut work_state, lease.clone());
    save_worktree_state_and_reports(&state.root, &work_state)?;
    Ok(json!({
        "component": "worktree_create",
        "worktree_lease": lease,
        "operation_status": OperationStatus::OperationCompleted
    }))
}

pub(super) fn dispatch_worktree_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorktreeStatusToolInput = serde_json::from_value(arguments)?;
    let requested = input
        .worktree_lease
        .or(input.worktree_lease_id)
        .context("worktree_lease is required")?;
    let work_state = load_work_state(&state.root)?;
    let lease = WorktreeLeaseId::from_str(&requested)
        .ok()
        .and_then(|lease_id| {
            work_state
                .worktree_leases
                .iter()
                .find(|lease| lease.worktree_lease_id == lease_id)
                .cloned()
        });
    Ok(json!({
        "component": "worktree_status",
        "requested_worktree_lease": requested,
        "worktree_lease": lease,
        "operation_status": if lease.is_some() {
            OperationStatus::Active
        } else {
            OperationStatus::Blocked
        }
    }))
}

pub(super) async fn dispatch_worktree_capture_diff(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: WorktreeLeaseToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let worktree_lease_id =
        WorktreeLeaseId::from_str(&input.worktree_lease).context("parse worktree lease id")?;
    let mut diff = CandidateDiffService
        .capture(
            &mut work_state,
            CandidateDiffCaptureInput {
                worktree_lease_id,
                diff_root: state.root.join("candidate-diffs"),
                max_diff_bytes: CandidateDiffService::default_max_diff_bytes(),
            },
        )
        .await?;
    let agent_id = agent_id_for_worktree(&work_state, worktree_lease_id);
    write_worktree_memory(state, None, Some(&mut diff), None, Some(agent_id)).await?;
    diff.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::CandidateDiff,
        &format!("candidate-diff-capture:{}", diff.candidate_diff_id),
        &diff,
    )
    .await?;
    diff.write_receipt = Some(receipt);
    replace_candidate_diff(&mut work_state, diff.clone());
    let mut lease = work_state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .cloned()
        .context("captured worktree lease disappeared")?;
    lease.write_receipt = None;
    write_worktree_memory(state, Some(&mut lease), None, None, None).await?;
    let lease_key = format!("worktree-capture:{}", lease.worktree_lease_id);
    write_canonical_worktree_lease(state, context, &mut lease, &lease_key).await?;
    let work_lease_index = work_state
        .leases
        .iter()
        .position(|item| item.work_lease_id == lease.work_lease_id)
        .context("captured work lease disappeared")?;
    let mut work_lease = work_state.leases[work_lease_index].clone();
    let work_lease_key = format!("worktree-capture-work:{}", work_lease.work_lease_id);
    write_canonical_work_lease(state, context, &mut work_lease, &work_lease_key).await?;
    work_state.leases[work_lease_index] = work_lease;
    replace_worktree_lease(&mut work_state, lease);
    save_worktree_state_and_reports(&state.root, &work_state)?;
    let operation_status = if diff.capture_status == CandidateDiffStatus::Captured {
        OperationStatus::OperationCompleted
    } else {
        OperationStatus::Blocked
    };
    Ok(json!({
        "component": "worktree_capture_diff",
        "candidate_diff": diff,
        "operation_status": operation_status
    }))
}

pub(super) async fn dispatch_worktree_review(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: WorktreeReviewToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let candidate_diff_id =
        CandidateDiffId::from_str(&input.candidate_diff).context("parse candidate diff id")?;
    let reviewer_session_id =
        require_current_candidate_reviewer(state, context, &work_state, candidate_diff_id).await?;
    let decision = parse_candidate_review_decision(&input.decision)?;
    let mut review = CandidateReviewService.review(
        &mut work_state,
        CandidateReviewInput {
            candidate_diff_id,
            reviewer_session_id,
            decision,
            reasons: vec![format!("mcp review decision: {decision:?}")],
        },
    )?;
    let mut diff = work_state
        .candidate_diffs
        .iter()
        .find(|diff| diff.candidate_diff_id == candidate_diff_id)
        .cloned()
        .context("candidate diff not found after review")?;
    write_worktree_memory(state, None, None, Some((&mut review, &diff)), None).await?;
    diff.write_receipt = None;
    let (diff_receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::CandidateDiff,
        &format!("candidate-diff-review:{}", review.review_id),
        &diff,
    )
    .await?;
    diff.write_receipt = Some(diff_receipt);
    review.write_receipt = None;
    let (review_receipt, _) = write_canonical_observation(
        state,
        context,
        diff.project_id,
        Some(diff.task_id),
        CanonicalReceiptKind::CandidateReview,
        &format!("candidate-review:{}", review.review_id),
        &review,
    )
    .await?;
    review.write_receipt = Some(review_receipt);
    replace_candidate_diff(&mut work_state, diff.clone());
    replace_candidate_review(&mut work_state, review.clone());
    save_worktree_state_and_reports(&state.root, &work_state)?;
    let operation_status = if review.decision == CandidateReviewDecision::AcceptForPatchRunner {
        OperationStatus::OperationCompleted
    } else {
        OperationStatus::Blocked
    };
    Ok(json!({
        "component": "worktree_review",
        "candidate_review": review,
        "candidate_diff": diff,
        "operation_status": operation_status
    }))
}

pub(super) async fn dispatch_worktree_cleanup(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorktreeLeaseToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let worktree_lease_id =
        WorktreeLeaseId::from_str(&input.worktree_lease).context("parse worktree lease id")?;
    let lease = work_state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .context("worktree lease not found")?;
    assert_production_worktree_cleanup_path(lease)?;
    let mut lease = WorktreeCleanupService
        .cleanup(&mut work_state, worktree_lease_id)
        .await?;
    write_worktree_memory(state, Some(&mut lease), None, None, None).await?;
    replace_worktree_lease(&mut work_state, lease.clone());
    save_worktree_state_and_reports(&state.root, &work_state)?;
    Ok(json!({
        "component": "worktree_cleanup",
        "worktree_lease": lease,
        "operation_status": OperationStatus::OperationCompleted
    }))
}
