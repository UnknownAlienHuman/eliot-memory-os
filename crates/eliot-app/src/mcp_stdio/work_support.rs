async fn write_worktree_memory(
    state: &McpState,
    worktree_lease: Option<&mut WorktreeLease>,
    candidate_diff: Option<&mut CandidateDiff>,
    candidate_review: Option<(&mut CandidateReview, &CandidateDiff)>,
    diff_agent_id: Option<AgentId>,
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    if let Some(lease) = worktree_lease {
        WorktreeMemoryWriter::write_worktree_lease(&handle, &admission, lease).await?;
    }
    if let Some(diff) = candidate_diff {
        WorktreeMemoryWriter::write_candidate_diff(
            &handle,
            &admission,
            diff,
            diff_agent_id.unwrap_or_else(AgentId::new_v7),
        )
        .await?;
    }
    if let Some((review, diff)) = candidate_review {
        WorktreeMemoryWriter::write_candidate_review(&handle, &admission, review, diff).await?;
    }
    Ok(())
}

async fn write_canonical_worktree_lease(
    state: &McpState,
    context: AuthenticatedRequestContext,
    lease: &mut WorktreeLease,
    idempotency_key: &str,
) -> Result<()> {
    lease.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        lease.project_id,
        Some(lease.task_id),
        CanonicalReceiptKind::WorktreeLease,
        idempotency_key,
        lease,
    )
    .await?;
    lease.write_receipt = Some(receipt);
    Ok(())
}

async fn write_canonical_work_lease(
    state: &McpState,
    context: AuthenticatedRequestContext,
    lease: &mut WorkLease,
    idempotency_key: &str,
) -> Result<()> {
    lease.write_receipt = None;
    let (receipt, _) = write_canonical_observation(
        state,
        context,
        lease.project_id,
        Some(lease.task_id),
        CanonicalReceiptKind::WorkLease,
        idempotency_key,
        lease,
    )
    .await?;
    lease.write_receipt = Some(receipt);
    Ok(())
}

async fn write_collective_memory(
    state: &McpState,
    work_state: &mut WorkState,
    blackboard_item_ids: &[BlackboardItemId],
    mailbox_message_ids: &[MailboxMessageId],
    recovery_ids: &[String],
    collective_trace_ids: &[String],
) -> Result<()> {
    let handle = state.writer.clone();
    let admission = WriteAdmissionService;
    for item_id in blackboard_item_ids {
        if let Some(item) = work_state
            .blackboard_items
            .iter_mut()
            .find(|item| item.blackboard_item_id == *item_id)
        {
            CollectiveMemoryWriter::write_blackboard_item(&handle, &admission, item).await?;
        }
    }
    for message_id in mailbox_message_ids {
        if let Some(message) = work_state
            .mailbox_messages
            .iter_mut()
            .find(|message| message.message_id == *message_id)
        {
            CollectiveMemoryWriter::write_mailbox_message(&handle, &admission, message).await?;
        }
    }
    for recovery_id in recovery_ids {
        if let Some(record) = work_state
            .recovery_records
            .iter_mut()
            .find(|record| &record.recovery_id == recovery_id)
        {
            CollectiveMemoryWriter::write_recovery_record(&handle, &admission, record).await?;
        }
    }
    for collective_trace_id in collective_trace_ids {
        if let Some(trace) = work_state
            .collective_traces
            .iter_mut()
            .find(|trace| &trace.collective_trace_id == collective_trace_id)
        {
            CollectiveMemoryWriter::write_collective_trace(&handle, &admission, trace).await?;
        }
    }
    Ok(())
}

fn save_collective_reports(
    root: &Path,
    state: &WorkState,
    project: &str,
    task: &str,
) -> Result<()> {
    let blackboard = blackboard_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("blackboard").join("latest.json"),
        &blackboard,
    )?;
    write_markdown_report(
        &root.join("reports").join("blackboard").join("latest.md"),
        &collective_report_markdown("Blackboard Report", &blackboard),
    )?;
    let mailbox = mailbox_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("mailbox").join("latest.json"),
        &mailbox,
    )?;
    write_markdown_report(
        &root.join("reports").join("mailbox").join("latest.md"),
        &collective_report_markdown("Mailbox Report", &mailbox),
    )?;
    let recovery = recovery_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("recovery").join("latest.json"),
        &recovery,
    )?;
    write_markdown_report(
        &root.join("reports").join("recovery").join("latest.md"),
        &collective_report_markdown("Recovery Report", &recovery),
    )?;
    let collective = collective_report_value(state, project, task);
    write_json_report(
        &root.join("reports").join("collective").join("latest.json"),
        &collective,
    )?;
    write_markdown_report(
        &root.join("reports").join("collective").join("latest.md"),
        &collective_report_markdown("Collective Trace Report", &collective),
    )
}

fn blackboard_report_value(state: &WorkState, project: &str, task: &str) -> Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let items = state
        .blackboard_items
        .iter()
        .filter(|item| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    item.project_id == project_id && item.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "component": "blackboard",
        "project": project,
        "task": task,
        "items": items,
        "blackboard_candidate_not_truth": true,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn mailbox_report_value(state: &WorkState, project: &str, task: &str) -> Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let messages = state
        .mailbox_messages
        .iter()
        .filter(|message| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    message.project_id == project_id && message.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "component": "mailbox",
        "project": project,
        "task": task,
        "messages": messages,
        "mailbox_grants_no_authority": true,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn recovery_report_value(state: &WorkState, project: &str, task: &str) -> Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let records = state
        .recovery_records
        .iter()
        .filter(|record| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    record.project_id == project_id && record.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "component": "recovery",
        "project": project,
        "task": task,
        "records": records,
        "silent_candidate_promotion": false,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn collective_report_value(state: &WorkState, project: &str, task: &str) -> Value {
    let ids = project_task_ids_for_labels(state, project, task);
    let include_all = project.is_empty() && task.is_empty();
    let traces = state
        .collective_traces
        .iter()
        .filter(|trace| {
            include_all
                || ids.is_some_and(|(project_id, task_id)| {
                    trace.project_id == project_id && trace.task_id == task_id
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "component": "collective_trace",
        "project": project,
        "task": task,
        "traces": traces,
        "operation_status": OperationStatus::OperationCompleted
    })
}

fn collective_report_markdown(title: &str, report: &Value) -> String {
    let status = report
        .get("operation_status")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    format!("# {title}\n\n- operation_status: `{status}`\n")
}

fn replace_worktree_lease(state: &mut WorkState, replacement: WorktreeLease) {
    if let Some(existing) = state
        .worktree_leases
        .iter_mut()
        .find(|lease| lease.worktree_lease_id == replacement.worktree_lease_id)
    {
        *existing = replacement;
    } else {
        state.worktree_leases.push(replacement);
    }
}

fn agent_id_for_worktree(state: &WorkState, worktree_lease_id: WorktreeLeaseId) -> AgentId {
    state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .and_then(|worktree| {
            state
                .leases
                .iter()
                .find(|lease| lease.work_lease_id == worktree.work_lease_id)
        })
        .map_or_else(AgentId::new_v7, |lease| lease.agent_id)
}

fn parse_blackboard_kind(value: &str) -> Result<BlackboardItemKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "finding" | "finding_candidate" | "finding-candidate" => {
            Ok(BlackboardItemKind::FindingCandidate)
        }
        "evidence" | "evidence_handle" | "evidence-handle" => {
            Ok(BlackboardItemKind::EvidenceHandle)
        }
        "unknown" => Ok(BlackboardItemKind::Unknown),
        "hypothesis" | "hypothesis_candidate" | "hypothesis-candidate" => {
            Ok(BlackboardItemKind::HypothesisCandidate)
        }
        "conflict" | "conflict_notice" | "conflict-notice" => {
            Ok(BlackboardItemKind::ConflictNotice)
        }
        "decision" | "decision_request" | "decision-request" => {
            Ok(BlackboardItemKind::DecisionRequest)
        }
        "verifier" | "verifier_result" | "verifier-result" => {
            Ok(BlackboardItemKind::VerifierResult)
        }
        "artifact" | "artifact_handle" | "artifact-handle" => {
            Ok(BlackboardItemKind::ArtifactHandle)
        }
        "blocker" => Ok(BlackboardItemKind::Blocker),
        other => anyhow::bail!("unknown blackboard kind: {other}"),
    }
}

fn parse_confidence(value: &str) -> Result<ConfidenceLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(ConfidenceLevel::Low),
        "medium" | "med" => Ok(ConfidenceLevel::Medium),
        "high" => Ok(ConfidenceLevel::High),
        other => anyhow::bail!("unknown confidence level: {other}"),
    }
}

fn parse_mailbox_kind(value: &str) -> Result<MailboxMessageKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "work_assigned" | "work-assigned" | "assigned" => Ok(MailboxMessageKind::WorkAssigned),
        "work_blocked" | "work-blocked" | "blocked" => Ok(MailboxMessageKind::WorkBlocked),
        "lease_expiring" | "lease-expiring" => Ok(MailboxMessageKind::LeaseExpiring),
        "lease_revoked" | "lease-revoked" => Ok(MailboxMessageKind::LeaseRevoked),
        "worktree_captured" | "worktree-captured" => Ok(MailboxMessageKind::WorktreeCaptured),
        "candidate_ready" | "candidate-ready" => Ok(MailboxMessageKind::CandidateReady),
        "review_requested" | "review-requested" => Ok(MailboxMessageKind::ReviewRequested),
        "conflict_raised" | "conflict-raised" => Ok(MailboxMessageKind::ConflictRaised),
        "verifier_failed" | "verifier-failed" => Ok(MailboxMessageKind::VerifierFailed),
        "completion_blocked" | "completion-blocked" => Ok(MailboxMessageKind::CompletionBlocked),
        "agent_expired" | "agent-expired" => Ok(MailboxMessageKind::AgentExpired),
        "ack_required" | "ack-required" => Ok(MailboxMessageKind::AckRequired),
        other => anyhow::bail!("unknown mailbox kind: {other}"),
    }
}

fn parse_mailbox_recipient(value: &str) -> Result<MailboxRecipient> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("controller") {
        return Ok(MailboxRecipient::Controller);
    }
    if let Some(role) = value.strip_prefix("role:") {
        return Ok(MailboxRecipient::Role(parse_agent_role(role)?));
    }
    if let Some(session_id) = value.strip_prefix("session:") {
        return Ok(MailboxRecipient::Session(AgentSessionId::from_str(
            session_id,
        )?));
    }
    if let Some(work_item_id) = value.strip_prefix("work-item:") {
        return Ok(MailboxRecipient::WorkItem(WorkItemId::from_str(
            work_item_id,
        )?));
    }
    anyhow::bail!("unknown mailbox recipient: {value}")
}

/// Build the scope for the MCP work-create surface from caller-owned inputs.
///
/// The canonical project key may itself be an absolute repository path; when a
/// non-path identity is used, the explicit governed repository environment is
/// required.  Either authority is validated against Git before it enters
/// durable scope state. Missing or invalid authority fails closed instead of
/// silently selecting a process CWD or an installed package directory.
fn work_create_scope(
    project: &str,
    read: Option<Vec<String>>,
    write: Option<Vec<String>>,
) -> Result<(ProjectId, eliot_types::WorkScope, Vec<VerifierRequirement>)> {
    let project_id = project_id_from_label(project);
    let write_set = write.unwrap_or_default();
    let read_set = read.unwrap_or_else(|| write_set.clone());
    let required_verifiers = if write_set.is_empty() {
        Vec::new()
    } else {
        default_work_verifier(&write_set)
    };
    let verifier_set = required_verifiers
        .iter()
        .map(|requirement| requirement.command_display.clone())
        .collect();
    let repo_root = governed_work_repo_root(project)?;
    Ok((
        project_id,
        default_work_scope(repo_root.display().to_string(), read_set, write_set, verifier_set),
        required_verifiers,
    ))
}

fn governed_work_repo_root(project: &str) -> Result<PathBuf> {
    let configured_root = std::env::var_os("ELIOT_GOVERNOR_REPO_ROOT").map(PathBuf::from);
    governed_work_repo_root_from(project, configured_root.as_deref())
}

fn governed_work_repo_root_from(project: &str, configured_root: Option<&Path>) -> Result<PathBuf> {
    let project_path = Path::new(project);
    let candidate = if project_path.is_absolute() {
        project_path.to_path_buf()
    } else {
        configured_root
            .context("work create requires an absolute project key or ELIOT_GOVERNOR_REPO_ROOT")?
            .to_path_buf()
    };
    anyhow::ensure!(
        candidate.is_absolute(),
        "governed work repository root must be an absolute path: {}",
        candidate.display()
    );
    let canonical = std::fs::canonicalize(&candidate).with_context(|| {
        format!(
            "governed work repository root does not resolve: {}",
            candidate.display()
        )
    })?;
    anyhow::ensure!(
        canonical.is_dir(),
        "governed work repository root must be a directory: {}",
        canonical.display()
    );
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&canonical)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .with_context(|| format!("validate governed work root with git: {}", canonical.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "governed work repository root is not a Git checkout: {}",
        canonical.display()
    );
    let git_root = String::from_utf8(output.stdout)
        .context("git returned a non-UTF-8 governed work repository root")?;
    let canonical_git_root = std::fs::canonicalize(git_root.trim()).with_context(|| {
        format!(
            "canonicalize Git root returned for governed work root {}",
            canonical.display()
        )
    })?;
    anyhow::ensure!(
        canonical_git_root == canonical,
        "governed work root must name the exact Git root: {}",
        canonical.display()
    );
    Ok(canonical)
}

fn production_worktree_root(
    repo_root: &Path,
    project_id: ProjectId,
    task_id: TaskId,
    work_lease_id: WorkLeaseId,
) -> Result<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is required for production WorktreeLease roots")?;
    let sync_roots = [
        std::env::var_os("OneDrive"),
        std::env::var_os("OneDriveCommercial"),
    ]
    .into_iter()
    .flatten()
    .map(PathBuf::from)
    .collect::<Vec<_>>();
    production_worktree_root_from(
        repo_root,
        &local_app_data,
        &sync_roots,
        project_id,
        task_id,
        work_lease_id,
    )
}

fn production_worktree_root_from(
    repo_root: &Path,
    local_app_data: &Path,
    sync_roots: &[PathBuf],
    project_id: ProjectId,
    task_id: TaskId,
    work_lease_id: WorkLeaseId,
) -> Result<PathBuf> {
    if !local_app_data.is_absolute() {
        anyhow::bail!("LOCALAPPDATA must be absolute for production WorktreeLease roots");
    }
    for sync_root in sync_roots {
        if local_app_data.starts_with(sync_root) {
            anyhow::bail!("LOCALAPPDATA WorktreeLease root must not be inside a sync root");
        }
    }
    let root = local_app_data
        .join("Eliot")
        .join("worktrees")
        .join(authority_path_segment("p", &project_id.to_string()))
        .join(authority_path_segment("t", &task_id.to_string()))
        .join(authority_path_segment("l", &work_lease_id.to_string()));
    if root.starts_with(repo_root) || repo_root.starts_with(&root) {
        anyhow::bail!("production WorktreeLease root must be isolated from the source repository");
    }
    Ok(root)
}

fn authority_path_segment(prefix: &str, authority_id: &str) -> String {
    let digest = blake3::hash(authority_id.as_bytes()).to_hex();
    format!("{prefix}-{}", &digest[..16])
}

struct TerminalChainContext<'a> {
    state: &'a McpState,
    broker: &'a eliot_types::DelegationState,
    work: &'a WorkState,
    project_id: ProjectId,
    task_id: TaskId,
}

struct CanonicalAuthorityScope<'a> {
    state: &'a McpState,
    project_id: ProjectId,
    task_id: TaskId,
}

struct AuthorityProjection<'a, T> {
    entity_kind: &'a str,
    entity_ref: String,
    payload_field: &'a str,
    receipt: Option<&'a WriteReceiptRef>,
    projected: &'a T,
}

struct CurrentChainProjections<'a> {
    result: &'a AgentResultEnvelope,
    disposition: &'a eliot_types::AgentResultDisposition,
    diff: &'a CandidateDiff,
    review: &'a CandidateReview,
    worktree: &'a WorktreeLease,
    work_lease: &'a WorkLease,
}

struct CanonicalTerminalEntities {
    result: AgentResultEnvelope,
    disposition: eliot_types::AgentResultDisposition,
    diff: CandidateDiff,
    review: CandidateReview,
    worktree: WorktreeLease,
    work_lease: WorkLease,
}

fn persist_rehydrated_terminal_chain(
    state: &McpState,
    context: &TerminalChainContext<'_>,
    chain: &AutonomyHostResultChain,
) -> Result<()> {
    let entities = resolve_current_chain_projections(context, chain)?;
    let mut broker = delegation_runtime::load_state(&state.root)?;
    broker
        .agent_results
        .retain(|item| item.result_id != entities.result.result_id);
    broker.agent_results.push(entities.result.clone());
    broker.agent_result_dispositions.retain(|item| {
        item.disposition_id != entities.disposition.disposition_id
            && item.result_id != entities.disposition.result_id
    });
    broker
        .agent_result_dispositions
        .push(entities.disposition.clone());
    delegation_runtime::save_host_broker_state(&state.root, &broker)?;

    let mut work = load_work_state(&state.root)?;
    replace_candidate_diff(&mut work, entities.diff.clone());
    replace_candidate_review(&mut work, entities.review.clone());
    replace_worktree_lease(&mut work, entities.worktree.clone());
    if let Some(stored) = work
        .leases
        .iter_mut()
        .find(|item| item.work_lease_id == entities.work_lease.work_lease_id)
    {
        *stored = entities.work_lease.clone();
    } else {
        work.leases.push(entities.work_lease.clone());
    }
    save_worktree_state_and_reports(&state.root, &work)
}

async fn rehydrate_terminal_chain(
    context: &TerminalChainContext<'_>,
    work_item_id: WorkItemId,
    host_label: &str,
    lease: &AutonomyLeaseBinding,
) -> Result<(eliot_types::DelegationState, WorkState)> {
    let host_id = parse_real_autonomy_host(host_label)?;
    let work_lease_id = work_lease_id_from_autonomy_ref(&lease.lease_ref)?;
    let request = context
        .broker
        .agent_invocations
        .iter()
        .rev()
        .find(|request| {
            request.project_id == context.project_id
                && request.task_id == context.task_id
                && request.work_item_id == work_item_id
                && request.work_lease_id == Some(work_lease_id)
        })
        .context("terminal authority has no governed invocation")?;
    let result_id = context
        .broker
        .operation_jobs
        .iter()
        .find(|job| job.invocation_id == request.invocation_id && job.host_id == host_id)
        .and_then(|job| job.result_ref.as_deref())
        .context("terminal authority job has no canonical result_ref")?;
    let entities = load_canonical_terminal_entities(
        context.state,
        context.project_id,
        context.task_id,
        result_id,
        work_lease_id,
    )
    .await?;
    let mut broker = context.broker.clone();
    broker
        .agent_results
        .retain(|item| item.result_id != entities.result.result_id);
    broker.agent_results.push(entities.result);
    broker.agent_result_dispositions.retain(|item| {
        item.disposition_id != entities.disposition.disposition_id
            && item.result_id != entities.disposition.result_id
    });
    broker.agent_result_dispositions.push(entities.disposition);
    let mut work = context.work.clone();
    work.candidate_diffs
        .retain(|item| item.candidate_diff_id != entities.diff.candidate_diff_id);
    work.candidate_diffs.push(entities.diff);
    work.candidate_reviews
        .retain(|item| item.review_id != entities.review.review_id);
    work.candidate_reviews.push(entities.review);
    work.worktree_leases
        .retain(|item| item.worktree_lease_id != entities.worktree.worktree_lease_id);
    work.worktree_leases.push(entities.worktree);
    work.leases
        .retain(|item| item.work_lease_id != entities.work_lease.work_lease_id);
    work.leases.push(entities.work_lease);
    Ok((broker, work))
}

async fn load_canonical_terminal_entities(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    result_id: &str,
    work_lease_id: WorkLeaseId,
) -> Result<CanonicalTerminalEntities> {
    let scope = Some(task_id);
    let (result, disposition) =
        load_canonical_broker_entities(state, project_id, task_id, result_id).await?;
    let diff_id = result
        .artifact_refs
        .iter()
        .find_map(|reference| reference.strip_prefix("candidate-diff-id:"))
        .context("canonical terminal AgentResult lacks candidate-diff ID binding")?;
    let mut diff_record = state
        .store
        .canonical_records_by_subject_ref::<CandidateDiff>(
            project_id,
            scope,
            &["candidate_diff"],
            diff_id,
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal CandidateDiff is absent")?;
    diff_record.receipt_body.write_receipt = Some(diff_record.canonical_receipt);
    let diff = diff_record.receipt_body;
    let mut review_record = state
        .store
        .canonical_records_by_subject_ref::<CandidateReview>(
            project_id,
            scope,
            &["candidate_review"],
            &diff.candidate_diff_id.to_string(),
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal CandidateReview is absent")?;
    review_record.receipt_body.write_receipt = Some(review_record.canonical_receipt);
    let review = review_record.receipt_body;
    let mut worktree_record = state
        .store
        .canonical_records_by_subject_ref::<WorktreeLease>(
            project_id,
            scope,
            &["worktree_lease"],
            &diff.worktree_lease_id.to_string(),
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal WorktreeLease is absent")?;
    worktree_record.receipt_body.write_receipt = Some(worktree_record.canonical_receipt);
    let worktree = worktree_record.receipt_body;
    let mut work_lease_record = state
        .store
        .canonical_records_by_subject_ref::<WorkLease>(
            project_id,
            scope,
            &["work_lease"],
            &work_lease_id.to_string(),
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal WorkLease is absent")?;
    work_lease_record.receipt_body.write_receipt = Some(work_lease_record.canonical_receipt);
    Ok(CanonicalTerminalEntities {
        result,
        disposition,
        diff,
        review,
        worktree,
        work_lease: work_lease_record.receipt_body,
    })
}

async fn load_canonical_broker_entities(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    result_id: &str,
) -> Result<(AgentResultEnvelope, eliot_types::AgentResultDisposition)> {
    let mut result_record = state
        .store
        .canonical_records_by_subject_ref::<AgentResultEnvelope>(
            project_id,
            Some(task_id),
            &["agent_result"],
            result_id,
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal AgentResult is absent")?;
    result_record.receipt_body.canonical_receipt = Some(result_record.canonical_receipt);
    let result = result_record.receipt_body;
    let mut disposition_record = state
        .store
        .canonical_records_by_subject_ref::<eliot_types::AgentResultDisposition>(
            project_id,
            Some(task_id),
            &["agent_result_disposition"],
            &result.result_id,
            2,
        )
        .await?
        .into_iter()
        .next()
        .context("canonical terminal AgentResultDisposition is absent")?;
    disposition_record.receipt_body.canonical_receipt = Some(disposition_record.canonical_receipt);
    Ok((result, disposition_record.receipt_body))
}

async fn validate_current_chain_projections(
    context: &TerminalChainContext<'_>,
    chain: &AutonomyHostResultChain,
) -> Result<()> {
    let CurrentChainProjections {
        result,
        disposition,
        diff,
        review,
        worktree,
        work_lease,
    } = resolve_current_chain_projections(context, chain)?;
    let scope = CanonicalAuthorityScope {
        state: context.state,
        project_id: context.project_id,
        task_id: context.task_id,
    };
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "agent_result",
            entity_ref: result.result_id.clone(),
            payload_field: "receipt_body",
            receipt: result.canonical_receipt.as_ref(),
            projected: result,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "agent_result_disposition",
            entity_ref: result.result_id.clone(),
            payload_field: "receipt_body",
            receipt: disposition.canonical_receipt.as_ref(),
            projected: disposition,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "candidate_diff",
            entity_ref: diff.candidate_diff_id.to_string(),
            payload_field: "receipt_body",
            receipt: diff.write_receipt.as_ref(),
            projected: diff,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "candidate_review",
            entity_ref: diff.candidate_diff_id.to_string(),
            payload_field: "receipt_body",
            receipt: review.write_receipt.as_ref(),
            projected: review,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "worktree_lease",
            entity_ref: worktree.worktree_lease_id.to_string(),
            payload_field: "receipt_body",
            receipt: worktree.write_receipt.as_ref(),
            projected: worktree,
        },
    )
    .await?;
    exact_current_authority_body(
        &scope,
        AuthorityProjection {
            entity_kind: "work_lease",
            entity_ref: work_lease.work_lease_id.to_string(),
            payload_field: "receipt_body",
            receipt: work_lease.write_receipt.as_ref(),
            projected: work_lease,
        },
    )
    .await
}

fn resolve_current_chain_projections<'a>(
    context: &'a TerminalChainContext<'_>,
    chain: &AutonomyHostResultChain,
) -> Result<CurrentChainProjections<'a>> {
    let result = context
        .broker
        .agent_results
        .iter()
        .find(|item| item.result_id == chain.result_id)
        .context("terminal result projection disappeared")?;
    let disposition = context
        .broker
        .agent_result_dispositions
        .iter()
        .find(|item| item.disposition_id == chain.disposition_id)
        .context("terminal disposition projection disappeared")?;
    let diff = context
        .work
        .candidate_diffs
        .iter()
        .find(|item| item.diff_ref == chain.candidate_diff_ref)
        .context("terminal CandidateDiff projection disappeared")?;
    let review = context
        .work
        .candidate_reviews
        .iter()
        .find(|item| item.review_id == chain.candidate_review_ref)
        .context("terminal CandidateReview projection disappeared")?;
    let worktree = context
        .work
        .worktree_leases
        .iter()
        .find(|item| item.worktree_lease_id == diff.worktree_lease_id)
        .context("terminal WorktreeLease projection disappeared")?;
    let work_lease = context
        .work
        .leases
        .iter()
        .find(|item| item.work_lease_id == chain.work_lease_id)
        .context("terminal WorkLease projection disappeared")?;
    Ok(CurrentChainProjections {
        result,
        disposition,
        diff,
        review,
        worktree,
        work_lease,
    })
}

async fn exact_current_authority_body<T: serde::Serialize>(
    scope: &CanonicalAuthorityScope<'_>,
    projection: AuthorityProjection<'_, T>,
) -> Result<()> {
    let receipt = projection
        .receipt
        .context("terminal projection lacks its canonical receipt")?;
    let observations = scope
        .state
        .store
        .latest_authority_observations_by_entity(
            scope.project_id,
            Some(scope.task_id),
            projection.entity_kind,
            &projection.entity_ref,
        )
        .await?;
    let current = observations.first().with_context(|| {
        format!(
            "terminal canonical authority record is absent for {} {}",
            projection.entity_kind, projection.entity_ref
        )
    })?;
    if current.write_id != receipt.write_id {
        anyhow::bail!("terminal projection is stale relative to current canonical authority");
    }
    if observations.get(1).is_some_and(|previous| {
        previous.memory_revision == current.memory_revision
            && previous.project_sequence == current.project_sequence
    }) {
        anyhow::bail!("terminal canonical authority is ambiguous");
    }
    let mut expected = serde_json::to_value(projection.projected)?;
    if let Some(object) = expected.as_object_mut() {
        if object.contains_key("write_receipt") {
            object.insert("write_receipt".to_owned(), Value::Null);
        }
        if object.contains_key("canonical_receipt") {
            object.insert("canonical_receipt".to_owned(), Value::Null);
        }
    }
    let actual = if projection.payload_field == "receipt_body" {
        state_lossless_canonical_body(scope, &projection, receipt).await?
    } else {
        current
            .payload
            .get(projection.payload_field)
            .cloned()
            .context("terminal canonical authority payload is malformed")?
    };
    if actual != expected {
        anyhow::bail!(
            "terminal local {} projection differs from current canonical authority",
            projection.entity_kind
        );
    }
    let receipt_row = scope
        .state
        .store
        .write_receipt_by_id(&receipt.write_id)
        .await?
        .context("terminal canonical write receipt is absent")?;
    if receipt_row.write_id != receipt.write_id
        || !matches!(
            receipt_row.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
    {
        anyhow::bail!("terminal canonical authority receipt is not committed");
    }
    Ok(())
}

async fn state_lossless_canonical_body<T>(
    scope: &CanonicalAuthorityScope<'_>,
    projection: &AuthorityProjection<'_, T>,
    receipt: &WriteReceiptRef,
) -> Result<Value> {
    let record = scope
        .state
        .store
        .canonical_record_by_write_id::<Value>(
            scope.project_id,
            Some(scope.task_id),
            &[projection.entity_kind],
            receipt.write_id,
        )
        .await?
        .context("terminal lossless canonical authority body is absent")?;
    Ok(record.receipt_body)
}

fn canonical_projection_value<T: serde::Serialize>(value: &T) -> Result<Value> {
    let mut value = serde_json::to_value(value)?;
    if let Some(object) = value.as_object_mut() {
        if object.contains_key("write_receipt") {
            object.insert("write_receipt".to_owned(), Value::Null);
        }
        if object.contains_key("canonical_receipt") {
            object.insert("canonical_receipt".to_owned(), Value::Null);
        }
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
async fn require_exact_current_projection<T>(
    state: &McpState,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    entity_kind: &str,
    entity_ref: &str,
    payload_field: &str,
    expected_receipt_kind: Option<&str>,
    projected: &T,
) -> Result<WriteReceiptRef>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let observations = state
        .store
        .latest_authority_observations_by_entity(project_id, task_id, entity_kind, entity_ref)
        .await?;
    let current = observations
        .first()
        .with_context(|| format!("{entity_kind} has no current canonical authority"))?;
    if observations.get(1).is_some_and(|previous| {
        previous.memory_revision == current.memory_revision
            && previous.project_sequence == current.project_sequence
    }) {
        anyhow::bail!("{entity_kind} current canonical authority is ambiguous");
    }
    if let Some(kind) = expected_receipt_kind {
        let actual = current.payload.get("receipt_kind").and_then(Value::as_str);
        if actual != Some(kind) {
            anyhow::bail!(
                "{entity_kind} current canonical receipt kind differs: expected={kind} actual={}",
                actual.unwrap_or("missing")
            );
        }
    }
    let actual = current
        .payload
        .get(payload_field)
        .cloned()
        .with_context(|| format!("{entity_kind} current canonical body is absent"))?;
    let actual: T = serde_json::from_value(actual)
        .with_context(|| format!("{entity_kind} current canonical body has the wrong type"))?;
    let actual = canonical_projection_value(&actual)?;
    let expected = canonical_projection_value(projected)?;
    if actual != expected {
        anyhow::bail!(
            "local {entity_kind} projection differs from current canonical authority: actual={actual} expected={expected}"
        );
    }
    let receipt = state
        .store
        .write_receipt_by_id(&current.write_id)
        .await?
        .with_context(|| format!("{entity_kind} current canonical WriteReceipt is absent"))?;
    if receipt.project_id != project_id
        || receipt.task_id != task_id
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        || receipt.rejected_reason.is_some()
        || !receipt
            .created_records
            .iter()
            .any(|record| record == &current.observation_id)
    {
        anyhow::bail!("{entity_kind} current canonical WriteReceipt is invalid");
    }
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

struct ManagedFinalizationAuthority {
    managed: crate::host_runtime::ManagedControllerCandidate,
    controller_session_id: AgentSessionId,
    broker: eliot_types::DelegationState,
    work: WorkState,
    provider_result: AgentResultEnvelope,
    actual_verifier_refs: Vec<String>,
    task_revision: MemoryRevision,
    task_write_id: WriteId,
    authority_receipts: BTreeMap<String, WriteReceiptRef>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ManagedFinalizationIntent {
    schema_version: String,
    finalization_id: String,
    invocation_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    task_revision: MemoryRevision,
    task_write_id: WriteId,
    work_item_id: WorkItemId,
    controller_session_id: AgentSessionId,
    provider_result_id: String,
    provider_output_hash: String,
    candidate_diff_hash: String,
    verifier_refs: Vec<String>,
    candidate_diff_id: CandidateDiffId,
    review_id: String,
    result_id: String,
    disposition_id: String,
    work_lease_id: WorkLeaseId,
    worktree_lease_id: WorktreeLeaseId,
    baseline_commit: String,
    changed_files: Vec<String>,
    added_files: Vec<String>,
    modified_files: Vec<String>,
    deleted_files: Vec<String>,
    authority_receipts: BTreeMap<String, WriteReceiptRef>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ManagedFinalizationAggregate {
    schema_version: String,
    finalization_id: String,
    invocation_id: String,
    provider_output_hash: String,
    verifier_refs: Vec<String>,
    candidate_diff: CandidateDiff,
    candidate_review: CandidateReview,
    result: AgentResultEnvelope,
    disposition: eliot_types::AgentResultDisposition,
    worktree_lease: WorktreeLease,
    work_lease: WorkLease,
    operation_job: OperationJob,
    commit_ref: String,
}

struct FinalizedCandidateArtifacts {
    diff: CandidateDiff,
    review: CandidateReview,
    commit_ref: String,
}

struct FinalizedBrokerRecords {
    result: AgentResultEnvelope,
    disposition: eliot_types::AgentResultDisposition,
}

struct ManagedFinalizationProcessLock {
    path: PathBuf,
    record: Vec<u8>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ManagedFinalizationProcessLockRecord {
    schema_version: String,
    invocation_id: String,
    owner_pid: u32,
    created_unix_seconds: i64,
}

struct TaskTransitionProcessLock {
    path: PathBuf,
    record: Vec<u8>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TaskTransitionProcessLockRecord {
    schema_version: String,
    task_id: TaskId,
    owner_pid: u32,
    created_unix_seconds: i64,
}

impl Drop for TaskTransitionProcessLock {
    fn drop(&mut self) {
        if std::fs::read(&self.path).is_ok_and(|bytes| bytes == self.record) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for ManagedFinalizationProcessLock {
    fn drop(&mut self) {
        if std::fs::read(&self.path).is_ok_and(|bytes| bytes == self.record) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn assert_production_worktree_cleanup_path(lease: &WorktreeLease) -> Result<()> {
    let expected_root = production_worktree_root(
        Path::new(&lease.repo_root),
        lease.project_id,
        lease.task_id,
        lease.work_lease_id,
    )?;
    let expected = expected_root.join(lease.worktree_lease_id.to_string());
    let actual = PathBuf::from(&lease.worktree_path);
    let expected_leaf = lease.worktree_lease_id.to_string();
    if actual != expected
        || actual.parent() != Some(expected_root.as_path())
        || actual.file_name().and_then(|name| name.to_str()) != Some(expected_leaf.as_str())
    {
        anyhow::bail!("refuse WorktreeLease cleanup outside its exact LocalAppData authority root");
    }
    Ok(())
}

fn git_head_blocking(repo_root: &Path) -> Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .with_context(|| format!("run git rev-parse in {}", repo_root.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn work_report_markdown(report: &eliot_engine::WorkStatusReport) -> String {
    let mut output = String::from("# Work Status\n\n");
    let _ = writeln!(output, "- project: `{}`", report.project);
    let _ = writeln!(output, "- task: `{}`", report.task);
    let _ = writeln!(output, "- work_items: `{}`", report.work_items.len());
    let _ = writeln!(output, "- active_leases: `{}`", report.active_leases.len());
    let _ = writeln!(output, "- conflicts: `{}`", report.conflicts.len());
    let _ = writeln!(
        output,
        "- operation_status: `{}`",
        report.operation_status
    );
    output
}

fn find_work_item<'a>(state: &'a WorkState, project: &str, task: &str) -> Option<&'a WorkItem> {
    state
        .work_items
        .iter()
        .rev()
        .find(|item| item.project == project && item.task == task)
}

fn resolve_project_task_ids(state: &WorkState, project: &str, task: &str) -> (ProjectId, TaskId) {
    find_work_item(state, project, task).map_or_else(
        || (project_id_from_label(project), task_id_from_label(task)),
        |item| (item.project_id, item.task_id),
    )
}

fn project_task_ids_for_labels(
    state: &WorkState,
    project: &str,
    task: &str,
) -> Option<(ProjectId, TaskId)> {
    if project.is_empty() && task.is_empty() {
        return None;
    }
    find_work_item(state, project, task)
        .map(|item| (item.project_id, item.task_id))
        .or_else(|| {
            Some((
                ProjectId::from_str(project).ok()?,
                TaskId::from_str(task).ok()?,
            ))
        })
}

fn ensure_controller_session(
    state: &mut WorkState,
    project_id: ProjectId,
) -> eliot_types::AgentSession {
    if let Some(session) = state.sessions.iter().rev().find(|session| {
        session.project_id == project_id
            && session.role == AgentRole::Controller
            && session.status == eliot_types::AgentSessionStatus::Active
    }) {
        return session.clone();
    }
    AgentSessionService.create_controller(state, project_id)
}

fn latest_active_work_lease_id(
    state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
) -> Option<WorkLeaseId> {
    let now = time::OffsetDateTime::now_utc();
    state
        .leases
        .iter()
        .rev()
        .find(|lease| {
            lease.project_id == project_id
                && lease.task_id == task_id
                && matches!(
                    lease.state,
                    WorkLeaseState::Granted | WorkLeaseState::Renewed
                )
                && lease.expires_at > now
        })
        .map(|lease| lease.work_lease_id)
}

fn labels_for_project_task(
    state: &WorkState,
    project_id: ProjectId,
    task_id: TaskId,
) -> (String, String) {
    state
        .work_items
        .iter()
        .rev()
        .find(|item| item.project_id == project_id && item.task_id == task_id)
        .map_or_else(
            || (project_id.to_string(), task_id.to_string()),
            |item| (item.project.clone(), item.task.clone()),
        )
}

fn latest_conflict_ids_for_item(state: &WorkState, item_id: WorkItemId) -> Vec<String> {
    state
        .conflicts
        .iter()
        .filter(|conflict| conflict.work_item_id == item_id)
        .map(|conflict| conflict.conflict_id.clone())
        .collect()
}

fn labels_for_lease(state: &WorkState, lease_id: WorkLeaseId) -> (String, String) {
    state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == lease_id)
        .and_then(|lease| {
            state
                .work_items
                .iter()
                .find(|item| item.work_item_id == lease.work_item_id)
        })
        .map_or_else(
            || ("unknown".to_owned(), "unknown".to_owned()),
            |item| (item.project.clone(), item.task.clone()),
        )
}

fn parse_agent_role(value: &str) -> Result<AgentRole> {
    match value.trim().to_ascii_lowercase().as_str() {
        "controller" => Ok(AgentRole::Controller),
        "implementer" | "impl" => Ok(AgentRole::Implementer),
        "reviewer" => Ok(AgentRole::Reviewer),
        "auditor" | "read_only" | "read-only" => Ok(AgentRole::Auditor),
        "verifier" => Ok(AgentRole::Verifier),
        other => anyhow::bail!("unknown agent role: {other}"),
    }
}

fn project_id_from_label(value: &str) -> ProjectId {
    parse_project_id(value)
        .unwrap_or_else(|_| project_id_from_canonical_key("invalid-or-empty-project-label"))
}

fn task_id_from_label(value: &str) -> TaskId {
    TaskId::from_str(value).unwrap_or_else(|_| TaskId::new_v7())
}

fn normalized_cli_value(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
}

fn read_latest_report_value(root: &Path, dir: &str) -> Result<Value> {
    let path = latest_report_path(root, dir);
    if !path.is_file() {
        anyhow::bail!("latest J0 report not found: {}", path.display());
    }
    serde_json::from_reader(std::fs::File::open(path)?).context("parse latest J0 report JSON")
}

fn latest_report_path(root: &Path, dir: &str) -> PathBuf {
    root.join("reports").join(dir).join("latest.json")
}

fn parse_skill_id_or_new(value: &str) -> SkillId {
    SkillId::from_str(value).unwrap_or_else(|_| SkillId::new_v7())
}

fn mcp_skill_curator_run(project: &str, dry_run: bool) -> SkillCuratorRun {
    SkillCuratorService::run(SkillCuratorRunInput {
        project_id: project_id_from_label(project),
        project: project.to_owned(),
        dry_run,
        skills: mcp_skill_curator_cards(),
    })
}

fn mcp_skill_curator_cards() -> Vec<SkillCardV2> {
    let mut repeated = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator repeated success".clone_into(&mut repeated.name);
    repeated.success_count = 3;
    repeated.failure_count = 0;

    let mut missing_anti_scope = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator missing anti-scope".clone_into(&mut missing_anti_scope.name);
    missing_anti_scope.does_not_apply_when.clear();

    let mut low_utility = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator low utility high cost".clone_into(&mut low_utility.name);
    low_utility.success_count = 0;
    low_utility.failure_count = 5;
    low_utility
        .ordered_steps
        .extend((0..20).map(|index| SkillStep {
            step_id: format!("mcp-curator-expensive-{index}"),
            order: index + 10,
            instruction: "large context cost step with repeated low utility".repeat(4),
            expected_observation: None,
            required_tool_or_capability: None,
            stop_if_fails: false,
        }));

    let mut negative_transfer = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator negative transfer".clone_into(&mut negative_transfer.name);
    negative_transfer.success_count = 0;
    negative_transfer.failure_count = 2;
    negative_transfer
        .known_failure_modes
        .push(SkillFailureMode {
            failure_id: "mcp-negative-transfer".to_owned(),
            description: "negative transfer into unrelated task".to_owned(),
            detection_signal: "negative-transfer".to_owned(),
            mitigation: "quarantine and retain audit trail".to_owned(),
            negative_memory_refs: vec!["failure:mcp-negative-transfer".to_owned()],
        });

    let mut overbroad = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator overbroad".clone_into(&mut overbroad.name);
    overbroad.applies_when.push(SkillScopeRule {
        rule_id: "mcp-any-project".to_owned(),
        description: "any project task".to_owned(),
        positive_examples: vec!["any project".to_owned()],
        negative_examples: Vec::new(),
        required_evidence_refs: Vec::new(),
    });
    overbroad.applies_when.push(SkillScopeRule {
        rule_id: "mcp-all-tasks".to_owned(),
        description: "all tasks with tools".to_owned(),
        positive_examples: vec!["all tasks".to_owned()],
        negative_examples: Vec::new(),
        required_evidence_refs: Vec::new(),
    });

    let mut duplicate_a = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    "MCP curator duplicate".clone_into(&mut duplicate_a.name);
    "duplicate MCP curator routing".clone_into(&mut duplicate_a.purpose);
    let mut duplicate_b = duplicate_a.clone();
    duplicate_b.skill_id = SkillId::new_v7();

    vec![
        repeated,
        missing_anti_scope,
        low_utility,
        negative_transfer,
        overbroad,
        duplicate_a,
        duplicate_b,
    ]
}

fn mcp_active_skill(skill_id: SkillId, lifecycle_state: SkillLifecycleState) -> SkillCardV2 {
    let now = time::OffsetDateTime::now_utc();
    SkillCardV2 {
        skill_id,
        name: "MCP Skill Lifecycle Foundation".to_owned(),
        purpose: "govern skill activation and execution proof".to_owned(),
        level: eliot_types::SkillLevel::Procedure,
        lifecycle_state,
        applies_when: vec![SkillScopeRule {
            rule_id: "mcp-skill-scope".to_owned(),
            description: "skill lifecycle".to_owned(),
            positive_examples: vec!["skill lifecycle".to_owned()],
            negative_examples: vec!["release notes".to_owned()],
            required_evidence_refs: vec!["evidence:skill".to_owned()],
        }],
        does_not_apply_when: vec![SkillScopeRule {
            rule_id: "mcp-skill-anti-scope".to_owned(),
            description: "raw sql or external agent".to_owned(),
            positive_examples: vec!["raw sql".to_owned(), "external agent".to_owned()],
            negative_examples: vec!["governed skill proof".to_owned()],
            required_evidence_refs: Vec::new(),
        }],
        required_inputs: vec![SkillInputRequirement {
            name: "task_goal".to_owned(),
            description: "current task goal".to_owned(),
            required: true,
            source: SkillInputSource::UserPrompt,
        }],
        ordered_steps: vec![SkillStep {
            step_id: "inspect-scope".to_owned(),
            order: 1,
            instruction: "Inspect scope and verifier availability.".to_owned(),
            expected_observation: Some("activation decision is explicit".to_owned()),
            required_tool_or_capability: None,
            stop_if_fails: true,
        }],
        required_tools_and_capabilities: vec![SkillToolRequirement {
            capability: "rust-verifier".to_owned(),
            required: true,
            allowed_tools: vec!["cargo".to_owned(), "just".to_owned()],
            forbidden_tools: vec!["surreal sql".to_owned()],
        }],
        expected_outputs: vec![SkillOutputSpec {
            name: "SkillExecutionProof".to_owned(),
            description: "proof with verifier refs".to_owned(),
            evidence_required: true,
            verifier_required: true,
        }],
        verification_plan: VerifierPlan {
            required: vec![VerifierRequirement {
                name: "just_verify".to_owned(),
                command_kind: VerifierCommandKind::DomainVerifier,
                command_display: "just verify".to_owned(),
                scope: vec!["eliot-governor".to_owned()],
                required_for_done: true,
                expected_signal: "exit code 0".to_owned(),
            }],
            optional: Vec::new(),
            acceptance_items: vec!["skill proof has verifier refs".to_owned()],
        },
        stop_conditions: vec!["anti-scope matches".to_owned()],
        known_failure_modes: Vec::new(),
        rollback_or_recovery: Some("archive or quarantine with evidence".to_owned()),
        source_trace_refs: vec!["evidence:skill".to_owned()],
        replay_result_refs: Vec::new(),
        success_count: 1,
        failure_count: 0,
        last_verified_at: Some(now),
        version: "1.0.0".to_owned(),
        owner: "eliot-governor".to_owned(),
        created_at: now,
        updated_at: now,
    }
}

fn mcp_skill_context(task: &str) -> SkillActivationContext {
    SkillActivationContext {
        goal: format!("skill lifecycle {task}"),
        evidence_refs: vec!["evidence:skill".to_owned()],
        available_input_sources: vec![SkillInputSource::UserPrompt],
        available_input_names: vec!["task_goal".to_owned()],
        available_capabilities: vec!["rust-verifier".to_owned()],
        available_tools: vec!["cargo".to_owned(), "just".to_owned()],
        verifier_refs: vec!["just verify".to_owned()],
        active_negative_signals: Vec::new(),
        conflicting_skill_refs: Vec::new(),
        audit_mode: false,
    }
}

fn runtime_root(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

#[cfg(test)]
mod work_scope_tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    #[test]
    fn canonical_project_work_create_preserves_read_only_scope_and_root() -> Result<()> {
        let project_root = std::fs::canonicalize(workspace_root())?;
        let canonical_project = project_root.display().to_string();
        let (project_id, scope, required_verifiers) = work_create_scope(
            &canonical_project,
            Some(vec!["crates/eliot-app/src/mcp_stdio/work.rs".to_owned()]),
            Some(Vec::new()),
        )?;

        assert_eq!(project_id, project_id_from_label(&canonical_project));
        assert_eq!(scope.repo_root, project_root.display().to_string());
        assert_eq!(
            scope.read_set,
            vec!["crates/eliot-app/src/mcp_stdio/work.rs".to_owned()]
        );
        assert!(scope.write_set.is_empty());
        assert!(scope.verifier_set.is_empty());
        assert!(required_verifiers.is_empty());
        assert!(!scope
            .write_set
            .contains(&"crates/eliot-engine/src/work.rs".to_owned()));
        Ok(())
    }

    #[test]
    fn absolute_project_key_is_the_scope_root_and_identity_source() -> Result<()> {
        let project_root = std::fs::canonicalize(workspace_root())?;
        let absolute_project_key = project_root.display().to_string();
        let (_project_id, scope, _verifier) = work_create_scope(
            &absolute_project_key,
            Some(vec!["docs".to_owned()]),
            Some(vec!["crates/eliot-app/src/mcp_stdio/work.rs".to_owned()]),
        )?;
        assert_eq!(scope.repo_root, project_root.display().to_string());
        assert_eq!(scope.read_set, vec!["docs".to_owned()]);
        assert_eq!(
            scope.write_set,
            vec!["crates/eliot-app/src/mcp_stdio/work.rs".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn non_path_identity_uses_only_an_explicit_governed_root() -> Result<()> {
        let project_root = std::fs::canonicalize(workspace_root())?;
        let resolved = governed_work_repo_root_from(
            "4b751723-9cf1-84a1-8611-7e1f2a090dd7",
            Some(&project_root),
        )?;
        assert_eq!(resolved, project_root);
        Ok(())
    }

    #[test]
    fn governed_root_validation_is_stack_neutral() -> Result<()> {
        let temp_root = std::env::temp_dir().join(format!(
            "eliot-work-scope-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&temp_root)?;
        let init = std::process::Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(&temp_root)
            .output()?;
        anyhow::ensure!(
            init.status.success(),
            "git init failed for stack-neutral scope test: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let expected_root = std::fs::canonicalize(&temp_root)?;
        let root_result = governed_work_repo_root_from(&temp_root.display().to_string(), None);
        let cleanup_result = std::fs::remove_dir_all(&temp_root);
        let root = root_result?;
        cleanup_result?;
        assert_eq!(root, expected_root);
        Ok(())
    }

    #[test]
    fn missing_or_relative_project_key_fails_closed() {
        let missing = match governed_work_repo_root_from("eliot-memory-os", None) {
            Ok(root) => panic!(
                "non-path project key unexpectedly resolved to governed root {}",
                root.display()
            ),
            Err(error) => error,
        };
        assert!(missing.to_string().contains("absolute project key"));

        let relative = match governed_work_repo_root_from("projects/eliot-memory-os", None) {
            Ok(root) => panic!(
                "relative project key unexpectedly resolved to governed root {}",
                root.display()
            ),
            Err(error) => error,
        };
        assert!(relative.to_string().contains("absolute project key"));
    }
}
