fn dispatch_latest_report(state: &McpState, dir: &str) -> Result<Value> {
    read_latest_report_value(&state.root, dir)
}

async fn dispatch_blackboard_add(state: &McpState, arguments: Value) -> Result<Value> {
    let input: BlackboardAddToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let owner_session_id = ensure_controller_session(&mut work_state, project_id).agent_session_id;
    let work_item_id =
        find_work_item(&work_state, &input.project, &input.task).map(|item| item.work_item_id);
    let lease_id = latest_active_work_lease_id(&work_state, project_id, task_id);
    let item = BlackboardService.create_item(
        &mut work_state,
        BlackboardAddInput {
            project_id,
            task_id,
            owner_session_id,
            work_item_id,
            lease_id,
            kind: parse_blackboard_kind(input.kind.as_deref().unwrap_or("finding"))?,
            scope: BlackboardScope::default(),
            payload_ref: input.payload_ref,
            evidence_refs: input.evidence.unwrap_or_default(),
            confidence: input
                .confidence
                .map(|value| parse_confidence(&value))
                .transpose()?,
            expires_at: None,
        },
    );
    write_collective_memory(
        state,
        &mut work_state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(blackboard_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}

fn dispatch_blackboard_list(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let work_state = load_work_state(&state.root)?;
    let report = blackboard_report_value(&work_state, &input.project, &input.task);
    write_json_report(
        &state
            .root
            .join("reports")
            .join("blackboard")
            .join("latest.json"),
        &report,
    )?;
    write_markdown_report(
        &state
            .root
            .join("reports")
            .join("blackboard")
            .join("latest.md"),
        &collective_report_markdown("Blackboard Report", &report),
    )?;
    Ok(report)
}

async fn dispatch_blackboard_ack(state: &McpState, arguments: Value) -> Result<Value> {
    let input: BlackboardAckToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let item_id = input
        .item
        .or(input.item_id)
        .context("item or item_id is required")?;
    let item_id = BlackboardItemId::from_str(&item_id).context("parse blackboard item id")?;
    let session_id = input
        .session
        .map(|value| AgentSessionId::from_str(&value))
        .transpose()?
        .unwrap_or_else(|| {
            work_state
                .blackboard_items
                .iter()
                .find(|item| item.blackboard_item_id == item_id)
                .map_or_else(AgentSessionId::new_v7, |item| item.owner_session_id)
        });
    let item = BlackboardService.acknowledge(&mut work_state, item_id, session_id)?;
    write_collective_memory(
        state,
        &mut work_state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    let (project, task) = labels_for_project_task(&work_state, item.project_id, item.task_id);
    save_collective_reports(&state.root, &work_state, &project, &task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &project, &task),
    )?;
    Ok(blackboard_report_value(&work_state, &project, &task))
}

async fn dispatch_mailbox_send(state: &McpState, arguments: Value) -> Result<Value> {
    let input: MailboxSendToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let sender_session_id = ensure_controller_session(&mut work_state, project_id).agent_session_id;
    let message = MailboxService.send(
        &mut work_state,
        MailboxSendInput {
            message_id: input
                .message_id
                .map(|value| MailboxMessageId::from_str(&value))
                .transpose()?,
            project_id,
            task_id,
            sender_session_id,
            recipient: parse_mailbox_recipient(input.recipient.as_deref().unwrap_or("controller"))?,
            kind: parse_mailbox_kind(input.kind.as_deref().unwrap_or("ack-required"))?,
            payload_ref: input.payload_ref,
            requires_ack: None,
            expires_at: None,
        },
    );
    write_collective_memory(state, &mut work_state, &[], &[message.message_id], &[], &[]).await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(mailbox_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}

fn dispatch_mailbox_inbox(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let work_state = load_work_state(&state.root)?;
    let report = mailbox_report_value(&work_state, &input.project, &input.task);
    write_json_report(
        &state
            .root
            .join("reports")
            .join("mailbox")
            .join("latest.json"),
        &report,
    )?;
    write_markdown_report(
        &state.root.join("reports").join("mailbox").join("latest.md"),
        &collective_report_markdown("Mailbox Report", &report),
    )?;
    Ok(report)
}

async fn dispatch_mailbox_ack(state: &McpState, arguments: Value) -> Result<Value> {
    let input: MailboxAckToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let message_id = input
        .message
        .or(input.message_id)
        .context("message or message_id is required")?;
    let message_id = MailboxMessageId::from_str(&message_id).context("parse mailbox message id")?;
    let message = MailboxService.acknowledge(&mut work_state, message_id)?;
    write_collective_memory(state, &mut work_state, &[], &[message.message_id], &[], &[]).await?;
    let (project, task) = labels_for_project_task(&work_state, message.project_id, message.task_id);
    save_collective_reports(&state.root, &work_state, &project, &task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &project, &task),
    )?;
    Ok(mailbox_report_value(&work_state, &project, &task))
}

async fn dispatch_recovery_scan(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let records = LostAgentRecoveryService.scan(
        &mut work_state,
        project_id,
        task_id,
        time::Duration::minutes(30),
    );
    let recovery_ids = records
        .iter()
        .map(|record| record.recovery_id.clone())
        .collect::<Vec<_>>();
    let message_ids = records
        .iter()
        .flat_map(|record| record.mailbox_messages.iter().copied())
        .collect::<Vec<_>>();
    write_collective_memory(
        state,
        &mut work_state,
        &[],
        &message_ids,
        &recovery_ids,
        &[],
    )
    .await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(recovery_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}

async fn dispatch_collective_trace(state: &McpState, arguments: Value) -> Result<Value> {
    let input: WorkStatusToolInput = serde_json::from_value(arguments)?;
    let mut work_state = load_work_state(&state.root)?;
    let (project_id, task_id) = resolve_project_task_ids(&work_state, &input.project, &input.task);
    let trace = CollectiveTraceService.trace_task(&mut work_state, project_id, task_id);
    write_collective_memory(
        state,
        &mut work_state,
        &[],
        &[],
        &[],
        std::slice::from_ref(&trace.collective_trace_id),
    )
    .await?;
    save_collective_reports(&state.root, &work_state, &input.project, &input.task)?;
    save_work_state_and_report(
        &state.root,
        &work_state,
        &WorkQueueService.status_report(&work_state, &input.project, &input.task),
    )?;
    Ok(collective_report_value(
        &work_state,
        &input.project,
        &input.task,
    ))
}
