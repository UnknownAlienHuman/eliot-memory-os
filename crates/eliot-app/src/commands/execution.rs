pub fn run_metrics_registry(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_registry_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_record_smoke(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_samples_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_rollup(config_path: &Path, window: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let samples = write_metrics_samples_report(&root)?.samples;
    let report = write_metrics_rollup_report(&root, parse_metric_window(window)?, &samples)?;
    write_json(&report)
}

pub fn run_metrics_slo(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let samples = write_metrics_samples_report(&root)?.samples;
    let rollup = write_metrics_rollup_report(&root, MetricWindow::OneRun, &samples)?.rollup;
    let report = write_metrics_slo_report(&root, &rollup)?;
    write_json(&report)
}

pub fn run_metrics_latency(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let samples = write_metrics_samples_report(&root)?.samples;
    let rollup = write_metrics_rollup_report(&root, MetricWindow::OneRun, &samples)?.rollup;
    let report = write_metrics_latency_report(&root, &rollup)?;
    write_json(&report)
}

pub fn run_metrics_cost(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_cost_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_quality(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = write_metrics_quality_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_dashboard(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_metrics_dashboard_report(&root)?;
    write_json(&report)
}

pub fn run_metrics_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_metrics_summary(&root)?;
    write_json(&report)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsRegistryReport {
    component: String,
    definitions: Vec<MetricDefinition>,
    categories: Vec<String>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsSamplesReport {
    component: String,
    samples: Vec<MetricSample>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsRollupReport {
    component: String,
    rollup: TelemetryRollup,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsSloReport {
    component: String,
    definitions: Vec<SloDefinition>,
    evaluations: Vec<SloEvaluation>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsLatencyReport {
    component: String,
    histograms: Vec<LatencyHistogram>,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsCostReport {
    component: String,
    cost: CostLedger,
    generated_at: time::OffsetDateTime,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MetricsQualityReport {
    component: String,
    signals: Vec<QualitySignal>,
    generated_at: time::OffsetDateTime,
}

fn ensure_metrics_summary(root: &Path) -> Result<serde_json::Value> {
    let dashboard_report = ensure_metrics_dashboard_report(root)?;
    let registry = write_metrics_registry_report(root)?;
    let samples = write_metrics_samples_report(root)?;
    let rollup = write_metrics_rollup_report(root, MetricWindow::OneRun, &samples.samples)?;
    let slo = write_metrics_slo_report(root, &rollup.rollup)?;
    let latency = write_metrics_latency_report(root, &rollup.rollup)?;
    let cost = write_metrics_cost_report(root)?;
    let quality = write_metrics_quality_report(root)?;
    let report = serde_json::json!({
        "component": "metrics_report",
        "registry": registry,
        "samples": samples,
        "rollup": rollup,
        "slo": slo,
        "latency": latency,
        "cost": cost,
        "quality": quality,
        "dashboard": dashboard_report,
        "authority": "local-observability-only; no raw payloads, remote export, or authority mutation",
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_metrics_report(root, "metrics-report", "Metrics Report", &report)?;
    Ok(report)
}

fn ensure_metrics_dashboard_report(root: &Path) -> Result<DashboardReport> {
    let definitions = write_metrics_registry_report(root)?.definitions;
    let samples = write_metrics_samples_report(root)?.samples;
    let rollup = write_metrics_rollup_report(root, MetricWindow::OneRun, &samples)?.rollup;
    let latency = write_metrics_latency_report(root, &rollup)?.histograms;
    let slo = write_metrics_slo_report(root, &rollup)?;
    let cost = write_metrics_cost_report(root)?.cost;
    let quality = write_metrics_quality_report(root)?.signals;
    let dashboard = RuntimeDashboardService.dashboard(
        project_id_from_label("eliot-governor"),
        latency,
        cost,
        slo.evaluations,
        quality,
        recent_incident_refs(root),
        Some("reports/eval-report/latest.json".to_owned()),
        Some("reports/verification/latest.json".to_owned()),
    );
    let trends = RuntimeDashboardService.trends(&dashboard);
    let doctor = MetricsDoctorIntegration.status(&definitions, Some(&dashboard), &trends);
    let report = DashboardReport {
        component: "runtime_dashboard".to_owned(),
        dashboard,
        trends,
        doctor,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "runtime-dashboard", "Runtime Dashboard", &report)?;
    Ok(report)
}

fn write_metrics_registry_report(root: &Path) -> Result<MetricsRegistryReport> {
    let definitions = MetricRegistryService.definitions();
    for definition in &definitions {
        MetricRegistryService.validate_definition(definition)?;
    }
    let report = MetricsRegistryReport {
        component: "metrics_registry".to_owned(),
        categories: MetricRegistryService.categories(),
        definitions,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-registry", "Metrics Registry", &report)?;
    Ok(report)
}

fn write_metrics_samples_report(root: &Path) -> Result<MetricsSamplesReport> {
    let definitions = MetricRegistryService.definitions();
    let samples = MetricRecorderService.smoke_samples(&definitions)?;
    let report = MetricsSamplesReport {
        component: "metrics_samples".to_owned(),
        samples,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-samples", "Metrics Samples", &report)?;
    Ok(report)
}

fn write_metrics_rollup_report(
    root: &Path,
    window: MetricWindow,
    samples: &[MetricSample],
) -> Result<MetricsRollupReport> {
    let report = MetricsRollupReport {
        component: "metrics_rollups".to_owned(),
        rollup: MetricRollupService.rollup(
            project_id_from_label("eliot-governor"),
            window,
            samples,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-rollups", "Metrics Rollups", &report)?;
    Ok(report)
}

fn write_metrics_slo_report(root: &Path, rollup: &TelemetryRollup) -> Result<MetricsSloReport> {
    let definitions = SloService.definitions();
    let report = MetricsSloReport {
        component: "metrics_slo".to_owned(),
        evaluations: SloService.evaluate(&definitions, rollup),
        definitions,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-slo", "Metrics SLO", &report)?;
    Ok(report)
}

fn write_metrics_latency_report(
    root: &Path,
    rollup: &TelemetryRollup,
) -> Result<MetricsLatencyReport> {
    let report = MetricsLatencyReport {
        component: "metrics_latency".to_owned(),
        histograms: MetricRollupService.latency_histograms(rollup),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-latency", "Metrics Latency", &report)?;
    Ok(report)
}

fn write_metrics_cost_report(root: &Path) -> Result<MetricsCostReport> {
    let report = MetricsCostReport {
        component: "metrics_cost".to_owned(),
        cost: CostLedgerService.ledger(
            project_id_from_label("eliot-governor"),
            MetricWindow::OneRun,
        ),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-cost", "Metrics Cost", &report)?;
    Ok(report)
}

fn write_metrics_quality_report(root: &Path) -> Result<MetricsQualityReport> {
    let report = MetricsQualityReport {
        component: "metrics_quality".to_owned(),
        signals: QualitySignalService.signals(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_metrics_report(root, "metrics-quality", "Metrics Quality", &report)?;
    Ok(report)
}

fn write_metrics_report<T>(root: &Path, dir: &str, title: &str, value: &T) -> Result<()>
where
    T: serde::Serialize,
{
    write_report_pair(
        &root.join("reports").join(dir).join("latest.json"),
        &root.join("reports").join(dir).join("latest.md"),
        value,
        &metrics_value_markdown(title, &serde_json::to_value(value)?),
    )
}

fn metrics_value_markdown(title: &str, value: &serde_json::Value) -> String {
    let mut output = format!("# {title}\n\n");
    if let Some(component) = value.get("component").and_then(serde_json::Value::as_str) {
        let _ = writeln!(output, "- component: `{component}`");
    }
    let _ = writeln!(
        output,
        "- authority: `local-observability-only; redacted summaries; no raw payloads or remote export`"
    );
    output
}

fn parse_metric_window(value: &str) -> Result<MetricWindow> {
    match normalized_cli_value(value).as_str() {
        "oneminute" => Ok(MetricWindow::OneMinute),
        "fiveminutes" => Ok(MetricWindow::FiveMinutes),
        "onehour" => Ok(MetricWindow::OneHour),
        "oneday" => Ok(MetricWindow::OneDay),
        "onerun" => Ok(MetricWindow::OneRun),
        other => bail!("unknown metric window: {other}"),
    }
}

fn recent_incident_refs(root: &Path) -> Vec<String> {
    let path = root.join("reports").join("incident").join("latest.json");
    if path.is_file() {
        vec!["reports/incident/latest.json".to_owned()]
    } else {
        Vec::new()
    }
}

pub fn run_hook(config_path: &Path, kind: HookEventKind) -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let payload = if input.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&input).context("parse hook JSON stdin")?
    };
    let task_attached = std::env::var("ELIOT_TASK_ID")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    let result = EliotHookService::for_session(runtime_root(config_path), task_attached)
        .process(kind, &payload)?;
    write_json(&result.decision.stdout)
}

pub async fn run_action_plan(
    config_path: &Path,
    project: &str,
    task: &str,
    goal: &str,
) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let artifacts = action_plan::create_action_lease_artifacts(
        &root,
        CanonicalStore::new(config.db.surreal),
        &config.control_wal,
        action_plan::ActionPlanInput {
            project_label: project.to_owned(),
            task_label: task.to_owned(),
            goal: goal.to_owned(),
            requested_action_kind: ActionKind::ChangePlanOnly,
            change_plan: None,
            verifier_plan: None,
        },
    )
    .await?;
    action_plan::write_action_lease_report(&root, project, task, goal, &artifacts.record)?;
    write_json(&action_plan::action_lease_report_value(
        project,
        task,
        goal,
        &artifacts.record,
    ))
}

pub async fn run_action_validate_plan(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let goal = format!("Validate bounded E1 action plan for {project}/{task}");
    run_action_plan(config_path, project, task, &goal).await
}

pub fn run_action_lease_status(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let latest = action_plan::latest_action_lease_report(&root)?
        .context("no latest ActionLease report found; run action validate-plan first")?;
    write_json(&serde_json::json!({
        "component": "action_lease_status",
        "requested_project": project,
        "requested_task": task,
        "latest": latest
    }))
}

pub async fn run_work_create(
    config_path: &Path,
    project: &str,
    task: &str,
    goal: &str,
    read: &[String],
    write: &[String],
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let project_id = project_id_from_label(project);
    let task_id = task_id_from_label(task);
    let session = AgentSessionService.create_controller(&mut state, project_id);
    if read.is_empty() && write.is_empty() {
        bail!("work create requires an explicit --read or --write scope");
    }
    let write_set = write.to_vec();
    let read_set = if read.is_empty() {
        write_set.clone()
    } else {
        read.to_vec()
    };
    let verifier = if write_set.is_empty() {
        Vec::new()
    } else {
        default_work_verifier(&write_set)
    };
    let item = WorkQueueService.create_work_item(
        &mut state,
        WorkCreateRequest {
            project_id,
            task_id,
            project: project.to_owned(),
            task: task.to_owned(),
            goal: goal.to_owned(),
            scope: default_work_scope(
                std::env::current_dir()?.display().to_string(),
                read_set,
                write_set,
                verifier
                    .iter()
                    .map(|requirement| requirement.command_display.clone())
                    .collect(),
            ),
            required: true,
            created_by: session.agent_session_id,
            required_verifiers: verifier,
        },
    );
    write_work_entities(
        config_path,
        &mut state,
        Some(session.agent_session_id),
        Some(item.work_item_id),
        None,
        &[],
    )
    .await?;
    let report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub async fn run_work_claim(
    config_path: &Path,
    project: &str,
    task: &str,
    role: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let role = parse_agent_role(role)?;
    let item_id = find_work_item(&state, project, task)
        .map(|item| item.work_item_id)
        .context("no matching work item found; run work create first")?;
    let project_id = find_work_item(&state, project, task)
        .map(|item| item.project_id)
        .context("no matching work item found; run work create first")?;
    let session = AgentSessionService.create_for_role(&mut state, project_id, role);
    let decision = WorkLeaseService.claim(
        &mut state,
        WorkClaimRequest {
            work_item_id: item_id,
            agent_session_id: session.agent_session_id,
            role,
            ttl_minutes: default_lease_ttl_minutes(),
        },
    );
    let lease_id = decision.work_lease_id;
    let conflict_ids = latest_conflict_ids_for_item(&state, item_id);
    write_work_entities(
        config_path,
        &mut state,
        Some(session.agent_session_id),
        Some(item_id),
        lease_id,
        &conflict_ids,
    )
    .await?;
    let report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub fn run_work_status(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub async fn run_work_renew(config_path: &Path, lease_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let lease_id = WorkLeaseId::from_str(lease_id).context("parse work lease id")?;
    let decision = WorkLeaseService.renew(&mut state, lease_id, default_lease_ttl_minutes());
    write_work_entities(
        config_path,
        &mut state,
        None,
        None,
        decision.work_lease_id,
        &[],
    )
    .await?;
    let (project, task) = labels_for_lease(&state, lease_id);
    let report = WorkQueueService.status_report(&state, &project, &task);
    save_work_state_and_report(&root, &state, &report)?;
    write_json(&report)
}

pub async fn run_work_release(config_path: &Path, lease_id: &str) -> Result<()> {
    run_work_finish(config_path, lease_id, true).await
}

pub async fn run_work_revoke(config_path: &Path, lease_id: &str) -> Result<()> {
    run_work_finish(config_path, lease_id, false).await
}

pub fn run_work_conflicts(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = WorkQueueService.status_report(&state, project, task);
    write_json(&serde_json::json!({
        "component": "work_conflicts",
        "project": project,
        "task": task,
        "conflicts": report.conflicts,
        "operation_status": if report.conflicts.is_empty() {
            OperationStatus::OperationCompleted
        } else {
            OperationStatus::Blocked
        }
    }))
}

pub async fn run_blackboard_add(
    config_path: &Path,
    project: &str,
    task: &str,
    kind: &str,
    payload_ref: &str,
    evidence: &[String],
    confidence: Option<&str>,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let owner_session_id = ensure_controller_session(&mut state, project_id).agent_session_id;
    let work_item_id = find_work_item(&state, project, task).map(|item| item.work_item_id);
    let lease_id = latest_active_work_lease_id(&state, project_id, task_id);
    let item = BlackboardService.create_item(
        &mut state,
        BlackboardAddInput {
            project_id,
            task_id,
            owner_session_id,
            work_item_id,
            lease_id,
            kind: parse_blackboard_kind(kind)?,
            scope: BlackboardScope::default(),
            payload_ref: payload_ref.to_owned(),
            evidence_refs: evidence.to_vec(),
            confidence: confidence.map(parse_confidence).transpose()?,
            expires_at: None,
        },
    );
    write_collective_entities(
        config_path,
        &mut state,
        &[item.blackboard_item_id],
        &[],
        &[],
        &[],
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&serde_json::json!({
        "component": "blackboard_add",
        "blackboard_item": state
            .blackboard_items
            .iter()
            .find(|candidate| candidate.blackboard_item_id == item.blackboard_item_id),
        "operation_status": OperationStatus::OperationCompleted
    }))
}

pub fn run_blackboard_list(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = blackboard_report_value(&state, project, task);
    write_report_pair(
        &root.join("reports").join("blackboard").join("latest.json"),
        &root.join("reports").join("blackboard").join("latest.md"),
        &report,
        &report_markdown("Blackboard Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_blackboard_ack(
    config_path: &Path,
    item_id: &str,
    session: Option<&str>,
) -> Result<()> {
    run_blackboard_status_change(config_path, item_id, session, "ack").await
}

pub async fn run_blackboard_resolve(config_path: &Path, item_id: &str) -> Result<()> {
    run_blackboard_status_change(config_path, item_id, None, "resolve").await
}

pub async fn run_blackboard_reject(config_path: &Path, item_id: &str) -> Result<()> {
    run_blackboard_status_change(config_path, item_id, None, "reject").await
}

pub async fn run_mailbox_send(
    config_path: &Path,
    project: &str,
    task: &str,
    kind: &str,
    payload_ref: &str,
    recipient: &str,
    message_id: Option<&str>,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let sender_session_id = ensure_controller_session(&mut state, project_id).agent_session_id;
    let message = MailboxService.send(
        &mut state,
        MailboxSendInput {
            message_id: message_id.map(MailboxMessageId::from_str).transpose()?,
            project_id,
            task_id,
            sender_session_id,
            recipient: parse_mailbox_recipient(recipient)?,
            kind: parse_mailbox_kind(kind)?,
            payload_ref: payload_ref.to_owned(),
            requires_ack: None,
            expires_at: None,
        },
    );
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &[message.message_id],
        &[],
        &[],
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&serde_json::json!({
        "component": "mailbox_send",
        "mailbox_message": state
            .mailbox_messages
            .iter()
            .find(|candidate| candidate.message_id == message.message_id),
        "operation_status": OperationStatus::OperationCompleted
    }))
}

pub fn run_mailbox_inbox(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let report = mailbox_report_value(&state, project, task);
    write_report_pair(
        &root.join("reports").join("mailbox").join("latest.json"),
        &root.join("reports").join("mailbox").join("latest.md"),
        &report,
        &report_markdown("Mailbox Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_mailbox_ack(config_path: &Path, message_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let message_id = MailboxMessageId::from_str(message_id).context("parse mailbox message id")?;
    let message = MailboxService.acknowledge(&mut state, message_id)?;
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &[message.message_id],
        &[],
        &[],
    )
    .await?;
    let (project, task) = labels_for_project_task(&state, message.project_id, message.task_id);
    save_collective_reports(&root, &state, &project, &task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, &project, &task),
    )?;
    write_json(&serde_json::json!({
        "component": "mailbox_ack",
        "mailbox_message": state
            .mailbox_messages
            .iter()
            .find(|candidate| candidate.message_id == message.message_id),
        "operation_status": OperationStatus::OperationCompleted
    }))
}

pub async fn run_recovery_scan(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let records =
        LostAgentRecoveryService.scan(&mut state, project_id, task_id, time::Duration::minutes(30));
    let recovery_ids = records
        .iter()
        .map(|record| record.recovery_id.clone())
        .collect::<Vec<_>>();
    let message_ids = records
        .iter()
        .flat_map(|record| record.mailbox_messages.iter().copied())
        .collect::<Vec<_>>();
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &message_ids,
        &recovery_ids,
        &[],
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&recovery_report_value(&state, project, task))
}

pub fn run_recovery_report(config_path: &Path, latest: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let latest_path = root.join("reports").join("recovery").join("latest.json");
    if latest && latest_path.is_file() {
        let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(latest_path)?)?;
        return write_json(&value);
    }
    let state = load_work_state(&root)?;
    let report = recovery_report_value(&state, "", "");
    write_report_pair(
        &root.join("reports").join("recovery").join("latest.json"),
        &root.join("reports").join("recovery").join("latest.md"),
        &report,
        &report_markdown("Recovery Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_collective_trace(config_path: &Path, project: &str, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let (project_id, task_id) = resolve_project_task_ids(&state, project, task);
    let trace = CollectiveTraceService.trace_task(&mut state, project_id, task_id);
    write_collective_entities(
        config_path,
        &mut state,
        &[],
        &[],
        &[],
        std::slice::from_ref(&trace.collective_trace_id),
    )
    .await?;
    save_collective_reports(&root, &state, project, task)?;
    save_work_state_and_report(
        &root,
        &state,
        &WorkQueueService.status_report(&state, project, task),
    )?;
    write_json(&collective_report_value(&state, project, task))
}

pub fn run_collective_report(config_path: &Path, latest: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let latest_path = root.join("reports").join("collective").join("latest.json");
    if latest && latest_path.is_file() {
        let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(latest_path)?)?;
        return write_json(&value);
    }
    let state = load_work_state(&root)?;
    let report = collective_report_value(&state, "", "");
    write_report_pair(
        &root.join("reports").join("collective").join("latest.json"),
        &root.join("reports").join("collective").join("latest.md"),
        &report,
        &report_markdown("Collective Trace Report", &report),
    )?;
    write_json(&report)
}

pub async fn run_worktree_create(config_path: &Path, work_lease_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let work_lease_id = WorkLeaseId::from_str(work_lease_id).context("parse work lease id")?;
    let work_lease = state
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
        requested_scope: work_lease.scope.clone(),
        base_commit: Some(git_head_blocking(&repo_root)?),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let worktree_root = worktree_root_for_repo(&repo_root);
    let mut lease = WorktreeLeaseService
        .create(
            &mut state,
            WorktreeCreateInput {
                request,
                worktree_root,
                ttl_minutes: WorktreeLeaseService::default_ttl_minutes(),
            },
        )
        .await?;
    write_worktree_records(config_path, Some(&mut lease), None, None, None).await?;
    replace_worktree_lease(&mut state, lease.clone());
    save_worktree_state_and_reports(&root, &state)?;
    write_json(&serde_json::json!({
        "component": "worktree_create",
        "worktree_lease": lease,
        "operation_status": OperationStatus::OperationCompleted
    }))
}

pub fn run_worktree_status(config_path: &Path, worktree_lease: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let state = load_work_state(&root)?;
    let lease = WorktreeLeaseId::from_str(worktree_lease)
        .ok()
        .and_then(|lease_id| {
            state
                .worktree_leases
                .iter()
                .find(|lease| lease.worktree_lease_id == lease_id)
                .cloned()
        });
    write_json(&serde_json::json!({
        "component": "worktree_status",
        "requested_worktree_lease": worktree_lease,
        "worktree_lease": lease,
        "operation_status": if lease.is_some() {
            OperationStatus::Active
        } else {
            OperationStatus::Blocked
        }
    }))
}

pub async fn run_worktree_capture_diff(config_path: &Path, worktree_lease: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let worktree_lease_id =
        WorktreeLeaseId::from_str(worktree_lease).context("parse worktree lease id")?;
    let mut diff = CandidateDiffService
        .capture(
            &mut state,
            CandidateDiffCaptureInput {
                worktree_lease_id,
                diff_root: root.join("candidate-diffs"),
                max_diff_bytes: CandidateDiffService::default_max_diff_bytes(),
            },
        )
        .await?;
    let agent_id = state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == worktree_lease_id)
        .and_then(|worktree| {
            state
                .leases
                .iter()
                .find(|lease| lease.work_lease_id == worktree.work_lease_id)
        })
        .map_or_else(AgentId::new_v7, |lease| lease.agent_id);
    write_worktree_records(config_path, None, Some(&mut diff), None, Some(agent_id)).await?;
    replace_candidate_diff(&mut state, diff.clone());
    save_worktree_state_and_reports(&root, &state)?;
    let operation_status = if diff.capture_status == CandidateDiffStatus::Captured {
        OperationStatus::OperationCompleted
    } else {
        OperationStatus::Blocked
    };
    write_json(&serde_json::json!({
        "component": "worktree_capture_diff",
        "candidate_diff": diff,
        "operation_status": operation_status
    }))
}

pub async fn run_worktree_review(
    config_path: &Path,
    candidate_diff: &str,
    decision: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let candidate_diff_id =
        CandidateDiffId::from_str(candidate_diff).context("parse candidate diff id")?;
    let reviewer_session_id = state
        .candidate_diffs
        .iter()
        .find(|diff| diff.candidate_diff_id == candidate_diff_id)
        .and_then(|diff| {
            state
                .worktree_leases
                .iter()
                .find(|lease| lease.worktree_lease_id == diff.worktree_lease_id)
        })
        .map(|lease| lease.holder_session_id)
        .context("candidate diff worktree lease not found")?;
    let review_decision = parse_candidate_review_decision(decision)?;
    let mut review = CandidateReviewService.review(
        &mut state,
        CandidateReviewInput {
            candidate_diff_id,
            reviewer_session_id,
            decision: review_decision,
            reasons: vec![format!("cli review decision: {review_decision:?}")],
        },
    )?;
    let diff = state
        .candidate_diffs
        .iter()
        .find(|diff| diff.candidate_diff_id == candidate_diff_id)
        .cloned()
        .context("candidate diff not found after review")?;
    write_worktree_records(config_path, None, None, Some((&mut review, &diff)), None).await?;
    replace_candidate_review(&mut state, review.clone());
    save_worktree_state_and_reports(&root, &state)?;
    let operation_status = if review.decision == CandidateReviewDecision::AcceptForPatchRunner {
        OperationStatus::OperationCompleted
    } else {
        OperationStatus::Blocked
    };
    write_json(&serde_json::json!({
        "component": "worktree_review",
        "candidate_review": review,
        "candidate_diff": diff,
        "operation_status": operation_status
    }))
}

pub async fn run_worktree_cleanup(config_path: &Path, worktree_lease: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mut state = load_work_state(&root)?;
    let worktree_lease_id =
        WorktreeLeaseId::from_str(worktree_lease).context("parse worktree lease id")?;
    let mut lease = WorktreeCleanupService
        .cleanup(&mut state, worktree_lease_id)
        .await?;
    write_worktree_records(config_path, Some(&mut lease), None, None, None).await?;
    replace_worktree_lease(&mut state, lease.clone());
    save_worktree_state_and_reports(&root, &state)?;
    write_json(&serde_json::json!({
        "component": "worktree_cleanup",
        "worktree_lease": lease,
        "operation_status": OperationStatus::OperationCompleted
    }))
}

pub async fn run_patch_preflight(
    config_path: &Path,
    lease_id: &str,
    diff_path: &Path,
) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let blob_store = BlobStore::open(&config.blob_store)?;
    let input = load_patch_cli_input(&root, lease_id, diff_path)?;
    let repo_root = patch_repo_root(&input.lease)?;
    let runner = PatchRunner::new(&repo_root, Some(&blob_store));
    let incident_lockdown_active = IncidentService::new(&root).lockdown_active()?;
    let mut patch_run = runner
        .preflight(&PatchRunnerInput {
            request: &input.request,
            lease: Some(&input.lease),
            work_lease: Some(&input.work_lease),
            codecortex_reports: std::slice::from_ref(&input.report),
            verifier_plan: Some(&input.verifier_plan),
            incident_lockdown_active,
        })
        .await?;
    let mut verifier_runs = Vec::new();
    write_e2_runs_to_memory(config_path, &mut patch_run, &mut verifier_runs).await?;
    write_patch_reports(&root, &patch_run, &verifier_runs)?;
    write_json(&patch_report_value(&patch_run, &verifier_runs))
}

pub async fn run_patch_apply(config_path: &Path, lease_id: &str, diff_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let blob_store = BlobStore::open(&config.blob_store)?;
    let input = load_patch_cli_input(&root, lease_id, diff_path)?;
    let repo_root = patch_repo_root(&input.lease)?;
    let runner = PatchRunner::new(&repo_root, Some(&blob_store));
    let verifier = VerifierHarness::new(&repo_root, Some(&blob_store));
    let incident_lockdown_active = IncidentService::new(&root).lockdown_active()?;
    let (mut patch_run, mut verifier_runs) = runner
        .apply(
            &PatchRunnerInput {
                request: &input.request,
                lease: Some(&input.lease),
                work_lease: Some(&input.work_lease),
                codecortex_reports: std::slice::from_ref(&input.report),
                verifier_plan: Some(&input.verifier_plan),
                incident_lockdown_active,
            },
            &verifier,
        )
        .await?;
    write_e2_runs_to_memory(config_path, &mut patch_run, &mut verifier_runs).await?;
    write_patch_reports(&root, &patch_run, &verifier_runs)?;
    write_json(&patch_report_value(&patch_run, &verifier_runs))
}

pub fn run_patch_status(config_path: &Path, patch_run_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = latest_patch_report(&root)?.context("no latest PatchRun report found")?;
    let matches_requested = report
        .get("patch_run")
        .and_then(|value| value.get("patch_run_id"))
        .and_then(serde_json::Value::as_str)
        == Some(patch_run_id);
    write_json(&serde_json::json!({
        "component": "patch_status",
        "requested_patch_run": patch_run_id,
        "matches_latest": matches_requested,
        "latest": report
    }))
}

pub async fn run_verifier_run(config_path: &Path, plan_ref: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let blob_store = BlobStore::open(&config.blob_store)?;
    let latest = latest_action_lease(&root)?;
    let plan = latest
        .verifier_plan
        .clone()
        .context("latest ActionLease does not contain a VerifierPlan")?;
    let repo_root = patch_repo_root(&latest)?;
    let harness = VerifierHarness::new(repo_root, Some(&blob_store));
    let mut verifier_runs = harness
        .run_plan(latest.project_id, latest.task_id, latest.agent_id, &plan)
        .await?;
    write_e2_runs_to_memory_optional_patch(config_path, None, &mut verifier_runs).await?;
    write_verifier_report(&root, plan_ref, &verifier_runs)?;
    write_json(&verifier_report_value(plan_ref, &verifier_runs))
}

pub fn run_verifier_status(config_path: &Path, task: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = latest_verifier_report(&root)?.context("no latest VerifierRun report found")?;
    write_json(&serde_json::json!({
        "component": "verifier_status",
        "requested_task": task,
        "latest": report
    }))
}

async fn build_startup_report(config_path: &Path, offline: bool) -> Result<StartupHealthReport> {
    let config = load_config(config_path)?;
    let mut components = Vec::new();

    let wal = ControlWal::open(&config.control_wal)?;
    wal.record_bootstrap(&config.service.instance_id)?;
    components.push(ComponentHealth {
        component: "control_wal".to_owned(),
        status: HealthStatus::Ready,
        message: config.control_wal.path.clone(),
    });

    let blob_store = BlobStore::open(&config.blob_store)?;
    let probe = blob_store.put_bytes(b"eliot-governor startup probe")?;
    components.push(ComponentHealth {
        component: "blob_store".to_owned(),
        status: HealthStatus::Ready,
        message: probe.relative_path,
    });

    if offline {
        components.push(ComponentHealth {
            component: "surrealdb".to_owned(),
            status: HealthStatus::Degraded,
            message: "offline doctor skipped remote db health".to_owned(),
        });
    } else {
        match SurrealStore::new(config.db.surreal.clone())
            .health_check()
            .await
        {
            Ok(record) => components.push(ComponentHealth {
                component: record.component,
                status: HealthStatus::Ready,
                message: record.detail,
            }),
            Err(error) => components.push(ComponentHealth {
                component: "surrealdb".to_owned(),
                status: HealthStatus::NotReady,
                message: error.to_string(),
            }),
        }
    }

    Ok(StartupHealthReport::new(
        SCHEMA_VERSION,
        config.service.service_name,
        config.service.instance_id,
        components,
    ))
}
