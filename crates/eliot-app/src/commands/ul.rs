#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UlMiningInput {
    project_id: ProjectId,
    project_root: PathBuf,
}

#[derive(Debug, clap::Subcommand)]
pub enum UlCommand {
    MineGit {
        #[arg(long)]
        project: ProjectId,
        #[arg(long)]
        root: PathBuf,
    },
    Onboard {
        #[arg(long)]
        project: ProjectId,
        #[arg(long)]
        root: PathBuf,
    },
    Report {
        #[arg(long)]
        project: ProjectId,
    },
    Maintain {
        #[arg(long)]
        project: ProjectId,
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value_t = 5)]
        limit: u16,
        #[arg(long)]
        refine: bool,
    },
    DirtyReport {
        #[arg(long)]
        project: ProjectId,
    },
    InjectionPolicy {
        #[command(subcommand)]
        command: UlInjectionPolicyCommand,
    },
    Exam {
        #[command(subcommand)]
        command: UlExamCommand,
    },
    Prediction {
        #[command(subcommand)]
        command: UlPredictionCommand,
    },
    CrossAgent {
        #[command(subcommand)]
        command: UlCrossAgentCommand,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum UlCrossAgentCommand {
    Doctor,
    Run {
        #[arg(long)]
        confirm: String,
    },
    Report {
        #[arg(long)]
        run: String,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum UlExamCommand {
    Run {
        #[arg(long)]
        project: ProjectId,
        #[arg(long)]
        route: UlReasoningRouteArg,
    },
    Report {
        #[arg(long)]
        project: ProjectId,
        #[arg(long)]
        latest: bool,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum UlPredictionCommand {
    Sweep {
        #[arg(long)]
        project: ProjectId,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum UlReasoningRouteArg {
    Claude,
    Antigravity,
}

impl From<UlReasoningRouteArg> for eliot_types::UlReasoningRoute {
    fn from(value: UlReasoningRouteArg) -> Self {
        match value {
            UlReasoningRouteArg::Claude => Self::Claude,
            UlReasoningRouteArg::Antigravity => Self::Antigravity,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum UlInjectionPolicyCommand {
    Set {
        #[arg(long)]
        project: ProjectId,
        #[arg(long = "task-class")]
        task_class: String,
        #[arg(long)]
        mode: UlInjectionPolicyMode,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum UlInjectionPolicyMode {
    Payload,
    HandlesOnly,
}

impl From<UlInjectionPolicyMode> for UlInjectionMode {
    fn from(value: UlInjectionPolicyMode) -> Self {
        match value {
            UlInjectionPolicyMode::Payload => Self::Payload,
            UlInjectionPolicyMode::HandlesOnly => Self::HandlesOnly,
        }
    }
}

pub async fn run_ul_mine_git(
    config_path: &Path,
    project_id: ProjectId,
    root: &Path,
) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/mine-git",
        serde_json::json!({
            "project_id": project_id,
            "project_root": root,
        }),
    )
    .await
    .context("route UL mining through the daemon-owned WriterActor")?;
    write_json(&result)
}

pub(crate) async fn run_ul_mine_git_from_daemon(
    store: &CanonicalStore,
    writer: &eliot_engine::WriterHandle,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let input: UlMiningInput =
        serde_json::from_value(params).context("decode UL mining request")?;
    let project_id = input.project_id;
    let root = input.project_root;
    let _ = store.migrate_schema().await?;
    let cue_sources = store.load_cue_records(project_id).await?;
    let failure_refs_by_path = eliot_engine::failure_bindings_by_path(&cue_sources);
    let failure_density = failure_refs_by_path
        .iter()
        .map(|(path, refs)| {
            (
                path.clone(),
                u32::try_from(refs.len()).unwrap_or(u32::MAX),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mining_service = eliot_engine::GitMiningService::default();
    let artifacts = mining_service.mine(project_id, &root, &failure_density)?;
    let existing = store
        .ul_artifact_by_id::<eliot_types::MiningRun>(
            project_id,
            "mining_run",
            &artifacts.run.run_id,
        )
        .await?;
    let mining_unchanged = mining_service.is_noop(
        &artifacts,
        existing.as_ref().map(|record| &record.receipt_body),
    );

    let cards = eliot_engine::ModuleCardService::build(
        project_id,
        &root,
        &artifacts.hotspots,
        &artifacts.edges,
        &failure_refs_by_path,
        &std::collections::BTreeMap::new(),
    )?;
    let artifact_writer = eliot_engine::UlArtifactWriterService;
    let mining_report = if mining_unchanged {
        eliot_engine::UlArtifactWriteReport {
            artifacts_written: 0,
            relations_written: 0,
            receipts: Vec::new(),
        }
    } else {
        artifact_writer
            .write_mining(writer, &WriteAdmissionService, &artifacts)
            .await?
    };
    let card_report = if cards.is_empty() {
        eliot_engine::UlArtifactWriteReport {
            artifacts_written: 0,
            relations_written: 0,
            receipts: Vec::new(),
        }
    } else {
        artifact_writer
            .write_module_cards(
                writer,
                &WriteAdmissionService,
                &artifacts.run.run_id,
                &cards,
            )
            .await?
    };

    refresh_card_cues(store, project_id, &cards).await?;
    refresh_card_dependencies(store, project_id, &cards).await?;
    let card_committed = card_report
        .receipts
        .iter()
        .any(|receipt| receipt.status == eliot_types::WriteStatus::Committed);
    let (status, mining_status, card_status) =
        mining_delivery_status(mining_unchanged, card_committed);

    Ok(serde_json::json!({
        "status": status,
        "mining_status": mining_status,
        "card_status": card_status,
        "project_id": project_id,
        "run_id": artifacts.run.run_id,
        "head_commit": artifacts.run.head_commit,
        "commits_scanned": artifacts.run.commits_scanned,
        "baskets_used": artifacts.run.baskets_used,
        "edges_written": if mining_unchanged { 0 } else { artifacts.edges.len() },
        "hotspots_written": if mining_unchanged { 0 } else { artifacts.hotspots.len() },
        "cards_written": card_report.artifacts_written,
        "artifacts_written": mining_report
            .artifacts_written
            .saturating_add(card_report.artifacts_written),
        "relations_written": mining_report
            .relations_written
            .saturating_add(card_report.relations_written),
        "write_receipts": mining_report
            .receipts
            .len()
            .saturating_add(card_report.receipts.len()),
    }))
}

async fn refresh_card_dependencies(
    store: &CanonicalStore,
    project_id: ProjectId,
    cards: &[eliot_types::ModuleCard],
) -> Result<()> {
    let dependency = eliot_engine::UlDependencyService::new(store.clone());
    for card in cards {
        dependency.index_card(card).await?;
        store
            .clear_ul_artifact_dirty(
                project_id,
                eliot_types::PyramidTargetKind::ModuleCard,
                &card.path,
                &card.build_fingerprint,
            )
            .await?;
    }
    Ok(())
}

fn mining_delivery_status(
    mining_unchanged: bool,
    card_committed: bool,
) -> (&'static str, &'static str, &'static str) {
    match (mining_unchanged, card_committed) {
        (true, true) => ("repaired", "noop", "repaired"),
        (true, false) => ("noop", "noop", "idempotent"),
        (false, true) => ("written", "written", "written"),
        (false, false) => ("written", "written", "idempotent"),
    }
}

pub async fn run_ul_onboard(
    config_path: &Path,
    project_id: ProjectId,
    project_root: &Path,
) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/onboard",
        serde_json::json!({
            "project_id": project_id,
            "project_root": project_root,
        }),
    )
    .await
    .context("route UL onboarding through the daemon-owned WriterActor")?;
    register_ul_scheduled_project(config_path, project_id)?;
    write_json(&result)
}

pub async fn run_ul_report(config_path: &Path, project_id: ProjectId) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/report",
        serde_json::json!({ "project_id": project_id }),
    )
    .await
    .context("read the passive UL report from the ready Governor daemon")?;
    write_json(&result)
}

pub async fn run_ul_maintain(
    config_path: &Path,
    project_id: ProjectId,
    project_root: &Path,
    limit: u16,
    refine: bool,
) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/maintain",
        serde_json::json!({
            "project_id": project_id,
            "project_root": project_root,
            "limit": limit,
            "refine": refine,
        }),
    )
    .await
    .context("route bounded UL maintenance through the daemon-owned WriterActor")?;
    register_ul_scheduled_project(config_path, project_id)?;
    write_json(&result)
}

pub async fn run_ul_exam_run(
    config_path: &Path,
    project_id: ProjectId,
    route: UlReasoningRouteArg,
) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/exam-run",
        serde_json::json!({
            "project_id": project_id,
            "route": eliot_types::UlReasoningRoute::from(route),
        }),
    )
    .await
    .context("route the UL understanding exam through the supervised host boundary")?;
    register_ul_scheduled_project(config_path, project_id)?;
    write_json(&result)
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct UlWeeklyScheduleRegistry {
    projects: std::collections::BTreeSet<ProjectId>,
    completed_windows: std::collections::BTreeMap<ProjectId, String>,
}

fn ul_weekly_schedule_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("state")
        .join("ul-weekly-exams.json")
}

fn load_ul_weekly_schedule(config_path: &Path) -> Result<UlWeeklyScheduleRegistry> {
    let path = ul_weekly_schedule_path(config_path);
    if !path.is_file() {
        return Ok(UlWeeklyScheduleRegistry::default());
    }
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("decode UL weekly exam registry {}", path.display()))
}

fn write_ul_weekly_schedule(
    config_path: &Path,
    registry: &UlWeeklyScheduleRegistry,
) -> Result<()> {
    let path = ul_weekly_schedule_path(config_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write_bytes(&path, &serde_json::to_vec_pretty(registry)?)
}

fn register_ul_scheduled_project(config_path: &Path, project_id: ProjectId) -> Result<()> {
    let mut registry = load_ul_weekly_schedule(config_path)?;
    if registry.projects.insert(project_id) {
        write_ul_weekly_schedule(config_path, &registry)?;
    }
    Ok(())
}

pub(crate) fn pending_ul_scheduled_projects(
    config_path: &Path,
    window: &str,
) -> Result<Vec<ProjectId>> {
    let registry = load_ul_weekly_schedule(config_path)?;
    Ok(registry
        .projects
        .into_iter()
        .filter(|project_id| {
            registry
                .completed_windows
                .get(project_id)
                .is_none_or(|completed| completed != window)
        })
        .collect())
}

pub(crate) fn mark_ul_scheduled_project_complete(
    config_path: &Path,
    project_id: ProjectId,
    window: &str,
) -> Result<()> {
    let mut registry = load_ul_weekly_schedule(config_path)?;
    registry.projects.insert(project_id);
    registry.completed_windows.insert(project_id, window.to_owned());
    write_ul_weekly_schedule(config_path, &registry)
}

pub async fn run_ul_exam_report(
    config_path: &Path,
    project_id: ProjectId,
    latest: bool,
) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/exam-report",
        serde_json::json!({ "project_id": project_id, "latest": latest }),
    )
    .await
    .context("read the canonical UL exam projection")?;
    write_json(&result)
}

pub async fn run_ul_prediction_sweep(
    config_path: &Path,
    project_id: ProjectId,
) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/prediction-sweep",
        serde_json::json!({ "project_id": project_id }),
    )
    .await
    .context("sweep expired unresolved UL predictions")?;
    write_json(&result)
}

pub async fn run_ul_dirty_report(config_path: &Path, project_id: ProjectId) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/dirty-report",
        serde_json::json!({ "project_id": project_id }),
    )
    .await
    .context("read the derived UL dirty report from the ready Governor daemon")?;
    write_json(&result)
}

pub async fn run_ul_injection_policy_set(
    config_path: &Path,
    project_id: ProjectId,
    task_class_key: &str,
    mode: UlInjectionPolicyMode,
) -> Result<()> {
    let instance = ul_daemon_instance(config_path)?;
    let result = named_pipe_ipc::host_governor_request(
        &instance,
        "ul/injection-policy-set",
        serde_json::json!({
            "project_id": project_id,
            "task_class_key": task_class_key,
            "mode": UlInjectionMode::from(mode),
        }),
    )
    .await
    .context("route the operator UL injection policy action through the daemon-owned store")?;
    write_json(&result)
}

pub(crate) async fn run_ul_injection_policy_set_from_daemon(
    runtime_root: &Path,
    store: &CanonicalStore,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
        task_class_key: String,
        mode: UlInjectionMode,
    }

    let input: Input =
        serde_json::from_value(params).context("decode UL injection policy operator action")?;
    if input.task_class_key.trim().is_empty() {
        bail!("--task-class must be non-empty");
    }
    store.migrate_schema().await?;
    let previous = store
        .load_ul_task_class_policy(input.project_id, &input.task_class_key)
        .await?;
    let policy = UlTaskClassPolicy {
        project_id: input.project_id,
        task_class_key: input.task_class_key.clone(),
        injection_mode: input.mode,
        treatment_tasks: previous.as_ref().map_or(0, |row| row.treatment_tasks),
        control_tasks: previous.as_ref().map_or(0, |row| row.control_tasks),
        control_median_exploration_tokens: previous
            .as_ref()
            .map_or(0, |row| row.control_median_exploration_tokens),
        treatment_median_net_delta: previous
            .as_ref()
            .map_or(0, |row| row.treatment_median_net_delta),
        reason: match input.mode {
            UlInjectionMode::Payload => "operator_payload_reenable",
            UlInjectionMode::HandlesOnly => "operator_handles_only",
        }
        .to_owned(),
        evidence_task_ids: previous
            .as_ref()
            .map_or_else(Vec::new, |row| row.evidence_task_ids.clone()),
    };
    let persisted = store.upsert_ul_task_class_policy(&policy).await?;
    let receipt_id = format!("UL-INJECTION-POLICY-ADMIN-{}", WriteId::new_v7());
    let receipt = serde_json::json!({
        "schema_version": "eliot-ul-injection-policy-admin-receipt-v1",
        "receipt_id": receipt_id,
        "authority": "local_operator_cli",
        "project_id": persisted.project_id,
        "task_class_key": persisted.task_class_key,
        "previous_mode": previous.as_ref().map(|row| row.injection_mode),
        "mode": persisted.injection_mode,
        "reason": persisted.reason,
        "recorded_at": time::OffsetDateTime::now_utc(),
    });
    let receipt_path = runtime_root
        .join("reports")
        .join("ul-token-policy")
        .join("admin-receipts")
        .join(format!("{receipt_id}.json"));
    if let Some(parent) = receipt_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write_bytes(&receipt_path, &serde_json::to_vec_pretty(&receipt)?)?;
    Ok(serde_json::json!({
        "policy": persisted,
        "administrative_receipt": receipt,
        "receipt_path": receipt_path,
    }))
}

pub(crate) async fn run_ul_maintain_from_daemon(
    config_path: &Path,
    store: &CanonicalStore,
    writer: &eliot_engine::WriterHandle,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
        project_root: PathBuf,
        limit: u16,
        #[serde(default)]
        refine: bool,
    }

    let input: Input = serde_json::from_value(params).context("decode UL maintenance request")?;
    store.migrate_schema().await?;
    let report = eliot_engine::UlMaintenanceService::new(store.clone(), writer.clone())
        .rebuild_dirty(input.project_id, &input.project_root, input.limit)
        .await?;
    let runner = SupervisedReasoningRunner {
        config_path,
        cwd: &input.project_root,
    };
    let refinements = if input.refine {
        refine_current_capsules(store, writer, input.project_id, input.limit, &runner).await?
    } else {
        Vec::new()
    };
    Ok(serde_json::json!({
        "maintenance": report,
        "refinements": refinements,
    }))
}

struct SupervisedReasoningRunner<'a> {
    config_path: &'a Path,
    cwd: &'a Path,
}

impl eliot_engine::UlReasoningRunner for SupervisedReasoningRunner<'_> {
    fn run<'a>(
        &'a self,
        request: &'a eliot_types::UlReasoningRequest,
    ) -> eliot_engine::BoxUlReasoningFuture<'a> {
        Box::pin(async move {
            match crate::host_runtime::invoke_ul_reasoning(self.config_path, self.cwd, request).await
            {
                Ok(value) => Ok(value
                    .get("answers")
                    .cloned()
                    .and_then(|answers| serde_json::from_value(answers).ok())
                    .map_or_else(
                        || {
                            eliot_engine::UlReasoningOutcome::UnknownOutcome(
                                "supervised host returned an invalid UL exam answer".to_owned(),
                            )
                        },
                        eliot_engine::UlReasoningOutcome::Completed,
                    )),
                Err(error) => Ok(reasoning_failure(request, &error)),
            }
        })
    }
}

impl eliot_engine::UlRefinementRunner for SupervisedReasoningRunner<'_> {
    fn run<'a>(
        &'a self,
        request: &'a eliot_types::UlReasoningRequest,
    ) -> eliot_engine::BoxUlRefinementFuture<'a> {
        Box::pin(async move {
            match crate::host_runtime::invoke_ul_reasoning(self.config_path, self.cwd, request).await
            {
                Ok(value) => Ok(eliot_engine::UlRefinementOutcome::Completed(
                    serde_json::to_string(&value)?,
                )),
                Err(error) => {
                    let reason = format!("{} supervised host: {error:#}", request.route.as_str());
                    if provider_unavailable(&reason) {
                        Ok(eliot_engine::UlRefinementOutcome::Unavailable(reason))
                    } else {
                        Ok(eliot_engine::UlRefinementOutcome::UnknownOutcome(reason))
                    }
                }
            }
        })
    }
}

fn reasoning_failure(
    request: &eliot_types::UlReasoningRequest,
    error: &anyhow::Error,
) -> eliot_engine::UlReasoningOutcome {
    let reason = format!("{} supervised host: {error:#}", request.route.as_str());
    if provider_unavailable(&reason) {
        eliot_engine::UlReasoningOutcome::Unavailable(reason)
    } else {
        eliot_engine::UlReasoningOutcome::UnknownOutcome(reason)
    }
}

fn provider_unavailable(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("doctor is not ready")
        || reason.contains("unavailable")
        || reason.contains("without a sealed cognitive invocation plan")
}

pub(crate) async fn run_ul_exam_run_from_daemon(
    config_path: &Path,
    runtime_root: &Path,
    store: &CanonicalStore,
    writer: &eliot_engine::WriterHandle,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
        route: eliot_types::UlReasoningRoute,
    }
    let input: Input = serde_json::from_value(params).context("decode UL exam request")?;
    store.migrate_schema().await?;
    let cwd = std::env::current_dir().context("resolve UL supervised host working directory")?;
    let runner = SupervisedReasoningRunner {
        config_path,
        cwd: &cwd,
    };
    let record = eliot_engine::UlExamService::new(store.clone(), writer.clone())
        .run(input.project_id, input.route, &runner)
        .await?;
    write_exam_projection(runtime_root, &record)?;
    serde_json::to_value(record).context("encode UL exam record")
}

fn write_exam_projection(
    runtime_root: &Path,
    record: &eliot_types::UlExamRecord,
) -> Result<()> {
    let mut markdown = format!(
        "# UL understanding exam\n\n- Exam: `{}`\n- Project: `{}`\n- Route/status: `{}`\n- Questions: {}\n- Dirty capsules: {}\n\n",
        record.exam_id,
        record.project_id,
        record.route,
        record.questions.len(),
        record.dirty_capsule_refs.len(),
    );
    for (concept, score) in &record.subsystem_scores_milli {
        writeln!(markdown, "- `{concept}`: {score}/1000")?;
    }
    let directory = runtime_root.join("reports").join("ul-exams");
    std::fs::create_dir_all(&directory)?;
    atomic_write_bytes(
        &directory.join(format!("{}.md", record.exam_id)),
        markdown.as_bytes(),
    )?;
    atomic_write_bytes(&directory.join("latest.md"), markdown.as_bytes())
}

pub(crate) async fn run_ul_exam_report_from_daemon(
    store: &CanonicalStore,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
        #[serde(default)]
        latest: bool,
    }
    let input: Input = serde_json::from_value(params).context("decode UL exam report request")?;
    store.migrate_schema().await?;
    let mut records = store
        .observability_records_by_kind::<eliot_types::UlExamRecord>(
            input.project_id,
            None,
            eliot_types::ObservabilityKind::ExamRecord,
        )
        .await?;
    if input.latest {
        records = records.into_iter().rev().take(1).collect();
    }
    Ok(serde_json::json!({
        "project_id": input.project_id,
        "exam_count": records.len(),
        "exams": records,
    }))
}

pub(crate) async fn run_ul_prediction_sweep_from_daemon(
    store: &CanonicalStore,
    writer: &eliot_engine::WriterHandle,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
    }
    let input: Input =
        serde_json::from_value(params).context("decode UL prediction sweep request")?;
    store.migrate_schema().await?;
    let records = eliot_engine::PredictionMatcherService::new(store.clone(), writer.clone())
        .sweep_unresolvable(input.project_id, time::OffsetDateTime::now_utc())
        .await?;
    Ok(serde_json::json!({
        "project_id": input.project_id,
        "swept": records.len(),
        "predictions": records,
    }))
}

async fn refine_current_capsules(
    store: &CanonicalStore,
    writer: &eliot_engine::WriterHandle,
    project_id: ProjectId,
    limit: u16,
    runner: &dyn eliot_engine::UlRefinementRunner,
) -> Result<Vec<eliot_types::SubsystemCapsule>> {
    let mut records = store
        .load_ul_artifacts::<eliot_types::SubsystemCapsule>(
            project_id,
            &["subsystem_capsule"],
            512,
        )
        .await?;
    records.sort_by_key(|record| {
        std::cmp::Reverse(
            record
                .memory_revision
                .map_or(0, eliot_types::MemoryRevision::value),
        )
    });
    let mut seen = std::collections::BTreeSet::new();
    let capsules = records
        .into_iter()
        .filter_map(|record| {
            seen.insert(record.receipt_body.concept_id.clone())
                .then_some(record.receipt_body)
        })
        .take(usize::from(limit.clamp(1, 5)))
        .collect::<Vec<_>>();
    let service = eliot_engine::UlRefinementService::new(store.clone(), writer.clone());
    let mut refined = Vec::new();
    for capsule in capsules {
        let anchors = capsule
            .source_refs
            .iter()
            .take(8)
            .enumerate()
            .map(|(index, reference)| eliot_engine::UlRefinementAnchor {
                anchor_id: format!("{}-{index}", capsule.concept_id),
                text: reference.clone(),
            })
            .collect::<Vec<_>>();
        let result = service
            .refine(
                &capsule,
                eliot_engine::UlRefinementTrigger::ExplicitMaintain,
                eliot_engine::refinement_route(&capsule.build_id),
                &anchors,
                runner,
            )
            .await?;
        refined.push(result.capsule);
    }
    Ok(refined)
}


pub(crate) async fn run_ul_dirty_report_from_daemon(
    store: &CanonicalStore,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
    }

    let input: Input = serde_json::from_value(params).context("decode UL dirty report request")?;
    store.migrate_schema().await?;
    let dirty = store.load_ul_dirty_artifacts(input.project_id, 512).await?;
    Ok(serde_json::json!({
        "project_id": input.project_id,
        "dirty_count": dirty.len(),
        "dirty": dirty,
    }))
}

pub(crate) async fn run_ul_onboard_from_daemon(
    runtime_root: &Path,
    store: &CanonicalStore,
    writer: &eliot_engine::WriterHandle,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
        project_root: PathBuf,
    }

    let input: Input = serde_json::from_value(params).context("decode UL onboarding request")?;
    let _ = store.migrate_schema().await?;
    let service = eliot_engine::OnboardingService::new(store.clone(), writer.clone());
    let report = service
        .run(
            input.project_id,
            &input.project_root,
            runtime_root,
            eliot_types::OnboardingTestHook::None,
        )
        .await?;
    let dependency = eliot_engine::UlDependencyService::new(store.clone());
    let _ = dependency.rebuild_index(input.project_id).await?;
    clear_rebuilt_dirty(store, input.project_id).await?;
    let _ = dependency.scan_project(input.project_id).await?;
    serde_json::to_value(report).context("encode UL onboarding report")
}

async fn clear_rebuilt_dirty(store: &CanonicalStore, project_id: ProjectId) -> Result<()> {
    let dirty = store.load_ul_dirty_artifacts(project_id, 512).await?;
    let cards = store
        .load_ul_artifacts::<eliot_types::ModuleCard>(project_id, &["module_card"], 128)
        .await?;
    let capsules = store
        .load_ul_artifacts::<eliot_types::SubsystemCapsule>(
            project_id,
            &["subsystem_capsule"],
            128,
        )
        .await?;
    let maps = store
        .load_ul_artifacts::<eliot_types::SystemMap>(project_id, &["system_map"], 128)
        .await?;
    let charters = store
        .load_ul_artifacts::<eliot_types::ProjectCharter>(
            project_id,
            &["project_charter"],
            128,
        )
        .await?;
    for state in dirty {
        let build_id = match state.target_kind {
            eliot_types::PyramidTargetKind::ModuleCard => cards
                .iter()
                .filter(|record| record.receipt_body.path == state.target_id)
                .max_by_key(|record| record.memory_revision)
                .map(|record| record.receipt_body.build_fingerprint.as_str()),
            eliot_types::PyramidTargetKind::SubsystemCapsule => capsules
                .iter()
                .filter(|record| record.receipt_body.concept_id == state.target_id)
                .max_by_key(|record| record.memory_revision)
                .map(|record| record.receipt_body.build_id.as_str()),
            eliot_types::PyramidTargetKind::SystemMap => maps
                .iter()
                .max_by_key(|record| record.memory_revision)
                .map(|record| record.receipt_body.build_id.as_str()),
            eliot_types::PyramidTargetKind::ProjectCharter => charters
                .iter()
                .max_by_key(|record| record.memory_revision)
                .map(|record| record.receipt_body.build_id.as_str()),
        };
        if let Some(build_id) = build_id {
            store
                .clear_ul_artifact_dirty(
                    project_id,
                    state.target_kind,
                    &state.target_id,
                    build_id,
                )
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn run_ul_report_from_daemon(
    runtime_root: &Path,
    store: &CanonicalStore,
    ledger: &eliot_engine::UlLedgerService,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        project_id: ProjectId,
    }

    let input: Input = serde_json::from_value(params).context("decode UL report request")?;
    let _ = store.migrate_schema().await?;
    let (report, ledgers, injection_receipts) = ledger.report(input.project_id).await?;
    let predictions = store
        .load_predictions(input.project_id, None, None, false, None)
        .await?;
    let calibration = eliot_engine::CalibrationService::scores(input.project_id, &predictions);
    let read_tool_input_bytes = ledgers
        .iter()
        .map(|ledger| ledger.read_tool_input_bytes)
        .sum::<u64>();
    let read_tool_output_bytes = ledgers
        .iter()
        .map(|ledger| ledger.read_tool_output_bytes)
        .sum::<u64>();
    let acknowledged_items = ledgers
        .iter()
        .map(|ledger| u64::from(ledger.acknowledged_items))
        .sum::<u64>();
    let expanded_injected_handles = ledgers
        .iter()
        .map(|ledger| u64::from(ledger.expanded_injected_handles))
        .sum::<u64>();
    let readiness = eliot_engine::UlReadinessService::new(store.clone())
        .collect(runtime_root, input.project_id)
        .await?;
    let readiness_table = render_task08_readiness_table(&readiness.task08_readiness);
    let markdown = format!(
        "# UL use report\n\n- Project: `{}`\n- Tasks: {}\n- Injection receipts: {}\n- Injected tokens: {}\n- Exploration tokens: {}\n- Read input bytes: {}\n- Read output bytes: {}\n- Acknowledged items: {}\n- Expanded injected handles: {}\n- Predictions: {}\n- Calibration groups: {}\n- UL graph edges: {}\n- Capsules fresh/total: {}/{}\n- Real injected field tasks: {}\n- Second repository: {}\n\n## Task08 readiness\n\n{}\n",
        input.project_id,
        report.tasks,
        injection_receipts,
        report.injected_tokens,
        report.exploration_tokens,
        read_tool_input_bytes,
        read_tool_output_bytes,
        acknowledged_items,
        expanded_injected_handles,
        predictions.len(),
        calibration.len(),
        readiness.inventory.graph.total_ul_edges,
        readiness.inventory.artifacts.fresh_capsule_count,
        readiness.inventory.artifacts.capsule_count,
        readiness.field_evidence.matched_real_injected_tasks,
        readiness.field_evidence.second_repository_status,
        readiness_table,
    );
    let output = serde_json::json!({
        "report": report,
        "raw": {
            "injection_receipts": injection_receipts,
            "read_tool_input_bytes": read_tool_input_bytes,
            "read_tool_output_bytes": read_tool_output_bytes,
            "acknowledged_items": acknowledged_items,
            "expanded_injected_handles": expanded_injected_handles,
        },
        "ledgers": ledgers,
        "prediction_count": predictions.len(),
        "calibration": calibration,
        "inventory": readiness.inventory,
        "task08_readiness": readiness.task08_readiness,
        "field_validation": readiness.field_evidence,
        "warnings": readiness.warnings,
        "markdown": markdown,
    });
    let report_root = runtime_root
        .join("reports")
        .join("ul")
        .join("measurement")
        .join(input.project_id.to_string());
    write_report_pair(
        &report_root.join("latest.json"),
        &report_root.join("latest.md"),
        &output,
        &markdown,
    )?;
    Ok(output)
}

fn render_task08_readiness_table(readiness: &eliot_types::UlTask08Readiness) -> String {
    let rows = [
        (
            "Reverse dependency index",
            &readiness.reverse_dependency_index,
        ),
        ("Spreading activation", &readiness.spreading_activation),
        ("Token A/B and downgrade", &readiness.token_ab_and_downgrade),
        ("Weekly understanding exam", &readiness.weekly_understanding_exam),
        ("Model prose refinement", &readiness.model_prose_refinement),
        ("Host/package optimization", &readiness.host_surface_optimization),
    ];
    let mut table = vec![
        "Feature | Eligible | Blocking reasons".to_owned(),
        "--- | --- | ---".to_owned(),
    ];
    table.extend(rows.into_iter().map(|(name, feature)| {
        let eligible = match feature.state {
            eliot_types::UlReadinessState::Eligible => "yes",
            eliot_types::UlReadinessState::NotEligible => "no",
        };
        let reasons = if feature.reasons.is_empty() {
            "-".to_owned()
        } else {
            feature.reasons.join(", ")
        };
        format!("{name} | {eligible} | {reasons}")
    }));
    table.join("\n")
}

fn ul_daemon_instance(config_path: &Path) -> Result<RuntimeInstance> {
    let default = RuntimeInstance::select(
        config_path,
        Some(crate::runtime_instance::DEFAULT_INSTANCE_NAME),
    )?;
    if default
        .read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION)
        .is_ok_and(|publication| {
            crate::runtime_instance::path_identity(&publication.config_path)
                == crate::runtime_instance::path_identity(config_path)
        })
    {
        return Ok(default);
    }

    let isolated = RuntimeInstance::select(config_path, None)?;
    let publication = isolated
        .read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION)
        .context("UL command requires a ready Governor daemon for this config")?;
    if crate::runtime_instance::path_identity(&publication.config_path)
        != crate::runtime_instance::path_identity(config_path)
    {
        anyhow::bail!("UL daemon config does not match the requested config");
    }
    Ok(isolated)
}

async fn refresh_card_cues(
    store: &CanonicalStore,
    project_id: ProjectId,
    cards: &[eliot_types::ModuleCard],
) -> Result<()> {
    let cue_index = eliot_engine::CueIndexService::new(store.clone());
    for card in cards {
        cue_index
            .replace_record_bindings(
                project_id,
                &format!("card:{}", card.card_id),
                "module_card",
                &card.body_md,
                &card.cue_bindings,
                false,
            )
            .await?;
    }
    Ok(())
}
