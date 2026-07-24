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
    serde_json::to_value(report).context("encode UL onboarding report")
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
    let markdown = format!(
        "# UL use report\n\n- Project: `{}`\n- Tasks: {}\n- Injection receipts: {}\n- Injected tokens: {}\n- Exploration tokens: {}\n- Read input bytes: {}\n- Read output bytes: {}\n- Acknowledged items: {}\n- Expanded injected handles: {}\n- Predictions: {}\n- Calibration groups: {}\n",
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
