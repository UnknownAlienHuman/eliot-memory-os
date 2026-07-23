#[derive(Debug, clap::Subcommand)]
pub enum UlCommand {
    MineGit {
        #[arg(long)]
        project: ProjectId,
        #[arg(long)]
        root: PathBuf,
    },
}

pub async fn run_ul_mine_git(
    config_path: &Path,
    project_id: ProjectId,
    root: &Path,
) -> Result<()> {
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
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
    let artifacts = mining_service.mine(project_id, root, &failure_density)?;
    let existing = store
        .ul_artifact_by_id::<eliot_types::MiningRun>(
            project_id,
            "mining_run",
            &artifacts.run.run_id,
        )
        .await?;
    if mining_service.is_noop(
        &artifacts,
        existing.as_ref().map(|record| &record.receipt_body),
    ) {
        return write_json(&serde_json::json!({
            "status": "noop",
            "project_id": project_id,
            "run_id": artifacts.run.run_id,
            "head_commit": artifacts.run.head_commit,
            "artifacts_written": 0,
            "relations_written": 0,
        }));
    }

    let cards = eliot_engine::ModuleCardService::build(
        project_id,
        root,
        &artifacts.hotspots,
        &artifacts.edges,
        &failure_refs_by_path,
        &std::collections::BTreeMap::new(),
    )?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (writer, actor) = WriterActor::channel(wal, store.clone(), &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let artifact_writer = eliot_engine::UlArtifactWriterService;
    let mining_report = artifact_writer
        .write_mining(&writer, &WriteAdmissionService, &artifacts)
        .await?;
    let card_report = if cards.is_empty() {
        eliot_engine::UlArtifactWriteReport {
            artifacts_written: 0,
            relations_written: 0,
            receipts: Vec::new(),
        }
    } else {
        artifact_writer
            .write_module_cards(
                &writer,
                &WriteAdmissionService,
                &artifacts.run.run_id,
                &cards,
            )
            .await?
    };

    refresh_card_cues(store, project_id, &cards).await?;
    drop(writer);
    actor_task.await?;

    write_json(&serde_json::json!({
        "status": "written",
        "project_id": project_id,
        "run_id": artifacts.run.run_id,
        "head_commit": artifacts.run.head_commit,
        "commits_scanned": artifacts.run.commits_scanned,
        "baskets_used": artifacts.run.baskets_used,
        "edges_written": artifacts.edges.len(),
        "hotspots_written": artifacts.hotspots.len(),
        "cards_written": cards.len(),
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

async fn refresh_card_cues(
    store: CanonicalStore,
    project_id: ProjectId,
    cards: &[eliot_types::ModuleCard],
) -> Result<()> {
    let cue_index = eliot_engine::CueIndexService::new(store);
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
