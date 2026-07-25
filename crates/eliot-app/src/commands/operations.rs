pub async fn run_doctor_command(config_path: &Path, offline: bool) -> Result<()> {
    let startup = build_startup_report(config_path, offline).await?;
    write_report(&startup)?;
    if startup.overall == HealthStatus::NotReady {
        bail!("governor startup health is not ready");
    }
    let root = runtime_root(config_path);
    let report = DoctorService::new(&root, repo_root()).report()?;
    write_safety_report(&root, "doctor", "Doctor", &report)?;
    write_json(&report)
}

pub fn run_doctor_report(config_path: &Path) -> Result<()> {
    read_or_generate_doctor_report(config_path).and_then(|report| write_json(&report))
}

pub fn run_operations_doctor(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let surreal = surreal_logical_config(config_path)?;
    let report = DoctorService::new(&root, repo_root()).operations_report(&surreal)?;
    write_safety_report(&root, "operations-doctor", "Operations Doctor", &report)?;
    write_json(&report)
}

pub fn run_data_root_validate(config_path: &Path, profile: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let mode = parse_data_root_mode(profile)?;
    let validation = DataRootService::new(&root).validate(mode)?;
    write_safety_report(&root, "data-root", "Data Root", &validation)?;
    write_json(&validation)
}

pub fn run_data_root_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "data-root", || {
        DataRootService::new(runtime_root(config_path)).validate(DataRootMode::DevProjectLocal)
    })
}

pub fn run_backup_plan(config_path: &Path, kind: &str) -> Result<()> {
    run_backup_run(config_path, kind, true)
}

pub fn run_backup_run(config_path: &Path, kind: &str, dry_run: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let surreal = surreal_logical_config(config_path)?;
    let report =
        BackupService::new(&root).run_logical(parse_backup_kind(kind)?, &surreal, dry_run)?;
    write_safety_report(&root, "backup", "Backup", &report)?;
    write_json(&report)
}

pub fn run_backup_verify(config_path: &Path, backup: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest = BackupService::new(&root).verify(backup)?;
    let report = serde_json::json!({
        "component": "backup_verify",
        "status": "verified",
        "manifest": manifest,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_safety_report(&root, "backup", "Backup Verify", &report)?;
    write_json(&report)
}

pub fn run_backup_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    write_json(&serde_json::json!({
        "component": "backup_inventory",
        "entries": BackupService::new(&root).list()?,
        "generated_at": time::OffsetDateTime::now_utc(),
    }))
}

pub fn run_backup_status(config_path: &Path, backup: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let service = BackupService::new(&root);
    let manifest = service.read_manifest(backup)?;
    let verified = service.verify(backup).is_ok();
    write_json(&serde_json::json!({
        "component": "backup_status",
        "backup_id": manifest.backup_id,
        "verified": verified,
        "age_seconds": (time::OffsetDateTime::now_utc() - manifest.created_at).whole_seconds(),
        "dry_run": manifest.dry_run,
        "generated_at": time::OffsetDateTime::now_utc(),
    }))
}

pub fn run_backup_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "backup", || {
        BackupService::new(runtime_root(config_path)).run(BackupKind::LogicalExport, true)
    })
}

pub fn run_restore_plan(
    config_path: &Path,
    backup: &str,
    target: &Path,
    target_config_path: &Path,
) -> Result<()> {
    let root = runtime_root(config_path);
    let target_surreal = surreal_logical_config(target_config_path)?;
    let plan = RestoreService::new(&root).plan_logical(backup, target, &target_surreal)?;
    write_safety_report(&root, "restore", "Restore Plan", &plan)?;
    write_json(&plan)
}

pub fn run_restore_verify(config_path: &Path, backup: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = RestoreService::new(&root).verify(backup)?;
    write_safety_report(&root, "restore", "Restore", &report)?;
    write_json(&report)
}

pub fn run_restore_run(
    config_path: &Path,
    backup: &str,
    target: &Path,
    target_config_path: &Path,
    maintenance_mode: bool,
    approval_hash: &str,
    dry_run: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let target_surreal = surreal_logical_config(target_config_path)?;
    let report = RestoreService::new(&root).run_logical(
        backup,
        target,
        &target_surreal,
        maintenance_mode,
        approval_hash,
        dry_run,
    )?;
    write_safety_report(&root, "restore", "Restore", &report)?;
    write_json(&report)
}

pub fn run_restore_rollback(
    config_path: &Path,
    target: &Path,
    maintenance_mode: bool,
    approval_hash: &str,
    dry_run: bool,
) -> Result<()> {
    let root = runtime_root(config_path);
    let receipt = RestoreService::new(&root).rollback_isolated(
        target,
        maintenance_mode,
        approval_hash,
        dry_run,
    )?;
    write_safety_report(&root, "restore-rollback", "Restore Rollback", &receipt)?;
    write_json(&receipt)
}

pub fn run_restore_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "restore", || {
        RestoreService::new(runtime_root(config_path)).verify("latest")
    })
}

pub fn run_export_plan(config_path: &Path, kind: &str) -> Result<()> {
    run_export_run(config_path, kind)
}

pub fn run_export_run(config_path: &Path, kind: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let bundle = ExportService::new(&root).run(parse_export_kind(kind)?)?;
    write_safety_report(&root, "export", "Export", &bundle)?;
    write_json(&bundle)
}

pub fn run_import_validate(config_path: &Path, path: &Path, maintenance_mode: bool) -> Result<()> {
    let root = runtime_root(config_path);
    let plan =
        ImportService::new(&root).validate(path, ImportKind::ReportsBundle, maintenance_mode)?;
    write_safety_report(&root, "import", "Import", &plan)?;
    write_json(&plan)
}

pub fn run_import_preview(config_path: &Path, path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let fingerprint = target_store_fingerprint(config_path)?;
    let preview = ImportService::new(&root).preview(path, &fingerprint)?;
    write_safety_report(&root, "import", "Historical Import Preview", &preview)?;
    write_json(&preview)
}

pub async fn run_import_execute(
    config_path: &Path,
    path: &Path,
    approval_hash: &str,
    maintenance_mode: bool,
) -> Result<()> {
    if !maintenance_mode {
        bail!("historical import execute requires --maintenance-mode");
    }
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let fingerprint = format!(
        "{}|{}|{}",
        config.db.surreal.endpoint, config.db.surreal.ns, config.db.surreal.db
    );
    let service = ImportService::new(&root);
    let preview = service.preview(path, &fingerprint)?;
    if approval_hash != preview.plan_hash {
        bail!("approval hash does not match the current historical import preview");
    }
    let store = CanonicalStore::new(config.db.surreal);
    store.migrate_schema().await?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let mut write_receipts = Vec::new();
    for envelope in &preview.accepted {
        write_receipts.push(
            HistoricalImportMemoryWriter::write_envelope(&writer, &WriteAdmissionService, envelope)
                .await?,
        );
    }
    drop(writer);
    actor_task.await?;
    let receipt = service.finalize(&preview, approval_hash, maintenance_mode, write_receipts)?;
    write_safety_report(&root, "import", "Historical Import Receipt", &receipt)?;
    write_json(&receipt)
}

pub fn run_import_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "import")
}

pub fn run_blob_manifest(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest = BlobGcService::new(root.join("blobs")).manifest()?;
    let report = BlobReport {
        component: "blob".to_owned(),
        manifest: Some(manifest),
        gc_plan: None,
        gc_receipt: None,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_safety_report(&root, "blob", "Blob", &report)?;
    write_json(&report)
}

pub async fn run_blob_gc_plan(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let service = BlobGcService::new(root.join("blobs"));
    let manifest = service.manifest()?;
    let snapshot = CanonicalStore::new(config.db.surreal)
        .blob_reference_snapshot(&manifest.blob_root, 512)
        .await?;
    let plan = service.gc_plan(&manifest, &snapshot)?;
    let report = BlobReport {
        component: "blob".to_owned(),
        manifest: Some(manifest),
        gc_plan: Some(plan),
        gc_receipt: None,
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_safety_report(&root, "blob", "Blob GC Plan", &report)?;
    write_json(&report)
}

pub async fn run_blob_gc_run(
    config_path: &Path,
    dry_run: bool,
    approval_hash: Option<&str>,
    under_load: bool,
) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let service = BlobGcService::new(root.join("blobs"));
    let prior_report_path = root.join("reports").join("blob").join("latest.json");
    let prior_report: BlobReport =
        serde_json::from_reader(std::fs::File::open(&prior_report_path).with_context(|| {
            format!(
                "blob GC requires a persisted gc-plan report at {}",
                prior_report_path.display()
            )
        })?)?;
    let plan = prior_report
        .gc_plan
        .context("latest blob report does not contain an approved GC plan")?;
    let manifest = service.manifest()?;
    let snapshot = CanonicalStore::new(config.db.surreal)
        .blob_reference_snapshot(&manifest.blob_root, 512)
        .await?;
    let receipt = service.gc_run_authorized(
        &plan,
        &manifest,
        &snapshot,
        approval_hash.unwrap_or_default(),
        dry_run,
        under_load,
    )?;
    let report = BlobReport {
        component: "blob".to_owned(),
        manifest: Some(manifest),
        gc_plan: Some(plan),
        gc_receipt: Some(receipt),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_safety_report(&root, "blob", "Blob GC", &report)?;
    write_json(&report)
}

pub fn run_cutover_plan(
    config_path: &Path,
    proposed_data_root: &Path,
    executable_path: &Path,
) -> Result<()> {
    let root = runtime_root(config_path);
    let manifest =
        ProductionCutoverService::plan(&root, proposed_data_root, config_path, executable_path);
    write_safety_report(&root, "cutover", "Production Cutover", &manifest)?;
    write_json(&manifest)
}

pub fn run_blob_report(config_path: &Path) -> Result<()> {
    read_latest_or_generate(config_path, "blob", || {
        BlobGcService::new(runtime_root(config_path).join("blobs")).report(true)
    })
}

pub async fn run_maintenance_run(config_path: &Path, job: &str, dry_run: bool) -> Result<()> {
    let config = load_config(config_path)?;
    let root = runtime_root(config_path);
    let store = CanonicalStore::new(config.db.surreal);
    store.migrate_schema().await?;
    let mut job =
        MaintenanceScheduler::new(&root).run_one_shot(parse_maintenance_job_kind(job)?, dry_run)?;
    let wal = ControlWal::open(&config.control_wal)?;
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    MaintenanceMemoryWriter::write_job(&writer, &WriteAdmissionService, &mut job).await?;
    drop(writer);
    actor_task.await?;
    write_safety_report(&root, "maintenance", "Maintenance", &job)?;
    write_json(&job)
}

pub fn run_maintenance_status(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "maintenance")
}

pub fn run_maintenance_report(config_path: &Path) -> Result<()> {
    read_latest_json(config_path, "maintenance")
}

pub fn run_incident_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&report)
}

pub fn run_incident_open(
    config_path: &Path,
    kind: &str,
    severity: &str,
    summary: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let incident = IncidentService::new(&root).open(
        parse_incident_kind(kind)?,
        parse_incident_severity(severity)?,
        summary.to_owned(),
    )?;
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&incident)
}

pub fn run_incident_acknowledge(config_path: &Path, incident: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let incident = IncidentService::new(&root).acknowledge(incident)?;
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&incident)
}

pub fn run_incident_close(config_path: &Path, incident: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let incident = IncidentService::new(&root).close(incident)?;
    let report = IncidentService::new(&root).report()?;
    write_safety_report(&root, "incidents", "Incidents", &report)?;
    write_json(&incident)
}

pub fn run_incident_report(config_path: &Path) -> Result<()> {
    run_incident_list(config_path)
}

pub fn run_daemon_init_default(
    destination_config: &Path,
    source_config: &Path,
    force: bool,
) -> Result<()> {
    let expected_destination = default_config_path()?;
    if crate::runtime_instance::path_identity(destination_config)
        != crate::runtime_instance::path_identity(&expected_destination)
    {
        bail!(
            "daemon init-default writes only the stable default config {}",
            expected_destination.display()
        );
    }
    if destination_config.exists() && !force {
        bail!(
            "default Eliot config already exists at {}; pass --force to replace it",
            destination_config.display()
        );
    }
    let mut config = load_config(source_config)?;
    let eliot_home = destination_config
        .parent()
        .and_then(Path::parent)
        .context("default config must be under Eliot/config")?;
    std::fs::create_dir_all(eliot_home)?;
    named_pipe_ipc::restrict_owned_directory_to_current_user(eliot_home)?;

    let source_project_root = config_runtime_root(source_config)
        .parent()
        .context("source config must be inside a project runtime root")?
        .to_path_buf();
    let source_surql = resolve_source_resource(&source_project_root, &config.store.surql_dir);
    let source_migrations =
        resolve_source_resource(&source_project_root, &config.store.migrations_dir);
    let resources = eliot_home.join("resources");
    let destination_surql = resources.join("surql");
    let destination_migrations = resources.join("migrations");
    copy_resource_tree(&source_surql, &destination_surql)?;
    copy_resource_tree(&source_migrations, &destination_migrations)?;

    "EliotGovernor".clone_into(&mut config.service.service_name);
    "default".clone_into(&mut config.service.instance_id);
    config.db.surreal.storage = format!(
        "rocksdb:{}",
        config_path_text(&eliot_home.join("data").join("surrealdb-rocks"))
    );
    config.db.surreal.credential_provider = CredentialProviderKind::WindowsCredentialManager;
    "surreal-runtime/default".clone_into(&mut config.db.surreal.credential_id);
    config.control_wal.path = config_path_text(&eliot_home.join("control").join("control.redb"));
    config.blob_store.root = config_path_text(&eliot_home.join("blobs"));
    config.store.surql_dir = config_path_text(&destination_surql);
    config.store.migrations_dir = config_path_text(&destination_migrations);
    config.validate()?;
    let encoded = toml::to_string_pretty(&config)?;
    atomic_write_bytes(destination_config, encoded.as_bytes())?;
    write_json(&serde_json::json!({
        "component": "daemon_init_default",
        "status": "initialized",
        "instance": "default",
        "config_path": destination_config,
        "eliot_home": eliot_home,
        "data_root": eliot_home.join("data"),
        "resources": resources,
        "source_config": source_config,
        "long_lived_one_drive_paths": false
    }))
}

fn resolve_source_resource(project_root: &Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        path
    } else {
        project_root.join(path)
    }
}

fn copy_resource_tree(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_dir() {
        bail!(
            "required standalone resource directory is missing: {}",
            source.display()
        );
    }
    if destination.is_dir() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!(
                "standalone resources may not contain symlinks: {}",
                entry.path().display()
            );
        }
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_resource_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn config_path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub async fn run_daemon(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let result = run_daemon_instance(config_path, &instance).await;
    if let Err(error) = &result {
        let _ = instance
            .record_startup_failure(named_pipe_ipc::IPC_PROTOCOL_VERSION, &format!("{error:#}"));
    }
    result
}

async fn run_daemon_instance(config_path: &Path, instance: &RuntimeInstance) -> Result<()> {
    let config = load_config(config_path)?;
    let data_root = runtime_root(config_path);
    let root = instance.publication_root().to_path_buf();
    let lifecycle = LifecycleService::new(&root);
    let lock = lifecycle.acquire_single_instance()?;
    let stop_marker = instance.stop_marker();
    if stop_marker.is_file() {
        std::fs::remove_file(&stop_marker)?;
    }
    let database = if instance.standalone() {
        Some(
            SurrealServerSupervisor::new(config.db.surreal.clone())
                .start_or_connect()
                .await
                .context("start or connect the standalone instance-owned SurrealDB server")?,
        )
    } else {
        None
    };
    let database_started_pid = database
        .as_ref()
        .and_then(eliot_store::ReadySurrealServer::started_pid);
    let store_root = store_root_from_storage(&config.db.surreal.storage);
    let runtime_result = run_published_daemon(
        config_path,
        instance,
        &data_root,
        &store_root,
        database_started_pid,
    )
    .await;
    let database_result = match database {
        Some(database) => database
            .shutdown_if_spawned()
            .await
            .map_err(anyhow::Error::from),
        None => Ok(eliot_store::SurrealShutdown::not_owned()),
    };
    match (runtime_result, database_result) {
        (Ok(publication_cleaned), Ok(database)) => {
            lock.mark_clean_shutdown()?;
            info!("governor daemon shutdown requested");
            tracing::info!(
                database_stopped = database.stopped_owned_process,
                database_drain_incomplete = database.drain_incomplete,
                database_already_exited = database.already_exited,
                publication_cleaned,
                "owned runtime resources released"
            );
            Ok(())
        }
        (Err(runtime_error), Ok(_)) => Err(runtime_error),
        (Ok(_), Err(database_error)) => Err(database_error),
        (Err(runtime_error), Err(database_error)) => Err(runtime_error.context(format!(
            "standalone database cleanup also failed: {database_error:#}"
        ))),
    }
}

async fn run_published_daemon(
    config_path: &Path,
    instance: &RuntimeInstance,
    data_root: &Path,
    store_root: &Path,
    database_started_pid: Option<u32>,
) -> Result<bool> {
    let stop_marker = instance.stop_marker();
    async {
        let mut ipc_server = named_pipe_ipc::IpcServer::bind(config_path, instance, store_root)?;
        let pipe_name = ipc_server.name().to_owned();
        let starting_publication =
            instance.read_publication_any_state(named_pipe_ipc::IPC_PROTOCOL_VERSION)?;
        let mcp_daemon = mcp_stdio::McpDaemon::new(config_path, instance, &starting_publication)?;
        let (ipc_shutdown, ipc_shutdown_rx) = tokio::sync::watch::channel(false);
        let mut supervisor = ServiceSupervisor::new(default_runtime_services());
        supervisor.start_all("daemon").await?;
        let publication = ipc_server.publish_ready()?;
        let scheduler_task = tokio::spawn(run_weekly_ul_exam_scheduler(
            config_path.to_path_buf(),
            std::sync::Arc::clone(&mcp_daemon),
            ipc_shutdown_rx.clone(),
        ));
        let ipc_task = tokio::spawn(ipc_server.serve(mcp_daemon, ipc_shutdown_rx));
        let bundle = write_runtime_bundle(
            config_path,
            supervisor.service_statuses(),
            RuntimeMode::Daemon,
            true,
        )?;
        let log_service = LogService::new(data_root.join("logs"));
        let _ = log_service.write_event(LogService::event(
            LogLevel::Info,
            LogEventKind::DaemonStart,
            "eliot_governor.daemon",
            "governor daemon reached READY",
            Some("daemon-run".to_owned()),
        ))?;
        write_json(&serde_json::json!({
            "component": "daemon",
            "status": "running",
            "profile": "daemon",
            "instance": instance.name(),
            "standalone": instance.standalone(),
            "runtime_id": publication.runtime_id,
            "auth_generation": publication.auth_generation,
            "publication": instance.publication_path(),
            "database_started_pid": database_started_pid,
            "runtime_report": bundle.runtime_report_path,
            "health": bundle.health.ready,
            "ipc": {
                "enabled": true,
                "transport": "windows_named_pipe",
                "name": pipe_name
            }
        }))?;
        info!("governor daemon reached READY");
        tokio::select! {
            signal = tokio::signal::ctrl_c() => signal?,
            () = wait_for_stop_marker(&stop_marker) => {}
        }
        let _ = ipc_shutdown.send(true);
        let joined = tokio::time::timeout(Duration::from_secs(5), ipc_task)
            .await
            .context("named-pipe server shutdown timed out")?;
        joined.context("named-pipe server task failed")??;
        tokio::time::timeout(Duration::from_secs(5), scheduler_task)
            .await
            .context("UL weekly exam scheduler shutdown timed out")?
            .context("UL weekly exam scheduler task failed")?;
        supervisor
            .shutdown_all(shutdown_deadline_after(Duration::from_secs(5)))
            .await?;
        let mut stopping = publication.clone();
        instance.publish_state(&mut stopping, RuntimePublicationState::Stopping)?;
        let publication_cleaned = instance.cleanup_owned(&stopping)?;
        let _ = log_service.write_event(LogService::event(
            LogLevel::Info,
            LogEventKind::DaemonStop,
            "eliot_governor.daemon",
            "governor daemon shutdown requested",
            Some("daemon-run".to_owned()),
        ))?;
        Ok(publication_cleaned)
    }
    .await
}

async fn run_weekly_ul_exam_scheduler(
    config_path: PathBuf,
    daemon: std::sync::Arc<mcp_stdio::McpDaemon>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let local_now = match time::OffsetDateTime::now_local() {
                    Ok(now) => now,
                    Err(error) => {
                        tracing::warn!(%error, "UL weekly exam scheduler could not resolve local time");
                        continue;
                    }
                };
                if !eliot_engine::weekly_exam_due(
                    local_now.weekday().number_from_monday(),
                    local_now.hour(),
                ) {
                    continue;
                }
                let (year, iso_week, _) = local_now.to_iso_week_date();
                let window = format!("{year}-W{iso_week:02}");
                let projects = match pending_ul_scheduled_projects(&config_path, &window) {
                    Ok(projects) => projects,
                    Err(error) => {
                        tracing::warn!(%error, "UL weekly exam registry read failed");
                        continue;
                    }
                };
                let route = eliot_engine::weekly_exam_route(iso_week);
                for project_id in projects {
                    match daemon.run_scheduled_ul_exam(project_id, route).await {
                        Ok(_) => {
                            if let Err(error) = mark_ul_scheduled_project_complete(
                                &config_path,
                                project_id,
                                &window,
                            ) {
                                tracing::warn!(%error, %project_id, "UL weekly exam completion window write failed");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, %project_id, "UL weekly exam run failed");
                        }
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

pub fn run_daemon_status(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let root = instance.publication_root();
    let lifecycle = LifecycleService::new(root);
    let status = lifecycle.status()?;
    let publication = instance.read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION);
    let (publication_value, discovery_error) = match publication {
        Ok(publication) => (serde_json::to_value(publication)?, serde_json::Value::Null),
        Err(error) => (
            serde_json::Value::Null,
            serde_json::json!({"code": error.code, "detail": error.detail}),
        ),
    };
    write_json(&serde_json::json!({
        "component": "daemon_status",
        "active_profile": if instance.standalone() { "standalone-user-instance" } else { "isolated-config-instance" },
        "instance": instance.name(),
        "publication_root": instance.publication_root(),
        "publication": publication_value,
        "discovery_error": discovery_error,
        "lifecycle": status,
        "stop_requested": instance.stop_marker().exists()
    }))
}

pub fn run_daemon_health(config_path: &Path, instance: Option<&str>) -> Result<()> {
    run_daemon_doctor(config_path, instance)
}

pub fn run_daemon_doctor(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let publication = instance.read_publication(named_pipe_ipc::IPC_PROTOCOL_VERSION);
    let mut blockers = Vec::new();
    if !config_path.is_file() {
        blockers.push("config_missing");
    }
    let (publication_value, authentication_error) = match publication {
        Ok(publication) => {
            let authentication_error =
                named_pipe_ipc::validate_authentication_publication(&instance, &publication)
                    .err()
                    .map_or(serde_json::Value::Null, |error| {
                        blockers.push("runtime_authentication_invalid");
                        serde_json::json!({"error_code": error.code, "detail": error.detail})
                    });
            (serde_json::to_value(publication)?, authentication_error)
        }
        Err(error) => {
            blockers.push("runtime_publication_invalid");
            (
                serde_json::json!({"error_code": error.code, "detail": error.detail}),
                serde_json::Value::Null,
            )
        }
    };
    if !instance.authentication_path().is_file() {
        blockers.push("authentication_file_missing");
    }
    write_json(&serde_json::json!({
        "component": "daemon_doctor",
        "instance": instance.name(),
        "standalone": instance.standalone(),
        "config_path": config_path,
        "publication_root": instance.publication_root(),
        "publication": publication_value,
        "authentication_file_present": instance.authentication_path().is_file(),
        "authentication_error": authentication_error,
        "blockers": blockers,
        "status": if blockers.is_empty() { "ready" } else { "not_ready" }
    }))
}

pub fn run_daemon_stop(config_path: &Path, instance: Option<&str>) -> Result<()> {
    let instance = RuntimeInstance::select(config_path, instance)?;
    let runtime_dir = instance.runtime_dir();
    std::fs::create_dir_all(&runtime_dir)?;
    let marker = instance.stop_marker();
    std::fs::write(&marker, time::OffsetDateTime::now_utc().to_string())?;
    write_json(&serde_json::json!({
        "component": "daemon_stop",
        "instance": instance.name(),
        "status": "cooperative_marker_written",
        "marker": marker,
        "ipc_stop_available": true
    }))
}

async fn wait_for_stop_marker(marker: &Path) {
    let mut interval = tokio::time::interval(Duration::from_millis(25));
    loop {
        interval.tick().await;
        if marker.is_file() {
            return;
        }
    }
}

pub fn run_runtime_status(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = runtime_status_report(
        &root,
        default_service_statuses(),
        RuntimeMode::DevSingleProcess,
        false,
    );
    let report_service = ReportService::new(root.join("reports"));
    report_service.write_latest(
        "runtime",
        &report,
        &typed_report_markdown("Runtime Status", &report)?,
    )?;
    write_json(&report)
}

pub fn run_runtime_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = HealthService::report(RuntimeMode::DevSingleProcess, default_service_statuses());
    let report_service = ReportService::new(root.join("reports"));
    report_service.write_latest(
        "runtime",
        &report,
        &typed_report_markdown("Runtime Health", &report)?,
    )?;
    write_json(&report)
}

pub fn run_runtime_report(config_path: &Path) -> Result<()> {
    let bundle = write_runtime_bundle(
        config_path,
        default_service_statuses(),
        RuntimeMode::DevSingleProcess,
        false,
    )?;
    write_json(&serde_json::json!({
        "component": "runtime_report",
        "status": "written",
        "runtime_report": bundle.runtime_report_path,
        "module_report": bundle.module_report_path,
        "logs_report": bundle.logs_report_path
    }))
}

pub fn run_module_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = module_registry(config_path)?;
    let report = registry.report();
    ReportService::new(root.join("reports")).write_latest(
        "modules",
        &report,
        &typed_report_markdown("Module Registry", &report)?,
    )?;
    write_json(&report)
}

pub fn run_module_inspect(config_path: &Path, module: &str) -> Result<()> {
    let registry = module_registry(config_path)?;
    let manifest = registry
        .manifests()
        .iter()
        .find(|manifest| manifest.name == module || manifest.module_id.to_string() == module)
        .with_context(|| format!("module not found: {module}"))?;
    write_json(manifest)
}

pub fn run_module_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = module_registry(config_path)?.report();
    ReportService::new(root.join("reports")).write_latest(
        "modules",
        &report,
        &typed_report_markdown("Module Health", &report)?,
    )?;
    write_json(&report)
}

pub fn run_module_validate_manifest(path: &Path) -> Result<()> {
    let manifest = read_module_manifest(path)?;
    ModuleRegistryService::new(vec![manifest.clone()])?;
    write_json(&serde_json::json!({
        "component": "module_manifest_validation",
        "status": "valid",
        "module_id": manifest.module_id,
        "name": manifest.name
    }))
}

pub fn run_logs_tail(config_path: &Path, limit: usize) -> Result<()> {
    let root = runtime_root(config_path);
    let events = LogService::new(root.join("logs")).tail(limit)?;
    write_json(&serde_json::json!({
        "component": "logs_tail",
        "limit": limit,
        "events": events
    }))
}

pub fn run_logs_inspect(config_path: &Path, trace: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let events = LogService::new(root.join("logs"))
        .tail(usize::MAX)?
        .into_iter()
        .filter(|event| event.trace_id.as_deref() == Some(trace))
        .collect::<Vec<_>>();
    write_json(&serde_json::json!({
        "component": "logs_inspect",
        "trace_id": trace,
        "events": events
    }))
}

pub fn run_logs_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ensure_log_report(&root)?;
    ReportService::new(root.join("reports")).write_latest(
        "logs",
        &report,
        &typed_report_markdown("Logs Report", &report)?,
    )?;
    write_json(&report)
}

pub async fn run_adapter_list(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = AdapterRegistry::builtin()?;
    let report = registry.report().await;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &report,
        &typed_report_markdown("Adapter Registry", &report)?,
    )?;
    write_json(&report)
}

pub fn run_adapter_inspect(config_path: &Path, adapter: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = AdapterRegistry::builtin()?;
    let manifest = registry.inspect(adapter)?;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &manifest,
        &typed_report_markdown("Adapter Inspect", &manifest)?,
    )?;
    write_json(&manifest)
}

pub async fn run_adapter_health(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let supervisor = AdapterSupervisor::builtin()?;
    let health = supervisor.health_all().await;
    let report = serde_json::json!({
        "component": "adapter_health",
        "health": health,
        "generated_at": time::OffsetDateTime::now_utc()
    });
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &report,
        &typed_report_markdown("Adapter Health", &report)?,
    )?;
    write_json(&report)
}

pub async fn run_adapter_execute_test(config_path: &Path, adapter: &str) -> Result<()> {
    let report = execute_adapter_test(config_path, adapter).await?;
    write_json(&report)
}

pub async fn run_adapter_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let registry = AdapterRegistry::builtin()?;
    let adapter_report = registry.report().await;
    let observations = read_latest_adapter_observation_report(&root)?;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &adapter_report,
        &typed_report_markdown("Adapter Registry", &adapter_report)?,
    )?;
    if let Some(observations) = &observations {
        ReportService::new(root.join("reports")).write_latest(
            "adapter-observations",
            observations,
            &adapter_observation_markdown(observations),
        )?;
    }
    write_json(&serde_json::json!({
        "component": "adapter_report",
        "adapters": root.join("reports").join("adapters").join("latest.json"),
        "adapter_observations": root.join("reports").join("adapter-observations").join("latest.json"),
        "observation_report_available": observations.is_some()
    }))
}

pub fn run_external_review_providers(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = ExternalProviderRegistryService.report();
    write_external_review_report(&root, "external-providers", "External Providers", &report)?;
    write_json(&report)
}

pub fn run_external_review_provider_inspect(config_path: &Path, provider: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let profile = ExternalProviderRegistryService.inspect(provider)?;
    write_external_review_report(
        &root,
        "external-providers",
        "External Provider Inspect",
        &profile,
    )?;
    write_json(&profile)
}

pub fn run_external_review_request(
    config_path: &Path,
    project: &str,
    task: &str,
    provider: &str,
    role: &str,
    question: &str,
) -> Result<()> {
    let root = runtime_root(config_path);
    let profile = ExternalProviderRegistryService.inspect(provider)?;
    let mut request = external_review_request(
        project,
        task,
        provider,
        parse_external_review_role(role)?,
        question,
    );
    request.project_id = project_id_from_label(project);
    request.task_id = task_id_from_label(task);
    request.output_schema = external_output_schema_for(&request, &profile);
    request.budget = ExternalReviewBudget {
        max_packet_bytes: profile.limits.max_packet_bytes,
        max_output_bytes: profile.limits.max_raw_output_bytes,
        max_findings: profile.limits.max_findings,
    };
    let (state, work_lease) = ensure_external_review_work_lease(&root, &mut request)?;
    let packet = ExternalReviewPacketBuilder.build(
        &request,
        "context_packet_l3:external-review-minimal",
        serde_json::json!({
            "project": project,
            "task": task,
            "question": question,
            "evidence_refs": &request.evidence_refs,
            "allowed_paths": &request.allowed_paths,
            "secrets": "[redacted]"
        }),
    )?;
    let gate = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: provider_integration_eval_gate_passed(&root)?,
            incident_lockdown: false,
        },
    );
    let job = ExternalReviewJobService.create_job(&request);
    let work_report = WorkQueueService.status_report(&state, project, task);
    save_work_state_and_report(&root, &state, &work_report)?;
    write_external_review_report(
        &root,
        "external-providers",
        "External Providers",
        &ExternalProviderRegistryService.report(),
    )?;
    write_external_review_report(
        &root,
        "external-review-requests",
        "External Review Request",
        &request,
    )?;
    write_external_review_report(
        &root,
        "external-review-packets",
        "External Review Packet",
        &packet,
    )?;
    write_external_review_report(
        &root,
        "external-review-gates",
        "External Review Gates",
        &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
    )?;
    write_external_review_report(
        &root,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    write_json(&serde_json::json!({
        "component": "external_review_request",
        "request": request,
        "packet": packet,
        "gate": gate,
        "job": job
    }))
}

pub fn run_external_review_job_status(config_path: &Path, job: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = read_json_value(
        &root
            .join("reports")
            .join("external-review-jobs")
            .join("latest.json"),
    )?;
    write_json(&filter_report_item(&report, "jobs", "job_id", job))
}

fn external_review_queued_job_for_request(
    root: &Path,
    request_id: &str,
) -> Result<Option<ExternalReviewJob>> {
    let path = root
        .join("reports")
        .join("external-review-jobs")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let report = read_json_value(&path)?;
    let Some(jobs) = report.get("jobs").and_then(serde_json::Value::as_array) else {
        return Ok(None);
    };
    for value in jobs {
        let job: ExternalReviewJob = serde_json::from_value(value.clone())
            .context("parse external review job from latest report")?;
        if job.request_id == request_id && job.status == ExternalReviewJobStatus::Queued {
            return Ok(Some(job));
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_lines)]
pub async fn run_external_review_run_mock(config_path: &Path, request_id: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let config = load_config(config_path)?;
    let request: ExternalReviewRequest = read_report_json(
        &root
            .join("reports")
            .join("external-review-requests")
            .join("latest.json"),
    )?;
    if request.request_id != request_id {
        bail!("external review request not found in latest report: {request_id}");
    }
    let profile = ExternalProviderRegistryService.inspect(&request.provider_id)?;
    let packet: ExternalReviewPacket = read_report_json(
        &root
            .join("reports")
            .join("external-review-packets")
            .join("latest.json"),
    )?;
    let mut state = load_work_state(&root)?;
    let work_lease = request.work_lease_id.and_then(|lease_id| {
        state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == lease_id)
            .cloned()
    });
    let gate = ExternalReviewGate.decide(
        &request,
        &profile,
        ExternalReviewGateContext {
            work_lease: work_lease.as_ref(),
            worktree_lease: None,
            provider_integration_eval_gate_passed: provider_integration_eval_gate_passed(&root)?,
            incident_lockdown: false,
        },
    );
    if gate.decision != ExternalReviewGateDecisionKind::AllowMockRun {
        write_external_review_report(
            &root,
            "external-review-gates",
            "External Review Gates",
            &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
        )?;
        bail!(
            "external review gate did not allow mock run: {:?}",
            gate.decision
        );
    }
    let blob_store = BlobStore::open(&config.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let queued_job = external_review_queued_job_for_request(&root, request_id)?
        .unwrap_or_else(|| ExternalReviewJobService.create_job(&request));
    let (mut job, raw_output) = ExternalReviewJobService
        .run_mock_job(
            &request,
            &profile,
            &packet,
            queued_job,
            &supervisor,
            &blob_store,
        )
        .await?;
    let normalization = ExternalReviewNormalizer.normalize(&request, &job, &raw_output);
    let mut results = Vec::new();
    let mut bridge_report = None;
    if let Some(mut result) = normalization.result.clone() {
        job.result_id = Some(result.result_id.clone());
        let store = CanonicalStore::new(config.db.surreal.clone());
        store.migrate_schema().await?;
        let wal = ControlWal::open(&config.control_wal)?;
        let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
        let actor_task = tokio::spawn(actor.run());
        let session_id = AgentSessionId::new_v7();
        let bridge = ExternalReviewBridgeService
            .write_and_route(
                &writer,
                &WriteAdmissionService,
                &mut state,
                session_id,
                &mut result,
            )
            .await?;
        drop(writer);
        actor_task.await?;
        bridge_report = Some(bridge);
        results.push(result);
    }
    let work_report = WorkQueueService.status_report(&state, &request.project, &request.task);
    save_work_state_and_report(&root, &state, &work_report)?;
    write_external_review_report(
        &root,
        "external-review-jobs",
        "External Review Jobs",
        &ExternalReviewReportService.jobs_report(std::slice::from_ref(&job)),
    )?;
    write_external_review_report(
        &root,
        "external-review-results",
        "External Review Results",
        &ExternalReviewReportService.results_report(&results),
    )?;
    write_external_review_report(
        &root,
        "external-review-gates",
        "External Review Gates",
        &ExternalReviewReportService.gates_report(std::slice::from_ref(&gate)),
    )?;
    write_external_review_report(
        &root,
        "external-review-normalization",
        "External Review Normalization",
        &ExternalReviewReportService
            .normalization_report(std::slice::from_ref(&normalization.receipt)),
    )?;
    if let Some(bridge) = &bridge_report {
        write_external_review_report(
            &root,
            "external-review-bridge",
            "External Review Bridge",
            bridge,
        )?;
    }
    write_json(&serde_json::json!({
        "component": "external_review_run_mock",
        "job": job,
        "normalization": normalization.receipt,
        "results": results,
        "bridge": bridge_report
    }))
}

pub fn run_external_review_result_inspect(config_path: &Path, result: &str) -> Result<()> {
    let root = runtime_root(config_path);
    let report = read_json_value(
        &root
            .join("reports")
            .join("external-review-results")
            .join("latest.json"),
    )?;
    write_json(&filter_report_item(&report, "results", "result_id", result))
}

pub fn run_external_review_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let report = serde_json::json!({
        "component": "external_review_report",
        "providers": report_path_status(&root, "external-providers"),
        "jobs": report_path_status(&root, "external-review-jobs"),
        "results": report_path_status(&root, "external-review-results"),
        "gates": report_path_status(&root, "external-review-gates"),
        "normalization": report_path_status(&root, "external-review-normalization"),
        "doctor": ExternalReviewReportService.doctor_status(external_review_mcp_tools_governed_only()),
        "generated_at": time::OffsetDateTime::now_utc()
    });
    write_external_review_report(&root, "external-review", "External Review", &report)?;
    write_json(&report)
}

pub fn run_service_validate(config_path: &Path) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.validate();
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Validate",
        &receipt,
    )?;
    write_json(&receipt)?;
    if receipt.status == ServiceInstallStatus::Failed {
        bail!("service validation failed; inspect service report");
    }
    Ok(())
}

pub fn run_service_install(config_path: &Path, dry_run: bool) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.install(dry_run);
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Install",
        &receipt,
    )?;
    write_json(&receipt)?;
    if receipt.status == ServiceInstallStatus::Failed {
        bail!("service install validation failed; inspect service report");
    }
    Ok(())
}

pub fn run_service_uninstall(config_path: &Path, dry_run: bool) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let receipt = manager.uninstall(dry_run);
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Uninstall",
        &receipt,
    )?;
    write_json(&receipt)
}

pub fn run_service_status(config_path: &Path) -> Result<()> {
    let manager = h1_service_manager(config_path)?;
    let report = manager.status();
    write_h1_report(
        &runtime_root(config_path),
        "service",
        "Service Status",
        &report,
    )?;
    write_json(&report)
}

pub fn run_service_start(config_path: &Path) -> Result<()> {
    run_service_control(config_path, ServiceInstallAction::Start, "Service Start")
}

pub fn run_service_stop(config_path: &Path) -> Result<()> {
    run_service_control(config_path, ServiceInstallAction::Stop, "Service Stop")
}

pub fn run_service_restart(config_path: &Path) -> Result<()> {
    run_service_control(
        config_path,
        ServiceInstallAction::Restart,
        "Service Restart",
    )
}

pub fn run_service_report(config_path: &Path) -> Result<()> {
    run_service_status(config_path)
}

pub fn run_ipc_smoke(config_path: &Path) -> Result<()> {
    let (mut server, token) = h1_started_ipc(config_path)?;
    let decision = StdioShimService::forwards_to_ipc_in_daemon_profile(&mut server, &token);
    let payload = serde_json::json!({ "kind": "health", "bounded": true });
    let frame = IpcFrame {
        frame_id: "h1-ipc-smoke-frame".to_owned(),
        protocol_version: h1_protocol_version().to_owned(),
        trace_id: "service-readiness-smoke".to_owned(),
        request_id: "h1-health".to_owned(),
        kind: IpcFrameKind::HealthRequest,
        payload_ref: None,
        payload_inline: Some(payload.clone()),
        payload_hash: hash_secret(&serde_json::to_string(&payload)?),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let response = IpcGovernorClient::send(&server, &frame)?;
    let status = server.status();
    let report = serde_json::json!({
        "component": "ipc_smoke",
        "handshake": decision,
        "status": status,
        "response": response,
        "bounded": true
    });
    write_h1_report(&runtime_root(config_path), "ipc", "IPC Smoke", &report)?;
    write_json(&report)?;
    if !decision.accepted || response.kind != IpcFrameKind::EventNotification {
        bail!("ipc smoke failed; inspect ipc report");
    }
    Ok(())
}

pub fn run_ipc_handshake(config_path: &Path) -> Result<()> {
    let (mut server, token) = h1_started_ipc(config_path)?;
    let handshake = IpcGovernorClient::handshake(
        "admin-cli-smoke",
        RuntimeMode::AdminCli,
        &token,
        vec!["admin".to_owned()],
    );
    let decision = server.handshake(&handshake);
    let report = serde_json::json!({
        "component": "ipc_handshake",
        "decision": decision,
        "status": server.status()
    });
    write_h1_report(&runtime_root(config_path), "ipc", "IPC Handshake", &report)?;
    write_json(&report)?;
    if report
        .get("decision")
        .and_then(|value| value.get("accepted"))
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        bail!("admin IPC handshake unexpectedly accepted without governed admin capability");
    }
    Ok(())
}

pub fn run_ipc_status(config_path: &Path) -> Result<()> {
    let (server, _) = h1_started_ipc(config_path)?;
    let report = server.status();
    write_h1_report(&runtime_root(config_path), "ipc", "IPC Status", &report)?;
    write_json(&report)
}

pub fn run_ipc_report(config_path: &Path) -> Result<()> {
    run_ipc_status(config_path)
}

pub fn run_credentials_validate(config_path: &Path) -> Result<()> {
    let report = h1_credentials_report(config_path)?;
    write_h1_report(
        &runtime_root(config_path),
        "credentials",
        "Credentials Validate",
        &report,
    )?;
    write_json(&report)?;
    if report.toml_contains_secret_values || report.command_line_contains_secret_values {
        bail!("credential boundary validation failed; inspect credentials report");
    }
    Ok(())
}

pub fn run_credentials_report(config_path: &Path) -> Result<()> {
    let report = h1_credentials_report(config_path)?;
    write_h1_report(
        &runtime_root(config_path),
        "credentials",
        "Credentials Report",
        &report,
    )?;
    write_json(&report)
}

pub fn run_readiness_probe(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let probe = service_readiness_probe(&root)?;
    write_h1_report(&root, "readiness", "Readiness Probe", &probe)?;
    write_json(&probe)?;
    if probe.status != ServiceReadinessStatus::Ready {
        bail!("service readiness probe is not READY; inspect readiness report");
    }
    Ok(())
}

pub fn run_readiness_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let probe = service_readiness_probe(&root)?;
    write_h1_report(&root, "readiness", "Readiness Report", &probe)?;
    write_json(&probe)
}

pub fn run_startup_recovery_scan(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let receipt = StartupRecoveryService::new(&root).scan()?;
    write_h1_report(&root, "startup-recovery", "Startup Recovery", &receipt)?;
    write_json(&receipt)
}

pub fn run_startup_recovery_report(config_path: &Path) -> Result<()> {
    let root = runtime_root(config_path);
    let path = root
        .join("reports")
        .join("startup-recovery")
        .join("latest.json");
    if !path.is_file() {
        return run_startup_recovery_scan(config_path);
    }
    let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    write_json(&value)
}

struct RuntimeReportBundle {
    health: RuntimeHealthReport,
    runtime_report_path: PathBuf,
    module_report_path: PathBuf,
    logs_report_path: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AdapterExecutionReport {
    component: String,
    adapter_id: String,
    result: AdapterResult,
    observations: Vec<AdapterObservation>,
    blackboard_items: Vec<BlackboardItem>,
    mailbox_messages: Vec<MailboxMessage>,
    trace_id: String,
    final_status: CompletionStatus,
}

async fn execute_adapter_test(config_path: &Path, adapter: &str) -> Result<AdapterExecutionReport> {
    let root = runtime_root(config_path);
    let config = load_config(config_path)?;
    let store = CanonicalStore::new(config.db.surreal.clone());
    store.migrate_schema().await?;
    let blob_store = BlobStore::open(&config.blob_store)?;
    let supervisor = AdapterSupervisor::builtin()?;
    let request = test_request(adapter, AdapterCapability::ExecuteTest);
    let mut result = supervisor
        .execute(adapter, request, Some(&blob_store))
        .await
        .with_context(|| format!("execute adapter {adapter}"))?;
    let mut state = load_work_state(&root)?;
    let session_id = AgentSessionId::new_v7();
    let wal = ControlWal::open(&config.control_wal)?;
    let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let admission = WriteAdmissionService;
    let mut observations = Vec::new();
    let mut blackboard_items = Vec::new();
    let mut mailbox_messages = Vec::new();
    for observation in &mut result.observations {
        AdapterMemoryWriter::write_observation(&writer, &admission, observation).await?;
        let item =
            AdapterObservationBridge::to_blackboard_candidate(&mut state, session_id, observation);
        let message =
            AdapterObservationBridge::to_mailbox_notification(&mut state, session_id, observation);
        observations.push(observation.clone());
        blackboard_items.push(item);
        mailbox_messages.push(message);
    }
    drop(writer);
    actor_task.await?;
    write_report_pair(
        &work_state_path(&root),
        &work_state_markdown_path(&root),
        &state,
        "",
    )?;
    let observation_report = AdapterObservationReport {
        component: "adapter_observations".to_owned(),
        observations: observations.clone(),
        blackboard_items: blackboard_items.clone(),
        mailbox_messages: mailbox_messages.clone(),
        generated_at: time::OffsetDateTime::now_utc(),
    };
    write_adapter_reports(&root, &supervisor, Some(&observation_report)).await?;
    LogService::new(root.join("logs")).write_event(LogService::event(
        LogLevel::Info,
        LogEventKind::BlackboardUpdated,
        "eliot_adapter_runtime",
        format!("adapter {adapter} emitted tainted observation"),
        Some(result.trace_id.clone()),
    ))?;
    let final_status = if matches!(result.status, AdapterResultStatus::Succeeded) {
        CompletionStatus::DoneVerified
    } else {
        CompletionStatus::PartialProgress
    };
    Ok(AdapterExecutionReport {
        component: "adapter_execute_test".to_owned(),
        adapter_id: adapter.to_owned(),
        trace_id: result.trace_id.clone(),
        result,
        observations,
        blackboard_items,
        mailbox_messages,
        final_status,
    })
}

async fn write_adapter_reports(
    root: &Path,
    supervisor: &AdapterSupervisor,
    observations: Option<&AdapterObservationReport>,
) -> Result<()> {
    let adapter_report = supervisor.registry().report().await;
    ReportService::new(root.join("reports")).write_latest(
        "adapters",
        &adapter_report,
        &typed_report_markdown("Adapter Registry", &adapter_report)?,
    )?;
    if let Some(observations) = observations {
        ReportService::new(root.join("reports")).write_latest(
            "adapter-observations",
            observations,
            &adapter_observation_markdown(observations),
        )?;
    }
    Ok(())
}

fn read_latest_adapter_observation_report(root: &Path) -> Result<Option<AdapterObservationReport>> {
    let path = root
        .join("reports")
        .join("adapter-observations")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

fn adapter_observation_markdown(report: &AdapterObservationReport) -> String {
    let mut output = String::from("# Adapter Observations\n\n");
    let _ = writeln!(output, "- observations: `{}`", report.observations.len());
    let _ = writeln!(
        output,
        "- blackboard_items: `{}`",
        report.blackboard_items.len()
    );
    let _ = writeln!(
        output,
        "- mailbox_messages: `{}`",
        report.mailbox_messages.len()
    );
    for observation in &report.observations {
        let _ = writeln!(
            output,
            "- `{}` `{}` taint=`{:?}` receipt=`{}`",
            observation.adapter_id,
            observation.observation_id,
            observation.taint,
            observation.write_receipt.as_ref().map_or_else(
                || "none".to_owned(),
                |receipt| receipt.receipt_id.to_string()
            )
        );
    }
    output
}

fn write_runtime_bundle(
    config_path: &Path,
    statuses: Vec<ServiceRuntimeStatus>,
    mode: RuntimeMode,
    single_instance_owned: bool,
) -> Result<RuntimeReportBundle> {
    let root = runtime_root(config_path);
    let report_service = ReportService::new(root.join("reports"));
    let runtime_status =
        runtime_status_report(&root, statuses.clone(), mode, single_instance_owned);
    let runtime_health = HealthService::report(mode, statuses);
    let runtime_report = serde_json::json!({
        "component": "runtime_report",
        "status": runtime_status,
        "health": runtime_health
    });
    let (runtime_report_path, _) = report_service.write_latest(
        "runtime",
        &runtime_report,
        &report_markdown("Runtime Report", &runtime_report),
    )?;

    let module_report = module_registry(config_path)?.report();
    let (module_report_path, _) = report_service.write_latest(
        "modules",
        &module_report,
        &typed_report_markdown("Module Registry", &module_report)?,
    )?;

    let log_report = ensure_log_report(&root)?;
    let (logs_report_path, _) = report_service.write_latest(
        "logs",
        &log_report,
        &typed_report_markdown("Logs Report", &log_report)?,
    )?;

    Ok(RuntimeReportBundle {
        health: runtime_health,
        runtime_report_path,
        module_report_path,
        logs_report_path,
    })
}

fn runtime_status_report(
    root: &Path,
    services: Vec<ServiceRuntimeStatus>,
    mode: RuntimeMode,
    single_instance_owned: bool,
) -> RuntimeStatusReport {
    RuntimeStatusReport {
        component: "runtime_status".to_owned(),
        mode,
        pid: std::process::id(),
        data_root: root.display().to_string(),
        active_profile: "dev-single-process".to_owned(),
        single_instance_owned,
        ipc_enabled: matches!(mode, RuntimeMode::Daemon),
        services,
        generated_at: time::OffsetDateTime::now_utc(),
    }
}

fn default_service_statuses() -> Vec<ServiceRuntimeStatus> {
    [
        "lifecycle",
        "memory",
        "coordination",
        "module_registry",
        "adapter_supervisor",
        "mailbox_blackboard",
        "logs",
        "reports",
    ]
    .into_iter()
    .map(|service_name| ServiceRuntimeStatus {
        service_name: service_name.to_owned(),
        health: ServiceHealthState::Healthy,
        started: true,
        restart_budget_remaining: 3,
        message: "dev-single-process service ready".to_owned(),
    })
    .collect()
}

fn ensure_log_report(root: &Path) -> Result<RuntimeLogReport> {
    let log_service = LogService::new(root.join("logs"));
    let mut correlated = LogService::event(
        LogLevel::Info,
        LogEventKind::ServiceHealth,
        "eliot_governor.runtime",
        "runtime health probe",
        Some("g0-trace".to_owned()),
    );
    correlated.task_id = Some(TaskId::new_v7());
    correlated.agent_session_id = Some(AgentSessionId::new_v7());
    let _ = log_service.write_event(correlated)?;
    let _ = log_service.write_event(LogService::event(
        LogLevel::Warn,
        LogEventKind::Error,
        "eliot_governor.runtime",
        "secret token=local-test-redacted",
        Some("g0-trace".to_owned()),
    ))?;
    log_service.report().map_err(Into::into)
}

fn module_registry(config_path: &Path) -> Result<ModuleRegistryService> {
    let manifest_dir = module_manifest_dir(config_path);
    let manifests = if manifest_dir.is_dir() {
        let mut loaded = Vec::new();
        for entry in std::fs::read_dir(&manifest_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("toml") {
                loaded.push(read_module_manifest(&path)?);
            }
        }
        if loaded.is_empty() {
            builtin_manifests()
        } else {
            loaded
        }
    } else {
        builtin_manifests()
    };
    Ok(ModuleRegistryService::new(manifests)?)
}

fn module_manifest_dir(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("config")
        .join("modules")
}

fn read_module_manifest(path: &Path) -> Result<ModuleManifest> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read module manifest {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("parse module manifest {}", path.display()))
}

fn typed_report_markdown<T: serde::Serialize>(title: &str, report: &T) -> Result<String> {
    let value = serde_json::to_value(report)?;
    Ok(report_markdown(title, &value))
}
