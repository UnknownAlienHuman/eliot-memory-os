use eliot_engine::{
    BackupService, HistoricalImportMemoryWriter, ImportService, RestoreService,
    SurrealLogicalConfig, SurrealLogicalService, WriteAdmissionService, WriterActor, WriterConfig,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    AgentId, BackupKind, ClaimCardInput, ClaimId, ClaimProposeCommand, CommandContext,
    CredentialProviderKind, EpistemicStatus, GovernorConfig, LifecycleStatus, ProjectId,
    ProjectSequence, ReadConsistencyMode, RecallL0Request, RestoreStatus, SemanticCommand,
    SurrealServerConfig, TaintClass, TaskAcceptanceEvidenceKind, TaskAcceptanceItem,
    TaskContractInput, TaskContractStatus, TaskContractWriteCommand, TaskId, VerificationId,
    VerificationResult, Visibility, WriteId, WriteStatus,
};
use serde_json::json;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn real_surreal_store_backup_restore_to_new_root() -> TestResult {
    let surreal = std::env::var_os("ELIOT_SURREAL_EXE")
        .map_or_else(|| PathBuf::from("surreal"), PathBuf::from);
    if !surreal.is_file() {
        return Ok(());
    }
    let fixture = test_root("real-store")?;
    let source_root = fixture.join("source");
    let target_root = fixture.join("target");
    let backup_root = fixture.join("backup-owner");
    std::fs::create_dir_all(&source_root)?;
    std::fs::create_dir_all(&backup_root)?;
    let source_blob = backup_root.join("blobs").join("ab").join("proof.blob");
    std::fs::create_dir_all(source_blob.parent().ok_or("blob fixture has no parent")?)?;
    std::fs::write(&source_blob, b"m5-immutable-blob-payload")?;
    let Ok(password_config) = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE") else {
        return Ok(());
    };
    let password_file = resolve_test_password_file(&password_config)?;
    let Ok(password) = std::env::var("SURREAL_PASS") else {
        return Ok(());
    };
    if password.is_empty() {
        return Err("isolated test credential is empty".into());
    }

    let source_port = free_port()?;
    let source_storage = source_root.join("store");
    let mut source = IsolatedSurreal::start(&surreal, source_port, &source_storage, &password)?;
    let source_config = logical_config(&surreal, source_port, &password_file, &source_storage);
    let source_store_config =
        canonical_config(&surreal, source_port, &password_config, &source_storage);
    let source_store = CanonicalStore::new(source_store_config);
    source_store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let task_write_id = WriteId::new_v7();
    let task_command = SemanticCommand::TaskContractWrite(TaskContractWriteCommand {
        context: command_context(task_write_id, project_id, Some(task_id)),
        contract: TaskContractInput {
            task_id,
            title: "Restored semantic-memory acceptance".to_owned(),
            status: TaskContractStatus::Active,
            acceptance_items: vec![TaskAcceptanceItem {
                item_id: "m5-restore-known-task".to_owned(),
                description: "known task survives backup and restore".to_owned(),
                required_evidence: TaskAcceptanceEvidenceKind::Observation,
                satisfied: false,
                observation_id: None,
                verification_id: None,
                verification_scope_hash: None,
            }],
            expected_revision: None,
            action_lease_id: None,
            understanding_proof_hash: Some("m5-understanding-proof".to_owned()),
            action_provenance: None,
            observation_ids: Vec::new(),
            verification_ids: Vec::new(),
            verification_scopes: Vec::new(),
            completion_write_id: None,
        },
        observation: None,
        verification: None,
    });
    let mut task_envelope = WriteAdmissionService.admit(&task_command)?;
    task_envelope.project_sequence_hint = Some(ProjectSequence::new(9));
    let task_receipt = source_store.apply_write_envelope(&task_envelope).await?;
    assert_eq!(task_receipt.status, WriteStatus::Committed);
    assert_eq!(
        task_receipt
            .memory_revision
            .map(eliot_types::MemoryRevision::value),
        Some(9)
    );
    let claim_id = ClaimId::new_v7();
    let claim_command = SemanticCommand::ClaimPropose(ClaimProposeCommand {
        context: command_context(WriteId::new_v7(), project_id, Some(task_id)),
        claim: ClaimCardInput {
            claim_id,
            statement: "Semantic memory survives isolated restore".to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({"layer": "semantic_memory", "provenance": "m5-isolated-e2e"}),
        },
    });
    let mut claim_envelope = WriteAdmissionService.admit(&claim_command)?;
    claim_envelope.project_sequence_hint = Some(ProjectSequence::new(10));
    let claim_receipt = source_store.apply_write_envelope(&claim_envelope).await?;
    assert_eq!(claim_receipt.status, WriteStatus::Committed);
    assert_eq!(
        claim_receipt
            .memory_revision
            .map(eliot_types::MemoryRevision::value),
        Some(10)
    );
    let seed = fixture.join("seed.surql");
    std::fs::write(
        &seed,
        "OPTION IMPORT; DEFINE TABLE m5 SCHEMALESS; CREATE m5:proof CONTENT { value: 'backup-restore-proof' };",
    )?;
    SurrealLogicalService::validate(&source_config, &seed)?;
    SurrealLogicalService::import(&source_config, &seed)?;

    let backup = BackupService::new(&backup_root).run_logical(
        BackupKind::LogicalExport,
        &source_config,
        false,
    )?;
    assert_eq!(backup.manifest.surreal_export_status, "validated");
    assert_eq!(backup.manifest.blob_payloads.len(), 1);
    BackupService::new(&backup_root).verify("latest")?;
    let latest_manifest = backup_root.join("backups/latest/manifest.json");
    let latest_manifest_bytes = std::fs::read(&latest_manifest)?;
    let mut escaped_manifest = backup.manifest.clone();
    escaped_manifest.surreal_export_ref = Some(seed.to_string_lossy().into_owned());
    std::fs::write(
        &latest_manifest,
        serde_json::to_vec_pretty(&escaped_manifest)?,
    )?;
    assert!(BackupService::new(&backup_root).verify("latest").is_err());
    escaped_manifest.surreal_export_ref = backup.manifest.surreal_export_ref.clone();
    escaped_manifest.blob_manifest_ref = seed.to_string_lossy().into_owned();
    std::fs::write(
        &latest_manifest,
        serde_json::to_vec_pretty(&escaped_manifest)?,
    )?;
    assert!(BackupService::new(&backup_root).verify("latest").is_err());
    std::fs::write(&latest_manifest, latest_manifest_bytes)?;
    BackupService::new(&backup_root).verify("latest")?;
    let copied_blob = PathBuf::from(&backup.manifest.blob_payloads[0].backup_path);
    let copied_bytes = std::fs::read(&copied_blob)?;
    std::fs::write(&copied_blob, b"tampered")?;
    assert!(BackupService::new(&backup_root).verify("latest").is_err());
    std::fs::write(&copied_blob, &copied_bytes)?;
    BackupService::new(&backup_root).verify("latest")?;
    let source_before = backup
        .manifest
        .surreal_export_ref
        .as_ref()
        .map(std::fs::read)
        .transpose()?
        .ok_or("backup export missing")?;

    let target_port = free_port()?;
    let target_storage = target_root.join("store");
    let mut target = IsolatedSurreal::start(&surreal, target_port, &target_storage, &password)?;
    let target_config = logical_config(&surreal, target_port, &password_file, &target_storage);
    let restore_service = RestoreService::new(&backup_root);
    let restore_plan = restore_service.plan_logical("latest", &target_root, &target_config)?;
    let refused = restore_service.run_logical(
        "latest",
        &target_root,
        &target_config,
        true,
        "wrong-approval",
        false,
    )?;
    assert_eq!(refused.receipt.status, RestoreStatus::FailedWrite);
    let restore = restore_service.run_logical(
        "latest",
        &target_root,
        &target_config,
        true,
        restore_plan
            .exact_action_hash
            .as_deref()
            .unwrap_or_default(),
        false,
    )?;
    assert_eq!(restore.receipt.status, RestoreStatus::RestoredToNewRoot);
    assert_eq!(restore.receipt.restored_blobs, 1);
    assert_eq!(
        std::fs::read(target_root.join("blobs").join("ab").join("proof.blob"))?,
        b"m5-immutable-blob-payload"
    );

    let target_export = fixture.join("target-export.surql");
    SurrealLogicalService::export(&target_config, &target_export)?;
    let target_text = std::fs::read_to_string(target_export)?;
    assert!(target_text.contains("backup-restore-proof"));
    let target_store = CanonicalStore::new(canonical_config(
        &surreal,
        target_port,
        &password_config,
        &target_storage,
    ));
    let restored_task = target_store
        .task_contract_by_id(task_id)
        .await?
        .ok_or("restored task contract missing")?;
    assert_eq!(restored_task.memory_revision.value(), 9);
    let recall = target_store
        .recall_l0(&RecallL0Request {
            project_id,
            query: "semantic memory survives".to_owned(),
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
            lifecycle_audit: false,
            task_id: None,
            task_class_cues: Vec::new(),
            scope_refs: Vec::new(),
            concept_refs: Vec::new(),
        })
        .await?;
    assert!(
        recall
            .handles
            .iter()
            .any(|handle| handle.handle.contains(&claim_id.to_string()))
    );
    let replay = target_store.apply_write_envelope(&task_envelope).await?;
    assert_eq!(replay.status, WriteStatus::IdempotentReplay);
    assert_eq!(replay.write_id, task_write_id);

    let import_path = fixture.join("historical-import.json");
    let historical_claim_id = ClaimId::new_v7();
    let historical_verification_id = VerificationId::new_v7();
    std::fs::write(
        &import_path,
        serde_json::to_vec_pretty(&json!([
            {
                "artifact_id": "historical-claim",
                "kind": "claim",
                "project_id": project_id,
                "task_id": task_id,
                "payload": {
                    "claim_id": historical_claim_id,
                    "statement": "historical claim remains candidate"
                }
            },
            {
                "artifact_id": "historical-evidence",
                "kind": "evidence",
                "project_id": project_id,
                "task_id": task_id,
                "payload": {"summary": "historical evidence remains user provided"}
            },
            {
                "artifact_id": "historical-failure",
                "kind": "failure",
                "project_id": project_id,
                "payload": {"fingerprint": "m5-historical-failure", "summary": "legacy failure"}
            },
            {
                "artifact_id": "historical-verification",
                "kind": "verification",
                "project_id": project_id,
                "payload": {
                    "verification_id": historical_verification_id,
                    "result": "passed",
                    "summary": "must remain inconclusive"
                }
            },
            {"artifact_id": "unsupported", "kind": "truth_promotion", "payload": {}}
        ]))?,
    )?;
    let import_service = ImportService::new(&backup_root);
    let fingerprint = format!(
        "{}|{}|{}",
        target_config.endpoint, target_config.namespace, target_config.database
    );
    let preview = import_service.preview(&import_path, &fingerprint)?;
    assert_eq!(preview.accepted.len(), 4);
    assert_eq!(preview.quarantined.len(), 1);
    let mut wal_config = GovernorConfig::default().control_wal;
    wal_config.path = fixture
        .join("import-control.redb")
        .to_string_lossy()
        .into_owned();
    let wal = ControlWal::open(&wal_config)?;
    let (writer, actor) = WriterActor::channel(wal, target_store.clone(), &WriterConfig::default());
    let actor_task = tokio::spawn(actor.run());
    let mut import_receipts = Vec::new();
    for envelope in &preview.accepted {
        import_receipts.push(
            HistoricalImportMemoryWriter::write_envelope(&writer, &WriteAdmissionService, envelope)
                .await?,
        );
    }
    drop(writer);
    actor_task.await?;
    let import_receipt =
        import_service.finalize(&preview, &preview.plan_hash, true, import_receipts)?;
    assert_eq!(import_receipt.imported_ids.len(), 4);
    let imported_verification = target_store
        .verification_run_by_id(historical_verification_id)
        .await?
        .ok_or("historical verification was not written")?;
    assert_eq!(
        imported_verification.result,
        VerificationResult::Inconclusive
    );
    let imported_recall = target_store
        .recall_l0(&RecallL0Request {
            project_id,
            query: "historical claim remains candidate".to_owned(),
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
            lifecycle_audit: false,
            task_id: None,
            task_class_cues: Vec::new(),
            scope_refs: Vec::new(),
            concept_refs: Vec::new(),
        })
        .await?;
    assert!(imported_recall.handles.iter().any(|handle| {
        handle.handle.contains(&historical_claim_id.to_string())
            && handle
                .preview
                .contains("historical claim remains candidate")
    }));
    let second_preview = import_service.preview(&import_path, &fingerprint)?;
    assert!(second_preview.accepted.is_empty());
    assert_eq!(second_preview.already_imported.len(), 4);
    let second_receipt =
        import_service.finalize(&second_preview, &second_preview.plan_hash, true, Vec::new())?;
    assert!(second_receipt.imported_ids.is_empty());
    if let Ok(governor) = std::env::var("ELIOT_M5_GOVERNOR_EXE") {
        let target_config_path =
            write_governor_config(&target_root, &target_storage, target_port, &password_config)?;
        assert_governed_operator_snapshot(
            Path::new(&governor),
            &target_config_path,
            &target_root,
            project_id,
            task_id,
        )?;
    }
    let source_after_path = fixture.join("source-after.surql");
    SurrealLogicalService::export(&source_config, &source_after_path)?;
    assert_eq!(source_before, std::fs::read(source_after_path)?);

    target.stop();
    let rollback_plan = restore_service.rollback_isolated(&target_root, false, "", true)?;
    assert_eq!(rollback_plan.status, "planned");
    let rollback = restore_service.rollback_isolated(
        &target_root,
        true,
        &rollback_plan.exact_action_hash,
        false,
    )?;
    assert_eq!(rollback.status, "rolled_back_to_quarantine");
    assert!(!target_root.exists());
    assert!(rollback.quarantined_root.as_deref().is_some_and(|path| {
        Path::new(path)
            .join("restore-evidence/rollback-receipt.json")
            .is_file()
    }));
    source.stop();
    Ok(())
}

struct IsolatedSurreal {
    child: Option<Child>,
}

impl IsolatedSurreal {
    fn start(executable: &Path, port: u16, storage: &Path, password: &str) -> TestResult<Self> {
        if let Some(parent) = storage.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bind = format!("127.0.0.1:{port}");
        let child = Command::new(executable)
            .arg("start")
            .arg("--bind")
            .arg(&bind)
            .arg("--no-banner")
            .arg(format!("rocksdb:{}", storage.display()))
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", password)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut server = Self { child: Some(child) };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(server);
            }
            if server
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_some())
            {
                return Err("isolated SurrealDB exited during startup".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        server.stop();
        Err("isolated SurrealDB startup timed out".into())
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for IsolatedSurreal {
    fn drop(&mut self) {
        self.stop();
    }
}

fn logical_config(
    executable: &Path,
    port: u16,
    password_file: &Path,
    storage: &Path,
) -> SurrealLogicalConfig {
    SurrealLogicalConfig {
        executable: executable.to_path_buf(),
        endpoint: format!("ws://127.0.0.1:{port}/rpc"),
        namespace: "eliot".to_owned(),
        database: "system".to_owned(),
        username: "root".to_owned(),
        credential_provider: CredentialProviderKind::LegacyPasswordFile,
        credential_id: String::new(),
        password_file: password_file.to_path_buf(),
        legacy_password_file_authorized: true,
        storage_root: Some(storage.to_path_buf()),
    }
}

fn canonical_config(
    executable: &Path,
    port: u16,
    password_config: &str,
    storage: &Path,
) -> SurrealServerConfig {
    let mut config = GovernorConfig::default().db.surreal;
    config.exe = executable.to_string_lossy().into_owned();
    config.bind = format!("127.0.0.1:{port}");
    config.endpoint = format!("ws://127.0.0.1:{port}/rpc");
    config.storage = format!("rocksdb:{}", storage.display());
    config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    "test-only/m5-isolated".clone_into(&mut config.credential_id);
    password_config.clone_into(&mut config.password_file);
    config
}

fn command_context(
    write_id: WriteId,
    project_id: ProjectId,
    task_id: Option<TaskId>,
) -> CommandContext {
    CommandContext {
        write_id,
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id,
        scope: "m5-isolated-recovery".to_owned(),
        authority: "m5-acceptance-test".to_owned(),
        visibility: Visibility::Project,
        taint: TaintClass::LocalTool,
        lifecycle_status: LifecycleStatus::Active,
    }
}

fn write_governor_config(
    root: &Path,
    storage: &Path,
    port: u16,
    password_config: &str,
) -> TestResult<PathBuf> {
    let config_dir = root.join("config");
    std::fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("eliot-governor.toml");
    let slash = |path: &Path| path.to_string_lossy().replace('\\', "/");
    let config = format!(
        concat!(
            "schema_version = \"1\"\n",
            "[service]\nservice_name = \"EliotGovernorM5\"\ninstance_id = \"m5-restored\"\n",
            "[db]\nmode = \"surreal_rpc_server\"\n",
            "[db.surreal]\nexe = \"surreal\"\n",
            "bind = \"127.0.0.1:{port}\"\nendpoint = \"ws://127.0.0.1:{port}/rpc\"\n",
            "storage = \"rocksdb:{storage}\"\nns = \"eliot\"\ndb = \"system\"\nuser = \"root\"\n",
            "credential_provider = \"legacy_password_file\"\ncredential_id = \"test-only/m5-isolated\"\n",
            "password_file = \"{password}\"\nlog_level = \"warn\"\nquery_timeout_ms = 15000\n",
            "transaction_timeout_ms = 15000\nstartup_timeout_ms = 20000\nrestart_backoff_ms = 200\nmax_restart_backoff_ms = 2000\n",
            "[db.surreal.capabilities]\ndeny_all = true\nallow_funcs = [\"array\", \"string\", \"time\", \"type\", \"math\", \"vector\", \"search\"]\nallow_net = []\nallow_scripting = false\nallow_guests = false\n",
            "[control_wal]\npath = \"{control}\"\n[blob_store]\nroot = \"{blobs}\"\n",
            "[store]\nsurql_dir = \"crates/eliot-store/src/surql\"\nmigrations_dir = \"crates/eliot-store/migrations\"\n"
        ),
        port = port,
        storage = slash(storage),
        password = password_config,
        control = slash(&root.join("control/control.redb")),
        blobs = slash(&root.join("blobs")),
    );
    std::fs::write(&config_path, config)?;
    Ok(config_path)
}

fn resolve_test_password_file(configured: &str) -> TestResult<PathBuf> {
    let path = if let Some(relative) = configured
        .strip_prefix("%LOCALAPPDATA%/")
        .or_else(|| configured.strip_prefix("%LOCALAPPDATA%\\"))
    {
        PathBuf::from(std::env::var("LOCALAPPDATA")?).join(relative.replace('/', "\\"))
    } else {
        PathBuf::from(configured)
    };
    if !path.is_absolute() || !path.is_file() {
        return Err("isolated test credential path is not an existing absolute file".into());
    }
    Ok(path)
}

fn assert_governed_operator_snapshot(
    governor: &Path,
    config: &Path,
    expected_store_root: &Path,
    project_id: ProjectId,
    task_id: TaskId,
) -> TestResult {
    if !governor.is_file() {
        return Err(format!("M5 Governor executable missing: {}", governor.display()).into());
    }
    let local_app_data = config
        .parent()
        .and_then(Path::parent)
        .ok_or("M5 Governor config did not have an isolated root")?
        .join("governor-local-app-data");
    let test_root = config
        .parent()
        .and_then(Path::parent)
        .ok_or("M5 Governor config did not have an isolated root")?;
    let instance = format!(
        "m5-restore-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let fake_default_marker = local_app_data
        .join("Eliot/instances/default/runtime")
        .join("production-sentinel.json");
    std::fs::create_dir_all(
        fake_default_marker
            .parent()
            .ok_or("fake default marker parent missing")?,
    )?;
    std::fs::write(&fake_default_marker, b"fake-live-default-must-not-change")?;
    let mut daemon = IsolatedGovernor::start(
        governor,
        config,
        expected_store_root,
        test_root,
        &local_app_data,
        &instance,
    )?;
    let result = call_governed_operator_snapshot(
        governor,
        config,
        &local_app_data,
        &instance,
        project_id,
        task_id,
    );
    let stop_result = daemon.stop();
    result?;
    stop_result?;
    if std::fs::read(&fake_default_marker)? != b"fake-live-default-must-not-change" {
        return Err("M5 named-instance test mutated the isolated fake default marker".into());
    }
    Ok(())
}

fn call_governed_operator_snapshot(
    governor: &Path,
    config: &Path,
    local_app_data: &Path,
    instance: &str,
    project_id: ProjectId,
    task_id: TaskId,
) -> TestResult {
    let mut child = Command::new(governor)
        .arg("--config")
        .arg(config)
        .args(["mcp", "stdio", "--profile", "human_readonly"])
        .arg("--instance")
        .arg(instance)
        .env("LOCALAPPDATA", local_app_data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "m5-isolated-e2e", "version": "1.0.0"}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "eliot_operator_snapshot",
                "arguments": {"project_id": project_id, "task_id": task_id}
            }
        }),
    ];
    let mut stdin = child.stdin.take().ok_or("Governor stdin unavailable")?;
    for request in requests {
        writeln!(stdin, "{}", serde_json::to_string(&request)?)?;
    }
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "restored Governor MCP failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    let responses = stdout
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = responses
        .iter()
        .find(|response| response.get("id") == Some(&json!(2)))
        .ok_or("Governor did not return the Operator snapshot response")?;
    if snapshot.get("error").is_some() {
        return Err(format!("Operator snapshot returned an error: {snapshot}").into());
    }
    let rendered = serde_json::to_string(snapshot)?;
    if !rendered.contains(&task_id.to_string()) {
        return Err(
            format!("Operator snapshot omitted restored task {task_id}: {snapshot}").into(),
        );
    }
    if !rendered.contains("Restored semantic-memory acceptance") {
        return Err(format!("Operator snapshot omitted restored task title: {snapshot}").into());
    }
    Ok(())
}

struct IsolatedGovernor {
    child: Option<Child>,
    executable: PathBuf,
    config: PathBuf,
    expected_store: PathBuf,
    local_app_data: PathBuf,
    instance: String,
    publication_path: PathBuf,
}

impl IsolatedGovernor {
    fn start(
        executable: &Path,
        config: &Path,
        expected_store_root: &Path,
        test_root: &Path,
        local_app_data: &Path,
        instance: &str,
    ) -> TestResult<Self> {
        std::fs::create_dir_all(local_app_data)?;
        let publication_root = local_app_data.join("Eliot/instances").join(instance);
        assert_isolated_publication_root(&publication_root, test_root)?;
        let publication_path = publication_root.join("runtime/publication.json");
        let child = Command::new(executable)
            .arg("--config")
            .arg(config)
            .args(["daemon", "run", "--instance"])
            .arg(instance)
            .env("LOCALAPPDATA", local_app_data)
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env(
                "ELIOT_TEST_SURREAL_PASSWORD_FILE",
                std::env::var_os("ELIOT_TEST_SURREAL_PASSWORD_FILE")
                    .ok_or("isolated test credential path is unavailable")?,
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut daemon = Self {
            child: Some(child),
            executable: executable.to_path_buf(),
            config: config.to_path_buf(),
            expected_store: expected_store_root.to_path_buf(),
            local_app_data: local_app_data.to_path_buf(),
            instance: instance.to_owned(),
            publication_path: publication_path.clone(),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if publication_path
                .is_file()
                .then(|| std::fs::read_to_string(&publication_path).ok())
                .flatten()
                .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                .is_some_and(|value| value.get("state") == Some(&json!("ready")))
            {
                daemon.validate_publication_identity()?;
                return Ok(daemon);
            }
            if daemon
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_some())
            {
                let output = daemon
                    .child
                    .take()
                    .ok_or("isolated Governor child disappeared")?
                    .wait_with_output()?;
                return Err(format!(
                    "isolated Governor exited during startup: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        daemon.stop()?;
        Err(format!(
            "isolated Governor publication did not become ready: {}",
            publication_path.display()
        )
        .into())
    }

    fn stop(&mut self) -> TestResult {
        if self.child.is_none() {
            return Ok(());
        }
        if let Err(error) = self.validate_publication_identity() {
            self.terminate_owned_child();
            return Err(format!(
                "refused named-instance stop because publication identity changed: {error}"
            )
            .into());
        }
        let output = Command::new(&self.executable)
            .arg("--config")
            .arg(&self.config)
            .args(["daemon", "stop", "--instance"])
            .arg(&self.instance)
            .env("LOCALAPPDATA", &self.local_app_data)
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .env(
                "ELIOT_TEST_SURREAL_PASSWORD_FILE",
                std::env::var_os("ELIOT_TEST_SURREAL_PASSWORD_FILE")
                    .ok_or("isolated test credential path is unavailable")?,
            )
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "isolated Governor stop request failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_some())
            {
                self.child = None;
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.terminate_owned_child();
        Err("isolated Governor did not stop cooperatively".into())
    }

    fn validate_publication_identity(&self) -> TestResult {
        let child = self
            .child
            .as_ref()
            .ok_or("isolated Governor child missing")?;
        let publication: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.publication_path)?)?;
        let expected_publication_root = self
            .publication_path
            .parent()
            .and_then(Path::parent)
            .ok_or("publication root missing")?;
        let required_path = |field: &str, expected: &Path| -> TestResult {
            let actual = publication
                .get(field)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("publication omitted {field}"))?;
            if !same_test_path(Path::new(actual), expected) {
                return Err(format!(
                    "publication {field} mismatch: actual={actual} expected={}",
                    expected.display()
                )
                .into());
            }
            Ok(())
        };
        if publication.get("state") != Some(&json!("ready"))
            || publication.get("instance_name") != Some(&json!(self.instance))
            || publication
                .get("daemon_pid")
                .and_then(serde_json::Value::as_u64)
                != Some(u64::from(child.id()))
            || publication
                .get("runtime_id")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(format!(
                "publication state/instance/pid/runtime identity mismatch for child {}: {publication}",
                child.id()
            )
            .into());
        }
        required_path("config_path", &self.config)?;
        required_path("store_root", &self.expected_store)?;
        required_path("publication_root", expected_publication_root)?;
        required_path("executable", &self.executable)?;
        Ok(())
    }

    fn terminate_owned_child(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for IsolatedGovernor {
    fn drop(&mut self) {
        if self.stop().is_err() {
            self.terminate_owned_child();
        }
    }
}

fn assert_isolated_publication_root(publication_root: &Path, test_root: &Path) -> TestResult {
    let publication_root = absolute_test_path(publication_root);
    let test_root = absolute_test_path(test_root);
    if !publication_root.starts_with(&test_root) {
        return Err(format!(
            "M5 publication root escaped test root: publication={} test={}",
            publication_root.display(),
            test_root.display()
        )
        .into());
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let live_root = absolute_test_path(&PathBuf::from(local_app_data).join("Eliot"));
        if publication_root.starts_with(&live_root) || live_root.starts_with(&publication_root) {
            return Err(format!(
                "M5 publication root overlaps live Eliot root: publication={} live={}",
                publication_root.display(),
                live_root.display()
            )
            .into());
        }
    }
    Ok(())
}

fn same_test_path(left: &Path, right: &Path) -> bool {
    absolute_test_path(left) == absolute_test_path(right)
}

fn absolute_test_path(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    PathBuf::from(
        absolute
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .replace('/', "\\")
            .to_ascii_lowercase(),
    )
}

fn free_port() -> TestResult<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn test_root(name: &str) -> TestResult<PathBuf> {
    let root = std::env::temp_dir().join(format!(
        "eliot-m5-{name}-{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    Ok(root)
}
