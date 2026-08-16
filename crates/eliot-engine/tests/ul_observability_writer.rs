use eliot_engine::{
    CognitiveMemoryWriter, WriteAdmissionService, WriterActor, WriterConfig, WriterHandle,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    AgentId, AgentSessionId, ClaimCardInput, ClaimId, CommandContext, ControlWalConfig,
    CredentialProviderKind, CurrentStateRequest, EpistemicStatus, GovernorConfig, LifecycleStatus,
    MemoryAdmissionDecision, MemoryInfluenceClass, MemoryInfluenceTrace, ObservabilityKind,
    ObservabilityWriteStatus, ProjectId, ReadConsistencyMode, SemanticCommand, TaintClass,
    TaskAcceptanceEvidenceKind, TaskAcceptanceItem, TaskContractInput, TaskContractStatus,
    TaskContractWriteCommand, TaskId, Visibility, WriteId,
};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_writer_does_not_advance_truth() -> TestResult {
    if rerun_with_isolated_credential_backend("t02_writer_does_not_advance_truth")? {
        return Ok(());
    }
    let harness = Harness::start("truth-revision").await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let observability_write_id = WriteId::new_v7();
    let (writer, actor) = harness.writer()?;

    submit(
        &writer,
        task_contract_command(project_id, task_id, WriteId::new_v7()),
    )
    .await?;
    submit(
        &writer,
        candidate_command(project_id, task_id, WriteId::new_v7()),
    )
    .await?;
    let revision = current_revision(&harness.store, project_id).await?;
    let trace = influence_trace(task_id);

    let first = CognitiveMemoryWriter::write_memory_influence_trace(
        &writer,
        project_id,
        observability_write_id,
        &trace,
    )
    .await?;
    let after_first = current_revision(&harness.store, project_id).await?;
    let replay = CognitiveMemoryWriter::write_memory_influence_trace(
        &writer,
        project_id,
        observability_write_id,
        &trace,
    )
    .await?;
    let after_replay = current_revision(&harness.store, project_id).await?;
    let records = harness
        .store
        .observability_records_by_kind::<MemoryInfluenceTrace>(
            project_id,
            Some(task_id),
            ObservabilityKind::MemoryInfluenceTrace,
        )
        .await?;

    assert_eq!(first.status, ObservabilityWriteStatus::Committed);
    assert_eq!(replay.status, ObservabilityWriteStatus::IdempotentReplay);
    assert_eq!(after_first, revision);
    assert_eq!(after_replay, revision);
    assert_eq!(records.len(), 1);
    assert!(records[0].canonical_receipt.is_none());
    assert!(
        harness
            .store
            .write_receipt_by_id(&observability_write_id)
            .await?
            .is_none()
    );
    assert!(!harness.raw_record_exists("memory_transition", &observability_write_id.to_string())?);

    drop(writer);
    actor.await?;
    Ok(())
}

async fn submit(
    writer: &WriterHandle,
    command: SemanticCommand,
) -> TestResult<eliot_types::WriteReceipt> {
    Ok(writer
        .submit(WriteAdmissionService.admit(&command)?)
        .await?)
}

async fn current_revision(
    store: &CanonicalStore,
    project_id: ProjectId,
) -> TestResult<eliot_types::MemoryRevision> {
    Ok(store
        .current_state(&CurrentStateRequest {
            project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?
        .memory_revision)
}

fn influence_trace(task_id: TaskId) -> MemoryInfluenceTrace {
    MemoryInfluenceTrace {
        task_id,
        session_id: AgentSessionId::new_v7(),
        memory_handle: "claim:quartz".to_owned(),
        packet_id: "packet:ul-t02".to_owned(),
        admission_decision: MemoryAdmissionDecision::IncludeVerified,
        inclusion_or_suppression_reason: "loaded for bounded verification".to_owned(),
        epistemic_status_at_use: "verified".to_owned(),
        cited_in_understanding_proof: false,
        action_or_probe_changed: false,
        write_set_changed: false,
        verifier_changed: false,
        repeated_failure_prevented: false,
        suppressed_as_stale_or_wrong_scope: false,
        downstream_outcome_ref: None,
        influence_class: MemoryInfluenceClass::SeenButNotUsed,
        canonical_receipt: None,
    }
}

fn task_contract_command(
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
) -> SemanticCommand {
    SemanticCommand::TaskContractWrite(TaskContractWriteCommand {
        context: context(project_id, task_id, write_id, "task-contract"),
        contract: TaskContractInput {
            task_id,
            title: "UL-02 observability truth isolation".to_owned(),
            status: TaskContractStatus::Open,
            acceptance_items: vec![
                TaskAcceptanceItem {
                    item_id: "semantic-seed".to_owned(),
                    description: "semantic revision is seeded".to_owned(),
                    required_evidence: TaskAcceptanceEvidenceKind::Observation,
                    satisfied: false,
                    observation_id: None,
                    verification_id: None,
                    verification_scope_hash: None,
                },
                TaskAcceptanceItem {
                    item_id: "truth-isolation".to_owned(),
                    description: "observability cannot advance truth".to_owned(),
                    required_evidence: TaskAcceptanceEvidenceKind::Verification,
                    satisfied: false,
                    observation_id: None,
                    verification_id: None,
                    verification_scope_hash: None,
                },
            ],
            expected_revision: None,
            action_lease_id: None,
            understanding_proof_hash: None,
            action_provenance: None,
            observation_ids: Vec::new(),
            verification_ids: Vec::new(),
            verification_scopes: Vec::new(),
            completion_proof: None,
            completion_write_id: None,
        },
        observation: None,
        verification: None,
    })
}

fn candidate_command(project_id: ProjectId, task_id: TaskId, write_id: WriteId) -> SemanticCommand {
    SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: context(project_id, task_id, write_id, "candidate"),
        claim: ClaimCardInput {
            claim_id: ClaimId::from_uuid(write_id.as_uuid()),
            statement: "QUARTZ observability is isolated from semantic truth".to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({
                "candidate_only": true,
                "task_id": task_id,
                "topic": "observability-isolation"
            }),
        },
    })
}

fn context(
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
    suffix: &str,
) -> CommandContext {
    CommandContext {
        write_id,
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        scope: format!("task:{task_id}:ul-t02-{suffix}"),
        authority: "ul-t02-test".to_owned(),
        visibility: Visibility::Project,
        taint: TaintClass::ExternalAgent,
        lifecycle_status: LifecycleStatus::Active,
    }
}

fn rerun_with_isolated_credential_backend(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T02_ENGINE_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let credentials =
        eliot_windows_ipc::test_support::IsolatedTestCredentialFixture::new(test_name)?;
    let mut command = Command::new(std::env::current_exe()?);
    credentials.configure_command(&mut command);
    let status = command
        .env("ELIOT_UL_T02_ENGINE_CHILD", test_name)
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
        .args(["--exact", test_name, "--nocapture"])
        .status()?;
    if !status.success() {
        return Err(format!("credential-gated child test failed with {status}").into());
    }
    Ok(true)
}

struct Harness {
    root: PathBuf,
    port: u16,
    surreal_exe: PathBuf,
    store: CanonicalStore,
    surreal: OwnedChild,
}

impl Harness {
    async fn start(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = test_runtime_root()?.join(format!(
            "eliot-ul-t02-engine-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        fs::write(root.join("surreal-root.txt"), "ul-t02-test-secret")?;
        let surreal_exe = pinned_surreal_exe()?;
        let port = test_port()?;
        let surreal = start_surreal(&surreal_exe, port)?;
        wait_for_tcp(port, Duration::from_secs(20))?;

        let mut config = GovernorConfig::default();
        config.db.surreal.exe = slash(&surreal_exe);
        config.db.surreal.bind = format!("127.0.0.1:{port}");
        config.db.surreal.endpoint = format!("ws://127.0.0.1:{port}/rpc");
        "memory".clone_into(&mut config.db.surreal.storage);
        "ultest".clone_into(&mut config.db.surreal.ns);
        "ultest".clone_into(&mut config.db.surreal.db);
        "root".clone_into(&mut config.db.surreal.user);
        config.db.surreal.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        "test-only/ul-t02-engine".clone_into(&mut config.db.surreal.credential_id);
        let run_id = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("test runtime name missing")?;
        config.db.surreal.password_file =
            format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/surreal-root.txt");
        let store = CanonicalStore::new(config.db.surreal);
        store.migrate_schema().await?;
        Ok(Self {
            root,
            port,
            surreal_exe,
            store,
            surreal,
        })
    }

    fn writer(&self) -> TestResult<(WriterHandle, JoinHandle<()>)> {
        let wal = ControlWal::open(&ControlWalConfig {
            path: slash(&self.root.join("control.redb")),
        })?;
        let (writer, actor) =
            WriterActor::channel(wal, self.store.clone(), &WriterConfig::default());
        Ok((writer, tokio::spawn(actor.run())))
    }

    fn raw_record_exists(&self, table: &str, record_id: &str) -> TestResult<bool> {
        let quoted_id = serde_json::to_string(record_id)?;
        let query =
            format!("RETURN (SELECT * FROM ONLY type::record('{table}', {quoted_id})) != NONE;");
        let mut child = Command::new(&self.surreal_exe)
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", "ul-t02-test-secret")
            .arg("sql")
            .arg("--endpoint")
            .arg(format!("ws://127.0.0.1:{}/rpc", self.port))
            .arg("--namespace")
            .arg("ultest")
            .arg("--database")
            .arg("ultest")
            .arg("--json")
            .arg("--hide-welcome")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("SurrealDB SQL stdin missing")?
            .write_all(query.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(format!(
                "SurrealDB SQL failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        parse_single_boolean_sql_result(&output.stdout)
    }
}

fn parse_single_boolean_sql_result(stdout: &[u8]) -> TestResult<bool> {
    let start = stdout
        .iter()
        .position(|byte| *byte == b'[')
        .ok_or("SurrealDB SQL output did not contain a JSON result")?;
    let end = stdout
        .iter()
        .rposition(|byte| *byte == b']')
        .filter(|end| *end >= start)
        .ok_or("SurrealDB SQL output contained an incomplete JSON result")?;
    let value: Value = serde_json::from_slice(&stdout[start..=end])?;
    match value.as_array().map(Vec::as_slice) {
        Some([Value::Bool(found)]) => Ok(*found),
        _ => Err("SurrealDB SQL output was not one boolean result".into()),
    }
}

#[test]
fn surreal_sql_prompt_is_removed_from_boolean_json_result() -> TestResult {
    let stdout = b"ultest/ultest> [false]\r\n\r\nultest/ultest> ";
    assert!(!parse_single_boolean_sql_result(stdout)?);
    Ok(())
}

#[test]
fn surreal_sql_non_boolean_json_result_fails_closed() {
    let stdout = b"ultest/ultest> [\"query failed\"]\r\n\r\nultest/ultest> ";
    assert!(parse_single_boolean_sql_result(stdout).is_err());
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.surreal.stop();
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-t02-engine-"))
            && self
                .root
                .starts_with(test_runtime_root().unwrap_or_else(|_| PathBuf::new()))
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn stop(&mut self) -> TestResult {
        if let Some(mut child) = self.0.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn start_surreal(exe: &Path, port: u16) -> TestResult<OwnedChild> {
    let child = Command::new(exe)
        .env("SURREAL_USER", "root")
        .env("SURREAL_PASS", "ul-t02-test-secret")
        .arg("start")
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--log")
        .arg("warn")
        .arg("--deny-all")
        .arg("--allow-funcs")
        .arg("array,string,time,type,math,vector,search")
        .arg("--deny-net")
        .arg("--")
        .arg("memory")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(OwnedChild(Some(child)))
}

fn pinned_surreal_exe() -> TestResult<PathBuf> {
    let path = std::env::var_os("ELIOT_SURREAL_EXE").map_or_else(
        || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        PathBuf::from,
    );
    let output = Command::new(&path).arg("version").output()?;
    let version = String::from_utf8(output.stdout)?;
    if !output.status.success() || !version.trim().starts_with("3.1.4") {
        return Err(format!("UL-02 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn test_port() -> TestResult<u16> {
    for port in 8700..=8799 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no free UL-02 engine test port in 8700-8799".into())
}

fn wait_for_tcp(port: u16, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(format!("SurrealDB did not listen on port {port}").into())
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn test_runtime_root() -> TestResult<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?)
            .join("Eliot")
            .join("tests"),
    )
}
