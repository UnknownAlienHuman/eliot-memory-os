use eliot_engine::{ReadService, WriteAdmissionService, WriterActor, WriterConfig, WriterHandle};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, CommandContext, ControlWalConfig, CredentialProviderKind,
    EpistemicStatus, FetchAtomsL2Request, GovernorConfig, LifecycleStatus, ProjectId,
    ReadConsistencyMode, RelationType, SemanticCommand, TaintClass, TaskAcceptanceEvidenceKind,
    TaskAcceptanceItem, TaskContractInput, TaskContractStatus, TaskContractWriteCommand, TaskId,
    Visibility, WriteId,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t01_candidate_creates_one_belongs_to_edge() -> TestResult {
    if rerun_with_legacy_credential_gate("t01_candidate_creates_one_belongs_to_edge")? {
        return Ok(());
    }
    let harness = Harness::start("candidate-belongs-to").await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let write_id = WriteId::new_v7();
    let claim_id = ClaimId::from_uuid(write_id.as_uuid());
    let (writer, actor) = harness.writer()?;

    submit(
        &writer,
        task_contract_command(project_id, task_id, WriteId::new_v7()),
    )
    .await?;
    let candidate = candidate_command(project_id, task_id, write_id, claim_id);
    let first = submit(&writer, candidate.clone()).await?;
    let replay = submit(&writer, candidate).await?;
    drop(writer);
    actor.await?;

    let revision = first
        .memory_revision
        .ok_or("candidate receipt has no memory revision")?;
    let l2 = ReadService::new(harness.store.clone())
        .fetch_atoms_l2(&FetchAtomsL2Request {
            project_id,
            handles: vec![format!("claim:{claim_id}")],
            continuation: None,
            consistency: ReadConsistencyMode::AtLeastRevision,
            at_least_revision: Some(revision),
        })
        .await?;
    let belongs_to = l2
        .relations
        .iter()
        .filter(|relation| {
            relation.relation_type == RelationType::BelongsTo
                && relation.from == claim_id.to_string()
                && relation.to == task_id.to_string()
        })
        .count();

    assert_eq!(l2.claims.len(), 1);
    assert_eq!(belongs_to, 1);
    assert_eq!(first.created_relations.len(), 1);
    assert_eq!(replay.created_relations.len(), 1);
    Ok(())
}

fn rerun_with_legacy_credential_gate(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T01_CREDENTIAL_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let status = Command::new(std::env::current_exe()?)
        .env("ELIOT_UL_T01_CREDENTIAL_CHILD", test_name)
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
        .env("ELIOT_TEST_ALLOW_LEGACY_OPERATOR_CURSOR_KEY_FILE", "1")
        .args(["--exact", test_name, "--nocapture"])
        .status()?;
    if !status.success() {
        return Err(format!("credential-gated child test failed with {status}").into());
    }
    Ok(true)
}

async fn submit(
    writer: &WriterHandle,
    command: SemanticCommand,
) -> TestResult<eliot_types::WriteReceipt> {
    Ok(writer
        .submit(WriteAdmissionService.admit(&command)?)
        .await?)
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
            title: "UL-01 ownership edge".to_owned(),
            status: TaskContractStatus::Open,
            acceptance_items: vec![
                TaskAcceptanceItem {
                    item_id: "candidate".to_owned(),
                    description: "candidate is written".to_owned(),
                    required_evidence: TaskAcceptanceEvidenceKind::Observation,
                    satisfied: false,
                    observation_id: None,
                    verification_id: None,
                    verification_scope_hash: None,
                },
                TaskAcceptanceItem {
                    item_id: "edge".to_owned(),
                    description: "ownership edge is written".to_owned(),
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
            completion_write_id: None,
        },
        observation: None,
        verification: None,
    })
}

fn candidate_command(
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
    claim_id: ClaimId,
) -> SemanticCommand {
    SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: context(project_id, task_id, write_id, "candidate"),
        claim: ClaimCardInput {
            claim_id,
            statement: "QUARTZ parser belongs to the configuration task".to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({
                "candidate_only": true,
                "task_id": task_id,
                "topic": "belongs_to:quartz"
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
        scope: format!("task:{task_id}:ul-t01-{suffix}"),
        authority: "ul-t01-test".to_owned(),
        visibility: Visibility::Project,
        taint: TaintClass::ExternalAgent,
        lifecycle_status: LifecycleStatus::Active,
    }
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
    surreal: OwnedChild,
}

impl Harness {
    async fn start(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = test_runtime_root()?.join(format!(
            "eliot-ul-t01-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        let password_file = root.join("surreal-root.txt");
        fs::write(&password_file, "ul-t01-test-secret")?;
        let surreal_exe = pinned_surreal_exe()?;
        let port = test_port()?;
        let surreal = start_surreal(&surreal_exe, port)?;
        wait_for_tcp(port, Duration::from_secs(20))?;

        let mut config = GovernorConfig::default();
        config.db.surreal.exe = slash(&surreal_exe);
        config.db.surreal.bind = format!("127.0.0.1:{port}");
        config.db.surreal.endpoint = format!("ws://127.0.0.1:{port}/rpc");
        config.db.surreal.storage = format!("rocksdb:{}", slash(&root.join("unused-rocksdb")));
        "ultest".clone_into(&mut config.db.surreal.ns);
        "ultest".clone_into(&mut config.db.surreal.db);
        "root".clone_into(&mut config.db.surreal.user);
        config.db.surreal.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        "test-only/ul-t01-engine".clone_into(&mut config.db.surreal.credential_id);
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
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.surreal.stop();
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-t01-"))
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
        .env("SURREAL_PASS", "ul-t01-test-secret")
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
        return Err(format!("UL-01 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn test_port() -> TestResult<u16> {
    for port in 8500..=8599 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no free UL-01 test port in 8500-8599".into())
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
