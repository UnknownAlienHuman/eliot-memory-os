use eliot_engine::{
    CueIndexService, WriteAdmissionService, WriterActor, WriterConfig, WriterHandle,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    AgentCandidateSubmitInput, AgentId, ClaimCardInput, ClaimId, CommandContext, ControlWalConfig,
    CredentialProviderKind, CueBinding, CueKind, CueMatchMode, CueStrength, EpistemicStatus,
    GovernorConfig, LifecycleStatus, ProjectId, SemanticCommand, TaintClass, TaskId, Visibility,
    WriteId, normalize_bindings,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn t03_candidate_persists_normalized_bindings() -> TestResult {
    if rerun_with_legacy_credential_gate("t03_candidate_persists_normalized_bindings")? {
        return Ok(());
    }
    let harness = Harness::start(8904).await?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let write_id = WriteId::new_v7();
    let claim_id = ClaimId::from_uuid(write_id.as_uuid());
    let mut input = AgentCandidateSubmitInput {
        project_id: project_id.to_string(),
        task_id: task_id.to_string(),
        write_id: write_id.to_string(),
        topic: "canonical store cue".to_owned(),
        statement: "The canonical store path is reusable.".to_owned(),
        where_applicable: Vec::new(),
        where_not_applicable: Vec::new(),
        negative_constraints: Vec::new(),
        provenance_refs: vec!["task:03".to_owned()],
        freshness_rule: "recheck after path changes".to_owned(),
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: r"Crates\Eliot-Store\src\LIB.rs".to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "Reuse for canonical store edits.".to_owned(),
        }],
        auto_bind: None,
        expected_reuse_note: "Reuse when the canonical store is active.".to_owned(),
        curation: None,
    };
    input.cue_bindings = normalize_bindings(input.cue_bindings, None)?;
    let payload = json!({
        "candidate_only": true,
        "controller_reconciliation_required": true,
        "task_id": task_id,
        "topic": input.topic,
        "statement": input.statement,
        "where_applicable": input.where_applicable,
        "where_not_applicable": input.where_not_applicable,
        "negative_constraints": input.negative_constraints,
        "provenance_refs": input.provenance_refs,
        "freshness_rule": input.freshness_rule,
        "cue_bindings": input.cue_bindings,
        "expected_reuse_note": input.expected_reuse_note,
        "curation": input.curation,
    });
    let command = SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: Some(task_id),
            scope: format!("task:{task_id}:agent-candidate-memory"),
            authority: "mcp-profile:dynamic_agent".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::ExternalAgent,
            lifecycle_status: LifecycleStatus::Active,
        },
        claim: ClaimCardInput {
            claim_id,
            statement: "The canonical store path is reusable.".to_owned(),
            status: EpistemicStatus::Candidate,
            payload,
        },
    });
    let (writer, actor) = harness.writer()?;
    let receipt = writer
        .submit(WriteAdmissionService.admit(&command)?)
        .await?;
    assert!(matches!(
        receipt.status,
        eliot_types::WriteStatus::Committed | eliot_types::WriteStatus::IdempotentReplay
    ));
    let claim = harness
        .store
        .claim_card_by_id(project_id, claim_id)
        .await?
        .ok_or("candidate claim missing")?;
    let bindings: Vec<CueBinding> = serde_json::from_value(claim.payload["cue_bindings"].clone())?;
    CueIndexService::new(harness.store.clone())
        .replace_record_bindings(
            project_id,
            &format!("claim:{claim_id}"),
            "claim",
            &claim.statement,
            &bindings,
            false,
        )
        .await?;
    let rows = harness.store.load_cue_rows(project_id).await?;

    assert_eq!(
        claim.payload["cue_bindings"][0]["cue_value"],
        "crates/eliot-store/src/lib.rs"
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cue_value_norm, "crates/eliot-store/src/lib.rs");
    assert_eq!(rows[0].record_ref, format!("claim:{claim_id}"));

    drop(writer);
    actor.await?;
    Ok(())
}

fn rerun_with_legacy_credential_gate(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T03_APP_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let status = Command::new(std::env::current_exe()?)
        .env("ELIOT_UL_T03_APP_CHILD", test_name)
        .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
        .env("ELIOT_TEST_ALLOW_LEGACY_OPERATOR_CURSOR_KEY_FILE", "1")
        .args(["--exact", test_name, "--nocapture"])
        .status()?;
    if !status.success() {
        return Err(format!("credential-gated child test failed with {status}").into());
    }
    Ok(true)
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
    surreal: OwnedChild,
}

impl Harness {
    async fn start(port: u16) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root =
            test_runtime_root()?.join(format!("eliot-ul-t03-app-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root)?;
        fs::write(root.join("surreal-root.txt"), "ul-t03-test-secret")?;
        ensure_port_available(port)?;
        let surreal_exe = pinned_surreal_exe()?;
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
        "test-only/ul-t03-app".clone_into(&mut config.db.surreal.credential_id);
        let run_id = root
            .file_name()
            .and_then(|value| value.to_str())
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
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("eliot-ul-t03-app-"))
            && self
                .root
                .starts_with(test_runtime_root().unwrap_or_default())
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
        .env("SURREAL_PASS", "ul-t03-test-secret")
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
        return Err(format!("UL-03 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn ensure_port_available(port: u16) -> TestResult {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|error| format!("UL-03 app test port {port} is unavailable: {error}"))?;
    drop(listener);
    Ok(())
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

fn test_runtime_root() -> TestResult<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?)
            .join("Eliot")
            .join("tests"),
    )
}

fn slash(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}
