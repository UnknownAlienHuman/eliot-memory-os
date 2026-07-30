use eliot_engine::{CueIndexService, ObservedCue};
use eliot_store::CanonicalStore;
use eliot_types::{
    CredentialProviderKind, CueIndexRow, CueKind, CueMatchMode, CueStrength, GovernorConfig,
    ProjectId, cue_row_id, ul_token_estimate,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const PATH_CUE: &str = "crates/eliot-store/src/lib.rs";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_firing_order_and_cap() -> TestResult {
    if rerun_with_isolated_credential_backend("t03_firing_order_and_cap")? {
        return Ok(());
    }
    let harness = Harness::start("order", 8901).await?;
    let project = ProjectId::new_v7();
    let records = [
        (
            "failure:a",
            "failure_fingerprint",
            CueStrength::Secondary,
            true,
        ),
        (
            "failure:b",
            "failure_fingerprint",
            CueStrength::Primary,
            true,
        ),
        ("invariant:a", "invariant", CueStrength::Primary, false),
        ("decision:a", "decision", CueStrength::Primary, false),
        ("claim:a", "claim", CueStrength::Primary, false),
        ("claim:b", "claim", CueStrength::Primary, false),
        ("claim:c", "claim", CueStrength::Secondary, false),
        ("skill:a", "skill", CueStrength::Primary, false),
        ("module:a", "module_card", CueStrength::Primary, false),
        (
            "subsystem:a",
            "subsystem_capsule",
            CueStrength::Primary,
            false,
        ),
    ];
    for (record_ref, record_kind, strength, negative) in records {
        let row = row(
            project,
            record_ref,
            record_kind,
            strength,
            negative,
            "active",
        );
        harness
            .store
            .replace_cue_rows(project, record_ref, &[row])
            .await?;
    }

    let result = CueIndexService::new(harness.store.clone())
        .fire(project, &[file_cue()])
        .await?;
    let refs = result
        .fired
        .iter()
        .map(|memory| memory.record_ref.as_str())
        .collect::<Vec<_>>();

    assert_eq!(result.fired.len(), 8);
    assert_eq!(result.matched, 10);
    assert_eq!(result.deduplicated, 0);
    assert_eq!(result.suppressed, 0);
    assert_eq!(result.overflow, 2);
    assert_eq!(&refs[..2], ["failure:b", "failure:a"]);
    assert!(
        refs.iter().position(|item| *item == "claim:a")
            < refs.iter().position(|item| *item == "claim:b")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_rebuild_after_restart_is_identical() -> TestResult {
    if rerun_with_isolated_credential_backend("t03_rebuild_after_restart_is_identical")? {
        return Ok(());
    }
    let harness = Harness::start("restart", 8902).await?;
    let project = ProjectId::new_v7();
    harness
        .store
        .replace_cue_rows(
            project,
            "claim:restart",
            &[row(
                project,
                "claim:restart",
                "claim",
                CueStrength::Primary,
                false,
                "active",
            )],
        )
        .await?;

    let first_service = CueIndexService::new(harness.store.clone());
    let first = first_service.fire(project, &[file_cue()]).await?;
    drop(first_service);
    let second = CueIndexService::new(harness.store.clone())
        .fire(project, &[file_cue()])
        .await?;
    assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_no_cross_project_or_stale_leak() -> TestResult {
    if rerun_with_isolated_credential_backend("t03_no_cross_project_or_stale_leak")? {
        return Ok(());
    }
    let harness = Harness::start("scope", 8903).await?;
    let project_a = ProjectId::new_v7();
    let project_b = ProjectId::new_v7();
    for (record_ref, lifecycle) in [("claim:a", "active"), ("claim:stale", "suppressed")] {
        harness
            .store
            .replace_cue_rows(
                project_a,
                record_ref,
                &[row(
                    project_a,
                    record_ref,
                    "claim",
                    CueStrength::Primary,
                    false,
                    lifecycle,
                )],
            )
            .await?;
    }
    harness
        .store
        .replace_cue_rows(
            project_b,
            "claim:b",
            &[row(
                project_b,
                "claim:b",
                "claim",
                CueStrength::Primary,
                false,
                "active",
            )],
        )
        .await?;

    let result = CueIndexService::new(harness.store.clone())
        .fire(project_a, &[file_cue()])
        .await?;
    assert_eq!(result.matched, 2);
    assert_eq!(result.deduplicated, 0);
    assert_eq!(result.suppressed, 1);
    assert_eq!(result.overflow, 0);
    assert_eq!(result.fired.len(), 1);
    assert_eq!(result.fired[0].record_ref, "claim:a");
    assert!(
        result
            .fired
            .iter()
            .all(|memory| memory.record_ref != "claim:b")
    );
    Ok(())
}

fn file_cue() -> ObservedCue {
    ObservedCue {
        kind: CueKind::FilePath,
        value: PATH_CUE.to_owned(),
    }
}

fn row(
    project_id: ProjectId,
    record_ref: &str,
    record_kind: &str,
    strength: CueStrength,
    negative_memory: bool,
    lifecycle: &str,
) -> CueIndexRow {
    CueIndexRow {
        row_id: cue_row_id(project_id, CueKind::FilePath, PATH_CUE, record_ref),
        project_id,
        cue_kind: CueKind::FilePath,
        cue_value_norm: PATH_CUE.to_owned(),
        match_mode: CueMatchMode::Exact,
        record_ref: record_ref.to_owned(),
        record_kind: record_kind.to_owned(),
        strength,
        negative_memory,
        lifecycle: lifecycle.to_owned(),
        token_estimate: ul_token_estimate(record_ref),
    }
}

fn rerun_with_isolated_credential_backend(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T03_ENGINE_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let credentials =
        eliot_windows_ipc::test_support::IsolatedTestCredentialFixture::new(test_name)?;
    let mut command = Command::new(std::env::current_exe()?);
    credentials.configure_command(&mut command);
    let status = command
        .env("ELIOT_UL_T03_ENGINE_CHILD", test_name)
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
    store: CanonicalStore,
    surreal: OwnedChild,
}

impl Harness {
    async fn start(name: &str, port: u16) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = test_runtime_root()?.join(format!(
            "eliot-ul-t03-engine-{name}-{}-{nonce}",
            std::process::id()
        ));
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
        "test-only/ul-t03-engine".clone_into(&mut config.db.surreal.credential_id);
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
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.surreal.stop();
        if self
            .root
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("eliot-ul-t03-engine-"))
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
        .map_err(|error| format!("UL-03 test port {port} is unavailable: {error}"))?;
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
