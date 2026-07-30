use eliot_store::CanonicalStore;
use eliot_types::{
    CredentialProviderKind, GovernorConfig, ProjectId, TaskId, UlExperimentArm, UlInjectionMode,
    UlTaskClass, UlTaskClassPolicy,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn u9_1_assignment_is_stable_across_restart_and_project_scoped() -> TestResult {
    const TEST_NAME: &str = "u9_1_assignment_is_stable_across_restart_and_project_scoped";
    if std::env::var("ELIOT_UL_U9_STORE_CHILD").as_deref() != Ok(TEST_NAME) {
        let credentials =
            eliot_windows_ipc::test_support::IsolatedTestCredentialFixture::new(TEST_NAME)?;
        let mut command = Command::new(std::env::current_exe()?);
        credentials.configure_command(&mut command);
        let status = command
            .env("ELIOT_UL_U9_STORE_CHILD", TEST_NAME)
            .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
            .args(["--exact", TEST_NAME, "--nocapture"])
            .status()?;
        if !status.success() {
            return Err(format!("credential-gated child test failed with {status}").into());
        }
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_store_test())
}

async fn run_store_test() -> TestResult {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let run_id = format!("eliot-ul-u9-store-{}-{nonce}", std::process::id());
    let root = test_root()?.join(&run_id);
    fs::create_dir_all(&root)?;
    fs::write(root.join("surreal-root.txt"), "ul-u9-test-secret")?;
    let surreal_exe = pinned_surreal_exe()?;
    let port = available_port()?;
    let mut surreal = start_surreal(&surreal_exe, port)?;
    wait_for_tcp(port, Duration::from_secs(20))?;

    let mut config = GovernorConfig::default().db.surreal;
    config.exe = slash(&surreal_exe);
    config.bind = format!("127.0.0.1:{port}");
    config.endpoint = format!("ws://127.0.0.1:{port}/rpc");
    "memory".clone_into(&mut config.storage);
    "ultest".clone_into(&mut config.ns);
    "ultest".clone_into(&mut config.db);
    "root".clone_into(&mut config.user);
    config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    "test-only/ul-u9-store".clone_into(&mut config.credential_id);
    config.password_file = format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/surreal-root.txt");

    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;
    let project_a = ProjectId::new_v7();
    let project_b = ProjectId::new_v7();
    let task_a = TaskId::new_v7();
    let task_b = TaskId::new_v7();
    let task_other_project = TaskId::new_v7();
    let class = UlTaskClass {
        action_class: "single_file".to_owned(),
        subsystem: "concept:alpha".to_owned(),
        artifact_class: "code".to_owned(),
    };

    let first = store
        .assign_ul_experiment_arm(project_a, task_a, &class, "config-v1")
        .await?;
    let replay = store
        .assign_ul_experiment_arm(project_a, task_a, &class, "different-config")
        .await?;
    let second = store
        .assign_ul_experiment_arm(project_a, task_b, &class, "config-v1")
        .await?;
    let isolated = store
        .assign_ul_experiment_arm(project_b, task_other_project, &class, "config-v1")
        .await?;

    assert_eq!(first.arm, UlExperimentArm::Control);
    assert_eq!(first.ordinal, 1);
    assert_eq!(replay, first);
    assert_eq!(second.arm, UlExperimentArm::Treatment);
    assert_eq!(second.ordinal, 2);
    assert_eq!(isolated.arm, UlExperimentArm::Control);
    assert_eq!(isolated.ordinal, 1);

    let policy = UlTaskClassPolicy {
        project_id: project_a,
        task_class_key: class.key(),
        injection_mode: UlInjectionMode::HandlesOnly,
        treatment_tasks: 10,
        control_tasks: 5,
        control_median_exploration_tokens: 25,
        treatment_median_net_delta: 4,
        reason: "positive_median_net_token_delta".to_owned(),
        evidence_task_ids: vec![task_a, task_b],
    };
    store.upsert_ul_task_class_policy(&policy).await?;

    let restarted = CanonicalStore::new(config);
    assert_eq!(
        restarted
            .load_ul_experiment_assignment(project_a, task_a)
            .await?,
        Some(first)
    );
    assert_eq!(
        restarted
            .load_ul_task_class_policy(project_a, &class.key())
            .await?,
        Some(policy)
    );

    stop_child(&mut surreal)?;
    if root.starts_with(test_root()?) {
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn start_surreal(exe: &Path, port: u16) -> TestResult<OwnedChild> {
    Ok(OwnedChild(
        Command::new(exe)
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", "ul-u9-test-secret")
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
            .spawn()?,
    ))
}

fn stop_child(child: &mut OwnedChild) -> TestResult {
    if child.0.try_wait()?.is_none() {
        child.0.kill()?;
    }
    let _ = child.0.wait()?;
    Ok(())
}

fn wait_for_tcp(port: u16, timeout: Duration) -> TestResult {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(format!("SurrealDB did not listen on port {port}").into())
}

fn available_port() -> TestResult<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn pinned_surreal_exe() -> TestResult<PathBuf> {
    let path = std::env::var_os("ELIOT_SURREAL_EXE").map_or_else(
        || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        PathBuf::from,
    );
    let output = Command::new(&path).arg("version").output()?;
    let version = String::from_utf8(output.stdout)?;
    if !output.status.success() || !version.trim().starts_with("3.1.4") {
        return Err(format!("UL-09 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn test_root() -> TestResult<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?)
            .join("Eliot")
            .join("tests"),
    )
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
