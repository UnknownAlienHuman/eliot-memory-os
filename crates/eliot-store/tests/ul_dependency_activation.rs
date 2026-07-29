use eliot_store::CanonicalStore;
use eliot_types::{
    CredentialProviderKind, GovernorConfig, ProjectId, PyramidTargetKind, UlArtifactDirtyState,
    UlDependencyKind, UlDependencyRef, UlDirtyReason,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn u8_2_reverse_index_dirty_state_survives_store_restart() -> TestResult {
    const TEST_NAME: &str = "u8_2_reverse_index_dirty_state_survives_store_restart";
    if std::env::var("ELIOT_UL_U8_STORE_CHILD").as_deref() != Ok(TEST_NAME) {
        let status = Command::new(std::env::current_exe()?)
            .env("ELIOT_UL_U8_STORE_CHILD", TEST_NAME)
            .env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1")
            .env("ELIOT_TEST_ALLOW_LEGACY_OPERATOR_CURSOR_KEY_FILE", "1")
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
    let run_id = format!("eliot-ul-u8-store-{}-{nonce}", std::process::id());
    let root = test_root()?.join(&run_id);
    fs::create_dir_all(&root)?;
    fs::write(root.join("surreal-root.txt"), "ul-u8-test-secret")?;
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
    "test-only/ul-u8-store".clone_into(&mut config.credential_id);
    config.password_file = format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/surreal-root.txt");

    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let dependency = UlDependencyRef {
        kind: UlDependencyKind::File,
        key: "src/a.rs".to_owned(),
    };
    store
        .replace_ul_reverse_dependencies(
            project_id,
            PyramidTargetKind::SubsystemCapsule,
            "concept:a",
            "build:a",
            std::slice::from_ref(&dependency),
        )
        .await?;
    let rows = store
        .load_ul_reverse_dependents(project_id, std::slice::from_ref(&dependency))
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_id, "concept:a");

    let now = OffsetDateTime::now_utc();
    store
        .mark_ul_artifact_dirty(&UlArtifactDirtyState {
            project_id,
            target_kind: PyramidTargetKind::SubsystemCapsule,
            target_id: "concept:a".to_owned(),
            build_id: "build:a".to_owned(),
            dirty: true,
            reasons: vec![UlDirtyReason {
                dependency: dependency.clone(),
                expected_fingerprint: Some("old".to_owned()),
                observed_fingerprint: Some("new".to_owned()),
                event_ref: "tool:test".to_owned(),
            }],
            first_dirty_at: now,
            updated_at: now,
        })
        .await?;

    let restarted = CanonicalStore::new(config);
    let dirty = restarted.load_ul_dirty_artifacts(project_id, 10).await?;
    assert_eq!(dirty.len(), 1);
    assert_eq!(dirty[0].reasons[0].dependency, dependency);
    assert!(
        restarted
            .load_ul_reverse_dependents(
                project_id,
                &[UlDependencyRef {
                    kind: UlDependencyKind::File,
                    key: "src/unrelated.rs".to_owned(),
                }],
            )
            .await?
            .is_empty()
    );

    stop_child(&mut surreal)?;
    if root.starts_with(test_root()?) {
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn start_surreal(exe: &Path, port: u16) -> TestResult<Child> {
    Ok(Command::new(exe)
        .env("SURREAL_USER", "root")
        .env("SURREAL_PASS", "ul-u8-test-secret")
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
        .spawn()?)
}

fn stop_child(child: &mut Child) -> TestResult {
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    let _ = child.wait()?;
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
        return Err(format!("UL-08 requires SurrealDB 3.1.4, got {}", version.trim()).into());
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
