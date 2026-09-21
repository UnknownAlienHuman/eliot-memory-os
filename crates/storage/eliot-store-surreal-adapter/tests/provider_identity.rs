//! Live proved-provider identity proof (issues #1932/#1933).
//!
//! Spawns a real temporary `surreal.exe` provider (loopback bind,
//! per-test temporary roots, pinned test binary) and proves over the
//! ownership-verified channel that:
//! - no identity exists before connect (`None`);
//! - after connect the adapter reports the live `provider.version` triple
//!   plus the spawn-validated artifact digest, agreeing with the artifact
//!   binary's own version output;
//! - `note_connection_loss` invalidates the claim (`None` again).
//! No in-memory stand-in, no record echo, no CLI output as identity.

#![allow(clippy::expect_used)]

use eliot_platform_windows::WindowsPlatform;
use eliot_store_api::sha256_hex;
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::SecretString;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
const TEST_USER: &str = "identity-test";
const TEST_SECRET: &str = "identity-test-secret";

fn surreal_exe() -> PathBuf {
    std::env::var("ELIOT_TEST_SURREAL_EXE")
        .map_or_else(|_| PathBuf::from(TEST_SURREAL_EXE), PathBuf::from)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("loopback")
        .local_addr()
        .expect("port")
        .port()
}

fn adapter_config(
    exe: &Path,
    digest: String,
    bind: String,
    data: &Path,
    work: &Path,
    tmp: &Path,
) -> SurrealAdapterConfig {
    let mut config = SurrealAdapterConfig {
        endpoint: format!("ws://{bind}/rpc"),
        namespace: "eliot".to_owned(),
        database: "identity_1932".to_owned(),
        username: TEST_USER.to_owned(),
        password: SecretString::new(TEST_SECRET.into()),
        provider_bind_address: bind,
        installation_id: "installation-test-identity".to_owned(),
        installation_profile: "portable_dev".to_owned(),
        runtime_state_roots_digest: "a".repeat(64),
        provider_executable_path: exe.to_string_lossy().into_owned(),
        provider_artifact_digest: digest,
        provider_arguments: Vec::new(),
        store_data_root: data.to_string_lossy().into_owned(),
        store_work_root: work.to_string_lossy().into_owned(),
        store_temp_root: tmp.to_string_lossy().into_owned(),
        connect_timeout_ms: 60_000,
        query_timeout_ms: 30_000,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: SchemaGeneration::v2(),
    };
    config.provider_arguments = config.expected_provider_arguments();
    config
}

fn prepare_initial_root_user(exe: &Path, bind: &str, data: &Path, work: &Path, tmp: &Path) {
    let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut child = std::process::Command::new(exe)
        .args([
            "start",
            "--no-banner",
            "--bind",
            bind,
            "--username",
            TEST_USER,
            "--password",
            TEST_SECRET,
            "--temporary-directory",
            &tmp.to_string_lossy(),
            &data_url,
        ])
        .current_dir(work)
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("WINDIR", &system_root)
        .env("TEMP", tmp)
        .env("TMP", tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("preparation provider");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if std::net::TcpStream::connect(bind).is_ok() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("preparation provider never bound {bind}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(2));
    child.kill().expect("stop preparation provider");
    let _ = child.wait();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::net::TcpStream::connect(bind).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "preparation provider never released {bind}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(1));
}

/// Triple reported by the artifact binary itself (`surreal.exe version`
/// prints `<semver> for windows on ...`); used only to cross-check the live
/// RPC observation of the same bytes, never as identity.
fn artifact_version_triple(exe: &Path) -> (u16, u16, u16) {
    let output = std::process::Command::new(exe)
        .arg("version")
        .output()
        .expect("artifact version output");
    assert!(output.status.success(), "artifact reports its version");
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.split_whitespace().next().expect("version token");
    let mut parts = first.split('.');
    let triple = (
        parts.next().expect("major").parse::<u16>().expect("major"),
        parts.next().expect("minor").parse::<u16>().expect("minor"),
        parts.next().expect("patch").parse::<u16>().expect("patch"),
    );
    assert!(parts.next().is_none(), "exact triple: {first}");
    triple
}

struct Harness {
    root: PathBuf,
    adapter: Option<SurrealStoreAdapter>,
    digest: String,
}

impl Harness {
    async fn provision() -> Self {
        let port = free_port();
        let root =
            std::env::temp_dir().join(format!("eliot-identity-1932-{}-{port}", std::process::id()));
        let bin = root.join("bin");
        let data = root.join("store").join("data");
        let work = root.join("store").join("work");
        let tmp = root.join("store").join("tmp");
        for dir in [&bin, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("test dirs");
        }
        let source_exe = surreal_exe();
        let exe = bin.join("surreal.exe");
        std::fs::copy(&source_exe, &exe).expect("stage provider");
        let digest = sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
        println!(
            "identity provider: exe={} sha256={} port={}",
            exe.display(),
            digest,
            port
        );
        let platform = WindowsPlatform::new(root.clone()).expect("platform");
        let bind = format!("127.0.0.1:{port}");
        prepare_initial_root_user(&exe, &bind, &data, &work, &tmp);
        let lease = platform
            .retain_process_path_lease(&exe, &work, &digest)
            .expect("process lease");
        let config = adapter_config(&exe, digest.clone(), bind, &data, &work, &tmp);
        let adapter = SurrealStoreAdapter::new(config, lease).expect("adapter");
        Self {
            root,
            adapter: Some(adapter),
            digest,
        }
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_ref().expect("adapter live")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.adapter = None;
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn live_connect_proves_identity_and_loss_invalidates() {
    let harness = Harness::provision().await;
    // No authenticated session exists before connect: no identity to claim.
    assert_eq!(harness.adapter().authenticated_provider_identity(), None);
    harness.adapter().connect().await.expect("provider connect");
    // The live RPC triple agrees with the artifact binary's own output for
    // the same staged bytes, and the digest is the spawn-validated one.
    let observed = harness
        .adapter()
        .authenticated_provider_identity()
        .expect("proved identity after connect");
    let (major, minor, patch) =
        artifact_version_triple(&harness.root.join("bin").join("surreal.exe"));
    assert_eq!(observed.version_major, major);
    assert_eq!(observed.version_minor, minor);
    assert_eq!(observed.version_patch, patch);
    assert_eq!(observed.version_major, PINNED_SURREALDB_MAJOR);
    assert_eq!(observed.artifact_digest, harness.digest);
    println!(
        "identity observed: {major}.{minor}.{patch} sha256={} (live RPC agrees with artifact)",
        harness.digest
    );
    // Observed connection loss invalidates the claim until re-proof.
    harness.adapter().note_connection_loss();
    assert_eq!(harness.adapter().authenticated_provider_identity(), None);
}
