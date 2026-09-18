//! Bounded session-set guards for S-CONC-CLIENTS (issue #987).
//!
//! The live lane behavior (shared generation, bounded checkout, role
//! isolation) executes as inline native tests in
//! `src/client/session_pool.rs`, where the crate-private pool surface is
//! reachable. This integration target proves, without a provider:
//!
//! - every finite fixture profile in `data/rpc_session_pool.json`
//!   validates (or refuses) through the public [`ClientSetLimits`] API;
//! - the public constructors bind the expected profile without changing any
//!   existing `SurrealAdapterConfig` struct literal;
//! - the pool seam keeps its fixed structural contract (roles, bounds,
//!   facade compatibility, single-process ownership).
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use eliot_store_api::{GENESIS_MANIFEST_NAME, generated_operation_manifests};
use eliot_store_surreal_adapter::{
    ClientSetLimits, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::SecretString;
use serde_json::Value;
use uuid::Uuid;

fn descriptor() -> Value {
    serde_json::from_str(include_str!("data/rpc_session_pool.json")).expect("pool fixture")
}

fn source(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("current source")
}

fn limits(value: &Value) -> ClientSetLimits {
    ClientSetLimits::new(
        value["read_sessions"].as_u64().expect("read") as u8,
        value["write_sessions"].as_u64().expect("write") as u8,
        value["admin_sessions"].as_u64().expect("admin") as u8,
    )
    .expect("fixture profile is valid")
}

/// Builds an isolated, never-started adapter composition: staged provider
/// bytes and a retained lease prove construction, but no process spawns and
/// no socket connects here.
fn isolated_config(root: &Path) -> (SurrealAdapterConfig, PathBuf) {
    let exe = root.join("bin/surreal.exe");
    std::fs::create_dir_all(root.join("bin")).expect("bin");
    std::fs::create_dir_all(root.join("store/data")).expect("data");
    std::fs::create_dir_all(root.join("store/work")).expect("work");
    std::fs::create_dir_all(root.join("store/tmp")).expect("tmp");
    let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
        || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        PathBuf::from,
    );
    std::fs::copy(provider, &exe).expect("stage provider");
    let bind = "127.0.0.1:18001";
    let mut config = SurrealAdapterConfig {
        endpoint: format!("ws://{bind}/rpc"),
        namespace: "pool987".into(),
        database: "selected987".into(),
        username: "pool987-user".into(),
        password: SecretString::new("redacted-987".into()),
        provider_bind_address: bind.into(),
        installation_id: "pool987".into(),
        installation_profile: "portable_dev".into(),
        runtime_state_roots_digest: "a".repeat(64),
        provider_executable_path: exe.to_string_lossy().into_owned(),
        provider_artifact_digest: eliot_store_api::sha256_hex(
            &std::fs::read(&exe).expect("provider bytes"),
        ),
        provider_arguments: Vec::new(),
        store_data_root: root.join("store/data").to_string_lossy().into_owned(),
        store_work_root: root.join("store/work").to_string_lossy().into_owned(),
        store_temp_root: root.join("store/tmp").to_string_lossy().into_owned(),
        connect_timeout_ms: 1_000,
        query_timeout_ms: 1_000,
        expected_provider_major: eliot_store_surreal_adapter::PINNED_SURREALDB_MAJOR,
        expected_schema_generation: SchemaGeneration::v2(),
    };
    config.provider_arguments = config.expected_provider_arguments();
    (config, exe)
}

// WORK_UNIT_CASE: 987/10
#[test]
fn fixture_profiles_validate_through_the_public_limits_api() {
    let descriptor = descriptor();
    for (name, profile) in descriptor["profiles"].as_object().expect("profiles") {
        let parsed = limits(profile);
        assert_eq!(
            parsed.total_sessions(),
            match name.as_str() {
                "compatibility" => 3,
                "concurrent_lanes" => 5,
                "maximal" => 24,
                unexpected => panic!("unlisted profile {unexpected}"),
            }
        );
    }
    assert_eq!(descriptor["invalid"].as_array().expect("invalid").len(), 5);
    for profile in descriptor["invalid"].as_array().expect("invalid") {
        assert!(
            ClientSetLimits::new(
                profile["read_sessions"].as_u64().expect("read") as u8,
                profile["write_sessions"].as_u64().expect("write") as u8,
                profile["admin_sessions"].as_u64().expect("admin") as u8,
            )
            .is_err(),
            "invalid profile accepted: {profile}"
        );
    }
}

// WORK_UNIT_CASE: 987/11
/// Windows-only: construction binds a retained executable lease, which needs
/// the staged provider bytes. No process spawns and no socket connects here.
#[cfg(windows)]
#[test]
fn public_constructors_bind_the_expected_profile_without_config_churn() {
    let facade_root = std::env::temp_dir().join(format!("eliot-987-facade-{}", Uuid::new_v4()));
    let (config, exe) = isolated_config(&facade_root);
    let lease = {
        let platform =
            eliot_platform_windows::WindowsPlatform::new(facade_root.clone()).expect("platform");
        platform
            .retain_process_path_lease(
                &exe,
                Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .expect("retained lease")
    };
    // `new` preserves the pre-pool facade through the compatibility profile.
    let facade = SurrealStoreAdapter::new(config, lease).expect("facade adapter");
    assert_eq!(facade.client_set_limits(), ClientSetLimits::compatibility());
    // `new_with_client_set` carries an explicit bounded profile while the
    // `SurrealAdapterConfig` struct literal above stays unchanged. A second
    // isolated root keeps the data-root lease exclusive per composition.
    let pooled_root = std::env::temp_dir().join(format!("eliot-987-pooled-{}", Uuid::new_v4()));
    let (config, exe) = isolated_config(&pooled_root);
    let entries = generated_operation_manifests().expect("operation catalogue");
    let manifest = entries
        .into_iter()
        .find(|entry| entry.name == GENESIS_MANIFEST_NAME)
        .expect("genesis manifest");
    let profile = limits(&descriptor()["profiles"]["concurrent_lanes"]);
    let lease = {
        let platform =
            eliot_platform_windows::WindowsPlatform::new(pooled_root.clone()).expect("platform");
        platform
            .retain_process_path_lease(
                &exe,
                Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .expect("retained lease")
    };
    let pooled = SurrealStoreAdapter::new_with_client_set(config, lease, manifest, profile)
        .expect("pooled adapter");
    assert_eq!(pooled.client_set_limits(), profile);
    assert_eq!(pooled.client_set_limits().total_sessions(), 5);
    // Construction diagnostics never carry the credential.
    let rendered = format!("{facade:?} {pooled:?}");
    assert!(!rendered.contains("redacted-987"));
    drop(facade);
    drop(pooled);
    // Lease handles release on adapter drop above; a failed delete retries
    // briefly rather than proving a leak.
    for dir in [facade_root, pooled_root] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => break,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => panic!("isolated fixture cleanup failed: {error}"),
            }
        }
    }
}

// WORK_UNIT_CASE: 987/12
#[test]
fn pool_seam_keeps_its_fixed_structural_contract() {
    let pool = source("src/client/session_pool.rs");
    for required in [
        "pub enum SessionRole",
        "Read,",
        "NormalWrite,",
        "HealthAdmin,",
        "pub struct SessionPool",
        "pub struct PooledSession",
        "pub fn new(owner: Arc<ProviderOwner>, limits: ClientSetLimits)",
        "pub async fn checkout(",
        "pub fn try_checkout(",
        "pub async fn query(",
        "Semaphore::new(slot_count)",
        "RpcSession::connect(&self.inner.owner, deadline)",
    ] {
        assert!(pool.contains(required), "pool seam lost: {required}");
    }
    // No pool session can start a process: construction takes an already
    // owned provider handle, never a spawn/command surface. The test
    // harness below the cfg gate intentionally spawns its isolated
    // warm-up provider, so only the production part is guarded (986 pattern).
    let production = pool
        .split("#[cfg(all(test, windows))]")
        .next()
        .expect("production");
    for forbidden in ["Command::", ".spawn(", "ProviderOwner::start"] {
        assert!(
            !production.contains(forbidden),
            "pool gained process launch: {forbidden}"
        );
    }
    let facade = source("src/client.rs");
    for required in [
        "mod session_pool;",
        "connect_with_limits",
        "fn query_read(",
        "fn query_write(",
        "fn query_admin(",
        "is_pool_read_operation",
        "ProviderOwner::start(config, Arc::clone(process_lease))",
        "RpcSession::connect(&provider, deadline)",
    ] {
        assert!(
            facade.contains(required),
            "facade lost pool dispatch: {required}"
        );
    }
    let descriptor = descriptor();
    for operation in descriptor["pool_read_operations"]
        .as_array()
        .expect("reads")
    {
        let operation = operation.as_str().expect("operation");
        assert!(
            operation.starts_with("read.") || operation.starts_with("recovery."),
            "read mapping is not closed: {operation}"
        );
    }
    for operation in descriptor["facade_operations"].as_array().expect("facade") {
        let operation = operation.as_str().expect("operation");
        assert!(
            !(operation.starts_with("read.") || operation.starts_with("recovery.")),
            "facade operation leaks into the read lane: {operation}"
        );
    }
    assert_eq!(descriptor["denominator"], 12);
}
