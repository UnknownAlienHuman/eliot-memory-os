use super::*;
use crate::CanonicalStore;
use eliot_types::{
    CredentialProviderKind, CurrentStateRequest, GovernorConfig, ProjectId, ReadConsistencyMode,
};
use serde_json::json;
use std::error::Error;
use std::net::TcpStream as StdTcpStream;
use std::path::{Path, PathBuf};
use tokio::sync::Barrier;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires scripts/run-isolated-tests.ps1 SurrealDB guardian"]
async fn warm_sessions_concurrency_and_external_shutdown_are_bounded() -> TestResult {
    let config = isolated_config()?;
    let owned_pid = guardian_pid(&config)?;
    assert!(eliot_windows_ipc::process_is_alive(owned_pid)?);

    let clients = Arc::new(DbClientSet::start(config.clone()).await?);
    let initial = clients.metrics();
    assert_eq!(initial.read_pool_size, DEFAULT_DB_READ_POOL_SIZE);
    assert_eq!(initial.sessions_opened, 6);

    assert_production_store_path(&clients, initial.sessions_opened).await?;
    let production_read_queries = clients.metrics().read_queries;

    for index in 0..100_u64 {
        let expected = format!("warm-project-{index}");
        let raw = clients
            .execute_classified(
                SurqlAccessClass::Read,
                "RETURN $project_id;",
                json!({ "project_id": expected.clone() }),
            )
            .await?;
        assert_eq!(returned_value(&raw), Some(&Value::String(expected)));
    }

    let after_warm = clients.metrics();
    assert_eq!(after_warm.sessions_opened, initial.sessions_opened);
    assert_eq!(after_warm.reconnect_attempts, 0);
    assert_eq!(after_warm.read_queries, production_read_queries + 100);

    let project_a = "db-client-project-a";
    let project_b = "db-client-project-b";
    clients
        .execute_classified(
            SurqlAccessClass::Write,
            "DELETE db_client_set_probe; \
             CREATE db_client_set_probe:a CONTENT { project_id: $project_a, value: 'a' }; \
             CREATE db_client_set_probe:b CONTENT { project_id: $project_b, value: 'b' };",
            json!({ "project_a": project_a, "project_b": project_b }),
        )
        .await?;

    let barrier = Arc::new(Barrier::new(17));
    let mut readers = Vec::with_capacity(16);
    for index in 0..16_u64 {
        let client = clients.clone();
        let barrier = Arc::clone(&barrier);
        readers.push(tokio::spawn(async move {
            let (expected_project, expected_value) = if index % 2 == 0 {
                (project_a, "a")
            } else {
                (project_b, "b")
            };
            barrier.wait().await;
            let raw = client
                .execute_classified(
                    SurqlAccessClass::Read,
                    "SLEEP 50ms; \
                     SELECT project_id, value FROM db_client_set_probe \
                     WHERE project_id = $project_id;",
                    json!({ "project_id": expected_project }),
                )
                .await;
            (expected_project, expected_value, raw)
        }));
    }
    barrier.wait().await;
    for reader in readers {
        let (expected_project, expected_value, raw) = reader.await?;
        let raw = raw?;
        let rows = returned_value(&raw)
            .and_then(Value::as_array)
            .ok_or("project-scoped query did not return rows")?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["project_id"], expected_project);
        assert_eq!(rows[0]["value"], expected_value);
    }

    let after_concurrent = clients.metrics();
    assert_eq!(after_concurrent.sessions_opened, initial.sessions_opened);
    assert_eq!(after_concurrent.reconnect_attempts, 0);
    assert_eq!(after_concurrent.read_queries, production_read_queries + 116);
    assert_eq!(after_concurrent.active_readers, 0);
    assert_eq!(after_concurrent.peak_readers, DEFAULT_DB_READ_POOL_SIZE);

    assert_shutdown_and_external_survival(&clients, owned_pid, &config.bind).await?;
    Ok(())
}

async fn assert_shutdown_and_external_survival(
    clients: &Arc<DbClientSet>,
    owned_pid: u32,
    bind: &str,
) -> TestResult {
    let shutdown_barrier = Arc::new(Barrier::new(9));
    let mut shutdowns = Vec::with_capacity(8);
    for _ in 0..8 {
        let client = clients.clone();
        let barrier = Arc::clone(&shutdown_barrier);
        shutdowns.push(tokio::spawn(async move {
            barrier.wait().await;
            client.shutdown().await
        }));
    }
    shutdown_barrier.wait().await;
    for shutdown in shutdowns {
        assert_eq!(shutdown.await??, SurrealShutdown::not_owned());
    }
    assert_eq!(clients.shutdown().await?, SurrealShutdown::not_owned());
    assert!(clients.metrics().shutdown_completed);
    assert!(matches!(
        clients
            .execute_classified(SurqlAccessClass::Read, "RETURN true;", Value::Null)
            .await,
        Err(StoreError::ClientSetShuttingDown)
    ));

    assert!(eliot_windows_ipc::process_is_alive(owned_pid)?);
    let witness = StdTcpStream::connect(bind)?;
    drop(witness);
    Ok(())
}

fn isolated_config() -> TestResult<SurrealServerConfig> {
    let mut config = GovernorConfig::default().db.surreal;
    config.exe = required_env("ELIOT_SURREAL_EXE")?;
    config.bind = required_env("ELIOT_TEST_SURREAL_BIND")?;
    config.endpoint = required_env("ELIOT_TEST_SURREAL_ENDPOINT")?;
    config.password_file = required_env("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
    config.storage = required_env("ELIOT_TEST_SURREAL_STORAGE")?;
    config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    config.query_timeout_ms = 20_000;
    config.startup_timeout_ms = 20_000;
    Ok(config)
}

fn required_env(name: &str) -> TestResult<String> {
    std::env::var(name).map_err(|error| format!("{name} is required: {error}").into())
}

fn guardian_pid(config: &SurrealServerConfig) -> TestResult<u32> {
    let storage = config
        .storage
        .strip_prefix("rocksdb:")
        .ok_or("isolated storage must use rocksdb:")?;
    let storage = PathBuf::from(storage);
    let owned_root = storage
        .parent()
        .ok_or("isolated storage has no owned root")?;
    let pid_path = owned_root.join("tmp").join("owned-surreal.pid");
    read_pid(&pid_path)
}

fn read_pid(path: &Path) -> TestResult<u32> {
    Ok(std::fs::read_to_string(path)?.trim().parse()?)
}

fn returned_value(raw: &Value) -> Option<&Value> {
    raw.as_array()?.last()?.get("result")
}

async fn assert_production_store_path(
    clients: &Arc<DbClientSet>,
    expected_sessions: u64,
) -> TestResult {
    let store = CanonicalStore::from_client_set(Arc::clone(clients));
    store.migrate_schema().await?;
    let cloned_store = store.clone();
    let project_id = ProjectId::new_v7();
    let state = cloned_store
        .current_state(&CurrentStateRequest {
            project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?;
    assert_eq!(state.project_id, project_id);
    assert_eq!(clients.metrics().sessions_opened, expected_sessions);
    Ok(())
}
