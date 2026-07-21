use eliot_engine::{
    CodeCortexMemoryWriter, CodeCortexService, WriteAdmissionService, WriterActor, WriterConfig,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{CodeCortexRequest, ControlWalConfig, GovernorConfig};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::time::{Duration, sleep};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn codecortex_git_health_detects_repo() -> TestResult {
    let report = CodeCortexService::new(repo_root()).health("eliot-governor")?;

    assert_eq!(report.project, "eliot-governor");
    assert_eq!(
        fs::canonicalize(&report.repo_root)?,
        fs::canonicalize(repo_root())?
    );
    assert!(report.git_head.is_some());
    assert!(
        report
            .verifier_evidence
            .iter()
            .any(|evidence| evidence.name == "git_repo_root_adapter" && evidence.status == "pass")
    );
    Ok(())
}

#[test]
fn codecortex_manifest_reads_workspace() -> TestResult {
    let report = CodeCortexService::new(repo_root()).health("eliot-governor")?;

    for crate_name in [
        "eliot-app",
        "eliot-engine",
        "eliot-store",
        "eliot-types",
        "eliot-windows-ipc",
    ] {
        assert!(
            report.crates.iter().any(|name| name == crate_name),
            "missing crate {crate_name}"
        );
    }
    assert_eq!(report.workspace_members.len(), 5);
    Ok(())
}

#[test]
fn codecortex_rg_finds_known_symbol() -> TestResult {
    let report = CodeCortexService::new(repo_root()).scan(&request(
        "codecortex-rg",
        "Find CognitiveGate implementation",
        vec!["CognitiveGate".to_owned()],
    ))?;

    assert!(
        report
            .file_evidence
            .iter()
            .any(|evidence| evidence.excerpt.contains("CognitiveGate"))
    );
    assert!(
        report
            .symbol_evidence
            .iter()
            .any(|evidence| evidence.name == "CognitiveGate")
    );
    Ok(())
}

#[tokio::test]
async fn codecortex_report_written_to_memory() -> TestResult {
    let _guard = lock_tests().await;
    let harness = Harness::new("codecortex-report-write").await?;
    let mut report = CodeCortexService::new(repo_root()).scan(&request(
        "codecortex-memory",
        "Find CodeCortex service",
        vec!["CodeCortexService".to_owned()],
    ))?;

    let (handle, actor) = harness.writer_pair("codecortex")?;
    let actor_task = tokio::spawn(actor.run());
    let receipt =
        CodeCortexMemoryWriter::write_report(&handle, &WriteAdmissionService, &mut report).await?;
    drop(handle);
    actor_task.await?;

    assert_eq!(
        report.memory_receipt.as_ref().map(|stored| stored.write_id),
        Some(receipt.write_id)
    );
    Ok(())
}

#[test]
fn codecortex_health_reports_unavailable_adapters_honestly() -> TestResult {
    let report = CodeCortexService::new(repo_root()).health("eliot-governor")?;

    assert!(adapter_status(
        &report,
        "codebase_memory_adapter",
        "unavailable"
    ));
    assert!(adapter_status(&report, "domain_api_adapter", "disabled"));
    Ok(())
}

#[test]
fn phase_b_c_non_regression() -> TestResult {
    let mcp_stdio = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;
    let context = fs::read_to_string(repo_root().join("crates/eliot-engine/src/context.rs"))?;

    assert!(mcp_stdio.contains("eliot_codecortex_scan"));
    assert!(mcp_stdio.contains("eliot_codecortex_latest"));
    for raw_tool in ["raw_shell", "raw_rg", "raw_ast_grep", "raw_git", "raw_file"] {
        assert!(!mcp_stdio.contains(raw_tool));
    }
    assert!(mcp_stdio.contains("eliot_cognitive_gate"));
    assert!(context.contains("pub struct ContextCompiler"));
    assert!(context.contains("pub struct CognitiveGate"));
    Ok(())
}

struct Harness {
    root: PathBuf,
    store: CanonicalStore,
}

impl Harness {
    async fn new(name: &str) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("eliot-phase-d1-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let mut config = GovernorConfig::default();
        let repo = repo_root();
        config.db.surreal.password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")
            .unwrap_or_else(|_| {
                repo.join(".eliot-governor/secrets/surreal_root_password.txt")
                    .display()
                    .to_string()
            });
        config.db.surreal.storage =
            std::env::var("ELIOT_TEST_SURREAL_STORAGE").unwrap_or_else(|_| {
                format!(
                    "rocksdb:{}",
                    repo.join(".eliot-governor/surrealdb-rocks").display()
                )
            });
        if let Ok(bind) = std::env::var("ELIOT_TEST_SURREAL_BIND") {
            config.db.surreal.bind = bind;
        }
        if let Ok(endpoint) = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT") {
            config.db.surreal.endpoint = endpoint;
        }
        let store = CanonicalStore::new(config.db.surreal);
        migrate_schema_locked(&store).await?;
        Ok(Self { root, store })
    }

    fn writer_pair(&self, name: &str) -> TestResult<(eliot_engine::WriterHandle, WriterActor)> {
        let path = self.root.join(name).join("control.redb");
        let wal = ControlWal::open(&ControlWalConfig {
            path: path.display().to_string(),
        })?;
        Ok(WriterActor::channel(
            wal,
            self.store.clone(),
            &WriterConfig::default(),
        ))
    }
}

async fn lock_tests() -> TestLock {
    let lock_path = repo_root().join("target/eliot-governor-shared-db-test.lock");
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_file) => return TestLock { lock_path },
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
}

struct TestLock {
    lock_path: PathBuf,
}

impl Drop for TestLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

async fn migrate_schema_locked(store: &CanonicalStore) -> TestResult {
    let lock_path = repo_root().join("target/phase-d1-migrate.lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let lock_file = loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => break file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    };

    let result = store.migrate_schema().await;
    drop(lock_file);
    let _ = fs::remove_file(lock_path);
    result?;
    Ok(())
}

fn request(task: &str, goal: &str, exact_patterns: Vec<String>) -> CodeCortexRequest {
    CodeCortexRequest {
        project: "eliot-governor".to_owned(),
        task: task.to_owned(),
        goal: goal.to_owned(),
        exact_patterns,
        max_files: 40,
        max_matches_per_pattern: 12,
        include_diagnostics: false,
    }
}

fn adapter_status(report: &eliot_types::CodeCortexReport, name: &str, status: &str) -> bool {
    report
        .verifier_evidence
        .iter()
        .any(|evidence| evidence.name == name && evidence.status == status)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
