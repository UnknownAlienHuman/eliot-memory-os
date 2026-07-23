use eliot_engine::{
    GitMiningService, ModuleCardService, OnboardingService, UlArtifactWriterService,
    WriteAdmissionService, WriterActor, WriterConfig,
};
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::{
    CoChangeEdge, ConceptNode, ControlWalConfig, CredentialProviderKind, GovernorConfig,
    HotspotScore, ModuleCard, OnboardingTestHook, ProjectId, normalize_bindings,
};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_onboarding_is_resumable_and_model_free() -> TestResult {
    if rerun_with_credential_gate("t06_onboarding_is_resumable_and_model_free")? {
        return Ok(());
    }
    let harness = Harness::start().await?;
    let repository = harness.create_repository()?;
    let project_id = ProjectId::new_v7();
    let wal = ControlWal::open(&ControlWalConfig {
        path: slash(&harness.root.join("control.redb")),
    })?;
    let (writer, actor) =
        WriterActor::channel(wal, harness.store.clone(), &WriterConfig::default());
    let actor = tokio::spawn(actor.run());
    let mining = GitMiningService::default().mine_history(
        project_id,
        &large_mining_history(&repository)?,
        &std::collections::BTreeMap::new(),
    )?;
    UlArtifactWriterService
        .write_mining(&writer, &WriteAdmissionService, &mining)
        .await?;
    let mined_cards = ModuleCardService::build(
        project_id,
        &repository,
        &mining.hotspots,
        &mining.edges,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeMap::new(),
    )?;
    UlArtifactWriterService
        .write_module_cards(
            &writer,
            &WriteAdmissionService,
            &mining.run.run_id,
            &mined_cards,
        )
        .await?;
    let service = OnboardingService::new(harness.store.clone(), writer.clone());

    let interrupted = service
        .run(
            project_id,
            &repository,
            &harness.root,
            OnboardingTestHook::InterruptAfterConcepts,
        )
        .await;
    assert!(interrupted.is_err());
    let resumed = service
        .run(
            project_id,
            &repository,
            &harness.root,
            OnboardingTestHook::None,
        )
        .await?;
    let uninterrupted = service
        .run(
            project_id,
            &repository,
            &harness.root,
            OnboardingTestHook::None,
        )
        .await?;
    let concepts = harness
        .store
        .load_ul_artifacts::<ConceptNode>(project_id, &["concept_node"], 128)
        .await?;
    let cards = harness
        .store
        .load_ul_artifacts::<ModuleCard>(project_id, &["module_card"], 128)
        .await?;

    assert_eq!(resumed, uninterrupted);
    assert_eq!(resumed.reasoning_job_calls, 0);
    assert_eq!(concepts.len(), resumed.concept_count);
    assert_cards_are_normalized(&cards)?;
    assert_multi_binding_card_is_normalized(project_id, &repository)?;
    assert!(
        harness
            .root
            .join("reports")
            .join("ul")
            .join("onboarding")
            .join(project_id.to_string())
            .join("checkpoint.json")
            .is_file()
    );
    drop(service);
    drop(writer);
    actor.await?;
    Ok(())
}

fn assert_cards_are_normalized(cards: &[eliot_store::CanonicalRecord<ModuleCard>]) -> TestResult {
    for card in cards {
        assert_eq!(
            normalize_bindings(card.receipt_body.cue_bindings.clone(), None)?,
            card.receipt_body.cue_bindings
        );
    }
    Ok(())
}

fn assert_multi_binding_card_is_normalized(project_id: ProjectId, repository: &Path) -> TestResult {
    let multi_binding = ModuleCardService::build(
        project_id,
        repository,
        &[HotspotScore {
            hotspot_id: "hotspot-policy".to_owned(),
            project_id,
            path: "src/policy.rs".to_owned(),
            touches: 3,
            fix_touches: 0,
            churn_decayed: 1.0,
            bugfix_density: 0.0,
            failure_density: 0,
            score: 10,
            mining_run_ref: "mining-fixture".to_owned(),
            cue_bindings: Vec::new(),
        }],
        &[CoChangeEdge {
            edge_id: "edge-model-policy".to_owned(),
            project_id,
            path_a: "src/model.rs".to_owned(),
            path_b: "src/policy.rs".to_owned(),
            support: 3,
            confidence_ab: 1.0,
            confidence_ba: 1.0,
            last_cochange_at_unix: 0,
            static_edge_exists: None,
            mining_run_ref: "mining-fixture".to_owned(),
            cue_bindings: Vec::new(),
        }],
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeMap::new(),
    )?;
    assert_eq!(multi_binding.len(), 1);
    assert_eq!(multi_binding[0].cue_bindings.len(), 2);
    assert_eq!(
        normalize_bindings(multi_binding[0].cue_bindings.clone(), None)?,
        multi_binding[0].cue_bindings
    );
    Ok(())
}

fn rerun_with_credential_gate(test_name: &str) -> TestResult<bool> {
    if std::env::var("ELIOT_UL_T06_ENGINE_CHILD").as_deref() == Ok(test_name) {
        return Ok(false);
    }
    let status = Command::new(std::env::current_exe()?)
        .env("ELIOT_UL_T06_ENGINE_CHILD", test_name)
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
    async fn start() -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = test_runtime_root()?.join(format!(
            "eliot-ul-t06-onboarding-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        fs::write(root.join("surreal-root.txt"), "ul-t06-test-secret")?;
        let surreal_exe = pinned_surreal_exe()?;
        let port = test_port()?;
        let surreal = start_surreal(&surreal_exe, port)?;
        wait_for_tcp(port, Duration::from_secs(20))?;

        let mut config = GovernorConfig::default();
        config.db.surreal.exe = slash(&surreal_exe);
        config.db.surreal.bind = format!("127.0.0.1:{port}");
        config.db.surreal.endpoint = format!("ws://127.0.0.1:{port}/rpc");
        "memory".clone_into(&mut config.db.surreal.storage);
        "ult06".clone_into(&mut config.db.surreal.ns);
        "ult06".clone_into(&mut config.db.surreal.db);
        "root".clone_into(&mut config.db.surreal.user);
        config.db.surreal.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        "test-only/ul-t06-engine".clone_into(&mut config.db.surreal.credential_id);
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

    fn create_repository(&self) -> TestResult<PathBuf> {
        let root = self.root.join("repo");
        fs::create_dir_all(root.join("src"))?;
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='onboarding-fixture'\nversion='0.1.0'\nedition='2024'\ndescription='Exercises deterministic onboarding.'\n",
        )?;
        fs::write(
            root.join("README.md"),
            "# Fixture\nA deterministic onboarding fixture.\n\n## Non-goals\n- network access\n",
        )?;
        fs::write(
            root.join("src/lib.rs"),
            "//! Owns the onboarding fixture behavior.\npub mod model;\npub mod policy;\n",
        )?;
        fs::write(root.join("src/model.rs"), "pub struct Model;\n")?;
        fs::write(root.join("src/policy.rs"), "pub fn verify() {}\n")?;
        git(&root, &["init", "-q"])?;
        git(&root, &["add", "."])?;
        git(
            &root,
            &[
                "-c",
                "user.name=UL Test",
                "-c",
                "user.email=ul-test@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
        )?;
        Ok(root)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.surreal.stop();
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-t06-onboarding-"))
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
        .env("SURREAL_PASS", "ul-t06-test-secret")
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
        return Err(format!("UL-06 requires SurrealDB 3.1.4, got {}", version.trim()).into());
    }
    Ok(path)
}

fn test_port() -> TestResult<u16> {
    for port in 8700..=8799 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no free UL-06 test port in 8700-8799".into())
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

fn git(root: &Path, args: &[&str]) -> TestResult {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(())
}

fn large_mining_history(root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let head = String::from_utf8(output.stdout)?.trim().to_owned();
    let mut history = String::new();
    for index in 0..70 {
        let hash = if index == 0 {
            head.clone()
        } else {
            format!("synthetic-{index}")
        };
        let timestamp = 1_760_100_000_i64 - i64::from(index) * 3_600;
        writeln!(
            history,
            "@@ELIOT@@{hash}\u{1f}UL Test\u{1f}{timestamp}\u{1f}fixture history\nsegment_{index}/a.rs\nsegment_{index}/b.rs"
        )?;
    }
    Ok(history)
}

fn test_runtime_root() -> TestResult<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?)
            .join("Eliot")
            .join("tests"),
    )
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
