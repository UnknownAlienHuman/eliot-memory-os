#![cfg(windows)]

use eliot_types::{ProjectId, TaskId, WriteId};
use serde_json::Value;
use std::fs;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn facade_and_daemon_resolve_one_runtime_across_windows_path_spellings() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;

    let mut daemon = OwnedChild::spawn(
        governor_command()
            .arg("--config")
            .arg(&config_path)
            .args(["daemon", "run"])
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )?;
    wait_for_changed_json(
        &runtime.path().join("runtime").join("publication.json"),
        "auth_generation",
        "",
        Duration::from_secs(10),
    )?;

    let canonical_config = config_path.canonicalize()?;
    assert_ne!(
        canonical_config.to_string_lossy(),
        config_path.to_string_lossy(),
        "the red test requires Windows canonicalization to add a distinct path spelling"
    );

    let mut facade = governor_command()
        .arg("--config")
        .arg(&canonical_config)
        .args(["mcp", "stdio", "--profile", "external_auditor"])
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = facade.stdin.take().ok_or("facade stdin unavailable")?;
    serde_json::to_writer(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "multi-agent-red", "version": "0.1.0"}
            }
        }),
    )?;
    writeln!(stdin)?;
    drop(stdin);
    let output = facade.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "facade exited before initialize: {stderr}"
    );
    let response: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        response
            .pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some("eliot-governor")
    );

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    daemon.wait_for_exit(Duration::from_secs(10))?;
    Ok(())
}

#[test]
fn doctor_and_facade_name_the_exact_authentication_mismatch() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;
    let mut daemon = start_daemon(&config_path)?;
    wait_for_changed_json(
        &runtime.path().join("runtime").join("publication.json"),
        "auth_generation",
        "",
        Duration::from_secs(10),
    )?;

    let authentication_path = runtime.path().join("runtime").join("ipc-auth.json");
    let mut authentication: Value = serde_json::from_slice(&fs::read(&authentication_path)?)?;
    authentication["pipe_name"] = Value::String(r"\\.\pipe\wrong-runtime".to_owned());
    fs::write(
        &authentication_path,
        serde_json::to_vec_pretty(&authentication)?,
    )?;

    let doctor = governor_command()
        .arg("--config")
        .arg(&config_path)
        .args(["daemon", "doctor"])
        .output()?;
    assert!(doctor.status.success());
    let doctor: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(doctor["status"], "not_ready");
    assert_eq!(
        doctor.pointer("/authentication_error/error_code"),
        Some(&Value::String("authentication_field_mismatch".to_owned()))
    );
    assert!(
        doctor["authentication_error"]["detail"]
            .as_str()
            .is_some_and(|detail| detail.ends_with("pipe_name"))
    );

    let output = governor_command()
        .arg("--config")
        .arg(&config_path)
        .args(["mcp", "stdio", "--profile", "external_auditor"])
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("runtime authentication mismatch: pipe_name")
    );

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    daemon.wait_for_exit(Duration::from_secs(10))?;
    Ok(())
}

#[test]
fn initialize_cannot_widen_the_authenticated_profile() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;
    let mut daemon = start_daemon(&config_path)?;
    wait_for_changed_json(
        &runtime.path().join("runtime").join("publication.json"),
        "auth_generation",
        "",
        Duration::from_secs(10),
    )?;

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "Antigravity", "version": "multi-agent-test"},
            "eliotProfile": "codex_controller"
        }
    });
    let responses = run_facade_requests(&config_path, "external_auditor", &[request])?;
    assert_eq!(
        responses[0].pointer("/error/code").and_then(Value::as_i64),
        Some(-32603)
    );
    assert!(
        responses[0]
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("cannot widen handshake profile"))
    );

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    daemon.wait_for_exit(Duration::from_secs(10))?;
    Ok(())
}

#[test]
fn canonical_profiles_publish_bounded_tool_sets() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    write_test_config(runtime.path(), &config_path, free_local_port()?)?;
    let mut daemon = start_daemon(&config_path)?;
    wait_for_changed_json(
        &runtime.path().join("runtime").join("publication.json"),
        "auth_generation",
        "",
        Duration::from_secs(10),
    )?;

    for profile in [
        "codex_controller",
        "codex_worker",
        "external_auditor",
        "verifier",
        "human_readonly",
    ] {
        let responses = run_facade_requests(
            &config_path,
            profile,
            &[
                initialize_request(1, profile),
                serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            ],
        )?;
        assert_eq!(
            responses[0]
                .pointer("/result/experimental/eliotAgentSession/access_profile")
                .and_then(Value::as_str),
            Some(profile)
        );
        let names = responses[1]
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .ok_or("profile tools missing")?
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"eliot_project_identity"));
        assert!(names.contains(&"eliot_runtime_status"));
        match profile {
            "codex_controller" => assert!(names.contains(&"eliot_submit_completion_proof")),
            "codex_worker" => {
                assert!(!names.contains(&"eliot_submit_completion_proof"));
                assert!(!names.contains(&"eliot_patch_apply"));
                assert!(!names.contains(&"eliot_delegate_review"));
            }
            "external_auditor" => {
                assert!(names.contains(&"eliot_agent_candidate_submit"));
                assert!(!names.contains(&"eliot_submit_completion_proof"));
            }
            "verifier" | "human_readonly" => {
                assert!(!names.contains(&"eliot_agent_candidate_submit"));
                assert!(!names.contains(&"eliot_submit_completion_proof"));
            }
            _ => unreachable!(),
        }
    }

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    daemon.wait_for_exit(Duration::from_secs(10))?;
    Ok(())
}

#[test]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn default_instance_bootstrap_is_stable_and_outside_the_repository() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let local_app_data = runtime.path().join("local-app-data");
    let source_config = repository_root()?
        .join(".eliot-governor")
        .join("config")
        .join("governor.toml");
    let output = governor_command()
        .args(["daemon", "init-default", "--source-config"])
        .arg(&source_config)
        .env("LOCALAPPDATA", &local_app_data)
        .output()?;
    assert!(
        output.status.success(),
        "default init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config_path = local_app_data
        .join("Eliot")
        .join("config")
        .join("governor.toml");
    let config = fs::read_to_string(&config_path)?;
    assert!(!config.to_ascii_lowercase().contains("onedrive"));
    assert!(local_app_data.join("Eliot/resources/surql").is_dir());
    assert!(local_app_data.join("Eliot/resources/migrations").is_dir());
    assert!(config.contains("instance_id = \"default\""));
    Ok(())
}

#[test]
#[ignore = "requires a provisioned SurrealDB executable"]
fn standalone_startup_failure_stops_its_owned_database_and_publishes_failed() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    let port = free_local_port()?;
    write_test_config(runtime.path(), &config_path, port)?;
    let invalid_wal_path = runtime.path().join("control").join("control.redb");
    fs::create_dir_all(&invalid_wal_path)?;
    let local_app_data = runtime.path().join("local-app-data");

    let output = governor_command()
        .arg("--config")
        .arg(&config_path)
        .args(["daemon", "run", "--instance", "default"])
        .env("LOCALAPPDATA", &local_app_data)
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .output()?;
    assert!(!output.status.success());

    let publication_path = local_app_data
        .join("Eliot")
        .join("instances")
        .join("default")
        .join("runtime")
        .join("publication.json");
    let publication: Value = serde_json::from_slice(&fs::read(publication_path)?)?;
    assert_eq!(publication["state"], "failed");
    wait_for_tcp_closed(port, Duration::from_secs(10))?;
    assert!(
        local_app_data
            .join("Eliot/instances/default/reports/startup/latest.json")
            .is_file()
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn external_candidate_is_shared_without_authority_widening() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    let port = free_local_port()?;
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;
    let mut daemon = OwnedChild::spawn(
        governor_command()
            .arg("--config")
            .arg(&config_path)
            .args(["daemon", "run"])
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )?;
    wait_for_changed_json(
        &runtime.path().join("runtime").join("publication.json"),
        "auth_generation",
        "",
        Duration::from_secs(15),
    )?;

    let project_id = "eliot-governor";
    let task_id = TaskId::new_v7().to_string();
    let task = run_facade_requests(
        &config_path,
        "codex_controller",
        &[
            initialize_request(90, "Codex"),
            serde_json::json!({
                "jsonrpc":"2.0","id":91,"method":"tools/call",
                "params":{"name":"eliot_task_contract_create","arguments":{
                    "project_id": project_id,
                    "task_id": task_id,
                    "write_id": WriteId::new_v7().to_string(),
                    "title": "task-bound external candidate sharing",
                    "acceptance_items": [
                        {"item_id":"candidate","description":"candidate is task scoped","required_evidence":"observation"},
                        {"item_id":"authority","description":"candidate has no completion authority","required_evidence":"verification"}
                    ]
                }}
            }),
        ],
    )?;
    assert!(
        task[1]
            .pointer("/result/structuredContent/task_contract")
            .is_some(),
        "task creation response: {}",
        task[1]
    );
    let phrase = format!("orchid-runtime-{}", WriteId::new_v7());
    let external = run_facade_requests(
        &config_path,
        "external_auditor",
        &[
            initialize_request(1, "Antigravity"),
            serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            serde_json::json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"eliot_project_identity","arguments":{
                    "project_key": project_id
                }}
            }),
            serde_json::json!({
                "jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":"eliot_agent_candidate_submit","arguments":{
                    "project_id": project_id,
                    "task_id": task_id,
                    "write_id": WriteId::new_v7().to_string(),
                    "topic": "standalone multi-agent runtime",
                    "statement": format!("{phrase} uses one Governor writer and one canonical store"),
                    "where_applicable": ["standalone default instance"],
                    "where_not_applicable": ["isolated disposable test instances"],
                    "negative_constraints": ["never treat candidate memory as completion authority"],
                    "provenance_refs": ["multi-agent-process-test"],
                    "freshness_rule": "revalidate after runtime generation or repository truth changes"
                }}
            }),
            serde_json::json!({
                "jsonrpc":"2.0","id":5,"method":"tools/call",
                "params":{"name":"eliot_submit_completion_proof","arguments":{}}
            }),
        ],
    )?;
    assert_eq!(
        external[0]
            .pointer("/result/experimental/eliotAgentSession/access_profile")
            .and_then(Value::as_str),
        Some("external_auditor")
    );
    let listed = external[1]
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("tools missing")?;
    assert!(
        listed
            .iter()
            .any(|tool| tool["name"] == "eliot_agent_candidate_submit")
    );
    assert!(
        !listed
            .iter()
            .any(|tool| tool["name"] == "eliot_submit_completion_proof")
    );
    let read_tool = listed
        .iter()
        .find(|tool| tool["name"] == "eliot_runtime_status")
        .ok_or("read tool missing")?;
    assert_eq!(
        read_tool.pointer("/annotations/readOnlyHint"),
        Some(&Value::Bool(true))
    );
    let candidate_tool = listed
        .iter()
        .find(|tool| tool["name"] == "eliot_agent_candidate_submit")
        .ok_or("candidate tool missing")?;
    assert_eq!(
        candidate_tool.pointer("/annotations/destructiveHint"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        candidate_tool.pointer("/annotations/idempotentHint"),
        Some(&Value::Bool(true))
    );
    assert!(
        candidate_tool
            .pointer("/inputSchema/required")
            .and_then(Value::as_array)
            .is_some_and(|required| required.iter().any(|field| field == "task_id"))
    );
    assert_eq!(
        external[2]
            .pointer("/result/structuredContent/canonical_project_key")
            .and_then(Value::as_str),
        Some(project_id)
    );
    assert_eq!(
        external[3]
            .pointer("/result/structuredContent/status")
            .and_then(Value::as_str),
        Some("candidate_committed")
    );
    assert_eq!(
        external[4]
            .pointer("/result/isError")
            .and_then(Value::as_bool),
        Some(true)
    );

    let codex = run_facade_requests(
        &config_path,
        "codex_controller",
        &[
            initialize_request(10, "Codex"),
            serde_json::json!({
                "jsonrpc":"2.0","id":12,"method":"tools/call",
                "params":{"name":"eliot_project_identity","arguments":{
                    "project_key": project_id
                }}
            }),
            serde_json::json!({
                "jsonrpc":"2.0","id":11,"method":"tools/call",
                "params":{"name":"eliot_recall_l0","arguments":{
                    "project_id": project_id,
                    "query": phrase,
                    "limit": 10
                }}
            }),
        ],
    )?;
    assert_eq!(
        codex[1]
            .pointer("/result/structuredContent/canonical_project_key")
            .and_then(Value::as_str),
        Some(project_id)
    );
    let recalled = serde_json::to_string(&codex[2])?;
    assert!(
        recalled.contains(&phrase),
        "candidate was not recalled across clients: {recalled}"
    );

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    daemon.wait_for_exit(Duration::from_secs(15))?;
    database.stop()?;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
#[ignore = "requires a provisioned local Governor runtime: a running daemon, an authenticated SurrealDB and a git identity"]
fn facade_reconnects_after_rotation_and_replay_does_not_duplicate_memory() -> TestResult {
    let runtime = OwnedRuntime::new()?;
    let config_path = runtime.path().join("config").join("governor.toml");
    let port = free_local_port()?;
    write_test_config(runtime.path(), &config_path, port)?;
    let mut database = start_surreal(runtime.path(), port)?;
    wait_for_tcp(port, Duration::from_secs(15))?;

    let mut first_daemon = start_daemon(&config_path)?;
    let publication_path = runtime.path().join("runtime").join("publication.json");
    let first_publication = wait_for_changed_json(
        &publication_path,
        "auth_generation",
        "",
        Duration::from_secs(15),
    )?;
    let first_generation = first_publication["auth_generation"]
        .as_str()
        .ok_or("first auth generation missing")?
        .to_owned();
    let mut facade = LiveFacade::start(&config_path, "external_auditor")?;
    let initialized = facade.request(
        &initialize_request(20, "Antigravity"),
        Duration::from_secs(10),
    )?;
    assert_eq!(
        initialized
            .pointer("/result/experimental/eliotAgentSession/auth_generation")
            .and_then(Value::as_str),
        Some(first_generation.as_str())
    );

    let project_id = ProjectId::new_v7().to_string();
    let task_id = TaskId::new_v7().to_string();
    let task = run_facade_requests(
        &config_path,
        "codex_controller",
        &[
            initialize_request(190, "Codex"),
            serde_json::json!({
                "jsonrpc":"2.0","id":191,"method":"tools/call",
                "params":{"name":"eliot_task_contract_create","arguments":{
                    "project_id": project_id,
                    "task_id": task_id,
                    "write_id": WriteId::new_v7().to_string(),
                    "title": "task-bound candidate survives daemon rotation",
                    "acceptance_items": [
                        {"item_id":"restart","description":"candidate replay survives restart","required_evidence":"observation"},
                        {"item_id":"dedupe","description":"replay remains singular","required_evidence":"verification"}
                    ]
                }}
            }),
        ],
    )?;
    assert!(
        task[1]
            .pointer("/result/structuredContent/task_contract")
            .is_some(),
        "rotation task creation response: {}",
        task[1]
    );
    let phrase = format!("rotation-idempotency-{}", WriteId::new_v7());
    let candidate = serde_json::json!({
        "jsonrpc":"2.0","id":21,"method":"tools/call",
        "params":{"name":"eliot_agent_candidate_submit","arguments":{
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7().to_string(),
            "topic": "rotation replay",
            "statement": phrase,
            "where_applicable": ["same canonical store after daemon restart"],
            "where_not_applicable": ["different instance selector"],
            "negative_constraints": ["replay must not create a second claim"],
            "provenance_refs": ["multi-agent-rotation-test"],
            "freshness_rule": "valid only while project and instance identity remain the same"
        }}
    });
    let first_write = facade.request(&candidate, Duration::from_secs(30))?;
    let first_receipt = first_write
        .pointer("/result/structuredContent/write_receipt/receipt_id")
        .and_then(Value::as_str)
        .ok_or("first write receipt missing")?
        .to_owned();

    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "rotate\n",
    )?;
    first_daemon.wait_for_exit(Duration::from_secs(15))?;
    let mut second_daemon = start_daemon(&config_path)?;
    let second_publication = wait_for_changed_json(
        &publication_path,
        "auth_generation",
        &first_generation,
        Duration::from_secs(15),
    )?;
    assert_ne!(
        second_publication["runtime_id"],
        first_publication["runtime_id"]
    );

    let replayed = facade.request(&candidate, Duration::from_secs(30))?;
    assert_eq!(
        replayed
            .pointer("/result/structuredContent/write_receipt/receipt_id")
            .and_then(Value::as_str),
        Some(first_receipt.as_str()),
        "replayed response: {replayed}"
    );
    let recalled = facade.request(
        &serde_json::json!({
            "jsonrpc":"2.0","id":22,"method":"tools/call",
            "params":{"name":"eliot_recall_l0","arguments":{
                "project_id": project_id,
                "query": phrase,
                "limit": 10
            }}
        }),
        Duration::from_secs(30),
    )?;
    assert_eq!(
        recalled
            .pointer("/result/structuredContent/handles")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "idempotent replay must leave exactly one candidate claim"
    );

    facade.stop()?;
    fs::write(
        runtime.path().join("runtime").join("stop.requested"),
        "test\n",
    )?;
    second_daemon.wait_for_exit(Duration::from_secs(15))?;
    database.stop()?;
    Ok(())
}

fn initialize_request(id: u64, client_name: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "multi-agent-test"}
        }
    })
}

fn run_facade_requests(
    config_path: &Path,
    profile: &str,
    requests: &[Value],
) -> TestResult<Vec<Value>> {
    let mut child = governor_command()
        .arg("--config")
        .arg(config_path)
        .args(["mcp", "stdio", "--profile", profile])
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("facade stdin unavailable")?;
    for request in requests {
        serde_json::to_writer(&mut stdin, request)?;
        writeln!(stdin)?;
    }
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "facade {profile} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    String::from_utf8(output.stdout)?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn start_daemon(config_path: &Path) -> TestResult<OwnedChild> {
    OwnedChild::spawn(
        governor_command()
            .arg("--config")
            .arg(config_path)
            .args(["daemon", "run"])
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
}

struct LiveFacade {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    responses: Receiver<TestResult<String>>,
    reader: Option<JoinHandle<()>>,
}

impl LiveFacade {
    fn start(config_path: &Path, profile: &str) -> TestResult<Self> {
        let mut child = governor_command()
            .arg("--config")
            .arg(config_path)
            .args(["mcp", "stdio", "--profile", profile])
            .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child.stdin.take().ok_or("facade stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("facade stdout unavailable")?;
        let (sender, responses) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut lines = std::io::BufReader::new(stdout).lines();
            loop {
                let message = match lines.next() {
                    Some(Ok(line)) => Ok(line),
                    Some(Err(error)) => Err(error.into()),
                    None => Err("facade stdout closed".into()),
                };
                let stop = message.is_err();
                if sender.send(message).is_err() || stop {
                    break;
                }
            }
        });
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            responses,
            reader: Some(reader),
        })
    }

    fn request(&mut self, request: &Value, timeout: Duration) -> TestResult<Value> {
        let stdin = self.stdin.as_mut().ok_or("facade stdin closed")?;
        serde_json::to_writer(&mut *stdin, request)?;
        writeln!(stdin)?;
        stdin.flush()?;
        let line = self
            .responses
            .recv_timeout(timeout)
            .map_err(|error| format!("timed out waiting for facade response: {error}"))??;
        Ok(serde_json::from_str(&line)?)
    }

    fn stop(&mut self) -> TestResult {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let _ = child.wait()?;
        }
        if let Some(reader) = self.reader.take() {
            reader.join().map_err(|_| "facade reader panicked")?;
        }
        Ok(())
    }
}

impl Drop for LiveFacade {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct OwnedRuntime(PathBuf);

impl OwnedRuntime {
    fn new() -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "eliot-multi-agent-path-identity-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if self.0.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.0);
        }
        if let Ok(secret_root) = test_secret_root(&self.0) {
            let _ = fs::remove_dir_all(secret_root);
        }
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn spawn(command: &mut Command) -> TestResult<Self> {
        Ok(Self(Some(command.spawn()?)))
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> TestResult {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self
                .0
                .as_mut()
                .ok_or("owned child already consumed")?
                .try_wait()?
                .is_some()
            {
                self.0.take();
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        Err("owned child did not stop before deadline".into())
    }

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
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_for_changed_json(
    path: &Path,
    field: &str,
    previous: &str,
    timeout: Duration,
) -> TestResult<Value> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = fs::read(path)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && value.get(field).and_then(Value::as_str) != Some(previous)
            && value["state"] == "ready"
        {
            return Ok(value);
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!(
        "timed out waiting for changed {field} in {}",
        path.display()
    )
    .into())
}

fn write_test_config(runtime: &Path, config_path: &Path, port: u16) -> TestResult {
    fs::create_dir_all(config_path.parent().ok_or("config parent missing")?)?;
    let secret_root = test_secret_root(runtime)?;
    let password_file = secret_root
        .join("secrets")
        .join("surreal_root_password.txt");
    fs::create_dir_all(password_file.parent().ok_or("password parent missing")?)?;
    fs::write(&password_file, "multi-agent-test-secret")?;
    let storage = slash(&runtime.join("surrealdb-rocks"));
    let run_id = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("test runtime name missing")?;
    let password_file =
        format!("%LOCALAPPDATA%/Eliot/tests/{run_id}/secrets/surreal_root_password.txt");
    let wal = slash(&runtime.join("control").join("control.redb"));
    let blobs = slash(&runtime.join("blobs"));
    let repo = repository_root()?;
    let surql = slash(&repo.join("crates/eliot-store/src/surql"));
    let migrations = slash(&repo.join("crates/eliot-store/migrations"));
    let config = format!(
        r#"schema_version = "1"

[service]
service_name = "EliotGovernorMultiAgent"
instance_id = "multi-agent-path-identity"

[db]
mode = "surreal_rpc_server"

[db.surreal]
exe = "surreal"
bind = "127.0.0.1:{port}"
endpoint = "ws://127.0.0.1:{port}/rpc"
storage = "rocksdb:{storage}"
ns = "eliot_phase_l5"
db = "memory_os_multi_agent_access"
user = "root"
password_file = "{password_file}"
log_level = "warn"
query_timeout_ms = 15000
transaction_timeout_ms = 15000
startup_timeout_ms = 20000
restart_backoff_ms = 200
max_restart_backoff_ms = 2000

[db.surreal.capabilities]
deny_all = true
allow_funcs = ["array", "string", "time", "type", "math", "vector", "search"]
allow_net = []
allow_scripting = false
allow_guests = false

[control_wal]
path = "{wal}"

[blob_store]
root = "{blobs}"

[store]
surql_dir = "{surql}"
migrations_dir = "{migrations}"
"#
    );
    fs::write(config_path, config)?;
    Ok(())
}

fn repository_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root missing")?
        .to_path_buf())
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn free_local_port() -> TestResult<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn start_surreal(runtime: &Path, port: u16) -> TestResult<OwnedChild> {
    let storage = format!("rocksdb:{}", slash(&runtime.join("surrealdb-rocks")));
    OwnedChild::spawn(
        Command::new("surreal")
            .env("SURREAL_USER", "root")
            .env("SURREAL_PASS", "multi-agent-test-secret")
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
            .arg(storage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
}

fn wait_for_tcp(port: u16, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("SurrealDB did not listen on port {port}").into())
}

fn wait_for_tcp_closed(port: u16, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("SurrealDB still listens on port {port}").into())
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eliot-governor"))
}

fn governor_command() -> Command {
    let mut command = Command::new(binary());
    for variable in [
        "ELIOT_GOVERNOR_CONFIG",
        "ELIOT_TEST_SURREAL_BIND",
        "ELIOT_TEST_SURREAL_ENDPOINT",
        "ELIOT_TEST_SURREAL_PASSWORD_FILE",
        "ELIOT_TEST_SURREAL_STORAGE",
        "ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION",
        "SURREAL_USER",
        "SURREAL_PASS",
    ] {
        command.env_remove(variable);
    }
    command.env("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION", "1");
    command
}

fn test_secret_root(runtime: &Path) -> TestResult<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA missing")?;
    let run_id = runtime
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.starts_with("eliot-multi-agent-path-identity-"))
        .ok_or("unsafe multi-agent test runtime name")?;
    Ok(PathBuf::from(local_app_data)
        .join("Eliot")
        .join("tests")
        .join(run_id))
}
