//! Feature-gated, explicit-invocation R13 two-token Windows proof harness.
//!
//! This module is deliberately not part of the normal Kernel startup path.
//! The controller mutates SCM only after strict argument and filesystem
//! preflight, and the service worker proves its own `LocalService` token before
//! it creates the Kernel-side transport boundary.

#![allow(clippy::print_stderr)]

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SERVICE_NAME: &str = "EliotR13DeniedHarness";
const SERVICE_DISPLAY_NAME: &str = "ELIOT R13 two-token denied harness";
const LOCAL_SERVICE_SID: &str = "S-1-5-19";
const MAX_STAGE_BYTES: u64 = 2 * 1024 * 1024;
const STAGE_TIMEOUT: Duration = Duration::from_secs(45);
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(40);
const FRONT_DOOR_PIPE: &str = r"\\.\pipe\eliot\kernel\frontdoor";
// Pre-provisioned with the bounded LocalService + approved-interactive-user
// mailbox ACL. The harness never creates this directory or changes its DACL.
const EVIDENCE_ROOT: &str = r"C:\ProgramData\Eliot\R13\harness";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControllerArgs {
    bridge_exe: PathBuf,
    control_root: PathBuf,
    evidence_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkerArgs {
    bridge_exe: PathBuf,
    control_root: PathBuf,
    evidence_root: PathBuf,
    approved_user_sid: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FileIdentityWire {
    volume_serial_number: u32,
    file_index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityReceiptWire {
    host_state_root_identity: FileIdentityWire,
    bridge_directory_identity: FileIdentityWire,
    profile_identity: FileIdentityWire,
    declaration_identity: FileIdentityWire,
    host_state_root_descriptor_sha256: String,
    bridge_directory_descriptor_sha256: String,
    profile_descriptor_sha256: String,
    declaration_descriptor_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessEvidenceWire {
    process_id: u32,
    start_time_100ns: Option<u64>,
    sid: String,
    session_id: u32,
    image_path: String,
    image_file_identity: Option<FileIdentityWire>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReadyStage {
    stage: String,
    declaration_path: String,
    profile_path: String,
    profile_sha256: String,
    declaration_sha256: String,
    admission_descriptor_sha256: String,
    kernel_principal_binding: String,
    kernel_artifact_sha256: String,
    kernel_config_snapshot_sha256: String,
    worker: ProcessEvidenceWire,
    security_receipt: SecurityReceiptWire,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportReadyStage {
    stage: String,
    connection_id: String,
    challenge_nonce: String,
    challenge_sha256: String,
    bridge: ProcessEvidenceWire,
    client_hello_sha256: String,
    admission_receipt_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalResultStage {
    stage: String,
    disposition: String,
    denial_code: String,
    no_session: bool,
    no_auth_binding: bool,
    cleanup: Option<CleanupOutcome>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupOutcome {
    stopped: bool,
    deleted: bool,
    absent_after_cleanup: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupReceipt {
    stage: String,
    service_name: String,
    outcome: CleanupOutcome,
}

fn managed_attach_line(connection_id: &str) -> Result<String, String> {
    let attach = serde_json::json!({
        "op": "attach",
        "request": {
            "demand_id": "r13-denied-os-demand",
            "connection_id": connection_id,
            "attach_kind": "MANAGED",
            "pre_attach_blind_interval": null
        }
    });
    serde_json::to_string(&attach)
        .map(|line| format!("{line}\n"))
        .map_err(|error| format!("encode managed attach request: {error}"))
}

fn cleanup_succeeded(outcome: &CleanupOutcome) -> bool {
    outcome.stopped && outcome.deleted && outcome.absent_after_cleanup
}

fn service_absent_code(raw_os_error: Option<i32>) -> bool {
    raw_os_error == Some(1060)
}

fn parse_controller_args<I>(args: I) -> Result<ControllerArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|arg| arg == "--service-worker") {
        return Err(
            "controller requires --execute-approved and must not be service worker".to_owned(),
        );
    }
    let mut execute = false;
    let mut bridge = None;
    let mut root = None;
    let mut evidence = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--execute-approved" if !execute => execute = true,
            "--bridge-exe" if bridge.is_none() => {
                index += 1;
                bridge = args.get(index).map(PathBuf::from);
            }
            "--control-root" if root.is_none() => {
                index += 1;
                root = args.get(index).map(PathBuf::from);
            }
            "--evidence-root" if evidence.is_none() => {
                index += 1;
                evidence = args.get(index).map(PathBuf::from);
            }
            _ => return Err("unexpected, duplicate, or incomplete controller argument".to_owned()),
        }
        index += 1;
    }
    if !execute {
        return Err("--execute-approved is required before any system-changing action".to_owned());
    }
    let bridge_exe = bridge.ok_or_else(|| "--bridge-exe is required".to_owned())?;
    let control_root = root.ok_or_else(|| "--control-root is required".to_owned())?;
    let evidence_root = evidence.ok_or_else(|| "--evidence-root is required".to_owned())?;
    validate_absolute_path(&bridge_exe, "bridge executable")?;
    validate_absolute_path(&control_root, "control root")?;
    validate_absolute_path(&evidence_root, "evidence root")?;
    Ok(ControllerArgs {
        bridge_exe,
        control_root,
        evidence_root,
    })
}

fn parse_worker_args<I>(args: I) -> Result<WorkerArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    if args.first().map(String::as_str) != Some("--service-worker") {
        return Err("service worker entry requires --service-worker".to_owned());
    }
    let mut bridge = None;
    let mut root = None;
    let mut evidence = None;
    let mut sid = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--bridge-exe" if bridge.is_none() => {
                index += 1;
                bridge = args.get(index).map(PathBuf::from);
            }
            "--control-root" if root.is_none() => {
                index += 1;
                root = args.get(index).cloned();
            }
            "--evidence-root" if evidence.is_none() => {
                index += 1;
                evidence = args.get(index).cloned();
            }
            "--approved-user-sid" if sid.is_none() => {
                index += 1;
                sid = args.get(index).cloned();
            }
            _ => return Err("unexpected, duplicate, or incomplete service argument".to_owned()),
        }
        index += 1;
    }
    let bridge_exe = bridge.ok_or_else(|| "service bridge executable is missing".to_owned())?;
    let control_root =
        PathBuf::from(root.ok_or_else(|| "service control root is missing".to_owned())?);
    let evidence_root =
        PathBuf::from(evidence.ok_or_else(|| "service evidence root is missing".to_owned())?);
    let approved_user_sid = sid.ok_or_else(|| "service approved SID is missing".to_owned())?;
    validate_absolute_path(&bridge_exe, "bridge executable")?;
    validate_absolute_path(&control_root, "control root")?;
    validate_absolute_path(&evidence_root, "evidence root")?;
    if !is_sid(&approved_user_sid) || approved_user_sid == LOCAL_SERVICE_SID {
        return Err("approved bridge SID must be a non-service canonical SID".to_owned());
    }
    Ok(WorkerArgs {
        bridge_exe,
        control_root,
        evidence_root,
        approved_user_sid,
    })
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.to_string_lossy().chars().any(char::is_control)
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(format!(
            "{label} must be an exact absolute path without traversal"
        ));
    }
    Ok(())
}

fn validate_protected_control_root(path: &Path) -> Result<(), String> {
    let text = path.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    if !text
        .to_ascii_lowercase()
        .starts_with(r"c:\programdata\eliot\")
    {
        return Err(
            "control root must remain below the protected C:\\ProgramData\\Eliot root".to_owned(),
        );
    }
    Ok(())
}

fn validate_evidence_root(path: &Path, material_root: &Path) -> Result<(), String> {
    validate_absolute_path(path, "evidence root")?;
    if path == material_root
        || !path.is_dir()
        || !path.to_string_lossy().eq_ignore_ascii_case(EVIDENCE_ROOT)
    {
        return Err(format!(
            "evidence root must be the existing pre-provisioned mailbox {EVIDENCE_ROOT}"
        ));
    }
    Ok(())
}

fn is_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    matches!(parts.next(), Some("S"))
        && matches!(parts.next(), Some("1"))
        && parts.next().is_some()
        && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn stage_path(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

const STAGE_NAMES: &[&str] = &[
    "security-receipt.json",
    "security-receipt.json.tmp",
    "worker-ready.json",
    "worker-ready.json.tmp",
    "transport-ready.json",
    "transport-ready.json.tmp",
    "final-result.json",
    "final-result.json.tmp",
    "cleanup-result.json",
    "cleanup-result.json.tmp",
];

fn stale_stage_name(root: &Path) -> Option<&'static str> {
    STAGE_NAMES
        .iter()
        .copied()
        .find(|name| stage_path(root, name).exists())
}

fn write_atomic<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<(), String> {
    let path = stage_path(root, name);
    let temporary = path.with_extension("json.tmp");
    if path.exists() || temporary.exists() {
        return Err(format!("stage already exists: {}", path.display()));
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("create atomic stage: {error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("flush atomic stage: {error}"))?;
    std::fs::rename(&temporary, &path).map_err(|error| format!("publish atomic stage: {error}"))
}

fn read_stage<T: for<'de> Deserialize<'de>>(root: &Path, name: &str) -> Result<T, String> {
    let path = stage_path(root, name);
    let metadata =
        std::fs::metadata(&path).map_err(|error| format!("read stage metadata: {error}"))?;
    if metadata.len() == 0 || metadata.len() > MAX_STAGE_BYTES {
        return Err(format!(
            "stage size outside bounded contour: {}",
            path.display()
        ));
    }
    let bytes = std::fs::read(&path).map_err(|error| format!("read stage: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("decode stage: {error}"))
}

#[cfg(not(windows))]
pub fn run() -> i32 {
    eprintln!("R13 two-token harness is unavailable off Windows; no mutation performed");
    1
}

#[cfg(windows)]
pub fn run() -> i32 {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--service-worker")) {
        match run_dispatcher() {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("R13 service dispatcher failed: {error}");
                1
            }
        }
    } else {
        match parse_controller_args(std::env::args().skip(1)).and_then(|args| run_controller(&args))
        {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("R13 harness rejected before or during bounded run: {error}");
                1
            }
        }
    }
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
fn run_controller(args: &ControllerArgs) -> Result<(), String> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let root = std::fs::canonicalize(&args.control_root)
        .map_err(|error| format!("control root preflight: {error}"))?;
    validate_protected_control_root(&root)?;
    let evidence_root = std::fs::canonicalize(&args.evidence_root)
        .map_err(|error| format!("evidence root preflight: {error}"))?;
    validate_evidence_root(&evidence_root, &root)?;
    let bridge = std::fs::canonicalize(&args.bridge_exe)
        .map_err(|error| format!("bridge preflight: {error}"))?;
    if !bridge.is_file() || bridge.extension().and_then(|value| value.to_str()) != Some("exe") {
        return Err("bridge path must resolve to an .exe regular file".to_owned());
    }
    let current = eliot_platform_windows::current_process_named_pipe_expectation()
        .map_err(|error| format!("approved interactive identity: {error}"))?;
    if current.expected_sid() == LOCAL_SERVICE_SID || current.expected_session_id() == 0 {
        return Err("controller must run as the approved interactive user".to_owned());
    }
    let profile = root.join("agent-bridge").join("admission-profile-v1.json");
    let declaration = root.join("agent-bridge").join("client-declaration-v2.json");
    if let Some(stage) = stale_stage_name(&evidence_root) {
        return Err(format!("stale harness stage exists: {stage}"));
    }
    let final_binding_lease = eliot_platform_windows::open_agent_bridge_final_read_lease(
        &root,
        current.expected_sid(),
        &profile,
        &declaration,
    )
    .map_err(|error| format!("protected Agent Bridge retained readback: {error}"))?;
    let security_wire = security_receipt_wire(final_binding_lease.receipt());
    write_atomic(&evidence_root, "security-receipt.json", &security_wire)?;
    let reread: SecurityReceiptWire = read_stage(&evidence_root, "security-receipt.json")?;
    if reread != security_wire {
        return Err("persisted security receipt changed during readback".to_owned());
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|error| format!("open SCM: {error}"))?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(_) => return Err("fixed harness service already exists; refusing collision".to_owned()),
        Err(error) if !service_absent(&error) => {
            return Err(format!("query fixed service: {error}"));
        }
        Err(_) => {}
    }
    let executable =
        std::env::current_exe().map_err(|error| format!("current harness path: {error}"))?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: vec![
            OsString::from("--service-worker"),
            OsString::from("--bridge-exe"),
            OsString::from(bridge.as_os_str()),
            OsString::from("--control-root"),
            OsString::from(root.as_os_str()),
            OsString::from("--evidence-root"),
            OsString::from(evidence_root.as_os_str()),
            OsString::from("--approved-user-sid"),
            OsString::from(current.expected_sid()),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(r"NT AUTHORITY\LocalService")),
        account_password: None,
    };
    let service = manager
        .create_service(
            &service_info,
            ServiceAccess::START
                | ServiceAccess::STOP
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::DELETE,
        )
        .map_err(|error| format!("create fixed harness service: {error}"))?;
    let result = (|| {
        service
            .start::<OsString>(&[])
            .map_err(|error| format!("start harness service: {error}"))?;
        let worker_ready =
            wait_for_stage::<WorkerReadyStage>(&evidence_root, "worker-ready.json", STAGE_TIMEOUT)?;
        if worker_ready.stage != "worker_ready"
            || worker_ready.worker.sid != LOCAL_SERVICE_SID
            || worker_ready.worker.session_id != 0
            || worker_ready.worker.start_time_100ns.is_none()
            || worker_ready.worker.image_file_identity.is_none()
            || worker_ready.admission_descriptor_sha256.len() != 64
            || worker_ready.security_receipt != security_wire
        {
            return Err(
                "worker-ready receipt did not prove the exact LocalService Kernel".to_owned(),
            );
        }
        let mut child = tokio::process::Command::new(&bridge);
        child
            .args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--transport",
                "stdio",
                "--client-declaration",
            ])
            .arg(&declaration)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(async {
            use tokio::io::AsyncWriteExt;
            let mut child = child.spawn().map_err(|error| format!("spawn bridge: {error}"))?;
            let mut child_stdin = child
                .stdin
                .take()
                .ok_or_else(|| "bridge stdin was not piped".to_owned())?;
            let transport = wait_for_stage_async::<TransportReadyStage>(
                &evidence_root,
                "transport-ready.json",
                STAGE_TIMEOUT,
            )
            .await?;
            if transport.stage != "transport_ready"
                || transport.connection_id.is_empty()
                || transport.bridge.sid != current.expected_sid()
                || transport.bridge.session_id != current.expected_session_id()
                || !transport
                    .bridge
                    .image_path
                    .eq_ignore_ascii_case(&bridge.to_string_lossy())
                || transport.bridge.image_file_identity.is_none()
                || transport.admission_receipt_sha256.len() != 64
            {
                return Err("transport receipt did not prove the approved interactive bridge".to_owned());
            }
            let attach_line = managed_attach_line(&transport.connection_id)?;
            tokio::time::timeout(BRIDGE_TIMEOUT, async {
                child_stdin
                    .write_all(attach_line.as_bytes())
                    .await
                    .map_err(|error| format!("write managed attach request: {error}"))?;
                child_stdin
                    .flush()
                    .await
                    .map_err(|error| format!("flush managed attach request: {error}"))
            })
            .await
            .map_err(|_| "bridge attach write deadline exceeded".to_owned())??;
            let final_stage = wait_for_stage_async::<FinalResultStage>(&evidence_root, "final-result.json", STAGE_TIMEOUT).await?;
            if final_stage.disposition != "DENIED" || final_stage.denial_code != "SEMANTIC_RESOLUTION_UNAVAILABLE" || !final_stage.no_session || !final_stage.no_auth_binding {
                return Err("worker final result was not the typed no-session denial".to_owned());
            }
            drop(child_stdin);
            let output = tokio::time::timeout(BRIDGE_TIMEOUT, child.wait_with_output())
                .await
                .map_err(|_| "bridge output deadline exceeded".to_owned())?
                .map_err(|error| format!("bridge wait: {error}"))?;
            let stdout = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
            let stderr = String::from_utf8(output.stderr).map_err(|error| error.to_string())?;
            let expected = "{\"status\":\"error\",\"code\":\"BRIDGE_REQUEST_REJECTED\",\"detail\":\"activation denied by the trusted host provider: SEMANTIC_RESOLUTION_UNAVAILABLE\"}\n";
            if stdout != expected || !stderr.is_empty() || !output.status.success() {
                return Err("bridge output or exit status did not match exact denial".to_owned());
            }
            Ok::<(), String>(())
        })
    })();
    let cleanup = cleanup_service(service, &manager);
    let cleanup = match cleanup {
        Ok(outcome) => outcome,
        Err(error) => {
            let primary = result
                .err()
                .unwrap_or_else(|| "harness run failed".to_owned());
            return Err(format!("{primary}; cleanup failed: {error}"));
        }
    };
    let cleanup_receipt = CleanupReceipt {
        stage: "cleanup_result".to_owned(),
        service_name: SERVICE_NAME.to_owned(),
        outcome: cleanup.clone(),
    };
    let cleanup_receipt_result =
        write_atomic(&evidence_root, "cleanup-result.json", &cleanup_receipt);
    if let Err(error) = cleanup_receipt_result {
        let primary = result
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(|| "harness run failed".to_owned());
        return Err(format!(
            "{primary}; cleanup receipt publication failed: {error}"
        ));
    }
    let persisted_cleanup: CleanupReceipt = match read_stage(&evidence_root, "cleanup-result.json")
    {
        Ok(receipt) if receipt == cleanup_receipt => receipt,
        Ok(_) => {
            let primary = result
                .as_ref()
                .err()
                .cloned()
                .unwrap_or_else(|| "harness run failed".to_owned());
            return Err(format!(
                "{primary}; cleanup receipt changed during readback"
            ));
        }
        Err(error) => {
            let primary = result
                .as_ref()
                .err()
                .cloned()
                .unwrap_or_else(|| "harness run failed".to_owned());
            return Err(format!(
                "{primary}; cleanup receipt readback failed: {error}"
            ));
        }
    };
    if !cleanup_succeeded(&persisted_cleanup.outcome) {
        let primary = result
            .err()
            .unwrap_or_else(|| "harness run failed".to_owned());
        return Err(format!(
            "{primary}; cleanup did not prove stop/delete/absence"
        ));
    }
    result
}

#[cfg(windows)]
fn cleanup_service(
    service: windows_service::service::Service,
    manager: &windows_service::service_manager::ServiceManager,
) -> Result<CleanupOutcome, String> {
    use windows_service::service::{ServiceAccess, ServiceState};
    let mut errors = Vec::new();
    let status = match service.query_status() {
        Ok(status) => Some(status),
        Err(error) => {
            errors.push(format!("query service for cleanup: {error}"));
            None
        }
    };
    let stopped = if status.is_some_and(|status| status.current_state == ServiceState::Stopped) {
        true
    } else {
        match service.stop() {
            Ok(_) => match wait_for_service_state(&service, ServiceState::Stopped, STAGE_TIMEOUT) {
                Ok(()) => true,
                Err(error) => {
                    errors.push(error);
                    false
                }
            },
            Err(error) => {
                errors.push(format!("stop service: {error}"));
                false
            }
        }
    };
    let deleted = match service.delete() {
        Ok(()) => true,
        Err(error) => {
            errors.push(format!("delete service: {error}"));
            false
        }
    };
    // Close the service handle before probing absence; Windows can retain a
    // deleted service while an existing handle remains open.
    drop(service);
    let deadline = std::time::Instant::now() + STAGE_TIMEOUT;
    let absent_after_cleanup = loop {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(error) if service_absent(&error) => break true,
            Ok(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                errors.push("service remained present after cleanup deadline".to_owned());
                break false;
            }
            Err(error) => {
                errors.push(format!("verify service absence: {error}"));
                break false;
            }
        }
    };
    let outcome = CleanupOutcome {
        stopped,
        deleted,
        absent_after_cleanup,
    };
    if errors.is_empty() {
        Ok(outcome)
    } else {
        Err(format!("{}; cleanup proof={outcome:?}", errors.join("; ")))
    }
}

#[cfg(windows)]
fn wait_for_stage<T: for<'de> Deserialize<'de>>(
    root: &Path,
    name: &str,
    timeout: Duration,
) -> Result<T, String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if stage_path(root, name).is_file() {
            return read_stage(root, name);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for {name}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
async fn wait_for_stage_async<T: for<'de> Deserialize<'de>>(
    root: &Path,
    name: &str,
    timeout: Duration,
) -> Result<T, String> {
    tokio::time::timeout(timeout, async {
        loop {
            if stage_path(root, name).is_file() {
                return read_stage(root, name);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {name}"))?
}

#[cfg(windows)]
fn wait_for_service_state(
    service: &windows_service::service::Service,
    state: windows_service::service::ServiceState,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if service
            .query_status()
            .map_err(|error| error.to_string())?
            .current_state
            == state
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("service state deadline exceeded".to_owned());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
fn service_absent(error: &windows_service::Error) -> bool {
    matches!(error, windows_service::Error::Winapi(io) if service_absent_code(io.raw_os_error()))
}

#[cfg(windows)]
fn security_receipt_wire(
    receipt: &eliot_platform_windows::AgentBridgeSecurityConvergenceReceipt,
) -> SecurityReceiptWire {
    let wire = |identity: eliot_platform_windows::FileIdentity| FileIdentityWire {
        volume_serial_number: identity.volume_serial_number,
        file_index: identity.file_index,
    };
    SecurityReceiptWire {
        host_state_root_identity: wire(receipt.host_state_root_identity),
        bridge_directory_identity: wire(receipt.bridge_directory_identity),
        profile_identity: wire(receipt.profile_identity),
        declaration_identity: wire(receipt.declaration_identity),
        host_state_root_descriptor_sha256: receipt.host_state_root_descriptor_sha256.clone(),
        bridge_directory_descriptor_sha256: receipt.bridge_directory_descriptor_sha256.clone(),
        profile_descriptor_sha256: receipt.profile_descriptor_sha256.clone(),
        declaration_descriptor_sha256: receipt.declaration_descriptor_sha256.clone(),
    }
}

#[cfg(windows)]
fn admission_descriptor(
    profile: &eliot_installation::AgentBridgeInstallationProfile,
    declaration: &eliot_protocol::AgentBridgeClientDeclaration,
) -> Result<eliot_kernel_service::AgentBridgeAdmissionDescriptor, String> {
    let caller_session_policy = match profile.caller_session_policy {
        eliot_installation::AgentBridgeCallerSessionPolicy::AnyInteractiveSessionForApprovedSid => {
            eliot_kernel_service::AgentBridgeCallerSessionPolicy::AnyInteractiveSessionForApprovedSid
        }
    };
    let process_policy = match profile.process_policy {
        eliot_installation::AgentBridgeProcessPolicy::ExactProcessPerConnection => {
            eliot_kernel_service::AgentBridgeProcessPolicy::ExactProcessPerConnection
        }
    };
    let descriptor = eliot_kernel_service::AgentBridgeAdmissionDescriptor {
        wire_id: eliot_kernel_service::AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::AGENT_BRIDGE_ADMISSION_DESCRIPTOR_WIRE_VERSION,
        module_id: profile.module_id.clone(),
        profile_id: profile.profile_id.clone(),
        profile_sha256: profile.profile_sha256.as_str().to_owned(),
        executable: profile.executable_path.clone(),
        executable_sha256: profile.executable_sha256.as_str().to_owned(),
        executable_identity: eliot_kernel_service::HostFileIdentity {
            volume_serial_number: profile.executable_identity.volume_serial_number,
            file_index: profile.executable_identity.file_index,
        },
        generation: profile.module_generation.generation,
        authority_epoch: profile.module_generation.state_fence.authority_epoch,
        state_fence: profile.module_generation.state_fence.clone(),
        approved_user_sid: profile.approved_user_sid.clone(),
        caller_session_policy,
        process_policy,
        allowed_capabilities: profile.allowed_capabilities.clone(),
        allowed_privacy_classes: profile.allowed_privacy_classes.clone(),
        max_frame: profile.max_frame,
        allowed_effects: profile.allowed_effects.clone(),
        expected_kernel_principal_binding: declaration.expected_kernel_principal_binding.clone(),
        expected_kernel_config_snapshot_sha256: declaration
            .expected_kernel_config_snapshot_sha256
            .clone(),
        client_declaration_path: profile.protected_paths.client_declaration_path.clone(),
        client_declaration_sha256: declaration.declaration_sha256.clone(),
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| error.to_string())?;
    descriptor
        .validate_client_declaration(declaration)
        .map_err(|error| error.to_string())?;
    Ok(descriptor)
}

#[cfg(windows)]
fn harness_candidate(
    admission: &eliot_kernel_service::AgentBridgeAdmissionDescriptor,
    worker: &eliot_platform_windows::NamedPipePeerProcessBinding,
) -> Result<eliot_kernel_service::HostKernelCandidateBinding, String> {
    // This candidate is only the real Kernel lifecycle state-machine setup;
    // it is deliberately not presented as OS Job evidence.  The production
    // bridge admission below uses the authenticated named-pipe peer and its
    // live process binding, never this inert candidate projection.
    let worker_image = worker
        .executable_file_identity()
        .ok_or_else(|| "Worker executable file identity is unavailable".to_owned())?;
    let activation_id = "r13-two-token-activation".to_owned();
    let installation_id = "r13-two-token-installation".to_owned();
    let supervision_incarnation = eliot_runtime_contracts::SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-r13-two-token-harness:v1".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: installation_id.clone(),
        host_epoch: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "r13-host-lineage".to_owned(),
            sequence: 1,
        },
        activation_id: activation_id.clone(),
        activation_generation: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "r13-activation-lineage".to_owned(),
            sequence: 1,
        },
        kernel_generation: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "r13-kernel-lineage".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "r13-watchdog-lineage".to_owned(),
            sequence: 1,
        },
        observation_scope: eliot_runtime_contracts::SupervisionObservationScope {
            targets: vec![crate::SERVICE_NAME.to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: eliot_runtime_contracts::RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .map_err(|error| error.to_string())?;
    let host_epoch = eliot_contracts::AuthorityEpoch::new(1).map_err(|error| error.to_string())?;
    Ok(eliot_kernel_service::HostKernelCandidateBinding {
        installation_id: eliot_platform::PlatformHandle::new(installation_id)
            .map_err(|error| error.to_string())?,
        host_epoch,
        kernel_epoch: admission.authority_epoch,
        activation_id: eliot_platform::PlatformHandle::new(activation_id)
            .map_err(|error| error.to_string())?,
        artifact_hash: eliot_platform::PlatformHandle::new(admission.executable_sha256.clone())
            .map_err(|error| error.to_string())?,
        config_hash: eliot_platform::PlatformHandle::new(
            admission.expected_kernel_config_snapshot_sha256.clone(),
        )
        .map_err(|error| error.to_string())?,
        job_object_id: eliot_platform::PlatformHandle::new(
            "Local\\Eliot-R13-Two-Token-HARNESS-ONLY",
        )
        .map_err(|error| error.to_string())?,
        pipe_identity: eliot_platform::PlatformHandle::new(FRONT_DOOR_PIPE)
            .map_err(|error| error.to_string())?,
        host_process: eliot_kernel_service::HostProcessBinding {
            process_id: worker.process_id(),
            start_time_100ns: worker.start_time_100ns(),
            image_path: worker.image_path().to_owned(),
        },
        job_binding: eliot_kernel_service::HostJobBinding {
            job: eliot_kernel_service::HostJobIdentity {
                name: "Local\\Eliot-R13-Two-Token-HARNESS-ONLY".to_owned(),
            },
            root: eliot_kernel_service::HostJobRoot {
                process: eliot_kernel_service::HostProcessBinding {
                    process_id: worker.process_id(),
                    start_time_100ns: worker.start_time_100ns(),
                    image_path: worker.image_path().to_owned(),
                },
                executable: eliot_kernel_service::HostFileIdentity {
                    volume_serial_number: worker_image.volume_serial_number,
                    file_index: worker_image.file_index,
                },
            },
        },
        supervision_incarnation,
        restart_budget: eliot_kernel_service::RestartBudget::new(1, 1)
            .map_err(|error| error.to_string())?,
        agent_bridge_admission: Some(admission.clone()),
        containment_action: None,
    })
}

#[cfg(windows)]
fn run_dispatcher() -> windows_service::Result<()> {
    use std::ffi::OsString;
    use windows_service::define_windows_service;
    use windows_service::service_dispatcher;
    define_windows_service!(ffi_service_main, service_main);
    fn service_main(_arguments: Vec<OsString>) {
        // ServiceInfo.launch_arguments are part of this process command line,
        // while callback arguments are only StartService arguments.  The
        // process command line is the one authoritative, fixed worker vector.
        let _ = run_service();
    }
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(windows)]
fn run_service() -> windows_service::Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stop.store(true, Ordering::Release);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let parsed = parse_worker_args(args).map_err(|error| {
        windows_service::Error::Winapi(std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
    })?;
    let result = run_worker(&parsed, &stop);
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(u32::from(result.is_err())),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    result.map_err(|error| windows_service::Error::Winapi(std::io::Error::other(error)))
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
fn run_worker(
    args: &WorkerArgs,
    stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    let identity = eliot_platform_windows::current_process_named_pipe_expectation()
        .map_err(|error| error.to_string())?;
    if identity.expected_sid() != LOCAL_SERVICE_SID || identity.expected_session_id() != 0 {
        return Err(format!(
            "worker token was not exact LocalService/session0: sid={} session={}",
            identity.expected_sid(),
            identity.expected_session_id()
        ));
    }
    let root = std::fs::canonicalize(&args.control_root).map_err(|error| error.to_string())?;
    validate_protected_control_root(&root)?;
    let evidence_root = std::fs::canonicalize(&args.evidence_root)
        .map_err(|error| format!("evidence root preflight: {error}"))?;
    validate_evidence_root(&evidence_root, &root)?;
    let declaration_path = root.join("agent-bridge").join("client-declaration-v2.json");
    let profile_path = root.join("agent-bridge").join("admission-profile-v1.json");
    let mut final_lease = eliot_platform_windows::open_agent_bridge_final_read_lease(
        &root,
        &args.approved_user_sid,
        &profile_path,
        &declaration_path,
    )
    .map_err(|error| format!("retain final Agent Bridge binding: {error}"))?;
    let security = final_lease.receipt().clone();
    let profile_bytes = final_lease
        .read_profile_bytes()
        .map_err(|error| format!("read retained admission profile: {error}"))?;
    let declaration_bytes = final_lease
        .read_declaration_bytes()
        .map_err(|error| format!("read retained client declaration: {error}"))?;
    let profile: eliot_installation::AgentBridgeInstallationProfile =
        serde_json::from_slice(&profile_bytes).map_err(|error| error.to_string())?;
    let declaration: eliot_protocol::AgentBridgeClientDeclaration =
        serde_json::from_slice(&declaration_bytes).map_err(|error| error.to_string())?;
    profile.validate().map_err(|error| error.to_string())?;
    declaration.validate().map_err(|error| error.to_string())?;
    if profile.client_declaration != declaration
        || profile.approved_user_sid != args.approved_user_sid
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(profile.executable_path.as_str()),
            &args.bridge_exe,
        )
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(profile.protected_paths.client_declaration_path.as_str()),
            &declaration_path,
        )
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(profile.protected_paths.admission_profile_path.as_str()),
            &profile_path,
        )
    {
        return Err(
            "retained profile/declaration binding does not match the approved harness inputs"
                .to_owned(),
        );
    }
    if declaration.expected_kernel_sid != LOCAL_SERVICE_SID
        || declaration.expected_kernel_session_id != 0
    {
        return Err(
            "declaration does not bind the Kernel worker to LocalService/session0".to_owned(),
        );
    }
    let profile_sha256 = profile.profile_sha256.as_str().to_owned();
    let declaration_sha256 = declaration
        .compute_digest()
        .map_err(|error| error.to_string())?;
    if declaration_sha256 != declaration.declaration_sha256 {
        return Err("retained declaration does not match its semantic digest".to_owned());
    }
    let worker_binding =
        eliot_platform_windows::observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| format!("observe Worker process identity: {error}"))?;
    let worker_image = worker_binding
        .executable_file_identity()
        .ok_or_else(|| "Worker executable file identity is unavailable".to_owned())?;
    let worker = ProcessEvidenceWire {
        process_id: std::process::id(),
        start_time_100ns: Some(worker_binding.start_time_100ns()),
        sid: identity.expected_sid().to_owned(),
        session_id: identity.expected_session_id(),
        image_path: worker_binding.image_path().to_owned(),
        image_file_identity: Some(FileIdentityWire {
            volume_serial_number: worker_image.volume_serial_number,
            file_index: worker_image.file_index,
        }),
    };

    let admission = admission_descriptor(&profile, &declaration)?;
    let kernel = crate::KernelComposition::new(
        crate::KernelConfig::new(&root)
            .with_kernel_artifact_sha256(declaration.expected_kernel_artifact_sha256.clone())
            .with_agent_bridge_admission(admission.clone()),
    )
    .map_err(|error| format!("construct Kernel composition: {error}"))?;
    let policy = kernel
        .front_door_policy
        .lock()
        .map_err(|_| "Kernel policy lock poisoned".to_owned())?
        .clone();
    let policy_artifact = policy
        .config_snapshot
        .get("artifact_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Kernel policy artifact digest is absent".to_owned())?;
    let policy_config_digest = crate::sha256_json(&policy.config_snapshot)
        .map_err(|error| format!("compute Kernel policy digest: {error}"))?;
    if policy.session_principal_binding != declaration.expected_kernel_principal_binding
        || policy.module_generation.state_fence.authority_epoch
            != declaration.expected_kernel_authority_epoch
        || policy.module_generation.generation != declaration.expected_kernel_generation
        || policy_artifact != declaration.expected_kernel_artifact_sha256
        || policy_config_digest != declaration.expected_kernel_config_snapshot_sha256
    {
        return Err(
            "retained declaration does not bind the actual LocalService Kernel policy".to_owned(),
        );
    }
    *kernel
        .agent_bridge_profile
        .lock()
        .map_err(|_| "bridge profile lock poisoned".to_owned())? =
        Some(crate::AgentBridgeProfile {
            admission: admission.clone(),
            declaration: declaration.clone(),
        });
    let candidate = harness_candidate(&admission, &worker_binding)?;
    {
        let mut service = kernel
            .service
            .lock()
            .map_err(|_| "Kernel service lock poisoned".to_owned())?;
        service
            .reconcile(candidate.clone())
            .map_err(|error| format!("reconcile Kernel candidate: {error}"))?;
        service
            .apply(eliot_kernel_service::KernelControlCommand::Shadow)
            .map_err(|error| format!("shadow Kernel candidate: {error}"))?;
        service
            .apply(eliot_kernel_service::KernelControlCommand::PrepareHandoff)
            .map_err(|error| format!("prepare Kernel handoff: {error}"))?;
        let permit = eliot_kernel_service::KernelActivationPermit {
            operation_id: eliot_platform::PlatformHandle::new(format!(
                "r13-two-token-activation:{}",
                std::process::id()
            ))
            .map_err(|error| error.to_string())?,
            candidate_binding_digest: candidate
                .compute_digest()
                .map_err(|error| error.to_string())?,
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: eliot_platform::PlatformHandle::new(format!(
                "r13-two-token-transaction:{}",
                std::process::id()
            ))
            .map_err(|error| error.to_string())?,
            journal_sequence: 1,
            generation: admission.generation,
            authority_epoch: admission.authority_epoch,
            activation_nonce: eliot_platform::KernelActivationNonce::new(
                eliot_platform::PlatformHandle::new(
                    eliot_platform_windows::fresh_activation_nonce_material()
                        .map_err(|error| error.to_string())?
                        .to_string(),
                )
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?,
        };
        service
            .activate_permit(
                &permit,
                admission.generation,
                declaration.expected_kernel_config_snapshot_sha256.clone(),
            )
            .map_err(|error| format!("activate Kernel candidate: {error}"))?;
        let activation_nonce_digest = service
            .activation_receipt()
            .ok_or_else(|| "Kernel activation receipt missing".to_owned())?
            .activation_nonce_digest
            .clone();
        service
            .publish_ready(eliot_kernel_service::KernelReadyReceipt {
                activation_id: candidate.activation_id.clone(),
                activation_operation_id: permit.operation_id,
                activation_nonce_digest,
                process: eliot_kernel_service::ProcessObservation {
                    process_id: eliot_platform::PlatformHandle::new(format!(
                        "pid:{}:start:{}",
                        worker_binding.process_id(),
                        worker_binding.start_time_100ns()
                    ))
                    .map_err(|error| error.to_string())?,
                    job_object_id: candidate.job_object_id.clone(),
                    state: eliot_runtime_contracts::ServiceProcessState::Ready,
                    health: eliot_runtime_contracts::HealthVector::healthy(),
                    evidence_refs: vec![
                        eliot_platform::PlatformHandle::new("r13-two-token-worker-evidence")
                            .map_err(|error| error.to_string())?,
                    ],
                },
                health: eliot_runtime_contracts::HealthVector::healthy(),
                evidence_refs: vec![
                    eliot_platform::PlatformHandle::new("r13-two-token-worker-evidence")
                        .map_err(|error| error.to_string())?,
                ],
            })
            .map_err(|error| format!("publish Kernel Ready state: {error}"))?;
    }
    kernel.note_agent_bridge_peer_set_change();
    write_atomic(
        &evidence_root,
        "worker-ready.json",
        &WorkerReadyStage {
            stage: "worker_ready".to_owned(),
            declaration_path: declaration_path.to_string_lossy().into_owned(),
            profile_path: profile_path.to_string_lossy().into_owned(),
            profile_sha256,
            declaration_sha256,
            admission_descriptor_sha256: admission.descriptor_sha256.clone(),
            kernel_principal_binding: declaration.expected_kernel_principal_binding.clone(),
            kernel_artifact_sha256: declaration.expected_kernel_artifact_sha256.clone(),
            kernel_config_snapshot_sha256: declaration
                .expected_kernel_config_snapshot_sha256
                .clone(),
            worker,
            security_receipt: security_receipt_wire(&security),
        },
    )?;

    let peers = kernel
        .front_door_peer_set(&identity)
        .map_err(|error| format!("construct production front-door peer set: {error}"))?;
    let mut server = eliot_ipc::NamedPipeServer::create_with_peer_set(FRONT_DOOR_PIPE, &peers)
        .map_err(|error| error.to_string())?;
    let limits = eliot_ipc::TransportLimits::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        if stop.load(Ordering::Acquire) {
            return Err("worker stopped before transport".to_owned());
        }
        let selection = tokio::time::timeout(
            STAGE_TIMEOUT,
            server.wait_for_authenticated_client_with_peer_set(STAGE_TIMEOUT, &peers),
        )
        .await
        .map_err(|_| "bridge peer authentication deadline exceeded".to_owned())?
        .map_err(|error| error.to_string())?;
        let peer = server.peer_identity().clone();
        let handshake = kernel
            .begin_agent_bridge(&selection, peer.clone())
            .map_err(|error| format!("begin production Agent Bridge handshake: {error}"))?;
        tokio::time::timeout(
            STAGE_TIMEOUT,
            server.send_frame(&handshake.challenge_frame, limits),
        )
        .await
        .map_err(|_| "challenge send deadline exceeded".to_owned())?
        .map_err(|error| error.to_string())?;
        let hello_frame = tokio::time::timeout(STAGE_TIMEOUT, server.receive_frame(limits))
            .await
            .map_err(|_| "bridge hello deadline exceeded".to_owned())?
            .map_err(|error| error.to_string())?;
        let receipt = kernel
            .accept_agent_bridge_hello(&handshake.connection_id, &hello_frame)
            .map_err(|error| format!("accept production Agent Bridge hello: {error}"))?;
        receipt.validate().map_err(|error| error.to_string())?;
        let binding = peer
            .process_binding()
            .ok_or_else(|| "missing observed bridge process proof".to_owned())?;
        let image = binding
            .executable_file_identity()
            .ok_or_else(|| "missing observed bridge image identity".to_owned())?;
        let (sid, session_id) = match &peer {
            eliot_ipc::PeerIdentity::Authenticated {
                user_identity,
                session_identity,
                ..
            } => (
                user_identity.clone(),
                session_identity
                    .parse::<u32>()
                    .map_err(|_| "invalid observed session".to_owned())?,
            ),
            eliot_ipc::PeerIdentity::Unavailable { .. } => {
                return Err("bridge peer was not authenticated".to_owned());
            }
        };
        let transport = TransportReadyStage {
            stage: "transport_ready".to_owned(),
            connection_id: handshake.connection_id.clone(),
            challenge_nonce: handshake.challenge.challenge_nonce.clone(),
            challenge_sha256: handshake.challenge.challenge_sha256.clone(),
            bridge: ProcessEvidenceWire {
                process_id: binding.process_id(),
                start_time_100ns: Some(binding.start_time_100ns()),
                sid,
                session_id,
                image_path: binding.image_path().to_owned(),
                image_file_identity: Some(FileIdentityWire {
                    volume_serial_number: image.0,
                    file_index: image.1,
                }),
            },
            client_hello_sha256: receipt.client_hello_sha256.clone(),
            admission_receipt_sha256: receipt.receipt_sha256.clone(),
        };
        write_atomic(&evidence_root, "transport-ready.json", &transport)?;
        let receipt_frame = kernel
            .agent_bridge_admission_receipt_frame(&handshake.connection_id)
            .map_err(|error| error.to_string())?;
        tokio::time::timeout(STAGE_TIMEOUT, server.send_frame(&receipt_frame, limits))
            .await
            .map_err(|_| "admission receipt send deadline exceeded".to_owned())?
            .map_err(|error| error.to_string())?;
        let activation_frame = tokio::time::timeout(STAGE_TIMEOUT, server.receive_frame(limits))
            .await
            .map_err(|_| "bridge activation deadline exceeded".to_owned())?
            .map_err(|error| error.to_string())?;
        let response_frame = tokio::time::timeout(
            STAGE_TIMEOUT,
            kernel.await_agent_bridge_activation_response(
                &handshake.connection_id,
                &activation_frame,
            ),
        )
        .await
        .map_err(|_| "Kernel activation resolver deadline exceeded".to_owned())?
        .map_err(|error| error.to_string())?;
        let denial = match &response_frame.payload {
            eliot_protocol::ProtocolPayload::Json(payload) => serde_json::from_value::<
                eliot_protocol::AgentBridgeActivationResponse,
            >(payload.clone())
            .map_err(|error| error.to_string())?,
            _ => return Err("Kernel activation response was not JSON".to_owned()),
        };
        if !matches!(
            denial.disposition,
            eliot_protocol::AgentBridgeActivationDisposition::Denied {
                reason_code:
                    eliot_protocol::AgentBridgeActivationDenialCode::SemanticResolutionUnavailable
            }
        ) {
            return Err(
                "production Kernel did not return the typed semantic-resolution denial".to_owned(),
            );
        }
        if kernel
            .agent_bridge_connections
            .lock()
            .map_err(|_| "bridge connection lock poisoned".to_owned())?
            .values()
            .any(|state| state.session.is_some() || state.activation_completed)
        {
            return Err("typed denial unexpectedly minted a session or auth binding".to_owned());
        }
        tokio::time::timeout(STAGE_TIMEOUT, server.send_frame(&response_frame, limits))
            .await
            .map_err(|_| "activation response send deadline exceeded".to_owned())?
            .map_err(|error| error.to_string())?;
        write_atomic(
            &evidence_root,
            "final-result.json",
            &FinalResultStage {
                stage: "final_result".to_owned(),
                disposition: "DENIED".to_owned(),
                denial_code: "SEMANTIC_RESOLUTION_UNAVAILABLE".to_owned(),
                no_session: true,
                no_auth_binding: true,
                cleanup: None,
            },
        )
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn controller_requires_explicit_approval_before_path_use() {
        let result =
            parse_controller_args(["--bridge-exe".to_owned(), "C:\\bridge.exe".to_owned()]);
        assert!(result.is_err());
        assert!(matches!(result, Err(error) if error.contains("execute-approved")));
    }

    #[test]
    fn controller_rejects_service_worker_mode() {
        let result = parse_controller_args(["--service-worker".to_owned()]);
        assert!(result.is_err());
    }

    #[test]
    fn worker_command_line_vector_is_closed() {
        let result = parse_worker_args([
            "--service-worker".to_owned(),
            "--bridge-exe".to_owned(),
            "C:\\ProgramData\\Eliot\\agent-bridge\\bridge.exe".to_owned(),
            "--control-root".to_owned(),
            "C:\\ProgramData\\Eliot\\host".to_owned(),
            "--evidence-root".to_owned(),
            "C:\\ProgramData\\Eliot\\R13\\harness".to_owned(),
            "--approved-user-sid".to_owned(),
            "S-1-5-21-1000".to_owned(),
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn sid_parser_is_closed() {
        assert!(is_sid("S-1-5-21-1000"));
        assert!(!is_sid("S-1-5-19-"));
        assert!(!is_sid("user"));
    }

    #[test]
    fn attach_emission_is_managed_and_connection_bound() {
        let line = managed_attach_line("agent-bridge:connection-1").expect("attach JSON");
        assert_eq!(
            line,
            "{\"op\":\"attach\",\"request\":{\"attach_kind\":\"MANAGED\",\"connection_id\":\"agent-bridge:connection-1\",\"demand_id\":\"r13-denied-os-demand\",\"pre_attach_blind_interval\":null}}\n"
        );
    }

    #[test]
    fn only_service_not_found_is_absent() {
        assert!(service_absent_code(Some(1060)));
        assert!(!service_absent_code(Some(5)));
        assert!(!service_absent_code(None));
    }

    #[test]
    fn cleanup_receipt_is_separate_and_requires_all_proofs() {
        let incomplete = CleanupOutcome {
            stopped: true,
            deleted: true,
            absent_after_cleanup: false,
        };
        assert!(!cleanup_succeeded(&incomplete));
        let complete = CleanupOutcome {
            stopped: true,
            deleted: true,
            absent_after_cleanup: true,
        };
        assert!(cleanup_succeeded(&complete));
        let receipt = CleanupReceipt {
            stage: "cleanup_result".to_owned(),
            service_name: SERVICE_NAME.to_owned(),
            outcome: complete,
        };
        let encoded = serde_json::to_string(&receipt).expect("cleanup receipt JSON");
        assert!(encoded.contains("cleanup_result"));
        assert!(encoded.contains("absent_after_cleanup"));
    }

    #[test]
    fn stale_stage_refusal_is_deterministic() {
        let root =
            std::env::temp_dir().join(format!("eliot-r13-harness-test-{}", std::process::id()));
        std::fs::create_dir(&root).expect("temporary stage root");
        std::fs::write(root.join("transport-ready.json.tmp"), b"stale").expect("stale stage");
        assert_eq!(stale_stage_name(&root), Some("transport-ready.json.tmp"));
        std::fs::remove_dir_all(root).expect("remove temporary stage root");
    }
}
