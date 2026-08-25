use crate::{
    named_pipe_ipc,
    runtime_instance::{
        DEFAULT_INSTANCE_NAME, RuntimeInstance, RuntimePublication, atomic_write_json,
    },
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const START_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);
const OWNED_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn daemon_run_arguments(instance_name: &str) -> [&str; 4] {
    ["daemon", "run", "--instance", instance_name]
}

pub(crate) async fn ensure_default_daemon_ready(
    config_path: &Path,
    governor: &Path,
    protocol_version: &str,
    requester: &str,
) -> Result<Value> {
    ensure_daemon_ready(
        config_path,
        governor,
        protocol_version,
        requester,
        DEFAULT_INSTANCE_NAME,
    )
    .await
}

pub(crate) async fn ensure_daemon_ready(
    config_path: &Path,
    governor: &Path,
    protocol_version: &str,
    requester: &str,
    instance_name: &str,
) -> Result<Value> {
    // Re-read and reject the legacy config before even reading runtime
    // publication state or spawning a Governor child.  This is deliberately
    // the first effectful-path guard for the reserved runtime-live endpoint.
    crate::config::load_config(config_path)
        .context("reject legacy configuration colliding with runtime-live store")?;
    let instance = RuntimeInstance::select(config_path, Some(instance_name))?;
    if let Ok(publication) = live_publication(&instance, protocol_version).await {
        validate_runtime_request_binding(&publication, governor, config_path)
            .context("existing Eliot daemon does not match the requested runtime")?;
        let report = readiness_report(&publication, governor, config_path, requester, false, false);
        write_report(&instance, &report)?;
        return Ok(report);
    }

    let discovery_before = match instance.read_publication(protocol_version) {
        Ok(publication) => format!(
            "stale_or_unreachable runtime_id={} pid={}",
            publication.runtime_id, publication.daemon_pid
        ),
        Err(error) => error.to_string(),
    };
    let stale_runtime_recovered = recover_stale_runtime(&instance, protocol_version)?;
    let mut command = Command::new(governor);
    command
        .arg("--config")
        .arg(config_path)
        .args(daemon_run_arguments(instance_name))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    #[cfg(windows)]
    command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .spawn()
        .context("start hidden user-local Eliot Governor daemon")?;
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    loop {
        if let Ok(publication) = live_publication(&instance, protocol_version).await {
            if let Err(error) =
                validate_runtime_request_binding(&publication, governor, config_path)
            {
                if child.try_wait()?.is_none() {
                    stop_owned_daemon(&instance, &mut child)
                        .await
                        .context("stop owned daemon after runtime binding mismatch")?;
                }
                return Err(error)
                    .context("started Eliot daemon does not match the requested runtime");
            }
            let report = readiness_report(
                &publication,
                governor,
                config_path,
                requester,
                true,
                stale_runtime_recovered,
            );
            write_report(&instance, &report)?;
            return Ok(report);
        }
        if let Some(status) = child.try_wait()? {
            bail!(
                "Eliot Governor daemon exited before readiness with {status}; prior discovery: {discovery_before}"
            );
        }
        if tokio::time::Instant::now() >= deadline {
            stop_owned_daemon(&instance, &mut child)
                .await
                .context("stop owned daemon after readiness timeout")?;
            bail!(
                "Eliot Governor daemon did not become ready within {} seconds; prior discovery: {discovery_before}",
                START_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn stop_owned_daemon(
    instance: &RuntimeInstance,
    child: &mut tokio::process::Child,
) -> Result<()> {
    std::fs::create_dir_all(instance.runtime_dir())?;
    std::fs::write(
        instance.stop_marker(),
        time::OffsetDateTime::now_utc().to_string(),
    )?;
    tokio::time::timeout(OWNED_STOP_TIMEOUT, child.wait())
        .await
        .context("owned Eliot daemon did not stop cooperatively")??;
    Ok(())
}

#[cfg(windows)]
fn recover_stale_runtime(instance: &RuntimeInstance, protocol_version: &str) -> Result<bool> {
    let lock_path = instance.runtime_dir().join("daemon.lock");
    if !lock_path.is_file() {
        return Ok(false);
    }
    let lock_snapshot = std::fs::read(&lock_path)
        .with_context(|| format!("read Eliot daemon lock {}", lock_path.display()))?;
    let pid_path = instance.runtime_dir().join("daemon.pid");
    let pid_snapshot = std::fs::read(&pid_path).ok();
    let publication_snapshot = instance.read_publication_any_state(protocol_version).ok();
    let owner_pid = pid_snapshot
        .as_deref()
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| parse_pid(bytes, &pid_path))
        .or_else(|| {
            (!lock_snapshot.is_empty()).then(|| parse_pid(&lock_snapshot, &lock_path))
        })
        .transpose()?
        .or_else(|| publication_snapshot.as_ref().map(|publication| publication.daemon_pid))
        .context(
            "Eliot daemon lock has no owner PID or publication; refusing unproven stale-lock removal",
        )?;
    if process_is_alive(owner_pid)? {
        bail!(
            "Eliot daemon pid {owner_pid} is alive but authenticated IPC is not ready; refusing competing startup"
        );
    }

    if std::fs::read(&lock_path).ok().as_deref() != Some(lock_snapshot.as_slice()) {
        bail!("Eliot daemon lock changed during stale-runtime recovery");
    }
    match &pid_snapshot {
        Some(snapshot) if std::fs::read(&pid_path).ok().as_deref() == Some(snapshot.as_slice()) => {
        }
        Some(_) => bail!("Eliot daemon PID changed during stale-runtime recovery"),
        None if pid_path.exists() => {
            bail!("Eliot daemon PID appeared during stale-runtime recovery");
        }
        None => {}
    }
    if pid_snapshot.is_none()
        && lock_snapshot.is_empty()
        && let Some(observed) = &publication_snapshot
    {
        let current = instance.read_publication_any_state(protocol_version)?;
        if current.runtime_id != observed.runtime_id
            || current.auth_generation != observed.auth_generation
        {
            bail!("Eliot runtime publication rotated during stale-runtime recovery");
        }
    }
    if process_is_alive(owner_pid)? {
        bail!(
            "Eliot daemon pid {owner_pid} became live during stale-runtime recovery; refusing lock removal"
        );
    }
    if pid_snapshot.is_some() {
        remove_file_if_present(&pid_path)?;
    }
    remove_file_if_present(&lock_path)?;
    Ok(true)
}

#[cfg(windows)]
fn parse_pid(bytes: &[u8], source: &Path) -> Result<u32> {
    let text = std::str::from_utf8(bytes)
        .with_context(|| format!("Eliot daemon PID source is not UTF-8: {}", source.display()))?;
    let pid = text
        .trim()
        .parse::<u32>()
        .with_context(|| format!("invalid Eliot daemon PID in {}", source.display()))?;
    if pid == 0 {
        bail!("invalid zero Eliot daemon PID in {}", source.display());
    }
    Ok(pid)
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> Result<bool> {
    eliot_windows_ipc::process_is_alive(pid)
        .with_context(|| format!("verify liveness of Eliot daemon pid {pid}"))
}

#[cfg(not(windows))]
fn recover_stale_runtime(_instance: &RuntimeInstance, _protocol_version: &str) -> Result<bool> {
    Ok(false)
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove stale runtime file {}", path.display()))
        }
    }
}

async fn live_publication(
    instance: &RuntimeInstance,
    protocol_version: &str,
) -> Result<RuntimePublication> {
    let published = instance.read_publication(protocol_version)?;
    let probed = tokio::time::timeout(
        PROBE_TIMEOUT,
        named_pipe_ipc::probe_authenticated_client(instance, "dynamic_agent"),
    )
    .await
    .context("authenticated Eliot IPC readiness probe timed out")??;
    if published.runtime_id != probed.runtime_id
        || published.auth_generation != probed.auth_generation
    {
        bail!("Eliot runtime publication rotated during authenticated readiness probe");
    }
    Ok(probed)
}

fn readiness_report(
    publication: &RuntimePublication,
    governor: &Path,
    config_path: &Path,
    requester: &str,
    started_by_request: bool,
    stale_runtime_recovered: bool,
) -> Value {
    let requested_executable = governor
        .canonicalize()
        .unwrap_or_else(|_| governor.to_path_buf());
    let published = publication
        .executable
        .canonicalize()
        .unwrap_or_else(|_| publication.executable.clone());
    let requested_hash = file_hash(&requested_executable);
    let runtime_hash = file_hash(&published);
    let executable_bytes_match = runtime_hash.is_some() && runtime_hash == requested_hash;
    let requested_config = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    let published_config = publication
        .config_path
        .canonicalize()
        .unwrap_or_else(|_| publication.config_path.clone());
    json!({
        "schema_version": "eliot-runtime-bootstrap-readiness-v1",
        "status": "ready",
        "requester": requester,
        "instance": publication.instance_name,
        "daemon_pid": publication.daemon_pid,
        "runtime_id": publication.runtime_id,
        "auth_generation": publication.auth_generation,
        "started_by_request": started_by_request,
        "stale_runtime_recovered": stale_runtime_recovered,
        "runtime_executable": published,
        "requested_executable": requested_executable,
        "runtime_executable_matches_request": path_eq_case_insensitive(&published, &requested_executable),
        "runtime_executable_hash": runtime_hash,
        "requested_executable_hash": requested_hash,
        "runtime_executable_bytes_match_request": executable_bytes_match,
        "runtime_config": published_config,
        "requested_config": requested_config,
        "runtime_config_matches_request": path_eq_case_insensitive(&published_config, &requested_config),
        "service_registry_or_admin_mutation": false
    })
}

fn validate_runtime_request_binding(
    publication: &RuntimePublication,
    governor: &Path,
    config_path: &Path,
) -> Result<()> {
    let requested_executable = governor
        .canonicalize()
        .unwrap_or_else(|_| governor.to_path_buf());
    let published_executable = publication
        .executable
        .canonicalize()
        .unwrap_or_else(|_| publication.executable.clone());
    if !path_eq_case_insensitive(&published_executable, &requested_executable) {
        bail!(
            "Eliot daemon executable mismatch: requested {}, published {}",
            requested_executable.display(),
            published_executable.display()
        );
    }
    let requested_hash =
        file_hash(&requested_executable).context("hash requested Eliot Governor executable")?;
    let published_hash =
        file_hash(&published_executable).context("hash published Eliot Governor executable")?;
    if requested_hash != published_hash {
        bail!("Eliot daemon executable bytes differ from the requested Governor");
    }

    let requested_config = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    let published_config = publication
        .config_path
        .canonicalize()
        .unwrap_or_else(|_| publication.config_path.clone());
    if !path_eq_case_insensitive(&published_config, &requested_config) {
        bail!(
            "Eliot daemon config mismatch: requested {}, published {}",
            requested_config.display(),
            published_config.display()
        );
    }
    Ok(())
}

fn write_report(instance: &RuntimeInstance, report: &Value) -> Result<()> {
    atomic_write_json(
        &instance
            .publication_root()
            .join("reports")
            .join("runtime-bootstrap")
            .join("latest.json"),
        report,
    )
}

fn path_eq_case_insensitive(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .replace('/', "\\")
        .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
}

fn file_hash(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|bytes| format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication_for_binding(
        executable: &Path,
        config_path: &Path,
        root: &Path,
    ) -> RuntimePublication {
        RuntimePublication {
            schema_version: "test".to_owned(),
            protocol_version: "test".to_owned(),
            instance_name: "test".to_owned(),
            runtime_id: uuid::Uuid::now_v7().to_string(),
            auth_generation: uuid::Uuid::now_v7().to_string(),
            pipe_name: r"\\.\pipe\eliot-test".to_owned(),
            daemon_pid: 1,
            process_start_identity: "test".to_owned(),
            executable: executable.to_path_buf(),
            executable_sha256: String::new(),
            config_path: config_path.to_path_buf(),
            store_root: root.to_path_buf(),
            publication_root: root.to_path_buf(),
            state: crate::runtime_instance::RuntimePublicationState::Ready,
            auth_ref: root.join("auth.bin"),
            published_at: "test".to_owned(),
        }
    }

    #[test]
    fn unique_bootstrap_target_never_falls_back_to_default() -> Result<()> {
        let config = std::env::temp_dir().join("eliot-bootstrap-instance-regression.toml");
        let unique_name = format!("mcp-proof-{}", uuid::Uuid::now_v7());
        let unique = RuntimeInstance::select(&config, Some(&unique_name))?;
        let default = RuntimeInstance::select(&config, Some(DEFAULT_INSTANCE_NAME))?;

        assert_eq!(unique.name(), unique_name);
        assert_ne!(unique.publication_root(), default.publication_root());
        assert_eq!(
            daemon_run_arguments(unique.name()),
            ["daemon", "run", "--instance", unique_name.as_str()]
        );
        assert!(!daemon_run_arguments(unique.name()).contains(&DEFAULT_INSTANCE_NAME));
        Ok(())
    }

    #[test]
    fn default_bootstrap_target_is_unchanged() {
        assert_eq!(
            daemon_run_arguments(DEFAULT_INSTANCE_NAME),
            ["daemon", "run", "--instance", DEFAULT_INSTANCE_NAME]
        );
    }

    #[test]
    fn runtime_binding_requires_exact_executable_and_config() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("eliot-bootstrap-binding-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root)?;
        let governor = root.join("eliot-governor.exe");
        let other_governor = root.join("other-governor.exe");
        let config = root.join("governor.toml");
        let other_config = root.join("other.toml");
        std::fs::write(&governor, b"governor")?;
        std::fs::write(&other_governor, b"governor")?;
        std::fs::write(&config, b"config")?;
        std::fs::write(&other_config, b"config")?;

        let exact = publication_for_binding(&governor, &config, &root);
        validate_runtime_request_binding(&exact, &governor, &config)?;

        let substituted_executable = publication_for_binding(&other_governor, &config, &root);
        assert!(
            validate_runtime_request_binding(&substituted_executable, &governor, &config).is_err()
        );
        let substituted_config = publication_for_binding(&governor, &other_config, &root);
        assert!(validate_runtime_request_binding(&substituted_config, &governor, &config).is_err());

        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
