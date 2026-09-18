//! Single retained provider-process and data-root owner. No socket or RPC state.
//! The accepted kill-on-drop fallback is unchanged; drop is not clean-exit proof.
use super::millis;
use crate::config::{StoreDataRootLease, SurrealAdapterConfig};
use crate::error::AdapterError;
use eliot_platform_windows::{
    ProcessIdentity, RetainedProcessPathLease, is_eliot_governor_running,
    observe_loopback_tcp_listener_owner,
};
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout};

pub(crate) struct ProviderOwner {
    pub(super) config: SurrealAdapterConfig,
    pub(super) process_lease: Arc<RetainedProcessPathLease>,
    pub(super) provider_child: Mutex<Child>,
    pub(super) provider_process_id: u32,
    pub(super) provider_process_identity: ProcessIdentity,
    data_root_lease: StoreDataRootLease,
}
impl fmt::Debug for ProviderOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderOwner")
            .field("process_id", &self.provider_process_id)
            .field(
                "process_start",
                &self.provider_process_identity.start_time_100ns,
            )
            .field("process_lease", &"retained")
            .field("data_root_lease", &"retained")
            .finish_non_exhaustive()
    }
}
impl ProviderOwner {
    pub(super) async fn start(
        config: &SurrealAdapterConfig,
        provider_process_lease: Arc<RetainedProcessPathLease>,
    ) -> Result<(Arc<Self>, Instant), AdapterError> {
        config
            .validate()
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        // Exclusive data-root ownership is acquired before any endpoint
        // observation: a second generation sharing this data root fails here
        // with a typed denial instead of racing through the probe-to-spawn gap.
        let data_root_lease = StoreDataRootLease::claim(&config.store_data_root)?;
        config.validate_data_root_lease(&data_root_lease)?;
        let connect_timeout = millis(config.connect_timeout_ms);
        provider_process_lease
            .validate(
                Path::new(&config.provider_executable_path),
                Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .map_err(|_| {
                AdapterError::Config(
                    "canonical provider process lease failed identity validation".to_owned(),
                )
            })?;
        match is_eliot_governor_running() {
            Ok(true) => {
                return Err(AdapterError::Config(
                    "legacy eliot-governor.exe is running; refusing canonical provider launch"
                        .to_owned(),
                ));
            }
            Ok(false) => {}
            Err(error) => {
                return Err(AdapterError::Config(format!(
                    "legacy eliot-governor.exe process state is unknown: {error}"
                )));
            }
        }
        // The data-root lease above is held across this probe-to-spawn-to-bind
        // gap, closing the TOCTOU in which two generations could each observe a
        // free endpoint and spawn a provider against one data root.
        reject_occupied_endpoint(config, connect_timeout).await?;
        let mut provider_child = spawn_provider(config)?;
        let provider_process_id = provider_child.id().ok_or_else(|| {
            AdapterError::Config("canonical provider child PID is unavailable".to_owned())
        })?;
        let identity_before_listener = validate_child_process(
            config,
            &provider_process_lease,
            &mut provider_child,
            provider_process_id,
        )?;
        let deadline = Instant::now() + connect_timeout;
        Ok((
            Arc::new(Self {
                config: config.clone(),
                process_lease: provider_process_lease,
                provider_child: Mutex::new(provider_child),
                provider_process_id,
                provider_process_identity: identity_before_listener,
                data_root_lease,
            }),
            deadline,
        ))
    }
    pub(super) async fn validate_owned(&self) -> Result<(), AdapterError> {
        self.validate_liveness(&self.config, &self.process_lease)
            .await
    }
    pub(super) async fn validate_liveness(
        &self,
        config: &SurrealAdapterConfig,
        provider_process_lease: &RetainedProcessPathLease,
    ) -> Result<(), AdapterError> {
        // The retained data-root lease must still be bound to this
        // configuration's root before any child or listener proof is trusted.
        config.validate_data_root_lease(&self.data_root_lease)?;
        let mut child = self.provider_child.lock().await;
        let identity_before_listener = validate_child_process(
            config,
            provider_process_lease,
            &mut child,
            self.provider_process_id,
        )?;
        require_unchanged_identity(
            &self.provider_process_identity,
            &identity_before_listener,
            "liveness precheck",
        )?;
        let endpoint = config
            .provider_bind_address
            .parse::<SocketAddr>()
            .map_err(|_| {
                AdapterError::Config(
                    "provider bind address is not an exact loopback socket".to_owned(),
                )
            })?;
        let owner = observe_loopback_tcp_listener_owner(endpoint).map_err(|_| {
            AdapterError::Config(
                "canonical provider listener ownership could not be proven".to_owned(),
            )
        })?;
        require_listener_owner(self.provider_process_id, owner.process_id())?;
        let identity_after_listener = validate_child_process(
            config,
            provider_process_lease,
            &mut child,
            self.provider_process_id,
        )?;
        require_unchanged_identity(
            &identity_before_listener,
            &identity_after_listener,
            "liveness listener observation",
        )?;
        Ok(())
    }
}

pub(super) async fn reject_occupied_endpoint(
    config: &SurrealAdapterConfig,
    connect_timeout: Duration,
) -> Result<(), AdapterError> {
    let probe_timeout = connect_timeout.min(Duration::from_millis(100));
    if matches!(
        timeout(
            probe_timeout,
            TcpStream::connect(&config.provider_bind_address)
        )
        .await,
        Ok(Ok(_))
    ) {
        return Err(AdapterError::Config(
            "provider endpoint was occupied before the canonical child launch".to_owned(),
        ));
    }
    Ok(())
}

fn spawn_provider(config: &SurrealAdapterConfig) -> Result<Child, AdapterError> {
    let environment = provider_environment(config)?;
    let mut command = Command::new(&config.provider_executable_path);
    configure_provider_command(&mut command, config, &environment);
    command
        .spawn()
        .map_err(|_| AdapterError::Config("canonical provider process launch failed".to_owned()))
}

pub(super) trait ProviderCommand {
    fn arguments(&mut self, arguments: &[String]);
    fn working_directory(&mut self, path: &str);
    fn clear_environment(&mut self);
    fn environment(&mut self, entries: &[(OsString, OsString)]);
    fn close_standard_io(&mut self);
    fn terminate_on_drop(&mut self);
}

impl ProviderCommand for Command {
    fn arguments(&mut self, arguments: &[String]) {
        self.args(arguments);
    }

    fn working_directory(&mut self, path: &str) {
        self.current_dir(path);
    }

    fn clear_environment(&mut self) {
        self.env_clear();
    }

    fn environment(&mut self, entries: &[(OsString, OsString)]) {
        self.envs(entries.iter().cloned());
    }

    fn close_standard_io(&mut self) {
        self.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }

    fn terminate_on_drop(&mut self) {
        self.kill_on_drop(true);
    }
}

pub(super) fn configure_provider_command<T: ProviderCommand>(
    command: &mut T,
    config: &SurrealAdapterConfig,
    environment: &ProviderEnvironment,
) {
    command.arguments(&config.provider_arguments);
    command.working_directory(&config.store_work_root);
    command.clear_environment();
    command.environment(&environment.entries);
    command.close_standard_io();
    command.terminate_on_drop();
}

pub(super) fn validate_child_process(
    config: &SurrealAdapterConfig,
    provider_process_lease: &RetainedProcessPathLease,
    child: &mut Child,
    expected_process_id: u32,
) -> Result<ProcessIdentity, AdapterError> {
    let child_process_id = child.id();
    let child_exited = child
        .try_wait()
        .map_err(|_| AdapterError::ProviderUnavailable)?
        .is_some();
    require_live_child(child_process_id, expected_process_id, child_exited)?;
    provider_process_lease
        .validate_process_identity(
            expected_process_id,
            Path::new(&config.provider_executable_path),
            Path::new(&config.store_work_root),
            &config.provider_artifact_digest,
        )
        .map_err(|_| {
            AdapterError::Config(
                "canonical provider process path, digest, or live identity mismatch".to_owned(),
            )
        })
}

pub(super) fn require_live_child(
    child_process_id: Option<u32>,
    expected_process_id: u32,
    child_exited: bool,
) -> Result<(), AdapterError> {
    if child_process_id != Some(expected_process_id) || child_exited {
        return Err(AdapterError::Config(
            "canonical provider child identity is unavailable".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn require_listener_owner(expected: u32, observed: u32) -> Result<(), AdapterError> {
    if expected == 0 || observed != expected {
        return Err(AdapterError::Config(
            "provider listener is not owned by the retained canonical child".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn require_unchanged_identity(
    before: &ProcessIdentity,
    after: &ProcessIdentity,
    phase: &str,
) -> Result<(), AdapterError> {
    if before != after {
        return Err(AdapterError::Config(format!(
            "canonical provider process identity changed during {phase}"
        )));
    }
    Ok(())
}

pub(super) struct ProviderEnvironment {
    pub(super) entries: Vec<(OsString, OsString)>,
}

pub(super) fn provider_environment(
    config: &SurrealAdapterConfig,
) -> Result<ProviderEnvironment, AdapterError> {
    let system_root = std::env::var_os("SystemRoot")
        .filter(|value| Path::new(value).is_absolute())
        .ok_or_else(|| {
            AdapterError::Config("required Windows SystemRoot is unavailable".to_owned())
        })?;
    Ok(ProviderEnvironment {
        entries: vec![
            ("SystemRoot".into(), system_root.clone()),
            ("WINDIR".into(), system_root),
            ("TEMP".into(), config.store_temp_root.clone().into()),
            ("TMP".into(), config.store_temp_root.clone().into()),
        ],
    })
}
