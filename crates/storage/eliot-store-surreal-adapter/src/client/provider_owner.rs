//! Single retained provider-process and data-root owner. No socket or RPC state.
//!
//! The provider child is assigned to a kill-on-close Windows Job Object at
//! launch and the owning handle is retained for the child's whole life
//! (issue #1888, package K-STORE), so the provider now ends with this owner for
//! any reason the owner ends. `kill_on_drop` remains as the cooperative path for
//! ordinary drops; it is still not proof of clean exit, and the Job Object is
//! what covers the cases `Drop` never reaches.
use super::millis;
use super::rpc_parse::ProviderVersion;
use crate::config::{StoreDataRootLease, SurrealAdapterConfig};
use crate::error::AdapterError;
use crate::provider_job::ProviderKillOnCloseLease;
use eliot_platform_windows::{
    ProcessIdentity, RetainedProcessPathLease, is_eliot_governor_running,
    observe_loopback_tcp_connection_peer_owner, observe_loopback_tcp_listener_owner,
};
use secrecy::ExposeSecret;
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
    /// Sole owning handle of the kill-on-close Job Object the provider child is
    /// assigned to (#1888, K-STORE). Held for the child's whole life, so the
    /// provider ends with this owner even when the owner is terminated from
    /// outside and no `Drop` runs.
    ///
    /// It is held in a `Mutex` for a type reason, not for concurrency: the
    /// owning crate gives `JobObject` an `unsafe impl Send` and deliberately no
    /// `unsafe impl Sync`, on the stated grounds that "a Job Object handle is
    /// process-global and uniquely owned here". This owner must be `Sync`
    /// because `Arc<ProviderOwner>` reaches the adapter's port bounds, so the
    /// lease is wrapped exactly as `provider_child: Mutex<Child>` is - the same
    /// treatment the same owner already gives its other process-owned handle.
    ///
    /// The lease is never READ; it is held so its Job handle outlives the
    /// child. The mechanism is NOT this `Drop`: closing the last handle to a
    /// kill-on-close Job terminates every process assigned to it, and Windows
    /// closes that handle when the owning process ends for any reason,
    /// including an external kill that runs no destructor. That kernel-side
    /// close is what ends the provider with this owner, which is why taking the
    /// lease away or forgetting it would defeat the guarantee, and why it is
    /// stored unconditionally for the owner's whole life.
    #[expect(
        dead_code,
        reason = "never read: the retained Job handle is what ends the provider with its owner"
    )]
    pub(crate) kill_on_close_job: Mutex<ProviderKillOnCloseLease>,
    data_root_lease: StoreDataRootLease,
    /// Server version proved by the last ownership-verified authentication
    /// on this provider child (issue #1932). Set only after the full
    /// spawn/owner/version/auth chain succeeds; cleared when the bridge
    /// observes connection loss so no stale session is ever claimed live.
    authenticated_version: std::sync::Mutex<Option<ProviderVersion>>,
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
        let (mut provider_child, kill_on_close_job) = spawn_provider(config)?;
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
                kill_on_close_job: Mutex::new(kill_on_close_job),
                data_root_lease,
                authenticated_version: std::sync::Mutex::new(None),
            }),
            deadline,
        ))
    }
    /// Records the server version proved by one ownership-verified
    /// authentication on this provider child. Called only after the full
    /// spawn/owner/version/auth/identity chain succeeds.
    pub(super) fn record_authenticated_version(&self, version: ProviderVersion) {
        if let Ok(mut slot) = self.authenticated_version.lock() {
            *slot = Some(version);
        }
    }
    /// Returns the last proved server version, or `None` when no
    /// ownership-verified authentication is currently claimed live.
    pub(crate) fn authenticated_version(&self) -> Option<ProviderVersion> {
        self.authenticated_version
            .lock()
            .ok()
            .and_then(|slot| *slot)
    }
    /// Forgets the proved server version after observed connection loss, so
    /// the bridge stops claiming a live authenticated session until the next
    /// ownership-verified authentication re-proves it.
    pub(crate) fn clear_authenticated_version(&self) {
        if let Ok(mut slot) = self.authenticated_version.lock() {
            *slot = None;
        }
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

    /// Proves the connected socket's server-side TCP row belongs to the
    /// retained provider child before a reusable credential is attached.
    pub(super) async fn validate_connected_peer(
        &self,
        client_local_endpoint: SocketAddr,
        peer_endpoint: SocketAddr,
    ) -> Result<(), AdapterError> {
        self.config
            .validate_data_root_lease(&self.data_root_lease)?;
        let mut child = self.provider_child.lock().await;
        let identity_before_peer = validate_child_process(
            &self.config,
            &self.process_lease,
            &mut child,
            self.provider_process_id,
        )?;
        require_unchanged_identity(
            &self.provider_process_identity,
            &identity_before_peer,
            "authentication TCP peer precheck",
        )?;
        let configured_endpoint = self
            .config
            .provider_bind_address
            .parse::<SocketAddr>()
            .map_err(|_| {
                AdapterError::Config(
                    "provider bind address is not an exact loopback socket".to_owned(),
                )
            })?;
        if peer_endpoint != configured_endpoint {
            return Err(AdapterError::Config(
                "connected provider peer does not match its configured endpoint".to_owned(),
            ));
        }
        let observation =
            observe_loopback_tcp_connection_peer_owner(client_local_endpoint, peer_endpoint)
                .map_err(|_| {
                    AdapterError::Config(
                        "connected provider peer ownership could not be proven".to_owned(),
                    )
                })?;
        require_connected_peer_owner(self.provider_process_id, observation.process_id())?;
        let identity_after_peer = validate_child_process(
            &self.config,
            &self.process_lease,
            &mut child,
            self.provider_process_id,
        )?;
        require_unchanged_identity(
            &identity_before_peer,
            &identity_after_peer,
            "connected peer observation",
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

fn spawn_provider(
    config: &SurrealAdapterConfig,
) -> Result<(Child, ProviderKillOnCloseLease), AdapterError> {
    let environment = provider_environment(config)?;
    let mut command = Command::new(&config.provider_executable_path);
    configure_provider_command(&mut command, config, &environment);
    // One launch path (issue #1888, K-STORE): the spawned provider is admitted
    // into the kill-on-close Job Object immediately, and the returned lease is
    // held for the child's whole life. A refused assignment terminates and
    // reaps the child instead of leaving an unassigned provider running.
    crate::provider_job::spawn_provider_kill_on_close(
        || command.spawn(),
        |child: &Child| child.id(),
        |child: &mut Child| {
            let _kill_result = child.start_kill();
        },
    )
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

pub(super) fn require_connected_peer_owner(
    expected: u32,
    observed: u32,
) -> Result<(), AdapterError> {
    if expected == 0 || observed != expected {
        return Err(AdapterError::Config(
            "connected provider peer is not owned by the retained canonical child".to_owned(),
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

/// Environment name the pinned `SurrealDB` provider reads its initial root-level
/// user from.
///
/// This is the fixed channel the integration provider harness already uses for
/// this exact purpose against the pinned provider build
/// (`scripts/integration/IntegrationHarness.Store.psm1`,
/// `$Script:StoreCredentialUserEnv`), so the admitted channel is the one already
/// named for this provider rather than a newly invented one.
pub(super) const PROVIDER_BOOTSTRAP_USER_ENV: &str = "SURREAL_USER";

/// Environment name the pinned `SurrealDB` provider reads its initial root-level
/// password from. It is delivered only inside the fresh child-only block, never
/// in argv, never serialized, and never sourced from the parent environment.
pub(super) const PROVIDER_BOOTSTRAP_PASSWORD_ENV: &str = "SURREAL_PASS";

pub(super) struct ProviderEnvironment {
    pub(super) entries: Vec<(OsString, OsString)>,
}

/// Builds the provider child's own fresh environment block from a closed
/// allowlist. I15.4 (`docs/architecture/I15-04-secrets.md`) admits exactly this
/// channel for the `surreal.exe` dependency: "Host materializes a fresh
/// child-only environment block ... immediately before process creation; secret
/// values are never placed in argv, `HostStateJournal`, Module Catalog, crash
/// command text or reusable environment snapshots."
///
/// The allowlist is the literal below: the two Windows roots, the store temp
/// root, and the provider's OWN bootstrap/admin identity under the two fixed
/// names the pinned provider reads. Nothing else can appear, because
/// [`configure_provider_command`] calls `clear_environment()` before
/// `environment()`, so no parent environment and no database secret another
/// contour may be holding is ever inherited.
///
/// The ordinary client credential of this launch is absent from the block
/// because the block is closed, not because this function compares strings: it
/// only ever reads [`SurrealAdapterConfig::provider_bootstrap_password`], the
/// value resolved from the reserved provider bootstrap reference. The ordinary
/// client credential is delivered to no child contour at all — it is used by
/// this process's own `signin` only.
///
/// A missing bootstrap credential is terminal here, immediately before process
/// creation: the provider would otherwise start as an unauthenticated server.
pub(super) fn provider_environment(
    config: &SurrealAdapterConfig,
) -> Result<ProviderEnvironment, AdapterError> {
    let system_root = std::env::var_os("SystemRoot")
        .filter(|value| Path::new(value).is_absolute())
        .ok_or_else(|| {
            AdapterError::Config("required Windows SystemRoot is unavailable".to_owned())
        })?;
    if config
        .provider_bootstrap_password
        .expose_secret()
        .is_empty()
    {
        return Err(AdapterError::Config(
            "provider bootstrap credential is unavailable; refusing to launch an \
             unauthenticated provider server"
                .to_owned(),
        ));
    }
    let entries = vec![
        ("SystemRoot".into(), system_root.clone()),
        ("WINDIR".into(), system_root),
        ("TEMP".into(), config.store_temp_root.clone().into()),
        ("TMP".into(), config.store_temp_root.clone().into()),
        (
            PROVIDER_BOOTSTRAP_USER_ENV.into(),
            config.provider_bootstrap_username.clone().into(),
        ),
        (
            PROVIDER_BOOTSTRAP_PASSWORD_ENV.into(),
            config.provider_bootstrap_password.expose_secret().into(),
        ),
    ];
    Ok(ProviderEnvironment { entries })
}
