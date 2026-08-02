use crate::StoreError;
use crate::surreal_rpc::SurrealRpcTransport;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use eliot_types::{CredentialProviderKind, SurrealServerConfig};
use eliot_windows_ipc::{credential_read_current_user, credential_write_current_user};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest as _, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{self, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x0000_0008;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Debug)]
pub struct SurrealServerSupervisor {
    config: SurrealServerConfig,
}

#[derive(Debug)]
pub struct ReadySurrealServer {
    transport: Option<Arc<SurrealRpcTransport>>,
    started_pid: Option<u32>,
    lease_path: Option<PathBuf>,
    supervisor: SurrealServerSupervisor,
}

/// Outcome of releasing this runtime's handle on the canonical `SurrealDB` server.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SurrealShutdown {
    /// True when this runtime started the server and has now stopped it.
    /// False when the runtime merely connected to a pre-existing server, which
    /// it does not own and must not stop.
    pub stopped_owned_process: bool,
    /// True when other client leases were still held when the owned process was
    /// stopped. Shutdown proceeds anyway: leaving the process this runtime is
    /// responsible for running is the worse outcome, and it is the exact defect
    /// that orphaned `SurrealDB` after `daemon stop`.
    pub drain_incomplete: bool,
    /// True when the recorded pid was already gone before shutdown ran.
    pub already_exited: bool,
}

impl SurrealShutdown {
    /// The outcome for a server this runtime connected to but does not own.
    #[must_use]
    pub const fn not_owned() -> Self {
        Self {
            stopped_owned_process: false,
            drain_incomplete: false,
            already_exited: false,
        }
    }
}

/// Evidence that a rotation happened, carrying no value derived from either
/// secret. The report is printed to stdout, so a deterministic hash of the old
/// or new password would be a durable, offline-attackable record of it for no
/// operational gain.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CredentialRotationReport {
    pub schema_version: String,
    pub credential_id: String,
    /// Randomly generated per rotation. Deliberately not derived from any
    /// secret, so it identifies the operation without describing its inputs.
    pub rotation_id: String,
    pub authority_before: CredentialProviderKind,
    pub authority_after: CredentialProviderKind,
    pub database_auth_verified: bool,
    pub legacy_file_deleted: bool,
}

struct StartLock {
    path: PathBuf,
    _file: fs::File,
}

/// Owns the exact child handle from the moment `SurrealDB` is spawned until a
/// ready runtime takes responsibility for its pid. Every ordinary error after
/// spawn is routed through [`Self::finalize_error`]; cancellation still gets a
/// best-effort synchronous kill signal from [`Drop`].
struct SpawnedServerFinalizer<'a> {
    supervisor: &'a SurrealServerSupervisor,
    child: Option<Child>,
    pid: Option<u32>,
}

impl<'a> SpawnedServerFinalizer<'a> {
    fn new(supervisor: &'a SurrealServerSupervisor, child: Child, pid: Option<u32>) -> Self {
        Self {
            supervisor,
            child: Some(child),
            pid,
        }
    }

    const fn pid(&self) -> Option<u32> {
        self.pid
    }

    fn child_mut(&mut self) -> Result<&mut Child, StoreError> {
        self.child
            .as_mut()
            .ok_or_else(|| StoreError::Process("spawned server finalizer was disarmed".to_owned()))
    }

    /// Transfers process ownership to `ReadySurrealServer` without terminating
    /// the detached server when this guard is dropped.
    fn disarm(mut self) {
        let _detached_child = self.child.take();
    }

    async fn finalize_error(mut self, primary: StoreError) -> StoreError {
        let mut cleanup_failures = Vec::new();

        if let Some(child) = self.child.as_mut() {
            let child_is_live = match child.try_wait() {
                Ok(Some(_status)) => {
                    // `try_wait` returned the exit status and reaped this exact
                    // child, so there is no live process left to kill.
                    false
                }
                Ok(None) => true,
                Err(error) => {
                    cleanup_failures.push(format!("exact child status probe: {error}"));
                    true
                }
            };
            if child_is_live {
                if let Err(error) = child.start_kill() {
                    cleanup_failures.push(format!("exact child kill: {error}"));
                }
                let wait_bound =
                    Duration::from_millis(self.supervisor.config.startup_timeout_ms.max(1_000));
                match timeout(wait_bound, child.wait()).await {
                    Ok(Ok(_status)) => {}
                    Ok(Err(error)) => {
                        cleanup_failures.push(format!("exact child wait: {error}"));
                    }
                    Err(_elapsed) => cleanup_failures.push(format!(
                        "exact child wait exceeded {}ms",
                        wait_bound.as_millis()
                    )),
                }
            }
        }
        self.child.take();

        if let Some(pid) = self.pid
            && let Err(error) = self.supervisor.remove_pid_file_if_matches(pid)
        {
            cleanup_failures.push(format!("owned pid receipt removal: {error}"));
        }

        if cleanup_failures.is_empty() {
            primary
        } else {
            StoreError::ServerStartFailed(format!(
                "primary post-spawn failure: {primary}; cleanup failures: {}",
                cleanup_failures.join("; ")
            ))
        }
    }
}

impl Drop for SpawnedServerFinalizer<'_> {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _kill_result = child.start_kill();
        }
    }
}

impl SurrealServerSupervisor {
    pub const fn new(config: SurrealServerConfig) -> Self {
        Self { config }
    }

    /// Resolves an explicit path or a bare executable name through the current
    /// process `PATH`. The resolved absolute executable is passed to the child
    /// after its environment is cleared, so runtime lookup never depends on the
    /// child's environment.
    pub fn executable_path(&self) -> Result<PathBuf, StoreError> {
        resolve_executable_path(&self.config.exe)
            .ok_or_else(|| StoreError::ServerNotFound(PathBuf::from(&self.config.exe)))
    }

    pub async fn start_or_connect(&self) -> Result<ReadySurrealServer, StoreError> {
        self.executable_path()?;

        let existing_password = self.read_existing_password()?;
        if !self.start_lock_path().is_file()
            && let Some(password) = existing_password.as_ref()
        {
            match self.connect_and_auth(password, 750).await {
                Ok(transport) => return self.ready_server(transport, None),
                Err(error @ StoreError::ServerAuthFailed(_)) => return Err(error),
                Err(_connection_error) => {}
            }
        }

        let deadline = Instant::now() + Duration::from_millis(self.config.startup_timeout_ms);
        let mut last_error: String;

        loop {
            if let Some(_lock) = self.try_acquire_start_lock()? {
                let password = self.read_or_create_password()?;
                match self.connect_and_auth(&password, 750).await {
                    Ok(transport) => return self.ready_server(transport, None),
                    Err(error @ StoreError::ServerAuthFailed(_)) => return Err(error),
                    Err(_connection_error) => {}
                }
                return Box::pin(self.spawn_and_wait(password)).await;
            }

            match self.read_existing_password()? {
                Some(password) => match self.connect_and_auth(&password, 750).await {
                    Ok(transport) => return self.ready_server(transport, None),
                    Err(error @ StoreError::ServerAuthFailed(_)) => return Err(error),
                    Err(error) => last_error = error.to_string(),
                },
                None => last_error = "credential is not initialized by lock owner".to_owned(),
            }

            if Instant::now() >= deadline {
                return Err(StoreError::ServerStartFailed(format!(
                    "startup lock wait timed out after {}ms; last error: {last_error}",
                    self.config.startup_timeout_ms
                )));
            }

            sleep(Duration::from_millis(
                self.config.restart_backoff_ms.max(250),
            ))
            .await;
        }
    }

    pub(crate) fn active_credential_fingerprint_if_exposed(
        &self,
        bytes: &[u8],
    ) -> Result<Option<String>, StoreError> {
        let Some(credential) = self.read_existing_password()? else {
            return Ok(None);
        };
        let credential = credential.expose_secret().as_bytes();
        if credential.is_empty()
            || !bytes
                .windows(credential.len())
                .any(|window| window == credential)
        {
            return Ok(None);
        }
        Ok(Some(format!("{:x}", Sha256::digest(credential))))
    }

    /// Rotates the persisted `SurrealDB` root user from the configured legacy
    /// password file to the already provisioned Windows credential.
    ///
    /// The new password is escaped into the statement text rather than bound as
    /// an RPC variable. That is not a preference: `SurrealDB` 3.1.4 rejects a
    /// parameter in the `DEFINE USER ... PASSWORD` position outright, while
    /// accepting a literal, so a bound variable is not available here. The
    /// statement is therefore treated as secret-bearing -- built immediately
    /// before the call, never logged, never echoed into an error, and dropped
    /// with the function. Secrets are never placed in argv and never returned.
    pub async fn rotate_legacy_credential_to_windows(
        &self,
    ) -> Result<CredentialRotationReport, StoreError> {
        if self.config.credential_provider != CredentialProviderKind::WindowsCredentialManager {
            return Err(StoreError::PolicyViolation(
                "credential rotation requires the Windows Credential Manager provider".to_owned(),
            ));
        }
        if self.config.user != "root" {
            return Err(StoreError::PolicyViolation(
                "credential rotation is bounded to the configured root user".to_owned(),
            ));
        }
        let previous = self.read_existing_legacy_password()?.ok_or_else(|| {
            StoreError::PolicyViolation(
                "legacy credential file is absent; refusing an ungrounded rotation".to_owned(),
            )
        })?;
        let current = self.read_windows_credential()?.ok_or_else(|| {
            StoreError::PolicyViolation(
                "Windows credential must be provisioned before database rotation".to_owned(),
            )
        })?;
        if previous.expose_secret() == current.expose_secret() {
            return Err(StoreError::PolicyViolation(
                "credential rotation requires a distinct native credential".to_owned(),
            ));
        }

        let transport = SurrealRpcTransport::connect(&self.config, 2_000).await?;
        transport.signin(&self.config.user, &previous).await?;
        let password_literal = surrealql_single_quoted(current.expose_secret());
        let statement =
            format!("DEFINE USER OVERWRITE root ON ROOT PASSWORD {password_literal} ROLES OWNER;");
        let raw = transport
            .query(
                &statement,
                serde_json::Value::Object(serde_json::Map::new()),
            )
            .await?;
        ensure_credential_rotation_query_ok(&raw)?;
        drop(transport);

        let verified = self.connect_and_auth(&current, 2_000).await?;
        drop(verified);
        let (legacy_path, _) = resolve_password_path(&self.config.password_file)?;
        fs::remove_file(&legacy_path)?;

        Ok(CredentialRotationReport {
            schema_version: "eliot-credential-rotation-v2".to_owned(),
            credential_id: self.config.credential_id.clone(),
            rotation_id: Uuid::new_v4().to_string(),
            authority_before: CredentialProviderKind::LegacyPasswordFile,
            authority_after: CredentialProviderKind::WindowsCredentialManager,
            database_auth_verified: true,
            legacy_file_deleted: true,
        })
    }

    pub async fn status(&self) -> Result<bool, StoreError> {
        let Some(password) = self.read_existing_password()? else {
            return Ok(false);
        };
        self.connect_and_auth(&password, 750).await.map(|_| true)
    }

    pub async fn stop(&self) -> Result<bool, StoreError> {
        let pid_path = self.pid_path();
        if !pid_path.is_file() {
            return Ok(false);
        }

        let pid = fs::read_to_string(&pid_path)?
            .trim()
            .parse::<u32>()
            .map_err(|error| StoreError::Process(error.to_string()))?;
        stop_pid(pid).await?;
        fs::remove_file(pid_path)?;
        Ok(true)
    }

    async fn spawn_and_wait(
        &self,
        password: SecretString,
    ) -> Result<ReadySurrealServer, StoreError> {
        let child = self.spawn_server(&password)?;
        let pid = child.id();
        let mut spawned = SpawnedServerFinalizer::new(self, child, pid);

        let startup = async {
            let pid = spawned.pid().ok_or_else(|| {
                StoreError::ServerStartFailed(
                    "spawned SurrealDB process did not expose a process id".to_owned(),
                )
            })?;

            // The executable was resolved before the spawn. Confirm the image
            // the kernel actually loaded is that same file, so a substitution
            // landing in the window between resolution and exec cannot pass
            // itself off as the canonical server -- and is never recorded as
            // an owned pid this runtime would later terminate.
            self.verify_owned_process_identity(pid)?;
            let pid_path = self.pid_path();
            if let Some(parent) = pid_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&pid_path, pid.to_string()).map_err(|error| {
                StoreError::ServerStartFailed(format!(
                    "cannot write owned pid receipt for pid {pid} at {}: {error}",
                    pid_path.display()
                ))
            })?;

            let deadline = Instant::now() + Duration::from_millis(self.config.startup_timeout_ms);
            let mut backoff = Duration::from_millis(self.config.restart_backoff_ms.max(50));
            let max_backoff = Duration::from_millis(self.config.max_restart_backoff_ms.max(50));
            let mut last_error = String::from("connection not attempted");

            while Instant::now() < deadline {
                if let Some(status) = spawned
                    .child_mut()?
                    .try_wait()
                    .map_err(|error| StoreError::Process(error.to_string()))?
                {
                    return Err(StoreError::ServerStartFailed(format!(
                        "process exited before readiness with status {status}; last error: {last_error}"
                    )));
                }

                match self
                    .connect_and_auth(&password, self.config.restart_backoff_ms.max(250))
                    .await
                {
                    Ok(transport) => return Ok((transport, pid)),
                    Err(error) => last_error = error.to_string(),
                }

                sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(max_backoff);
            }

            Err(StoreError::ServerStartFailed(format!(
                "readiness timeout after {}ms; last error: {last_error}",
                self.config.startup_timeout_ms
            )))
        }
        .await;

        match startup {
            Ok((transport, pid)) => match self.ready_server(transport, Some(pid)) {
                Ok(ready) => {
                    spawned.disarm();
                    Ok(ready)
                }
                Err(error) => Err(spawned.finalize_error(error).await),
            },
            Err(error) => Err(spawned.finalize_error(error).await),
        }
    }

    fn spawn_server(&self, password: &SecretString) -> Result<tokio::process::Child, StoreError> {
        let log_path = self.log_path();
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        let stdout = log.try_clone()?;

        let executable = self.executable_path()?;
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("SURREAL_USER", &self.config.user)
            .env("SURREAL_PASS", password.expose_secret())
            .arg("start")
            .arg("--bind")
            .arg(&self.config.bind)
            .arg("--log")
            .arg(&self.config.log_level);
        copy_minimal_windows_environment(&mut command);

        if self.config.capabilities.deny_all {
            command.arg("--deny-all");
        }
        if !self.config.capabilities.allow_funcs.is_empty() {
            command
                .arg("--allow-funcs")
                .arg(self.config.capabilities.allow_funcs.join(","));
        }
        #[cfg(windows)]
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);

        command
            .arg("--deny-net")
            .arg("--")
            .arg(&self.config.storage);

        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|error| StoreError::ServerStartFailed(error.to_string()))
    }

    fn read_or_create_password(&self) -> Result<SecretString, StoreError> {
        if let Some(password) = self.read_existing_password()? {
            return Ok(password);
        }
        match self.effective_credential_provider()? {
            CredentialProviderKind::WindowsCredentialManager => {
                let password = generate_password();
                credential_write_current_user(&self.config.credential_id, password.as_bytes())?;
                let persisted = self.read_windows_credential()?.ok_or_else(|| {
                    StoreError::PolicyViolation(
                        "Windows Credential Manager write did not persist".to_owned(),
                    )
                })?;
                if persisted.expose_secret() != password {
                    return Err(StoreError::PolicyViolation(
                        "Windows Credential Manager readback did not match the generated credential"
                            .to_owned(),
                    ));
                }
                Ok(persisted)
            }
            CredentialProviderKind::LegacyPasswordFile => self.read_or_create_legacy_password(),
            provider => Err(StoreError::PolicyViolation(format!(
                "unsupported SurrealDB credential provider: {provider:?}"
            ))),
        }
    }

    fn read_existing_password(&self) -> Result<Option<SecretString>, StoreError> {
        match self.effective_credential_provider()? {
            CredentialProviderKind::WindowsCredentialManager => self.read_windows_credential(),
            CredentialProviderKind::LegacyPasswordFile => self.read_existing_legacy_password(),
            provider => Err(StoreError::PolicyViolation(format!(
                "unsupported SurrealDB credential provider: {provider:?}"
            ))),
        }
    }

    fn read_windows_credential(&self) -> Result<Option<SecretString>, StoreError> {
        let Some(bytes) = credential_read_current_user(&self.config.credential_id)? else {
            return Ok(None);
        };
        let password = String::from_utf8(bytes).map_err(|_| {
            StoreError::PolicyViolation(
                "Windows Credential Manager value is not valid UTF-8".to_owned(),
            )
        })?;
        if password.is_empty() {
            return Err(StoreError::PolicyViolation(
                "Windows Credential Manager value is empty".to_owned(),
            ));
        }
        Ok(Some(SecretString::from(password)))
    }

    fn effective_credential_provider(&self) -> Result<CredentialProviderKind, StoreError> {
        let test_override = std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() == Ok("1")
            && std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE").as_deref()
                == Ok(self.config.password_file.as_str());
        if test_override {
            return Ok(CredentialProviderKind::LegacyPasswordFile);
        }
        if self.config.credential_provider == CredentialProviderKind::LegacyPasswordFile
            && std::env::var("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION").as_deref() != Ok("1")
        {
            return Err(StoreError::PolicyViolation(
                "legacy SurrealDB password_file requires the explicit migration gate".to_owned(),
            ));
        }
        Ok(self.config.credential_provider)
    }

    fn read_existing_legacy_password(&self) -> Result<Option<SecretString>, StoreError> {
        let (path, _) = resolve_password_path(&self.config.password_file)?;
        reject_reparse_points(&path)?;
        if path.is_dir() {
            return Err(StoreError::PolicyViolation(format!(
                "SurrealDB password path must name a file: {}",
                path.display()
            )));
        }
        if path.is_file() {
            restrict_secret_path(&path, false)?;
            return read_password(&path).map(Some);
        }
        Ok(None)
    }

    fn read_or_create_legacy_password(&self) -> Result<SecretString, StoreError> {
        let (path, dedicated_secret_dir) = resolve_password_path(&self.config.password_file)?;
        if let Some(password) = self.read_existing_legacy_password()? {
            return Ok(password);
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            reject_reparse_points(parent)?;
            if dedicated_secret_dir {
                restrict_secret_path(parent, true)?;
            }
        }
        let password = generate_password();
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if let Err(error) = restrict_secret_path(&path, false) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                file.write_all(format!("{password}\n").as_bytes())?;
                file.flush()?;
                file.sync_all()?;
                Ok(SecretString::from(password))
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                reject_reparse_points(&path)?;
                restrict_secret_path(&path, false)?;
                read_password(&path)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn connect_and_auth(
        &self,
        password: &SecretString,
        connect_timeout_ms: u64,
    ) -> Result<SurrealRpcTransport, StoreError> {
        let transport = SurrealRpcTransport::connect(&self.config, connect_timeout_ms).await?;
        transport.signin(&self.config.user, password).await?;
        transport
            .use_ns_db(&self.config.ns, &self.config.db)
            .await?;
        Ok(transport)
    }

    pub(crate) async fn connect_authenticated_sibling(
        &self,
        connect_timeout_ms: u64,
    ) -> Result<SurrealRpcTransport, StoreError> {
        let password = self.read_existing_password()?.ok_or_else(|| {
            StoreError::ServerStartFailed(
                "cannot connect a sibling transport before credentials are initialized".to_owned(),
            )
        })?;
        self.connect_and_auth(&password, connect_timeout_ms).await
    }

    fn pid_path(&self) -> PathBuf {
        self.runtime_root().join("tmp").join("surreal.pid")
    }

    fn start_lock_path(&self) -> PathBuf {
        self.runtime_root().join("tmp").join("surreal.start.lock")
    }

    fn client_lease_dir(&self) -> PathBuf {
        self.runtime_root().join("tmp").join("surreal.clients")
    }

    fn log_path(&self) -> PathBuf {
        self.runtime_root()
            .join("logs")
            .join("surreal-server-current.jsonl")
    }

    fn try_acquire_start_lock(&self) -> Result<Option<StartLock>, StoreError> {
        let path = self.start_lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        if stale_start_lock(&path, self.config.startup_timeout_ms) {
            let _ = fs::remove_file(&path);
        }

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => Ok(Some(StartLock { path, _file: file })),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn acquire_start_lock(&self) -> Result<StartLock, StoreError> {
        let deadline = Instant::now() + Duration::from_millis(self.config.startup_timeout_ms);
        loop {
            if let Some(lock) = self.try_acquire_start_lock()? {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                return Err(StoreError::ServerStartFailed(format!(
                    "startup lock acquire timed out after {}ms",
                    self.config.startup_timeout_ms
                )));
            }
            sleep(Duration::from_millis(
                self.config.restart_backoff_ms.max(250),
            ))
            .await;
        }
    }

    fn create_client_lease(&self) -> Result<PathBuf, StoreError> {
        let dir = self.client_lease_dir();
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}-{}.lease", process::id(), Uuid::new_v4()));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(path)
    }

    async fn wait_for_client_leases_to_drain(&self) -> Result<(), StoreError> {
        let deadline =
            Instant::now() + Duration::from_millis(self.config.startup_timeout_ms.max(600_000));
        loop {
            if self.active_client_lease_count()? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(StoreError::ServerStartFailed(
                    "timed out waiting for active surreal clients to drain".to_owned(),
                ));
            }
            sleep(Duration::from_millis(
                self.config.restart_backoff_ms.max(250),
            ))
            .await;
        }
    }

    fn active_client_lease_count(&self) -> Result<usize, StoreError> {
        let dir = self.client_lease_dir();
        cleanup_stale_client_leases(&dir, self.config.startup_timeout_ms)?;
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("lease")
            {
                count += 1;
            }
        }
        Ok(count)
    }

    fn ready_server(
        &self,
        transport: SurrealRpcTransport,
        started_pid: Option<u32>,
    ) -> Result<ReadySurrealServer, StoreError> {
        Ok(ReadySurrealServer {
            transport: Some(Arc::new(transport)),
            started_pid,
            lease_path: Some(self.create_client_lease()?),
            supervisor: self.clone(),
        })
    }

    fn remove_pid_file_if_matches(&self, pid: u32) -> Result<(), StoreError> {
        let pid_path = self.pid_path();
        if !pid_path.is_file() {
            return Ok(());
        }

        let recorded_pid = fs::read_to_string(&pid_path)?
            .trim()
            .parse::<u32>()
            .map_err(|error| StoreError::Process(error.to_string()))?;
        if recorded_pid == pid {
            fs::remove_file(pid_path)?;
        }
        Ok(())
    }

    fn runtime_root(&self) -> PathBuf {
        storage_path(&self.config.storage)
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from(".eliot-governor"))
    }

    /// Stops the `SurrealDB` process this runtime started, returning whether the
    /// process had already exited on its own.
    ///
    /// A recorded pid is not by itself authority to terminate anything. Pids are
    /// reused, so a stale record can name an unrelated process; the pid is bound
    /// to the executable image actually backing it before any termination, and
    /// the exit is confirmed afterwards.
    async fn stop_owned_process(&self, pid: u32) -> Result<bool, StoreError> {
        if !process_is_alive(pid)? {
            return Ok(true);
        }
        self.verify_owned_process_identity(pid)?;
        stop_pid(pid).await?;
        self.wait_for_process_exit(pid).await?;
        Ok(false)
    }

    /// Refuses to act on a pid whose running image is not the `SurrealDB`
    /// executable this supervisor is configured to own.
    #[cfg(windows)]
    fn verify_owned_process_identity(&self, pid: u32) -> Result<(), StoreError> {
        let expected = self.executable_path()?;
        let actual = eliot_windows_ipc::process_image_path(pid).map_err(|error| {
            StoreError::Process(format!("cannot read the image of pid {pid}: {error}"))
        })?;
        if same_executable(&expected, &actual) {
            return Ok(());
        }
        Err(StoreError::PolicyViolation(format!(
            "refusing to stop pid {pid}: running image {} is not the owned SurrealDB executable {}",
            actual.display(),
            expected.display()
        )))
    }

    #[cfg(not(windows))]
    fn verify_owned_process_identity(&self, _pid: u32) -> Result<(), StoreError> {
        Ok(())
    }

    async fn wait_for_process_exit(&self, pid: u32) -> Result<(), StoreError> {
        let deadline =
            Instant::now() + Duration::from_millis(self.config.startup_timeout_ms.max(5_000));
        loop {
            if !process_is_alive(pid)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(StoreError::Process(format!(
                    "owned SurrealDB pid {pid} did not exit after being stopped"
                )));
            }
            sleep(Duration::from_millis(
                self.config.restart_backoff_ms.max(50),
            ))
            .await;
        }
    }
}

fn generate_password() -> String {
    STANDARD_NO_PAD.encode(format!(
        "{}{}{}",
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4()
    ))
}

fn resolve_executable_path(configured: &str) -> Option<PathBuf> {
    let configured_path = PathBuf::from(configured);
    if configured_path.is_file() {
        return Some(configured_path);
    }
    if configured_path.components().count() != 1 {
        return None;
    }

    let mut names = vec![configured.to_owned()];
    #[cfg(windows)]
    if configured_path.extension().is_none() {
        names.push(format!("{configured}.exe"));
    }

    let search_path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&search_path) {
        for name in &names {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn copy_minimal_windows_environment(command: &mut Command) {
    for name in ["SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn ensure_credential_rotation_query_ok(raw: &serde_json::Value) -> Result<(), StoreError> {
    let results = raw.as_array().ok_or_else(|| {
        StoreError::PolicyViolation("credential rotation returned an invalid response".to_owned())
    })?;
    if results
        .iter()
        .any(|result| result.get("status").and_then(serde_json::Value::as_str) == Some("ERR"))
    {
        return Err(StoreError::PolicyViolation(
            "credential rotation query was rejected".to_owned(),
        ));
    }
    Ok(())
}

fn surrealql_single_quoted(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

const LOCAL_APP_DATA_PREFIXES: &[&str] = &["%LOCALAPPDATA%/", "%LOCALAPPDATA%\\"];

fn resolve_password_path(configured: &str) -> Result<(PathBuf, bool), StoreError> {
    for prefix in LOCAL_APP_DATA_PREFIXES {
        let Some(configured_prefix) = configured.get(..prefix.len()) else {
            continue;
        };
        if configured_prefix.eq_ignore_ascii_case(prefix) {
            let relative = &configured[prefix.len()..];
            let local = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
                StoreError::PolicyViolation(
                    "LOCALAPPDATA is required by db.surreal.password_file".to_owned(),
                )
            })?;
            let local = PathBuf::from(local);
            if !local.is_absolute() {
                return Err(StoreError::PolicyViolation(
                    "LOCALAPPDATA must be absolute for db.surreal.password_file".to_owned(),
                ));
            }
            let relative = Path::new(relative);
            let has_only_normal_components = relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)));
            if relative.as_os_str().is_empty()
                || configured.ends_with(['/', '\\'])
                || !has_only_normal_components
                || relative.file_name().is_none()
            {
                return Err(StoreError::PolicyViolation(
                    "db.surreal.password_file must be a normalized file below LOCALAPPDATA"
                        .to_owned(),
                ));
            }
            return Ok((local.join(relative), true));
        }
    }
    Err(StoreError::PolicyViolation(
        "db.surreal.password_file must use the %LOCALAPPDATA%/ prefix".to_owned(),
    ))
}

fn read_password(path: &Path) -> Result<SecretString, StoreError> {
    let password = fs::read_to_string(path)?;
    let password = password.trim();
    if password.is_empty() {
        return Err(StoreError::PolicyViolation(
            "SurrealDB password file is empty".to_owned(),
        ));
    }
    Ok(SecretString::from(password.to_owned()))
}

fn reject_reparse_points(path: &Path) -> Result<(), StoreError> {
    for candidate in path.ancestors().filter(|candidate| candidate.exists()) {
        let metadata = fs::symlink_metadata(candidate)?;
        if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
            return Err(StoreError::PolicyViolation(format!(
                "SurrealDB password path crosses a reparse point: {}",
                candidate.display()
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn current_windows_sid() -> Result<String, StoreError> {
    let output = std::process::Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|error| StoreError::Process(error.to_string()))?;
    if !output.status.success() {
        return Err(StoreError::Process(
            "whoami.exe failed while resolving the current Windows SID".to_owned(),
        ));
    }
    let text =
        String::from_utf8(output.stdout).map_err(|error| StoreError::Process(error.to_string()))?;
    text.trim()
        .trim_matches('"')
        .rsplit_once("\",\"")
        .map(|(_, sid)| sid.trim_matches('"').to_owned())
        .filter(|sid| {
            sid.starts_with("S-")
                && sid.chars().all(|character| {
                    character == 'S' || character == '-' || character.is_ascii_digit()
                })
        })
        .ok_or_else(|| StoreError::Process("whoami.exe returned an invalid Windows SID".to_owned()))
}

#[cfg(windows)]
fn restrict_secret_path(path: &Path, directory: bool) -> Result<(), StoreError> {
    let sid = current_windows_sid()?;
    let user_grant = if directory {
        format!("*{sid}:(OI)(CI)F")
    } else {
        format!("*{sid}:F")
    };
    let system_grant = if directory {
        "*S-1-5-18:(OI)(CI)F"
    } else {
        "*S-1-5-18:F"
    };
    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &user_grant,
            "/grant:r",
            system_grant,
            "/remove:g",
            "*S-1-1-0",
            "*S-1-5-11",
            "*S-1-5-32-545",
        ])
        .output()
        .map_err(|error| StoreError::Process(error.to_string()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(StoreError::PolicyViolation(format!(
            "failed to restrict the SurrealDB secret ACL without resetting inheritance: {}{}",
            path.display(),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn restrict_secret_path(_path: &Path, _directory: bool) -> Result<(), StoreError> {
    Ok(())
}

impl ReadySurrealServer {
    pub(crate) fn transport(&self) -> Result<&SurrealRpcTransport, StoreError> {
        self.transport.as_deref().ok_or_else(|| {
            StoreError::PolicyViolation(
                "ready server transport was already transferred to its client set".to_owned(),
            )
        })
    }

    pub(crate) fn take_transport_handle(&mut self) -> Result<Arc<SurrealRpcTransport>, StoreError> {
        self.transport.take().ok_or_else(|| {
            StoreError::PolicyViolation(
                "ready server transport was already transferred to its client set".to_owned(),
            )
        })
    }

    pub const fn started_pid(&self) -> Option<u32> {
        self.started_pid
    }

    /// Releases this runtime's handle on the `SurrealDB` server, stopping the
    /// server process when — and only when — this runtime started it.
    ///
    /// Draining and lock acquisition are cooperative courtesies to other
    /// clients, not preconditions for ownership. Neither may abort the
    /// shutdown: a runtime that started a server and then exits without
    /// stopping it leaves an orphan holding the canonical data directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the owned process cannot be identified, refuses to
    /// stop, or when pid/lease bookkeeping cannot be updated.
    pub async fn shutdown_if_spawned(mut self) -> Result<SurrealShutdown, StoreError> {
        let mut cleanup_failures = Vec::new();
        if let Err(error) = self.release_client_lease() {
            cleanup_failures.push(format!("client lease release: {error}"));
        }
        let Some(pid) = self.started_pid.take() else {
            // Connected to a pre-existing server. It is not ours to stop.
            return if cleanup_failures.is_empty() {
                Ok(SurrealShutdown::not_owned())
            } else {
                Err(StoreError::Process(cleanup_failures.join("; ")))
            };
        };

        // Best-effort: a start lock held by another starter must not strand the
        // process this runtime owns.
        let lock = match self.supervisor.acquire_start_lock().await {
            Ok(lock) => Some(lock),
            Err(error) => {
                cleanup_failures.push(format!("shutdown coordination lock: {error}"));
                None
            }
        };
        let drain_incomplete = self
            .supervisor
            .wait_for_client_leases_to_drain()
            .await
            .is_err();

        let stop = self.supervisor.stop_owned_process(pid).await;
        drop(lock);
        let already_exited = match stop {
            Ok(already_exited) => already_exited,
            Err(error) => {
                cleanup_failures.push(format!("owned process stop: {error}"));
                return Err(StoreError::Process(cleanup_failures.join("; ")));
            }
        };

        if let Err(error) = self.supervisor.remove_pid_file_if_matches(pid) {
            cleanup_failures.push(format!("owned pid receipt removal: {error}"));
        }
        let outcome = SurrealShutdown {
            stopped_owned_process: true,
            drain_incomplete,
            already_exited,
        };
        if cleanup_failures.is_empty() {
            Ok(outcome)
        } else {
            Err(StoreError::Process(cleanup_failures.join("; ")))
        }
    }

    fn release_client_lease(&mut self) -> Result<(), StoreError> {
        if let Some(path) = self.lease_path.take()
            && path.is_file()
        {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

impl Drop for StartLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for ReadySurrealServer {
    fn drop(&mut self) {
        let _ = self.release_client_lease();
    }
}

fn storage_path(uri: &str) -> Option<PathBuf> {
    uri.strip_prefix("rocksdb:").map(PathBuf::from)
}

fn stale_start_lock(path: &Path, startup_timeout_ms: u64) -> bool {
    let stale_after = Duration::from_millis(startup_timeout_ms.saturating_mul(2).max(30_000));
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .is_ok_and(|elapsed| elapsed > stale_after)
}

fn cleanup_stale_client_leases(dir: &Path, startup_timeout_ms: u64) -> Result<(), StoreError> {
    if !dir.is_dir() {
        return Ok(());
    }
    let stale_after = Duration::from_millis(startup_timeout_ms.max(600_000));
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("lease") {
            continue;
        }
        let stale = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
            .is_ok_and(|elapsed| elapsed > stale_after);
        if stale || lease_owner_is_gone(&path) {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> Result<bool, StoreError> {
    eliot_windows_ipc::process_is_alive(pid)
        .map_err(|error| StoreError::Process(format!("cannot query pid {pid}: {error}")))
}

#[cfg(not(windows))]
fn process_is_alive(pid: u32) -> Result<bool, StoreError> {
    let status = std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| StoreError::Process(error.to_string()))?;
    Ok(status.success())
}

/// Compares two executable paths as Windows resolves them: canonical where the
/// file is reachable, case-insensitive either way.
#[cfg(windows)]
fn same_executable(expected: &Path, actual: &Path) -> bool {
    let normalize = |path: &Path| {
        fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .to_lowercase()
    };
    normalize(expected) == normalize(actual)
}

/// Extracts the owning process id encoded in a `{pid}-{uuid}.lease` file name.
fn lease_owner_pid(path: &Path) -> Option<u32> {
    path.file_stem()?
        .to_str()?
        .split_once('-')
        .and_then(|(pid, _)| pid.parse::<u32>().ok())
}

/// A lease whose owning process no longer exists can never be released by that
/// process. Waiting out the full stale window for it would block graceful
/// shutdown behind a client that is already gone.
///
/// Pid reuse only makes this more conservative: if the pid now belongs to some
/// unrelated live process the lease is still treated as held, and the
/// age-based sweep remains the backstop.
fn lease_owner_is_gone(path: &Path) -> bool {
    lease_owner_pid(path).is_some_and(|pid| matches!(process_is_alive(pid), Ok(false)))
}

async fn stop_pid(pid: u32) -> Result<(), StoreError> {
    let status = if cfg!(windows) {
        Command::new("taskkill")
            .arg("/PID")
            .arg(pid.to_string())
            .arg("/T")
            .arg("/F")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
    } else {
        Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
    }
    .map_err(|error| StoreError::Process(error.to_string()))?;

    if status.success() {
        Ok(())
    } else {
        Err(StoreError::Process(format!(
            "failed to stop pid {pid}: {status}"
        )))
    }
}

#[cfg(test)]
mod security_tests {
    use super::{
        SurrealServerSupervisor, reject_reparse_points, resolve_executable_path,
        resolve_password_path, surrealql_single_quoted,
    };
    use eliot_types::{GovernorConfig, TaskId};
    use secrecy::ExposeSecret;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn credential_rotation_literal_is_single_quoted_and_escaped() {
        assert_eq!(surrealql_single_quoted("safe-value"), "'safe-value'");
        assert_eq!(surrealql_single_quoted("a'b\\c"), "'a\\'b\\\\c'");
    }

    #[test]
    fn executable_resolution_accepts_explicit_paths_and_path_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let current = std::env::current_exe()?;
        assert_eq!(
            resolve_executable_path(current.to_string_lossy().as_ref()),
            Some(current)
        );
        assert!(resolve_executable_path("cargo").is_some());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn local_app_data_password_path_is_absolute_and_outside_the_repository()
    -> Result<(), Box<dyn std::error::Error>> {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .ok_or("LOCALAPPDATA is required for this Windows test")?;
        let (resolved, dedicated) =
            resolve_password_path("%LOCALAPPDATA%/Eliot/secrets/surreal_root_password.txt")?;
        assert!(dedicated);
        assert!(resolved.is_absolute());
        assert!(resolved.starts_with(local_app_data));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn local_app_data_password_path_is_case_insensitive_and_rejects_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let (resolved, dedicated) =
            resolve_password_path("%localappdata%/Eliot/secrets/password.txt")?;
        assert!(dedicated);
        assert!(resolved.is_absolute());
        for invalid in [
            "%LOCALAPPDATA%/",
            "%LOCALAPPDATA%/.",
            "%LOCALAPPDATA%/Eliot/secrets/",
            "%LOCALAPPDATA%/Eliot/../password.txt",
            "C:/temp/surreal_root_password.txt",
        ] {
            assert!(
                resolve_password_path(invalid).is_err(),
                "accepted {invalid}"
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn local_app_data_password_path_rejects_a_junction_ancestor()
    -> Result<(), Box<dyn std::error::Error>> {
        let test_id = format!("eliot-secret-reparse-{}", TaskId::new_v7());
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .ok_or("LOCALAPPDATA is required for this Windows test")?;
        let root = PathBuf::from(local_app_data)
            .join("Eliot")
            .join("tests")
            .join(&test_id);
        let target = root.join("target");
        let junction = root.join("redirected");
        fs::create_dir_all(&target)?;

        let outcome = (|| -> Result<(), Box<dyn std::error::Error>> {
            let output = std::process::Command::new("cmd.exe")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&junction)
                .arg(&target)
                .output()?;
            if !output.status.success() {
                return Err(format!("mklink /J failed with {}", output.status).into());
            }
            let configured = format!(
                "%LOCALAPPDATA%/Eliot/tests/{test_id}/redirected/surreal_root_password.txt"
            );
            let (resolved, _) = resolve_password_path(&configured)?;
            let Some(error) = reject_reparse_points(&resolved).err() else {
                return Err(std::io::Error::other("junction ancestor was accepted").into());
            };
            assert!(error.to_string().contains("reparse point"));
            Ok(())
        })();

        if junction.exists() {
            fs::remove_dir(&junction)?;
        }
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        outcome
    }

    #[cfg(windows)]
    #[test]
    fn password_is_written_only_after_inheritance_is_removed()
    -> Result<(), Box<dyn std::error::Error>> {
        let test_id = format!("eliot-secret-acl-{}", TaskId::new_v7());
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .ok_or("LOCALAPPDATA is required for this Windows test")?;
        let root = PathBuf::from(local_app_data)
            .join("Eliot")
            .join("tests")
            .join(&test_id);
        let password_path = root.join("secrets").join("surreal_root_password.txt");
        let mut config = GovernorConfig::default().db.surreal;
        config.password_file =
            format!("%LOCALAPPDATA%/Eliot/tests/{test_id}/secrets/surreal_root_password.txt");
        let supervisor = SurrealServerSupervisor::new(config);

        let first = supervisor.read_or_create_legacy_password()?;
        assert!(!first.expose_secret().is_empty());
        let second = supervisor.read_or_create_legacy_password()?;
        assert_eq!(first.expose_secret(), second.expose_secret());

        let output = std::process::Command::new("icacls.exe")
            .arg(&password_path)
            .output()?;
        assert!(output.status.success());
        let acl = String::from_utf8(output.stdout)?.to_ascii_lowercase();
        assert!(
            !acl.contains("(i)"),
            "secret file must not inherit ACL entries"
        );
        for forbidden in [
            "everyone",
            "authenticated users",
            "builtin\\users",
            "codexsandboxusers",
        ] {
            assert!(
                !acl.contains(forbidden),
                "forbidden ACL principal: {forbidden}"
            );
        }

        fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{
        SurrealServerSupervisor, SurrealShutdown, cleanup_stale_client_leases, lease_owner_pid,
        process_is_alive,
    };
    use eliot_types::{CredentialProviderKind, SurrealCapabilities, SurrealServerConfig};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn test_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-surreal-lifecycle-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(root.join("tmp").join("surreal.clients"))?;
        Ok(root)
    }

    fn supervisor_for(exe: &str, root: &Path) -> SurrealServerSupervisor {
        SurrealServerSupervisor::new(SurrealServerConfig {
            exe: exe.to_owned(),
            bind: "127.0.0.1:0".to_owned(),
            endpoint: "ws://127.0.0.1:0/rpc".to_owned(),
            storage: format!("rocksdb:{}/surrealdb-rocks", root.display()),
            ns: "eliot".to_owned(),
            db: "eliot".to_owned(),
            user: "root".to_owned(),
            credential_provider: CredentialProviderKind::WindowsCredentialManager,
            credential_id: "surreal-runtime/lifecycle-test".to_owned(),
            password_file: "%LOCALAPPDATA%/Eliot/secrets/lifecycle-test-unused.txt".to_owned(),
            log_level: "warn".to_owned(),
            query_timeout_ms: 2_000,
            transaction_timeout_ms: 2_000,
            startup_timeout_ms: 2_000,
            restart_backoff_ms: 50,
            max_restart_backoff_ms: 200,
            capabilities: SurrealCapabilities {
                deny_all: true,
                allow_funcs: Vec::new(),
                allow_net: Vec::new(),
                allow_scripting: false,
                allow_guests: false,
            },
        })
    }

    /// Returns a pid that is guaranteed to have exited.
    fn exited_pid() -> Result<u32, Box<dyn std::error::Error>> {
        let mut child = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/c", "exit"])
                .spawn()?
        } else {
            std::process::Command::new("true").spawn()?
        };
        let pid = child.id();
        child.wait()?;
        Ok(pid)
    }

    #[test]
    fn lease_file_names_carry_their_owning_process_id() {
        assert_eq!(
            lease_owner_pid(Path::new("4321-2f1d6d1e-0000-4000-8000-000000000000.lease")),
            Some(4321)
        );
        assert_eq!(lease_owner_pid(Path::new("not-a-pid.lease")), None);
    }

    /// The drain window is ten minutes. Before this, a lease left behind by a
    /// client that had already died held graceful shutdown open for that entire
    /// window, which is what orphaned `SurrealDB` after `daemon stop`.
    #[test]
    fn a_fresh_lease_from_a_dead_client_is_reclaimed_immediately()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("dead-lease")?;
        let leases = root.join("tmp").join("surreal.clients");
        let dead = leases.join(format!("{}-{}.lease", exited_pid()?, uuid::Uuid::new_v4()));
        let live = leases.join(format!(
            "{}-{}.lease",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::write(&dead, "")?;
        fs::write(&live, "")?;

        cleanup_stale_client_leases(&leases, 2_000)?;

        assert!(
            !dead.is_file(),
            "dead client lease must not block the drain"
        );
        assert!(live.is_file(), "a live client lease must still be honored");
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    /// Pids are reused. A recorded pid alone must never authorize termination:
    /// this test points the supervisor at a pid whose image is deliberately not
    /// `SurrealDB` -- the running test process itself. If the identity check is
    /// removed, this test kills its own process instead of failing politely.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_pid_whose_image_is_not_surreal_is_never_stopped()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("identity")?;
        let supervisor = supervisor_for("cmd", &root);
        let self_pid = std::process::id();

        let refusal = supervisor.stop_owned_process(self_pid).await;

        assert!(
            refusal.is_err(),
            "stopping a pid backed by a foreign image must be refused"
        );
        assert!(
            process_is_alive(self_pid)?,
            "the refused process must still be running"
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    /// A pid that has already exited is reported, not re-killed.
    #[cfg(windows)]
    #[tokio::test]
    async fn an_already_exited_owned_process_is_reported_not_killed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("exited")?;
        let supervisor = supervisor_for("cmd", &root);

        assert!(supervisor.stop_owned_process(exited_pid()?).await?);

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    /// Forces a failure after the real detached process has spawned but before
    /// its ownership receipt can be persisted. The exact child must be reaped;
    /// neither a live pid, a listening port, nor locked runtime files may remain.
    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "requires the isolated-test harness and a real SurrealDB executable"]
    async fn a_pid_receipt_write_failure_reaps_the_exact_spawned_child()
    -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() != Ok("1") {
            return Err("ELIOT_DISABLE_REAL_PROVIDER=1 is required".into());
        }
        let exe = std::env::var("ELIOT_SURREAL_EXE")?;
        let password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
        let root = test_root("pid-receipt-write")?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let bind = listener.local_addr()?;
        drop(listener);

        let mut config = supervisor_for(&exe, &root).config;
        config.bind = bind.to_string();
        config.endpoint = format!("ws://{bind}/rpc");
        config.password_file = password_file;
        config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        config.startup_timeout_ms = 5_000;
        let supervisor = SurrealServerSupervisor::new(config);

        let pid_path = root.join("tmp").join("surreal.pid");
        fs::create_dir(&pid_path)?;

        let failure = match supervisor.start_or_connect().await {
            Err(error) => error,
            Ok(ready) => {
                let shutdown = ready.shutdown_if_spawned().await;
                return Err(format!(
                    "the pid receipt directory did not make its file write fail; shutdown: {shutdown:?}"
                )
                .into());
            }
        };
        let failure = failure.to_string();
        let pid_text = failure
            .split_once("cannot write owned pid receipt for pid ")
            .and_then(|(_, suffix)| suffix.split_once(" at ").map(|(pid, _)| pid))
            .ok_or_else(|| format!("failure did not reach the injected pid write: {failure}"))?;
        let pid = pid_text.parse::<u32>()?;

        assert!(
            !process_is_alive(pid)?,
            "post-spawn failure left pid {pid} alive"
        );
        assert!(
            std::net::TcpStream::connect(bind).is_err(),
            "post-spawn failure left {bind} accepting connections"
        );
        fs::remove_dir_all(&root)?;
        assert!(!root.exists(), "runtime root was not removable");
        Ok(())
    }

    /// The rotation report is printed to stdout. A deterministic digest of the
    /// old or new password would make that output a durable, offline-attackable
    /// record of a live credential, so no field may carry one.
    #[test]
    fn a_rotation_report_carries_no_secret_derived_digest() -> Result<(), Box<dyn std::error::Error>>
    {
        let report = super::CredentialRotationReport {
            schema_version: "eliot-credential-rotation-v2".to_owned(),
            credential_id: "surreal-runtime/default".to_owned(),
            rotation_id: uuid::Uuid::new_v4().to_string(),
            authority_before: CredentialProviderKind::LegacyPasswordFile,
            authority_after: CredentialProviderKind::WindowsCredentialManager,
            database_auth_verified: true,
            legacy_file_deleted: true,
        };

        let json = serde_json::to_string(&report)?;
        let longest_hex_run = json
            .split(|c: char| !c.is_ascii_hexdigit())
            .map(str::len)
            .max()
            .unwrap_or(0);
        assert!(
            longest_hex_run < 64,
            "a 64-character hex run in {json} looks like a secret digest"
        );
        Ok(())
    }

    #[test]
    fn a_server_this_runtime_did_not_start_is_not_owned() {
        let outcome = SurrealShutdown::not_owned();
        assert!(!outcome.stopped_owned_process);
        assert!(!outcome.drain_incomplete);
        assert!(!outcome.already_exited);
    }
}
