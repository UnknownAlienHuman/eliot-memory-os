use crate::mcp_stdio::{AuthenticatedRoleAuthority, CognitiveCapabilityFile, McpDaemon};
use crate::runtime_instance::{
    RuntimeDiscoveryErrorCode, RuntimeInstance, RuntimePublication, RuntimePublicationState,
    atomic_write_json,
};
use anyhow::{Context, Result};
use eliot_types::{ProjectId, SessionId, TaskId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::{Mutex, watch};
use uuid::Uuid;

#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const IPC_PROTOCOL_VERSION: &str = "eliot-ipc-l3-v2";
const MAX_REPLAY_NONCES: usize = 4096;
pub(crate) const MAX_FRAME_BYTES: usize = 1_048_576;
pub(crate) const MAX_CONNECTIONS: usize = 16;
const FORBIDDEN_FACADE_DB_ENV: &[&str] = &[
    "SURREAL_USER",
    "SURREAL_PASS",
    "ELIOT_TEST_SURREAL_BIND",
    "ELIOT_TEST_SURREAL_ENDPOINT",
    "ELIOT_TEST_SURREAL_PASSWORD_FILE",
    "ELIOT_TEST_SURREAL_STORAGE",
];

#[derive(Clone, Debug)]
#[allow(clippy::struct_field_names)]
pub(crate) struct RequestedSessionScope {
    pub session_id: Option<SessionId>,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub role_lease_id: String,
    pub role_lease_epoch: u64,
    pub role_lease_generation: u64,
}

pub(crate) fn pipe_name(config_path: &Path) -> String {
    RuntimeInstance::select(config_path, None)
        .map_or_else(|_| String::new(), |instance| instance.pipe_name())
}

#[cfg(windows)]
pub(crate) struct IpcServer {
    pipe_name: String,
    server: NamedPipeServer,
    authentication: Arc<IpcAuthenticationState>,
    instance: RuntimeInstance,
    publication: RuntimePublication,
}

#[cfg(windows)]
impl IpcServer {
    pub(crate) fn bind(
        config_path: &Path,
        instance: &RuntimeInstance,
        store_root: &Path,
    ) -> Result<Self> {
        let pipe_name = instance.pipe_name();
        let publication =
            instance.starting_publication(IPC_PROTOCOL_VERSION, config_path, store_root)?;
        let authentication = Arc::new(IpcAuthenticationState::initialize(instance, &publication)?);
        let server = eliot_windows_ipc::create_current_user_server(
            &pipe_name,
            &authentication.allowed_windows_sid,
            true,
        )
        .with_context(|| format!("bind named pipe {pipe_name}"))?;
        instance.publish(&publication)?;
        Ok(Self {
            pipe_name,
            server,
            authentication,
            instance: instance.clone(),
            publication,
        })
    }

    pub(crate) fn publish_ready(&mut self) -> Result<RuntimePublication> {
        self.instance
            .publish_state(&mut self.publication, RuntimePublicationState::Ready)?;
        Ok(self.publication.clone())
    }

    pub(crate) fn name(&self) -> &str {
        &self.pipe_name
    }

    pub(crate) async fn serve(
        self,
        daemon: Arc<McpDaemon>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let pipe_name = self.pipe_name;
        let mut server = self.server;
        let authentication = self.authentication;
        let mut connections = tokio::task::JoinSet::new();

        'serve: loop {
            while connections.len() >= MAX_CONNECTIONS {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break 'serve;
                        }
                    }
                    _ = connections.join_next() => {}
                }
            }
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                connected = server.connect() => {
                    connected.with_context(|| format!("accept named pipe {pipe_name}"))?;
                    let connection = server;
                    server = eliot_windows_ipc::create_current_user_server(
                        &pipe_name,
                        &authentication.allowed_windows_sid,
                        false,
                    )
                        .with_context(|| format!("create next named-pipe instance {pipe_name}"))?;
                    let daemon = Arc::clone(&daemon);
                    let authentication = Arc::clone(&authentication);
                    connections.spawn(async move {
                        serve_connection(connection, daemon, authentication).await
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(not(windows))]
pub(crate) struct IpcServer;

#[cfg(not(windows))]
impl IpcServer {
    pub(crate) fn bind(
        _config_path: &Path,
        _instance: &RuntimeInstance,
        _store_root: &Path,
    ) -> Result<Self> {
        anyhow::bail!("named-pipe IPC requires Windows")
    }

    pub(crate) fn name(&self) -> &str {
        "unsupported"
    }

    pub(crate) fn publish_ready(&mut self) -> Result<RuntimePublication> {
        anyhow::bail!("named-pipe IPC requires Windows")
    }

    pub(crate) async fn serve(
        self,
        _daemon: Arc<McpDaemon>,
        _shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        anyhow::bail!("named-pipe IPC requires Windows")
    }
}

#[cfg(windows)]
async fn serve_connection(
    connection: NamedPipeServer,
    daemon: Arc<McpDaemon>,
    authentication: Arc<IpcAuthenticationState>,
) -> Result<()> {
    let client_process_identity = eliot_windows_ipc::named_pipe_client_process(&connection).ok();
    let (reader, mut writer) = tokio::io::split(connection);
    let mut reader = BufReader::new(reader);
    let handshake_line =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_bounded_async_line(&mut reader)).await {
            Err(_) => {
                reject_handshake(&mut writer, "handshake_timeout").await?;
                return Ok(());
            }
            Ok(Err(_)) => {
                reject_handshake(&mut writer, "invalid_handshake_frame").await?;
                return Ok(());
            }
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(line))) => line,
        };
    let client_process = if handshake_requires_process_attestation(&handshake_line) {
        client_process_identity
            .and_then(|identity| ClientProcessAttestation::from_kernel_identity(identity).ok())
    } else {
        None
    };
    let mut principal = match authentication
        .authenticate(&handshake_line, client_process.as_ref())
        .await
    {
        Ok(principal) => principal,
        Err(reason) => {
            reject_handshake(&mut writer, reason).await?;
            return Ok(());
        }
    };
    if principal.profile == "cognitive_child" {
        let Some(capability_file) = principal.capability_file.as_deref() else {
            reject_handshake(&mut writer, "invalid_cognitive_capability").await?;
            return Ok(());
        };
        let Some(capability_token) = principal.capability_token.as_deref() else {
            reject_handshake(&mut writer, "invalid_cognitive_capability").await?;
            return Ok(());
        };
        if let Ok(session_id) = daemon
            .authenticate_cognitive_child(Path::new(capability_file), capability_token)
            .await
        {
            principal.session_id = session_id;
        } else {
            reject_handshake(&mut writer, "invalid_cognitive_capability").await?;
            return Ok(());
        }
    }
    let Ok((bound_project_id, bound_task_id)) = daemon.authoritative_host_scope(
        &principal.profile,
        principal.session_id,
        principal.bound_project_id,
        principal.bound_task_id,
        principal.role_lease_id.as_deref(),
        principal.role_lease_epoch,
        principal.role_lease_generation,
    ) else {
        reject_handshake(&mut writer, "invalid_session_scope").await?;
        return Ok(());
    };
    principal.bound_project_id = bound_project_id;
    principal.bound_task_id = bound_task_id;
    let session_id = principal.session_id.to_string();
    write_authentication_result(&mut writer, true, Some(&session_id), None).await?;
    while let Some(line) = read_bounded_async_line(&mut reader).await? {
        let role_authority = retained_role_authority(&principal)?;
        if let Some(response) = daemon
            .handle_line(
                &principal.profile,
                principal.session_id,
                principal.bound_project_id,
                principal.bound_task_id,
                role_authority,
                &line,
            )
            .await?
        {
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }
    }
    Ok(())
}

fn handshake_requires_process_attestation(line: &str) -> bool {
    serde_json::from_str::<IpcClientHandshake>(line).is_ok_and(|handshake| {
        matches!(
            handshake.kind.as_str(),
            "eliot_cognitive_governor_handshake" | "eliot_host_governor_handshake"
        )
    })
}

#[cfg(windows)]
pub(crate) async fn run_stdio_client(
    instance: &RuntimeInstance,
    profile: &str,
    requested_scope: Option<RequestedSessionScope>,
) -> Result<()> {
    reject_database_environment()?;
    let mut connection = connect_client(instance, profile, requested_scope.clone()).await?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut stdin = stdin.lock();
    while let Some(line) = read_bounded_stdio_line(&mut stdin)? {
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line)
            .with_context(|| format!("parse MCP JSON-RPC line: {line}"))?;
        let expects_response = request.get("id").is_some();
        let latest = wait_for_ready_publication(instance, CONNECT_TIMEOUT).await?;
        if !same_runtime_generation(&latest, &connection.publication) {
            connection = connect_client(instance, profile, requested_scope.clone()).await?;
        }
        let response = match relay_request(&mut connection, &request, expects_response).await {
            Ok(response) => response,
            Err(first_error) => {
                let changed =
                    wait_for_publication_change(instance, &connection.publication, CONNECT_TIMEOUT)
                        .await?;
                if !changed {
                    return Err(first_error).context(
                        "daemon connection failed and runtime publication did not rotate",
                    );
                }
                connection = connect_client(instance, profile, requested_scope.clone()).await?;
                relay_request(&mut connection, &request, expects_response)
                    .await
                    .context("retry MCP request after one runtime publication refresh")?
            }
        };
        if let Some(response) = response {
            std::io::Write::write_all(&mut stdout, response.as_bytes())?;
            std::io::Write::write_all(&mut stdout, b"\n")?;
            std::io::Write::flush(&mut stdout)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) async fn probe_authenticated_client(
    instance: &RuntimeInstance,
    profile: &str,
) -> Result<RuntimePublication> {
    let connection = connect_client(instance, profile, None).await?;
    Ok(connection.publication)
}

#[cfg(not(windows))]
pub(crate) async fn probe_authenticated_client(
    _instance: &RuntimeInstance,
    _profile: &str,
) -> Result<RuntimePublication> {
    anyhow::bail!("named-pipe IPC requires Windows")
}

#[cfg(windows)]
struct IpcClientConnection {
    responses: BufReader<tokio::io::ReadHalf<NamedPipeClient>>,
    writer: tokio::io::WriteHalf<NamedPipeClient>,
    publication: RuntimePublication,
}

#[cfg(windows)]
async fn connect_client(
    instance: &RuntimeInstance,
    profile: &str,
    requested_scope: Option<RequestedSessionScope>,
) -> Result<IpcClientConnection> {
    connect_global_client(instance, profile, requested_scope, "eliot_ipc_handshake").await
}

#[cfg(windows)]
async fn connect_global_client(
    instance: &RuntimeInstance,
    profile: &str,
    requested_scope: Option<RequestedSessionScope>,
    handshake_kind: &str,
) -> Result<IpcClientConnection> {
    match profile {
        "cognitive_governor" if handshake_kind == "eliot_cognitive_governor_handshake" => {}
        "host_governor" if handshake_kind == "eliot_host_governor_handshake" => {}
        "cognitive_governor" | "cognitive_child" | "host_governor" => {
            anyhow::bail!(
                "private Governor profiles cannot authenticate with the normal global-token handshake"
            );
        }
        _ if handshake_kind != "eliot_ipc_handshake" => {
            anyhow::bail!("private Governor handshake requires its exact private profile");
        }
        _ => {}
    }
    let publication = wait_for_ready_publication(instance, CONNECT_TIMEOUT).await?;
    let auth_file = read_authentication_file(instance, &publication)?;
    let pipe_name = publication.pipe_name.clone();
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let client = loop {
        match ClientOptions::new().open(&pipe_name) {
            Ok(client) => break client,
            Err(error) if tokio::time::Instant::now() < deadline => {
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) && error.raw_os_error() != Some(231)
                {
                    return Err(error).with_context(|| format!("connect named pipe {pipe_name}"));
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("daemon named pipe unavailable after {CONNECT_TIMEOUT:?}: {pipe_name}")
                });
            }
        }
    };

    let (reader, mut writer) = tokio::io::split(client);
    let mut responses = BufReader::new(reader);
    let handshake = IpcClientHandshake {
        kind: handshake_kind.to_owned(),
        protocol_version: IPC_PROTOCOL_VERSION.to_owned(),
        instance_name: publication.instance_name.clone(),
        runtime_id: publication.runtime_id.clone(),
        token: auth_file.token,
        token_generation_id: auth_file.auth_generation,
        client_nonce: Uuid::new_v4().to_string(),
        profile: profile.to_owned(),
        requested_session_id: requested_scope
            .as_ref()
            .and_then(|scope| scope.session_id)
            .map(|session_id| session_id.to_string()),
        requested_project_id: requested_scope
            .as_ref()
            .map(|scope| scope.project_id.to_string()),
        requested_task_id: requested_scope
            .as_ref()
            .and_then(|scope| scope.task_id)
            .map(|task_id| task_id.to_string()),
        requested_role_lease_id: requested_scope
            .as_ref()
            .map(|scope| scope.role_lease_id.clone()),
        requested_role_lease_epoch: requested_scope.as_ref().map(|scope| scope.role_lease_epoch),
        requested_role_lease_generation: requested_scope
            .as_ref()
            .map(|scope| scope.role_lease_generation),
        capability_file: None,
        capability_token: None,
    };
    writer
        .write_all(serde_json::to_string(&handshake)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let handshake_result = read_bounded_async_line(&mut responses)
        .await?
        .context("daemon closed named pipe before IPC handshake result")?;
    let handshake_result: IpcHandshakeResult =
        serde_json::from_str(&handshake_result).context("parse IPC handshake result")?;
    if !handshake_result.accepted {
        anyhow::bail!(
            "Governor IPC authentication rejected: {}",
            handshake_result.reason.as_deref().unwrap_or("rejected")
        );
    }
    Ok(IpcClientConnection {
        responses,
        writer,
        publication,
    })
}

#[cfg(windows)]
pub(crate) async fn cognitive_governor_request(
    instance: &RuntimeInstance,
    method: &str,
    params: Value,
) -> Result<Value> {
    if !matches!(
        method,
        "cognitive/seal" | "cognitive/begin" | "cognitive/terminal" | "cognitive/status"
    ) {
        anyhow::bail!("unsupported private cognitive Governor RPC method");
    }
    let mut connection = connect_global_client(
        instance,
        "cognitive_governor",
        None,
        "eliot_cognitive_governor_handshake",
    )
    .await?;
    let request_id = Uuid::new_v4().to_string();
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    });
    let response = relay_request(&mut connection, &request, true)
        .await?
        .context("private cognitive Governor RPC returned no response")?;
    let response: Value =
        serde_json::from_str(&response).context("decode cognitive Governor RPC")?;
    if let Some(error) = response.get("error") {
        anyhow::bail!("cognitive Governor RPC failed: {error}");
    }
    response
        .get("result")
        .cloned()
        .context("cognitive Governor RPC response has no result")
}

#[cfg(windows)]
pub(crate) async fn host_governor_request(
    instance: &RuntimeInstance,
    method: &str,
    params: Value,
) -> Result<Value> {
    if !private_host_governor_method_allowed(method) {
        anyhow::bail!("unsupported private host Governor RPC method");
    }
    let mut connection = connect_global_client(
        instance,
        "host_governor",
        None,
        "eliot_host_governor_handshake",
    )
    .await?;
    let request_id = Uuid::new_v4().to_string();
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    });
    let response = relay_request(&mut connection, &request, true)
        .await?
        .context("private host Governor RPC returned no response")?;
    let response: Value = serde_json::from_str(&response).context("decode host Governor RPC")?;
    if let Some(error) = response.get("error") {
        anyhow::bail!("host Governor RPC failed: {error}");
    }
    response
        .get("result")
        .cloned()
        .context("host Governor RPC response has no result")
}

fn private_host_governor_method_allowed(method: &str) -> bool {
    matches!(
        method,
        "host/role-grant"
            | "host/operation-scope-open"
            | "host/operation-scope-close"
            | "host/observation-record"
            | "ul/onboard"
            | "ul/mine-git"
            | "ul/report"
            | "ul/maintain"
            | "ul/dirty-report"
            | "ul/injection-policy-set"
            | "ul/exam-run"
            | "ul/exam-report"
            | "ul/prediction-sweep"
            | "runtime/operation"
    )
}

#[cfg(windows)]
fn read_cognitive_publication(file: &CognitiveCapabilityFile) -> Result<RuntimePublication> {
    let bytes = fs::read(&file.publication_path).context("read cognitive runtime publication")?;
    let publication: RuntimePublication =
        serde_json::from_slice(&bytes).context("decode cognitive runtime publication")?;
    if publication.protocol_version != IPC_PROTOCOL_VERSION
        || publication.instance_name != file.instance_name
        || publication.state != RuntimePublicationState::Ready
    {
        anyhow::bail!("cognitive runtime publication is stale or belongs to another instance");
    }
    Ok(publication)
}

#[cfg(windows)]
async fn connect_cognitive_child(capability_path: &Path) -> Result<IpcClientConnection> {
    let bytes = fs::read(capability_path).context("read cognitive child capability")?;
    let file: CognitiveCapabilityFile =
        serde_json::from_slice(&bytes).context("decode cognitive child capability")?;
    let publication = read_cognitive_publication(&file)?;
    let pipe_name = publication.pipe_name.clone();
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let client = loop {
        match ClientOptions::new().open(&pipe_name) {
            Ok(client) => break client,
            Err(error) if tokio::time::Instant::now() < deadline => {
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) && error.raw_os_error() != Some(231)
                {
                    return Err(error).with_context(|| format!("connect named pipe {pipe_name}"));
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "cognitive daemon pipe unavailable after {CONNECT_TIMEOUT:?}: {pipe_name}"
                    )
                });
            }
        }
    };
    let (reader, mut writer) = tokio::io::split(client);
    let mut responses = BufReader::new(reader);
    let handshake = IpcClientHandshake {
        kind: "eliot_cognitive_child_handshake".to_owned(),
        protocol_version: IPC_PROTOCOL_VERSION.to_owned(),
        instance_name: publication.instance_name.clone(),
        runtime_id: publication.runtime_id.clone(),
        token: String::new(),
        token_generation_id: String::new(),
        client_nonce: Uuid::new_v4().to_string(),
        profile: "cognitive_child".to_owned(),
        requested_session_id: None,
        requested_project_id: None,
        requested_task_id: None,
        requested_role_lease_id: None,
        requested_role_lease_epoch: None,
        requested_role_lease_generation: None,
        capability_file: Some(capability_path.to_string_lossy().into_owned()),
        capability_token: Some(file.capability_token),
    };
    writer
        .write_all(serde_json::to_string(&handshake)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let result = read_bounded_async_line(&mut responses)
        .await?
        .context("daemon closed before cognitive child handshake result")?;
    let result: IpcHandshakeResult =
        serde_json::from_str(&result).context("parse cognitive child handshake result")?;
    if !result.accepted {
        anyhow::bail!("cognitive child authentication rejected");
    }
    Ok(IpcClientConnection {
        responses,
        writer,
        publication,
    })
}

#[cfg(windows)]
pub(crate) async fn run_cognitive_stdio_client(capability_path: &Path) -> Result<()> {
    reject_database_environment()?;
    let mut connection = connect_cognitive_child(capability_path).await?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut stdin = stdin.lock();
    while let Some(line) = read_bounded_stdio_line(&mut stdin)? {
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line).context("parse cognitive MCP request")?;
        let expects_response = request.get("id").is_some();
        let response = if let Ok(response) =
            relay_request(&mut connection, &request, expects_response).await
        {
            response
        } else {
            connection = connect_cognitive_child(capability_path).await?;
            relay_request(&mut connection, &request, expects_response)
                .await
                .context("retry cognitive MCP request after daemon rotation")?
        };
        if let Some(response) = response {
            std::io::Write::write_all(&mut stdout, response.as_bytes())?;
            std::io::Write::write_all(&mut stdout, b"\n")?;
            std::io::Write::flush(&mut stdout)?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub(crate) async fn run_cognitive_stdio_client(_capability_path: &Path) -> Result<()> {
    anyhow::bail!("cognitive child MCP requires Windows named-pipe IPC")
}

#[cfg(not(windows))]
pub(crate) async fn cognitive_governor_request(
    _instance: &RuntimeInstance,
    _method: &str,
    _params: Value,
) -> Result<Value> {
    anyhow::bail!("private cognitive Governor RPC requires Windows named-pipe IPC")
}

#[cfg(not(windows))]
pub(crate) async fn host_governor_request(
    _instance: &RuntimeInstance,
    _method: &str,
    _params: Value,
) -> Result<Value> {
    anyhow::bail!("private host Governor RPC requires Windows named-pipe IPC")
}

async fn wait_for_ready_publication(
    instance: &RuntimeInstance,
    timeout: Duration,
) -> Result<RuntimePublication> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match instance.read_publication(IPC_PROTOCOL_VERSION) {
            Ok(publication) => return Ok(publication),
            Err(error)
                if matches!(
                    error.code,
                    RuntimeDiscoveryErrorCode::PublicationMissing
                        | RuntimeDiscoveryErrorCode::PublicationUnreadable
                        | RuntimeDiscoveryErrorCode::PublicationNotReady
                ) && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(windows)]
async fn relay_request(
    connection: &mut IpcClientConnection,
    request: &Value,
    expects_response: bool,
) -> Result<Option<String>> {
    connection
        .writer
        .write_all(serde_json::to_string(request)?.as_bytes())
        .await?;
    connection.writer.write_all(b"\n").await?;
    connection.writer.flush().await?;
    if !expects_response {
        return Ok(None);
    }
    read_bounded_async_line(&mut connection.responses)
        .await?
        .context("daemon closed named pipe before MCP response")
        .map(Some)
}

fn same_runtime_generation(left: &RuntimePublication, right: &RuntimePublication) -> bool {
    left.runtime_id == right.runtime_id && left.auth_generation == right.auth_generation
}

async fn wait_for_publication_change(
    instance: &RuntimeInstance,
    previous: &RuntimePublication,
    timeout: Duration,
) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if let Ok(current) = instance.read_publication(IPC_PROTOCOL_VERSION)
            && !same_runtime_generation(&current, previous)
        {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(false)
}

fn reject_database_environment() -> Result<()> {
    for variable in FORBIDDEN_FACADE_DB_ENV {
        if std::env::var_os(variable).is_some() {
            anyhow::bail!("stdio facade refuses database environment variable {variable}");
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct IpcAuthenticationFile {
    schema_version: String,
    protocol_version: String,
    instance_name: String,
    runtime_id: String,
    pipe_name: String,
    allowed_windows_sid: String,
    token: String,
    auth_generation: String,
    token_generation_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct IpcClientHandshake {
    kind: String,
    protocol_version: String,
    instance_name: String,
    runtime_id: String,
    token: String,
    token_generation_id: String,
    client_nonce: String,
    profile: String,
    #[serde(default)]
    requested_session_id: Option<String>,
    #[serde(default)]
    requested_project_id: Option<String>,
    #[serde(default)]
    requested_task_id: Option<String>,
    #[serde(default)]
    requested_role_lease_id: Option<String>,
    #[serde(default)]
    requested_role_lease_epoch: Option<u64>,
    #[serde(default)]
    requested_role_lease_generation: Option<u64>,
    #[serde(default)]
    capability_file: Option<String>,
    #[serde(default)]
    capability_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct IpcHandshakeResult {
    kind: String,
    accepted: bool,
    session_id: Option<String>,
    reason: Option<String>,
}

struct IpcPrincipal {
    profile: String,
    session_id: SessionId,
    bound_project_id: Option<ProjectId>,
    bound_task_id: Option<TaskId>,
    role_lease_id: Option<String>,
    role_lease_epoch: Option<u64>,
    role_lease_generation: Option<u64>,
    capability_file: Option<String>,
    capability_token: Option<String>,
}

fn retained_role_authority(
    principal: &IpcPrincipal,
) -> Result<Option<AuthenticatedRoleAuthority<'_>>> {
    match (
        principal.role_lease_id.as_deref(),
        principal.role_lease_epoch,
        principal.role_lease_generation,
    ) {
        (Some(role_lease_id), Some(epoch), Some(generation)) => {
            Ok(Some(AuthenticatedRoleAuthority {
                role_lease_id,
                epoch,
                generation,
            }))
        }
        (None, None, None) => Ok(None),
        _ => {
            tracing::warn!(
                profile = principal.profile.as_str(),
                session_id = %principal.session_id,
                "denied named-pipe request with incomplete retained role authority"
            );
            anyhow::bail!("authenticated named-pipe principal retained incomplete role authority")
        }
    }
}

/// Bounded window of recently seen handshake nonces.
///
/// Membership is what rejects a replay; the queue only decides what ages out.
/// Reaching capacity evicts the oldest nonce rather than refusing the client:
/// a full cache previously failed every subsequent handshake for the lifetime
/// of the auth generation, which turned the defence into an outage. Memory
/// stays bounded by `capacity` either way.
///
/// The window is per auth generation, so rotating the token discards it.
struct ReplayWindow {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl ReplayWindow {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Records a nonce, returning `false` when it was already in the window.
    fn accept(&mut self, nonce: String) -> bool {
        if self.seen.contains(&nonce) {
            return false;
        }
        if self.order.len() >= self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.seen.insert(nonce.clone());
        self.order.push_back(nonce);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }
}

struct IpcAuthenticationState {
    instance_name: String,
    runtime_id: String,
    allowed_windows_sid: String,
    token_hash: blake3::Hash,
    token_generation_id: String,
    cognitive_client_executable: PathBuf,
    cognitive_client_executable_sha256: String,
    replay_nonces: Mutex<ReplayWindow>,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ClientProcessAttestation {
    pid: u32,
    executable: PathBuf,
    executable_sha256: String,
}

#[cfg(windows)]
impl ClientProcessAttestation {
    fn from_kernel_identity(
        identity: eliot_windows_ipc::ProcessImageIdentity,
    ) -> std::io::Result<Self> {
        let eliot_windows_ipc::ProcessImageIdentity { pid, image, .. } = identity;
        let executable = image.canonicalize()?;
        let executable_sha256 = sha256_file(&executable)?;
        Ok(Self {
            pid,
            executable,
            executable_sha256,
        })
    }
}

impl IpcAuthenticationState {
    fn initialize(instance: &RuntimeInstance, publication: &RuntimePublication) -> Result<Self> {
        let runtime_dir = instance.runtime_dir();
        fs::create_dir_all(&runtime_dir)?;
        let allowed_windows_sid = current_windows_sid()?;
        restrict_directory_to_current_user(&runtime_dir, &allowed_windows_sid)?;
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let file = IpcAuthenticationFile {
            schema_version: publication.schema_version.clone(),
            protocol_version: IPC_PROTOCOL_VERSION.to_owned(),
            instance_name: publication.instance_name.clone(),
            runtime_id: publication.runtime_id.clone(),
            pipe_name: publication.pipe_name.clone(),
            allowed_windows_sid: allowed_windows_sid.clone(),
            token: token.clone(),
            auth_generation: publication.auth_generation.clone(),
            token_generation_id: publication.auth_generation.clone(),
        };
        let path = instance.authentication_path();
        atomic_write_json(&path, &file)?;
        let cognitive_client_executable = publication
            .executable
            .canonicalize()
            .context("canonicalize published Eliot executable")?;
        let current_executable = std::env::current_exe()?
            .canonicalize()
            .context("canonicalize current Eliot executable")?;
        if crate::runtime_instance::path_identity(&cognitive_client_executable)
            != crate::runtime_instance::path_identity(&current_executable)
        {
            anyhow::bail!("published Eliot executable differs from the current daemon image");
        }
        let cognitive_client_executable_sha256 = sha256_file(&cognitive_client_executable)?;
        Ok(Self {
            instance_name: publication.instance_name.clone(),
            runtime_id: publication.runtime_id.clone(),
            allowed_windows_sid,
            token_hash: blake3::hash(token.as_bytes()),
            token_generation_id: publication.auth_generation.clone(),
            cognitive_client_executable,
            cognitive_client_executable_sha256,
            replay_nonces: Mutex::new(ReplayWindow::with_capacity(MAX_REPLAY_NONCES)),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn authenticate(
        &self,
        line: &str,
        client_process: Option<&ClientProcessAttestation>,
    ) -> std::result::Result<IpcPrincipal, &'static str> {
        let handshake: IpcClientHandshake =
            serde_json::from_str(line).map_err(|_| "malformed_handshake")?;
        if !matches!(
            handshake.kind.as_str(),
            "eliot_ipc_handshake"
                | "eliot_cognitive_governor_handshake"
                | "eliot_host_governor_handshake"
                | "eliot_cognitive_child_handshake"
        ) {
            return Err("handshake_required");
        }
        if handshake.protocol_version != IPC_PROTOCOL_VERSION {
            return Err("protocol_mismatch");
        }
        if handshake.instance_name != self.instance_name {
            return Err("instance_mismatch");
        }
        if handshake.runtime_id != self.runtime_id {
            return Err("runtime_mismatch");
        }
        if handshake.client_nonce.is_empty() || handshake.client_nonce.len() > 128 {
            return Err("invalid_nonce");
        }
        match handshake.kind.as_str() {
            "eliot_ipc_handshake" => {
                if !allowed_ipc_profile(&handshake.profile)
                    || handshake.capability_file.is_some()
                    || handshake.capability_token.is_some()
                {
                    return Err("invalid_profile");
                }
                if handshake.token_generation_id != self.token_generation_id {
                    return Err("stale_token_generation");
                }
                if handshake.token.is_empty()
                    || blake3::hash(handshake.token.as_bytes()) != self.token_hash
                {
                    return Err("invalid_token");
                }
                if !valid_normal_scope_shape(
                    handshake.requested_session_id.is_some(),
                    handshake.requested_project_id.is_some(),
                    handshake.requested_task_id.is_some(),
                    handshake.requested_role_lease_id.is_some(),
                    handshake.requested_role_lease_epoch.is_some(),
                    handshake.requested_role_lease_generation.is_some(),
                ) {
                    return Err("invalid_session_scope");
                }
            }
            "eliot_cognitive_governor_handshake" => {
                self.authenticate_private_governor_handshake(
                    &handshake,
                    "cognitive_governor",
                    client_process,
                )?;
            }
            "eliot_host_governor_handshake" => {
                self.authenticate_private_governor_handshake(
                    &handshake,
                    "host_governor",
                    client_process,
                )?;
            }
            "eliot_cognitive_child_handshake" => {
                if handshake.profile != "cognitive_child"
                    || !handshake.token.is_empty()
                    || !handshake.token_generation_id.is_empty()
                    || handshake.requested_session_id.is_some()
                    || handshake.requested_project_id.is_some()
                    || handshake.requested_task_id.is_some()
                    || handshake.requested_role_lease_id.is_some()
                    || handshake.requested_role_lease_epoch.is_some()
                    || handshake.requested_role_lease_generation.is_some()
                    || handshake
                        .capability_file
                        .as_deref()
                        .is_none_or(str::is_empty)
                    || handshake
                        .capability_token
                        .as_deref()
                        .is_none_or(str::is_empty)
                {
                    return Err("invalid_cognitive_capability");
                }
            }
            _ => return Err("handshake_required"),
        }
        let mut replay_nonces = self.replay_nonces.lock().await;
        if !replay_nonces.accept(handshake.client_nonce) {
            return Err("replayed_handshake");
        }
        let session_id = if handshake.kind == "eliot_cognitive_child_handshake" {
            SessionId::new_v7()
        } else {
            handshake
                .requested_session_id
                .as_deref()
                .map(SessionId::from_str)
                .transpose()
                .map_err(|_| "invalid_session_id")?
                .unwrap_or_else(SessionId::new_v7)
        };
        let bound_project_id = handshake
            .requested_project_id
            .as_deref()
            .map(ProjectId::from_str)
            .transpose()
            .map_err(|_| "invalid_project_id")?;
        let bound_task_id = handshake
            .requested_task_id
            .as_deref()
            .map(TaskId::from_str)
            .transpose()
            .map_err(|_| "invalid_task_id")?;
        Ok(IpcPrincipal {
            profile: handshake.profile,
            session_id,
            bound_project_id,
            bound_task_id,
            role_lease_id: handshake.requested_role_lease_id,
            role_lease_epoch: handshake.requested_role_lease_epoch,
            role_lease_generation: handshake.requested_role_lease_generation,
            capability_file: handshake.capability_file,
            capability_token: handshake.capability_token,
        })
    }

    fn authenticate_private_governor_handshake(
        &self,
        handshake: &IpcClientHandshake,
        expected_profile: &str,
        client_process: Option<&ClientProcessAttestation>,
    ) -> std::result::Result<(), &'static str> {
        if handshake.profile != expected_profile
            || handshake.requested_session_id.is_some()
            || handshake.requested_project_id.is_some()
            || handshake.requested_task_id.is_some()
            || handshake.requested_role_lease_id.is_some()
            || handshake.requested_role_lease_epoch.is_some()
            || handshake.requested_role_lease_generation.is_some()
            || handshake.capability_file.is_some()
            || handshake.capability_token.is_some()
        {
            return Err("invalid_profile");
        }
        if handshake.token_generation_id != self.token_generation_id
            || handshake.token.is_empty()
            || blake3::hash(handshake.token.as_bytes()) != self.token_hash
        {
            return Err("invalid_token");
        }
        self.authenticate_attested_governor(client_process)
    }

    fn authenticate_attested_governor(
        &self,
        client_process: Option<&ClientProcessAttestation>,
    ) -> std::result::Result<(), &'static str> {
        let client_process = client_process.ok_or("unattested_cognitive_governor")?;
        if client_process.pid == 0
            || crate::runtime_instance::path_identity(&client_process.executable)
                != crate::runtime_instance::path_identity(&self.cognitive_client_executable)
            || client_process.executable_sha256 != self.cognitive_client_executable_sha256
        {
            return Err("unattested_cognitive_governor");
        }
        let stable_sha256 =
            sha256_file(&client_process.executable).map_err(|_| "unattested_cognitive_governor")?;
        if stable_sha256 != client_process.executable_sha256 {
            return Err("unstable_cognitive_governor_image");
        }
        Ok(())
    }
}

#[cfg(windows)]
fn sha256_file(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn allowed_ipc_profile(profile: &str) -> bool {
    matches!(
        profile,
        "dynamic_agent"
            | "claude_governed"
            | "claude_desktop"
            | "codex_controller"
            | "codex_worker"
            | "external_auditor"
            | "verifier"
            | "human_operator"
            | "human_readonly"
            | "cognitive_control"
    )
}

// each flag is an independent admission decision
#[allow(clippy::fn_params_excessive_bools)]
fn valid_normal_scope_shape(
    has_session: bool,
    has_project: bool,
    has_task: bool,
    has_role_lease: bool,
    has_role_epoch: bool,
    has_role_generation: bool,
) -> bool {
    matches!(
        (
            has_session,
            has_project,
            has_task,
            has_role_lease,
            has_role_epoch,
            has_role_generation,
        ),
        (false, _, false, false, false, false) | (true, true, true, true, true, true)
    )
}

async fn write_authentication_result<W>(
    writer: &mut W,
    accepted: bool,
    session_id: Option<&str>,
    reason: Option<&str>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let result = IpcHandshakeResult {
        kind: "eliot_ipc_handshake_result".to_owned(),
        accepted,
        session_id: session_id.map(str::to_owned),
        reason: reason.map(str::to_owned),
    };
    writer
        .write_all(serde_json::to_string(&result)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn reject_handshake<W>(writer: &mut W, reason: &'static str) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    tracing::warn!(reason, "IPC authentication rejected");
    write_authentication_result(writer, false, None, Some(reason)).await
}

pub(crate) fn validate_authentication_publication(
    instance: &RuntimeInstance,
    publication: &RuntimePublication,
) -> std::result::Result<(), crate::runtime_instance::RuntimeDiscoveryError> {
    read_authentication_file(instance, publication).map(|_| ())
}

fn read_authentication_file(
    instance: &RuntimeInstance,
    publication: &RuntimePublication,
) -> std::result::Result<IpcAuthenticationFile, crate::runtime_instance::RuntimeDiscoveryError> {
    let path = instance.authentication_path();
    let bytes =
        fs::read(&path).map_err(|error| crate::runtime_instance::RuntimeDiscoveryError {
            code: if error.kind() == std::io::ErrorKind::NotFound {
                RuntimeDiscoveryErrorCode::AuthenticationFileMissing
            } else {
                RuntimeDiscoveryErrorCode::AuthenticationFileUnreadable
            },
            detail: format!("{}: {error}", path.display()),
        })?;
    let file: IpcAuthenticationFile = serde_json::from_slice(&bytes).map_err(|error| {
        crate::runtime_instance::RuntimeDiscoveryError {
            code: RuntimeDiscoveryErrorCode::AuthenticationFileUnreadable,
            detail: format!("{}: {error}", path.display()),
        }
    })?;
    let mismatch = |field: &str| crate::runtime_instance::RuntimeDiscoveryError {
        code: RuntimeDiscoveryErrorCode::AuthenticationFieldMismatch,
        detail: format!("runtime authentication mismatch: {field}"),
    };
    if file.schema_version != publication.schema_version {
        return Err(mismatch("schema_version"));
    }
    if file.protocol_version != publication.protocol_version {
        return Err(mismatch("protocol_version"));
    }
    if file.instance_name != publication.instance_name {
        return Err(mismatch("instance_name"));
    }
    if file.runtime_id != publication.runtime_id {
        return Err(mismatch("runtime_id"));
    }
    if file.auth_generation != publication.auth_generation {
        return Err(mismatch("auth_generation"));
    }
    if file.token_generation_id != publication.auth_generation {
        return Err(mismatch("token_generation_id"));
    }
    if file.pipe_name != publication.pipe_name {
        return Err(mismatch("pipe_name"));
    }
    if crate::runtime_instance::path_identity(&path)
        != crate::runtime_instance::path_identity(&publication.auth_ref)
    {
        return Err(mismatch("auth_ref"));
    }
    Ok(file)
}

fn current_windows_sid() -> Result<String> {
    let output = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .context("resolve current Windows SID with whoami.exe")?;
    if !output.status.success() {
        anyhow::bail!("whoami.exe failed while resolving current Windows SID");
    }
    let text = String::from_utf8(output.stdout)?;
    text.trim()
        .trim_matches('"')
        .rsplit_once("\",\"")
        .map(|(_, sid)| sid.trim_matches('"').to_owned())
        .filter(|sid| {
            sid.starts_with("S-")
                && sid
                    .chars()
                    .all(|c| c == 'S' || c == '-' || c.is_ascii_digit())
        })
        .context("whoami.exe returned an invalid Windows SID")
}

fn restrict_directory_to_current_user(path: &Path, sid: &str) -> Result<()> {
    let user_grant = format!("*{sid}:(OI)(CI)F");
    let system_grant = "*S-1-5-18:(OI)(CI)F";
    let output = Command::new("icacls.exe")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &user_grant,
            "/grant:r",
            system_grant,
        ])
        .output()
        .context("restrict IPC runtime directory ACL with icacls.exe")?;
    if !output.status.success() {
        anyhow::bail!("icacls.exe failed to restrict IPC runtime directory");
    }
    Ok(())
}

pub(crate) fn restrict_owned_directory_to_current_user(path: &Path) -> Result<()> {
    let sid = current_windows_sid()?;
    restrict_directory_to_current_user(path, &sid)
}

async fn read_bounded_async_line<R>(reader: &mut R) -> Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut bounded = reader.take((MAX_FRAME_BYTES + 1) as u64);
    let read = bounded.read_until(b'\n', &mut bytes).await?;
    decode_bounded_line(bytes, read)
}

fn read_bounded_stdio_line<R>(reader: &mut R) -> Result<Option<String>>
where
    R: std::io::BufRead,
{
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(&mut *reader, (MAX_FRAME_BYTES + 1) as u64);
    let read = std::io::BufRead::read_until(&mut bounded, b'\n', &mut bytes)?;
    decode_bounded_line(bytes, read)
}

fn decode_bounded_line(mut bytes: Vec<u8>, read: usize) -> Result<Option<String>> {
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        anyhow::bail!("IPC frame exceeds max_frame_bytes {MAX_FRAME_BYTES}");
    }
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        bytes.drain(..3);
    }
    String::from_utf8(bytes)
        .context("IPC frame is not UTF-8")
        .map(Some)
}

#[cfg(not(windows))]
pub(crate) async fn run_stdio_client(
    _instance: &RuntimeInstance,
    _profile: &str,
    _requested_scope: Option<RequestedSessionScope>,
) -> Result<()> {
    anyhow::bail!("named-pipe IPC requires Windows")
}

#[cfg(test)]
mod tests {
    use super::{
        ClientProcessAttestation, IPC_PROTOCOL_VERSION, IpcAuthenticationState, IpcClientHandshake,
        IpcPrincipal, MAX_REPLAY_NONCES, ReplayWindow, allowed_ipc_profile, decode_bounded_line,
        handshake_requires_process_attestation, private_host_governor_method_allowed,
        retained_role_authority, sha256_file, valid_normal_scope_shape,
    };
    use anyhow::{Context as _, Result};
    use eliot_types::SessionId;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    #[test]
    fn claude_desktop_is_an_authenticated_ipc_profile() {
        assert!(allowed_ipc_profile("claude_desktop"));
        assert!(!allowed_ipc_profile("raw_patch_runner"));
    }

    #[test]
    fn normal_ipc_scope_accepts_project_only_without_task_authority() {
        assert!(valid_normal_scope_shape(
            false, false, false, false, false, false
        ));
        assert!(valid_normal_scope_shape(
            false, true, false, false, false, false
        ));
        assert!(valid_normal_scope_shape(true, true, true, true, true, true));

        assert!(!valid_normal_scope_shape(
            true, false, false, true, true, true
        ));
        assert!(!valid_normal_scope_shape(
            true, true, false, true, true, true
        ));
        assert!(!valid_normal_scope_shape(
            false, false, true, false, false, false
        ));
        assert!(!valid_normal_scope_shape(
            false, true, true, false, false, false
        ));
        assert!(!valid_normal_scope_shape(
            true, true, true, false, false, false
        ));
    }

    #[test]
    fn retained_role_authority_is_all_or_nothing() -> Result<()> {
        let mut principal = IpcPrincipal {
            profile: "codex_controller".to_owned(),
            session_id: SessionId::new_v7(),
            bound_project_id: None,
            bound_task_id: None,
            role_lease_id: None,
            role_lease_epoch: None,
            role_lease_generation: None,
            capability_file: None,
            capability_token: None,
        };

        assert!(retained_role_authority(&principal)?.is_none());

        principal.role_lease_id = Some("role-lease".to_owned());
        assert!(retained_role_authority(&principal).is_err());

        principal.role_lease_epoch = Some(7);
        principal.role_lease_generation = Some(11);
        let retained = retained_role_authority(&principal)?.context("retained role authority")?;
        assert_eq!(retained.role_lease_id, "role-lease");
        assert_eq!(retained.epoch, 7);
        assert_eq!(retained.generation, 11);
        Ok(())
    }

    #[test]
    fn process_attestation_is_reserved_for_private_governor_handshakes() -> Result<()> {
        let handshake = |kind: &str| {
            serde_json::to_string(&IpcClientHandshake {
                kind: kind.to_owned(),
                protocol_version: IPC_PROTOCOL_VERSION.to_owned(),
                instance_name: "default".to_owned(),
                runtime_id: Uuid::new_v4().to_string(),
                token: "token".to_owned(),
                token_generation_id: "generation".to_owned(),
                client_nonce: Uuid::new_v4().to_string(),
                profile: "dynamic_agent".to_owned(),
                requested_session_id: None,
                requested_project_id: None,
                requested_task_id: None,
                requested_role_lease_id: None,
                requested_role_lease_epoch: None,
                requested_role_lease_generation: None,
                capability_file: None,
                capability_token: None,
            })
        };

        assert!(!handshake_requires_process_attestation(&handshake(
            "eliot_ipc_handshake"
        )?));
        assert!(handshake_requires_process_attestation(&handshake(
            "eliot_cognitive_governor_handshake"
        )?));
        assert!(handshake_requires_process_attestation(&handshake(
            "eliot_host_governor_handshake"
        )?));
        assert!(!handshake_requires_process_attestation("not-json"));
        Ok(())
    }

    #[test]
    fn named_pipe_ipc_operation_scope_methods_are_private_allowlisted() {
        assert!(private_host_governor_method_allowed(
            "host/operation-scope-open"
        ));
        assert!(private_host_governor_method_allowed(
            "host/operation-scope-close"
        ));
        assert!(!private_host_governor_method_allowed(
            "tools/call/operation-scope-open"
        ));
    }

    #[test]
    fn stdio_frame_accepts_one_leading_utf8_bom_from_windows_powershell() -> Result<()> {
        let payload = b"\xEF\xBB\xBF{\"jsonrpc\":\"2.0\",\"id\":1}\r\n".to_vec();
        let decoded = decode_bounded_line(payload.clone(), payload.len())?.context("frame")?;
        assert_eq!(decoded, r#"{"jsonrpc":"2.0","id":1}"#);
        let parsed: serde_json::Value = serde_json::from_str(&decoded)?;
        assert_eq!(parsed["jsonrpc"], "2.0");
        Ok(())
    }

    #[test]
    fn a_repeated_handshake_nonce_is_rejected() {
        let mut window = ReplayWindow::with_capacity(8);
        let nonce = Uuid::new_v4().to_string();

        assert!(window.accept(nonce.clone()), "first use must be accepted");
        assert!(!window.accept(nonce), "the same nonce must not be reusable");
    }

    #[test]
    fn a_new_auth_generation_starts_with_an_empty_replay_window() {
        let nonce = Uuid::new_v4().to_string();
        let mut previous_generation = ReplayWindow::with_capacity(8);

        assert!(previous_generation.accept(nonce.clone()));
        assert!(!previous_generation.accept(nonce.clone()));

        // Rotating authentication creates a new IpcAuthenticationState and,
        // therefore, a new generation-local replay window.
        let mut rotated_generation = ReplayWindow::with_capacity(8);
        assert!(rotated_generation.accept(nonce));
    }

    /// The window used to refuse every client once it filled up, so a runtime
    /// that had seen `MAX_REPLAY_NONCES` handshakes could never be connected to
    /// again until its auth generation rotated.
    #[test]
    fn fresh_clients_still_connect_after_the_window_has_turned_over() {
        let capacity = 8;
        let mut window = ReplayWindow::with_capacity(capacity);

        for _ in 0..capacity * 4 {
            assert!(
                window.accept(Uuid::new_v4().to_string()),
                "a fresh nonce must be accepted however many preceded it"
            );
        }
    }

    #[test]
    fn the_replay_window_never_grows_past_its_capacity() {
        let capacity = 8;
        let mut window = ReplayWindow::with_capacity(capacity);

        for _ in 0..capacity * 10 {
            window.accept(Uuid::new_v4().to_string());
        }

        assert_eq!(window.len(), capacity);
    }

    /// Eviction is what bounds memory, so the oldest nonce is the one that
    /// becomes replayable again. Anything still inside the window must not be.
    #[test]
    fn only_nonces_evicted_from_the_window_become_acceptable_again() {
        let capacity = 4;
        let mut window = ReplayWindow::with_capacity(capacity);
        let oldest = Uuid::new_v4().to_string();
        let newest = Uuid::new_v4().to_string();

        assert!(window.accept(oldest.clone()));
        for _ in 0..capacity - 2 {
            window.accept(Uuid::new_v4().to_string());
        }
        assert!(window.accept(newest.clone()));
        assert!(!window.accept(newest.clone()), "still inside the window");

        // Push exactly enough fresh nonces to evict `oldest` but not `newest`.
        window.accept(Uuid::new_v4().to_string());
        assert!(window.accept(oldest), "evicted nonce is no longer tracked");
        assert!(!window.accept(newest), "newest is still inside the window");
    }

    #[test]
    fn governor_image_path_identity_is_case_and_prefix_insensitive() {
        assert_eq!(
            crate::runtime_instance::path_identity(std::path::Path::new(
                r"C:\Program Files\Eliot\eliot-governor.exe",
            )),
            crate::runtime_instance::path_identity(std::path::Path::new(
                r"\\?\c:\PROGRAM FILES\ELIOT\ELIOT-GOVERNOR.EXE",
            ))
        );
        assert_eq!(
            crate::runtime_instance::path_identity(std::path::Path::new(
                r"\\server\share\Eliot\eliot-governor.exe",
            )),
            crate::runtime_instance::path_identity(std::path::Path::new(
                r"\\?\UNC\SERVER\SHARE\ELIOT\ELIOT-GOVERNOR.EXE",
            ))
        );
    }

    #[cfg(windows)]
    fn governor_authentication(token: &str) -> Result<IpcAuthenticationState> {
        let executable = std::env::current_exe()?.canonicalize()?;
        Ok(IpcAuthenticationState {
            instance_name: "attestation-test".to_owned(),
            runtime_id: Uuid::new_v4().to_string(),
            allowed_windows_sid: "S-1-5-21-1".to_owned(),
            token_hash: blake3::hash(token.as_bytes()),
            token_generation_id: "generation".to_owned(),
            cognitive_client_executable_sha256: sha256_file(&executable)?,
            cognitive_client_executable: executable,
            replay_nonces: Mutex::new(ReplayWindow::with_capacity(MAX_REPLAY_NONCES)),
        })
    }

    #[cfg(windows)]
    fn governor_handshake(
        authentication: &IpcAuthenticationState,
        token: &str,
        kind: &str,
    ) -> Result<String> {
        Ok(serde_json::to_string(&IpcClientHandshake {
            kind: kind.to_owned(),
            protocol_version: IPC_PROTOCOL_VERSION.to_owned(),
            instance_name: authentication.instance_name.clone(),
            runtime_id: authentication.runtime_id.clone(),
            token: token.to_owned(),
            token_generation_id: authentication.token_generation_id.clone(),
            client_nonce: Uuid::new_v4().to_string(),
            profile: "cognitive_governor".to_owned(),
            requested_session_id: None,
            requested_project_id: None,
            requested_task_id: None,
            requested_role_lease_id: None,
            requested_role_lease_epoch: None,
            requested_role_lease_generation: None,
            capability_file: None,
            capability_token: None,
        })?)
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn governor_requires_the_attested_published_eliot_image() -> Result<()> {
        let token = "same-user-readable-token";
        let authentication = governor_authentication(token)?;
        let forged_executable = std::env::var_os("ComSpec")
            .map(std::path::PathBuf::from)
            .context("ComSpec")?
            .canonicalize()?;
        let forged = ClientProcessAttestation {
            pid: std::process::id(),
            executable_sha256: sha256_file(&forged_executable)?,
            executable: forged_executable,
        };
        let attested_handshake =
            governor_handshake(&authentication, token, "eliot_cognitive_governor_handshake")?;
        let rejected = authentication
            .authenticate(&attested_handshake, Some(&forged))
            .await;
        assert!(matches!(rejected, Err("unattested_cognitive_governor")));

        let official = ClientProcessAttestation {
            pid: std::process::id(),
            executable: authentication.cognitive_client_executable.clone(),
            executable_sha256: authentication.cognitive_client_executable_sha256.clone(),
        };
        let accepted = authentication
            .authenticate(&attested_handshake, Some(&official))
            .await;
        assert!(accepted.is_ok());
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn ordinary_global_handshake_cannot_select_governor_profile() -> Result<()> {
        let token = "same-user-readable-token";
        let authentication = governor_authentication(token)?;
        let official = ClientProcessAttestation {
            pid: std::process::id(),
            executable: authentication.cognitive_client_executable.clone(),
            executable_sha256: authentication.cognitive_client_executable_sha256.clone(),
        };
        let ordinary_handshake = governor_handshake(&authentication, token, "eliot_ipc_handshake")?;
        let rejected = authentication
            .authenticate(&ordinary_handshake, Some(&official))
            .await;
        assert!(matches!(rejected, Err("invalid_profile")));
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn host_governor_requires_its_private_profile_and_attested_image() -> Result<()> {
        let token = "same-user-readable-token";
        let authentication = governor_authentication(token)?;
        let official = ClientProcessAttestation {
            pid: std::process::id(),
            executable: authentication.cognitive_client_executable.clone(),
            executable_sha256: authentication.cognitive_client_executable_sha256.clone(),
        };
        let mut handshake: IpcClientHandshake = serde_json::from_str(&governor_handshake(
            &authentication,
            token,
            "eliot_host_governor_handshake",
        )?)?;
        handshake.profile = "host_governor".to_owned();
        let private_handshake = serde_json::to_string(&handshake)?;
        assert!(matches!(
            authentication.authenticate(&private_handshake, None).await,
            Err("unattested_cognitive_governor")
        ));
        assert!(
            authentication
                .authenticate(&private_handshake, Some(&official))
                .await
                .is_ok()
        );

        handshake.kind = "eliot_ipc_handshake".to_owned();
        handshake.client_nonce = Uuid::new_v4().to_string();
        let ordinary_handshake = serde_json::to_string(&handshake)?;
        assert!(matches!(
            authentication
                .authenticate(&ordinary_handshake, Some(&official))
                .await,
            Err("invalid_profile")
        ));
        Ok(())
    }
}
