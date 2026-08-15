//! Native .NET/MSBuild process instrumentation.
//!
//! The adapter deliberately invokes the selected executable directly.  It does
//! not use a shell, interpolate an invocation into a command string, or expose
//! the environment inherited by the host.  Process identity and lifecycle are
//! retained through the provider-neutral P-03 contract.

#![forbid(unsafe_code)]

use std::{collections::HashMap, process::Stdio, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_process::{
    CancellationReceipt, DescendantEvidence, ExitDisposition, ExitStatus,
    ProcessEvidence, ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessHealth,
    ProcessHealthStatus, ProcessId, ProcessIdentity, ProcessLifecycle, ProcessRequest,
    ProcessStartReceipt, ProcessState,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{io::AsyncReadExt, process::{Child, Command}, sync::Mutex, time};

/// Stable contract identifier for this adapter.
pub const CONTRACT_ID: &str = "eliot.instrument.dotnet.msbuild";
/// Default executable used for SDK-style projects.
pub const DOTNET_EXECUTABLE: &str = "dotnet";
/// Default MSBuild profile passed to `dotnet`.
pub const DEFAULT_PROFILE: &str = "msbuild";

/// Configuration for bounded .NET/MSBuild execution.
#[derive(Clone, Debug)]
pub struct DotnetMsbuildConfig {
    /// Executable used when a request names `dotnet`.
    pub dotnet_executable: String,
    /// Executable used when a request names `msbuild`.
    pub msbuild_executable: String,
    /// Maximum bytes retained from each output stream.
    pub output_limit: usize,
}

impl Default for DotnetMsbuildConfig {
    fn default() -> Self {
        Self {
            dotnet_executable: DOTNET_EXECUTABLE.to_owned(),
            msbuild_executable: "msbuild".to_owned(),
            output_limit: 4 * 1024 * 1024,
        }
    }
}

impl DotnetMsbuildConfig {
    /// Creates configuration and rejects an unbounded output policy.
    pub fn new(dotnet_executable: impl Into<String>, msbuild_executable: impl Into<String>, output_limit: usize) -> Result<Self, AdapterError> {
        if output_limit == 0 {
            return Err(AdapterError::InvalidConfiguration("output_limit must be non-zero"));
        }
        let dotnet_executable = dotnet_executable.into();
        let msbuild_executable = msbuild_executable.into();
        if dotnet_executable.trim().is_empty() || msbuild_executable.trim().is_empty() {
            return Err(AdapterError::InvalidConfiguration("tool executable must not be blank"));
        }
        Ok(Self { dotnet_executable, msbuild_executable, output_limit })
    }
}

/// Errors produced before or during adapter execution.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Configuration violates a bounded adapter invariant.
    #[error("invalid dotnet adapter configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// The invocation cannot be represented by the .NET/MSBuild adapter.
    #[error("unsupported .NET/MSBuild invocation: {0}")]
    UnsupportedInvocation(String),
    /// The process contract rejected a physical observation.
    #[error("process contract error: {0}")]
    Contract(#[from] eliot_process::ContractError),
}

struct Operation {
    state: Mutex<ProcessState>,
    child: Mutex<Option<Child>>,
}

/// A concurrent native process executor for `dotnet` and `msbuild`.
pub struct DotnetMsbuildExecutor {
    config: DotnetMsbuildConfig,
    operations: Arc<Mutex<HashMap<String, Arc<Operation>>>>,
}

impl DotnetMsbuildExecutor {
    /// Creates an executor with the default SDK and MSBuild tool names.
    pub fn new() -> Self { Self::with_config(DotnetMsbuildConfig::default()) }

    /// Creates an executor with explicit tool paths and output bounds.
    pub fn with_config(config: DotnetMsbuildConfig) -> Self {
        Self { config, operations: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Converts a validated instrument invocation into a process request shape.
    /// The caller supplies the authority-owned operation, generation and fence.
    pub fn validate_invocation(&self, invocation: &InstrumentInvocation) -> Result<(), AdapterError> {
        invocation.validate().map_err(|e| AdapterError::UnsupportedInvocation(e.to_string()))?;
        if !matches!(invocation.kind, InstrumentKind::Build | InstrumentKind::Test | InstrumentKind::Verify | InstrumentKind::Inspect) {
            return Err(AdapterError::UnsupportedInvocation("only build, test, verify, and inspect are supported".to_owned()));
        }
        if invocation.arguments.iter().any(|a| a.contains('\0')) {
            return Err(AdapterError::UnsupportedInvocation("arguments may not contain NUL".to_owned()));
        }
        Ok(())
    }

    async fn operation(&self, id: &str) -> Result<Arc<Operation>, ProcessExecutionError> {
        self.operations.lock().await.get(id).cloned().ok_or(ProcessExecutionError::NotFound)
    }

    async fn emit_evidence(state: &ProcessState, sink: &Arc<dyn eliot_process::ProcessEvidenceSink>, stdout: &[u8], stderr: &[u8]) {
        let view = state.view();
        let stdout_ref = (!stdout.is_empty()).then(|| evidence_ref("stdout", stdout));
        let stderr_ref = (!stderr.is_empty()).then(|| evidence_ref("stderr", stderr));
        let operation_id = view.operation_id().clone();
        let request_digest = view.request_digest().to_owned();
        if let Ok(evidence) = ProcessEvidence::new(operation_id, request_digest, view, stdout_ref, stderr_ref) {
            let _ = sink.record(evidence);
        }
    }
}

impl Default for DotnetMsbuildExecutor { fn default() -> Self { Self::new() } }

#[allow(async_fn_in_trait)]
impl ProcessExecutor for DotnetMsbuildExecutor {
    async fn start(&self, request: ProcessRequest, sink: Arc<dyn eliot_process::ProcessEvidenceSink>) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        request.validate().map_err(|e| ProcessExecutionError::Unavailable(format!("invalid process request: {e}")))?;
        let executable = request.executable().to_ascii_lowercase();
        if executable != DOTNET_EXECUTABLE && executable != "msbuild" && !executable.ends_with("\\dotnet.exe") && !executable.ends_with("\\msbuild.exe") {
            return Err(ProcessExecutionError::Unavailable("executable is not dotnet or msbuild".to_owned()));
        }
        let tool = if executable == DOTNET_EXECUTABLE { &self.config.dotnet_executable } else if executable == "msbuild" { &self.config.msbuild_executable } else { request.executable() };
        let mut command = Command::new(tool);
        command.args(request.argv()).current_dir(request.working_directory()).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        for (name, value) in request.environment().non_secret() { command.env(name, value); }
        let child = command.spawn().map_err(|e| ProcessExecutionError::Unavailable(e.to_string()))?;
        let pid = child.id().ok_or_else(|| ProcessExecutionError::Unavailable("child did not expose a process id".to_owned()))?;
        let started = unix_ms();
        let identity = ProcessIdentity::new(ProcessId::new(format!("pid:{pid}:{started}"))?, request.process_tree_id().clone(), request.generation(), pid, started, request.executable_sha256())?;
        let mut state = ProcessState::new(request.clone()).map_err(|e| ProcessExecutionError::Unavailable(format!("invalid process state: {e}")))?;
        state.start(identity).map_err(|e| ProcessExecutionError::Unavailable(format!("identity rejected: {e}")))?;
        state.mark_running(ProcessHealth::new(ProcessHealthStatus::Healthy, true, started, Some("dotnet/msbuild process started".to_owned())).map_err(|e| ProcessExecutionError::Unavailable(format!("health rejected: {e}")))?).map_err(|e| ProcessExecutionError::Unavailable(format!("running transition rejected: {e}")))?;
        let operation = Arc::new(Operation { state: Mutex::new(state), child: Mutex::new(Some(child)) });
        let id = request.operation_id().as_str().to_owned();
        if self.operations.lock().await.insert(id.clone(), operation.clone()).is_some() { return Err(ProcessExecutionError::Unavailable("operation id already exists".to_owned())); }
        let timeout = request.resource_limits().wall_timeout_ms();
        let ops = Arc::clone(&self.operations);
        let output_limit = self.config.output_limit.min(request.resource_limits().stdout_bytes() as usize);
        tokio::spawn(async move { monitor(id, operation, sink, timeout, output_limit).await; });
        let state = self.operation(request.operation_id().as_str()).await.map_err(|e| e)?;
        let lifecycle = state.state.lock().await.view().lifecycle();
        ProcessStartReceipt::new(&request, lifecycle).map_err(|e| ProcessExecutionError::Unavailable(format!("receipt rejected: {e}")))
    }

    async fn inspect(&self, operation_id: eliot_process::OperationId) -> Result<ProcessExecutionView, ProcessExecutionError> { Ok(self.operation(operation_id.as_str()).await?.state.lock().await.view()) }

    async fn cancel(&self, operation_id: eliot_process::OperationId) -> Result<CancellationReceipt, ProcessExecutionError> {
        let operation = self.operation(operation_id.as_str()).await?;
        let fence = operation.state.lock().await.view().fence().clone();
        let receipt = operation.state.lock().await.cancel(&fence).map_err(|e| ProcessExecutionError::Unavailable(format!("cancellation rejected: {e}")))?;
        if let Some(child) = operation.child.lock().await.as_mut() { child.kill().await.map_err(|e| ProcessExecutionError::Unavailable(e.to_string()))?; }
        Ok(receipt)
    }

    async fn reconcile(&self, operation_id: eliot_process::OperationId) -> Result<eliot_process::ProcessEvidence, ProcessExecutionError> {
        let operation = self.operation(operation_id.as_str()).await?;
        let state = operation.state.lock().await;
        ProcessEvidence::new(operation_id, state.view().request_digest().to_owned(), state.view(), None, None).map_err(|e| ProcessExecutionError::Unavailable(format!("evidence rejected: {e}")))
    }
}

async fn monitor(id: String, operation: Arc<Operation>, sink: Arc<dyn eliot_process::ProcessEvidenceSink>, timeout_ms: u64, output_limit: usize) {
    let mut child = match operation.child.lock().await.take() { Some(child) => child, None => return };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (out, err) = (read_bounded(stdout, output_limit), read_bounded(stderr, output_limit));
    let wait = child.wait();
    let (output, result) = time::timeout(Duration::from_millis(timeout_ms), async { tokio::join!(out, err, wait) }).await.map_or_else(|_| (None, None), |(o, e, r)| (Some((o.unwrap_or_default(), e.unwrap_or_default())), r.ok()));
    let (stdout, stderr) = output.unwrap_or_else(|| (Vec::new(), Vec::new()));
    let status = result.and_then(|s| s.code());
    let disposition = status.map_or(ExitDisposition::Unknown, |code| if code == 0 { ExitDisposition::Completed } else { ExitDisposition::NonZeroExit });
    let exit = ExitStatus::new(disposition, status, None, unix_ms());
    if let Ok(exit) = exit {
        let mut state = operation.state.lock().await;
        let descendants = DescendantEvidence::new(Vec::new(), true, true, None).unwrap_or_default();
        let _ = state.exit(exit, descendants);
        DotnetMsbuildExecutor::emit_evidence(&state, &sink, &stdout, &stderr).await;
    }
    let _ = id;
}

async fn read_bounded(mut stream: Option<impl tokio::io::AsyncRead + Unpin>, limit: usize) -> Vec<u8> {
    let Some(mut stream) = stream else { return Vec::new() };
    let mut bytes = Vec::new();
    let _ = stream.take(limit as u64 + 1).read_to_end(&mut bytes).await;
    bytes.truncate(limit);
    bytes
}

fn evidence_ref(kind: &str, bytes: &[u8]) -> String { let digest = blake3::hash(bytes).to_hex(); format!("process:{kind}:{digest}") }
fn unix_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64) }

/// Computes the SHA-256 identity required by [`ProcessRequest::new`].
pub fn executable_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}
