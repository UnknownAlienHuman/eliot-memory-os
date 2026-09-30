//! Kernel-owned adapters for the current LSP bridge process boundary.
//!
//! This module deliberately adapts the existing authenticated Kernel P-03
//! gateway while retaining the original EBP request and owner-read task
//! identity. It does not issue a process intent, lease, fence, deadline, or
//! source/artifact authority. Those values must arrive from their original
//! admitted owners.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::TaskId;
use eliot_git_bridge::{
    AsyncProcessRunner, GitProcessProfile, GitProcessRunError, GitProcessRunFuture, ProcessOutcome,
};
use eliot_ipc::Session;
use eliot_kernel_service::{
    PROCESS_STREAM_READ_CHUNK_MAX_BYTES, ProcessExecutionClient, ProcessExecutionFuture,
    ProcessExecutionRejection, ProcessExecutionRequest, ProcessExecutionResponse,
    ProcessStreamReadRequest,
};
use eliot_lsp_bridge::LspCurrentBridge;
use eliot_lsp_bridge::{LspProcessOwnerError, LspProcessOwnerFuture, LspProcessOwnerPort};
use eliot_process::{
    ExitDisposition, OperationId, ProcessEvidence, ProcessExecutionAdmissionRequest,
    ProcessLifecycle, ProcessSessionBinding, ProcessStartReceipt, ProcessStreamEvidence,
    ProcessStreamKind, StreamEvidenceGap, StreamTransportStatus,
};
use eliot_protocol::RequestIdentity;
use sha2::{Digest as _, Sha256};

use super::KernelComposition;
use super::process_execution_client::authenticated_process_route;

/// Identity-preserving adapter into the existing Kernel P-03 front door. Each
/// instance retains the original request identity and TaskBinding task for
/// one source-process operation; it does not expose the physical executor.
struct CurrentSourceProcessClient {
    kernel: Arc<KernelComposition>,
    session: Session,
    session_binding: ProcessSessionBinding,
    identity: RequestIdentity,
    admitted_task_id: TaskId,
}
impl CurrentSourceProcessClient {
    fn new(
        kernel: &Arc<KernelComposition>,
        session: &Session,
        session_binding: &ProcessSessionBinding,
        identity: RequestIdentity,
        admitted_task_id: TaskId,
    ) -> Result<Self, ProcessExecutionRejection> {
        let reject = |code: &str, detail: &str| ProcessExecutionRejection {
            code: code.to_owned(),
            detail: detail.to_owned(),
        };
        identity.validate().map_err(|_| {
            reject(
                "SOURCE_REQUEST_IDENTITY_INVALID",
                "original source request identity failed protocol validation",
            )
        })?;
        if identity.request.metadata.task_id.as_ref() != Some(&admitted_task_id)
            || identity.request.state_fence != session.module_generation.state_fence
            || identity.request.metadata.state_fence != identity.request.state_fence
        {
            return Err(reject(
                "SOURCE_REQUEST_TASK_OR_FENCE_MISMATCH",
                "original EBP request identity does not name the admitted task and session fence",
            ));
        }
        // Keep the same eager caller/session/P-03 readiness rejection as the
        // generic production client. Actual operations still enter the
        // identity-aware Kernel route below, which revalidates these bindings.
        drop(authenticated_process_route(
            kernel,
            session,
            session_binding,
        )?);
        Ok(Self {
            kernel: Arc::clone(kernel),
            session: session.clone(),
            session_binding: session_binding.clone(),
            identity,
            admitted_task_id,
        })
    }
}

impl ProcessExecutionClient for CurrentSourceProcessClient {
    fn execute(&self, request: ProcessExecutionRequest) -> ProcessExecutionFuture<'_> {
        let kernel = Arc::clone(&self.kernel);
        let session = self.session.clone();
        let session_binding = self.session_binding.clone();
        let identity = self.identity.clone();
        let admitted_task_id = self.admitted_task_id.clone();
        Box::pin(async move {
            kernel
                .execute_current_source_process_request(
                    &session,
                    session_binding,
                    request,
                    &identity,
                    &admitted_task_id,
                )
                .await
        })
    }
}

/// An identity-bound adapter from the LSP bridge to the existing Kernel P-03
/// front door. The wrapped client delegates Start/Reconcile to the original
/// process gateway; it does not expose the physical executor.
pub struct KernelLspProcessOwnerPort {
    client: Arc<CurrentSourceProcessClient>,
}

impl KernelLspProcessOwnerPort {
    /// Binds the LSP process port to an already authenticated session and its
    /// exact Kernel-established process-session binding.
    pub fn from_authenticated_session(
        kernel: &Arc<KernelComposition>,
        session: &Session,
        session_binding: &ProcessSessionBinding,
        original_identity: RequestIdentity,
        admitted_task_id: TaskId,
    ) -> Result<Self, ProcessExecutionRejection> {
        let client = CurrentSourceProcessClient::new(
            kernel,
            session,
            session_binding,
            original_identity,
            admitted_task_id,
        )?;
        Ok(Self {
            client: Arc::new(client),
        })
    }
}

impl LspProcessOwnerPort for KernelLspProcessOwnerPort {
    fn start(
        &self,
        admission: ProcessExecutionAdmissionRequest,
    ) -> LspProcessOwnerFuture<'_, ProcessStartReceipt> {
        let client: Arc<dyn ProcessExecutionClient> = self.client.clone();
        Box::pin(async move {
            match client
                .execute(ProcessExecutionRequest::Start(admission))
                .await
            {
                ProcessExecutionResponse::Started(receipt) => Ok(receipt),
                ProcessExecutionResponse::Rejected(rejection) => Err(owner_rejection(rejection)),
                _ => Err(LspProcessOwnerError::Rejected {
                    code: "PROCESS_RESPONSE_MISMATCH".to_owned(),
                    detail: "Kernel returned a non-start response for an admitted process start"
                        .to_owned(),
                }),
            }
        })
    }

    fn reconcile(&self, operation_id: OperationId) -> LspProcessOwnerFuture<'_, ProcessEvidence> {
        let client: Arc<dyn ProcessExecutionClient> = self.client.clone();
        Box::pin(async move {
            match client
                .execute(ProcessExecutionRequest::Reconcile { operation_id })
                .await
            {
                ProcessExecutionResponse::Reconciled(evidence) => Ok(evidence),
                ProcessExecutionResponse::Rejected(rejection) => Err(owner_rejection(rejection)),
                _ => Err(LspProcessOwnerError::Rejected {
                    code: "PROCESS_RESPONSE_MISMATCH".to_owned(),
                    detail: "Kernel returned a non-reconcile response for a process reconciliation"
                        .to_owned(),
                }),
            }
        })
    }
}

/// Future returned by the existing Instrument/Governor owner for one Git
/// subprocess admission. The owner must bind the complete command tuple and
/// return its already-admitted P-03 request with that child's exact EBP
/// identity; Kernel creates no admission or child identity.
pub type GitAdmissionFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    (ProcessExecutionAdmissionRequest, RequestIdentity),
                    GitProcessRunError,
                >,
            > + Send
            + 'a,
    >,
>;

/// Original admitted owner for one isolated-index Git command.
pub trait GitAdmissionPort: Send + Sync {
    /// Returns the original owner-created admission and identity for this
    /// exact tuple. Every Git child has its own request/idempotency identity.
    fn admit_git_command<'a>(
        &'a self,
        exe: &'a str,
        args: &'a [&'a str],
        cwd: &'a Path,
        stdin: &'a [u8],
        profile: &'a GitProcessProfile,
    ) -> GitAdmissionFuture<'a>;
}

/// Async Git runner over the authenticated Kernel P-03 route. Each child uses
/// its own original EBP identity from the admission owner. Full stream bytes
/// come only from the original P-03 stream reader.
pub struct KernelGitProcessRunner {
    kernel: Arc<KernelComposition>,
    session: Session,
    session_binding: ProcessSessionBinding,
    admitted_task_id: TaskId,
    admissions: Arc<dyn GitAdmissionPort>,
}

impl KernelGitProcessRunner {
    /// Composes the identity-aware P-03 route with original admission and
    /// stream-source owners supplied by the current Governor composition.
    pub(crate) fn new(
        kernel: &Arc<KernelComposition>,
        session: &Session,
        session_binding: &ProcessSessionBinding,
        admitted_task_id: TaskId,
        admissions: Arc<dyn GitAdmissionPort>,
    ) -> Self {
        Self {
            kernel: Arc::clone(kernel),
            session: session.clone(),
            session_binding: session_binding.clone(),
            admitted_task_id,
            admissions,
        }
    }
}

impl AsyncProcessRunner for KernelGitProcessRunner {
    fn run_profiled<'a>(
        &'a self,
        exe: &'a str,
        args: &'a [&'a str],
        cwd: &'a Path,
        stdin: &'a [u8],
        profile: &'a GitProcessProfile,
    ) -> GitProcessRunFuture<'a> {
        Box::pin(async move {
            if !stdin.is_empty() {
                return Err(git_rejection(
                    "GIT_STDIN_NOT_ADMITTED",
                    "the current Kernel P-03 request has no admitted stdin binding",
                ));
            }
            let (admission, identity) = self
                .admissions
                .admit_git_command(exe, args, cwd, stdin, profile)
                .await?;
            validate_git_admission(&admission, exe, args, cwd, profile)?;
            let deadline_unix_ms = identity.deadline_unix_ms;
            let stdout_limit = admission.intent().resource_limits().stdout_bytes();
            let stderr_limit = admission.intent().resource_limits().stderr_bytes();
            let client = CurrentSourceProcessClient::new(
                &self.kernel,
                &self.session,
                &self.session_binding,
                identity,
                self.admitted_task_id.clone(),
            )
            .map_err(|rejection| git_rejection(&rejection.code, &rejection.detail))?;
            let client: Arc<dyn ProcessExecutionClient> = Arc::new(client);

            let receipt = match client
                .execute(ProcessExecutionRequest::Start(admission))
                .await
            {
                ProcessExecutionResponse::Started(receipt) => receipt,
                ProcessExecutionResponse::Rejected(rejection) => {
                    return Err(git_rejection(&rejection.code, &rejection.detail));
                }
                _ => {
                    return Err(git_rejection(
                        "PROCESS_RESPONSE_MISMATCH",
                        "Kernel returned a non-start response for a Git process admission",
                    ));
                }
            };

            wait_for_terminal(&client, &receipt, deadline_unix_ms).await?;

            let evidence = match client
                .execute(ProcessExecutionRequest::Reconcile {
                    operation_id: receipt.operation_id().clone(),
                })
                .await
            {
                ProcessExecutionResponse::Reconciled(evidence) => evidence,
                ProcessExecutionResponse::Rejected(rejection) => {
                    return Err(git_rejection(&rejection.code, &rejection.detail));
                }
                _ => {
                    return Err(git_rejection(
                        "PROCESS_RESPONSE_MISMATCH",
                        "Kernel returned a non-reconcile response for a Git process operation",
                    ));
                }
            };
            if evidence.operation_id() != receipt.operation_id()
                || evidence.binding() != receipt.binding()
            {
                return Err(git_rejection(
                    "PROCESS_EVIDENCE_BINDING_MISMATCH",
                    "reconciled Git evidence is not bound to the original start receipt",
                ));
            }

            let stdout = self
                .read_stream(
                    &client,
                    &receipt,
                    &evidence,
                    ProcessStreamKind::Stdout,
                    stdout_limit,
                )
                .await?;
            let stderr = self
                .read_stream(
                    &client,
                    &receipt,
                    &evidence,
                    ProcessStreamKind::Stderr,
                    stderr_limit,
                )
                .await?;
            let code = process_exit_code(&evidence)?;
            Ok(ProcessOutcome {
                code,
                stdout,
                stderr,
            })
        })
    }
}

impl KernelGitProcessRunner {
    async fn read_stream(
        &self,
        client: &Arc<dyn ProcessExecutionClient>,
        started: &ProcessStartReceipt,
        evidence: &ProcessEvidence,
        kind: ProcessStreamKind,
        admitted_stream_limit: u64,
    ) -> Result<Vec<u8>, GitProcessRunError> {
        let stream = match kind {
            ProcessStreamKind::Stdout => evidence.stdout(),
            ProcessStreamKind::Stderr => evidence.stderr(),
        }
        .ok_or_else(|| {
            git_rejection(
                "PROCESS_STREAM_MISSING",
                "Git process evidence omitted a required output stream",
            )
        })?;
        validate_complete_stream(stream, started, kind, admitted_stream_limit)?;
        let bytes = self
            .read_stream_chunks(client, started, evidence, kind)
            .await?;
        if bytes.len() as u64 != stream.observed_bytes()
            || sha256_hex(&bytes) != stream.observed_sha256()
        {
            return Err(git_rejection(
                "PROCESS_STREAM_READBACK_MISMATCH",
                "full Git output did not match the original stream receipt identity",
            ));
        }
        Ok(bytes)
    }

    async fn read_stream_chunks(
        &self,
        client: &Arc<dyn ProcessExecutionClient>,
        started: &ProcessStartReceipt,
        evidence: &ProcessEvidence,
        kind: ProcessStreamKind,
    ) -> Result<Vec<u8>, GitProcessRunError> {
        let stream = match kind {
            ProcessStreamKind::Stdout => evidence.stdout(),
            ProcessStreamKind::Stderr => evidence.stderr(),
        }
        .ok_or_else(|| {
            git_rejection(
                "PROCESS_STREAM_MISSING",
                "Git process evidence omitted a required output stream",
            )
        })?;
        let expected_stream_digest = stream.identity_sha256().map_err(|error| {
            git_rejection("PROCESS_STREAM_IDENTITY_INVALID", &error.to_string())
        })?;
        let receipt_bytes = eliot_contracts::canonical_json_bytes(started).map_err(|error| {
            git_rejection("PROCESS_RECEIPT_IDENTITY_INVALID", &error.to_string())
        })?;
        let expected_receipt_digest = sha256_hex(&receipt_bytes);
        let expected_bytes = stream.observed_bytes();
        // The original P-03 readback owner enforces its retained-source
        // ceiling before returning bytes. Avoid allocating from caller-carried
        // evidence length before that owner check has succeeded.
        let mut output = Vec::new();
        let mut offset = 0_u64;
        loop {
            let max_bytes = PROCESS_STREAM_READ_CHUNK_MAX_BYTES;
            let request = ProcessStreamReadRequest::new(started.clone(), kind, offset, max_bytes)
                .map_err(|error| {
                git_rejection("PROCESS_STREAM_READ_INVALID", &error.to_string())
            })?;
            let chunk = match client
                .execute(ProcessExecutionRequest::ReadStream { request })
                .await
            {
                ProcessExecutionResponse::StreamChunk(chunk) => chunk,
                ProcessExecutionResponse::Rejected(rejection) => {
                    return Err(git_rejection(&rejection.code, &rejection.detail));
                }
                _ => {
                    return Err(git_rejection(
                        "PROCESS_RESPONSE_MISMATCH",
                        "Kernel returned a non-stream response for a Git output read",
                    ));
                }
            };
            chunk.validate().map_err(|error| {
                git_rejection("PROCESS_STREAM_CHUNK_INVALID", &error.to_string())
            })?;
            let page = chunk.bytes();
            let next_offset = offset.checked_add(page.len() as u64).ok_or_else(|| {
                git_rejection(
                    "PROCESS_STREAM_OFFSET_OVERFLOW",
                    "Git stream read offset overflowed",
                )
            })?;
            if chunk.operation_id() != started.operation_id()
                || chunk.binding() != started.binding()
                || chunk.stream() != kind
                || chunk.start_receipt_sha256() != expected_receipt_digest
                || chunk.stream_evidence_sha256() != expected_stream_digest
                || chunk.observed_sha256() != stream.observed_sha256()
                || chunk.observed_bytes() != expected_bytes
                || !chunk.stream_eof()
                || chunk.offset() != offset
                || page.len() as u64 > max_bytes
                || chunk.chunk_sha256() != sha256_hex(page)
                || chunk.chunk_eof() != (next_offset == expected_bytes)
                || next_offset > expected_bytes
                || (page.is_empty() && !chunk.chunk_eof())
            {
                return Err(git_rejection(
                    "PROCESS_STREAM_CHUNK_BINDING_MISMATCH",
                    "Kernel stream chunk did not match the original receipt, evidence, and byte range",
                ));
            }
            output.extend_from_slice(page);
            offset = next_offset;
            if chunk.chunk_eof() {
                break;
            }
        }
        if offset != expected_bytes || sha256_hex(&output) != stream.observed_sha256() {
            return Err(git_rejection(
                "PROCESS_STREAM_READBACK_MISMATCH",
                "full Git output did not match the original stream byte count and digest",
            ));
        }
        Ok(output)
    }
}

/// One retained same-session LSP Current bridge composition. Callers must keep
/// this object and the bridge's non-Clone started handle together through
/// retain/adopt; reconstructing either from serialized evidence is historical.
pub struct KernelLspCurrentExecutor {
    bridge: LspCurrentBridge<KernelLspProcessOwnerPort, KernelGitProcessRunner>,
}

impl KernelLspCurrentExecutor {
    /// Creates the production bridge over one authenticated Kernel session,
    /// the original EBP identity and TaskBinding task, and original Git
    /// admission/stream owners.
    pub fn from_authenticated_session(
        kernel: &Arc<KernelComposition>,
        session: &Session,
        session_binding: &ProcessSessionBinding,
        original_identity: RequestIdentity,
        admitted_task_id: TaskId,
        git_admissions: Arc<dyn GitAdmissionPort>,
    ) -> Result<Self, ProcessExecutionRejection> {
        let process_owner = Arc::new(KernelLspProcessOwnerPort::from_authenticated_session(
            kernel,
            session,
            session_binding,
            original_identity,
            admitted_task_id.clone(),
        )?);
        let git_owner = Arc::new(KernelGitProcessRunner::new(
            kernel,
            session,
            session_binding,
            admitted_task_id,
            git_admissions,
        ));
        Ok(Self {
            bridge: LspCurrentBridge::new(process_owner, git_owner),
        })
    }

    /// Borrows the one bridge instance that owns launch/reconcile/adoption.
    pub fn bridge(&self) -> &LspCurrentBridge<KernelLspProcessOwnerPort, KernelGitProcessRunner> {
        &self.bridge
    }
}

fn owner_rejection(rejection: ProcessExecutionRejection) -> LspProcessOwnerError {
    LspProcessOwnerError::Rejected {
        code: rejection.code,
        detail: rejection.detail,
    }
}

fn validate_git_admission(
    admission: &ProcessExecutionAdmissionRequest,
    exe: &str,
    args: &[&str],
    cwd: &Path,
    profile: &GitProcessProfile,
) -> Result<(), GitProcessRunError> {
    admission
        .validate()
        .map_err(|error| git_rejection("GIT_ADMISSION_INVALID", &error.to_string()))?;
    let intent = admission.intent();
    let expected_cwd = cwd.to_str().ok_or_else(|| {
        git_rejection(
            "GIT_WORKSPACE_PATH_INVALID",
            "Git workspace path is not UTF-8",
        )
    })?;
    let executable_name = Path::new(intent.executable())
        .file_stem()
        .and_then(|name| name.to_str());
    let expected_index = profile
        .index_file()
        .map(|path| {
            path.to_str().ok_or_else(|| {
                git_rejection(
                    "GIT_INDEX_PATH_INVALID",
                    "isolated Git index path is not UTF-8",
                )
            })
        })
        .transpose()?;
    let actual_index = intent.environment().non_secret().get("GIT_INDEX_FILE");
    if !exe.eq_ignore_ascii_case("git")
        || !executable_name.is_some_and(|name| name.eq_ignore_ascii_case("git"))
        || intent.argv() != args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>()
        || intent.working_directory() != expected_cwd
        || actual_index.map(String::as_str) != expected_index
    {
        return Err(git_rejection(
            "GIT_ADMISSION_BINDING_MISMATCH",
            "Git admission did not bind the exact executable, argv, workspace, and index profile",
        ));
    }
    Ok(())
}

async fn wait_for_terminal(
    client: &Arc<dyn ProcessExecutionClient>,
    receipt: &ProcessStartReceipt,
    deadline_unix_ms: u64,
) -> Result<(), GitProcessRunError> {
    let operation_id = receipt.operation_id();
    loop {
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                git_rejection(
                    "PROCESS_CLOCK_UNAVAILABLE",
                    "system clock predates Unix epoch",
                )
            })?
            .as_millis();
        if now_unix_ms >= u128::from(deadline_unix_ms) {
            return Err(git_rejection(
                "PROCESS_DEADLINE_EXCEEDED",
                "original admitted process deadline elapsed before terminal observation",
            ));
        }
        match client
            .execute(ProcessExecutionRequest::Inspect {
                operation_id: operation_id.clone(),
            })
            .await
        {
            ProcessExecutionResponse::Status(view)
                if view.operation_id() == operation_id
                    && view.binding() == receipt.binding()
                    && view.lifecycle().is_terminal()
                    && view.exit().is_some() =>
            {
                return Ok(());
            }
            ProcessExecutionResponse::Status(view)
                if view.operation_id() == operation_id
                    && view.binding() == receipt.binding()
                    && view.lifecycle().is_terminal() =>
            {
                return Err(git_rejection(
                    "PROCESS_TERMINAL_EXIT_MISSING",
                    "original process owner reported terminal lifecycle without an exit observation",
                ));
            }
            ProcessExecutionResponse::Status(view)
                if view.operation_id() == operation_id && view.binding() == receipt.binding() =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            ProcessExecutionResponse::Rejected(rejection) => {
                return Err(git_rejection(&rejection.code, &rejection.detail));
            }
            _ => {
                return Err(git_rejection(
                    "PROCESS_RESPONSE_MISMATCH",
                    "Kernel returned an unrelated status for the original Git process operation",
                ));
            }
        }
    }
}

fn validate_complete_stream(
    stream: &ProcessStreamEvidence,
    started: &ProcessStartReceipt,
    expected_kind: ProcessStreamKind,
    admitted_stream_limit: u64,
) -> Result<(), GitProcessRunError> {
    let disallowed_gap = stream.gaps().iter().any(|gap| {
        !matches!(
            gap,
            StreamEvidenceGap::PersistenceUnavailable
                | StreamEvidenceGap::PersistenceBackpressure
                | StreamEvidenceGap::PersistenceFailed
                | StreamEvidenceGap::PersistenceUnknownOutcome
        )
    });
    if stream.stream() != expected_kind
        || stream.binding() != started.binding()
        || stream.transport() != StreamTransportStatus::Complete
        || stream.observed_bytes() > admitted_stream_limit
        || disallowed_gap
    {
        return Err(git_rejection(
            "GIT_OUTPUT_INCOMPLETE",
            "Git output lacks complete, policy-admissible original transport bytes",
        ));
    }
    Ok(())
}

fn process_exit_code(evidence: &ProcessEvidence) -> Result<i32, GitProcessRunError> {
    let exit = evidence.view().exit().ok_or_else(|| {
        git_rejection(
            "GIT_EXIT_UNKNOWN",
            "Git process has no terminal exit observation",
        )
    })?;
    if exit.disposition() != ExitDisposition::Completed {
        return Err(git_rejection(
            "GIT_EXIT_INCOMPLETE",
            "Git process did not complete with a normal exit disposition",
        ));
    }
    let code = serde_json::to_value(exit)
        .ok()
        .and_then(|value| value.get("code").and_then(serde_json::Value::as_i64))
        .and_then(|code| i32::try_from(code).ok())
        .ok_or_else(|| git_rejection("GIT_EXIT_UNKNOWN", "Git exit code is unavailable"))?;
    Ok(code)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn git_rejection(code: &str, detail: &str) -> GitProcessRunError {
    GitProcessRunError {
        code: code.to_owned(),
        detail: detail.chars().take(512).collect(),
    }
}
