//! Production Cargo instrumentation boundary.
//!
//! This adapter owns Cargo's provider-facing policy and result projection. It
//! does not spawn a process, read the filesystem, mint a fence, or interpret
//! output as proof. Those effects are supplied by the two explicit ports below.
//!
//! [`parse_jsonl`] projects Cargo's own `--message-format=json` message stream:
//! diagnostic counters, the terminal `build-finished` outcome, and the artifact
//! identity Cargo reports for each produced artifact. It is a bounded
//! projection of real output only — it never reconstructs a message, never
//! treats an unterminated stream as a clean build, and never becomes a
//! verification verdict on its own.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation, VerificationOutcome};
use eliot_process::{
    CancellationReceipt, ExitDisposition, ExitStatus, OperationId, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessRequest, ProcessStartReceipt,
};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

/// Stable identity of the Cargo adapter.
pub const CONTRACT_NAME: &str = "eliot.instrument.cargo";
/// Wire revision of this adapter's receipts.
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

/// Supplies an already-authorized, sealed process request for Cargo.
///
/// Implementations belong to the runtime composition root. In particular, an
/// implementation must obtain the executable digest, generation, resource
/// limits, and fencing token from the owning control plane rather than deriving
/// or replacing them here.
pub trait CargoProcessRequestPort: Send + Sync {
    /// Binds an admitted instrument invocation to one immutable P-03 request.
    ///
    /// # Errors
    /// Returns an adapter error when the request cannot be issued or does not
    /// preserve the invocation identity.
    fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, CargoAdapterError>;
}

/// Failures raised before or during a Cargo invocation.
#[derive(Debug, Error)]
pub enum CargoAdapterError {
    /// The provider-neutral invocation was not structurally valid.
    #[error("invalid instrument invocation: {0}")]
    InvalidInvocation(String),
    /// The request port rejected the binding.
    #[error("Cargo process binding failed: {0}")]
    Binding(String),
    /// The process implementation rejected the operation.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
    /// The bound process request did not preserve invocation identity.
    #[error("Cargo process binding does not preserve invocation identity")]
    IdentityMismatch,
    /// The physical executor returned a receipt for a different generation.
    #[error("Cargo process receipt does not preserve the bound generation")]
    GenerationMismatch,
    /// The captured message stream exceeds the bounded capture limit.
    #[error("Cargo message stream exceeds the bounded capture limit")]
    OutputTooLarge,
    /// One message line exceeds the bounded per-line limit.
    #[error("Cargo message stream contains an oversized line")]
    LineTooLarge,
    /// The stream is not a valid Cargo `--message-format=json` message stream.
    #[error("Cargo emitted a malformed message stream")]
    MalformedMessage,
    /// A diagnostic counter overflowed its bounded type.
    #[error("Cargo diagnostic counter overflowed")]
    CounterOverflow,
}

/// The immutable pair passed between the adapter's admission and execution
/// methods.
#[derive(Debug)]
pub struct CargoBinding {
    /// The provider-neutral invocation admitted by the caller.
    pub invocation: InstrumentInvocation,
    /// The exact request delegated to P-03.
    process_request: Option<ProcessRequest>,
    operation_id: OperationId,
    request_digest: String,
    generation: u64,
}

impl CargoBinding {
    /// Validates the invocation and binds it through an explicit request port.
    ///
    /// # Errors
    /// Returns an error when invocation validation, request binding, request
    /// validation, or identity correlation fails.
    pub fn bind(
        invocation: InstrumentInvocation,
        port: &dyn CargoProcessRequestPort,
    ) -> Result<Self, CargoAdapterError> {
        invocation
            .validate()
            .map_err(|error| CargoAdapterError::InvalidInvocation(error.to_string()))?;
        let process_request = port.bind(&invocation)?;
        process_request
            .validate()
            .map_err(|error| CargoAdapterError::Binding(error.to_string()))?;
        if process_request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(CargoAdapterError::IdentityMismatch);
        }
        Ok(Self {
            invocation,
            operation_id: process_request.operation_id().clone(),
            request_digest: process_request.invocation_digest().to_owned(),
            generation: process_request.generation().get(),
            process_request: Some(process_request),
        })
    }

    /// Returns the operation identity without exposing the consuming request.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
}

/// Receipt returned after P-03 accepts a Cargo process.
#[derive(Debug)]
pub struct CargoStartReceipt {
    /// Original instrument invocation.
    pub invocation: InstrumentInvocation,
    /// P-03's acceptance receipt.
    pub process: ProcessStartReceipt,
}

/// Terminal or currently observable Cargo result.
#[derive(Clone, Debug)]
pub struct CargoObservation {
    /// Original instrument invocation.
    pub invocation: InstrumentInvocation,
    /// Current process view.
    pub view: ProcessExecutionView,
    /// Execution axis only; no verifier meaning is inferred here.
    pub execution: ExecutionStatus,
}

/// The sole adapter facade. Physical effects are exclusively delegated to the
/// injected provider-neutral process executor.
pub struct CargoInstrumentationAdapter<E> {
    executor: Arc<E>,
}

impl<E> CargoInstrumentationAdapter<E> {
    /// Creates an adapter around the active production process executor.
    #[must_use]
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> CargoInstrumentationAdapter<E> {
    /// Launches the exact bound Cargo request through P-03.
    ///
    /// # Errors
    /// Returns an error when the binding is already consumed, process launch
    /// fails, or the returned receipt does not preserve identity or generation.
    pub async fn launch(
        &self,
        binding: &mut CargoBinding,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<CargoStartReceipt, CargoAdapterError> {
        let process_request = binding
            .process_request
            .take()
            .ok_or(CargoAdapterError::IdentityMismatch)?;
        let process = self.executor.start(process_request, sink).await?;
        if process.operation_id() != &binding.operation_id {
            return Err(CargoAdapterError::IdentityMismatch);
        }
        if process.accepted_generation().get() != binding.generation {
            return Err(CargoAdapterError::GenerationMismatch);
        }
        Ok(CargoStartReceipt {
            invocation: binding.invocation.clone(),
            process,
        })
    }

    /// Inspects a running or terminal Cargo operation without changing it.
    ///
    /// # Errors
    /// Returns an error when process inspection fails or the observed operation
    /// does not match the binding.
    pub async fn inspect(
        &self,
        binding: &CargoBinding,
    ) -> Result<CargoObservation, CargoAdapterError> {
        let view = self.executor.inspect(binding.operation_id.clone()).await?;
        if view.operation_id() != &binding.operation_id
            || view.request_digest() != binding.request_digest
        {
            return Err(CargoAdapterError::IdentityMismatch);
        }
        Ok(CargoObservation {
            invocation: binding.invocation.clone(),
            execution: execution_status(&view),
            view,
        })
    }

    /// Cancels Cargo through the process contract's current fence.
    ///
    /// # Errors
    /// Returns an error when the process executor rejects cancellation.
    pub async fn cancel(
        &self,
        binding: &CargoBinding,
    ) -> Result<CancellationReceipt, CargoAdapterError> {
        Ok(self.executor.cancel(binding.operation_id.clone()).await?)
    }

    /// Reconciles an unknown Cargo result and retains the P-03 evidence record.
    ///
    /// # Errors
    /// Returns an error when the process executor rejects reconciliation.
    pub async fn reconcile(
        &self,
        binding: &CargoBinding,
    ) -> Result<ProcessEvidence, CargoAdapterError> {
        Ok(self
            .executor
            .reconcile(binding.operation_id.clone())
            .await?)
    }
}

/// Compatibility spelling for composition roots that call the adapter simply
/// `CargoAdapter`.
pub type CargoAdapter<E> = CargoInstrumentationAdapter<E>;

fn execution_status(view: &ProcessExecutionView) -> ExecutionStatus {
    use eliot_process::{ExitDisposition, ProcessLifecycle};
    match view.lifecycle() {
        ProcessLifecycle::Created | ProcessLifecycle::Starting => ExecutionStatus::Accepted,
        ProcessLifecycle::Running | ProcessLifecycle::Cancelling => ExecutionStatus::Running,
        ProcessLifecycle::UnknownOutcome | ProcessLifecycle::Quarantined => {
            ExecutionStatus::Unknown
        }
        ProcessLifecycle::Reconciled => ExecutionStatus::Partial,
        ProcessLifecycle::Exited => match view.exit() {
            Some(exit) if successful_exit(exit) => ExecutionStatus::Succeeded,
            Some(exit) if matches!(exit.disposition(), ExitDisposition::Cancelled) => {
                ExecutionStatus::Cancelled
            }
            Some(exit) if matches!(exit.disposition(), ExitDisposition::Unknown) => {
                ExecutionStatus::Unknown
            }
            None => ExecutionStatus::Unknown,
            _ => ExecutionStatus::Failed,
        },
        ProcessLifecycle::Failed => ExecutionStatus::Failed,
    }
}

fn successful_exit(exit: &ExitStatus) -> bool {
    if !matches!(exit.disposition(), ExitDisposition::Completed) {
        return false;
    }
    serde_json::to_value(exit)
        .ok()
        .and_then(|value| value.get("code").and_then(serde_json::Value::as_i64))
        .is_some_and(|code| code == 0)
}

// ---------------------------------------------------------------------------
// Machine-readable Cargo message stream
// ---------------------------------------------------------------------------

/// Content type of Cargo's newline-delimited `--message-format=json` stream.
///
/// Cargo writes one JSON message per line to stdout. Its stderr carries plain
/// progress text (`Compiling`, `Downloading`, …) which is never parsed as a
/// message: concatenating it would turn ordinary progress into malformed
/// messages and could hide a split line boundary.
pub const CARGO_MESSAGE_CONTENT_TYPE: &str = "application/json";
/// Maximum complete Cargo message stream accepted by the bounded parser.
pub const MAX_CARGO_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_MESSAGE_LINE_BYTES: usize = 1024 * 1024;

/// Artifact identity retained from one `compiler-artifact` message.
///
/// This is the identity Cargo itself reports for a produced artifact: the
/// package that owns it, the target it was produced for, the exact executable
/// path when the artifact is executable, and the produced filenames. It is
/// observation, never inference: nothing is derived from a path spelling, a
/// branch name, or a caller string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoArtifactRecord {
    /// Exact `package_id` Cargo reported for the artifact.
    pub package_id: String,
    /// Exact target name the artifact was produced for.
    pub target_name: String,
    /// Target kinds Cargo reported (for example `lib`, `bin`, `test`).
    pub target_kinds: Vec<String>,
    /// Executable path Cargo reported, when the artifact is an executable.
    pub executable: Option<String>,
    /// Exact produced filenames, in Cargo's own order.
    pub filenames: Vec<String>,
}

/// Bounded projection of one real Cargo message stream.
///
/// Diagnostic counters and the terminal `build-finished` outcome come from
/// Cargo's own messages. Lint codes are deliberately *not* projected here: the
/// Clippy lint projection over the same JSON dialect is owned by
/// `eliot_instrument_rustc::parse_clippy_jsonl`, so one stream has exactly one
/// owner per fact instead of two normalizers over one stream.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CargoReport {
    /// Number of `error` diagnostics Cargo reported.
    pub errors: u32,
    /// Number of `warning` diagnostics Cargo reported.
    pub warnings: u32,
    /// Number of `note` and `help` diagnostics Cargo reported.
    pub informational: u32,
    /// Artifact identities retained from the stream, in first-seen order.
    pub artifacts: Vec<CargoArtifactRecord>,
    /// Terminal `build-finished` success flag, when the stream reported one.
    pub build_finished: Option<bool>,
}

impl CargoReport {
    /// Maps the observed messages to the conservative verification algebra.
    ///
    /// A reported failure, or any error diagnostic, is [`VerificationOutcome::Fail`].
    /// A stream that never reported `build-finished` is
    /// [`VerificationOutcome::Unknown`], never Pass: a truncated or interrupted
    /// capture is not a successful build. Warnings alone never fail a build.
    pub fn outcome(&self) -> VerificationOutcome {
        if self.build_finished == Some(false) || self.errors != 0 {
            VerificationOutcome::Fail
        } else if self.build_finished == Some(true) {
            VerificationOutcome::Pass
        } else {
            VerificationOutcome::Unknown
        }
    }

    /// Maps the semantic result to execution status without conflating a
    /// failed build with a failed process launch.
    pub fn execution_status(&self) -> ExecutionStatus {
        match self.outcome() {
            VerificationOutcome::Pass => ExecutionStatus::Succeeded,
            VerificationOutcome::Cancelled => ExecutionStatus::Cancelled,
            VerificationOutcome::Unknown => ExecutionStatus::Unknown,
            _ => ExecutionStatus::Failed,
        }
    }
}

/// Parses Cargo's real newline-delimited `--message-format=json` stream.
///
/// The parser accepts exactly the four message kinds Cargo emits:
/// `compiler-message`, `compiler-artifact`, `build-finished`, and
/// `build-script-executed`. Any other or missing `reason` fails closed as
/// [`CargoAdapterError::MalformedMessage`] rather than being skipped, so a
/// stream this parser does not understand can never be read as a clean build.
/// The caller retains the exact raw bytes separately under
/// [`CARGO_MESSAGE_CONTENT_TYPE`]; this projection adds no verdict of its own.
///
/// # Errors
///
/// Returns [`CargoAdapterError::OutputTooLarge`] or
/// [`CargoAdapterError::LineTooLarge`] for an over-bound capture,
/// [`CargoAdapterError::MalformedMessage`] for any line that is not a valid
/// Cargo message of an accepted kind, and [`CargoAdapterError::CounterOverflow`]
/// for a diagnostic counter overflow.
pub fn parse_jsonl(bytes: &[u8]) -> Result<CargoReport, CargoAdapterError> {
    if bytes.len() > MAX_CARGO_OUTPUT_BYTES {
        return Err(CargoAdapterError::OutputTooLarge);
    }
    let mut report = CargoReport::default();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.len() > MAX_MESSAGE_LINE_BYTES {
            return Err(CargoAdapterError::LineTooLarge);
        }
        let line = std::str::from_utf8(line).map_err(|_| CargoAdapterError::MalformedMessage)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let message: CargoMessage =
            serde_json::from_str(line).map_err(|_| CargoAdapterError::MalformedMessage)?;
        apply_message(&mut report, message)?;
    }
    Ok(report)
}

/// Folds one accepted Cargo message into the report.
fn apply_message(report: &mut CargoReport, message: CargoMessage) -> Result<(), CargoAdapterError> {
    match message.reason.as_deref() {
        Some("compiler-message") => {
            let diagnostic = message.message.ok_or(CargoAdapterError::MalformedMessage)?;
            match diagnostic.level.as_deref() {
                Some("error") => report.errors = checked_increment(report.errors)?,
                Some("warning") => report.warnings = checked_increment(report.warnings)?,
                Some("note" | "help") => {
                    report.informational = checked_increment(report.informational)?;
                }
                Some(_) => {}
                None => return Err(CargoAdapterError::MalformedMessage),
            }
        }
        Some("compiler-artifact") => report.artifacts.push(artifact_record(message)),
        Some("build-finished") => {
            report.build_finished =
                Some(message.success.ok_or(CargoAdapterError::MalformedMessage)?);
        }
        // `build-script-executed` carries build-script outputs, not a build
        // outcome; it is accepted and contributes no counter.
        Some("build-script-executed") => {}
        Some(_) | None => return Err(CargoAdapterError::MalformedMessage),
    }
    Ok(())
}

/// Projects the artifact identity of one `compiler-artifact` message.
fn artifact_record(message: CargoMessage) -> CargoArtifactRecord {
    let target = message.target.unwrap_or(JsonTarget {
        name: None,
        kind: Vec::new(),
    });
    CargoArtifactRecord {
        package_id: message.package_id.unwrap_or_default(),
        target_name: target.name.unwrap_or_default(),
        target_kinds: target.kind,
        executable: message.executable,
        filenames: message.filenames,
    }
}

#[derive(Debug, Deserialize)]
struct CargoMessage {
    reason: Option<String>,
    #[serde(default)]
    message: Option<JsonDiagnostic>,
    #[serde(default)]
    package_id: Option<String>,
    #[serde(default)]
    target: Option<JsonTarget>,
    #[serde(default)]
    filenames: Vec<String>,
    #[serde(default)]
    executable: Option<String>,
    #[serde(default)]
    success: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct JsonDiagnostic {
    level: Option<String>,
    #[serde(flatten)]
    _extra: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct JsonTarget {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    kind: Vec<String>,
}

fn checked_increment(value: u32) -> Result<u32, CargoAdapterError> {
    value
        .checked_add(1)
        .ok_or(CargoAdapterError::CounterOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonzero_completed_exit_is_failed() -> Result<(), eliot_process::ContractError> {
        let exit = ExitStatus::new(ExitDisposition::Completed, Some(7), None, 1)?;
        assert!(!successful_exit(&exit));
        Ok(())
    }

    #[test]
    fn zero_completed_exit_succeeds() -> Result<(), eliot_process::ContractError> {
        let exit = ExitStatus::new(ExitDisposition::Completed, Some(0), None, 1)?;
        assert!(successful_exit(&exit));
        Ok(())
    }
}
