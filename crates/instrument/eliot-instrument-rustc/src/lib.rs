//! Provider adapter for one bounded, machine-readable Rust compiler invocation.
//!
//! The adapter owns command-shape validation and diagnostic interpretation. It
//! does not create a process or promote compiler output into a verification
//! decision; those effects remain behind the provider-neutral process contract.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation, InstrumentKind};
use eliot_process::{
    CancellationReceipt, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

/// Stable identity of the rustc adapter contract.
pub const RUSTC_INSTRUMENT: &str = "eliot.instrument.rustc";
/// The executable name accepted by a canonical rustc command.
pub const RUSTC_EXECUTABLE: &str = "rustc";
/// Maximum compiler diagnostic stream accepted by the parser.
pub const MAX_RUSTC_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_DIAGNOSTIC_LINE_BYTES: usize = 1024 * 1024;

/// An exact rustc command projection. Arguments remain separated and are
/// never rendered into a shell command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustcCommand {
    /// Executable selected by the authority.
    pub executable: String,
    /// Exact rustc argument vector.
    pub arguments: Vec<String>,
    /// Worktree in which the compiler is run.
    pub target: String,
}

impl RustcCommand {
    /// Builds a rustc command and requires JSON diagnostics for deterministic
    /// evidence parsing.
    pub fn new(
        target: impl Into<String>,
        source: impl Into<String>,
        options: &[String],
    ) -> Result<Self, RustcError> {
        let target = checked_text(target.into(), "target")?;
        let source = checked_text(source.into(), "source")?;
        let mut arguments = vec!["--error-format=json".to_owned(), source];
        for option in options {
            let option = checked_text(option.clone(), "option")?;
            if option == "--error-format=json" || option.starts_with("--error-format=json,") {
                return Err(RustcError::InvalidCommand(
                    "error format must be selected by the adapter".to_owned(),
                ));
            }
            arguments.push(option);
        }
        Ok(Self {
            executable: RUSTC_EXECUTABLE.to_owned(),
            arguments,
            target,
        })
    }

    /// Checks that a process request is exactly this command projection.
    pub fn matches_request(&self, request: &ProcessRequest) -> bool {
        request.executable().eq_ignore_ascii_case(&self.executable)
            && request.working_directory() == self.target
            && request.argv() == self.arguments
    }
}

/// Bounded summary of rustc's JSON diagnostic stream.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RustcReport {
    /// Number of emitted compiler errors.
    pub errors: u32,
    /// Number of emitted warnings.
    pub warnings: u32,
    /// Number of emitted notes and help records.
    pub informational: u32,
    /// Number of compiler artifact records.
    pub artifacts: u32,
}

impl RustcReport {
    /// Maps parsed diagnostics to an execution status without treating a
    /// warning as a failed compilation.
    pub fn execution_status(&self) -> ExecutionStatus {
        if self.errors != 0 {
            ExecutionStatus::Failed
        } else {
            ExecutionStatus::Succeeded
        }
    }
}

/// Parses rustc's newline-delimited JSON diagnostic output.
pub fn parse_jsonl(bytes: &[u8]) -> Result<RustcReport, RustcError> {
    if bytes.len() > MAX_RUSTC_OUTPUT_BYTES {
        return Err(RustcError::OutputTooLarge);
    }
    let mut report = RustcReport::default();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.len() > MAX_DIAGNOSTIC_LINE_BYTES {
            return Err(RustcError::DiagnosticTooLarge);
        }
        let line = std::str::from_utf8(line).map_err(|_| RustcError::MalformedDiagnostic)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let diagnostic: JsonDiagnostic =
            serde_json::from_str(line).map_err(|_| RustcError::MalformedDiagnostic)?;
        match diagnostic.reason.as_deref() {
            Some("compiler-message") => {
                let message = diagnostic.message.ok_or(RustcError::MalformedDiagnostic)?;
                match message.level.as_deref() {
                    Some("error") => report.errors = checked_increment(report.errors)?,
                    Some("warning") => report.warnings = checked_increment(report.warnings)?,
                    Some("note") | Some("help") => {
                        report.informational = checked_increment(report.informational)?
                    }
                    Some(_) => {}
                    None => return Err(RustcError::MalformedDiagnostic),
                }
            }
            Some("artifact") => report.artifacts = checked_increment(report.artifacts)?,
            Some("build-finished") | Some("rendered") => {}
            Some(_) | None => return Err(RustcError::MalformedDiagnostic),
        }
    }
    Ok(report)
}

/// Facade over the process contract for rustc launches.
pub struct RustcAdapter<E> {
    executor: Arc<E>,
}

impl<E> RustcAdapter<E> {
    /// Creates an adapter using the supplied process implementation.
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> RustcAdapter<E> {
    /// Validates and starts one exact rustc invocation through P-03.
    pub async fn launch(
        &self,
        invocation: &InstrumentInvocation,
        command: &RustcCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, RustcError> {
        invocation
            .validate()
            .map_err(|error| RustcError::Invocation(error.to_string()))?;
        if invocation.kind != InstrumentKind::Build
            || invocation.instrument.to_string() != RUSTC_INSTRUMENT
        {
            return Err(RustcError::WrongInstrument);
        }
        if !command.matches_request(&request) {
            return Err(RustcError::CommandMismatch);
        }
        let operation_id = request.operation_id().clone();
        let request_digest = request.invocation_digest().to_owned();
        let generation = request.generation().get();
        let receipt = self.executor.start(request, sink).await?;
        if receipt.operation_id() != &operation_id
            || receipt.request_digest() != request_digest
            || receipt.accepted_generation().get() != generation
        {
            return Err(RustcError::ReceiptMismatch);
        }
        Ok(receipt)
    }

    /// Returns the current process view for an operation.
    pub async fn inspect(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessExecutionView, RustcError> {
        Ok(self.executor.inspect(operation.clone()).await?)
    }

    /// Requests cancellation using the process implementation's fence.
    pub async fn cancel(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<CancellationReceipt, RustcError> {
        Ok(self.executor.cancel(operation.clone()).await?)
    }

    /// Reconciles durable process evidence without inventing compiler output.
    pub async fn reconcile(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessEvidence, RustcError> {
        Ok(self.executor.reconcile(operation.clone()).await?)
    }
}

#[derive(Debug, Deserialize)]
struct JsonDiagnostic {
    reason: Option<String>,
    message: Option<JsonMessage>,
    #[serde(flatten)]
    _extra: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct JsonMessage {
    level: Option<String>,
    #[serde(flatten)]
    _extra: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum RustcError {
    #[error("instrument invocation rejected: {0}")]
    Invocation(String),
    #[error("wrong instrument or invocation kind")]
    WrongInstrument,
    #[error("rustc command does not match the admitted process request")]
    CommandMismatch,
    #[error("process receipt does not bind to the admitted request")]
    ReceiptMismatch,
    #[error("invalid rustc command: {0}")]
    InvalidCommand(String),
    #[error("rustc output exceeds the bounded capture limit")]
    OutputTooLarge,
    #[error("rustc diagnostic line exceeds the bounded limit")]
    DiagnosticTooLarge,
    #[error("rustc emitted malformed JSON diagnostics")]
    MalformedDiagnostic,
    #[error("rustc diagnostic counter overflowed")]
    CounterOverflow,
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
}

fn checked_text(value: String, field: &'static str) -> Result<String, RustcError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RustcError::InvalidCommand(format!(
            "{field} must be non-blank and free of control characters"
        )));
    }
    Ok(value)
}

fn checked_increment(value: u32) -> Result<u32, RustcError> {
    value.checked_add(1).ok_or(RustcError::CounterOverflow)
}
