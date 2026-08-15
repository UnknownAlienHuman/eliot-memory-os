//! Process-facing rustfmt instrumentation.
//!
//! Rustfmt is admitted as a read-only format check.  The adapter constructs
//! one exact argument vector, binds it to the admitted invocation, and leaves
//! process ownership and evidence retention to P-03.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::Arc;

use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation, InstrumentKind, VerificationOutcome};
use eliot_process::{
    CancellationReceipt, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use thiserror::Error;

/// Stable identity registered for the rustfmt instrument.
pub const RUSTFMT_INSTRUMENT: &str = "eliot.instrument.rustfmt";
/// Maximum captured rustfmt output accepted by the adapter.
pub const MAX_RUSTFMT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 256 * 1024;

/// An exact, shell-free rustfmt check command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustfmtCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub target: String,
}

impl RustfmtCommand {
    /// Builds `cargo fmt --all -- --check` for one worktree.
    pub fn check(target: impl Into<String>) -> Result<Self, RustfmtError> {
        let target = checked_text(target.into(), "target")?;
        Ok(Self {
            executable: "cargo".to_owned(),
            arguments: vec![
                "fmt".to_owned(),
                "--all".to_owned(),
                "--".to_owned(),
                "--check".to_owned(),
            ],
            target,
        })
    }

    /// Returns whether a process request is exactly this admitted command.
    pub fn matches_request(&self, request: &ProcessRequest) -> bool {
        request.executable() == self.executable
            && request.working_directory() == self.target
            && request.argv() == self.arguments
    }
}

/// The bounded, lossless projection of rustfmt's check output.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RustfmtReport {
    pub changed_files: Vec<String>,
    pub diagnostics: Vec<String>,
}

impl RustfmtReport {
    /// Files for which rustfmt emitted a diff, in first-seen order.
    pub fn changed_files(&self) -> &[String] {
        &self.changed_files
    }

    /// Diagnostic lines retained without interpreting their wording as proof.
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    /// Computes the conservative semantic result from process termination.
    pub fn outcome(&self, exit_code: Option<i32>, cancelled: bool) -> VerificationOutcome {
        if cancelled {
            VerificationOutcome::Cancelled
        } else {
            match exit_code {
                Some(0) if self.changed_files.is_empty() && self.diagnostics.is_empty() => {
                    VerificationOutcome::Pass
                }
                Some(0) => VerificationOutcome::Unknown,
                Some(_) => VerificationOutcome::Fail,
                None => VerificationOutcome::Unknown,
            }
        }
    }

    /// Maps the semantic result to execution status.
    pub fn execution_status(&self, exit_code: Option<i32>, cancelled: bool) -> ExecutionStatus {
        match self.outcome(exit_code, cancelled) {
            VerificationOutcome::Pass => ExecutionStatus::Succeeded,
            VerificationOutcome::Cancelled => ExecutionStatus::Cancelled,
            VerificationOutcome::Unknown => ExecutionStatus::Unknown,
            _ => ExecutionStatus::Failed,
        }
    }
}

/// Parses rustfmt's bounded text output without treating diagnostics as proof.
pub fn parse_output(bytes: &[u8]) -> Result<RustfmtReport, RustfmtError> {
    if bytes.len() > MAX_RUSTFMT_OUTPUT_BYTES {
        return Err(RustfmtError::OutputTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RustfmtError::MalformedOutput)?;
    let mut report = RustfmtReport::default();
    let mut files = BTreeSet::new();
    for raw_line in text.split('\n') {
        if raw_line.len() > MAX_LINE_BYTES {
            return Err(RustfmtError::LineTooLarge);
        }
        let line = raw_line.trim_end_matches('\r');
        if line.chars().any(char::is_control) {
            return Err(RustfmtError::MalformedOutput);
        }
        if let Some(path) = line.strip_prefix("Diff in ") {
            let path = path.trim();
            if path.is_empty() {
                return Err(RustfmtError::MalformedOutput);
            }
            if !files.insert(path.to_owned()) {
                return Err(RustfmtError::DuplicateDiff);
            }
            report.changed_files.push(path.to_owned());
        } else if line.contains("error:") || line.contains("Error:") {
            report.diagnostics.push(line.to_owned());
        }
    }
    Ok(report)
}

/// Stateless facade over P-03 for exact rustfmt checks.
pub struct RustfmtAdapter<E> {
    executor: Arc<E>,
}

impl<E> RustfmtAdapter<E> {
    /// Creates an adapter over the supplied process executor.
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> RustfmtAdapter<E> {
    /// Validates and starts one exact rustfmt invocation through P-03.
    pub async fn launch(
        &self,
        invocation: &InstrumentInvocation,
        command: &RustfmtCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, RustfmtError> {
        invocation
            .validate()
            .map_err(|error| RustfmtError::Invocation(error.to_string()))?;
        if invocation.kind != InstrumentKind::Format
            || invocation.instrument.to_string() != RUSTFMT_INSTRUMENT
        {
            return Err(RustfmtError::WrongInstrument);
        }
        if !command.matches_request(&request) {
            return Err(RustfmtError::CommandMismatch);
        }
        let receipt = self.executor.start(request.clone(), sink).await?;
        if receipt.operation_id() != request.operation_id()
            || receipt.request_digest() != request.invocation_digest()
            || receipt.accepted_generation() != request.generation()
        {
            return Err(RustfmtError::ReceiptMismatch);
        }
        Ok(receipt)
    }

    /// Reads the current process projection.
    pub async fn inspect(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessExecutionView, RustfmtError> {
        Ok(self.executor.inspect(operation.clone()).await?)
    }

    /// Requests cancellation of an admitted operation.
    pub async fn cancel(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<CancellationReceipt, RustfmtError> {
        Ok(self.executor.cancel(operation.clone()).await?)
    }

    /// Reconciles an operation whose physical result is not yet classified.
    pub async fn reconcile(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessEvidence, RustfmtError> {
        Ok(self.executor.reconcile(operation.clone()).await?)
    }
}

#[derive(Debug, Error)]
pub enum RustfmtError {
    #[error("invocation rejected: {0}")]
    Invocation(String),
    #[error("wrong instrument or invocation kind")]
    WrongInstrument,
    #[error("process command does not match admitted rustfmt command")]
    CommandMismatch,
    #[error("process receipt does not bind to the admitted request")]
    ReceiptMismatch,
    #[error("rustfmt output exceeds the bounded capture limit")]
    OutputTooLarge,
    #[error("rustfmt output contains an oversized line")]
    LineTooLarge,
    #[error("rustfmt output is not valid bounded UTF-8 text")]
    MalformedOutput,
    #[error("rustfmt emitted a duplicate file diff")]
    DuplicateDiff,
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
}

fn checked_text(value: String, field: &'static str) -> Result<String, RustfmtError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RustfmtError::InvalidText { field });
    }
    Ok(value)
}
