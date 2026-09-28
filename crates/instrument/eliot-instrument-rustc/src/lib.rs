//! Provider adapter for one bounded, machine-readable Rust compiler invocation.
//!
//! The adapter owns command-shape validation and diagnostic interpretation. It
//! does not create a process or promote compiler output into a verification
//! decision; those effects remain behind the provider-neutral process contract.
//!
//! Two projections of the same JSON dialect live here and nowhere else:
//! [`parse_jsonl`] counts compiler diagnostics for a plain `rustc` run, and
//! [`parse_clippy_jsonl`] projects the lint identities Clippy reports on that
//! same dialect. Cargo's own message bookkeeping (artifact and build-finished
//! records) is owned by `eliot_instrument_cargo::parse_jsonl`, so one real
//! stream has exactly one owner per fact.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{
    ExecutionStatus, InstrumentInvocation, InstrumentKind, VerificationOutcome,
};
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
        // A response file would hide the real argument vector from the
        // adapter; only an explicit source path is admitted.
        if source.starts_with('@') {
            return Err(RustcError::InvalidCommand(
                "source must be a file path; response files are refused".to_owned(),
            ));
        }
        let mut arguments = vec!["--error-format=json".to_owned(), source];
        for option in options {
            let option = checked_text(option.clone(), "option")?;
            if option == "--error-format=json" || option.starts_with("--error-format=json,") {
                return Err(RustcError::InvalidCommand(
                    "error format must be selected by the adapter".to_owned(),
                ));
            }
            // The output location always comes from the admitted target
            // root: a caller-supplied output override or an opaque response
            // file could redirect the actual output elsewhere (issue #1806).
            if option.starts_with("-o")
                || option == "--out-dir"
                || option.starts_with("--out-dir=")
                || option.starts_with('@')
            {
                return Err(RustcError::InvalidCommand(
                    "output location must come from the admitted target root".to_owned(),
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

// ---------------------------------------------------------------------------
// Clippy lint projection over the same JSON dialect
// ---------------------------------------------------------------------------

/// Content type of Clippy's machine-readable diagnostic stream.
///
/// Clippy is a rustc driver: `cargo clippy --message-format=json` writes the
/// same newline-delimited JSON dialect to stdout that [`parse_jsonl`] reads,
/// and writes ordinary human progress and the rendered lint summary to stderr.
/// That stderr text is never parsed as a diagnostic — parsing prose would make
/// a lint count depend on wording — so this projection covers the JSON stream
/// that a real invocation actually produces.
pub const CLIPPY_MESSAGE_CONTENT_TYPE: &str = "application/json";
/// Maximum complete Clippy diagnostic stream accepted by the bounded parser.
pub const MAX_CLIPPY_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// One lint diagnostic retained from Clippy's JSON stream.
///
/// A lint is identified by the exact code Clippy reported (`clippy::…` or the
/// underlying rustc lint name) plus the level it was emitted at and the file
/// its primary span names. The primary file is the span Clippy marked
/// `is_primary`; when a message marks no primary span the lint is retained
/// without one rather than being attributed to a guessed file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClippyLint {
    /// Exact lint code reported for this diagnostic.
    pub code: String,
    /// Exact diagnostic level reported for this lint.
    pub level: String,
    /// File named by the message's primary span, when it marked one.
    pub primary_file: Option<String>,
    /// Exact diagnostic message text.
    pub message: String,
}

/// Bounded projection of one real Clippy run.
///
/// Only lint-bearing diagnostics are retained as [`ClippyLint`]s. Cargo's own
/// `compiler-artifact` / `build-finished` bookkeeping is accepted and ignored:
/// those facts are owned by `eliot_instrument_cargo::parse_jsonl`, so this
/// projection never becomes a second normalizer over the same stream.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClippyReport {
    /// Number of lints reported at `error` level.
    pub errors: u32,
    /// Number of lints reported at `warn` level.
    pub warnings: u32,
    /// Number of `note` and `help` diagnostics reported.
    pub informational: u32,
    /// Lints retained in first-seen order.
    pub lints: Vec<ClippyLint>,
}

impl ClippyReport {
    /// Distinct lint codes retained by this run, in sorted order.
    pub fn lint_codes(&self) -> Vec<&str> {
        let mut codes: Vec<&str> = self.lints.iter().map(|lint| lint.code.as_str()).collect();
        codes.sort_unstable();
        codes.dedup();
        codes
    }

    /// Maps the observed lints to the conservative verification algebra.
    ///
    /// A Clippy run passes only when it emitted no error-level lint. Warning
    /// lints are reported as evidence, not as a failed run, and an empty
    /// stream stays [`VerificationOutcome::Unknown`]: no captured output is
    /// never a clean lint result.
    pub fn outcome(&self) -> VerificationOutcome {
        if self.errors != 0 {
            VerificationOutcome::Fail
        } else if self.warnings == 0 && self.informational == 0 {
            VerificationOutcome::Unknown
        } else {
            VerificationOutcome::Pass
        }
    }

    /// Maps the semantic result to execution status without conflating a lint
    /// failure with a failed process launch.
    pub fn execution_status(&self) -> ExecutionStatus {
        match self.outcome() {
            VerificationOutcome::Pass => ExecutionStatus::Succeeded,
            VerificationOutcome::Cancelled => ExecutionStatus::Cancelled,
            VerificationOutcome::Unknown => ExecutionStatus::Unknown,
            _ => ExecutionStatus::Failed,
        }
    }
}

/// Parses Clippy's real newline-delimited JSON diagnostic stream.
///
/// The stream is the same dialect [`parse_jsonl`] reads, so `compiler-message`
/// records carrying a lint `code` become [`ClippyLint`]s and the Cargo
/// bookkeeping kinds are accepted and ignored. A `compiler-message` without a
/// level fails closed, exactly as in [`parse_jsonl`]; an unknown `reason` fails
/// closed as [`RustcError::MalformedDiagnostic`] rather than being skipped, so
/// a stream this parser does not understand can never be read as a clean lint
/// run. The caller retains the exact raw bytes separately under
/// [`CLIPPY_MESSAGE_CONTENT_TYPE`].
///
/// # Errors
///
/// Returns [`RustcError::OutputTooLarge`] or [`RustcError::DiagnosticTooLarge`]
/// for an over-bound capture, [`RustcError::MalformedDiagnostic`] for any line
/// that is not a valid accepted message, and [`RustcError::CounterOverflow`]
/// for a lint counter overflow.
pub fn parse_clippy_jsonl(bytes: &[u8]) -> Result<ClippyReport, RustcError> {
    if bytes.len() > MAX_CLIPPY_OUTPUT_BYTES {
        return Err(RustcError::OutputTooLarge);
    }
    let mut report = ClippyReport::default();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.len() > MAX_DIAGNOSTIC_LINE_BYTES {
            return Err(RustcError::DiagnosticTooLarge);
        }
        let line = std::str::from_utf8(line).map_err(|_| RustcError::MalformedDiagnostic)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let diagnostic: ClippyJsonMessage =
            serde_json::from_str(line).map_err(|_| RustcError::MalformedDiagnostic)?;
        apply_clippy_message(&mut report, diagnostic)?;
    }
    Ok(report)
}

/// Folds one accepted Clippy message into the report.
fn apply_clippy_message(
    report: &mut ClippyReport,
    diagnostic: ClippyJsonMessage,
) -> Result<(), RustcError> {
    match diagnostic.reason.as_deref() {
        Some("compiler-message") => {
            let message = diagnostic.message.ok_or(RustcError::MalformedDiagnostic)?;
            let level = message.level.ok_or(RustcError::MalformedDiagnostic)?;
            match level.as_str() {
                "error" => report.errors = checked_increment(report.errors)?,
                "warning" => report.warnings = checked_increment(report.warnings)?,
                "note" | "help" => report.informational = checked_increment(report.informational)?,
                _ => {}
            }
            let Some(code) = message.code else {
                return Ok(());
            };
            report.lints.push(ClippyLint {
                code,
                level,
                primary_file: primary_file(&message.spans),
                message: message.message,
            });
        }
        // Cargo bookkeeping kinds belong to the Cargo projection.
        Some("compiler-artifact") | Some("build-finished") | Some("build-script-executed") => {}
        Some("artifact") | Some("rendered") => {}
        Some(_) | None => return Err(RustcError::MalformedDiagnostic),
    }
    Ok(())
}

/// Returns the file named by the message's primary span, when it marked one.
///
/// The primary span is the one the diagnostic itself marked; a message that
/// marks none is retained without a file rather than attributed to the first
/// span it happens to carry.
fn primary_file(spans: &[ClippySpan]) -> Option<String> {
    spans
        .iter()
        .find(|span| span.is_primary)
        .map(|span| span.file_name.clone())
}

#[derive(Debug, Deserialize)]
struct ClippyJsonMessage {
    reason: Option<String>,
    message: Option<ClippyDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct ClippyDiagnostic {
    level: Option<String>,
    code: Option<String>,
    message: String,
    #[serde(default)]
    spans: Vec<ClippySpan>,
}

#[derive(Debug, Deserialize)]
struct ClippySpan {
    file_name: String,
    #[serde(default)]
    is_primary: bool,
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
