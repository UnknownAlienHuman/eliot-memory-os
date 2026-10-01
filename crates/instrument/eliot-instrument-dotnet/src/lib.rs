//! Provider adapter for bounded .NET/MSBuild process invocations.
//!
//! The adapter validates a declared command and delegates every external
//! process to the shared `eliot-process` executor.  It deliberately has no
//! private spawn path, process-tree owner, finish authority, or filesystem
//! policy.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{InstrumentInvocation, InstrumentKind, VerificationOutcome};
use eliot_process::{
    CancellationReceipt, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use thiserror::Error;

/// Stable contract identifier for this adapter.
pub const CONTRACT_ID: &str = "eliot.instrument.dotnet.msbuild";
/// Parser contract for MSBuild's console diagnostic and completion summary.
pub const OUTPUT_PARSER_ID: &str = "eliot.instrument.dotnet.msbuild-output";
/// Evaluator contract for the parsed MSBuild summary and terminal status.
pub const OUTPUT_EVALUATOR_ID: &str = "eliot.instrument.dotnet.msbuild-outcome";
/// Default executable used for SDK-style projects.
pub const DOTNET_EXECUTABLE: &str = "dotnet";
/// Default `MSBuild` profile passed to `dotnet`.
pub const DEFAULT_PROFILE: &str = "msbuild";

/// One compiler diagnostic projected from the canonical MSBuild console log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotnetDiagnostic {
    /// `error` or `warning`, as emitted by MSBuild.
    pub severity: String,
    /// Compiler or MSBuild diagnostic code.
    pub code: String,
    /// Diagnostic message text after the code.
    pub message: String,
}

/// Parsed MSBuild console summary and its diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotnetBuildReport {
    /// Diagnostics in output order.
    pub diagnostics: Vec<DotnetDiagnostic>,
    /// Warning count in the final MSBuild summary.
    pub warning_count: u64,
    /// Error count in the final MSBuild summary.
    pub error_count: u64,
    /// Whether MSBuild emitted its terminal success or failure summary.
    pub summary: DotnetBuildSummary,
    /// Optional VSTest summary emitted by `dotnet test`.
    /// A build summary by itself does not prove that tests ran.
    pub test_summary: Option<DotnetTestSummary>,
}

/// Standard VSTest outcome totals from a `dotnet test` console summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotnetTestSummary {
    /// Whether VSTest printed `Passed!` rather than `Failed!`.
    pub succeeded: bool,
    /// Number of failed tests.
    pub failed: u64,
    /// Number of passed tests.
    pub passed: u64,
    /// Number of skipped tests.
    pub skipped: u64,
    /// Total tests reported by VSTest.
    pub total: u64,
}

/// Terminal summary emitted by MSBuild's console logger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DotnetBuildSummary {
    /// MSBuild emitted `Build succeeded.` and its warning/error totals.
    Succeeded,
    /// MSBuild emitted `Build FAILED.` and its warning/error totals.
    Failed,
}

impl DotnetBuildReport {
    /// Evaluates parsed console evidence without inferring success from exit 0.
    ///
    /// A passing outcome requires MSBuild's complete success summary, zero
    /// summary errors, and agreement between parsed diagnostic counts and the
    /// summary. Warnings remain visible but do not fail a build. The caller
    /// must still combine this result with the exact terminal process status.
    #[must_use]
    pub fn outcome(&self) -> VerificationOutcome {
        if self.summary == DotnetBuildSummary::Failed || self.error_count != 0 {
            return VerificationOutcome::Fail;
        }
        let (warnings, errors) = self.diagnostics.iter().fold((0_u64, 0_u64), |counts, item| {
            match item.severity.as_str() {
                "warning" => (counts.0.saturating_add(1), counts.1),
                "error" => (counts.0, counts.1.saturating_add(1)),
                _ => counts,
            }
        });
        if self.summary == DotnetBuildSummary::Succeeded
            && errors == 0
            && warnings == self.warning_count
        {
            VerificationOutcome::Pass
        } else {
            VerificationOutcome::Unknown
        }
    }

    /// Evaluates a test run only when VSTest reports a complete nonempty set.
    #[must_use]
    pub fn test_outcome(&self) -> VerificationOutcome {
        let Some(summary) = &self.test_summary else {
            return VerificationOutcome::Unknown;
        };
        if summary.failed > 0 || !summary.succeeded {
            return VerificationOutcome::Fail;
        }
        if summary.total > 0
            && summary.passed.saturating_add(summary.skipped) == summary.total
            && summary.failed == 0
        {
            VerificationOutcome::Pass
        } else {
            VerificationOutcome::Unknown
        }
    }
}

/// Fail-closed errors while parsing MSBuild's standard console summary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DotnetOutputError {
    /// Output is not UTF-8 text.
    #[error("MSBuild output is not UTF-8")]
    InvalidUtf8,
    /// Output does not contain exactly one terminal MSBuild summary.
    #[error("MSBuild output has no unique terminal summary")]
    MissingOrDuplicateSummary,
    /// Output does not contain exactly one warning and error total.
    #[error("MSBuild output has no unique warning/error totals")]
    MissingOrDuplicateTotals,
    /// A VSTest summary appeared more than once.
    #[error("MSBuild output has duplicate VSTest summaries")]
    DuplicateTestSummary,
    /// A VSTest summary is malformed or has missing/invalid totals.
    #[error("MSBuild output has a malformed VSTest summary")]
    MalformedTestSummary,
    /// A numeric total overflowed the owning counter.
    #[error("MSBuild diagnostic total is outside the supported range")]
    CounterOverflow,
    /// A diagnostic resembles MSBuild's form but has no code/message pair.
    #[error("MSBuild diagnostic line is malformed")]
    MalformedDiagnostic,
}

/// Parses the MSBuild console output captured from one admitted process.
///
/// The standard console logger emits `Build succeeded.` or `Build FAILED.`
/// followed by `Warning(s)` and `Error(s)` totals. A stream without that full
/// summary is not an evaluation result. Tool stdout bytes remain separately
/// retained by the governed process-stream path.
pub fn parse_build_output(bytes: &[u8]) -> Result<DotnetBuildReport, DotnetOutputError> {
    let output = std::str::from_utf8(bytes).map_err(|_| DotnetOutputError::InvalidUtf8)?;
    let mut diagnostics = Vec::new();
    let mut summary = None;
    let mut warning_count = None;
    let mut error_count = None;
    let mut test_summary = None;
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Passed! - ") || line.starts_with("Failed! - ") {
            if test_summary.replace(parse_test_summary(line)?).is_some() {
                return Err(DotnetOutputError::DuplicateTestSummary);
            }
            continue;
        }
        match line {
            "Build succeeded." => {
                if summary.replace(DotnetBuildSummary::Succeeded).is_some() {
                    return Err(DotnetOutputError::MissingOrDuplicateSummary);
                }
                continue;
            }
            "Build FAILED." => {
                if summary.replace(DotnetBuildSummary::Failed).is_some() {
                    return Err(DotnetOutputError::MissingOrDuplicateSummary);
                }
                continue;
            }
            _ => {}
        }
        if let Some(count) = parse_summary_count(line, "Warning(s)")? {
            if warning_count.replace(count).is_some() {
                return Err(DotnetOutputError::MissingOrDuplicateTotals);
            }
            continue;
        }
        if let Some(count) = parse_summary_count(line, "Error(s)")? {
            if error_count.replace(count).is_some() {
                return Err(DotnetOutputError::MissingOrDuplicateTotals);
            }
            continue;
        }
        if let Some(diagnostic) = parse_diagnostic(line)? {
            diagnostics.push(diagnostic);
        }
    }
    match (summary, warning_count, error_count) {
        (Some(summary), Some(warning_count), Some(error_count)) => Ok(DotnetBuildReport {
            diagnostics,
            warning_count,
            error_count,
            summary,
            test_summary,
        }),
        _ => Err(DotnetOutputError::MissingOrDuplicateSummary),
    }
}

fn parse_test_summary(line: &str) -> Result<DotnetTestSummary, DotnetOutputError> {
    let succeeded = line.starts_with("Passed! - ");
    let totals = line
        .split_once(" - ")
        .map(|(_, values)| values)
        .ok_or(DotnetOutputError::MalformedTestSummary)?;
    let mut fields = totals.split(", ");
    let failed = parse_test_total(fields.next(), "Failed:")?;
    let passed = parse_test_total(fields.next(), "Passed:")?;
    let skipped = parse_test_total(fields.next(), "Skipped:")?;
    let total = parse_test_total(fields.next(), "Total:")?;
    if let Some(duration) = fields.next() {
        if !duration
            .strip_prefix("Duration:")
            .is_some_and(|value| !value.trim().is_empty())
            || fields.next().is_some()
        {
            return Err(DotnetOutputError::MalformedTestSummary);
        }
    }
    Ok(DotnetTestSummary {
        succeeded,
        failed,
        passed,
        skipped,
        total,
    })
}

fn parse_test_total(field: Option<&str>, label: &str) -> Result<u64, DotnetOutputError> {
    let value = field
        .and_then(|field| field.strip_prefix(label))
        .map(str::trim)
        .ok_or(DotnetOutputError::MalformedTestSummary)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DotnetOutputError::MalformedTestSummary);
    }
    value
        .parse::<u64>()
        .map_err(|_| DotnetOutputError::CounterOverflow)
}

fn parse_summary_count(line: &str, suffix: &str) -> Result<Option<u64>, DotnetOutputError> {
    let mut fields = line.split_whitespace();
    let Some(count) = fields.next() else {
        return Ok(None);
    };
    let Some(label) = fields.next() else {
        return Ok(None);
    };
    if fields.next().is_some() || label != suffix {
        return Ok(None);
    }
    count
        .parse::<u64>()
        .map(Some)
        .map_err(|_| DotnetOutputError::CounterOverflow)
}

fn parse_diagnostic(line: &str) -> Result<Option<DotnetDiagnostic>, DotnetOutputError> {
    for severity in ["error", "warning"] {
        let tail = if let Some((_, tail)) = line.split_once(&format!(": {severity} ")) {
            tail
        } else if let Some(tail) = line.strip_prefix(&format!("{severity} ")) {
            tail
        } else {
            continue;
        };
        let Some((code, message)) = tail.split_once(": ") else {
            return Err(DotnetOutputError::MalformedDiagnostic);
        };
        if code.is_empty() || message.is_empty() {
            return Err(DotnetOutputError::MalformedDiagnostic);
        }
        return Ok(Some(DotnetDiagnostic {
            severity: severity.to_owned(),
            code: code.to_owned(),
            message: message.to_owned(),
        }));
    }
    Ok(None)
}

/// Configuration for bounded .NET/MSBuild command validation.
#[derive(Clone, Debug)]
pub struct DotnetMsbuildConfig {
    /// Executable name accepted for dotnet requests.
    pub dotnet_executable: String,
    /// Executable name accepted for direct `MSBuild` requests.
    pub msbuild_executable: String,
}

impl Default for DotnetMsbuildConfig {
    fn default() -> Self {
        Self {
            dotnet_executable: DOTNET_EXECUTABLE.to_owned(),
            msbuild_executable: "msbuild".to_owned(),
        }
    }
}

impl DotnetMsbuildConfig {
    /// Creates configuration and rejects blank executable identities.
    pub fn new(
        dotnet_executable: impl Into<String>,
        msbuild_executable: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        let dotnet_executable = dotnet_executable.into();
        let msbuild_executable = msbuild_executable.into();
        if dotnet_executable.trim().is_empty() || msbuild_executable.trim().is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "tool executable must not be blank",
            ));
        }
        Ok(Self {
            dotnet_executable,
            msbuild_executable,
        })
    }
}

/// Exact declared .NET/MSBuild command shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotnetMsbuildCommand {
    /// Executable selected by the admitted profile.
    pub executable: String,
    /// Exact argument vector, kept separate from shell syntax.
    pub arguments: Vec<String>,
    /// Isolated external build root.
    pub target: String,
}

impl DotnetMsbuildCommand {
    /// Builds a command for `dotnet msbuild` or direct `msbuild` execution.
    pub fn new(
        target: impl Into<String>,
        executable: impl Into<String>,
        arguments: &[String],
    ) -> Result<Self, AdapterError> {
        let target = checked_text(target.into(), "target")?;
        let executable = checked_text(executable.into(), "executable")?;
        let mut args = Vec::with_capacity(arguments.len());
        for argument in arguments {
            args.push(checked_text(argument.clone(), "argument")?);
        }
        Ok(Self {
            executable,
            arguments: args,
            target,
        })
    }

    /// Checks exact request identity without interpreting process output.
    pub fn matches_request(&self, request: &ProcessRequest) -> bool {
        request.executable().eq_ignore_ascii_case(&self.executable)
            && request.working_directory() == self.target
            && request.argv() == self.arguments
    }
}

/// Errors produced before or during adapter execution.
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("invalid dotnet adapter configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("unsupported .NET/MSBuild invocation: {0}")]
    UnsupportedInvocation(String),
    #[error("dotnet process command does not match the declared profile")]
    CommandMismatch,
    #[error("process receipt does not bind to the admitted request")]
    ReceiptMismatch,
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
}

/// Shared-executor adapter for .NET/MSBuild.
pub struct DotnetMsbuildAdapter<E> {
    executor: Arc<E>,
    config: DotnetMsbuildConfig,
}

impl<E> DotnetMsbuildAdapter<E> {
    /// Creates an adapter around the active process executor.
    #[must_use]
    pub fn new(executor: Arc<E>) -> Self {
        Self::with_config(executor, DotnetMsbuildConfig::default())
    }

    /// Creates an adapter with explicit executable identities.
    #[must_use]
    pub fn with_config(executor: Arc<E>, config: DotnetMsbuildConfig) -> Self {
        Self { executor, config }
    }

    /// Validates the invocation class and executable policy.
    pub fn validate_invocation(
        &self,
        invocation: &InstrumentInvocation,
    ) -> Result<(), AdapterError> {
        invocation
            .validate()
            .map_err(|error| AdapterError::UnsupportedInvocation(error.to_string()))?;
        if !matches!(
            invocation.kind,
            InstrumentKind::Build
                | InstrumentKind::Test
                | InstrumentKind::Verify
                | InstrumentKind::Inspect
        ) {
            return Err(AdapterError::UnsupportedInvocation(
                "only build, test, verify, and inspect are supported".to_owned(),
            ));
        }
        if invocation.arguments.iter().any(|arg| arg.contains('\0')) {
            return Err(AdapterError::UnsupportedInvocation(
                "arguments may not contain NUL".to_owned(),
            ));
        }
        Ok(())
    }

    /// Launches one exact declared command through the shared executor.
    pub async fn launch(
        &self,
        invocation: &InstrumentInvocation,
        command: &DotnetMsbuildCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        self.validate_invocation(invocation)?;
        let expected = if command.executable.eq_ignore_ascii_case("dotnet") {
            &self.config.dotnet_executable
        } else {
            &self.config.msbuild_executable
        };
        if !command.executable.eq_ignore_ascii_case(expected) || !command.matches_request(&request)
        {
            return Err(AdapterError::CommandMismatch);
        }
        let operation = request.operation_id().clone();
        let digest = request.invocation_digest().to_owned();
        let generation = request.generation();
        let receipt = self.executor.start(request, sink).await?;
        if receipt.operation_id() != &operation
            || receipt.request_digest() != digest
            || receipt.accepted_generation() != generation
        {
            return Err(AdapterError::ReceiptMismatch);
        }
        Ok(receipt)
    }

    /// Inspects an operation through the shared executor.
    pub async fn inspect(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessExecutionView, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        Ok(self.executor.inspect(operation.clone()).await?)
    }

    /// Cancels an operation through the shared executor.
    pub async fn cancel(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<CancellationReceipt, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        Ok(self.executor.cancel(operation.clone()).await?)
    }

    /// Reconciles an operation and returns observation-only evidence.
    pub async fn reconcile(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessEvidence, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        Ok(self.executor.reconcile(operation.clone()).await?)
    }
}

/// Compatibility spelling for callers that refer to the adapter as an executor.
pub type DotnetMsbuildExecutor<E> = DotnetMsbuildAdapter<E>;

fn checked_text(value: String, field: &'static str) -> Result<String, AdapterError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(AdapterError::UnsupportedInvocation(format!(
            "{field} must be non-blank and free of control characters"
        )));
    }
    Ok(value)
}
