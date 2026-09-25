//! nextest's process-facing instrumentation adapter.
//!
//! The adapter deliberately owns neither a child process nor durable evidence.
//! It validates the admitted invocation, checks that the P-03 request is the
//! exact command selected by the invocation, and delegates all effects to the
//! injected [`ProcessExecutor`].  nextest's JSON stream is parsed separately so
//! incomplete or contradictory output cannot be promoted to a passing result.

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

/// Stable identity used when an invocation is admitted to nextest.
pub const NEXTEST_INSTRUMENT: &str = "eliot.instrument.nextest";
/// Explicit machine-readable reporter contract admitted for nextest 0.9.143.
pub const NEXTEST_LIBTEST_JSON_FORMAT_VERSION: &str = "0.1";
/// Content type used by TestD for the stdout event stream.
pub const NEXTEST_STDOUT_CONTENT_TYPE: &str = "application/x-nextest-libtest-json-plus";
/// Content type used by TestD for stderr, which is never parsed as events.
pub const NEXTEST_STDERR_CONTENT_TYPE: &str = "text/plain";
/// Maximum complete stream accepted by the bounded parser.
pub const MAX_NEXTEST_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 256 * 1024;

/// A validated nextest command projection.  Arguments are kept as individual
/// values and are never rendered into a shell command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NextestCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    pub target: String,
    pub profile: String,
}

impl NextestCommand {
    /// Builds the canonical command arguments for the admitted
    /// `cargo-nextest run` executable.
    pub fn run(
        target: impl Into<String>,
        profile: impl Into<String>,
        filters: &[String],
    ) -> Result<Self, NextestError> {
        let target = checked_text(target.into(), "target")?;
        let profile = checked_text(profile.into(), "profile")?;
        let mut arguments = vec![
            "run".to_owned(),
            "--profile".to_owned(),
            profile.clone(),
            "--message-format".to_owned(),
            "libtest-json-plus".to_owned(),
            "--message-format-version".to_owned(),
            NEXTEST_LIBTEST_JSON_FORMAT_VERSION.to_owned(),
        ];
        for filter in filters {
            arguments.push(checked_text(filter.clone(), "filter")?);
        }
        Ok(Self {
            executable: "cargo-nextest".to_owned(),
            arguments,
            target,
            profile,
        })
    }

    /// Checks that a process request contains precisely this command.
    pub fn matches_request(&self, request: &ProcessRequest) -> bool {
        request.executable() == self.executable
            && request.working_directory() == self.target
            && request.argv() == self.arguments
    }
}

/// Bounded nextest result counters.  A counter is incremented at most once per
/// completed test name; duplicate stream records are rejected by the parser.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NextestReport {
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub timed_out: u32,
    pub leaked: u32,
    pub cancelled: u32,
    pub started: u32,
    pub completed: u32,
}

impl NextestReport {
    /// Maps counters to the conservative verification algebra.
    pub fn outcome(&self) -> VerificationOutcome {
        if self.cancelled != 0 {
            VerificationOutcome::Cancelled
        } else if self.timed_out != 0 || self.leaked != 0 || self.failed != 0 {
            VerificationOutcome::Fail
        } else if self.started == 0 || self.completed != self.started {
            VerificationOutcome::Unknown
        } else {
            VerificationOutcome::Pass
        }
    }

    /// Maps the result to execution status without conflating a failed test
    /// with a failed process launch.
    pub fn execution_status(&self) -> ExecutionStatus {
        match self.outcome() {
            VerificationOutcome::Pass => ExecutionStatus::Succeeded,
            VerificationOutcome::Cancelled => ExecutionStatus::Cancelled,
            VerificationOutcome::Unknown => ExecutionStatus::Unknown,
            _ => ExecutionStatus::Failed,
        }
    }
}

/// Terminal status emitted for one libtest-compatible nextest test event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextestTestStatus {
    Pass,
    Fail,
    Skip,
    Timeout,
    Leak,
    Cancelled,
}

/// One parsed test lifecycle event from `libtest-json` or
/// `libtest-json-plus`.  Suite/progress events are deliberately omitted;
/// callers receive only test events which can contribute to verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NextestTestEvent {
    Started {
        name: String,
    },
    Completed {
        name: String,
        status: NextestTestStatus,
    },
}

/// Returns the catalog identity for a nextest test event.
///
/// Retries are emitted as `catalog-id#<retry-number>` by nextest. The numeric
/// suffix is execution metadata, not a second admitted test. A non-numeric or
/// non-terminal `#` segment remains part of the identity.
#[must_use]
pub fn catalog_test_id(name: &str) -> &str {
    let Some((base, suffix)) = name.rsplit_once('#') else {
        return name;
    };
    if !base.is_empty() && !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        base
    } else {
        name
    }
}

/// Parse nextest's machine-readable JSONL test events.
///
/// The productive profile uses `libtest-json-plus`, whose top-level event
/// names follow libtest (`ok`, `failed`, `ignored`). The `nextest` subobject
/// is suite metadata and is never consulted for test status. Older nextest
/// fixtures used `completed` plus a top-level `status`; that spelling remains
/// accepted only as a compatibility form. Suite events, progress events, and
/// stderr text are outside this parser and are ignored by the caller.
pub fn parse_test_events(bytes: &[u8]) -> Result<Vec<NextestTestEvent>, NextestError> {
    if bytes.len() > MAX_NEXTEST_OUTPUT_BYTES {
        return Err(NextestError::OutputTooLarge);
    }
    let mut events = Vec::new();
    let mut seen_started = std::collections::BTreeSet::new();
    let mut seen_completed = std::collections::BTreeSet::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.len() > MAX_LINE_BYTES {
            return Err(NextestError::LineTooLarge);
        }
        let line = trim_utf8(line)?;
        if line.is_empty() {
            continue;
        }
        let event: JsonEvent =
            serde_json::from_str(line).map_err(|_| NextestError::MalformedEvent)?;
        if event.kind.as_deref() != Some("test") {
            continue;
        }
        let event_name = event.event.as_deref().ok_or(NextestError::MalformedEvent)?;
        if matches!(event_name, "started" | "STARTED") {
            let name = event.name.ok_or(NextestError::MalformedEvent)?;
            if !seen_started.insert(name.clone()) {
                return Err(NextestError::DuplicateEvent);
            }
            events.push(NextestTestEvent::Started { name });
            continue;
        }
        let Some(status) = completion_status(&event, event_name)? else {
            continue;
        };
        let name = event.name.ok_or(NextestError::MalformedEvent)?;
        if !seen_completed.insert(name.clone()) {
            return Err(NextestError::DuplicateEvent);
        }
        events.push(NextestTestEvent::Completed { name, status });
    }
    Ok(events)
}

/// Parse nextest's machine-readable JSONL stream into bounded counters.
pub fn parse_jsonl(bytes: &[u8]) -> Result<NextestReport, NextestError> {
    let events = parse_test_events(bytes)?;
    let mut report = NextestReport::default();
    let mut started_names = std::collections::BTreeSet::new();
    let mut final_statuses = std::collections::BTreeMap::new();
    for event in events {
        match event {
            NextestTestEvent::Started { name } => {
                started_names.insert(catalog_test_id(&name).to_owned());
            }
            NextestTestEvent::Completed { name, status } => {
                // A retry is another physical event for the same catalog
                // test. The terminal attempt, rather than an earlier retry
                // failure, determines the catalog result.
                final_statuses.insert(catalog_test_id(&name).to_owned(), status);
            }
        }
    }
    report.started =
        u32::try_from(started_names.len()).map_err(|_| NextestError::CounterOverflow)?;
    report.completed =
        u32::try_from(final_statuses.len()).map_err(|_| NextestError::CounterOverflow)?;
    for status in final_statuses.values() {
        let counter = match status {
            NextestTestStatus::Pass => &mut report.passed,
            NextestTestStatus::Fail => &mut report.failed,
            NextestTestStatus::Skip => &mut report.skipped,
            NextestTestStatus::Timeout => &mut report.timed_out,
            NextestTestStatus::Leak => &mut report.leaked,
            NextestTestStatus::Cancelled => &mut report.cancelled,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(NextestError::CounterOverflow)?;
    }
    Ok(report)
}

/// Stateless facade over P-03.  It does not retain process state or output.
pub struct NextestAdapter<E> {
    executor: Arc<E>,
}

impl<E> NextestAdapter<E> {
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> NextestAdapter<E> {
    /// Admit and start one exact nextest invocation through P-03.
    pub async fn launch(
        &self,
        invocation: &InstrumentInvocation,
        command: &NextestCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, NextestError> {
        invocation
            .validate()
            .map_err(|error| NextestError::Invocation(error.to_string()))?;
        if invocation.kind != InstrumentKind::Test
            || invocation.instrument.to_string() != NEXTEST_INSTRUMENT
        {
            return Err(NextestError::WrongInstrument);
        }
        if !command.matches_request(&request) {
            return Err(NextestError::CommandMismatch);
        }
        let operation_id = request.operation_id().clone();
        let request_digest = request.invocation_digest().to_owned();
        let generation = request.generation().get();
        let receipt = self.executor.start(request, sink).await?;
        if receipt.operation_id() != &operation_id
            || receipt.request_digest() != request_digest
            || receipt.accepted_generation().get() != generation
        {
            return Err(NextestError::ReceiptMismatch);
        }
        Ok(receipt)
    }

    pub async fn inspect(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessExecutionView, NextestError> {
        Ok(self.executor.inspect(operation.clone()).await?)
    }

    pub async fn cancel(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<CancellationReceipt, NextestError> {
        Ok(self.executor.cancel(operation.clone()).await?)
    }

    pub async fn reconcile(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessEvidence, NextestError> {
        Ok(self.executor.reconcile(operation.clone()).await?)
    }
}

#[derive(Debug, Deserialize)]
struct JsonEvent {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    #[serde(flatten)]
    _extra: std::collections::BTreeMap<String, Value>,
}

fn completion_status(
    event: &JsonEvent,
    event_name: &str,
) -> Result<Option<NextestTestStatus>, NextestError> {
    let status = match event_name {
        "completed" | "COMPLETED" => event
            .status
            .as_deref()
            .ok_or(NextestError::MalformedEvent)?,
        "ok" | "OK" => "PASS",
        "failed" | "FAILED" => "FAIL",
        "ignored" | "IGNORED" => "SKIP",
        "timeout" | "TIMEOUT" => "TIMEOUT",
        "leak" | "LEAK" => "LEAK",
        "cancel" | "CANCEL" | "cancelled" | "CANCELLED" => "CANCELLED",
        _ => return Ok(None),
    };
    let normalized = match status {
        "PASS" | "pass" | "ok" => NextestTestStatus::Pass,
        "FAIL" | "fail" | "XPASS" | "xpass" | "failed" => NextestTestStatus::Fail,
        "SKIP" | "skip" | "XFAIL" | "xfail" | "ignored" => NextestTestStatus::Skip,
        "TIMEOUT" | "timeout" => NextestTestStatus::Timeout,
        "LEAK" | "leak" => NextestTestStatus::Leak,
        "CANCEL" | "cancel" | "CANCELLED" | "cancelled" => NextestTestStatus::Cancelled,
        other => return Err(NextestError::UnsupportedStatus(other.to_owned())),
    };
    Ok(Some(normalized))
}

#[derive(Debug, Error)]
pub enum NextestError {
    #[error("invocation rejected: {0}")]
    Invocation(String),
    #[error("wrong instrument or invocation kind")]
    WrongInstrument,
    #[error("process command does not match admitted nextest command")]
    CommandMismatch,
    #[error("process receipt does not bind to the admitted request")]
    ReceiptMismatch,
    #[error("nextest output exceeds the bounded capture limit")]
    OutputTooLarge,
    #[error("nextest output contains an oversized line")]
    LineTooLarge,
    #[error("nextest output is not valid JSONL")]
    MalformedEvent,
    #[error("nextest emitted a duplicate test event")]
    DuplicateEvent,
    #[error("nextest emitted an unsupported status: {0}")]
    UnsupportedStatus(String),
    #[error("nextest counter overflowed")]
    CounterOverflow,
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
}

fn checked_text(value: String, field: &'static str) -> Result<String, NextestError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NextestError::Invocation(format!(
            "{field} must be non-blank and free of control characters"
        )));
    }
    Ok(value)
}

fn trim_utf8(bytes: &[u8]) -> Result<&str, NextestError> {
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| NextestError::MalformedEvent)
}
