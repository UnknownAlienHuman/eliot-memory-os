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
/// Content type for `cargo nextest list --message-format json` inventory
/// documents. Inventory is never fed to the run-event parser.
pub const NEXTEST_LIST_CONTENT_TYPE: &str = "application/x-nextest-list-json";
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
            let filter = checked_text(filter.clone(), "filter")?;
            // Trailing positionals are test selections, never flags: a
            // filter that parses as a flag could redirect the actual build
            // output away from the admitted target root (issue #1806).
            if filter.starts_with('-') {
                return Err(NextestError::Invocation(
                    "filter must be a test selection, not a command flag".to_owned(),
                ));
            }
            arguments.push(filter);
        }
        Ok(Self {
            executable: "cargo-nextest".to_owned(),
            arguments,
            target,
            profile,
        })
    }

    /// Builds the canonical discovery arguments for the admitted
    /// `cargo-nextest list` executable (`cargo nextest list
    /// --message-format json`, I18.6 step 3).
    ///
    /// Discovery scope is bound by validated slots only: an optional Cargo
    /// package (`--package`) and an optional binary target (`--bin`). No
    /// other flag, filter, or caller text is rendered.
    pub fn list(
        target: impl Into<String>,
        package: Option<&str>,
        binary: Option<&str>,
    ) -> Result<Self, NextestError> {
        let target = checked_text(target.into(), "target")?;
        let mut arguments = vec![
            "list".to_owned(),
            "--message-format".to_owned(),
            "json".to_owned(),
        ];
        if let Some(package) = package {
            arguments.push("--package".to_owned());
            arguments.push(checked_scope_name(package.to_owned(), "package")?);
        }
        if let Some(binary) = binary {
            arguments.push("--bin".to_owned());
            arguments.push(checked_scope_name(binary.to_owned(), "binary")?);
        }
        Ok(Self {
            executable: "cargo-nextest".to_owned(),
            arguments,
            target,
            profile: String::new(),
        })
    }

    /// Builds the canonical scoped run arguments for the admitted
    /// `cargo-nextest run` executable.
    ///
    /// Scope renders from the validated [`NextestScope`] only: an optional
    /// package, an optional binary, a retry count, and exact test
    /// filters after `--` with `--exact`, so every filter matches the
    /// discovery identity exactly instead of by substring.
    pub fn run_scoped(
        target: impl Into<String>,
        profile: impl Into<String>,
        scope: &NextestScope,
    ) -> Result<Self, NextestError> {
        let target = checked_text(target.into(), "target")?;
        let profile = checked_text(profile.into(), "profile")?;
        scope.validate()?;
        let mut arguments = vec![
            "run".to_owned(),
            "--message-format".to_owned(),
            "libtest-json-plus".to_owned(),
            "--message-format-version".to_owned(),
            NEXTEST_LIBTEST_JSON_FORMAT_VERSION.to_owned(),
        ];
        if let Some(package) = &scope.package {
            arguments.push("--package".to_owned());
            arguments.push(package.clone());
        }
        if let Some(binary) = &scope.binary {
            arguments.push("--bin".to_owned());
            arguments.push(binary.clone());
        }
        if let Some(retries) = scope.retries {
            arguments.push("--retries".to_owned());
            arguments.push(retries.to_string());
        }
        if !scope.filters.is_empty() {
            arguments.push("--exact".to_owned());
            arguments.push("--".to_owned());
            arguments.extend(scope.filters.iter().cloned());
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

/// Validated selection scope for one governed nextest run.
///
/// Every value originates from the frozen discovery/selection material:
/// package and binary name admitted Cargo target slots, filters name exact
/// discovered test identities, and retries carry the declared per-test
/// policy. Nothing here is caller free text.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NextestScope {
    /// Optional Cargo package slot (`--package`).
    pub package: Option<String>,
    /// Optional binary target slot (`--bin`).
    pub binary: Option<String>,
    /// Exact discovered test identities rendered after `--` with `--exact`.
    pub filters: Vec<String>,
    /// Declared per-test retry count (`--retries`), when set.
    pub retries: Option<u32>,
}

impl NextestScope {
    /// Validates every slot without rendering anything.
    pub fn validate(&self) -> Result<(), NextestError> {
        if let Some(package) = &self.package {
            checked_scope_name(package.clone(), "package")?;
        }
        if let Some(binary) = &self.binary {
            checked_scope_name(binary.clone(), "binary")?;
        }
        for filter in &self.filters {
            checked_filter(filter)?;
        }
        Ok(())
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

/// One normalized discovered test identity from `cargo nextest list
/// --message-format json` (I18.6 step 3).
///
/// The identity is the stable `(package, binary, test)` triple parsed from
/// the inventory document's `rust-suites` map. It carries no execution
/// result and no policy; selection and execution join against it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiscoveredTest {
    /// Cargo package owning the test binary.
    pub package: String,
    /// Test binary name within the package.
    pub binary: String,
    /// Test name as listed by nextest.
    pub test: String,
    /// Whether nextest listed the test as ignored.
    pub ignored: bool,
}

impl DiscoveredTest {
    /// Canonical `package/binary/test` identity string.
    pub fn identity(&self) -> String {
        format!("{}/{}/{}", self.package, self.binary, self.test)
    }
}

/// Normalized inventory parsed from one discovery document.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveredInventory {
    /// Discovered tests in deterministic sorted identity order.
    pub tests: Vec<DiscoveredTest>,
    /// Test count declared by the inventory document.
    pub declared_count: u64,
}

impl DiscoveredInventory {
    /// Number of normalized discovered tests.
    pub fn len(&self) -> usize {
        self.tests.len()
    }

    /// Whether the inventory holds no discovered test.
    pub fn is_empty(&self) -> bool {
        self.tests.is_empty()
    }
}

/// Parse one `cargo nextest list --message-format json` inventory document.
///
/// The inventory is a single JSON document (never JSONL): `rust-suites`
/// maps binary identities to their package/binary/testcases, and
/// `test-count` declares the expected total. This parser is disjoint from
/// [`parse_test_events`]: inventory bytes must never reach the run-event
/// parser, and run-event bytes never parse here. Duplicate identities,
/// unlisted suites, unsupported testcase records, a `test-count` mismatch,
/// or an over-bound document fail closed; the caller retains the exact raw
/// bytes separately under [`NEXTEST_LIST_CONTENT_TYPE`]. The existing
/// [`MAX_NEXTEST_OUTPUT_BYTES`] capture bound applies to discovery too.
pub fn parse_list_json(bytes: &[u8]) -> Result<DiscoveredInventory, NextestError> {
    if bytes.len() > MAX_NEXTEST_OUTPUT_BYTES {
        return Err(NextestError::OutputTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NextestError::MalformedInventory)?;
    if text.trim().is_empty() {
        return Err(NextestError::MalformedInventory);
    }
    let document: Value =
        serde_json::from_str(text).map_err(|_| NextestError::MalformedInventory)?;
    let declared_count = document
        .get("test-count")
        .and_then(Value::as_u64)
        .ok_or(NextestError::MalformedInventory)?;
    let suites = document
        .get("rust-suites")
        .and_then(Value::as_object)
        .ok_or(NextestError::MalformedInventory)?;
    let mut tests = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for suite in suites.values() {
        let package = suite
            .get("package-name")
            .and_then(Value::as_str)
            .ok_or(NextestError::UnsupportedInventoryRecord)?;
        let binary = suite
            .get("binary-name")
            .and_then(Value::as_str)
            .ok_or(NextestError::UnsupportedInventoryRecord)?;
        if suite.get("status").and_then(Value::as_str) != Some("listed") {
            return Err(NextestError::IncompleteDiscovery);
        }
        let testcases = suite
            .get("testcases")
            .and_then(Value::as_object)
            .ok_or(NextestError::UnsupportedInventoryRecord)?;
        for (name, case) in testcases {
            if case.get("kind").and_then(Value::as_str) != Some("test") {
                return Err(NextestError::UnsupportedInventoryRecord);
            }
            let ignored = case
                .get("ignored")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let discovered = DiscoveredTest {
                package: package.to_owned(),
                binary: binary.to_owned(),
                test: name.clone(),
                ignored,
            };
            if !seen.insert(discovered.identity()) {
                return Err(NextestError::DuplicateInventoryRecord);
            }
            tests.push(discovered);
        }
    }
    tests.sort();
    if declared_count != tests.len() as u64 {
        return Err(NextestError::InventoryCountMismatch {
            declared: declared_count,
            listed: tests.len() as u64,
        });
    }
    Ok(DiscoveredInventory {
        tests,
        declared_count,
    })
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
    #[error("nextest inventory document is not a single valid list document")]
    MalformedInventory,
    #[error("nextest inventory carries an unsupported suite or testcase record")]
    UnsupportedInventoryRecord,
    #[error("nextest inventory lists a duplicate test identity")]
    DuplicateInventoryRecord,
    #[error("nextest inventory declares {declared} tests but lists {listed}")]
    InventoryCountMismatch {
        /// Declared `test-count`.
        declared: u64,
        /// Actually listed testcases.
        listed: u64,
    },
    #[error("nextest inventory holds an unlisted suite; discovery is incomplete")]
    IncompleteDiscovery,
    #[error("nextest scope slot is not an admitted value: {0}")]
    InvalidSlot(String),
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

/// Validates one Cargo package/binary slot name for argv rendering.
///
/// Admitted names use Cargo's common ASCII package/target characters, have no
/// leading `-`, and contain no controls. No shell string is constructed.
fn checked_scope_name(value: String, field: &'static str) -> Result<String, NextestError> {
    if value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
    {
        return Err(NextestError::InvalidSlot(format!(
            "{field} is not an admitted Cargo target name"
        )));
    }
    checked_text(value, field).map_err(|_| NextestError::InvalidSlot(format!("{field} is blank")))
}

/// Validates one exact test filter for `--exact --` rendering.
///
/// Filters are exact discovered test identities passed as individual argv
/// values after `--`; controls are rejected and no shell command is built.
fn checked_filter(value: &str) -> Result<(), NextestError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NextestError::InvalidSlot(
            "filter is not an exact discovered test identity".to_owned(),
        ));
    }
    Ok(())
}

fn trim_utf8(bytes: &[u8]) -> Result<&str, NextestError> {
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| NextestError::MalformedEvent)
}
