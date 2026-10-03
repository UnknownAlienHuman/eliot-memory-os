#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused diagnostics tests for F-LOG-HOST-3 item 978.
//!
//! Every case here is an EXECUTION of instrumented production code through an
//! existing public seam of the `eliot_host` library target, never a
//! hand-constructed expected log record. The facade
//! (`observe_entrypoint_with_detail`, `observe_terminal_error`) is never called
//! directly from this target: a record is only ever READ back out of a scoped
//! `tracing` subscriber after real production code ran, so no case can compare
//! the facade against itself.
//!
//! Reachable instrumented production seams (all `pub` in the library target):
//!
//! * `eliot_host::HostLaunchOptions::{parse, parse_system_service,
//!   validate_service_main_argv}` — `src/host_launch_options.rs`;
//! * `eliot_host::classify_host_scm_inspection` — `src/scm_launch.rs`
//!   (`Absent` / `Mismatched` / `Unknown` inspection arms);
//! * `eliot_host::validate_host_scm_bootstrap` — `src/scm_launch.rs`, driven to
//!   its deterministic pre-SCM refusal (no live SCM call, no FFI, no launch).
//!
//! The remaining boundaries of the eight instrumented files live in private
//! modules behind `pub(super)` items, so their runtime proof belongs to an
//! inline `#[cfg(test)]` case inside the owning source file, not here. Where
//! that is the case the test still executes every reachable part of the
//! boundary, names the exact inline owner, and asserts nothing weaker than
//! before; nothing is faked.
//!
//! Diagnostics are evidence only: they never change control flow, state,
//! errors, receipts, order, status, or cleanup, and stdout framing stays
//! exactly one-JSON-per-line. The Windows Event Log seam stays typed-
//! Unavailable here (#984 still open) and is asserted as such, never faked.

use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, HostDiagnosticsError,
    MAX_DIAGNOSTIC_DETAIL_BYTES, MAX_DIAGNOSTIC_FIELD_BYTES, sink_status,
};
use eliot_host::windows_event_log::{
    AdmittedEvent, EventLogRecord, WindowsEventLogError, event_log_sink_status, report_event,
};
use eliot_host::{
    HostError, HostLaunchOptions, HostScmRegistrationCause, classify_host_scm_inspection,
    validate_host_scm_bootstrap,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ServiceAccount,
    ServiceRegistrationRequest, ServiceRegistrationRuntimeInspection, ServiceStartMode,
};
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// The eight files this issue instruments, with the per-file observation
/// helper each one must keep defining.
const OBSERVER_HELPERS: [(&str, &str); 8] = [
    ("src/host_job_launch.rs", "host_launch_observe"),
    ("src/host_launch_options.rs", "host_launch_options_observe"),
    ("src/launch_artifact_lease.rs", "launch_artifact_observe"),
    (
        "src/launch_descriptor_validation.rs",
        "launch_descriptor_observe",
    ),
    ("src/scm_launch.rs", "scm_launch_observe"),
    (
        "src/store_kernel_launch_sequence.rs",
        "store_kernel_observe",
    ),
    (
        "src/kernel_activation_driver.rs",
        "kernel_activation_observe",
    ),
    (
        "src/kernel_front_door_client.rs",
        "kernel_front_door_observe",
    ),
];

/// The single readiness owner path. No other boundary may carry that claim.
const READINESS_OWNER_FILE: &str = "src/kernel_activation_driver.rs";
const READINESS_OWNER_SYMBOL: &str = "fn active(";

/// Records that one owner-held value was released exactly once.
type DropOrder = Arc<Mutex<Vec<&'static str>>>;

// ---------------------------------------------------------------- recording --

/// One facade record exactly as the instrumented production path emitted it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedRecord {
    target: String,
    fields: Vec<(String, String)>,
}

impl CapturedRecord {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn event(&self) -> &str {
        self.field("event").unwrap_or_default()
    }

    fn detail(&self) -> &str {
        self.field("detail").unwrap_or_default()
    }

    fn code(&self) -> &str {
        self.field("code").unwrap_or_default()
    }
}

/// Field visitor: keeps the emitted field names and values verbatim so a case
/// asserts on what production actually wrote, never on a locally built string.
#[derive(Default)]
struct EmittedFields {
    entries: Vec<(String, String)>,
}

impl Visit for EmittedFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.entries
            .push((field.name().to_owned(), value.to_owned()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.entries
            .push((field.name().to_owned(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.entries
            .push((field.name().to_owned(), value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.entries
            .push((field.name().to_owned(), format!("{value:?}")));
    }
}

/// Records every event that reaches the subscriber, before sink formatting.
#[derive(Clone)]
struct RecordingLayer {
    records: Arc<Mutex<Vec<CapturedRecord>>>,
}

impl<S> Layer<S> for RecordingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = EmittedFields::default();
        event.record(&mut fields);
        self.records.lock().unwrap().push(CapturedRecord {
            target: event.metadata().target().to_owned(),
            fields: fields.entries,
        });
    }
}

/// A sink-side filter that drops every record while the production path keeps
/// running, so delivery can be proven to change nothing downstream.
struct DroppingFilter;

impl<S> Layer<S> for DroppingFilter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _metadata: &Metadata<'_>, _context: Context<'_, S>) -> bool {
        false
    }
}

/// Sink that fails every write after counting the attempt.
#[derive(Clone)]
struct FaultSink {
    state: Arc<Mutex<FaultState>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FaultState {
    attempts: usize,
    failures: usize,
}

impl FaultSink {
    fn failing() -> Self {
        Self {
            state: Arc::new(Mutex::new(FaultState::default())),
        }
    }

    fn observed(&self) -> FaultState {
        self.state.lock().unwrap().clone()
    }
}

impl Write for FaultSink {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        state.failures += 1;
        Err(std::io::Error::other(format!(
            "injected diagnostic sink failure (978/11) over {} bytes",
            buffer.len()
        )))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `emit` under a recording subscriber and returns what production emitted.
fn record_emit(emit: impl FnOnce()) -> Vec<CapturedRecord> {
    let records = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(RecordingLayer {
        records: Arc::clone(&records),
    });
    tracing::subscriber::with_default(subscriber, emit);
    records.lock().unwrap().clone()
}

/// The same production execution behind a sink that drops every record.
fn record_emit_filtered(emit: impl FnOnce()) -> Vec<CapturedRecord> {
    let records = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry()
        .with(DroppingFilter)
        .with(RecordingLayer {
            records: Arc::clone(&records),
        });
    tracing::subscriber::with_default(subscriber, emit);
    records.lock().unwrap().clone()
}

/// The same production execution behind a sink whose every write fails.
fn record_emit_failing(emit: impl FnOnce()) -> (Vec<CapturedRecord>, FaultState) {
    let records = Arc::new(Mutex::new(Vec::new()));
    let sink = FaultSink::failing();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::registry()
        .with(RecordingLayer {
            records: Arc::clone(&records),
        })
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone()),
        );
    tracing::subscriber::with_default(subscriber, emit);
    let captured = records.lock().unwrap().clone();
    let faults = sink.observed();
    (captured, faults)
}

// -------------------------------------------------------------- assertions --

/// Records that carry a bounded detail, i.e. every phase observation and not a
/// terminal record (a terminal carries only its code).
fn detail_records(records: &[CapturedRecord]) -> Vec<CapturedRecord> {
    records
        .iter()
        .filter(|record| !record.detail().is_empty())
        .cloned()
        .collect()
}

/// Maps each captured record onto the frozen phase token its structured detail
/// carries. Every detail must carry exactly one token, so a phase can never be
/// smuggled in through an unrelated field value.
fn phase_tokens(records: &[CapturedRecord], tokens: &[String]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            let detail = record.detail();
            assert!(
                !detail.is_empty(),
                "every phase record must carry its bounded detail: {record:?}"
            );
            let mut matched = tokens
                .iter()
                .filter(|token| detail.contains(token.as_str()));
            let first = matched.next().unwrap_or_else(|| {
                panic!("emitted detail must carry a frozen phase token: {detail}")
            });
            assert!(
                matched.next().is_none(),
                "emitted detail must carry exactly one frozen phase token: {detail}"
            );
            first.clone()
        })
        .collect()
}

/// One frozen correlation slot value out of a rendered structured detail.
fn correlation_slot(detail: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = detail.find(&needle)? + needle.len();
    let rest = &detail[start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// The eight correlation slots must be rendered in the frozen order.
fn assert_correlation_key_order(detail: &str, keys: &[String]) {
    let mut previous = 0_usize;
    for key in keys {
        let needle = format!("{key}=");
        let index = detail
            .find(&needle)
            .unwrap_or_else(|| panic!("structured detail must carry {needle}: {detail}"));
        assert!(
            index >= previous,
            "correlation slots must stay in the frozen order, got: {detail}"
        );
        previous = index + needle.len();
    }
}

fn host_error_text(error: &HostError) -> String {
    error.to_string()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn terminal_records(records: &[CapturedRecord]) -> Vec<&CapturedRecord> {
    records
        .iter()
        .filter(|record| record.event() == "host.terminal_error")
        .collect()
}

// ------------------------------------------------------------------ fixture --

fn launch_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_launch_diagnostics.json");
    let bytes = std::fs::read(&path).expect("launch fixture must be readable");
    serde_json::from_slice(&bytes).expect("launch fixture must be valid JSON")
}

fn manifest_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).expect("tracked source must be readable")
}

fn string_list(values: &Value, what: &str) -> Vec<String> {
    values
        .as_array()
        .unwrap_or_else(|| panic!("{what} must be a frozen string list"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{what} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn fixture_list(fixture: &Value, key: &str) -> Vec<String> {
    string_list(&fixture[key], &format!("fixture {key}"))
}

fn object_list(map: &Map<String, Value>, key: &str) -> Vec<String> {
    string_list(&map[key], key)
}

fn eight_sources() -> Vec<(String, String)> {
    OBSERVER_HELPERS
        .iter()
        .map(|(path, _)| ((*path).to_owned(), manifest_source(path)))
        .collect()
}

/// Line span of the one readiness owner, `DurableKernelActivationDriver::active`.
fn readiness_owner_span(source: &str) -> (usize, usize) {
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.contains(READINESS_OWNER_SYMBOL))
        .unwrap_or_else(|| panic!("the activation driver must define {READINESS_OWNER_SYMBOL}"));
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            trimmed.starts_with("fn ") || trimmed.starts_with("pub(super) fn ")
        })
        .map_or(lines.len(), |(index, _)| index);
    (start, end)
}

/// One source line with its trailing line or doc comment removed. A readiness
/// claim is a label production carries, never prose that denies one, so the
/// guard reads code only and never a comment.
fn code_of(line: &str) -> &str {
    line.split("//").next().unwrap_or(line)
}

/// Every double-quoted literal of one code line.
fn quoted_literals(code: &str) -> Vec<&str> {
    code.split('"').skip(1).step_by(2).collect()
}

/// Whether a literal is a Host diagnostic phase token that claims readiness.
/// The `host.` prefix keeps prose ("already", "not ready", a readiness
/// evidence field) out of the rule: only an emitted label counts.
fn is_readiness_label(literal: &str) -> bool {
    literal.starts_with("host.") && (literal.contains("readiness") || literal.contains("-ready"))
}

/// Strict structural guard: a readiness label may exist only inside the
/// activation owner's `active` body, in exactly one of the eight files.
fn assert_readiness_owned_only_by_activation_active(sources: &[(String, String)]) {
    let mut owners: Vec<String> = Vec::new();
    for (path, source) in sources {
        let span = if path == READINESS_OWNER_FILE {
            Some(readiness_owner_span(source))
        } else {
            None
        };
        for (index, line) in source.lines().enumerate() {
            for literal in quoted_literals(code_of(line)) {
                if !is_readiness_label(literal) {
                    continue;
                }
                let (start, end) = span.unwrap_or_else(|| {
                    panic!("{path} carries the readiness label {literal:?} outside the owner path")
                });
                assert!(
                    index > start && index < end,
                    "{path} carries the readiness label {literal:?} outside {READINESS_OWNER_SYMBOL}"
                );
                owners.push(path.clone());
            }
        }
    }
    assert!(
        !owners.is_empty(),
        "the activation owner must keep observing its readiness phases"
    );
    assert!(
        owners.iter().all(|path| path == READINESS_OWNER_FILE),
        "readiness must have exactly one owner file"
    );
}

// --------------------------------------------------------- production seams --

fn synthetic_descriptor_path() -> std::path::PathBuf {
    std::env::temp_dir().join("eliot-launch-auth.json")
}

fn synthetic_state_root() -> std::path::PathBuf {
    std::env::temp_dir().join("eliot-host-state")
}

/// Synthetic, never-secret authority values. No real path, credential or nonce
/// value is ever produced by this target.
fn synthetic_digest() -> OsString {
    OsString::from("a".repeat(64))
}

fn synthetic_nonce() -> OsString {
    OsString::from("b".repeat(64))
}

fn valid_launch_args() -> Vec<OsString> {
    vec![
        OsString::from("--config-descriptor"),
        synthetic_descriptor_path().into_os_string(),
        OsString::from("--config-descriptor-sha256"),
        synthetic_digest(),
        OsString::from("--installation-id"),
        OsString::from("installation-7"),
        OsString::from("--tx-plan-generation"),
        OsString::from("7"),
        OsString::from("--host-state-root"),
        synthetic_state_root().into_os_string(),
    ]
}

fn valid_system_args() -> Vec<OsString> {
    let mut args = valid_launch_args();
    args.push(OsString::from("--registration-nonce"));
    args.push(synthetic_nonce());
    args
}

fn args_with(args: &[OsString], index: usize, value: &str) -> Vec<OsString> {
    let mut copy = args.to_vec();
    copy[index] = OsString::from(value);
    copy
}

fn args_reordered(args: &[OsString]) -> Vec<OsString> {
    let mut copy = args.to_vec();
    copy.swap(0, 2);
    copy.swap(1, 3);
    copy
}

fn args_without(args: &[OsString], index: usize) -> Vec<OsString> {
    let mut copy = args.to_vec();
    copy.remove(index);
    copy
}

fn registration_request() -> ServiceRegistrationRequest {
    let image = std::env::current_exe().expect("the test image must be resolvable");
    ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .expect("the canonical registration request must build")
}

/// Real execution of `HostLaunchOptions::parse`.
fn execute_launch_parse(
    args: &[OsString],
) -> (Result<HostLaunchOptions, String>, Vec<CapturedRecord>) {
    let outcome = std::cell::RefCell::new(None);
    let records = record_emit(|| {
        let parsed =
            HostLaunchOptions::parse(args.to_vec()).map_err(|error| host_error_text(&error));
        *outcome.borrow_mut() = Some(parsed);
    });
    let captured = outcome.borrow_mut().take().expect("captured");
    (captured, records)
}

/// Real execution of `HostLaunchOptions::parse_system_service`.
fn execute_system_service_parse(
    args: &[OsString],
) -> (Result<HostLaunchOptions, String>, Vec<CapturedRecord>) {
    let outcome = std::cell::RefCell::new(None);
    let records = record_emit(|| {
        let parsed = HostLaunchOptions::parse_system_service(args.to_vec())
            .map_err(|error| host_error_text(&error));
        *outcome.borrow_mut() = Some(parsed);
    });
    let captured = outcome.borrow_mut().take().expect("captured");
    (captured, records)
}

/// Real execution of `HostLaunchOptions::validate_service_main_argv`.
fn execute_service_main_argv(args: &[OsString]) -> (Result<(), String>, Vec<CapturedRecord>) {
    let outcome = std::cell::RefCell::new(None);
    let records = record_emit(|| {
        let validated = HostLaunchOptions::validate_service_main_argv(args.to_vec())
            .map_err(|error| host_error_text(&error));
        *outcome.borrow_mut() = Some(validated);
    });
    let captured = outcome.borrow_mut().take().expect("captured");
    (captured, records)
}

/// Real execution of `classify_host_scm_inspection`.
fn execute_scm_classification(
    request: &ServiceRegistrationRequest,
    inspection: &ServiceRegistrationRuntimeInspection,
) -> (Option<HostScmRegistrationCause>, Vec<CapturedRecord>) {
    let outcome = std::cell::RefCell::new(None);
    let records = record_emit(|| {
        let classified = classify_host_scm_inspection(request, inspection);
        *outcome.borrow_mut() = Some(classified);
    });
    let captured = outcome.borrow_mut().take().expect("captured");
    (captured, records)
}

/// Real execution of `validate_host_scm_bootstrap`, driven with launch options
/// that carry no registration nonce so it refuses before any SCM readback: no
/// live SCM query, no process launch, no FFI.
fn execute_scm_bootstrap(options: &HostLaunchOptions) -> (Result<(), String>, Vec<CapturedRecord>) {
    let outcome = std::cell::RefCell::new(None);
    let records = record_emit(|| {
        let validated = validate_host_scm_bootstrap(options);
        *outcome.borrow_mut() = Some(
            validated
                .map(|_| ())
                .map_err(|error| host_error_text(&error)),
        );
    });
    let captured = outcome.borrow_mut().take().expect("captured");
    (captured, records)
}

/// The deterministic inspection schedule this target injects: each entry is a
/// real platform-owned inspection value, executed by the real classifier.
fn injected_inspection_schedule() -> Vec<ServiceRegistrationRuntimeInspection> {
    vec![
        ServiceRegistrationRuntimeInspection::Absent,
        ServiceRegistrationRuntimeInspection::Mismatched,
        ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 4242),
        ServiceRegistrationRuntimeInspection::unknown_with_status(1066, "open-service", 3, 4242),
    ]
}

/// One pass over the injected schedule: the records the classifier emitted plus
/// the typed causes it actually returned for each entry.
fn run_injected_schedule() -> (Vec<CapturedRecord>, Vec<Option<String>>) {
    let request = registration_request();
    let outcome = std::cell::RefCell::new(Vec::new());
    let records = record_emit(|| {
        for inspection in injected_inspection_schedule() {
            let classified = classify_host_scm_inspection(&request, &inspection);
            outcome
                .borrow_mut()
                .push(classified.map(|cause| cause.detail()));
        }
    });
    let causes = outcome.into_inner();
    (records, causes)
}

/// Owner-retained launch identity exactly as the launch contour hands it back.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedLaunch {
    config_descriptor: String,
    digest: String,
    installation: String,
    generation: u64,
    state_root: String,
    nonce_present: bool,
}

impl RetainedLaunch {
    fn of(options: &HostLaunchOptions) -> Self {
        Self {
            config_descriptor: options.config_descriptor_path().display().to_string(),
            digest: options.config_descriptor_digest().as_str().to_owned(),
            installation: options.installation().as_str().to_owned(),
            generation: options.transaction_plan_generation(),
            state_root: options.host_state_root().display().to_string(),
            nonce_present: options.registration_nonce().is_some(),
        }
    }

    fn empty() -> Self {
        Self {
            config_descriptor: String::new(),
            digest: String::new(),
            installation: String::new(),
            generation: 0,
            state_root: String::new(),
            nonce_present: false,
        }
    }
}

struct DropTracked<T> {
    value: Option<T>,
    drops: DropOrder,
    label: &'static str,
}

impl<T> Drop for DropTracked<T> {
    fn drop(&mut self) {
        if self.value.take().is_some() {
            self.drops.lock().unwrap().push(self.label);
        }
    }
}

fn tracked_launch(
    options: HostLaunchOptions,
    drops: &DropOrder,
    label: &'static str,
) -> RetainedLaunch {
    let retained = RetainedLaunch::of(&options);
    let tracked = DropTracked {
        value: Some(options),
        drops: Arc::clone(drops),
        label,
    };
    drop(tracked);
    retained
}

fn tracked_parse(
    parsed: Result<HostLaunchOptions, String>,
    drops: &DropOrder,
    label: &'static str,
) -> Result<RetainedLaunch, String> {
    match parsed {
        Ok(options) => Ok(tracked_launch(options, drops, label)),
        Err(error) => Err(error),
    }
}

/// Everything one pass of the frozen production script produced.
#[derive(Debug, Eq, PartialEq)]
struct ScriptOutcome {
    parse: Result<RetainedLaunch, String>,
    parse_rejected: Result<RetainedLaunch, String>,
    system_service: Result<RetainedLaunch, String>,
    absent_cause: Option<String>,
    mismatched_cause: Option<String>,
    unknown_cause: Option<String>,
    bootstrap: Result<String, String>,
    drop_order: Vec<&'static str>,
}

/// The one frozen production script every sink configuration executes in case
/// 978/11. Every call below is instrumented production code reached through a
/// public seam, and every emission lands in the ambient subscriber.
fn run_launch_script() -> ScriptOutcome {
    let drops: DropOrder = Arc::new(Mutex::new(Vec::new()));
    let request = registration_request();
    let mut outcome = ScriptOutcome {
        parse: Ok(RetainedLaunch::empty()),
        parse_rejected: Err(String::new()),
        system_service: Ok(RetainedLaunch::empty()),
        absent_cause: None,
        mismatched_cause: None,
        unknown_cause: None,
        bootstrap: Err(String::new()),
        drop_order: Vec::new(),
    };

    let parse =
        HostLaunchOptions::parse(valid_launch_args()).map_err(|error| host_error_text(&error));
    outcome.parse = tracked_parse(parse, &drops, "parse");

    let relative = args_with(&valid_launch_args(), 1, "relative-auth.json");
    let rejected = HostLaunchOptions::parse(relative).map_err(|error| host_error_text(&error));
    outcome.parse_rejected = tracked_parse(rejected, &drops, "parse-rejected");

    let service = HostLaunchOptions::parse_system_service(valid_system_args())
        .map_err(|error| host_error_text(&error));
    outcome.system_service = tracked_parse(service, &drops, "system-service");

    outcome.absent_cause =
        classify_host_scm_inspection(&request, &ServiceRegistrationRuntimeInspection::Absent)
            .map(|cause| cause.detail());
    outcome.mismatched_cause =
        classify_host_scm_inspection(&request, &ServiceRegistrationRuntimeInspection::Mismatched)
            .map(|cause| cause.detail());
    outcome.unknown_cause = classify_host_scm_inspection(
        &request,
        &ServiceRegistrationRuntimeInspection::unknown_with_status(1066, "open-service", 3, 4242),
    )
    .map(|cause| cause.detail());

    let options = HostLaunchOptions::parse(valid_launch_args())
        .map_err(|error| host_error_text(&error))
        .expect("the admitted options must build");
    outcome.bootstrap = validate_host_scm_bootstrap(&options)
        .map(|validated| validated.registration().service_name().to_owned())
        .map_err(|error| host_error_text(&error));

    let drop_order = drops.lock().unwrap().clone();
    outcome.drop_order = drop_order;
    outcome
}

/// Frozen typed outcome of the launch-admission contour, shared by the cases
/// that need the admitted identity as an owner-held value.
fn admitted_launch_options() -> HostLaunchOptions {
    HostLaunchOptions::parse(valid_launch_args()).expect("valid argv must admit")
}

// ------------------------------------------------------------------- cases --

// WORK_UNIT_CASE: 978/1
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the complete eight-file denominator mapping"
)]
fn launch_01_eight_file_denominator() {
    assert_eq!(
        OBSERVER_HELPERS.len(),
        8,
        "the declared denominator is eight instrumented files"
    );
    for (path, helper) in OBSERVER_HELPERS {
        let source = manifest_source(path);
        assert!(
            source.contains("observe_entrypoint_with_detail"),
            "{path} must observe through the #889 facade"
        );
        assert!(source.contains(helper), "{path} must define {helper}");
        assert!(
            source.contains("LaunchPhaseCorrelation"),
            "{path} must bind every phase to a bounded correlation, never a static-only label"
        );
        assert!(
            source.contains("F-LOG-HOST-3 (#978)"),
            "{path} must mark the #978 instrumentation"
        );
        assert!(
            source.contains("event_log_sink_status"),
            "{path} must consume the live Event Log seam answer"
        );
    }

    let fixture = launch_fixture();
    let cases = fixture["cases"]
        .as_object()
        .expect("the fixture must pin the case map");
    assert_eq!(cases.len(), 14, "the declared denominator is 14 cases");
    for index in 1..=14 {
        assert!(
            cases.contains_key(&index.to_string()),
            "case 978/{index} must be pinned in the fixture"
        );
    }

    let sibling = [
        "src/scm_launch.rs",
        "src/store_kernel_launch_sequence.rs",
        "src/kernel_activation_driver.rs",
        "src/kernel_front_door_client.rs",
    ]
    .map(manifest_source)
    .join("");
    for boundary in fixture_list(&fixture, "frozen_sibling_boundaries") {
        assert!(
            sibling.contains(&boundary),
            "the frozen sibling boundary {boundary:?} must still exist in its owning file"
        );
    }
    // Every frozen phase token must still exist in the file this case
    // attributes it to: the mapping is bound to real source, not to a list.
    let bindings: [(&str, &str); 4] = [
        ("launch_options_details", "src/host_launch_options.rs"),
        ("launch_details", "src/host_job_launch.rs"),
        ("launch_artifact_details", "src/launch_artifact_lease.rs"),
        (
            "launch_descriptor_details",
            "src/launch_descriptor_validation.rs",
        ),
    ];
    for (key, path) in bindings {
        let source = manifest_source(path);
        for token in fixture_list(&fixture, key) {
            assert!(
                source.contains(&token),
                "the frozen {key} token {token:?} must exist in {path}"
            );
        }
    }
    for token in fixture_list(&fixture, "sibling_phase_details") {
        assert!(
            sibling.contains(&token),
            "the frozen sibling token {token:?} must exist in its owning file"
        );
    }
    for token in fixture_list(&fixture, "retired_phase_tokens") {
        assert!(
            !sibling.contains(&token),
            "the retired token {token:?} must not come back"
        );
    }

    assert_eq!(
        EntrypointStage::Startup.as_str(),
        fixture["stages"]["startup"]
            .as_str()
            .expect("the fixture pins startup")
    );
    assert_eq!(
        EntrypointStage::LaunchConfig.as_str(),
        fixture["stages"]["launch_config"]
            .as_str()
            .expect("the fixture pins launch_config")
    );

    // The reachable seam really executes and emits through the one facade.
    let (parsed, records) = execute_launch_parse(&valid_launch_args());
    assert!(parsed.is_ok(), "valid argv must admit through the seam");
    assert!(!records.is_empty(), "the executed seam must emit records");
    for record in &records {
        assert_eq!(
            record.target, HOST_DIAGNOSTICS_TARGET,
            "every observation goes through the one facade target"
        );
    }
    let event = fixture["entrypoint_event"]
        .as_str()
        .expect("the fixture pins event");
    assert!(
        records.iter().all(|record| record.event() == event),
        "the executed seam must emit the frozen entrypoint event"
    );
    assert_eq!(
        phase_tokens(
            &detail_records(&records),
            &fixture_list(&fixture, "launch_options_details")
        ),
        vec![
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse admitted".to_owned(),
        ]
    );
}

// WORK_UNIT_CASE: 978/2
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one frozen typed-rejection table per case"
)]
fn launch_02_options_descriptor_typed_rejection() {
    let fixture = launch_fixture();
    let tokens = fixture_list(&fixture, "launch_options_details");
    let valid = valid_launch_args();

    let cases: Vec<(&str, Vec<OsString>, &str)> = vec![
        (
            "missing",
            args_without(&valid, 8),
            "expected exactly five authority pairs",
        ),
        (
            "reordered",
            args_reordered(&valid),
            "authority flags are missing, reordered, or substituted",
        ),
        (
            "unknown",
            args_with(&valid, 8, "--unknown"),
            "authority flags are missing, reordered, or substituted",
        ),
        (
            "relative",
            args_with(&valid, 1, "relative-auth.json"),
            "config descriptor path must be absolute and valid",
        ),
        (
            "bad-digest",
            args_with(&valid, 3, &"ZZ".repeat(32)),
            "config descriptor digest must be lowercase SHA-256",
        ),
        (
            "zero-gen",
            args_with(&valid, 7, "0"),
            "transaction plan generation must be non-zero",
        ),
    ];
    for (label, args, reason) in &cases {
        let (parsed, records) = execute_launch_parse(args);
        assert_eq!(
            parsed,
            Err(format!("invalid Host launch argv: {reason}")),
            "{label} must keep its exact typed reason"
        );
        assert_eq!(
            phase_tokens(&detail_records(&records), &tokens),
            vec![
                "host.launch-options parse requested".to_owned(),
                "host.launch-options parse typed rejection".to_owned(),
            ],
            "{label}: a rejection is a distinct phase, never an admission"
        );
        assert!(
            terminal_records(&records).is_empty(),
            "{label}: a parse rejection owns no terminal record"
        );
    }

    let (service_rejected, service_rejected_records) = execute_system_service_parse(&valid);
    assert!(
        service_rejected.is_err(),
        "SystemService must need the nonce"
    );
    assert_eq!(
        phase_tokens(&detail_records(&service_rejected_records), &tokens),
        vec![
            "host.launch-options system-service requested".to_owned(),
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse admitted".to_owned(),
            "host.launch-options system-service typed rejection".to_owned(),
        ]
    );

    let (service_admitted, service_admitted_records) =
        execute_system_service_parse(&valid_system_args());
    assert!(service_admitted.is_ok());
    assert_eq!(
        phase_tokens(&detail_records(&service_admitted_records), &tokens),
        vec![
            "host.launch-options system-service requested".to_owned(),
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse admitted".to_owned(),
            "host.launch-options system-service admitted".to_owned(),
        ]
    );

    let name = OsString::from(ELIOT_HOST_SERVICE_NAME);
    let (main_admitted, main_records) = execute_service_main_argv(std::slice::from_ref(&name));
    assert_eq!(main_admitted, Ok(()));
    assert_eq!(
        phase_tokens(&detail_records(&main_records), &tokens),
        vec![
            "host.launch-options service-main requested".to_owned(),
            "host.launch-options service-main admitted".to_owned(),
        ]
    );
    let (main_rejected, main_rejected_records) =
        execute_service_main_argv(&[name, OsString::from("extra")]);
    assert!(main_rejected.is_err());
    assert_eq!(
        phase_tokens(&detail_records(&main_rejected_records), &tokens),
        vec![
            "host.launch-options service-main requested".to_owned(),
            "host.launch-options service-main typed rejection".to_owned(),
        ]
    );

    // The descriptor cell is private: `validate_eliotd_launch_descriptor_bytes`
    // is `pub(super)` inside `launch_descriptor_validation.rs`, so its typed
    // rejection is the inline owner case there, not an integration seam.
    let descriptor = manifest_source("src/launch_descriptor_validation.rs");
    assert!(descriptor.contains("fn validate_eliotd_launch_descriptor_bytes"));
    assert!(descriptor.contains("host.launch-descriptor eliotd typed rejection"));
    assert!(descriptor.contains("ProcessContour"));
}

// WORK_UNIT_CASE: 978/3
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one frozen substitution table per case"
)]
fn launch_03_retained_identity_on_substitution() {
    let fixture = launch_fixture();
    let tokens = fixture_list(&fixture, "launch_options_details");
    let keys = fixture_list(&fixture, "correlation_keys");

    // Two real substitution failures: a relocated descriptor locator and a
    // substituted digest value.
    let (relocated, relocated_records) =
        execute_launch_parse(&args_with(&valid_launch_args(), 1, "relative-auth.json"));
    assert_eq!(
        relocated,
        Err(
            "invalid Host launch argv: config descriptor path must be absolute and valid"
                .to_owned()
        )
    );
    assert_eq!(
        phase_tokens(&detail_records(&relocated_records), &tokens),
        vec![
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse typed rejection".to_owned(),
        ]
    );
    let substituted = args_with(&valid_launch_args(), 3, "");
    let (substituted_digest, substituted_records) = execute_launch_parse(&substituted);
    assert_eq!(
        substituted_digest,
        Err("invalid Host launch argv: config descriptor digest is not valid text".to_owned())
    );
    assert_eq!(
        phase_tokens(&detail_records(&substituted_records), &tokens),
        vec![
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse typed rejection".to_owned(),
        ]
    );

    // The retained identity of the admitted contour is exactly the admitted
    // one, unchanged by the records the very same execution emitted.
    let (admitted, admitted_records) = execute_launch_parse(&valid_launch_args());
    let retained = admitted.expect("valid argv must admit");
    assert_eq!(
        RetainedLaunch::of(&retained),
        RetainedLaunch {
            config_descriptor: synthetic_descriptor_path().display().to_string(),
            digest: "a".repeat(64),
            installation: "installation-7".to_owned(),
            generation: 7,
            state_root: synthetic_state_root().display().to_string(),
            nonce_present: false,
        },
        "the retained identity must survive the diagnostics exactly"
    );
    for record in &detail_records(&admitted_records) {
        let detail = record.detail();
        assert_correlation_key_order(detail, &keys);
        assert!(
            !detail.contains(&synthetic_descriptor_path().display().to_string()),
            "a retained path must never enter the record: {detail}"
        );
        assert!(
            !detail.contains(&synthetic_state_root().display().to_string()),
            "a retained state root must never enter the record: {detail}"
        );
    }

    // The launch/artifact/descriptor substitution sites are private helpers
    // (`approved_launch_paths`, `approved_locator`,
    // `approved_phase_b_destination_locator`); their substitution records are
    // the inline owner cases in `host_job_launch.rs`,
    // `launch_artifact_lease.rs` and `launch_descriptor_validation.rs`.
    let inline_owners = [
        manifest_source("src/host_job_launch.rs"),
        manifest_source("src/launch_artifact_lease.rs"),
        manifest_source("src/launch_descriptor_validation.rs"),
    ]
    .join("");
    for detail in [
        "host.launch substitution preserved",
        "host.launch-artifact substitution preserved",
        "host.launch-artifact phase-b substitution preserved",
        "host.launch-descriptor substitution preserved",
    ] {
        assert!(
            inline_owners.contains(detail),
            "the inline owner must keep {detail:?}"
        );
    }
}

// WORK_UNIT_CASE: 978/4
#[test]
fn launch_04_request_vs_process_vs_readiness() {
    let fixture = launch_fixture();
    let tokens = fixture_list(&fixture, "sibling_phase_details");
    let request = registration_request();
    let options = admitted_launch_options();

    // A real SCM bootstrap request that refuses before any readback.
    let (bootstrap, bootstrap_records) = execute_scm_bootstrap(&options);
    assert!(bootstrap.is_err());
    assert_eq!(
        phase_tokens(&detail_records(&bootstrap_records), &tokens),
        vec!["host.scm-launch requested".to_owned()],
        "the SCM request is a request and nothing more"
    );

    // Three real inspections, each executed on its own.
    let script: Vec<(ServiceRegistrationRuntimeInspection, Vec<String>)> = vec![
        (
            ServiceRegistrationRuntimeInspection::Absent,
            vec![
                "host.scm-launch classification requested".to_owned(),
                "host.scm-launch request observed".to_owned(),
            ],
        ),
        (
            ServiceRegistrationRuntimeInspection::Mismatched,
            vec![
                "host.scm-launch classification requested".to_owned(),
                "host.scm-launch process observed".to_owned(),
            ],
        ),
        (
            ServiceRegistrationRuntimeInspection::unknown_with_status(
                1066,
                "open-service",
                3,
                4242,
            ),
            vec![
                "host.scm-launch classification requested".to_owned(),
                "host.scm-launch pid observed".to_owned(),
            ],
        ),
    ];
    for (inspection, expected) in script {
        let (cause, records) = execute_scm_classification(&request, &inspection);
        assert!(
            cause.is_some(),
            "every fail-closed inspection must still classify"
        );
        assert_eq!(phase_tokens(&detail_records(&records), &tokens), expected);
    }

    let mut executed = detail_records(&bootstrap_records);
    for inspection in injected_inspection_schedule() {
        let (_cause, records) = execute_scm_classification(&request, &inspection);
        executed.extend(detail_records(&records));
    }
    assert!(
        executed.len() >= 9,
        "one SCM request plus four executed inspections, got {}",
        executed.len()
    );
    for record in &executed {
        let detail = record.detail();
        assert!(
            !detail.contains("readiness") && !detail.contains("-ready"),
            "an SCM request or an observed process is never readiness: {detail}"
        );
        assert!(
            !detail.contains("healthy"),
            "never a health claim: {detail}"
        );
    }
}

// WORK_UNIT_CASE: 978/5
#[test]
fn launch_05_start_identity_vs_pid() {
    let fixture = launch_fixture();
    let tokens = fixture_list(&fixture, "sibling_phase_details");
    let request = registration_request();

    // Executed pid-only observation: a live process id with no start identity.
    let (pid_cause, pid_records) = execute_scm_classification(
        &request,
        &ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 4242),
    );
    let pid_cause = pid_cause.expect("a pid-only inspection must classify");
    assert_eq!(pid_cause.cause(), "unknown");
    assert_eq!(
        phase_tokens(&detail_records(&pid_records), &tokens),
        vec![
            "host.scm-launch classification requested".to_owned(),
            "host.scm-launch pid observed".to_owned(),
        ],
        "a reusable pid is observed, never promoted to a start identity"
    );
    let pid_detail = pid_cause.detail();
    assert!(
        pid_detail.contains("4242"),
        "the pid stays in the typed cause"
    );
    assert!(
        !pid_detail.contains(&request.expected_configuration_digest()),
        "a pid observation carries no registration identity"
    );

    // Executed request-identity observation: an absent registration, no pid.
    let (absent_cause, absent_records) =
        execute_scm_classification(&request, &ServiceRegistrationRuntimeInspection::Absent);
    let absent_cause = absent_cause.expect("an absent registration must classify");
    assert_eq!(absent_cause.cause(), "absent");
    assert_eq!(
        phase_tokens(&detail_records(&absent_records), &tokens),
        vec![
            "host.scm-launch classification requested".to_owned(),
            "host.scm-launch request observed".to_owned(),
        ],
        "a registration request is not an observed process"
    );
    let absent_detail = absent_cause.detail();
    assert!(absent_detail.contains(ELIOT_HOST_SERVICE_NAME));
    assert!(absent_detail.contains(&request.expected_configuration_digest()));
    assert!(
        !absent_detail.contains("4242"),
        "a request identity carries no pid: {absent_detail}"
    );
    assert_ne!(absent_cause.cause(), pid_cause.cause());

    // The frozen correlation vocabulary has no pid slot at all, so neither
    // execution can record a pid as a process identity.
    let observed = detail_records(&pid_records)
        .into_iter()
        .chain(detail_records(&absent_records))
        .collect::<Vec<_>>();
    assert_eq!(observed.len(), 4);
    for record in &observed {
        let detail = record.detail();
        assert!(
            correlation_slot(detail, "process_start").is_some(),
            "every record must render the frozen process_start slot: {detail}"
        );
        assert!(
            !detail.contains("4242"),
            "neither execution holds a process-start identity, so no slot may carry the pid: {detail}"
        );
    }
    assert!(
        tokens.contains(&"host.scm-launch start-identity observed".to_owned())
            && tokens.contains(&"host.scm-launch pid observed".to_owned()),
        "the frozen SCM vocabulary keeps the start-identity claim distinct from a pid claim"
    );

    // The positive start-identity arm needs
    // `ServiceRegistrationRuntimeInspection::Matching { observation }`, whose
    // payload fields are `pub(super)` in `eliot-platform-windows`, so that arm
    // is the inline owner case inside `scm_launch.rs`.
    assert!(
        manifest_source("src/scm_launch.rs").contains("host.scm-launch start-identity observed")
    );
}

// WORK_UNIT_CASE: 978/6
#[test]
fn launch_06_store_before_kernel() {
    let fixture = launch_fixture();
    let sibling_tokens = fixture_list(&fixture, "sibling_phase_details");
    let options_tokens = fixture_list(&fixture, "launch_options_details");
    let request = registration_request();

    // Order measured from the records two real executions actually emitted,
    // never from substring offsets in a source file.
    let (_parse, parse_records) = execute_launch_parse(&valid_launch_args());
    let (_cause, scm_records) =
        execute_scm_classification(&request, &ServiceRegistrationRuntimeInspection::Absent);
    assert_eq!(
        phase_tokens(&detail_records(&parse_records), &options_tokens),
        vec![
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse admitted".to_owned(),
        ]
    );
    assert_eq!(
        phase_tokens(&detail_records(&scm_records), &sibling_tokens),
        vec![
            "host.scm-launch classification requested".to_owned(),
            "host.scm-launch request observed".to_owned(),
        ],
        "each boundary is separately observed, in the order it executed"
    );

    // No reachable boundary of this target may claim Store or Kernel state.
    let executed = detail_records(&parse_records)
        .into_iter()
        .chain(detail_records(&scm_records))
        .collect::<Vec<_>>();
    for record in &executed {
        let detail = record.detail();
        assert!(
            !detail.contains("store-launch") && !detail.contains("kernel-launch"),
            "a launch-admission or SCM request claims no Store or Kernel state: {detail}"
        );
    }

    // Store-before-Kernel runtime order is the inline owner case in
    // `store_kernel_launch_sequence.rs`, which drives the private
    // `launch_store_then_kernel` and records its call order. This target pins
    // the two renamed physical tokens and keeps the false readiness retired.
    let sequence = manifest_source("src/store_kernel_launch_sequence.rs");
    let renamed = fixture["renamed_phase_tokens"]
        .as_object()
        .expect("the fixture must pin the renamed phase tokens");
    for retired in object_list(renamed, "retired_tokens") {
        assert!(
            !sequence.contains(&retired),
            "the false readiness token {retired:?} must stay retired"
        );
    }
    assert_eq!(
        renamed["store_liveness"].as_str(),
        Some("host.store-launch store-liveness-proven observed")
    );
    assert_eq!(
        renamed["kernel_launched"].as_str(),
        Some("host.kernel-launch kernel-launched observed")
    );
    for live in [
        "host.store-launch store-liveness-proven observed",
        "host.kernel-launch kernel-launched observed",
    ] {
        assert!(sequence.contains(live), "the sequence must pin {live:?}");
    }
    assert!(sequence.contains("fn launch_store_then_kernel"));
}

// WORK_UNIT_CASE: 978/7
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the nonce boundary plus its private owners"
)]
fn launch_07_nonce_handshake_auth_activation_distinct() {
    let fixture = launch_fixture();
    let tokens = fixture_list(&fixture, "launch_options_details");
    let canaries = fixture_list(&fixture, "canaries");
    assert!(!canaries.is_empty(), "the fixture must pin canaries");

    // The nonce boundary is executed, not described: the base parse admits and
    // the SystemService admission refuses for the missing nonce pair.
    let (rejected, rejected_records) = execute_system_service_parse(&valid_launch_args());
    assert!(rejected.is_err());
    assert_eq!(
        phase_tokens(&detail_records(&rejected_records), &tokens),
        vec![
            "host.launch-options system-service requested".to_owned(),
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse admitted".to_owned(),
            "host.launch-options system-service typed rejection".to_owned(),
        ],
        "nonce admission stays distinct from the base parse admission"
    );

    let (admitted, admitted_records) = execute_system_service_parse(&valid_system_args());
    assert!(admitted.is_ok());
    assert_eq!(
        phase_tokens(&detail_records(&admitted_records), &tokens),
        vec![
            "host.launch-options system-service requested".to_owned(),
            "host.launch-options parse requested".to_owned(),
            "host.launch-options parse admitted".to_owned(),
            "host.launch-options system-service admitted".to_owned(),
        ]
    );

    // The nonce binding is required by the SCM bootstrap owner and never
    // observed by the diagnostics.
    let options = admitted_launch_options();
    let (bootstrap, bootstrap_records) = execute_scm_bootstrap(&options);
    let bootstrap = bootstrap.expect_err("a SystemService bootstrap must refuse");
    assert!(
        bootstrap.contains("registration nonce"),
        "the refusal must name the missing nonce binding: {bootstrap}"
    );
    let nonce = synthetic_nonce().to_string_lossy().into_owned();
    let emitted = detail_records(&rejected_records)
        .into_iter()
        .chain(detail_records(&admitted_records))
        .chain(detail_records(&bootstrap_records))
        .collect::<Vec<_>>();
    assert!(!emitted.is_empty());
    for record in &emitted {
        let detail = record.detail();
        assert!(
            !detail.contains(&nonce),
            "a nonce value must never be observed: {detail}"
        );
        assert!(
            !detail.contains("activation_nonce"),
            "not even the nonce field name: {detail}"
        );
        for canary in &canaries {
            assert!(
                !detail.contains(canary.as_str()),
                "no {canary:?} in {detail}"
            );
        }
    }

    // Handshake, peer authentication and activation live in private owners:
    // `kernel_front_door_client.rs` and `kernel_activation_driver.rs` are
    // private modules, so their distinctness is the inline owner case there.
    let frontdoor = manifest_source("src/kernel_front_door_client.rs");
    let driver = manifest_source("src/kernel_activation_driver.rs");
    for detail in [
        "host.kernel-front-door handshake requested",
        "host.kernel-front-door handshake observed",
        "host.kernel-front-door auth requested",
        "host.kernel-front-door authenticated peer observed",
        "host.kernel-front-door control requested",
    ] {
        assert!(
            frontdoor.contains(detail),
            "front-door owner must pin {detail:?}"
        );
    }
    for detail in [
        "host.kernel-activation nonce requested",
        "host.kernel-activation nonce issued",
        "host.kernel-activation activating requested",
        "host.kernel-activation candidate observed",
        "host.kernel-activation activation observed",
    ] {
        assert!(
            driver.contains(detail),
            "activation owner must pin {detail:?}"
        );
    }
}

// WORK_UNIT_CASE: 978/8
#[test]
fn launch_08_readiness_needs_owner_evidence() {
    let fixture = launch_fixture();
    let tokens = fixture_list(&fixture, "sibling_phase_details");
    let request = registration_request();
    let options = admitted_launch_options();

    // Execute every reachable boundary a readiness claim could have escaped
    // from, then inspect what they actually emitted.
    let mut executed = Vec::new();
    let (_parse, records) = execute_launch_parse(&valid_launch_args());
    executed.extend(detail_records(&records));
    let (_bootstrap, records) = execute_scm_bootstrap(&options);
    executed.extend(detail_records(&records));
    for inspection in injected_inspection_schedule() {
        let (_cause, records) = execute_scm_classification(&request, &inspection);
        executed.extend(detail_records(&records));
    }
    assert!(
        executed.len() >= 10,
        "the executed contour must cover every reachable boundary"
    );
    for record in &executed {
        let detail = record.detail();
        assert!(
            !detail.contains("readiness") && !detail.contains("-ready"),
            "a launch or SCM boundary must never claim readiness: {detail}"
        );
    }
    assert!(
        !phase_tokens(&executed, &tokens)
            .iter()
            .any(|token| token.contains("ready")),
        "no reachable phase may be a readiness phase"
    );

    // Readiness survives only inside the activation owner's evidence path.
    let sources = eight_sources();
    assert_readiness_owned_only_by_activation_active(&sources);
    let span = readiness_owner_span(&manifest_source(READINESS_OWNER_FILE));
    assert!(
        span.1 > span.0,
        "the readiness owner body must be locatable"
    );

    // The positive owner-evidence execution needs
    // `DurableKernelActivationDriver::active`, a `pub(super)` method over a
    // live journal backend: the inline owner case in
    // `kernel_activation_driver.rs`.
    let driver = manifest_source(READINESS_OWNER_FILE);
    assert!(driver.contains("host.kernel-activation readiness requested"));
    assert!(driver.contains("host.kernel-activation readiness observed"));
}

// WORK_UNIT_CASE: 978/9
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "four outcomes, each with its own execution"
)]
fn launch_09_before_start_vs_timeout_disconnect_unknown() {
    let fixture = launch_fixture();
    let tokens = fixture_list(&fixture, "sibling_phase_details");
    let request = registration_request();
    let options = admitted_launch_options();

    // Outcome 1, its own execution: a refusal BEFORE any possible start. The
    // bootstrap refuses while still holding no probe observation at all.
    let (before_start, before_start_records) = execute_scm_bootstrap(&options);
    assert!(before_start.is_err());
    let before_start_phases = phase_tokens(&detail_records(&before_start_records), &tokens);
    assert_eq!(
        before_start_phases,
        vec!["host.scm-launch requested".to_owned()]
    );
    assert!(
        !before_start_phases
            .iter()
            .any(|token| token.contains("probe") || token.contains("pid")),
        "a before-start refusal never observed a process: {before_start_phases:?}"
    );

    // Outcome 2, its own execution: a possible start whose outcome is not yet
    // known, a live pid without a settled classification.
    let (unknown, unknown_records) = execute_scm_classification(
        &request,
        &ServiceRegistrationRuntimeInspection::unknown_with_status(0, "query-status", 2, 4242),
    );
    let unknown_detail = unknown.expect("must classify").detail();
    assert_eq!(
        phase_tokens(&detail_records(&unknown_records), &tokens),
        vec![
            "host.scm-launch classification requested".to_owned(),
            "host.scm-launch pid observed".to_owned(),
        ],
        "a possible start that is not settled is observed, never resolved"
    );

    // Outcome 3, its own execution: a possible start with a settled failure.
    let (failed, failed_records) = execute_scm_classification(
        &request,
        &ServiceRegistrationRuntimeInspection::unknown_with_status(1066, "open-service", 3, 4242),
    );
    let failed = failed.expect("must classify");
    assert_eq!(failed.cause(), "unknown");
    assert!(
        failed.detail().contains("1066"),
        "the settled Win32 reason must survive: {}",
        failed.detail()
    );
    assert_eq!(
        phase_tokens(&detail_records(&failed_records), &tokens),
        vec![
            "host.scm-launch classification requested".to_owned(),
            "host.scm-launch pid observed".to_owned(),
        ]
    );
    assert_ne!(
        failed.detail(),
        unknown_detail,
        "an unsettled and a settled failure are different outcomes"
    );
    assert_ne!(
        before_start_phases,
        phase_tokens(&detail_records(&unknown_records), &tokens)
    );

    // Outcome 4, timeout and disconnect, belongs to
    // `kernel_front_door_client.rs::activation_response_or_reconcile`, a
    // `pub(super)` transport-loss path in a private module: the inline owner
    // case there.
    let frontdoor = manifest_source("src/kernel_front_door_client.rs");
    for detail in [
        "host.kernel-front-door before-start observed",
        "host.kernel-front-door timeout observed",
        "host.kernel-front-door disconnect observed",
        "host.kernel-front-door unknown observed",
        "host.kernel-front-door reconcile requested",
    ] {
        assert!(
            frontdoor.contains(detail),
            "the front-door owner must pin {detail:?}"
        );
    }
}

// WORK_UNIT_CASE: 978/10
#[test]
fn launch_10_one_terminal_across_nesting() {
    let fixture = launch_fixture();
    let keys = fixture_list(&fixture, "correlation_keys");
    let terminal_event = fixture["terminal_event"]
        .as_str()
        .expect("the fixture pins the terminal event");
    let scm_terminal = fixture["terminal_codes"]["scm_bootstrap_unknown"]
        .as_str()
        .expect("the fixture pins the SCM terminal code");

    // One real failed bootstrap: the outermost SCM contour propagates the error
    // out of its nested construction and inspection callsites.
    let options = admitted_launch_options();
    let (_failed, records) = execute_scm_bootstrap(&options);
    let terminals = terminal_records(&records);
    assert_eq!(
        terminals.len(),
        1,
        "one failed operation emits exactly one terminal, got: {records:?}"
    );
    assert_eq!(terminals[0].event(), terminal_event);
    assert_eq!(terminals[0].code(), scm_terminal);
    assert_eq!(
        terminals[0].field("code_truncated"),
        Some("false"),
        "the terminal code must not be truncated"
    );

    // Every subordinate phase record of that one operation renders the full
    // frozen correlation vector, and the identities this contour already holds
    // in `launch_options` are bound rather than guessed.
    let subordinate = detail_records(&records);
    assert!(!subordinate.is_empty());
    for record in &subordinate {
        let detail = record.detail();
        assert_correlation_key_order(detail, &keys);
        for key in keys.iter().filter(|key| key.as_str() != "phase") {
            let value = correlation_slot(detail, key)
                .unwrap_or_else(|| panic!("every subordinate record must render {key}="));
            assert!(
                !value.is_empty(),
                "a correlation slot must never render empty: {detail}"
            );
        }
        assert_eq!(
            correlation_slot(detail, "installation"),
            Some(options.installation().as_str().to_owned()),
            "the SCM bootstrap owner holds the admitted installation and must bind it: {detail}"
        );
        assert_eq!(
            correlation_slot(detail, "generation"),
            Some(options.transaction_plan_generation().to_string()),
            "the SCM bootstrap owner holds the admitted generation and must bind it: {detail}"
        );
    }

    // A successful contour emits no terminal at all.
    let (admitted, admitted_records) = execute_system_service_parse(&valid_system_args());
    assert!(admitted.is_ok());
    assert!(terminal_records(&admitted_records).is_empty());

    // The physical launch guard is phase-only: the single launch terminal is
    // `host-start-failed` in `lib.rs`, and the SCM bootstrap validation is a
    // different operation that keeps its own terminal.
    let ruling = fixture["single_terminal_ruling"]
        .as_object()
        .expect("the fixture must pin the single-terminal ruling");
    assert_eq!(ruling["physical_launch_guard"].as_str(), Some("phase-only"));
    assert_eq!(
        ruling["host_start_failed"].as_str(),
        Some("host-start-failed")
    );
    assert_eq!(ruling["scm_bootstrap_unknown"].as_str(), Some(scm_terminal));
}

// WORK_UNIT_CASE: 978/11
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one frozen script under three sink shapes"
)]
fn launch_11_sink_failure_leaves_operation_identical() {
    // One frozen production script, executed three times: behind a recording
    // sink, behind a sink that drops every record, and behind a sink whose
    // every write fails.
    let baseline_cell = std::cell::RefCell::new(None);
    let baseline_records = record_emit(|| {
        *baseline_cell.borrow_mut() = Some(run_launch_script());
    });
    let baseline = baseline_cell.borrow_mut().take().expect("captured");

    let filtered_cell = std::cell::RefCell::new(None);
    let filtered_records = record_emit_filtered(|| {
        *filtered_cell.borrow_mut() = Some(run_launch_script());
    });
    let filtered = filtered_cell.borrow_mut().take().expect("captured");

    let failing_cell = std::cell::RefCell::new(None);
    let (failing_records, faults) = record_emit_failing(|| {
        *failing_cell.borrow_mut() = Some(run_launch_script());
    });
    let failing = failing_cell.borrow_mut().take().expect("captured");

    // Call count and order: the identical emission attempts in every
    // configuration, and nothing at all delivered under the dropping filter.
    assert!(
        baseline_records.len() >= 18,
        "the frozen script must attempt every phase record, got {}",
        baseline_records.len()
    );
    assert_eq!(
        terminal_records(&baseline_records).len(),
        1,
        "one failed operation, one terminal record"
    );
    assert!(
        filtered_records.is_empty(),
        "the filter must drop every record, got: {filtered_records:?}"
    );
    assert_eq!(
        failing_records, baseline_records,
        "a failing sink must not change which records were emitted"
    );
    assert!(
        faults.failures > 0 && faults.attempts >= faults.failures,
        "the injected sink must really have failed: {faults:?}"
    );

    // Result, retained handles and cleanup: identical under every sink.
    assert_eq!(filtered, baseline, "a dropped sink must change no result");
    assert_eq!(failing, baseline, "a failing sink must change no result");
    assert!(baseline.parse.is_ok());
    assert!(baseline.parse_rejected.is_err());
    assert!(baseline.system_service.is_ok());
    assert!(baseline.bootstrap.is_err());
    assert!(baseline.absent_cause.is_some());
    assert!(baseline.mismatched_cause.is_some());
    assert!(baseline.unknown_cause.is_some());
    assert_eq!(
        baseline.drop_order,
        vec!["parse", "parse-rejected", "system-service"],
        "every owner-held launch value is released exactly once"
    );

    // The Event Log seam answer is the typed residual it always is (#984).
    let event_log = Err(WindowsEventLogError::EventLogUnavailable);
    assert_eq!(event_log_sink_status(), event_log);
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(HostDiagnosticsError::EventLogUnavailable)
    );
    assert_eq!(
        report_event(&EventLogRecord::new(
            AdmittedEvent::ServiceFailure,
            "host-start-failed",
        )),
        Err(WindowsEventLogError::EventLogUnavailable),
        "a failed sink never fakes Event Log delivery"
    );
    assert_eq!(
        launch_fixture()["stdout_protocol_contamination"].as_bool(),
        Some(false)
    );
}

// WORK_UNIT_CASE: 978/12
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one canary sweep over every emitted record"
)]
fn launch_12_canaries_absent_from_observations() {
    let fixture = launch_fixture();
    let canaries = fixture_list(&fixture, "canaries");
    assert!(!canaries.is_empty(), "the fixture must pin canaries");
    assert!(
        !fixture["correlation_missing_markers"]
            .as_array()
            .expect("the fixture pins the absent-slot vocabulary")
            .is_empty(),
        "the fixture must pin the absent-slot vocabulary"
    );
    let keys = fixture_list(&fixture, "correlation_keys");

    let forbidden: Vec<String> = canaries
        .iter()
        .cloned()
        .chain([
            synthetic_descriptor_path().display().to_string(),
            synthetic_state_root().display().to_string(),
            synthetic_nonce().to_string_lossy().into_owned(),
            "--config-descriptor".to_owned(),
            "--host-state-root".to_owned(),
        ])
        .collect();

    // Every diagnostic literal of all eight files stays canary-free.
    for (path, source) in eight_sources() {
        for line in source.lines().filter(|line| line.contains("\"host.")) {
            for canary in &forbidden {
                assert!(
                    !line.contains(canary.as_str()),
                    "{path} diagnostic line must not carry {canary:?}: {line}"
                );
            }
        }
    }

    // Every record the executed seams actually emitted stays canary-free and
    // inside the frozen bounds.
    let request = registration_request();
    let options = admitted_launch_options();
    let mut executed = Vec::new();
    for args in [
        valid_launch_args(),
        valid_system_args(),
        args_with(&valid_launch_args(), 1, "relative-auth.json"),
    ] {
        let (_parsed, records) = execute_launch_parse(&args);
        executed.extend(detail_records(&records));
        let (_parsed, records) = execute_system_service_parse(&args);
        executed.extend(detail_records(&records));
    }
    let (_bootstrap, records) = execute_scm_bootstrap(&options);
    executed.extend(detail_records(&records));
    for inspection in injected_inspection_schedule() {
        let (_cause, records) = execute_scm_classification(&request, &inspection);
        executed.extend(detail_records(&records));
    }
    assert!(
        executed.len() >= 20,
        "the canary sweep must cover every reachable phase, got {}",
        executed.len()
    );

    for record in &executed {
        let detail = record.detail();
        assert_correlation_key_order(detail, &keys);
        assert!(
            detail.len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
            "the detail must stay inside the frozen bound: {detail}"
        );
        assert!(
            detail
                .split(' ')
                .all(|piece| piece.len() <= MAX_DIAGNOSTIC_FIELD_BYTES),
            "every rendered correlation value must stay inside the field bound: {detail}"
        );
        assert_eq!(
            record.field("detail_bytes"),
            Some(detail.len().to_string().as_str()),
            "an emitted record must report its own retained length: {detail}"
        );
        assert_eq!(
            record.field("detail_truncated"),
            Some("false"),
            "no reachable correlation value may be silently truncated: {detail}"
        );
        for canary in &forbidden {
            assert!(
                !detail.contains(canary.as_str()),
                "no {canary:?} may appear in {detail}"
            );
        }
    }

    // The new correlation slots must never invent evidence. A pre-parse phase
    // holds no installation, generation, process start or fence, so its slots
    // cannot carry the values the admitted contour binds, and its correlation
    // vector must therefore differ from the admitted one.
    let (admitted, _admitted_records) = execute_launch_parse(&valid_launch_args());
    let admitted = admitted.expect("valid argv must admit");
    let (pre_parse, pre_parse_records) = execute_launch_parse(&valid_launch_args());
    assert!(pre_parse.is_ok());
    let phases = detail_records(&pre_parse_records);
    let first = &phases[0];
    let admitted_phase = phases
        .iter()
        .find(|record| record.detail().contains("parse admitted"))
        .expect("the admitted phase must be emitted");
    assert!(
        first
            .detail()
            .contains("host.launch-options parse requested"),
        "got: {}",
        first.detail()
    );
    for key in ["installation", "generation", "process_start", "fence"] {
        let value = correlation_slot(first.detail(), key)
            .unwrap_or_else(|| panic!("the pre-parse phase must render {key}="));
        assert!(
            !value.contains("installation-7") && value != "7",
            "a pre-parse phase holds no identity, so {key} must not carry one: {}",
            first.detail()
        );
        assert!(
            correlation_slot(admitted_phase.detail(), key).is_some(),
            "the admitted phase must render {key}="
        );
    }
    assert_ne!(
        first.detail(),
        admitted_phase.detail(),
        "the correlation vector must track real owner state, admission binds what the request cannot"
    );
    assert_eq!(
        correlation_slot(admitted_phase.detail(), "installation"),
        Some(admitted.installation().as_str().to_owned()),
        "the admitted phase binds the installation the owner actually holds"
    );
}

// WORK_UNIT_CASE: 978/13
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the frozen vocabulary plus the semantic bindings"
)]
fn launch_13_deterministic_semantic_fields() {
    let fixture = launch_fixture();
    let keys = fixture_list(&fixture, "correlation_keys");
    assert_eq!(
        keys,
        vec![
            "phase".to_owned(),
            "installation".to_owned(),
            "generation".to_owned(),
            "operation".to_owned(),
            "artifact".to_owned(),
            "process_start".to_owned(),
            "fence".to_owned(),
            "reason".to_owned(),
        ],
        "the frozen correlation vocabulary is the rendered slot order"
    );

    // The frozen vocabulary is bound to the rendering code that produces it.
    let render_owner = manifest_source("src/host_job_launch.rs");
    assert!(render_owner.contains("fn render_phase_slot"));
    assert!(render_owner.contains("fn render(&self, phase: &str)"));
    for key in &keys {
        assert!(
            render_owner.contains(&format!("\"{key}\""))
                || render_owner.contains(&format!("\"{key}=")),
            "the frozen correlation slot {key} must be rendered by LaunchPhaseCorrelation"
        );
    }

    // Two identical injected schedules must produce byte-identical records and
    // byte-identical typed outcomes.
    let (first_records, first_causes) = run_injected_schedule();
    let (second_records, second_causes) = run_injected_schedule();
    assert!(
        first_records.len() >= 8,
        "one classification pair per injected entry, got {}",
        first_records.len()
    );
    assert_eq!(second_records, first_records);
    assert_eq!(second_causes, first_causes);
    assert_eq!(
        first_causes.iter().filter(|cause| cause.is_some()).count(),
        4,
        "every injected inspection must classify fail-closed"
    );

    for record in &detail_records(&first_records) {
        let detail = record.detail();
        assert_correlation_key_order(detail, &keys);
        assert_eq!(
            record.field("detail_bytes"),
            Some(detail.len().to_string().as_str())
        );
        assert_eq!(record.field("detail_truncated"), Some("false"));
    }

    // Semantic fields, not a count: the admitted launch contour must carry the
    // installation and generation the owner actually holds.
    let (admitted, admitted_records) = execute_launch_parse(&valid_launch_args());
    let retained = admitted.expect("valid argv must admit");
    let admitted_phase = detail_records(&admitted_records)
        .into_iter()
        .find(|record| {
            record
                .detail()
                .contains("phase=host.launch-options parse admitted")
        })
        .expect("an admitted phase must be emitted");
    assert_eq!(
        correlation_slot(admitted_phase.detail(), "installation"),
        Some(retained.installation().as_str().to_owned()),
        "the installation slot must carry the owner's retained identity"
    );
    assert_eq!(
        correlation_slot(admitted_phase.detail(), "generation"),
        Some(retained.transaction_plan_generation().to_string()),
        "the generation slot must carry the owner's retained generation"
    );
    let (_again, again_records) = execute_launch_parse(&valid_launch_args());
    let again_phase = detail_records(&again_records)
        .into_iter()
        .find(|record| {
            record
                .detail()
                .contains("phase=host.launch-options parse admitted")
        })
        .expect("an admitted phase must be emitted");
    assert_eq!(
        again_phase.detail(),
        admitted_phase.detail(),
        "the same owner identity must render deterministically on every execution"
    );

    // The same identities on a different contour stay distinguishable.
    let (other, other_records) = execute_system_service_parse(&valid_system_args());
    let other = other.expect("valid system argv must admit");
    let other_phase = detail_records(&other_records)
        .into_iter()
        .find(|record| {
            record
                .detail()
                .contains("phase=host.launch-options system-service admitted")
        })
        .expect("an admitted system-service phase must be emitted");
    assert_eq!(
        correlation_slot(other_phase.detail(), "installation"),
        Some(other.installation().as_str().to_owned())
    );
    assert_ne!(
        other_phase.detail(),
        admitted_phase.detail(),
        "the phase slot must keep the two contours distinct"
    );
}

// WORK_UNIT_CASE: 978/14
#[test]
#[allow(clippy::too_many_lines, reason = "the strict source and diff guard")]
fn launch_14_source_guard_stays_diagnostics_only() {
    let sources = eight_sources();
    for (path, source) in &sources {
        for forbidden in ["unsafe", "println!", "print!", "eprintln!"] {
            assert!(
                !source.contains(forbidden),
                "a diagnostics-only change must not introduce {forbidden:?} in {path}"
            );
        }
        for direct in [
            "tracing::info!",
            "tracing::warn!",
            "tracing::error!",
            "tracing::debug!",
            "tracing::trace!",
            "tracing::event!",
        ] {
            assert!(
                !source.contains(direct),
                "all observations go through the single host_diagnostics facade, found {direct:?} in {path}"
            );
        }
        assert!(
            source.contains("observe_entrypoint") || source.contains("observe_terminal_error"),
            "every boundary file must emit through the facade: {path}"
        );
    }
    assert_readiness_owned_only_by_activation_active(&sources);

    // A second terminal emitter in the launch path is rejected: the physical
    // launch guard is phase-only and the SCM contour is the single owner.
    let fixture = launch_fixture();
    let renamed = fixture["renamed_phase_tokens"]
        .as_object()
        .expect("the fixture pins the renamed phase tokens");
    let retired = object_list(renamed, "retired_tokens");
    let scm_terminal = fixture["terminal_codes"]["scm_bootstrap_unknown"]
        .as_str()
        .expect("the fixture pins the SCM terminal code");
    let mut terminal_owners = Vec::new();
    for (path, source) in &sources {
        if source.contains("observe_terminal_error") {
            terminal_owners.push(path.clone());
        }
        for token in &retired {
            assert!(
                !source.contains(token),
                "{path} must keep the retired token {token:?} gone"
            );
        }
        if path != "src/scm_launch.rs" {
            assert!(
                !source.contains("observe_terminal_error"),
                "{path} must own no terminal record"
            );
        }
    }
    assert_eq!(
        terminal_owners,
        vec!["src/scm_launch.rs".to_owned()],
        "exactly one of the eight files may emit a terminal record"
    );
    let scm = manifest_source("src/scm_launch.rs");
    assert_eq!(
        count_occurrences(&scm, scm_terminal),
        1,
        "the SCM terminal code must have exactly one owner callsite"
    );
    assert!(scm.contains("struct ScmLaunchTerminalGuard"));
    let job = manifest_source("src/host_job_launch.rs");
    assert!(
        !job.contains("host-launch-failed"),
        "the physical launch guard must stay phase-only"
    );
    assert!(
        manifest_source("src/lib.rs").contains("host-start-failed"),
        "the single launch terminal stays owned by lib.rs"
    );
    for other in [
        "src/credential_control.rs",
        "src/host_activation_durable.rs",
        "src/host_composition_phase_b.rs",
        "src/host_composition_store_recovery.rs",
        "src/phase_b_materialization.rs",
        "src/store_recovery_persistence.rs",
    ] {
        assert!(
            !manifest_source(other).contains("978/"),
            "F-LOG-HOST-3 must not touch sibling item scope {other}"
        );
    }
    for (path, source) in &sources {
        assert!(
            !source.contains("static DEDUP") && !source.contains("static DEDUP_CACHE"),
            "{path} must keep the no-mutable-global-dedup-cache rule"
        );
    }
}
