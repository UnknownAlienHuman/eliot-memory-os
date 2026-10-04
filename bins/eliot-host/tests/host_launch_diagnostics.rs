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
//! * `eliot_host::publish_supervision_record_table` — `src/scm_launch.rs`, driven
//!   to its deterministic publication refusal (nothing is created, no live SCM
//!   call, no FFI, no launch). It is the one reachable seam that is HANDED the
//!   caller's own identities and then refuses, so its refusal record is real
//!   evidence that a typed-refusal record carries those identities instead of
//!   only its typed reason.
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
use eliot_host::windows_event_log::{WindowsEventLogError, event_log_sink_status};
use eliot_host::{
    HostError, HostLaunchOptions, HostScmRegistrationCause, classify_host_scm_inspection,
    validate_host_scm_bootstrap,
};
#[cfg(windows)]
use eliot_host::{
    SUPERVISION_RECORD_COMPONENTS, SUPERVISION_RECORD_WIRE, SupervisionComponentRecord,
    SupervisionRecordTable, publish_supervision_record_table,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME, ServiceAccount,
    ServiceRegistrationRequest, ServiceRegistrationRuntimeInspection, ServiceStartMode,
};
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
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

/// What the executed forwarded-correlation record of case 3 and case 6 proves,
/// stated by the fixture per case instead of implied by prose: a REACHABLE seam
/// that already forwarded its correlation renders the identities its caller
/// already held and renders every slot the caller does not hold as the explicit
/// missing marker. That is the forwarding PROPERTY, measured on a seam this
/// integration target can really execute - not a delivered twin's own rendered
/// record.
const EXECUTED_SEAM_PROVES: &str =
    "the forwarding property and the slot rendering on a reachable, already-forwarding seam";

/// Where the DELIVERED twins' own rendered records are proven instead. The eight
/// `#978` twins are private, `pub(crate)` or `pub(super)` inside a private module,
/// integration target can call one and never could; each twin's rendered record
/// is the inline owner case in its own file, mapped by the fixture key below.
const EXECUTED_SEAM_TWIN_OWNER_MAP: &str = "inline_case_owners";

/// The frozen non-identity correlation key: the phase label the renderer always
/// emits first, never a caller-held identity.
const NON_IDENTITY_CORRELATION_KEY: &str = "phase";

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

/// Sink that filters every record out while the production path keeps running.
///
/// The filter is deliberately modelled on the *sink* side of the subscriber,
/// not as a subscriber-wide filter: a subscriber-wide filter would suppress the
/// records themselves and this case could no longer compare the call count and
/// order it is here to prove. Here the production path still creates and emits
/// every record (the recording layer sees all of them, in order) and the sink
/// below is offered every one of them and delivers none.
#[derive(Clone, Default)]
struct DroppingSink {
    offered: Arc<Mutex<usize>>,
}

impl DroppingSink {
    fn offered_records(&self) -> usize {
        *self.offered.lock().unwrap()
    }
}

impl<S> Layer<S> for DroppingSink
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, _event: &Event<'_>, _context: Context<'_, S>) {
        *self.offered.lock().unwrap() += 1;
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

/// The same production execution behind a sink that filters every record out.
/// Returns what the subscriber still saw plus how many records the filtering
/// sink was offered, so a case can compare both against the delivered run.
fn record_emit_filtered(emit: impl FnOnce()) -> (Vec<CapturedRecord>, usize) {
    let records = Arc::new(Mutex::new(Vec::new()));
    let sink = DroppingSink::default();
    let subscriber = tracing_subscriber::registry()
        .with(RecordingLayer {
            records: Arc::clone(&records),
        })
        .with(sink.clone());
    tracing::subscriber::with_default(subscriber, emit);
    let captured = records.lock().unwrap().clone();
    (captured, sink.offered_records())
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

/// The rendered detail's `key=value` slots, parsed into `(key, value)` pairs in
/// the order of the supplied frozen key list.
///
/// This helper proves ONE thing only: where each value starts and ends. A value
/// is NOT whitespace-free - the `phase` value is a multi-word token by
/// construction (`phase=host.launch requested`) - so the record is never split
/// on spaces. Instead each value runs from its own `<key>=` anchor to the NEXT
/// `<key>=` anchor of another frozen key, which is the only separator the
/// renderer guarantees (`render_phase_slot` emits exactly one space before every
/// pair after the first, and `bound_field`'s `truncate_to` neither inserts nor
/// strips spaces). A value that happens to contain another key's letters, or a
/// key whose name is a prefix of a longer one, therefore cannot shift a boundary.
///
/// This helper does NOT prove order and does not prove completeness: it returns
/// pairs in the order of the list it was handed, by construction.
/// `assert_frozen_correlation_slots` owns the order claim, because only it reads
/// the record's own bytes.
fn parsed_correlation_slots(detail: &str, keys: &[String]) -> Vec<(String, String)> {
    keys.iter()
        .map(|key| {
            let anchor = format!("{key}=");
            let start = detail
                .find(&anchor)
                .unwrap_or_else(|| panic!("a rendered detail must carry {key}=: {detail}"))
                + anchor.len();
            let end = keys
                .iter()
                .filter(|other| *other != key)
                .map(|other| format!(" {other}="))
                .filter_map(|needle| detail[start..].find(&needle).map(|at| start + at))
                .min()
                .unwrap_or(detail.len());
            (key.clone(), detail[start..end].to_owned())
        })
        .collect()
}

/// The frozen correlation contract: every frozen key renders exactly once, in
/// the frozen order, with a non-empty value.
///
/// Both halves are recovered from the RECORD's own bytes, never compared against
/// the caller's key list - otherwise the assertion would be a tautology, because
/// the parser builds its result FROM that list. So this does two independent
/// things:
///
/// 1. it reads the byte offset of each `<key>=` anchor out of `detail` and
///    requires them to be strictly increasing, which is what proves the renderer
///    emitted the anchors in the frozen order; and
/// 2. it requires each frozen anchor to occur EXACTLY ONCE in the record, which
///    is what proves no frozen key is RENDERED TWICE. It does not prove the
///    record contains nothing else - see the stated limit below.
///
/// AN earlier version of this helper ALSO re-composed the record from the parsed
/// slots and asserted byte-for-byte equality, and its comment claimed that proved
/// "no extra slot". That claim was FALSE and the check was provably redundant: a
/// verifier showed that given (1) the `min()` inside the parser is necessarily
/// the next anchor, so the re-composition reproduces `detail` by construction and
/// can never fail for a record (1) accepts - while a trailing extra `k=v` or a
/// duplicated slot is absorbed into an adjacent value exactly as a count
/// comparison would absorb it. Both the check and the claim were removed rather
/// than kept as decoration.
///
/// STATED LIMIT, not papered over: because this parser is value-driven and the
/// last slot's value runs to the end of the detail, a trailing NON-frozen
/// `k=v` would still be absorbed into the last value and is not caught here.
/// Catching it would require rejecting `=` inside a value, which is impossible
/// because `installation` legitimately admits spaces and `=`.
///
/// A SECOND, OPPOSITE limit, also reachable and also not handled here: because
/// the once-only check counts the anchor string, a VALUE that itself contains
/// `" <key>="` would make the count 2 and fail a record production legitimately
/// emitted. `valid_launch_identity` admits an `installation` of `x reason=y`, so
/// that is a real false-failure path. It is latent here because every argv in this
/// suite uses a space-free installation id, but it is a property of the parser,
/// not of the fixture, and it is stated rather than left for the next reader to
/// discover.
fn assert_frozen_correlation_slots(detail: &str, keys: &[String]) {
    let mut previous_offset = 0_usize;
    for (index, key) in keys.iter().enumerate() {
        let needle = if index == 0 {
            format!("{key}=")
        } else {
            format!(" {key}=")
        };
        let offset = detail
            .find(&needle)
            .unwrap_or_else(|| panic!("a rendered detail must carry {key}=: {detail}"));
        // The first anchor is NOT compared against the sentinel: `render` always
        // emits `phase=` at offset 0, so asserting `offset > 0` there would fail
        // on every well-formed record and make this helper unsatisfiable.
        if index > 0 {
            assert!(
                offset > previous_offset,
                "correlation slots must stay in the frozen order, got: {detail}"
            );
        }
        previous_offset = offset + needle.len();
        assert_eq!(
            detail.matches(&needle).count(),
            1,
            "a frozen correlation key must be rendered exactly once: {detail}"
        );
    }

    for (_key, value) in parsed_correlation_slots(detail, keys) {
        assert!(
            !value.is_empty(),
            "a correlation slot must never render empty: {detail}"
        );
    }
}

fn host_error_text(error: &HostError) -> String {
    error.to_string()
}

/// Rendered value of one frozen correlation slot, read out of a record the
/// instrumented production path actually emitted.
///
/// This is the SAME parser `assert_frozen_correlation_slots` uses, so a slot
/// value here is exactly the bytes the renderer wrote between two frozen
/// anchors, never a value this target composed.
fn captured_slot(detail: &str, keys: &[String], key: &str) -> String {
    parsed_correlation_slots(detail, keys)
        .into_iter()
        .find(|(name, _)| name == key)
        .map_or_else(
            || panic!("a rendered detail must carry {key}=: {detail}"),
            |(_, value)| value,
        )
}

/// The frozen slots one captured record left explicitly absent, in the frozen
/// key order.
fn absent_correlation_slots(detail: &str, keys: &[String], marker: &str) -> Vec<String> {
    parsed_correlation_slots(detail, keys)
        .into_iter()
        .filter(|(_, value)| value == marker)
        .map(|(name, _)| name)
        .collect()
}

/// The frozen IDENTITY correlation keys: every frozen key except the phase label.
///
/// `phase` is NOT an identity slot. It is the phase LABEL the renderer always
/// emits as the first frozen key - `LaunchPhaseCorrelation::render` writes
/// `phase=` at offset 0 of every record and `assert_frozen_correlation_slots`
/// requires it exactly once there - so no seam ever forwards it, no seam ever
/// leaves it absent, and no record can declare it as bound or explicitly
/// missing. Accounting a record's bound + explicitly-absent slots against the
/// FULL `correlation_keys` length therefore asks for one declaration more than
/// any record can make, and the case fails before reaching its forwarding
/// assertion: `correlation_keys` has 8 entries, while case 3 declares 3 bound +
/// 4 absent = 7 and case 6 declares 2 bound + 5 absent = 7, which are exactly
/// these 7 identity keys. Both cases are checked against THIS length.
fn identity_correlation_keys(keys: &[String]) -> Vec<String> {
    let identities: Vec<String> = keys
        .iter()
        .filter(|key| key.as_str() != NON_IDENTITY_CORRELATION_KEY)
        .cloned()
        .collect();
    assert_eq!(
        identities.len() + 1,
        keys.len(),
        "exactly one frozen key is the non-identity phase label {NON_IDENTITY_CORRELATION_KEY:?}: {keys:?}"
    );
    identities
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

/// The frozen absent-value spelling, taken from the fixture's own declared
/// absent-slot vocabulary instead of being hand-copied into this target.
///
/// A renderer that re-spelled the marker, or a fixture that drifted from it,
/// would then fail here rather than passing because this file repeated itself.
fn missing_marker(fixture: &Value) -> String {
    let declared = fixture_list(fixture, "correlation_missing_markers");
    let first = declared
        .first()
        .unwrap_or_else(|| panic!("the fixture must pin the absent-slot vocabulary"));
    first.split_once('=').map_or_else(
        || panic!("an absent-slot marker must be spelled <slot>=<value>: {first}"),
        |(_, marker)| marker.to_owned(),
    )
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

/// Whole file with every comment removed. A retired label or a retired terminal
/// code may still be named in prose that explains the retirement; what must not
/// exist is the code that would emit it.
fn code_only(source: &str) -> String {
    source.lines().map(code_of).collect::<Vec<_>>().join("\n")
}

/// Whole file restricted to CODE THE COMPILER SHIPS IN A PRODUCTION BUILD: every
/// comment removed and every line belonging to an item gated on `#[cfg(... test
/// ...)]` dropped, the gating decided by `test_gated_lines` from the real
/// predicates rather than by a hand-listed range.
///
/// A whole-file needle cannot tell a production emission from this suite's own
/// scaffolding: `store_kernel_launch_sequence.rs` spells
/// `host.store-launch store-liveness-proven observed` and
/// `host.kernel-launch kernel-launched observed` three times each - once in the
/// sequence itself and twice inside its `#[cfg(all(test, windows))] mod tests` -
/// so deleting the production emission leaves a whole-file match standing. Same
/// for a declaration: `fn launch_store_then_kernel` is a PREFIX of the twin's own
/// `fn launch_store_then_kernel_with_correlation<...>(`, so the bare name is
/// satisfied by the twin and cannot prove the original still exists. A needle
/// read out of this text can fail for exactly the reason it is meant to.
fn production_code(source: &str) -> String {
    let gated = test_gated_lines(source);
    source
        .lines()
        .enumerate()
        .filter(|(index, _)| !gated[*index])
        .map(|(_, line)| code_of(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether a line opens an item whose `#[cfg(...)]` predicate includes `test`,
/// e.g. `#[cfg(test)]` or `#[cfg(all(test, windows))]`.
fn gates_on_test(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some(attribute) = trimmed.strip_prefix("#[cfg(") else {
        return false;
    };
    let (predicate, _) = attribute.split_once(']').unwrap_or((attribute, ""));
    predicate
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|term| term == "test")
}

/// Net `{`/`}` balance of one line, ignoring braces inside a string literal and
/// everything after a `//` comment, so a `format!("{}")` cannot skew a depth.
fn brace_balance(line: &str) -> i64 {
    let mut balance = 0_i64;
    let mut characters = line.chars().peekable();
    let mut in_string = false;
    while let Some(character) = characters.next() {
        match character {
            '"' if !in_string => in_string = true,
            '"' => in_string = false,
            '\\' if in_string => {
                characters.next();
            }
            '/' if !in_string && characters.peek() == Some(&'/') => break,
            '{' if !in_string => balance += 1,
            '}' if !in_string => balance -= 1,
            _ => {}
        }
    }
    balance
}

/// One entry per source line: whether that line belongs to an item gated behind
/// `#[cfg(... test ...)]`, the attribute line included.
///
/// A structural guard may only judge code the compiler SHIPS. An item gated on
/// `test` is this suite's own scaffolding: its phase-token constants and its
/// negative assertions spell labels production never emits, and counting them as
/// emissions would make the guard fail on its own harness. Nothing else is
/// excluded, and the exclusion is derived from the real `#[cfg]` predicates
/// rather than from a hand-listed line range, so a new test module cannot escape
/// it either.
fn test_gated_lines(source: &str) -> Vec<bool> {
    let lines: Vec<&str> = source.lines().collect();
    let mut gated = vec![false; lines.len()];
    let mut remaining = 0_i64;
    let mut inside = false;
    // Whether the gated item's block has actually opened yet. A multi-line
    // signature sits between the attribute and its `{` on lines whose net balance is
    // ZERO, so without this flag the close test below would fire on the first
    // parameter line and the rest of the item would read as production code.
    let mut opened = false;
    for index in 0..lines.len() {
        if inside {
            gated[index] = true;
            let balance = brace_balance(lines[index]);
            if balance > 0 {
                opened = true;
            }
            remaining += balance;
            if opened && remaining <= 0 {
                inside = false;
                opened = false;
            }
            continue;
        }
        if !gates_on_test(lines[index]) {
            continue;
        }
        gated[index] = true;
        let own_balance = brace_balance(lines[index]);
        if own_balance > 0 {
            inside = true;
            opened = true;
            remaining = own_balance;
            continue;
        }
        // The gate attribute itself carries no brace, so the gated item's own block
        // opens LATER - and for a multi-line signature it opens several lines later,
        // not on the next one: `#[cfg(all(test, windows))]` in front of
        // `pub(super) fn launch_store_then_kernel<S, K, LF, OF, KF, CF>(` leaves the
        // whole parameter list, the `where` clause and the bounds between the
        // attribute and the `{`. Reading only the next line therefore classified that
        // item's entire body as PRODUCTION code, which is the one thing this reader
        // exists to prevent. The block is therefore located by walking forward to the
        // first line whose net balance opens one; a single-line item (a `use`, a
        // `const`) is closed by its `;` and owns no block at all. A ONE-LINE `fn` IS NOT
        // HANDLED and would be walked past, because it has net balance zero and no
        // trailing `;`; rustfmt forbids that shape and no gated item in the eight
        // delivered files is one, so this is recorded rather than papered over.
        let mut probe = index + 1;
        let mut depth = 0_i64;
        let mut opens = false;
        while probe < lines.len() {
            depth += brace_balance(lines[probe]);
            if depth > 0 {
                opens = true;
                break;
            }
            if lines[probe].trim_end().ends_with(';') {
                break;
            }
            probe += 1;
        }
        if opens {
            inside = true;
            remaining = 0;
        }
    }
    gated
}

/// Body of one `impl` block, from its header to its own closing brace.
fn impl_body(source: &str, header: &str) -> String {
    let at = source
        .find(header)
        .unwrap_or_else(|| panic!("owning file must declare {header}"));
    let rest = &source[at..];
    let end = rest.find("\n}\n").map_or(rest.len(), |offset| offset + 3);
    rest[..end].to_owned()
}

/// The one `HostLifecycleBoundary { ... }` entry of `source` whose `name:` is
/// `name`.
///
/// Seven entries share `caller: "none (exported API; no in-repo caller)"`, so a
/// claim about "the boundary that has no in-repo caller" is only meaningful when
/// it is bound to the single entry it names.
fn lifecycle_boundary_entry(source: &str, name: &str) -> String {
    let marker = format!("name: \"{name}\"");
    let at = source
        .find(&marker)
        .unwrap_or_else(|| panic!("the boundary table must still declare {marker}"));
    let header = source[..at]
        .rfind("HostLifecycleBoundary {")
        .unwrap_or_else(|| {
            panic!("{marker} must be declared inside a HostLifecycleBoundary entry")
        });
    let rest = &source[header..];
    let end = rest
        .find("\n    },")
        .map_or(rest.len(), |offset| offset + "\n    },".len());
    rest[..end].to_owned()
}

/// Whether a trimmed source line opens a function declaration, looking through
/// the visibility chain so `fn`, `pub fn` and `pub(crate) fn` all match.
fn is_fn_declaration(trimmed: &str) -> bool {
    let mut rest = trimmed;
    while let Some(after_pub) = rest.strip_prefix("pub") {
        match after_pub.strip_prefix('(') {
            // `pub(crate)`, `pub(super)`, `pub(in crate::x)`: the whole group is
            // skipped, whatever it contains.
            Some(after_group) => match after_group.find(')') {
                Some(close) => rest = after_group[close + 1..].trim_start(),
                None => return false,
            },
            None => rest = after_pub.trim_start(),
        }
    }
    rest.starts_with("fn ")
}

/// 1-based line of the first source line carrying `needle`.
fn source_line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map_or_else(
            || panic!("the owning file must still carry {needle}"),
            |index| index + 1,
        )
}

/// 0-based line span `(declaration, next declaration)` of `fn <function>(`, so
/// every other claim about that function's body is derived from one place.
fn fn_body_span(source: &str, function: &str) -> (usize, usize) {
    let lines: Vec<&str> = source.lines().collect();
    let needle = format!("fn {function}(");
    let start = lines
        .iter()
        .position(|text| {
            let trimmed = text.trim_start();
            is_fn_declaration(trimmed) && trimmed.contains(&needle)
        })
        .unwrap_or_else(|| panic!("the owning file must still declare fn {function}("));
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, text)| is_fn_declaration(text.trim_start()))
        .map_or(lines.len(), |(index, _)| index);
    (start, end)
}

/// Whether 1-based `line` lies inside the body of `fn <function>(`: after that
/// declaration and before the next function declaration.
///
/// The enclosing symbol is therefore read out of real source instead of trusted
/// from prose, which is exactly how a ruling can name the wrong function without
/// any test noticing.
fn line_is_inside_fn(source: &str, function: &str, line: usize) -> bool {
    let (start, end) = fn_body_span(source, function);
    (start + 1..end).contains(&(line - 1))
}

/// Body source text of `fn <function>(`, declaration line included.
fn fn_body(source: &str, function: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let (start, end) = fn_body_span(source, function);
    lines[start..end].join("\n")
}

/// The declared name of a `fn` declaration line, whether the parameter list is
/// opened directly (`fn name(`) or after a generic parameter list
/// (`fn name<...>(`). `None` for every other line, including a call site.
///
/// The trailing delimiter is what keeps `fn launch_store_then_kernel_with_correlation<...>(`
/// from being read as `launch_store_then_kernel`, whose own declaration is a
/// different line: a name must be followed by `(` or `<` to be a declaration.
fn declared_fn_name(trimmed: &str) -> Option<String> {
    if !is_fn_declaration(trimmed) {
        return None;
    }
    let at = trimmed.find("fn ")? + "fn ".len();
    let rest = &trimmed[at..];
    let name: String = rest
        .chars()
        .take_while(|character| character.is_alphanumeric() || *character == '_')
        .collect();
    let after = &rest[name.len()..];
    if name.is_empty() || !(after.starts_with('(') || after.starts_with('<')) {
        return None;
    }
    Some(name)
}

/// 0-based line span `(declaration, next declaration)` of the declaration of
/// exactly `function`, with or without a generic parameter list.
///
/// `fn_body_span` above keys on the literal `fn name(`, which a generic entry
/// point does not have. Both readers exist because both are load-bearing: the
/// first is unchanged where existing cases depend on it, and this one is where a
/// declaration must be located by its exact name.
fn fn_declared_span(source: &str, function: &str) -> (usize, usize) {
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|text| declared_fn_name(text.trim_start()).as_deref() == Some(function))
        .unwrap_or_else(|| panic!("the owning file must still declare fn {function}"));
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, text)| declared_fn_name(text.trim_start()).is_some())
        .map_or(lines.len(), |(index, _)| index);
    (start, end)
}

/// Body of `fn <function>(` with every comment removed.
///
/// A structural claim about which correlation a call site passes must be read
/// out of CODE: a `//` note that names `&correlation` may not satisfy it, and a
/// `//` note that names `NONE` may not defeat it. `code_only` preserves line
/// structure, so the body still matches the declaration span's line indices.
fn fn_declared_code_body(source: &str, function: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let (start, end) = fn_declared_span(source, function);
    lines[start..end]
        .iter()
        .map(|line| code_of(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Body of `fn <function>(` bounded by its OWN braces, declaration line
/// included, comments stripped.
///
/// `fn_declared_code_body` above stops at the next `fn` declaration of ANY
/// indentation. For a file whose last top-level `fn` is followed by a
/// `#[cfg(test)] mod tests`, that swallows the whole test module: in
/// `launch_artifact_lease.rs` the body of `verify_launch_digest_with_correlation`
/// reached the module's own `const DIGEST_REJECTED_PHASE`, where a phase literal
/// re-declared for the tests reads as a SECOND emission of the function even
/// though the function emits it once. Counting braces from the declaration line
/// instead stops at the function's own closing brace, so every occurrence an
/// all-occurrences scan constrains is an occurrence the function really contains -
/// a narrower scope that is the CORRECT one, never a weaker proof.
///
/// `code_of` preserves line structure and the walk skips string literals, so a
/// `{` inside a rendered format string cannot move the boundary. If the braces
/// never balance the whole remaining file is returned, so a missing closer can
/// only ever widen the scope back to what `fn_declared_code_body` already read.
fn fn_declared_call_body(source: &str, function: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let (start, _) = fn_declared_span(source, function);
    let mut depth = 0_i64;
    let mut opened = false;
    let mut closed_at: Option<usize> = None;
    'scan: for (index, line) in lines[start..].iter().enumerate() {
        let mut in_string = false;
        for character in code_of(line).chars() {
            match character {
                '"' => in_string = !in_string,
                '{' if !in_string => {
                    depth += 1;
                    opened = true;
                }
                '}' if !in_string => {
                    depth -= 1;
                    if opened && depth <= 0 {
                        closed_at = Some(start + index + 1);
                        break 'scan;
                    }
                }
                _ => {}
            }
        }
    }
    lines[start..closed_at.unwrap_or(lines.len())]
        .iter()
        .map(|line| code_of(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The declared parameter list of `fn <function>(`, verbatim from its
/// declaration line through the matching closing parenthesis.
fn declared_parameters(source: &str, function: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let (start, _) = fn_declared_span(source, function);
    let mut text = String::new();
    let mut depth = 0_i64;
    let mut opened = false;
    for line in &lines[start..] {
        text.push_str(line);
        text.push('\n');
        for character in line.chars() {
            if character == '(' {
                depth += 1;
                opened = true;
            } else if character == ')' {
                depth -= 1;
            }
        }
        if opened && depth <= 0 {
            return text;
        }
    }
    panic!("fn {function} must declare a parameter list");
}

/// `(name, type)` of the FIRST declared parameter of `fn <function>(`.
///
/// A parameter-position claim - "this entry point takes the caller's
/// correlation first" - is therefore read out of the real signature, through
/// whatever visibility chain (`fn`, `pub fn`, `pub(crate) fn`) declares it and
/// whatever generic parameter list sits between the name and the parenthesis.
fn first_parameter(source: &str, function: &str) -> (String, String) {
    let parameters = declared_parameters(source, function);
    let needle = format!("fn {function}");
    let at = parameters
        .find(&needle)
        .unwrap_or_else(|| panic!("fn {function} must declare its parameters"));
    let after_name = &parameters[at + needle.len()..];
    let open = after_name
        .find('(')
        .unwrap_or_else(|| panic!("fn {function} must open a parameter list"));
    let rest = &after_name[open + 1..];
    let head = rest.split_once(',').map_or(rest, |(head, _)| head);
    let (name, ty) = head
        .split_once(':')
        .unwrap_or_else(|| panic!("fn {function} must name its first parameter: {head}"));
    (name.trim().to_owned(), ty.trim().to_owned())
}

/// EVERY argument that follows an OCCURRENCE of `marker` inside `body`, up to
/// the next top-level `,` or the matching `)`, each paired with the 1-based line
/// of `body` its occurrence sits on.
///
/// EVERY occurrence is returned, never only the first. A first-occurrence reader
/// constrains ONE emission site and leaves every twin of the same marker free to
/// render a fresh `LaunchPhaseCorrelation::NONE` and still pass: in
/// `kernel_arguments_with_doctor_anchor_with_correlation` the pinned phase
/// literal occurs 5 times, in `approved_locator_with_correlation` its two pinned
/// phase literals occur 2 and 3 times, and `start_approved` calls the forwarded
/// twins 20 times - 15 of which a first-occurrence reader never looked at. A
/// caller asserts against the WHOLE vector, so an unforwarded site names its own
/// occurrence index and line.
///
/// `marker` is a call name (with its `(`) or a frozen phase literal, so a caller
/// reads the argument a real call site really passed. String literals and nested
/// parentheses are tracked so neither a quoted value nor a closure argument can
/// shift the boundary, and each walk starts past the previous occurrence's own
/// end so one site's argument can never be read as the next site's argument.
fn every_argument_after(body: &str, marker: &str) -> Vec<(usize, String)> {
    let mut arguments: Vec<(usize, String)> = Vec::new();
    let mut search_from = 0_usize;
    while let Some(at) = body[search_from..].find(marker) {
        // `find` on the slice returns an offset RELATIVE to `search_from`, so
        // the absolute occurrence offset is the sum - and the next walk starts
        // past this occurrence's own marker, never before it.
        let at = search_from + at;
        search_from = at + marker.len();
        let rest = body[search_from..]
            .trim_start_matches(|character: char| character.is_whitespace() || character == ',')
            .to_owned();
        let bytes = rest.as_bytes();
        let mut depth = 0_i64;
        let mut index = 0_usize;
        let mut in_string = false;
        while index < bytes.len() {
            match bytes[index] {
                b'"' => in_string = !in_string,
                b'(' if !in_string => depth += 1,
                b')' | b',' if !in_string && depth == 0 => break,
                b')' if !in_string => depth -= 1,
                _ => {}
            }
            index += 1;
        }
        arguments.push((
            body[..at].lines().count().saturating_add(1),
            rest[..index].trim().to_owned(),
        ));
    }
    assert!(
        !arguments.is_empty(),
        "{marker:?} must appear in the owner body: {body}"
    );
    arguments
}

/// Every argument EVERY call to `callee` passes inside `body`.
fn every_call_argument(body: &str, callee: &str) -> Vec<(usize, String)> {
    every_argument_after(body, &format!("{callee}("))
}

/// The leading identifier of one rendered argument, ignoring a leading `&`.
///
/// Whether the callee takes the correlation by reference or already by value
/// decides whether a real call site writes `correlation` or `&correlation`, so
/// the borrow marker is not the claim. What IS the claim is that the argument's
/// first identifier is exactly the caller's own binding - and a fresh
/// `LaunchPhaseCorrelation::NONE` would read as `LaunchPhaseCorrelation`, never
/// as that binding.
fn argument_binding(argument: &str) -> &str {
    argument
        .trim()
        .trim_start_matches('&')
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .next()
        .unwrap_or_default()
}

/// Every double-quoted literal of one code line.
fn quoted_literals(code: &str) -> Vec<&str> {
    code.split('"').skip(1).step_by(2).collect()
}

/// One source expression with every whitespace run removed, so a builder chain
/// split across lines compares equal to the same chain written on one.
///
/// A correlation root is a multi-line expression in real source - `correlation`
/// on one line and its chained `.with_*` calls on the next - so a needle
/// containing spaces would never match it. Removing whitespace is a lossless
/// normalisation here: no Rust expression can contain whitespace that changes
/// its meaning other than inside a string literal, and the values compared are
/// builder chains, not strings.
fn squash(text: &str) -> String {
    text.split_whitespace().collect()
}

/// Whether a literal is a Host diagnostic phase token that claims readiness.
/// The `host.` prefix keeps prose ("already", "not ready", a readiness
/// evidence field) out of the rule: only an emitted label counts.
fn is_readiness_label(literal: &str) -> bool {
    literal.starts_with("host.") && (literal.contains("readiness") || literal.contains("-ready"))
}

/// Strict structural guard: a readiness label may exist only inside the
/// activation owner's `active` body, in exactly one of the eight files.
///
/// Strictness is preserved by exclusion, not by loosening: only items the
/// compiler drops for `test` builds are skipped, so a commented-out emission
/// still cannot satisfy the guard (`code_of` strips it first) and a label
/// anywhere outside the owner span still fails. Two lines may therefore own the
/// claim - the two emissions inside `DurableKernelActivationDriver::active`.
fn assert_readiness_owned_only_by_activation_active(sources: &[(String, String)]) {
    let mut owners: Vec<String> = Vec::new();
    for (path, source) in sources {
        let span = if path == READINESS_OWNER_FILE {
            Some(readiness_owner_span(source))
        } else {
            None
        };
        let gated = test_gated_lines(source);
        for (index, line) in source.lines().enumerate() {
            if gated[index] {
                continue;
            }
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

// The supervision-record contour is the one reachable seam that is HANDED the
// caller's own identities and then drives a typed-refusal arm, so its refusal
// record is real evidence that a refusal carries the caller-held identities
// instead of only its typed reason. Both entry points are `#[cfg(windows)]` in
// the library target, exactly like the rest of this issue's corpus.

/// The caller's own supervision table: the five canonical topology rows bound to
/// an installation identity and a Host epoch sequence the caller already holds.
///
/// Every cell is a synthetic, non-secret label. No real path, credential, nonce
/// or payload value is ever produced by this target.
#[cfg(windows)]
fn supervision_table() -> SupervisionRecordTable {
    SupervisionRecordTable {
        wire: SUPERVISION_RECORD_WIRE.to_owned(),
        installation: "installation-7".to_owned(),
        host_epoch_sequence: 11,
        host_lineage: "lineage-978".to_owned(),
        rows: SUPERVISION_RECORD_COMPONENTS
            .iter()
            .map(|component| SupervisionComponentRecord {
                component: (*component).to_owned(),
                artifact: "a".repeat(64),
                descriptor: "b".repeat(64),
                profile: "system_service".to_owned(),
                identity: "synthetic-identity-978".to_owned(),
                owner: "synthetic-owner-978".to_owned(),
                job: "synthetic-job-978".to_owned(),
                journal_or_root: "synthetic-root-978".to_owned(),
                generation: "synthetic-generation-978".to_owned(),
                restart_policy: "synthetic-policy-978".to_owned(),
            })
            .collect(),
    }
}

/// The file name `publish_supervision_record_table` publishes to, read out of
/// the real owning file's own `SUPERVISION_RECORD_FILE_NAME` declaration rather
/// than hand-copied into this target.
///
/// The constant lives in a private module that is not re-exported, so it cannot
/// be imported here; reading the declaration keeps the "nothing was created"
/// claim bound to the path the seam really writes, so a renamed constant cannot
/// leave this target asserting about a file the seam never produces.
#[cfg(windows)]
fn supervision_record_file_name() -> String {
    let scm = manifest_source("src/scm_launch.rs");
    let declaration = "pub const SUPERVISION_RECORD_FILE_NAME: &str = \"";
    let at = scm
        .find(declaration)
        .unwrap_or_else(|| panic!("scm_launch.rs must still declare {declaration:?}"));
    let rest = &scm[at + declaration.len()..];
    let close = rest
        .find('"')
        .unwrap_or_else(|| panic!("SUPERVISION_RECORD_FILE_NAME must carry a string value"));
    rest[..close].to_owned()
}

/// Real execution of `publish_supervision_record_table` against a state root
/// that does not exist, so the seam itself drives its publication arm to a typed
/// refusal: the durable staging write cannot create the file.
///
/// Nothing is created, no SCM call is made, no FFI is acquired, and no process is
/// launched. The refusal record itself is read back out of the scoped subscriber.
#[cfg(windows)]
fn execute_supervision_publication_refusal(
    state_root: &std::path::Path,
    table: &SupervisionRecordTable,
) -> (Result<(), String>, Vec<CapturedRecord>) {
    let outcome = std::cell::RefCell::new(None);
    let records = record_emit(|| {
        let published = publish_supervision_record_table(state_root, table)
            .map_err(|error| host_error_text(&error));
        *outcome.borrow_mut() = Some(published);
    });
    let captured = outcome.borrow_mut().take().expect("captured");
    (captured, records)
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

    // Honest reachability is pinned, not prose: every seam this target really
    // executes, every private owner whose proof is an inline case, and every
    // positive arm no eliot-host seam can construct.
    assert!(
        !fixture_list(&fixture, "reachable_seams").is_empty(),
        "the fixture must pin the seams this target executes"
    );
    assert!(
        !fixture_list(&fixture, "unreachable_positive_arms").is_empty(),
        "the fixture must pin what no eliot-host seam can construct"
    );
    let inline_owners = fixture["inline_case_owners"]
        .as_object()
        .expect("the fixture must pin the inline case owners");
    assert!(
        !inline_owners.is_empty(),
        "the fixture must name the private owners of the inline cases"
    );
    for (case, entries) in inline_owners {
        let owners = entries
            .as_array()
            .unwrap_or_else(|| panic!("inline_case_owners.{case} must be a list"))
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("inline owner entries must be strings"))
            })
            .collect::<Vec<_>>();
        assert!(!owners.is_empty(), "case {case} must name an inline owner");
        for owner in owners {
            let (path, symbol) = owner
                .split_once(':')
                .unwrap_or_else(|| panic!("inline owner must be path:symbol, got {owner}"));
            let leaf = symbol.rsplit("::").next().unwrap_or(symbol);
            assert!(
                manifest_source(path).contains(&format!("fn {leaf}")),
                "case {case}: {path} must still own {symbol}"
            );
            assert!(
                !path.starts_with("src/lib.rs"),
                "case {case}: an inline owner is the private module's own file"
            );
        }
    }

    // #978 W2/AUD3: every delivered twin is private, `pub(crate)` or `pub(super)` inside
    // private module, so this target cannot call one and never could. The
    // fixture therefore maps each twin to the INLINE OWNER CASE in its own file
    // that really does execute it, and this proves that mapping against real
    // source twice over: the case must exist as a declaration in that file, and
    // the twin must really be called inside that case. A mapping that named a
    // case which does not drive the twin would be prose, not proof.
    let twin_cases = fixture["inline_case_owner_cases"]
        .as_object()
        .expect("the fixture must map each delivered twin to its inline owner case");
    assert!(
        !twin_cases.is_empty(),
        "the fixture must name the inline owner case of every delivered twin"
    );
    for (owner, case) in twin_cases {
        let (path, symbol) = owner
            .split_once(':')
            .unwrap_or_else(|| panic!("a twin owner must be path:symbol, got {owner}"));
        let leaf = symbol.rsplit("::").next().unwrap_or(symbol);
        let case = case
            .as_str()
            .unwrap_or_else(|| panic!("an inline owner case must be a string, got {case}"));
        let source = manifest_source(path);
        let (case_start, case_end) = fn_declared_span(&source, case);
        assert!(
            case_start < case_end && case_end <= source.lines().count(),
            "{path}: the inline owner case {case} must be a real declaration in its own file"
        );
        let case_body = fn_declared_code_body(&source, case);
        assert!(
            case_body.contains(&format!("{leaf}(")),
            "{path}: the inline owner case {case} must really drive {symbol}, or the mapping is prose: {case_body}"
        );
        assert!(
            leaf.ends_with("_with_correlation"),
            "{path}: {symbol} must be one of this delivery's forwarding twins, since an original signature is proved by executing the original"
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
    let sibling_code = [
        "src/scm_launch.rs",
        "src/store_kernel_launch_sequence.rs",
        "src/kernel_activation_driver.rs",
        "src/kernel_front_door_client.rs",
    ]
    .map(|path| code_only(&manifest_source(path)))
    .join("\n");
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
            !sibling_code.contains(&token),
            "the retired token {token:?} must not be emitted anywhere"
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
    // `execute_launch_parse` renders the typed error through `HostError::to_string()`
    // and `HostError::Platform` is declared `#[error("host platform: {0}")]` in
    // `lib.rs`, so the observable refusal carries that prefix in front of its own
    // reason. Asserted here ONCE against the real type and then spelled out in full at
    // every site, so a change to the prefix cannot move the expectation together with
    // the production text it is supposed to pin.
    assert_eq!(
        HostError::Platform("invalid Host launch argv: probe".to_owned()).to_string(),
        "host platform: invalid Host launch argv: probe",
        "every pinned argv refusal below is HostError::Platform's Display over the argv reason"
    );
    for (label, args, reason) in &cases {
        let (parsed, records) = execute_launch_parse(args);
        assert_eq!(
            parsed,
            Err(format!("host platform: invalid Host launch argv: {reason}")),
            "{label} must keep its exact typed reason, host platform: prefix included"
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
            "host platform: invalid Host launch argv: config descriptor path must be absolute and valid"
                .to_owned()
        ),
        "a relocated descriptor locator must keep its exact typed reason, host platform: prefix included"
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
        Err(
            "host platform: invalid Host launch argv: config descriptor digest is not valid text"
                .to_owned()
        ),
        "a substituted digest must keep its exact typed reason, host platform: prefix included"
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
        assert_frozen_correlation_slots(detail, &keys);
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

    // #978 W2/AUD3, positive half, proved from a REAL captured record.
    //
    // The defect this closes is that a boundary which RECEIVES an already-held
    // handle emitted its phase records on a bare `NONE`, so installation,
    // generation and fence rendered `missing` on same-operation records whose
    // caller had already resolved them. `validate_host_scm_bootstrap` is such a
    // seam and this target can really execute it: it is handed the caller's
    // admitted `HostLaunchOptions` and builds its bounded correlation from the
    // installation handle, the transaction-plan generation and the approved
    // config-descriptor digest that handle already holds. Every value below is
    // read back out of the record the executed seam emitted and compared with the
    // identity the caller retained; nothing here composes an expected record, and
    // no slot may be filled with a value the executed code did not hold.
    //
    // WHAT THIS HALF IS, stated because the delivered twins are NOT reachable
    // from here: `validate_host_scm_bootstrap` is declared in `src/scm_launch.rs`,
    // a file this delivery does not modify, and it forwarded its correlation
    // before #978. Its record therefore proves the forwarding PROPERTY and the
    // slot rendering on a REACHABLE, ALREADY-FORWARDING seam - which is exactly
    // what the fixture's `proves` field is required to say. It does NOT prove any
    // delivered twin's rendered record: all eight twins of this delivery are
    // private, `pub(crate)` or `pub(super)` inside a private module, so an integration
    // cannot call one and never could, and each twin's own rendered record is its
    // inline owner case in its own file, mapped by `inline_case_owners`. The twin
    // forwarding itself is proved below from real source bytes.
    let forwarded = fixture["executed_forwarded_correlation"]["3"]
        .as_object()
        .expect("the fixture must pin case 3's executed forwarded-correlation seam");
    assert_eq!(
        forwarded["seam"].as_str(),
        Some("validate_host_scm_bootstrap"),
        "case 3's forwarded record must come from the seam the fixture names"
    );
    assert_eq!(
        forwarded["proves"].as_str(),
        Some(EXECUTED_SEAM_PROVES),
        "case 3 must state that its executed record proves the forwarding property on a reachable, already-forwarding seam, never a delivered twin's own rendered record"
    );
    assert_eq!(
        forwarded["delivered_twin_records_owner"].as_str(),
        Some(EXECUTED_SEAM_TWIN_OWNER_MAP),
        "case 3 must name inline_case_owners as where the delivered twins' own rendered records are proven"
    );
    assert_eq!(
        forwarded["seam_is_a_delivered_twin"].as_bool(),
        Some(false),
        "the executed seam is a reachable seam this delivery did not add, so it is not one of the delivered twins"
    );
    let forwarded_phase = forwarded["phase"]
        .as_str()
        .expect("the fixture must pin case 3's forwarded phase token");
    let marker = missing_marker(&fixture);
    let bound_slots = object_list(forwarded, "bound_slots");
    let declared_absent = object_list(forwarded, "absent_slots");
    let identity_keys = identity_correlation_keys(&keys);
    assert_eq!(
        bound_slots.len() + declared_absent.len(),
        identity_keys.len(),
        "case 3 must declare every frozen IDENTITY slot as either bound or explicitly absent, and the frozen phase label `phase` is excluded because the renderer always emits it first and no seam ever holds or drops it: bound {bound_slots:?} + absent {declared_absent:?} must cover exactly these {identity_keys:?} out of the frozen {keys:?}"
    );
    // The count above is a bare sum, and a sum cannot see a slot declared BOTH
    // bound and explicitly absent - two contradictory claims that still add up.
    // The declaration must be a strict SORTED PARTITION of the frozen identity
    // keys: disjoint, no gap, no overlap, each exactly once.
    for slot in bound_slots.iter().chain(declared_absent.iter()) {
        assert!(
            identity_keys.contains(slot),
            "case 3 declared a slot outside the frozen identity keys {identity_keys:?}: {slot:?}"
        );
    }
    for slot in &bound_slots {
        assert!(
            !declared_absent.contains(slot),
            "case 3 declared {slot:?} both bound and explicitly absent: bound {bound_slots:?} absent {declared_absent:?}"
        );
    }
    for slot in &declared_absent {
        assert!(
            !bound_slots.contains(slot),
            "case 3 declared {slot:?} both explicitly absent and bound: bound {bound_slots:?} absent {declared_absent:?}"
        );
    }
    let mut case3_cover: Vec<String> = bound_slots
        .iter()
        .chain(declared_absent.iter())
        .cloned()
        .collect();
    let mut case3_expected = identity_keys.clone();
    case3_cover.sort();
    case3_expected.sort();
    assert_eq!(
        case3_cover, case3_expected,
        "case 3's declared slots must cover the frozen identity keys exactly once each, with no gap and no overlap: bound {bound_slots:?} absent {declared_absent:?} of {identity_keys:?}"
    );

    let bootstrap_options = admitted_launch_options();
    let retained_bootstrap = RetainedLaunch::of(&bootstrap_options);
    let (bootstrap_refusal, bootstrap_records) = execute_scm_bootstrap(&bootstrap_options);
    assert_eq!(
        bootstrap_refusal,
        Err(forwarded["typed_refusal"]
            .as_str()
            .expect("the fixture must pin case 3's typed refusal")
            .to_owned()),
        "the executed seam must really refuse, deterministically and before any SCM readback"
    );
    let bootstrap_details = detail_records(&bootstrap_records);
    assert_eq!(
        phase_tokens(
            &bootstrap_details,
            &fixture_list(&fixture, "sibling_phase_details")
        ),
        vec![forwarded_phase.to_owned()],
        "one executed operation emits exactly the forwarded phase this fixture pins"
    );
    let forwarded_detail = bootstrap_details
        .first()
        .expect("the executed seam must emit its requested record")
        .detail();
    assert_frozen_correlation_slots(forwarded_detail, &keys);
    assert_eq!(
        captured_slot(forwarded_detail, &keys, "installation"),
        retained_bootstrap.installation,
        "the forwarded installation slot must carry the identity the caller actually held: {forwarded_detail}"
    );
    assert_eq!(
        captured_slot(forwarded_detail, &keys, "generation"),
        retained_bootstrap.generation.to_string(),
        "the forwarded generation slot must carry the caller's retained generation: {forwarded_detail}"
    );
    assert_eq!(
        captured_slot(forwarded_detail, &keys, "artifact"),
        retained_bootstrap.digest,
        "the forwarded artifact slot must carry the caller's retained approved digest: {forwarded_detail}"
    );
    for slot in &bound_slots {
        assert_ne!(
            captured_slot(forwarded_detail, &keys, slot),
            marker,
            "a slot the caller held must never render the frozen missing marker: {forwarded_detail}"
        );
    }
    assert_eq!(
        absent_correlation_slots(forwarded_detail, &keys, &marker),
        declared_absent,
        "only the slots the caller genuinely does not hold may render the frozen missing marker: {forwarded_detail}"
    );

    // #978 W2/AUD3, the private half of the same contour, bound to real source.
    //
    // The approved-start contour that names the counterexample is private and
    // Windows-only, so its RENDERED records are the inline owner cases in the
    // owning files (`inline_case_owners`). What this target can still prove from
    // real bytes is the whole forwarding chain: each correlated entry point takes
    // the caller's correlation as its FIRST parameter, `start_approved` calls
    // every one of them with the correlation it builds from its own held handles,
    // and each pre-existing signature is unchanged and still delegates with
    // `NONE`. A twin that reverted to a fresh `NONE`, or a caller that stopped
    // forwarding, fails here.
    let contour = fixture["forwarded_correlation_contour"]
        .as_object()
        .expect("the fixture must pin the forwarded-correlation contour");
    let binding = contour["correlation_binding"]
        .as_str()
        .expect("the fixture must pin the correlation binding name");
    let first_parameter_type = contour["first_parameter_type"]
        .as_str()
        .expect("the fixture must pin the correlated parameter type");
    let entries = fixture_list(&fixture, "correlated_entry_points");
    assert_eq!(
        object_list(contour, "forwarded_callers"),
        entries
            .iter()
            .map(|entry| {
                entry
                    .split_once(':')
                    .unwrap_or_else(|| {
                        panic!("a correlated entry point must be path:fn symbol, got {entry}")
                    })
                    .1
                    .strip_prefix("fn ")
                    .unwrap_or_else(|| {
                        panic!("a correlated entry point must name fn <symbol>, got {entry}")
                    })
                    .to_owned()
            })
            .collect::<Vec<String>>(),
        "every correlated entry point must be named as a forwarded caller, in the same order"
    );

    // The twin SET itself is derived from SOURCE here, not trusted from the fixture:
    // every `fn <name>_with_correlation` declaration the eight delivered files really
    // carry must be pinned by one of the two maps, and neither map may name a twin the
    // source does not declare. Without this, a ninth forwarding entry point added
    // later and listed in neither map would be reachable from no assertion at all -
    // the exact failure mode the two descriptor validators had. Comments are stripped
    // first, because a doc line naming a twin in prose is a mention, not a
    // declaration.
    let mut source_twins: Vec<String> = Vec::new();
    for (path, _) in OBSERVER_HELPERS {
        for line in manifest_source(path).lines() {
            let Some((_, after_fn)) = code_of(line).split_once("fn ") else {
                continue;
            };
            let name = after_fn.split(['(', '<']).next().unwrap_or_default().trim();
            if name.ends_with("_with_correlation") {
                source_twins.push(format!("{path}:fn {name}"));
            }
        }
    }
    source_twins.sort();
    let mut declared_twins = entries.clone();
    declared_twins.extend(
        fixture["correlated_entry_points_excluded"]
            .as_array()
            .expect("the fixture must declare every correlated entry point it excludes")
            .iter()
            .map(|excluded| {
                excluded["twin"]
                    .as_str()
                    .expect("an excluded twin must be spelled path:fn symbol")
                    .to_owned()
            }),
    );
    declared_twins.sort();
    assert_eq!(
        declared_twins, source_twins,
        "the two fixture maps must pin exactly the forwarding entry points the source declares"
    );

    // FIX 1: the list above is the SUBJECT SET of the all-sites call-site scan
    // below, so a twin that is missing from it is a twin whose every call site is
    // read by no assertion - and that is exactly how the two approved-descriptor
    // validators were unpinned: `start_approved` calls both with `&correlation`
    // (host_job_launch.rs:1666 and host_job_launch.rs:1710), both are declared in
    // `inline_case_owners` and `inline_case_owner_cases`, and before this
    // correction neither appeared here, so reverting either one to a fresh
    // `LaunchPhaseCorrelation::NONE` failed nothing in this suite.
    //
    // The list is therefore bound to the fixture's OWN map of delivered twins,
    // both spelled the same way, and the count is pinned rather than described.
    let twin_cases = fixture["inline_case_owner_cases"]
        .as_object()
        .expect("the fixture must map each delivered twin to its inline owner case");
    let declared_count = fixture["correlated_entry_points_count"]
        .as_u64()
        .expect("the fixture must pin the correlated entry point count");
    assert_eq!(
        entries.len() as u64,
        declared_count,
        "correlated_entry_points must hold exactly the count the fixture pins: {entries:?}"
    );
    assert_eq!(
        declared_count, 7,
        "the approved-start contour forwards seven twins, each called with the caller's correlation: approved_locator_with_correlation 7 sites, open_launch_lease_with_correlation 6, verify_launch_digest_with_correlation 5, kernel_arguments_with_doctor_anchor_with_correlation 1, launch_store_then_kernel_with_correlation 1, validate_store_bootstrap_descriptor_with_correlation 1, validate_eliotd_launch_descriptor_with_correlation 1 - 22 of the contour's 31 &correlation-consuming sites in total: {entries:?}"
    );
    let mut listed_twins: Vec<String> = Vec::new();
    for entry in &entries {
        let (path, symbol) = entry.split_once(':').unwrap_or_else(|| {
            panic!("a correlated entry point must be path:fn symbol, got {entry}")
        });
        let leaf = symbol.strip_prefix("fn ").unwrap_or_else(|| {
            panic!("a correlated entry point must name fn <symbol>, got {entry}")
        });
        let twin = format!("{path}:{leaf}");
        assert!(
            twin_cases.contains_key(&twin),
            "every correlated entry point must be one of this delivery's twins, which the fixture already maps to its inline owner case: {entry}"
        );
        listed_twins.push(twin);
    }
    // The delivery's EIGHT twins are all pinned, but not all on this contour:
    // `start_approved` never calls `approved_launch_paths_with_correlation`, whose
    // only production call site is inside `HostJobBranches::launch`. So the set
    // difference must be exactly the exclusions the fixture declares - no twin
    // may go missing quietly, and no phantom twin may be excused.
    let expected_twins: Vec<String> = twin_cases
        .keys()
        .map(|key| {
            let (path, symbol) = key.split_once(':').unwrap_or_else(|| {
                panic!("an inline owner case key must be path:symbol, got {key}")
            });
            format!("{path}:fn {symbol}")
        })
        .collect();
    let excluded: Vec<String> = fixture["correlated_entry_points_excluded"]
        .as_array()
        .expect("the fixture must declare every correlated entry point it excludes")
        .iter()
        .map(|declared| {
            declared["twin"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!("an excluded twin must be spelled path:fn symbol: {declared:?}")
                })
                .to_owned()
        })
        .collect();
    assert_eq!(
        expected_twins.len() as u64,
        declared_count + excluded.len() as u64,
        "the delivered twins must be exactly the correlated entry points plus the declared exclusions: {expected_twins:?} against {excluded:?}"
    );
    // The set difference is taken in the SAME SPELLING on both sides. `listed_twins`
    // above is built without the `fn ` prefix because that is how `inline_case_owner_cases`
    // keys its members, while `expected_twins` and the fixture's `excluded` entries
    // both carry it - so comparing those directly compares 7 unprefixed strings
    // against 9 prefixed ones and can never hold. The delivered twins this contour
    // does NOT call are exactly the declared exclusions, so the comparison is
    // "every twin, minus the exclusions" against the listed entry points.
    let mut listed_with_prefix: Vec<String> = listed_twins
        .iter()
        .map(|twin| twin.replacen(':', ":fn ", 1))
        .collect();
    listed_with_prefix.sort();
    let mut expected_called: Vec<String> = expected_twins
        .iter()
        .filter(|twin| !excluded.contains(twin))
        .cloned()
        .collect();
    expected_called.sort();
    assert_eq!(
        listed_with_prefix, expected_called,
        "the declared exclusions must be exactly the delivered twins this contour does not call, no more and no fewer: listed {listed_twins:?} of {expected_twins:?}, excluded {excluded:?}"
    );
    // An exclusion is only honest while the twin it excuses really is pinned on
    // the contour the fixture names, so the leaf must really be one of that
    // contour's forwarded callees here and not merely excused in prose.
    let branch = fixture["forwarded_correlation_branch_contour"]
        .as_object()
        .expect("the fixture must pin the branch-launch forwarded-correlation contour");
    let branch_forwarded = object_list(branch, "forwarded_callers");
    for declared in fixture["correlated_entry_points_excluded"]
        .as_array()
        .expect("the fixture must declare every correlated entry point it excludes")
    {
        let twin = declared["twin"].as_str().unwrap_or_else(|| {
            panic!("an excluded twin must be spelled path:fn symbol: {declared:?}")
        });
        let symbol = twin
            .split_once(':')
            .unwrap_or_else(|| panic!("an excluded twin must be path:fn symbol, got {twin}"))
            .1;
        let leaf = symbol
            .strip_prefix("fn ")
            .unwrap_or_else(|| panic!("an excluded twin must name fn <symbol>, got {twin}"));
        let pinned_by = declared["pinned_by"].as_str().unwrap_or_else(|| {
            panic!("an excluded twin must name the contour that pins it: {declared:?}")
        });
        assert_eq!(
            pinned_by, "forwarded_correlation_branch_contour",
            "the one delivered twin this contour cannot call is approved_launch_paths_with_correlation, and the contour that pins it is named here: {declared:?}"
        );
        assert!(
            branch_forwarded.iter().any(|callee| callee == leaf),
            "an excluded twin must really be a forwarded callee of the contour the fixture names as pinning it, not merely excused in prose: {twin} is not in {branch_forwarded:?}"
        );
    }
    for entry in &entries {
        let (path, symbol) = entry.split_once(':').unwrap_or_else(|| {
            panic!("a correlated entry point must be path:fn symbol, got {entry}")
        });
        let leaf = symbol.strip_prefix("fn ").unwrap_or_else(|| {
            panic!("a correlated entry point must name fn <symbol>, got {entry}")
        });
        let (name, ty) = first_parameter(&manifest_source(path), leaf);
        assert_eq!(
            name, binding,
            "{path}: {leaf} must take the caller's correlation as its first parameter, got {name:?}"
        );
        assert!(
            ty.starts_with(first_parameter_type),
            "{path}: {leaf} must take a correlation REFERENCE, got {ty:?}"
        );
        // The pre-existing entry point keeps its own signature and keeps
        // delegating with `NONE`, so only the approved-start contour changes.
        let original = leaf.strip_suffix("_with_correlation").unwrap_or_else(|| {
            panic!("{path}: {leaf} must name a new entry point beside an unchanged original")
        });
        let original_body = fn_declared_code_body(&manifest_source(path), original);
        assert!(
            original_body.contains("&LaunchPhaseCorrelation::NONE"),
            "{path}: {original} must keep its exact signature and delegate with NONE: {original_body}"
        );
    }

    let launch_source = manifest_source("src/host_job_launch.rs");
    let caller = contour["caller"]
        .as_str()
        .expect("the fixture must pin the forwarded-correlation caller");
    // Split on the FIRST colon, not the last: the caller is spelled
    // `path:Type::method`, so the path half carries no colon while the symbol
    // half carries two. R splitting yields `path:Type` and therefore made the
    // approved-start contour assertion below compare `src/host_job_launch.rs:
    // HostJobBranches` against `src/host_job_launch.rs` and fail on a caller that
    // is in fact the one the fixture pins.
    let (caller_path, caller_symbol) = caller.split_once(':').unwrap_or_else(|| {
        panic!("the forwarded-correlation caller must be path:symbol, got {caller}")
    });
    let caller_leaf = caller_symbol
        .rsplit("::")
        .next()
        .unwrap_or(caller_symbol)
        .to_owned();
    assert_eq!(
        caller_path, "src/host_job_launch.rs",
        "the forwarded-correlation caller is the approved-start contour"
    );
    assert_eq!(
        caller_symbol, "HostJobBranches::start_approved",
        "the forwarding claims below are read out of the approved-start contour, not some other function"
    );
    let start_body = fn_declared_code_body(&launch_source, &caller_leaf);
    // The same contour read again bounded by its OWN braces, for the call-site
    // scan below: an occurrence walk must see every call this contour really
    // makes and nothing that merely sits after its closing brace.
    let start_call_body = fn_declared_call_body(&launch_source, &caller_leaf);
    assert!(
        start_call_body.len() <= start_body.len(),
        "the approved-start contour's brace-bounded read must terminate INSIDE the span that ends at the next declaration: an equal or shorter read is what proves the brace scan found this function's own closing brace rather than running to end of file"
    );
    for slot in object_list(contour, "bound_slots") {
        assert!(
            start_body.contains(&format!(".with_{slot}(")),
            "the approved-start contour must bind {slot} from a handle it already holds: {start_body}"
        );
    }
    for expression in object_list(contour, "held_slot_bindings") {
        assert!(
            start_body.contains(&expression),
            "the approved-start contour must bind the held handle {expression:?}: {start_body}"
        );
    }
    for callee in object_list(contour, "forwarded_callers") {
        let sites = every_call_argument(&start_call_body, &callee);
        for (index, (line, argument)) in sites.iter().enumerate() {
            assert_eq!(
                argument_binding(argument),
                binding,
                "the approved-start contour must forward its own correlation into {callee} at EVERY call site: site {index} at body line {line} passed {argument:?}"
            );
            assert!(
                !argument.contains("LaunchPhaseCorrelation::NONE"),
                "the approved-start contour must never re-derive the correlation for {callee} at site {index} at body line {line}: {argument:?}"
            );
        }
    }
    // The pinned call-site total, so the scan above is not merely non-vacuous:
    // seven twins at 22 sites, counted from source. A twin dropped from the
    // fixture's list, or a call site deleted from the contour, fails here.
    let declared_callers = object_list(contour, "forwarded_callers");
    let pinned_sites: usize = declared_callers
        .iter()
        .map(|callee| every_call_argument(&start_call_body, callee).len())
        .sum();
    assert_eq!(
        pinned_sites as u64,
        contour["forwarded_call_site_count"]
            .as_u64()
            .expect("the fixture must pin the forwarded call site count"),
        "the approved-start contour must forward its correlation at exactly the pinned number of call sites: {declared_callers:?}"
    );

    // #978, second forwarded-correlation caller edge: `HostJobBranches::launch`.
    //
    // The contour above names only `start_approved`, and its all-sites scan is
    // bounded to that one body - which is correct, because `start_approved` never
    // calls `approved_launch_paths_with_correlation`. But `launch` is a second
    // real forwarding caller: it builds its OWN correlation from the identities it
    // already holds and forwards that binding into that twin at
    // host_job_launch.rs:1016. With no assertion on this edge, reverting it to a
    // fresh `LaunchPhaseCorrelation::NONE` failed nothing anywhere in this suite.
    //
    // Read with the SAME per-occurrence all-sites reader the approved-start check
    // uses, scoped to `launch`'s own braces, so every call site it really makes is
    // constrained and nothing that merely sits after its closing brace is.
    let branch_binding = branch["correlation_binding"]
        .as_str()
        .expect("the fixture must pin the branch contour's correlation binding name");
    let branch_caller = branch["caller"]
        .as_str()
        .expect("the fixture must pin the branch contour's caller");
    // First colon again, for the same reason as the approved-start caller above:
    // the pinned spelling is `path:Type::method`, so splitting on the last colon
    // leaves `path:Type` on the path side.
    let (branch_path, branch_symbol) = branch_caller.split_once(':').unwrap_or_else(|| {
        panic!("the branch forwarded-correlation caller must be path:symbol, got {branch_caller}")
    });
    let branch_leaf = branch_symbol
        .rsplit("::")
        .next()
        .unwrap_or(branch_symbol)
        .to_owned();
    assert_eq!(
        branch_path, "src/host_job_launch.rs",
        "the second forwarded-correlation caller lives in the launch owner file"
    );
    assert_eq!(
        branch_symbol, "HostJobBranches::launch",
        "the second forwarding claim is read out of the branch launch contour, not some other function"
    );
    let branch_source = manifest_source(branch_path);
    let branch_call_body = fn_declared_call_body(&branch_source, &branch_leaf);
    assert!(
        branch_call_body.contains(&format!("fn {branch_leaf}(")),
        "the branch launch contour must really be declared where the fixture says it is, and its scan below must be bounded by its own braces: {branch_call_body}"
    );
    for slot in object_list(branch, "bound_slots") {
        assert!(
            branch_call_body.contains(&format!(".with_{slot}(")),
            "the branch launch contour must bind {slot} from a handle it already holds: {branch_call_body}"
        );
    }
    for expression in object_list(branch, "held_slot_bindings") {
        assert!(
            branch_call_body.contains(&expression),
            "the branch launch contour must bind the held handle {expression:?}: {branch_call_body}"
        );
    }
    let mut branch_sites = 0_usize;
    for callee in object_list(branch, "forwarded_callers") {
        let sites = every_call_argument(&branch_call_body, &callee);
        for (index, (line, argument)) in sites.iter().enumerate() {
            assert_eq!(
                argument_binding(argument),
                branch_binding,
                "the branch launch contour must forward its own correlation into {callee} at EVERY call site: site {index} at body line {line} passed {argument:?}"
            );
            assert!(
                !argument.contains("LaunchPhaseCorrelation::NONE"),
                "the branch launch contour must never re-derive the correlation for {callee} at site {index} at body line {line}: {argument:?}"
            );
        }
        branch_sites += sites.len();
    }
    let declared_branch_callers = object_list(branch, "forwarded_callers");
    assert_eq!(
        branch_sites as u64,
        branch["forwarded_call_site_count"]
            .as_u64()
            .expect("the fixture must pin the branch contour's forwarded call site count"),
        "the branch launch contour must forward its correlation at exactly the pinned number of call sites: {declared_branch_callers:?}"
    );
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
#[allow(
    clippy::too_many_lines,
    reason = "the executed order, the executed refusal record and the private forwarding chain"
)]
fn launch_06_store_before_kernel() {
    let fixture = launch_fixture();
    let sibling_tokens = fixture_list(&fixture, "sibling_phase_details");
    let options_tokens = fixture_list(&fixture, "launch_options_details");
    let keys = fixture_list(&fixture, "correlation_keys");
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
            !code_only(&sequence).contains(&retired),
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

    // The two needles above are whole-file and prefix matches, so both survive
    // deleting what they are supposed to prove. Two stricter readings follow, and
    // both are re-derived from real source rather than from what the weak needles
    // happened to find.
    //
    // (a) `fn launch_store_then_kernel` is a PREFIX of the twin's own
    // declaration, `fn launch_store_then_kernel_with_correlation<...>(`, so the
    // bare name above is satisfied by the twin alone and cannot tell the
    // original from its own replacement. The original's declaration is located by
    // its EXACT name - the only place it can be seen - and it is a `#[cfg(all(test,
    // windows))]` item by design, which is why the assertions further down require it
    // to be ABSENT from production code (`store_kernel_launch_sequence.rs:188`).
    //
    // (b) both live literals occur THREE times in that file - once in the
    // sequence and twice in its own `#[cfg(all(test, windows))] mod tests` - so a
    // whole-file match still stands after the production emission is deleted.
    // `production_code` strips comments and drops every line the compiler drops
    // from a test build, so only a real production emission can satisfy these.
    let production_sequence = production_code(&sequence);
    for live in [
        "host.store-launch store-liveness-proven observed",
        "host.kernel-launch kernel-launched observed",
    ] {
        assert_eq!(
            production_sequence.matches(live).count(),
            1,
            "the sequence must still emit {live:?} from production code exactly once: its own test module re-declares the same literal, so a whole-file match would pass after the production emission is deleted"
        );
    }
    // The identity-free ORIGINAL is `#[cfg(all(test, windows))]` on purpose - the
    // production contour calls the twin, and the gate is what keeps a non-test build
    // free of a dead-code finding without an `allow`. So a CORRECT production-code
    // read must contain the twin and must NOT contain the original. Asserting the
    // original's presence in production code instead would pin the reader's own blind
    // spot: the original's block opens twelve lines after its attribute, so a reader that
    // looked only at the next line classified that test-only body as production.
    assert!(
        production_sequence.contains("fn launch_store_then_kernel_with_correlation<"),
        "the production contour's entry point must be the correlated twin: {production_sequence}"
    );
    assert!(
        !production_sequence.contains("fn launch_store_then_kernel<"),
        "the identity-free original is test-gated, so production code must not contain it: {production_sequence}"
    );
    assert!(
        !production_sequence
            .contains("fn launch_store_then_kernel_with_correlation_with_correlation"),
        "the twin must remain a single new entry point beside an unchanged original"
    );
    // The reader that located the original by EXACT name must also find it, which
    // is the same claim from the declaration reader the other cases use.
    let (original_start, original_end) = fn_declared_span(&sequence, "launch_store_then_kernel");
    assert!(
        original_start < original_end && original_end <= sequence.lines().count(),
        "the ORIGINAL launch_store_then_kernel must still be a real declaration: its exact name resolves to lines {}..{} of {}",
        original_start,
        original_end,
        sequence.lines().count()
    );
    let original_body = fn_declared_code_body(&sequence, "launch_store_then_kernel");
    assert!(
        original_body.contains("&LaunchPhaseCorrelation::NONE"),
        "the original must keep its exact signature and delegate with NONE: {original_body}"
    );

    // #978 W2/AUD3, refusal half, proved from a REAL captured record.
    //
    // A typed-refusal branch of a seam that is HANDED the caller's identities
    // must carry those identities ON THE REFUSAL RECORD, not only its typed
    // reason: the counterexample names the `observe_store` Dead/Unknown arms and
    // the artifact substitution/rejection arms as exactly the places where a
    // refusal record dropped known caller identities onto a bare `NONE`.
    // `publish_supervision_record_table` is the nearest such branch this
    // integration target can really execute - it receives the caller's own
    // `SupervisionRecordTable`, already holding the installation identity and the
    // Host epoch sequence, and is driven to its publication refusal by naming a
    // state root that does not exist, so the durable staging write itself fails.
    // Nothing is created, no SCM call is made, no FFI is acquired and no process
    // is launched; the refusal record below is what the executed seam emitted.
    //
    // WHAT THIS HALF IS, stated because the delivered twins are NOT reachable
    // from here: `publish_supervision_record_table` is declared in
    // `src/scm_launch.rs`, a file this delivery does not modify, and it forwarded
    // its correlation before #978. Its record proves the forwarding PROPERTY and
    // the slot rendering on a REACHABLE, ALREADY-FORWARDING seam - which is
    // exactly what the fixture's `proves` field is required to say. It does NOT
    // prove any delivered twin's rendered record: all eight twins of this delivery
    // are private, `pub(crate)` or `pub(super)` inside a private module, so an integration
    // target cannot call one and never could, and each twin's own rendered record
    // is its inline owner case in its own file, mapped by `inline_case_owners`.
    // That is also why this seam is deliberately NOT one of
    // `correlated_entry_points`: the rule below that every forwarded refusal arm
    // belongs to a correlated entry point governs the delivered twins, and these
    // two reachable seams are exempt from it for exactly that reason.
    let refusal = fixture["executed_forwarded_correlation"]["6"]
        .as_object()
        .expect("the fixture must pin case 6's executed forwarded-correlation seam");
    assert_eq!(
        refusal["seam"].as_str(),
        Some("publish_supervision_record_table"),
        "case 6's refusal record must come from the seam the fixture names"
    );
    assert_eq!(
        refusal["proves"].as_str(),
        Some(EXECUTED_SEAM_PROVES),
        "case 6 must state that its executed refusal record proves the forwarding property on a reachable, already-forwarding seam, never a delivered twin's own rendered record"
    );
    assert_eq!(
        refusal["delivered_twin_records_owner"].as_str(),
        Some(EXECUTED_SEAM_TWIN_OWNER_MAP),
        "case 6 must name inline_case_owners as where the delivered twins' own rendered records are proven"
    );
    assert_eq!(
        refusal["seam_is_a_delivered_twin"].as_bool(),
        Some(false),
        "the executed seam is a reachable seam this delivery did not add, so it is not one of the delivered twins"
    );
    let refusal_phase = refusal["phase"]
        .as_str()
        .expect("the fixture must pin case 6's refusal phase token");
    assert!(
        sibling_tokens.iter().any(|token| token == refusal_phase),
        "case 6's refusal phase must be a frozen sibling phase token: {refusal_phase:?}"
    );
    assert!(
        !refusal["typed_refusal"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .is_empty(),
        "the fixture must state which typed refusal case 6 drives"
    );
    assert!(
        !refusal["bound_slots"]
            .as_array()
            .expect("the fixture must declare case 6's bound slots")
            .is_empty(),
        "the fixture must declare the slots case 6's refusal record binds"
    );
    assert!(
        !refusal["absent_slots"]
            .as_array()
            .expect("the fixture must declare case 6's absent slots")
            .is_empty(),
        "the fixture must declare the slots case 6's refusal record leaves absent"
    );

    // Strict slot accounting, on EVERY host and in the SHARED path, because the
    // executed half below is Windows-only while the declaration it describes is
    // not: on Windows the declaration was only ever checked by a bare SUM, and a
    // slot declared BOTH bound and explicitly absent passes a sum while claiming
    // two contradictory things. The declaration must be a strict SORTED PARTITION
    // of the frozen identity keys - disjoint, no gap, no overlap, each exactly
    // once - and the frozen phase label `phase` stays excluded because the
    // renderer always emits it first and no seam ever holds or drops it.
    let bound_slots = object_list(refusal, "bound_slots");
    let declared_absent = object_list(refusal, "absent_slots");
    let identity_keys = identity_correlation_keys(&keys);
    assert!(
        !bound_slots.is_empty() && !declared_absent.is_empty(),
        "case 6 must declare both the slots its refusal record binds and the slots it leaves absent: bound {bound_slots:?} absent {declared_absent:?}"
    );
    for slot in bound_slots.iter().chain(declared_absent.iter()) {
        assert!(
            identity_keys.contains(slot),
            "case 6 declared a slot outside the frozen identity keys {identity_keys:?}: {slot:?}"
        );
    }
    for slot in &bound_slots {
        assert!(
            !declared_absent.contains(slot),
            "case 6 declared {slot:?} both bound and explicitly absent: bound {bound_slots:?} absent {declared_absent:?}"
        );
    }
    for slot in &declared_absent {
        assert!(
            !bound_slots.contains(slot),
            "case 6 declared {slot:?} both explicitly absent and bound: bound {bound_slots:?} absent {declared_absent:?}"
        );
    }
    let mut declared_cover: Vec<String> = bound_slots
        .iter()
        .chain(declared_absent.iter())
        .cloned()
        .collect();
    let mut expected_cover = identity_keys.clone();
    declared_cover.sort();
    expected_cover.sort();
    assert_eq!(
        declared_cover, expected_cover,
        "case 6's declared slots must cover the frozen identity keys exactly once each, with no gap and no overlap: bound {bound_slots:?} absent {declared_absent:?} of {identity_keys:?}"
    );
    assert_eq!(
        bound_slots.len() as u64 + declared_absent.len() as u64,
        identity_keys.len() as u64,
        "the strict partition above already implies the count, and it is stated here so the two cannot drift apart: bound {bound_slots:?} absent {declared_absent:?} of {identity_keys:?}"
    );
    #[cfg(windows)]
    {
        let marker = missing_marker(&fixture);
        let table = supervision_table();
        let absent_root = synthetic_state_root().join("absent-supervision-record-root");
        assert!(
            !absent_root.exists(),
            "the refusal root must not exist, or the publication would succeed: {absent_root:?}"
        );
        let (published, publication_records) =
            execute_supervision_publication_refusal(&absent_root, &table);
        assert!(
            published.is_err(),
            "the executed seam must really refuse its publication arm: {published:?}"
        );
        let publication_details = detail_records(&publication_records);
        assert_eq!(
            phase_tokens(&publication_details, &sibling_tokens),
            vec![
                "host.scm-launch supervision record publish requested".to_owned(),
                refusal_phase.to_owned(),
            ],
            "a publication that never committed emits its request and its refusal, nothing else: {publication_details:?}"
        );
        let refusal_record = publication_details
            .into_iter()
            .find(|record| record.detail().contains(refusal_phase))
            .expect("the executed seam must emit its refusal record");
        let refusal_detail = refusal_record.detail();
        assert_frozen_correlation_slots(refusal_detail, &keys);
        assert_eq!(
            captured_slot(refusal_detail, &keys, "installation"),
            table.installation,
            "the refusal record must carry the installation identity the caller already held: {refusal_detail}"
        );
        assert_eq!(
            captured_slot(refusal_detail, &keys, "generation"),
            table.host_epoch_sequence.to_string(),
            "the refusal record must carry the Host epoch sequence the caller already held: {refusal_detail}"
        );
        for slot in &bound_slots {
            assert_ne!(
                captured_slot(refusal_detail, &keys, slot),
                marker,
                "a refusal record must not drop a caller-held identity to the frozen missing marker: {refusal_detail}"
            );
        }
        assert_eq!(
            absent_correlation_slots(refusal_detail, &keys, &marker),
            declared_absent,
            "a refusal record may leave absent only the slots the caller does not hold: {refusal_detail}"
        );
        // The refusal arm's OWN observable result, replacing an assertion that
        // could not fail. The old one compared a borrowed
        // `&SupervisionRecordTable` with a second call to a pure constructor, so
        // it compared this target's own fixture with itself: no mutation of the
        // refused publication, and no change in what the seam returned, could ever
        // break it. What is asserted now is what the seam actually produced.
        let refusal_text = published
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("the refused publication must return a typed error"));
        assert!(
            !refusal_text.trim().is_empty(),
            "the seam's typed refusal must carry the platform's own error text, so this is a real refusal and not an empty stand-in: {refusal_text:?}"
        );
        // WHICH typed refusal fired, re-derived from the seam's own source: this
        // fixture claims the arm where the durable staging write cannot create its
        // file, so the returned text can be neither of the seam's two
        // pre-write refusals ("supervision record is not publishable" from
        // `table.validate`, and "supervision record exceeds its bounded size"),
        // nor its post-write "supervision record atomic replace failed". A bare
        // `is_err()` cannot tell those apart; this can.
        for other_refusal in [
            "supervision record is not publishable",
            "supervision record exceeds its bounded size",
            "supervision record atomic replace failed",
        ] {
            assert!(
                !refusal_text.contains(other_refusal),
                "case 6 claims the refused durable staging write, so the seam must not have refused one of its other arms instead: {other_refusal:?} in {refusal_text:?}"
            );
        }
        // No artefact of the refused publication exists: not the absent state
        // root the seam was handed, and not the record path it names for itself
        // inside that root.
        let record_file = supervision_record_file_name();
        assert!(
            !absent_root.exists() && !absent_root.join(&record_file).exists(),
            "a refused publication must leave no artefact: neither the absent state root {absent_root:?} nor the record path {record_file:?} beneath it may exist"
        );
    }

    // The `#[cfg(windows)]` arm above is gated on the SEAM, not on the claim: the
    // durable staging write it drives to its refusal exists only on Windows, so
    // off Windows that executed half genuinely cannot run. What CAN be asserted
    // on any host must therefore still be asserted here, or the case would reduce
    // to asserting nothing about this contour off Windows.
    //
    // The strict slot accounting - disjointness, no gap, no overlap, sorted
    // partition over the frozen identity keys - now runs in the SHARED path above,
    // on every host, because a bare sum cannot see a slot declared both bound and
    // explicitly absent. So the mirror below keeps only what only IT can add: the
    // source-side checks, which have no executed half anywhere and are therefore
    // the only assertions about this seam that are genuinely off-Windows-only.
    #[cfg(not(windows))]
    {
        let seam = refusal["seam"]
            .as_str()
            .expect("the fixture must pin case 6's executed seam name");
        assert!(
            fixture_list(&fixture, "reachable_seams")
                .iter()
                .any(|reachable| reachable == seam),
            "case 6's executed seam {seam:?} must be a seam this target really executes: {seam:?} is not in reachable_seams"
        );
        let scm = manifest_source("src/scm_launch.rs");
        assert!(
            code_only(&scm).contains(refusal_phase),
            "case 6's declared refusal phase must still be real code in the owning file: {refusal_phase:?}"
        );
        for entry in fixture_list(&fixture, "correlated_entry_points") {
            let (path, symbol) = entry.split_once(':').unwrap_or_else(|| {
                panic!("a correlated entry point must be path:fn symbol, got {entry}")
            });
            let leaf = symbol.strip_prefix("fn ").unwrap_or_else(|| {
                panic!("a correlated entry point must name fn <symbol>, got {entry}")
            });
            assert!(
                manifest_source(path).contains(&format!("fn {leaf}")),
                "the private forwarding proof below must still have a real subject: {path} must still declare {symbol}"
            );
        }
    }

    // #978 W2/AUD3, the named refusal arms of the private sequence and the
    // artifact lease, bound to real source.
    //
    // Those arms live in private modules, so their own RENDERED records are the
    // inline owner cases in the owning files, mapped per twin by
    // `inline_case_owner_cases` and proved against real source in case 1. What
    // this target can still make load-bearing is that each correlated entry point
    // renders the FORWARDED correlation at EVERY occurrence of each of its refusal
    // phases inside its own body - never a fresh `NONE` at any of them - and that
    // the two liveness arms still name their typed reason on top of the forwarded
    // identities instead of replacing them. Every occurrence is checked, because
    // one phase literal is emitted from several arms: the Doctor-anchor seam
    // renders its typed rejection 5 times and the locator twin 3 times, so a
    // first-occurrence reader would leave 7 sites free to revert.
    let entries = fixture_list(&fixture, "correlated_entry_points");
    let binding = fixture["forwarded_correlation_contour"]["correlation_binding"]
        .as_str()
        .expect("the fixture must pin the correlation binding name");
    // The refusal arms that also carry a TYPED reason, and the exact value each one
    // must bind. The fixture declares them as `<phase>: <typed reason kind>`, so
    // the phase and its reason value cannot drift apart, and the values are read
    // out of the real source vocabulary rather than hand-copied.
    let reason_values = fixture["forwarded_reason_arms"]
        .as_object()
        .expect("the fixture must name the refusal arms that also carry a typed reason");
    assert!(
        !reason_values.is_empty(),
        "the fixture must name the refusal arms that also carry a typed reason"
    );
    let reason_phases: Vec<String> = reason_values.keys().cloned().collect();
    let refusal_arms = fixture["forwarded_refusal_arms"]
        .as_object()
        .expect("the fixture must pin the forwarded refusal arms");
    assert!(
        !refusal_arms.is_empty(),
        "the fixture must pin at least one forwarded refusal arm"
    );
    // Proved sites per DECLARED reason arm, so the requirement below is per arm
    // rather than a floor over all arms.
    let mut proved_reason_arms: Vec<(String, usize)> = Vec::new();
    let chained = fixture["forwarded_chained_correlation"]
        .as_object()
        .expect("the fixture must pin every twin that renders a chained correlation local");
    for twin in chained.keys() {
        assert!(
            entries.iter().any(|entry| {
                entry
                    .split_once(':')
                    .is_some_and(|(_, name)| name == format!("fn {twin}"))
            }),
            "a chained-correlation twin must be a correlated entry point, or its chain is proved against a call site no scan reads: {twin}"
        );
    }
    let mut proved_arms = 0_usize;
    for (symbol, phases) in refusal_arms {
        let entry = entries
            .iter()
            .find(|entry| {
                entry
                    .split_once(':')
                    .is_some_and(|(_, name)| name == format!("fn {symbol}"))
            })
            .unwrap_or_else(|| {
                panic!(
                    "every forwarded refusal arm must belong to a correlated entry point: {symbol}"
                )
            });
        let (path, _) = entry.split_once(':').expect("checked above");
        let source = manifest_source(path);
        let body = fn_declared_code_body(&source, symbol);
        // The same function read again bounded by its OWN braces: a phase literal
        // re-declared as a test `const` after the function's closing brace is a
        // mention, not a second emission, and constraining it would be a false
        // failure while ignoring it inside the body would be a real gap.
        let call_body = fn_declared_call_body(&source, symbol);
        assert!(
            call_body.len() <= body.len(),
            "{path}: {symbol}'s brace-bounded read must terminate INSIDE the span that ends at the next declaration: an equal or shorter read is what proves the brace scan found this function's own closing brace rather than running to end of file"
        );
        assert!(
            !body.contains("LaunchPhaseCorrelation::NONE"),
            "{path}: {symbol} must render the forwarded correlation on every phase record, never a fresh NONE: {body}"
        );
        // A twin need not render the caller's binding verbatim: the two approved
        // descriptor validators chain one already-held handle onto it and render
        // that local. The local is therefore accepted only when its own
        // declaration is proved to be ROOTED AT the forwarded binding - never at a
        // fresh `NONE` and never through an unchecked indirection - so the chain
        // itself is what is checked, not the name at the call site.
        let chained_entry = chained.get(symbol.as_str()).and_then(Value::as_object);
        let local = chained_entry
            .and_then(|entry| entry["local"].as_str())
            .unwrap_or(binding);
        if let Some(entry) = chained_entry {
            let root_expression = entry["root_expression"].as_str().unwrap_or_else(|| {
                panic!("a chained twin must declare its exact root expression: {entry:?}")
            });
            let roots_at = entry["rooted_at"].as_str().unwrap_or_else(|| {
                panic!("a chained twin must declare the binding it is rooted at: {entry:?}")
            });
            assert_eq!(
                roots_at, binding,
                "a chained correlation must be rooted at the contour's own binding name, or the forwarded identities cannot survive into the records: {entry:?}"
            );
            let chain = every_argument_after(&call_body, &format!("let {local}"))
                .pop()
                .map_or_else(
                    || {
                        panic!(
                            "{path}: {symbol} must declare its chained correlation `let {local}`"
                        )
                    },
                    |(_, rendered)| squash(rendered.trim_start().trim_start_matches('=').trim()),
                );
            assert!(
                chain.starts_with(&squash(root_expression)),
                "{path}: {symbol} must root {local} at exactly {root_expression:?}, so every forwarded identity survives into every record: got {chain:?}"
            );
            assert!(
                !chain.contains("LaunchPhaseCorrelation::NONE"),
                "{path}: {symbol} must never re-root its {local} chain at a fresh NONE: {chain:?}"
            );
            // A mediated chain is only as trustworthy as the helper behind it, so
            // the helper must take the correlation it is handed and build its own
            // chain from that parameter. This is the one place a revert to
            // `LaunchPhaseCorrelation::NONE` would drop every forwarded identity
            // without changing a single byte of the twin itself.
            if let Some(helper) = entry.get("root_helper").and_then(Value::as_str) {
                let declared_parameter = entry["root_helper_parameter"].as_str().unwrap_or_else(|| {
                    panic!("a mediated chain must declare the helper parameter it roots at: {entry:?}")
                });
                let (parameter, parameter_type) = first_parameter(&source, helper);
                assert_eq!(
                    parameter, declared_parameter,
                    "{path}: {helper} must take the forwarded correlation under the parameter name the fixture declares"
                );
                assert!(
                    parameter_type.starts_with('&')
                        && parameter_type.contains("LaunchPhaseCorrelation"),
                    "{path}: {helper} must take the correlation it is handed BY REFERENCE, got {parameter_type:?}"
                );
                let helper_body = squash(&fn_declared_call_body(&source, helper));
                assert!(
                    !helper_body.contains("LaunchPhaseCorrelation::NONE"),
                    "{path}: {helper} composes {local} for {symbol}, so it must be rooted at the correlation it is handed and never at a fresh NONE: {helper_body}"
                );
                assert!(
                    helper_body.contains(&format!("{parameter}.with_")),
                    "{path}: {helper} must build its chain from its own {parameter:?} parameter: got {helper_body}"
                );
            }
        }
        for phase in phases.as_array().unwrap_or_else(|| {
            panic!("forwarded refusal phases for {symbol} must be a frozen string list")
        }) {
            let phase = phase
                .as_str()
                .unwrap_or_else(|| panic!("a forwarded refusal phase must be a string: {phase}"));
            // EVERY occurrence of the phase literal in the twin's own body, not just the
            // first: a first-occurrence reader left the remaining emission sites of
            // the SAME phase free to render a fresh `NONE` and still pass.
            let sites = every_argument_after(&call_body, &format!("\"{phase}\""));
            for (index, (line, rendered)) in sites.iter().enumerate() {
                assert_eq!(
                    argument_binding(rendered),
                    local,
                    "{path}: {symbol} must render the forwarded correlation on its {phase:?} refusal arm, at occurrence {index} of {} on body line {line} got {rendered:?}",
                    sites.len()
                );
                assert!(
                    !rendered.contains("LaunchPhaseCorrelation::NONE"),
                    "{path}: {symbol} must never re-derive the correlation for {phase:?} at occurrence {index} of {} on body line {line}: {rendered:?}",
                    sites.len()
                );
                if let Some(kind) = reason_values.get(phase) {
                    let kind = kind.as_str().unwrap_or_else(|| {
                        panic!("a typed reason value must be a string: {kind:?}")
                    });
                    assert!(
                        rendered.contains(".with_reason("),
                        "{path}: {symbol} must keep the typed reason on {phase:?} while also carrying the forwarded identities: {rendered}"
                    );
                    assert!(
                        !rendered.contains("evidence") && !rendered.contains("unknown:"),
                        "{path}: {symbol} must never bind the Unknown evidence payload as the reason: {rendered}"
                    );
                    // The METHOD is not the claim: `with_reason("dead")`,
                    // `with_reason("anything")` and `with_reason("")` all satisfy
                    // `.with_reason(`, so the typed VALUE this arm must name is
                    // required too.
                    assert!(
                        rendered.contains(&format!(".with_reason(\"{kind}\")")),
                        "{path}: {symbol} must bind the EXACT typed reason {kind:?} on {phase:?}, not merely the method: a fresh with_reason of any other value would render a classified liveness kind this call site never established: {rendered}"
                    );
                    let counted = proved_reason_arms
                        .iter_mut()
                        .find(|(name, _)| name == phase);
                    match counted {
                        Some((_, sites)) => *sites += 1,
                        None => proved_reason_arms.push((phase.to_owned(), 1)),
                    }
                }
            }
            proved_arms += sites.len();
        }
    }
    assert!(
        proved_arms >= 2,
        "case 6 must bind at least the Store liveness Dead/Unknown refusal arms, got {proved_arms}"
    );
    // A floor over all arms cannot see the loss of the pair its own message names:
    // dropping the Dead/Unknown arms from `forwarded_refusal_arms` leaves 20 sites
    // proved, still above the floor. So each DECLARED reason arm is required to be
    // individually proved, and the proved set must be exactly the declared one.
    for phase in &reason_phases {
        let proved = proved_reason_arms
            .iter()
            .find(|(name, _)| name == phase)
            .map_or(0, |(_, sites)| *sites);
        assert!(
            proved > 0,
            "every DECLARED reason arm must be individually proved, not merely counted inside a floor over all arms: {phase:?} is declared to carry a typed reason but no occurrence of it was proved: {proved_reason_arms:?} of {proved_arms} proved sites over {refusal_arms:?}"
        );
    }
    let mut proved_sorted: Vec<String> = proved_reason_arms
        .iter()
        .map(|(phase, _)| phase.clone())
        .collect();
    let mut declared_sorted = reason_phases.clone();
    proved_sorted.sort();
    declared_sorted.sort();
    assert_eq!(
        proved_sorted, declared_sorted,
        "the proved reason arms must be exactly the declared ones: nothing declared may go unproved, and no arm may bind a typed reason the fixture does not declare: proved {proved_reason_arms:?} against declared {reason_phases:?}"
    );
    assert_eq!(
        reason_phases.len(),
        2,
        "exactly two of the delivered twins carry a typed reason, the Store liveness Dead/Unknown pair: no other delivered refusal arm binds one, and launch_descriptor_validation.rs composes no reason at all: {reason_phases:?}"
    );
    // Every delivered twin's refusal arms are listed, and the twin each refusal
    // phase belongs to is bound to the phase itself, so an arm cannot be moved to
    // another twin to dodge the per-occurrence scan.
    assert_eq!(
        refusal_arms.len(),
        7,
        "all SEVEN twins that start_approved calls with its correlation and that emit a refusal phase must be listed here: {refusal_arms:?}. The eighth delivered twin, approved_launch_paths_with_correlation, is deliberately absent because start_approved never calls it; its refusal arms are executed by its own inline owner case and its one call site is scanned on the branch contour"
    );
    let sequence_entries = entries
        .iter()
        .filter(|entry| entry.starts_with("src/store_kernel_launch_sequence.rs:"))
        .count();
    assert_eq!(
        sequence_entries, 1,
        "case 6 must own exactly one correlated entry point in the Store/Kernel sequence: {entries:?}"
    );
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
    // Read as PRODUCTION code, never as raw text: `host.kernel-front-door handshake
    // requested` occurs three times in that file - once in a `//` comment, once at the
    // real emission, and once inside a `#[cfg(test)]` string - so a raw `contains`
    // stays green after the production emission is deleted, which is the whole defect
    // this case exists to catch. Both owners are read through the same reader the
    // retired-label guards use.
    let frontdoor_production = production_code(&frontdoor);
    let driver_production = production_code(&driver);
    for detail in [
        "host.kernel-front-door handshake requested",
        "host.kernel-front-door handshake observed",
        "host.kernel-front-door auth requested",
        "host.kernel-front-door authenticated peer observed",
        "host.kernel-front-door control requested",
    ] {
        assert!(
            frontdoor_production.contains(detail),
            "front-door owner must emit {detail:?} from production code, not name it in a comment or a test string"
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
            driver_production.contains(detail),
            "activation owner must emit {detail:?} from production code, not name it in a comment or a test string"
        );
    }
}

// WORK_UNIT_CASE: 978/8
#[test]
fn launch_08_readiness_needs_owner_evidence() {
    let fixture = launch_fixture();
    let sibling_tokens = fixture_list(&fixture, "sibling_phase_details");
    let options_tokens = fixture_list(&fixture, "launch_options_details");
    let request = registration_request();
    let options = admitted_launch_options();

    // Execute every reachable boundary a readiness claim could have escaped
    // from, then inspect what they actually emitted.
    //
    // Each boundary's records are classified against the token list that owns
    // them, exactly as case 6 does. Classifying the whole set against
    // `sibling_phase_details` alone cannot work: the parse contour emits
    // `host.launch-options parse …`, which is frozen under
    // `launch_options_details`, so every parse record matched no token at all and
    // the classification panicked instead of reporting the phase names. Carrying
    // the per-boundary classification also keeps the stronger half of the rule:
    // every executed record must still carry EXACTLY ONE frozen token, so a
    // record that smuggles in an unlisted phase cannot pass as "no readiness".
    let mut executed = Vec::new();
    let mut phase_names = Vec::new();
    let (_parse, records) = execute_launch_parse(&valid_launch_args());
    let parse_records = detail_records(&records);
    phase_names.extend(phase_tokens(&parse_records, &options_tokens));
    executed.extend(parse_records);
    let (_bootstrap, records) = execute_scm_bootstrap(&options);
    let bootstrap_records = detail_records(&records);
    phase_names.extend(phase_tokens(&bootstrap_records, &sibling_tokens));
    executed.extend(bootstrap_records);
    for inspection in injected_inspection_schedule() {
        let (_cause, records) = execute_scm_classification(&request, &inspection);
        let classified = detail_records(&records);
        phase_names.extend(phase_tokens(&classified, &sibling_tokens));
        executed.extend(classified);
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
        !phase_names.iter().any(|token| token.contains("ready")),
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

    // Outcome 4 belongs to
    // `kernel_front_door_client.rs::activation_response_or_reconcile`, a
    // `pub(super)` path in a private module: the inline owner case there.
    //
    // It is NOT the timeout/disconnect arm. A genuine transport loss and
    // `DeliveryOutcome::UnknownOutcome` are mapped to `None` by the caller at
    // `lib.rs:3422` BEFORE this function is invoked, and the `TransportError`
    // variant is erased by `error.to_string()` into `HostError::RecoveryRequired`
    // at `lib.rs:3416`/`:3419`, so this arm can never name a transport failure
    // kind. It records only that a DELIVERED response could not be turned into a
    // typed control response. `unusable-response` is therefore the honest phase,
    // and `disconnect observed` + `reason=transport-lost` are retired - the old
    // pair claimed a disconnect on the one arm that proves the opposite.
    let frontdoor = manifest_source("src/kernel_front_door_client.rs");
    // Production code only, for the same reason case 978/7 reads it that way: each of
    // these five literals is ALSO declared inside this file's own
    // `#[cfg(all(test, windows))] mod tests`, so a raw `contains` survives the
    // deletion of the real emission.
    let frontdoor_production = production_code(&frontdoor);
    for detail in [
        "host.kernel-front-door before-start observed",
        "host.kernel-front-door no-receipt reconcile observed",
        "host.kernel-front-door unusable-response observed",
        "host.kernel-front-door unknown observed",
        "host.kernel-front-door reconcile requested",
    ] {
        assert!(
            frontdoor_production.contains(detail),
            "the front-door owner must emit {detail:?} from production code, not name it in a comment or in the file's own #[cfg(all(test, windows))] module"
        );
    }
    // The retired pair must be gone from EMITTED code. `code_only` strips
    // comments, so the `RETIRED here:` note that names the old label cannot
    // satisfy this - the pin above can no longer be met by prose.
    let frontdoor_code = code_only(&frontdoor);
    for retired in [
        "host.kernel-front-door disconnect observed",
        "reason=transport-lost",
    ] {
        assert!(
            !frontdoor_code.contains(retired),
            "the retired front-door label {retired:?} must reach no emitted code"
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
        assert_frozen_correlation_slots(detail, &keys);
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

    // The physical launch guard is phase-only: the ONE surviving terminal for a
    // failed physical launch belongs to the outer #891 contour in `lib.rs`, and
    // the SCM bootstrap validation is a different operation that keeps its own.
    //
    // Which code that outer terminal carries is NOT `host-start-failed` on the
    // production path, and this case asserts the truth rather than the earlier
    // claim: `start_approved_contour` (the only site arming
    // BOUNDARY_START_TERMINAL, lib.rs:9901) has no in-repo caller, so the code
    // that actually fires is the one armed by `HostComposition::open`
    // (BOUNDARY_OPEN_TERMINAL, lib.rs:7423). The naming question is #891's and
    // is raised as a contract challenge; this card does not touch `lib.rs`.
    let ruling = fixture["single_terminal_ruling"]
        .as_object()
        .expect("the fixture must pin the single-terminal ruling");
    assert_eq!(ruling["physical_launch_guard"].as_str(), Some("phase-only"));
    assert_eq!(
        ruling["production_path_terminal"].as_str(),
        Some("host-open-failed"),
        "the production path's terminal is the open contour's, not the exported-API start boundary"
    );
    assert_eq!(
        ruling["exported_api_only_terminal"].as_str(),
        Some("host-start-failed"),
        "host-start-failed stays reachable only through the uncalled exported API"
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
    let (filtered_records, offered) = record_emit_filtered(|| {
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
    assert_eq!(
        filtered_records, baseline_records,
        "a filtered sink must change neither the call count nor the order: {filtered_records:?}"
    );
    assert_eq!(
        offered,
        baseline_records.len(),
        "the filtering sink must be offered every emitted record and deliver none"
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
    // `tracked_parse` wraps a value in `DropTracked` only on its `Ok` arm, so the
    // REJECTED parse can never appear here - and that absence is the proof, not a gap:
    // `HostLaunchOptions::parse` returned `Err` before it ever owned a launch value, so
    // there is nothing of the caller's to release. Exactly the two admitted values are
    // released, each exactly once, and no third release exists.
    assert_eq!(
        baseline.drop_order,
        vec!["parse", "system-service"],
        "every owner-held launch value is released exactly once, and the rejected parse owned none"
    );

    // The Event Log seam keeps the platform's own live answer. #984's safe port is
    // available on Windows, so the seam is live there and stays typed
    // Unavailable off Windows; either way this asserts the real answer, never a
    // faked delivery, and never drives a real OS report from a fixture.
    let live_event_log: Result<(), WindowsEventLogError> = event_log_sink_status();
    #[cfg(windows)]
    assert_eq!(
        live_event_log,
        Ok(()),
        "#984's safe Event Log port is live on Windows"
    );
    #[cfg(not(windows))]
    assert_eq!(
        live_event_log,
        Err(WindowsEventLogError::EventLogUnavailable),
        "off Windows the seam stays typed-Unavailable"
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(HostDiagnosticsError::EventLogUnavailable),
        "the facade routes to tracing only and must never claim an Event Log sink"
    );
    assert_eq!(
        sink_status(DiagnosticSink::TracingStderr),
        Err(HostDiagnosticsError::SetupInProgress),
        "this target never installs the facade's process-global subscriber, so the stderr sink is honestly not certified"
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

    // The declared absent-slot vocabulary must EQUAL what the renderer actually
    // emits, not merely be non-empty. The absence spelling is read out of a real
    // captured production record that genuinely leaves identities absent, so a
    // renderer that re-spelled the marker - or a fixture that drifted from it -
    // fails here instead of sitting unread. `phase` is excluded because the
    // renderer always renders it.
    let (_, marker_records) = execute_launch_parse(&args_with(
        &valid_launch_args(),
        1,
        "marker-probe-auth.json",
    ));
    let marker_records = detail_records(&marker_records);
    let marker_probe = marker_records.first().map_or_else(
        || panic!("a real launch must emit at least one correlation record"),
        CapturedRecord::detail,
    );
    let observed_absence = parsed_correlation_slots(marker_probe, &keys)
        .into_iter()
        .find(|(key, _)| key != "phase")
        .map_or_else(
            || panic!("a real record must leave at least one identity absent: {marker_probe}"),
            |(_, value)| value,
        );
    let declared_markers = fixture_list(&fixture, "correlation_missing_markers");
    assert_eq!(
        declared_markers.len(),
        keys.len() - 1,
        "every non-phase key declares exactly one absent-slot marker: {declared_markers:?}"
    );
    for (index, key) in keys.iter().enumerate() {
        if key == "phase" {
            assert!(
                !declared_markers
                    .iter()
                    .any(|marker| marker.starts_with("phase=")),
                "phase is always rendered and can never be absent"
            );
            continue;
        }
        // `declared_markers` has ONE FEWER entry than `keys` because it omits
        // `phase`, so it is indexed by the position among the NON-PHASE keys -
        // not by the position in `keys`. Indexing it with `index` would compare
        // the wrong pair and would index out of bounds on the last key.
        let non_phase_index = keys[..index]
            .iter()
            .filter(|earlier| *earlier != "phase")
            .count();
        assert_eq!(
            declared_markers[non_phase_index],
            format!("{key}={observed_absence}"),
            "the fixture's absent-slot marker must match the renderer's own spelling"
        );
    }

    // The correlation-slot canaries come from the frozen fixture, so every
    // declared canary is actually asserted absent instead of a hand-copied
    // subset that could silently drop one.
    let slot_canaries = fixture_list(&fixture, "correlation_slot_canaries");
    assert!(
        !slot_canaries.is_empty(),
        "the fixture must pin the correlation-slot canaries"
    );
    // Each declared canary must be a real flag of an argv this case really
    // constructs and then executes, so asserting its absence from a record
    // cannot pass by never having built the probe.
    let probe_argv: Vec<String> = valid_system_args()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    for canary in &slot_canaries {
        assert!(
            probe_argv.iter().any(|argument| argument == canary),
            "the declared correlation-slot canary {canary:?} must be a real flag of the executed argv: {probe_argv:?}"
        );
    }

    let forbidden: Vec<String> = canaries
        .iter()
        .cloned()
        .chain(slot_canaries)
        .chain([
            synthetic_descriptor_path().display().to_string(),
            synthetic_state_root().display().to_string(),
            synthetic_nonce().to_string_lossy().into_owned(),
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
        assert_frozen_correlation_slots(detail, &keys);
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
    for key in [
        "installation",
        "generation",
        "artifact",
        "process_start",
        "fence",
    ] {
        let value = correlation_slot(first.detail(), key)
            .unwrap_or_else(|| panic!("the pre-parse phase must render {key}="));
        assert!(
            !value.contains("installation-7") && value != "7",
            "a pre-parse phase holds no identity, so {key} must not carry one: {}",
            first.detail()
        );
    }
    // Admission binds exactly what the parse boundary provably holds, read from
    // the options it just admitted: the installation, the transaction-plan
    // generation and the config-descriptor digest. Each must therefore render
    // DIFFERENTLY from the pre-parse record - a slot still reading `missing` on
    // admission would mean the parse boundary bound nothing. This is NOT a
    // presence check: `correlation_slot(..).is_some()` can never fail for a
    // record that already passed `assert_frozen_correlation_slots`, which
    // requires each frozen anchor exactly once.
    for key in ["installation", "generation", "artifact"] {
        let admitted_value = correlation_slot(admitted_phase.detail(), key)
            .unwrap_or_else(|| panic!("the admitted phase must render {key}="));
        let pre_parse_value = correlation_slot(first.detail(), key)
            .unwrap_or_else(|| panic!("the pre-parse phase must render {key}="));
        assert_ne!(
            admitted_value,
            pre_parse_value,
            "the admitted phase must bind an identity where the pre-parse phase binds none: {}",
            admitted_phase.detail()
        );
    }
    // The other four slots stay absent on BOTH records, and that is the honest
    // reading rather than a coverage gap. Parsing an argv observes no started
    // process and no authority epoch, so `HostLaunchOptions` holds no
    // process-start, fence, operation or reason handle for
    // `host_launch_options_admitted_correlation` to forward, and it binds only
    // the three slots above. Requiring these to differ from the pre-parse record
    // would demand an identity this seam cannot prove, which is exactly the
    // invention issue #978 forbids ("Missing evidence cannot be invented by
    // logging") and I15.4 rules out; the admission correlation is asserted to
    // bind no fourth slot instead.
    for key in ["operation", "process_start", "fence", "reason"] {
        assert_eq!(
            correlation_slot(admitted_phase.detail(), key),
            correlation_slot(first.detail(), key),
            "this seam holds no {key} handle, so admission must not invent one: {}",
            admitted_phase.detail()
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
        assert_frozen_correlation_slots(detail, &keys);
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
                !code_only(source).contains(token),
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
    let scm_guard = impl_body(&scm, "impl Drop for ScmLaunchTerminalGuard");
    assert!(
        scm_guard.contains("scm_launch_observe_terminal"),
        "the one SCM terminal emitter must live in the SCM guard's own drop"
    );
    let job = manifest_source("src/host_job_launch.rs");
    assert!(
        !code_only(&job).contains("host-launch-failed"),
        "the physical launch guard must stay phase-only"
    );
    assert!(
        job.contains("struct HostLaunchTerminalGuard"),
        "the phase-only launch guard must still exist"
    );
    let launch_guard = impl_body(&job, "impl Drop for HostLaunchTerminalGuard");
    assert!(
        launch_guard.contains("host_launch_observe"),
        "the phase-only launch guard must emit one correlated subordinate phase record"
    );
    assert!(
        !launch_guard.contains("observe_terminal_error"),
        "the phase-only launch guard must emit no terminal: {launch_guard}"
    );
    // The single terminal stays owned by lib.rs. This asserts OWNERSHIP, not a
    // particular code: the physical launch reaches `jobs.start_approved` from the
    // contour whose armed boundary is BOUNDARY_OPEN_TERMINAL, so the code that
    // actually fires there is `host-open-failed`.
    // `host-start-failed` is armed only inside `start_approved_contour`, which
    // has no in-repo caller. Asserting the text "host-start-failed" is present
    // in lib.rs would be true either way and would detect neither fact.
    let lib = manifest_source("src/lib.rs");
    assert!(
        lib.contains("HostTerminalGuard::armed(BOUNDARY_OPEN_TERMINAL)"),
        "the production contour that reaches the physical launch must still own a terminal"
    );
    // A strengthening, not a loosening: seven boundary entries share
    // `caller: "none (exported API; no in-repo caller)"`, so the claim is bound to
    // the ONE entry it names - the start terminal - by requiring the name, the
    // frozen terminal event and the caller to appear together inside that single
    // table entry. It can no longer be satisfied by any other boundary keeping the
    // same caller string.
    let start_terminal_code = fixture["terminal_codes"]["host_start_failed"]
        .as_str()
        .expect("the fixture pins the start terminal code");
    let start_entry = lifecycle_boundary_entry(&lib, "start.terminal");
    for (field, value) in [
        ("name", "start.terminal".to_owned()),
        ("event", start_terminal_code.to_owned()),
        (
            "caller",
            "none (exported API; no in-repo caller)".to_owned(),
        ),
    ] {
        assert!(
            start_entry.contains(&format!("{field}: \"{value}\"")),
            "the start.terminal entry must keep {field}: {value:?}, got: {start_entry}"
        );
    }
    let requested_entry = lifecycle_boundary_entry(&lib, "start.requested");
    assert!(
        !requested_entry.contains(&format!("event: \"{start_terminal_code}\"")),
        "a sibling entry must not carry the start terminal event: {requested_entry}"
    );

    // The single-terminal ruling is proved against real `lib.rs` STRUCTURE, not
    // against prose that names a symbol: which function actually encloses each
    // arming site, and whether that function has an in-repo call site. These
    // facts hold whatever wording the frozen ruling uses, so a re-freeze of the
    // fixture prose cannot make this guard pass or fail by accident.
    let open_arm = source_line_of(&lib, "HostTerminalGuard::armed(BOUNDARY_OPEN_TERMINAL)");
    let start_arm = source_line_of(&lib, "HostTerminalGuard::armed(BOUNDARY_START_TERMINAL)");
    assert!(
        line_is_inside_fn(&lib, "open_for_profile", open_arm),
        "the open terminal is armed inside HostComposition::open_for_profile"
    );
    assert!(
        !line_is_inside_fn(&lib, "open", open_arm),
        "HostComposition::open only delegates, so it is not the enclosing function of the open terminal"
    );
    assert!(
        fn_body(&lib, "open_for_profile").contains("start_approved_manifest_contour("),
        "the open contour must keep reaching the approved-start contour that owns the physical launch"
    );
    assert!(
        line_is_inside_fn(&lib, "start_approved_contour", start_arm),
        "the start terminal is armed inside HostComposition::start_approved_contour"
    );
    assert_eq!(
        count_occurrences(&lib, "start_approved_contour("),
        1,
        "start_approved_contour must keep exactly one declaration and no in-repo call site"
    );
    // Every owner the ruling names must still be stated by the frozen fixture, so a
    // re-freeze cannot quietly drop a claim. `other_live_terminal_owners` joined this
    // list for the same reason the round-4 repair added the key at all: the key was
    // otherwise read by no assertion, so dropping it again would have failed nothing.
    let ruling = fixture["single_terminal_ruling"]
        .as_object()
        .expect("the fixture must pin the single-terminal ruling");
    for owner in [
        "production_path_owner",
        "exported_api_only_owner",
        "other_live_terminal_owners",
    ] {
        let stated = ruling[owner]
            .as_str()
            .unwrap_or_else(|| panic!("the ruling must state {owner}"));
        assert!(
            !stated.trim().is_empty(),
            "the ruling must state a non-empty {owner}"
        );
    }
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
