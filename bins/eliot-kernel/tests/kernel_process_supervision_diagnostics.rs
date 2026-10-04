#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Kernel process-execution and supervision diagnostics (F-LOG-KERNEL-3, issue #901).
//!
//! Every case drives a real production callsite through an existing public
//! seam and asserts against the bytes that run actually emitted. The six
//! owned modules stay read-only here: this suite adds no production
//! behaviour, no inline test inside them, and no expected-log vector in
//! place of executing a callsite.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use eliot_contracts::{ArtifactId, ContractId, EpochId, EpochLineageId, ResourceGeneration};
use eliot_ipc::{PeerIdentity, Session};
use eliot_kernel::kernel_diagnostics::{
    KERNEL_DIAGNOSTICS_TARGET, MAX_DIAGNOSTIC_FIELD_BYTES, bound_field,
};
use eliot_kernel::{KernelComposition, KernelConfig};
use eliot_kernel_core::{
    AuthoritySnapshotBinding, DispatchSnapshotCodec, KernelAuthorityReplaySnapshot, KernelError,
    KernelResult, ProcessDispatchAuthorityController, SealedAuthoritySnapshot,
};
use eliot_kernel_service::{
    ProcessExecutionClient, ProcessExecutionRejection, ProcessExecutionRequest,
    ProcessExecutionResponse,
};
use eliot_observability::field_policy::{RedactionReason, TelemetryFieldFamily, mint_handle};
use eliot_ors::{
    EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, ProcessStartReplayRecord,
    ProcessStartReplayState, RecoveryPayload, RedbRecoveryStore, StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, EnvironmentInheritance, EnvironmentProjection,
    FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessExecutionAdmissionRequest, ProcessIntent, ProcessOwnerBinding, ProcessSessionBinding,
    ProcessTreeId, ResourceLimits, SecretRef, SessionId,
};
use eliot_runtime_contracts::{HealthVector, ModuleGeneration, ModuleGenerationState};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The EXACT FIVE source files this leaf owns, in the fixture's spelling.
///
/// These are the five modules issue #901's exclusive mutable scope names, and
/// nothing else is added here: the denominator is a statement about what this
/// issue OWNS, so widening it to a sixth file the issue never listed would make
/// the "exact" claim a restatement of whatever the fixture happens to say.
///
/// `bins/eliot-kernel/src/process_execution_client.rs` is the file that was
/// wrongly folded in. It does carry one production `observe_process_in_context`
/// callsite at `:106`, emitting `kernel.process.request_rejected` with outcome
/// `path_proof`, and it still carries that callsite and its boundary row
/// (covering case 4) - nothing was deleted to make this denominator come out at
/// five. It is named in [`OUT_OF_SCOPE_INSTRUMENTED_FILES`] instead, and its row
/// is still resolved against its real source by `assert_boundary_inventory`, so
/// the boundary stays inventoried while the OWNED set stays exact.
const OWNED_FILES: [&str; 5] = [
    "bins/eliot-kernel/src/process_execution.rs",
    "bins/eliot-kernel/src/daemon_process_launch.rs",
    "bins/eliot-kernel/src/daemon_live_receipt.rs",
    "bins/eliot-kernel/src/daemon_supervision.rs",
    "bins/eliot-kernel/src/supervision_lease_authority.rs",
];

/// Every production file in this package that CALLS one of the six observers and
/// is NOT one of the five this issue owns, as repository-relative paths.
///
/// This is a refusal, not an omission. The derivation in
/// `derived_instrumented_files` walks the whole `src/` tree, so a sixth
/// instrumented file cannot simply be left out of the fixture: it would turn
/// `assert_denominator` red in the direction that says "an instrumented file is
/// in neither named list". Naming it here is what keeps the owned denominator at
/// exactly five AND keeps the sixth file's boundary accounted for, instead of
/// trading a false "exact five" for an unowned boundary nobody looks at.
///
/// [`OWNED_FILES`] is the whole of what this issue owns; this list is the
/// measurement of what it touches without owning. A file is in one or the other,
/// never both, and `assert_denominator` enforces that.
const OUT_OF_SCOPE_INSTRUMENTED_FILES: [&str; 1] =
    ["bins/eliot-kernel/src/process_execution_client.rs"];

/// The crate-relative owned paths this suite reads for case 30's sweep.
///
/// One entry per [`OWNED_FILES`] path. The sixth derived path is swept too,
/// through [`SWEPT_PATHS`], because a sweep that stopped at the owned five would
/// leave a second subscriber owner in that file unobserved.
const OWNED_PATHS: [&str; 5] = [
    "src/process_execution.rs",
    "src/daemon_process_launch.rs",
    "src/daemon_live_receipt.rs",
    "src/daemon_supervision.rs",
    "src/supervision_lease_authority.rs",
];

/// Every crate-relative path case 30 sweeps: the five owned modules PLUS the one
/// out-of-scope instrumented file, which is why the sweep is not
/// [`OWNED_PATHS`].
///
/// `assert_sweep_covers_derivation` fails if this list and the derived
/// instrumented set ever differ, so the sweep cannot quietly stop covering a
/// file the denominator counts. That correspondence is what lets case 30 read as
/// a whole-surface sweep rather than a sweep of the owned subset.
const SWEPT_PATHS: [&str; 6] = [
    "src/process_execution.rs",
    "src/daemon_process_launch.rs",
    "src/daemon_live_receipt.rs",
    "src/daemon_supervision.rs",
    "src/supervision_lease_authority.rs",
    "src/process_execution_client.rs",
];

/// Vocabulary no owned module may contain AT ALL, in any region: a facade
/// installer, a process-global subscriber install, or a new public observation
/// surface.
///
/// The subscriber CALLS are deliberately NOT in this list. Both in-crate
/// capsules legitimately install a thread-local subscriber
/// (`daemon_supervision.rs:841`, `process_execution.rs:4866`) from inside a
/// `#[cfg(test)]` module, so a whole-file needle would redden on test code that
/// is allowed to capture. Those needles live in
/// [`FORBIDDEN_SUBSCRIBER_IN_PRODUCTION`], which is checked outside the
/// test-module extents instead.
///
/// `tracing::subscriber::set_global` WAS the fifth entry here and is GONE. It is
/// a strict prefix of the `set_global_default` entry, so it could only ever
/// fire together with that entry - never on its own - while `set_default` and
/// `with_default`, which DO install a subscriber, were not needled at all. Its
/// honest form is the call needle `set_global(` in the production list, which
/// matches the bare `tracing::subscriber::set_global(subscriber)` call no other
/// needle names and still does not match `set_global_default(`.
///
/// `pub fn observe_` stays a whole-file needle, and is now also covered by the
/// exact declaration set in [`OWNED_OBSERVATION_DECLARATIONS`], which does not
/// depend on the visibility spelling.
const FORBIDDEN_IN_OWNED: [&str; 6] = [
    "try_init",
    "set_global_default",
    "install_kernel_diagnostics",
    "pub fn observe_",
    // A new event family emitted STRAIGHT through `tracing::info!` instead of
    // through one of the six observers, which the observer-name derivation
    // cannot see at all. The six observer declarations pass a BOUND field
    // (`event = event_bound.text()`, `process_execution.rs:84`), so a direct
    // emission has to name a literal and both literal spellings are needled:
    // `event = "kernel.` is this tree's rustfmt spelling (16 measured sites,
    // `kernel_diagnostics.rs:704` among them, none of them owned) and
    // `event="kernel.` is the unspaced spelling.
    "event = \"kernel.",
    "event=\"kernel.",
];

/// Vocabulary that makes a module a SUBSCRIBER OWNER: every spelling of a
/// thread-local or process-global subscriber install, plus the one facade
/// installer.
///
/// These are CALL forms, not bare names, so an unrelated mention in a comment
/// cannot redden, and so `set_global(` and `set_global_default(` are
/// INDEPENDENT: neither is a prefix of the other, which is exactly what the
/// dropped `tracing::subscriber::set_global` needle was not. `with_default(`
/// and `set_default(` are the two thread-local installers the old five-entry
/// list could not name at all, and they are what both in-crate capsules use.
const FORBIDDEN_SUBSCRIBER_IN_PRODUCTION: [&str; 5] = [
    "set_global_default(",
    "set_global(",
    "set_default(",
    "with_default(",
    "install_kernel_diagnostics(",
];

/// The ONLY modules under this package's `src/` allowed to install a subscriber
/// in PRODUCTION code, named rather than assumed.
///
/// `src/kernel_diagnostics.rs` DECLARES the one installer
/// (`install_kernel_diagnostics`, `:242`) and `src/main.rs` is the composition
/// root that CALLS it exactly once (`:224`), which is the accepted single-owner
/// shape the diagnostic brief describes. Every other production module under
/// `src/` must be free of the list above.
const FACADE_SUBSCRIBER_OWNERS: [&str; 2] = ["src/kernel_diagnostics.rs", "src/main.rs"];

/// Every `observe`-named function DECLARATION the six owned modules may carry,
/// as `(owned path, function name)`, measured from the tree on 2026-10-03.
///
/// Visibility and the `async` modifier are NOT part of the key on purpose: the
/// escapes this pins are exactly the spellings a substring test CAN read -
/// `pub(crate) fn observe_...` (`process_execution.rs:73` is the one legitimate
/// `pub(crate)` surface the crate has), `pub async fn observe_...` and
/// `pub fn observe(` with no underscore. Two entries are not observation
/// surfaces at all and are listed so the set is honest rather than narrowed:
/// `observe_process` is the unscoped wrapper that forwards, and
/// `observe_external_filesystem_transition` (`process_execution.rs:601`) is a
/// production helper whose name merely begins with `observe`.
const OWNED_OBSERVATION_DECLARATIONS: [(&str, &str); 7] = [
    ("src/daemon_live_receipt.rs", "observe_live_receipt"),
    ("src/daemon_process_launch.rs", "observe_daemon_launch"),
    ("src/daemon_supervision.rs", "observe_supervision"),
    (
        "src/process_execution.rs",
        "observe_external_filesystem_transition",
    ),
    ("src/process_execution.rs", "observe_process"),
    ("src/process_execution.rs", "observe_process_in_context"),
    (
        "src/supervision_lease_authority.rs",
        "observe_supervision_lease",
    ),
];

/// Event families the six owned modules alone emit; neither the crate root
/// nor the shared facade may learn them.
const OWNED_EVENT_FAMILIES: [&str; 4] = [
    "kernel.process.",
    "kernel.live_receipt.",
    "kernel.daemon.launch",
    "kernel.supervision.commit_",
];

/// A spot-check of the identity slots the shared operation span declares with the
/// literal `"unavailable"` default, as `name = "unavailable"` source spellings.
///
/// It is deliberately NOT the full declared-slot list: the facade declares SEVENTEEN
/// slots, of which TEN carry a literal default - these eight plus
/// `request_id = "unavailable"` and `request_id_redaction = "none"`
/// (`kernel_diagnostics.rs:660`-`:661`), which are left to
/// [`declared_operation_slots`] - and seven carry a computed value or a
/// redaction marker (`operation`, `generation`, `state_fence`, `authority_epoch`
/// and their four `_redaction` companions). The complete, source-derived list is
/// [`declared_operation_slots`], which the canary sweep in case 28 uses; this
/// constant only pins the spelling of the eight identity-slot defaults, so a
/// facade that renamed one of them is red in case 1 as well.
const SPAN_SLOT_DEFAULTS: [&str; 8] = [
    "process_tree = \"unavailable\"",
    "process_id = \"unavailable\"",
    "process_start_100ns = \"unavailable\"",
    "image_sha256 = \"unavailable\"",
    "lease = \"unavailable\"",
    "lease_operation = \"unavailable\"",
    "receipt = \"unavailable\"",
    "request_id = \"unavailable\"",
];

/// The six observation helpers the boundary inventory is derived from: the
/// two process funnels, the daemon-launch funnel, the live-receipt funnel and
/// the two supervision funnels. A production file that CALLS one of these owns
/// an observable boundary, whether or not this suite names it.
const OBSERVER_FUNCTIONS: [&str; 6] = [
    "observe_process",
    "observe_process_in_context",
    "observe_daemon_launch",
    "observe_live_receipt",
    "observe_supervision",
    "observe_supervision_lease",
];

/// The exact text that opens a frozen case marker in this file. Kept as a
/// named constant so the self-read in [`local_case_owners`] and the markers
/// themselves cannot drift apart.
const WORK_UNIT_MARKER: &str = "// WORK_UNIT_CASE: 901/";

#[derive(Clone, Default)]
struct CaptureSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("capture lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A sink whose every `write` fails, as a dropped/full target would.
///
/// `offered` records what production handed the writer *before* the `Err` is
/// returned, so a failing arm can still be observed; nothing is ever delivered
/// through this sink. The failure is not a flag: `write` unconditionally
/// returns `Err`, and the `tracing-subscriber` fmt layer ignores writer errors
/// because `log_internal_errors` is off by default
/// (tracing-subscriber-0.3.23 `src/fmt/fmt_layer.rs:1049-1055`), which is
/// exactly the failed/dropped-sink condition under test.
#[derive(Clone, Default)]
struct FailingSink {
    offered: Arc<Mutex<Vec<u8>>>,
    attempts: Arc<AtomicU64>,
}

impl Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.offered
            .lock()
            .map_err(|_| std::io::Error::other("failing sink lock poisoned"))?
            .extend_from_slice(buf);
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("capture sink write failed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("capture sink flush failed"))
    }
}

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kernel_process_supervision_diagnostics.json");
    let bytes = std::fs::read(&path).expect("process/supervision fixture must be readable");
    serde_json::from_slice(&bytes).expect("process/supervision fixture must be valid JSON")
}

/// Thread-local capture: `with_default` never installs a process-global
/// subscriber, so these tests stay parallel-safe with every sibling suite.
///
/// The closure is run to COMPLETION INSIDE the subscriber region; that is the
/// constraint this name states, and every call site below honours it by passing
/// a synchronous body. `with_default` takes a synchronous closure and returns
/// its result - it never awaits - so an async body passed here would come back
/// as an UN-POLLED future with the guard already dropped, and would then be
/// polled with NO subscriber current: every span-field assertion would silently
/// read a dispatcher that was never installed.
///
/// Any `tracing::Span` an assertion needs must be CONSTRUCTED inside this call,
/// because a span binds its dispatcher at construction, not at first use.
///
/// A test that genuinely needs an async body must instead install the
/// subscriber by value and hold the guard across the await:
///
/// ```rust
/// let guard = tracing::subscriber::set_default(subscriber);
/// let value = run().await;
/// drop(guard);
/// ```
///
/// which is the form the five in-crate capsules of #901 now use.
fn capture_blocking<F, R>(f: F) -> (String, R)
where
    F: FnOnce() -> R,
{
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f)
    };
    let bytes = sink.bytes.lock().expect("capture lock").clone();
    (String::from_utf8_lossy(&bytes).into_owned(), result)
}

/// Thread-local capture through a sink whose every write fails: returns the
/// bytes production offered the writer, the driven result, and the number of
/// real (failed) write attempts.
fn capture_with_failing_sink<F, R>(f: F) -> (String, R, u64)
where
    F: FnOnce() -> R,
{
    let sink = FailingSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f)
    };
    let offered = sink.offered.lock().expect("offered lock").clone();
    let attempts = sink.attempts.load(Ordering::SeqCst);
    (
        String::from_utf8_lossy(&offered).into_owned(),
        result,
        attempts,
    )
}

struct TempGuard {
    root: PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        // The composition must already be released when this runs, or Windows
        // refuses `remove_dir_all` on the still-open redb file and `let _ =`
        // swallows the failure, leaking one `eliot-901-*` root per run. Both
        // carriers in this file order the drop that way on purpose:
        // `process_authority_kernel` returns the guard FIRST, so a test's
        // `let (_guard, kernel) = ...` drops `kernel` before `_guard`; and
        // `SupervisionFixture` declares `kernel` before `_guard`, so struct
        // field drop order releases the composition first too.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

static ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_root(suffix: &str) -> PathBuf {
    let n = ROOT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u128::from(n), |d| d.as_nanos());
    let unique = format!("{suffix}-{n}-{nanos}-{}", std::process::id());
    let root = std::env::temp_dir().join(format!("eliot-901-{unique}"));
    std::fs::create_dir_all(&root).expect("test work root");
    root
}

// ---------------------------------------------------------------------------
// Captured-byte readers
// ---------------------------------------------------------------------------

fn captured_line<'a>(logs: &'a str, needle: &str) -> &'a str {
    logs.lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no captured line carries {needle}; captured: {logs}"))
}

fn quoted_value<'a>(line: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=\"");
    let start = line
        .find(&prefix)
        .unwrap_or_else(|| panic!("field {key} absent from captured line: {line}"))
        + prefix.len();
    let rest = &line[start..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated field {key} in captured line: {line}"));
    &rest[..end]
}

/// Reads one slot of the `kernel.operation` span the given event is printed
/// under, returning the RECORDED value where the owner recorded one.
///
/// Two properties of the real renderer force this shape, both read from
/// tracing-subscriber 0.3.23 rather than assumed:
///
/// * `fmt::format::Format::format_event` writes exactly one opening brace
///   around the whole `FormattedFields` run
///   (`src/fmt/format/mod.rs:997`), and `FormattedFields` renders as a single
///   space-separated `key=value` sequence. A needle of `{slot="` therefore
///   only ever matches the FIRST declared field (`request_id`), and every
///   other slot would panic as absent.
/// * `FmtLayer::on_record` appends through `add_fields`
///   (`src/fmt/fmt_layer.rs`, `src/fmt/format/mod.rs:244-253`), which pushes a
///   space and formats; it never rewrites the declared slot. A recorded slot
///   therefore appears AFTER its declared default, so the last occurrence on
///   the line is the recorded value and the first is the declared default.
///
/// A slot the owner never recorded occurs exactly once and resolves to its
/// declared `"unavailable"` default, which is the honest answer for it.
///
/// A third property decides WHICH occurrence of a name counts, and it is
/// what makes this a field reader rather than a substring reader. The needle
/// `{slot}="` alone matches inside a LONGER identifier that ends in the same
/// letters: `operation="` also matches inside `lease_operation="`, and
/// `supervision_lease_authority.rs` records `lease_operation` (`:120`, `:137`)
/// before any `operation`, so a plain `rfind` on a supervision span answers
/// `"expire"`/`"revoke"` to a request for `operation`. The renderer makes the
/// fix exact rather than heuristic: `DefaultVisitor` emits `name` then `=`
/// then the value (`format/mod.rs:1332-1338`) and separates fields with a
/// single space (`maybe_pad`, `format/mod.rs:1250-1260`), and the run is
/// wrapped in one `{...}` pair (`format/mod.rs:997`). So the byte before any
/// rendered key is always `{` or a space - never part of a longer identifier -
/// and requiring that byte to be outside `[A-Za-z0-9_]` accepts every real
/// field and rejects every suffix of a longer one.
fn span_field(logs: &str, event: &str, slot: &str) -> String {
    let line = captured_line(logs, &format!("event=\"{event}\""));
    let key = format!("{slot}=\"");
    let bytes = line.as_bytes();
    let mut last = None;
    for (hit, _) in line.match_indices(&key) {
        let boundary =
            hit == 0 || !(bytes[hit - 1].is_ascii_alphanumeric() || bytes[hit - 1] == b'_');
        if boundary {
            last = Some(hit);
        }
    }
    let last = last.unwrap_or_else(|| panic!("span slot {slot} absent from captured line: {line}"));
    let rest = &line[last + key.len()..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated span slot {slot} in captured line: {line}"));
    rest[..end].to_owned()
}

/// The exact field names the shared operation span DECLARES, read out of
/// `kernel_diagnostics::operation_context` in the facade source instead of
/// restated here.
///
/// That function builds one `tracing::info_span!` (`kernel_diagnostics.rs:657`
/// through `:677`), so every declared field is rendered on every record under
/// the span whether or not an owner ever records a value for it. Sweeping
/// exactly this list is what makes the canary sweep in case 28 total over the
/// span: a slot added to the facade extends the sweep without editing this
/// file, and a slot the facade stops declaring turns the sweep red rather than
/// silently narrowing it.
fn declared_operation_slots() -> Vec<String> {
    let facade = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/kernel_diagnostics.rs"),
    )
    .expect("shared facade source");
    let start = facade
        .find("pub fn operation_context(")
        .expect("the facade declares operation_context");
    let body = &facade[start..];
    let end = body
        .find("\n    )")
        .expect("the operation_context declaration closes");
    let mut slots = Vec::new();
    for line in body[..end].lines() {
        let Some((name, value)) = line.trim().split_once(" = ") else {
            continue;
        };
        let is_field_name = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if is_field_name && value.ends_with(',') {
            slots.push(name.to_owned());
        }
    }
    assert!(
        !slots.is_empty(),
        "the facade declaration yielded no operation span slots"
    );
    slots
}

fn event_outcome(logs: &str, event: &str) -> String {
    quoted_value(
        captured_line(logs, &format!("event=\"{event}\"")),
        "outcome",
    )
    .to_owned()
}

fn event_count(logs: &str, event: &str) -> usize {
    logs.matches(&format!("event=\"{event}\"")).count()
}

fn terminal_codes(logs: &str) -> Vec<String> {
    logs.lines()
        .filter(|line| line.contains("event=\"kernel.terminal_error\""))
        .map(|line| quoted_value(line, "code").to_owned())
        .collect()
}

fn byte_offset(logs: &str, needle: &str) -> usize {
    logs.find(needle)
        .unwrap_or_else(|| panic!("{needle} absent from captured run: {logs}"))
}

// ---------------------------------------------------------------------------
// Fixture accessors: every read is a hard expectation, so the fixture cannot
// drift away from this suite silently.
// ---------------------------------------------------------------------------

fn fixture_event(key: &str) -> String {
    fixture()["events"][key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must name events.{key}"))
        .to_owned()
}

fn fixture_canary(key: &str) -> String {
    fixture()["canaries"][key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture must name canaries.{key}"))
        .to_owned()
}

fn fixture_terminal_codes() -> Vec<String> {
    fixture()["terminal_codes"]["process"]
        .as_array()
        .expect("fixture must pin terminal_codes.process")
        .iter()
        .map(|value| value.as_str().expect("terminal code string").to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Derived-source readers
//
// Case 1 proves the issue's denominator instead of restating it. Everything
// below reads the production tree at TEST time instead of trusting a constant
// written next to the assertion that consumes it.
// ---------------------------------------------------------------------------

/// True when `source` CALLS `observer`, as opposed to declaring, importing or
/// merely mentioning it.
///
/// Four measured conditions, all read off this crate's own sources:
///
/// * the name is not preceded by an identifier byte, so a longer name that
///   merely ends in it - `observe_supervision_lease` seen while looking for
///   `observe_supervision` - is not a match;
/// * the name is followed by `(`, so a `use` list is not a match: see
///   `src/process_execution_client.rs:23 use super::process_execution::{
///   observe_process_in_context, process_terminal_code};`;
/// * the line does not begin with `//`, so no comment can manufacture a
///   callsite;
/// * the name is not a name an `fn` keyword DECLARES - see
///   [`is_observer_declaration`] - so the six helper declarations
///   (`src/process_execution.rs:65` and `:73`, `src/daemon_live_receipt.rs:38`,
///   `src/daemon_process_launch.rs:55`, `src/daemon_supervision.rs:52`,
///   `src/supervision_lease_authority.rs:55`) are not counted. That exclusion is
///   made by what a declaration IS rather than by a property of its line, so a
///   callsite sharing a line with a function's own `fn` keyword is still
///   counted.
///
/// The `observe_process` forwarder at `src/process_execution.rs:67` IS a
/// callsite by this definition - it is a call - and the fixture note already
/// records that it owns no boundary row of its own.
fn calls_observer(source: &str, observer: &str) -> bool {
    !observer_callsite_offsets(source, observer).is_empty()
}

/// Every byte offset in `source` at which `observer` is CALLED, under the same
/// four conditions [`calls_observer`] states.
///
/// The offsets are what the completeness derivation below needs: a BOOLEAN
/// cannot tell one callsite from two, so the conditions live here once and
/// both readers - the per-FILE denominator walk and the per-CALLSITE multiset -
/// decide "is this a callsite" with one definition that cannot drift.
fn observer_callsite_offsets(source: &str, observer: &str) -> Vec<usize> {
    source
        .match_indices(observer)
        .filter_map(|(hit, _)| {
            if source
                .as_bytes()
                .get(hit.wrapping_sub(1))
                .copied()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return None;
            }
            if !source[hit + observer.len()..].trim_start().starts_with('(') {
                return None;
            }
            let head = source[..hit]
                .rsplit_once('\n')
                .map_or("", |(_, tail)| tail)
                .trim();
            if head.starts_with("//") || is_observer_declaration(source, hit) {
                return None;
            }
            Some(hit)
        })
        .collect()
}

/// True when the name at byte `name_start` is the name an `fn` keyword
/// DECLARES, as opposed to a USE of an already-declared name.
///
/// The distinction is structural: a declaration is a `fn` whose OWN NAME is
/// this name, so the `fn` keyword is the nearest preceding token and only
/// whitespace lies between them. A USE of the same name on the same line as some
/// function's own `fn` keyword leaves that function's declared name, a parameter
/// list or an opening brace in between, so the nearest preceding token is not
/// the keyword and the call is counted - which is what keeps a one-line wrapper
/// such as `fn observe_process_scoped(event: &str, outcome: &str) { ... }`, or
/// any call written on an `fn` line, inside the derived denominator.
///
/// Two shapes count as one declaration: the keyword immediately before the name
/// (`pub(crate) fn observe_process_in_context(`), and a signature split across
/// lines whose preceding line ends with the keyword. A comment line is never
/// read as a declaration, so `// ... forwards to fn` above a call cannot hide
/// it, and the keyword must be a whole word so `myfn` never introduces one.
fn is_observer_declaration(source: &str, name_start: usize) -> bool {
    fn ends_with_fn_keyword(text: &str) -> bool {
        let Some(head) = text.strip_suffix("fn") else {
            return false;
        };
        match head.chars().next_back() {
            None => true,
            Some(character) => !(character.is_alphanumeric() || character == '_'),
        }
    }

    let bytes = source.as_bytes();
    let mut index = name_start;
    while index > 0 && matches!(bytes[index - 1], b' ' | b'\t' | b'\r') {
        index -= 1;
    }
    let head = &source[..index];
    if ends_with_fn_keyword(head) {
        return true;
    }
    let Some(line_start) = head.rfind('\n') else {
        return false;
    };
    let previous = head[..line_start].trim_end();
    !previous.starts_with("//") && ends_with_fn_keyword(previous)
}

/// The half-open line range each COLUMN-ZERO test-gated `mod` capsule occupies
/// in `lines`, so the exclusion is by MODULE EXTENT and never truncates a file.
///
/// A callsite inside one of them is a TEST callsite, not a production boundary:
/// `process_execution.rs:4827` (`#[cfg(test)] mod
/// process_execution_diagnostics_tests`) and `daemon_supervision.rs:802`
/// (`#[cfg(all(test, windows))] mod daemon_supervision_diagnostics_tests`). Only
/// an attribute that is followed by a `mod` item counts, so the `#[cfg(test)]`
/// inside a function body at `process_execution.rs:4790` and the one named inside
/// a doc comment at `daemon_process_launch.rs:788` do not shorten anyone's
/// production region.
///
/// #901's five private-boundary capsules are INLINE in the owned modules
/// themselves, which makes this reader the one that has to exclude them, and the
/// extent is therefore found by ITEM BOUNDARY rather than by brace depth.
///
/// WHY NOT BRACE DEPTH. Counting braces requires lexing string literals so a
/// quoted brace cannot move the depth, and the simple form of that lex is not
/// reliable here, because these files defeat it: `daemon_live_receipt.rs` carries
/// a raw string (`r"C:\ProgramData\Eliot\HostState"`), a byte-string char literal
/// (`&b'"'`) and doc comments quoting unbalanced braces, so a depth walk closes
/// that module several hundred lines early and then excludes only part of it. An
/// under-exclusion is the dangerous direction - it lets a test helper's name be
/// read as a production observation surface - so the extent is measured from
/// rustfmt's own guarantee instead: inside a `mod` body every item is indented,
/// and every top-level item BEGINS at column zero.
///
/// The rule, then: a column-zero `#[cfg(` attribute naming `test` whose next line
/// declares a `mod` opens an extent at that attribute; the extent closes at the
/// next column-zero line that is neither blank, nor the module's own `mod` header,
/// nor indented. `process_execution.rs` exercises the case that matters - it
/// carries TWO capsules with a production line between them - and this rule closes
/// the first at its own `}` and opens the second at its own attribute, so that
/// production line is still production.
///
/// KNOWN AND STATED LIMIT, and its direction: a column-zero non-blank, non-`}`
/// line INSIDE a gated module closes the extent early, and an indented
/// `#[cfg(test)]` inside a module body is not recognised at all. Both fail toward
/// reading MORE text as production, never toward hiding production text, which is
/// the conservative direction for every caller here: an unexcluded capsule can
/// only redden a reader, never quietly satisfy one.
fn test_module_extents(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut extents: Vec<(usize, usize)> = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let gated = lines[index].starts_with("#[cfg(") && lines[index].contains("test");
        let declares_module = lines
            .get(index + 1)
            .is_some_and(|next| next.trim_start().starts_with("mod "));
        if !(gated && declares_module) {
            index += 1;
            continue;
        }
        // The `mod` header on the line after the attribute belongs to the extent,
        // so the search for its end starts below it.
        let mut end = lines.len();
        let mut cursor = index + 2;
        while cursor < lines.len() {
            let line = lines[cursor];
            let starts_a_new_top_level_item = !line.trim().is_empty()
                && !line.starts_with('}')
                && !line.starts_with(char::is_whitespace);
            if starts_a_new_top_level_item {
                end = cursor;
                break;
            }
            cursor += 1;
        }
        extents.push((index, end));
        index = end.max(index + 1);
    }
    extents
}

/// The parenthesised argument list of the callsite whose observer name ends at
/// `name_end`, matched by depth so a nested call - or a bracket inside a string
/// literal the callsite passes - cannot end it early.
fn callsite_arguments(source: &str, name_end: usize) -> &str {
    let open = source[name_end..].find('(').map_or_else(
        || panic!("a callsite at byte {name_end} is followed by its argument list"),
        |offset| name_end + offset,
    );
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..=index];
                }
            }
            b'"' => {
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
            }
            _ => {}
        }
        index += 1;
    }
    panic!("the callsite's argument list at byte {open} is unterminated");
}

/// The first string literal in `arguments`, or `None` when the argument list
/// carries none.
fn first_string_literal(arguments: &str) -> Option<&str> {
    let bytes = arguments.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let mut end = index + 1;
            while end < bytes.len() && bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            return Some(&arguments[index + 1..end]);
        }
        index += 1;
    }
    None
}

/// Item VISIBILITY and SIGNATURE modifiers, longest first so `pub(crate)` is
/// consumed before a bare `pub` could be tried against it.
const SIGNATURE_MODIFIERS: [&str; 9] = [
    "pub(crate)",
    "pub(super)",
    "pub(in",
    "pub",
    "async",
    "unsafe",
    "const",
    "extern",
    "default",
];

/// The declared name on an item signature line once its visibility and
/// signature modifiers are stripped, or `None` when the line declares no
/// function.
///
/// A function declaration is not spelled `fn ` at column zero:
/// `pub(crate) fn observe_process_in_context(`, `pub async fn start_in_context(`
/// and `pub(crate) async fn close_registered_descendant_in_context(` are all
/// declarations. An earlier revision of this file matched the bare `fn `
/// prefix only, so `ProductionCallsite::enclosing` - the field the FORWARDER
/// classification and the literal-free diagnostic both read - carried the name
/// of whatever unprefixed helper happened to precede the callsite. Measured on
/// this tree that returned `live_receipt_terminal_code` for the callsite at
/// `daemon_live_receipt.rs:146`, `staged_ticket` for the one at
/// `supervision_lease_authority.rs:830` and `from` for the one at
/// `daemon_supervision.rs:556`: 117 of the 118 derived callsites carried a name
/// that is not the function they sit in. The forwarder count stayed at one only
/// because the forwarder at `process_execution.rs:67` is the one callsite whose
/// own declaration is the bare `fn observe_process(` - so the classification
/// rested on an accident of spelling, not on the enclosing function. With the
/// modifiers stripped the derivation is unchanged in every count: 118 measured
/// callsites, the same ONE forwarder at `process_execution.rs:67`, 117 keyed
/// rows, the same ONE literal-free callsite at `process_execution.rs:2403`.
fn declared_item_name(line: &str) -> Option<String> {
    let mut start = line.len() - line.trim_start().len();
    if line[start..].starts_with("//") {
        return None;
    }
    loop {
        let Some(modifier) = SIGNATURE_MODIFIERS
            .iter()
            .find(|modifier| line[start..].starts_with(*modifier))
        else {
            // The loop exits at the first byte that is no longer a MODIFIER, which
            // is the only place a declared name can start: a declaration spells
            // `fn ` here, and every other line - a body statement, an attribute,
            // a blank line, a comment already refused above - declares nothing and
            // is skipped. The name ends at the `(`, `<` or space that opens the
            // parameter list, so `observe_process(` and `observe_process_in_`
            // context<T>(` both yield their own name.
            let signature = line[start..].strip_prefix("fn ")?;
            let name = signature
                .split(['(', '<', ' '])
                .next()
                .unwrap_or(signature)
                .trim();
            return (!name.is_empty()).then(|| name.to_owned());
        };
        let after_start = start + modifier.len();
        let after = &line[after_start..];
        // `pub(in path)` and `extern "C"` carry a delimited tail, so consume
        // through the closing delimiter instead of only the keyword.
        let consumed = if modifier.starts_with("pub(in") {
            after.find(')').map_or(after.len(), |close| close + 1)
        } else if modifier.starts_with("extern") {
            after
                .find('"')
                .and_then(|open| {
                    after[open + 1..]
                        .find('"')
                        .map(|close| open + 1 + close + 1)
                })
                .unwrap_or(after.len())
        } else {
            0
        };
        start = after_start + consumed;
        start += line[start..].len() - line[start..].trim_start().len();
    }
}

/// The name of the function whose body the line at `lines` sits in, found by
/// the nearest preceding function DECLARATION.
///
/// A declaration is read by [`declared_item_name`], so a `pub`/`pub(crate)`/
/// `async`/`unsafe`/`const`/`extern` prefix is stripped before the `fn `
/// keyword is required and a `//` comment line is never read as one.
fn enclosing_function(lines: &[&str]) -> Option<String> {
    let mut enclosing = None;
    for line in lines {
        if let Some(name) = declared_item_name(line) {
            enclosing = Some(name);
        }
    }
    enclosing
}

/// One PRODUCTION observation callsite, keyed by what the fixture can name:
/// its file and the event literal its argument list carries.
struct ProductionCallsite {
    file: &'static str,
    event: String,
    line: usize,
    /// The observer this callsite calls.
    observer: &'static str,
    /// The function whose body the callsite sits in.
    enclosing: Option<String>,
    /// True for a callsite inside one of the six observer DECLARATIONS, which
    /// forwards the caller's `event`/`outcome` parameters instead of naming an
    /// event of its own and therefore owns no boundary row.
    forwarder: bool,
}

/// Every production observer callsite in `sources`, as a MULTISET keyed on
/// `(file, event literal)`.
///
/// This is per CALLSITE, where [`derived_instrumented_files`] is per FILE: a
/// file that still calls fifteen observers derives as present either way, so
/// deleting the sixteenth callsite from it is invisible to a file-level check
/// and invisible to a row-resolution check whose needles - `fn <name>` and the
/// event string - usually occur elsewhere in the same file. Counting per event
/// is what makes a deleted callsite cost the fixture exactly one row.
///
/// The key is `(file, event)` and NOT `(file, function, detail_prefix)`:
/// 64 of the 117 rows share a `detail_prefix` that occurs 2 to 15 times in its
/// module, so a prefix cannot address a callsite. The event literal can,
/// because it is what the callsite passes to the observer.
///
/// Two measured shapes are handled rather than assumed:
///
/// * a callsite whose argument list carries NO string literal has its event
///   bound to a local tuple - `process_execution.rs:2403` inside
///   `origin_grant_effect_receipt`, where `event` is one of the three
///   `kernel.process.grant_reconcile_*` literals above it. It keys on the
///   EMPTY event, which is exactly how the fixture's one empty-`event` row
///   (`reconcile_origin_grant_effect`, covering case 20) is spelled;
/// * a callsite inside an observer DECLARATION is a FORWARDER, not a boundary:
///   `process_execution.rs:67` forwards `(&context, event, outcome)` out of
///   `fn observe_process` (declared at `:65`), so it has no event of its own
///   and owns no row. It is reported separately instead of being folded into a
///   gap allowance.
fn derived_production_callsites(
    sources: &BTreeMap<&'static str, String>,
) -> Vec<ProductionCallsite> {
    let mut callsites = Vec::new();
    for (file, source) in sources {
        let lines: Vec<&str> = source.lines().collect();
        let excluded = test_module_extents(&lines);
        for observer in OBSERVER_FUNCTIONS {
            for hit in observer_callsite_offsets(source, observer) {
                let line_index = source[..hit].lines().count();
                if excluded
                    .iter()
                    .any(|(start, end)| line_index >= *start && line_index < *end)
                {
                    // A callsite inside an in-crate capsule is a TEST boundary,
                    // skipped exactly as `derived_instrumented_files` skips
                    // `src/tests/`. Only the capsule's own extent is skipped, so
                    // a production callsite BELOW one is still counted.
                    continue;
                }
                let enclosing = enclosing_function(&lines[..line_index]);
                let forwarder = enclosing
                    .as_deref()
                    .is_some_and(|name| OBSERVER_FUNCTIONS.contains(&name));
                let event = if forwarder {
                    String::new()
                } else {
                    first_string_literal(callsite_arguments(source, hit + observer.len()))
                        .unwrap_or_default()
                        .to_owned()
                };
                callsites.push(ProductionCallsite {
                    file,
                    event,
                    line: line_index + 1,
                    observer,
                    enclosing,
                    forwarder,
                });
            }
        }
    }
    callsites
}

/// The expected number of cases that own no boundary row, and what each claim
/// is.
///
/// Every claim below is quoted VERBATIM from issue #901's own
/// "## Required test matrix" section, read read-only from GitHub on 2026-10-03
/// with `gh issue view 901 --repo UnknownAlienHuman/eliot-memory-os
/// --comments` and `gh issue view 901 --repo
/// UnknownAlienHuman/eliot-memory-os --json body`: the numbered matrix list
/// "**30 cases, exactly 1..30.**", items 1..30. No claim is taken from the
/// FIXTURE's `note` gloss, from its `boundaries` rows or from its
/// `case_owners[].boundary` list; no sentence claims the matrix is unavailable.
/// Because none of these nine strings occurs anywhere in the fixture, the
/// expected set is independent of the artifact it checks.
///
/// WHAT THE ISSUE DOES NOT SAY. The matrix assigns a claim to each of the
/// thirty numbered cases and contains NO statement, in the body or in any
/// comment, that any case owns no boundary row: it never uses "row",
/// "rowless" or "cross-cutting" of a case. That these nine own no row is
/// therefore NOT read from the issue - it is MEASURED, from the production tree
/// and the fixture's declared `covering_case` values, by the two-way comparison
/// in [`assert_boundary_completeness`]. The issue supplies the wording; this
/// suite supplies the rowlessness, and asserts it in both directions.
///
/// CASE 1 is the single deliberate deviation and is not a rewrite of the issue.
/// The matrix line is "exact five-file process/supervision boundary
/// denominator" - the issue names five modules. This suite's denominator is
/// SIX instrumented files: those five plus `process_execution_client.rs`, which
/// carries one #901 callsite of its own. Entry 1 keeps the suite's corrected
/// denominator; the matrix line it corrects is quoted above so the difference
/// is visible rather than silent.
///
/// Each claim names what the ISSUE claims for its case, verbatim, and NOT one
/// instrumented callsite's emitted observation - which is the property that
/// makes these nine cross-cutting and every other declared case a boundary
/// owner. It is deliberately NOT a claim about what the test here proves: entry
/// 11 is the case where the two come apart, and case 11's own scope note
/// (`stale_generation_owner_stays_fenced_and_current_generation_is_admitted`)
/// records that the PID-reuse half of the issue's sentence has no
/// representation in these owned modules - no `pid_reused` or `foreign`
/// outcome literal exists in them - so that test proves the
/// generation/identity half only. The constant is the issue's expected set for
/// the rowlessness comparison, and the honest statement of what each case
/// reaches stays on that case.
const CROSS_CUTTING_ISSUE_CASES: [(u64, &str); 9] = [
    (1, "exact six-file process/supervision boundary denominator"),
    (9, "changed same-operation payload remains conflict"),
    (11, "PID reuse/foreign identity remains stale/foreign"),
    (
        25,
        "one terminal failure per underlying operation across propagation",
    ),
    (26, "typed cause/recovery owner preserved"),
    (
        27,
        "command/argument/environment/path/credential canaries absent",
    ),
    (28, "stream/provider/user payload canaries absent"),
    (
        29,
        "sink failure/drop/disabled logging preserves launch/cancel/lease/reap result, cleanup and order",
    ),
    (
        30,
        "fixed observations and actual instrumented-path captures preserve causal fields/order and exact diagnostic-only diff",
    ),
];

/// The nine cross-cutting case numbers, read out of [`CROSS_CUTTING_ISSUE_CASES`].
fn issue_cross_cutting_cases() -> BTreeSet<u64> {
    let cases: BTreeSet<u64> = CROSS_CUTTING_ISSUE_CASES
        .iter()
        .map(|(case, _claim)| *case)
        .collect();
    assert_eq!(
        cases.len(),
        CROSS_CUTTING_ISSUE_CASES.len(),
        "CROSS_CUTTING_ISSUE_CASES names no cross-cutting case twice"
    );
    for (case, claim) in CROSS_CUTTING_ISSUE_CASES {
        assert!(
            !claim.is_empty(),
            "cross-cutting case {case} carries its stated claim"
        );
    }
    cases
}

/// Proves the inventory is COMPLETE, not merely resolvable.
///
/// Five independent directions, all measured from the production tree or from
/// the nine rowless case numbers stated in [`CROSS_CUTTING_ISSUE_CASES`] - never
/// from the fixture's `boundaries` - against the fixture's `boundaries`:
///
/// * every derived `(file, event)` must have AT LEAST as many production
///   callsites as the fixture carries rows for it. This direction alone does
///   NOT catch a deleted callsite whose event literal occurs more than once in
///   the same module - `kernel.process.effect_observed` is passed to an
///   observer at fifteen production callsites - because deleting one of the
///   fifteen leaves the measured count above the row count. What catches it is
///   the per-file equality and the total below, and both name the module;
/// * every fixture row must correspond to a real production callsite of that
///   event in that file, and the multiset is compared in BOTH directions, so
///   DELETING one row and DUPLICATING another keeps the pinned row count at
///   117 and still turns this red;
/// * the derived callsite count and the fixture row count must be EQUAL PER
///   FILE, in both directions, which is the local form of the total below: it
///   is implied by the two key directions plus the total, and is stated here so
///   the failure names the module and both numbers instead of one difference;
/// * exactly one callsite may lack an event of its own, the named forwarder
///   `observe_process` in `process_execution.rs` (declared `:65`, forwarding
///   at `:67`), so there is no gap tolerance a second missing row could hide
///   inside;
/// * the set of declared cases owning NO row must be exactly the nine
///   cross-cutting cases, in BOTH directions, so a row moved ONTO one of them
///   and a case moved OFF one are both red here. That set check says nothing
///   about which ROW a boundary belongs to: repointing one row's
///   `covering_case` from one declared case to another leaves the unrowed set
///   unchanged and stays green, and this suite does not claim otherwise.
// One length buys this: the whole completeness proof reads as one ordered pass.
#[allow(clippy::too_many_lines)]
fn assert_boundary_completeness(
    boundaries: &[Value],
    declared: &BTreeSet<u64>,
    sources: &BTreeMap<&'static str, String>,
) {
    let callsites = derived_production_callsites(sources);
    let mut derived: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut forwarders: Vec<String> = Vec::new();
    let mut per_file: BTreeMap<&str, usize> = BTreeMap::new();
    for callsite in &callsites {
        *per_file.entry(callsite.file).or_insert(0) += 1;
        if callsite.forwarder {
            forwarders.push(format!("{}:{}", callsite.file, callsite.line));
            continue;
        }
        *derived
            .entry((callsite.file.to_owned(), callsite.event.clone()))
            .or_insert(0) += 1;
    }
    let mut rows: BTreeMap<(String, String), usize> = BTreeMap::new();
    for boundary in boundaries {
        let file = boundary["file"]
            .as_str()
            .expect("boundary file is a string")
            .to_owned();
        let event = boundary["event"]
            .as_str()
            .expect("boundary event is a string")
            .to_owned();
        *rows.entry((file, event)).or_insert(0) += 1;
    }

    // Direction 1: production is never UNDERSTATED by the inventory.
    for ((file, event), measured) in &derived {
        let named = rows
            .get(&(file.clone(), event.clone()))
            .copied()
            .unwrap_or_default();
        assert!(
            measured >= &named,
            "{file} passes \"{event}\" to an observer {measured} time(s) and the \
             fixture names it {named} time(s): a deleted production callsite \
             leaves every row-resolution check green and must be red here"
        );
    }
    // Direction 2: the inventory is never OVERSTATED by production, row by row.
    for ((file, event), named) in &rows {
        let measured = derived
            .get(&(file.clone(), event.clone()))
            .copied()
            .unwrap_or_default();
        assert!(
            measured >= *named,
            "the fixture names {named} row(s) for {file} :: \"{event}\" but the \
             production tree calls it {measured} time(s): deleting one row and \
             duplicating another keeps the pinned row COUNT and is red here"
        );
    }
    // The ONE forwarder, named - not an allowance.
    assert_eq!(
        forwarders.len(),
        1,
        "exactly one production callsite forwards its event argument instead of \
         naming one of its own: {forwarders:?}; a second one would be a second \
         unrowed boundary, not tolerance"
    );
    let forwarder = callsites
        .iter()
        .find(|callsite| callsite.forwarder)
        .expect("the one forwarder");
    assert_eq!(
        forwarder.file,
        OWNED_FILES
            .iter()
            .find(|owned| owned.ends_with("process_execution.rs"))
            .copied()
            .expect("process_execution.rs is an owned file"),
        "the one forwarder lives in process_execution.rs"
    );
    assert_eq!(
        forwarder.observer, "observe_process_in_context",
        "the one forwarder is the call `observe_process` makes into the shared \
         process observer"
    );
    assert_eq!(
        forwarder.enclosing.as_deref(),
        Some("observe_process"),
        "the one forwarder is the unscoped wrapper declared at \
         process_execution.rs:65, which forwards its own `event`/`outcome` \
         parameters at :67 and therefore owns no boundary row"
    );
    // The LITERAL-FREE callsites, pinned by their own count rather than by the
    // enclosing function's NAME. A second wrapper - `fn observe_process_scoped(
    // event, outcome) { observe_process_in_context(&ctx, event, outcome) }` - is
    // classified a NON-forwarder (its enclosing name is not one of the six
    // observers) and keyed on the empty event, so the one-forwarder count above
    // stays GREEN for it and the failure is reported three times over: this
    // count names the wrapper's file, line and enclosing function, the per-file
    // equality above names its module, and the total difference names the one
    // forwarder it knows. A wrapper whose enclosing name IS one of the six
    // observers is caught by the forwarder count instead, which also names it.
    // The tree legitimately has exactly ONE callsite whose argument list carries
    // no string literal (`process_execution.rs:2403`, inside
    // `reconcile_origin_grant_effect_receipt`, which owns a real row), and the
    // fixture exactly ONE row whose `event` is the empty string, so those two
    // counts are equal and must stay equal: a wrapper adds one to each.
    let literal_free: Vec<String> = callsites
        .iter()
        .filter(|callsite| !callsite.forwarder && callsite.event.is_empty())
        .map(|callsite| {
            format!(
                "{}:{} calls {} in fn {}",
                callsite.file,
                callsite.line,
                callsite.observer,
                callsite.enclosing.as_deref().unwrap_or("<none>")
            )
        })
        .collect();
    let empty_event_rows: Vec<String> = boundaries
        .iter()
        .filter(|boundary| boundary["event"].as_str() == Some(""))
        .map(|boundary| {
            let file = boundary["file"]
                .as_str()
                .expect("boundary file is a string");
            let covering_case = boundary["covering_case"]
                .as_u64()
                .expect("boundary covering_case is a case number");
            format!("{file} :: \"\" (covering case {covering_case})")
        })
        .collect();
    assert_eq!(
        literal_free.len(),
        empty_event_rows.len(),
        "the production callsites with NO string literal in their argument list \
         number {literal_free:?}, and the fixture rows whose event is the empty \
         string number {empty_event_rows:?}; those two counts are equal by \
         construction, so a wrapper that forwards a non-literal argument instead \
         of naming an event adds one to each and is red here"
    );
    let derived_total: usize = derived.values().sum();
    let rows_total: usize = rows.values().sum();
    let production_total = derived_total + forwarders.len();
    // PER FILE, in BOTH directions, before the total. The two `(file, event)`
    // directions above compare `measured >= named` per KEY and the total below
    // closes the sum, so per-file equality is already implied - but an implied
    // equality is reported only as one number, and the number does not say which
    // module lost or gained a callsite. This states it per module, naming both
    // sides, so a DELETED callsite is a message that reads "process_execution.rs:
    // 84 derived against 85 rows" instead of "the totals differ by -1".
    let mut rows_per_file: BTreeMap<&str, usize> = BTreeMap::new();
    for boundary in boundaries {
        let file = boundary["file"]
            .as_str()
            .expect("boundary file is a string");
        *rows_per_file.entry(file).or_insert(0) += 1;
    }
    let mut derived_per_file: BTreeMap<&str, usize> = BTreeMap::new();
    for ((file, _event), count) in &derived {
        *derived_per_file.entry(file.as_str()).or_insert(0) += *count;
    }
    for file in derived_per_file.keys().chain(rows_per_file.keys()) {
        let measured = derived_per_file.get(*file).copied().unwrap_or(0);
        let named = rows_per_file.get(*file).copied().unwrap_or(0);
        assert_eq!(
            measured, named,
            "{file} carries {measured} production observation callsite(s) that \
             name an event of their own and the fixture names it {named} row(s), \
             in EITHER direction: a deleted production callsite, or a row \
             duplicated in one module while another module's callsite went \
             missing, is red here with both numbers named"
        );
    }
    // Signed, so a fixture that names MORE rows than the tree calls reports
    // this difference instead of underflowing on the way to the message.
    assert_eq!(
        i64::try_from(production_total).expect("the production callsite total is a count")
            - i64::try_from(rows_total).expect("the fixture row total is a count"),
        i64::try_from(forwarders.len()).expect("the forwarder total is a count"),
        "the production callsites exceed the fixture's rows by EXACTLY the one \
         named forwarder and by nothing else: measured per file {per_file:?} \
         against rows per file {rows_per_file:?}, that is {production_total} \
         production callsites ({derived_total} keyed + {} forwarder) against \
         {rows_total} rows; this difference is derived, never a tolerance. The \
         per-file equality above localises any such difference to its module",
        forwarders.len()
    );

    // The nine cross-cutting cases, and no others, own no row.
    let owned_by_a_row: BTreeSet<u64> = boundaries
        .iter()
        .map(|boundary| {
            boundary["covering_case"]
                .as_u64()
                .expect("boundary covering_case is a case number")
        })
        .collect();
    let cross_cutting = issue_cross_cutting_cases();
    let unrowed: BTreeSet<u64> = declared.difference(&owned_by_a_row).copied().collect();
    assert_eq!(
        unrowed, cross_cutting,
        "exactly the nine cross-cutting cases own no boundary row and every \
         other declared case owns at least one: the unrowed SET is compared in \
         both directions, so a row given a cross-cutting covering_case, or a \
         cross-cutting case given a row, is red here. Repointing one row from \
         one DECLARED case to another DECLARED case is NOT what this checks - \
         it leaves the unrowed set unchanged - and no claim is made about it"
    );
    let reclaimed: Vec<u64> = cross_cutting.difference(declared).copied().collect();
    assert_eq!(
        reclaimed,
        Vec::<u64>::new(),
        "every cross-cutting case is a DECLARED case"
    );
}

/// Walks this package's `src/` tree once and returns every PRODUCTION Rust
/// source file, paired with its repository-relative path spelling, sorted by
/// that spelling.
///
/// Both derivations that walk the tree share this one walk, so they cannot
/// disagree about which files exist or which two shapes are skipped.
///
/// The root is `env!("CARGO_MANIFEST_DIR")`, which Cargo fixes at COMPILE time
/// to this integration-test target's own package directory,
/// `<repo>/bins/eliot-kernel`. Nothing here reads the process working
/// directory, so the walk cannot follow wherever the test binary was started
/// from. The walk is a `read_dir` recursion because `std` has no
/// directory-tree iterator available here; the result is collected through a
/// `BTreeMap` because `read_dir` order is unspecified and every assertion must
/// not depend on it.
///
/// Exactly two shapes are skipped, and both are test code rather than
/// production code: `src/tests.rs` and everything under `src/tests/`. That is
/// where `src/lib.rs` registers its five `#[cfg(test)]` capsules (`#[cfg(test)]
/// mod tests;` at `:5699` and one `#[path = "tests/....rs"]` module per
/// capsule), and a callsite inside one of them is a test callsite, not a
/// production boundary. The skip is structural rather than name-based, so adding
/// a production module anywhere else under `src/` still reaches every assertion.
///
/// WHAT THIS WALK DOES NOT EXCLUDE, stated so no caller reads it as a single
/// definition of "production" for the whole file: an IN-FILE `#[cfg(test)] mod`
/// capsule is walked like any other text. This crate has several - measured on
/// this tree, `process_execution.rs:4827` and `:4948`, `daemon_supervision.rs
/// :802`, `daemon_process_launch.rs:681`, `generation_control.rs:1324`,
/// `generation_recovery.rs:556` and `runtime_identity.rs:195` - so the two
/// derivations that use this walk use DIFFERENT definitions on purpose:
/// [`derived_instrumented_files`] counts a FILE as instrumented if it calls an
/// observer anywhere, including inside an in-file capsule, and
/// [`derived_production_callsites`] excludes the capsule EXTENT via
/// [`test_module_extents`] before keying a CALLSITE. That asymmetry is
/// conservative in the only direction that matters here: a module whose only
/// observer callsite is test-gated still enters the denominator and turns case 1
/// red rather than quietly shrinking it, while the per-callsite multiset never
/// counts a test callsite as a production boundary.
fn production_source_files() -> Vec<(String, String)> {
    let package_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut pending = vec![package_root.join("src")];
    let mut files = BTreeMap::new();
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("{} must be readable: {error}", dir.display()));
        for entry in entries {
            let path = entry.expect("a readable source directory entry").path();
            let relative = path
                .strip_prefix(&package_root)
                .expect("every walked path is under this package")
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "src/tests.rs" || relative.starts_with("src/tests/") {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
                files.insert(relative, source);
            }
        }
    }
    files.into_iter().collect()
}

/// Every production source file that CALLS one of [`OBSERVER_FUNCTIONS`], as
/// sorted repository-relative paths.
///
/// This walk is [`production_source_files`], filtered; the root and the two
/// skipped test shapes are stated there. `package_prefix` is taken from the
/// fixture's own `test_file`, so the repository-relative spelling compared
/// against `files` cannot drift away from the tree that was actually walked;
/// case 1 asserts the manifest directory really ends with that prefix before
/// calling this.
fn derived_instrumented_files(package_prefix: &str) -> Vec<String> {
    let mut derived: Vec<String> = production_source_files()
        .into_iter()
        .filter(|(_relative, source)| {
            OBSERVER_FUNCTIONS
                .iter()
                .any(|observer| calls_observer(source, observer))
        })
        .map(|(relative, _source)| format!("{package_prefix}/{relative}"))
        .collect();
    derived.sort();
    derived
}

/// Every `observe`-named function DECLARATION in `source`, as a set of names.
///
/// "DECLARATION" is decided by [`is_observer_declaration`], so the same
/// structural question is answered one way in the denominator derivation and
/// here: the name is introduced by an `fn` keyword, with only whitespace,
/// `async`, `unsafe` or `pub(..)` between it and the name. A `use` of the same
/// name, and any mention inside a `//` comment line, are not declarations.
///
/// The visibility modifier is deliberately NOT part of what is returned, which
/// is what lets one set pin the three escaped spellings at once: a
/// `pub(crate) fn observe_...`, a `pub async fn observe_...` and a
/// `pub fn observe(` are all read here as the declarations they are, so
/// comparing the set against [`OWNED_OBSERVATION_DECLARATIONS`] closes all
/// three without three separate needles.
///
/// The matched prefix must END a name, or the set would pin production
/// accessors whose names merely begin with those letters: `observed` is
/// matched by `fn observe` and is declared twice in `process_execution.rs`
/// (`:372`, `:407`, both `pub(crate) fn observed(&self) -> bool`), and it is a
/// state accessor, not an observation surface. So a name that continues with an
/// identifier byte is not a name at all here.
fn derived_observation_declarations(source: &str) -> BTreeSet<String> {
    // Test-gated module bodies are EXCLUDED here, by the same brace-matched
    // extent rule the subscriber check uses. The claim this reader backs is about
    // the observation surfaces an owned module EXPOSES, and a `fn observe...`
    // declared inside that module's own `#[cfg(test)]` capsule exposes nothing:
    // it is a test helper, it is not reachable from production, and it is not a
    // second observation surface. This exclusion is what makes the reading
    // independent of where the private-boundary proof physically lives - a
    // helper named `observe_live_receipt_callsites` inside the inlined #901
    // capsule is the same helper whether it sits in `daemon_live_receipt.rs` or in
    // a separate `src/tests/` file the walk skips, and this reader must not
    // change its answer when the file moves.
    let lines: Vec<&str> = source.lines().collect();
    let extents = test_module_extents(&lines);
    let mut declared = BTreeSet::new();
    for (hit, _) in source.match_indices("fn observe") {
        let line_index = source[..hit].matches('\n').count();
        if extents
            .iter()
            .any(|(start, end)| line_index >= *start && line_index < *end)
        {
            continue;
        }
        let name_start = hit + "fn ".len();
        if source[hit + "fn observe".len()..]
            .starts_with(|character: char| character.is_ascii_alphanumeric())
        {
            continue;
        }
        if !is_observer_declaration(source, name_start) {
            continue;
        }
        let head = source[..hit]
            .rsplit_once('\n')
            .map_or("", |(_, tail)| tail)
            .trim();
        if head.starts_with("//") {
            continue;
        }
        let rest = &source[name_start..];
        let end = rest
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(rest.len());
        declared.insert(rest[..end].to_owned());
    }
    declared
}

/// Every production module under `src/` that installs a subscriber, as sorted
/// crate-relative paths.
///
/// This is the derivation that finds a module which installs its OWN subscriber
/// without calling one of the six observers: such a module is in neither
/// [`OWNED_FILES`] nor [`OWNED_PATHS`], and
/// [`derived_instrumented_files`] is keyed only on the observer names, so no
/// other reader in this file can reach it.
///
/// "Production" excludes a test-gated `mod` capsule by MODULE EXTENT, measured
/// by the existing [`test_module_extents`] rather than by a second brace
/// mechanism, so the same definition decides both exclusions. FIVE installs
/// legitimately sit inside such capsules and are excluded by that extent alone
/// - `process_execution.rs:4866` inside the two capsules of one owned module,
///   `daemon_supervision.rs:841` inside the capsule of another, and
///   `generation_recovery.rs:606`, `generation_control.rs:1358` and
///   `runtime_identity.rs:234` inside three capsules outside the owned six.
///   The count is five and the enumeration above names five: it is the only
///   subscriber install outside a capsule that exists on this tree besides the
///   facade declaration at `kernel_diagnostics.rs:242` and the composition
///   root's single call at `main.rs:224`, which are the two NAMED owners in
///   [`FACADE_SUBSCRIBER_OWNERS`].
fn derived_subscriber_installers() -> Vec<String> {
    production_source_files()
        .into_iter()
        .filter_map(|(relative, source)| {
            let lines: Vec<&str> = source.lines().collect();
            let extents = test_module_extents(&lines);
            let installs = FORBIDDEN_SUBSCRIBER_IN_PRODUCTION
                .iter()
                .any(|needle| !production_needle_offsets(&source, needle, &extents).is_empty());
            installs.then_some(relative)
        })
        .collect()
}

/// The line indices in `source` at which `needle` occurs OUTSIDE every
/// `(start, end)` line extent in `extents`.
///
/// One definition of "this occurrence is in production code", shared by the
/// per-owned-module check and the whole-tree derivation, so the two cannot
/// decide the four legitimate test-gated installs differently.
fn production_needle_offsets(source: &str, needle: &str, extents: &[(usize, usize)]) -> Vec<usize> {
    source
        .match_indices(needle)
        .map(|(hit, _)| source[..hit].lines().count())
        .filter(|line| {
            !extents
                .iter()
                .any(|(start, end)| *line >= *start && *line < *end)
        })
        .collect()
}

/// Asserts that no owned module installs a subscriber outside a test-gated
/// module, naming the offending file and line.
///
/// The exclusion is by MODULE EXTENT from [`test_module_extents`], so the TWO
/// legitimate thread-local installs in the owned six - the `with_default(` call
/// at `daemon_supervision.rs:841` and the one at `process_execution.rs:4866` -
/// are excluded as a property of the capsule that contains them rather than as
/// two enumerated exceptions, while the same `with_default(` or `set_default(`
/// call added anywhere else in any owned module - including BELOW a capsule,
/// which a file-truncating shortcut would hide - is red here.
fn assert_no_production_subscriber(owned: &str, source: &str) {
    let lines: Vec<&str> = source.lines().collect();
    let extents = test_module_extents(&lines);
    let mut installs: Vec<String> = Vec::new();
    for needle in FORBIDDEN_SUBSCRIBER_IN_PRODUCTION {
        for line in production_needle_offsets(source, needle, &extents) {
            installs.push(format!("{needle} at line {}", line + 1));
        }
    }
    assert_eq!(
        installs,
        Vec::<String>::new(),
        "{owned} installs a subscriber OUTSIDE every test-gated module: {installs:?}. \
         The thread-local installs that exist today all sit inside `#[cfg(test)]` \
         capsules, and there are exactly TWO of them in the owned six: the \
         `with_default(` call at daemon_supervision.rs:841 and the one at \
         process_execution.rs:4866 (`:837` and `:4862` are the \
         `tracing_subscriber::fmt()` builder lines of the same two capture \
         helpers, not installs). The exclusion is by that capsule's \
         brace-matched extent, so a production thread-local subscriber - \
         including one appended BELOW a capsule - is a second owner exactly \
         like a process-global one"
    );
}

/// Asserts that `owned` declares exactly the observation surfaces the owned set
/// already carries, in any visibility and with or without `async`.
fn assert_observation_declarations(owned: &str, source: &str) {
    let expected: BTreeSet<String> = OWNED_OBSERVATION_DECLARATIONS
        .iter()
        .filter(|(path, _name)| *path == owned)
        .map(|(_path, name)| (*name).to_owned())
        .collect();
    assert_eq!(
        derived_observation_declarations(source),
        expected,
        "{owned} declares exactly the observation surfaces the five owned modules \
         already carry, in BOTH directions and reading PRODUCTION text only: the \
         visibility and the `async` modifier are not part of the key, so \
         `pub(crate) fn observe_...` (the one legitimate spelling, \
         process_execution.rs:73), `pub async fn observe_...` and `pub fn observe(` \
         are all read as declarations and a second one is red here. A `fn \
         observe...` inside this module's own `#[cfg(test)]` capsule is excluded \
         by brace-matched extent and is not a second observation surface"
    );
}

/// The `(case, test function)` pairs THIS file claims, read out of its own
/// issue markers through a compile-time `include_str!` of itself.
///
/// This is the INDEPENDENT expected set for the fixture's `case_owners`: the
/// marker text in this source file is the authority for which case number
/// belongs to which test function, so renaming a test, moving a marker or
/// dropping one turns case 1 red instead of leaving a copied table agreeing
/// with itself.
fn local_case_owners() -> BTreeMap<u64, String> {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/kernel_process_supervision_diagnostics.rs"
    ));
    let mut owners: BTreeMap<u64, String> = BTreeMap::new();
    let mut pending: Option<u64> = None;
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(WORK_UNIT_MARKER) {
            assert!(
                pending.is_none(),
                "two issue markers with no test between them: {trimmed}"
            );
            pending = Some(
                rest.trim()
                    .parse::<u64>()
                    .expect("an issue marker carries a case number"),
            );
        } else if let Some(signature) = trimmed.strip_prefix("fn ")
            && let Some(case) = pending.take()
        {
            let name = signature
                .split_once('(')
                .map_or("", |(name, _)| name)
                .to_owned();
            assert!(
                owners.insert(case, name).is_none(),
                "case {case} is claimed by two tests in this file"
            );
        }
    }
    assert!(
        pending.is_none(),
        "an issue marker in this file owns no test function"
    );
    owners
}

// ---------------------------------------------------------------------------
// Authenticated session fixtures
// ---------------------------------------------------------------------------

const MODULE_ID: &str = "eliot-901-module";
const PEER_SID: &str = "S-1-5-21-1000";
const PEER_SESSION: &str = "4";
const CONNECTION_ID: &str = "conn-901-process";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

fn test_generation() -> Generation {
    Generation::new(1).expect("generation")
}

fn authenticated_peer() -> PeerIdentity {
    let binding = eliot_ipc::ProcessBinding::from_observation(4242, 99_001, r"C:\Eliot\bridge.exe")
        .expect("fake process binding");
    PeerIdentity::authenticated_for_test(binding, PEER_SID.to_owned(), PEER_SESSION.to_owned())
        .expect("fake authenticated peer")
}

fn process_session() -> Session {
    let resource_gen = ResourceGeneration::new(1).expect("resource generation");
    let fence = eliot_contracts::StateFence::new(test_epoch(1), resource_gen);
    Session {
        connection_id: CONNECTION_ID.to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer: authenticated_peer(),
        authority_epoch: test_epoch(1),
        module_generation: ModuleGeneration {
            module_id: ContractId::new(MODULE_ID).expect("module id"),
            generation: resource_gen,
            artifact_id: ArtifactId::new("a".repeat(64)).expect("artifact id"),
            state: ModuleGenerationState::Starting,
            health: HealthVector::healthy(),
            state_fence: fence,
        },
        launch_nonce: "eliot-901-launch-nonce".to_owned(),
        capabilities: vec![],
        privacy_classes: vec!["PUBLIC".to_owned()],
        effects: vec![],
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn session_binding() -> ProcessSessionBinding {
    ProcessSessionBinding::new(CONNECTION_ID, 1).expect("process session binding")
}

/// Fixture-only reproduction of the crate-internal stable owner digest
/// (`src/runtime_identity.rs:176`) so a durable replay record can be seeded
/// with the exact owner this authenticated session derives. No observation
/// behaviour, no event name and no terminal code is reproduced here.
fn session_owner(session: &Session) -> ProcessOwnerBinding {
    let PeerIdentity::Authenticated { user_identity, .. } = &session.peer else {
        panic!("process fixture requires an authenticated peer");
    };
    let generation = test_generation();
    let mut principal = Sha256::new();
    principal.update(user_identity.as_str().as_bytes());
    principal.update(session.module_generation.module_id.as_str().as_bytes());
    principal.update(session.authority_epoch.lineage_id.as_str().as_bytes());
    principal.update(session.authority_epoch.sequence.get().to_le_bytes());
    principal.update(generation.get().to_le_bytes());
    ProcessOwnerBinding::new(
        session.module_generation.module_id.as_str(),
        format!("{:x}", Sha256::digest(principal.finalize())),
        session.authority_epoch.clone(),
        generation,
    )
    .expect("derived process owner")
}

// ---------------------------------------------------------------------------
// Admission fixtures
// ---------------------------------------------------------------------------

struct IntentShape {
    operation_id: String,
    process_tree_id: String,
    executable: String,
    executable_sha256: String,
    argv: Vec<String>,
    working_directory: String,
    environment: BTreeMap<String, String>,
    secret_refs: Vec<SecretRef>,
}

fn default_shape(operation_id: &str) -> IntentShape {
    IntentShape {
        operation_id: operation_id.to_owned(),
        process_tree_id: format!("{operation_id}-tree"),
        executable: r"C:\Eliot\worker.exe".to_owned(),
        executable_sha256: "c".repeat(64),
        argv: vec!["--serve".to_owned()],
        working_directory: r"C:\Eliot".to_owned(),
        environment: BTreeMap::from([("ELIOT_MODE".to_owned(), "kernel".to_owned())]),
        secret_refs: Vec::new(),
    }
}

fn shape_intent(shape: &IntentShape) -> ProcessIntent {
    ProcessIntent::new(
        OperationId::new(shape.operation_id.clone()).expect("operation id"),
        ProcessTreeId::new(shape.process_tree_id.clone()).expect("process tree id"),
        JobId::new(format!("{}-job", shape.operation_id)).expect("job id"),
        ImageId::new(format!("{}-image", shape.operation_id)).expect("image id"),
        SessionId::new(format!("{}-session", shape.operation_id)).expect("session id"),
        test_generation(),
        shape.executable.clone(),
        shape.executable_sha256.clone(),
        shape.argv.clone(),
        shape.working_directory.clone(),
        EnvironmentProjection::new(
            shape.environment.clone(),
            shape.secret_refs.clone(),
            EnvironmentInheritance::None,
        )
        .expect("environment projection"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
            .expect("resource limits"),
    )
    .expect("process intent")
}

fn shape_admission(shape: &IntentShape) -> ProcessExecutionAdmissionRequest {
    ProcessExecutionAdmissionRequest::new(
        MODULE_ID,
        shape_intent(shape),
        ActionLeaseRef::new(format!("{}-lease", shape.operation_id)).expect("action lease"),
        FencingToken::new(
            test_epoch(1),
            test_generation(),
            format!("{}-fence", shape.operation_id),
        )
        .expect("fencing token"),
        4_102_444_800_000,
    )
    .expect("process execution admission")
}

/// Seed intent used only to persist the process-authority replay snapshot the
/// public `new_with_process_authority` constructor restores from.
fn authority_seed_intent() -> ProcessIntent {
    ProcessIntent::new(
        OperationId::new("eliot-901-authority-seed-operation").expect("operation id"),
        ProcessTreeId::new("eliot-901-authority-seed-tree").expect("tree"),
        JobId::new("eliot-901-authority-seed-job").expect("job"),
        ImageId::new("eliot-901-authority-seed-image").expect("image"),
        SessionId::new("eliot-901-authority-seed-session").expect("session"),
        test_generation(),
        r"C:\Eliot\seed-worker.exe",
        "d".repeat(64),
        vec!["--seed".to_owned()],
        r"C:\Eliot",
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .expect("environment"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
            .expect("resource limits"),
    )
    .expect("authority seed intent")
}

// ---------------------------------------------------------------------------
// Public composition construction
// ---------------------------------------------------------------------------

/// Opaque, secret-free test codec standing in for the production DPAPI
/// authority snapshot codec. It exists only so the public
/// `new_with_process_authority` constructor has a codec to restore through;
/// it grants no authority and is not production behaviour.
struct FixtureAuthorityCodec;

impl DispatchSnapshotCodec for FixtureAuthorityCodec {
    fn seal(
        &self,
        snapshot: &KernelAuthorityReplaySnapshot,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<SealedAuthoritySnapshot> {
        let ciphertext = serde_json::to_vec(snapshot)
            .map_err(|e| KernelError::DependencyUnavailable(e.to_string()))?;
        let key = SecretReference::new("fixture-provider", "eliot-901-authority")
            .map_err(|e| KernelError::DependencyUnavailable(e.to_string()))?;
        SealedAuthoritySnapshot::new(key, ciphertext)
    }

    fn open(
        &self,
        payload: &RecoveryPayload,
        _binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<KernelAuthorityReplaySnapshot> {
        let RecoveryPayload::Encrypted { ciphertext, .. } = payload else {
            return Err(KernelError::RecoveryUnavailable(
                "901 authority fixture payload is not encrypted".to_owned(),
            ));
        };
        serde_json::from_slice(ciphertext)
            .map_err(|e| KernelError::RecoveryUnavailable(e.to_string()))
    }
}

fn authority_binding(authority_id: &DispatchAuthorityId) -> AuthoritySnapshotBinding {
    let epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new("eliot-901-lineage").expect("lineage"),
            epoch: 1,
        },
        predecessor: None,
    };
    let state_fence =
        StateFenceSnapshot::capture(&serde_json::json!({"authority": "eliot-901"}), 1)
            .expect("state fence snapshot");
    AuthoritySnapshotBinding::new(
        authority_id.clone(),
        OperationIdentity::new("eliot-901-authority-record").expect("record id"),
        epoch,
        state_fence,
        1,
        None,
    )
    .expect("authority snapshot binding")
}

fn ors_path(root: &std::path::Path) -> PathBuf {
    root.join(".eliot").join("kernel-ors.redb")
}

fn open_ors(root: &std::path::Path) -> RedbRecoveryStore {
    let path = ors_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("ors parent");
    }
    RedbRecoveryStore::open(&path).expect("real ORS store")
}

/// Persists one durable process-start replay record through the same public
/// ORS seam the gateway's own replay store reads.
fn seed_replay_record(store: &RedbRecoveryStore, operation_id: &str, owner: ProcessOwnerBinding) {
    let record = ProcessStartReplayRecord {
        operation_id: OperationIdentity::new(operation_id).expect("replay operation identity"),
        admission_digest: "a".repeat(64),
        owner,
        state: ProcessStartReplayState::Reserved,
        receipt: None,
    };
    store
        .begin_process_start(&record)
        .expect("seed durable process-start replay record");
}

/// Builds one process-authority composition, seeding the durable replay
/// records the named operations will later be read back under.
///
/// The guard is returned FIRST on purpose: it is bound first and therefore
/// dropped last, after the `Arc<KernelComposition>` has released its open
/// redb file.
fn process_authority_kernel(
    suffix: &str,
    seeds: &[(&str, ProcessOwnerBinding)],
) -> (TempGuard, Arc<KernelComposition>) {
    let root = unique_root(suffix);
    let authority_id =
        DispatchAuthorityId::new("eliot-901-kernel-authority").expect("authority id");
    let binding = authority_binding(&authority_id);
    let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(FixtureAuthorityCodec);
    let key = KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("dispatch key");

    {
        let store = Arc::new(open_ors(&root));
        let store_port: Arc<dyn eliot_ors::OperationalRecoveryStore> = store.clone();
        let mut controller = ProcessDispatchAuthorityController::activate(
            authority_id.clone(),
            KernelDispatchKey::from_secret_bytes([0x4a; 32]).expect("seed dispatch key"),
            store_port,
            Arc::clone(&codec),
        );
        let seed_fence =
            FencingToken::new(test_epoch(1), test_generation(), "eliot-901-seed-fence")
                .expect("seed fence");
        controller
            .issue(
                &authority_seed_intent(),
                PermitIssuance::new(
                    ActionLeaseRef::new("eliot-901-seed-lease").expect("seed lease"),
                    seed_fence,
                    BTreeMap::from([("authority".to_owned(), "a".repeat(64))]),
                    1,
                    2,
                    "eliot-901-seed-nonce",
                )
                .expect("seed issuance"),
                &binding,
            )
            .expect("seed the authority replay snapshot");
        drop(controller);
        for (operation_id, owner) in seeds {
            seed_replay_record(store.as_ref(), operation_id, owner.clone());
        }
    }

    let mut config = KernelConfig::new(&root);
    config.pipe_name = format!(r"\\.\pipe\eliot\kernel-901-{suffix}-{}", std::process::id());
    let kernel = KernelComposition::new_with_process_authority(
        config,
        eliot_kernel::ProcessExecutionAuthorityConfig {
            authority_id,
            key,
            snapshot_binding: binding,
            snapshot_codec: codec,
        },
    )
    .expect("process-authority composition");
    assert!(kernel.process_execution_configured());
    (TempGuard { root }, Arc::new(kernel))
}

// ---------------------------------------------------------------------------
// Callsite drivers
// ---------------------------------------------------------------------------

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn drive_request<'a>(
    kernel: &'a KernelComposition,
    session: &'a Session,
    binding: &'a ProcessSessionBinding,
    request: ProcessExecutionRequest,
) -> (String, ProcessExecutionResponse) {
    let rt = current_thread_runtime();
    capture_blocking(move || {
        rt.block_on(kernel.execute_process_request(session, binding.clone(), request))
    })
}

fn drive_client_start(
    kernel: &Arc<KernelComposition>,
    session: &Session,
    binding: &ProcessSessionBinding,
    admission: ProcessExecutionAdmissionRequest,
) -> (String, ProcessExecutionResponse) {
    let rt = current_thread_runtime();
    capture_blocking(move || {
        let client = eliot_kernel::process_execution_client(kernel, session, binding)
            .expect("front-door process-execution client");
        rt.block_on(client.execute(ProcessExecutionRequest::Start(admission)))
    })
}

fn operation_request(operation_id: &str) -> ProcessExecutionRequest {
    let id = OperationId::new(operation_id).expect("operation id");
    ProcessExecutionRequest::Cancel { operation_id: id }
}

fn inspect_request(operation_id: &str) -> ProcessExecutionRequest {
    let id = OperationId::new(operation_id).expect("operation id");
    ProcessExecutionRequest::Inspect { operation_id: id }
}

fn reconcile_request(operation_id: &str) -> ProcessExecutionRequest {
    let id = OperationId::new(operation_id).expect("operation id");
    ProcessExecutionRequest::Reconcile { operation_id: id }
}

fn rejection_code(response: &ProcessExecutionResponse) -> String {
    let ProcessExecutionResponse::Rejected(rejection) = response else {
        panic!("expected a typed rejection, got {response:?}");
    };
    rejection.code.clone()
}

fn rejection_detail(response: &ProcessExecutionResponse) -> String {
    let ProcessExecutionResponse::Rejected(rejection) = response else {
        panic!("expected a typed rejection, got {response:?}");
    };
    rejection.detail.clone()
}

/// The fixture's `files` array, read as owned strings.
fn fixture_owned_files(f: &Value) -> Vec<String> {
    f["files"]
        .as_array()
        .expect("fixture files array")
        .iter()
        .map(|value| value.as_str().expect("owned file string").to_owned())
        .collect()
}

/// The fixture's `out_of_scope_instrumented_files` array, read as owned strings.
///
/// This is the array that lets the OWNED denominator stay at exactly five while
/// the sixth instrumented file stays accounted for, so it is read here rather
/// than folded into `fixture_owned_files`: merging the two is the widening this
/// case refuses.
fn fixture_out_of_scope_files(f: &Value) -> Vec<String> {
    f["out_of_scope_instrumented_files"]
        .as_array()
        .expect("fixture out_of_scope_instrumented_files array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("an out-of-scope file string")
                .to_owned()
        })
        .collect()
}

/// Proves case 30's forbidden-vocabulary sweep covers exactly the paths the
/// denominator derivation covers.
///
/// The two lists are spelled differently - [`OWNED_FILES`] repository-relative,
/// [`OWNED_PATHS`] crate-relative - so they are compared AFTER the same
/// `src/<module>` suffix is taken from both. Without this, adding an owned
/// module would sweep five paths while the derivation walks six, and a second
/// subscriber owner or a new public observation surface could be added in the
/// unswept file with every assertion green.
fn assert_sweep_covers_derivation() {
    let crate_relative = |repository_relative: &str| {
        let (_, module) = repository_relative.split_once("/src/").unwrap_or_else(|| {
            panic!("swept file {repository_relative} names a module under this package's src/")
        });
        format!("src/{module}")
    };
    let mut measured: BTreeSet<String> = OWNED_FILES
        .iter()
        .chain(OUT_OF_SCOPE_INSTRUMENTED_FILES.iter())
        .map(|file| crate_relative(file))
        .collect();
    let swept: BTreeSet<&str> = SWEPT_PATHS.iter().copied().collect();
    assert_eq!(
        swept.len(),
        SWEPT_PATHS.len(),
        "the sweep names no path twice"
    );
    for path in swept {
        measured.remove(path);
    }
    assert_eq!(
        measured,
        BTreeSet::new(),
        "case 30's forbidden-vocabulary sweep covers every path the derivation \
         covers: a file the denominator names but OWNED_PATHS/SWEPT_PATHS do not \
         sweep is never read"
    );
    let unswept: Vec<&str> = SWEPT_PATHS
        .iter()
        .copied()
        .filter(|path| {
            !OWNED_FILES
                .iter()
                .chain(OUT_OF_SCOPE_INSTRUMENTED_FILES.iter())
                .any(|named| named.ends_with(path))
        })
        .collect();
    assert_eq!(
        unswept,
        Vec::<&str>::new(),
        "case 30 sweeps no path the derivation does not cover"
    );
}

/// Proves the denominator of case 1 in BOTH directions against the DERIVED
/// callsite set, and returns nothing.
///
/// * the length of `files` must equal the length of [`OWNED_FILES`] and the two
///   sets must match member for member, so the OWNED denominator is EXACTLY the
///   five modules issue #901 names - a sixth file cannot be added to the fixture
///   to make a derived set agree with it, which is the widening this case exists
///   to refuse;
/// * the length of `out_of_scope` must equal the length of
///   [`OUT_OF_SCOPE_INSTRUMENTED_FILES`] exactly and the two must be disjoint
///   from `files`, so an instrumented file outside this issue's scope is NAMED
///   rather than absorbed into the owned set;
/// * the derived set must equal the union of those two lists exactly - so a
///   seventh instrumented module, a renamed module, a relocated module, or the
///   loss of the client module's `observe_process_in_context` callsite at
///   `process_execution_client.rs:106` all turn this red;
/// * the two lists must differ in neither direction against the derived set, so
///   neither a named file that stopped instrumenting nor an instrumented file in
///   neither list can survive here.
fn assert_denominator(files: &[String], out_of_scope: &[String], derived: &[String]) {
    assert_sweep_covers_derivation();
    assert_eq!(
        files.len(),
        OWNED_FILES.len(),
        "the fixture names exactly the five modules this issue owns, and no more: \
         widening `files` is not how a disagreement with the derived set is settled"
    );
    for expected in OWNED_FILES {
        assert!(
            files.iter().any(|value| value == expected),
            "fixture must list the owned file {expected}"
        );
    }
    assert_eq!(
        out_of_scope.len(),
        OUT_OF_SCOPE_INSTRUMENTED_FILES.len(),
        "the fixture names exactly the instrumented files this issue does NOT own"
    );
    for expected in OUT_OF_SCOPE_INSTRUMENTED_FILES {
        assert!(
            out_of_scope.iter().any(|value| value == expected),
            "fixture must list {expected} as an out-of-scope instrumented file"
        );
    }
    for file in files {
        assert!(
            !out_of_scope.contains(file),
            "{file} is claimed as both owned and out of scope"
        );
    }
    let mut measured: Vec<String> = OWNED_FILES
        .iter()
        .chain(OUT_OF_SCOPE_INSTRUMENTED_FILES.iter())
        .map(|file| (*file).to_owned())
        .collect();
    measured.sort();
    assert_eq!(
        derived, measured,
        "the DERIVED instrumented-file set is exactly the owned five plus the \
         named out-of-scope files"
    );
    let uncovered: Vec<&String> = derived
        .iter()
        .filter(|file| !files.contains(*file) && !out_of_scope.contains(*file))
        .collect();
    assert_eq!(
        uncovered,
        Vec::<&String>::new(),
        "no derived instrumented file is unnamed: every one of them is either an \
         owned file or a named out-of-scope file, so a boundary cannot go \
         unaccounted for"
    );
    let unowned: Vec<&String> = files
        .iter()
        .chain(out_of_scope.iter())
        .filter(|file| !derived.contains(*file))
        .collect();
    assert_eq!(
        unowned,
        Vec::<&String>::new(),
        "no named file has stopped instrumenting"
    );
}

/// Proves the fixture's `inline_tests` field against the inline `#901`
/// capsules DERIVED from the five owned modules' own sources.
///
/// `inline_tests` is this delivery's record of which in-crate capsules carry the
/// private-boundary proof, so a name in that array with no `mod` behind it would
/// be a field asserting something no test performs.
///
/// The five names are therefore NOT written here: they are read out of the five
/// owned module sources, in [`OWNED_FILES`] order, and compared in full, so this
/// is red in both drift directions. That derivation replaced an earlier one that
/// read the same five names out of `src/lib.rs`: this issue's exclusive mutable
/// scope excludes `src/lib.rs`, so an earlier delivery that registered five
/// `#[cfg(test)] #[path = "tests/process_supervision_*.rs"]` modules there was
/// refused for widening the scope past the issue, the five separate files it
/// registered are gone, and the proof is inline in the owned modules where the
/// issue's own "directly relevant private inline tests in these five modules"
/// clause puts it.
///
/// The extraction is structural. `INLINE_MODULE_PREFIX` selects this issue's
/// capsule family out of every `mod` item the owned modules declare, so
/// `process_execution_diagnostics_tests`, `new_effect_operation_authority_1884_tests`
/// and `daemon_supervision_diagnostics_tests` - none of which is #901's - can
/// never be mistaken for one of these. The attribute buffer is what makes the
/// `#[cfg(test)]` half load-bearing: the `#[path = "tests/..."]` spelling is gone
/// with the registrations, and a `#[cfg(windows)]` alone must not open an extent,
/// so the gate is read from an attribute that both BEGINS `#[cfg(` and names
/// `test`. A `mod` whose attribute is not adjacent to it, and a declaration
/// inside a `#[cfg(test)]` module body, both open no extent. All five of this
/// issue's capsules are `test`-gated, so the assertion can require the gate
/// rather than tolerate its absence.
fn assert_inline_tests(f: &Value, package_prefix: &str) {
    const INLINE_MODULE_PREFIX: &str = "process_supervision_";
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut derived: Vec<String> = Vec::new();
    for owned in OWNED_FILES {
        let module_relative = owned
            .strip_prefix(&format!("{package_prefix}/"))
            .expect("an owned file is inside this package");
        let source = std::fs::read_to_string(manifest.join(module_relative))
            .unwrap_or_else(|_| panic!("owned module {owned} must be readable"));
        let mut attributes: Vec<&str> = Vec::new();
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                attributes.push(trimmed);
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            let test_gated = attributes
                .iter()
                .any(|attribute| attribute.starts_with("#[cfg(") && attribute.contains("test"));
            if test_gated
                && let Some(signature) = trimmed.strip_prefix("mod ")
                && let Some(name) = signature.strip_suffix('{').map(str::trim)
                && name.starts_with(INLINE_MODULE_PREFIX)
            {
                derived.push(name.to_owned());
            }
            attributes.clear();
        }
    }
    assert_eq!(
        derived.len(),
        OWNED_FILES.len(),
        "each of the five owned modules carries exactly one inline #901 capsule, \
         in OWNED_FILES order: {derived:?}"
    );
    let declared: Vec<String> = f["inline_tests"]
        .as_array()
        .expect("fixture inline_tests array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("an inline_tests capsule module name")
                .to_owned()
        })
        .collect();
    assert_eq!(
        declared, derived,
        "the fixture's `inline_tests` is exactly the inline capsules DERIVED from \
         the five owned module sources, in owned-file order: a capsule inlined \
         there and missing here is unrecorded, and a name here with no `mod` \
         behind it asserts nothing"
    );
    // The registration this delivery REMOVED must stay removed. `src/lib.rs` is
    // outside this issue's mutable scope, and a reader who cannot see the
    // five `#[path]` registrations come back would have no other way to know.
    let crate_root =
        std::fs::read_to_string(manifest.join("src/lib.rs")).expect("crate root source");
    assert!(
        !crate_root.contains("process_supervision_"),
        "src/lib.rs registers no #901 capsule: this issue's exclusive mutable \
         scope excludes src/lib.rs, and the private-boundary proof is inline in \
         the owned modules"
    );
}

/// Proves the fixture's `case_owners` table against sets that do not come from
/// it, and returns the declared case numbers for the boundary cross-check.
///
/// * `case_owners` must declare exactly the issue's thirty case numbers, 1..=30,
///   with no number declared twice - checked against the literal issue range,
///   not against `boundaries`;
/// * the rows naming `suite` must equal [`local_case_owners`] EXACTLY, in both
///   directions: every frozen marker in this file must have a row with this
///   test's `test_fn`, and every row naming this suite must correspond to a
///   marker. Renaming a test, moving a marker or dropping one is therefore red.
fn assert_case_owners(f: &Value, suite: &str) -> BTreeSet<u64> {
    let rows = f["case_owners"].as_array().expect("fixture case_owners");
    let declared: BTreeSet<u64> = rows
        .iter()
        .map(|row| row["case"].as_u64().expect("a case_owners case number"))
        .collect();
    assert_eq!(
        declared.len(),
        rows.len(),
        "no case number is declared by two case_owners rows"
    );
    assert_eq!(
        declared.iter().copied().collect::<Vec<u64>>(),
        (1..=30).collect::<Vec<u64>>(),
        "case_owners declares exactly the issue's thirty cases, 1..=30"
    );
    let mut suite_rows: BTreeMap<u64, String> = BTreeMap::new();
    for row in rows {
        if row["test_file"].as_str() != Some(suite) {
            continue;
        }
        let case = row["case"].as_u64().expect("a case_owners case number");
        let test_fn = row["test_fn"].as_str().expect("a case_owners test_fn");
        assert!(
            suite_rows.insert(case, test_fn.to_owned()).is_none(),
            "case {case} is claimed by two case_owners rows for this suite"
        );
    }
    assert_eq!(
        suite_rows,
        local_case_owners(),
        "this suite's case_owners rows are exactly its own frozen case markers"
    );
    declared
}

/// Reads every file the DENOMINATOR names - the five owned modules plus the
/// out-of-scope instrumented file - once, keyed by the fixture's own
/// repository-relative spelling of each path.
///
/// The out-of-scope file is read here for the same reason its row is kept: a
/// boundary row is only proved when the module it names really defines the
/// function and really passes that event prefix, and that check must reach the
/// sixth file's source rather than skip it because the file is not owned.
fn owned_module_sources(package_prefix: &str) -> BTreeMap<&'static str, String> {
    OWNED_FILES
        .iter()
        .chain(OUT_OF_SCOPE_INSTRUMENTED_FILES.iter())
        .map(|owned| {
            let manifest_relative = owned
                .strip_prefix(&format!("{package_prefix}/"))
                .expect("a denominator file is inside this package");
            (
                *owned,
                std::fs::read_to_string(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(manifest_relative),
                )
                .unwrap_or_else(|_| panic!("denominator module {owned} must be readable")),
            )
        })
        .collect()
}

/// Proves the boundary inventory against three sets that do not come from it.
///
/// * [`assert_boundary_completeness`] first, because the checks below only
///   RESOLVE rows: the per-CALLSITE `(file, event)` multiset derived from the
///   production tree and the nine cross-cutting rowless cases are what make
///   the inventory COMPLETE;
/// * every row's `file` must be inside the fixture's DENOMINATOR - the owned
///   five plus the named out-of-scope file - AND still in the DERIVED callsite
///   set, so a row cannot name a module that stopped instrumenting, and the
///   out-of-scope file's row is resolved against its real source rather than
///   skipped;
/// * every row's `covering_case` must be a case number `case_owners` declares,
///   which is what makes the old `(1..=30).contains(&case)` range test
///   unnecessary - that predicate is true of every number that parses as
///   `u64` and constrained nothing;
/// * every row's `function` and `detail_prefix` must appear literally in the
///   production module the row names, so the inventory cannot drift away from
///   the event literals the module really passes to an observer. The one row
///   whose `event` is empty is unaffected: it carries the shared
///   `kernel.process.grant_reconcile_` prefix, which that module does contain.
fn assert_boundary_inventory(
    boundaries: &[Value],
    files: &[String],
    derived: &[String],
    declared: &BTreeSet<u64>,
    sources: &BTreeMap<&'static str, String>,
) {
    assert!(!boundaries.is_empty(), "boundary table is non-empty");
    assert_boundary_completeness(boundaries, declared, sources);
    for boundary in boundaries {
        let file = boundary["file"]
            .as_str()
            .expect("boundary file is a string");
        assert!(
            files.iter().any(|value| value == file),
            "boundary file {file} is inside the denominator"
        );
        assert!(
            derived.iter().any(|value| value == file),
            "boundary file {file} still carries an observer callsite"
        );
        let covering_case = boundary["covering_case"]
            .as_u64()
            .expect("boundary covering_case is a case number");
        assert!(
            declared.contains(&covering_case),
            "boundary {file} names case {covering_case}, which case_owners never declares"
        );
        let source = sources
            .get(file)
            .unwrap_or_else(|| panic!("boundary file {file} is an owned module"));
        let function = boundary["function"]
            .as_str()
            .expect("boundary function is a string");
        assert!(
            source.contains(&format!("fn {function}")),
            "boundary {file} names function {function}, which that module does not define"
        );
        let detail_prefix = boundary["detail_prefix"]
            .as_str()
            .expect("boundary detail_prefix is a string");
        assert!(
            source.contains(detail_prefix),
            "boundary {file}::{function} names event prefix {detail_prefix}, \
             which that module never passes to an observer"
        );
    }
}

// WORK_UNIT_CASE: 901/1
// The denominator is DERIVED, not restated. `derived_instrumented_files` walks
// this package's own `src/` tree and keeps every production file that CALLS one
// of the six observer functions; that measured set is what the fixture's `files`
// array and its `out_of_scope_instrumented_files` array are compared against, in
// BOTH directions. A seventh instrumented module, or a renamed or relocated one,
// now changes the derived set and turns this red instead of agreeing with a
// restated constant.
//
// THE OWNED DENOMINATOR IS EXACTLY FIVE, and that is the point this case exists
// to hold. `files` is asserted member for member against `OWNED_FILES`, which is
// the five modules issue #901's exclusive mutable scope names, so adding a sixth
// file to the fixture to make the derived set agree is refused here rather than
// accepted. `bins/eliot-kernel/src/process_execution_client.rs` is the file an
// earlier revision folded in: it really does carry a production
// `observe_process_in_context` callsite at :106 emitting
// `kernel.process.request_rejected` with outcome `path_proof`, and that callsite
// and its boundary row (covering case 4) are both STILL HERE - the boundary was
// not deleted to make the count come out. The file is named in the fixture's
// `out_of_scope_instrumented_files` instead, and `assert_denominator` requires
// the derived set to be exactly those two named lists, disjoint. So the sixth
// file is accounted for in full and the owned set is still exact five.
#[test]
fn process_supervision_denominator_is_exact() {
    let f = fixture();
    assert_eq!(f["issue"].as_u64(), Some(901), "fixture pins this issue");
    let suite = f["test_file"].as_str().expect("fixture test_file");
    let (package_prefix, _) = suite
        .split_once("/tests/")
        .expect("the fixture names this package's tests directory");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .to_string_lossy()
        .replace('\\', "/");
    assert!(
        manifest.ends_with(&format!("/{package_prefix}")),
        "this package directory is the tree the fixture names: {manifest}"
    );

    let derived = derived_instrumented_files(package_prefix);
    let files = fixture_owned_files(&f);
    let out_of_scope = fixture_out_of_scope_files(&f);
    let declared = assert_case_owners(&f, suite);
    assert_denominator(&files, &out_of_scope, &derived);
    // The `inline_tests` half is derived from the five owned module SOURCES for
    // the same reason: the field names the capsules this delivery inlined, so it
    // is compared against the inline `mod` items themselves rather than against a
    // list copied beside them - and against `src/lib.rs` for the registrations
    // that must stay removed.
    assert_inline_tests(&f, package_prefix);
    let mut denominator: Vec<String> = files.clone();
    denominator.extend(out_of_scope.iter().cloned());
    let boundaries = f["boundaries"].as_array().expect("fixture boundaries");
    assert_boundary_inventory(
        boundaries,
        &denominator,
        &derived,
        &declared,
        &owned_module_sources(package_prefix),
    );
    // COMPLETENESS TRIPWIRE. `assert_boundary_inventory` proves only that each
    // row RESOLVES - that its `function` is defined and its `detail_prefix`
    // really appears in the module it names - so a DELETED row passes it
    // silently. This delivery pins 117 boundary rows, counted from the fixture
    // itself (85 `process_execution.rs`, 11 `daemon_live_receipt.rs`, 9
    // `supervision_lease_authority.rs`, 7 `daemon_supervision.rs`, 4
    // `daemon_process_launch.rs`, 1 `process_execution_client.rs`).
    //
    // It pins a COUNT, not a MAPPING, and it is now only the second line of
    // defence: `assert_boundary_completeness` compares the per-CALLSITE
    // `(file, event)` multiset DERIVED from the production tree against the
    // fixture's rows in both directions, so deleting one row and duplicating
    // another satisfies this count and is red there. What this count adds is
    // the reviewable total, and the derivation is scoped to what a text reader
    // can decide exactly - it stops at the first top-level `#[cfg(test)] mod`,
    // so the two in-crate capsules cannot be counted as production boundaries.
    assert_eq!(
        boundaries.len(),
        117,
        "the fixture pins 117 boundary rows: one per production observation \
         callsite that names an event of its own, which is the 118 measured \
         production callsites MINUS the one named forwarder at \
         process_execution.rs:67; this count is NOT the completeness proof on \
         its own, because deleting one row and duplicating another keeps it at \
         117 - the derived (file, event) multiset asserted by \
         assert_boundary_completeness is what makes the mapping honest"
    );
    assert_eq!(
        f["test_file"].as_str(),
        Some("bins/eliot-kernel/tests/kernel_process_supervision_diagnostics.rs"),
        "the fixture names this suite"
    );
    assert_eq!(
        f["target"].as_str(),
        Some(KERNEL_DIAGNOSTICS_TARGET),
        "fixture targets the shared facade"
    );
    assert_eq!(
        f["terminal_event"].as_str(),
        Some("kernel.terminal_error"),
        "fixture pins the one terminal event"
    );

    let facade = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/kernel_diagnostics.rs"),
    )
    .expect("shared facade source");
    for slot in SPAN_SLOT_DEFAULTS {
        assert!(facade.contains(slot), "facade declares {slot}");
    }
    assert_eq!(
        f["max_field_bytes"].as_u64(),
        Some(u64::try_from(MAX_DIAGNOSTIC_FIELD_BYTES).expect("field bound")),
        "fixture pins the shared field bound"
    );

    let (_guard, kernel) = process_authority_kernel("case01", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case01-unknown"),
    );
    assert!(
        logs.contains(KERNEL_DIAGNOSTICS_TARGET),
        "a real callsite ran under the facade target: {logs}"
    );
    assert_eq!(rejection_code(&response), "NOT_FOUND");
}

// WORK_UNIT_CASE: 901/2
#[test]
fn admitted_owner_and_rejected_owner_are_distinct_sites() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let foreign = ProcessOwnerBinding::new(
        MODULE_ID,
        "b".repeat(64),
        session.authority_epoch.clone(),
        test_generation(),
    )
    .expect("foreign principal owner");
    let (_guard, kernel) = process_authority_kernel(
        "case02",
        &[
            ("op-901-case02-admitted", owner),
            ("op-901-case02-rejected", foreign),
        ],
    );

    let (admitted_logs, admitted) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case02-admitted"),
    );
    assert!(
        matches!(admitted, ProcessExecutionResponse::Rejected(_)),
        "the admitted owner's inspect still returns a typed result: {admitted:?}"
    );
    assert!(
        admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.request_received")
        )),
        "admitted run observed the request: {admitted_logs}"
    );
    assert!(
        admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.request_admitted")
        )),
        "admitted run passed the process-authority gate: {admitted_logs}"
    );
    assert!(
        admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.owner_admitted")
        )),
        "admitted run recorded the authorized owner: {admitted_logs}"
    );
    assert!(
        !admitted_logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.owner_rejected")
        )),
        "the admitted owner was never rejected: {admitted_logs}"
    );
    assert_eq!(
        terminal_codes(&admitted_logs).len(),
        1,
        "one terminal for the one failed underlying operation: {admitted_logs}"
    );

    let (rejected_logs, rejected) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case02-rejected"),
    );
    assert!(
        rejection_code(&rejected) == "CONTRACT_REJECTED",
        "a foreign principal is refused with the contract code: {:?}",
        rejection_code(&rejected)
    );
    let owner_rejected = fixture_event("process.owner_rejected");
    assert_eq!(
        event_outcome(&rejected_logs, &owner_rejected),
        "fenced",
        "the foreign owner is fenced: {rejected_logs}"
    );
    assert_eq!(
        terminal_codes(&rejected_logs).len(),
        1,
        "the subordinate owner site still emits no terminal of its own: {rejected_logs}"
    );
    assert!(
        byte_offset(&rejected_logs, &format!("event=\"{owner_rejected}\""))
            < byte_offset(&rejected_logs, "event=\"kernel.terminal_error\""),
        "the single terminal is emitted after the subordinate rejection, not at it: {rejected_logs}"
    );
}

// WORK_UNIT_CASE: 901/3
#[test]
fn operation_tree_and_lease_bind_the_validated_admission() {
    let (_guard, kernel) = process_authority_kernel("case03", &[]);
    let session = process_session();
    let binding = session_binding();
    let shape = default_shape("op-901-case03");
    let admission = shape_admission(&shape);
    let (logs, response) = drive_client_start(&kernel, &session, &binding, admission);

    let rejection = fixture_event("process.request_rejected");
    let operation = span_field(&logs, &rejection, "operation");
    let process_tree = span_field(&logs, &rejection, "process_tree");
    let lease = span_field(&logs, &rejection, "lease");
    let generation = span_field(&logs, &rejection, "generation");
    assert_eq!(
        operation, shape.operation_id,
        "operation is the admitted one: {logs}"
    );
    assert_ne!(
        operation, "unavailable",
        "an absent identity stays unavailable"
    );
    assert_eq!(
        process_tree, shape.process_tree_id,
        "process tree is the admitted one: {logs}"
    );
    assert_ne!(
        process_tree, "unavailable",
        "an absent tree stays unavailable"
    );
    assert_eq!(
        lease,
        format!("{}-lease", shape.operation_id),
        "lease is the admitted one: {logs}"
    );
    assert_ne!(lease, "unavailable", "an absent lease stays unavailable");
    assert_eq!(
        generation,
        test_generation().get().to_string(),
        "generation is the admitted one: {logs}"
    );
    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the start was refused before any launch attempt"
    );
}

// WORK_UNIT_CASE: 901/4
#[test]
fn pre_launch_refusal_stays_not_attempted() {
    let (_guard, kernel) = process_authority_kernel("case04", &[]);
    let session = process_session();
    let binding = session_binding();
    let admission = shape_admission(&default_shape("op-901-case04"));
    let (logs, response) = drive_client_start(&kernel, &session, &binding, admission);

    let request_rejected = fixture_event("process.request_rejected");
    assert_eq!(
        event_count(&logs, &request_rejected),
        1,
        "exactly one pre-launch refusal: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, &request_rejected),
        "watchdog_coverage",
        "the pre-launch admission refusal is the observed outcome: {logs}"
    );
    let codes = terminal_codes(&logs);
    assert_eq!(
        codes,
        vec![ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE.to_owned()],
        "exactly one typed terminal: {logs}"
    );
    // REGRESSION GUARD (absence), non-vacuously satisfiable: this run is proven
    // POSITIVE first - the guard emitted `kernel.process.request_rejected` with
    // outcome `watchdog_coverage` exactly once and exactly one typed terminal,
    // both asserted immediately above - and every name below is read through
    // `fixture_event`, which PANICS if the fixture does not carry it, so a
    // renamed or misspelled event cannot satisfy the loop by naming nothing.
    // The four emitters it guards are `process_execution.rs:2906`
    // (start_requested), `:3949` (start_registration), `:4143`
    // (start_handoff) and `:2943` (start_committed), all of which sit inside
    // `start_in_context` (`:2881`) or the `run_process_start` projection it
    // reaches (`:3949`/`:4143`), behind the guard that returned above; and
    // `daemon_process_launch.rs:127` (launch_requested) sits behind a launch
    // that this run never reaches.
    for never in [
        "process.start_requested",
        "process.start_registration",
        "process.start_handoff",
        "process.start_committed",
    ] {
        let event = fixture_event(never);
        assert!(
            !logs.contains(&format!("event=\"{event}\"")),
            "{event} must never run after the refusal: {logs}"
        );
    }
    let launch = fixture_event("daemon.launch_requested");
    assert!(
        !logs.contains(&launch),
        "no daemon launch was requested either: {logs}"
    );
    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the typed refusal is projected unchanged"
    );
}

// WORK_UNIT_CASE: 901/7
#[test]
fn possible_effect_outcome_stays_unknown_under_its_operation() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let (_guard, kernel) = process_authority_kernel("case07", &[("op-901-case07", owner)]);
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case07"),
    );

    let cancel_failed = fixture_event("process.cancel_failed");
    assert!(
        logs.contains(&format!("event=\"{cancel_failed}\"")),
        "the unproven effect was observed: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, &cancel_failed),
        "unknown",
        "a possible effect never reports a decided outcome: {logs}"
    );
    let codes = terminal_codes(&logs);
    assert_eq!(codes.len(), 1, "exactly one terminal: {logs}");
    assert_eq!(
        codes[0], "process_unknown_outcome",
        "static unknown code: {logs}"
    );
    assert_eq!(
        span_field(&logs, &cancel_failed, "operation"),
        "op-901-case07",
        "the original operation identity is retained: {logs}"
    );
    assert_eq!(rejection_code(&response), "UNKNOWN_OUTCOME");
}

// WORK_UNIT_CASE: 901/11
#[test]
fn stale_generation_owner_stays_fenced_and_current_generation_is_admitted() {
    let session = process_session();
    let binding = session_binding();
    let current = session_owner(&session);
    // F-LOG-KERNEL-3 (#901 T11). The durable record is seeded with the SAME
    // principal, module and authority epoch this authenticated session derives,
    // and only the GENERATION differs. `ProcessOwnerBinding` derives `PartialEq`
    // over {module_id, principal_digest, authority_epoch, generation}
    // (crates/kernel/eliot-process/src/lib.rs:675-682) and
    // `authorize_process_owner_in_context` compares that whole binding
    // (process_execution.rs:4520), so generation is genuinely part of the
    // compared authorization tuple. The two-arm pair below is what discriminates:
    // a mutation that ignored the generation would let the stale arm go
    // green-admitted and turn the first assertion red.
    let stale = ProcessOwnerBinding::new(
        current.module_id(),
        current.principal_digest(),
        current.authority_epoch().clone(),
        Generation::new(7).expect("stale generation"),
    )
    .expect("same-principal stale-generation owner");
    // Premise guard on the fixture itself, not production evidence: the two
    // durable owners must differ in exactly the generation.
    assert_eq!(
        stale.module_id(),
        current.module_id(),
        "module is not varied"
    );
    assert_eq!(
        stale.principal_digest(),
        current.principal_digest(),
        "principal is not varied"
    );
    assert_eq!(
        stale.authority_epoch(),
        current.authority_epoch(),
        "authority epoch is not varied"
    );
    assert_ne!(
        stale.generation(),
        current.generation(),
        "generation is the only varied leg of the authorization binding"
    );

    let (_guard, kernel) = process_authority_kernel(
        "case11",
        &[
            ("op-901-case11-stale-generation", stale),
            ("op-901-case11-current-generation", current),
        ],
    );
    let owner_rejected = fixture_event("process.owner_rejected");
    let owner_admitted = fixture_event("process.owner_admitted");

    let (stale_logs, stale_response) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case11-stale-generation"),
    );
    assert_eq!(
        event_outcome(&stale_logs, &owner_rejected),
        "fenced",
        "the same principal under a stale generation is fenced, never admitted: {stale_logs}"
    );
    assert!(
        !stale_logs.contains(&format!("event=\"{owner_admitted}\"")),
        "no stale owner is ever admitted: {stale_logs}"
    );
    assert_eq!(
        terminal_codes(&stale_logs).len(),
        1,
        "exactly one terminal, owned by the gateway boundary: {stale_logs}"
    );
    assert!(
        byte_offset(&stale_logs, &format!("event=\"{owner_rejected}\""))
            < byte_offset(&stale_logs, "event=\"kernel.terminal_error\""),
        "the subordinate owner site emits no terminal: {stale_logs}"
    );
    assert_eq!(rejection_code(&stale_response), "CONTRACT_REJECTED");

    let (current_logs, _) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case11-current-generation"),
    );
    assert_eq!(
        event_outcome(&current_logs, &owner_admitted),
        "success",
        "the identical principal under its own generation IS admitted: {current_logs}"
    );
    assert!(
        !current_logs.contains(&format!("event=\"{owner_rejected}\"")),
        "the generation, not the principal, is what the gate reads: {current_logs}"
    );
    assert_eq!(
        terminal_codes(&current_logs).len(),
        1,
        "the admitted arm still fails later in the operation, with its own single terminal: {current_logs}"
    );
    assert!(
        byte_offset(&current_logs, &format!("event=\"{owner_admitted}\""))
            < byte_offset(&current_logs, "event=\"kernel.terminal_error\""),
        "the admitted owner site is still subordinate to the one terminal: {current_logs}"
    );

    // Honest scope note: PID reuse itself has no representation in these
    // owned modules. No `pid_reused` or `foreign` outcome literal exists
    // anywhere in them, and `process_id`/`process_start_100ns` are recorded only
    // from a validated start receipt (process_execution.rs:187-204), never
    // reopened by number. So case 11 is proven in its generation/identity half
    // only; the PID-reuse half is unreachable from these public seams.
}

// WORK_UNIT_CASE: 901/18
#[test]
fn cancellation_request_differs_from_acknowledgement() {
    let (_guard, kernel) = process_authority_kernel("case18", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case18-unknown"),
    );

    let requested = fixture_event("process.cancel_requested");
    let acknowledged = fixture_event("process.cancel_acknowledged");
    assert!(
        logs.contains(&format!("event=\"{requested}\"")),
        "the cancellation request is observed: {logs}"
    );
    assert_ne!(
        requested, acknowledged,
        "request and acknowledgement differ"
    );
    assert!(
        !logs.contains(&format!("event=\"{acknowledged}\"")),
        "a request is never an acknowledgement: {logs}"
    );
    assert_eq!(
        terminal_codes(&logs).len(),
        1,
        "the refused acknowledgement carries exactly one terminal: {logs}"
    );
    assert!(
        byte_offset(&logs, &format!("event=\"{requested}\""))
            < byte_offset(&logs, "event=\"kernel.terminal_error\""),
        "the request precedes the refusal of the acknowledgement: {logs}"
    );
    assert_eq!(rejection_code(&response), "NOT_FOUND");
}

// WORK_UNIT_CASE: 901/20
#[test]
fn unknown_reconcile_outcome_emits_exactly_one_terminal() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let (_guard, kernel) = process_authority_kernel("case20", &[("op-901-case20", owner)]);
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        reconcile_request("op-901-case20"),
    );

    let requested = fixture_event("process.reconcile_requested");
    let unknown = fixture_event("process.reconcile_unknown");
    assert!(
        logs.contains(&format!("event=\"{requested}\"")),
        "the exit/evidence boundary was entered: {logs}"
    );
    assert!(
        logs.contains(&format!("event=\"{unknown}\"")),
        "the unprovable exit was observed: {logs}"
    );
    assert_eq!(
        event_outcome(&logs, &unknown),
        "unknown",
        "the outcome literal stays unknown: {logs}"
    );
    let codes = terminal_codes(&logs);
    assert_eq!(
        codes.len(),
        1,
        "exactly one terminal for one operation: {logs}"
    );
    // REGRESSION GUARD (absence): the emitted code must be one of the FIVE stable
    // literals `process_terminal_code` (`process_execution.rs:236-244`) can
    // return, so a free-form error string reaching `observe_terminal_error_in_context`
    // (`kernel_diagnostics.rs:699-712`, which bounds the code with
    // `bound_field` but does not make it static) is red here. It is
    // non-vacuously satisfiable because `codes.len() == 1` is asserted
    // immediately above, so the predicate is evaluated over one real code read
    // out of the captured terminal line rather than over an empty set.
    assert!(
        codes
            .iter()
            .all(|code| fixture_terminal_codes().contains(code)),
        "the terminal code is a stable mapper projection: {codes:?}"
    );
    assert_eq!(
        span_field(&logs, &unknown, "operation"),
        "op-901-case20",
        "the original operation identity is retained: {logs}"
    );
    assert!(matches!(response, ProcessExecutionResponse::Rejected(_)));
}

// WORK_UNIT_CASE: 901/21
#[test]
fn exit_observation_never_claims_completed_work() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    let (_guard, kernel) = process_authority_kernel(
        "case21",
        &[
            ("op-901-case21-inspect", owner.clone()),
            ("op-901-case21-reconcile", owner),
        ],
    );

    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case21-inspect"),
    );

    let requested = fixture_event("process.inspect_requested");
    let failed = fixture_event("process.inspect_failed");
    let reported = fixture_event("process.inspect_reported");
    assert!(
        logs.contains(&format!("event=\"{requested}\"")),
        "the exit observation boundary was entered: {logs}"
    );
    assert!(
        logs.contains(&format!("event=\"{failed}\"")),
        "the exit observation was read and stayed unproven: {logs}"
    );
    assert!(
        !logs.contains(&format!("event=\"{reported}\"")),
        "an exit observation never becomes a reported success: {logs}"
    );
    assert!(
        matches!(response, ProcessExecutionResponse::Rejected(_)),
        "an exit observation never becomes a status projection: {response:?}"
    );

    // The exit direction. `reconcile_in_context` (process_execution.rs:3517) is
    // the projection that owns an exit observation: it requests, and an exit the
    // owner cannot prove takes the :3560 arm, `reconcile_unknown`/"unknown"
    // (:3561), never the `reconcile_reported`/"success" arm at :3557. Reaching
    // `reconcile_reported` would require the executor to hand back proven
    // evidence, which no fake-free path here can fabricate.
    let (exit_logs, exit_response) = drive_request(
        &kernel,
        &session,
        &binding,
        reconcile_request("op-901-case21-reconcile"),
    );
    let reconcile_requested = fixture_event("process.reconcile_requested");
    let reconcile_unknown = fixture_event("process.reconcile_unknown");
    let reconcile_reported = fixture_event("process.reconcile_reported");
    assert_eq!(
        event_count(&exit_logs, &reconcile_requested),
        1,
        "the exit/evidence boundary was entered exactly once: {exit_logs}"
    );
    assert_eq!(
        event_count(&exit_logs, &reconcile_unknown),
        1,
        "the unprovable exit is observed as unknown exactly once: {exit_logs}"
    );
    assert_eq!(
        event_outcome(&exit_logs, &reconcile_unknown),
        "unknown",
        "exit zero never promotes an exit observation to a decided outcome: {exit_logs}"
    );
    assert_eq!(
        event_count(&exit_logs, &reconcile_reported),
        0,
        "an unprovable exit is never reported as decided evidence: {exit_logs}"
    );
    assert_eq!(
        terminal_codes(&exit_logs).len(),
        1,
        "the unprovable exit still carries exactly one designated terminal: {exit_logs}"
    );
    assert!(
        matches!(exit_response, ProcessExecutionResponse::Rejected(_)),
        "an unprovable exit never becomes an evidence projection: {exit_response:?}"
    );
    // REGRESSION GUARD (absence), NOT the primary discrimination above. It is
    // non-vacuously satisfiable because this capture is already proven POSITIVE
    // immediately above: `reconcile_requested` and `reconcile_unknown` each
    // occur EXACTLY once with their outcomes pinned, so
    // `exit_logs` is a non-empty rendering of a real `reconcile_in_context` run
    // (`process_execution.rs:3527`/`:3561`) rather than an empty string that
    // trivially contains no vocabulary. What it adds is a whole-run scan
    // rather than a field read: it turns red the moment the projection grows an
    // `exit_code`, `exit_status`, `completion` or `completed` string ANYWHERE
    // in the rendered record - in a span slot, in a message, in a target - none
    // of which the owned modules emit today, and which a field reader over the
    // seventeen declared span slots would not see.
    for forbidden in ["exit_code", "exit_status", "completion", "completed"] {
        assert!(
            !exit_logs.contains(forbidden),
            "no {forbidden} field may be formatted by the exit projection: {exit_logs}"
        );
    }
}

// WORK_UNIT_CASE: 901/25
#[test]
fn one_designated_terminal_per_failed_operation() {
    let session = process_session();
    let binding = session_binding();
    let owner = session_owner(&session);
    // ONE operation, seeded so the owner gate passes and the failure happens
    // downstream, observed by THREE owners that all see the same failure:
    // `execute_process_request` (request boundary, :4603),
    // `inspect_in_context` (the gateway boundary that OWNS the terminal, :3037)
    // and `inspect_inner` (the subordinate exit observation, :3073). That is
    // the propagation case: several correlated subordinate observations, one
    // designated terminal. Two independent operations would prove nothing
    // about propagation, so there is only one here.
    let (_guard, kernel) = process_authority_kernel("case25", &[("op-901-case25-inspect", owner)]);
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        inspect_request("op-901-case25-inspect"),
    );

    let inspect_requested = fixture_event("process.inspect_requested");
    let inspect_failed = fixture_event("process.inspect_failed");
    let request_failed = fixture_event("process.request_failed");
    assert_eq!(
        event_count(&logs, &inspect_requested),
        1,
        "the subordinate exit observation ran exactly once: {logs}"
    );
    assert_eq!(
        event_count(&logs, &inspect_failed),
        1,
        "the failure is observed by the subordinate owner exactly once: {logs}"
    );
    assert_eq!(
        event_count(&logs, &request_failed),
        1,
        "the same failure is projected by the outer request owner exactly once: {logs}"
    );
    assert_eq!(
        terminal_codes(&logs).len(),
        1,
        "three owners of one failed operation, exactly one designated terminal: {logs}"
    );
    assert_eq!(
        span_field(&logs, &inspect_failed, "operation"),
        "op-901-case25-inspect",
        "the subordinate owner is correlated to the same underlying operation: {logs}"
    );
    assert_eq!(
        span_field(&logs, &request_failed, "operation"),
        "op-901-case25-inspect",
        "the propagated refusal carries the same underlying operation: {logs}"
    );
    assert!(
        byte_offset(&logs, &format!("event=\"{inspect_failed}\""))
            < byte_offset(&logs, "event=\"kernel.terminal_error\""),
        "the owning gateway boundary emits the terminal right after the failure it owns: {logs}"
    );
    assert!(
        byte_offset(&logs, "event=\"kernel.terminal_error\"")
            < byte_offset(&logs, &format!("event=\"{request_failed}\"")),
        "the outer request owner projects the failure after the terminal and adds none of its own: {logs}"
    );
    assert_eq!(rejection_code(&response), "NOT_FOUND");
}

// WORK_UNIT_CASE: 901/26
#[test]
fn terminal_code_is_a_static_projection_not_error_prose() {
    let (_guard, kernel) = process_authority_kernel("case26", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case26"),
    );

    let codes = terminal_codes(&logs);
    assert_eq!(codes.len(), 1, "exactly one terminal: {logs}");
    let code = codes[0].clone();
    assert!(
        fixture_terminal_codes().contains(&code),
        "the code is a pinned mapper projection, got {code}"
    );
    let detail = rejection_detail(&response);
    assert!(
        !detail.is_empty(),
        "the caller still receives its typed detail"
    );
    assert_ne!(code, detail, "the code is never the error's rendered prose");
    assert!(
        !logs.contains(&detail),
        "no rendered error prose reaches the captured bytes: {logs}"
    );
}

// WORK_UNIT_CASE: 901/27
// HONEST LIMIT, stated here rather than left for a reader to assume away: on
// this path no production line ever dereferences the payload. The start is
// refused by `admit_material_process_start` (`src/lib.rs:3308`), which reads
// only `admission.state_fence()` plus the Kernel's own service and activation
// state, and the composition path returns at `process_execution.rs:4708` before
// `retain_process_path_proof` (declared `:4752`, whose `:4756`-`:4757` are the
// only reads of `executable` and `working_directory`) can run. So these loops
// prove the REFUSAL BOUNDARY
// DOES NOT LEAK the payload, which is the property issue-901-body.md:45 asks
// for ("Redact before formatting ... Fixed-field tests include nested and
// oversized canaries"). They are reddened by ADDING a leak on this path, not
// by deleting a callsite, and they do not prove reader-side redaction on a path
// that does read the payload. No canary can travel into a record as payload
// either: every span field is fed from a typed identity through
// `record_process_context_field`, never from free text.
//
// The captured-byte loop below is therefore not the only leak channel this case
// checks. The other one is the returned `ProcessExecutionRejection.detail`,
// which production builds from the typed error at `process_execution.rs:4593`
// (`detail: error.to_string().chars().take(512).collect()`), so it is inspected
// for every canary too. And the
// redaction owner itself is driven directly through
// `eliot_kernel::kernel_diagnostics::bound_field`, the single emission boundary
// every one of these owned modules reaches (`kernel_diagnostics.rs:347-349`),
// which is what puts the oversized/nested screening under test rather than only
// the refusal path.
#[test]
// One length buys this: every leak channel of this shape is swept in one pass.
#[allow(clippy::too_many_lines)]
fn command_argument_environment_path_credential_canaries_are_absent() {
    let mut shape = default_shape("op-901-case27");
    let command = fixture_canary("command");
    let argument = fixture_canary("argument");
    let environment = fixture_canary("environment");
    let working_path = fixture_canary("working_path");
    let data_path = fixture_canary("data_path");
    let credential = fixture_canary("credential");
    let token = fixture_canary("token");
    let nested = fixture_canary("nested");
    let oversized = fixture_canary("oversized");
    assert!(
        oversized.len() > MAX_DIAGNOSTIC_FIELD_BYTES,
        "the oversized canary exceeds the shared field bound"
    );
    shape.executable = format!(r"C:\Eliot\{command}.exe");
    shape.argv = vec![
        format!("--flag={argument}"),
        format!("--nested={nested}"),
        oversized.clone(),
    ];
    shape.working_directory = format!(r"C:\Eliot\{working_path}");
    shape.environment.insert(
        "ELIOT_901_ENV".to_owned(),
        format!("{environment}/{data_path}"),
    );
    shape
        .environment
        .insert("ELIOT_901_NESTED".to_owned(), nested.clone());
    shape.secret_refs = vec![
        SecretRef::new("eliot-901", credential.clone()).expect("opaque secret reference"),
        SecretRef::new("eliot-901", token.clone()).expect("opaque secret reference"),
    ];

    let (_guard, kernel) = process_authority_kernel("case27", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_client_start(&kernel, &session, &binding, shape_admission(&shape));

    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the canary admission still ran the real refusal"
    );
    for canary in [
        &command,
        &argument,
        &environment,
        &working_path,
        &data_path,
        &credential,
        &token,
        &nested,
        &oversized,
    ] {
        assert!(
            !logs.contains(canary.as_str()),
            "canary {canary} must never reach the captured bytes: {logs}"
        );
        assert!(
            !rejection_detail(&response).contains(canary.as_str()),
            "canary {canary} must never reach the returned rejection detail, which production renders from the typed error: {}",
            rejection_detail(&response)
        );
    }

    // The redaction owner itself, driven through its public API. Honest
    // disposition for this input, read off the code rather than guessed:
    // `bounded_value` (kernel_diagnostics.rs:453-500) screens FIRST through
    // `requires_evidence_handle`, whose length threshold is 256 CHARACTERS
    // (field_policy.rs:299-301); this canary is 320 characters, so it is
    // replaced whole by an immutable evidence handle and `truncated` stays
    // `false`. Asserting `truncated() == true` here would be asserting a lie:
    // a prefix of an over-long value is exactly what the policy forbids.
    let bounded = bound_field(&oversized);
    assert!(
        bounded.text().len() <= MAX_DIAGNOSTIC_FIELD_BYTES,
        "the emitted value stays inside the shared field bound, got {} bytes",
        bounded.text().len()
    );
    assert_eq!(
        bounded.original_bytes(),
        oversized.len(),
        "the boundary records the length of the input it refused to emit"
    );
    assert!(
        !bounded.truncated(),
        "a screened value is replaced whole, never truncated to a prefix"
    );
    assert_eq!(
        bounded.redaction_status(),
        Some("redacted:content"),
        "an over-long value is screened as content before bounding, not silently truncated"
    );
    // The emitted value is anchored against an INDEPENDENTLY minted handle, not
    // against `bounded.evidence_handle()`: comparing two accessors of one
    // `BoundedField` cannot fail unless the implementation defines text ==
    // handle, so it proved nothing. The expected handle is what production's own
    // public `mint_handle` produces for THIS input under the Kernel family the
    // facade declares (`KERNEL_TELEMETRY_FAMILY =
    // TelemetryFieldFamily::OperationalLog` and `FIELD_LABEL_KEY = "code"`,
    // `kernel_diagnostics.rs:68` and `:73`), which binds the handle to the
    // canary's CONTENT: a facade that emitted a constant, a prefix, a different
    // value's handle or a truncated input is now red here.
    let expected_handle = mint_handle(
        TelemetryFieldFamily::OperationalLog,
        "code",
        &oversized,
        RedactionReason::Content,
    )
    .handle;
    assert_eq!(
        bounded.text(),
        expected_handle,
        "the emitted value IS the immutable evidence handle minted for this \
         screened input"
    );
    assert_eq!(
        bounded.evidence_handle(),
        Some(expected_handle.as_str()),
        "the recorded handle is that same content-bound handle"
    );
    for fragment in ["CANARY_OVERSIZED_901", "oversized-field-filler", "CANARY"] {
        assert!(
            !bounded.text().contains(fragment),
            "no fragment {fragment} of the screened input survives: {}",
            bounded.text()
        );
    }
    assert_ne!(
        bounded.text(),
        oversized,
        "the emitted value is never the input itself"
    );
}

// WORK_UNIT_CASE: 901/28
// The same honest limit as case 27 applies to this canary sweep: the refusal
// path never reads argv, environment or secret_refs, so these loops prove the
// boundary does not leak them rather than proving reader-side redaction. The
// returned rejection detail (built by production from the typed error at
// `process_execution.rs:4593`) is the second channel and is checked for every
// canary too; the oversized value's screening disposition itself is pinned in
// case 27 through the public `bound_field` boundary.
//
// The three `span_field(... "process_id" | "process_start_100ns" |
// "image_sha256") == "unavailable"` comparisons are BACK, at the end of this
// case, each labelled for what it is. They are REGRESSION GUARDS (absences) on
// production behaviour, NOT a proof that this path produced an identity: the
// only writer that can fill those three slots is
// `record_process_start_receipt_identity` (`process_execution.rs:187-204`),
// which takes a `&ProcessStartReceipt` this pre-launch refusal never mints, so
// what they pin is that a production change recording a GUESSED PID, start time
// or image digest on this path turns all three red. They are kept for that
// reason, with the seventeen-slot sweep
// (`assert_operation_span_carries_no_canary`) and the recorded-admission anchor
// (`assert_recorded_admission_identity`) alongside them, unchanged.
// No canary was removed from the planted payload to make any assertion pass.
#[test]
fn stream_provider_model_user_canaries_stay_unavailable_not_guessed() {
    let mut shape = default_shape("op-901-case28");
    let stream = fixture_canary("stream");
    let provider = fixture_canary("provider");
    let model = fixture_canary("model");
    let user = fixture_canary("user");
    let lease_signature = fixture_canary("lease_signature");
    let process_memory = fixture_canary("process_memory");
    let error_debug = fixture_canary("error_debug");
    let nested = fixture_canary("nested");
    let oversized = fixture_canary("oversized");
    shape.argv = vec![
        format!("--stdout={stream}"),
        format!("--stderr={oversized}"),
        format!("--memory={process_memory}"),
        format!("--lease={lease_signature}"),
        format!("--error={error_debug}"),
        format!("--nested={nested}"),
    ];
    shape
        .environment
        .insert("ELIOT_901_USER".to_owned(), user.clone());
    shape.secret_refs = vec![
        SecretRef::new("eliot-901", provider.clone()).expect("opaque secret reference"),
        SecretRef::new("eliot-901", model.clone()).expect("opaque secret reference"),
    ];

    let (_guard, kernel) = process_authority_kernel("case28", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_client_start(&kernel, &session, &binding, shape_admission(&shape));

    assert_eq!(
        rejection_code(&response),
        ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
        "the canary admission still ran the real refusal"
    );
    let detail = rejection_detail(&response);
    let payload_canaries = [
        stream.as_str(),
        provider.as_str(),
        model.as_str(),
        user.as_str(),
        lease_signature.as_str(),
        process_memory.as_str(),
        error_debug.as_str(),
        nested.as_str(),
        oversized.as_str(),
    ];
    assert_payload_canaries_absent(&logs, &detail, &payload_canaries);
    let rejection = fixture_event("process.request_rejected");
    assert_operation_span_carries_no_canary(&logs, &rejection, &payload_canaries);
    assert_recorded_admission_identity(&logs, &rejection, &shape);

    // Three REGRESSION GUARDS (absences) on the physical process identity, the
    // same class the in-crate capsules of this issue keep and name as such in
    // `src/tests/process_supervision_unknown_outcome.rs`.
    //
    // What each one IS: a guard on production behaviour. What each one is NOT:
    // a proof that this path PRODUCED an identity - it produces none, which is
    // the whole point. The shared span declares exactly these three slots as
    // the literal "unavailable" (`kernel_diagnostics.rs:671-673`), and the
    // ONLY writer that can fill them is
    // `record_process_start_receipt_identity` (`process_execution.rs:187-204`),
    // which needs a `&ProcessStartReceipt`. Its one callsite (`:2936`) sits on
    // the `Ok(receipt)` arm of a launch that already completed, while this
    // pre-launch refusal returns out of
    // `reject_process_start_without_material_coverage_in_context`
    // (`process_execution.rs:4575-4597`) - before a receipt exists and before
    // `start_in_context` is ever reached (`process_execution_client.rs:118`,
    // the `gateway.start_in_context(...)` call behind the path-proof match
    // that begins at `:103`), so this path cannot reach that writer.
    //
    // That is why the guard bites instead of being vacuous: a production change
    // that recorded a GUESSED PID, a guessed start time or a guessed image
    // digest on a pre-launch refusal would overwrite the declared default and
    // redden all three comparisons at once. That is the rule they hold, in the
    // issue's own words - TASK.md:61 "PID alone cannot identify a process after
    // reuse" and :63 "A malformed or absent identity remains unavailable, not
    // guessed".
    assert_eq!(
        span_field(&logs, &rejection, "process_id"),
        "unavailable",
        "a pre-launch refusal records no PID: the identity is absent, not guessed: {logs}"
    );
    assert_eq!(
        span_field(&logs, &rejection, "process_start_100ns"),
        "unavailable",
        "a pre-launch refusal records no start time: the identity is absent, not guessed: {logs}"
    );
    assert_eq!(
        span_field(&logs, &rejection, "image_sha256"),
        "unavailable",
        "a pre-launch refusal records no image digest: the identity is absent, not guessed: {logs}"
    );
}

/// Case 28's first canary channel: the captured diagnostic bytes and the
/// returned `ProcessExecutionRejection.detail`, which production renders from
/// the typed error at `process_execution.rs:4593`.
fn assert_payload_canaries_absent(logs: &str, detail: &str, canaries: &[&str]) {
    for canary in canaries {
        assert!(
            !logs.contains(canary),
            "payload canary {canary} must never reach the captured bytes: {logs}"
        );
        assert!(
            !detail.contains(canary),
            "payload canary {canary} must never reach the returned rejection detail, which production renders from the typed error: {detail}"
        );
    }
}

/// Case 28's second canary channel, and a TOTAL sweep over every field the
/// shared operation span declares - the list is read out of the facade by
/// [`declared_operation_slots`], not restated here - requiring no declared slot
/// to carry a payload canary.
///
/// What it adds OVER the payload scan that ran two lines earlier on the same
/// bytes with the same canary list: a different MECHANISM. That scan is a
/// substring search over the captured line, so anything it cannot see as
/// literal canary bytes is invisible to it, while this reads each declared slot
/// off the RENDERED record through [`span_field`] and compares the slot's value
/// itself. A recorder that emitted a canary transformed rather than verbatim, or
/// a span whose slots arrived as recorded fields the scan's needle never matches
/// as one token, is caught here and only here.
///
/// What it does NOT add: it is LOGICALLY SUBSUMED by that scan. Any canary
/// reaching a declared slot appears in the same bytes and is therefore already
/// caught by `assert_payload_canaries_absent`, so in the absence of a
/// transforming recorder this sweep cannot fail independently. It is kept
/// because it covers the failure mode the scan structurally cannot, and because
/// it is total over the declared slot list - a slot the facade stops declaring
/// turns it red instead of narrowing it - not as an independent proof.
fn assert_operation_span_carries_no_canary(logs: &str, event: &str, canaries: &[&str]) {
    for slot in declared_operation_slots() {
        let value = span_field(logs, event, &slot);
        for canary in canaries {
            assert!(
                !value.contains(canary),
                "declared span slot {slot} must never carry payload canary \
                 {canary}, got {value}: {logs}"
            );
        }
    }
}

/// Case 28's anchor, and the reason the sweep above is not vacuous: this
/// pre-launch refusal path DOES record the caller's own admission identities
/// onto the span. `record_process_start_request_context`
/// (`process_execution.rs:145-183`) feeds `operation`, `generation`,
/// `state_fence`, `process_tree` and `lease` from the admission, and the
/// admission under test validated at construction -
/// `ProcessExecutionAdmissionRequest::new` returns only a validated request
/// (eliot-process `lib.rs:1108`), so the early return at
/// `process_execution.rs:161-163` is not taken. So the sweep reads RECORDED
/// values, not only declared defaults. Case 3 pins the same identities against
/// a canary-free payload; this is the canary-bearing counterpart.
fn assert_recorded_admission_identity(logs: &str, event: &str, shape: &IntentShape) {
    assert_eq!(
        span_field(logs, event, "operation"),
        shape.operation_id,
        "the span carries the caller's own operation identity: {logs}"
    );
    assert_eq!(
        span_field(logs, event, "process_tree"),
        shape.process_tree_id,
        "the span carries the caller's own process tree: {logs}"
    );
    assert_eq!(
        span_field(logs, event, "lease"),
        format!("{}-lease", shape.operation_id),
        "the span carries the caller's own lease reference: {logs}"
    );
}

// WORK_UNIT_CASE: 901/29
#[test]
fn sink_presence_leaves_results_unchanged() {
    let (_guard, kernel) = process_authority_kernel("case29", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, enabled) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case29"),
    );
    let rt = current_thread_runtime();
    let disabled = rt.block_on(kernel.execute_process_request(
        &session,
        session_binding(),
        operation_request("op-901-case29"),
    ));

    assert_eq!(
        format!("{enabled:?}"),
        format!("{disabled:?}"),
        "a capture subscriber leaves the exact result unchanged"
    );
    assert!(
        matches!(enabled, ProcessExecutionResponse::Rejected(_))
            && matches!(disabled, ProcessExecutionResponse::Rejected(_)),
        "both arms return the same typed refusal"
    );
    assert!(
        logs.contains(KERNEL_DIAGNOSTICS_TARGET),
        "the enabled arm really had a live sink: {logs}"
    );
    assert!(
        logs.contains(&format!(
            "event=\"{}\"",
            fixture_event("process.request_received")
        )),
        "the enabled arm really executed the callsite: {logs}"
    );
    assert_eq!(
        terminal_codes(&logs).len(),
        1,
        "the sink did not add or remove a terminal: {logs}"
    );

    // The FAILED sink arm. issue-901-body.md:43 requires that a
    // "Failed/disabled/dropped sink leaves calls, results, primary and cleanup
    // errors, receipts, deadlines and ordering unchanged". The comparison above
    // covers `disabled`; this covers `failed`. The sink's `write` returns `Err`
    // unconditionally while still counting what production offered it.
    let (offered, failing, refused_writes) = capture_with_failing_sink(|| {
        current_thread_runtime().block_on(kernel.execute_process_request(
            &session,
            session_binding(),
            operation_request("op-901-case29"),
        ))
    });
    assert!(
        refused_writes > 0,
        "the failing sink really was written to, so this arm is not vacuous"
    );
    assert_eq!(
        format!("{failing:?}"),
        format!("{enabled:?}"),
        "a FAILED sink leaves the exact result unchanged; {refused_writes} writes were refused"
    );
    assert!(
        matches!(failing, ProcessExecutionResponse::Rejected(_)),
        "the failed-sink arm still returns the same typed refusal"
    );
    // The one terminal is emitted whether the sink delivers it or refuses it:
    // `offered` is what production handed the writer, so the emission itself is
    // still observable through a sink that accepted none of it.
    assert_eq!(
        offered
            .matches(&format!(
                "event=\"{}\"",
                fixture_event("process.request_received")
            ))
            .count(),
        1,
        "the failed-sink arm really executed the callsite: {offered}"
    );
    assert_eq!(
        terminal_codes(&offered),
        terminal_codes(&logs),
        "a failed sink emits the identical single terminal; it neither adds, drops nor reorders one"
    );
}

// WORK_UNIT_CASE: 901/30
#[test]
fn captured_causal_order_and_diagnostic_only_diff() {
    let (_guard, kernel) = process_authority_kernel("case30", &[]);
    let session = process_session();
    let binding = session_binding();
    let (logs, response) = drive_request(
        &kernel,
        &session,
        &binding,
        operation_request("op-901-case30"),
    );

    let received = format!("event=\"{}\"", fixture_event("process.request_received"));
    let admitted = format!("event=\"{}\"", fixture_event("process.request_admitted"));
    let requested = format!("event=\"{}\"", fixture_event("process.cancel_requested"));
    let terminal = "event=\"kernel.terminal_error\"".to_owned();
    assert!(byte_offset(&logs, &received) < byte_offset(&logs, &admitted));
    assert!(byte_offset(&logs, &admitted) < byte_offset(&logs, &requested));
    assert!(byte_offset(&logs, &requested) < byte_offset(&logs, &terminal));
    assert_eq!(rejection_code(&response), "NOT_FOUND");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // F-LOG-KERNEL-3 (#901 T30): the sweep must establish its OWN coverage
    // before it sweeps. `assert_sweep_covers_derivation` was reached only
    // through `assert_denominator`, whose sole caller is case 1, so running
    // case 30 on its own swept six paths with the six-against-six
    // correspondence between `OWNED_FILES` and `OWNED_PATHS` unasserted on this
    // path. It is called here too, not moved: it reports the DIRECTION of any
    // drift - "an owned module missing from OWNED_PATHS is never swept" for an
    // extra owned file, "case 30 sweeps no path the derivation does not cover"
    // for an extra swept path - naming which lists differ.
    assert_sweep_covers_derivation();
    // The sweep covers the whole DERIVED denominator - the five owned modules
    // plus the one out-of-scope instrumented file - because a sweep that stopped
    // at the owned five would leave a second subscriber owner in that sixth file
    // unobserved. The observation-surface check stays on the owned five, which is
    // where OWNED_OBSERVATION_DECLARATIONS is defined.
    for swept in SWEPT_PATHS {
        let src = std::fs::read_to_string(manifest_dir.join(swept))
            .unwrap_or_else(|_| panic!("swept module {swept} must be readable"));
        for needle in FORBIDDEN_IN_OWNED {
            assert!(!src.contains(needle), "{swept} must not contain {needle}");
        }
        // A THREAD-LOCAL subscriber install, which the whole-file list above
        // cannot carry because the capsules' own `with_default(` calls are
        // legitimate, plus the exact observation-surface declaration set in any
        // visibility.
        assert_no_production_subscriber(swept, &src);
    }
    for owned in OWNED_PATHS {
        let src = std::fs::read_to_string(manifest_dir.join(owned))
            .unwrap_or_else(|_| panic!("owned module {owned} must be readable"));
        assert_observation_declarations(owned, &src);
    }
    // F-LOG-KERNEL-3 (#901 T30), the seventh-module gap: a module that installs
    // its OWN subscriber without calling one of the six observers is in neither
    // owned list, is not produced by `derived_instrumented_files` - which is
    // keyed only on the observer names - and is not in the unowned list below.
    // That gap is CLOSED BY WIDENING THE DERIVATION rather than by prose:
    // `derived_subscriber_installers` walks the same `src/` tree as the
    // denominator derivation and reports every module whose PRODUCTION region
    // installs a subscriber, so such a module is found here by measurement. The
    // comparison is against a NAMED exclusion list, `FACADE_SUBSCRIBER_OWNERS`:
    // the shared facade that declares the one installer and the composition root
    // that calls it once. The owned six are filtered out because the loop above
    // already proves each of them individually and names the exact line.
    let outsiders: Vec<String> = derived_subscriber_installers()
        .into_iter()
        .filter(|path| !SWEPT_PATHS.contains(&path.as_str()))
        .collect();
    assert_eq!(
        outsiders,
        FACADE_SUBSCRIBER_OWNERS
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<String>>(),
        "no production module under src/ installs a subscriber except the two \
         NAMED owners: {outsiders:?}. A module with its own facade and no \
         observer call is in neither owned list and is not produced by the \
         observer-keyed denominator derivation, so this whole-tree derivation \
         is the only reader in this file that can find it"
    );
    // F-LOG-KERNEL-3 (#901 T30): the guard against a new PUBLIC observation
    // surface is `pub fn observe_` (not `fn observe_`: the six owned paths swept
    // above legitimately carry `process_execution.rs:73 observe_process_in_context`,
    // which is `pub(crate)`), and it is asserted per file above because
    // `pub fn observe_` is one of the `FORBIDDEN_IN_OWNED` needles.
    // `assert_observation_declarations` in that same loop now CLOSES THE THREE
    // SPELLINGS the needle evaded, because its key is the DECLARATION and not
    // the visibility: `pub(crate) fn observe_...`, `pub async fn observe_...`
    // and `pub fn observe(` are all read and none is in the pinned set except
    // `observe_process_in_context` at `process_execution.rs:73`. A separate
    // zero-count over the concatenated sources would be implied by those two
    // assertions, so it is deliberately absent rather than duplicated.
    //
    // WHAT IS STILL NOT COVERED, so that no reader of this case over-claims it:
    // a public observation surface whose name does not begin with `observe`
    // (`pub fn emit_boundary`), a re-export of a facade type (`pub use
    // super::kernel_diagnostics::...`, bare or renamed with `as`), and a
    // `macro_rules!` or trait impl that emits without naming `fn observe`. A
    // direct emission of a `kernel.*` event IS partly covered: both literal
    // spellings of `event` are needled above, but a new family emitted through
    // any other field shape is not.

    for unowned in ["src/lib.rs", "src/kernel_diagnostics.rs"] {
        let src = std::fs::read_to_string(manifest_dir.join(unowned))
            .unwrap_or_else(|_| panic!("{unowned} must be readable"));
        for family in OWNED_EVENT_FAMILIES {
            assert!(
                !src.contains(family),
                "{unowned} must not gain the owned vocabulary {family}"
            );
        }
        for mapper in [
            "process_terminal_code",
            "live_receipt_terminal_code",
            "daemon_launch_terminal_code",
            "supervision_authority_terminal_code",
        ] {
            assert!(
                !src.contains(mapper),
                "{unowned} must not gain the owned mapper {mapper}"
            );
        }
    }

    let cargo_toml =
        std::fs::read_to_string(manifest_dir.join("Cargo.toml")).expect("manifest readable");
    for family in OWNED_EVENT_FAMILIES {
        assert!(
            !cargo_toml.contains(family),
            "the manifest must not gain the owned vocabulary {family}"
        );
    }
    for forbidden in [
        "[dependencies.kernel]",
        "serial_test",
        "kernel_process_supervision",
    ] {
        assert!(
            !cargo_toml.contains(forbidden),
            "the manifest must not gain {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// Supervision-lease authority fixtures
//
// Cases 15 and 16 drive `KernelSupervisionLeaseAuthority` through its existing
// public seam. The composition only carries an authority when the configuration
// supplies one, so the fixture provisions the installer-owned disposable
// `PortableDev` signing key with the same public key provider the production
// installer uses and hands the resulting `SupervisionLeaseAuthorityConfig` to
// `KernelConfig`. No production code, `pub`, or helper is added here.
// ---------------------------------------------------------------------------

#[cfg(windows)]
use eliot_contracts::{AuthorityEpoch, StateFence};
#[cfg(windows)]
use eliot_installation::InstallationProfile;
#[cfg(windows)]
use eliot_kernel::{KernelSupervisionLeaseAuthority, SupervisionLeaseAuthorityConfig};
#[cfg(windows)]
use eliot_ors::{
    SupervisionLeaseBinding, SupervisionLeaseOperation, SupervisionLeasePrepareRequest,
    SupervisionLeaseProjection, SupervisionLeaseSnapshot, SupervisionLeaseStageReceipt,
};
#[cfg(windows)]
use eliot_platform_windows::{
    PortableDevSupervisionAuthorityKeyRequest, PortableDevSupervisionAuthorityKeyWriteOutcome,
    UserOwnedRootLease, WindowsPortableDevSupervisionAuthorityKeyProvider,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    LeaseState, ProvisionedSupervisionAuthority, RegisteredActivityWakePolicy,
    SupervisionAuthorityKeyReference, SupervisionGenerationBinding,
    SupervisionLeaseTerminalDisposition, SupervisionObservationScope,
};

/// Installation identity pinned into both the provisioned trust anchor and the
/// observation scope of every lease this fixture stages.
#[cfg(windows)]
const SUPERVISION_INSTALLATION_ID: &str = "eliot-901-installation";
#[cfg(windows)]
const SUPERVISION_SCOPE_ID: &str = "eliot-901-supervision-scope";
#[cfg(windows)]
const SUPERVISION_CANDIDATE_GENERATION: &str = "eliot-901-candidate-generation";
#[cfg(windows)]
const SUPERVISION_SIGNER_ID: &str = "eliot-901-kernel-signer";
#[cfg(windows)]
const SUPERVISION_KEY_ID: &str = "eliot-901-supervision-key";
#[cfg(windows)]
const SUPERVISION_KEY_RELATIVE_PATH: &str =
    ".eliot-dev/state/supervision/eliot-901-supervision-authority.key";

/// One composition that really carries a `KernelSupervisionLeaseAuthority`,
/// plus the non-secret contour values a lease binding must reproduce.
#[cfg(windows)]
struct SupervisionFixture {
    kernel: Arc<KernelComposition>,
    _guard: TempGuard,
    observation_scope: SupervisionObservationScope,
    wake_policy: RegisteredActivityWakePolicy,
    fence: StateFence,
    now_ms: u64,
}

#[cfg(windows)]
fn unix_now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the unix epoch")
            .as_millis(),
    )
    .expect("unix millisecond timestamp fits an unsigned 64-bit counter")
}

#[cfg(windows)]
fn supervision_generation() -> ResourceGeneration {
    ResourceGeneration::new(1).expect("supervision resource generation")
}

/// Provisions the disposable repository-local signing key and builds one
/// composition whose `supervision_lease_authority` accessor is therefore live.
#[cfg(windows)]
fn supervision_fixture(suffix: &str) -> SupervisionFixture {
    let root = unique_root(suffix);
    // The disposable provider keeps its seed below the exact repository-local
    // contour, so the whole contour must already exist before a key is
    // prepared: the provider refuses a missing ancestor rather than creating
    // one for a repository-local contour it does not own.
    let contour = root.join(".eliot-dev").join("state").join("supervision");
    std::fs::create_dir_all(&contour).expect("portable-dev supervision contour");
    let repository_identity = UserOwnedRootLease::open_existing(&root)
        .expect("portable-dev repository root lease")
        .identity();

    let provider = WindowsPortableDevSupervisionAuthorityKeyProvider::new();
    let prepared = provider
        .prepare(PortableDevSupervisionAuthorityKeyRequest {
            transaction_id: format!("eliot-901-{suffix}-transaction"),
            effect_id: format!("eliot-901-{suffix}-effect"),
            installation_id: SUPERVISION_INSTALLATION_ID.to_owned(),
            candidate_generation: SUPERVISION_CANDIDATE_GENERATION.to_owned(),
            authority_generation: supervision_generation(),
            supervision_lease_scope_id: SUPERVISION_SCOPE_ID.to_owned(),
            signer_id: SUPERVISION_SIGNER_ID.to_owned(),
            key_id: SUPERVISION_KEY_ID.to_owned(),
            repository_root: root.clone(),
            repository_root_identity: repository_identity,
            relative_path: SUPERVISION_KEY_RELATIVE_PATH.to_owned(),
        })
        .expect("prepared portable-dev supervision authority key");
    let trust_anchor = prepared.receipt().trust_anchor.clone();
    let written = provider
        .write_prepared(prepared)
        .expect("written portable-dev supervision authority key");
    assert!(
        matches!(
            &written,
            PortableDevSupervisionAuthorityKeyWriteOutcome::Created { .. }
        ),
        "the disposable repository-local key must be created, got {written:?}"
    );

    let authority = ProvisionedSupervisionAuthority::new(
        SUPERVISION_SCOPE_ID,
        SUPERVISION_CANDIDATE_GENERATION,
        supervision_generation(),
        SupervisionAuthorityKeyReference::portable_dev(SUPERVISION_KEY_RELATIVE_PATH)
            .expect("portable-dev supervision key reference"),
        trust_anchor,
    )
    .expect("provisioned supervision authority");
    // The canonical observation scope and wake policy are read back from the
    // provisioned receipt itself, so a lease binding can never invent them.
    let observation_scope = authority.observation_scope.clone();
    let wake_policy = authority.wake_policy.clone();

    let mut config = KernelConfig::new(&root);
    config.pipe_name = format!(
        r"\\.\pipe\eliot\kernel-901-supervision-{suffix}-{}",
        std::process::id()
    );
    let config = config
        .with_supervision_installation_profile(
            InstallationProfile::PortableDev,
            Some((root.clone(), repository_identity)),
        )
        .with_supervision_lease_authority(SupervisionLeaseAuthorityConfig { authority });
    let kernel = KernelComposition::new(config).expect("supervision-authority composition");
    assert!(
        kernel.supervision_lease_authority().is_some(),
        "the composition really carries the supervision lease authority"
    );

    SupervisionFixture {
        kernel: Arc::new(kernel),
        _guard: TempGuard { root },
        observation_scope,
        wake_policy,
        fence: StateFence::new(test_epoch(1), supervision_generation()),
        now_ms: unix_now_ms(),
    }
}

/// One `ACTIVE` binding over the fixture's exact lineage. `expires_at_ms` is the
/// only field a renewal is allowed to move.
#[cfg(windows)]
fn active_lease_binding(
    fixture: &SupervisionFixture,
    expires_at_ms: u64,
) -> SupervisionLeaseBinding {
    let issued_at_ms = fixture.now_ms - 60_000;
    SupervisionLeaseBinding {
        scope_ref: OpaqueLabel::new(SUPERVISION_SCOPE_ID).expect("lease scope label"),
        observation_scope: fixture.observation_scope.clone(),
        installation_id: OpaqueLabel::new(SUPERVISION_INSTALLATION_ID)
            .expect("installation identity label"),
        host_epoch: AuthorityEpoch::new(11).expect("host authority epoch"),
        activation_id: OpaqueLabel::new("eliot-901-activation").expect("activation label"),
        activation_generation: supervision_generation(),
        kernel_epoch: test_epoch(1),
        kernel_front_door_server_sid: PEER_SID.to_owned(),
        kernel_front_door_session_id: 4,
        kernel_front_door_artifact_sha256: "b".repeat(64),
        watchdog_epoch: AuthorityEpoch::new(12).expect("watchdog authority epoch"),
        generation_binding: SupervisionGenerationBinding {
            target_id: "a".repeat(64),
            module_id: MODULE_ID.to_owned(),
            process_id: "pid:4242:start:99001".to_owned(),
            target_generation: supervision_generation(),
            module_generation: supervision_generation(),
            process_generation: supervision_generation(),
        },
        state_fence: fixture.fence.clone(),
        issued_at_ms,
        expires_at_ms,
        renew_before_ms: issued_at_ms + (expires_at_ms - issued_at_ms) / 2,
        wake_policy: fixture.wake_policy.clone(),
        state: LeaseState::Active,
        terminal_disposition: None,
        revocation_reason: None,
        revocation_id: None,
        revocation_epoch: None,
    }
}

#[cfg(windows)]
fn lease_prepare_request(
    lease_id: &str,
    tag: &str,
    operation: SupervisionLeaseOperation,
    expected_revision: Option<u64>,
    binding: SupervisionLeaseBinding,
) -> SupervisionLeasePrepareRequest {
    SupervisionLeasePrepareRequest {
        ticket_id: OperationIdentity::new(format!("{tag}-ticket")).expect("ticket identity"),
        operation_id: OperationIdentity::new(format!("{tag}-operation"))
            .expect("lease operation identity"),
        lease_id: OperationIdentity::new(lease_id.to_owned()).expect("lease identity"),
        expected_revision,
        operation,
        binding,
    }
}

/// Clones the exact active head into its `REVOKED` successor shape. Only the
/// revocation fields move, so the lineage the predecessor proof requires is
/// preserved exactly.
#[cfg(windows)]
fn revocation_binding(head: &SupervisionLeaseSnapshot, reason: &str) -> SupervisionLeaseBinding {
    let mut binding = head.record.binding.clone();
    binding.state = LeaseState::Revoked;
    binding.terminal_disposition = Some(SupervisionLeaseTerminalDisposition::Revoked);
    binding.revocation_reason = Some(reason.to_owned());
    binding.revocation_id = Some("eliot-901-revocation-identity".to_owned());
    binding.revocation_epoch = Some(AuthorityEpoch::new(13).expect("revocation authority epoch"));
    binding
}

/// Stages one ticket and drives the public active-commit boundary, returning
/// the captured bytes and the committed revision.
#[cfg(windows)]
fn drive_commit_active(
    authority: &KernelSupervisionLeaseAuthority,
    lease_id: &str,
    tag: &str,
    operation: SupervisionLeaseOperation,
    expected_revision: Option<u64>,
    binding: SupervisionLeaseBinding,
) -> (String, SupervisionLeaseSnapshot) {
    let stage = authority
        .prepare(lease_prepare_request(
            lease_id,
            tag,
            operation,
            expected_revision,
            binding,
        ))
        .expect("staged supervision lease ticket");
    let (logs, committed) = capture_blocking(|| authority.commit_active(stage.ticket()));
    (
        logs,
        committed.expect("committed active supervision lease revision"),
    )
}

#[cfg(windows)]
fn stage_terminal_ticket(
    authority: &KernelSupervisionLeaseAuthority,
    lease_id: &str,
    tag: &str,
    operation: SupervisionLeaseOperation,
    expected_revision: Option<u64>,
    binding: SupervisionLeaseBinding,
) -> SupervisionLeaseStageReceipt {
    authority
        .prepare(lease_prepare_request(
            lease_id,
            tag,
            operation,
            expected_revision,
            binding,
        ))
        .expect("staged terminal supervision lease ticket")
}

/// Captured bytes and committed revision of each distinct phase of case 16.
#[cfg(windows)]
struct DistinctLeasePhases {
    acquired: SupervisionLeaseSnapshot,
    renewed: SupervisionLeaseSnapshot,
    renew_logs: String,
    revoked: SupervisionLeaseSnapshot,
    revoke_logs: String,
    expired: SupervisionLeaseSnapshot,
    expire_logs: String,
    conflict_logs: String,
    conflict_is_error: bool,
}

/// Drives renewal, revocation, expiry and one conflicting terminal commit over
/// four independent lease identities of one real supervision authority.
#[cfg(windows)]
fn drive_distinct_lease_phases(fixture: &SupervisionFixture) -> DistinctLeasePhases {
    let authority = fixture
        .kernel
        .supervision_lease_authority()
        .expect("composition carries the supervision lease authority");
    let first_expiry_ms = fixture.now_ms + 3_600_000;

    let (_acquire_logs, acquired) = drive_commit_active(
        authority,
        "eliot-901-case16-renew",
        "eliot-901-case16-renew-acquire",
        SupervisionLeaseOperation::Commit,
        None,
        active_lease_binding(fixture, first_expiry_ms),
    );
    let (renew_logs, renewed) = drive_commit_active(
        authority,
        "eliot-901-case16-renew",
        "eliot-901-case16-renew-renewal",
        SupervisionLeaseOperation::Renew,
        Some(acquired.record.revision),
        active_lease_binding(fixture, fixture.now_ms + 7_200_000),
    );

    let (_revoke_acquire_logs, revoke_head) = drive_commit_active(
        authority,
        "eliot-901-case16-revoke",
        "eliot-901-case16-revoke-acquire",
        SupervisionLeaseOperation::Commit,
        None,
        active_lease_binding(fixture, first_expiry_ms),
    );
    let revoke_stage = stage_terminal_ticket(
        authority,
        "eliot-901-case16-revoke",
        "eliot-901-case16-revoke-terminal",
        SupervisionLeaseOperation::Revoke,
        Some(revoke_head.record.revision),
        revocation_binding(&revoke_head, "eliot-901-case16-revocation"),
    );
    let (revoke_logs, revoked) =
        capture_blocking(|| authority.commit_terminal(revoke_stage.ticket()));
    let revoked = revoked.expect("committed revoked supervision lease revision");

    let (_expire_acquire_logs, expire_head) = drive_commit_active(
        authority,
        "eliot-901-case16-expire",
        "eliot-901-case16-expire-acquire",
        SupervisionLeaseOperation::Commit,
        None,
        active_lease_binding(fixture, first_expiry_ms),
    );
    let past_due_ms = expire_head.record.binding.expires_at_ms + 1;
    let (expire_logs, expired) = capture_blocking(|| {
        authority.expire_past_due_lease("eliot-901-case16-expire", &fixture.fence, past_due_ms)
    });
    let expired = expired
        .expect("past-due lease expiry read")
        .expect("a past-due active lease is expired");

    let conflict_stage = stage_terminal_ticket(
        authority,
        "eliot-901-case16-renew",
        "eliot-901-case16-conflict",
        SupervisionLeaseOperation::Revoke,
        Some(renewed.record.revision),
        revocation_binding(&renewed, "eliot-901-case16-conflict"),
    );
    let mut conflicting = conflict_stage.ticket().clone();
    conflicting.binding.revocation_reason = Some("eliot-901-case16-conflict-altered".to_owned());
    let (conflict_logs, conflict) = capture_blocking(|| authority.commit_terminal(&conflicting));

    DistinctLeasePhases {
        acquired,
        renewed,
        renew_logs,
        revoked,
        revoke_logs,
        expired,
        expire_logs,
        conflict_logs,
        conflict_is_error: conflict.is_err(),
    }
}

// WORK_UNIT_CASE: 901/15
#[cfg(windows)]
#[test]
fn lease_acquisition_is_not_yet_active_ownership() {
    let fixture = supervision_fixture("case15");
    let authority = fixture
        .kernel
        .supervision_lease_authority()
        .expect("composition carries the supervision lease authority");
    let lease_id = "eliot-901-case15-lease";

    let stage = authority
        .prepare(lease_prepare_request(
            lease_id,
            "eliot-901-case15-acquire",
            SupervisionLeaseOperation::Commit,
            None,
            active_lease_binding(&fixture, fixture.now_ms + 3_600_000),
        ))
        .expect("staged lease acquisition");
    assert_eq!(
        stage.projection,
        SupervisionLeaseProjection::Staged,
        "an acquired ticket is staged, never an active lease: {stage:?}"
    );
    let acquired_only = authority
        .current_snapshot(lease_id)
        .expect("durable lease head read");
    assert!(
        acquired_only.is_none(),
        "a staged acquisition is not active ownership yet"
    );

    let (logs, committed) = capture_blocking(|| authority.commit_active(stage.ticket()));
    let committed = committed.expect("committed active supervision lease revision");

    let requested = "kernel.supervision.commit_requested";
    let committed_event = "kernel.supervision.commit_committed";
    assert_eq!(event_count(&logs, requested), 1, "one acquisition: {logs}");
    assert_eq!(
        event_outcome(&logs, requested),
        "attempt",
        "acquisition is requested before it is ownership: {logs}"
    );
    assert_ne!(
        event_outcome(&logs, requested),
        event_outcome(&logs, committed_event),
        "a requested acquisition is never the committed outcome: {logs}"
    );
    assert_eq!(
        span_field(&logs, requested, "lease_operation"),
        "commit",
        "the acquisition phase is recorded on the shared operation span: {logs}"
    );
    assert_eq!(
        span_field(&logs, requested, "lease"),
        lease_id,
        "the acquisition keeps its exact lease identity: {logs}"
    );
    assert!(
        byte_offset(&logs, &format!("event=\"{requested}\""))
            < byte_offset(&logs, &format!("event=\"{committed_event}\"")),
        "the requested acquisition precedes the committed ownership: {logs}"
    );
    assert!(
        terminal_codes(&logs).is_empty(),
        "an acquisition that commits emits no terminal: {logs}"
    );

    assert_eq!(
        committed.record.state,
        LeaseState::Active,
        "committed ownership reaches the ACTIVE lease state: {logs}"
    );
    assert_eq!(
        format!("{}", committed.record.state),
        "ACTIVE",
        "the production state literal is the lifecycle vocabulary value: {logs}"
    );
    assert_eq!(
        committed.record.projection,
        SupervisionLeaseProjection::Active,
        "only a committed revision becomes the active projection: {logs}"
    );
    let owned = authority
        .current_snapshot(lease_id)
        .expect("durable lease head read after the commit")
        .expect("the committed revision is the durable head");
    assert_eq!(
        owned.record.state,
        LeaseState::Active,
        "the durable head is active only after the commit evidence: {logs}"
    );
}

// WORK_UNIT_CASE: 901/16
#[cfg(windows)]
#[test]
fn renewal_revocation_expiry_and_conflict_are_distinct_observations() {
    let fixture = supervision_fixture("case16");
    let phases = drive_distinct_lease_phases(&fixture);

    let renew_operation = assert_renewal_phase(&phases);
    let revoke_operation = assert_revocation_phase(&phases);
    let expire_operation = assert_expiry_phase(&phases);
    assert_conflict_phase(&phases);

    // Distinctness: the three committed phases are three different production
    // phase discriminators, and the conflict is a fourth observation with its
    // own refusal outcome and its own terminal code.
    assert_ne!(
        renew_operation,
        revoke_operation,
        "renewal and revocation stay distinct: {logs}",
        logs = phases.renew_logs
    );
    assert_ne!(
        revoke_operation,
        expire_operation,
        "revocation and expiry stay distinct: {logs}",
        logs = phases.revoke_logs
    );
    assert_ne!(
        renew_operation,
        expire_operation,
        "renewal and expiry stay distinct: {logs}",
        logs = phases.expire_logs
    );
    // REGRESSION GUARD (absence), non-vacuously satisfiable. Each of these three
    // captures is already proven POSITIVE above: `span_field` PANICS unless the
    // capture carries that phase's own `commit_requested` /
    // `terminal_requested` / `expire_committed` line, and
    // `event_outcome(...) == "success"` PINNED its committed sibling, so each
    // capture is non-empty and carries the committed pair. What the loop adds is
    // the negative half of the same commit: `terminal_failed`
    // (`supervision_lease_authority.rs:918`, the refusal arm of
    // `commit_terminal_in_context`) and a `kernel.terminal_error`
    // (`:923`) must be absent from a run that committed - the difference between
    // "attempted and refused" and "attempted and committed" is what this case
    // draws, and neither absence can be satisfied by an empty capture.
    for logs in [&phases.renew_logs, &phases.revoke_logs, &phases.expire_logs] {
        assert!(
            !logs.contains("event=\"kernel.supervision.terminal_failed\""),
            "no committed phase emits the refusal event: {logs}"
        );
        assert!(
            terminal_codes(logs).is_empty(),
            "no committed phase emits a terminal: {logs}"
        );
    }
}

/// A renewal is a new revision and a new expiry over the same lineage; the
/// returned phase discriminator is what makes it distinct from the others.
#[cfg(windows)]
fn assert_renewal_phase(phases: &DistinctLeasePhases) -> String {
    let operation = span_field(
        &phases.renew_logs,
        "kernel.supervision.commit_requested",
        "lease_operation",
    );
    assert_eq!(
        operation,
        "renew",
        "the renewal phase discriminator is observed: {logs}",
        logs = phases.renew_logs
    );
    assert_eq!(
        event_outcome(&phases.renew_logs, "kernel.supervision.commit_committed"),
        "success",
        "the renewal commits: {logs}",
        logs = phases.renew_logs
    );
    assert_eq!(
        phases.renewed.record.state,
        LeaseState::Active,
        "a renewal stays ACTIVE: {logs}",
        logs = phases.renew_logs
    );
    assert_eq!(
        phases.renewed.record.revision,
        phases.acquired.record.revision + 1,
        "a renewal is a new revision: {logs}",
        logs = phases.renew_logs
    );
    assert_ne!(
        phases.renewed.record.binding.expires_at_ms,
        phases.acquired.record.binding.expires_at_ms,
        "a renewal carries a new expiry: {logs}",
        logs = phases.renew_logs
    );
    operation
}

/// A revocation crosses the terminal commit boundary into the REVOKED state and
/// is fenced by its terminal projection.
#[cfg(windows)]
fn assert_revocation_phase(phases: &DistinctLeasePhases) -> String {
    let operation = span_field(
        &phases.revoke_logs,
        "kernel.supervision.terminal_requested",
        "lease_operation",
    );
    assert_eq!(
        operation,
        "revoke",
        "the revocation phase discriminator is observed: {logs}",
        logs = phases.revoke_logs
    );
    assert_eq!(
        event_outcome(&phases.revoke_logs, "kernel.supervision.terminal_committed"),
        "success",
        "the revocation commits: {logs}",
        logs = phases.revoke_logs
    );
    assert_eq!(
        format!("{}", phases.revoked.record.state),
        "REVOKED",
        "revocation reaches the REVOKED lifecycle state: {logs}",
        logs = phases.revoke_logs
    );
    assert_eq!(
        phases.revoked.record.projection,
        SupervisionLeaseProjection::Terminal,
        "a revoked revision is fenced, not active: {logs}",
        logs = phases.revoke_logs
    );
    operation
}

/// An expiry past the validity boundary reaches the EXPIRED state through the
/// expiry boundary rather than the terminal boundary alone.
#[cfg(windows)]
fn assert_expiry_phase(phases: &DistinctLeasePhases) -> String {
    let operation = span_field(
        &phases.expire_logs,
        "kernel.supervision.expire_committed",
        "lease_operation",
    );
    assert_eq!(
        operation,
        "expire",
        "the expiry phase discriminator is observed: {logs}",
        logs = phases.expire_logs
    );
    assert_eq!(
        event_outcome(&phases.expire_logs, "kernel.supervision.expire_committed"),
        "success",
        "the expiry commits: {logs}",
        logs = phases.expire_logs
    );
    assert_eq!(
        format!("{}", phases.expired.record.state),
        "EXPIRED",
        "expiry reaches the EXPIRED lifecycle state: {logs}",
        logs = phases.expire_logs
    );
    operation
}

/// A changed same-ticket payload keeps the actual conflict: a refusal outcome
/// plus exactly one typed identity-conflict terminal, never a commit.
#[cfg(windows)]
fn assert_conflict_phase(phases: &DistinctLeasePhases) {
    assert!(
        phases.conflict_is_error,
        "a changed same-ticket payload retains the conflict: {logs}",
        logs = phases.conflict_logs
    );
    assert_eq!(
        event_outcome(&phases.conflict_logs, "kernel.supervision.terminal_failed"),
        "rejected",
        "the conflict is a refusal, never a commit: {logs}",
        logs = phases.conflict_logs
    );
    assert_eq!(
        terminal_codes(&phases.conflict_logs),
        vec!["SUPERVISION_IDENTITY_CONFLICT".to_owned()],
        "the conflict carries exactly one typed terminal: {logs}",
        logs = phases.conflict_logs
    );
}
